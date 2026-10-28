"""Где живёт сервер AWG и как до него дотянуться.

Два вида «цели»:
  * container — контейнер AmneziaVPN (amnezia-awg2 / amnezia-awg), конфиг в /opt/amnezia/awg;
  * host      — AmneziaWG прямо на хосте под systemd (awg-quick@awg0), конфиг в
                /etc/amnezia/amneziawg. Панель может установить такой сервер сама.

Панель запущена с pid: host и privileged, поэтому видит файлы цели через
/proc/<pid>/root и входит в её пространства имён через nsenter.
"""
from __future__ import annotations

import glob
import hashlib
import http.client
import json
import logging
import os
import random
import shutil
import socket
import subprocess
import time
import urllib.parse

from . import awgserver, config
from .i18n import Msg, MsgError

log = logging.getLogger("awgr.system")

HOST_BIN_DIR = "/usr/local/bin"
HOST_UNIT = "/etc/systemd/system/awg-quick@.service"
UNIT_TEXT = """[Unit]
Description=AmneziaWG via awg-quick for %I (AWG Router)
After=network-online.target nss-lookup.target
Wants=network-online.target nss-lookup.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/awg-quick up %i
ExecStop=/usr/local/bin/awg-quick down %i
ExecReload=/bin/bash -c 'exec /usr/local/bin/awg syncconf %i <(exec /usr/local/bin/awg-quick strip %i)'
Environment=WG_ENDPOINT_RESOLUTION_RETRIES=infinity

[Install]
WantedBy=multi-user.target
"""


class SysError(MsgError, RuntimeError):
    """Ошибка с сообщением для интерфейса (Msg) или технической строкой."""

    def __init__(self, msg):
        if isinstance(msg, Msg):
            super().__init__(msg)
        else:
            RuntimeError.__init__(self, msg)
            self.msg = str(msg)


# ======================================================================= docker
class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: int = 10):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def docker_api(method: str, path: str, timeout: int = 10):
    conn = _UnixHTTP(config.DOCKER_SOCK, timeout)
    try:
        conn.request(method, path)
        r = conn.getresponse()
        body = r.read()
        if r.status == 404:
            return None
        if r.status >= 300:
            raise SysError(f"Docker API {method} {path}: HTTP {r.status} {body[:200]!r}")
        return json.loads(body) if body.strip() else {}
    finally:
        conn.close()


def docker_get(path: str):
    return docker_api("GET", path)


def docker_containers() -> list[str]:
    try:
        cs = docker_get("/containers/json") or []
    except OSError:
        return []
    return [n.lstrip("/") for c in cs for n in c.get("Names", [])]


def run(cmd: list[str], *, input: str | None = None, timeout: int = 30,
        check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, input=input, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise SysError(f"{' '.join(cmd[-6:])}: {(p.stderr or p.stdout).strip()[:400]}")
    return p


def _parse_dump(text: str) -> dict:
    peers = {}
    lines = text.strip().split("\n")
    for line in lines[1:]:
        f = line.split("\t")
        if len(f) < 8:
            continue
        pk, _psk, endpoint, allowed, hs, rx, tx = f[:7]
        peers[pk] = {
            "endpoint": None if endpoint == "(none)" else endpoint,
            "allowed_ips": allowed,
            "handshake": int(hs or 0),
            "rx": int(rx or 0),
            "tx": int(tx or 0),
        }
    return peers


def local_awg(args: list[str], input: str | None = None) -> str:
    """Утилита awg самой панели (для genkey/pubkey/genpsk)."""
    return run(["awg"] + args, input=input, timeout=10).stdout.strip()


def genkey() -> tuple[str, str]:
    priv = local_awg(["genkey"])
    return priv, local_awg(["pubkey"], input=priv + "\n")


def pubkey(priv: str) -> str:
    return local_awg(["pubkey"], input=priv + "\n")


# ======================================================================= цели
class Target:
    kind = "?"

    def __init__(self, name: str, pid: int, iface: str, conf_path: str, started: str):
        self.name = name
        self.pid = pid
        self.iface = iface
        self.conf_path = conf_path   # путь внутри файловой системы цели
        self.started = started
        self.exists = True

    # совместимость со старым кодом/интерфейсом
    @property
    def container(self) -> str:
        return self.name

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.name}:{self.pid}:{self.started}"

    @property
    def dir(self) -> str:
        return os.path.dirname(self.conf_path)

    @property
    def clients_table_path(self) -> str:
        return f"{self.dir}/clientsTable"

    def host_path(self, p: str) -> str:
        return f"/proc/{self.pid}/root{p}"

    # наши бинарники в сети цели
    def ns(self, cmd: list[str], **kw) -> subprocess.CompletedProcess:
        return run(["nsenter", "-t", str(self.pid), "-n", "--"] + cmd, **kw)

    # бинарники и сокеты самой цели
    def native(self, cmd: list[str], **kw) -> subprocess.CompletedProcess:
        raise NotImplementedError

    ns_container = native  # старое имя

    def read_file(self, p: str) -> str | None:
        try:
            with open(self.host_path(p)) as f:
                return f.read()
        except OSError:
            return None

    def write_file(self, p: str, text: str, mode: int = 0o600) -> None:
        hp = self.host_path(p)
        os.makedirs(os.path.dirname(hp), exist_ok=True)
        tmp = f"{hp}.awgr-{os.getpid()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, hp)

    # ------------------------------------------------------------- сервер
    @property
    def awg_bin(self) -> str:
        return "awg"

    def dump(self) -> dict:
        errors = []
        for b in dict.fromkeys([self.awg_bin, "awg", "wg"]):
            try:
                return _parse_dump(self.native([b, "show", self.iface, "dump"], timeout=10).stdout)
            except Exception as e:  # noqa: BLE001
                errors.append(str(e))
        raise SysError("awg show: " + " | ".join(errors)[:300])

    def sync(self, sc: awgserver.ServerConf) -> None:
        """Применить пиры и параметры без перезапуска интерфейса."""
        tmp = self.sync_tmp
        self.write_file(tmp, sc.stripped())
        try:
            self.native([self.awg_bin, "syncconf", self.iface, tmp], timeout=20)
        finally:
            try:
                os.remove(self.host_path(tmp))
            except OSError:
                pass

    sync_tmp = "/tmp/awgr-sync.conf"

    def restart(self) -> None:
        raise NotImplementedError

    def psk_for_new_client(self) -> str:
        return local_awg(["genpsk"])


class ContainerTarget(Target):
    kind = "container"

    def native(self, cmd, **kw):
        return run(["nsenter", "-t", str(self.pid), "-m", "-n", "--"] + cmd, **kw)

    ns_container = native

    @property
    def awg_bin(self) -> str:
        return "wg" if self.iface == "wg0" else "awg"

    def restart(self) -> None:
        docker_api("POST", f"/containers/{urllib.parse.quote(self.name)}/restart?t=3", timeout=40)

    def psk_for_new_client(self) -> str:
        # приложение AmneziaVPN использует один общий PSK на всех клиентов
        psk = (self.read_file(f"{self.dir}/wireguard_psk.key") or "").strip()
        return psk if awgserver.KEY_RE.match(psk) else local_awg(["genpsk"])


class HostTarget(Target):
    kind = "host"

    def __init__(self, iface: str):
        super().__init__("host", 1, iface, f"{config.HOST_AWG_DIR}/{iface}.conf", "host")
        self.exists = os.path.exists(self.host_path(self.conf_path))

    @property
    def key(self) -> str:
        return f"host:{self.iface}"

    def native(self, cmd, **kw):
        return run(["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--"] + cmd, **kw)

    ns_container = native
    sync_tmp = "/run/awgr-sync.conf"

    def is_up(self) -> bool:
        return self.native(["ip", "link", "show", self.iface], check=False).returncode == 0

    def restart(self) -> None:
        unit = f"awg-quick@{self.iface}"
        if self.native(["systemctl", "cat", unit], check=False).returncode == 0:
            self.native(["systemctl", "restart", unit], timeout=60)
        else:
            self.native(["awg-quick", "down", self.iface], check=False, timeout=30)
            self.native(["awg-quick", "up", self.iface], timeout=60)


# ============================================================= поиск цели
def _container_target(name: str) -> ContainerTarget:
    info = docker_get(f"/containers/{urllib.parse.quote(name)}/json")
    if not info:
        raise SysError(Msg("sys.container_missing", name=name))
    st = info.get("State", {})
    if not st.get("Running") or not st.get("Pid"):
        raise SysError(Msg("sys.container_stopped", name=name))
    pid = int(st["Pid"])
    root = f"/proc/{pid}/root"
    if not os.path.isdir(root + config.AWG_DIR):
        raise SysError(Msg("sys.no_awg_dir", name=name, dir=config.AWG_DIR))
    if config.AWG_IFACE:
        iface = config.AWG_IFACE
        conf = f"{config.AWG_DIR}/{iface}.conf"
    else:
        confs = sorted(glob.glob(root + config.AWG_DIR + "/*.conf"),
                       key=lambda p: (not p.endswith("/awg0.conf"), p))
        if not confs:
            raise SysError(Msg("sys.no_conf", name=name, dir=config.AWG_DIR))
        conf = confs[0][len(root):]
        iface = os.path.basename(conf)[:-5]
    return ContainerTarget(name, pid, iface, conf, st.get("StartedAt", ""))


def find_amnezia_container() -> str | None:
    if config.AWG_CONTAINER:
        return config.AWG_CONTAINER
    names = docker_containers()
    for n in ("amnezia-awg2", "amnezia-awg"):
        if n in names:
            return n
    return next((n for n in sorted(names) if n.startswith("amnezia-awg") and "-old-" not in n), None)


def discover() -> Target:
    """Находит сервер AWG согласно AWG_MODE (auto | container | host)."""
    mode = config.AWG_MODE
    if mode in ("auto", "container"):
        name = find_amnezia_container()
        if name:
            return _container_target(name)
        if mode == "container":
            raise SysError(Msg("sys.no_container"))
    return HostTarget(config.AWG_IFACE or "awg0")


# ============================================================ сервер на хосте
def _sha_file(p: str) -> str | None:
    try:
        with open(p, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def install_host_runtime(t: HostTarget) -> bool:
    """Ставит на хост awg, awg-quick, amneziawg-go и unit systemd. True — что-то обновлено."""
    changed = False
    for name in ("awg", "awg-quick", "amneziawg-go"):
        src = shutil.which(name)
        if not src:
            raise SysError(f"{name} is missing in the panel image")
        dst = t.host_path(f"{HOST_BIN_DIR}/{name}")
        if _sha_file(src) != _sha_file(dst):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            tmp = dst + ".awgr-new"
            shutil.copyfile(src, tmp)
            os.chmod(tmp, 0o755)
            os.replace(tmp, dst)   # замена «на лету» безопасна для работающего процесса
            changed = True
    unit = t.host_path(HOST_UNIT)
    try:
        current = open(unit).read()
    except OSError:
        current = None
    if current != UNIT_TEXT:
        t.write_file(HOST_UNIT, UNIT_TEXT, 0o644)
        t.native(["systemctl", "daemon-reload"], check=False)
        changed = True
    return changed


def init_host_server(t: HostTarget, port: int, subnet: str, params: dict[str, str]) -> None:
    if t.exists:
        raise SysError(Msg("srv.already_exists"))
    install_host_runtime(t)
    priv, _ = genkey()
    sc = awgserver.new_server(priv, port, subnet, params)
    t.write_file(t.conf_path, sc.render())
    t.write_file(t.clients_table_path, "[]")
    t.native(["systemctl", "enable", "--now", f"awg-quick@{t.iface}"], timeout=60)
    open_firewall_udp(t, port)
    t.exists = True


def open_firewall_udp(t: HostTarget, port: int) -> None:
    """Если на хосте включён ufw — открыть UDP-порт сервера."""
    try:
        p = t.native(["ufw", "status"], check=False)
    except OSError:
        return
    if p.returncode == 0 and "Status: active" in p.stdout:
        t.native(["ufw", "allow", f"{port}/udp"], check=False)


def random_udp_port() -> int:
    return random.randint(20000, 59999)


# ======================================================================= демо
class DemoTarget(Target):
    """DRY_RUN: настоящие файлы в data/demo-root, команды не выполняются."""
    kind = "demo"

    def __init__(self):
        super().__init__("amnezia-awg2 (demo)", 4242, "awg0", "/opt/amnezia/awg/awg0.conf", "demo")
        self.root = os.path.join(config.DATA_DIR, "demo-root")
        self.log: list[str] = []
        self.handshakes: dict[str, float] = {}
        self._seed()

    def host_path(self, p: str) -> str:
        return self.root + p

    def _cmd(self, cmd):
        self.log.append(" ".join(cmd))
        self.log[:] = self.log[-200:]
        out = ""
        if cmd[:2] == ["nft", "list"]:
            out = "table ip awgr {}"
        if cmd[:1] == ["ip"] and "-j" in cmd:
            out = "[]"
        if len(cmd) > 3 and cmd[1] == "show" and cmd[-1] == "dump":
            if cmd[2] == self.iface:
                out = self._server_dump()
            else:
                hs = int(self.handshakes.get(cmd[2], time.time() - 20))
                out = ("priv\tpub\t0\toff\n"
                       f"PEER\t(none)\t203.0.113.7:51820\t0.0.0.0/0\t{hs}\t{int(time.time()) % 900000 * 731}\t"
                       f"{int(time.time()) % 900000 * 113}\t25\n")
        return subprocess.CompletedProcess(cmd, 0, out, "")

    def ns(self, cmd, **kw):
        return self._cmd(cmd)

    def native(self, cmd, **kw):
        return self._cmd(cmd)

    ns_container = native

    def restart(self) -> None:
        self.log.append("docker restart amnezia-awg2")

    def psk_for_new_client(self) -> str:
        return (self.read_file(f"{self.dir}/wireguard_psk.key") or "").strip()

    def _server_dump(self) -> str:
        sc = awgserver.parse(self.read_file(self.conf_path) or "")
        now = time.time()
        lines = ["priv\tpub\t47823\toff"]
        for i, p in enumerate(sc.peers):
            if not p.enabled:
                continue
            age = [40, 300, 15, 4000, 86400 * 3, 0, 25, 9][i % 8]
            hs = int(now - age) if age else 0
            lines.append(f"{p.public_key}\t{p.psk or '(none)'}\t198.51.100.{20 + i}:{40000 + i}\t"
                         f"{p.allowed_ips}\t{hs}\t{(i + 1) * 98_304_000}\t{(i + 1) * 734_003_200}\t0")
        return "\n".join(lines) + "\n"

    def _seed(self) -> None:
        if os.path.exists(self.host_path(self.conf_path)):
            return
        import base64
        import secrets as _s

        def key():
            return base64.b64encode(_s.token_bytes(32)).decode()
        psk = key()
        params = awgserver.generate_params(True)
        sc = awgserver.ServerConf()
        sc.iface = [("PrivateKey", key()), ("Address", "10.8.1.0/24"), ("ListenPort", "47823")]
        for k, v in params.items():
            sc.set(k, v)
        rows = []
        for i, name in enumerate(["Anna iPhone", "Anna MacBook", "Dad", "Office router",
                                  "Living room TV", "Guest"]):
            pk = key()
            sc.peers.append(awgserver.Peer(pk, psk, f"10.8.1.{i + 1}/32"))
            rows.append({"clientId": pk, "userData": {"clientName": name,
                                                      "creationDate": awgserver.amnezia_date()}})
        self.write_file(self.conf_path, sc.render())
        self.write_file(f"{self.dir}/wireguard_psk.key", psk + "\n")
        self.write_file(self.clients_table_path, awgserver.render_clients_table(rows))
