"""Где живёт сервер AWG и как до него дотянуться.

Два вида «цели»:
  * container — контейнер AmneziaVPN (amnezia-awg2 / amnezia-awg), конфиг в /opt/amnezia/awg;
  * host      — AmneziaWG прямо на хосте под systemd (awg-quick@awg0), конфиг в
                /etc/amnezia/amneziawg. Панель может установить такой сервер сама.

Панель запущена с pid: host и privileged, поэтому видит файлы цели через
/proc/<pid>/root и входит в её пространства имён через nsenter.
"""
from __future__ import annotations

import base64
import glob
import hashlib
import http.client
import json
import logging
import os
import random
import re
import secrets
import shutil
import socket
import subprocess
import time
import urllib.parse

from . import awgserver, config, nftgen
from .i18n import Msg, MsgError

log = logging.getLogger("awgr.system")

HOST_BIN_DIR = "/usr/local/bin"
HOST_UNIT = "/etc/systemd/system/awg-quick@.service"
# Правила панели «до её запуска» (engine.HOLD_FILE): после перезагрузки хоста таблицы панели нет, и пока
# панель не запустилась, клиенты шли бы мимо выходов напрямую. Служба ставит их перед подъёмом сервера —
# только если таблицы ещё нет (при перезапуске службы действуют настоящие правила панели). Ошибка не
# мешает запуску сервера: «-» и exit 0.
HOLD_NAME = "awgr-hold-{iface}.nft"
UNIT_TEXT = f"""[Unit]
Description=AmneziaWG via awg-quick for %I (AWG Router)
After=network-online.target nss-lookup.target
Wants=network-online.target nss-lookup.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/bin/sh -c 'f={config.HOST_AWG_DIR}/{HOLD_NAME.format(iface="%i")}; [ -f "$$f" ] && command -v nft >/dev/null && ! nft list table ip {config.NFT_TABLE} >/dev/null 2>&1 && nft -f "$$f"; exit 0'
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


def docker_api(method: str, path: str, timeout: int = 10, body: dict | bytes | None = None):
    """Запрос к Docker. body: dict — JSON, bytes — архив tar (PUT …/archive)."""
    conn = _UnixHTTP(config.DOCKER_SOCK, timeout)
    try:
        if body is None:
            conn.request(method, path)
        elif isinstance(body, bytes):
            conn.request(method, path, body, {"Content-Type": "application/x-tar"})
        else:
            conn.request(method, path, json.dumps(body).encode(), {"Content-Type": "application/json"})
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


def docker_events(fn) -> None:
    """Поток событий запуска контейнеров (GET /events): fn(имя контейнера) на каждое. Возвращается, когда
    Docker закрыл соединение (перезапуск Docker); ждёт без предела времени — вызывать в своём потоке."""
    flt = urllib.parse.quote(json.dumps({"type": ["container"], "event": ["start", "restart"]}))
    conn = _UnixHTTP(config.DOCKER_SOCK, None)
    try:
        conn.request("GET", f"/events?filters={flt}")
        r = conn.getresponse()
        if r.status != 200:
            raise SysError(f"Docker API /events: HTTP {r.status}")
        while True:
            line = r.readline(65536)
            if not line:
                return
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            name = ((ev.get("Actor") or {}).get("Attributes") or {}).get("name")
            if isinstance(name, str):
                fn(name)
    finally:
        conn.close()


def docker_containers() -> list[str]:
    try:
        cs = docker_get("/containers/json") or []
    except OSError:
        return []
    return [n.lstrip("/") for c in cs for n in c.get("Names", [])]


def cmd_label(cmd: list[str]) -> str:
    """Команда для текста ошибки, как её понял бы человек: без обёртки `nsenter … --` и без путей
    (это временные файлы панели в её контейнере — на хосте их нет, искать там нечего)."""
    if cmd and cmd[0] == "nsenter" and "--" in cmd:
        cmd = cmd[cmd.index("--") + 1:]
    return " ".join(a for a in cmd[:6] if not a.startswith("/"))


def run(cmd: list[str], *, input: str | None = None, timeout: int = 30,
        check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, input=input, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise SysError(f"{cmd_label(cmd)}: {(p.stderr or p.stdout).strip()[:400]}")
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


def parse_all_dump(text: str) -> dict[str, dict]:
    """`awg show all dump` → {интерфейс: пиры, как у _parse_dump}. Первое поле каждой строки — имя
    интерфейса; первая строка интерфейса — его собственная (у AmneziaWG в ней ещё и Jc, S1–S4, H1–H4…,
    поэтому строки различаются по порядку, а не по числу полей), дальше — его пиры."""
    out: dict[str, dict] = {}
    for line in text.strip().split("\n"):
        f = line.split("\t")
        if len(f) < 2:
            continue
        if f[0] not in out:                 # первая строка интерфейса — его ключи и порт
            out[f[0]] = {}
            continue
        if len(f) < 9:
            continue
        _, pk, _psk, endpoint, allowed, hs, rx, tx = f[:8]
        try:
            out[f[0]][pk] = {"endpoint": None if endpoint == "(none)" else endpoint, "allowed_ips": allowed,
                             "handshake": int(hs or 0), "rx": int(rx or 0), "tx": int(tx or 0)}
        except ValueError:
            continue
    return out


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

    def conf_path_for(self, iface: str) -> str:
        """Путь к конфигу указанного серверного интерфейса."""
        return self.conf_path if iface == self.iface else f"{self.dir}/{iface}.conf"

    def clients_table_for(self, iface: str) -> str:
        """Путь к clientsTable указанного серверного интерфейса."""
        return self.clients_table_path if iface == self.iface else f"{self.dir}/{iface}.clientsTable"

    def wg_exists(self) -> bool:
        """Есть ли параллельный классический интерфейс wg0 (конфиг на диске)."""
        return self.iface != "wg0" and os.path.exists(self.host_path(self.conf_path_for("wg0")))

    def server_ifaces(self) -> list[str]:
        """Активные интерфейсы WireGuard сервера: основной (self.iface) и классический wg0, если включён."""
        return [self.iface, "wg0"] if self.wg_exists() and self.iface != "wg0" else [self.iface]

    def host_path(self, p: str) -> str:
        return f"/proc/{self.pid}/root{p}"

    # наши бинарники в сети цели
    def ns(self, cmd: list[str], **kw) -> subprocess.CompletedProcess:
        return run(["nsenter", "-t", str(self.pid), "-n", "--"] + cmd, **kw)

    # бинарники и сокеты самой цели
    def native(self, cmd: list[str], **kw) -> subprocess.CompletedProcess:
        raise NotImplementedError


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
            f.flush()
            os.fsync(f.fileno())        # конфиг сервера с клиентами: после сбоя питания не должен оказаться пустым
        os.replace(tmp, hp)

    # ------------------------------------------------------------- сервер
    @property
    def awg_bin(self) -> str:
        return "awg"

    def dump(self) -> dict:
        return self.dump_iface(self.iface)

    def dump_iface(self, iface: str) -> dict[str, dict]:
        """Считать активных пиров указанного серверного интерфейса."""
        errors = []
        for b in dict.fromkeys([self.awg_bin, "awg", "wg"]):
            try:
                return _parse_dump(self.native([b, "show", iface, "dump"], timeout=10).stdout)
            except Exception as e:  # noqa: BLE001
                errors.append(str(e))
        raise SysError("awg show: " + " | ".join(errors)[:300])

    def sync(self, sc: awgserver.ServerConf) -> None:
        """Применить пиры и параметры без перезапуска интерфейса."""
        self.sync_iface(self.iface, sc)

    def sync_iface(self, iface: str, sc: awgserver.ServerConf) -> None:
        """Применить пиры и параметры указанного интерфейса без перезапуска."""
        tmp = self.sync_tmp
        self.write_file(tmp, sc.stripped())
        try:
            if iface == "wg0":
                errors = []
                for b in dict.fromkeys([self.awg_bin, "awg", "wg"]):
                    try:
                        self.native([b, "syncconf", iface, tmp], timeout=20)
                        return
                    except Exception as e:  # noqa: BLE001
                        errors.append(str(e))
                raise SysError("awg syncconf: " + " | ".join(errors)[:300])
            self.native([self.awg_bin, "syncconf", iface, tmp], timeout=20)
        finally:
            try:
                os.remove(self.host_path(tmp))
            except OSError:
                pass

    def _wg_genkey(self) -> str:
        return local_awg(["genkey"])

    def _write_wg_files(self, port: int, subnet: str) -> None:
        priv = self._wg_genkey()
        sc = awgserver.new_wg_server(priv, port, subnet, wan_masq=(self.kind == "host"))
        self.write_file(self.conf_path_for("wg0"), sc.render())
        self.write_file(self.clients_table_for("wg0"), "[]")

    def _remove_wg_files(self) -> None:
        for p in (self.conf_path_for("wg0"), self.clients_table_for("wg0")):
            try:
                os.remove(self.host_path(p))
            except FileNotFoundError:
                pass

    def enable_wg(self, port: int, subnet: str) -> None:
        """Создать и поднять параллельный классический интерфейс wg0."""
        raise NotImplementedError

    def disable_wg(self) -> None:
        """Остановить и удалить параллельный классический интерфейс wg0."""
        raise NotImplementedError

    sync_tmp = "/tmp/awgr-sync.conf"

    def is_up(self) -> bool:
        """Есть ли интерфейс сервера в его сети (контейнер мог остаться без awg0, если упал amneziawg-go)."""
        return self.ns(["ip", "link", "show", self.iface], check=False).returncode == 0

    def restart(self) -> None:
        raise NotImplementedError

    def change_port(self, old_port: int, new_port: int, old_conf: str | None) -> None:
        """Запустить сервер на новом порту (ListenPort в конфиге уже новый). На хосте хватает перезапуска."""
        self.restart()

    def stop(self) -> None:
        """Остановить сервер (интерфейс убран) — между stop и start выгружается модуль ядра."""
        raise NotImplementedError

    def start(self) -> None:
        raise NotImplementedError

    def psk_for_new_client(self) -> str:
        return local_awg(["genpsk"])


class ContainerTarget(Target):
    kind = "container"

    def native(self, cmd, **kw):
        return run(["nsenter", "-t", str(self.pid), "-m", "-n", "--"] + cmd, **kw)


    @property
    def awg_bin(self) -> str:
        return "wg" if self.iface == "wg0" else "awg"

    def restart(self) -> None:
        docker_api("POST", f"/containers/{urllib.parse.quote(self.name)}/restart?t=3", timeout=40)

    def stop(self) -> None:
        docker_api("POST", f"/containers/{urllib.parse.quote(self.name)}/stop?t=3", timeout=40)

    def start(self) -> None:
        docker_api("POST", f"/containers/{urllib.parse.quote(self.name)}/start", timeout=40)

    def change_port(self, old_port: int, new_port: int, old_conf: str | None) -> None:
        """Порт контейнера задан Docker'ом при создании: контейнер пересоздаётся с тем же содержимым и новым
        портом (recreate_with_port). Не поднялся — прежний контейнер обратно, с прежним конфигом."""
        recreate_with_port(self.name, self.dir, self.iface, old_port, new_port, old_conf)

    def psk_for_new_client(self) -> str:
        # приложение AmneziaVPN использует один общий PSK на всех клиентов
        psk = (self.read_file(f"{self.dir}/wireguard_psk.key") or "").strip()
        return psk if awgserver.KEY_RE.match(psk) else local_awg(["genpsk"])

    def enable_wg(self, port: int, subnet: str) -> None:
        self._write_wg_files(port, subnet)
        try:
            self.native(["awg-quick", "up", self.conf_path_for("wg0")], timeout=60)
        except Exception:
            self._remove_wg_files()
            raise

    def disable_wg(self) -> None:
        self.native(["awg-quick", "down", self.conf_path_for("wg0")], check=False, timeout=30)
        self._remove_wg_files()


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

    def _unit(self) -> str | None:
        unit = f"awg-quick@{self.iface}"
        return unit if self.native(["systemctl", "cat", unit], check=False).returncode == 0 else None

    def stop(self) -> None:
        unit = self._unit()
        if unit:
            self.native(["systemctl", "stop", unit], timeout=60)
        else:
            self.native(["awg-quick", "down", self.iface], check=False, timeout=30)

    def start(self) -> None:
        unit = self._unit()
        if unit:
            self.native(["systemctl", "start", unit], timeout=60)
        else:
            self.native(["awg-quick", "up", self.iface], timeout=60)

    def enable_wg(self, port: int, subnet: str) -> None:
        self._write_wg_files(port, subnet)
        try:
            unit = "awg-quick@wg0"
            if self.native(["systemctl", "cat", unit], check=False).returncode == 0:
                self.native(["systemctl", "enable", "--now", unit], timeout=60)
            else:
                self.native(["awg-quick", "up", "wg0"], timeout=60)
            open_firewall_udp(self, port)
        except Exception:
            self._remove_wg_files()
            raise

    def disable_wg(self) -> None:
        unit = "awg-quick@wg0"
        if self.native(["systemctl", "cat", unit], check=False).returncode == 0:
            self.native(["systemctl", "disable", "--now", unit], check=False, timeout=60)
        else:
            self.native(["awg-quick", "down", "wg0"], check=False, timeout=30)
        self._remove_wg_files()


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


# ------------------------------------------------- смена порта контейнера
PORT_IMAGE = "awg-router-port"       # образы, снятые с контейнера без папки сервера на диске хоста (AmneziaVPN)
PORT_UP_SECS = 15                    # сколько ждать интерфейс сервера в новом контейнере


def recreate_body(info: dict, image: str, old_port: int, new_port: int) -> dict:
    """Тело POST /containers/create: тот же контейнер (настройки из docker inspect), порт old_port/udp
    заменён на new_port. Сети, кроме первой, подключаются после создания (extra_networks)."""
    cfg = dict(info.get("Config") or {})
    host = dict(info.get("HostConfig") or {})
    short = str(info.get("Id") or "")[:12]
    if short and cfg.get("Hostname") == short:          # имя машины по Id — у нового контейнера своё
        cfg.pop("Hostname", None)
    cfg["Image"] = image
    old_key, new_key = f"{old_port}/udp", f"{new_port}/udp"
    exposed = {k: v for k, v in (cfg.get("ExposedPorts") or {}).items() if k != old_key}
    exposed[new_key] = {}
    cfg["ExposedPorts"] = exposed
    binds = {}
    for k, v in (host.get("PortBindings") or {}).items():
        if k == old_key:
            binds[new_key] = [{**b, "HostPort": str(new_port)} for b in (v or [{}])]
        else:
            binds[k] = v
    if new_key not in binds:
        binds[new_key] = [{"HostIp": "", "HostPort": str(new_port)}]
    host["PortBindings"] = binds
    # безымянные тома (VOLUME образа) не записаны в Binds: без них новый контейнер получил бы пустые
    vols = list(host.get("Binds") or [])
    taken = {b.split(":")[1] for b in vols if b.count(":") >= 1} | {m.get("Target") for m in host.get("Mounts") or []}
    for m in info.get("Mounts") or []:
        if m.get("Type") == "volume" and m.get("Name") and m.get("Destination") not in taken:
            vols.append(f"{m['Name']}:{m['Destination']}")
    if vols:
        host["Binds"] = vols
    cfg["HostConfig"] = host
    nets = ((info.get("NetworkSettings") or {}).get("Networks") or {})
    first = host.get("NetworkMode")
    if first in nets:
        cfg["NetworkingConfig"] = {"EndpointsConfig": {first: _endpoint(nets[first], short)}}
    return cfg


def extra_networks(info: dict) -> dict:
    """Сети контейнера, кроме основной (NetworkMode): старый Docker создаёт контейнер только с одной."""
    nets = ((info.get("NetworkSettings") or {}).get("Networks") or {})
    first = (info.get("HostConfig") or {}).get("NetworkMode")
    short = str(info.get("Id") or "")[:12]
    return {n: _endpoint(ep, short) for n, ep in nets.items() if n != first}


def _endpoint(ep: dict, short: str) -> dict:
    out = {}
    if ep.get("IPAMConfig"):
        out["IPAMConfig"] = ep["IPAMConfig"]
    aliases = [a for a in (ep.get("Aliases") or []) if a != short]
    if aliases:
        out["Aliases"] = aliases
    return out


def _tar_one(name: str, text: str) -> bytes:
    import io
    import tarfile
    data = text.encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo(name)
        ti.size, ti.mode, ti.mtime = len(data), 0o600, int(time.time())
        tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def recreate_with_port(name: str, conf_dir: str, iface: str, old_port: int, new_port: int,
                       old_conf: str | None) -> None:
    """Пересоздаёт контейнер сервера с новым портом UDP, сохраняя всё содержимое: ключи, клиентов,
    clientsTable приложения AmneziaVPN. Папка сервера на диске хоста (свой контейнер панели) переходит в
    новый контейнер как есть; иначе с остановленного контейнера снимается образ (docker commit). Прежний
    контейнер удаляется, только когда в новом поднялся интерфейс; иначе он возвращается с прежним конфигом
    (old_conf) и ошибкой srv.port_failed."""
    q = urllib.parse.quote
    info = docker_get(f"/containers/{q(name)}/json")
    if not info:
        raise SysError(Msg("sys.container_missing", name=name))
    policy = (info.get("HostConfig") or {}).get("RestartPolicy") or {"Name": "always"}
    on_disk = any(m.get("Destination") == conf_dir for m in info.get("Mounts") or [])
    old = f"{name}-old-{_stamp()}"
    renamed, made = False, None
    # конфиг с новым портом уже записан: оборвись смена посреди — recover_renamed вернёт прежнему контейнеру и его конфиг
    _port_mark({"old": old, "dir": conf_dir, "iface": iface, "conf": old_conf})
    try:
        docker_api("POST", f"/containers/{q(name)}/update", body={"RestartPolicy": {"Name": "no"}})
        docker_api("POST", f"/containers/{q(name)}/stop?t=3", timeout=40)     # освобождает порт
        docker_api("POST", f"/containers/{q(name)}/rename?name={q(old)}")
        renamed = True
        image = info.get("Image")
        if not on_disk:
            tag = _stamp()
            docker_api("POST", f"/commit?container={q(old)}&repo={PORT_IMAGE}&tag={tag}&pause=false", timeout=120)
            image = f"{PORT_IMAGE}:{tag}"
        made = (docker_api("POST", f"/containers/create?name={q(name)}",
                           body=recreate_body(info, image, old_port, new_port)) or {}).get("Id")
        for net, ep in extra_networks(info).items():
            docker_api("POST", f"/networks/{q(net)}/connect", body={"Container": made, "EndpointConfig": ep})
        docker_api("POST", f"/containers/{q(name)}/start", timeout=40)
        if not _wait_iface(name, iface):
            raise SysError(f"{iface} did not come up in {PORT_UP_SECS} s")
    except Exception as e:
        log.warning("new port %s for %s: %s — the old container comes back", new_port, name, e)
        # каждый шаг возврата — даже если прошлый не удался: прежний контейнер должен запуститься
        cur = old if renamed else name
        if made:
            _quiet("DELETE", f"/containers/{made}?force=1", timeout=40)
        if old_conf is not None:
            _quiet("PUT", f"/containers/{q(cur)}/archive?path={q(conf_dir)}",
                   body=_tar_one(f"{iface}.conf", old_conf), timeout=30)
        if renamed:
            _quiet("POST", f"/containers/{q(old)}/rename?name={q(name)}")
        _quiet("POST", f"/containers/{q(name)}/update", body={"RestartPolicy": policy})
        _quiet("POST", f"/containers/{q(name)}/restart?t=3", timeout=40)
        _port_mark(None)
        raise SysError(f"new port {new_port}: {e}") from None
    _port_mark(None)
    _quiet("DELETE", f"/containers/{q(old)}?force=1", timeout=40)
    prev = (info.get("Config") or {}).get("Image") or ""
    if not on_disk and prev.startswith(PORT_IMAGE + ":"):
        _quiet("DELETE", f"/images/{q(prev)}", timeout=40)   # образ прошлой смены порта больше не нужен


def _stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _port_mark_path() -> str:
    return os.path.join(config.DATA_DIR, "port-change.json")


def _port_mark(mark: dict | None) -> None:
    """Идущая смена порта контейнера (data/port-change.json): имя прежнего контейнера и его конфиг (в нём ключ сервера —
    как и state.json, только для root). None — смена закончилась."""
    p = _port_mark_path()
    try:
        if mark is None:
            if os.path.exists(p):
                os.remove(p)
            return
        fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(mark, f)
        os.replace(p + ".tmp", p)
    except OSError as e:
        log.warning("port change mark: %s", e)


def _port_mark_done(name: str) -> None:
    """Контейнер сервера с обычным именем работает — смена его порта закончилась (или панель упала уже после неё):
    отметка больше не нужна. Иначе, пропади он потом, recover_renamed вернул бы давний «-old-» со старым конфигом —
    а у своего контейнера папка сервера общая, и в неё лёг бы прежний список клиентов."""
    m = _RENAMED.fullmatch(str(_port_mark_get().get("old") or ""))
    if m and m.group(1) == name:
        _port_mark(None)


def _port_mark_get() -> dict:
    try:
        with open(_port_mark_path()) as f:
            m = json.load(f)
        return m if isinstance(m, dict) else {}
    except (OSError, ValueError):
        return {}


def _quiet(method: str, path: str, **kw) -> None:
    try:
        docker_api(method, path, **kw)
    except (SysError, OSError) as e:
        log.warning("%s %s: %s", method, path, e)


def _wait_iface(name: str, iface: str) -> bool:
    end = time.monotonic() + PORT_UP_SECS
    while time.monotonic() < end:
        time.sleep(1)
        try:
            pid = int(((docker_get(f"/containers/{urllib.parse.quote(name)}/json") or {}).get("State") or {})
                      .get("Pid") or 0)
            if pid and run(["nsenter", "-t", str(pid), "-n", "--", "ip", "link", "show", iface],
                           check=False, timeout=5).returncode == 0:
                return True
        except (SysError, OSError, subprocess.SubprocessError):
            pass
    return False


# Смена порта (`<имя>-old-<время>`, recreate_with_port) и обновление своего контейнера установщиком
# (`<имя>-prev-<время>`, refresh_own_server) на секунды выключают сервер, отключают ему автозапуск и переименовывают.
# Прервались посреди (панель упала, VPS выключился, оборвался SSH) — VPN не работал бы, пока контейнер не вернут
# руками. Возврат — только если контейнера с обычным именем нет, установщик не работает и прежний остановлен дольше
# RECOVER_AFTER (идущую замену так не спутать с прерванной).
RECOVER_AFTER = 60
_RENAMED = re.compile(r"(amnezia-awg2?)-(?:old|prev)-\d{8}-\d{6}")
recovered: list[str] = []          # что вернули (движок пишет это в журнал событий)


def _docker_time(s) -> float:
    """Время Docker («2026-11-19T04:58:02.123456789Z», UTC) → секунды; пусто или непонятно — 0 (давно)."""
    import calendar
    try:
        return float(calendar.timegm(time.strptime(str(s)[:19], "%Y-%m-%dT%H:%M:%S")))
    except (ValueError, OverflowError):
        return 0.0


def recover_renamed() -> str | None:
    """Контейнер сервера, оставшийся переименованным после прерванной смены порта или обновления: вернуть ему
    имя и автозапуск и запустить. Смена порта, прерванная ещё до переименования, оставляет контейнер с обычным
    именем выключенным и без автозапуска — его тоже. → имя или None."""
    if config.AWG_MODE != "container" or config.AWG_CONTAINER:
        return None
    try:
        cs = docker_get("/containers/json?all=1") or []
    except (SysError, OSError):
        return None
    names = {n.lstrip("/") for c in cs for n in c.get("Names", [])}
    from . import selfupdate          # selfupdate импортирует system: здесь — при вызове
    if selfupdate.installer_running():
        return None                                  # установщик сам вернёт прежний контейнер, если надо
    # «-old-» — только тот, что оставила прерванная смена порта панели (port-change.json): такой же оставляет и
    # установщик, ставя новый сервер вместо неисправного, — нарочно, его не возвращаем
    mark = _port_mark_get()
    mf = _RENAMED.fullmatch(str(mark.get("old") or ""))
    cands = sorted((n for n in names if _RENAMED.fullmatch(n) and ("-prev-" in n or n == mark.get("old"))),
                   key=lambda n: n[-15:])
    if cands:
        old = cands[-1]
        name = _RENAMED.fullmatch(old).group(1)
        if name in names:
            return None                              # контейнер с обычным именем есть (пусть и выключен)
    elif mf and mf.group(1) in names and mark["old"] not in names:
        old = name = mf.group(1)                     # смену прервали до переименования
    else:
        return None
    by_mark = old == mark.get("old") or (old == name and bool(mf))
    q = urllib.parse.quote
    try:
        info = docker_get(f"/containers/{q(old)}/json") or {}
        st = info.get("State") or {}
        if st.get("Running") or time.time() - _docker_time(st.get("FinishedAt")) < RECOVER_AFTER:
            return None
        if old == name and ((info.get("HostConfig") or {}).get("RestartPolicy") or {}).get("Name") != "no":
            return None                              # выключен руками, а не сменой порта: автозапуск у него остался
        if by_mark and isinstance(mark.get("conf"), str) and mark.get("dir") and mark.get("iface"):
            # в нём уже конфиг с новым портом, а Docker открывает прежний: без возврата конфига VPN бы не заработал
            docker_api("PUT", f"/containers/{q(old)}/archive?path={q(mark['dir'])}",
                       body=_tar_one(f"{mark['iface']}.conf", mark["conf"]), timeout=30)
        if old != name:
            docker_api("POST", f"/containers/{q(old)}/rename?name={q(name)}")
        docker_api("POST", f"/containers/{q(name)}/update", body={"RestartPolicy": {"Name": "always"}})
        docker_api("POST", f"/containers/{q(name)}/start", timeout=40)
    except (SysError, OSError) as e:
        log.warning("container %s left off, could not bring it back: %s", old, e)
        return None
    log.warning("container %s was left off by an interrupted port change or update: brought back as %s and started",
                old, name)
    if by_mark:
        _port_mark(None)
    recovered.append(name)
    return name


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
        name = find_amnezia_container() or recover_renamed()
        if name:
            _port_mark_done(name)
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


def _firewall_port(t: Target, port: int, proto: str, allow: bool = True) -> None:
    """Если на хосте включён ufw — открыть или закрыть порт (udp или tcp)."""
    try:
        p = t.native(["ufw", "status"], check=False)
    except OSError:
        return
    if p and p.returncode == 0 and "Status: active" in p.stdout:
        cmd = ["ufw", "allow", f"{int(port)}/{proto}"] if allow else ["ufw", "delete", "allow", f"{int(port)}/{proto}"]
        t.native(cmd, check=False)


def open_firewall_udp(t: HostTarget, port: int) -> None:
    """Если на хосте включён ufw — открыть UDP-порт сервера."""
    _firewall_port(t, port, "udp", allow=True)


def open_firewall_tcp(t: Target, port: int) -> None:
    """Если на хосте включён ufw — открыть TCP-порт."""
    _firewall_port(t, port, "tcp", allow=True)


def close_firewall_tcp(t: Target, port: int) -> None:
    """Если на хосте включён ufw — закрыть TCP-порт."""
    _firewall_port(t, port, "tcp", allow=False)


# Порты, на которые не попадает случайный порт AmneziaWG: другие VPN, VoIP, STUN, обнаружение в
# локальной сети — их часто режут операторы и DPI. Тот же список — AWG_AVOID в install.sh (тест
# PortsTest); вручную такой порт выбрать можно.
AWG_AVOID = frozenset({1080, 1194, 1701, 1723, 1812, 1813, 1900, 3478, 3479, 4500, 5060, 5061, 5353, 5355})
# UDP 53 в сети сервера AWG занимает DNS на сервере (dnsproxy.py на адресе сервера в туннеле)
AWG_RESERVED = frozenset({53})


def random_udp_port() -> int:
    """Случайный четырёхзначный порт для нового сервера AWG: высокие порты некоторые мобильные
    операторы режут."""
    return random.choice([p for p in range(1000, 10000) if p not in AWG_AVOID and p not in AWG_RESERVED])


# ======================================================================= демо
class DemoTarget(Target):
    """DRY_RUN: настоящие файлы в data/demo-root, команды не выполняются."""
    kind = "demo"

    def __init__(self):
        super().__init__("amnezia-awg2 (demo)", 4242, "awg0", "/opt/amnezia/awg/awg0.conf", "demo")
        self.root = os.path.join(config.DATA_DIR, "demo-root")
        self.log: list[str] = []
        self.handshakes: dict[str, float] = {}
        self.born = time.time()
        self._seed()

    def host_path(self, p: str) -> str:
        return self.root + p

    def _cmd(self, cmd):
        self.log.append(" ".join(cmd))
        self.log[:] = self.log[-200:]
        out = ""
        if cmd[:2] == ["nft", "list"]:
            out = "table ip awgr {}"
        if cmd[:3] == ["nft", "-j", "list"] and cmd[-1] == nftgen.ACCT_TABLE:
            out = self._acct_dump()
        if cmd[:1] == ["ip"] and "-j" in cmd:
            out = "[]"
        if len(cmd) > 3 and cmd[1] == "show" and cmd[-1] == "dump":
            if cmd[2] in (self.iface, "wg0"):
                out = self._server_dump(cmd[2])
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


    def restart(self) -> None:
        self.log.append("docker restart amnezia-awg2")

    def stop(self) -> None:
        self.log.append("docker stop amnezia-awg2")

    def start(self) -> None:
        self.log.append("docker start amnezia-awg2")

    def change_port(self, old_port: int, new_port: int, old_conf: str | None) -> None:
        self.log.append(f"recreate amnezia-awg2 with port {new_port}/udp")

    def psk_for_new_client(self) -> str:
        return (self.read_file(f"{self.dir}/wireguard_psk.key") or "").strip()

    def _wg_genkey(self) -> str:
        return base64.b64encode(secrets.token_bytes(32)).decode()

    def enable_wg(self, port: int, subnet: str) -> None:
        self._write_wg_files(port, subnet)
        self.log.append(f"wg0 up ({port}, {subnet})")

    def disable_wg(self) -> None:
        self._remove_wg_files()
        self.log.append("wg0 down")

    def _server_dump(self, iface: str | None = None) -> str:
        sc = awgserver.parse(self.read_file(self.conf_path_for(iface or self.iface)) or "")
        now = time.time()
        grow = int(now - self.born)
        lines = ["priv\tpub\t47823\toff"]
        for i, p in enumerate(sc.peers):
            if not p.enabled:
                continue
            age = [40, 300, 15, 4000, 86400 * 3, 0, 25, 9][i % 8]
            hs = int(now - age) if age else 0
            lines.append(f"{p.public_key}\t{p.psk or '(none)'}\t198.51.100.{20 + i}:{40000 + i}\t"
                         f"{p.allowed_ips}\t{hs}\t{(i + 1) * 98_304_000 + grow * 40_000 * (i + 1)}\t"
                         f"{(i + 1) * 734_003_200 + grow * 300_000 * (i + 1)}\t0")
        return "\n".join(lines) + "\n"

    def _acct_dump(self) -> str:
        """Таблица учёта трафика по выходам: у каждого клиента часть трафика идёт напрямую,
        часть через выходы 1 и 2 (если такие добавлены в демо)."""
        sc = awgserver.parse(self.read_file(self.conf_path) or "")
        grow = int(time.time() - self.born)
        items = [{"rule": {"family": "ip", "table": nftgen.ACCT_TABLE, "chain": "c_acct",
                           "comment": nftgen.acct_marker(self.iface)}}]
        sets = {"up": [], "down": []}
        for i, p in enumerate(sc.peers):
            if not p.enabled:
                continue
            ip = p.allowed_ips.split("/")[0]
            for ifn, share in (("eth0", 5), ("awgr1", 3), ("awgr2", 1)):
                base = (i + 1) * share
                for name, rate in (("up", 4_000), ("down", 30_000)):
                    b = base * grow * rate
                    sets[name].append({"elem": {"val": {"concat": [ip, ifn]},
                                                "counter": {"packets": b // 900, "bytes": b}}})
        for name, elems in sets.items():
            items.append({"set": {"family": "ip", "name": name, "table": nftgen.ACCT_TABLE,
                                  "type": ["ipv4_addr", "ifname"], "elem": elems}})
        return json.dumps({"nftables": items})

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


FakeTarget = DemoTarget
