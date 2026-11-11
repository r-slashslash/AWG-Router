"""Параметры и управление strongSwan для выходов IKEv2 с парольной аутентификацией."""
from __future__ import annotations

import base64
import ipaddress
import logging
import os
import re
import shutil
import ssl
import subprocess
import time

from .i18n import Msg, MsgError

# Такой MTU оставляет место для ESP и UDP-инкапсуляции на обычных сетевых путях.
DEFAULT_MTU = 1280
# Отдельный диапазон не пересекается с обычными малыми ID сторонних IPsec-подключений.
XFRM_ID_BASE = 0x41570000
# Внешние IKE/ESP-пакеты не должны снова попадать в таблицу своего туннеля.
OUTER_MARK = 0x40000000
log = logging.getLogger("awgr.ikev2")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")


class Ikev2Error(MsgError, ValueError):
    """Ошибки реквизитов передаются интерфейсу без содержимого секретных полей."""


def normalize(fields: dict) -> dict:
    """Проверка на границе не позволяет передавать произвольный конфиг демону IPsec."""
    result = {key: fields.get(key, "") for key in ("host", "remote_id", "local_id", "user", "password", "ca")}
    for key, value in result.items():
        if not isinstance(value, str) or len(value) > (65536 if key == "ca" else 1024):
            raise Ikev2Error(Msg("ike.invalid", field=key))
        if key != "ca" and any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise Ikev2Error(Msg("ike.invalid", field=key))
    host = result["host"].strip()
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        if not _HOSTNAME.fullmatch(host):
            raise Ikev2Error(Msg("ike.invalid", field="host")) from None
        host = host.lower()
    result["host"] = host
    result["remote_id"] = result["remote_id"].strip() or host
    # Специальные значения strongSwan отключили бы привязку сертификата к серверу.
    if result["remote_id"].startswith("%") or "*" in result["remote_id"] or not result["user"] or not result["password"]:
        raise Ikev2Error(Msg("ike.invalid", field="remote_id / user / password"))
    result["ca"] = result["ca"].strip()
    if result["ca"]:
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=result["ca"])
        except (ssl.SSLError, TypeError, ValueError):
            raise Ikev2Error(Msg("ike.invalid", field="ca")) from None
    mtu_value = fields.get("mtu", DEFAULT_MTU)
    try:
        mtu = int(mtu_value)
    except (OverflowError, TypeError, ValueError):
        raise Ikev2Error(Msg("ike.invalid", field="mtu")) from None
    if not 1100 <= mtu <= 1500 or isinstance(mtu_value, float) and mtu_value != mtu:
        raise Ikev2Error(Msg("ike.invalid", field="mtu"))
    return {"kind": "ikev2", **result, "mtu": mtu}


def _quoted(value: str) -> str:
    """Экранирование сохраняет секрет как значение, исключая вставку секций strongSwan."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def connection_config(fields: dict, name: str, server_ip: str, ca_file: str = "") -> str:
    """Только выбранный XFRM-интерфейс получает политики, остальные маршруты не меняются."""
    num = XFRM_ID_BASE + int(re.search(r"\d+$", name).group())
    ca = f"            cacerts = {_quoted(ca_file)}\n" if ca_file else ""
    # strongSwan декодирует 0x/0s даже внутри кавычек. Явное Base64 сохраняет
    # буквальный пароль с любым префиксом, пробелами и синтаксическими символами.
    secret = "0s" + base64.b64encode(fields["password"].encode()).decode("ascii")
    return f"""connections {{
    {name} {{
        version = 2
        remote_addrs = {_quoted(server_ip)}
        vips = 0.0.0.0
        mobike = no
        dpd_delay = 30s
        local {{
            auth = eap-mschapv2
            id = {_quoted(fields['local_id'] or fields['user'])}
            eap_id = {_quoted(fields['user'])}
        }}
        remote {{
            auth = pubkey
            id = {_quoted(fields['remote_id'])}
{ca}        }}
        children {{
            net {{
                local_ts = dynamic
                remote_ts = 0.0.0.0/0
                if_id_in = {num}
                if_id_out = {num}
                reqid = {num}
                set_mark_out = {OUTER_MARK:#x}/0xffffffff
                start_action = start
                dpd_action = restart
                close_action = restart
            }}
        }}
    }}
}}
secrets {{
    eap-user {{
        id = {_quoted(fields['user'])}
        secret = {secret}
    }}
}}
"""


def daemon_config(socket_path: str) -> str:
    """Разрешённые плагины исключают изменение DNS, маршрутов и чужих управляющих сокетов."""
    plugins = "random nonce kdf x509 revocation constraints pubkey pem openssl gmp curve25519 kernel-netlink socket-default vici eap-identity eap-mschapv2"
    return f"""charon {{
    load_modular = no
    load = {plugins}
    port = 0
    port_nat_t = 0
    install_routes = no
    install_virtual_ip = no
    plugins {{
        socket-default {{
            fwmark = {OUTER_MARK:#x}
        }}
        vici {{
            socket = unix://{socket_path}
        }}
    }}
    filelog {{
        stderr {{
            default = 0
            flush_line = yes
        }}
    }}
}}
"""


def _private_file(path: str, content: str) -> None:
    """Пароли и управляющие настройки доступны только владельцу процесса панели."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(content)


class Runtime:
    """Отдельный демон на выход изолирует пароли даже при одинаковом имени пользователя."""

    def __init__(self, root: str, name: str):
        """Каталог принадлежит одному выходу и не разделяется с другими демонами."""
        self.root = root
        self.name = name
        self.socket = os.path.join(root, "vici.sock")
        self.proc: subprocess.Popen | None = None
        self.target_pid: int | None = None
        self.prepared = False        # право удалять каталог возникает только после проверки владельца

    def command(self, *args: str, timeout: int = 10) -> subprocess.CompletedProcess:
        """Управляющий сокет выбирается явно, чтобы не обратиться к чужому IPsec."""
        return subprocess.run(["swanctl", *args, "--uri", "unix://" + self.socket],
                              capture_output=True, text=True, timeout=timeout)

    def check_owner(self) -> None:
        """Проверка до изменения сети сохраняет интерфейс и файлы действующего владельца."""
        if os.path.islink(self.root):
            raise Ikev2Error(Msg("ike.start_failed"))
        if os.path.isdir(self.root):
            alive = False
            try:
                with open(os.path.join(self.root, "charon.pid")) as pidfile:
                    pid = int(pidfile.read().strip())
                with open(f"/proc/{pid}/environ", "rb") as environ:
                    alive = b"STRONGSWAN_CONF=" + os.fsencode(os.path.join(self.root, "strongswan.conf")) in environ.read().split(b"\0")
            except FileNotFoundError:
                pass
            except (OSError, ValueError) as exc:
                raise Ikev2Error(Msg("ike.start_failed")) from exc
            if alive:
                raise Ikev2Error(Msg("ike.already_running"))

    def _prepare(self, fields: dict, server_ip: str) -> tuple[str, str, str]:
        """Остатки аварийного запуска не должны подменять каталог доверенных сертификатов."""
        self.check_owner()
        if os.path.isdir(self.root):
            self._cleanup_ipsec()
            shutil.rmtree(self.root)
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        self.prepared = True
        os.chmod(self.root, 0o700)
        ca_dir = os.path.join(self.root, "x509ca")
        ca_file = ""
        if fields["ca"]:
            os.makedirs(ca_dir, mode=0o700, exist_ok=True)
            ca_file = os.path.join(ca_dir, "company.pem")
            _private_file(ca_file, fields["ca"])
        else:
            os.symlink("/etc/ssl/certs", ca_dir)
        conf = os.path.join(self.root, "swanctl.conf")
        _private_file(conf, connection_config(fields, self.name, server_ip, ca_file))
        daemon = os.path.join(self.root, "strongswan.conf")
        _private_file(daemon, daemon_config(self.socket))
        pid_file = os.path.join(self.root, "charon.pid")
        _private_file(pid_file, "0\n")
        return conf, daemon, pid_file

    def start(self, target, fields: dict, server_ip: str, log_path: str) -> None:
        """Приватный mount namespace разделяет фиксированный PID-файл charon между выходами."""
        self.target_pid = target.pid
        conf, daemon, pid_file = self._prepare(fields, server_ip)
        # Не трогаем содержимое общего PID-файла: в дочернем пространстве поверх него
        # монтируется собственный файл. Оба демона могут работать независимо.
        fd = os.open("/run/charon.pid", os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
        env = dict(os.environ, STRONGSWAN_CONF=daemon)
        launcher = 'mount --bind "$1" /run/charon.pid && exec /usr/lib/strongswan/charon'
        with open(log_path, "w") as logf:
            self.proc = subprocess.Popen(
                ["nsenter", "-t", str(target.pid), "-n", "--", "unshare", "--mount", "--propagation", "private",
                 "--", "sh", "-c", launcher, "sh", pid_file],
                stdout=logf, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        for _ in range(50):
            if os.path.exists(self.socket):
                break
            if self.proc.poll() is not None:
                raise Ikev2Error(Msg("ike.start_failed"))
            time.sleep(0.1)
        else:
            raise Ikev2Error(Msg("ike.start_failed"))
        # В выводе загрузки могут быть реквизиты, поэтому ошибка не включает stdout/stderr.
        result = self.command("--load-all", "--file", conf, timeout=20)
        if result.returncode:
            raise Ikev2Error(Msg("ike.load_failed"))
        os.remove(conf)

    def status(self) -> dict:
        """Наличие процесса не заменяет проверку установленной сессии IPsec."""
        result = self.command("--list-sas", "--ike", self.name, "--raw")
        if_id = XFRM_ID_BASE + int(re.search(r"\d+$", self.name).group())
        return parse_status(result.stdout if result.returncode == 0 else "", if_id)

    def close(self) -> None:
        """SIGTERM удаляет только SA собственного демона; после остановки удаляются секреты."""
        if not self.prepared:
            return
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        try:
            self._cleanup_ipsec()
        finally:
            self.target_pid = None
            self.prepared = False
            if os.path.isdir(self.root):
                shutil.rmtree(self.root)

    def _cleanup_ipsec(self) -> None:
        """При SIGKILL ядро сохраняет SA; чистим только свой диапазон reqid и if_id."""
        if self.target_pid is None:
            return
        prefix = ["nsenter", "-t", str(self.target_pid), "-n", "--", "ip", "xfrm"]
        result = subprocess.run(prefix + ["policy", "list"], capture_output=True, text=True, timeout=10)
        if result.returncode:
            return                  # исчезнувшее пространство сети не содержит живых объектов
        own_id = XFRM_ID_BASE + int(re.search(r"\d+$", self.name).group())
        for policy in re.split(r"(?m)(?=^src )", result.stdout):
            if not re.search(rf"\bif_id 0x{own_id:x}\b", policy) or not re.search(rf"\breqid {own_id}\b", policy):
                continue
            selector = re.search(r"^src (\S+) dst (\S+)", policy)
            direction = re.search(r"\bdir (in|out|fwd)\b", policy)
            if selector and direction:
                command = prefix + ["policy", "delete", "src", selector.group(1), "dst", selector.group(2),
                                    "dir", direction.group(1), "if_id", str(own_id)]
                deleted = subprocess.run(command, capture_output=True, text=True, timeout=10)
                if deleted.returncode:
                    log.warning("ikev2 policy cleanup failed exit=%s", self.name)
        result = subprocess.run(prefix + ["state", "deleteall", "reqid", str(own_id)], capture_output=True, text=True, timeout=10)
        if result.returncode:
            log.warning("ikev2 state cleanup failed exit=%s", self.name)


def parse_status(output: str, if_id: int) -> dict:
    """Состояния разных SA при обновлении ключей проверяются по отдельности."""
    for event in output.splitlines():
        if not event.startswith("list-sa event {") or not re.search(r"\bstate=ESTABLISHED\b", event):
            continue
        vip = re.search(r"\blocal-vips=\[([^\]]*)\]", event)
        addresses = []
        for value in vip.group(1).split() if vip else []:
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue
            if ip.version == 4:
                addresses.append(ip)
        for match in re.finditer(r"\{name=net\b([^{}]*)\}", event):
            child = match.group(1)
            if not re.search(r"\bstate=INSTALLED\b", child):
                continue
            if any(not re.search(rf"\bif-id-{direction}={if_id:08x}\b", child) for direction in ("in", "out")):
                continue
            selectors = re.search(r"\blocal-ts=\[([^\]]*)\]", child)
            for value in selectors.group(1).split() if selectors else []:
                try:
                    network = ipaddress.ip_network(value)
                except ValueError:
                    continue
                for address in addresses:
                    if address in network:
                        counters = {key: int(re.search(rf"\b{field}=(\d+)", child).group(1))
                                    if re.search(rf"\b{field}=(\d+)", child) else 0
                                    for key, field in (("rx", "bytes-in"), ("tx", "bytes-out"))}
                        return {"healthy": True, "address": str(address), **counters}
    return {"healthy": False, "address": "", "rx": 0, "tx": 0}
