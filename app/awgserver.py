"""Модель серверного конфига AmneziaWG: чтение/запись, параметры, клиентские конфиги.

Формат записи совместим с приложением AmneziaVPN:
  * разделитель « = » (приложение разбирает строки по нему);
  * I1–I5 на сервере хранятся закомментированными «# I1 = …» — это клиентские
    параметры, приложение читает их оттуда при повторном сканировании сервера;
  * отключённые панелью клиенты остаются в файле закомментированным блоком
    «# [Peer]», чтобы их адрес не занял никто другой.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import secrets
import struct
import time
import zlib
from dataclasses import dataclass, field

from .i18n import Msg, MsgError

QUICK_ONLY = {"address", "dns", "mtu", "table", "preup", "postup", "predown", "postdown",
              "saveconfig"}

# Параметры обфускации: ключ → (тип, сторона)
#   server — должен совпадать у сервера и клиентов
#   client — задаётся только клиенту (на сервере хранится для выдачи клиентам)
AWG_PARAMS: dict[str, tuple[str, str]] = {
    "Jc": ("int", "client"), "Jmin": ("int", "client"), "Jmax": ("int", "client"),
    "S1": ("int", "server"), "S2": ("int", "server"), "S3": ("int", "server"), "S4": ("int", "server"),
    "H1": ("hrange", "server"), "H2": ("hrange", "server"),
    "H3": ("hrange", "server"), "H4": ("hrange", "server"),
    "I1": ("text", "client"), "I2": ("text", "client"), "I3": ("text", "client"),
    "I4": ("text", "client"), "I5": ("text", "client"),
    "HeaderProtectionKey": ("key", "server"),
    "ContentPaddingAddition": ("range", "client"),
    "RekeyAfterTime": ("range", "client"), "RekeyTimeout": ("range", "client"),
    "RejectAfterTime": ("range", "client"), "KeepaliveTimeout": ("range", "client"),
    "MaxHandshakeAttempts": ("range", "client"),
    "RandomTrailers": ("bool", "client"), "DisableCookies": ("bool", "client"),
}
PARAM_ORDER = list(AWG_PARAMS)
I_KEYS = {"I1", "I2", "I3", "I4", "I5"}
_CANON = {k.lower(): k for k in list(AWG_PARAMS) + [
    "PrivateKey", "Address", "ListenPort", "MTU", "DNS", "PostUp", "PostDown", "PreUp", "PreDown",
    "Table", "SaveConfig", "FwMark", "PublicKey", "PresharedKey", "AllowedIPs", "Endpoint",
    "PersistentKeepalive"]}

KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")
DISABLED_MARK = "#awgr:disabled"

DEFAULT_I1 = ("<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c0001000100"
              "00105a00044d583737>")


class ServerConfError(MsgError, ValueError):
    pass


def canon(k: str) -> str:
    return _CANON.get(k.strip().lower(), k.strip())


@dataclass
class Peer:
    public_key: str
    psk: str = ""
    allowed_ips: str = ""
    extra: list[tuple[str, str]] = field(default_factory=list)
    enabled: bool = True

    @property
    def ip(self) -> str | None:
        for a in re.split(r"[,\s]+", self.allowed_ips):
            try:
                n = ipaddress.ip_network(a, strict=False)
            except ValueError:
                continue
            if n.version == 4:
                return str(n.network_address)
        return None


@dataclass
class ServerConf:
    iface: list[tuple[str, str]] = field(default_factory=list)  # порядок сохраняется
    commented: dict[str, str] = field(default_factory=dict)     # «# I1 = …»
    peers: list[Peer] = field(default_factory=list)

    # -------------------------------------------------------------- доступ
    def get(self, key: str, default: str = "") -> str:
        key = canon(key)
        for k, v in self.iface:
            if k == key:
                return v
        if key in I_KEYS:
            return self.commented.get(key, default)
        return default

    def set(self, key: str, value: str | None) -> None:
        key = canon(key)
        if key in I_KEYS:
            # I1–I5 на сервере — только комментарием (как у Amnezia)
            self.iface = [(k, v) for k, v in self.iface if k != key]
            if value:
                self.commented[key] = value
            else:
                self.commented.pop(key, None)
            return
        for i, (k, _) in enumerate(self.iface):
            if k == key:
                if value in (None, ""):
                    del self.iface[i]
                else:
                    self.iface[i] = (k, str(value))
                return
        if value not in (None, ""):
            self.iface.append((key, str(value)))

    @property
    def port(self) -> int:
        try:
            return int(self.get("ListenPort") or 0)
        except ValueError:
            return 0

    @property
    def network(self) -> ipaddress.IPv4Interface | None:
        for a in re.split(r"[,\s]+", self.get("Address")):
            try:
                i = ipaddress.ip_interface(a)
            except ValueError:
                continue
            if i.version == 4:
                return i
        return None

    def params(self) -> dict[str, str]:
        return {k: self.get(k) for k in PARAM_ORDER if self.get(k)}

    def peer(self, pk: str) -> Peer | None:
        return next((p for p in self.peers if p.public_key == pk), None)

    # --------------------------------------------------------- адреса
    def used_ips(self) -> set[str]:
        out = {p.ip for p in self.peers if p.ip}
        net = self.network
        if net:
            out.add(str(net.ip))
        return out

    def next_ip(self) -> str:
        net = self.network
        if not net:
            raise ServerConfError(Msg("srv.no_address"))
        used = self.used_ips()
        for host in net.network.hosts():
            s = str(host)
            if s not in used:
                return s
        raise ServerConfError(Msg("srv.subnet_full"))

    # --------------------------------------------------------- запись
    def render(self) -> str:
        out = ["[Interface]"]
        out += [f"{k} = {v}" for k, v in self.iface]
        for k in sorted(self.commented, key=lambda x: PARAM_ORDER.index(x) if x in PARAM_ORDER else 99):
            out.append(f"# {k} = {self.commented[k]}")
        out.append("")
        for p in self.peers:
            lines = [("PublicKey", p.public_key)]
            if p.psk:
                lines.append(("PresharedKey", p.psk))
            lines.append(("AllowedIPs", p.allowed_ips))
            lines += p.extra
            if p.enabled:
                out.append("[Peer]")
                out += [f"{k} = {v}" for k, v in lines]
            else:
                out.append(DISABLED_MARK)
                out.append("# [Peer]")
                out += [f"# {k} = {v}" for k, v in lines]
            out.append("")
        return "\n".join(out)

    def stripped(self) -> str:
        """То, что принимает `awg setconf/syncconf` (без ключей awg-quick и комментариев)."""
        out = ["[Interface]"]
        out += [f"{k} = {v}" for k, v in self.iface if k.lower() not in QUICK_ONLY]
        for p in self.peers:
            if not p.enabled:
                continue
            out.append("")
            out.append("[Peer]")
            out.append(f"PublicKey = {p.public_key}")
            if p.psk:
                out.append(f"PresharedKey = {p.psk}")
            out.append(f"AllowedIPs = {p.allowed_ips}")
            out += [f"{k} = {v}" for k, v in p.extra if k.lower() not in QUICK_ONLY]
        return "\n".join(out) + "\n"


def parse(text: str) -> ServerConf:
    sc = ServerConf()
    section = None
    peer: Peer | None = None
    disabled_block = False

    def close_peer():
        nonlocal peer
        if peer and peer.public_key:
            sc.peers.append(peer)
        peer = None

    for raw in (text or "").replace("\r", "").split("\n"):
        line = raw.strip()
        if not line:
            if disabled_block:
                close_peer()
                disabled_block = False
            continue
        if line == DISABLED_MARK:
            close_peer()
            disabled_block = True
            section = "disabled"
            continue
        if disabled_block:
            body = line.lstrip("#").strip()
            if body == "[Peer]":
                peer = Peer(public_key="", enabled=False)
                continue
            if "=" in body and peer is not None:
                k, v = (x.strip() for x in body.split("=", 1))
                _peer_kv(peer, k, v)
                continue
            close_peer()
            disabled_block = False
            # обычная строка после блока — разбираем ниже
        if line.startswith("[") and line.endswith("]"):
            close_peer()
            section = line[1:-1].strip().lower()
            if section == "peer":
                peer = Peer(public_key="")
            continue
        if line.startswith("#") or line.startswith(";"):
            m = re.match(r"^#\s*(I[1-5])\s*=\s*(.*)$", line)
            if m and section == "interface" and m.group(2).strip():
                sc.commented[m.group(1)] = m.group(2).strip()
            continue
        if "=" not in line:
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        if section == "interface":
            if v == "":
                continue
            sc.iface.append((canon(k), v))
        elif section == "peer" and peer is not None:
            _peer_kv(peer, k, v)
    close_peer()
    return sc


def _peer_kv(peer: Peer, k: str, v: str) -> None:
    kl = k.lower()
    if kl == "publickey":
        peer.public_key = v
    elif kl in ("presharedkey",):
        peer.psk = v
    elif kl == "allowedips":
        peer.allowed_ips = v
    else:
        peer.extra.append((canon(k), v))


# ======================================================================= параметры
def _rng(lo: int, hi: int) -> int:
    return lo + secrets.randbelow(hi - lo + 1)


def generate_params(header_protection: bool = True) -> dict[str, str]:
    """Новые параметры обфускации (по образцу установщика AmneziaVPN для AWG 3.1)."""
    if header_protection:
        return {
            "Jc": str(_rng(4, 6)), "Jmin": "10", "Jmax": "50",
            "S1": "12", "S2": "12", "S3": "12", "S4": "12",
            "H1": "1", "H2": "2", "H3": "3", "H4": "4",
            "I1": DEFAULT_I1,
            "HeaderProtectionKey": base64.b64encode(secrets.token_bytes(32)).decode(),
            "ContentPaddingAddition": "10-100",
            "RekeyAfterTime": "100-120", "RekeyTimeout": "3-7", "RejectAfterTime": "150-180",
            "KeepaliveTimeout": "5-15", "MaxHandshakeAttempts": "15-20",
            "RandomTrailers": "on", "DisableCookies": "on",
        }
    # без защиты заголовков: случайные непересекающиеся H и размеры S
    while True:
        s1, s2 = _rng(15, 150), _rng(15, 150)
        if s1 + 56 != s2:
            break
    hs = sorted(secrets.SystemRandom().sample(range(5, 2 ** 31 - 1), 4))
    return {"Jc": str(_rng(4, 6)), "Jmin": "10", "Jmax": "50", "S1": str(s1), "S2": str(s2),
            "S3": str(_rng(15, 64)), "S4": str(_rng(0, 32)),
            "H1": str(hs[0]), "H2": str(hs[1]), "H3": str(hs[2]), "H4": str(hs[3]),
            "I1": DEFAULT_I1}


def _parse_range(v: str) -> tuple[int, int] | None:
    v = v.strip()
    m = re.fullmatch(r"(\d+)\s*(?:-\s*(\d+))?", v)
    if not m:
        return None
    a = int(m.group(1))
    b = int(m.group(2)) if m.group(2) else a
    return (a, b) if a <= b else None


def validate_params(p: dict[str, str]) -> dict[str, str]:
    """Проверяет и нормализует параметры. Пустое значение = параметр не задан."""
    out: dict[str, str] = {}
    for k, v in p.items():
        k = canon(k)
        if k not in AWG_PARAMS:
            raise ServerConfError(Msg("srv.bad_param", key=k))
        v = str(v if v is not None else "").strip()
        if v == "":
            out[k] = ""
            continue
        kind = AWG_PARAMS[k][0]
        if kind == "int":
            if not v.isdigit() or int(v) > 65535:
                raise ServerConfError(Msg("srv.bad_int", key=k))
            v = str(int(v))
        elif kind in ("range", "hrange"):
            r = _parse_range(v)
            limit = 2 ** 32 - 1 if kind == "hrange" else 65535
            if not r or r[1] > limit:
                raise ServerConfError(Msg("srv.bad_range", key=k))
            v = f"{r[0]}-{r[1]}" if r[0] != r[1] else str(r[0])
        elif kind == "bool":
            if v.lower() not in ("on", "off", "true", "false", "1", "0"):
                raise ServerConfError(Msg("srv.bad_bool", key=k))
            v = "on" if v.lower() in ("on", "true", "1") else "off"
        elif kind == "key":
            if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", v):
                raise ServerConfError(Msg("srv.bad_key", key=k))
        elif kind == "text":
            if "\n" in v or len(v) > 4000 or not re.fullmatch(r"(<[^<>]{1,2000}>\s*)+", v):
                raise ServerConfError(Msg("srv.bad_junk", key=k))
        out[k] = v
    # связи между параметрами
    jmin, jmax = out.get("Jmin"), out.get("Jmax")
    if jmin and jmax and int(jmin) > int(jmax):
        raise ServerConfError(Msg("srv.jmin_jmax"))
    if jmax and int(jmax) > 1280:
        raise ServerConfError(Msg("srv.jmax_big"))
    s1, s2 = out.get("S1"), out.get("S2")
    if s1 and s2 and int(s1) + 56 == int(s2):
        raise ServerConfError(Msg("srv.s1_s2"))
    hr = [(_parse_range(out[k]), k) for k in ("H1", "H2", "H3", "H4") if out.get(k)]
    hr = [(r, k) for r, k in hr if r]
    for i in range(len(hr)):
        for j in range(i + 1, len(hr)):
            (a, ka), (b, kb) = hr[i], hr[j]
            if a[0] <= b[1] and b[0] <= a[1]:
                raise ServerConfError(Msg("srv.h_overlap", a=ka, b=kb))
    return out


def server_side_changed(old: dict[str, str], new: dict[str, str]) -> bool:
    return any(old.get(k, "") != new.get(k, "") for k, (_, side) in AWG_PARAMS.items()
               if side == "server")


def protocol_version(params: dict[str, str]) -> str:
    keys = {k.lower() for k in params}
    if keys & {"headerprotectionkey", "contentpaddingaddition", "rekeyaftertime",
               "randomtrailers", "disablecookies"}:
        return "3.1"
    if keys & {"s3", "s4", "i1", "i2", "i3", "i4", "i5"}:
        return "2"
    if keys & {"jc", "s1", "h1"}:
        return "1.5"
    return ""


# ================================================================ клиентский конфиг
@dataclass
class ClientProfile:
    """Общие настройки, которые получают клиенты."""
    host: str
    port: int
    server_pub: str
    dns: list[str]
    mtu: int = 1376
    keepalive: str = "25"


def client_conf(sc: ServerConf, prof: ClientProfile, peer: Peer, priv: str) -> str:
    params = sc.params()
    lines = ["[Interface]", f"Address = {peer.ip}/32"]
    if prof.dns:
        lines.append("DNS = " + ", ".join(prof.dns))
    lines.append(f"PrivateKey = {priv}")
    if prof.mtu:
        lines.append(f"MTU = {prof.mtu}")
    for k in PARAM_ORDER:
        if params.get(k):
            lines.append(f"{k} = {params[k]}")
    lines += ["", "[Peer]", f"PublicKey = {prof.server_pub}"]
    if peer.psk:
        lines.append(f"PresharedKey = {peer.psk}")
    host = f"[{prof.host}]" if ":" in prof.host else prof.host
    lines += ["AllowedIPs = 0.0.0.0/0, ::/0", f"Endpoint = {host}:{prof.port}",
              f"PersistentKeepalive = {prof.keepalive}", ""]
    return "\n".join(lines)


def default_keepalive(params: dict[str, str]) -> str:
    return "25-35" if protocol_version(params) == "3.1" else "25"


def vpn_link(sc: ServerConf, prof: ClientProfile, peer: Peer, priv: str, conf: str,
             description: str) -> str:
    """Ссылка vpn:// для импорта в приложение AmneziaVPN."""
    params = sc.params()
    net = sc.network
    client = {
        "config": conf, "hostName": prof.host, "port": prof.port, "client_ip": peer.ip,
        "client_priv_key": priv, "client_pub_key": peer.public_key,
        "server_pub_key": prof.server_pub, "psk_key": peer.psk, "clientId": peer.public_key,
        "allowed_ips": ["0.0.0.0/0", "::/0"], "persistent_keep_alive": prof.keepalive,
        "mtu": str(prof.mtu), **params,
    }
    awg = {"port": str(prof.port), "transport_proto": "udp",
           "protocol_version": protocol_version(params) or "1.5",
           "subnet_address": str(net.network.network_address) if net else "10.8.1.0",
           "subnet_cidr": str(net.network.prefixlen) if net else "24",
           **params,
           "last_config": json.dumps(client, ensure_ascii=False, separators=(",", ":"))}
    doc = {"format_version": 1, "description": description, "hostName": prof.host,
           "containers": [{"container": "amnezia-awg2", "awg": awg}],
           "defaultContainer": "amnezia-awg2"}
    if prof.dns:
        doc["dns1"] = prof.dns[0]
        if len(prof.dns) > 1:
            doc["dns2"] = prof.dns[1]
    raw = json.dumps(doc, ensure_ascii=False, indent=4).encode()
    packed = struct.pack(">I", len(raw)) + zlib.compress(raw, 8)  # как qCompress
    return "vpn://" + base64.urlsafe_b64encode(packed).decode().rstrip("=")


# ==================================================================== clientsTable
def amnezia_date() -> str:
    return time.strftime("%a %b %-d %H:%M:%S %Y")


def parse_clients_table(raw: str | None) -> list[dict]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    if isinstance(data, dict):  # старый формат
        data = [{"clientId": k, "userData": v} for k, v in data.items()]
    return [c for c in data if isinstance(c, dict) and c.get("clientId")]


def render_clients_table(rows: list[dict]) -> str:
    return json.dumps(rows, ensure_ascii=False, indent=4)


# ======================================================================== новый сервер
def new_server(priv: str, port: int, subnet: str, params: dict[str, str], wan_masq: bool = True,
               amnezia_style: bool = False) -> ServerConf:
    """amnezia_style — как создаёт AmneziaVPN: Address = адрес сети (10.8.1.0/24), NAT в start.sh."""
    net = ipaddress.ip_interface(subnet)
    if net.version != 4 or net.network.prefixlen > 29:
        raise ServerConfError(Msg("srv.bad_subnet"))
    if amnezia_style:
        addr = str(net.network)
        wan_masq = False
    else:
        addr = f"{next(net.network.hosts())}/{net.network.prefixlen}"
    sc = ServerConf()
    sc.iface = [("PrivateKey", priv), ("Address", addr), ("ListenPort", str(port))]
    for k, v in params.items():
        sc.set(k, v)
    if wan_masq:
        cidr = str(net.network)
        wan = "$(ip -4 route show default | awk '{print $5; exit}')"
        up = ("sysctl -qw net.ipv4.ip_forward=1; "
              "iptables -I FORWARD -i %i -j ACCEPT; "
              "iptables -I FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; "
              f"iptables -t nat -A POSTROUTING -s {cidr} -o {wan} -j MASQUERADE; true")
        down = ("iptables -D FORWARD -i %i -j ACCEPT; "
                "iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; "
                f"iptables -t nat -D POSTROUTING -s {cidr} -o {wan} -j MASQUERADE; true")
        sc.iface += [("PostUp", up), ("PostDown", down)]
    return sc
