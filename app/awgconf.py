"""Разбор клиентских конфигов AmneziaWG (.conf и ссылок vpn://)."""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import zlib
from dataclasses import dataclass, field

from .i18n import Msg, MsgError

# Ключи, которые понимает только awg-quick; в `awg setconf` их передавать нельзя
QUICK_ONLY_KEYS = {"address", "dns", "mtu", "table", "preup", "postup",
                   "predown", "postdown", "saveconfig"}

KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")


class ConfigError(MsgError, ValueError):
    pass


# Параметры, по которым определяем поколение протокола AmneziaWG
AWG3_KEYS = {"headerprotectionkey", "contentpaddingaddition", "rekeyaftertime", "rekeytimeout",
             "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts", "randomtrailers",
             "disablecookies", "advancedsecurity"}
AWG2_KEYS = {"s3", "s4", "i1", "i2", "i3", "i4", "i5"}
AWG1_KEYS = {"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"}


def protocol_version(keys) -> str:
    """'3' | '2' | '1' | '' (обычный WireGuard)."""
    k = {x.lower() for x in keys}
    if k & AWG3_KEYS:
        return "3"
    if k & AWG2_KEYS:
        return "2"
    if k & AWG1_KEYS:
        return "1"
    return ""


@dataclass
class UpstreamConf:
    raw: str                       # нормализованный текст .conf
    setconf: str                   # то, что уходит в `awg setconf`
    address: str                   # IPv4 адрес клиента на удалённом сервере
    mtu: int
    endpoint: str
    peer_public_key: str
    rekey_after: int = 120
    params: dict = field(default_factory=dict)
    version: str = ""


def _parse_sections(text: str, strict: bool = True) -> list[tuple[str, list[tuple[str, str]]]]:
    sections: list[tuple[str, list[tuple[str, str]]]] = []
    cur = None
    for line in text.replace("\r", "").split("\n"):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        if s.startswith("[") and s.endswith("]"):
            cur = (s[1:-1].strip().lower(), [])
            sections.append(cur)
            continue
        if "=" not in s or cur is None:
            if not strict:
                continue
            if cur is None:
                raise ConfigError(Msg("cfg.outside_section"))
            raise ConfigError(Msg("cfg.bad_line", line=s[:60]))
        k, v = s.split("=", 1)
        cur[1].append((k.strip(), v.strip()))
    return sections


def _b64_any(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s)
    except Exception:
        return base64.b64decode(s)


def _find_conf_in_json(obj) -> str | None:
    """Ищет текст [Interface]... внутри JSON-экспорта Amnezia (vpn://)."""
    if isinstance(obj, str):
        st = obj.strip()
        if st.startswith("{"):  # last_config — это JSON, вложенный строкой
            try:
                return _find_conf_in_json(json.loads(st))
            except ValueError:
                pass
        return obj if "[Interface]" in obj else None
    if isinstance(obj, dict):
        # приоритет: containers[].awg.last_config.config
        for key in ("last_config", "config"):
            if key in obj:
                r = _find_conf_in_json(obj[key])
                if r:
                    return r
        for v in obj.values():
            r = _find_conf_in_json(v)
            if r:
                return r
    if isinstance(obj, list):
        for v in obj:
            r = _find_conf_in_json(v)
            if r:
                return r
    return None


def extract_conf_text(user_input: str) -> str:
    """Принимает .conf, JSON или vpn://… и возвращает текст .conf."""
    t = user_input.strip()
    if not t:
        raise ConfigError(Msg("cfg.empty"))
    if "[Interface]" in t:
        return t
    if t.startswith("vpn://"):
        t = t[len("vpn://"):]
    if t.startswith("{"):
        conf = _find_conf_in_json(t)
        if conf:
            return conf
        raise ConfigError(Msg("cfg.no_awg_in_json"))
    try:
        raw = _b64_any(t)
    except Exception:
        raise ConfigError(Msg("cfg.unrecognized"))
    data = None
    # qCompress: 4 байта длины (big-endian) + zlib
    for cand in (raw[4:], raw):
        try:
            data = zlib.decompress(cand)
            break
        except Exception:
            continue
    if data is None:
        data = raw
    text = data.decode("utf-8", errors="replace")
    if "[Interface]" in text and not text.lstrip().startswith("{"):
        return text
    try:
        obj = json.loads(text)
    except Exception:
        raise ConfigError(Msg("cfg.bad_vpn_link"))
    conf = _find_conf_in_json(obj)
    if not conf:
        raise ConfigError(Msg("cfg.vpn_no_awg"))
    return conf


def _range_max(v: str, default: int) -> int:
    nums = [int(x) for x in re.findall(r"\d+", v or "")]
    return max(nums) if nums else default


def parse_upstream(user_input: str) -> UpstreamConf:
    text = extract_conf_text(user_input)
    sections = _parse_sections(text)
    ifaces = [s for s in sections if s[0] == "interface"]
    peers = [s for s in sections if s[0] == "peer"]
    if len(ifaces) != 1:
        raise ConfigError(Msg("cfg.one_interface"))
    if not peers:
        raise ConfigError(Msg("cfg.no_peer"))
    if len(peers) > 1:
        raise ConfigError(Msg("cfg.many_peers"))

    iface = ifaces[0][1]
    peer = peers[0][1]
    ilow = {k.lower(): v for k, v in iface}
    plow = {k.lower(): v for k, v in peer}

    if not KEY_RE.match(ilow.get("privatekey", "")):
        raise ConfigError(Msg("cfg.bad_privkey"))
    if not KEY_RE.match(plow.get("publickey", "")):
        raise ConfigError(Msg("cfg.bad_pubkey"))
    endpoint = plow.get("endpoint", "")
    if not endpoint or ":" not in endpoint:
        raise ConfigError(Msg("cfg.no_endpoint"))

    address = None
    for a in re.split(r"[,\s]+", ilow.get("address", "")):
        if not a:
            continue
        try:
            ip = ipaddress.ip_interface(a)
        except ValueError:
            continue
        if ip.version == 4:
            address = str(ip.ip)
            break
    if not address:
        raise ConfigError(Msg("cfg.no_ipv4"))

    try:
        mtu = int(ilow.get("mtu", "") or 1280)
    except ValueError:
        mtu = 1280
    mtu = max(1100, min(mtu, 1500))

    # [Interface] для setconf: без ключей awg-quick и без пустых значений
    out = ["[Interface]"]
    params = {}
    for k, v in iface:
        if k.lower() in QUICK_ONLY_KEYS or v == "":
            continue
        out.append(f"{k} = {v}")
        if k.lower() != "privatekey":
            params[k] = v
    out.append("")
    out.append("[Peer]")
    has_keepalive = False
    for k, v in peer:
        if v == "":
            continue
        kl = k.lower()
        if kl == "allowedips":
            v = "0.0.0.0/0"  # маршруты задаёт панель; принимаем любой IPv4
        if kl == "persistentkeepalive":
            has_keepalive = True
            # AWG 3 допускает диапазон «22-30»; выключенный keepalive включаем —
            # без него не определить, жив ли туннель
            if v.strip("() ").lower() in ("0", "off", ""):
                v = "25"
        out.append(f"{k} = {v}")
    if not has_keepalive:
        out.append("PersistentKeepalive = 25")
    setconf = "\n".join(out) + "\n"

    return UpstreamConf(
        raw=text.strip() + "\n",
        setconf=setconf,
        address=address,
        mtu=mtu,
        endpoint=endpoint,
        peer_public_key=plow["publickey"],
        rekey_after=_range_max(ilow.get("rekeyaftertime", ""), 120),
        params=params,
        version=protocol_version(ilow.keys()),
    )


def parse_server_conf(text: str) -> dict:
    """Серверный awg0.conf/wg0.conf Amnezia → адрес интерфейса и пиры."""
    res = {"address": None, "peers": []}
    for name, kv in _parse_sections(text, strict=False):
        d = {k.lower(): v for k, v in kv}
        if name == "interface":
            res["address"] = d.get("address")
            res["mtu"] = d.get("mtu")
        elif name == "peer":
            ip = None
            for a in re.split(r"[,\s]+", d.get("allowedips", "")):
                try:
                    n = ipaddress.ip_network(a, strict=False)
                except ValueError:
                    continue
                if n.version == 4:
                    ip = str(n.network_address)
                    break
            res["peers"].append({"public_key": d.get("publickey", ""), "ip": ip})
    return res
