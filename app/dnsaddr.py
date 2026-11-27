"""Адрес своего DNS правила по доменам и запасного DNS (1.25.0): обычный DNS — IPv4 («77.88.8.8»), DoH —
«https://имя[:порт]/путь» (HTTP/2 или HTTP/1.1 — что выберет сервер), DoH только по HTTP/3 — «h3://имя[:порт]/путь»,
DoT — «tls://имя[:порт]» (имя или IPv4). Как вписан, так и спрашивается: шифрованный, который
не ответил, без шифрования не спрашивается, и на другой способ сам не переходит (владелец 2026-11-26). До двух адресов:
второй спрашивается, когда не ответил первый.

Имя сервиса (dns.google) на пути «напрямую» с адреса системы разбирает панель в своей сети: dnsproxy.py работает в сети
сервера AWG, где имён не разобрать («nsenter -n меняет только сеть»), и получает запись с адресом:
«tls://dns.google#8.8.8.8» (for_proxy). На пути через выход и «Напрямую — адрес» имя ищет сам dnsproxy.py тем же путём
(dnsproxy._name_addr), чтобы запрос не ушёл мимо выхода или с адреса системы.

На диске и в резервной копии (to_disk) в «dns» правила — только обычные адреса: панель до 1.25.0 других не понимает и
спрашивала бы «tls://…» как адрес (правило без ответа). Без них она спрашивает общие серверы. Весь список по порядку —
в «dns_all»; from_disk его возвращает, если обычные адреса за это время не правили (откат и правка в прежнем выпуске)."""
from __future__ import annotations

import copy
import ipaddress
import re
import socket
import threading
import time

MAX = 2
DOT_PORT, DOH_PORT = 853, 443
DOH_PATH = "/dns-query"
LOOKUP_TIMEOUT = 3.0
ALL = "dns_all"                 # поле правила на диске: весь список, когда в нём есть шифрованные

_NAME = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")
_PATH = re.compile(r"^/[A-Za-z0-9/._~%+-]*$")


class DnsAddrError(ValueError):
    """Неверная запись: why — "bad" (не адрес DNS), "many" (больше MAX); value — что вписано."""

    def __init__(self, why: str, value: str = ""):
        super().__init__(why)
        self.why, self.value = why, value


def _ipv4(s: str) -> str | None:
    """IPv4 для DNS (не 0.0.0.0, не multicast); не IPv4 — None. IPv6 — ошибка: в туннеле и у DNS на сервере только IPv4."""
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    if a.version != 4 or a.is_unspecified or a.is_multicast:
        raise DnsAddrError("bad", s)
    return str(a)


def _host(s: str, raw: str) -> str:
    if s.startswith("[") or s.count(":"):
        raise DnsAddrError("bad", raw)                  # IPv6
    ip = _ipv4(s)
    if ip:
        return ip
    try:
        name = s.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise DnsAddrError("bad", raw) from None
    if not _NAME.match(name) or name.replace(".", "").isdigit():
        raise DnsAddrError("bad", raw)
    return name


def parse(s) -> dict:
    """Одна запись → {"mode": plain|doh|doh3|dot, "host": IPv4 или имя, "port", "path"}. Неверная — DnsAddrError."""
    raw = str(s).strip() if isinstance(s, str) else ""
    if not raw or len(raw) > 200:
        raise DnsAddrError("bad", raw[:60])
    if "://" not in raw:
        ip = _ipv4(raw)
        if not ip:
            raise DnsAddrError("bad", raw[:60])
        return {"mode": "plain", "host": ip, "port": 53, "path": ""}
    scheme, rest = raw.split("://", 1)
    scheme = scheme.lower()
    if scheme == "tls":
        mode, port = "dot", DOT_PORT
        hostport, path = rest.rstrip("/"), ""
        if "/" in hostport:
            raise DnsAddrError("bad", raw[:60])
    elif scheme in ("https", "h3"):
        mode, port = ("doh" if scheme == "https" else "doh3"), DOH_PORT
        hostport, sl, path = rest.partition("/")
        path = sl + path
        path = re.sub(r"\{\?[^}]*\}$", "", path)        # шаблон из документации: …/dns-query{?dns}
        if path in ("", "/"):
            path = DOH_PATH
        if not _PATH.match(path):
            raise DnsAddrError("bad", raw[:60])
    else:
        raise DnsAddrError("bad", raw[:60])
    host = hostport
    if hostport.count(":") == 1:
        host, p = hostport.split(":")
        if not p.isdigit() or not 1 <= int(p) <= 65535:
            raise DnsAddrError("bad", raw[:60])
        port = int(p)
    return {"mode": mode, "host": _host(host, raw[:60]), "port": port, "path": path}


def fmt(p: dict) -> str:
    """Запись в обычном виде (как сохраняется): порт — только не обычный."""
    if p["mode"] == "plain":
        return p["host"]
    if p["mode"] == "dot":
        return "tls://" + p["host"] + ("" if p["port"] == DOT_PORT else f":{p['port']}")
    scheme = "h3" if p["mode"] == "doh3" else "https"
    return scheme + "://" + p["host"] + ("" if p["port"] == DOH_PORT else f":{p['port']}") + p["path"]


def entries(v) -> list[str]:
    """Поле (список или строка через запятую или пробел) → записи в обычном виде без повторов; пусто — []."""
    if v in (None, "", []):
        return []
    if isinstance(v, list):
        items = [str(x) for x in v]
    elif isinstance(v, str):
        items = re.split(r"[,\s]+", v)
    else:
        raise DnsAddrError("bad", "")
    out = []
    for x in filter(None, (s.strip() for s in items)):
        e = fmt(parse(x))
        if e not in out:
            out.append(e)
    if len(out) > MAX:
        raise DnsAddrError("many", str(MAX))
    return out


def host(entry: str) -> str:
    try:
        return parse(entry)["host"]
    except DnsAddrError:
        return ""


def is_h3(entry) -> bool:
    """Запись DoH только по HTTP/3 («h3://…»)."""
    return isinstance(entry, str) and entry.lower().startswith("h3://")


def is_plain(entry) -> bool:
    return isinstance(entry, str) and "://" not in entry


def names(entries_) -> list[str]:
    """Имена сервисов (не адреса) из записей: их адрес узнаёт панель."""
    out = []
    for e in entries_ or ():
        try:
            p = parse(e)
        except DnsAddrError:
            continue
        if p["mode"] != "plain" and not _ipv4_quiet(p["host"]) and p["host"] not in out:
            out.append(p["host"])
    return out


def _ipv4_quiet(s: str) -> bool:
    try:
        return ipaddress.ip_address(s).version == 4
    except ValueError:
        return False


def lookup(hosts, timeout: float = LOOKUP_TIMEOUT) -> dict[str, str]:
    """IPv4 имён в сети панели, параллельно, всего не дольше timeout: {имя: адрес}; не разобранных нет."""
    res: dict[str, str] = {}

    def one(h):
        try:
            # наименьший из адресов, а не первый: порядок в ответе меняется при каждом запросе, и запись «#адрес» для
            # dnsproxy.py менялась бы — SIGHUP, сброс кэша и состояния запасного DNS раз в 10–20 минут (П47)
            res[h] = min((a[4][0] for a in socket.getaddrinfo(h, None, socket.AF_INET, socket.SOCK_STREAM)),
                         key=ipaddress.ip_address)
        except (OSError, UnicodeError, ValueError):
            pass
    ths = [threading.Thread(target=one, args=(h,), daemon=True) for h in hosts]
    for th in ths:
        th.start()
    end = time.monotonic() + timeout          # общий срок на все имена, а не timeout на каждое по очереди (А10)
    for th in ths:
        th.join(max(0.0, end - time.monotonic()))
    return dict(res)


def for_proxy(entry: str, ips: dict) -> str:
    """Запись для dnsproxy.py: у имени — адрес после «#» («tls://dns.google#8.8.8.8»); адреса ещё нет — без него
    (dnsproxy.py такой сервер не спрашивает: не ответил)."""
    try:
        p = parse(entry)
    except DnsAddrError:
        return entry
    if p["mode"] == "plain" or _ipv4_quiet(p["host"]) or not ips.get(p["host"]):
        return fmt(p)
    return fmt(p) + "#" + ips[p["host"]]


# ---------------------------------------------------------------- диск и копии
def rules_of(st: dict):
    """Все правила состояния: общие и свои правила клиентов."""
    return _rules(st)


def _rules(st: dict):
    r = st.get("routing")
    if isinstance(r, dict):
        yield from (x for x in r.get("rules") or [] if isinstance(x, dict))
    for c in (st.get("clients") or {}).values():
        if isinstance(c, dict):
            yield from (x for x in c.get("rules") or [] if isinstance(x, dict))


def _has_enc(st: dict) -> bool:
    return any((isinstance(x.get("dns"), list) and not all(map(is_plain, x["dns"]))) or ALL in x for x in _rules(st))


def to_disk(st: dict) -> dict:
    """Состояние для state.json и копии: в «dns» — только обычные адреса, весь список — в «dns_all». Без шифрованных —
    то же состояние, без копии (так почти у всех, а запись идёт на каждое изменение)."""
    if not _has_enc(st):
        return st
    out = copy.deepcopy(st)
    for x in _rules(out):
        x.pop(ALL, None)
        d = x.get("dns")
        if isinstance(d, list) and not all(map(is_plain, d)):
            x[ALL] = d
            plain = [e for e in d if is_plain(e)]
            if plain:
                x["dns"] = plain
            else:
                x.pop("dns")
    return out


def from_disk(st: dict) -> dict:
    """Обратно (в том же состоянии): «dns_all» → «dns», если обычные адреса в нём те же, что в «dns» (иначе правило
    правили в прежнем выпуске — его «dns» и остаётся)."""
    for x in _rules(st):
        a = x.pop(ALL, None)
        if isinstance(a, list) and all(isinstance(e, str) for e in a) and \
                [e for e in a if is_plain(e)] == list(x.get("dns") or []):
            x["dns"] = a
    return st


def on_disk(st: dict) -> bool:
    """Есть ли в состоянии с диска «dns_all» (from_disk нужен)."""
    return any(ALL in x for x in _rules(st))
