"""Списки сетей: страны, URL-списки, ручные CIDR; списки доменов (domains.py)."""
from __future__ import annotations

import bisect
import ipaddress
import os
import re
import threading
import time
import urllib.error
import urllib.request

from . import config, domains
from .i18n import Msg

COUNTRY_SOURCES = [
    # Фактическая регистрация сетей (включая субаллокации) — точнее для маршрутизации
    "https://raw.githubusercontent.com/ipverse/geo-ip-blocks/master/country/{cc}/{cc}-ipv4.txt",
    # Делегирование RIR
    "https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/{cc}/ipv4-aggregated.txt",
    "https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone",
]

ASN_SOURCES = [
    # Префиксы, анонсируемые автономной системой (обновляется ежедневно)
    "https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/{asn}/ipv4-aggregated.txt",
]
# Запасной источник — живые BGP-данные RIPE NCC
RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"

# Коды стран для подсказки при вводе (названия переводит браузер)
COUNTRY_CODES = ["ru", "cn", "ir", "by", "kz", "ua", "uz", "am", "ge", "az", "kg", "tj", "tm",
                 "md", "tr", "ae", "us", "de", "nl", "fi", "fr", "gb", "pl", "lv", "lt", "ee",
                 "se", "jp", "kr", "sg", "hk", "in", "vn", "th", "id", "my", "il", "sa", "eg",
                 "br", "ca", "cy", "rs", "mn", "kp", "af", "iq", "pk", "tw", "mo"]


LISTS_DIR = os.path.join(config.DATA_DIR, "lists")
LINE_TOKEN = re.compile(r"^\s*([0-9.]+(?:/\d{1,2})?)")


WIDE_MIN = 8        # в скачанных списках префиксы короче /8 не принимаются (испорченная строка, а не страна)


def parse_cidrs(text: str, min_prefix: int = 0) -> list[ipaddress.IPv4Network]:
    """min_prefix — для скачанных списков (страны, ASN, по ссылке): сеть шире /8 там означает испорченную
    строку, и правило «список → напрямую» увело бы мимо выхода огромную часть интернета. Ручной список
    не ограничивается: там это решение человека."""
    nets = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or ":" in line.split()[0]:
            continue
        # допускаем "a.b.c.d/nn", "a.b.c.d", а также запятые/пробелы
        for tok in re.split(r"[,\s]+", line):
            m = LINE_TOKEN.match(tok)
            if not m:
                continue
            try:
                n = ipaddress.IPv4Network(m.group(1), strict=False)
            except ValueError:
                continue
            if n.prefixlen >= min_prefix:
                nets.append(n)
    return list(ipaddress.collapse_addresses(nets))


def count_ipv6(text: str) -> int:
    """Сколько IPv6-адресов и подсетей в тексте: parse_cidrs их пропускает (в туннеле только
    IPv4), а пользователю стоит знать, что часть его списка не используется."""
    n = 0
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0]
        for tok in re.split(r"[,\s]+", line):
            if ":" not in tok:
                continue
            try:
                ipaddress.IPv6Network(tok.strip("[]"), strict=False)
                n += 1
            except ValueError:
                continue
    return n


def path_for(list_id: str) -> str:
    return os.path.join(LISTS_DIR, f"{list_id}.txt")


def save_cidrs(list_id: str, nets: list[ipaddress.IPv4Network]) -> None:
    domains.write_atomic(path_for(list_id), "\n".join(str(n) for n in nets) + ("\n" if nets else ""))


def load_cidrs(list_id: str) -> list[str]:
    try:
        with open(path_for(list_id)) as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


def delete_cidrs(list_id: str) -> None:
    try:
        os.remove(path_for(list_id))
    except FileNotFoundError:
        pass
    domains.delete(list_id)


def fetch_domains(lst: dict) -> tuple[list[str], list[str]]:
    """Список доменов: строки текста + содержимое ссылок из него → (домены, ошибки ссылок, что не скачались).
    Бросает ListError, когда доменов нет совсем."""
    urls, text = domains.split_source(lst.get("source", ""))
    found = domains.parse(text)
    errors = []
    for url in urls:
        try:
            found += domains.parse(_fetch(url))
        except Exception as e:  # noqa: BLE001
            errors.append(f"{url.split('/')[2]}: {e}")
    if errors and (not found or len(errors) == len(urls) and not text.strip()):
        raise ListError(Msg("list.fetch_failed", detail="; ".join(errors)))
    names = domains.compact(list(dict.fromkeys(found)))
    if not names:
        raise ListError(Msg("list.no_domains"))
    if len(names) > domains.MAX_DOMAINS:
        raise ListError(Msg("list.too_many_domains", n=domains.MAX_DOMAINS))
    return names, errors


FETCH_MAX = 64 * 1024 * 1024
FETCH_DEADLINE = 300        # секунд на всё скачивание: timeout у urlopen — на одно чтение, и сервер, что шлёт по
                            # байту раз в 29 секунд, держал бы обновление всех списков до перезапуска панели
# Скачать через рабочий выход (url → (текст, framed)), если напрямую не вышло: задаёт main.py. Нужно серверам в КНР и
# Иране, где raw.githubusercontent.com часто закрыт, — иначе списки стран пусты и их правила не действуют.
alt_fetch = None


def whole_lines(text: str, framed: bool) -> str:
    """Ответ без Content-Length и без chunked заканчивается, когда сервер закрыл соединение, — и обрыв
    выглядит так же. Недописанная последняя строка «185.10.0.0/16» превратилась бы в «185.10.0.0/1»
    (половина интернета), поэтому у такого ответа она отбрасывается."""
    if framed or not text or text.endswith("\n"):
        return text
    return text[:text.rfind("\n") + 1]


def _fetch_direct(url: str, timeout: int = 30) -> tuple[str, bool]:
    """→ (текст, framed — у ответа есть Content-Length или chunked)."""
    req = urllib.request.Request(url, headers={"User-Agent": "awg-router/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        if r.status != 200:
            raise RuntimeError(f"HTTP {r.status}")
        data = _read_limited(r, FETCH_MAX + 1, time.monotonic() + FETCH_DEADLINE)
        if len(data) > FETCH_MAX:                  # раньше молча обрезалось на середине строки
            raise RuntimeError("larger than 64 MB")
        cl = (r.headers.get("Content-Length") or "").strip()
        if cl.isascii() and cl.isdigit() and len(data) < int(cl):
            # read(n) при обрыве отдаёт, что успело прийти, без ошибки: обрезанный список заменил бы целый
            raise RuntimeError(f"cut short: {len(data)} of {cl} bytes")
        framed = bool(cl or r.headers.get("Transfer-Encoding"))
        return data.decode("utf-8", errors="replace"), framed


def _read_limited(r, limit: int, deadline: float) -> bytes:
    """Тело ответа: не больше limit байт и не дольше deadline (time.monotonic) — по одному чтению из сети."""
    buf = bytearray()
    while len(buf) < limit:
        if time.monotonic() > deadline:
            raise RuntimeError(f"too slow: {len(buf)} bytes in {FETCH_DEADLINE} s")
        chunk = r.read1(min(65536, limit - len(buf)))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _fetch(url: str, timeout: int = 30, lines: bool = True) -> str:
    """lines — ответ построчный (списки): недописанная последняя строка отбрасывается (whole_lines).
    JSON (RIPEstat) — без этого: обрыв в нём и так ошибка разбора."""
    text, framed = _fetch_any(url, timeout)
    return whole_lines(text, framed) if lines else text


def _fetch_any(url: str, timeout: int) -> tuple[str, bool]:
    try:
        return _fetch_direct(url, timeout)
    except urllib.error.HTTPError:
        raise                                       # сайт ответил (404 и т. п.): через выход ответ тот же
    except OSError as e:                            # не дошли: нет связи, сброс, подмена сертификата
        if alt_fetch is None or not url.startswith("https://"):
            raise
        try:
            return alt_fetch(url)
        except Exception as e2:  # noqa: BLE001
            raise RuntimeError(f"{e}; via exit: {e2}") from None


def fetch_list(lst: dict, stats: dict | None = None) -> list[ipaddress.IPv4Network]:
    """Скачивает/собирает список. Бросает исключение при неудаче.
    stats["v6"] — сколько IPv6-строк пропущено (для ручных списков и списков по ссылке)."""
    stats = stats if stats is not None else {}
    kind = lst["kind"]
    if kind == "manual":
        stats["v6"] = count_ipv6(lst.get("source", ""))
        return parse_cidrs(lst.get("source", ""))
    if kind == "country":
        cc = lst["source"].lower()
        errors = []
        for tpl in COUNTRY_SOURCES:
            url = tpl.format(cc=cc)
            try:
                nets = parse_cidrs(_fetch(url), WIDE_MIN)
                if nets:
                    return nets
                errors.append(f"{url.split('/')[2]}: empty")
            except Exception as e:  # noqa: BLE001
                errors.append(f"{url.split('/')[2]}: {e}")
        raise ListError(Msg("list.fetch_failed", detail="; ".join(errors)))
    if kind == "asn":
        nets = []
        for asn in parse_asns(lst["source"]):
            nets.extend(_fetch_asn(asn))
        nets = list(ipaddress.collapse_addresses(nets))
        if not nets:
            raise ListError(Msg("list.empty"))
        return nets
    if kind == "url":
        nets = []
        stats["v6"] = 0
        for url in [u.strip() for u in lst["source"].split() if u.strip()]:
            text = _fetch(url)
            stats["v6"] += count_ipv6(text)
            nets.extend(parse_cidrs(text, WIDE_MIN))
        nets = list(ipaddress.collapse_addresses(nets))
        if not nets:
            raise ListError(Msg("list.empty"))
        return nets
    raise ListError(Msg("list.bad_kind", kind=kind))


def parse_asns(text: str) -> list[int]:
    """«AS13238, 15169 as47541» → [13238, 15169, 47541]"""
    out = []
    for tok in re.split(r"[,\s;]+", text or ""):
        m = re.fullmatch(r"(?i)(?:as)?(\d{1,10})", tok.strip())
        if m and 0 < int(m.group(1)) < 2 ** 32:
            out.append(int(m.group(1)))
    return list(dict.fromkeys(out))


def _fetch_asn(asn: int) -> list[ipaddress.IPv4Network]:
    errors = []
    for tpl in ASN_SOURCES:
        try:
            nets = parse_cidrs(_fetch(tpl.format(asn=asn)), WIDE_MIN)
            if nets:
                return nets
            errors.append("ipverse: empty")
        except Exception as e:  # noqa: BLE001
            errors.append(f"ipverse: {e}")
    try:
        import json
        data = json.loads(_fetch(RIPESTAT_URL.format(asn=asn), lines=False))
        nets = parse_cidrs("\n".join(p["prefix"] for p in data["data"]["prefixes"]), WIDE_MIN)
        if nets:
            return nets
        errors.append("ripestat: empty")
    except Exception as e:  # noqa: BLE001
        errors.append(f"ripestat: {e}")
    raise ListError(Msg("list.asn_failed", asn=asn, detail="; ".join(errors)))


class ListError(Exception):
    def __init__(self, msg: Msg):
        self.msg = msg
        super().__init__(str(msg))


_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def refresh(lst: dict) -> dict:
    """Обновляет файл списка; возвращает поля для записи в состояние. Один список обновляется одним
    потоком за раз: второй ждёт первого (фон, восстановление копии и кнопка «Обновить» могут совпасть)."""
    with _locks_guard:
        lock = _locks.setdefault(str(lst.get("id")), threading.Lock())
    with lock:
        return _refresh(lst)


def _refresh(lst: dict) -> dict:
    if lst["kind"] == "domains":
        try:
            names, errors = fetch_domains(lst)
        except ListError as e:
            return {"error": e.msg.to_json(), "checked": time.time()}
        except Exception as e:  # noqa: BLE001
            return {"error": Msg("list.fetch_failed", detail=str(e)[:300]).to_json(),
                    "checked": time.time()}
        err = Msg("list.fetch_failed", detail="; ".join(errors)[:300]).to_json() if errors else None
        if err and os.path.exists(domains.path_for(lst["id"])):
            # одна из ссылок не скачалась: без неё её домены пропали бы до следующего обновления (сутки), и
            # их сайты пошли бы мимо выхода — прежний список остаётся целиком, ошибка видна, попытка через 15 минут
            return {"error": err, "checked": time.time()}
        domains.save(lst["id"], names)
        # first — первый домен списка: им подписано правило со своим списком выхода («youtube.com +19»)
        return {"error": err, "count": len(names), "first": names[0][:80], "addresses": None, "skipped_v6": 0,
                "updated": time.time(), "checked": time.time()}
    stats: dict = {}
    try:
        nets = fetch_list(lst, stats)
    except ListError as e:
        return {"error": e.msg.to_json(), "checked": time.time()}
    except Exception as e:  # noqa: BLE001
        return {"error": Msg("list.fetch_failed", detail=str(e)[:300]).to_json(),
                "checked": time.time()}
    save_cidrs(lst["id"], nets)
    total = sum(n.num_addresses for n in nets)
    return {"error": None, "count": len(nets), "addresses": total, "skipped_v6": stats.get("v6", 0),
            "updated": time.time(), "checked": time.time()}


class Matcher:
    """Быстрая проверка вхождения IP в набор списков (для «проверки маршрута»)."""

    def __init__(self):
        self._cache: dict[str, tuple[float, list[int], list[int]]] = {}

    def _load(self, list_id: str):
        p = path_for(list_id)
        try:
            mtime = os.path.getmtime(p)
        except OSError:
            return [], []
        c = self._cache.get(list_id)
        if c and c[0] == mtime:
            return c[1], c[2]
        starts, ends = [], []
        for s in load_cidrs(list_id):
            n = ipaddress.IPv4Network(s)
            starts.append(int(n.network_address))
            ends.append(int(n.broadcast_address))
        self._cache[list_id] = (mtime, starts, ends)
        return starts, ends

    def contains(self, list_id: str, ip: str) -> str | None:
        starts, ends = self._load(list_id)
        x = int(ipaddress.IPv4Address(ip))
        i = bisect.bisect_right(starts, x) - 1
        if i >= 0 and x <= ends[i]:
            n = ipaddress.summarize_address_range(ipaddress.IPv4Address(starts[i]),
                                                  ipaddress.IPv4Address(ends[i]))
            return str(next(iter(n)))
        return None
