"""Списки сетей: страны, URL-списки, ручные CIDR."""
from __future__ import annotations

import bisect
import ipaddress
import os
import re
import time
import urllib.request

from . import config
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


def parse_cidrs(text: str) -> list[ipaddress.IPv4Network]:
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
                nets.append(ipaddress.IPv4Network(m.group(1), strict=False))
            except ValueError:
                continue
    return list(ipaddress.collapse_addresses(nets))


def path_for(list_id: str) -> str:
    return os.path.join(LISTS_DIR, f"{list_id}.txt")


def save_cidrs(list_id: str, nets: list[ipaddress.IPv4Network]) -> None:
    os.makedirs(LISTS_DIR, exist_ok=True)
    tmp = path_for(list_id) + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(str(n) for n in nets) + ("\n" if nets else ""))
    os.replace(tmp, path_for(list_id))


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


def _fetch(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "awg-router/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        if r.status != 200:
            raise RuntimeError(f"HTTP {r.status}")
        return r.read(64 * 1024 * 1024).decode("utf-8", errors="replace")


def fetch_list(lst: dict) -> list[ipaddress.IPv4Network]:
    """Скачивает/собирает список. Бросает исключение при неудаче."""
    kind = lst["kind"]
    if kind == "manual":
        return parse_cidrs(lst.get("source", ""))
    if kind == "country":
        cc = lst["source"].lower()
        errors = []
        for tpl in COUNTRY_SOURCES:
            url = tpl.format(cc=cc)
            try:
                nets = parse_cidrs(_fetch(url))
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
        for url in [u.strip() for u in lst["source"].split() if u.strip()]:
            nets.extend(parse_cidrs(_fetch(url)))
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
            nets = parse_cidrs(_fetch(tpl.format(asn=asn)))
            if nets:
                return nets
            errors.append("ipverse: empty")
        except Exception as e:  # noqa: BLE001
            errors.append(f"ipverse: {e}")
    try:
        import json
        data = json.loads(_fetch(RIPESTAT_URL.format(asn=asn)))
        nets = parse_cidrs("\n".join(p["prefix"] for p in data["data"]["prefixes"]))
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


def refresh(lst: dict) -> dict:
    """Обновляет файл списка; возвращает поля для записи в состояние."""
    try:
        nets = fetch_list(lst)
    except ListError as e:
        return {"error": e.msg.to_json(), "checked": time.time()}
    except Exception as e:  # noqa: BLE001
        return {"error": Msg("list.fetch_failed", detail=str(e)[:300]).to_json(),
                "checked": time.time()}
    save_cidrs(lst["id"], nets)
    total = sum(n.num_addresses for n in nets)
    return {"error": None, "count": len(nets), "addresses": total,
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
