"""Списки доменов: разбор распространённых форматов и проверка «домен или его поддомен».

Правило по домену действует на TCP 80/443: sniproxy.py узнаёт сайт по имени в начале
соединения (SNI у HTTPS, Host у HTTP) и ведёт его на выход правила (SOCKS5 — по имени).
Запись `example.com` подходит для `example.com` и всех `*.example.com`.
"""
from __future__ import annotations

import os
import re
import tempfile

from . import config

LISTS_DIR = os.path.join(config.DATA_DIR, "lists")
MAX_DOMAINS = 300_000

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)\Z")
# dnsmasq: server=/a.com/b.com/1.1.1.1, nftset=/a.com/…, ipset=/a.com/…, address=/a.com/…
_DNSMASQ = re.compile(r"^(?:server|nftset|ipset|address|local)=/([^#]*?)/[^/]*\Z")
_HOSTS_IP = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]*)\Z", re.I)


def normalize(name: str) -> str | None:
    """Домен в каноническом виде (строчные, без точки в конце, IDN → punycode) или None."""
    s = name.strip().strip(".").lower()
    if s.startswith("*."):
        s = s[2:]
    if not s or len(s) > 253:
        return None
    if any(ord(ch) > 127 for ch in s):
        try:
            s = s.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    labels = s.split(".")
    if not all(_LABEL.match(x) for x in labels):
        return None
    if labels[-1].isdigit():            # IP-адрес — не домен
        return None
    return s


def _candidates(line: str) -> list[str]:
    """Строка любого из поддерживаемых форматов → кандидаты в домены."""
    s = line.strip()
    if not s or s[0] in "#!;[" or s.startswith("//"):
        return []
    s = re.split(r"\s#|\s//", s, maxsplit=1)[0].strip()
    m = _DNSMASQ.match(s)
    if m:
        return [d for d in m.group(1).split("/") if d]
    if s.startswith("||"):                                  # Adblock: ||example.com^
        s = s[2:].split("^", 1)[0].split("$", 1)[0]
        return [s] if "/" not in s and "*" not in s else []
    low = s.lower()
    for p in ("domain:", "full:", "domain-suffix,", "domain,", "host-suffix,", "host,", "+."):
        if low.startswith(p):                               # v2ray / Clash / Surge
            return [s[len(p):].split(",", 1)[0].split(":@", 1)[0]]
    if low.startswith(("regexp:", "keyword:", "include:", "domain-keyword,", "ip-cidr", "geoip")):
        return []
    parts = s.split()
    if len(parts) >= 2 and _HOSTS_IP.match(parts[0]):        # hosts: 0.0.0.0 example.com
        return parts[1:]
    if len(parts) == 1:
        tok = parts[0]
        if "://" in tok:                                    # https://example.com/path → example.com
            tok = tok.split("://", 1)[1].split("/", 1)[0].split("@")[-1].rsplit(":", 1)[0]
        return [tok.split(",", 1)[0]]
    return []


def parse(text: str) -> list[str]:
    """Текст списка → домены без повторов, в исходном порядке. Поддомены уже вошедших
    доменов отбрасываются: `example.com` их и так покрывает."""
    seen: dict[str, None] = {}
    for line in text.splitlines():
        for c in _candidates(line):
            d = normalize(c)
            if d:
                seen[d] = None
    return compact(list(seen))


def compact(names: list[str]) -> list[str]:
    have = set(names)
    out = []
    for d in names:
        labels = d.split(".")
        if any(".".join(labels[i:]) in have for i in range(1, len(labels))):
            continue
        out.append(d)
    return out


def is_url(line: str) -> bool:
    return bool(re.match(r"^https?://\S+\Z", line.strip()))


def split_source(text: str) -> tuple[list[str], str]:
    """Источник списка доменов: строки-ссылки (их содержимое скачивается) и остальной текст."""
    urls, rest = [], []
    for line in text.splitlines():
        (urls if is_url(line) else rest).append(line.strip() if is_url(line) else line)
    return urls, "\n".join(rest)


def matches(name: str, domains: set[str]) -> str | None:
    """Запись списка, которой соответствует имя (оно само или его родитель), или None."""
    if len(name) > 254:
        return None
    labels = name.strip(".").lower().split(".")
    for i in range(len(labels)):
        d = ".".join(labels[i:])
        if d in domains:
            return d
    return None


# ------------------------------------------------------------------ файлы
def path_for(list_id: str) -> str:
    return os.path.join(LISTS_DIR, f"{list_id}.domains")


def write_atomic(path: str, text: str) -> None:
    """Файл списка целиком или никак: временный файл со своим именем (два обновления одного списка
    одновременно — фон, восстановление копии, кнопка — писали бы в один .tmp вперемешку) и os.replace."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save(list_id: str, names: list[str]) -> None:
    write_atomic(path_for(list_id), "\n".join(names) + ("\n" if names else ""))


def load(list_id: str) -> list[str]:
    try:
        with open(path_for(list_id)) as f:
            return [x.strip() for x in f if x.strip()]
    except FileNotFoundError:
        return []


def delete(list_id: str) -> None:
    try:
        os.remove(path_for(list_id))
    except FileNotFoundError:
        pass


class Matcher:
    """Проверка «домен в списке» для «проверки маршрута»: файл списка читается построчно на каждую проверку, а не
    держится в памяти множеством. Кэш множеств оставался в панели навсегда после первой проверки: список в
    300 000 доменов — около 36 МБ на сервере с 1 ГБ (оптимизация 2026-11-21); чтение такого файла — доли секунды,
    а проверку маршрута нажимают руками."""

    def match(self, list_id: str, name: str) -> str | None:
        """То же, что matches(name, set(load(list_id))): самая длинная запись — имя само или ближайший родитель."""
        if len(name) > 254:
            return None
        labels = name.strip(".").lower().split(".")
        want = {".".join(labels[i:]): i for i in range(len(labels))}
        best: tuple[int, str] | None = None
        try:
            with open(path_for(list_id)) as f:
                for line in f:
                    s = line.strip()
                    i = want.get(s) if s else None
                    if i is not None and (best is None or i < best[0]):
                        best = (i, s)
                        if i == 0:
                            break
        except OSError:
            return None
        return best[1] if best else None
