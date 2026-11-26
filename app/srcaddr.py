"""Исходящие адреса сервера (1.25.0): с какого IPv4 сервера уходит «Напрямую» и с какого он подключается к выходам.

В панели выход «Напрямую» бывает с адресом: «Напрямую — 198.51.100.7». В памяти панели (Store.state, проверки, движок)
это одна строка "direct@198.51.100.7" в поле выхода; просто "direct" — основной исходящий адрес сервера
(settings.out_main: пусто — адрес системы, иначе один из дополнительных settings.out_hosts); "direct@system" — адрес
системы, когда основным выбран дополнительный.

На диске (state.json) и в резервной копии — как поймёт панель до 1.25.0: в поле выхода "direct", адрес — рядом, в поле
«<поле>_src» (to_disk / from_disk). Прежний выпуск, запущенный на этих файлах, не знает «_src» и ведёт всё по «Напрямую»
с адреса системы, а не в блок: неизвестный выход nftgen 1.24.0 превратил бы в «блок» (откат на 1.24.x, решение
владельца 2026-11-26), а clean_backup_state 1.24.0 и так выбрасывает незнакомые поля.

Подключение выхода к другому серверу (окно выхода, «Подключаться с адреса») — поле выхода "bind": пусто — основной
адрес, "system" или один из out_hosts. Адреса — свои у сервера: из копии не берутся (restore_state), а места, где в копии
стоит адрес, которого у этого сервера нет, переходят на основной (normalize)."""
from __future__ import annotations

import copy
import ipaddress
import re

from .i18n import Msg

DIRECT = "direct"
PFX = "direct@"
SYSTEM = "system"
OUT_HOSTS_MAX = 16          # дополнительных исходящих адресов (столько номеров меток и таблиц маршрутов)
SUFFIX = "_src"


def ipv4(v) -> str | None:
    """Строка IPv4 в обычном виде или None."""
    if not isinstance(v, str):
        return None
    try:
        return str(ipaddress.IPv4Address(v.strip()))
    except ValueError:
        return None


def valid(a) -> bool:
    """Годится как адрес «Напрямую — …» (по записи, без проверки, есть ли он у сервера): system или IPv4."""
    return a == SYSTEM or (isinstance(a, str) and ipv4(a) == a)


def split(v) -> tuple[str, str | None]:
    """«direct@a» → ("direct", "a"); всё остальное → (v, None)."""
    if isinstance(v, str) and v.startswith(PFX):
        return DIRECT, v[len(PFX):]
    return v, None


def is_direct(v) -> bool:
    return v == DIRECT or (isinstance(v, str) and v.startswith(PFX))


def out_hosts(st: dict) -> list[str]:
    v = (st.get("settings") or {}).get("out_hosts")
    return [a for a in v if ipv4(a) == a] if isinstance(v, list) else []


def main(st: dict) -> str:
    """Основной исходящий адрес: "" — адрес системы, иначе IPv4 из out_hosts."""
    m = (st.get("settings") or {}).get("out_main") or ""
    return m if m in out_hosts(st) else ""


# ------------------------------------------------------------------ где стоит выход
def _rule_slots(rule: dict, label):
    yield rule, "outbound", label
    yield rule, "balance_fb", label
    yield rule, "quota_action", label


def slots(st: dict):
    """Все поля выхода в состоянии: (объект, имя поля, подпись места — Msg или None)."""
    from .store import Store
    r = st.get("routing")
    if isinstance(r, dict):
        yield r, "default", Msg("ref.default")
        for i, rule in enumerate(r.get("rules") or []):
            if isinstance(rule, dict):
                yield from _rule_slots(rule, Store._rule_ref(rule, i))
    for u in st.get("upstreams") or []:
        if isinstance(u, dict):
            yield u, "fallback", Msg("ref.fallback", name=u.get("name") or "")
            yield u, "quota_action", Msg("ref.quota", name=u.get("name") or "")
    for pk, c in (st.get("clients") or {}).items():
        if not isinstance(c, dict):
            continue
        name = c.get("name") or str(pk)[:8]
        yield c, "outbound", Msg("ref.client", client=name)
        for i, rule in enumerate(c.get("rules") or []):
            if isinstance(rule, dict):
                yield from _rule_slots(rule, Store._rule_ref(rule, i, name))
    tg = (st.get("settings") or {}).get("telegram")
    if isinstance(tg, dict):
        yield tg, "via", Msg("ref.telegram")


def pinned(st: dict) -> bool:
    """Есть ли в состоянии адреса «Напрямую — …» (в памяти или на диске)."""
    return any(isinstance(o.get(f), str) and o[f].startswith(PFX) for o, f, _ in slots(st)) or \
        any(isinstance(o, dict) and (f + SUFFIX) in o for o, f, _ in slots(st))


def to_disk(st: dict) -> dict:
    """Состояние для state.json и резервной копии: "direct@a" → "direct" и «<поле>_src»: "a". Без адресов — то же
    самое состояние (без копии): так почти у всех, а запись идёт на каждое изменение."""
    if not pinned(st):
        return st
    out = copy.deepcopy(st)
    for o, f, _ in slots(out):
        o.pop(f + SUFFIX, None)
        v, a = split(o.get(f))
        if a is not None:
            o[f], o[f + SUFFIX] = v, a
    return out


def from_disk(st: dict) -> dict:
    """Обратно: "direct" и «<поле>_src» → "direct@a" (в том же состоянии). «_src» у выхода, который не «Напрямую», и
    неверный адрес выбрасываются: остаётся основной адрес, как у панели до 1.25.0."""
    for o, f, _ in slots(st):
        a = o.pop(f + SUFFIX, None)
        if o.get(f) == DIRECT and valid(a):
            o[f] = PFX + a
    return st


def fold(st: dict, v: str) -> str:
    """«Напрямую — основной адрес» записывается просто "direct": он и переезжает при смене основного."""
    _, a = split(v)
    if a is None:
        return v
    m = main(st)
    return DIRECT if (a == SYSTEM and not m) or a == m else v


def normalize(st: dict, moved: list | None = None) -> bool:
    """Привести адреса к тем, что есть у сервера: основной — "direct"; адрес, которого больше нет (убрали из списка,
    копия с другого сервера), — тоже "direct" (основной), а его место — в moved (для сообщения). Так же — адрес
    подключения выходов (bind) и «С какого адреса выходит сам сервер» (own_src). True — что-то поменялось."""
    moved = [] if moved is None else moved
    known = set(out_hosts(st))
    s = st.setdefault("settings", {})
    changed = False
    if "out_main" in s and (not s["out_main"] or s["out_main"] not in known):
        s.pop("out_main")
        changed = True
    for o, f, label in slots(st):
        v, a = split(o.get(f))
        if a is None:
            continue
        if a != SYSTEM and a not in known:
            o[f] = DIRECT
            if label is not None:
                moved.append(label)
        else:
            o[f] = fold(st, o[f])
        changed = changed or o[f] != PFX + a
    m = main(st)
    for u in st.get("upstreams") or []:
        if not isinstance(u, dict) or "bind" not in u:
            continue
        b = u["bind"]
        if b != SYSTEM and b not in known:
            if b:
                moved.append(Msg("ref.exit_bind", name=u.get("name") or ""))
            u.pop("bind")
            changed = True
        elif (b == SYSTEM and not m) or b == m:
            u.pop("bind")
            changed = True
    if "own_src" in s and (not s["own_src"] or s["own_src"] not in known):
        s.pop("own_src")
        changed = True
    return changed


def refs(st: dict, a: str) -> list[Msg]:
    """Где стоит исходящий адрес a (IPv4 или system): «Напрямую — a» в выборе выхода и подключение выходов. Основной
    адрес стоит и везде, где выбрано просто «Напрямую» (первая строка выбора)."""
    m = main(st) or SYSTEM
    out = [label for o, f, label in slots(st) if label is not None and (
        o.get(f) == PFX + a or (a == m and o.get(f) == DIRECT))]
    for u in st.get("upstreams") or []:
        b = (u.get("bind") or m) if isinstance(u, dict) else None
        if b == a and isinstance(u, dict):
            out.append(Msg("ref.exit_bind", name=u.get("name") or ""))
    if (st.get("settings") or {}).get("own_src") == a:
        out.append(Msg("ref.own_src"))
    return out


def bind_of(st: dict, u: dict) -> str:
    """С какого адреса выход подключается к своему серверу: system или IPv4 (основной, если не задан)."""
    b = u.get("bind") or ""
    known = set(out_hosts(st))
    if b == SYSTEM or b in known:
        return b
    return main(st) or SYSTEM


# ------------------------------------------------------------------ ввод
_SPLIT = re.compile(r"[,\s]+")


class AddrError(ValueError):
    def __init__(self, msg: Msg):
        super().__init__(str(msg))
        self.msg = msg


def parse_out_hosts(value) -> list[str]:
    """Дополнительные исходящие адреса: только IPv4 (через запятую, пробел, перевод строки — или списком). Домен —
    ошибка: адрес добавляется в систему сервера, а домен туда не добавить."""
    if isinstance(value, str):
        items = _SPLIT.split(value)
    elif isinstance(value, list) and all(isinstance(x, str) for x in value):
        items = value
    else:
        raise AddrError(Msg("err.bad_value"))
    out = []
    for raw in items:
        h = raw.strip()
        if not h:
            continue
        a = ipv4(h)
        if a is None or not usable(a):
            raise AddrError(Msg("srv.bad_out_host", value=h[:60]))
        if a not in out:
            out.append(a)
    if len(out) > OUT_HOSTS_MAX:
        raise AddrError(Msg("srv.out_hosts_max", n=OUT_HOSTS_MAX))
    return out


def usable(a: str) -> bool:
    """Адрес, с которого можно выходить в интернет: не 0.0.0.0/8, не 127/8, не link-local, не групповой и не служебный."""
    ip = ipaddress.IPv4Address(a)
    return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved
                or int(ip) >> 24 == 0 or ip == ipaddress.IPv4Address("255.255.255.255"))
