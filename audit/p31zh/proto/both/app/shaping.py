"""Ограничение скорости: очереди tc (HTB) на интерфейсах сервера AWG. Только генерация команд —
запускает их движок (Engine._sync_shaping) в сети сервера AWG.

Где ограничиваем:
  * клиенты — на интерфейсе клиентов (awg0): через него идёт весь трафик клиента, куда бы он ни
    уходил дальше (выход AWG, SOCKS5, напрямую, sniproxy.py, DNS панели). Загрузка к клиенту —
    исходящая очередь awg0; отдача от клиента — входящий трафик awg0, перенаправленный на ifb awgq0
    (у входящего трафика очереди нет, а у ifb — обычная исходящая);
  * выход N — на его туннеле awgrN: отдача в выход — исходящая очередь awgrN, загрузка из выхода —
    вход awgrN через ifb awgqN.
Пакет после ifb возвращается в сеть как пришедший на исходный интерфейс: правила nftables, учёт
трафика и маршруты видят его так же, как без ограничения.

Дерево HTB клиентов: корень — общий лимит; при общем лимите у каждого клиента свой класс с равной
гарантированной долей (свободное занимают те, кто качает), без общего — классы только у клиентов
с личным лимитом. Класс по умолчанию — остальные адреса. В листьях fq_codel: под нагрузкой не
растёт задержка. Класс клиента выбирает фильтр u32 с хеш-таблицей по последнему байту адреса —
поиск не зависит от числа клиентов.

Все наши корневые очереди — с главным номером HANDLE: по нему чужие очереди не трогаются.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json

HANDLE = "7a77"            # главный номер наших корневых qdisc (hex)
IFB_PREFIX = "awgq"        # awgq0 — вход awg0 (отдача клиентов), awgqN — вход выхода awgrN
MIN_MBIT = 0.1
MAX_MBIT = 100_000         # 100 Гбит/с: и предел ввода, и «без общего лимита» у корня дерева
DEFAULT_MINOR = 2          # класс по умолчанию; клиенты — с CLIENT_MINOR
CLIENT_MINOR = 0x100
HASH_HT = 2                # номер хеш-таблицы u32


def ifb_for(num: int) -> str:
    """ifb для входящего трафика: 0 — интерфейс клиентов, N — выход N."""
    return f"{IFB_PREFIX}{int(num)}"


def mbit(v) -> float | None:
    """Значение из настроек → Мбит/с или None (без ограничения)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return float(v) if MIN_MBIT <= v <= MAX_MBIT else None


def _rate(m: float) -> str:
    return f"{max(1, int(round(m * 1000)))}kbit"


def _bytes(m: float) -> int:
    return int(m * 1_000_000 / 8)


def _sizes(rate: float, ceil: float) -> tuple[int, int]:
    # burst — 10 мс на полной скорости, не меньше 64 КБ: пакеты GSO у туннелей бывают до 64 КБ,
    # и с маленьким burst класс не добирал бы до своей скорости
    return max(_bytes(ceil) // 100, 65536), max(1514, min(_bytes(rate) // 10, 60000))


def _class(dev: str, parent: str, minor: int, rate: float, ceil: float) -> str:
    b, q = _sizes(rate, ceil)
    return (f"class add dev {dev} parent {parent} classid {HANDLE}:{minor:x} htb rate {_rate(rate)} "
            f"ceil {_rate(ceil)} burst {b} cburst {b} quantum {q}")


def cap_change(dev: str, m: float) -> list[str]:
    """Команда смены скорости класса cap_tree(dev, m) без пересоздания очереди: {kbit} — новая скорость
    в кбит/с (её подставляет sniproxy.py, когда делит предел выхода SOCKS5 со своими соединениями)."""
    b, q = _sizes(m, m)
    return ["tc", "class", "change", "dev", dev, "parent", f"{HANDLE}:", "classid", f"{HANDLE}:1", "htb",
            "rate", "{kbit}kbit", "ceil", "{kbit}kbit", "burst", str(b), "cburst", str(b), "quantum", str(q)]


def _leaf(dev: str, minor: int) -> str:
    return f"qdisc add dev {dev} parent {HANDLE}:{minor:x} fq_codel"


def client_tree(dev: str, total: float | None, caps: dict[str, float | None], key: str) -> list[str]:
    """Команды tc -batch для дерева клиентов на dev. total — общий лимит (Мбит/с) или None;
    caps — {IP клиента: личный лимит или None}; key — "dst" (загрузка к клиенту) или "src" (отдача).
    Пустой список — ограничивать нечего."""
    own = {ip: c for ip, c in caps.items() if c}
    if not total and not own:
        return []
    root = total or MAX_MBIT
    # при общем лимите — класс у каждого клиента (равная доля), без него — только у ограниченных
    members = sorted(caps if total else own, key=lambda ip: int(ipaddress.IPv4Address(ip)))
    share = root / (len(members) + 1)
    off = 16 if key == "dst" else 12
    cmds = [f"qdisc add dev {dev} root handle {HANDLE}: htb default {DEFAULT_MINOR:x}",
            _class(dev, f"{HANDLE}:", 1, root, root),
            _class(dev, f"{HANDLE}:1", DEFAULT_MINOR, share, root), _leaf(dev, DEFAULT_MINOR)]
    if not members:
        return cmds
    flt = f"filter add dev {dev} parent {HANDLE}: protocol ip prio 10"
    cmds += [f"{flt} u32",
             f"{flt} handle {HASH_HT}: u32 divisor 256",
             f"{flt} u32 ht 800:: match u32 0 0 hashkey mask 0x000000ff at {off} link {HASH_HT}:"]
    for i, ip in enumerate(members):
        minor = CLIENT_MINOR + i
        ceil = min(caps.get(ip) or root, root)
        cmds += [_class(dev, f"{HANDLE}:1", minor, min(share, ceil), ceil), _leaf(dev, minor),
                 f"{flt} u32 ht {HASH_HT}:{int(ip.rsplit('.', 1)[1]):x}: match ip {key} {ip}/32 "
                 f"flowid {HANDLE}:{minor:x}"]
    return cmds


def cap_tree(dev: str, m: float) -> list[str]:
    """Одно ограничение на весь интерфейс (выход)."""
    return [f"qdisc add dev {dev} root handle {HANDLE}: htb default 1",
            _class(dev, f"{HANDLE}:", 1, m, m), _leaf(dev, 1)]


def redirect(dev: str, ifb: str) -> list[str]:
    """Входящий трафик dev → ifb (там его ограничивает исходящая очередь ifb)."""
    return [f"qdisc add dev {dev} handle ffff: ingress",
            f"filter add dev {dev} parent ffff: protocol all prio 1 matchall action mirred egress redirect dev {ifb}"]


def plan(wg_iface: str, total: dict, clients: dict[str, dict], exits: list[dict]) -> dict:
    """Что должно стоять на интерфейсах.

    total — {"down", "up"} в Мбит/с (общий лимит клиентов); clients — {IP: {"down", "up"}};
    exits — [{"num", "iface", "down", "up"}] запущенных выходов.
    → {"roots": {интерфейс: [команды]}, "ingress": {интерфейс: ifb}}: корневые очереди (на ifb
    тоже) и перенаправления входящего трафика. Ничего не задано — пустые словари."""
    roots: dict[str, list[str]] = {}
    ingress: dict[str, str] = {}
    td, tu = mbit((total or {}).get("down")), mbit((total or {}).get("up"))
    down = client_tree(wg_iface, td, {ip: mbit(c.get("down")) for ip, c in clients.items()}, "dst")
    if down:
        roots[wg_iface] = down
    ifb = ifb_for(0)
    up = client_tree(ifb, tu, {ip: mbit(c.get("up")) for ip, c in clients.items()}, "src")
    if up:
        roots[ifb] = up
        ingress[wg_iface] = ifb
    for e in exits:
        dev = e["iface"]
        if mbit(e.get("up")):
            roots[dev] = cap_tree(dev, mbit(e["up"]))
        if mbit(e.get("down")):
            ifb = ifb_for(e["num"])
            roots[ifb] = cap_tree(ifb, mbit(e["down"]))
            ingress[dev] = ifb
    return {"roots": roots, "ingress": ingress}


def digest(cmds: list[str]) -> str:
    return hashlib.sha256(json.dumps(cmds).encode()).hexdigest()[:16]


def parse_qdiscs(text: str) -> tuple[set[str], set[str]]:
    """`tc -j qdisc show` → (интерфейсы с нашей корневой очередью, интерфейсы с очередью ingress)."""
    try:
        items = json.loads(text or "[]")
    except ValueError:
        return set(), set()
    ours, ing = set(), set()
    for q in items if isinstance(items, list) else []:
        if not isinstance(q, dict) or not isinstance(q.get("dev"), str):
            continue
        if q.get("kind") == "ingress":
            ing.add(q["dev"])
        elif q.get("root") and q.get("handle") == HANDLE + ":":
            ours.add(q["dev"])
    return ours, ing
