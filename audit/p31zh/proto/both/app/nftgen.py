"""Генерация набора правил nftables (чистая функция, легко тестировать).

Логика для пакета, пришедшего от клиента сервера (iif = wg0/awg0):
  1. локальные/приватные адреса — не трогаем (идут как обычно);
  2. IP клиента ищется в карте clients → цепочка его личной политики,
     иначе — глобальная политика;
  3. политика проверяет правила по порядку (ip daddr @список → выход),
     затем выход по умолчанию;
  4. выход = метка fwmark → ip rule → отдельная таблица маршрутизации
     с маршрутом в нужный туннель (или без метки = напрямую через eth0).
"""
from __future__ import annotations

import itertools

from . import config

LOCAL_NETS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
]


# Сеть link-local: в облаках там служебный адрес 169.254.169.254 (данные сервера, у AWS — и ключи доступа к
# облаку). Клиентам VPN он не нужен, а маршрутизаторы такие адреса и так не пересылают (RFC 3927)
LINK_LOCAL = "169.254.0.0/16"
# служебный адрес Alibaba Cloud (данные сервера и ключи роли RAM): он в 100.64.0.0/10, а не в link-local
CLOUD_META = "100.100.100.200"

ACCT_TABLE = "awgr_acct"
ACCT_VER = 1


def acct_marker(wg_iface: str) -> str:
    """Метка в комментарии правила: по ней видно, что таблица учёта наша и актуальна."""
    return f"awgr-acct {ACCT_VER} {wg_iface}"


def acct_ruleset(wg_iface: str) -> str:
    """Отдельная таблица учёта трафика по выходам.

    Только считает: никаких меток, маршрутов и запретов, поэтому на маршрутизацию не
    влияет. Основная таблица пересоздаётся при каждом изменении правил, а эта — только
    когда её нет (иначе счётчики обнулялись бы). Ключ — адрес клиента и «другой»
    интерфейс пакета: awgrN — выход N, всё остальное — напрямую. Цепочка стоит после
    c_forward, поэтому заблокированный трафик (reject там) сюда не доходит.
    Счётчик задан в правиле, а не в наборе: так работает и на ядрах до 5.11."""
    T = ACCT_TABLE
    w = wg_iface
    sets = "".join(f"""\tset {name} {{
\t\ttype ipv4_addr . ifname
\t\tsize 65535
\t\tflags dynamic
\t}}
""" for name in ("up", "down"))
    return f"""table ip {T}
delete table ip {T}
table ip {T} {{
{sets}\tchain c_acct {{
\t\ttype filter hook forward priority filter + 10; policy accept;
\t\tiifname "{w}" oifname != "{w}" update @up {{ ip saddr . oifname counter }} comment "{acct_marker(w)}"
\t\toifname "{w}" iifname != "{w}" update @down {{ ip daddr . iifname counter }}
\t}}
}}
"""


def parse_acct(data: dict, wg_iface: str) -> dict[tuple[str, str], list[int]] | None:
    """`nft -j list table ip awgr_acct` → {(ip, интерфейс): [от клиента, к клиенту]}.
    None — таблица не наша или устарела (нужно пересоздать)."""
    items = data.get("nftables") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return None
    marker = acct_marker(wg_iface)
    if not any(isinstance(x, dict) and isinstance(x.get("rule"), dict)
               and x["rule"].get("comment") == marker for x in items):
        return None
    out: dict[tuple[str, str], list[int]] = {}
    for x in items:
        s = x.get("set") if isinstance(x, dict) else None
        if not isinstance(s, dict) or s.get("table") != ACCT_TABLE or s.get("name") not in ("up", "down"):
            continue
        i = 0 if s["name"] == "up" else 1
        for e in s.get("elem") or []:
            e = e.get("elem") if isinstance(e, dict) else None
            if not isinstance(e, dict):
                continue
            key = (e.get("val") or {}).get("concat") if isinstance(e.get("val"), dict) else None
            cnt = e.get("counter") or {}
            b = cnt.get("bytes") if isinstance(cnt, dict) else None
            if not (isinstance(key, list) and len(key) == 2 and all(isinstance(k, str) for k in key)
                    and isinstance(b, int) and b >= 0):
                continue
            out.setdefault((key[0], key[1]), [0, 0])[i] = b
    return out


RACCT_TABLE = "awgr_racct"
RACCT_VER = 1


def racct_marker(wg_iface: str) -> str:
    return f"awgr-racct {RACCT_VER} {wg_iface}"


def racct_ruleset(wg_iface: str, slots) -> str:
    """Учёт трафика по правилам (1.24.0): счётчик на пару «адрес клиента + номер правила» по метке соединения
    (ct label), которую ставят цепочки политик (_policy_chain с labels). Отдельная таблица, как awgr_acct: основная
    пересоздаётся при каждой правке, а эта — никогда. Строки по номерам правил меняются (их столько, сколько
    номеров в политиках), поэтому цепочки очищаются и пишутся заново, а наборы со счётчиками остаются (add —
    без ошибки, если набор уже есть). Только считает: на путь пакетов не влияет."""
    T, w = RACCT_TABLE, wg_iface
    out = [f"table ip {T} {{}}"]
    for name in ("up", "down"):
        out.append(f"add set ip {T} {name} {{ type ipv4_addr . mark; size 65535; flags dynamic; }}")
    out.append(f"add chain ip {T} c_racct {{ type filter hook forward priority filter + 11; policy accept; }}")
    for c in ("c_racct", "r_up", "r_down"):
        out.append(f"add chain ip {T} {c}")
        out.append(f"flush chain ip {T} {c}")
    out.append(f'add rule ip {T} c_racct iifname "{w}" oifname != "{w}" jump r_up comment "{racct_marker(w)}"')
    out.append(f'add rule ip {T} c_racct oifname "{w}" iifname != "{w}" jump r_down')
    for k in sorted({int(x) for x in slots}):
        out.append(f"add rule ip {T} r_up ct label {k} update @up {{ ip saddr . {k:#x} counter }} return")
        out.append(f"add rule ip {T} r_down ct label {k} update @down {{ ip daddr . {k:#x} counter }} return")
    return "\n".join(out) + "\n"


def parse_racct(data: dict, wg_iface: str) -> dict[tuple[str, int], list[int]] | None:
    """`nft -j list table ip awgr_racct` → {(ip, номер правила): [от клиента, к клиенту]}. None — таблицы нет или
    она не наша (её нужно поставить заново: наборы, если есть, останутся со своими счётчиками)."""
    items = data.get("nftables") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return None
    marker = racct_marker(wg_iface)
    if not any(isinstance(x, dict) and isinstance(x.get("rule"), dict)
               and x["rule"].get("comment") == marker for x in items):
        return None
    out: dict[tuple[str, int], list[int]] = {}
    for x in items:
        st = x.get("set") if isinstance(x, dict) else None
        if not isinstance(st, dict) or st.get("table") != RACCT_TABLE or st.get("name") not in ("up", "down"):
            continue
        i = 0 if st["name"] == "up" else 1
        for e in st.get("elem") or []:
            if not isinstance(e, dict):
                continue
            el = e.get("elem") if isinstance(e.get("elem"), dict) else e
            key = (el.get("val") or {}).get("concat") if isinstance(el.get("val"), dict) else None
            cnt = el.get("counter") or {}
            b = cnt.get("bytes") if isinstance(cnt, dict) else None
            if not (isinstance(key, list) and len(key) == 2 and isinstance(key[0], str) and isinstance(b, int)
                    and b >= 0 and isinstance(key[1], int) and 0 <= key[1] <= config.RULE_DEFAULT_SLOT):
                continue
            out.setdefault((key[0], key[1]), [0, 0])[i] = b
    return out


class Sticky(int):
    """Выход N с запоминанием выхода у соединения (балансировка): первый пакет соединения
    записывает метку выхода в conntrack (ct mark), следующие берут её оттуда, пока этот выход
    среди рабочих выходов балансировки. Поэтому перенос клиента на другой выход не рвёт его открытые
    соединения: новые идут через новый выход, старые доживают на прежнем. Во всём остальном — то же
    число N (метка, таблица, учёт)."""
    __slots__ = ()

    def __repr__(self) -> str:
        return f"Sticky({int(self)})"


class Addr(str):
    """«Напрямую» с дополнительного исходящего адреса (1.25.0): строка "direct@<адрес>" (так её видят браузер, журнал и
    ключи политик sniproxy.py), k — номер адреса: метка addr_mark(k) → ip rule → своя таблица маршрутов. Не число: везде,
    где isinstance(…, int), — выход через туннель, а это не он."""

    def __new__(cls, ip: str, k: int):
        o = str.__new__(cls, "direct@" + ip)
        o.ip, o.k = ip, int(k)
        return o

    def __repr__(self) -> str:
        return f"Addr({self.ip!r}, {self.k})"


def addr_mark(k: int) -> int:
    return config.ADDR_MARK_BASE + int(k)


ADDR_LO, ADDR_HI = config.ADDR_MARK_BASE + 1, config.ADDR_MARK_BASE + config.ADDR_MAX


def out_chain(out) -> str:
    if isinstance(out, Addr):
        return f"o_a{out.k}"
    if out == "direct":
        return "o_direct"
    if out == "block":
        return "o_block"
    if isinstance(out, Sticky):
        return f"ob_u{int(out)}"
    return f"o_u{int(out)}"


def _mss(match: str, u: dict) -> str:
    """MSS clamp под MTU туннеля выхода: пересылка в обе стороны (c_forward) и свои соединения sniproxy.py (c_mss_out)."""
    mss = int(u.get("mtu", 1280)) - 40
    return f"\t\t{match} tcp flags & (syn | rst) == syn tcp option maxseg size > {mss} tcp option maxseg size set {mss}"


def _okey(o):
    """Выход в ключе политики: Sticky(N) и N — разные цепочки; адрес — по номеру."""
    if isinstance(o, Addr):
        return ("addr", o.k)
    return ("sticky", int(o)) if isinstance(o, Sticky) else o


def _no_quic(block: bool) -> str:
    """Строка выхода без QUIC (SOCKS5 без галочки): UDP 443 — отказ, браузер сразу берёт TCP."""
    return f"\t\tudp dport 443 meta mark set {config.MARK_BLOCK:#x} accept\n" if block else ""


def _sticky_chain(name: str, num: int, alive: list[int], no_quic: bool = False, quic: bool = False) -> str:
    marks = ", ".join(f"{mark_for(n):#x}" for n in alive)
    m = mark_for(num)
    # QUIC «пропустить» (очередь, сайт не из правил): решение — этот выход, и оно остаётся в conntrack
    # с QUIC_CT_BIT, иначе после ответа сервера строка блока QUIC в политике оборвала бы соединение
    qpass = (f"\t\tudp dport 443 meta mark {config.QUIC_PASS_MARK:#x} meta mark set {m:#x} "
             f"ct mark set {m | config.QUIC_CT_BIT:#x} accept\n") if quic else ""
    # соединение, уже записанное на рабочий выход, доживает на нём; новое QUIC к выходу без QUIC — отказ
    return (f"\tchain {name} {{\n\t\tct mark {{ {marks} }} meta mark set ct mark accept\n{_no_quic(no_quic)}"
            f"{qpass}\t\tmeta mark set {m:#x} ct mark set {m:#x} accept\n\t}}")


def mark_for(num: int) -> int:
    return config.MARK_BASE + num


def _policy_key(policy: dict) -> tuple:
    key = (tuple((tuple(l), _okey(o)) for l, o in policy["rules"]), _okey(policy["default"]),
           tuple((tuple(l), str(o)) for l, o in policy.get("domain") or ()))
    if policy.get("dns"):          # без своего DNS ключ прежний: номера политик sniproxy.py не сдвигаются
        key += (tuple((tuple(l), str(o), tuple(d)) for l, o, d in policy["dns"]),)
    if policy.get("slots") is not None:
        # учёт по правилам (1.24.0): одинаковые правила в разном порядке — разные номера меток, значит разные политики
        key += (("slots", tuple(policy["slots"]), tuple(policy.get("dslots") or ())),)
    if policy.get("lims") is not None:
        # ограничения скорости правил (1.24.0): у одинаковых правил двух клиентов свои ограничения — свои политики
        key += (("lims", tuple(policy["lims"]), tuple(policy.get("dlims") or ())),)
    return key


def _set_block(name: str, cidrs: list[str], comment: str = "") -> str:
    lines = [f"\tset {name} {{", "\t\ttype ipv4_addr", "\t\tflags interval",
             "\t\tauto-merge"]
    if comment:
        lines.append(f'\t\tcomment "{comment}"')
    if cidrs:
        lines.append("\t\telements = {")
        for i in range(0, len(cidrs), 8):
            lines.append("\t\t\t" + ", ".join(cidrs[i:i + 8]) + ",")
        lines.append("\t\t}")
    lines.append("\t}")
    return "\n".join(lines)


DOM_SET = "dom4"     # адреса сайтов из правил по доменам по ответам DNS на сервере (режим «фильтр по DNS»)
# метки выходов (MARK_BASE + 1…MAX_UPSTREAMS) и политик sniproxy.py (SNIFF_OUT_BASE + i) — по старшим битам
EXIT_MASK = 0xFFFFFF00


def _policy_chain(name: str, policy: dict, available: set[str], sniff: bool = False,
                  outs=None, dom: bool = False, quic: bool = False, labels: bool = False) -> str:
    """Цепочка политики. sniff — у политики есть правила по доменам: её TCP 80/443 идёт в
    sniproxy.py, а QUIC (UDP 443) блокируется — кроме пакетов, которые разобрала по имени очередь
    (quic: метка «пропустить» — дальше обычные правила; остальные решения цепочка c_prerouting
    принимает раньше), и браузер переходит на обычный HTTPS. dom — только к адресам из набора
    DOM_SET (режим «фильтр по DNS»): остальное идёт ядром, и HTTP/3 к ним работает.
    outs — свои цепочки выходов (для q_* в hook output).
    labels — учёт по правилам: совпавшее правило ставит соединению метку conntrack со своим номером в политике
    (policy["slots"]), «По умолчанию» — RULE_DEFAULT_SLOT; по ним считает таблица racct_ruleset. У правила с
    ограничением скорости (policy["lims"]) — ещё метки RULE_LIM_BASE + номер ограничения и RULE_LIM_ANY."""
    oc = outs or out_chain
    slots = policy.get("slots") if labels else None
    lims = (policy.get("lims") or ()) if labels else ()
    lines = [f"\tchain {name} {{"]
    if sniff:
        pre = f"ip daddr @{DOM_SET} " if dom else ""
        skip = f"meta mark != {config.QUIC_PASS_MARK:#x} " if quic else ""
        lines.append(f"\t\t{pre}udp dport 443 {skip}goto {oc('block')}")
        # только новые соединения: открытое раньше (до перенаправления или до того, как адрес попал в dom4) с этой меткой
        # ушло бы по основной таблице мимо выхода — перенаправить его уже нельзя, оно идёт по правилам ниже
        lines.append(f"\t\t{pre}tcp dport {{ 80, 443 }} ct state new meta mark set {config.SNIFF_MARK:#x} accept")
        # пакеты уже перенаправленных соединений (их ведёт conntrack) — посреднику, мимо правил по адресам
        lines.append(f"\t\t{pre}tcp dport {{ 80, 443 }} ct status dnat accept")
    for i, (list_ids, out) in enumerate(policy["rules"]):
        lab = f"ct label set {int(slots[i])} " if slots is not None else ""
        if i < len(lims) and lims[i] is not None:
            lab += f"ct label set {config.RULE_LIM_BASE + int(lims[i])} ct label set {config.RULE_LIM_ANY} "
        for lid in list_ids:
            if lid in available:
                lines.append(f"\t\tip daddr @l_{lid} {lab}goto {oc(out)}")
    dlab = f"ct label set {config.RULE_DEFAULT_SLOT} " if slots is not None else ""
    lines.append(f"\t\t{dlab}goto {oc(policy['default'])}")
    lines.append("\t}")
    return "\n".join(lines)


def layout(global_policy: dict, client_policies: dict[str, dict], up_nums: set[int],
           balance: set[int] | frozenset = frozenset()) -> tuple[dict, dict]:
    """Уникальные политики и какому клиенту какая: ({имя: политика}, {IP клиента: имя}).
    Политика: {"rules": [(списки, выход)], "default": выход, "domain": [(списки доменов, выход)]}.
    Ту же раскладку использует sniproxy.py (через engine), поэтому имена должны совпадать.
    balance — номера рабочих выходов балансировки: Sticky на другой выход становится обычным."""
    def norm(policy: dict) -> dict:
        # выход на несуществующий туннель → блок (безопасный вариант)
        # «Напрямую — адрес» приходит уже проверенным (Engine.resolve: адрес работает и его путь стоит)
        fix = lambda o: o if isinstance(o, Addr) or o in ("direct", "block") or o in up_nums else "block"  # noqa: E731
        # Sticky — только на рабочий выход балансировки (у «По умолчанию» и у правил с балансировкой, 1.24.0)
        unstick = lambda o: int(o) if isinstance(o, Sticky) and int(o) not in balance else o  # noqa: E731
        rules = [(l, unstick(fix(o))) for l, o in policy["rules"]]
        default = unstick(fix(policy["default"]))
        slots = policy.get("slots")
        # хвостовые правила ничего не меняют в пути — но с учётом по правилам (slots) их строки ставят свою метку
        while slots is None and rules and _okey(rules[-1][1]) == _okey(default):
            rules.pop()
        out = {"rules": rules, "default": default, "domain": list(policy.get("domain") or ())}
        if policy.get("dns"):                        # свой DNS правил по сайтам (только dnsproxy.py)
            out["dns"] = list(policy["dns"])
        if slots is not None:
            out["slots"] = list(slots)
            out["dslots"] = list(policy.get("dslots") or ())
        if policy.get("lims") is not None:
            out["lims"] = list(policy["lims"])
            out["dlims"] = list(policy.get("dlims") or ())
        return out

    gp = norm(global_policy)
    chains: dict[tuple, str] = {_policy_key(gp): "p_global"}
    client_map: dict[str, str] = {}
    policies: dict[str, dict] = {"p_global": gp}
    for ip, pol in sorted(client_policies.items()):
        p = norm(pol)
        key = _policy_key(p)
        if key not in chains:
            chains[key] = f"p_{len(chains)}"
            policies[chains[key]] = p
        if chains[key] != "p_global":
            client_map[ip] = chains[key]
    return policies, client_map


def sniff_marks(policies: dict, slots: dict | None = None) -> dict[str, int]:
    """Метки соединений sniproxy.py для политик с правилами по доменам.
    slots — {политика: номер} движка между проходами (меняется здесь): у политики тот же номер, пока она есть.
    Иначе номера сдвигались бы при добавлении клиента, и на миг между новыми настройками sniproxy.py и прежними
    правилами nftables метка одной политики вела бы по правилам другой. Номер ушедшей политики занимается
    снова не раньше следующего прохода: до конца этого он ещё в прежних правилах nftables."""
    names = sorted((n for n, p in policies.items() if p.get("domain")), key=lambda n: (n != "p_global", n))
    if slots is None:
        return {n: config.SNIFF_OUT_BASE + i for i, n in enumerate(names)}
    keys = {n: _policy_key(policies[n]) for n in names}
    busy = set(slots.values())
    new = {k: slots[k] for k in keys.values() if k in slots}
    free = (i for i in itertools.count() if i not in busy)
    for n in names:
        if keys[n] not in new:
            new[keys[n]] = next(free)
    slots.clear()
    slots.update(new)
    return {n: config.SNIFF_OUT_BASE + new[keys[n]] for n in names}


def _addr_guard(addrs: dict[int, dict], verdict: str, post: bool = False) -> list[str]:
    """Защита «Напрямую — адрес» (1.25.0): пакет с меткой адреса K уходит только через интерфейс своего пути (post — и
    после подмены — только с этим адресом на хосте); метка номера без пути — никуда. Только точные метки панели."""
    out = []
    for k, a in sorted(addrs.items()):
        m = addr_mark(k)
        lo = 'oifname != "lo" ' if post else ""     # соединение посредника к адресу самого сервера — через lo
        out.append(f'\t\tmeta mark {m:#x} {lo}oifname != "{a["dev"]}" {verdict}')
        if post and a.get("nat") == "snat":
            out.append(f"\t\tmeta mark {m:#x} {lo}ip saddr != {a['ip']} {verdict}")
    known = ", ".join(f"{addr_mark(k):#x}" for k in sorted(addrs))
    out.append(f"\t\tmeta mark {ADDR_LO:#x}-{ADDR_HI:#x} " + (f"meta mark != {{ {known} }} " if known else "") + verdict)
    return out


def _own_lim() -> str:
    """Условие «метка панели с битами номера ограничения»: биты RULE_LIM_MASK есть, а остальная метка — выход, политика
    sniproxy.py или RULE_LIM_TAG (RULE_LIM_OWN). Чужие метки с теми же битами (Tailscale: 0x40000, 0x80000) — мимо."""
    return (f"meta mark & {config.RULE_LIM_MASK:#x} != 0x0 "
            f"meta mark & {0xFFFFFFFF ^ config.RULE_LIM_MASK:#x} {{ {config.RULE_LIM_OWN} }}")


def _lim_label(j: int) -> str:
    """Строка rl_lab/q_lab: номер ограничения j в битах RULE_LIM_MASK метки → метки соединения."""
    return (f"\t\tmeta mark & {config.RULE_LIM_MASK:#x} == {(j + 1) << config.RULE_LIM_SHIFT:#x} "
            f"ct label set {config.RULE_LIM_BASE + j} ct label set {config.RULE_LIM_ANY}\n")


def _limit_chains(wg: str, limits: dict[int, tuple[int, int]], labels: bool) -> list[str]:
    """Ограничение скорости правил (1.24.0). Предел — общий «limit» на правило и сторону; пакеты сверх него
    отбрасываются там, куда приходят: от клиента (транзитные — forward, к sniproxy.py — input) и из сети (транзитные к
    клиенту — forward, ответы сайтов посреднику — input). Потеря при приёме для отправителя — обычная потеря в сети:
    TCP сбавляет скорость. Отбрасывать отправляемое самим сервером (ответы посредника клиенту) нельзя: потерянное в
    своём же стеке TCP не считает потерей и ждёт таймера.
    c_rlim_out (labels, даже без ограничений: на неё полагается номер в метках сокетов посредника, см. _rlim_key) —
    номер ограничения из метки сокета sniproxy.py → метки соединения, биты снимаются (и служебная RULE_LIM_TAG у сокетов
    без своей метки); type route: с исходной меткой маршрут выбирается заново, до c_output. Только метки панели
    (_own_lim): на сервере «на хосте» цепочка видит пакеты всех программ, а Tailscale держит в тех же битах свои метки."""
    out = []
    if labels:
        strip = 0xFFFFFFFF ^ config.RULE_LIM_MASK
        out.append("\tchain rl_lab {\n" + "".join(_lim_label(j) for j in sorted(limits))
                   + f"\t\tmeta mark set meta mark & {strip:#x}\n"
                   + f"\t\tmeta mark {config.RULE_LIM_TAG:#x} meta mark set 0x0\n\t}}")
        out.append("\tchain c_rlim_out {\n\t\ttype route hook output priority mangle - 1; policy accept;\n"
                   f"\t\t{_own_lim()} jump rl_lab\n\t}}")
    if not limits:
        return out
    fw, inp = [], []
    for j, (down, up) in sorted(limits.items()):
        lab = f"ct label {config.RULE_LIM_BASE + j}"
        if up:
            fw.append(f'\t\tiifname "{wg}" {lab} limit name "rl_{j}_u" drop')
            inp.append(f'\t\tiifname "{wg}" {lab} limit name "rl_{j}_u" drop')
        if down:
            fw.append(f'\t\toifname "{wg}" {lab} limit name "rl_{j}_d" drop')
            inp.append(f'\t\tiifname != "{wg}" {lab} limit name "rl_{j}_d" drop')
    out.append("\tchain rl_f {\n" + "\n".join(fw) + "\n\t}")
    out.append("\tchain rl_i {\n" + "\n".join(inp) + "\n\t}")
    # до c_forward и до учёта (racct — filter + 11): отброшенное не считается
    out.append("\tchain c_rlim_fwd {\n\t\ttype filter hook forward priority filter - 1; policy accept;\n"
               f"\t\tct label {config.RULE_LIM_ANY} jump rl_f\n\t}}")
    out.append("\tchain c_rlim_in {\n\t\ttype filter hook input priority filter - 1; policy accept;\n"
               f"\t\tct label {config.RULE_LIM_ANY} jump rl_i\n\t}}")
    return out


def generate(wg_iface: str, lists: dict[str, list[str]], upstreams: list[dict],
             global_policy: dict, client_policies: dict[str, dict], sniff_port: int | None = None,
             balance: set[int] | frozenset = frozenset(), dom_filter: bool = False,
             quic: bool = False, strict: bool = False, slots: dict | None = None, labels: bool = False,
             limits: dict[int, tuple[int, int]] | None = None, addrs: dict[int, dict] | None = None,
             dns_to: str | None = None) -> str:
    """sniff_port — где слушает sniproxy.py (правила по доменам);
    None — посредника нет, правила по доменам не действуют, работают только правила по адресам.
    balance — номера рабочих выходов балансировки: соединение, записанное в conntrack на один из них,
    остаётся на нём (цепочки ob_u*, выход Sticky в политике).
    dom_filter — перехватывать только адреса из набора DOM_SET (его наполняет dnsproxy.py).
    quic — первые пакеты QUIC таких клиентов идут в очередь ядра (sniproxy.py разбирает имя), а не
    блокируются: цепочка c_quic; без слушателя (bypass) пакет блокируется, как без очереди.
    strict — правила по доменам сейчас не действуют (sniff_port None), а выбрано «тогда блокировать»:
    у клиентов с правилами по доменам весь трафик (кроме местных сетей и самого сервера) — в блок.
    labels — учёт трафика по правилам (1.24.0): правила политик ставят метку conntrack (ct label) со своим номером.
    limits — ограничения скорости правил (1.24.0, только с labels): {номер j: (к клиентам, от клиентов) байт/с; 0 — нет}.
    addrs — исходящие адреса, чей путь стоит (1.25.0): {номер K: {"ip", "dev", "nat"}}; dev — интерфейс, через который
    уходит «Напрямую — адрес» (на хосте — интерфейс маршрута по умолчанию, в контейнере — сеть Docker адреса), nat:
    "snat" (на хосте: подменить адрес отправителя на этот) | "masq" (в контейнере: адрес этой сети, дальше — Docker).
    Адрес без пути — блок (o_a<K> ставит метку блока): метка адреса без своего ip rule ушла бы по основной таблице —
    «Напрямую» с адреса системы.
    dns_to — адрес DNS на сервере (включён «DNS на сервере», 1.25.0, П5): все запросы DNS клиентов (UDP и TCP 53, к
    любому адресу) идут к нему — и второй DNS из конфига, и DNS, вписанный на устройстве: иначе имена сайтов правил
    «через выход» уходили бы мимо выхода открытым текстом. Свои запросы сервера (dnsproxy.py — output) не задеты."""
    T = config.NFT_TABLE
    up_nums = {u["num"] for u in upstreams}
    alive = sorted(n for n in balance if n in up_nums)
    policies, client_map = layout(global_policy, client_policies, up_nums, balance)
    addrs = {int(k): v for k, v in (addrs or {}).items() if 1 <= int(k) <= config.ADDR_MAX}
    addr_ks = sorted({o.k for p in policies.values() for o in [p["default"], *(o for _, o in p["rules"])]
                      if isinstance(o, Addr)} | set(addrs))
    marks = sniff_marks(policies, slots) if sniff_port else {}

    used_lists = sorted({lid for p in policies.values() for l, _ in p["rules"] for lid in l})
    available = {lid for lid in used_lists if lists.get(lid)}

    dom_filter = bool(dom_filter and marks)
    quic = bool(quic and marks)
    out = [f"table ip {T}", f"delete table ip {T}", f"table ip {T} {{"]
    out.append(_set_block("local4", LOCAL_NETS))
    if dom_filter:
        out.append(f"\tset {DOM_SET} {{\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}}")
    for lid in sorted(available):
        out.append(_set_block(f"l_{lid}", lists[lid]))
    limits = {int(j): v for j, v in (limits or {}).items() if 0 <= int(j) < config.RULE_LIM_MAX} if labels else {}
    for j, pair in sorted(limits.items()):
        for d, bps in zip("du", pair):
            if bps:
                # без burst: у «limit» в байтах ядро и так держит запас в секунду на этой скорости (rate + burst) — с ним
                # TCP через VPN с задержкой 100–200 мс добирает до предела; первая секунда после паузы может быть быстрее
                out.append(f"\tlimit rl_{j}_{d} {{\n\t\trate over {int(bps)} bytes/second\n\t}}")

    out.append("\tmap clients {")
    out.append("\t\ttype ipv4_addr : verdict")
    if client_map:
        out.append("\t\telements = {")
        for ip, ch in client_map.items():
            out.append(f"\t\t\t{ip} : goto {ch},")
        out.append("\t\t}")
    out.append("\t}")

    # QUIC, разобранный по имени (метка из очереди или из conntrack), — сразу на выбранный путь, и
    # решение запоминается в conntrack для остальных пакетов соединения. «Пропустить» тоже
    # запоминается (и идёт дальше, к обычным правилам политики): иначе пакеты после ответа сервера —
    # уже не «новые», в очередь не идут и без метки попали бы в строку блока QUIC политики
    bits = config.QUIC_SLOT_MASK | config.RULE_LIM_MASK
    qlab = (f"\t\tudp dport 443 meta mark & {bits:#x} != 0x0 jump q_lab\n") if quic else ""
    quic_line = qlab + (f"\t\tudp dport 443 meta mark {config.QUIC_PASS_MARK:#x} "
                 f"ct mark set {config.QUIC_PASS_MARK | config.QUIC_CT_BIT:#x}\n"
                 f"\t\tudp dport 443 meta mark != 0x0 meta mark != {config.QUIC_PASS_MARK:#x} "
                 f"ct mark set meta mark | {config.QUIC_CT_BIT:#x} accept\n") if quic else ""
    out.append(f"""\tchain c_prerouting {{
\t\ttype filter hook prerouting priority mangle + 10; policy accept;
\t\tiifname != "{wg_iface}" return
\t\tip daddr @local4 return
{quic_line}\t\tip saddr vmap @clients
\t\tgoto p_global
\t}}""")

    for name in sorted(policies, key=lambda n: (n != "p_global", n)):
        if strict and not sniff_port and policies[name].get("domain"):
            out.append(f"\tchain {name} {{\n\t\tgoto o_block\n\t}}")
            continue
        out.append(_policy_chain(name, policies[name], available, name in marks, dom=dom_filter, quic=quic,
                                 labels=labels))
    if quic:
        # вердикт QUIC с номером правила (биты QUIC_SLOT_MASK; их ставит sniproxy.py, только когда этот набор уже
        # стоит) — метка соединения для учёта; биты снимаются всегда: с ними метка выхода не совпала бы с ip rule
        # (и номер ограничения скорости правила — биты RULE_LIM_MASK: метки RULE_LIM_BASE + j и RULE_LIM_ANY)
        strip = 0xFFFFFFFF ^ bits
        qs = sorted({int(k) for n in marks for k in (policies[n].get("dslots") or ())}) if labels else []
        lab = "".join(_lim_label(j) for j in sorted(limits))
        lab += "".join(f"\t\tmeta mark & {config.QUIC_SLOT_MASK:#x} == {(k + 1) << config.QUIC_SLOT_SHIFT:#x} "
                       f"ct label set {k} meta mark set meta mark & {strip:#x} return\n" for k in qs)
        out.append(f"\tchain q_lab {{\n{lab}\t\tmeta mark set meta mark & {strip:#x}\n\t}}")

    out.append("\tchain o_direct {\n\t\taccept\n\t}")
    out.append(f"\tchain o_block {{\n\t\tmeta mark set {config.MARK_BLOCK:#x} accept\n\t}}")
    for k in addr_ks:
        m = addr_mark(k) if k in addrs else config.MARK_BLOCK
        out.append(f"\tchain o_a{k} {{\n\t\tmeta mark set {m:#x} accept\n\t}}")
    no_quic = {u["num"] for u in upstreams if u.get("no_quic")}
    for u in sorted(upstreams, key=lambda x: x["num"]):
        out.append(f"\tchain o_u{u['num']} {{\n{_no_quic(u['num'] in no_quic)}"
                   f"\t\tmeta mark set {mark_for(u['num']):#x} accept\n\t}}")
    for n in alive:
        out.append(_sticky_chain(f"ob_u{n}", n, alive, n in no_quic, quic))

    fwd = [
        "\tchain c_forward {",
        "\t\ttype filter hook forward priority filter; policy accept;",
        # служебный адрес облака (169.254.169.254): link-local входит в local4 и шёл бы с самого сервера при любом выходе
        f'\t\tiifname "{wg_iface}" ip daddr {LINK_LOCAL} reject with icmp type admin-prohibited',
        f'\t\tiifname "{wg_iface}" ip daddr {CLOUD_META} reject with icmp type admin-prohibited',
        # пакет с меткой перенаправления в посредника пересылается — значит, перенаправлен не был (П2): никуда
        f'\t\tiifname "{wg_iface}" meta mark {config.SNIFF_MARK:#x} reject with icmp type admin-prohibited',
        f"\t\tmeta mark {config.MARK_BLOCK:#x} reject with icmp type admin-prohibited",
        # биты номера правила из вердикта QUIC снимает q_lab; дошли сюда — метка выхода не та, что у ip rule
        f'\t\tiifname "{wg_iface}" meta mark & {bits:#x} != 0x0 reject with icmp type admin-prohibited',
        # страховка: пакет с меткой выхода уходит не в туннель (ip rule этой метки ещё нет или уже нет —
        # основная таблица) — отказ, а не путь мимо выхода
        f'\t\tmeta mark & {EXIT_MASK:#x} == {config.MARK_BASE:#x} oifname != "{config.IFACE_PREFIX}*" '
        "reject with icmp type admin-prohibited",
        *_addr_guard(addrs, "reject with icmp type admin-prohibited"),
    ]
    for u in sorted(upstreams, key=lambda x: x["num"]):
        ifn = f"{config.IFACE_PREFIX}{u['num']}"
        fwd += [_mss(f'oifname "{ifn}"', u), _mss(f'iifname "{ifn}"', u)]
    fwd.append("\t}")
    out.append("\n".join(fwd))
    out.extend(_limit_chains(wg_iface, limits, labels))

    if quic:
        # первые пакеты новых соединений QUIC клиентов с правилами по доменам — в очередь ядра
        # (sniproxy.py); соединение с решением в conntrack берёт метку оттуда. Приоритет раньше
        # c_prerouting: её строка выше видит метку вердикта
        if "p_global" in marks:
            elems = sorted(ip for ip, n in client_map.items() if n not in marks)
            who, sname = "ip saddr != @q_skip ", "q_skip"
        else:
            elems = sorted(ip for ip, n in client_map.items() if n in marks)
            who, sname = "ip saddr @q_take ", "q_take"
        out.append(f"\tset {sname} {{\n\t\ttype ipv4_addr\n"
                   + (f"\t\telements = {{ {', '.join(elems)} }}\n" if elems else "") + "\t}")
        dom = f"ip daddr @{DOM_SET} " if dom_filter else ""
        keep = 0xFFFFFFFF ^ config.QUIC_CT_BIT
        # Чужая метка до нас (wg-quick с полным туннелем: `meta mark set ct mark` в premangle) — не решение: c_prerouting
        # принял бы её как решение очереди, а решение для остановленного выхода ушло бы мимо него (проверка исправлений)
        # Решение из conntrack — только если его путь ещё есть: метка выхода, который остановили, без
        # своего ip rule пошла бы по основной таблице, то есть мимо выхода напрямую. Такой поток QUIC
        # дальше блокируется (строка блока QUIC в политике), и браузер переходит на TCP.
        live = sorted({mark_for(n) for n in up_nums} | {addr_mark(k) for k in addrs}
                      | {config.QUIC_PASS_MARK, config.QUIC_DIRECT_MARK, config.MARK_BLOCK})
        restore = ", ".join(f"{m | config.QUIC_CT_BIT:#x}" for m in live)
        out.append(f"""\tchain c_quic {{
\t\ttype filter hook prerouting priority mangle + 5; policy accept;
\t\tiifname != "{wg_iface}" return
\t\tudp dport != 443 return
\t\tip daddr @local4 return
\t\tmeta mark set 0x0
\t\tct mark {{ {restore} }} meta mark set ct mark & {keep:#x} accept
\t\tct state != new return
\t\t{who}{dom}queue num {config.QUIC_QUEUE} bypass
\t}}""")

    if marks:
        # TCP 80/443 клиентов с правилами по доменам — в sniproxy.py на адресе сервера в туннеле
        out.append(f"""\tchain c_sniff {{
\t\ttype nat hook prerouting priority dstnat; policy accept;
\t\tiifname "{wg_iface}" meta mark {config.SNIFF_MARK:#x} meta l4proto tcp redirect to :{int(sniff_port)}
\t}}""")
        # соединения sniproxy.py без совпадения по домену: обычные правила политики клиента
        # (метка политики → цепочка q_*; смена метки в type route — новый выбор маршрута)
        oq = lambda o: "oq" + out_chain(o)[1:]          # o_u1 → oq_u1, ob_u1 → oqb_u1, o_direct → oq_direct
        vm = ", ".join(f"{m:#x} : goto q_{n}" for n, m in marks.items())
        out.append(f"""\tchain c_output {{
\t\ttype route hook output priority mangle; policy accept;
\t\tmeta mark vmap {{ {vm} }}
\t}}""")
        for n in marks:
            out.append(_policy_chain("q_" + n, policies[n], available, False, oq).replace(
                f"\tchain q_{n} {{", f"\tchain q_{n} {{\n\t\tip daddr @local4 goto oq_direct", 1))
        out.append("\tchain oq_direct {\n\t\tmeta mark set 0x0 accept\n\t}")
        out.append("\tchain oq_block {\n\t\treject with tcp reset\n\t}")
        for k in addr_ks:
            out.append(f"\tchain oq_a{k} {{\n\t\tmeta mark set {addr_mark(k):#x} accept\n\t}}" if k in addrs
                       else f"\tchain oq_a{k} {{\n\t\treject with tcp reset\n\t}}")
        for u in sorted(upstreams, key=lambda x: x["num"]):
            out.append(f"\tchain oq_u{u['num']} {{\n\t\tmeta mark set {mark_for(u['num']):#x} accept\n\t}}")
        for n in alive:
            out.append(_sticky_chain(f"oqb_u{n}", n, alive))
        # MSS clamp для соединений sniproxy.py: они локальные (output), а не транзитные, поэтому
        # правило из c_forward их не видит — без него SYN объявит MSS 1460 под MTU туннеля ~1280
        mss = [_mss(f'oifname "{config.IFACE_PREFIX}{u["num"]}"', u) for u in sorted(upstreams, key=lambda x: x["num"])]
        if mss:
            out.append("\tchain c_mss_out {\n\t\ttype filter hook postrouting priority mangle; policy accept;\n"
                       + "\n".join(mss) + "\n\t}")

    # та же страховка для своих соединений сервера (sniproxy.py, dnsproxy.py, проверки выходов): метка выхода
    # мимо туннеля — в никуда; метка политики sniproxy.py, которой нет в c_output (его настройки и nftables на миг
    # разошлись), — тоже, а не основная таблица. В hook postrouting, а не output: в output имя интерфейса —
    # прежний путь, до того как c_output (type route) сменил метку и маршрут; reject там нельзя — только drop
    out.append("\tchain c_guard_post {\n\t\ttype filter hook postrouting priority filter; policy accept;\n"
               f'\t\tmeta mark & {EXIT_MASK:#x} == {config.MARK_BASE:#x} oifname != "lo" '
               f'oifname != "{config.IFACE_PREFIX}*" drop\n'
               # все метки политик sniproxy.py, а не только первые 256 (у сотен клиентов со своими правилами их больше)
               f"\t\tmeta mark {config.SNIFF_OUT_BASE:#x}-{config.QUIC_PASS_MARK - 1:#x} drop\n"
               # номер ограничения скорости в метке сокета sniproxy.py, который не сняла rl_lab (набор без неё): с ним
               # метка выхода не совпала бы с ip rule — соединение ушло бы мимо выхода. Только метки панели: на сервере
               # «на хосте» здесь и пакеты других программ (Tailscale метит свои 0x40000 и 0x80000)
               f"\t\t{_own_lim()} drop\n\t}}")

    if addrs:
        # «Напрямую — адрес»: подмена адреса отправителя раньше MASQUERADE сервера (iptables, srcnat): для соединения
        # действует первая цепочка, сделавшая NAT. Только по меткам панели — пакеты других программ сюда не попадают
        nat = []
        for k, a in sorted(addrs.items()):
            to = f"snat to {a['ip']}" if a.get("nat") == "snat" else "masquerade"
            nat.append(f'\t\tmeta mark {addr_mark(k):#x} oifname "{a["dev"]}" {to}')
        out.append("\tchain c_addr_nat {\n\t\ttype nat hook postrouting priority srcnat - 1; policy accept;\n"
                   + "\n".join(nat) + "\n\t}")
    # после подмены адреса: пакет с меткой адреса ушёл не через свой интерфейс или (на хосте) не с этим адресом —
    # в никуда, а не с адреса системы. Номер адреса без пути — тоже (его метку ставит только панель)
    out.append("\tchain c_addr_post {\n\t\ttype filter hook postrouting priority srcnat + 1; policy accept;\n"
               + "\n".join(_addr_guard(addrs, "drop", post=True)) + "\n\t}")

    if dns_to:
        dns = "\n".join(f'\t\tiifname "{wg_iface}" ip daddr != {dns_to} {p} dport 53 dnat to {dns_to}:53'
                        for p in ("udp", "tcp"))
        out.append(f"\tchain c_dns {{\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n{dns}\n\t}}")

    post = ["\tchain c_postrouting {",
            "\t\ttype nat hook postrouting priority srcnat - 1; policy accept;"]
    for u in sorted(upstreams, key=lambda x: x["num"]):
        if not u.get("snat"):          # SOCKS5: соединения завершает hev-socks5-tunnel, SNAT не нужен
            continue
        ifn = f"{config.IFACE_PREFIX}{u['num']}"
        # адрес туннеля не назначаем на интерфейс (он часто пересекается с подсетью
        # наших же клиентов 10.8.1.0/24), а подставляем через SNAT
        post.append(f'\t\toifname "{ifn}" snat to {u["snat"]}')
    post.append("\t}")
    out.append("\n".join(post))

    out.append("}")
    return "\n".join(out) + "\n"
