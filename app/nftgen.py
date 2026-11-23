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

from collections.abc import Sequence
import itertools

from . import config

LOCAL_NETS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
]


# Сеть link-local: в облаках там служебный адрес 169.254.169.254 (данные сервера, у AWS — и ключи доступа к
# облаку). Клиентам VPN он не нужен, а маршрутизаторы такие адреса и так не пересылают (RFC 3927)
LINK_LOCAL = "169.254.0.0/16"

ACCT_TABLE = "awgr_acct"
ACCT_VER = 1


def _ifaces_expr(wg_iface: str | Sequence[str]) -> tuple[list[str], str]:
    """Список активных интерфейсов сервера и выражение nftables для iifname/oifname."""
    ifaces = [wg_iface] if isinstance(wg_iface, str) else list(wg_iface)
    if len(ifaces) == 1:
        return ifaces, f'"{ifaces[0]}"'
    return ifaces, "{ " + ", ".join(f'"{w}"' for w in ifaces) + " }"


def acct_marker(wg_iface: str | Sequence[str]) -> str:
    """Метка в комментарии правила: по ней видно, что таблица учёта наша и актуальна."""
    ifaces, _ = _ifaces_expr(wg_iface)
    return f"awgr-acct {ACCT_VER} {','.join(ifaces)}"


def acct_ruleset(wg_iface: str | Sequence[str]) -> str:
    """Отдельная таблица учёта трафика по выходам.

    Только считает: никаких меток, маршрутов и запретов, поэтому на маршрутизацию не
    влияет. Основная таблица пересоздаётся при каждом изменении правил, а эта — только
    когда её нет (иначе счётчики обнулялись бы). Ключ — адрес клиента и «другой»
    интерфейс пакета: awgrN — выход N, всё остальное — напрямую. Цепочка стоит после
    c_forward, поэтому заблокированный трафик (reject там) сюда не доходит.
    Счётчик задан в правиле, а не в наборе: так работает и на ядрах до 5.11."""
    T = ACCT_TABLE
    _, expr = _ifaces_expr(wg_iface)
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
\t\tiifname {expr} oifname != {expr} update @up {{ ip saddr . oifname counter }} comment "{acct_marker(wg_iface)}"
\t\toifname {expr} iifname != {expr} update @down {{ ip daddr . iifname counter }}
\t}}
}}
"""


def parse_acct(data: dict, wg_iface: str | Sequence[str]) -> dict[tuple[str, str], list[int]] | None:
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


class Sticky(int):
    """Выход N с запоминанием выхода у соединения (балансировка): первый пакет соединения
    записывает метку выхода в conntrack (ct mark), следующие берут её оттуда, пока этот выход
    среди рабочих выходов балансировки. Поэтому перенос клиента на другой выход не рвёт его открытые
    соединения: новые идут через новый выход, старые доживают на прежнем. Во всём остальном — то же
    число N (метка, таблица, учёт)."""
    __slots__ = ()

    def __repr__(self) -> str:
        return f"Sticky({int(self)})"


def out_chain(out) -> str:
    if out == "direct":
        return "o_direct"
    if out == "block":
        return "o_block"
    if isinstance(out, Sticky):
        return f"ob_u{int(out)}"
    return f"o_u{int(out)}"


def _okey(o):
    """Выход в ключе политики: Sticky(N) и N — разные цепочки."""
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
    key = (tuple((tuple(l), o) for l, o in policy["rules"]), _okey(policy["default"]),
           tuple((tuple(l), str(o)) for l, o in policy.get("domain") or ()))
    if policy.get("dns"):          # без своего DNS ключ прежний: номера политик sniproxy.py не сдвигаются
        key += (tuple((tuple(l), str(o), tuple(d)) for l, o, d in policy["dns"]),)
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
                  outs=None, dom: bool = False, quic: bool = False) -> str:
    """Цепочка политики. sniff — у политики есть правила по доменам: её TCP 80/443 идёт в
    sniproxy.py, а QUIC (UDP 443) блокируется — кроме пакетов, которые разобрала по имени очередь
    (quic: метка «пропустить» — дальше обычные правила; остальные решения цепочка c_prerouting
    принимает раньше), и браузер переходит на обычный HTTPS. dom — только к адресам из набора
    DOM_SET (режим «фильтр по DNS»): остальное идёт ядром, и HTTP/3 к ним работает.
    outs — свои цепочки выходов (для q_* в hook output)."""
    oc = outs or out_chain
    lines = [f"\tchain {name} {{"]
    if sniff:
        pre = f"ip daddr @{DOM_SET} " if dom else ""
        skip = f"meta mark != {config.QUIC_PASS_MARK:#x} " if quic else ""
        lines.append(f"\t\t{pre}udp dport 443 {skip}goto {oc('block')}")
        lines.append(f"\t\t{pre}tcp dport {{ 80, 443 }} meta mark set {config.SNIFF_MARK:#x} accept")
    for list_ids, out in policy["rules"]:
        for lid in list_ids:
            if lid in available:
                lines.append(f"\t\tip daddr @l_{lid} goto {oc(out)}")
    lines.append(f"\t\tgoto {oc(policy['default'])}")
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
        fix = lambda o: o if o in ("direct", "block") or o in up_nums else "block"
        rules = [(l, fix(o)) for l, o in policy["rules"]]
        default = fix(policy["default"])
        if isinstance(default, Sticky) and int(default) not in balance:
            default = int(default)
        while rules and rules[-1][1] == default:  # хвостовые правила ничего не меняют
            rules.pop()
        out = {"rules": rules, "default": default, "domain": list(policy.get("domain") or ())}
        if policy.get("dns"):                        # свой DNS правил по сайтам (только dnsproxy.py)
            out["dns"] = list(policy["dns"])
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


def generate(wg_iface: str | Sequence[str], lists: dict[str, list[str]], upstreams: list[dict],
             global_policy: dict, client_policies: dict[str, dict], sniff_port: int | None = None,
             balance: set[int] | frozenset = frozenset(), dom_filter: bool = False,
             quic: bool = False, strict: bool = False, slots: dict | None = None) -> str:
    """sniff_port — где слушает sniproxy.py (правила по доменам);
    None — посредника нет, правила по доменам не действуют, работают только правила по адресам.
    balance — номера рабочих выходов балансировки: соединение, записанное в conntrack на один из них,
    остаётся на нём (цепочки ob_u*, выход Sticky в политике).
    dom_filter — перехватывать только адреса из набора DOM_SET (его наполняет dnsproxy.py).
    quic — первые пакеты QUIC таких клиентов идут в очередь ядра (sniproxy.py разбирает имя), а не
    блокируются: цепочка c_quic; без слушателя (bypass) пакет блокируется, как без очереди.
    strict — правила по доменам сейчас не действуют (sniff_port None), а выбрано «тогда блокировать»:
    у клиентов с правилами по доменам весь трафик (кроме местных сетей и самого сервера) — в блок."""
    T = config.NFT_TABLE
    _, iface_expr = _ifaces_expr(wg_iface)
    up_nums = {u["num"] for u in upstreams}
    alive = sorted(n for n in balance if n in up_nums)
    policies, client_map = layout(global_policy, client_policies, up_nums, balance)
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
    quic_line = (f"\t\tudp dport 443 meta mark {config.QUIC_PASS_MARK:#x} "
                 f"ct mark set {config.QUIC_PASS_MARK | config.QUIC_CT_BIT:#x}\n"
                 f"\t\tudp dport 443 meta mark != 0x0 meta mark != {config.QUIC_PASS_MARK:#x} "
                 f"ct mark set meta mark | {config.QUIC_CT_BIT:#x} accept\n") if quic else ""
    out.append(f"""\tchain c_prerouting {{
\t\ttype filter hook prerouting priority mangle; policy accept;
\t\tiifname != {iface_expr} return
\t\tip daddr @local4 return
{quic_line}\t\tip saddr vmap @clients
\t\tgoto p_global
\t}}""")

    for name in sorted(policies, key=lambda n: (n != "p_global", n)):
        if strict and not sniff_port and policies[name].get("domain"):
            out.append(f"\tchain {name} {{\n\t\tgoto o_block\n\t}}")
            continue
        out.append(_policy_chain(name, policies[name], available, name in marks, dom=dom_filter, quic=quic))

    out.append("\tchain o_direct {\n\t\taccept\n\t}")
    out.append(f"\tchain o_block {{\n\t\tmeta mark set {config.MARK_BLOCK:#x} accept\n\t}}")
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
        f'\t\tiifname {iface_expr} ip daddr {LINK_LOCAL} reject with icmp type admin-prohibited',
        f"\t\tmeta mark {config.MARK_BLOCK:#x} reject with icmp type admin-prohibited",
        # страховка: пакет с меткой выхода уходит не в туннель (ip rule этой метки ещё нет или уже нет —
        # основная таблица) — отказ, а не путь мимо выхода
        f'\t\tmeta mark & {EXIT_MASK:#x} == {config.MARK_BASE:#x} oifname != "{config.IFACE_PREFIX}*" '
        "reject with icmp type admin-prohibited",
    ]
    for u in sorted(upstreams, key=lambda x: x["num"]):
        ifn = f"{config.IFACE_PREFIX}{u['num']}"
        mss = int(u.get("mtu", 1280)) - 40
        fwd.append(f'\t\toifname "{ifn}" tcp flags & (syn | rst) == syn '
                   f'tcp option maxseg size > {mss} tcp option maxseg size set {mss}')
        fwd.append(f'\t\tiifname "{ifn}" tcp flags & (syn | rst) == syn '
                   f'tcp option maxseg size > {mss} tcp option maxseg size set {mss}')
    fwd.append("\t}")
    out.append("\n".join(fwd))

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
        # Решение из conntrack — только если его путь ещё есть: метка выхода, который остановили, без
        # своего ip rule пошла бы по основной таблице, то есть мимо выхода напрямую. Такой поток QUIC
        # дальше блокируется (строка блока QUIC в политике), и браузер переходит на TCP.
        live = sorted({mark_for(n) for n in up_nums}
                      | {config.QUIC_PASS_MARK, config.QUIC_DIRECT_MARK, config.MARK_BLOCK})
        restore = ", ".join(f"{m | config.QUIC_CT_BIT:#x}" for m in live)
        out.append(f"""\tchain c_quic {{
\t\ttype filter hook prerouting priority mangle - 5; policy accept;
\t\tiifname != {iface_expr} return
\t\tudp dport != 443 return
\t\tip daddr @local4 return
\t\tct mark {{ {restore} }} meta mark set ct mark & {keep:#x} accept
\t\tct state != new return
\t\t{who}{dom}queue num {config.QUIC_QUEUE} bypass
\t}}""")

    if marks:
        # TCP 80/443 клиентов с правилами по доменам — в sniproxy.py на адресе сервера в туннеле
        out.append(f"""\tchain c_sniff {{
\t\ttype nat hook prerouting priority dstnat; policy accept;
\t\tiifname {iface_expr} meta mark {config.SNIFF_MARK:#x} meta l4proto tcp redirect to :{int(sniff_port)}
\t}}""")
        # соединения sniproxy.py без совпадения по домену: обычные правила политики клиента
        # (метка политики → цепочка q_*; смена метки в type route — новый выбор маршрута)
        oq = lambda o: "oq_direct" if o == "direct" else "oq_block" if o == "block" else \
            f"oqb_u{int(o)}" if isinstance(o, Sticky) else f"oq_u{int(o)}"
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
        for u in sorted(upstreams, key=lambda x: x["num"]):
            out.append(f"\tchain oq_u{u['num']} {{\n\t\tmeta mark set {mark_for(u['num']):#x} accept\n\t}}")
        for n in alive:
            out.append(_sticky_chain(f"oqb_u{n}", n, alive))
        # MSS clamp для соединений sniproxy.py: они локальные (output), а не транзитные, поэтому
        # правило из c_forward их не видит — без него SYN объявит MSS 1460 под MTU туннеля ~1280
        mss = [f'\t\toifname "{config.IFACE_PREFIX}{u["num"]}" tcp flags & (syn | rst) == syn '
               f'tcp option maxseg size > {int(u.get("mtu", 1280)) - 40} '
               f'tcp option maxseg size set {int(u.get("mtu", 1280)) - 40}'
               for u in sorted(upstreams, key=lambda x: x["num"])]
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
               f"\t\tmeta mark {config.SNIFF_OUT_BASE:#x}-{config.QUIC_PASS_MARK - 1:#x} drop\n\t}}")

    post = ["\tchain c_postrouting {",
            "\t\ttype nat hook postrouting priority srcnat; policy accept;"]
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
