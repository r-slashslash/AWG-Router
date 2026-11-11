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

from . import config

LOCAL_NETS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
]


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


def _sticky_chain(name: str, num: int, alive: list[int]) -> str:
    marks = ", ".join(f"{mark_for(n):#x}" for n in alive)
    m = mark_for(num)
    return (f"\tchain {name} {{\n\t\tct mark {{ {marks} }} meta mark set ct mark accept\n"
            f"\t\tmeta mark set {m:#x} ct mark set {m:#x} accept\n\t}}")


def mark_for(num: int) -> int:
    return config.MARK_BASE + num


def _policy_key(policy: dict) -> tuple:
    return (tuple((tuple(l), o) for l, o in policy["rules"]), _okey(policy["default"]),
            tuple((tuple(l), str(o)) for l, o in policy.get("domain") or ()),
            tuple((tuple(l), _okey(o)) for l, o in policy.get("private_rules") or ()),
            bool(policy.get("private_domain")), _okey(policy.get("private_default", "direct")))


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


def _policy_chain(name: str, policy: dict, available: set[str], sniff: bool = False,
                  outs=None, local_guard: bool = False) -> str:
    """Цепочка политики. sniff — у политики есть правила по доменам: её TCP 80/443 идёт в
    sniproxy.py, а QUIC (UDP 443) блокируется — имени сайта в нём не прочитать, и браузер
    переходит на обычный HTTPS. outs — свои цепочки выходов (для q_* в hook output)."""
    oc = outs or out_chain
    lines = [f"\tchain {name} {{"]
    # Частные корпоративные сайты тоже должны попасть к посреднику. Для остальных
    # политик исключение локальных сетей остаётся перед перехватом соединений.
    private_sniff = sniff and policy.get("private_domain")
    if private_sniff:
        lines.append(f"\t\tudp dport 443 goto {oc('block')}")
        lines.append(f"\t\ttcp dport {{ 80, 443 }} meta mark set {config.SNIFF_MARK:#x} accept")
    if local_guard:
        for list_ids, target in policy.get("private_rules", []):
            for lid in list_ids:
                if lid in available:
                    lines.append(f"\t\tip daddr @local4 ip daddr @l_{lid} goto {oc(target)}")
        lines.append(f"\t\tip daddr @local4 goto {oc(policy.get('private_default', 'direct'))}")
    if sniff and not private_sniff:
        lines.append(f"\t\tudp dport 443 goto {oc('block')}")
        lines.append(f"\t\ttcp dport {{ 80, 443 }} meta mark set {config.SNIFF_MARK:#x} accept")
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
        result = {"rules": rules, "default": default, "domain": list(policy.get("domain") or ())}
        if policy.get("private_rules"):
            result["private_rules"] = [(l, fix(o)) for l, o in policy["private_rules"]]
        if policy.get("private_domain"):
            result["private_domain"] = True
        if "private_default" in policy:
            result["private_default"] = fix(policy["private_default"])
        return result

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


def sniff_marks(policies: dict) -> dict[str, int]:
    """Метки соединений sniproxy.py для политик с правилами по доменам."""
    names = sorted((n for n, p in policies.items() if p.get("domain")), key=lambda n: (n != "p_global", n))
    return {n: config.SNIFF_OUT_BASE + i for i, n in enumerate(names)}


def generate(wg_iface: str, lists: dict[str, list[str]], upstreams: list[dict],
             global_policy: dict, client_policies: dict[str, dict], sniff_port: int | None = None,
             balance: set[int] | frozenset = frozenset()) -> str:
    """sniff_port — где слушает sniproxy.py (правила по доменам для выходов SOCKS5);
    None — посредника нет, правила по доменам не действуют, работают только правила по адресам.
    balance — номера рабочих выходов балансировки: соединение, записанное в conntrack на один из них,
    остаётся на нём (цепочки ob_u*, выход Sticky в политике)."""
    T = config.NFT_TABLE
    up_nums = {u["num"] for u in upstreams}
    alive = sorted(n for n in balance if n in up_nums)
    policies, client_map = layout(global_policy, client_policies, up_nums, balance)
    marks = sniff_marks(policies) if sniff_port else {}

    used_lists = sorted({lid for p in policies.values() for l, _ in [*p["rules"], *p.get("private_rules", [])] for lid in l})
    private = any(p.get("private_domain") or p.get("private_rules") or "private_default" in p for p in policies.values())
    available = {lid for lid in used_lists if lists.get(lid)}

    out = [f"table ip {T}", f"delete table ip {T}", f"table ip {T} {{"]
    out.append(_set_block("local4", LOCAL_NETS))
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

    local_bypass = "" if private else "\n\t\tip daddr @local4 return"
    out.append(f"""\tchain c_prerouting {{
\t\ttype filter hook prerouting priority mangle; policy accept;
\t\tiifname != "{wg_iface}" return{local_bypass}
\t\tip saddr vmap @clients
\t\tgoto p_global
\t}}""")

    for name in sorted(policies, key=lambda n: (n != "p_global", n)):
        out.append(_policy_chain(name, policies[name], available, name in marks, local_guard=private))

    out.append("\tchain o_direct {\n\t\taccept\n\t}")
    out.append(f"\tchain o_block {{\n\t\tmeta mark set {config.MARK_BLOCK:#x} accept\n\t}}")
    for u in sorted(upstreams, key=lambda x: x["num"]):
        out.append(f"\tchain o_u{u['num']} {{\n\t\tmeta mark set {mark_for(u['num']):#x} accept\n\t}}")
    for n in alive:
        out.append(_sticky_chain(f"ob_u{n}", n, alive))

    fwd = [
        "\tchain c_forward {",
        "\t\ttype filter hook forward priority filter; policy accept;",
        f"\t\tmeta mark {config.MARK_BLOCK:#x} reject with icmp type admin-prohibited",
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

    if marks:
        # TCP 80/443 клиентов с правилами по доменам — в sniproxy.py на адресе сервера в туннеле
        out.append(f"""\tchain c_sniff {{
\t\ttype nat hook prerouting priority dstnat; policy accept;
\t\tiifname "{wg_iface}" meta mark {config.SNIFF_MARK:#x} meta l4proto tcp redirect to :{int(sniff_port)}
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
            out.append(_policy_chain("q_" + n, policies[n], available, False, oq, local_guard=True))
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
