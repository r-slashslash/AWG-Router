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


def out_chain(out) -> str:
    if out == "direct":
        return "o_direct"
    if out == "block":
        return "o_block"
    return f"o_u{int(out)}"


def mark_for(num: int) -> int:
    return config.MARK_BASE + num


def _policy_key(policy: dict) -> tuple:
    return (tuple((tuple(l), o) for l, o in policy["rules"]), policy["default"])


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


def _policy_chain(name: str, policy: dict, available: set[str]) -> str:
    lines = [f"\tchain {name} {{"]
    for list_ids, out in policy["rules"]:
        for lid in list_ids:
            if lid in available:
                lines.append(f"\t\tip daddr @l_{lid} goto {out_chain(out)}")
    lines.append(f"\t\tgoto {out_chain(policy['default'])}")
    lines.append("\t}")
    return "\n".join(lines)


def generate(wg_iface: str, lists: dict[str, list[str]], upstreams: list[dict],
             global_policy: dict, client_policies: dict[str, dict]) -> str:
    T = config.NFT_TABLE
    up_nums = {u["num"] for u in upstreams}

    def norm(policy: dict) -> dict:
        # выход на несуществующий туннель → блок (безопасный вариант)
        fix = lambda o: o if o in ("direct", "block") or o in up_nums else "block"
        rules = [(l, fix(o)) for l, o in policy["rules"]]
        default = fix(policy["default"])
        while rules and rules[-1][1] == default:  # хвостовые правила ничего не меняют
            rules.pop()
        return {"rules": rules, "default": default}

    gp = norm(global_policy)
    # уникальные политики клиентов
    chains: dict[tuple, str] = {_policy_key(gp): "p_global"}
    client_map: dict[str, str] = {}
    for ip, pol in sorted(client_policies.items()):
        p = norm(pol)
        key = _policy_key(p)
        if key not in chains:
            chains[key] = f"p_{len(chains)}"
        if chains[key] != "p_global":
            client_map[ip] = chains[key]
    policies: dict[str, dict] = {"p_global": gp}
    for pol in client_policies.values():
        p = norm(pol)
        policies.setdefault(chains[_policy_key(p)], p)

    used_lists = sorted({lid for p in policies.values() for l, _ in p["rules"] for lid in l})
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

    out.append(f"""\tchain c_prerouting {{
\t\ttype filter hook prerouting priority mangle; policy accept;
\t\tiifname != "{wg_iface}" return
\t\tip daddr @local4 return
\t\tip saddr vmap @clients
\t\tgoto p_global
\t}}""")

    for name in sorted(policies, key=lambda n: (n != "p_global", n)):
        out.append(_policy_chain(name, policies[name], available))

    out.append("\tchain o_direct {\n\t\taccept\n\t}")
    out.append(f"\tchain o_block {{\n\t\tmeta mark set {config.MARK_BLOCK:#x} accept\n\t}}")
    for u in sorted(upstreams, key=lambda x: x["num"]):
        out.append(f"\tchain o_u{u['num']} {{\n\t\tmeta mark set {mark_for(u['num']):#x} accept\n\t}}")

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

    post = ["\tchain c_postrouting {",
            "\t\ttype nat hook postrouting priority srcnat; policy accept;"]
    for u in sorted(upstreams, key=lambda x: x["num"]):
        ifn = f"{config.IFACE_PREFIX}{u['num']}"
        # адрес туннеля не назначаем на интерфейс (он часто пересекается с подсетью
        # наших же клиентов 10.8.1.0/24), а подставляем через SNAT
        post.append(f'\t\toifname "{ifn}" snat to {u["snat"]}')
    post.append("\t}")
    out.append("\n".join(post))

    out.append("}")
    return "\n".join(out) + "\n"
