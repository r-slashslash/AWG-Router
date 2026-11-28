"""Ж: признак stage (Е1) и объединение не смешивают пути на настоящем ядре (сети e_net.sh: 10.99.0.2 — адрес системы,
.3 — «Напрямую — адрес» 0x2101, .4 — выход 0x2001). Общие DoH блокируются (данные теряются), клиенты повторяют запрос
раз в 1 с; одни и те же имена одновременно у: C4 — напрямую с адреса системы, C2 — «Напрямую — адрес», C3 — через выход,
C1 — правило без пути (имена *.rule.example). Нарушения: ответ запасного клиенту через выход или имени правила без пути;
запрос к запасному с адреса выхода; имя, которое спрашивали только с «Напрямую — адрес», у запасного с адреса системы (и
наоборот). Во время блокировки путь проходит «проверяется» и «не отвечает» — то есть оба значения stage.
Запуск: MARKS_VER=fix e_net.sh run … zh_marks.py"""
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402
from e_retry import ask_retry  # noqa: E402
from lab import FB_UDP, SHARED_DOH  # noqa: E402

SYS, ADDR, EXIT = "10.99.0.2", "10.99.0.3", "10.99.0.4"
C1, C2, C3, C4 = "127.0.2.1", "127.0.2.2", "127.0.2.3", "127.0.2.4"
FALLBACK = {lab.FB_UDP, lab.FB_DOT, lab.FB_DOH, lab.FB_H3, lab.FB_UDP2}
VER = os.environ.get("MARKS_VER", "fix")


async def main():
    lab.lo_up()
    await lab.start_servers(h3=False)
    d = tempfile.mkdtemp()
    lst = os.path.join(d, "rule.txt")
    with open(lst, "w") as f:
        f.write("rule.example\n")
    routes = {C2: {"mark": 0x2101, "tcp": False}, C3: {"mark": 0x2001, "tcp": False}}
    cfg = {"upstreams": SHARED_DOH, "encrypt": "doh", "routes": routes,
           "dom": {"lists": {"l": lst}, "clients": {C1: "p_rule"}, "set": None,
                   "policies": {"p_rule": [[["l"], None]]}},
           "direct_fallback": [FB_UDP]}
    p = lab.Proxy(VER, cfg)
    cl = lab.Clients()
    await asyncio.sleep(0.8)
    await lab.ready(cl, [p])
    bad, res = [], {k: {} for k in ("sys_name", "addr_name", "exit_same_as_sys", "exit_same_as_addr", "rule_c1",
                                    "rule_c4")}
    asked_by = {}
    lab.nft(f"table ip blk {{ chain in {{ type filter hook input priority 0; policy accept;\n"
            f"ip daddr {{ {', '.join(SHARED_DOH)} }} tcp dport {lab.UP_PORT} ip length > 120 drop\n}} }}")
    t_end = time.monotonic() + 50
    tasks = []

    def note(k, r):
        res[k][r[1]] = res[k].get(r[1], 0) + 1

    while time.monotonic() < t_end:
        w, z, rn = f"w{lab.uid()}.example", f"z{lab.uid()}.example", f"x{lab.uid()}.rule.example"
        asked_by[w + "."], asked_by[z + "."] = "sys", "addr"

        async def group(w=w, z=z, rn=rn):
            a, b, c, e, f, g = await asyncio.gather(
                ask_retry(p.listen, w, C4, 1.0, 30), ask_retry(p.listen, z, C2, 1.0, 30),
                ask_retry(p.listen, w, C3, 1.0, 30), ask_retry(p.listen, z, C3, 1.0, 30),
                ask_retry(p.listen, rn, C1, 1.0, 30), ask_retry(p.listen, rn, C4, 1.0, 30))
            note("sys_name", a)
            note("addr_name", b)
            note("exit_same_as_sys", c)
            note("exit_same_as_addr", e)
            note("rule_c1", f)
            note("rule_c4", g)
        tasks.append(asyncio.create_task(group()))
        await asyncio.sleep(0.6)
    await asyncio.gather(*tasks)
    for k in ("exit_same_as_sys", "exit_same_as_addr", "rule_c1"):
        if res[k].get("fallback"):
            bad.append((k + ": ответ запасного", res[k]["fallback"]))
    fb_src = {}
    for _t, srv, src, _kind, name in lab.LOG:
        if srv not in FALLBACK:
            continue
        fb_src[src] = fb_src.get(src, 0) + 1
        if src == EXIT:
            bad.append(("запасной спрошен с адреса выхода", name))
        who = asked_by.get(name)
        if who == "sys" and src == ADDR:
            bad.append(("имя адреса системы у запасного с «Напрямую — адрес»", name))
        if who == "addr" and src == SYS:
            bad.append(("имя «Напрямую — адрес» у запасного с адреса системы", name))
        if name.endswith(".rule.example.") and src != SYS:
            bad.append(("имя правила у запасного не с адреса системы", name, src))
    st = await p.fresh_stats()
    p.stop()
    print(json.dumps({"ver": VER, "n_violations": len(bad), "violations": bad[:30], "results": res,
                      "fallback_senders": fb_src,
                      "stats": {k: st.get(k) for k in ("joined", "join_checks", "join_full", "checks", "direct_fallback",
                                                       "errors")}}, ensure_ascii=False), flush=True)
    os._exit(0)


if __name__ == "__main__":
    asyncio.run(main())
