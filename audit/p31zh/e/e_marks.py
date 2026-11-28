"""Е: объединение одинаковых запросов (Д1) на настоящем ядре — не смешивает пути. Запуск как marks.py проверки П31: в сети
srv (ip netns exec srv), серверы в inet (LAB_SRV_NS, LAB_NET=10.99.1., LAB_NFT_NS). В srv: 10.99.0.2 — адрес системы
(метка 0), .3 — «Напрямую — адрес» (0x2101), .4 — «выход» (0x2001).
Клиенты: C1 — напрямую, у него правило по доменам *.rule.example без пути (выход лежит); C2 — «Напрямую — адрес»;
C3 — через выход; C4 — напрямую без правил; C5 — напрямую, по SIGHUP уходит в выход.
P1: одно и то же медленное имя сразу от C1, C2, C3, C4 — серверы должны получить его с .2, .3 и .4 (C1 и C4 — один путь).
P2: общие DoH режут; одно и то же имя правила от C1 (без пути) и C4 (обычный) — с повторами; одно и то же обычное имя от C3
    (выход) и C4. Ответ запасного у C1 и C3 — нарушение; имя у запасного не с .2 — нарушение.
P3: медленное имя от C5 (напрямую); SIGHUP — C5 через выход; повтор того же имени — должен уйти с .4 (не к старой задаче).
Печатает JSON с нарушениями."""
from __future__ import annotations

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
C1, C2, C3, C4, C5 = "127.0.2.1", "127.0.2.2", "127.0.2.3", "127.0.2.4", "127.0.2.5"
FALLBACK = {lab.FB_UDP, lab.FB_DOT, lab.FB_DOH, lab.FB_H3, lab.FB_UDP2}
VER = os.environ.get("MARKS_VER", "new")


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
    bad, notes = [], {}

    # P1: одно медленное имя сразу от четырёх клиентов
    for i in range(5):
        name = f"slow2-p1-{lab.uid()}.example"
        mark0 = len(lab.LOG)
        rs = await asyncio.gather(*(ask_retry(p.listen, name, c, 5.0, 15) for c in (C1, C2, C3, C4)))
        srcs = sorted({e[2] for e in lab.LOG[mark0:] if e[4] == name + "."})
        notes.setdefault("p1_sources", []).append(srcs)
        if not {SYS, ADDR, EXIT} <= set(srcs):
            bad.append(("P1: не все пути спросили имя", name, srcs))
        if any(r[1] != "shared" for r in rs):
            bad.append(("P1: не ответ общих", name, rs))

    # P2: блокировка общих DoH (SYN и данные), одинаковые имена у разных путей
    lab.nft(f"table ip blk {{ chain in {{ type filter hook input priority 0; policy accept;\n"
            f"ip daddr {{ {', '.join(SHARED_DOH)} }} tcp dport {lab.UP_PORT} drop\n}} }}")
    t_end = time.monotonic() + 40
    p2 = {"C1_rule": [], "C4_rule": [], "C3_name": [], "C4_name": []}
    tasks = []
    while time.monotonic() < t_end:
        rn, nn = f"x{lab.uid()}.rule.example", f"y{lab.uid()}.example"

        async def pair(rn=rn, nn=nn):
            a, b, c, e = await asyncio.gather(ask_retry(p.listen, rn, C1, 1.0, 30), ask_retry(p.listen, rn, C4, 1.0, 30),
                                              ask_retry(p.listen, nn, C3, 1.0, 30), ask_retry(p.listen, nn, C4, 1.0, 30))
            p2["C1_rule"].append(a[1])
            p2["C4_rule"].append(b[1])
            p2["C3_name"].append(c[1])
            p2["C4_name"].append(e[1])
        tasks.append(asyncio.create_task(pair()))
        await asyncio.sleep(0.7)
    await asyncio.gather(*tasks)
    pre = ["ip", "netns", "exec", lab.NFT_NS] if lab.NFT_NS else []
    subprocess.run([*pre, "nft", "delete", "table", "ip", "blk"], capture_output=True)
    for k, v in p2.items():
        notes["p2_" + k] = {r: v.count(r) for r in set(v)}
    if "fallback" in p2["C1_rule"]:
        bad.append(("P2: имя правила без пути получило ответ запасного", p2["C1_rule"].count("fallback")))
    if "fallback" in p2["C3_name"]:
        bad.append(("P2: имя через выход получило ответ запасного", p2["C3_name"].count("fallback")))
    for t, srv, src, kind, name in lab.LOG:
        if srv in FALLBACK and src not in (SYS, "?"):
            bad.append(("запасной спрошен не с адреса системы", srv, src, name))
        if srv in FALLBACK and name.startswith("y") and src == EXIT:
            bad.append(("имя через выход у запасного", srv, src, name))

    # P3: SIGHUP посреди запроса — повтор того же имени идёт новым путём
    await asyncio.sleep(3)
    for i in range(5):
        name = f"slow3-p3-{lab.uid()}.example"
        p.cfg["routes"] = dict(routes)
        p.hup()
        await asyncio.sleep(0.5)
        first = asyncio.create_task(ask_retry(p.listen, name, C5, 10.0, 15))
        await asyncio.sleep(0.5)
        p.hup(routes={**routes, C5: {"mark": 0x2001, "tcp": False}})
        await asyncio.sleep(0.3)
        mark0 = len(lab.LOG)
        second = await ask_retry(p.listen, name, C5, 10.0, 15)
        await first
        srcs = sorted({e[2] for e in lab.LOG[mark0:] if e[4] == name + "."})
        notes.setdefault("p3_sources_after_hup", []).append(srcs)
        if EXIT not in srcs:
            bad.append(("P3: после SIGHUP повтор не ушёл через выход", name, srcs, second))
    # P4: SIGHUP сменил общие серверы (ключ запроса тот же) — повтор не должен ждать задачу к прежним серверам
    for i in range(3):
        name = f"slow3-p4-{lab.uid()}.example"
        p.hup(routes=dict(routes), upstreams=SHARED_DOH, encrypt="doh")
        await asyncio.sleep(0.5)
        first = asyncio.create_task(ask_retry(p.listen, name, C4, 10.0, 15))
        await asyncio.sleep(0.5)
        p.hup(upstreams=lab.SHARED_DOT, encrypt="dot")
        await asyncio.sleep(0.3)
        mark0 = len(lab.LOG)
        await ask_retry(p.listen, name, C4, 10.0, 15)
        await first
        kinds = sorted({(e[1], e[3]) for e in lab.LOG[mark0:] if e[4] == name + "."})
        notes.setdefault("p4_after_hup", []).append(kinds)
        if not any(k == "dot" for _s, k in kinds):
            bad.append(("P4: после смены серверов повтор не спросил новые", name, kinds))
    st = await p.fresh_stats()
    p.stop()
    print(json.dumps({"ver": VER, "violations": bad[:40], "n_violations": len(bad), "notes": notes,
                      "stats": {k: st.get(k) for k in ("joined", "checks", "direct_fallback", "errors")}},
                     ensure_ascii=False), flush=True)
    os._exit(0)


if __name__ == "__main__":
    asyncio.run(main())
