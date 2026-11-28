"""Ж: признак stage и проверка от повтора (Е1) при нескольких путях «Напрямую — адрес», SIGHUP посреди ожидания, смене
и выключении запасного и на пути без запасного. Песочница: пути различает метка сокета; блокировка — правило nftables
в хуке output по метке (meta mark), счётчики — сколько запросов к запасному ушло с какой меткой. Клиенты повторяют
запрос через 1 с. Одна версия за прогон (VER), сравнить: new (c934013) и fix (b87eaa5).
Запуск: unshare -rn python3 -I zh_paths.py <old|new|fix>"""
import asyncio
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402
from e_retry import ask_retry  # noqa: E402
from lab import FB_UDP, FB_UDP2, SHARED_DOH  # noqa: E402

VER = sys.argv[1]
A, B = 0x2101, 0x2102
CA, CB, CS = "127.0.2.11", "127.0.2.12", "127.0.2.13"      # клиенты путей A, B и адреса системы


def table(block_marks=()):
    """Счётчики запросов к запасным по меткам; блокировка общих DoH для путей block_marks (данные теряются)."""
    blk = "".join(f"\t\tmeta mark {m:#x} ip daddr {{ {', '.join(SHARED_DOH)} }} tcp dport {lab.UP_PORT} ip length > 120 drop\n"
                  for m in block_marks)
    cnt = "".join(f"\t\tmeta mark {m:#x} ip daddr {fb} udp dport {lab.UP_PORT} counter\n"
                  for m in (0, A, B) for fb in (FB_UDP, FB_UDP2))
    subprocess.run(["nft", "delete", "table", "ip", "zh"], capture_output=True)
    lab.nft(f"table ip zh {{ chain o {{ type filter hook output priority 0; policy accept;\n{blk}{cnt}}} }}")


def counters():
    out = json.loads(subprocess.run(["nft", "-j", "list", "chain", "ip", "zh", "o"], capture_output=True, text=True).stdout)
    res = {}
    for x in out["nftables"]:
        r = x.get("rule")
        if not r or not any("counter" in e for e in r["expr"]):
            continue
        mark = dst = None
        for e in r["expr"]:
            m = e.get("match")
            if m and m["left"].get("meta", {}).get("key") == "mark":
                mark = m["right"]
            if m and m["left"].get("payload", {}).get("field") == "daddr":
                dst = m["right"]
        n = next(e["counter"]["packets"] for e in r["expr"] if "counter" in e)
        if n:
            res[f"{mark:#x}->{dst}"] = n
    return res


async def stream(p, src, dur, prefix, rows, retry=1.0, every=0.5):
    t0 = time.monotonic()
    tasks = []

    async def one():
        t = time.monotonic() - t0
        dt, r, _s = await ask_retry(p.listen, f"{prefix}{lab.uid()}.example", src, retry, 40)
        rows.append((round(t, 2), round(dt, 3), r))
    while time.monotonic() - t0 < dur:
        tasks.append(asyncio.create_task(one()))
        await asyncio.sleep(every)
    await asyncio.gather(*tasks)


def summ(rows):
    out = {}
    for _t, dt, r in rows:
        out.setdefault(r, []).append(dt)
    return {r: {"n": len(v), "max": max(v), "over2": sum(x > 2 for x in v), "over6": sum(x > 6 for x in v),
                "over10": sum(x > 10 for x in v)} for r, v in out.items()}


async def main():
    lab.lo_up()
    await lab.start_servers(h3=False)
    routes = {CA: {"mark": A, "tcp": False}, CB: {"mark": B, "tcp": False}}
    res = {}

    # 1. блокировка только у пути A: A — у запасного быстро и только со своей меткой; B и адрес системы — не задеты
    table()
    p = lab.Proxy(VER, {"upstreams": SHARED_DOH, "encrypt": "doh", "direct_fallback": [FB_UDP], "routes": routes,
                        "addr_marks": [0x2101, 0x2110]})
    cl = lab.Clients()
    await asyncio.sleep(0.6)
    await lab.ready(cl, [p])
    for src in (CA, CB, CS):                                    # пулы всех путей открыты
        await asyncio.gather(*(ask_retry(p.listen, f"pre{lab.uid()}.example", src, 1.0, 10) for _ in range(4)))
    table(block_marks=(A,))
    ra, rb, rs = [], [], []
    await asyncio.gather(stream(p, CA, 25, "a", ra), stream(p, CB, 25, "b", rb), stream(p, CS, 25, "s", rs))
    st = await p.fresh_stats()
    res["one_path_blocked"] = {"A": summ(ra), "B": summ(rb), "system": summ(rs), "fallback_by_mark": counters(),
                               "stats": {k: st.get(k) for k in ("checks", "join_checks", "joined", "direct_fallback")},
                               "addr_direct": st.get("addr_direct"), "fb_paths": st.get("fb_paths")}

    # 2. SIGHUP посреди ожидания (путь A блокирован заново): запасной меняется на FB_UDP2 — ждавшие и новые идут к нему
    p.stop()
    table()
    p = lab.Proxy(VER, {"upstreams": SHARED_DOH, "encrypt": "doh", "direct_fallback": [FB_UDP], "routes": routes,
                        "addr_marks": [0x2101, 0x2110]})
    await asyncio.sleep(0.6)
    await lab.ready(cl, [p])
    await asyncio.gather(*(ask_retry(p.listen, f"pre{lab.uid()}.example", CA, 1.0, 10) for _ in range(4)))
    table(block_marks=(A,))
    rows = []

    async def hup_later():
        await asyncio.sleep(3.0)
        p.hup(direct_fallback=[FB_UDP2])
    await asyncio.gather(stream(p, CA, 20, "h", rows), hup_later())
    res["sighup_change_fallback"] = {"A": summ(rows), "fallback_by_mark": counters()}

    # 3. запасной выключен посреди ожидания: ждавшие — SERVFAIL, а не ответ прежнего запасного
    p.stop()
    table()
    p = lab.Proxy(VER, {"upstreams": SHARED_DOH, "encrypt": "doh", "direct_fallback": [FB_UDP], "routes": routes,
                        "addr_marks": [0x2101, 0x2110]})
    await asyncio.sleep(0.6)
    await lab.ready(cl, [p])
    await asyncio.gather(*(ask_retry(p.listen, f"pre{lab.uid()}.example", CA, 1.0, 10) for _ in range(4)))
    table(block_marks=(A,))
    rows = []

    async def off_later():
        await asyncio.sleep(3.0)
        p.hup(direct_fallback=[])
    await asyncio.gather(stream(p, CA, 20, "o", rows), off_later())
    res["sighup_fallback_off"] = {"A": summ(rows), "fallback_by_mark": counters()}

    # 4. путь без запасного: повторы объединяются, проверок от повтора нет
    p.stop()
    table()
    p = lab.Proxy(VER, {"upstreams": SHARED_DOH, "encrypt": "doh", "direct_fallback": [], "routes": routes,
                        "addr_marks": [0x2101, 0x2110]})
    await asyncio.sleep(0.6)
    await lab.ready(cl, [p])
    table(block_marks=(0,))
    rows = []
    await stream(p, CS, 20, "n", rows)
    st = await p.fresh_stats()
    res["no_fallback"] = {"system": summ(rows),
                          "stats": {k: st.get(k) for k in ("checks", "join_checks", "joined", "direct_fallback",
                                                           "errors")}}
    p.stop()
    print(json.dumps({"ver": VER, "result": res}), flush=True)
    os._exit(0)


if __name__ == "__main__":
    asyncio.run(main())
