"""Объёмы (П31, ж): 1000 клиентов на 17 путях (адрес системы и 16 «Напрямую — адрес»), RATE запросов в секунду новых
имён, «мёртвые» имена потоком и всплеск в BURST мёртвых имён разом. Одна версия за прогон (процессор не делится).
Печатает задержки обычных имён, SERVFAIL, сколько у запасного, проверки, процессор, память, потоки и дескрипторы.
Запуск: unshare -rn python3 -I load.py <old|new|fix> [RATE] [DUR] [BURST]"""
import asyncio
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402

VER = sys.argv[1]
RATE = float(sys.argv[2]) if len(sys.argv) > 2 else 200
DUR = float(sys.argv[3]) if len(sys.argv) > 3 else 120
BURST = int(sys.argv[4]) if len(sys.argv) > 4 else 300
MARKS = [0] + [0x2101 + k for k in range(16)]


def cpu(pid):
    with open(f"/proc/{pid}/stat") as f:
        v = f.read().rsplit(")", 1)[1].split()
    return (int(v[11]) + int(v[12])) / os.sysconf("SC_CLK_TCK")


async def main():
    lab.lo_up()
    await lab.start_servers(h3=False)
    clients = [f"127.0.{4 + i // 250}.{1 + i % 250}" for i in range(1000)]
    routes = {ip: {"mark": MARKS[i % 17], "tcp": False} for i, ip in enumerate(clients)}
    p = lab.Proxy(VER, {"routes": routes, "listen": "127.0.1.9"})
    cl = lab.Clients()
    await asyncio.sleep(1.0)
    await lab.ready(cl, [p])
    rows, dead, samples = [], [], []
    t0 = time.monotonic()
    c0 = cpu(p.proc.pid)

    async def one(name, src, sink, timeout=30):
        dt, r = await cl.ask(p.listen, name, src=src, timeout=timeout)
        sink.append((round(time.monotonic() - t0, 2), dt, r))

    async def normal():
        tasks = []
        while time.monotonic() - t0 < DUR:
            tasks.append(asyncio.create_task(one(f"n{lab.uid()}.example", random.choice(clients), rows)))
            await asyncio.sleep(1.0 / RATE)
        await asyncio.gather(*tasks)

    async def deads():
        tasks = []
        while time.monotonic() - t0 < DUR:                 # два новых мёртвых имени в секунду на случайных путях
            tasks.append(asyncio.create_task(one(f"dead{lab.uid()}.example", random.choice(clients), dead, 60)))
            await asyncio.sleep(0.5)
        await asyncio.gather(*tasks)

    async def burst():
        await asyncio.sleep(DUR / 3)
        await asyncio.gather(*(one(f"dead{lab.uid()}.example", random.choice(clients), dead, 60) for _ in range(BURST)))

    async def sample():
        while time.monotonic() - t0 < DUR + 25:
            try:
                rss, thr, fds = p.rss_threads_fds()
                samples.append((round(time.monotonic() - t0), rss, thr, fds))
            except OSError:
                pass
            await asyncio.sleep(10)
    await asyncio.gather(normal(), deads(), burst(), sample())
    c1 = cpu(p.proc.pid)
    st = await p.fresh_stats()
    p.stop()
    lat = sorted(x[1] for x in rows if x[2] in ("shared", "fallback"))
    q = (lambda f: round(lat[min(len(lat) - 1, int(len(lat) * f))], 3)) if lat else (lambda f: None)
    after = [x for x in rows if x[0] > DUR / 3]
    print(json.dumps({"ver": VER, "rate": RATE, "dur": DUR, "burst": BURST,
                      "normal": lab.summary(rows), "p50": q(0.5), "p95": q(0.95), "p99": q(0.99),
                      "after_burst": lab.summary(after), "dead": lab.summary(dead),
                      "cpu_s": round(c1 - c0, 1), "cpu_pct": round(100 * (c1 - c0) / DUR, 1),
                      "checks": st.get("checks"), "checks_ok": st.get("checks_ok"), "fb_checks": st.get("fb_checks"),
                      "direct_fallback": st.get("direct_fallback"), "paths_down": sum(
                          1 for k, v in (st.get("addr_direct") or {}).items() if v[1] > v[0]) + int(
                          (st.get("direct_fail_at") or 0) > (st.get("direct_ok_at") or 0)),
                      "samples": samples[-4:], "rss_max": max(s[1] for s in samples), "thr_max": max(s[2] for s in samples),
                      "fds_max": max(s[3] for s in samples)}), flush=True)
    os._exit(0)


asyncio.run(main())
