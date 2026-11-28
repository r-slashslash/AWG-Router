"""Долгий прогон (П31, ж): DUR с, блокировка включается и выключается по кругу (4 мин: 90 с всё работает, 90 с RST на
ClientHello общих, 60 с общие и запасной HTTP/3 замерзают), запасной по кругу — HTTP/3, DoH, обычный (SIGHUP), обычные
имена 20 в секунду, «мёртвое» имя у общих и у запасного раз в 5 с. До и после рядом; раз в 30 с — память, потоки,
дескрипторы каждого процесса. Запуск: unshare -rn python3 -I soak.py [DUR]"""
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402

DUR = float(sys.argv[1]) if len(sys.argv) > 1 else 2400
FBS = [[f"h3://{lab.FB_H3}/dns-query"], [f"https://{lab.FB_DOH}/dns-query"], [lab.FB_UDP]]
RST = (f"table ip blk {{ chain in {{ type filter hook input priority 0; policy accept;\n"
       f"ip daddr {{ {', '.join(lab.SHARED_DOH)} }} tcp dport {lab.UP_PORT} ip length > 120 reject with tcp reset\n}} }}")


async def main():
    lab.lo_up()
    await lab.start_servers(h3=True)
    ps = {v: lab.Proxy(v, {"direct_fallback": FBS[0]}) for v in os.environ.get("LAB_VERS", "old,new").split(",")}
    cl = lab.Clients()
    await asyncio.sleep(1.0)
    await lab.ready(cl, ps.values())
    t0 = time.monotonic()
    samples = {v: [] for v in ps}
    counts = {v: {} for v in ps}

    async def ask(p, v, name, timeout=30):
        _, r = await cl.ask(p.listen, name, timeout=timeout)
        counts[v][r] = counts[v].get(r, 0) + 1

    async def names():
        tasks = []
        while time.monotonic() - t0 < DUR:
            for v, p in ps.items():
                tasks.append(asyncio.create_task(ask(p, v, f"n{lab.uid()}.example")))
            if len(tasks) > 2000:
                await asyncio.gather(*tasks)
                tasks = []
            await asyncio.sleep(0.05)
        await asyncio.gather(*tasks)

    async def deads():
        tasks = []
        while time.monotonic() - t0 < DUR:
            for v, p in ps.items():
                tasks.append(asyncio.create_task(ask(p, v, f"dead{lab.uid()}.example", 60)))
                tasks.append(asyncio.create_task(ask(p, v, f"fbdead{lab.uid()}.example", 60)))
            await asyncio.sleep(5)
        await asyncio.gather(*tasks)

    async def cycle():
        k = 0
        while time.monotonic() - t0 < DUR:
            await asyncio.sleep(90)
            lab.nft(RST)
            await asyncio.sleep(90)
            lab.nft("delete table ip blk")
            lab.B["frozen"].update(lab.SHARED_DOH + [lab.FB_H3])
            await asyncio.sleep(60)
            lab.B["frozen"].clear()
            k += 1
            for p in ps.values():
                p.hup(direct_fallback=FBS[k % 3])

    async def sample():
        while time.monotonic() - t0 < DUR + 5:
            for v, p in ps.items():
                try:
                    samples[v].append((round(time.monotonic() - t0),) + p.rss_threads_fds())
                except OSError:
                    pass
            await asyncio.sleep(30)
    await asyncio.gather(names(), deads(), cycle(), sample())
    out = {}
    for v, p in ps.items():
        s = samples[v]
        third = len(s) // 3
        out[v] = {"answers": counts[v], "first": s[1] if len(s) > 1 else None, "last": s[-1],
                  "rss_kb_min_max": [min(x[1] for x in s[1:]), max(x[1] for x in s)],
                  "rss_kb_avg_first_third": round(sum(x[1] for x in s[1:third]) / max(1, third - 1)),
                  "rss_kb_avg_last_third": round(sum(x[1] for x in s[-third:]) / max(1, third)),
                  "threads_max": max(x[2] for x in s), "fds_max": max(x[3] for x in s),
                  "fds_last": s[-1][3], "threads_last": s[-1][2], "series": s[::4]}
        p.stop()
    print(json.dumps(out), flush=True)
    os._exit(0)


asyncio.run(main())
