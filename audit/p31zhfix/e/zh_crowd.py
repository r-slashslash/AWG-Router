"""Ж: пределы Е3 (JOIN_MAX 1024 на запрос, JOIN_ALL 8192 всего) при 1000 клиентах в начале настоящей блокировки.
Устройства повторяют запрос, пока нет ответа: половина — как Windows/iOS (1, 1, 2, 4 с…), половина — как Android/Linux
(каждые 5 с). Имена — по закону Ципфа из POOL популярных (у стенда TTL 0: каждое — к серверам, это худший случай) и
доля новых. Блокировка (ClientHello общих DoH теряется) — с BLOCK_AT до конца. Одна версия за прогон.
Печатает: исходы имён до и во время блокировки, SERVFAIL, join_full, joined, join_checks, checks, ждали > 5 / 9 с,
память и процессор dnsproxy.py.
Запуск: unshare -rn python3 -I zh_crowd.py <old|new|fix> [RATE] [DUR] [BLOCK_AT] [ZIPF_S]"""
from __future__ import annotations

import asyncio
import bisect
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402
from lab import FB_UDP, SHARED_DOH  # noqa: E402

VER = sys.argv[1]
RATE = float(sys.argv[2]) if len(sys.argv) > 2 else 300
DUR = float(sys.argv[3]) if len(sys.argv) > 3 else 60
BLOCK_AT = float(sys.argv[4]) if len(sys.argv) > 4 else 20
ZS = float(sys.argv[5]) if len(sys.argv) > 5 else 1.0
POOL = 3000
DEVICES = 1000


class Dev(asyncio.DatagramProtocol):
    def __init__(self):
        self.wait: dict[int, asyncio.Future] = {}

    def datagram_received(self, data, addr):
        qid = int.from_bytes(data[:2], "big")
        f = self.wait.get(qid)
        if f and not f.done():
            f.set_result(data)


async def main():
    lab.lo_up()
    await lab.start_servers(h3=False)
    p = lab.Proxy(VER, {"upstreams": SHARED_DOH, "encrypt": "doh", "direct_fallback": [FB_UDP],
                        "clients": "127.0.0.0/8"})
    cl = lab.Clients()
    await asyncio.sleep(0.6)
    await lab.ready(cl, [p])
    loop = asyncio.get_running_loop()
    devs = []
    for i in range(DEVICES):
        src = f"127.1.{i // 250}.{1 + i % 250}"
        proto = Dev()
        tr, _ = await loop.create_datagram_endpoint(lambda pr=proto: pr, local_addr=(src, 0))
        devs.append((tr, proto, "win" if i % 2 == 0 else "android"))
    w = [1.0 / (k + 1) ** ZS for k in range(POOL)]
    cum, s = [], 0.0
    for x in w:
        s += x
        cum.append(s)
    rnd = random.Random(5)
    rows = []                       # (момент, фаза, задержка, итог, отправок)
    t0 = time.monotonic()

    async def ask(dev, name):
        tr, pr, kind = dev
        qid = rnd.randrange(65536)
        while qid in pr.wait:
            qid = rnd.randrange(65536)
        fut = loop.create_future()
        pr.wait[qid] = fut
        msg = lab.qmsg(name, qid=qid)
        start = time.monotonic()
        at = start - t0
        sched = [1, 1, 2, 4, 4, 8] if kind == "win" else [5, 5, 5, 5, 5, 5]
        sent, k = 0, 0
        try:
            while time.monotonic() - start < 30:
                tr.sendto(msg, (p.listen, 53))
                sent += 1
                try:
                    await asyncio.wait_for(asyncio.shield(fut), sched[min(k, len(sched) - 1)])
                    break
                except asyncio.TimeoutError:
                    k += 1
            if not fut.done():
                rows.append((at, at >= BLOCK_AT, time.monotonic() - start, "timeout", sent))
                return
            rc, a, _tc = lab.parse(fut.result())
            r = "servfail" if rc == 2 else ("fallback" if a and int(a.rsplit(".", 1)[1]) >= 10 else
                                             "shared" if a else f"rc{rc}")
            rows.append((at, at >= BLOCK_AT, time.monotonic() - start, r, sent))
        finally:
            pr.wait.pop(qid, None)

    def pick():
        if rnd.random() < 0.3:
            return f"u{lab.uid()}.example"
        return f"pz{bisect.bisect_left(cum, rnd.random() * s)}.example"

    tasks = []
    blocked = False
    cpu0 = None
    rss_max = 0
    nxt = t0
    while time.monotonic() - t0 < DUR:
        now = time.monotonic()
        if not blocked and now - t0 >= BLOCK_AT:
            lab.nft(f"""table ip blk {{ chain in {{ type filter hook input priority 0; policy accept;
                ip daddr {{ {", ".join(SHARED_DOH)} }} tcp dport {lab.UP_PORT} ip length > 120 drop
            }} }}""")
            blocked = True
        while nxt <= now:
            tasks.append(asyncio.create_task(ask(devs[rnd.randrange(DEVICES)], pick())))
            nxt += rnd.expovariate(RATE)
        if int(now - t0) % 5 == 0:
            try:
                rss_max = max(rss_max, p.rss_threads_fds()[0])
            except OSError:
                pass
        if cpu0 is None:
            cpu0 = _cpu(p.proc.pid)
        await asyncio.sleep(0.005)
    cpu1 = _cpu(p.proc.pid)
    await asyncio.gather(*tasks)
    st = await p.fresh_stats()
    p.stop()

    def summ(sel):
        out = {}
        for _a, _b, dt, r, _s in sel:
            out.setdefault(r, []).append(dt)
        res = {}
        for r, v in out.items():
            v.sort()
            res[r] = {"n": len(v), "med": round(v[len(v) // 2], 3), "max": round(v[-1], 2),
                      "over5": sum(x > 5 for x in v), "over9": sum(x > 9 for x in v)}
        return res
    pre = [r for r in rows if not r[1]]
    blk = [r for r in rows if r[1]]
    early = [r for r in blk if r[0] < BLOCK_AT + 15]
    # по секундам от начала блокировки: исходы вопросов, заданных в эту секунду, и когда пришёл первый ответ запасного
    tl = {}
    for at, b, dt, r, _s in blk:
        k = int(at - BLOCK_AT)
        if k < 30:
            tl.setdefault(k, {})
            tl[k][r] = tl[k].get(r, 0) + 1
    fb_first = min((at + dt - BLOCK_AT for at, b, dt, r, _s in blk if r == "fallback"), default=None)
    return {"ver": VER, "rate": RATE, "zipf": ZS, "names": len(rows), "before": summ(pre), "blocking": summ(blk),
            "timeline": {str(k): tl[k] for k in sorted(tl)}, "first_fallback_answer_s": fb_first and round(fb_first, 2),
            "blocking_first15s": summ(early), "sent_total": sum(r[4] for r in rows),
            "cpu_s": round(cpu1 - cpu0, 2), "rss_max_kb": rss_max,
            "stats": {k: st.get(k) for k in ("queries", "errors", "joined", "join_full", "join_checks", "checks",
                                             "direct_fallback", "cached")}}


def _cpu(pid):
    with open(f"/proc/{pid}/stat") as f:
        x = f.read().rsplit(")", 1)[1].split()
    return (int(x[11]) + int(x[12])) / os.sysconf("SC_CLK_TCK")


if __name__ == "__main__":
    out = asyncio.run(main())
    print(json.dumps(out), flush=True)
    os._exit(0)
