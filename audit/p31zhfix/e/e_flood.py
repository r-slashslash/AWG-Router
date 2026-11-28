"""Е: поток одного и того же «мёртвого» запроса (риск R4 своей карты): сколько памяти и задач держит dnsproxy.py, когда
«последователи» не занимают мест клиентов (MAX_INFLIGHT). Одна версия за прогон.
Запуск: unshare -rn python3 -I e_flood.py <old|new|fix> [RATE в секунду] [DUR с] [NAMES — сколько разных мёртвых имён]"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402

VER = sys.argv[1]
RATE = float(sys.argv[2]) if len(sys.argv) > 2 else 3000
DUR = float(sys.argv[3]) if len(sys.argv) > 3 else 20
NAMES = int(sys.argv[4]) if len(sys.argv) > 4 else 1


async def main():
    lab.lo_up()
    await lab.start_servers(h3=False)
    p = lab.Proxy(VER, {"listen": "127.0.1.9"})
    cl = lab.Clients()
    await asyncio.sleep(1.0)
    await lab.ready(cl, [p])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.2.77", 0))
    s.setblocking(False)
    names = [f"dead{lab.uid()}.example" for _ in range(NAMES)]
    msgs = [lab.qmsg(n) for n in names]
    samples, sent, got = [], 0, 0
    t0 = time.monotonic()
    nxt = t0
    while time.monotonic() - t0 < DUR:
        now = time.monotonic()
        while nxt <= now:
            try:
                s.sendto(msgs[sent % len(msgs)], (p.listen, 53))
                sent += 1
            except BlockingIOError:
                pass
            nxt += 1.0 / RATE
        try:
            while True:
                s.recv(4096)
                got += 1
        except BlockingIOError:
            pass
        if not samples or now - t0 - samples[-1][0] >= 2:
            try:
                samples.append((round(now - t0, 1), *p.rss_threads_fds()))
            except OSError:
                pass
        await asyncio.sleep(0.002)
    for _ in range(15):                         # ответы, которые ещё в пути
        await asyncio.sleep(1)
        try:
            while True:
                s.recv(4096)
                got += 1
        except BlockingIOError:
            pass
        samples.append((round(time.monotonic() - t0, 1), *p.rss_threads_fds()))
    st = await p.fresh_stats()
    p.stop()
    print(json.dumps({"ver": VER, "rate": RATE, "dur": DUR, "names": NAMES, "sent": sent, "answers": got,
                      "rss_max_kb": max(x[1] for x in samples), "samples": samples,
                      "stats": {k: st.get(k) for k in ("queries", "errors", "joined", "checks", "fb_checks")}}),
          flush=True)
    os._exit(0)


asyncio.run(main())
