"""Е: одинаковые запросы при настоящей блокировке (риск R5 своей карты). Клиенты ведут себя как настоящие заглушки:
повторяют тот же запрос через RETRY с, пока не придёт ответ (Windows ~1 с, glibc и Android ~5 с). До (d7a90cc) и после
(c934013) — одновременно на одних серверах и одной блокировке (стенд lab.py проверки П31).
Запуск: unshare -rn python3 -I e_retry.py <stream|popular> kind=syn|hello|udp|freeze enc=doh|dot|plain retry=1 [pre_open=1]
Печатает JSON: время до первого ответа на каждый логический запрос, итог (shared/fallback/servfail/timeout)."""
from __future__ import annotations

import asyncio
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402
from lab import B, FB_UDP, SHARED_DOH, SHARED_DOT, SHARED_UDP  # noqa: E402

VERS = tuple(os.environ.get("LAB_VERS", "old,new").split(","))
BLOCKS = {
    "syn": "ip daddr {ips} tcp dport {port} tcp flags syn drop",
    "hello": "ip daddr {ips} tcp dport {port} ip length > 120 drop",
    "udp": "ip daddr {ips} udp dport {port} drop",
}


class _Ep(asyncio.DatagramProtocol):
    def __init__(self, fut):
        self.fut = fut

    def datagram_received(self, data, addr):
        if not self.fut.done():
            self.fut.set_result(data)


async def ask_retry(dst: str, name: str, src: str, retry: float, timeout: float = 40.0):
    """Один логический запрос со своего порта: тот же запрос (тот же ID) каждые retry с до ответа. → (с, итог, отправок)."""
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    tr, _ = await loop.create_datagram_endpoint(lambda: _Ep(fut), local_addr=(src, 0))
    msg = lab.qmsg(name)
    t0, sent = time.monotonic(), 0
    try:
        while not fut.done() and time.monotonic() - t0 < timeout:
            tr.sendto(msg, (dst, 53))
            sent += 1
            try:
                await asyncio.wait_for(asyncio.shield(fut), retry)
            except asyncio.TimeoutError:
                pass
        if not fut.done():
            return round(time.monotonic() - t0, 3), "timeout", sent
        dt = time.monotonic() - t0
        rc, a, _tc = lab.parse(fut.result())
        r = "servfail" if rc == 2 else ("fallback" if a and int(a.rsplit(".", 1)[1]) >= 10 else
                                         "shared" if a else f"rc{rc}")
        return round(dt, 3), r, sent
    finally:
        tr.close()


def summ(rows):
    out = {}
    for _t, dt, r, _s in rows:
        out.setdefault(r, []).append(dt)
    res = {}
    for r, v in out.items():
        v.sort()
        res[r] = {"n": len(v), "med": v[len(v) // 2], "max": v[-1], "over2": sum(x > 2 for x in v), "over3": sum(x > 3 for x in v),
                  "over5": sum(x > 5 for x in v), "over9": sum(x > 9 for x in v)}
    return res


async def main(mode: str, kind="syn", enc="doh", retry=1.0, pre_open=0, dur=30.0, every=0.25, clients=10):
    ups = {"doh": SHARED_DOH, "dot": SHARED_DOT, "plain": SHARED_UDP}[enc]
    lab.lo_up()
    await lab.start_servers(h3=False)
    ps = {v: lab.Proxy(v, {"upstreams": ups, "encrypt": enc, "direct_fallback": [FB_UDP]}) for v in VERS}
    cl = lab.Clients()
    await asyncio.sleep(0.6)
    await lab.ready(cl, ps.values())
    if pre_open:
        for p in ps.values():
            await asyncio.gather(*(cl.ask(p.listen, f"pre{lab.uid()}.example") for _ in range(8)))
    if kind == "freeze":
        B["frozen"].update(ups)
    elif kind == "freezeold":
        # Ж: Д5 — замерзают только соединения, открытые до этого мига (новые отвечают); с pre_open=1
        B.setdefault("freeze_old", {}).update({ip: time.time() for ip in ups})
    elif kind.startswith("blink"):
        # Ж: Д3 — «мигает»: замерзает доля запросов и контрольных запросов (blink30 — 30 %)
        B["freeze_req"].update({ip: int(kind[5:]) / 100 for ip in ups})
    elif kind == "none":
        pass
    else:
        lab.nft(f"""table ip blk {{ chain in {{ type filter hook input priority 0; policy accept;
            {BLOCKS[kind].format(ips="{ " + ", ".join(ups) + " }", port=lab.UP_PORT)}
        }} }}""")
    res = {}

    async def per(v, p):
        rows = []
        t0 = time.monotonic()

        async def one(name, src):
            t = time.monotonic() - t0
            dt, r, s = await ask_retry(p.listen, name, src, retry)
            rows.append((round(t, 2), dt, r, s))
        tasks = []
        if mode == "stream":
            # новое имя каждые every с, у каждого своя заглушка с повтором
            i = 0
            while time.monotonic() - t0 < dur:
                tasks.append(asyncio.create_task(one(f"n{lab.uid()}.example", f"127.0.2.{1 + i % 200}")))
                i += 1
                await asyncio.sleep(every)
        else:
            # «популярные» имена: каждые 5 с новое имя, его спрашивают clients устройств по очереди через 0,3 с
            k = 0
            while time.monotonic() - t0 < dur:
                name = f"pop{lab.uid()}.example"
                for c in range(clients):
                    tasks.append(asyncio.create_task(one(name, f"127.0.2.{1 + (k * clients + c) % 200}")))
                    await asyncio.sleep(0.3)
                k += 1
                await asyncio.sleep(max(0.0, 5.0 - 0.3 * clients))
        await asyncio.gather(*tasks)
        rows.sort()
        early = [r for r in rows if r[0] < 6.0]
        res[v] = {"all": summ(rows), "first_6s": summ(early), "rows_first_6s": early[:40]}
    await asyncio.gather(*(per(v, p) for v, p in ps.items()))
    for v, p in ps.items():
        s = await p.fresh_stats()
        res[v]["stats"] = {k: s.get(k) for k in ("checks", "joined", "join_checks", "join_full", "direct_fallback", "errors", "queries")}
        p.stop()
    return res


if __name__ == "__main__":
    kw = {}
    for a in sys.argv[2:]:
        k, v = a.split("=", 1)
        try:
            v = json.loads(v)
        except ValueError:
            pass
        kw[k] = v
    t = time.time()
    out = asyncio.run(main(sys.argv[1], **kw))
    print(json.dumps({"mode": sys.argv[1], "args": kw, "secs": round(time.time() - t, 1), "result": out}), flush=True)
    os._exit(0)
