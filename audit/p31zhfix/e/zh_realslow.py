"""Ж: живой, но медленный путь к настоящим серверам (без блокировки) — сколько имён уходит к запасному и сколько
проверок пути начинают повторы (JOIN_CHECK, Е1). Три версии рядом (LAB_VERS), у каждой свои имена того же вида.
Общие — настоящие DoH одного поставщика (dnspod: 1.12.12.12 и 120.53.53.53 — имя doh.pub дописывается в KNOWN_NAMES
одинаково во всех трёх копиях кода; quad9, cloudflare, google), запасной — Яндекс 77.88.8.8. Клиент повторяет тот же
запрос через RETRY с, пока не придёт ответ. Имена — новые поддомены больших доменов (NXDOMAIN: резолвер спрашивает их
серверы имён; кэш панели не помогает).
Запуск: python3 -I zh_realslow.py <поставщик> <пользователей> <раз в, с> <длительность, с>"""
from __future__ import annotations

import asyncio
import json
import os
import random
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402
from e_retry import ask_retry  # noqa: E402

VERS = tuple(os.environ.get("LAB_VERS", "old,new,fix").split(","))
RETRY = float(os.environ.get("RETRY", "1"))
PAIRS = {"dnspod": ["1.12.12.12", "120.53.53.53"], "quad9": ["9.9.9.9", "149.112.112.112"],
         "cloudflare": ["1.1.1.1", "1.0.0.1"], "google": ["8.8.8.8", "8.8.4.4"]}
DOMS = ["example.com", "google.com", "cloudflare.com", "yandex.ru", "wikipedia.org", "microsoft.com", "apple.com",
        "github.com", "baidu.com", "qq.com"]


def patched(ver: str) -> str:
    """Копия dnsproxy.py версии с именем сервиса DNSPod (сертификат DoH по имени, как у Cloudflare и Google)."""
    src = lab.CODE[ver]
    d = tempfile.mkdtemp(prefix=f"zh-{ver}-")
    shutil.copytree(os.path.dirname(src), d + "/app", ignore=shutil.ignore_patterns("__pycache__"))
    p = d + "/app/dnsproxy.py"
    s = open(p).read()
    old = 'KNOWN_NAMES = {"1.1.1.1": "cloudflare-dns.com",'
    assert old in s
    s = s.replace(old, 'KNOWN_NAMES = {"1.12.12.12": "doh.pub", "120.53.53.53": "doh.pub", "1.1.1.1": "cloudflare-dns.com",')
    open(p, "w").write(s)
    return p


def summ(v):
    v = sorted(v)
    if not v:
        return None
    return {"n": len(v), "med": round(v[len(v) // 2], 3), "p90": round(v[int(len(v) * 0.9)], 3),
            "max": round(v[-1], 3), "over3": sum(x > 3 for x in v), "over5": sum(x > 5 for x in v),
            "over9": sum(x > 9 for x in v)}


async def main(prov: str, users: int, every: float, dur: float):
    cfg = dict(upstreams=PAIRS[prov], encrypt="doh", direct_fallback=["77.88.8.8"], upstream_port=None, ca_file=None)
    ps = {v: lab.Proxy(v, dict(cfg), code=patched(v)) for v in VERS}
    cl = lab.Clients()
    await asyncio.sleep(0.8)
    await lab.ready(cl, ps.values(), 20.0)
    rnd = random.Random(9)
    plan = []
    t = 0.0
    while t < dur:
        for u in range(users):
            plan.append((t + rnd.random() * every, u, rnd.choice(DOMS)))
        t += every
    plan.sort()
    res = {}

    async def per(v, p):
        rows = []
        t0 = time.monotonic()

        async def one(at, u, dom):
            await asyncio.sleep(max(0.0, at - (time.monotonic() - t0)))
            name = f"zh{lab.uid()}{v}.{dom}"
            dt, r, s = await ask_retry(p.listen, name, f"127.0.2.{1 + u}", RETRY, 40)
            rows.append((at, dt, r, s))
        await asyncio.gather(*(one(*x) for x in plan))
        res[v] = {"waits": summ([r[1] for r in rows]),
                  "results": {k: sum(1 for r in rows if r[2] == k) for k in {r[2] for r in rows}},
                  "repeats_sent": sum(r[3] for r in rows) - len(rows)}
    await asyncio.gather(*(per(v, p) for v, p in ps.items()))
    for v, p in ps.items():
        s = await p.fresh_stats()
        res[v]["stats"] = {k: s.get(k) for k in ("queries", "checks", "checks_ok", "join_checks", "joined",
                                                  "direct_fallback", "errors", "last_error")}
        p.stop()
    return res


if __name__ == "__main__":
    lab.lo_up()
    prov, users, every, dur = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])
    t = time.time()
    out = asyncio.run(main(prov, users, every, dur))
    head = {"prov": prov, "users": users, "every": every, "dur": dur, "retry": RETRY, "secs": round(time.time() - t)}
    for v, r in out.items():
        print("REALSLOW " + json.dumps({**head, "ver": v, **r}), flush=True)
    os._exit(0)
