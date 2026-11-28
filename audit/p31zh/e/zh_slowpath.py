"""Ж: ложная проверка пути от повтора (JOIN_CHECK, Е1) на живом, но медленном пути. Три версии рядом (LAB_VERS:
old — d7a90cc, new — c934013, fix — b87eaa5) на одних серверах стенда lab.py. Клиент повторяет тот же запрос через
retry с (как настоящие заглушки). Блокировки нет: каждое имя, ушедшее к запасному, и каждая проверка пути — лишние.

Режимы (lat=…):
  fixed:L     — все ответы общих (и «. NS») через L с (задержка пути 300–600 мс);
  dnspod      — как DNSPod DoH из России: задержка ответа логнормальная, медиана 1,25 с, 95 % ≤ 4 с, 8 % без ответа
                (и у «. NS» так же — проверка 5 с иногда не дотягивает);
  dnspod1     — то же, но молчание сразу у обоих общих (один сервер в настройках или общая беда сервиса).
Имена: доля slow (по умолчанию 0.15) — «slowK» с K 3 или 4 с (резолвер разбирает долго, но отвечает до срока попытки 5 с),
остальные — обычные. users — сколько клиентов, every — каждый спрашивает новое имя раз в every с (редкие вопросы — один
пользователь, every 8).
Запуск: unshare -rn python3 -I zh_slowpath.py lat=dnspod retry=1 users=1 every=8 dur=300 slow=0.15"""
from __future__ import annotations

import asyncio
import json
import math
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402
from e_retry import ask_retry  # noqa: E402
from lab import B, FB_UDP, SHARED_DOH  # noqa: E402

VERS = tuple(os.environ.get("LAB_VERS", "old,new,fix").split(","))
_orig_delay = lab.delay
MODE = {"lat": "fixed:0"}


def delay(name, ip, qtype, src="?", kind="?"):
    d = _orig_delay(name, ip, qtype, src, kind)
    lab_ = name.split(".", 1)[0]
    if d is None or ip in lab.FALLBACK_IPS or lab_.startswith("slow"):
        return d
    m = MODE["lat"]
    if m.startswith("fixed:"):
        return float(m.split(":", 1)[1])
    if m.startswith("dnspod"):
        r = random.random()
        if m == "dnspod1":
            # общее молчание: решается по времени (секунда за секундой), одинаково для обоих серверов
            r = random.Random(int(time.time())).random()
        if r < 0.08:
            return None
        return min(9.0, math.exp(math.log(1.25) + 0.707 * random.gauss(0, 1)))
    return d


lab.delay = delay


def summ(v):
    v = sorted(v)
    if not v:
        return None
    return {"n": len(v), "med": round(v[len(v) // 2], 3), "p95": round(v[int(len(v) * 0.95)], 3),
            "max": round(v[-1], 3), "over5": sum(x > 5 for x in v), "over9": sum(x > 9 for x in v)}


async def main(lat="fixed:0", retry=1.0, users=1, every=8.0, dur=300.0, slow=0.15, seed=1):
    MODE["lat"] = str(lat)
    rnd = random.Random(seed)
    lab.lo_up()
    await lab.start_servers(h3=False)
    ps = {v: lab.Proxy(v, {"upstreams": SHARED_DOH, "encrypt": "doh", "direct_fallback": [FB_UDP]}) for v in VERS}
    cl = lab.Clients()
    await asyncio.sleep(0.6)
    MODE["lat"] = "fixed:0"
    await lab.ready(cl, ps.values())
    MODE["lat"] = str(lat)
    # одна и та же последовательность имён для всех версий
    plan = []
    t = 0.0
    while t < dur:
        for u in range(int(users)):
            k = rnd.random()
            nm = (f"slow{rnd.choice([3, 4])}x{lab.uid()}.example" if k < slow
                  else f"n{lab.uid()}.example")
            plan.append((t + rnd.random() * float(every), u, nm))
        t += float(every)
    plan.sort()
    res = {}

    async def per(v, p):
        rows = []
        t0 = time.monotonic()

        async def one(at, u, nm):
            await asyncio.sleep(max(0.0, at - (time.monotonic() - t0)))
            dt, r, s = await ask_retry(p.listen, nm, f"127.0.2.{1 + u % 200}", float(retry))
            rows.append((at, nm.startswith("slow"), dt, r))
        await asyncio.gather(*(one(*x) for x in plan))
        out = {}
        for kind in (False, True):
            sel = [r for r in rows if r[1] == kind]
            out["slow" if kind else "normal"] = {res_: summ([r[2] for r in sel if r[3] == res_])
                                                 for res_ in sorted({r[3] for r in sel})}
        res[v] = out
    await asyncio.gather(*(per(v, p) for v, p in ps.items()))
    for v, p in ps.items():
        s = await p.fresh_stats()
        res[v]["stats"] = {k: s.get(k) for k in ("queries", "checks", "checks_ok", "join_checks", "join_full", "joined",
                                                  "direct_fallback", "errors", "direct_fail_at")}
        p.stop()
    return res


if __name__ == "__main__":
    kw = {}
    for a in sys.argv[1:]:
        k, v = a.split("=", 1)
        try:
            v = json.loads(v)
        except ValueError:
            pass
        kw[k] = v
    t = time.time()
    out = asyncio.run(main(**kw))
    print(json.dumps({"script": "slowpath", "args": kw, "secs": round(time.time() - t, 1), "result": out}), flush=True)
    os._exit(0)
