"""Сценарии «до/после» П31 на своём стенде (lab.py). Запуск: unshare -rn python3 -I scen.py <сценарий> [параметры].
Каждый сценарий идёт одновременно на обоих процессах (до — 6a8c54f, после — d7a90cc) при одних и тех же серверах и
блокировках и печатает JSON."""
from __future__ import annotations

import asyncio
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402
from lab import B, FB_DOH, FB_DOT, FB_H3, FB_UDP, FB_UDP2, SHARED_DOH, SHARED_DOT, SHARED_UDP  # noqa: E402

VERS = tuple(os.environ.get("LAB_VERS", "old,new").split(","))


async def stream(cl, p, t_end, every, rows, src="127.0.2.1", prefix="n"):
    """Новое имя каждые every с до t_end: [(t от начала, задержка, итог)]."""
    t0 = time.monotonic()
    tasks = []

    async def one(t):
        dt, r = await cl.ask(p.listen, f"{prefix}{lab.uid()}.example", src=src)
        rows.append((round(t, 2), round(dt, 3), r))
    while time.monotonic() - t0 < t_end:
        tasks.append(asyncio.create_task(one(time.monotonic() - t0)))
        await asyncio.sleep(every)
    await asyncio.gather(*tasks)


def timeline(rows, step=10.0):
    """По 10 с: сколько имён ответили общие / запасной / SERVFAIL / нет ответа, и медиана задержки."""
    out = {}
    for t, dt, r in rows:
        b = int(t // step) * int(step)
        e = out.setdefault(b, {})
        e[r] = e.get(r, 0) + 1
    return {k: out[k] for k in sorted(out)}


def env(**cfg):
    return {v: lab.Proxy(v, dict(cfg)) for v in VERS}


async def setup(**cfg):
    lab.lo_up()
    await lab.start_servers(h3=cfg.pop("h3", True))
    ps = env(**cfg)
    cl = lab.Clients()
    await asyncio.sleep(0.6)
    await lab.ready(cl, ps.values())
    return cl, ps


async def finish(ps):
    out = {}
    for v, p in ps.items():
        s = await p.fresh_stats()
        out[v] = {k: s.get(k) for k in ("direct_ok_at", "direct_fail_at", "checks", "checks_ok", "fb_checks",
                                       "fb_checks_ok", "direct_fallback", "errors", "queries")}
        out[v]["warn_direct_down"] = bool(s.get("direct_fail_at") and s["direct_fail_at"] > (s.get("direct_ok_at") or 0))
        fb = (s.get("fb_paths") or {}).get("0") or [0, 0]
        out[v]["warn_fb_down"] = bool(fb[1] and fb[1] > fb[0])
        p.stop()
    return out


# ------------------------------------------------------------------ 1. одно медленное имя
async def slow_one(enc="doh", fb="udp", name="dead", dur=60.0):
    ups = {"doh": SHARED_DOH, "dot": SHARED_DOT, "plain": SHARED_UDP}[enc]
    fbe = {"udp": [FB_UDP], "dot": [f"tls://{FB_DOT}"], "doh": [f"https://{FB_DOH}/dns-query"],
           "h3": [f"h3://{FB_H3}/dns-query"]}[fb]
    cl, ps = await setup(upstreams=ups, encrypt=enc, direct_fallback=fbe)
    res = {}

    async def per(v, p):
        rows, slow = [], {}

        async def s():
            dt, r = await cl.ask(p.listen, f"{name}{lab.uid()}.example", src="127.0.2.9", timeout=60)
            slow.update(dt=round(dt, 2), r=r)
        await asyncio.gather(s(), stream(cl, p, dur, 0.5, rows))
        res[v] = {"slow_name": slow, "names": lab.summary(rows), "timeline": timeline(rows),
                  "rows": sorted(rows)[:400] if os.environ.get("LAB_ROWS") else None}
    await asyncio.gather(*(per(v, p) for v, p in ps.items()))
    st = await finish(ps)
    for v in VERS:
        res[v]["stats"] = st[v]
    return res


# ------------------------------------------------------------------ 2. медленное имя повторяют
async def slow_repeat(rate=1.0, enc="doh", dur=60.0, clients=3, name="dead"):
    ups = {"doh": SHARED_DOH, "dot": SHARED_DOT, "plain": SHARED_UDP}[enc]
    cl, ps = await setup(upstreams=ups, encrypt=enc, direct_fallback=[FB_UDP])
    res = {}

    async def per(v, p):
        rows, slow = [], []
        dead = f"{name}{lab.uid()}.example"

        async def rep():
            t0 = time.monotonic()
            tasks, i = [], 0
            while time.monotonic() - t0 < dur:
                async def one(i=i):
                    dt, r = await cl.ask(p.listen, dead, src=f"127.0.3.{1 + i % clients}", timeout=60)
                    slow.append((0, dt, r))
                tasks.append(asyncio.create_task(one()))
                i += 1
                await asyncio.sleep(1.0 / rate)
            await asyncio.gather(*tasks)
        await asyncio.gather(rep(), stream(cl, p, dur, 0.5, rows))
        res[v] = {"dead_queries": lab.summary(slow), "names": lab.summary(rows), "timeline": timeline(rows)}
    await asyncio.gather(*(per(v, p) for v, p in ps.items()))
    st = await finish(ps)
    for v in VERS:
        res[v]["stats"] = st[v]
    return res


# ------------------------------------------------------------------ 3. сайт с несколькими «мёртвыми» поддоменами
async def dead_site(n=8, enc="doh", dur=60.0, repeat=0.0):
    ups = {"doh": SHARED_DOH, "dot": SHARED_DOT, "plain": SHARED_UDP}[enc]
    cl, ps = await setup(upstreams=ups, encrypt=enc, direct_fallback=[FB_UDP])
    res = {}

    async def per(v, p):
        rows, slow = [], []
        site = lab.uid()

        async def burst():
            async def one(i):
                dt, r = await cl.ask(p.listen, f"dead{i}.{site}.example", src="127.0.3.1", timeout=60)
                slow.append((0, dt, r))
            await asyncio.gather(*(one(i) for i in range(n)))
            if repeat:                                  # браузер открывает сайт ещё раз через repeat с
                await asyncio.sleep(repeat)
                await asyncio.gather(*(one(i) for i in range(n)))
        await asyncio.gather(burst(), stream(cl, p, dur, 0.5, rows))
        res[v] = {"dead_queries": lab.summary(slow), "names": lab.summary(rows), "timeline": timeline(rows)}
    await asyncio.gather(*(per(v, p) for v, p in ps.items()))
    st = await finish(ps)
    for v in VERS:
        res[v]["stats"] = st[v]
    return res


# ------------------------------------------------------------------ 4. потери на пути (обычный DNS и DoH)
async def loss(pct=10, enc="plain", dur=120.0, every=0.25, nft_loss=True):
    ups = {"doh": SHARED_DOH, "dot": SHARED_DOT, "plain": SHARED_UDP}[enc]
    cl, ps = await setup(upstreams=ups, encrypt=enc, direct_fallback=[FB_UDP])
    ips = ", ".join(ups)
    if nft_loss:
        lab.nft(f"""table ip loss {{ chain in {{ type filter hook input priority 0; policy accept;
        ip daddr {{ {ips} }} numgen random mod 100 < {pct} drop
        ip saddr {{ {ips} }} numgen random mod 100 < {pct} drop
    }} }}""")
    res = {}

    async def per(v, p):
        rows = []
        await stream(cl, p, dur, every, rows)
        res[v] = {"names": lab.summary(rows), "timeline": timeline(rows, 30.0)}
    await asyncio.gather(*(per(v, p) for v, p in ps.items()))
    if nft_loss:
        lab.nft("delete table ip loss")
    st = await finish(ps)
    for v in VERS:
        res[v]["stats"] = st[v]
    return res


# ------------------------------------------------------------------ 5. настоящая блокировка
BLOCKS = {
    "syn": "ip daddr {ips} tcp dport {port} tcp flags syn drop",
    "rst": "ip daddr {ips} tcp dport {port} ip length > 120 reject with tcp reset",
    "hello": "ip daddr {ips} tcp dport {port} ip length > 120 drop",
    "udp": "ip daddr {ips} udp dport {port} drop",
}


async def block(kind="syn", enc="doh", fb="udp", dur=40.0, pre_open=False, every=0.5):
    """kind: syn / rst / hello / udp (правило nftables) или freeze (сервер замерзает после рукопожатия).
    pre_open — блокировка начинается, когда соединения пула уже открыты."""
    ups = {"doh": SHARED_DOH, "dot": SHARED_DOT, "plain": SHARED_UDP}[enc]
    fbe = {"udp": [FB_UDP], "dot": [f"tls://{FB_DOT}"], "doh": [f"https://{FB_DOH}/dns-query"],
           "h3": [f"h3://{FB_H3}/dns-query"]}[fb]
    cl, ps = await setup(upstreams=ups, encrypt=enc, direct_fallback=fbe)
    if pre_open:
        for p in ps.values():
            await asyncio.gather(*(cl.ask(p.listen, f"pre{lab.uid()}.example") for _ in range(8)))
    if kind == "freeze":
        B["frozen"].update(ups)
    else:
        lab.nft(f"""table ip blk {{ chain in {{ type filter hook input priority 0; policy accept;
            {BLOCKS[kind].format(ips="{ " + ", ".join(ups) + " }", port=lab.UP_PORT)}
        }} }}""")
    res = {}

    async def per(v, p):
        rows = []
        await stream(cl, p, dur, every, rows)
        first = rows[0] if rows else None
        after = [r for r in rows if r[0] >= (first[1] if first else 0) + 1.0]
        res[v] = {"first": first, "names": lab.summary(rows), "after_first": lab.summary(after),
                  "timeline": timeline(rows)}
    await asyncio.gather(*(per(v, p) for v, p in ps.items()))
    B["frozen"].clear()
    st = await finish(ps)
    for v in VERS:
        res[v]["stats"] = st[v]
    return res


# ------------------------------------------------------------------ 6. «мигающая» блокировка
async def flaky(pass_pct=30, mode="syn", enc="doh", dur=300.0, every=1.0):
    """pass_pct — доля соединений, которые проходят. mode syn — решение на соединение (conntrack): остальные теряют
    SYN; freeze — остальные замерзают после рукопожатия."""
    ups = {"doh": SHARED_DOH, "dot": SHARED_DOT}[enc]
    cl, ps = await setup(upstreams=ups, encrypt=enc, direct_fallback=[FB_UDP])
    ips = "{ " + ", ".join(ups) + " }"
    if mode == "syn":
        lab.nft(f"""table ip fl {{ chain in {{ type filter hook input priority 0; policy accept;
            ip daddr {ips} tcp dport {lab.UP_PORT} ct mark 0 numgen random mod 100 < {pass_pct} ct mark set 1
            ip daddr {ips} tcp dport {lab.UP_PORT} ct mark 0 ct mark set 2
            ip daddr {ips} tcp dport {lab.UP_PORT} ct mark 2 drop
        }} }}""")
    elif mode == "freeze":
        for ip in ups:
            B["flaky"][ip] = 1 - pass_pct / 100
    else:                                           # req: замерзает доля запросов (имён и проверок) на любом соединении
        for ip in ups:
            B["freeze_req"][ip] = 1 - pass_pct / 100
    res = {}

    async def per(v, p):
        rows = []
        await stream(cl, p, dur, every, rows)
        waited = [r for r in rows if r[1] > 3.0]
        res[v] = {"names": lab.summary(rows), "waited_over_3s": len(waited),
                  "waited_per_min": round(len(waited) / (dur / 60), 1), "timeline": timeline(rows, 60.0)}
    await asyncio.gather(*(per(v, p) for v, p in ps.items()))
    B["flaky"].clear()
    B["freeze_req"].clear()
    st = await finish(ps)
    for v in VERS:
        res[v]["stats"] = st[v]
    return res


# ------------------------------------------------------------------ 7. зеркальный случай — запасной
async def mirror(fb="udp", dur=60.0, two=False, fb_rate=1.0):
    """Общие серверы режут (SYN), одно имя, у которого молчит запасной (fbdead), — дальше имена."""
    fbe = {"udp": [FB_UDP], "dot": [f"tls://{FB_DOT}"], "doh": [f"https://{FB_DOH}/dns-query"],
           "h3": [f"h3://{FB_H3}/dns-query"]}[fb]
    if two:
        fbe = fbe + [FB_UDP2]
    cl, ps = await setup(upstreams=SHARED_DOH, encrypt="doh", direct_fallback=fbe)
    lab.nft(f"""table ip blk {{ chain in {{ type filter hook input priority 0; policy accept;
        ip daddr {{ {", ".join(SHARED_DOH)} }} tcp dport {lab.UP_PORT} tcp flags syn drop }} }}""")
    if fb_rate < 1.0:                                # запасной отвечает «через раз» (на «. NS» — всегда)
        for ip in (FB_UDP, FB_DOT, FB_DOH, FB_UDP2):
            B["rate"][ip] = fb_rate
    res = {}

    async def per(v, p):
        rows, slow = [], {}
        await cl.ask(p.listen, f"w{lab.uid()}.example", timeout=30)     # путь уходит к запасному
        await asyncio.sleep(6)

        async def s():
            dt, r = await cl.ask(p.listen, f"fbdead{lab.uid()}.example", src="127.0.2.9", timeout=60)
            slow.update(dt=round(dt, 2), r=r)
        await asyncio.gather(s(), stream(cl, p, dur, 0.5, rows))
        res[v] = {"fb_slow_name": slow, "names": lab.summary(rows), "timeline": timeline(rows)}
    await asyncio.gather(*(per(v, p) for v, p in ps.items()))
    st = await finish(ps)
    for v in VERS:
        res[v]["stats"] = st[v]
    return res


SCEN = {"slow_one": slow_one, "slow_repeat": slow_repeat, "dead_site": dead_site, "loss": loss, "block": block,
        "flaky": flaky, "mirror": mirror}


def main():
    name = sys.argv[1]
    kw = {}
    for a in sys.argv[2:]:
        k, v = a.split("=", 1)
        try:
            v = json.loads(v)
        except ValueError:
            pass
        kw[k] = v
    t0 = time.time()
    res = asyncio.run(SCEN[name](**kw))
    print(json.dumps({"scenario": name, "args": kw, "secs": round(time.time() - t0, 1), "result": res},
                     ensure_ascii=False), flush=True)
    os._exit(0)


if __name__ == "__main__":
    main()
