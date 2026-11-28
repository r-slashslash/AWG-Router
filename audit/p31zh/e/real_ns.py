"""Настоящие серверы DNS (П31): как часто одна проверка пути ложно не проходит. Proxy._check кода d7a90cc (в этом
процессе) — каждому серверу и способу раз в EVERY с в течение DUR с; рядом — то же самое, но с обычным популярным именем
вместо «. NS» (отвечают ли на «. NS» иначе). Пары общих серверов (cfg encrypt + upstreams: Cloudflare, Google, Quad9) —
как у людей, оба сразу. По UDP — размер, TC и EDNS ответа «. NS». Печатает только публичные адреса серверов DNS.
Запуск: python3 -I real_ns.py <путь к app> [DUR] [EVERY]."""
from __future__ import annotations

import asyncio
import contextvars  # noqa: F401
import json
import os
import random
import socket
import struct
import sys
import tempfile
import time

sys.path.insert(0, sys.argv[1])
import dnsproxy  # noqa: E402

DUR = float(sys.argv[2]) if len(sys.argv) > 2 else 1500.0
EVERY = float(sys.argv[3]) if len(sys.argv) > 3 else 10.0
NAMES = ["www.wikipedia.org", "github.com", "www.google.com", "yandex.ru", "www.baidu.com", "cloudflare.com"]

PROV = {
    "cloudflare": ("1.1.1.1", "cloudflare-dns.com", "/dns-query", True),
    "google": ("8.8.8.8", "dns.google", "/dns-query", True),
    "quad9": ("9.9.9.9", "dns.quad9.net", "/dns-query", False),
    "yandex": ("77.88.8.8", "common.dot.dns.yandex.net", "/dns-query", False),
    "adguard": ("94.140.14.14", "dns.adguard-dns.com", "/dns-query", True),
    "alibaba": ("223.5.5.5", "dns.alidns.com", "/dns-query", True),
    "dnspod": ("119.29.29.29", "doh.pub", "/dns-query", False),
}
DOT_NAME = {"dnspod": "dot.pub"}
PAIRS = {"cloudflare": ["1.1.1.1", "1.0.0.1"], "google": ["8.8.8.8", "8.8.4.4"], "quad9": ["9.9.9.9", "149.112.112.112"]}


def resolve(name: str) -> str | None:
    try:
        ips = sorted({a[4][0] for a in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)})
        return ips[0] if ips else None
    except OSError:
        return None


def proxy(**cfg) -> dnsproxy.Proxy:
    d = tempfile.mkdtemp()
    conf = os.path.join(d, "dns.json")
    base = {"listen": "127.0.1.9", "port": 53, "clients": "127.0.0.0/8", "upstreams": ["1.1.1.1"], "encrypt": "plain",
            "default": {"mark": 0, "tcp": False}, "routes": {}, "dom": {}, "direct_fallback": []}
    base.update(cfg)
    with open(conf, "w") as f:
        json.dump(base, f)
    return dnsproxy.Proxy(conf)


async def probe(p: dnsproxy.Proxy, servers: tuple, query: bytes) -> bool:
    """Как Proxy._check, но с любым запросом (для сравнения «. NS» и обычного имени)."""
    cq = dnsproxy.parse_query(query)
    tok = dnsproxy._CHECKING.set(True)
    try:
        tasks = [asyncio.ensure_future(p._ask(query, cq, 0, False, servers, s)) for s in p._order(0, servers)]
    finally:
        dnsproxy._CHECKING.reset(tok)
    try:
        for fut in asyncio.as_completed(tasks, timeout=dnsproxy.CHECK_TIMEOUT):
            try:
                if await fut is not None:
                    return True
            except Exception:  # noqa: BLE001
                pass
        return False
    except asyncio.TimeoutError:
        return False
    finally:
        for t in tasks:
            t.cancel()


def udp_details(ip: str) -> dict:
    out = {}
    for edns in (False, True):
        q = dnsproxy.check_query()
        if edns:
            q = q[:10] + b"\x00\x01" + q[12:] + b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(q, (ip, 53))
            r = s.recv(65535)
            fl, an, ns, ar = struct.unpack("!H", r[2:4])[0], *struct.unpack("!HHH", r[6:12])
            out["edns" if edns else "plain"] = {"size": len(r), "tc": bool(fl & 0x200), "rcode": fl & 0xF,
                                                 "an": an, "ar": ar}
        except OSError as e:
            out["edns" if edns else "plain"] = {"error": str(e)[:60]}
        finally:
            s.close()
    return out


async def main():
    tests = []        # (id, Proxy, servers)
    for prov, (ip, name, path, h3) in PROV.items():
        tests.append((f"{prov}/plain", proxy(), (ip,)))
        dn = DOT_NAME.get(prov, name)
        dip, hip = resolve(dn), resolve(name)
        if dip:
            tests.append((f"{prov}/dot", proxy(), (f"tls://{dn}#{dip}",)))
        if hip:
            tests.append((f"{prov}/doh", proxy(), (f"https://{name}{path}#{hip}",)))
            if h3 and dnsproxy.dohttp.h3_supported():
                tests.append((f"{prov}/h3", proxy(), (f"h3://{name}{path}#{hip}",)))
    for prov, ups in PAIRS.items():
        for enc in ("plain", "dot", "doh"):
            tests.append((f"pair:{prov}/{enc}", proxy(upstreams=ups, encrypt=enc), ()))
    print("tests:", [t[0] for t in tests], "h3:", dnsproxy.dohttp.h3_supported(), flush=True)
    res = {t[0]: {"ns": [], "name": []} for t in tests}
    errs = {t[0]: {} for t in tests}
    t_end = time.monotonic() + DUR
    rnd = 0

    async def one(tid, p, servers, delay):
        await asyncio.sleep(delay)
        for kind in ("ns", "name"):
            q = dnsproxy.check_query() if kind == "ns" else dnsproxy.a_query(random.choice(NAMES))
            p.last_error = ""
            t0 = time.monotonic()
            ok = await probe(p, servers, q)
            res[tid][kind].append((ok, round(time.monotonic() - t0, 3)))
            if not ok:
                e = (p.last_error.split(": ", 1)[-1] or "?")[:50]
                errs[tid][f"{kind}:{e}"] = errs[tid].get(f"{kind}:{e}", 0) + 1
    while time.monotonic() < t_end:
        t0 = time.monotonic()
        await asyncio.gather(*(one(tid, p, s, i * EVERY / len(tests) * 0.8) for i, (tid, p, s) in enumerate(tests)))
        rnd += 1
        if rnd % 30 == 0:
            bad = {k: sum(1 for ok, _ in v["ns"] if not ok) for k, v in res.items()}
            print(f"round {rnd}: ns fails", {k: n for k, n in bad.items() if n}, flush=True)
        await asyncio.sleep(max(0.0, EVERY - (time.monotonic() - t0)))
    summary = {}
    for tid, v in res.items():
        row = {}
        for kind in ("ns", "name"):
            xs = v[kind]
            t = sorted(x[1] for x in xs if x[0]) or [0]
            f = sum(1 for ok, _ in xs if not ok)
            row[kind] = {"n": len(xs), "failed": f, "fail_pct": round(100 * f / max(1, len(xs)), 2),
                         "p50": t[len(t) // 2], "p95": t[int(len(t) * 0.95)], "max": t[-1]}
        row["errors"] = errs[tid]
        summary[tid] = row
    udp = {prov: udp_details(PROV[prov][0]) for prov in PROV}
    print("SUMMARY " + json.dumps({"rounds": rnd, "every": EVERY, "tests": summary, "udp_ns": udp}), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
    os._exit(0)
