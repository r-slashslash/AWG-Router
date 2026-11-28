"""Настоящая блокировка шифрованного DNS к настоящим серверам (П31, требование 2): процессы dnsproxy.py до (6a8c54f) и
после (d7a90cc) рядом в своей сети (контейнер), общие серверы — настоящие DoH/DoT (Cloudflare, Google, Quad9), запасной —
Яндекс 77.88.8.8 обычным DNS. Блокировка — nftables в этой же сети, не на сервере целиком:
  syn   — теряется SYN-ACK сервера (SYN «не доходит»);
  rst   — на ClientHello сразу приходит RST;
  hello — ClientHello теряется;
  freeze — после рукопожатия данные сервера теряются (ct reply packets > 6, nf_conntrack_acct=1).
pre — блокировка начинается, когда соединения пула уже открыты. Имена — новые поддомены example.com (ответ NXDOMAIN):
при блокировке быстрый ответ может дать только запасной. Печатает время первого имени и задержки следующих.
Запуск: python3 -I realblk.py <kind> <doh|dot> <provider> <pre 0|1>."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402

PAIRS = {"cloudflare": ["1.1.1.1", "1.0.0.1"], "google": ["8.8.8.8", "8.8.4.4"], "quad9": ["9.9.9.9", "149.112.112.112"]}


def rules(kind: str, ips: list[str], port: int) -> str:
    s = "{ " + ", ".join(ips) + " }"
    if kind == "syn":
        return f"chain i {{ type filter hook input priority 0; policy accept;\n" \
               f"ip saddr {s} tcp sport {port} tcp flags & (syn | ack) == syn | ack drop\n}}"
    if kind == "rst":
        return f"chain o {{ type filter hook output priority 0; policy accept;\n" \
               f"ip daddr {s} tcp dport {port} ip length > 120 reject with tcp reset\n}}"
    if kind == "hello":
        return f"chain o {{ type filter hook output priority 0; policy accept;\n" \
               f"ip daddr {s} tcp dport {port} ip length > 120 drop\n}}"
    if kind == "freeze":
        return f"chain i {{ type filter hook input priority 0; policy accept;\n" \
               f"ip saddr {s} tcp sport {port} ct reply packets > 6 drop\n}}"
    raise ValueError(kind)


async def main(kind: str, enc: str, prov: str, pre: bool):
    ups = PAIRS[prov]
    port = 443 if enc == "doh" else 853
    cfg = dict(upstreams=ups, encrypt=enc, direct_fallback=["77.88.8.8"], upstream_port=None, ca_file=None)
    ps = {v: lab.Proxy(v, dict(cfg)) for v in ("old", "new")}
    cl = lab.Clients()
    await asyncio.sleep(0.8)
    await lab.ready(cl, ps.values(), 20.0)            # оба процесса отвечают, прежде чем греть пул
    warm = {}
    for v, p in ps.items():
        for attempt in (1, 2):
            t0 = time.monotonic()
            rs = await asyncio.gather(*(cl.ask(p.listen, f"w{lab.uid()}.example.com", timeout=20)
                                        for _ in range(8 if pre else 1)))
            warm[v] = [r[1] for r in rs], round(time.monotonic() - t0, 2), attempt
            if all(r[1] != "timeout" for r in rs):
                break
            with open(p.log.name) as f:
                print(f"WARMLOG {v}: " + f.read()[-600:].replace(chr(10), " | "), flush=True)
            await asyncio.sleep(5)
    if not pre:
        await asyncio.sleep(55)                       # соединения пула закрываются (POOL_IDLE 50 с) — блокировка «с нуля»
    subprocess.run(["nft", "-f", "-"], text=True, input=f"table ip blk {{\n{rules(kind, ups, port)}\n}}", check=True)
    res = {}

    async def per(v, p):
        rows, t0, tasks = [], time.monotonic(), []

        async def one(t):
            dt, r = await cl.ask(p.listen, f"n{lab.uid()}.example.com", timeout=40)
            rows.append((round(t, 2), round(dt, 3), r))
        while time.monotonic() - t0 < 30:
            tasks.append(asyncio.create_task(one(time.monotonic() - t0)))
            await asyncio.sleep(0.5)
        await asyncio.gather(*tasks)
        rows.sort()
        first = rows[0]
        after = [r for r in rows if r[0] >= first[1] + 1.0]
        slow = [r for r in after if r[1] > 1.0]
        res[v] = {"first": first, "after_first": lab.summary(after), "after_first_over_1s": len(slow),
                  "all": lab.summary(rows)}
    await asyncio.gather(*(per(v, p) for v, p in ps.items()))
    subprocess.run(["nft", "delete", "table", "ip", "blk"], capture_output=True)
    for v, p in ps.items():
        s = p.stats()
        res[v]["stats"] = {k: s.get(k) for k in ("direct_fallback", "checks", "checks_ok", "errors")}
        res[v]["warm"] = warm[v]
        p.stop()
    print("RESULT " + json.dumps({"kind": kind, "enc": enc, "prov": prov, "pre": pre, "res": res}), flush=True)


if __name__ == "__main__":
    lab.lo_up()
    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1"))
    os._exit(0)
