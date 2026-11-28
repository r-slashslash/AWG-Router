"""Д6 на настоящем ядре (машина GitHub, сети srv/inet из net.sh): «Напрямую — адрес» (10.99.0.3, метка 0x2101), общие
серверы без шифрования (обычный DNS), которые с этого адреса не отвечают, запасной вписан именем — tls://dns.test с
адресом, который нашла панель (#адрес). Ждём: имена клиента этого пути получают ответ запасного; DoT к запасному и любой
поиск имени dns.test уходят с 10.99.0.3 и с его меткой, с адреса системы (10.99.0.2) — ничего.
Запуск: ip netns exec srvN env LAB_…  MARKS_VER=old|new python3 -I d6marks.py (lab.py — из скриптов проверки П31)."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.environ.get("LAB_DIR") or os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402
from marks import counters  # noqa: E402

SYS, ADDR = "10.99.0.2", "10.99.0.3"
C1, C2 = "127.0.2.1", "127.0.2.2"
VER = os.environ.get("MARKS_VER", "new")


async def main():
    lab.lo_up()
    subprocess.run(["ip", "netns", "exec", lab.NFT_NS, "nft", "-f", "-"], text=True, input="""table ip cnt {
  set seen { type ipv4_addr . ipv4_addr . inet_proto; flags dynamic; counter; size 65535; }
  chain in { type filter hook input priority -10; policy accept;
    ip daddr 10.99.1.0/24 update @seen { ip saddr . ip daddr . meta l4proto }
  }
}""", check=True)
    subprocess.run(["nft", "-f", "-"], text=True, input="""table ip cnt {
  set out { type mark . ipv4_addr . ipv4_addr . inet_proto; flags dynamic; counter; size 65535; }
  chain o { type filter hook postrouting priority 100; policy accept;
    ip daddr 10.99.1.0/24 update @out { meta mark . ip saddr . ip daddr . meta l4proto }
  }
}""", check=True)
    await lab.start_servers(h3=False)
    fb = "tls://dns.test#" + lab.FB_DOT                     # так панель передаёт запасной по имени (dnsaddr.for_proxy)
    p = lab.Proxy(VER, {"upstreams": lab.SHARED_UDP, "encrypt": "plain", "direct_fallback": [fb],
                        "routes": {C2: {"mark": 0x2101, "tcp": False}}})
    cl = lab.Clients()
    await asyncio.sleep(0.8)
    await lab.ready(cl, [p])
    shared = "{ " + ", ".join(lab.SHARED_UDP) + " }"
    lab.nft(f"table ip blk {{ chain in {{ type filter hook input priority 0; policy accept;\n"
            f"ip saddr {ADDR} ip daddr {shared} udp dport {lab.UP_PORT} drop\n}} }}")
    rows = {"c1": [], "c2": []}
    t0 = time.monotonic()
    while time.monotonic() - t0 < 40:
        for c, tag in ((C1, "c1"), (C2, "c2")):
            dt, r = await cl.ask(p.listen, f"d6-{tag}-{lab.uid()}.example", src=c, timeout=30)
            rows[tag].append((round(time.monotonic() - t0, 1), round(dt, 3), r))
        await asyncio.sleep(0.5)
    st = await p.fresh_stats()
    p.stop()
    inet = counters(lab.NFT_NS, "cnt", "seen")
    out = counters(None, "cnt", "out")
    to_fb = {f"{r[0]}->{r[1]}/{r[2]}": r[3] for r in inet if r[1] == lab.FB_DOT}
    lookups = [x for x in lab.LOG if x[4] == "dns.test."]
    print(json.dumps({
        "ver": VER,
        "c2_address_path": lab.summary(rows["c2"]), "c1_system_path": lab.summary(rows["c1"]),
        "c2_first": rows["c2"][:3],
        "fallback_dot_packets_by_src": to_fb,
        "name_lookups_by_src": sorted({x[2] for x in lookups}), "name_lookups": len(lookups),
        "mark_mismatch": [r for r in out if (r[1] == ADDR and r[0] != 0x2101) or (r[1] == SYS and r[0] != 0)],
        "from_system_to_fallback": [r for r in out if r[1] == SYS and r[2] == lab.FB_DOT],
        "stats": {k: st.get(k) for k in ("name_hint", "direct_fallback", "fb_checks", "fb_checks_ok", "checks",
                                         "checks_ok", "fb_paths", "addr_direct")}}, ensure_ascii=False, indent=1),
          flush=True)
    os._exit(0)


if __name__ == "__main__":
    asyncio.run(main())
