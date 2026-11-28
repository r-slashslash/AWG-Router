"""Метки и адрес отправителя на настоящих сокетах (П31). Запуск в сети srv (ip netns exec srv), серверы — в сети inet
(LAB_SRV_NS=/run/netns/inet, LAB_NET=10.99.1., LAB_NFT_NS=inet). В srv: 10.99.0.2 — адрес системы (метка 0),
10.99.0.3 — «Напрямую — адрес» (метка 0x2101, ip rule → таблица 201, src .3), 10.99.0.4 — «выход» (метка 0x2001,
таблица 101, src .4). Клиенты: c1 — напрямую с адреса системы, c2 — «Напрямую — адрес», c3 — через выход; имена
*.rule.example — правило по доменам без пути (выход лежит). Серверы пишут, от кого пришло каждое имя; nftables считает
пакеты по метке и отправителю.

Проверяет: проверка пути, проба, вторая попытка UDP, запасной (обычный, DoT по имени, HTTP/3) и поиск адреса имени
запасного уходят с адреса своего пути и с его меткой; имена через выход и имена правил без пути никогда не доходят до
запасного — и во время проверки, пробы и SIGHUP."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402
from lab import B, FB_DOT, FB_H3, FB_UDP, SHARED_DOH, SHARED_UDP  # noqa: E402

SYS, ADDR, EXIT = "10.99.0.2", "10.99.0.3", "10.99.0.4"
C1, C2, C3 = "127.0.2.1", "127.0.2.2", "127.0.2.3"
FALLBACK = {lab.FB_UDP, lab.FB_DOT, lab.FB_DOH, lab.FB_H3, lab.FB_UDP2}
VER = os.environ.get("MARKS_VER", "new")


def sh(*a, ns=None):
    pre = ["ip", "netns", "exec", ns] if ns else []
    return subprocess.run([*pre, *a], capture_output=True, text=True)


def counters(ns, table, setname):
    out = json.loads(sh("nft", "-j", "list", "set", "ip", table, setname, ns=ns).stdout or "{}")
    rows = []
    for item in out.get("nftables", []):
        for e in (item.get("set") or {}).get("elem") or ():
            v = e["elem"]["val"]["concat"]
            rows.append((*v, e["elem"]["counter"]["packets"]))
    return rows


async def main():
    lab.lo_up()
    # счётчики: в inet — по отправителю; в srv — по метке и отправителю на выходе
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
    await lab.start_servers(h3=True)
    d = tempfile.mkdtemp()
    lst = os.path.join(d, "rule.txt")
    with open(lst, "w") as f:
        f.write("rule.example\n")
    cfg = {"upstreams": SHARED_DOH, "encrypt": "doh",
           "routes": {C2: {"mark": 0x2101, "tcp": False}, C3: {"mark": 0x2001, "tcp": False}},
           "dom": {"lists": {"l": lst}, "clients": {}, "set": None, "policies": {"p_global": [[["l"], None]]}},
           "direct_fallback": [FB_UDP]}
    p = lab.Proxy(VER, cfg)
    cl = lab.Clients()
    await asyncio.sleep(0.8)
    await lab.ready(cl, [p])
    phases, marks = [], {}

    async def stream(phase, dur, every=0.4):
        """Имена всех трёх клиентов и имена правила без пути — всё время фазы."""
        t0, tasks = time.monotonic(), []
        while time.monotonic() - t0 < dur:
            for c, tag in ((C1, "c1"), (C2, "c2"), (C3, "c3")):
                tasks.append(asyncio.create_task(cl.ask(p.listen, f"{phase}-{tag}-{lab.uid()}.example", src=c)))
                tasks.append(asyncio.create_task(cl.ask(p.listen, f"{phase}-{tag}-{lab.uid()}.rule.example", src=c)))
            await asyncio.sleep(every)
        return await asyncio.gather(*tasks)

    async def phase(name, dur, setup=None, dead=None):
        t0 = time.time()
        if setup:
            setup()
        jobs = [stream(name, dur)]
        if dead:
            for c, tag, prefix in dead:
                jobs.append(cl.ask(p.listen, f"{prefix}{name}-{tag}-{lab.uid()}.example", src=c, timeout=40))
        res = await asyncio.gather(*jobs)
        phases.append((name, t0, time.time()))
        return res

    def block(rule):
        lab.nft(f"table ip blk {{ chain in {{ type filter hook input priority 0; policy accept;\n{rule}\n}} }}")

    def unblock():
        subprocess.run(["ip", "netns", "exec", lab.NFT_NS, "nft", "delete", "table", "ip", "blk"], capture_output=True)

    shared = "{ " + ", ".join(SHARED_DOH) + " }"
    # A: всё работает
    await phase("A", 4)
    # B: медленное имя на пути «Напрямую — адрес» — проверка этого пути, не системы
    await phase("B", 25, dead=[(C2, "c2", "dead")])
    # C: шифрованный DNS режут только с адреса .3 — запасной и проба с .3
    await phase("C", 25, setup=lambda: block(f"ip saddr {ADDR} ip daddr {shared} tcp dport {lab.UP_PORT} drop"))
    # C2: SIGHUP — запасной DoT по имени: адрес имени ищется с .3 (обычным DNS через общие серверы)
    await phase("Cn", 25, setup=lambda: p.hup(direct_fallback=["tls://dns.test#" + FB_DOT]),
                dead=[(C2, "c2", "fbdead")])
    # D: запасной HTTP/3 с адресом — с .3; имя без ответа запасного — проверка запасного по HTTP/3 с .3
    if lab.quic_ok():
        await phase("D", 25, setup=lambda: p.hup(direct_fallback=[f"h3://{FB_H3}/dns-query"]),
                    dead=[(C2, "c2", "fbdead")])
    unblock()
    # E: обычный DNS, каждый второй пакет с .3 к общим теряется: вторая попытка проверки — с .3
    await phase("E", 20, setup=lambda: (p.hup(upstreams=SHARED_UDP, encrypt="plain", direct_fallback=[FB_UDP]),
                                        block(f"ip saddr {ADDR} ip daddr {{ {', '.join(SHARED_UDP)} }} "
                                              f"udp dport {lab.UP_PORT} numgen inc mod 2 == 0 drop")),
                dead=[(C2, "c2", "dead")])
    unblock()
    # F: режут всё шифрованное отовсюду; через 60 с SIGHUP — c1 уходит в выход; проба через DIRECT_RETRY (120 с)
    p.hup(upstreams=SHARED_DOH, encrypt="doh", direct_fallback=[FB_UDP])
    block(f"ip daddr {shared} tcp dport {lab.UP_PORT} drop")
    t_f = time.time()

    async def later():
        await asyncio.sleep(60)
        p.hup(routes={C1: {"mark": 0x2001, "tcp": False}, C2: {"mark": 0x2101, "tcp": False},
                      C3: {"mark": 0x2001, "tcp": False}})
        marks["hup_at"] = time.time()
    await asyncio.gather(phase("F", 135), later())
    unblock()
    p.stop()

    # ---- разбор
    log = lab.LOG
    bad = []
    for t, srv, src, kind, name in log:
        fb = srv in FALLBACK
        if "-c3-" in name and (fb or src not in (EXIT, "?")):
            bad.append(("имя через выход", t, srv, src, name))
        if ".rule.example" in name and fb:
            bad.append(("имя правила без пути у запасного", t, srv, src, name))
        if "-c2-" in name and src not in (ADDR, "?"):
            bad.append(("имя «Напрямую — адрес» не с .3", t, srv, src, name))
        if "-c1-" in name and src not in (SYS, "?") and not (name.startswith("F-") and t > marks.get("hup_at", 1e12)):
            bad.append(("имя системы не с .2", t, srv, src, name))
        if name.startswith("F-c1-") and t > marks.get("hup_at", 1e12) + 1 and (fb or src != EXIT):
            bad.append(("c1 после SIGHUP (выход) мимо выхода", t, srv, src, name))
        if name == "dns.test." and src != ADDR:
            bad.append(("адрес имени запасного не с .3", t, srv, src, name))
    ns_by = {}
    for t, srv, src, kind, name in log:
        if name == ". NS":
            ph = next((n for n, a, b in phases if a <= t <= b + 1), "?")
            ns_by.setdefault(ph, {}).setdefault(f"{src}->{srv}/{kind}", 0)
            ns_by[ph][f"{src}->{srv}/{kind}"] += 1
    # в фазах B–E (сбой только на пути .3) контрольный запрос с адреса системы — ошибка
    for ph in ("B", "C", "Cn", "D", "E"):
        for k in (ns_by.get(ph) or {}):
            if k.startswith(SYS + "->"):
                bad.append(("проверка с адреса системы в фазе пути .3", ph, k))
    inet = counters(lab.NFT_NS, "cnt", "seen")
    out = counters(None, "cnt", "out")
    h3_from = {r[0]: r[3] for r in inet if r[1] == FB_H3}
    fb_from = {}
    for r in inet:
        if r[1] in FALLBACK:
            fb_from[f"{r[0]}->{r[1]}/{r[2]}"] = r[3]
    mark_bad = [r for r in out if (r[1] == ADDR and r[0] != 0x2101) or (r[1] == SYS and r[0] != 0)
                or (r[1] == EXIT and r[0] != 0x2001)]
    exit_to_fb = [r for r in out if r[0] == 0x2001 and r[2] in FALLBACK]
    print(json.dumps({"ver": VER, "violations": bad[:40], "n_violations": len(bad), "log_entries": len(log),
                      "ns_checks_by_phase": ns_by, "fallback_packets_by_src": fb_from, "h3_by_src": h3_from,
                      "mark_mismatch": mark_bad, "exit_mark_to_fallback": exit_to_fb,
                      "marks_seen": sorted({hex(r[0]) + " " + r[1] for r in out})}, ensure_ascii=False, indent=1),
          flush=True)
    os._exit(0)


if __name__ == "__main__":
    asyncio.run(main())
