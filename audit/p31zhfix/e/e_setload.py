"""Е: «фильтр по DNS» под потоком новых адресов (Д2: команда nft не чаще раза в SET_FLUSH, ответ ждёт записи) — процессор
процессов nft, задержка ответов, set_late, попал ли адрес в набор к моменту ответа. Таблица — как у панели: набор dom4 и
список сетей LISTS (как страна). Один процесс dnsproxy.py за прогон, один процессор (taskset снаружи).
Запуск: unshare -rn taskset -c 0 python3 -I e_setload.py <папка app> RATE DUR LISTS"""
from __future__ import annotations

import asyncio
import json
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile
import time

APP, RATE, DUR, LISTS = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4])
UP = ("127.0.0.2", 8053)


def lo_up():
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fcntl.ioctl(s.fileno(), 0x8914, struct.pack("16sH14s", b"lo", 0x49, b""))
    s.close()


def table(n):
    el = ", ".join(f"{10 + i // 65536}.{(i // 256) % 256}.{i % 256}.0/24" for i in range(n)) if n else ""
    lst = ("\tset l_big {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { %s }\n\t}\n" % el) if n else ""
    return ("table ip awgr {\n\tset dom4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n" + lst +
            "\tchain c_pre {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n"
            "\t\tip daddr @dom4 tcp dport { 80, 443 } ct state new meta mark set 0xd000 accept\n\t}\n}\n")


class Up(asyncio.DatagramProtocol):
    """Отвечает на каждое имя своим адресом из 100.64.0.0/10 (новые адреса потоком)."""
    def connection_made(self, tr):
        self.tr = tr

    def datagram_received(self, data, addr):
        qid, flags = struct.unpack("!HH", data[:4])
        off = 12
        while data[off]:
            off += 1 + data[off]
        qend = off + 5
        ip = struct.pack("!I", 0x64400000 + (hash(data[12:qend]) & 0x3FFFFF))
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip
        self.tr.sendto(struct.pack("!6H", qid, 0x8180, 1, 1, 0, 0) + data[12:qend] + rr, addr)


def in_set(addrs):
    out = subprocess.run(["nft", "-j", "list", "set", "ip", "awgr", "dom4"], capture_output=True, text=True).stdout
    have = set()
    for x in json.loads(out)["nftables"]:
        for e in (x.get("set") or {}).get("elem") or ():
            v = e["elem"]["val"] if isinstance(e, dict) and "elem" in e else e
            have.add(v if isinstance(v, str) else str(v))
    return sum(a in have for a in addrs)


def child_cpu(pid):
    with open(f"/proc/{pid}/stat") as f:
        v = f.read().rsplit(")", 1)[1].split()
    tck = os.sysconf("SC_CLK_TCK")
    return (int(v[11]) + int(v[12])) / tck, (int(v[13]) + int(v[14])) / tck


async def main():
    lo_up()
    d = tempfile.mkdtemp()
    with open(d + "/t.nft", "w") as f:
        f.write(table(LISTS))
    subprocess.run(["nft", "-f", d + "/t.nft"], check=True)
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(Up, local_addr=UP)
    with open(d + "/rule.txt", "w") as f:
        f.write("rule.example\n")
    cfg = {"listen": "127.0.1.1", "port": 53, "clients": "127.0.0.0/8", "stats": d + "/st.json", "upstreams": [UP[0]],
           "encrypt": "plain", "upstream_port": UP[1], "default": {"mark": 0, "tcp": False}, "routes": {},
           "dom": {"lists": {"l": d + "/rule.txt"}, "clients": {}, "set": ["awgr", "dom4"],
                   "policies": {"p_global": [[["l"], {"mark": 0, "tcp": False}]]}}}
    with open(d + "/dns.json", "w") as f:
        json.dump(cfg, f)
    proc = subprocess.Popen([sys.executable, "-I", APP + "/dnsproxy.py", d + "/dns.json"],
                            stdout=open(d + "/log.txt", "w"), stderr=subprocess.STDOUT)
    await asyncio.sleep(1.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.2.1", 0))
    s.setblocking(False)
    sent, lat, addrs, pend = 0, [], [], {}
    c0 = child_cpu(proc.pid)
    t0 = time.monotonic()
    nxt = t0
    check_at = []                                     # (адрес, время ответа) — выборка: был ли адрес в наборе к ответу
    while time.monotonic() - t0 < DUR:
        now = time.monotonic()
        while nxt <= now:
            qid = sent & 0xFFFF
            name = f"n{random.randrange(10**12)}.rule.example"
            labels = b"".join(bytes([len(x)]) + x.encode() for x in name.split("."))
            s.sendto(struct.pack("!6H", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00\x00\x01\x00\x01", ("127.0.1.1", 53))
            pend[qid] = now
            sent += 1
            nxt += 1.0 / RATE
        try:
            while True:
                r = s.recv(4096)
                qid = struct.unpack("!H", r[:2])[0]
                if qid in pend:
                    lat.append(time.monotonic() - pend.pop(qid))
                    a = socket.inet_ntoa(r[-4:])
                    if len(check_at) < 40 and random.random() < 0.02:
                        check_at.append(a)
                        if in_set([a]) != 1:
                            check_at[-1] = "MISSING " + a
        except BlockingIOError:
            pass
        await asyncio.sleep(0.001)
    await asyncio.sleep(2)
    c1 = child_cpu(proc.pid)
    try:
        st = json.load(open(d + "/st.json"))
    except (OSError, ValueError):
        st = {}
    proc.terminate()
    proc.wait()
    lat.sort()
    q = lambda f: round(lat[min(len(lat) - 1, int(len(lat) * f))] * 1000, 1) if lat else None  # noqa: E731
    print(json.dumps({"app": APP, "rate": RATE, "dur": DUR, "list_nets": LISTS, "sent": sent, "answered": len(lat),
                      "p50_ms": q(0.5), "p95_ms": q(0.95), "p99_ms": q(0.99),
                      "proxy_cpu_pct": round(100 * (c1[0] - c0[0]) / DUR, 1),
                      "nft_children_cpu_pct": round(100 * (c1[1] - c0[1]) / DUR, 1),
                      "sampled_missing_at_answer": sum(1 for x in check_at if x.startswith("MISSING")),
                      "sampled": len(check_at), "set_late": st.get("set_late"), "set_added": st.get("set_added")}),
          flush=True)
    os._exit(0)


asyncio.run(main())
