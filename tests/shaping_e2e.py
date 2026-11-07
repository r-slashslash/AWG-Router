"""Сквозная проверка ограничения скорости и балансировки в сетевых пространствах (нужен root, nft, tc,
pyroute2, модули ядра ifb, sch_htb, act_mirred, cls_u32, cls_matchall).

   cli ──(awg0)── amz ──(eth0)── inet        «напрямую»        → DIRECT
                   ├──(awgr1)── up1          выход 1            → UP1
                   └──(awgr2)── up2          выход 2            → UP2

Очереди tc ставит тот же код, что в панели (Engine._sync_shaping, цель — пространство amz), правила
nftables — nftgen.generate. Туннели заменены veth: для очередей и маршрутов разницы нет.
Скорость меряется настоящей передачей TCP: загрузка — у клиента, отдача — на сервере.
Запуск: sudo PYTHONPATH=<pyroute2>:. python3 tests/shaping_e2e.py
"""
import os
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

from pyroute2 import IPRoute, NetNS, netns

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import config, nftgen  # noqa: E402
from app import engine as eng_mod  # noqa: E402

NS = ["cli", "amz", "inet", "up1", "up2"]
TARGET = "8.8.8.8"
SNAT = {1: "10.9.1.2", 2: "10.9.2.2"}
SERVER = r"""
import socket, sys, threading, time
name = sys.argv[1]
def serve(port, fn):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(16)
    while True:
        c, a = s.accept(); threading.Thread(target=fn, args=(c, a), daemon=True).start()
def hello(c, a):
    c.sendall((name + " from " + a[0]).encode()); c.close()
def stream(c, a):                       # имя, затем данные, пока клиент не закроет
    try:
        c.sendall((name + "\n").encode()); buf = b"x" * 65536
        while True: c.sendall(buf)
    except OSError: pass
def sink(c, a):                         # принимает до конца, отвечает «байт секунд»
    n, t0 = 0, None
    while True:
        d = c.recv(262144)
        if not d: break
        if t0 is None: t0 = time.monotonic()
        n += len(d)
    c.sendall(f"{n} {time.monotonic() - (t0 or time.monotonic()):.3f}".encode()); c.close()
for port, fn in ((5001, stream), (5002, sink)):
    threading.Thread(target=serve, args=(port, fn), daemon=True).start()
serve(80, hello)
"""
DOWN = r"""
import socket, sys, time
src = sys.argv[3] if len(sys.argv) > 3 else None
s = socket.create_connection((sys.argv[1], 5001), timeout=5, source_address=(src, 0) if src else None)
f = s.makefile("rb"); name = f.readline().decode().strip()
t_end = time.monotonic() + 0.7                       # разгон
while time.monotonic() < t_end: f.read1(262144)
n, t0 = 0, time.monotonic()
while time.monotonic() - t0 < float(sys.argv[2]): n += len(f.read1(262144))
print(name, round(n * 8 / (time.monotonic() - t0) / 1e6, 2))
"""
UPLOAD = r"""
import socket, sys, time
s = socket.create_connection((sys.argv[1], 5002), timeout=5)
buf = b"y" * 65536; t0 = time.monotonic()
while time.monotonic() - t0 < float(sys.argv[2]): s.sendall(buf)
s.shutdown(socket.SHUT_WR); n, dt = s.recv(100).decode().split()
print(round(int(n) * 8 / float(dt) / 1e6, 2))
"""
HELLO = r"""
import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect((sys.argv[1], 80)); print(s.recv(100).decode())
except OSError as e: print("FAIL", e)
"""


def sh(ns, *cmd, **kw):
    return subprocess.run(["nsenter", f"--net=/var/run/netns/{ns}", "--", *cmd],
                          capture_output=True, text=True, **kw)


def sysctl(ns, key, val):
    sh(ns, "sh", "-c", f"echo {val} > /proc/sys/{key.replace('.', '/')}")


def nft(ns, text):
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
        f.write(text)
    p = sh(ns, "nft", "-f", f.name)
    assert p.returncode == 0, p.stderr


def setup():
    for n in NS:
        if n in netns.listnetns():
            netns.remove(n)
        netns.create(n)
    pairs = (("c0", "awg0"), ("eth0", "i0"), ("awgr1", "u1"), ("awgr2", "u2"))
    moves = {"c0": "cli", "awg0": "amz", "eth0": "amz", "i0": "inet", "awgr1": "amz", "u1": "up1",
             "awgr2": "amz", "u2": "up2"}
    with IPRoute() as ip:
        for a, b in pairs:
            ip.link("add", ifname="t_" + a, kind="veth", peer="t_" + b)
        for ifn, ns in moves.items():
            ip.link("set", index=ip.link_lookup(ifname="t_" + ifn)[0], net_ns_fd=ns)
    for ifn, ns in moves.items():
        with NetNS(ns) as nip:
            nip.link("set", index=nip.link_lookup(ifname="t_" + ifn)[0], ifname=ifn)

    def conf(ns, addrs, routes=()):
        with NetNS(ns) as ip:
            for ifn in ["lo"] + [x[0] for x in addrs]:
                ip.link("set", index=ip.link_lookup(ifname=ifn)[0], state="up")
            for ifn, a, p in addrs:
                if a:
                    ip.addr("add", index=ip.link_lookup(ifname=ifn)[0], address=a, prefixlen=p)
            for r in routes:
                ip.route("add", **r)

    conf("cli", [("c0", "10.8.1.2", 24)], [dict(dst="0.0.0.0/0", gateway="10.8.1.1")])
    with NetNS("cli") as ip:
        ip.addr("add", index=ip.link_lookup(ifname="c0")[0], address="10.8.1.3", prefixlen=24)
    conf("amz", [("awg0", "10.8.1.1", 24), ("eth0", "172.20.0.2", 24), ("awgr1", "169.254.200.1", 32),
                 ("awgr2", "169.254.200.2", 32)], [dict(dst="0.0.0.0/0", gateway="172.20.0.1")])
    conf("inet", [("i0", "172.20.0.1", 24)])
    for n in (1, 2):
        conf(f"up{n}", [(f"u{n}", None, 0)])
    for ns in ("inet", "up1", "up2"):
        with NetNS(ns) as ip:
            ip.addr("add", index=ip.link_lookup(ifname="lo")[0], address=TARGET, prefixlen=32)
    for n in (1, 2):
        with NetNS(f"up{n}") as ip:
            u = ip.link_lookup(ifname=f"u{n}")[0]
            ip.route("add", dst=SNAT[n] + "/32", oif=u)
            ip.route("add", dst=f"169.254.200.{n}/32", oif=u)   # см. netns_e2e.py: ARP у veth
            with NetNS("amz") as ip2:
                mac = ip2.get_links(ip2.link_lookup(ifname=f"awgr{n}")[0])[0].get_attr("IFLA_ADDRESS")
            ip.neigh("add", dst=SNAT[n], lladdr=mac, ifindex=u, state=0x80)
    sysctl("amz", "net.ipv4.ip_forward", 1)
    for k in ("all", "default", "awgr1", "awgr2", "eth0", "awg0"):
        sysctl("amz", f"net.ipv4.conf.{k}.rp_filter", 2)
    nft("amz", "table ip amnezia {\n chain c_post {\n  type nat hook postrouting priority 100;\n"
               "  oifname \"eth0\" ip saddr 10.8.1.0/24 masquerade\n }\n}\n")
    with NetNS("amz") as ip:
        for n in (1, 2):
            table = config.TABLE_BASE + n
            ip.rule("add", fwmark=nftgen.mark_for(n), table=table, priority=config.RULE_PRIO_BASE + n)
            ip.route("replace", dst="0.0.0.0/0", type="unreachable", table=table, priority=4096)
            ip.route("replace", dst="0.0.0.0/0", oif=ip.link_lookup(ifname=f"awgr{n}")[0], table=table)
    procs = [subprocess.Popen(["nsenter", f"--net=/var/run/netns/{ns}", "--", sys.executable, "-c", SERVER, name])
             for ns, name in (("inet", "DIRECT"), ("up1", "UP1"), ("up2", "UP2"))]
    time.sleep(0.7)
    return procs


UPS = [{"num": n, "snat": SNAT[n], "mtu": 1420} for n in (1, 2)]


def rules(global_policy, clients=None, balance=frozenset()):
    nft("amz", nftgen.generate("awg0", {}, UPS, global_policy, clients or {}, None, set(balance)))


class Target:
    """Цель панели — пространство amz."""
    key, iface = "netns-amz", "awg0"

    def ns(self, cmd, **kw):
        return sh("amz", *cmd, timeout=kw.get("timeout", 30))


def engine():
    """Engine только с тем, что нужно _sync_shaping (без контейнера и state.json)."""
    os.makedirs(eng_mod.RUN_DIR, exist_ok=True)

    class E:
        _sync_shaping = eng_mod.Engine._sync_shaping
        _shape_failed = eng_mod.Engine._shape_failed
        _tc_batch = eng_mod.Engine._tc_batch
        _ifb_source = eng_mod.Engine._ifb_source
        _clear_shaping = eng_mod.Engine._clear_shaping
        _links = eng_mod.Engine._links
        shaping_plan = eng_mod.Engine.shaping_plan
    e = E()
    e.rt = {f"u{n}": SimpleNamespace(num=n, iface=f"awgr{n}", target_key=Target.key) for n in (1, 2)}
    e.clients = [{"ip": "10.8.1.2", "public_key": "A"}, {"ip": "10.8.1.3", "public_key": "B"}]
    e.events = []
    e.event = lambda lvl, m: e.events.append(str(m))
    e.shape_state, e._shape, e._shape_key, e._shape_retry = None, {}, None, 0.0
    return e


def state(total=None, limits=None, exits=None):
    return {"settings": {"shaping": total} if total else {}, "limits": limits or {},
            "upstreams": [{"id": f"u{n}", "num": n, **((exits or {}).get(n) or {})} for n in (1, 2)]}


def shape(e, st):
    config.DRY_RUN = False
    e._sync_shaping(Target(), st)
    assert not (e.shape_state or {}).get("error"), e.shape_state
    return e.shape_state


def down(src=None, secs=3.0):
    """Скорость загрузки клиента (Мбит/с) и через кого шла."""
    out = sh("cli", sys.executable, "-c", DOWN, TARGET, str(secs), *([src] if src else []), timeout=30).stdout.split()
    return (out[0], float(out[1])) if len(out) == 2 else ("FAIL", 0.0)


def upload(secs=3.0):
    out = sh("cli", sys.executable, "-c", UPLOAD, TARGET, str(secs), timeout=30).stdout.split()
    return float(out[0]) if out else 0.0


def hello(src="10.8.1.2"):
    code = HELLO.replace("s.connect(", f"s.bind(({src!r}, 0)); s.connect(")
    return sh("cli", sys.executable, "-c", code, TARGET, timeout=10).stdout.strip()


def near(label, got, want, lo=0.6, hi=1.15):
    ok = lo * want <= got <= hi * want
    print(f"{'OK ' if ok else 'BAD'} {label:62} {got:7.2f} Мбит/с (ожидалось ≈ {want})")
    return ok


def check(label, ok, detail=""):
    print(f"{'OK ' if ok else 'BAD'} {label:62} {detail}")
    return ok


def main():
    procs = setup()
    results = []
    e = engine()
    try:
        rules({"rules": [], "default": "direct"})
        name, free = down()
        results.append(check("без ограничений: загрузка напрямую", name == "DIRECT" and free > 100, f"{free} Мбит/с"))

        shape(e, state(total={"down": 20}))
        results.append(near("общий лимит 20 Мбит/с: загрузка одного клиента", down()[1], 20))

        # двое качают одновременно — делят поровну
        res = {}
        th = [threading.Thread(target=lambda s=s: res.__setitem__(s, down(s, 4.0)[1])) for s in ("10.8.1.2", "10.8.1.3")]
        [t.start() for t in th]
        [t.join() for t in th]
        results.append(near("общий лимит: клиент .2 при двух качающих", res.get("10.8.1.2", 0), 10, 0.55, 1.3))
        results.append(near("общий лимит: клиент .3 при двух качающих", res.get("10.8.1.3", 0), 10, 0.55, 1.3))

        shape(e, state(total={"down": 20}, limits={"A": {"rate_down": 5}}))
        results.append(near("личный лимит 5 Мбит/с внутри общего", down("10.8.1.2")[1], 5))
        results.append(near("сосед без личного лимита — общий", down("10.8.1.3")[1], 20))

        shape(e, state(limits={"A": {"rate_up": 8}}))
        results.append(near("отдача клиента 8 Мбит/с (ifb на входе awg0)", upload(), 8))
        results.append(check("загрузка без ограничения после смены настроек", down()[1] > 100))

        rules({"rules": [], "default": 1})
        shape(e, state(exits={1: {"rate_down": 15, "rate_up": 6}}))
        name, sp = down()
        results.append(check("через выход 1", name == "UP1", name))
        results.append(near("выход 1: загрузка 15 Мбит/с (ifb на входе awgr1)", sp, 15))
        results.append(near("выход 1: отдача 6 Мбит/с", upload(), 6))

        shape(e, state())
        q = sh("amz", "tc", "qdisc", "show").stdout
        links = sh("amz", "ip", "-o", "link", "show").stdout
        results.append(check("выключено: наших очередей и ifb не осталось",
                             f"htb {eng_mod.shaping.HANDLE}:" not in q and "awgq" not in links))
        results.append(check("выключено: скорость снова полная", down()[1] > 100))

        # балансировка: открытое соединение остаётся на прежнем выходе, новые — на новом
        S = nftgen.Sticky
        rules({"rules": [], "default": "direct"}, {"10.8.1.2": {"rules": [], "default": S(1)}}, {1, 2})
        s = subprocess.Popen(["nsenter", "--net=/var/run/netns/cli", "--", sys.executable, "-c",
                              "import socket,sys,time\ns=socket.socket(); s.bind(('10.8.1.2',0))\n"
                              f"s.connect(({TARGET!r},5001)); f=s.makefile('rb'); print(f.readline().decode().strip(), flush=True)\n"
                              "for line in sys.stdin:\n"
                              "    n=0; t=time.monotonic()\n"
                              "    s.settimeout(3)\n"
                              "    try:\n"
                              "        while time.monotonic()-t<1: n+=len(f.read1(65536))\n"
                              "    except OSError: pass\n"
                              "    print(n, flush=True)\n"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        first = s.stdout.readline().strip()
        results.append(check("балансировка: соединение открыто через выход 1", first == "UP1", first))
        rules({"rules": [], "default": "direct"}, {"10.8.1.2": {"rules": [], "default": S(2)}}, {1, 2})
        results.append(check("клиент перенесён на выход 2: новое соединение — через UP2",
                             hello().startswith("UP2"), hello()))
        s.stdin.write("go\n")
        s.stdin.flush()
        got = int((s.stdout.readline() or "0").strip() or 0)
        results.append(check("старое соединение не порвалось — данные идут", got > 1_000_000, f"{got} байт за 1 с"))
        s.kill()
        # обычный выход (не Sticky) при той же смене переносит и открытые соединения — так было до 1.19
        rules({"rules": [], "default": "direct"}, {"10.8.1.2": {"rules": [], "default": 1}})
        results.append(check("без балансировки: выход 1", hello().startswith("UP1")))
    finally:
        for p in procs:
            p.kill()
        for n in NS:
            netns.remove(n)
    print(f"\n{sum(results)}/{len(results)} проверок пройдено")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
