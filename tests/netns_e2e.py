"""Сквозная проверка схемы маршрутизации в сетевых пространствах (нужен root, nft, pyroute2).

   cli ──(awg0)── amz ──(eth0)── inet      «интернет напрямую»  → отвечает DIRECT
                   └──(awgr1)── up1        «выходной сервер»     → отвечает UP1

В amz применяются ровно те правила nftables, ip rule и маршруты, что создаёт панель.
Туннель AWG заменён veth — для маршрутизации разницы нет.
Запуск: PYTHONPATH=<pyroute2>:. python3 tests/netns_e2e.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time

from pyroute2 import IPRoute, NetNS, netns

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import config, nftgen  # noqa: E402

NS = ["cli", "amz", "inet", "up1"]
TARGETS = {"foreign": "8.8.8.8", "russian": "77.88.55.242"}
SERVER = r"""
import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",80)); s.listen(16)
while True:
    c,a=s.accept(); c.sendall((sys.argv[1]+" from "+a[0]).encode()); c.close()
"""
CLIENT = r"""
import socket,sys
s=socket.socket(); s.settimeout(2)
if len(sys.argv) > 2: s.bind((sys.argv[2], 0))
try:
    s.connect((sys.argv[1],80)); print(s.recv(100).decode())
except OSError as e: print("FAIL", type(e).__name__, e.errno)
"""


def sh(ns, *cmd, **kw):
    return subprocess.run(["nsenter", f"--net=/var/run/netns/{ns}", "--", *cmd],
                          capture_output=True, text=True, **kw)


def sysctl(ns, key, val):
    sh(ns, "sh", "-c", f"echo {val} > /proc/sys/{key.replace('.', '/')}")


def setup():
    for n in NS:
        if n in netns.listnetns():
            netns.remove(n)
        netns.create(n)
    with IPRoute() as ip:
        # временные имена (в корневом пространстве eth0 уже есть), затем переименование
        for a, b in (("c0", "awg0"), ("eth0", "i0"), ("awgr1", "u0")):
            ip.link("add", ifname="t_" + a, kind="veth", peer="t_" + b)
        moves = {"c0": "cli", "awg0": "amz", "eth0": "amz", "i0": "inet", "awgr1": "amz", "u0": "up1"}
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
    with NetNS("cli") as ip:  # второй клиент с тем же адресом, что у нас на выходном сервере
        ip.addr("add", index=ip.link_lookup(ifname="c0")[0], address="10.8.1.3", prefixlen=24)
    conf("amz", [("awg0", "10.8.1.1", 24), ("eth0", "172.20.0.2", 24), ("awgr1", "169.254.200.1", 32)],
         [dict(dst="0.0.0.0/0", gateway="172.20.0.1")])
    for ns, ifn in (("inet", "i0"), ("up1", "u0")):
        addrs = [(ifn, "172.20.0.1", 24)] if ns == "inet" else [(ifn, None, 0)]
        conf(ns, addrs)
        with NetNS(ns) as ip:
            lo = ip.link_lookup(ifname="lo")[0]
            for t in TARGETS.values():
                ip.addr("add", index=lo, address=t, prefixlen=32)
    with NetNS("up1") as ip:
        u0 = ip.link_lookup(ifname="u0")[0]
        ip.route("add", dst="10.8.1.3/32", oif=u0)  # адрес «нашего клиента» на выходном сервере
        with NetNS("amz") as ip2:
            mac = ip2.get_links(ip2.link_lookup(ifname="awgr1")[0])[0].get_attr("IFLA_ADDRESS")
        ip.neigh("add", dst="10.8.1.3", lladdr=mac, ifindex=u0, state=0x80)
    sysctl("amz", "net.ipv4.ip_forward", 1)
    # как у Docker по умолчанию — строгая проверка источника; панель переключает на «loose»
    for k in ("all", "awgr1", "eth0", "awg0"):
        sysctl("amz", f"net.ipv4.conf.{k}.rp_filter", 1)
    # имитация iptables Amnezia: MASQUERADE клиентов через eth0
    nft("amz", "table ip amnezia {\n chain c_post {\n  type nat hook postrouting priority 100;\n"
               "  oifname \"eth0\" ip saddr 10.8.1.0/24 masquerade\n }\n}\n")
    procs = []
    for ns, name in (("inet", "DIRECT"), ("up1", "UP1")):
        procs.append(subprocess.Popen(["nsenter", f"--net=/var/run/netns/{ns}", "--",
                                       sys.executable, "-c", SERVER, name]))
    time.sleep(0.5)
    return procs


def nft(ns, text):
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
        f.write(text)
    p = sh(ns, "nft", "-f", f.name)
    assert p.returncode == 0, p.stderr


def panel_apply(global_policy, clients, upstream_alive=True):
    """То, что делает engine.reconcile() внутри контейнера Amnezia."""
    for k in ("all", "default", "awgr1"):
        sysctl("amz", f"net.ipv4.conf.{k}.rp_filter", 2)
    ups = [{"num": 1, "snat": "10.8.1.3", "mtu": 1280}] if upstream_alive else []
    nft("amz", nftgen.generate("awg0", {"ru": ["77.88.0.0/18", "5.3.0.0/16"]}, ups,
                               global_policy, clients))
    with NetNS("amz") as ip:
        table = config.TABLE_BASE + 1
        if not ip.get_rules(priority=config.RULE_PRIO_BASE + 1):
            ip.rule("add", fwmark=nftgen.mark_for(1), table=table, priority=config.RULE_PRIO_BASE + 1)
        ip.route("replace", dst="0.0.0.0/0", type="unreachable", table=table, priority=4096)
        idx = ip.link_lookup(ifname="awgr1")
        if idx:
            try:
                ip.route("replace", dst="0.0.0.0/0", oif=idx[0], table=table)
            except Exception:  # интерфейс лежит — панель тоже игнорирует (check=False)
                pass


def acct():
    """Счётчики таблицы учёта трафика по выходам в amz."""
    p = sh("amz", "nft", "-j", "list", "table", "ip", nftgen.ACCT_TABLE)
    assert p.returncode == 0, p.stderr
    return nftgen.parse_acct(json.loads(p.stdout), "awg0")


def check(label, ok):
    print(f"{'OK ' if ok else 'BAD'} {label}")
    return ok


def probe(target, src="10.8.1.2"):
    return sh("cli", sys.executable, "-c", CLIENT, TARGETS[target], src, timeout=10).stdout.strip()


def expect(label, target, want, src="10.8.1.2"):
    got = probe(target, src)
    ok = got.startswith(want)
    print(f"{'OK ' if ok else 'BAD'} {label:58} {target:8} → {got}")
    return ok


def main():
    procs = setup()
    results = []
    try:
        # таблица учёта стоит с самого начала: все проверки маршрутов ниже идут с ней
        nft("amz", nftgen.acct_ruleset("awg0"))
        g = {"rules": [(["ru"], "direct")], "default": 1}
        panel_apply(g, {})
        results += [expect("глобально: всё через выход, RU напрямую", "foreign", "UP1 from 10.8.1.3"),
                    expect("глобально: всё через выход, RU напрямую", "russian", "DIRECT from 172.20.0.2")]
        panel_apply(g, {"10.8.1.3": {"rules": [], "default": "direct"}})
        results += [expect("клиент .2 через выход (SNAT в 10.8.1.3)", "foreign", "UP1 from 10.8.1.3"),
                    expect("клиент .3 с тем же адресом — напрямую, без конфликта", "foreign",
                           "DIRECT from 172.20.0.2", src="10.8.1.3")]
        panel_apply(g, {"10.8.1.2": {"rules": [], "default": "direct"}})
        results += [expect("клиенту назначено «напрямую»", "foreign", "DIRECT")]
        before = acct()
        panel_apply(g, {"10.8.1.2": {"rules": [], "default": "block"}})
        results += [expect("клиенту назначено «блокировать»", "foreign", "FAIL")]
        a = acct()
        results += [
            check("учёт: клиент .2 через выход — счётчики в обе стороны",
                  all(a.get(("10.8.1.2", "awgr1"), [0, 0]))),
            check("учёт: клиент .2 напрямую (RU) — счётчики в обе стороны",
                  all(a.get(("10.8.1.2", "eth0"), [0, 0]))),
            check("учёт: клиент .3 напрямую", all(a.get(("10.8.1.3", "eth0"), [0, 0]))),
            check("учёт: заблокированный трафик не считается", a == before),
            check("учёт: таблица пережила 4 пересоздания основной таблицы", a.get(("10.8.1.2", "awgr1"))
                  is not None and a[("10.8.1.2", "awgr1")] >= before[("10.8.1.2", "awgr1")])]
        panel_apply({"rules": [], "default": 1}, {})
        results += [expect("без правил: RU тоже через выход", "russian", "UP1")]
        # туннель исчез (упал amneziawg-go): маршрут по таблице → unreachable, утечки нет
        panel_apply(g, {})
        with NetNS("amz") as ip:
            ip.link("set", index=ip.link_lookup(ifname="awgr1")[0], state="down")
        results += [expect("туннель упал до реакции панели: не утекает напрямую", "foreign", "FAIL"),
                    expect("туннель упал: RU по-прежнему напрямую", "russian", "DIRECT")]
        # панель заметила и переключила на резерв «напрямую»
        panel_apply({"rules": [(["ru"], "direct")], "default": "direct"}, {}, upstream_alive=False)
        results += [expect("резерв «напрямую» после переключения", "foreign", "DIRECT")]
    finally:
        for p in procs:
            p.kill()
        for n in NS:
            netns.remove(n)
    print(f"\n{sum(results)}/{len(results)} проверок пройдено")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
