"""Сквозная проверка правил по доменам (dnsproxy.py) и выхода SOCKS5 (hev-socks5-tunnel)
в сетевых пространствах. Нужны root, nft, pyroute2 и hev-socks5-tunnel в PATH.

   cli ──(awg0 10.8.1.0/24)── amz ──(eth0)── inet ──── prx
                               │                         SOCKS5 172.21.0.2:1080 (логин/пароль),
                               └─ awgr1: hev-socks5-tunnel → SOCKS5 в prx

У inet и prx свои серверы на одних и тех же «внешних» адресах (8.8.8.8, 8.8.4.4, 77.88.55.242):
в inet они отвечают DIRECT, в prx — PROXY. Так видно, каким путём прошло соединение.
DNS: в inet (172.20.0.2) — обычная зона, в prx (5.5.5.5) — зона, которую видно только через прокси.

В amz работают ровно те части панели, что и на сервере: правила nftgen.generate (наборы доменов,
перенаправление DNS), сам dnsproxy.py, конфиг socks.hev_config и проверка socks.check.
Запуск: sudo PYTHONPATH=<pyroute2>:. python3 tests/domains_socks_e2e.py
hev-socks5-tunnel открывает сокеты AF_INET6: в ядре должна быть поддержка IPv6 (на обычных
серверах она есть; в песочнице без IPv6 нужна подмена сокетов на IPv4 через LD_PRELOAD).
"""
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

from pyroute2 import IPRoute, NetNS, netns

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import config, dnsproxy, nftgen, socks  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SRV = os.path.join(HERE, "e2e_servers.py")
NS = ["cli", "amz", "inet", "prx"]
USER, PW = "alice", "s3cret:pw"
TMP = tempfile.mkdtemp(prefix="awgr-e2e-")
ZONE = ["foreign.test=8.8.8.8", "www.foreign.test=8.8.8.8", "ru.test=77.88.55.242",
        "cdn.video.test=CNAME:edge.cdnfoo.test", "edge.cdnfoo.test=8.8.4.4"]

CLIENT_TCP = r"""
import socket,sys
s=socket.socket(); s.settimeout(3)
try:
    s.connect((sys.argv[1],80)); print(s.recv(100).decode())
except OSError as e: print("FAIL", type(e).__name__, e.errno)
"""
CLIENT_UDP = r"""
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(b"x",(sys.argv[1],7)); print(s.recvfrom(100)[0].decode())
except OSError as e: print("FAIL", type(e).__name__)
"""
# DNS-запрос клиента: печатает «rcode адрес,адрес» (или FAIL)
CLIENT_DNS = r"""
import socket,struct,sys,random
name,server,qtype,tcp=sys.argv[1],sys.argv[2],int(sys.argv[3]),sys.argv[4]=="tcp"
q=struct.pack("!HHHHHH",random.randint(1,65535),0x0100,1,0,0,0)+b"".join(bytes([len(x)])+x.encode() for x in name.split("."))+b"\0"+struct.pack("!HH",qtype,1)
try:
    if tcp:
        s=socket.create_connection((server,53),timeout=4); s.sendall(struct.pack("!H",len(q))+q)
        n=struct.unpack("!H",s.recv(2))[0]; r=b""
        while len(r)<n: r+=s.recv(n-len(r))
    else:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(4); s.sendto(q,(server,53)); r=s.recvfrom(4096)[0]
except OSError as e:
    print("FAIL",type(e).__name__); sys.exit()
sys.path.insert(0,sys.argv[5]); from app import dnsproxy
names,ips=dnsproxy.answers(r)
print(r[3]&15, ",".join(ips), struct.unpack("!H",r[6:8])[0])
"""


def sh(ns, *cmd, **kw):
    return subprocess.run(["nsenter", f"--net=/var/run/netns/{ns}", "--", *cmd],
                          capture_output=True, text=True, **kw)


def bg(ns, *cmd):
    return subprocess.Popen(["nsenter", f"--net=/var/run/netns/{ns}", "--", *cmd],
                            stdout=subprocess.DEVNULL, stderr=open(os.path.join(TMP, f"{ns}-{cmd[-1] if cmd else ''}.log".replace("/", "_")), "w"))


def sysctl(ns, key, val):
    sh(ns, "sh", "-c", f"echo {val} > /proc/sys/{key.replace('.', '/')}")


def nft(ns, text):
    path = os.path.join(TMP, "rules.nft")
    with open(path, "w") as f:
        f.write(text)
    p = sh(ns, "nft", "-f", path)
    assert p.returncode == 0, p.stderr


def setup():
    for n in NS:
        if n in netns.listnetns():
            netns.remove(n)
        netns.create(n)
    with IPRoute() as ip:
        for a, b in (("c0", "awg0"), ("eth0", "i0"), ("i1", "p0")):
            ip.link("add", ifname="t_" + a, kind="veth", peer="t_" + b)
        moves = {"c0": "cli", "awg0": "amz", "eth0": "amz", "i0": "inet", "i1": "inet", "p0": "prx"}
        for ifn, ns in moves.items():
            ip.link("set", index=ip.link_lookup(ifname="t_" + ifn)[0], net_ns_fd=ns)
    for ifn, ns in moves.items():
        with NetNS(ns) as nip:
            nip.link("set", index=nip.link_lookup(ifname="t_" + ifn)[0], ifname=ifn)

    def conf(ns, addrs, routes=(), lo=()):
        with NetNS(ns) as ip:
            for ifn in ["lo"] + [x[0] for x in addrs]:
                ip.link("set", index=ip.link_lookup(ifname=ifn)[0], state="up")
            for ifn, a, p in addrs:
                ip.addr("add", index=ip.link_lookup(ifname=ifn)[0], address=a, prefixlen=p)
            for a in lo:
                ip.addr("add", index=ip.link_lookup(ifname="lo")[0], address=a, prefixlen=32)
            for r in routes:
                ip.route("add", **r)

    targets = ["8.8.8.8", "8.8.4.4", "77.88.55.242"]
    conf("cli", [("c0", "10.8.1.2", 24)], [dict(dst="0.0.0.0/0", gateway="10.8.1.0")])
    # адрес сервера — адрес сети, как в контейнере AmneziaVPN (Address = 10.8.1.0/24)
    conf("amz", [("awg0", "10.8.1.0", 24), ("eth0", "172.20.0.1", 24)], [dict(dst="0.0.0.0/0", gateway="172.20.0.2")])
    conf("inet", [("i0", "172.20.0.2", 24), ("i1", "172.21.0.1", 24)], lo=targets)
    conf("prx", [("p0", "172.21.0.2", 24)], [dict(dst="0.0.0.0/0", gateway="172.21.0.1")], lo=targets + ["5.5.5.5"])
    sysctl("amz", "net.ipv4.ip_forward", 1)
    sysctl("inet", "net.ipv4.ip_forward", 1)
    for k in ("all", "default"):
        sysctl("amz", f"net.ipv4.conf.{k}.rp_filter", 2)
    sysctl("amz", "net.ipv4.conf.all.src_valid_mark", 1)
    # как iptables AmneziaVPN: клиенты выходят в интернет через NAT на eth0
    nft("amz", "table ip amnezia {\n chain c_post {\n  type nat hook postrouting priority 100;\n"
               "  oifname \"eth0\" ip saddr 10.8.1.0/24 masquerade\n }\n}\n")
    procs = [
        bg("inet", sys.executable, SRV, "http", "DIRECT", *targets),
        bg("inet", sys.executable, SRV, "echo", "DIRECT-UDP", "8.8.8.8"),
        bg("inet", sys.executable, SRV, "dns", "172.20.0.2", *ZONE),
        bg("prx", sys.executable, SRV, "http", "PROXY", *targets),
        bg("prx", sys.executable, SRV, "echo", "PROXY-UDP", "8.8.8.8"),
        bg("prx", sys.executable, SRV, "dns", "5.5.5.5", "only-proxy.test=8.8.4.4", *ZONE),
        bg("prx", sys.executable, SRV, "socks", "172.21.0.2", "1080", USER, PW),
    ]
    time.sleep(0.7)
    return procs


def start_hev():
    cfg = os.path.join(TMP, "awgr1.yml")
    with open(cfg, "w") as f:
        f.write(socks.hev_config("awgr1", 1, "172.21.0.2", {"port": 1080, "user": USER, "password": PW}))
    p = bg("amz", socks.HEV, cfg)
    for _ in range(50):
        with NetNS("amz") as ip:
            if ip.link_lookup(ifname="awgr1"):
                break
        time.sleep(0.1)
    sysctl("amz", "net.ipv4.conf.awgr1.rp_filter", 2)
    with NetNS("amz") as ip:
        table = config.TABLE_BASE + 1
        ip.rule("add", fwmark=nftgen.mark_for(1), table=table, priority=config.RULE_PRIO_BASE + 1)
        ip.route("replace", dst="0.0.0.0/0", type="unreachable", table=table, priority=4096)
        ip.route("replace", dst="0.0.0.0/0", oif=ip.link_lookup(ifname="awgr1")[0], table=table)
    return p


def rules(global_policy, domain_lists, dns=("proxy", config.DNS_PROXY_PORT), ip_lists=None):
    lists = {**(ip_lists or {}), **{lid: [] for lid in domain_lists}}
    ups = [{"num": 1, "snat": "", "mtu": 8500}]
    nft("amz", nftgen.generate("awg0", lists, ups, global_policy, {}, set(domain_lists), dns))


def write_lists(lists):
    files = {}
    for lid, names in lists.items():
        p = os.path.join(TMP, f"{lid}.domains")
        with open(p, "w") as f:
            f.write("\n".join(names) + "\n")
        files[lid] = p
    return files


def proxy_conf(files, upstreams):
    p = os.path.join(TMP, "dns.json")
    with open(p, "w") as f:
        json.dump({"listen": "10.8.1.0", "port": config.DNS_PROXY_PORT, "clients": "10.8.1.0/24",
                   "table": config.NFT_TABLE, "upstreams": upstreams, "lists": files,
                   "timeout": 3600, "stats": os.path.join(TMP, "dns-stats.json"), "strip_aaaa": True}, f)
    return p


def tcp(ip):
    return sh("cli", sys.executable, "-c", CLIENT_TCP, ip, timeout=10).stdout.strip()


def udp(ip):
    return sh("cli", sys.executable, "-c", CLIENT_UDP, ip, timeout=10).stdout.strip()


def resolve(name, server="9.9.9.9", qtype=1, proto="udp"):
    return sh("cli", sys.executable, "-c", CLIENT_DNS, name, server, str(qtype), proto,
              os.path.join(HERE, ".."), timeout=10).stdout.strip()


def socks_check(pw):
    """socks.check панели (у сервера та же сеть, что у amz)."""
    return sh("amz", sys.executable, "-c",
              "import sys;sys.path.insert(0,sys.argv[1]);from app import socks;"
              "r=socks.check({'host':'172.21.0.2','port':1080,'user':sys.argv[2],'password':sys.argv[3]});"
              "print('ok' if r['ok'] else r['error'].key)", os.path.join(HERE, ".."), USER, pw,
              timeout=30).stdout.strip() or "?"


RESULTS = []


def check(label, got, want):
    ok = (want(got) if callable(want) else got.startswith(want))
    print(f"{'OK ' if ok else 'BAD'} {label:62} → {got}")
    RESULTS.append(ok)


def set_elems(lid):
    p = sh("amz", "nft", "-j", "list", "set", "ip", config.NFT_TABLE, f"l_{lid}")
    try:
        items = json.loads(p.stdout)["nftables"]
    except (ValueError, KeyError):
        return []
    out = []
    for x in items:
        for e in (x.get("set") or {}).get("elem") or []:
            v = e.get("elem", {}).get("val") if isinstance(e, dict) and "elem" in e else e
            out.append(v)
    return out


def main():
    if not shutil.which(socks.HEV):
        print("hev-socks5-tunnel не найден в PATH")
        return 1
    procs = setup()
    procs.append(start_hev())
    try:
        # ---------------------------------------------------- проверка прокси панелью
        check("socks.check: верный логин", socks_check(PW), "ok")
        check("socks.check: неверный пароль", socks_check("nope"), "socks.auth_failed")

        # ------------------------------------------- без правил: всё напрямую
        rules({"rules": [], "default": "direct"}, [], dns=None)
        check("без правил: 8.8.8.8 напрямую", tcp("8.8.8.8"), "DIRECT")
        rules({"rules": [], "default": 1}, [], dns=None)
        check("основной выход SOCKS5: TCP через прокси", tcp("8.8.8.8"), "PROXY")
        check("основной выход SOCKS5: UDP через прокси (UDP ASSOCIATE)", udp("8.8.8.8"), "PROXY-UDP")

        # ------------------------------------------------- правила по доменам
        files = write_lists({"dvid": ["foreign.test", "cdnfoo.test"]})
        conf = proxy_conf(files, [{"ip": "172.20.0.2", "mark": 0}])
        # запасной путь DNS — как у панели: отдельная таблица, всегда на месте
        nft("amz", nftgen.dns_fallback_ruleset("awg0", "172.20.0.2"))
        rules({"rules": [(["dvid"], 1)], "default": "direct"}, ["dvid"])
        proxy = bg("amz", sys.executable, os.path.join(HERE, "..", "app", "dnsproxy.py"), conf)
        procs.append(proxy)
        time.sleep(0.8)
        check("до DNS-запроса 8.8.8.8 напрямую (набора ещё нет)", tcp("8.8.8.8"), "DIRECT")
        check("DNS foreign.test (запрос на 9.9.9.9 перехвачен)", resolve("foreign.test"), "0 8.8.8.8")
        check("после DNS: 8.8.8.8 через SOCKS5", tcp("8.8.8.8"), "PROXY")
        check("адрес попал в набор nftables", ",".join(map(str, set_elems("dvid"))), lambda g: "8.8.8.8" in g)
        check("ru.test не в списке: 77.88.55.242 напрямую",
              resolve("ru.test") + " | " + tcp("77.88.55.242"), lambda g: g.startswith("0 77.88.55.242") and "DIRECT" in g)
        check("8.8.4.4 без DNS-запроса — напрямую", tcp("8.8.4.4"), "DIRECT")
        check("CNAME cdn.video.test → edge.cdnfoo.test (в списке)", resolve("cdn.video.test"), "0 8.8.4.4")
        check("…и 8.8.4.4 теперь через SOCKS5", tcp("8.8.4.4"), "PROXY")
        check("поддомен www.foreign.test тоже по правилу", resolve("www.foreign.test"), "0 8.8.8.8")
        check("DNS по TCP", resolve("foreign.test", proto="tcp"), "0 8.8.8.8")
        check("DNS на адрес сервера 10.8.1.0", resolve("foreign.test", server="10.8.1.0"), "0 8.8.8.8")
        check("AAAA: пустой ответ (в туннеле только IPv4)", resolve("foreign.test", qtype=28), lambda g: g.startswith("0 ") and g.endswith(" 0"))
        check("HTTPS-запись домена из списка — пустой ответ", resolve("foreign.test", qtype=65), lambda g: g.endswith(" 0"))
        check("несуществующий домен: NXDOMAIN", resolve("nope.test"), "3")

        # таблица пересоздаётся (любое изменение правил) → SIGHUP → адреса возвращаются
        rules({"rules": [(["dvid"], 1)], "default": "direct"}, ["dvid"])
        check("после пересоздания таблицы набор пуст", tcp("8.8.8.8"), "DIRECT")
        proxy.send_signal(1)
        time.sleep(0.8)
        check("SIGHUP: адреса снова в наборе, 8.8.8.8 через SOCKS5", tcp("8.8.8.8"), "PROXY")

        # личное правило клиента и правило «напрямую» поверх выхода по умолчанию
        rules({"rules": [(["dvid"], "direct")], "default": 1}, ["dvid"])
        proxy.send_signal(1)
        time.sleep(0.8)
        check("обратное правило: домены напрямую, остальное через SOCKS5",
              tcp("8.8.8.8") + " | " + tcp("77.88.55.242"), lambda g: g.startswith("DIRECT") and "PROXY" in g)
        # DNS-запрос клиента к 9.9.9.9 по правилам получил метку выхода — всё равно доходит до посредника
        check("DNS при выходе по умолчанию через SOCKS5", resolve("ru.test"), "0 77.88.55.242")

        # DNS-сервер, который виден только через выход: запрос идёт с меткой выхода по TCP
        proxy.terminate()
        proxy.wait(5)
        conf = proxy_conf(files, [{"ip": "5.5.5.5", "mark": nftgen.mark_for(1), "tcp": True}])
        rules({"rules": [(["dvid"], 1)], "default": "direct"}, ["dvid"])
        proxy = bg("amz", sys.executable, os.path.join(HERE, "..", "app", "dnsproxy.py"), conf)
        procs.append(proxy)
        time.sleep(0.8)
        check("DNS через выход SOCKS5 (метка + TCP)", resolve("only-proxy.test"), "0 8.8.4.4")

        # посредник остановлен: DNS клиентов уходит запасным путём (awgr_dns) прямо на DNS из настроек
        proxy.terminate()
        proxy.wait(5)
        rules({"rules": [(["dvid"], 1)], "default": "direct"}, ["dvid"], dns=None)
        check("посредник не работает: DNS отвечает запасным путём", resolve("ru.test", server="10.8.1.0"), "0 77.88.55.242")
        check("…и по TCP", resolve("ru.test", server="10.8.1.0", proto="tcp"), "0 77.88.55.242")
        # остановка панели при «оставлять правила»: цепочку c_dns убирают из основной таблицы
        rules({"rules": [(["dvid"], 1)], "default": "direct"}, ["dvid"])
        check("redirect есть, посредника нет → DNS не отвечает", resolve("ru.test", server="10.8.1.0"), "FAIL")
        nft("amz", f"flush chain ip {config.NFT_TABLE} c_dns\ndelete chain ip {config.NFT_TABLE} c_dns\n")
        check("после удаления c_dns (как при остановке панели) DNS снова отвечает",
              resolve("ru.test", server="10.8.1.0"), "0 77.88.55.242")

        # прокси упал — трафик выхода не утекает напрямую
        procs[6].terminate()
        procs[6].wait(5)
        rules({"rules": [], "default": 1}, [], dns=None)
        check("прокси недоступен: соединение не уходит напрямую", tcp("8.8.8.8"), "FAIL")
        check("socks.check видит, что прокси недоступен", socks_check(PW), "socks.unreachable")
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        for n in NS:
            if n in netns.listnetns():
                netns.remove(n)
    print(f"\n{sum(RESULTS)}/{len(RESULTS)} проверок пройдено")
    if not all(RESULTS):
        print("журналы:", TMP)
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
