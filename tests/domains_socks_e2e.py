"""Сквозная проверка выхода SOCKS5 (hev-socks5-tunnel) и правил по доменам для него (sniproxy.py)
в сетевых пространствах. Нужны root, nft, pyroute2 и hev-socks5-tunnel в PATH.

   cli ──(awg0 10.8.1.0/24)── amz ──(eth0)── inet ──── prx
                               │                         SOCKS5 172.21.0.2:1080 (логин/пароль),
                               └─ awgr1: hev-socks5-tunnel → SOCKS5 в prx

У inet и prx свои серверы на одних и тех же «внешних» адресах (8.8.8.8, 8.8.4.4, 77.88.55.242):
в inet они отвечают DIRECT, в prx — PROXY. Так видно, каким путём прошло соединение. SOCKS5 в prx
знает имена *.test (CONNECT по имени), поэтому видно и то, что прокси передано имя сайта.

В amz работают ровно те части панели, что и на сервере: правила nftgen.generate (перенаправление
в sniproxy.py, блок QUIC, цепочки type route для соединений без совпадения), сам sniproxy.py,
конфиг socks.hev_config и проверка socks.check.
Запуск: sudo PYTHONPATH=<pyroute2>:. python3 tests/domains_socks_e2e.py
hev-socks5-tunnel открывает сокеты AF_INET6: в ядре должна быть поддержка IPv6 (на обычных
серверах она есть; в песочнице без IPv6 нужна подмена сокетов на IPv4 через LD_PRELOAD).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

from pyroute2 import IPRoute, NetNS, netns

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import config, nftgen, socks  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SRV = os.path.join(HERE, "e2e_servers.py")
NS = ["cli", "amz", "inet", "prx"]
USER, PW = "alice", "s3cret:pw"
TMP = tempfile.mkdtemp(prefix="awgr-e2e-")
NAMES = ["foreign.test=8.8.8.8", "www.foreign.test=8.8.8.8", "cdnfoo.test=8.8.4.4", "ru.test=77.88.55.242"]
SOCKS = {"ip": "172.21.0.2", "port": 1080, "user": USER, "password": PW}

CLIENT_TCP = r"""
import socket,sys
s=socket.socket(); s.settimeout(float(sys.argv[2]) if len(sys.argv) > 2 else 3)
try:
    s.connect((sys.argv[1],80)); print(s.recv(100).decode())
except OSError as e: print("FAIL", type(e).__name__, e.errno)
"""
# соединение с данными клиента: TLS ClientHello с именем, запрос HTTP или просто байты
CLIENT_HELLO = r"""
import socket,ssl,sys
ip,port,name=sys.argv[1],int(sys.argv[2]),sys.argv[3]
if name=="-": data=b"not tls at all\r\n"
elif name.startswith("http:"): data=("GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % name[5:]).encode()
else:
    i,o=ssl.MemoryBIO(),ssl.MemoryBIO(); obj=ssl.create_default_context().wrap_bio(i,o,server_hostname=name)
    try: obj.do_handshake()
    except ssl.SSLWantReadError: pass
    data=o.read()
s=socket.socket(); s.settimeout(5)
try:
    s.connect((ip,port)); s.sendall(data); print(s.recv(100).decode() or "EMPTY")
except OSError as e: print("FAIL", type(e).__name__)
"""
CLIENT_UDP = r"""
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(b"x",(sys.argv[1],int(sys.argv[2]))); print(s.recvfrom(100)[0].decode())
except OSError as e: print("FAIL", type(e).__name__)
"""


def sh(ns, *cmd, **kw):
    return subprocess.run(["nsenter", f"--net=/var/run/netns/{ns}", "--", *cmd],
                          capture_output=True, text=True, **kw)


def bg(ns, *cmd, log=None):
    name = log or f"{ns}-{os.path.basename(cmd[2] if len(cmd) > 2 else cmd[0])}-{len(os.listdir(TMP))}"
    return subprocess.Popen(["nsenter", f"--net=/var/run/netns/{ns}", "--", *cmd],
                            stdout=subprocess.DEVNULL, stderr=open(os.path.join(TMP, name + ".log"), "w"))


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
    conf("prx", [("p0", "172.21.0.2", 24)], [dict(dst="0.0.0.0/0", gateway="172.21.0.1")], lo=targets)
    sysctl("amz", "net.ipv4.ip_forward", 1)
    sysctl("inet", "net.ipv4.ip_forward", 1)
    for k in ("all", "default"):
        sysctl("amz", f"net.ipv4.conf.{k}.rp_filter", 2)
    sysctl("amz", "net.ipv4.conf.all.src_valid_mark", 1)
    # как iptables AmneziaVPN: клиенты выходят в интернет через NAT на eth0
    nft("amz", "table ip amnezia {\n chain c_post {\n  type nat hook postrouting priority 100;\n"
               "  oifname \"eth0\" ip saddr 10.8.1.0/24 masquerade\n }\n}\n")
    procs = {
        "inet-http": bg("inet", sys.executable, SRV, "http", "DIRECT", *targets),
        "inet-echo": bg("inet", sys.executable, SRV, "echo", "DIRECT-UDP", "8.8.8.8"),
        "prx-http": bg("prx", sys.executable, SRV, "http", "PROXY", *targets),
        "prx-echo": bg("prx", sys.executable, SRV, "echo", "PROXY-UDP", "8.8.8.8"),
        "socks": bg("prx", sys.executable, SRV, "socks", "172.21.0.2", "1080", USER, PW, *NAMES, log="socks"),
    }
    time.sleep(0.7)
    return procs


def start_hev():
    cfg = os.path.join(TMP, "awgr1.yml")
    with open(cfg, "w") as f:
        f.write(socks.hev_config("awgr1", 1, "172.21.0.2", {"port": 1080, "user": USER, "password": PW}))
    p = bg("amz", socks.HEV, cfg, log="hev")
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


UPS = [{"num": 1, "snat": "", "mtu": 8500}]
IP_LISTS = {"via": ["8.8.4.4/32"]}


def rules(policy, sniff=True):
    nft("amz", nftgen.generate("awg0", IP_LISTS, UPS, policy, {}, config.SNI_PROXY_PORT if sniff else None))


def sni_conf(policy, to):
    """Конфиг sniproxy.py — как его собирает engine._sync_sni."""
    lists = {}
    with open(os.path.join(TMP, "dvid.domains"), "w") as f:
        f.write("foreign.test\ncdnfoo.test\n")
    lists["dvid"] = os.path.join(TMP, "dvid.domains")
    policies, cmap = nftgen.layout(policy, {}, {1})
    marks = nftgen.sniff_marks(policies)
    cfg = {"listen": "10.8.1.0", "port": config.SNI_PROXY_PORT, "clients": "10.8.1.0/24",
           "stats": os.path.join(TMP, "sni-stats.json"), "lists": lists, "client_policy": cmap,
           "policies": {n: {"mark": m, "rules": [{"lists": l, "to": to} for l, _ in policies[n]["domain"]]}
                        for n, m in marks.items()}}
    p = os.path.join(TMP, "sni.json")
    with open(p, "w") as f:
        json.dump(cfg, f)
    return p


def start_sni(conf):
    p = bg("amz", sys.executable, os.path.join(HERE, "..", "app", "sniproxy.py"), conf, log="sniproxy")
    time.sleep(0.8)
    return p


def tcp(ip, wait=3):
    return sh("cli", sys.executable, "-c", CLIENT_TCP, ip, str(wait), timeout=15).stdout.strip()


def hello(ip, name, port=443):
    return sh("cli", sys.executable, "-c", CLIENT_HELLO, ip, str(port), name, timeout=15).stdout.strip()


def udp(ip, port=7):
    return sh("cli", sys.executable, "-c", CLIENT_UDP, ip, str(port), timeout=10).stdout.strip()


RESULTS = []


def check(label, got, want):
    ok = (want(got) if callable(want) else got.startswith(want))
    print(f"{'OK ' if ok else 'BAD'} {label:66} → {got}")
    RESULTS.append(ok)


def socks_check(pw):
    """socks.check панели (у сервера та же сеть, что у amz)."""
    return sh("amz", sys.executable, "-c",
              "import sys;sys.path.insert(0,sys.argv[1]);from app import socks;"
              "r=socks.check({'host':'172.21.0.2','port':1080,'user':sys.argv[2],'password':sys.argv[3]});"
              "print('ok' if r['ok'] else r['error'].key)", os.path.join(HERE, ".."), USER, pw,
              timeout=30).stdout.strip() or "?"


def main():
    if not shutil.which(socks.HEV):
        print("hev-socks5-tunnel не найден в PATH")
        return 1
    procs = setup()
    procs["hev"] = start_hev()
    try:
        # ---------------------------------------------------- проверка прокси панелью
        check("socks.check: верный логин", socks_check(PW), "ok")
        check("socks.check: неверный пароль", socks_check("nope"), "socks.auth_failed")

        # ---------------------------------------------------- выход SOCKS5 по адресам
        rules({"rules": [], "default": "direct"}, sniff=False)
        check("без правил: 8.8.8.8 напрямую", tcp("8.8.8.8"), "DIRECT")
        rules({"rules": [], "default": 1}, sniff=False)
        check("основной выход SOCKS5: TCP через прокси", tcp("8.8.8.8"), "PROXY")
        check("основной выход SOCKS5: UDP через прокси (UDP ASSOCIATE)", udp("8.8.8.8"), "PROXY-UDP")

        # ---------------------------------------------------- правила по доменам
        pol = {"rules": [(["via"], 1)], "default": "direct", "domain": [(["dvid"], "up:u1")]}
        rules(pol)
        procs["sni"] = start_sni(sni_conf(pol, {"socks": SOCKS}))
        check("TLS, домен из списка → через SOCKS5", hello("8.8.8.8", "foreign.test"), "PROXY")
        check("поддомен www.foreign.test → через SOCKS5", hello("8.8.8.8", "www.foreign.test"), "PROXY")
        check("подменённый адрес (192.0.2.1): прокси получил имя сайта", hello("192.0.2.1", "foreign.test"), "PROXY")
        check("HTTP, Host из списка → через SOCKS5", hello("8.8.8.8", "http:foreign.test", 80), "PROXY")
        check("TLS, домен не из списка → напрямую", hello("77.88.55.242", "ru.test"), "DIRECT")
        check("не TLS на 443 (имени нет) → напрямую", hello("77.88.55.242", "-"), "DIRECT")
        check("без совпадения, но адрес в правиле на SOCKS5 → через hev", hello("8.8.4.4", "other.test"), "PROXY")
        check("QUIC (UDP 443) у клиента с правилами по доменам блокируется", udp("8.8.8.8", 443), "FAIL")
        check("остальной UDP — как раньше (напрямую)", udp("8.8.8.8"), "DIRECT-UDP")
        check("клиент молчит (сервер говорит первым): соединение идёт через 3 с", tcp("77.88.55.242", 6), "DIRECT")
        stats = json.load(open(os.path.join(TMP, "sni-stats.json"))) if os.path.exists(os.path.join(TMP, "sni-stats.json")) else {}
        check("счётчики sniproxy.py пишутся", str(sorted(stats)), lambda g: "pid" in g)

        # резервный путь вместо прокси: соединение по совпавшему домену — с меткой (напрямую)
        procs["sni"].terminate()
        procs["sni"].wait(5)
        procs["sni"] = start_sni(sni_conf(pol, {"mark": 0}))
        check("выход не работает → его резервный путь (напрямую)", hello("8.8.8.8", "foreign.test"), "DIRECT")
        procs["sni"].terminate()
        procs["sni"].wait(5)
        procs["sni"] = start_sni(sni_conf(pol, {"block": True}))
        check("резерв «блок» → соединение закрыто", hello("8.8.8.8", "foreign.test"), lambda g: g in ("EMPTY",) or g.startswith("FAIL"))

        # SIGHUP: новые списки без перезапуска
        procs["sni"].terminate()
        procs["sni"].wait(5)
        conf = sni_conf(pol, {"socks": SOCKS})
        procs["sni"] = start_sni(conf)
        with open(os.path.join(TMP, "dvid.domains"), "w") as f:
            f.write("ru.test\n")
        procs["sni"].send_signal(1)
        time.sleep(0.5)
        check("SIGHUP: список перечитан (ru.test теперь через прокси)", hello("77.88.55.242", "ru.test"), "PROXY")
        check("…а foreign.test — уже напрямую", hello("8.8.8.8", "foreign.test"), "DIRECT")

        # посредник остановлен: панель применяет правила без перенаправления — HTTPS не ломается
        procs["sni"].terminate()
        procs["sni"].wait(5)
        check("перенаправление есть, посредника нет → соединение не проходит", hello("8.8.8.8", "foreign.test"), "FAIL")
        rules(pol, sniff=False)
        check("правила без посредника: HTTPS работает по правилам адресов", hello("8.8.8.8", "foreign.test"), "DIRECT")
        check("…и правило по адресу на SOCKS5 по-прежнему действует", hello("8.8.4.4", "x.test"), "PROXY")

        # прокси упал — трафик выхода не утекает напрямую
        procs["socks"].terminate()
        procs["socks"].wait(5)
        rules({"rules": [], "default": 1}, sniff=False)
        check("прокси недоступен: соединение не уходит напрямую", tcp("8.8.8.8"), "FAIL")
        check("socks.check видит, что прокси недоступен", socks_check(PW), "socks.unreachable")
    finally:
        for p in procs.values():
            if p.poll() is None:
                p.terminate()
        for p in procs.values():
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
