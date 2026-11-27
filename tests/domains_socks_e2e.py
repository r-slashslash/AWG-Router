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
import threading
import time

from pyroute2 import IPRoute, NetNS, netns

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import config, nftgen, shaping, socks  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SRV = os.path.join(HERE, "e2e_servers.py")
NS = ["cli", "amz", "inet", "prx"]
USER, PW = "alice", "s3cret:pw"
TMP = tempfile.mkdtemp(prefix="awgr-e2e-")
NAMES = ["foreign.test=8.8.8.8", "www.foreign.test=8.8.8.8", "cdnfoo.test=8.8.4.4", "ru.test=77.88.55.242",
         "big.test=1.1.1.1"]
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
# замер загрузки: ClientHello с именем (если не «-»), затем читаем поток; → Мбит/с
CLIENT_STREAM = r"""
import socket,ssl,sys,time
ip,port,name,secs=sys.argv[1],int(sys.argv[2]),sys.argv[3],float(sys.argv[4])
s=socket.create_connection((ip,port),timeout=5)
if name!="-":
    i,o=ssl.MemoryBIO(),ssl.MemoryBIO(); obj=ssl.create_default_context().wrap_bio(i,o,server_hostname=name)
    try: obj.do_handshake()
    except ssl.SSLWantReadError: pass
    s.sendall(o.read())
f=s.makefile("rb"); t=time.monotonic()+1.5          # разгон и время панели поделить предел
while time.monotonic()<t: f.read1(262144)
n,t0=0,time.monotonic()
while time.monotonic()-t0<secs: n+=len(f.read1(262144))
print(round(n*8/(time.monotonic()-t0)/1e6,2))
"""
# «фильтр по DNS» (Д2 независимой проверки П31): спросить имя у DNS на сервере и сразу — как браузер — соединиться с
# адресом из ответа; → «адрес мс-ответа ответ-сервера»
CLIENT_DNS_HELLO = r"""
import socket,ssl,struct,sys,time
name,dns=sys.argv[1],sys.argv[2]
q=struct.pack("!6H",0x4242,0x0100,1,0,0,0)+b"".join(bytes([len(x)])+x.encode() for x in name.split("."))+b"\0"
q+=struct.pack("!HH",1,1)
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.settimeout(5)
t0=time.monotonic(); u.sendto(q,(dns,53)); r=u.recv(512); ms=round((time.monotonic()-t0)*1000)
ip=socket.inet_ntoa(r[-4:])
i,o=ssl.MemoryBIO(),ssl.MemoryBIO(); obj=ssl.create_default_context().wrap_bio(i,o,server_hostname=name)
try: obj.do_handshake()
except ssl.SSLWantReadError: pass
s=socket.socket(); s.settimeout(5)
try:
    s.connect((ip,443)); s.sendall(o.read()); print(ip, ms, s.recv(100).decode() or "EMPTY")
except OSError as e: print(ip, ms, "FAIL", type(e).__name__)
"""
CLIENT_UDP = r"""
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(b"x",(sys.argv[1],int(sys.argv[2]))); print(s.recvfrom(100)[0].decode())
except OSError as e: print("FAIL", type(e).__name__)
"""

# QUIC: настоящие первые датаграммы Chromium 153 (ClientHello в двух пакетах, имя quic.test) с одного
# сокета, затем ответ эхо-сервера; extra — ещё датаграмма с короткого заголовка того же «соединения»
CLIENT_QUIC = r"""
import socket,sys
ip,path,count,extra=sys.argv[1],sys.argv[2],int(sys.argv[3]),sys.argv[4]=="1"
ds=[bytes.fromhex(l) for l in open(path).read().split()][:count]
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.connect((ip,443))
out=[]
try:
    for d in ds: s.send(d)
    out.append(s.recv(100).decode())
    while True:
        try: s.recv(100)
        except socket.timeout: break
    if extra:
        s.send(bytes([0x41])+bytes(40)); out.append(s.recv(100).decode())
except OSError as e: out.append("FAIL "+type(e).__name__)
print(" ".join(out))
"""
QUIC_V1 = os.path.join(HERE, "fixtures", "quic-chromium153-v1.hex")
QUIC_V2 = os.path.join(HERE, "fixtures", "quic-chromium153-v2.hex")


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
    conf("prx", [("p0", "172.21.0.2", 24)], [dict(dst="0.0.0.0/0", gateway="172.21.0.1")],
         lo=targets + ["1.1.1.1", "9.9.9.9"])
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
        # потоки для замера скорости: big.test (правило по доменам → посредник) и 8.8.4.4 (правило по адресу → hev)
        # 9.9.9.9:443 — правило по адресу, но TCP 443 у клиента с правилами по доменам идёт через посредник (1.24.0:
        # ограничение скорости правила общее для этой дороги и транзитной 8.8.4.4:5001)
        "prx-stream": bg("prx", sys.executable, SRV, "stream", "1.1.1.1:443", "8.8.4.4:5001", "9.9.9.9:443",
                         log="stream"),
    }
    time.sleep(0.7)
    return procs


def cpu() -> str:
    """Процессор и ядро машины: от процессора зависит стек сигналов (AMX), см. hev_diag."""
    try:
        with open("/proc/cpuinfo") as f:
            text = f.read()
    except OSError:
        return f"ядро: {os.uname().release}"
    model = next((ln.split(":", 1)[1].strip() for ln in text.splitlines() if ln.startswith("model name")), "?")
    amx = " amx_tile" in text
    return f"процессор: {model}{' (AMX)' if amx else ''}; ядро: {os.uname().release}"


def hev_diag(cfg):
    """hev завершился молча (код 254 — любая ошибка запуска): процессор, ядро и системные вызовы.
    Так было на Intel с AMX, пока сборка не увеличила стек сигналов (musl 1.2.6, см. Dockerfile)."""
    print(f"  {cpu()}")
    if shutil.which("strace"):
        out = os.path.join(TMP, "hev.strace")
        sh("amz", "timeout", "5", "strace", "-f", "-o", out, socks.HEV, cfg, timeout=15)
        with open(out) as f:
            lines = f.read().splitlines()
        print("  strace (конец):\n    " + "\n    ".join(lines[-40:]))
    else:
        print("  strace нет")


def start_hev():
    cfg = os.path.join(TMP, "awgr1.yml")
    with open(cfg, "w") as f:
        f.write(socks.hev_config("awgr1", 1, "172.21.0.2", {"port": 1080, "user": USER, "password": PW}))
    for attempt in range(3):
        p = bg("amz", socks.HEV, cfg, log=f"hev{attempt}")
        for _ in range(150):                      # до 15 с: на занятой машине CI интерфейс бывает не сразу
            with NetNS("amz") as ip:
                if ip.link_lookup(ifname="awgr1"):
                    break
            if p.poll() is not None:
                break
            time.sleep(0.1)
        with NetNS("amz") as ip:
            if ip.link_lookup(ifname="awgr1"):
                break
        with open(os.path.join(TMP, f"hev{attempt}.log")) as f:
            print(f"hev-socks5-tunnel не поднял awgr1 (попытка {attempt + 1}, код {p.poll()}): {f.read()[-400:]!r}")
        if attempt == 0:
            hev_diag(cfg)
        p.kill()
        time.sleep(1)
    sysctl("amz", "net.ipv4.conf.awgr1.rp_filter", 2)
    with NetNS("amz") as ip:
        table = config.TABLE_BASE + 1
        ip.rule("add", fwmark=nftgen.mark_for(1), table=table, priority=config.RULE_PRIO_BASE + 1)
        ip.route("replace", dst="0.0.0.0/0", type="unreachable", table=table, priority=4096)
        ip.route("replace", dst="0.0.0.0/0", oif=ip.link_lookup(ifname="awgr1")[0], table=table)
    return p


UPS = [{"num": 1, "snat": "", "mtu": 8500}]
IP_LISTS = {"via": ["8.8.4.4/32", "9.9.9.9/32"]}


def rules(policy, sniff=True, quic=False, strict=False, balance=frozenset(), labels=False, limits=None,
          dom_filter=False):
    nft("amz", nftgen.generate("awg0", IP_LISTS, UPS, policy, {}, config.SNI_PROXY_PORT if sniff else None,
                               balance, dom_filter=dom_filter, quic=quic, strict=strict, labels=labels, limits=limits))


def racct():
    """Счётчики учёта трафика по правилам (1.24.0) в amz: {(адрес, номер правила): [от клиента, к клиенту]}."""
    p = sh("amz", "nft", "-j", "list", "table", "ip", nftgen.RACCT_TABLE)
    return nftgen.parse_racct(json.loads(p.stdout), "awg0") if p.returncode == 0 else {}


def quic_ok() -> bool:
    """Ядро принимает очередь в nftables (nft_queue): иначе QUIC по имени не проверить."""
    path = os.path.join(TMP, "q.nft")
    with open(path, "w") as f:
        f.write("table ip qprobe {\n chain c {\n  type filter hook prerouting priority 0;\n"
                "  udp dport 9 queue num 9 bypass\n }\n}\ndelete table ip qprobe\n")
    return sh("amz", "nft", "-f", path).returncode == 0


def quic(ip, path=QUIC_V1, count=2, extra=False):
    return sh("cli", sys.executable, "-c", CLIENT_QUIC, ip, path, str(count), "1" if extra else "0",
              timeout=20).stdout.strip()


def sni_conf(policy, to, extra=None, qmark=None):
    """Конфиг sniproxy.py — как его собирает engine._sync_sni."""
    lists = {}
    with open(os.path.join(TMP, "dvid.domains"), "w") as f:
        f.write("foreign.test\ncdnfoo.test\nbig.test\n")
    lists["dvid"] = os.path.join(TMP, "dvid.domains")
    with open(os.path.join(TMP, "dq.domains"), "w") as f:
        f.write("quic.test\n")
    lists["dq"] = os.path.join(TMP, "dq.domains")
    policies, cmap = nftgen.layout(policy, {}, {1})
    marks = nftgen.sniff_marks(policies)
    cfg = {"listen": "10.8.1.0", "port": config.SNI_PROXY_PORT, "clients": "10.8.1.0/24",
           "stats": os.path.join(TMP, "sni-stats.json"), "lists": lists, "client_policy": cmap,
           "policies": {n: {"mark": m, "rules": [{"lists": l, "to": to, "qmark": qmark or config.MARK_BLOCK}
                                                  for l, _ in policies[n]["domain"]]}
                        for n, m in marks.items()},
           "quic": {"queue": config.QUIC_QUEUE, "pass": config.QUIC_PASS_MARK, "block": config.MARK_BLOCK},
           **(extra or {})}
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


def speed(ip, port, name, secs=4.0):
    out = sh("cli", sys.executable, "-c", CLIENT_STREAM, ip, str(port), name, str(secs), timeout=30).stdout.strip()
    try:
        return float(out)
    except ValueError:
        return 0.0


def shared_limit(procs, pol):
    """Предел выхода SOCKS5 20 Мбит/с на загрузку — общий для туннеля (hev) и посредника."""
    cap = 20
    tc = lambda *a: sh("amz", "tc", *a)
    sh("amz", "ip", "link", "add", "awgq1", "type", "ifb")
    sh("amz", "ip", "link", "set", "awgq1", "up")
    for cmds in (shaping.cap_tree("awgq1", cap), shaping.redirect("awgr1", "awgq1")):
        path = os.path.join(TMP, "tc.batch")
        with open(path, "w") as f:
            f.write("\n".join(cmds) + "\n")
        p = sh("amz", "tc", "-batch", path)
        assert p.returncode == 0, p.stderr
    bps = cap * 125_000
    extra = {"rates": {"u1": [0, bps]},
             "shared": {"u1": {"1": {"iface": "awgr1", "dev": "awgq1", "cap": bps,
                                     "tc": shaping.cap_change("awgq1", cap)}}}}
    procs["sni"] = start_sni(sni_conf(pol, {"socks": SOCKS, "acct": "u1"}, extra))
    try:
        res = {}
        alone_sni = speed("1.1.1.1", 443, "big.test")
        alone_tun = speed("8.8.4.4", 5001, "-")
        th = [threading.Thread(target=lambda k=k, a=a: res.__setitem__(k, speed(*a, secs=5.0)))
              for k, a in (("sni", ("1.1.1.1", 443, "big.test")), ("tun", ("8.8.4.4", 5001, "-")))]
        [t.start() for t in th]
        [t.join() for t in th]
        within = lambda lo, hi: (lambda g: lo <= float(g) <= hi)
        check("предел 20: только сайт из правила по доменам (посредник)", f"{alone_sni}", within(13, 23))
        check("предел 20: только трафик через туннель (hev)", f"{alone_tun}", within(13, 23))
        both = res.get("sni", 0) + res.get("tun", 0)
        check(f"обе дороги сразу: вместе не больше предела ({res})", f"{round(both, 2)}", within(13, 24))
        check("обе дороги сразу: каждой достаётся заметная доля",
              f"{min(res.get('sni', 0), res.get('tun', 0))}", within(4, 20))
        procs["sni"].terminate()
        procs["sni"].wait(5)
        q = tc("class", "show", "dev", "awgq1").stdout
        check("посредник остановлен: туннелю вернулся весь предел", q.strip().replace("\n", " ")[:90],
              lambda g: "rate 20Mbit" in g)
    finally:
        tc("qdisc", "del", "dev", "awgr1", "ingress")
        sh("amz", "ip", "link", "del", "awgq1")


def rule_limits(procs):
    """1.24.0: ограничение скорости правила. Правило по адресам (8.8.4.4, 9.9.9.9 → выход 1) — 10 Мбит/с к клиентам,
    правило по доменам (big.test → SOCKS5) — 6. Один «limit» правила на обе дороги: транзитную (8.8.4.4:5001, ядро)
    и через посредник (9.9.9.9:443 без имени — без совпадения по домену, правило по адресам)."""
    pol = {"rules": [(["via"], 1)], "default": "direct", "domain": [(["dvid"], "up:u1")],
           "slots": [0], "dslots": [1], "lims": [0], "dlims": [1]}
    lim = lambda j: (j + 1) << config.RULE_LIM_SHIFT  # noqa: E731

    def conf(to=None):
        p = sni_conf(pol, to or {"socks": SOCKS, "acct": "u1", "lim": lim(1)})
        cfg = json.load(open(p))
        for v in cfg["policies"].values():
            v["acct"] = {"rules": [[["via"], "u1", 0, lim(0)]], "default": "direct", "slot": config.RULE_DEFAULT_SLOT}
        cfg["cidrs"] = {"via": os.path.join(TMP, "via.cidrs")}
        with open(cfg["cidrs"]["via"], "w") as f:
            f.write("\n".join(IP_LISTS["via"]) + "\n")
        with open(p, "w") as f:
            json.dump(cfg, f)
        return p
    within = lambda lo, hi: (lambda g: lo <= float(g) <= hi)  # noqa: E731
    rules(pol, labels=True, limits={0: (10 * 125_000, 0), 1: (6 * 125_000, 0)})
    procs["sni"] = start_sni(conf())
    try:
        check("ограничение правила по доменам 6: сайт через посредник (SOCKS5)", f"{speed('1.1.1.1', 443, 'big.test')}",
              within(3.3, 7.2))
        check("ограничение правила по адресам 10: транзитом (ядро)", f"{speed('8.8.4.4', 5001, '-')}", within(5.5, 12))
        check("…через посредник (TCP 443 без совпадения по домену)", f"{speed('9.9.9.9', 443, 'raw')}", within(5.5, 12))
        res = {}
        th = [threading.Thread(target=lambda k=k, a=a: res.__setitem__(k, speed(*a, secs=5.0)))
              for k, a in (("sni", ("9.9.9.9", 443, "raw")), ("tun", ("8.8.4.4", 5001, "-")))]
        [t.start() for t in th]
        [t.join() for t in th]
        check(f"обе дороги одного правила сразу: вместе не больше 10 ({res})",
              f"{round(res.get('sni', 0) + res.get('tun', 0), 2)}", within(5.5, 12.5))
        rules(pol, labels=True)
        check("ограничения сняты: снова полная скорость", f"{speed('8.8.4.4', 5001, '-')}", within(30, 1e9))
        # сайт правила на выход-туннель по метке: метка выхода с номером ограничения. С rl_lab — через туннель; набор без
        # неё (как до 1.24.0 или без меток), а посредник ещё с номером в метках сокетов — соединение не проходит, а не
        # уходит мимо выхода по основной таблице
        procs["sni"].terminate()
        procs["sni"].wait(5)
        procs["sni"] = start_sni(conf({"mark": nftgen.mark_for(1), "acct": "u1", "lim": lim(1)}))
        rules(pol, labels=True, limits={1: (6 * 125_000, 0)})
        check("сайт правила с ограничением → выход по метке: в туннеле выхода", hello("8.8.8.8", "foreign.test"), "PROXY")
        rules(pol)
        check("номер в метке сокета без rl_lab: сайт не открывается (не мимо выхода)", hello("8.8.8.8", "foreign.test"),
              lambda g: g in ("EMPTY",) or g.startswith("FAIL"))
    finally:
        procs["sni"].terminate()
        procs["sni"].wait(5)


def dns_filter(procs, pol):
    """«Правила по доменам — только для адресов из ответов этого DNS» (набор dom4 наполняет dnsproxy.py). Д2 независимой
    проверки П31: клиент соединяется сразу после ответа DNS, и первое соединение к новому адресу должно уже быть в наборе
    — иначе оно идёт по правилам адресов и «По умолчанию» («Напрямую»), мимо выхода. Код до исправления —
    P31_DNSPROXY=<другой app/dnsproxy.py> (адрес попадал в набор через ~0,3 с: здесь — DIRECT)."""
    rules(pol, dom_filter=True)
    procs["dns-up"] = bg("inet", sys.executable, SRV, "dns", "172.20.0.2", "foreign.test=8.8.8.8",
                         "www.foreign.test=8.8.8.8", "cdnfoo.test=8.8.4.4", "ru.test=77.88.55.242", log="dns-up")
    policies, _ = nftgen.layout(pol, {}, {1})
    stats = os.path.join(TMP, "dns-stats.json")
    conf = os.path.join(TMP, "dns.json")
    with open(conf, "w") as f:
        json.dump({"listen": "10.8.1.0", "port": 53, "clients": "10.8.1.0/24", "stats": stats,
                   "upstreams": ["172.20.0.2"], "encrypt": "plain", "default": {"mark": 0, "tcp": False},
                   "routes": {}, "dom": {"lists": {"dvid": os.path.join(TMP, "dvid.domains")}, "clients": {},
                                         "set": [config.NFT_TABLE, nftgen.DOM_SET],
                                         "policies": {n: [[["dvid"], {"mark": 0, "tcp": False}]] for n in policies}}},
                  f)
    code = os.environ.get("P31_DNSPROXY") or os.path.join(HERE, "..", "app", "dnsproxy.py")
    procs["dns"] = bg("amz", sys.executable, code, conf, log="dnsproxy")
    time.sleep(1.0)

    def ask(name):
        return sh("cli", sys.executable, "-c", CLIENT_DNS_HELLO, name, "10.8.1.0", timeout=15).stdout.strip()

    def in_set(ip):
        return ip in sh("amz", "nft", "list", "set", "ip", config.NFT_TABLE, nftgen.DOM_SET).stdout

    check("фильтр по DNS: адреса до ответа в наборе нет", str(in_set("8.8.8.8")), "False")
    got = ask("foreign.test")
    check("фильтр по DNS: первое соединение к новому адресу — уже через выход", got, lambda g: g.split()[2:3] == ["PROXY"])
    ms = int(got.split()[1]) if got.count(" ") >= 2 and got.split()[1].isdigit() else -1
    print(f"    ответ DNS на новое имя: {ms} мс")
    check("…ответ DNS на новое имя — быстро (запись в набор, не 0,3 с ожидания)", str(ms), lambda g: 0 <= int(g) < 300)
    check("…адрес правда в наборе", str(in_set("8.8.8.8")), "True")
    check("…имя не из правила — по правилам адресов, как раньше", ask("ru.test"), lambda g: g.split()[2:3] == ["DIRECT"])
    # панель пересобирает таблицу: nft ждёт, ответ — не дольше SET_WAIT (1 с), потом как раньше
    big = os.path.join(TMP, "big.nft")
    with open(big, "w") as f:
        f.write("table ip awgr_big {\n set s {\n  type ipv4_addr\n  elements = { ")
        f.write(", ".join(f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}" for i in range(1, 300001)))
        f.write(" }\n }\n}\n")
    sh("amz", "nft", "flush", "set", "ip", config.NFT_TABLE, nftgen.DOM_SET)
    sh("amz", "nft", "delete", "table", "ip", "awgr_big")
    rebuild = subprocess.Popen(["nsenter", "--net=/var/run/netns/amz", "--", "nft", "-f", big])
    time.sleep(0.3)
    t0 = time.monotonic()
    got = ask("cdnfoo.test")
    dt = time.monotonic() - t0
    rebuild.wait(120)
    print(f"    во время пересборки таблицы (nft -f, 300 000 адресов): ответ и соединение за {dt:.2f} с → {got}")
    check("…во время пересборки таблицы ответ DNS не ждёт nft дольше 1 с", f"{dt:.2f}", lambda g: float(g) < 2.5)
    sh("amz", "nft", "delete", "table", "ip", "awgr_big")
    procs["dns"].terminate()
    procs["dns"].wait(5)
    procs["dns-up"].terminate()
    procs["dns-up"].wait(5)
    rules(pol)


def udp(ip, port=7):
    return sh("cli", sys.executable, "-c", CLIENT_UDP, ip, str(port), timeout=10).stdout.strip()


RESULTS = []


def check(label, got, want):
    ok = (want(got) if callable(want) else got.startswith(want))
    print(f"{'OK ' if ok else 'BAD'} {label:66} → {got}")
    RESULTS.append(ok)


class AmzTarget:
    """Цель «сервер AWG» в сети amz — как system.Target.ns для socks.check_in."""

    def ns(self, cmd, input=None, timeout=30, check=False):
        return subprocess.run(["nsenter", "--net=/var/run/netns/amz", "--", *cmd], input=input,
                              capture_output=True, text=True, timeout=timeout)


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
    print(cpu())
    procs = setup()
    procs["hev"] = start_hev()
    try:
        # ---------------------------------------------------- проверка прокси панелью
        check("socks.check: верный логин", socks_check(PW), "ok")
        check("socks.check: неверный пароль", socks_check("nope"), "socks.auth_failed")
        # 1.22.0: здоровье выхода — из сети сервера AWG (socks.check_in), как ходит hev; из сети машины прокси
        # не виден — так проверяла панель раньше и ошибалась, когда сети сервера и панели видят прокси по-разному
        r = socks.check_in(AmzTarget(), {"host": "proxy.name", "port": 1080, "user": USER, "password": PW},
                           "172.21.0.2")
        check("socks.check_in: из сети сервера AWG прокси работает", "ok" if r["ok"] else r["error"].key, "ok")
        r = socks.check_in(AmzTarget(), {"port": 1080, "user": USER, "password": "nope"}, "172.21.0.2")
        check("socks.check_in: неверный пароль виден и оттуда", r["error"].key if not r["ok"] else "ok",
              "socks.auth_failed")
        r = socks.check({"host": "172.21.0.2", "port": 1080, "user": USER, "password": PW})
        check("…а из сети самой машины этот прокси не виден", "ok" if r["ok"] else r["error"].key, "socks.")

        # ---------------------------------------------------- выход SOCKS5 по адресам
        rules({"rules": [], "default": "direct"}, sniff=False)
        check("без правил: 8.8.8.8 напрямую", tcp("8.8.8.8"), "DIRECT")
        rules({"rules": [], "default": 1}, sniff=False)
        check("основной выход SOCKS5: TCP через прокси", tcp("8.8.8.8"), "PROXY")
        check("основной выход SOCKS5: UDP через прокси (UDP ASSOCIATE)", udp("8.8.8.8"), "PROXY-UDP")
        # 1.21.0: у SOCKS5 без галочки «Пропускать QUIC» UDP 443 — отказ (браузер сразу берёт TCP)
        UPS[0]["no_quic"] = True
        rules({"rules": [], "default": 1}, sniff=False)
        check("SOCKS5 без QUIC: UDP 443 → отказ", udp("8.8.8.8", 443), "FAIL")
        check("SOCKS5 без QUIC: остальной UDP — через прокси", udp("8.8.8.8"), "PROXY-UDP")
        UPS[0].pop("no_quic")

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
        dns_filter(procs, pol)

        # общий предел скорости выхода SOCKS5 для туннеля и посредника
        procs["sni"].terminate()
        procs["sni"].wait(5)
        shared_limit(procs, pol)
        rule_limits(procs)

        # 1.21.0: правила по доменам не работают (посредника нет) и выбран блок — у таких клиентов всё в блок
        rules(pol, sniff=False, strict=True)
        check("правила по доменам не работают, «блокировать»: TCP → отказ", tcp("77.88.55.242"), "FAIL")
        check("правила по доменам не работают, «блокировать»: UDP → отказ", udp("8.8.8.8"), "FAIL")
        rules(pol, sniff=False)
        check("без галочки: сайт по правилу по адресам и основному пути", tcp("77.88.55.242"), "DIRECT")
        rules(pol)

        # резервный путь вместо прокси: соединение по совпавшему домену — с меткой (напрямую)
        procs["sni"].terminate()
        procs["sni"].wait(5)
        procs["sni"] = start_sni(sni_conf(pol, {"mark": 0}))
        check("выход не работает → его резервный путь (напрямую)", hello("8.8.8.8", "foreign.test"), "DIRECT")
        procs["sni"].terminate()
        procs["sni"].wait(5)
        procs["sni"] = start_sni(sni_conf(pol, {"block": True}))
        check("резерв «блок» → соединение закрыто", hello("8.8.8.8", "foreign.test"), lambda g: g in ("EMPTY",) or g.startswith("FAIL"))

        # 1.21.0: QUIC по имени — первые пакеты из очереди ядра, решение в conntrack
        if not quic_ok():
            print("SKIP QUIC по имени: ядро не принимает очередь в nftables (nft_queue)")
        else:
            procs["sni"].terminate()
            procs["sni"].wait(5)
            qpol = {"rules": [], "default": 1, "domain": [(["dq"], "direct")]}
            rules(qpol, quic=True)
            procs["sni"] = start_sni(sni_conf(qpol, {"mark": 0}, qmark=config.QUIC_DIRECT_MARK))
            check("QUIC: сайт из правила «напрямую» (основной выход — SOCKS5)", quic("8.8.8.8"), "DIRECT-UDP")
            check("QUIC v2: то же", quic("8.8.8.8", QUIC_V2), "DIRECT-UDP")
            check("QUIC: дальше пакеты соединения — тем же путём (conntrack)",
                  quic("8.8.8.8", extra=True), lambda g: g == "DIRECT-UDP DIRECT-UDP")
            check("QUIC: ClientHello не собрался (один пакет из двух) → отказ, браузер уйдёт на TCP",
                  quic("8.8.8.8", count=1), "FAIL")
            # первый байт 0x16 (как у DTLS): без бита «фиксированный» — не QUIC
            check("не QUIC на UDP 443 → обычные правила (основной выход SOCKS5)", sh("cli", sys.executable, "-c",
                  CLIENT_UDP.replace('b"x"', 'b"\\x16dtls"'), "8.8.8.8", "443", timeout=10).stdout.strip(), "PROXY-UDP")
            check("короткий заголовок QUIC без решения → отказ", sh("cli", sys.executable, "-c", CLIENT_UDP.replace(
                'b"x"', 'bytes([0x41])+bytes(40)'), "8.8.8.8", "443", timeout=10).stdout.strip(), "FAIL")
            procs["sni"].terminate()
            procs["sni"].wait(5)
            qpol = {"rules": [], "default": "direct", "domain": [(["dq"], "up:u1")]}
            rules(qpol, quic=True)
            procs["sni"] = start_sni(sni_conf(qpol, {"mark": nftgen.mark_for(1)}, qmark=nftgen.mark_for(1)))
            check("QUIC: сайт из правила → выход-туннель по метке (AWG; SOCKS5 с «Пропускать QUIC» — через UDP ASSOCIATE)",
                  quic("8.8.8.8"), "PROXY-UDP")
            # 1.24.0: номер правила в вердикте QUIC (биты QUIC_SLOT_MASK): q_lab ставит метку соединения и снимает биты
            # до маршрутизации — путь тот же, а таблица учёта по правилам видит трафик правила
            nft("amz", nftgen.racct_ruleset("awg0", [0, config.RULE_DEFAULT_SLOT]))
            qlp = {**qpol, "slots": [], "dslots": [0]}
            bits = 1 << config.QUIC_SLOT_SHIFT
            for want, qm in (("PROXY-UDP", nftgen.mark_for(1)), ("DIRECT-UDP", config.QUIC_DIRECT_MARK)):
                procs["sni"].terminate()
                procs["sni"].wait(5)
                rules(qlp, quic=True, labels=True)
                procs["sni"] = start_sni(sni_conf(qlp, {"mark": nftgen.mark_for(1)}, qmark=qm | bits))
                before = racct().get(("10.8.1.2", 0), [0, 0])
                check(f"QUIC с номером правила в вердикте: тот же путь ({want}), и после ответа сервера",
                      quic("8.8.8.8", extra=True), lambda g, w=want: g == f"{w} {w}")
                after = racct().get(("10.8.1.2", 0), [0, 0])
                check("QUIC с номером правила: учёт видит правило в обе стороны",
                      f"{after[0] > before[0]} {after[1] > before[1]}", "True True")
            procs["sni"].terminate()
            procs["sni"].wait(5)
            rules(qpol, quic=True)
            procs["sni"] = start_sni(sni_conf(qpol, {"socks": SOCKS}, qmark=config.MARK_BLOCK))
            check("QUIC: сайт из правила на SOCKS5 → отказ (HTTPS через прокси по имени)", quic("8.8.8.8"), "FAIL")
            procs["sni"].terminate()
            procs["sni"].wait(5)
            procs["sni"] = start_sni(sni_conf({"rules": [], "default": "direct", "domain": [(["dvid"], "up:u1")]},
                                              {"mark": nftgen.mark_for(1)}, qmark=nftgen.mark_for(1)))
            rules({"rules": [], "default": "direct", "domain": [(["dvid"], "up:u1")]}, quic=True)
            check("QUIC: сайт не из правила → обычные правила, HTTP/3 работает", quic("8.8.8.8"), "DIRECT-UDP")
            check("QUIC: сайт не из правила — и после ответа сервера (conntrack)",
                  quic("8.8.8.8", extra=True), lambda g: g == "DIRECT-UDP DIRECT-UDP")
            # балансировка: «пропустить» ведёт в выход Sticky, и решение остаётся в conntrack
            rules({"rules": [], "default": nftgen.Sticky(1), "domain": [(["dvid"], "direct")]}, quic=True,
                  balance={1})
            check("QUIC: сайт не из правила, основной выход с балансировкой — и после ответа сервера",
                  quic("8.8.8.8", extra=True), lambda g: g == "PROXY-UDP PROXY-UDP")
            rules({"rules": [], "default": "direct", "domain": [(["dvid"], "up:u1")]}, quic=True)
            procs["sni"].terminate()
            procs["sni"].wait(5)
            check("QUIC: обработчик не работает (очередь без слушателя) → отказ, как без очереди",
                  quic("8.8.8.8"), "FAIL")
            procs["sni"] = start_sni(sni_conf(pol, {"block": True}))
            rules(pol)

        # 1.21.0: домен на выход-туннель (так идёт выход AWG): к исходному адресу с меткой выхода,
        # через его таблицу маршрутизации и интерфейс awgr1, а не командой CONNECT по имени
        procs["sni"].terminate()
        procs["sni"].wait(5)
        procs["sni"] = start_sni(sni_conf(pol, {"mark": nftgen.mark_for(1), "acct": "u1"}))
        check("домен → выход по метке: соединение в туннеле выхода", hello("8.8.8.8", "foreign.test"), "PROXY")
        check("…к адресу из DNS клиента: подменённый адрес не исправляется",
              hello("192.0.2.1", "foreign.test"), lambda g: g != "PROXY")
        check("…домен не из списка — по-прежнему напрямую", hello("77.88.55.242", "ru.test"), "DIRECT")

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
