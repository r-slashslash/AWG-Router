"""Исходящие адреса сервера (1.25.0) в сетевых пространствах: «Напрямую — адрес», защита, выходы с адреса.

   cli ──(awg0)── srv ──(eth0: 172.20.0.2 — адрес системы, 172.20.0.7 — второй)── inet (172.20.0.1, шлюз)
                                                                                    «сайт» 8.8.8.8, 77.88.55.242
                                                                                    выход AWG :51820, SOCKS5 :1080
В srv — те же правила nftables, ip rule и маршруты, что ставит панель «на хосте» (nftgen.generate с addrs,
Engine._sync_addr_routes), и MASQUERADE клиентов, как у сервера на хосте (awg-quick PostUp, iptables, srcnat).
Сайт отвечает «SITE from <адрес отправителя>» — так видно, с какого адреса сервера ушло соединение.

Проверки: «Напрямую — адрес» и «Напрямую» (адрес системы) рядом, правило по адресам на второй адрес; адрес пропал
— блок, а не адрес системы; свои соединения сервера с меткой адреса (посредник, DNS на сервере, проверки) и с битами
номера ограничения скорости (rl_lab); метка номера адреса без пути — никуда; чужая метка (0x40000, Tailscale) не
мешает; выход AWG (amneziawg-go, FwMark) и SOCKS5 (hev-socks5-tunnel, mark) подключаются со второго адреса.

Нужны root, nft, iproute2, pyroute2; для выходов — awg, amneziawg-go, hev-socks5-tunnel в PATH.
Запуск: sudo env PATH=<bin>:$PATH PYTHONPATH=<pyroute2>:. python3 tests/addrs_e2e.py
"""
import os
import subprocess
import sys
import tempfile
import time

from pyroute2 import IPRoute, NetNS, netns

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import awgconf, config, nftgen, socks  # noqa: E402
from app.engine import Engine  # noqa: E402

NS = ["acli", "asrv", "ainet"]
SYS, SECOND, GW = "172.20.0.2", "172.20.0.7", "172.20.0.1"
SITE, RU = "8.8.8.8", "77.88.55.242"
HERE = os.path.dirname(os.path.abspath(__file__))
SERVERS = os.path.join(HERE, "e2e_servers.py")
CLIENT = r"""
import socket,sys
s=socket.socket(); s.settimeout(3)
if len(sys.argv) > 2 and int(sys.argv[2], 0): s.setsockopt(socket.SOL_SOCKET, 36, int(sys.argv[2], 0))
try:
    s.connect((sys.argv[1],80)); print(s.recv(100).decode())
except OSError as e: print("FAIL", type(e).__name__, e.errno)
"""
INFRA = {1: {"ip": SECOND, "dev": "eth0", "gw": GW, "nat": "snat"}}
ECHO = r"""
import socket,threading
def h(c,a):
    try:
        while True:
            d=c.recv(100)
            if not d: break
            c.sendall(d+b" from "+a[0].encode()+b"\n")
    except OSError: pass
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",7000)); s.listen(16)
while True:
    c,a=s.accept(); threading.Thread(target=h,args=(c,a),daemon=True).start()
"""
HOLD = r"""
import socket,sys,time
s=socket.create_connection((sys.argv[1],7000),timeout=3); s.settimeout(3)
out=open(sys.argv[2],"w",buffering=1)
while True:
    try:
        s.sendall(b"ping"); d=s.recv(100)
        out.write((d.decode().strip() if d else "CLOSED")+"\n")
        if not d: break
    except OSError as e:
        out.write("ERR "+str(e.errno)+"\n"); break
    time.sleep(0.3)
"""
results = []
procs = []


def sh(ns, *cmd, check=False, **kw):
    p = subprocess.run(["nsenter", f"--net=/var/run/netns/{ns}", "--", *cmd], capture_output=True, text=True, **kw)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {p.stderr or p.stdout}")
    return p


def bg(ns, *cmd, env=None):
    p = subprocess.Popen(["nsenter", f"--net=/var/run/netns/{ns}", "--", *cmd], env={**os.environ, **(env or {})},
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p)
    return p


def nft(ns, text):
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
        f.write(text)
    p = sh(ns, "nft", "-f", f.name)
    assert p.returncode == 0, p.stderr


class SrvTarget:
    """Цель «на хосте» для Engine._sync_addr_routes: команды — в сети srv."""
    kind, key, iface, exists = "host", "host:e2e", "awg0", True

    def ns(self, cmd, **kw):
        kw.pop("check", None)
        return sh("asrv", *cmd, **kw)


def check(label, ok, got=""):
    print(f"{'OK ' if ok else 'BAD'} {label:66} {got}")
    results.append(bool(ok))
    return ok


def probe(dst=SITE, ns="acli", mark=0):
    return sh(ns, sys.executable, "-c", CLIENT, dst, str(mark), timeout=10).stdout.strip()


def expect(label, want, dst=SITE, ns="acli", mark=0):
    got = probe(dst, ns, mark)
    return check(label, got.startswith(want), got)


def setup():
    for n in NS:
        if n in netns.listnetns():
            netns.remove(n)
        netns.create(n)
    with IPRoute() as ip:
        for a, b in (("c0", "awg0"), ("eth0", "i0")):
            ip.link("add", ifname="t_" + a, kind="veth", peer="t_" + b)
        moves = {"c0": "acli", "awg0": "asrv", "eth0": "asrv", "i0": "ainet"}
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
                ip.addr("add", index=ip.link_lookup(ifname=ifn)[0], address=a, prefixlen=p)
            for r in routes:
                ip.route("add", **r)
    conf("acli", [("c0", "10.8.1.2", 24)], [dict(dst="0.0.0.0/0", gateway="10.8.1.1")])
    conf("asrv", [("awg0", "10.8.1.1", 24), ("eth0", SYS, 24)], [dict(dst="0.0.0.0/0", gateway=GW)])
    conf("ainet", [("i0", GW, 24)])
    with NetNS("ainet") as ip:
        lo = ip.link_lookup(ifname="lo")[0]
        for a in (SITE, RU):
            ip.addr("add", index=lo, address=a, prefixlen=32)
    sh("asrv", "sysctl", "-qw", "net.ipv4.ip_forward=1")
    sh("asrv", "sysctl", "-qw", "net.ipv4.conf.all.src_valid_mark=1")
    # как у сервера на хосте: MASQUERADE клиентов в PostUp (iptables, приоритет srcnat)
    nft("asrv", "table ip awgq {\n chain post {\n  type nat hook postrouting priority 100;\n"
                '  oifname "eth0" ip saddr 10.8.1.0/24 masquerade\n }\n}\n')
    bg("ainet", sys.executable, SERVERS, "http", "SITE", SITE, RU, GW)
    time.sleep(0.5)


def add_second():
    """Второй адрес — так, как его добавляет панель (AddrsMixin._addr_add): /32 на интерфейсе маршрута по умолчанию."""
    sh("asrv", "ip", "addr", "add", f"{SECOND}/32", "dev", "eth0", "label", "eth0:awgr", check=True)


def apply(gp, cps=None, ups=(), labels=False, infra=INFRA):
    """То, что делает проход движка «на хосте»: пути адресов (ip rule, таблицы), затем правила nftables."""
    eng = Engine.__new__(Engine)
    eng._sync_addr_routes(SrvTarget(), {SECOND: 1}, infra, add_only=True)
    eng._addr_routes = None
    nft("asrv", nftgen.generate("awg0", {"ru": ["77.88.0.0/18"]}, list(ups), gp, cps or {}, None, labels=labels,
                                addrs=infra))


def main():
    setup()
    add_second()
    try:
        a = nftgen.Addr(SECOND, 1)
        apply({"rules": [], "default": a})
        expect("«Напрямую — 172.20.0.7»: сайт видит второй адрес", f"SITE from {SECOND}")
        apply({"rules": [], "default": "direct"})
        expect("«Напрямую» (адрес системы): сайт видит адрес системы", f"SITE from {SYS}")
        apply({"rules": [(["ru"], a)], "default": "direct"})
        expect("правило RU → второй адрес: RU с него", f"SITE from {SECOND}", dst=RU)
        expect("правило RU → второй адрес: остальное — с адреса системы", f"SITE from {SYS}")
        # свои соединения сервера с меткой адреса: посредник правил по доменам, DNS на сервере, проверка probe.py
        expect("своё соединение сервера с меткой адреса — со второго адреса", f"SITE from {SECOND}", ns="asrv",
               mark=nftgen.addr_mark(1))
        expect("своё соединение без метки — с адреса системы", f"SITE from {SYS}", ns="asrv")
        expect("метка номера адреса без пути (0x2105) — никуда, не с адреса системы", "FAIL", ns="asrv",
               mark=nftgen.addr_mark(5))
        # сокет посредника с номером ограничения скорости правила: rl_lab снимает биты (адреса — метки панели)
        apply({"rules": [], "default": a, "slots": [], "dslots": []}, labels=True)
        expect("сокет посредника: метка адреса и номер ограничения — со второго адреса", f"SITE from {SECOND}",
               ns="asrv", mark=nftgen.addr_mark(1) | (1 << config.RULE_LIM_SHIFT))
        # чужая метка на пересылке (Tailscale на сервере «на хосте»): «Напрямую» без адреса — как было; пакет с меткой
        # адреса и чужими битами (защита видит метку панели с лишними битами) — не уходит с адреса системы
        nft("asrv", "table ip ts {\n chain f {\n  type filter hook forward priority 10; policy accept;\n"
                    '  iifname "awg0" meta mark set meta mark or 0x40000\n }\n}\n')
        apply({"rules": [], "default": "direct"})
        expect("чужая метка 0x40000 на пересылке — «Напрямую» как было", f"SITE from {SYS}")
        apply({"rules": [], "default": a})
        got = probe()
        check("чужие биты на пакете «Напрямую — адрес» — не с адреса системы", got != f"SITE from {SYS}", got)
        sh("asrv", "nft", "delete", "table", "ip", "ts")
        # адрес пропал (перезапустили сеть системы, убрали руками): до реакции панели — не с адреса системы (пересылка
        # ещё с подменой на него: хостинг доставит ответ, только если адрес по-прежнему его), свои соединения — никуда
        sh("asrv", "ip", "addr", "del", f"{SECOND}/32", "dev", "eth0", check=True)
        got = probe()
        check("адрес пропал до реакции панели: не с адреса системы", got != f"SITE from {SYS}", got)
        expect("адрес пропал: своё соединение с меткой адреса — тоже никуда", "FAIL", ns="asrv",
               mark=nftgen.addr_mark(1))
        apply({"rules": [], "default": "block"}, infra={})      # панель заметила: адрес не работает → блок
        expect("панель заметила: блок", "FAIL")
        add_second()
        apply({"rules": [], "default": a})
        expect("адрес вернулся (панель добавила снова): снова с него", f"SITE from {SECOND}")
        manual_change(a)
        exits()
    finally:
        for p in procs:
            p.kill()
        for n in NS:
            if n in netns.listnetns():
                netns.remove(n)
    print(f"\n{sum(results)}/{len(results)} проверок пройдено")
    sys.exit(0 if all(results) else 1)


def last(path):
    with open(path) as f:
        lines = f.read().split()
    return " ".join(lines[-4:])


def manual_change(a):
    """Ручная смена «По умолчанию» (адрес системы → второй адрес): открытое соединение этого пути обрывается и новое
    идёт новым путём; соединение правила RU, которое не меняли, — живёт (ctflush.py, как Engine._run_drops)."""
    bg("ainet", sys.executable, "-c", ECHO)
    time.sleep(0.5)
    old = {"rules": [[["ru"], "direct@" + SECOND]], "default": "direct@system"}
    new = {"rules": [[["ru"], "direct@" + SECOND]], "default": "direct@" + SECOND}
    apply({"rules": [(["ru"], a)], "default": "direct"})
    f_site, f_ru = tempfile.mktemp(), tempfile.mktemp()
    bg("acli", sys.executable, "-c", HOLD, SITE, f_site)
    bg("acli", sys.executable, "-c", HOLD, RU, f_ru)
    time.sleep(1.5)
    check("до смены: соединение «По умолчанию» — с адреса системы", f"from {SYS}" in last(f_site), last(f_site))
    check("до смены: соединение правила RU — со второго адреса", f"from {SECOND}" in last(f_ru), last(f_ru))
    apply({"rules": [(["ru"], a)], "default": a})
    job = {"clients": {"10.8.1.2": {"old": old, "new": new}}, "lists": {"ru": ["77.88.0.0/18"]},
           "skip": nftgen.LOCAL_NETS, "quic": []}
    import json
    r = sh("asrv", sys.executable, os.path.join(HERE, "..", "app", "ctflush.py"), input=json.dumps(job), timeout=30)
    try:
        n = json.loads(r.stdout or "{}").get("deleted", 0)
    except ValueError:
        n = 0
    check("ctflush удалил записи изменившегося пути", n >= 1, (r.stdout or r.stderr).strip())
    time.sleep(1.5)
    check("после смены: соединение «По умолчанию» оборвано (приложение откроет новое)",
          last(f_site).split()[-1:] != [SYS] and ("ERR" in last(f_site) or "CLOSED" in last(f_site)), last(f_site))
    check("после смены: соединение правила RU, которое не меняли, живёт", last(f_ru).endswith(SECOND), last(f_ru))
    expect("после смены: новое соединение — новым путём", f"SITE from {SECOND}")


def exits():
    """Выход AWG (FwMark) и SOCKS5 (mark у hev и у проверки прокси) подключаются со второго адреса."""
    have = {b: subprocess.run(["sh", "-c", f"command -v {b}"], capture_output=True).returncode == 0
            for b in ("awg", "amneziawg-go", "hev-socks5-tunnel")}
    if have["awg"] and have["amneziawg-go"]:
        exit_awg()
    else:
        print("-- выход AWG: нет awg / amneziawg-go в PATH — пропуск")
    if have["hev-socks5-tunnel"]:
        exit_socks()
    else:
        print("-- выход SOCKS5: нет hev-socks5-tunnel в PATH — пропуск")


def awg(*args, inp=None):
    return subprocess.run(["awg", *args], input=inp, capture_output=True, text=True, check=True).stdout.strip()


def up_go(ns, ifn, conf, addr):
    log = open(f"/tmp/{ifn}.log", "w")
    procs.append(subprocess.Popen(["nsenter", f"--net=/var/run/netns/{ns}", "--", "amneziawg-go", "-f", ifn],
                                  stdout=log, stderr=log))
    for _ in range(50):
        if os.path.exists(f"/var/run/amneziawg/{ifn}.sock"):
            break
        time.sleep(0.1)
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write(conf)
    sh(ns, "awg", "setconf", ifn, f.name, check=True)
    sh(ns, "ip", "addr", "add", addr, "dev", ifn, check=True)
    sh(ns, "ip", "link", "set", ifn, "up", check=True)


def exit_awg():
    """Выход AWG: внешний сервер в inet; туннель панели awgr1 с FwMark второго адреса (как _start_up)."""
    spriv, spub = (k := awg("genkey")), awg("pubkey", inp=k + "\n")
    cpriv, cpub = (k := awg("genkey")), awg("pubkey", inp=k + "\n")
    up_go("ainet", "awgs", f"[Interface]\nPrivateKey = {spriv}\nListenPort = 51820\n\n"
                           f"[Peer]\nPublicKey = {cpub}\nAllowedIPs = 10.99.0.2/32\n", "10.99.0.1/24")
    sh("ainet", "sysctl", "-qw", "net.ipv4.ip_forward=1")
    setconf = awgconf.with_fwmark(f"[Interface]\nPrivateKey = {cpriv}\n\n[Peer]\nPublicKey = {spub}\n"
                                  f"Endpoint = {GW}:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 1\n",
                                  nftgen.addr_mark(1))
    check("setconf выхода с FwMark второго адреса", f"FwMark = {nftgen.addr_mark(1):#x}" in setconf)
    up_go("asrv", "awgr1", setconf, "169.254.200.1/32")
    with NetNS("asrv") as ip:
        t = config.TABLE_BASE + 1
        ip.rule("add", fwmark=nftgen.mark_for(1), table=t, priority=config.RULE_PRIO_BASE + 1)
        ip.route("replace", dst="0.0.0.0/0", oif=ip.link_lookup(ifname="awgr1")[0], table=t)
    apply({"rules": [], "default": 1}, ups=[{"num": 1, "snat": "10.99.0.2", "mtu": 1280}])
    time.sleep(2)
    ep = sh("ainet", "awg", "show", "awgs", "endpoints").stdout
    check("выход AWG подключается со второго адреса (так его видит сервер выхода)", f"{SECOND}:" in ep, ep.strip())
    expect("клиент через выход AWG (с адреса туннеля)", "SITE from 10.99.0.2")
    sh("asrv", "ip", "link", "del", "awgr1")
    sh("ainet", "ip", "link", "del", "awgs")


def exit_socks():
    """Выход SOCKS5: hev-socks5-tunnel с mark второго адреса (как _start_socks) и проверка прокси с той же меткой."""
    peers = tempfile.mktemp()
    bg("ainet", sys.executable, SERVERS, "socks", GW, "1080", env={"AWGR_PEERS": peers})
    time.sleep(0.5)
    mark = nftgen.addr_mark(1)
    r = sh("asrv", sys.executable, "-c", "import sys,json;sys.path.insert(0,sys.argv[1]);from app import socks;"
           f"print(json.dumps(socks.check({{'host':'{GW}','port':1080,'mark':{mark}}})))",
           os.path.join(HERE, ".."), timeout=30).stdout
    check("проверка прокси с меткой адреса прошла", '"ok": true' in r, r.strip()[:80])
    with open(peers) as f:
        seen = f.read().split()
    check("проверка прокси подключается со второго адреса", seen[-1:] == [SECOND], " ".join(seen))
    conf = tempfile.mktemp(suffix=".yml")
    with open(conf, "w") as f:
        f.write(socks.hev_config("awgr2", 2, GW, {"port": 1080}, mark=mark))
    bg("asrv", "hev-socks5-tunnel", conf)
    for _ in range(50):
        if sh("asrv", "ip", "link", "show", "awgr2").returncode == 0:
            break
        time.sleep(0.1)
    sh("asrv", "ip", "addr", "replace", "169.254.200.2/32", "dev", "awgr2")
    sh("asrv", "ip", "link", "set", "awgr2", "up")
    sh("asrv", "sysctl", "-qw", "net.ipv4.conf.awgr2.rp_filter=2")
    with NetNS("asrv") as ip:
        t = config.TABLE_BASE + 2
        ip.rule("add", fwmark=nftgen.mark_for(2), table=t, priority=config.RULE_PRIO_BASE + 2)
        ip.route("replace", dst="0.0.0.0/0", oif=ip.link_lookup(ifname="awgr2")[0], table=t)
    apply({"rules": [], "default": 2}, ups=[{"num": 2, "snat": None, "mtu": 8500}])
    expect("клиент через выход SOCKS5 (ответ пришёл через прокси)", f"SITE from {SITE}")    # прокси — у «сайта»
    with open(peers) as f:
        seen = f.read().split()
    check("hev подключается к прокси со второго адреса", seen[-1:] == [SECOND], " ".join(seen[-3:]))


if __name__ == "__main__":
    main()
