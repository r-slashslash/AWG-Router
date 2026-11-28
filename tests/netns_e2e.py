"""Сквозная проверка схемы маршрутизации в сетевых пространствах (нужен root, nft, pyroute2).

   cli ──(awg0)── amz ──(eth0)── inet      «интернет напрямую»  → отвечает DIRECT
                   └──(awgr1)── up1        «выходной сервер»     → отвечает UP1

В amz применяются ровно те правила nftables, ip rule и маршруты, что создаёт панель.
Туннель AWG заменён veth — для маршрутизации разницы нет.
Запуск: PYTHONPATH=<pyroute2>:. python3 tests/netns_e2e.py
"""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

from pyroute2 import IPRoute, NetNS, netns

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import config, nftgen, web  # noqa: E402

NS = ["cli", "amz", "inet", "up1"]
TARGETS = {"foreign": "8.8.8.8", "russian": "77.88.55.242", "metadata": "169.254.169.254"}
SERVER = r"""
import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",80)); s.listen(16)
while True:
    c,a=s.accept(); c.sendall((sys.argv[1]+" from "+a[0]).encode()); c.close()
"""
# DNS (UDP и TCP 53): отвечает своим именем и адресом спросившего — видно, кто ответил (П5 полной проверки 1.25.0)
# UDP — на самом адресе сайта: сокет на 0.0.0.0 ответил бы с адреса интерфейса (172.20.0.1), и ответ не нашёл бы
# своего соединения в conntrack сервера
DNS_SERVER = r"""
import socket,sys,threading
def udp(addr):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((addr,53))
    while True:
        d,a=s.recvfrom(512); s.sendto((sys.argv[1]+" from "+a[0]).encode(),a)
def tcp(addr):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((addr,53)); s.listen(16)
    while True:
        c,a=s.accept(); c.sendall((sys.argv[1]+" from "+a[0]).encode()); c.close()
for addr in sys.argv[2].split(","):
    threading.Thread(target=udp,args=(addr,),daemon=True).start()
    threading.Thread(target=tcp,args=(addr,),daemon=True).start()
threading.Event().wait()
"""
DNS_CLIENT = r"""
import socket,sys
kind, dst = sys.argv[1], sys.argv[2]
try:
    if kind == "udp":
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.bind(("10.8.1.2",0))
        s.sendto(b"q",(dst,53)); print(s.recv(100).decode())
    else:
        s=socket.socket(); s.settimeout(2); s.bind(("10.8.1.2",0)); s.connect((dst,53)); print(s.recv(100).decode())
except OSError as e: print("FAIL", type(e).__name__)
"""
# П31 полной проверки 1.25.0: DoH и запасной DNS «в интернете» (inet). DoH — 8.8.8.8 (имя dns.google, свой сертификат),
# на имена из argv[3] отвечает через 7 с; запасной — обычный DNS 77.88.55.242 на том же порту. Печатает порт, в файл
# argv[4] пишет, сколько рукопожатий TLS прошло (видно, что «замерзание» — после рукопожатия, а не на нём).
DOH_SERVER = r"""
import os,sys,time
sys.path.insert(0, os.getcwd())
from tests.test_doh_http import H2Server, PlainServer
s = H2Server(sys.argv[1], sys.argv[2], "8.8.8.8")
s.slow = {n: 7.0 for n in sys.argv[3].split(",") if n}
PlainServer("77.88.55.242", s.port, "203.0.113.77")
print(s.port, flush=True)
while True:
    with open(sys.argv[4] + ".tmp", "w") as f:
        f.write(str(s.conns))
    os.replace(sys.argv[4] + ".tmp", sys.argv[4])
    time.sleep(0.1)
"""
# запросы к dnsproxy.py в amz по очереди: кто ответил (shared — DoH, fb — запасной, SF — SERVFAIL) и за сколько
DNS_ASK = r"""
import json,os,socket,struct,sys,time
out = []
for name in sys.argv[2].split(","):
    q = struct.pack("!6H", 7, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) \
        + b"\0\0\1\0\1"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(25); s.bind(("10.8.1.1", 0))
    t0 = time.monotonic(); s.sendto(q, ("10.8.1.1", int(sys.argv[1])))
    try:
        r = s.recv(4096)
        who = "SF" if r[3] & 0xF == 2 else "shared" if socket.inet_aton("203.0.113.9") in r else \
            "fb" if socket.inet_aton("203.0.113.77") in r else "rc%d" % (r[3] & 0xF)
    except OSError:
        who = "TIMEOUT"
    out.append([who, round(time.monotonic() - t0, 3)])
print(json.dumps(out))
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
        # Обратный путь к адресу туннеля в amz. Настоящему туннелю AWG он не нужен (там нет ARP), а veth,
        # которым туннель здесь заменён, нужен: без него up1 не отвечал на ARP от 169.254.200.1 (так было
        # на машинах GitHub, ядро 7.0), и пакеты в выход падали с «host unreachable».
        ip.route("add", dst="169.254.200.1/32", oif=u0)
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
    for ns, name, addr in (("inet", "DNS-INET", "8.8.8.8"), ("up1", "DNS-UP1", "8.8.8.8"), ("amz", "DNS-PANEL", "10.8.1.1")):
        procs.append(subprocess.Popen(["nsenter", f"--net=/var/run/netns/{ns}", "--",
                                       sys.executable, "-c", DNS_SERVER, name, addr]))
    time.sleep(0.5)
    return procs


def nft(ns, text):
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
        f.write(text)
    p = sh(ns, "nft", "-f", f.name)
    assert p.returncode == 0, p.stderr


def panel_apply(global_policy, clients, upstream_alive=True, labels=False, balance=frozenset(), dns_to=None):
    """То, что делает engine.reconcile() внутри контейнера Amnezia. labels — учёт трафика по правилам (1.24.0)."""
    for k in ("all", "default", "awgr1"):
        sysctl("amz", f"net.ipv4.conf.{k}.rp_filter", 2)
    ups = [{"num": 1, "snat": "10.8.1.3", "mtu": 1280}] if upstream_alive else []
    nft("amz", nftgen.generate("awg0", {"ru": ["77.88.0.0/18", "5.3.0.0/16"]}, ups,
                               global_policy, clients, balance, labels=labels, dns_to=dns_to))
    with NetNS("amz") as ip:
        table = config.TABLE_BASE + 1
        if not ip.get_rules(priority=config.RULE_PRIO_BASE + 1):
            ip.rule("add", fwmark=nftgen.mark_for(1), table=table, priority=config.RULE_PRIO_BASE + 1)
        ip.route("replace", dst="0.0.0.0/0", type="unreachable", table=table, priority=4096)
        idx = ip.link_lookup(ifname="awgr1")
        if idx:
            try:
                ip.route("replace", dst="0.0.0.0/0", oif=idx[0], table=table)
            except Exception as e:  # интерфейс лежит — панель тоже игнорирует (check=False)
                if upstream_alive:  # а когда выход жив, это ошибка самого теста: не прятать её
                    raise RuntimeError(f"route to awgr1 in table {table}: {e!r}") from e


def acct():
    """Счётчики таблицы учёта трафика по выходам в amz."""
    p = sh("amz", "nft", "-j", "list", "table", "ip", nftgen.ACCT_TABLE)
    assert p.returncode == 0, p.stderr
    return nftgen.parse_acct(json.loads(p.stdout), "awg0")


def racct():
    """Счётчики таблицы учёта трафика по правилам в amz (1.24.0)."""
    p = sh("amz", "nft", "-j", "list", "table", "ip", nftgen.RACCT_TABLE)
    assert p.returncode == 0, p.stderr
    return nftgen.parse_racct(json.loads(p.stdout), "awg0")


def check(label, ok):
    print(f"{'OK ' if ok else 'BAD'} {label}")
    return ok


def probe(target, src="10.8.1.2"):
    return sh("cli", sys.executable, "-c", CLIENT, TARGETS[target], src, timeout=10).stdout.strip()


def expect_dns(label, kind, dst, want):
    got = sh("cli", sys.executable, "-c", DNS_CLIENT, kind, dst, timeout=10).stdout.strip()
    ok = got.startswith(want)
    print(f"{'OK ' if ok else 'BAD'} {label:58} {kind} {dst} → {got}")
    return ok


def expect(label, target, want, src="10.8.1.2"):
    got = probe(target, src)
    ok = got.startswith(want)
    print(f"{'OK ' if ok else 'BAD'} {label:58} {target:8} → {got}")
    return ok


def panel_dual_stack():
    """Панель слушает «все адреса» одним сокетом IPv6 и отвечает и по IPv4, и по IPv6 (issue #20).
    Здесь, а не в юнит-тестах: юнит-тесты на ветке идут и там, где IPv6 в ядре нет."""
    app = web.App()

    @app.get("/ping")
    def ping(req):
        return {"ip": req.client_ip}

    srv = app.serve("0.0.0.0", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def get(host):
        try:
            c = http.client.HTTPConnection(host, srv.server_address[1], timeout=5)
            c.request("GET", "/ping")
            return json.loads(c.getresponse().read())["ip"]
        except OSError as e:
            return f"FAIL {e}"
    try:
        v4, v6 = get("127.0.0.1"), get("::1")
        return [check("панель: один сокет IPv6 на все адреса", srv.address_family == socket.AF_INET6),
                check(f"панель по IPv4: {v4}", v4 == "127.0.0.1"),
                check(f"панель по IPv6, адрес сетью /64: {v6}", v6 == "::/64")]
    finally:
        srv.shutdown()
        srv.server_close()


def dns_fallback():
    """П31 полной проверки 1.25.0: запасной DNS «Напрямую» на настоящих сокетах и сроках, блокировки — правилами nftables
    «в интернете» (inet): dnsproxy.py в amz, DoH 8.8.8.8 и запасной 77.88.55.242 в inet. Одно медленное имя — следующие
    имена у DoH (не у запасного); настоящая блокировка (SYN, RST после ClientHello, ClientHello, «замерзание» после
    рукопожатия) — первое имя у запасного за один срок ответа, следующие сразу. P31_DNSPROXY — dnsproxy.py другого кода
    (сравнить до и после); печатает время каждого имени."""
    from tests.test_doh_http import cert
    d = tempfile.mkdtemp()
    crt, key = cert(d, "dns.google")
    conns = os.path.join(d, "conns")
    srv = subprocess.Popen(["nsenter", "--net=/var/run/netns/inet", "--", sys.executable, "-c", DOH_SERVER, crt, key,
                            "slow.example.", conns], stdout=subprocess.PIPE, text=True)
    port = int(srv.stdout.readline())

    def handshakes():
        time.sleep(0.3)
        with open(conns) as f:
            return int(f.read() or 0)
    proxy_py = os.environ.get("P31_DNSPROXY") or os.path.join(os.path.dirname(__file__), "..", "app", "dnsproxy.py")
    results = []

    def start():
        conf = os.path.join(d, "dns.json")
        with open(conf, "w") as f:
            json.dump({"listen": "10.8.1.1", "port": 5300, "clients": "10.8.1.0/24", "upstreams": ["8.8.8.8"],
                       "encrypt": "doh", "direct_fallback": ["77.88.55.242"], "default": {"mark": 0, "tcp": False},
                       "routes": {}, "ca_file": crt, "upstream_port": port}, f)
        p = subprocess.Popen(["nsenter", "--net=/var/run/netns/amz", "--", sys.executable, "-I", proxy_py, conf],
                             stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        for _ in range(50):
            if sh("amz", sys.executable, "-c", "import socket; socket.create_connection(('10.8.1.1', 5300), 0.3)"
                  ).returncode == 0:
                break
            time.sleep(0.1)
        return p

    def ask(*names):
        return json.loads(sh("amz", sys.executable, "-c", DNS_ASK, "5300", ",".join(names), timeout=180).stdout)

    def block(text):
        sh("inet", "nft", "delete", "table", "ip", "p31")
        if text:
            nft("inet", "table ip p31 {\n chain c_in {\n  type filter hook input priority 0;\n  " + text + "\n }\n}\n")

    def show(label, got):
        print(f"    {label:44} " + ", ".join(f"{w} {t:.2f} с" for w, t in got))

    # ложная тревога: DoH в порядке, одно имя он разбирает 7 с
    block("")
    p = start()
    try:
        got = ask("a.example") + ask("slow.example")
        time.sleep(0.5)                                     # проверка пути контрольным запросом — доли секунды
        got += ask("n1.example", "n2.example", "n3.example")
    finally:
        p.terminate()
        p.wait(10)
    show("медленное имя: a, slow, затем три имени", got)
    results += [check("П31: одно медленное имя — само у запасного", got[1][0] == "fb"),
                check("П31: следующие имена — у DoH, а не у запасного", [w for w, _ in got[2:]] == ["shared"] * 3)]

    # настоящая блокировка в пути
    for label, rule in (("SYN отбрасывается", "tcp flags & (syn|ack) == syn drop"),
                        ("RST после ClientHello", "ip length > 120 reject with tcp reset"),
                        ("ClientHello отбрасывается", "ip length > 120 drop"),
                        # Отбрасываются пакеты dnsproxy.py, в которых начинается запись TLS с данными (тип 0x17): в TLS 1.3
                        # это всё после рукопожатия — начало HTTP/2, запросы, контрольный «. NS». ClientHello (0x16),
                        # ChangeCipherSpec с Finished (0x14 в начале пакета) и пустые подтверждения TCP проходят, поэтому
                        # рукопожатие доходит. Прежний порог «байты рукопожатия + 200» зависел от числа подтверждений TCP и
                        # пропускал короткий «. NS» на новом соединении: проверка проходила, и следующее имя отвечал DoH
                        # (красный 4 раза из 40 на машинах GitHub, проверка Ж4)
                        ("замерзание после рукопожатия", "@ih,0,8 0x17 drop")):
        block(f"ip daddr 8.8.8.8 tcp dport {port} {rule}")
        p = start()
        was = handshakes()
        try:
            got = ask(("x" * 50 + ".") * 4 + "first.example", "n1.example", "n2.example", "n3.example")
        finally:
            p.terminate()
            p.wait(10)
        hs_done = handshakes() - was
        show(label, got)
        print(f"    {'':44} рукопожатий TLS у DoH: {hs_done}")
        if label.startswith("замерзание"):
            results += [check("П31, замерзание: рукопожатие проходит, ответа нет", hs_done >= 1)]
        elif label.startswith(("SYN", "ClientHello")):
            results += [check(f"П31, {label}: рукопожатие не проходит", hs_done == 0)]
        results += [check(f"П31, {label}: первое имя — у запасного за один срок ответа",
                          got[0][0] == "fb" and got[0][1] < 11),
                    check(f"П31, {label}: следующие — сразу у запасного",
                          all(w == "fb" and t < 0.5 for w, t in got[1:]))]
    block("")
    srv.kill()
    srv.wait()
    return results


def main():
    if sys.argv[1:] == ["dns"]:                             # только П31 (сравнить код до и после: P31_DNSPROXY)
        procs = setup()
        try:
            results = dns_fallback()
        finally:
            for p in procs:
                p.kill()
            for n in NS:
                netns.remove(n)
        print(f"\n{sum(results)}/{len(results)} проверок пройдено")
        sys.exit(0 if all(results) else 1)
    results = panel_dual_stack()
    procs = setup()
    try:
        # таблица учёта стоит с самого начала: все проверки маршрутов ниже идут с ней
        nft("amz", nftgen.acct_ruleset("awg0"))
        g = {"rules": [(["ru"], "direct")], "default": 1}
        panel_apply(g, {})
        results += [expect("глобально: всё через выход, RU напрямую", "foreign", "UP1 from 10.8.1.3"),
                    expect("глобально: всё через выход, RU напрямую", "russian", "DIRECT from 172.20.0.2"),
                    # служебный адрес облака есть «в интернете» (inet), но клиенту закрыт
                    expect("служебный адрес облака 169.254.169.254 закрыт", "metadata", "FAIL")]
        panel_apply({"rules": [], "default": "direct"}, {})
        results += [expect("всё напрямую: служебный адрес облака всё равно закрыт", "metadata", "FAIL"),
                    expect("всё напрямую: остальное открыто", "foreign", "DIRECT")]
        panel_apply(g, {})
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
        # учёт по правилам (1.24.0): метки соединений (ct label) в цепочках политик и таблица awgr_racct
        d = config.RULE_DEFAULT_SLOT
        nft("amz", nftgen.racct_ruleset("awg0", [0, d]))
        lg = {**g, "slots": [0], "dslots": []}
        panel_apply(lg, {}, labels=True)
        results += [expect("с метками правил: всё через выход", "foreign", "UP1 from 10.8.1.3"),
                    expect("с метками правил: RU напрямую", "russian", "DIRECT from 172.20.0.2")]
        r = racct()
        results += [check("учёт по правилам: правило RU (номер 0) — в обе стороны", all(r.get(("10.8.1.2", 0), [0, 0]))),
                    check("учёт по правилам: «По умолчанию» — в обе стороны", all(r.get(("10.8.1.2", d), [0, 0])))]
        panel_apply(lg, {}, labels=True)
        nft("amz", nftgen.racct_ruleset("awg0", [0, 1, 2, d]))     # правил стало больше: цепочки — заново
        r2 = racct()
        results += [check("учёт по правилам: счётчики пережили новую основную таблицу и новые строки",
                          r2.get(("10.8.1.2", 0), [0, 0])[1] >= r[("10.8.1.2", 0)][1] > 0)]
        # балансировка в правиле (1.24.0): правило по адресам ведёт в Sticky-выход — соединение держится на выходе
        panel_apply({"rules": [(["ru"], nftgen.Sticky(1))], "default": "direct"}, {}, balance={1})
        results += [expect("балансировка в правиле: RU через выход группы", "russian", "UP1 from 10.8.1.3"),
                    expect("балансировка в правиле: остальное напрямую", "foreign", "DIRECT from 172.20.0.2")]
        # чужая программа на сервере «на хосте» метит пересылаемые пакеты теми же битами, что и номер ограничения
        # скорости правила (Tailscale: 0x40000 — пересылка, 0x80000 — свои соединения): защита панели их не трогает
        panel_apply({"rules": [], "default": "direct"}, {}, labels=True)
        nft("amz", "table ip ts {\n chain f {\n  type filter hook forward priority 10; policy accept;\n"
                   '  iifname "awg0" meta mark set meta mark or 0x40000\n }\n}\n')
        results += [expect("чужая метка 0x40000 (Tailscale) на пересылке — проходит", "foreign", "DIRECT")]
        assert sh("amz", "nft", "delete", "table", "ip", "ts").returncode == 0
        panel_apply({"rules": [], "default": 1}, {})
        results += [expect("без правил: RU тоже через выход", "russian", "UP1")]
        # «DNS на сервере» (П5): любой запрос DNS клиента — к DNS на сервере, и через выход, и напрямую, UDP и TCP
        results += [expect_dns("без DNS на сервере: DNS клиента — как его трафик (через выход)", "udp", "8.8.8.8",
                               "DNS-UP1")]
        for default, how in ((1, "через выход"), ("direct", "напрямую")):
            panel_apply({"rules": [(["ru"], "direct")], "default": default}, {}, dns_to="10.8.1.1")
            for kind in ("udp", "tcp"):
                results += [expect_dns(f"DNS на сервере, {how}: второй DNS 8.8.8.8 отвечает панель ({kind})", kind,
                                       "8.8.8.8", "DNS-PANEL from 10.8.1.2"),
                            expect_dns(f"DNS на сервере, {how}: адрес самого DNS — без перенаправления ({kind})",
                                       kind, "10.8.1.1", "DNS-PANEL from 10.8.1.2")]
            results += [expect_dns(f"DNS на сервере, {how}: частная сеть — тоже панель", "udp", "192.168.77.1",
                                   "DNS-PANEL from 10.8.1.2")]
        panel_apply({"rules": [(["ru"], "direct")], "default": "direct"}, {})
        results += [expect_dns("DNS на сервере выключен: напрямую, как раньше", "udp", "8.8.8.8",
                               "DNS-INET from 172.20.0.2")]
        results += dns_fallback()
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
