"""1.15.0: имя в Endpoint выхода разбирает панель, повторный разбор, DNS на сервере.

python3 -m unittest discover tests
"""
import os
import socket
import sys
import tempfile
import time
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json  # noqa: E402
import shutil  # noqa: E402
import signal  # noqa: E402
import socketserver  # noqa: E402
import struct  # noqa: E402
import subprocess  # noqa: E402
import threading  # noqa: E402

from app import awgconf, config, dnsproxy, engine, system, tgbot, users  # noqa: E402

KEY = "A" * 42 + "E="


def conf(endpoint: str) -> str:
    return (f"[Interface]\nPrivateKey = {KEY}\nAddress = 10.8.1.2/32\n\n"
            f"[Peer]\nPublicKey = {KEY}\nEndpoint = {endpoint}\nAllowedIPs = 0.0.0.0/0\n")


def answer(ip, fam=socket.AF_INET):
    return [(fam, socket.SOCK_STREAM, 6, "", (ip, 0))]


class SplitTest(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(awgconf.split_endpoint("relay.example.com:30070"), ("relay.example.com", "30070"))
        self.assertEqual(awgconf.split_endpoint("203.0.113.5:51820"), ("203.0.113.5", "51820"))
        self.assertEqual(awgconf.split_endpoint("[2001:db8::1]:51820"), ("2001:db8::1", "51820"))


class ResolveTest(unittest.TestCase):
    def test_ip_is_not_resolved(self):
        with mock.patch("socket.getaddrinfo", side_effect=AssertionError("DNS не нужен")):
            self.assertEqual(awgconf.resolve_host("203.0.113.5"), "203.0.113.5")
            self.assertEqual(awgconf.resolve_host("2001:db8::1"), "2001:db8::1")

    def test_domain_prefers_ipv4(self):
        def gai(host, port, fam, typ):
            return answer("203.0.113.7") if fam == socket.AF_INET else answer("2001:db8::7", fam)
        with mock.patch("socket.getaddrinfo", side_effect=gai):
            self.assertEqual(awgconf.resolve_host("relay.example.com"), "203.0.113.7")

    def test_ipv6_fallback(self):
        def gai(host, port, fam, typ):
            if fam == socket.AF_INET:
                raise socket.gaierror(-2, "no A")
            return answer("2001:db8::7", fam)
        with mock.patch("socket.getaddrinfo", side_effect=gai):
            self.assertEqual(awgconf.resolve_host("relay.example.com"), "2001:db8::7")

    def test_failure_is_a_message(self):
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror(-2, "unknown")):
            with self.assertRaises(awgconf.ConfigError) as cm:
                awgconf.resolve_host("nope.example.com")
        self.assertEqual(cm.exception.msg.key, "cfg.endpoint_resolve")
        self.assertEqual(cm.exception.msg.p["host"], "nope.example.com")

    def test_hang_is_cut_off(self):
        """Резолвер, который не отвечает, не должен вешать движок."""
        with mock.patch("socket.getaddrinfo", side_effect=lambda *a: time.sleep(5)):
            t0 = time.monotonic()
            with self.assertRaises(awgconf.ConfigError):
                awgconf.resolve_host("slow.example.com", timeout=0.3)
            self.assertLess(time.monotonic() - t0, 2)


class SetconfTest(unittest.TestCase):
    def test_domain_replaced_raw_kept(self):
        pc = awgconf.parse_upstream(conf("relay.example.com:30070"))
        with mock.patch("socket.getaddrinfo", return_value=answer("203.0.113.7")):
            text = awgconf.setconf_resolved(pc)
        self.assertIn("Endpoint = 203.0.113.7:30070\n", text)
        self.assertNotIn("relay.example.com", text)
        self.assertIn("PersistentKeepalive = 25", text)
        # исходный конфиг и показываемый адрес остаются с именем: при следующем запуске оно разберётся заново
        self.assertIn("relay.example.com:30070", pc.raw)
        self.assertEqual(pc.endpoint, "relay.example.com:30070")
        self.assertIn("relay.example.com", pc.setconf)

    def test_ipv6_in_brackets(self):
        pc = awgconf.parse_upstream(conf("relay.example.com:30070"))
        with mock.patch("socket.getaddrinfo", side_effect=[socket.gaierror(-2, "x"), answer("2001:db8::7", socket.AF_INET6)]):
            self.assertIn("Endpoint = [2001:db8::7]:30070\n", awgconf.setconf_resolved(pc))

    def test_ip_endpoint_unchanged(self):
        pc = awgconf.parse_upstream(conf("203.0.113.5:51820"))
        with mock.patch("socket.getaddrinfo", side_effect=AssertionError("DNS не нужен")):
            self.assertEqual(awgconf.setconf_resolved(pc), pc.setconf)

    def test_lowercase_key(self):
        pc = awgconf.parse_upstream(conf("relay.example.com:30070").replace("Endpoint", "endpoint"))
        with mock.patch("socket.getaddrinfo", return_value=answer("203.0.113.7")):
            self.assertIn("endpoint = 203.0.113.7:30070\n", awgconf.setconf_resolved(pc))


class StartUpTest(unittest.TestCase):
    """_start_up: в `awg setconf` уходит IP, а при неудаче разбора интерфейс не создаётся."""

    def setUp(self):
        self.t = mock.Mock(pid=4321, key="k")
        self.t.ns.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        self.u = {"num": 2, "name": "exit"}
        self.pc = awgconf.parse_upstream(conf("relay.example.com:30070"))
        self.eng = engine.Engine.__new__(engine.Engine)
        self.eng.rt = {}
        self.eng.event = mock.Mock()
        self.written = None

    def run_start(self):
        d = tempfile.mkdtemp()
        real_open = os.open

        def fake_open(path, flags, mode=0o777):
            return real_open(os.path.join(d, os.path.basename(path)), flags, mode)

        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(config, "UPSTREAM_BACKEND", "kernel"), \
                mock.patch("os.open", side_effect=fake_open), mock.patch("os.remove", side_effect=lambda p: None):
            self.eng._start_up(self.t, "u1", self.u, self.pc, "h")
        with open(os.path.join(d, "awgr2.conf")) as f:
            return f.read()

    def test_setconf_gets_ip(self):
        with mock.patch("socket.getaddrinfo", return_value=answer("203.0.113.7")):
            text = self.run_start()
        self.assertIn("Endpoint = 203.0.113.7:30070", text)
        self.assertTrue(any(c.args[0][:2] == ["awg", "setconf"] for c in self.t.ns.call_args_list))

    def test_resolve_failure_creates_nothing(self):
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror(-2, "x")):
            with self.assertRaises(system.SysError) as cm:
                self.run_start()
        self.assertEqual(cm.exception.msg.key, "cfg.endpoint_resolve")
        cmds = [c.args[0] for c in self.t.ns.call_args_list]
        self.assertFalse(any(c[:3] == ["ip", "link", "add"] for c in cmds))
        self.assertEqual(self.eng.rt, {})


class ProbeHostsTest(unittest.TestCase):
    def test_many_in_parallel(self):
        def gai(host, *a):
            time.sleep(0.5)
            if host == "bad.example.com":
                raise socket.gaierror(-2, "x")
            return answer("203.0.113.9")
        with mock.patch("socket.getaddrinfo", side_effect=gai):
            t0 = time.monotonic()
            res = awgconf.resolve_many(("a.example.com", "b.example.com", "bad.example.com"), 3)
            self.assertLess(time.monotonic() - t0, 1.4)     # по очереди было бы 1.5 с и больше
        self.assertEqual(res, {"a.example.com": "203.0.113.9", "b.example.com": "203.0.113.9"})

    def test_probe_gets_addresses(self):
        eng = engine.Engine.__new__(engine.Engine)
        eng.target = mock.Mock(pid=1)
        eng.target.ns.return_value = mock.Mock(stdout='{"ok": true, "ip": "198.51.100.1"}', stderr="")
        eng.store = mock.Mock()
        eng.resolve = lambda out, st: 3
        with mock.patch.object(config, "DRY_RUN", False), \
                mock.patch("socket.getaddrinfo", return_value=answer("203.0.113.9")):
            res = eng.probe("up:x")
        cmd = eng.target.ns.call_args.args[0]
        self.assertEqual(cmd[0], "python3")
        self.assertIn("ip-api.com=203.0.113.9", cmd)
        self.assertIn("ifconfig.me=203.0.113.9", cmd)
        self.assertTrue(res["ok"])



class ReresolveTest(unittest.TestCase):
    """Туннель с именем в Endpoint не отвечает → имя разбирается заново, адрес пира меняется без перезапуска."""

    def make(self, endpoint="relay.example.com:30070"):
        eng = engine.Engine.__new__(engine.Engine)
        eng._rr_busy = set()
        eng.event = mock.Mock()
        pc = awgconf.parse_upstream(conf(endpoint))
        eng.parsed = lambda u: pc
        r = engine.UpRT(2, "h", "k")
        r.started -= 600
        eng.rt = {"u1": r}
        t = mock.Mock()
        t.ns.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        return eng, t, r, {"id": "u1", "name": "exit"}

    def run_it(self, eng, t, r, u, peer_ep, ip="203.0.113.8"):
        with mock.patch.object(awgconf, "resolve_host", return_value=ip):
            eng._reresolve(t, u, r, {"endpoint": peer_ep}, time.time())
            for th in threading.enumerate():
                if th.name.startswith("reresolve-"):
                    th.join(2)

    def test_changed_address_is_set(self):
        eng, t, r, u = self.make()
        self.run_it(eng, t, r, u, "203.0.113.7:30070")
        cmd = t.ns.call_args.args[0]
        self.assertEqual(cmd[:3], ["awg", "set", "awgr2"])
        self.assertEqual(cmd[-2:], ["endpoint", "203.0.113.8:30070"])
        self.assertEqual(eng.event.call_args.args[1].key, "ev.endpoint_changed")

    def test_same_address_nothing(self):
        eng, t, r, u = self.make()
        self.run_it(eng, t, r, u, "203.0.113.8:30070")
        t.ns.assert_not_called()
        eng.event.assert_not_called()

    def test_ip_endpoint_nothing(self):
        eng, t, r, u = self.make("198.51.100.4:51820")
        self.run_it(eng, t, r, u, "198.51.100.4:51820")
        t.ns.assert_not_called()
        self.assertEqual(r.reresolved, 0.0)

    def test_rate_limited(self):
        eng, t, r, u = self.make()
        self.run_it(eng, t, r, u, "203.0.113.7:30070")
        t.ns.reset_mock()
        self.run_it(eng, t, r, u, "203.0.113.7:30070", ip="203.0.113.9")   # сразу снова — рано
        t.ns.assert_not_called()

    def test_only_unhealthy_tunnels(self):
        """Живой туннель не трогаем: _update_health зовёт разбор только при нездоровом handshake."""
        eng, t, r, u = self.make()
        eng.health, eng._fake, eng.store = {}, None, None
        eng._reresolve = mock.Mock()
        now = time.time()
        dump = "priv\tpub\t51820\toff\npk\t(none)\t203.0.113.7:30070\t0.0.0.0/0\t%d\t1\t2\t25\n"
        with mock.patch.object(config, "DRY_RUN", False):
            t.ns.return_value = mock.Mock(returncode=0, stdout=dump % int(now - 10))
            eng._update_health(t, {"upstreams": [dict(u, enabled=True)]})
            eng._reresolve.assert_not_called()
            t.ns.return_value = mock.Mock(returncode=0, stdout=dump % int(now - 900))
            eng._update_health(t, {"upstreams": [dict(u, enabled=True)]})
            eng._reresolve.assert_called_once()


# ---------------------------------------------------------------- DNS на сервере
def q_msg(name, qtype=1, qid=0x1234, edns=None):
    m = struct.pack("!6H", qid, 0x0100, 1, 0, 0, 1 if edns else 0)
    m += b"".join(bytes([len(x)]) + x.encode() for x in name.strip(".").split(".")) + b"\0"
    m += struct.pack("!HH", qtype, 1)
    if edns:
        m += b"\0" + struct.pack("!HHIH", 41, edns, 0, 0)
    return m


def a_reply(query, ips, ttl=300, rcode=0, soa=None):
    """Ответ сервера: записи A со сжатым именем (указатель на вопрос) или SOA в разделе authority."""
    q = dnsproxy.parse_query(query)
    head = struct.pack("!6H", q["id"], 0x8180 | rcode, 1, len(ips), 1 if soa else 0, 0)
    body = query[12:q["qend"]]
    for ip in ips:
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip)
    if soa:
        rd = b"\x02ns\xc0\x0c" + b"\x01h\xc0\x0c" + struct.pack("!5I", 1, 2, 3, 4, soa[1])
        body += b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, soa[0], len(rd)) + rd
    return head + body


class DnsParseTest(unittest.TestCase):
    def test_query(self):
        q = dnsproxy.parse_query(q_msg("Example.COM", 28, edns=1232))
        self.assertEqual((q["name"], q["qtype"], q["udp_max"]), ("example.com.", 28, 1232))
        self.assertIsNone(dnsproxy.parse_query(a_reply(q_msg("a.b"), ["192.0.2.1"])))   # ответ, не запрос
        self.assertIsNone(dnsproxy.parse_query(b"\x00" * 5))

    def test_cache_ttl_min_of_answers(self):
        q = q_msg("a.example")
        r = bytearray(a_reply(q, ["192.0.2.1", "192.0.2.2"], ttl=300))
        ttl, offs = dnsproxy.cache_ttl(bytes(r))
        self.assertEqual((ttl, len(offs)), (300, 2))
        r[offs[1]:offs[1] + 4] = struct.pack("!I", 60)
        self.assertEqual(dnsproxy.cache_ttl(bytes(r))[0], 60)
        self.assertEqual(dnsproxy.cache_ttl(a_reply(q, ["192.0.2.1"], ttl=10 ** 6))[0], dnsproxy.TTL_MAX)

    def test_negative_uses_soa(self):
        q = q_msg("nope.example")
        self.assertEqual(dnsproxy.cache_ttl(a_reply(q, [], rcode=3, soa=(900, 120)))[0], 120)
        self.assertEqual(dnsproxy.cache_ttl(a_reply(q, [], rcode=3, soa=(9000, 9000)))[0], dnsproxy.NEG_TTL_MAX)
        self.assertEqual(dnsproxy.cache_ttl(a_reply(q, [], rcode=3))[0], dnsproxy.NEG_TTL_DEFAULT)
        self.assertEqual(dnsproxy.cache_ttl(a_reply(q, [], rcode=2))[0], 0)          # SERVFAIL не храним

    def test_ttl_decrement(self):
        r = a_reply(q_msg("a.example"), ["192.0.2.1"], ttl=300)
        _, offs = dnsproxy.cache_ttl(r)
        r2 = dnsproxy.with_ttl(r, offs, 100)
        self.assertEqual(struct.unpack("!I", r2[offs[0]:offs[0] + 4])[0], 200)
        self.assertEqual(struct.unpack("!I", dnsproxy.with_ttl(r, offs, 999)[offs[0]:offs[0] + 4])[0], 0)

    def test_mark_on_socket(self):
        with mock.patch("socket.socket") as S:
            dnsproxy.Proxy._sock(socket.SOCK_DGRAM, 0x2003)
        S.return_value.setsockopt.assert_called_with(socket.SOL_SOCKET, dnsproxy.SO_MARK, 0x2003)


class FakeUpstream:
    """Сервер DNS для тестов: UDP и TCP на 127.0.0.1, считает запросы. «big.example» по UDP без EDNS — TC."""

    def __init__(self):
        self.count = 0
        up = self

        def answer(data, tcp):
            up.count += 1
            q = dnsproxy.parse_query(data)
            if q["name"] == "big.example.":
                r = a_reply(data, [f"192.0.2.{i}" for i in range(1, 60)])
                if not tcp and len(r) > q["udp_max"]:
                    r = dnsproxy.truncated(r, q)
                return r
            if q["name"] == "nx.example.":
                return a_reply(data, [], rcode=3, soa=(600, 60))
            return a_reply(data, ["203.0.113.1"], ttl=300)

        class U(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                sock.sendto(answer(data, False), self.client_address)

        class T(socketserver.BaseRequestHandler):
            def handle(self):
                n = struct.unpack("!H", self.request.recv(2))[0]
                data = b""
                while len(data) < n:
                    data += self.request.recv(n - len(data))
                r = answer(data, True)
                self.request.sendall(struct.pack("!H", len(r)) + r)

        self.udp = socketserver.ThreadingUDPServer(("127.0.0.1", 0), U)
        port = self.udp.server_address[1]
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self.tcp = socketserver.ThreadingTCPServer(("127.0.0.1", port), T)
        self.port = port
        for srv in (self.udp, self.tcp):
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    def close(self):
        for srv in (self.udp, self.tcp):
            srv.shutdown()
            srv.server_close()


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u, socket.socket() as t:
        for _ in range(50):
            u2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u2.bind(("127.0.0.1", 0))
            port = u2.getsockname()[1]
            u2.close()
            try:
                t2 = socket.socket()
                t2.bind(("127.0.0.1", port))
                t2.close()
                return port
            except OSError:
                continue
    raise OSError("no port")


class DnsProxyProcessTest(unittest.TestCase):
    """dnsproxy.py как отдельный процесс: UDP и TCP, кэш, обрезанный ответ, блок, SIGHUP."""

    @classmethod
    def setUpClass(cls):
        cls.up = FakeUpstream()
        cls.dir = tempfile.mkdtemp()
        cls.conf = os.path.join(cls.dir, "dns.json")
        cls.port = free_port()
        cls.cfg = {"listen": "127.0.0.1", "port": cls.port, "clients": "127.0.0.0/8",
                   "stats": os.path.join(cls.dir, "stats.json"), "upstreams": ["127.0.0.1"],
                   "upstream_port": cls.up.port, "default": {"mark": 0, "tcp": False}, "routes": {}}
        cls.write(cls.cfg)
        cls.proc = subprocess.Popen([sys.executable, "-I", engine.DNSPROXY, cls.conf],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", cls.port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def write(cls, cfg):
        with open(cls.conf, "w") as f:
            json.dump(cfg, f)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(5)
        cls.up.close()

    def udp(self, msg):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.sendto(msg, ("127.0.0.1", self.port))
            return s.recv(65535)

    def tcp(self, msg):
        with socket.create_connection(("127.0.0.1", self.port), 5) as s:
            s.sendall(struct.pack("!H", len(msg)) + msg)
            data = b""
            while len(data) < 2 or len(data) < 2 + struct.unpack("!H", data[:2])[0]:
                data += s.recv(65535)
            return data[2:]

    def test_1_answer_and_cache(self):
        n0 = self.up.count
        r1 = self.udp(q_msg("www.example", qid=0x1111))
        self.assertEqual(r1[:2], b"\x11\x11")
        self.assertIn(socket.inet_aton("203.0.113.1"), r1)
        time.sleep(1.1)
        r2 = self.udp(q_msg("WWW.example", qid=0x2222))
        self.assertEqual(r2[:2], b"\x22\x22")
        self.assertEqual(self.up.count - n0, 1, "второй ответ — из кэша")
        _, offs = dnsproxy.cache_ttl(r2)
        self.assertLess(struct.unpack("!I", r2[offs[0]:offs[0] + 4])[0], 300)

    def test_2_tcp(self):
        r = self.tcp(q_msg("tcp.example", qid=0x3333))
        self.assertEqual(r[:2], b"\x33\x33")
        self.assertIn(socket.inet_aton("203.0.113.1"), r)

    def test_3_big_udp_truncated_then_tcp(self):
        r = self.udp(q_msg("big.example"))
        self.assertTrue(struct.unpack("!H", r[2:4])[0] & 0x0200, "без EDNS большой ответ — с флагом TC")
        self.assertEqual(struct.unpack("!H", r[6:8])[0], 0)
        full = self.tcp(q_msg("big.example"))
        self.assertEqual(struct.unpack("!H", full[6:8])[0], 59)
        big = self.udp(q_msg("big.example", edns=4096))
        self.assertEqual(struct.unpack("!H", big[6:8])[0], 59)

    def test_4_nxdomain(self):
        r = self.udp(q_msg("nx.example"))
        self.assertEqual(r[3] & 0xF, 3)

    def test_5_block_after_reload(self):
        self.write(dict(self.cfg, default=None))
        self.proc.send_signal(signal.SIGHUP)
        time.sleep(0.3)
        try:
            r = self.udp(q_msg("blocked.example"))
            self.assertEqual(r[3] & 0xF, dnsproxy.RC_REFUSED)
        finally:
            self.write(self.cfg)
            self.proc.send_signal(signal.SIGHUP)
            time.sleep(0.3)

    def test_6_dead_upstream_servfail(self):
        self.write(dict(self.cfg, upstreams=["127.0.0.2"], upstream_port=9))
        self.proc.send_signal(signal.SIGHUP)
        time.sleep(0.3)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(15)
                s.sendto(q_msg("dead.example"), ("127.0.0.1", self.port))
                r = s.recv(512)
            self.assertEqual(r[3] & 0xF, dnsproxy.RC_SERVFAIL)
        finally:
            self.write(self.cfg)
            self.proc.send_signal(signal.SIGHUP)
            time.sleep(0.3)

    def test_7_stats(self):
        self.udp(q_msg("stats.example"))
        deadline = time.time() + 3
        while time.time() < deadline and not os.path.exists(self.cfg["stats"]):
            time.sleep(0.1)
        with open(self.cfg["stats"]) as f:
            s = json.load(f)
        self.assertEqual(s["pid"], self.proc.pid)


class DnsRoutesTest(unittest.TestCase):
    """Путь запросов DNS = основной выход политики клиента; выхода нет среди запущенных — блок."""

    def test_routes(self):
        eng = engine.Engine.__new__(engine.Engine)
        socks_u = {"id": "s", "num": 3}
        awg_u = {"id": "a", "num": 2}
        kinds = {"s": "socks5", "a": "awg"}
        eng.parsed = lambda u: mock.Mock(kind=kinds[u["id"]])
        eng.rt = {"a": mock.Mock(num=2), "s": mock.Mock(num=3)}
        eng._policies = lambda st: ({"default": 2, "rules": [], "domain": []}, {
            "10.8.1.5": {"default": "direct", "rules": [], "domain": []},
            "10.8.1.6": {"default": 3, "rules": [], "domain": []},
            "10.8.1.7": {"default": "block", "rules": [], "domain": []},
            "10.8.1.8": {"default": 2, "rules": [(["ru"], "direct")], "domain": []},
            "10.8.1.9": {"default": 4, "rules": [], "domain": []}})
        with mock.patch.object(config, "DRY_RUN", False):
            default, routes = eng.dns_routes({"upstreams": [socks_u, awg_u]})
        self.assertEqual(default, {"mark": 0x2002, "tcp": False})
        self.assertEqual(routes, {"10.8.1.5": {"mark": 0, "tcp": False},
                                  "10.8.1.6": {"mark": 0x2003, "tcp": True},
                                  "10.8.1.7": None, "10.8.1.9": None})


class PanelDnsConfigTest(unittest.TestCase):
    def test_profile_dns(self):
        sc = mock.Mock()
        sc.get = lambda k: "10.8.1.1/24" if k == "Address" else ""
        self.assertEqual(users.profile_dns({"client_dns": ["9.9.9.9", "1.1.1.1"]}, sc), ["9.9.9.9", "1.1.1.1"])
        self.assertEqual(users.profile_dns({"client_dns": ["9.9.9.9", "1.1.1.1"], "panel_dns": True}, sc),
                         ["10.8.1.1", "9.9.9.9"])
        sc.get = lambda k: "10.8.1.0/24" if k == "Address" else ""
        self.assertEqual(users.profile_dns({"panel_dns": True}, sc)[0], "10.8.1.0")
        self.assertEqual(users.profile_dns({"panel_dns": True}, sc, "10.8.1.1")[0], "10.8.1.1")   # где слушает
        sc.get = lambda k: ""
        self.assertEqual(users.profile_dns({"panel_dns": True}, sc), users.DEFAULT_DNS)


class DetectHostTest(unittest.TestCase):
    """Внешний IPv4: не сдаётся после первых неудач и помнит, ищет он ещё или уже не нашёл."""

    def run_detect(self, answers):
        eng = engine.Engine.__new__(engine.Engine)
        eng.public_v4, eng.public_v4_state = None, "pending"
        eng.target = mock.Mock(exists=True)
        eng.srv = mock.Mock()
        eng.srv.public_host.return_value = "203.0.113.5"
        eng.store = mock.Mock()
        it = iter(answers)
        seen, waits = [], []

        def probe(out):
            a = next(it, None)
            if a is None:
                eng.stop_ev.set()
                return {"ok": True, "ip": None}
            return a

        eng.probe = probe
        eng.stop_ev = threading.Event()
        real_wait = eng.stop_ev.wait
        eng.stop_ev.wait = lambda t: (waits.append(t), seen.append(eng.public_v4_state), real_wait(0))[-1]
        with mock.patch.object(engine, "HOST_FAST_TRIES", 3):
            eng._detect_host()
        return eng, seen, waits

    def test_keeps_trying_then_finds(self):
        no = {"ok": True, "ip": None, "warn": "no_ip"}
        eng, seen, waits = self.run_detect([no, no, no, no, {"ok": True, "ip": "198.51.100.7"}])
        self.assertEqual(seen[:4], ["pending", "pending", "failed", "failed"])
        self.assertEqual(waits[:4], [engine.HOST_FAST_WAIT] * 2 + [engine.HOST_SLOW_WAIT] * 2)  # 3 частые попытки
        self.assertEqual((eng.public_v4, eng.public_v4_state), ("198.51.100.7", "ok"))
        self.assertEqual(waits[4], engine.HOST_RECHECK)

    def test_recheck_failure_keeps_address(self):
        eng, seen, waits = self.run_detect([{"ok": True, "ip": "198.51.100.7"}, {"ok": False}])
        self.assertEqual((eng.public_v4, eng.public_v4_state), ("198.51.100.7", "ok"))
        self.assertEqual(waits[1], engine.HOST_SLOW_WAIT)


class BotStatusTest(unittest.TestCase):
    """Экран бота «Сервер › Состояние»: IPv4 и IPv6 без голого прочерка, строка DNS на сервере."""

    def screen(self, **host):
        b = tgbot.Bot.__new__(tgbot.Bot)
        b.ops = mock.Mock(version="1.15.0")
        b.ops.status.return_value = {"host": "203.0.113.5", "server_ok": True, "version": {}}
        b.ops.host_info.return_value = {"awg": "3.1", "uptime": 60, "memory": None, **host}
        b.ops.clients.return_value = []
        b._show = mock.Mock()
        b._back_server = lambda c: []
        b.show_status({"lang": "ru"}, None)
        return b._show.call_args.args[1]

    def test_addresses(self):
        t = self.screen(v4="198.51.100.7", v4_state="ok", v6=None)
        self.assertIn("IPv4: <code>198.51.100.7</code>", t)
        self.assertIn("IPv6: на сервере нет", t)
        self.assertIn("определяется", self.screen(v4=None, v4_state="pending"))
        self.assertIn("не определён", self.screen(v4=None, v4_state="failed"))
        for t in (self.screen(v4=None, v4_state="failed"), self.screen(v4=None, v6=None)):
            self.assertNotIn("IPv4: —", t)
            self.assertNotIn("IPv6: —", t)

    def test_dns(self):
        self.assertIn("DNS на сервере: выключен", self.screen(dns=None))
        t = self.screen(dns={"state": "on", "listen": "10.8.1.1", "queries": 12, "cached": 5})
        self.assertIn("DNS на сервере: работает на <code>10.8.1.1</code>", t)
        self.assertIn("запросов 12, из кэша 5", t)
        self.assertIn("DNS на сервере: не работает", self.screen(dns={"state": "error", "error": "x"}))


if __name__ == "__main__":
    unittest.main()
