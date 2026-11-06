"""1.14.3: имя в Endpoint разбирается в сети панели, а не в сети контейнера Amnezia.

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

from app import awgconf, config, engine, system  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
