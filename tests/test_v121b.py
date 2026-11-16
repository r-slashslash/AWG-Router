"""1.21.0, вторая часть: имя файла конфига, QUIC через SOCKS5 по галочке, проверка выхода (задержка до
первого ответа, UDP), присмотр за sniproxy.py, блок при неработающих правилах по доменам.

python3 -m unittest discover tests
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import config, engine, nftgen, users, web  # noqa: E402
from app.store import Store  # noqa: E402
import importlib.util  # noqa: E402

# app/probe.py — отдельный скрипт (запускается в сети сервера AWG), не модуль пакета
_spec = importlib.util.spec_from_file_location("probe", os.path.join(os.path.dirname(__file__), "..", "app", "probe.py"))
probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probe)
from app import sniproxy  # noqa: E402
from app import panel  # noqa: E402
from app.api import backup, exits, routing, state  # noqa: E402

PK = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="


class Req:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


# ------------------------------------------------------------------ имя файла конфига
class ConfFilenameTest(unittest.TestCase):
    """Приложения AmneziaWG и WireGuard берут имя туннеля из имени файла: [A-Za-z0-9_=+.-]{1,15}."""

    def test_latin_name_as_is(self):
        self.assertEqual(users.conf_filename("Phone", PK), "Phone.conf")
        self.assertEqual(users.conf_filename("my-pc_2.home", PK), "my-pc_2.home.conf")

    def test_spaces_and_symbols(self):
        self.assertEqual(users.conf_filename("My Phone", PK), "My_Phone.conf")
        self.assertEqual(users.conf_filename("a/b:c", PK), "a_b_c.conf")

    def test_long_latin_name_is_cut(self):
        name = users.conf_filename("Laptop of the big office", PK)
        self.assertRegex(name, r"^[A-Za-z0-9_=+.-]{1,15}\.conf$")
        self.assertTrue(name.startswith("Laptop_of_the"))

    def test_other_language_gets_8_digits(self):
        for n in ("Мой телефон", "我的手机", "تلفن من", "Phone ✓", "Ноут"):
            name = users.conf_filename(n, PK)
            self.assertRegex(name, r"^\d{8}\.conf$", n)

    def test_digits_stable_per_client(self):
        a = users.conf_filename("Мой телефон", PK)
        self.assertEqual(a, users.conf_filename("Другое имя", PK))          # от ключа, не от имени
        self.assertNotEqual(a, users.conf_filename("Мой телефон", "A" * 43 + "="))

    def test_nothing_left(self):
        self.assertRegex(users.conf_filename("___", PK), r"^\d{8}\.conf$")
        self.assertRegex(users.conf_filename("", PK), r"^\d{8}\.conf$")


# ------------------------------------------------------------------ QUIC через SOCKS5
UP = {"num": 1, "snat": None, "mtu": 1280}


class NftNoQuicTest(unittest.TestCase):
    def test_exit_without_quic_rejects_udp_443(self):
        r = nftgen.generate("awg0", {}, [{**UP, "no_quic": True}], {"rules": [], "default": 1}, {})
        chain = r.split("chain o_u1 {")[1].split("}")[0]
        self.assertIn(f"udp dport 443 meta mark set {config.MARK_BLOCK:#x} accept", chain)
        self.assertLess(chain.index("udp dport 443"), chain.index(f"meta mark set {nftgen.mark_for(1):#x}"))

    def test_exit_with_quic_untouched(self):
        r = nftgen.generate("awg0", {}, [UP], {"rules": [], "default": 1}, {})
        self.assertNotIn("udp dport 443", r.split("chain o_u1 {")[1].split("}")[0])

    def test_sticky_keeps_live_connections_first(self):
        """Балансировка: соединение, уже записанное на рабочий выход, доживает на нём; отказ — новым."""
        r = nftgen.generate("awg0", {}, [{**UP, "no_quic": True}, {**UP, "num": 2}],
                            {"rules": [], "default": nftgen.Sticky(1)}, {}, None, {1, 2})
        chain = r.split("chain ob_u1 {")[1].split("}\n")[0]
        self.assertLess(chain.index("ct mark {"), chain.index("udp dport 443"))
        self.assertNotIn("udp dport 443", r.split("chain ob_u2 {")[1].split("}\n")[0])


class SocksQuicApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        panel.engine.reconcile()

    def setUp(self):
        self.ids = []

    def tearDown(self):
        for uid in self.ids:
            if Store.upstream(panel.store.snapshot(), uid):
                exits.del_upstream(Req({"replace": "direct"}), uid)

    def add(self, **kw):
        uid = exits.add_upstream(Req({"name": "P", "config": "socks5://198.51.100.9:1080", **kw}))["id"]
        self.ids.append(uid)
        return uid

    def view(self, uid):
        return next(u for u in state.get_state(None)["upstreams"] if u["id"] == uid)

    def test_off_by_default(self):
        uid = self.add()
        self.assertIs(self.view(uid)["quic"], False)
        ups = {u["num"]: u for u in panel.engine._up_list(panel.store.snapshot())}
        num = Store.upstream(panel.store.snapshot(), uid)["num"]
        if num in ups:                      # выход запущен (в демо — да)
            self.assertTrue(ups[num]["no_quic"])

    def test_turn_on_and_off(self):
        uid = self.add(quic=True)
        self.assertIs(self.view(uid)["quic"], True)
        exits.edit_upstream(Req({"quic": False}), uid)
        self.assertNotIn("quic", Store.upstream(panel.store.snapshot(), uid))
        exits.edit_upstream(Req({"quic": True}), uid)
        self.assertTrue(Store.upstream(panel.store.snapshot(), uid)["quic"])

    def test_bad_value(self):
        with self.assertRaises(web.HTTPError):
            self.add(quic="yes")

    def test_awg_exit_ignores_it(self):
        up = ("[Interface]\nAddress = 10.9.0.7/32\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\n"
              "[Peer]\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\nAllowedIPs = 0.0.0.0/0\n"
              "Endpoint = 198.51.100.7:51820\n")
        uid = exits.add_upstream(Req({"name": "A", "config": up, "quic": True}))["id"]
        self.ids.append(uid)
        self.assertNotIn("quic", Store.upstream(panel.store.snapshot(), uid))
        self.assertIs(self.view(uid)["quic"], True)          # AWG пропускает QUIC всегда

    def test_rule_quic_mark(self):
        """Первый пакет QUIC к сайту из правила на SOCKS5: с галочкой — в туннель выхода, без — отказ."""
        uid = self.add()
        st = panel.store.snapshot()
        u = Store.upstream(st, uid)
        with mock.patch.object(panel.engine, "resolve", return_value=u["num"]):
            self.assertEqual(panel.engine._quic_mark(st, "up:" + uid), config.MARK_BLOCK)
            exits.edit_upstream(Req({"quic": True}), uid)
            st = panel.store.snapshot()
            self.assertEqual(panel.engine._quic_mark(st, "up:" + uid), nftgen.mark_for(u["num"]))

    def test_restore_keeps_only_for_socks(self):
        st = backup.clean_backup_state({
            "upstreams": [{"id": "u000001", "name": "S", "num": 1, "config": "socks5://198.51.100.9:1080", "quic": True},
                          {"id": "u000002", "name": "S2", "num": 2, "config": "socks5://198.51.100.8:1080", "quic": "1"}],
            "routing": {"default": "direct", "rules": []}})
        self.assertTrue(st["upstreams"][0]["quic"])
        self.assertNotIn("quic", st["upstreams"][1])


# ------------------------------------------------------------------ проверка выхода (probe.py)
class ProbeTest(unittest.TestCase):
    def test_quic_packet(self):
        p = probe.quic_probe()
        self.assertEqual(len(p), 1200)            # меньше 1200 байт сервер QUIC не отвечает
        self.assertTrue(p[0] & 0xC0 == 0xC0)      # длинный заголовок, бит «фиксированный»
        self.assertEqual(p[1:5], bytes.fromhex("1a2a3a4a"))
        self.assertEqual(p[5], 8)

    def test_udp_ok_with_version_negotiation(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        self.addCleanup(srv.close)

        def answer():
            data, addr = srv.recvfrom(2048)
            srv.sendto(bytes([0x80]) + b"\x00\x00\x00\x00" + data[5:30] + b"\x00\x00\x00\x01", addr)
        threading.Thread(target=answer, daemon=True).start()
        real = probe.sock
        port = srv.getsockname()[1]
        with mock.patch.object(probe, "sock", lambda h, p, t=6, k=socket.SOCK_STREAM: real("127.0.0.1", port, t, k)):
            self.assertTrue(probe.udp_ok(timeout=2))

    def test_udp_silent(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        self.addCleanup(srv.close)
        real = probe.sock
        port = srv.getsockname()[1]
        with mock.patch.object(probe, "sock", lambda h, p, t=6, k=socket.SOCK_STREAM: real("127.0.0.1", port, t, k)):
            self.assertFalse(probe.udp_ok(timeout=0.2))

    def test_latency_is_time_to_first_answer(self):
        """Не время connect(): у SOCKS5 его принимает сам hev-socks5-tunnel (0 мс)."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        self.addCleanup(srv.close)

        def serve():
            c, _ = srv.accept()
            c.recv(10)
            time.sleep(0.15)
            c.sendall(b"\x15")
            c.close()
        threading.Thread(target=serve, daemon=True).start()
        ms = probe.answer_ms("127.0.0.1", srv.getsockname()[1], timeout=3)
        self.assertGreaterEqual(ms, 140)

    def test_whoami_order_and_errors(self):
        calls = []

        def get(host, path, tls=False):
            calls.append((host, tls))
            if host == "1.1.1.1":
                return "fl=1\nip=198.51.100.4\nloc=NL\n"
            raise OSError("no")
        with mock.patch.object(probe, "http_get", get):
            self.assertEqual(probe.whoami(), {"ip": "198.51.100.4", "cc": "NL"})
        self.assertEqual(calls, [("1.1.1.1", True)])

        def bad(host, path, tls=False):
            raise OSError(f"{host} down")
        with mock.patch.object(probe, "http_get", bad):
            with self.assertRaises(OSError) as cm:
                probe.whoami()
        self.assertIn("1.1.1.1", str(cm.exception))
        self.assertIn("ifconfig.me", str(cm.exception))

    def test_no_ip_text_shows_detail(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "static", "i18n.js"), encoding="utf-8") as f:
            i18n = f.read()
        self.assertEqual(i18n.count('"probe.no_ip": "'), 4)
        for line in i18n.split("\n"):
            if '"probe.no_ip": "' in line:
                self.assertIn("{detail}", line.split('"probe.no_ip": "')[1].split('"')[0])

    def test_engine_asks_udp_for_socks_only(self):
        eng = engine.Engine.__new__(engine.Engine)
        eng.target = mock.Mock(pid=1)
        eng.target.ns.return_value = mock.Mock(stdout='{"ok": true, "ip": "198.51.100.1", "udp": false}', stderr="")
        eng.store = mock.Mock()
        eng.store.snapshot.return_value = {"upstreams": [{"num": 3, "config": "socks5://198.51.100.9:1080"},
                                                         {"num": 4, "config": "x"}]}
        eng._parsed = {}
        from app import awgconf
        eng.parsed = lambda u: awgconf.parse_upstream(u["config"]) if u["num"] == 3 else mock.Mock(kind="awg")
        for num, want in ((3, True), (4, False)):
            eng.resolve = lambda out, st, n=num: n
            with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(awgconf, "resolve_many", return_value={}):
                res = eng.probe("up:x")
            self.assertEqual("--udp" in eng.target.ns.call_args.args[0], want)
        self.assertIs(res["udp"], False)


# ------------------------------------------------------------------ присмотр за sniproxy.py
class SniHeartbeatTest(unittest.TestCase):
    def test_beat_creates_and_touches(self):
        d = tempfile.mkdtemp()
        s = sniproxy.Sniffer.__new__(sniproxy.Sniffer)
        s.cfg = {"beat": os.path.join(d, "beat")}
        s.beat()
        self.assertTrue(os.path.exists(s.cfg["beat"]))
        os.utime(s.cfg["beat"], (1, 1))
        s.beat()
        self.assertGreater(os.stat(s.cfg["beat"]).st_mtime, time.time() - 5)

    def test_beat_without_path(self):
        s = sniproxy.Sniffer.__new__(sniproxy.Sniffer)
        s.cfg = {}
        s.beat()

    def test_watch_wakes_on_dead_process(self):
        eng = engine.Engine.__new__(engine.Engine)
        eng.stop_ev, eng.wake = threading.Event(), threading.Event()
        proc = mock.Mock()
        proc.poll.return_value = 1
        eng.sni = engine.HelperRT(proc, "k", "h")
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(engine.sni, "SNI_WATCH_EVERY", 0.01):
            th = threading.Thread(target=eng._watch_sni, daemon=True)
            th.start()
            self.assertTrue(eng.wake.wait(2))
            eng.stop_ev.set()
            th.join(2)

    def test_watch_kills_hung_process(self):
        eng = engine.Engine.__new__(engine.Engine)
        eng.stop_ev, eng.wake = threading.Event(), threading.Event()
        proc = mock.Mock()
        proc.poll.return_value = None
        eng.sni = engine.HelperRT(proc, "k", "h")
        eng.sni.started = time.time() - 600
        open(engine.sni.SNI_BEAT, "a").close()
        os.utime(engine.sni.SNI_BEAT, (time.time() - 300, time.time() - 300))
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(engine.sni, "SNI_WATCH_EVERY", 0.01):
            th = threading.Thread(target=eng._watch_sni, daemon=True)
            th.start()
            self.assertTrue(eng.wake.wait(2))
            eng.stop_ev.set()
            th.join(2)
        proc.kill.assert_called()
        os.utime(engine.sni.SNI_BEAT)

    def test_engine_passes_beat_path(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "engine", "sni.py"), encoding="utf-8") as f:
            src = f.read()
        self.assertIn('"beat": SNI_BEAT', src)


# ------------------------------------------------------------------ блок при неработающих правилах по доменам
DPOL = {"rules": [], "default": "direct", "domain": [(["d1"], "up:u1")]}


class StrictNftTest(unittest.TestCase):
    def test_domain_clients_blocked_without_handler(self):
        r = nftgen.generate("awg0", {}, [UP], DPOL, {"10.8.1.5": {"rules": [], "default": 1}}, None, strict=True)
        g = r.split("chain p_global {")[1].split("}")[0]
        self.assertEqual(g.strip(), "goto o_block")
        other = r.split("chain p_1 {")[1].split("}")[0]
        self.assertIn("goto o_u1", other)            # у клиента без правил по доменам — как обычно
        # местные сети и сам сервер — раньше политики
        pre = r.split("chain c_prerouting {")[1].split("}")[0]
        self.assertLess(pre.index("@local4 return"), pre.index("goto p_global"))

    def test_not_when_handler_works(self):
        r = nftgen.generate("awg0", {}, [UP], DPOL, {}, config.SNI_PROXY_PORT, strict=True)
        self.assertIn(f"meta mark set {config.SNIFF_MARK:#x}", r.split("chain p_global {")[1].split("\n\t}")[0])

    def test_not_without_setting(self):
        r = nftgen.generate("awg0", {}, [UP], DPOL, {}, None)
        self.assertIn("goto o_direct", r.split("chain p_global {")[1].split("}")[0])


class StrictEngineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        panel.engine.reconcile()

    def setUp(self):
        st = panel.store.snapshot()
        self._routing = json.loads(json.dumps(st["routing"]))

    def tearDown(self):
        r = self._routing
        panel.store.mutate(lambda st: st.update(routing=r))
        panel.engine.reconcile()

    def test_api_and_state(self):
        r = dict(self._routing)
        routing.put_routing(Req({**r, "strict": True}))
        self.assertTrue(panel.store.snapshot()["routing"]["strict"])
        routing.put_routing(Req({"default": r["default"], "rules": r["rules"]}))       # без поля — как было
        self.assertTrue(panel.store.snapshot()["routing"]["strict"])
        routing.put_routing(Req({**r, "strict": False}))
        self.assertNotIn("strict", panel.store.snapshot()["routing"])
        with self.assertRaises(web.HTTPError):
            routing.put_routing(Req({**r, "strict": "on"}))

    def test_blocked_only_with_domain_rules_and_no_handler(self):
        e = panel.engine
        st = {"routing": {"strict": True}}
        with mock.patch.object(e, "_policies", return_value=(DPOL, {})):
            self.assertTrue(e.strict_blocked(st, None))
            self.assertFalse(e.strict_blocked(st, config.SNI_PROXY_PORT))
            self.assertFalse(e.strict_blocked({"routing": {}}, None))
        with mock.patch.object(e, "_policies", return_value=({"rules": [], "default": "direct", "domain": []}, {})):
            self.assertFalse(e.strict_blocked(st, None))

    def test_events_on_change(self):
        e = panel.engine
        events = []
        with mock.patch.object(e, "event", lambda lvl, m: events.append(m.key)), \
                mock.patch.object(e, "strict_blocked", return_value=True):
            e.reconcile()
            e.reconcile()
        self.assertEqual(events.count("ev.dom_strict_on"), 1)
        self.assertTrue(panel.engine.strict_on)
        with mock.patch.object(e, "event", lambda lvl, m: events.append(m.key)), \
                mock.patch.object(e, "strict_blocked", return_value=False):
            e.reconcile()
        self.assertEqual(events[-1], "ev.dom_strict_off")

    def test_backup_keeps_it(self):
        st = backup.clean_backup_state({"routing": {"default": "direct", "rules": [], "strict": True}})
        self.assertTrue(st["routing"]["strict"])
        st = backup.clean_backup_state({"routing": {"default": "direct", "rules": [], "strict": "yes"}})
        self.assertNotIn("strict", st["routing"])

    def test_telegram_texts(self):
        from app import notify
        for k in ("ev.dom_strict_on", "ev.dom_strict_off"):
            kind, text = notify.ENGINE_EVENTS[k]
            self.assertEqual(kind, "server")
            for lang in ("ru", "en", "zh", "fa"):
                self.assertIn(text, notify.TEXTS[lang])


if __name__ == "__main__":
    unittest.main()
