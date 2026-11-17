"""1.21.0, вторая проверка (2026-11-16): поведение, которое раньше не закрепляли тесты. Каждый тест здесь
проходил на проверенном коде и падал на нарочно испорченном (вход, сессии, записи на диск, копии, правила
nftables, учёт трафика); в комментарии у теста — номер такой порчи из проверки.

python3 -m unittest discover tests
"""
import http.client
import os
import shutil
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))      # tests/test_api.py

from app import awgserver, store, totp, web  # noqa: E402
from app.api import auth, backup  # noqa: E402
from app.web import HTTPError  # noqa: E402


class Req:
    def __init__(self, body=None, ip="203.0.113.99", headers=None, cookies=None, method="POST", path=None):
        self.body = body or {}
        self.client_ip = ip
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.method = method
        self.path = path or auth.BASE + "/api/thing"
        self.set_cookies = []

    def json(self, limit=None):
        return self.body

    def cookie(self, name, value, *, max_age, path, secure=False):
        self.set_cookies.append((name, value, secure))


def code(fn):
    try:
        fn()
    except HTTPError as e:
        return e.code, getattr(e.detail, "key", None)
    return 200, None


class Isolated(unittest.TestCase):
    """Своё место для panel_password.json и totp.json; без пауз после неверного пароля."""

    def setUp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        for p in (mock.patch.object(auth, "PW_FILE", os.path.join(d, "pw.json")),
                  mock.patch.object(totp, "PATH", os.path.join(d, "totp.json")),
                  # не time.sleep целиком: на него опираются потоки сервера (http-deadline) и других тестов
                  mock.patch.object(auth, "time", types.SimpleNamespace(time=time.time, sleep=lambda s: None)),
                  mock.patch.object(auth.notifier, "event")):
            p.start()
            self.addCleanup(p.stop)
        auth._pw_cache = (None, None)
        totp._cache = (None, None)
        auth._fails.clear()
        auth._inflight.clear()
        self.addCleanup(auth._fails.clear)

    def signed(self, exp: int, tag: str) -> str:
        e = str(exp)
        return f"{e}.{tag}.{auth._sign(e + tag)}"


class SessionTest(Isolated):
    def test_signature_is_checked(self):                                    # A7
        exp, tag, _ = auth.make_session().split(".")
        self.assertFalse(auth.check_session(f"{exp}.{tag}.{'0' * 32}"))

    def test_expired_session_refused(self):                                 # A8
        s = auth.make_session()
        with mock.patch.object(auth.time, "time", return_value=time.time() + auth.SESSION_TTL + 5):
            self.assertFalse(auth.check_session(s))

    def test_signed_cookie_with_old_tag_refused(self):                      # A9
        self.assertFalse(auth.check_session(self.signed(int(time.time()) + 60, "deadbeef")))

    def test_password_change_logs_out_everywhere(self):                     # A9 (behaviour)
        s = auth.make_session()
        auth.set_password("a-new-password-1")
        self.assertFalse(auth.check_session(s))

    def test_cookie_longer_than_ttl_refused(self):                          # A10
        self.assertFalse(auth.check_session(self.signed(int(time.time()) + 7 * 86400, auth.sec_tag())))

    def test_new_2fa_secret_does_not_revive_old_sessions(self):            # A21
        totp.save({"secret": totp.new_secret(), "since": 0, "last_step": -1})
        s = auth.make_session()
        totp.save(None)
        totp.save({"secret": totp.new_secret(), "since": 0, "last_step": -1})
        self.assertFalse(auth.check_session(s))

    def test_enabling_2fa_logs_out_everywhere(self):                        # A21
        s = auth.make_session()
        totp.save({"secret": totp.new_secret(), "since": 0, "last_step": -1})
        self.assertFalse(auth.check_session(s))

    def test_malformed_cookie_is_just_refused(self):                        # AU1
        for v in ("", "a", "1.2", "1.2.3.4", "x.y.z"):
            self.assertFalse(auth.check_session(v))


class LoginTest(Isolated):
    def test_password_then_wrong_and_right_code(self):                     # A14
        secret = totp.new_secret()
        totp.save({"secret": secret, "since": 0, "last_step": -1})
        r = Req({"password": auth.PASSWORD})
        self.assertEqual(auth.login(r), {"ok": False, "need_code": True})
        self.assertEqual(r.set_cookies, [])
        good = totp.code_at(secret, int(time.time() // totp.STEP))
        wrong = "%06d" % ((int(good) + 1) % 10 ** 6)
        r = Req({"password": auth.PASSWORD, "code": wrong})
        self.assertEqual(code(lambda: auth.login(r)), (403, "err.wrong_code"))
        self.assertEqual(r.set_cookies, [])
        r = Req({"password": auth.PASSWORD, "code": good})
        self.assertEqual(auth.login(r), {"ok": True})
        self.assertEqual(r.set_cookies[0][0], auth.COOKIE)

    def test_password_set_in_panel_replaces_env_one(self):                 # A6
        auth.set_password("a-new-password-1")
        for pw in ("wrong-password", auth.PASSWORD):                      # и прежний из .env больше не подходит
            self.assertEqual(code(lambda pw=pw: auth.login(Req({"password": pw}))), (403, "err.wrong_password"), pw)
        self.assertEqual(auth.login(Req({"password": "a-new-password-1"})), {"ok": True})

    def test_wrong_password_sets_no_cookie(self):                          # A5 (behaviour)
        r = Req({"password": "nope"})
        self.assertEqual(code(lambda: auth.login(r)), (403, "err.wrong_password"))
        self.assertEqual(r.set_cookies, [])

    def test_disable_2fa_needs_code(self):                                  # A15
        totp.save({"secret": totp.new_secret(), "since": 0, "last_step": -1})
        self.assertEqual(code(lambda: auth.totp_disable(Req({"code": "000000"}))), (403, "err.wrong_code"))
        self.assertIsNotNone(totp.load())

    def test_change_password_needs_current_and_length(self):               # A16, A17
        self.assertEqual(code(lambda: auth.change_password(Req({"current": "nope", "new": "long-enough-1"}))),
                         (403, "err.wrong_password"))
        self.assertFalse(os.path.exists(auth.PW_FILE))
        for new in ("short", "x" * 129):
            self.assertEqual(code(lambda: auth.change_password(Req({"current": auth.PASSWORD, "new": new}))),
                             (400, "err.pw_length"))
        self.assertFalse(os.path.exists(auth.PW_FILE))

    def test_totp_setup_expires(self):                                      # A20
        auth._totp_pending.clear()
        auth._totp_pending.update(secret=totp.new_secret(), t=time.time() - 1801)
        c = totp.code_at(auth._totp_pending["secret"], int(time.time() // totp.STEP))
        self.assertEqual(code(lambda: auth.totp_enable(Req({"code": c, "password": auth.PASSWORD}))),
                         (400, "err.totp_expired"))
        self.assertIsNone(totp.load())

    def test_secure_cookie_behind_https_proxy(self):                        # A22
        r = Req(headers={"X-Forwarded-Proto": "https"})
        auth._set_session(r)
        self.assertTrue(r.set_cookies[0][2])

    def test_secret_files_are_private(self):                                # A24, A25, S9
        auth.set_password("a-new-password-1")
        self.assertEqual(os.stat(auth.PW_FILE).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.join(auth.config.DATA_DIR, "session.key")).st_mode & 0o777, 0o600)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        s = store.Store(os.path.join(d, "state.json"))
        s.mutate(lambda st: st["keys"].__setitem__("k", "private"))
        self.assertEqual(os.stat(s.path).st_mode & 0o777, 0o600)

    def test_form_body_refused(self):                                       # A18
        r = Req(headers={"Content-Length": "5", "Content-Type": "text/plain", "Sec-Fetch-Site": "same-origin"},
                cookies={auth.COOKIE: auth.make_session()})
        self.assertEqual(code(lambda: auth.auth_mw(r)), (415, "err.json_required"))


class StaticTest(unittest.TestCase):
    """Файлы панели отдаются без проверки входа: выйти за каталог нельзя, открытые — только из списка."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        os.makedirs(os.path.join(self.d, "static"))
        with open(os.path.join(self.d, "secret.txt"), "w") as f:
            f.write("PRIVATE")
        for n in ("a.css", "b.css"):
            with open(os.path.join(self.d, "static", n), "w") as f:
                f.write("body{}")
        a = web.App("/base")
        a.static = ("/base/static", os.path.join(self.d, "static"))
        a.public_static = ("/s/assets", os.path.join(self.d, "static"))
        a.public_files = {"a.css"}
        self.srv = a.serve("127.0.0.1", 0)
        import threading
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=5)
        try:
            c.request("GET", path)
            r = c.getresponse()
            return r.status, r.read(), dict(r.getheaders())
        finally:
            c.close()

    def test_no_way_out_of_static(self):                                    # W4
        for p in ("/base/static/%2e%2e/secret.txt", "/base/static/..%2fsecret.txt", "/base/static/../secret.txt"):
            status, body, _ = self.get(p)
            self.assertEqual(status, 404, p)
            self.assertNotIn(b"PRIVATE", body)

    def test_public_files_only_listed(self):                                # W5
        self.assertEqual(self.get("/s/assets/a.css")[0], 200)
        self.assertEqual(self.get("/s/assets/b.css")[0], 404)

    def test_frame_options(self):                                           # W8
        self.assertEqual(self.get("/base/static/a.css")[2].get("X-Frame-Options"), "DENY")


class DurableWritesTest(unittest.TestCase):
    """Запись целиком и на диск: os.fsync до os.replace (state.json, конфиг сервера)."""

    def test_state_fsynced_before_replace(self):                            # S1
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        s = store.Store(os.path.join(d, "state.json"))
        events = []
        real_fsync, real_replace = os.fsync, os.replace
        with mock.patch.object(store.os, "fsync", side_effect=lambda fd: (events.append("fsync"), real_fsync(fd))[1]), \
                mock.patch.object(store.os, "replace", side_effect=lambda a, b: (events.append(("replace", os.path.basename(b))), real_replace(a, b))[1]):
            s.mutate(lambda st: st["settings"].__setitem__("x", 1))
        self.assertIn("fsync", events)
        self.assertLess(events.index("fsync"), events.index(("replace", "state.json")))

    def test_server_file_replaced_whole(self):                              # SY2
        from app import system
        t = system.DemoTarget()
        with mock.patch.object(system.os, "replace", wraps=os.replace) as r:
            t.write_file("/tmp/x.conf", "[Interface]\n")
        self.assertTrue(r.called)
        self.assertEqual(r.call_args.args[1], t.host_path("/tmp/x.conf"))
        self.assertNotEqual(r.call_args.args[0], r.call_args.args[1])

    def test_server_file_fsynced(self):                                     # SY1
        from app import system
        t = system.DemoTarget()
        with mock.patch.object(system.os, "fsync", wraps=os.fsync) as fs:
            t.write_file("/tmp/x.conf", "[Interface]\n")
        self.assertTrue(fs.called)


class BackupIdsTest(unittest.TestCase):
    def bad(self, fn):
        import test_api
        s = test_api.good_state()
        fn(s)
        with self.assertRaises(HTTPError):
            backup.clean_backup_state(s)

    def bad_id(self, bad_id):
        import json
        import test_api
        s = json.loads(json.dumps(test_api.good_state()).replace("u000001", bad_id))   # id и все ссылки на него
        with self.assertRaises(HTTPError, msg=bad_id) as cm:
            backup.clean_backup_state(s)
        self.assertEqual(cm.exception.detail.p["field"], "upstreams[0]", bad_id)

    def test_exit_id_and_num(self):                                         # C7, C8
        backup.clean_backup_state(__import__("test_api").good_state())     # исходная копия годится
        for bad_id in ("U0", "u-1", "a" * 25, "u 1", "u}x"):    # id выхода — короткое имя [a-z0-9_]
            self.bad_id(bad_id)
        for n in (0, 201, 54_000, True):
            self.bad(lambda s, n=n: s["upstreams"][0].__setitem__("num", n))

    def test_country_code(self):                                            # C10
        # у страны id списка = код страны (api/routing.add_list): он идёт в имя набора nftables и файла
        from app import checks
        for src in ("../../etc/x", "ru}", "r u", "rus", "1a"):
            with self.assertRaises(HTTPError, msg=src) as cm:
                checks.list_fields({"kind": "country", "source": src})
            self.assertEqual(cm.exception.detail.key, "err.country_code", src)


class HostInputTest(unittest.TestCase):
    def test_public_host_is_one_plain_token(self):                          # U1
        # адрес панели идёт в server_name файла nginx на хосте (webfront.snippet) и в конфиги клиентов
        from app import users
        for bad in ("p.example.com;\nlocation / { return 200; }", "a b", "x\ny", "$(id)", "a/b"):
            with self.assertRaises(users.UserError, msg=bad):
                users.check_public_host(bad)
        self.assertEqual(users.check_public_host(" [2001:db8::1] "), "2001:db8::1")

    def test_backup_client_host_whole_value(self):                          # C14
        from app import checks
        for bad in ("1.2.3.4\nPostUp = id", "1.2.3.4 x", ""):
            with self.assertRaises(HTTPError, msg=bad):
                checks.host_text(bad)


class ServerSettingsTest(unittest.TestCase):
    """users.update_server на своей цели (как SubnetNatTest в test_v1122): порт и подсеть."""
    PRIV = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="

    def run_update(self, kind, body):
        from app import panel, system, users
        t = system.DemoTarget()
        t.kind = kind
        t.conf_path = "/etc/test1/awg0.conf"
        t.write_file(t.conf_path, awgserver.new_server(self.PRIV, 51820, "10.8.1.0/24", {}).render())
        old, panel.engine.target = panel.engine.target, t
        try:
            with mock.patch.object(system, "open_firewall_udp"):
                panel.engine.srv.update_server(body)
            return None, t
        except users.UserError as e:
            return e.msg.key, t
        finally:
            panel.engine.target = old

    def test_port_53_refused_on_host(self):                                 # U9
        key, t = self.run_update("host", {"port": 53})
        self.assertEqual(key, "srv.port_dns")
        self.assertIn("ListenPort = 51820", t.read_file(t.conf_path))

    def test_container_port_is_dockers(self):                               # U10
        key, t = self.run_update("container", {"port": 40000})
        self.assertEqual(key, "srv.port_container")

    def test_tiny_subnet_refused(self):                                     # U11
        for net in ("10.66.0.1/30", "10.66.0.1/32"):
            key, t = self.run_update("host", {"address": net})
            self.assertEqual(key, "srv.bad_subnet", net)
            self.assertIn("10.8.1.1/24", t.read_file(t.conf_path))


class ClientKeysTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app import panel
        panel.engine.reconcile()                    # демо-сервер (DRY_RUN) — цель для клиентов

    def test_deleted_client_key_forgotten(self):                            # U16
        from app import panel
        pk = panel.engine.srv.add_client("TEST1 gone")
        self.assertIn(pk, panel.store.snapshot()["keys"])
        panel.engine.srv.delete_client(pk)
        self.assertNotIn(pk, panel.store.snapshot()["keys"])

    def test_failed_add_leaves_no_key(self):                                # U8
        from app import panel, users
        before = dict(panel.store.snapshot()["keys"])
        with mock.patch.object(users.ServerManager, "_write", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                panel.engine.srv.add_client("TEST1 fail")
        self.assertEqual(panel.store.snapshot()["keys"], before)


class ParamsTest(unittest.TestCase):
    def test_int_params_bounded(self):                                      # AS10
        for k in ("Jc", "S1", "S4"):
            with self.assertRaises(awgserver.ServerConfError, msg=k):
                awgserver.validate_params({k: "70000"})


class ServerConfTest(unittest.TestCase):
    def test_restored_hooks_dropped_on_host_too(self):                      # AS6
        sc = awgserver.parse("[Interface]\nPrivateKey = x\nAddress = 10.8.1.1/24\nPreUp = id\nPreDown = id\n")
        awgserver.safe_hooks(sc, True)
        self.assertFalse([k for k, _ in sc.iface if k in ("PreUp", "PreDown")])


# ------------------------------------------------------------------ маршрутизация (то, что сейчас ловят только e2e)
UPS = [{"num": 1, "snat": "10.9.0.2", "mtu": 1280}]


def chain(text, name):
    c = text[text.index(f"chain {name} {{"):]
    return c[:c.index("\n\t}")]


class NftBlockTest(unittest.TestCase):
    def test_block_is_marked_and_rejected(self):                            # N4, N5
        from app import config, nftgen
        text = nftgen.generate("awg0", {}, UPS, {"rules": [], "default": "block"}, {})
        self.assertIn(f"meta mark set {config.MARK_BLOCK:#x} accept", chain(text, "o_block"))
        self.assertIn(f"meta mark {config.MARK_BLOCK:#x} reject", chain(text, "c_forward"))

    def test_only_client_interface_is_policed(self):                        # N21
        from app import nftgen
        text = nftgen.generate("awg0", {}, UPS, {"rules": [], "default": 1}, {})
        lines = chain(text, "c_prerouting").splitlines()
        self.assertEqual(lines[2].strip(), 'iifname != "awg0" return')       # первая строка после type

    def test_quic_chain_runs_before_policy(self):                           # N19
        import re
        from app import nftgen
        gp = {"rules": [], "default": 1, "domain": [(["d1"], 1)]}
        text = nftgen.generate("awg0", {}, UPS, gp, {}, 8443, quic=True)
        prio = lambda name: re.search(r"priority mangle( [-+] \d+)?;", chain(text, name)).group(1) or ""
        val = lambda p: int(p.replace(" ", "")) if p else 0
        self.assertLess(val(prio("c_quic")), val(prio("c_prerouting")))

    def test_trailing_rules_only(self):                                     # N8
        from app import nftgen
        pol, _ = nftgen.layout({"rules": [(["a"], "direct"), (["b"], 1)], "default": 1}, {}, {1})
        self.assertEqual(pol["p_global"]["rules"], [(["a"], "direct")])


class ResolveTest(unittest.TestCase):
    def test_unknown_is_block(self):                                        # R4, R5
        from app.engine import Engine
        e = Engine.__new__(Engine)
        e.health = {}
        st = {"upstreams": []}
        self.assertEqual(e.resolve("up:gone", st), "block")
        self.assertEqual(e.resolve("nonsense", st), "block")


class SyncRulesTest(unittest.TestCase):
    def test_rule_with_foreign_mark_replaced(self):                         # R7
        import json
        from app import config, engine, nftgen
        e = engine.Engine.__new__(engine.Engine)
        e.rt = {"u1": engine.UpRT(1, "h", "k")}
        calls = []
        have = json.dumps([{"priority": config.RULE_PRIO_BASE + 1, "table": str(config.TABLE_BASE + 1),
                            "fwmark": "0x9999"}])
        t = mock.Mock(key="k1")
        t.ns = lambda cmd, check=True, input=None, **kw: (calls.append(input), mock.Mock(
            returncode=0, stdout=have if cmd[:3] == ["ip", "-j", "rule"] else "", stderr=""))[1]
        e._sync_rules(t)
        batch = [c for c in calls if c][0].splitlines()
        self.assertIn(f"rule del priority {config.RULE_PRIO_BASE + 1}", batch)
        self.assertIn(f"rule add fwmark {hex(nftgen.mark_for(1))} lookup {config.TABLE_BASE + 1} "
                      f"priority {config.RULE_PRIO_BASE + 1}", batch)


class HoldRulesetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app import panel
        panel.engine.reconcile()

    def test_hold_rules_have_no_exit_marks(self):                           # R10
        from app import nftgen, panel
        from app.store import Store
        e = panel.engine
        up = ("[Interface]\nAddress = 10.9.0.2/32\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\n"
              "[Peer]\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\nAllowedIPs = 0.0.0.0/0\n"
              "Endpoint = 198.51.100.1:51820\n")
        st = e.store.snapshot()
        num = Store.free_num(st)
        st["upstreams"].append({"id": "uhold1", "name": "H", "num": num, "config": up, "enabled": True,
                                "fallback": "block"})
        st["routing"]["default"] = "up:uhold1"
        with mock.patch.dict(e.rt, {"uhold1": e.rt.get("uhold1") or mock.Mock(num=num, iface=f"awgr{num}")}), \
                mock.patch.dict(e.health, {"uhold1": {"healthy": True}}):
            live = e.build_ruleset(e.target, st, None)
            hold = e.build_ruleset(e.target, st, None, hold=True)
        mark = f"meta mark set {nftgen.mark_for(num):#x}"
        self.assertIn(mark, live)                       # с туннелем — через выход
        self.assertNotIn(mark, hold)                    # «до панели» туннеля нет: блок, а не метка без ip rule


class MonthTest(unittest.TestCase):
    def test_month_is_utc(self):                                            # TR1
        from app import traffic
        old = os.environ.get("TZ")
        os.environ["TZ"] = "Asia/Tokyo"
        time.tzset()
        try:
            self.assertEqual(traffic.month_key(1796069400), "2026-11")       # 2026-11-30 20:10 UTC = 1 дек. в Токио
        finally:
            if old is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old
            time.tzset()


class SniCountTest(unittest.TestCase):
    def test_new_process_counted_from_zero(self):                           # TR9
        from app.traffic import Traffic
        tr = Traffic(os.path.join(tempfile.mkdtemp(), "t.json"))
        tr.update_sni(100, {"10.8.1.2|u1": [15, 300]}, {"u1"}, {})
        tr.update_sni(200, {"10.8.1.2|u1": [20, 400]}, {"u1"}, {})         # новый процесс, уже больше прежнего
        self.assertEqual(tr.out_month("u1"), [35, 700])


class CookieTest(unittest.TestCase):
    def test_session_cookie_attributes(self):                               # W21
        r = type("R", (), {"set_cookies": []})()
        web.Request.cookie(r, "awgr_session", "v", max_age=60, path="/p")
        parts = r.set_cookies[0].split("; ")
        self.assertIn("HttpOnly", parts)
        self.assertIn("SameSite=Strict", parts)


class ExitConfigTest(unittest.TestCase):
    KEY = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
    PUBK = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="

    def conf(self, iface_extra="", priv=None, peers=1, ifaces=1):
        i = f"[Interface]\nAddress = 10.9.0.2/32\nPrivateKey = {priv or self.KEY}\n{iface_extra}\n"
        p = f"[Peer]\nPublicKey = {self.PUBK}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.1:51820\n\n"
        return i * ifaces + p * peers

    def err(self, text):
        from app import awgconf
        with self.assertRaises(awgconf.ConfigError) as cm:
            awgconf.parse_upstream(text)
        return cm.exception.msg.key

    def test_structure_and_keys(self):                                      # AC9, AC11, AC12
        self.assertEqual(self.err(self.conf(priv="not-a-key")), "cfg.bad_privkey")
        self.assertEqual(self.err(self.conf(ifaces=2)), "cfg.one_interface")
        self.assertEqual(self.err(self.conf(peers=2)), "cfg.many_peers")

    def test_mtu_clamped(self):                                             # AC13
        from app import awgconf
        self.assertEqual(awgconf.parse_upstream(self.conf("MTU = 9000")).mtu, 1500)
        self.assertEqual(awgconf.parse_upstream(self.conf("MTU = 576")).mtu, 1100)

    def test_vpn_link_inflated_with_a_limit(self):                          # AC5
        import base64
        import struct
        import zlib
        from app import awgconf
        seen = []
        real = zlib.decompressobj

        class D:
            def __init__(self):
                self.d = real()

            def decompress(self, data, max_length=0):
                seen.append(max_length)
                return self.d.decompress(data, max_length)

            @property
            def eof(self):
                return self.d.eof
        raw = b'{"x": "' + b"0" * 1000 + b'"}'
        link = "vpn://" + base64.urlsafe_b64encode(struct.pack(">I", len(raw)) + zlib.compress(raw)).decode()
        with mock.patch.object(awgconf.zlib, "decompressobj", D):
            with self.assertRaises(awgconf.ConfigError):
                awgconf.parse_upstream(link)
        self.assertTrue(seen and all(0 < n <= awgconf.LINK_MAX + 1 for n in seen), seen)


class BackupTelegramTest(unittest.TestCase):
    def test_no_bot_control_from_username_chat(self):                       # C12
        import test_api
        s = test_api.good_state()
        s["settings"]["telegram"].update(chat_id="@some_channel", control=True)
        self.assertFalse(backup.clean_backup_state(s)["settings"]["telegram"]["control"])


class JsonBodyTest(unittest.TestCase):
    def test_body_must_be_an_object(self):                                  # W16
        import io

        class H:
            headers = {"Content-Length": "6"}
            rfile = io.BytesIO(b"[1, 2]")
            server = None
            connection = None
            body_read = False
        req = web.Request.__new__(web.Request)
        req.h, req.headers, req._body = H(), H.headers, None
        with self.assertRaises(HTTPError) as cm:
            req.json()
        self.assertEqual(cm.exception.code, 400)


class ReapplyMissingTableTest(unittest.TestCase):
    def test_table_deleted_outside_is_put_back(self):                       # E1
        from app import panel
        e = panel.engine
        e.reconcile()
        t = e.target
        real, applied = t.ns, []

        def ns(cmd, **kw):
            r = real(cmd, **kw)
            if cmd[:2] == ["nft", "-f"]:
                applied.append(cmd)
            if cmd[:3] == ["nft", "list", "chain"]:
                r.returncode = 1                       # кто-то сделал nft flush ruleset
            return r
        with mock.patch.object(t, "ns", side_effect=ns):
            e.reconcile()
        self.assertEqual(len(applied), 1)

class TrafficSavedTest(unittest.TestCase):
    def test_counts_reach_the_file(self):                                   # TR11
        from app.traffic import SAVE_EVERY, Traffic
        path = os.path.join(tempfile.mkdtemp(), "t.json")
        tr = Traffic(path)
        peer = lambda rx: [{"public_key": "K", "enabled": True, "live": {"rx": rx, "tx": 0}}]
        t0 = time.time()                       # save() отмечает время по часам, не по now
        tr.update(peer(0), now=t0)
        tr.update(peer(500), now=t0 + SAVE_EVERY + 1)
        self.assertEqual(Traffic(path).total("K"), [500, 0])               # сбой панели после этого — итог цел


class RestoreKindTest(unittest.TestCase):
    def test_server_files_of_other_kind_refused(self):                     # B3
        from app import panel
        import test_api
        panel.engine.reconcile()
        before = panel.store.snapshot()
        b = {"format": backup.BACKUP_FORMAT, "state": test_api.good_state(),
             "server": {"kind": "host", "conf": "awg0.conf", "files": {}}}
        r = Req({"backup": b, "server": True})
        self.assertEqual(code(lambda: backup.restore_backup(r)), (400, "err.backup_kind"))
        self.assertEqual(panel.store.snapshot(), before)                    # ничего не восстановлено


if __name__ == "__main__":
    unittest.main()
