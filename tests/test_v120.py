"""1.20.0: проверка Let's Encrypt через веб-сервер кладёт файл в папку токенов (issue #21); выход по IPv6
без пути до него, панель по IPv6 и сертификат на адрес IPv6 (issue #20).

python3 -m unittest discover tests
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
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import config, engine, main, system, tlsconf, tlsmgr, web, webfront  # noqa: E402


class SelfTestPathTest(unittest.TestCase):
    """С настоящим HOST_ROOT (/proc/1/root) файл проверки должен лечь в .well-known/acme-challenge/,
    а не рядом с ней: без этого проверка через nginx, Apache, Caddy всегда получала 404."""

    def test_token_inside_challenge_dir(self):
        root = tempfile.mkdtemp()
        webroot = "/var/lib/awg-router/acme"
        seen = []

        class Conn:
            """Веб-сервер: отдаёт файлы из webroot на хосте по пути запроса."""

            def __init__(self, *a, **k):
                pass

            def request(self, method, path, headers=None):
                fp = root + webroot + path
                seen.append(fp)
                if os.path.isfile(fp):
                    with open(fp) as f:
                        self.status, self.body = 200, f.read()
                else:
                    self.status, self.body = 404, ""

            def getresponse(self):
                me = self

                class R:
                    status = me.status

                    def read(self, n):
                        return me.body.encode()
                return R()

            def close(self):
                pass

        with mock.patch.object(config, "HOST_ROOT", root), mock.patch.object(config, "DRY_RUN", False), \
                mock.patch.object(webfront.http.client, "HTTPConnection", Conn), \
                mock.patch.object(webfront.time, "sleep"):
            ok, detail = webfront.self_test(webroot, "203.0.113.5", tries=1)
        self.assertEqual((ok, detail), (True, ""))
        self.assertTrue(seen[0].startswith(f"{root}{webroot}/.well-known/acme-challenge/awgr-check-"))
        self.assertEqual(os.listdir(f"{root}{webroot}/.well-known/acme-challenge"), [])   # файл убран
        self.assertEqual(sorted(os.listdir(f"{root}{webroot}/.well-known")), ["acme-challenge"])


class V6RouteTest(unittest.TestCase):
    """Выход по IPv6 проверяет путь в сети сервера AWG, а не режим: у кого IPv6 в Docker включён, работает."""

    def target(self, kind: str, rc: int):
        calls = []
        t = mock.Mock(kind=kind)
        t.ns = lambda cmd, **kw: calls.append(cmd) or subprocess.CompletedProcess(cmd, rc, "", "")
        return t, calls

    def test_ipv4_not_checked(self):
        t, calls = self.target("container", 2)
        engine.Engine._v6_route(t, "203.0.113.7")
        self.assertEqual(calls, [])

    def test_no_route(self):
        for kind, key in (("container", "sys.no_v6_container"), ("host", "sys.no_v6_route")):
            t, calls = self.target(kind, 2)
            with self.assertRaises(system.SysError) as cm:
                engine.Engine._v6_route(t, "2001:db8::7")
            self.assertEqual(cm.exception.msg.key, key)
            self.assertEqual(cm.exception.msg.p, {"ip": "2001:db8::7"})
            self.assertEqual(calls, [["ip", "-6", "route", "get", "2001:db8::7"]])

    def test_route_ok(self):
        t, _ = self.target("container", 0)
        engine.Engine._v6_route(t, "2001:db8::7")


class PanelV6Test(unittest.TestCase):
    """Панель слушает и IPv6: «Внешний адрес сервера» может быть IPv6 — по нему открывается панель, на него
    выписан сертификат и к нему подключаются клиенты, как и задумано у одного поля (issue #20)."""

    def test_v6_public_host_accepted(self):
        main.engine.reconcile()            # демо-сервер AWG как цель
        try:
            main.engine.srv.update_server({"public_host": "[2001:db8::5]"})
            self.assertEqual(main.store.snapshot()["settings"]["public_host"], "2001:db8::5")
            self.assertEqual(main.panel_url().split("//", 1)[1].split("/", 1)[0][:14], "[2001:db8::5]:")
        finally:
            main.engine.srv.update_server({"public_host": "203.0.113.5"})

    def test_client_key(self):
        self.assertEqual(web.client_key("203.0.113.5"), "203.0.113.5")
        self.assertEqual(web.client_key("::ffff:203.0.113.5"), "203.0.113.5")      # IPv4 через сокет IPv6
        # один абонент — одна /64: смена адреса внутри неё не обходит блокировку подбора пароля
        self.assertEqual(web.client_key("2001:db8:1:2::1"), web.client_key("2001:db8:1:2:abcd::9"))
        self.assertEqual(web.client_key("2001:db8:1:2::1"), "2001:db8:1:2::/64")
        self.assertNotEqual(web.client_key("2001:db8:1:2::1"), web.client_key("2001:db8:1:3::1"))
        self.assertEqual(web.client_key("fe80::1%eth0"), "fe80::/64")

    def test_listens_v4_and_v6(self):
        """Один сокет на «все адреса» принимает IPv4 и IPv6; без IPv6 в ядре — только IPv4."""
        app = web.App()

        @app.get("/ping")
        def ping(req):
            return {"ip": req.client_ip}

        srv = app.serve("0.0.0.0", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]

            def get(host):
                c = http.client.HTTPConnection(host, port, timeout=5)
                c.request("GET", "/ping")
                r = c.getresponse()
                return json.loads(r.read())["ip"]
            self.assertEqual(get("127.0.0.1"), "127.0.0.1")
            if srv.address_family == socket.AF_INET6:
                self.assertEqual(get("::1"), "::/64")
            else:
                with self.assertRaises(OSError):
                    socket.socket(socket.AF_INET6)         # уходит на IPv4 только без IPv6 в ядре
        finally:
            srv.shutdown()
            srv.server_close()


class LePathsTest(unittest.TestCase):
    """lego меняет «:» в имени файла на «-»: сертификат на IPv6 ищется по имени внутри него."""

    def test_sanitized_file_found(self):
        d = os.path.join(tlsmgr.ACME_DIR, "certificates")
        os.makedirs(d, exist_ok=True)
        cert, key = os.path.join(d, "2001-db8--5.crt"), os.path.join(d, "2001-db8--5.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "30", "-subj", "/CN=test", "-addext", "subjectAltName=IP:2001:db8::5",
                        "-keyout", key, "-out", cert], capture_output=True, check=True)
        tlsconf.update(domain="")
        try:
            self.assertEqual(tlsmgr.TLSManager(lambda: "2001:db8::5")._le_paths(), (cert, key))
            # обычное имя (IPv4, домен) — как раньше, без перебора папки
            self.assertEqual(tlsmgr.TLSManager(lambda: "203.0.113.5")._le_paths(),
                             (os.path.join(d, "203.0.113.5.crt"), os.path.join(d, "203.0.113.5.key")))
        finally:
            for p in (cert, key):
                os.remove(p)


class TwoAddressCertTest(unittest.TestCase):
    """Сертификат панели на оба адреса сервера (IPv4 и IPv6), чтобы она открывалась без предупреждения по
    любому; Let's Encrypt не проверил второй — сертификат на основной, повтор не раньше ALT_RETRY."""

    def setUp(self):
        self.d = os.path.join(tlsmgr.ACME_DIR, "certificates")
        os.makedirs(self.d, exist_ok=True)
        tlsconf.update(domain="", web=None)
        self.runs, self.fail = [], set()
        real = subprocess.run

        def fake(cmd, **kw):
            if cmd[:2] != ["lego", "run"]:
                return real(cmd, **kw)
            names = [cmd[i + 1] for i, x in enumerate(cmd) if x == "-d"]
            self.runs.append((names, "--renew-force" in cmd))
            if tuple(names) in self.fail:
                return subprocess.CompletedProcess(cmd, 1, "", "acme: error: 403 :: urn:ietf:params:acme:error:connection")
            base = os.path.join(self.d, names[0].replace(":", "-"))
            san = ",".join(f"IP:{n}" for n in names)
            real(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                  "-days", "6", "-subj", "/CN=x", "-addext", f"subjectAltName={san}", "-keyout", base + ".key",
                  "-out", base + ".crt"], capture_output=True, check=True)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        self.patches = [mock.patch.object(tlsmgr.subprocess, "run", side_effect=fake),
                        mock.patch.object(config, "DRY_RUN", False),
                        mock.patch.object(webfront, "listeners", return_value=[])]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        for n in os.listdir(self.d):
            os.remove(os.path.join(self.d, n))

    def mgr(self, host, alt):
        m = tlsmgr.TLSManager(lambda: host, lambda: alt)
        m.mode = "letsencrypt"
        return m

    def test_names(self):
        self.assertEqual(self.mgr("203.0.113.5", ["2001:db8::5"]).names(), ["203.0.113.5", "2001:db8::5"])
        self.assertEqual(self.mgr("2001:db8::5", ["203.0.113.5"]).names(), ["2001:db8::5", "203.0.113.5"])
        self.assertEqual(self.mgr("203.0.113.5", ["198.51.100.1"]).names(), ["203.0.113.5"])   # то же семейство
        self.assertEqual(self.mgr("203.0.113.5", []).names(), ["203.0.113.5"])
        self.assertEqual(self.mgr("vpn.example.com", ["2001:db8::5"]).names(), ["vpn.example.com"])
        tlsconf.update(domain="panel.example.com")
        self.assertEqual(self.mgr("203.0.113.5", ["2001:db8::5"]).names(), ["panel.example.com"])

    def test_both_addresses(self):
        m = self.mgr("2001:db8::5", ["203.0.113.5"])
        self.assertTrue(m._lego())
        self.assertEqual(self.runs, [(["2001:db8::5", "203.0.113.5"], False)])
        cert = m._le_paths()[0]
        self.assertTrue(tlsmgr._san_matches(cert, "203.0.113.5") and tlsmgr._san_matches(cert, "2001:db8::5"))

    def test_second_address_refused_falls_back(self):
        self.fail = {("203.0.113.5", "2001:db8::5")}
        m = self.mgr("203.0.113.5", ["2001:db8::5"])
        self.assertTrue(m._lego())
        self.assertEqual([r[0] for r in self.runs], [["203.0.113.5", "2001:db8::5"], ["203.0.113.5"]])
        self.assertEqual(m._want(), ["203.0.113.5"])           # до ALT_RETRY второй адрес не просим
        with mock.patch.object(tlsmgr.time, "time", return_value=time.time() + tlsmgr.ALT_RETRY + 1):
            self.assertEqual(m._want(), ["203.0.113.5", "2001:db8::5"])

    def test_add_second_to_valid_cert(self):
        """Действующий сертификат на один адрес: дополняется вторым (--renew-force), а при отказе остаётся."""
        m = self.mgr("203.0.113.5", [])
        m._apply()
        self.assertEqual(self.runs, [(["203.0.113.5"], False)])
        m._get_alt = lambda: ["2001:db8::5"]
        self.fail = {("203.0.113.5", "2001:db8::5")}
        m._apply()
        self.assertEqual(self.runs[1:], [(["203.0.113.5", "2001:db8::5"], True)])   # лишнего на один нет
        self.assertEqual((m.active, m.error), ("letsencrypt", None))
        self.fail, m._alt_failed = set(), {}
        m._apply()
        self.assertEqual(self.runs[-1], (["203.0.113.5", "2001:db8::5"], True))
        self.assertTrue(tlsmgr._san_matches(m._le_paths()[0], "2001:db8::5"))

    def test_web_server_only_main_address(self):
        tlsconf.update(web={"kind": "manual", "host": "203.0.113.5", "webroot": "/var/lib/awg-router/acme"})
        with mock.patch.object(config, "HOST_ROOT", ""):
            self.assertTrue(self.mgr("203.0.113.5", ["2001:db8::5"])._lego())
        self.assertEqual([r[0] for r in self.runs], [["203.0.113.5"]])

    def test_selfsigned_both(self):
        m = self.mgr("2001:db8::7", ["203.0.113.7"])
        m._selfsigned()
        cert = os.path.join(tlsmgr.TLS_DIR, "self.crt")
        self.assertTrue(tlsmgr._san_matches(cert, "2001:db8::7") and tlsmgr._san_matches(cert, "203.0.113.7"))

    def test_main_alt(self):
        """Второй адрес — только если IPv6 в ходу: в «Внешнем адресе» или в «Адрес в конфигах»."""
        st = main.store.snapshot()["settings"]
        def with_settings(**kw):
            main.store.mutate(lambda s: s["settings"].update(kw))
            return main._tls_alt()
        try:
            with mock.patch.object(config, "PUBLIC_HOST", "203.0.113.5"):
                self.assertEqual(with_settings(public_host="2001:db8::5", client_host=""), ["203.0.113.5"])
                self.assertEqual(with_settings(public_host="203.0.113.5", client_host="2001:db8::9"), ["2001:db8::9"])
                self.assertEqual(with_settings(public_host="203.0.113.5", client_host=""), [])
                self.assertEqual(with_settings(public_host="vpn.example.com", client_host="2001:db8::9"), [])
        finally:
            main.store.mutate(lambda s: s["settings"].update({k: st.get(k, "") for k in ("public_host", "client_host")}))


if __name__ == "__main__":
    unittest.main()
