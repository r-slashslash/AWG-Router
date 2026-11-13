"""1.19.5: проверка Let's Encrypt через веб-сервер кладёт файл в папку токенов (issue #21); выход по IPv6
без пути до него и IPv6 во «Внешнем адресе сервера» (issue #20).

python3 -m unittest discover tests
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import config, engine, hostnet, main, system, tlsconf, tlsmgr, users, webfront  # noqa: E402
from app.store import Store  # noqa: E402


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
                self.status, self.body = (200, open(fp).read()) if os.path.isfile(fp) else (404, "")

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


class PublicHostV6Test(unittest.TestCase):
    """«Внешний адрес сервера» — ещё и адрес панели и имя в её сертификате, а панель слушает только IPv4."""

    def test_is_v6(self):
        self.assertTrue(hostnet.is_v6("2001:db8::1"))
        self.assertTrue(hostnet.is_v6("[2001:db8::1]"))
        self.assertFalse(hostnet.is_v6("203.0.113.5"))
        self.assertFalse(hostnet.is_v6("panel.example.com"))
        self.assertFalse(hostnet.is_v6(""))

    def test_input_rejects_v6(self):
        main.engine.reconcile()            # демо-сервер AWG как цель
        with self.assertRaises(users.UserError) as cm:
            main.engine.srv.update_server({"public_host": "[2001:db8::5]"})
        self.assertEqual(cm.exception.msg.key, "srv.host_v6")

    def test_upgrade_moves_v6_to_client_host(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "state.json")
        for settings, want in (({"public_host": "2001:0db8::5"}, {"client_host": "2001:db8::5"}),
                               ({"public_host": "2001:db8::5", "client_host": "203.0.113.9"},
                                {"client_host": "203.0.113.9"}),            # выбранный адрес не трогаем
                               ({"public_host": "203.0.113.5"}, {"public_host": "203.0.113.5"})):
            with open(path, "w") as f:
                json.dump({"settings": settings}, f)
            s = Store(path).snapshot()["settings"]
            self.assertEqual({k: s[k] for k in ("public_host", "client_host") if k in s}, want)

    def test_restore_drops_v6(self):
        from test_api import good_state
        for h, kept in (("2001:db8::5", False), ("203.0.113.5", True), ("panel.example.com", True)):
            st = good_state()
            st.setdefault("settings", {})["public_host"] = h
            self.assertEqual(main.clean_backup_state(st)["settings"].get("public_host") == h, kept)


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


if __name__ == "__main__":
    unittest.main()
