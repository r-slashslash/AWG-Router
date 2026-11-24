"""1.24.0: сертификат Let's Encrypt с проверкой домена через DNS Cloudflare (DNS-01, идея PR #51).
python3 -m unittest tests.test_v124_cfdns"""
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import config, panel, tlsconf, tlsmgr, web, webfront  # noqa: E402
from app.api import server  # noqa: E402

TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-Aa"


class Req:
    def __init__(self, body):
        self.body = body

    def json(self, limit=None):
        return self.body


def reset():
    tlsconf.update(domain=None, source=None, cert=None, key=None, web=None, challenge=None, cf_token=None)


class LegoTest(unittest.TestCase):
    """Команда lego: через Cloudflare — --dns cloudflare, токен только в окружении, без порта 80 и без второго
    адреса; профиль shortlived — только если задан явно; через порт 80 — как раньше."""

    def setUp(self):
        self.runs = []
        real = subprocess.run

        def fake(cmd, **kw):
            if cmd[:2] != ["lego", "run"]:
                return real(cmd, **kw)
            self.runs.append((cmd, kw.get("env")))
            return subprocess.CompletedProcess(cmd, 1, "", "acme: error: test")
        for p in (mock.patch.object(tlsmgr.subprocess, "run", side_effect=fake),
                  mock.patch.object(config, "DRY_RUN", False),
                  mock.patch.object(webfront, "listeners", return_value=["nginx"]),
                  mock.patch.object(webfront, "detect", return_value={"process": "nginx"})):
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(reset)

    def mgr(self, host="203.0.113.5", alt=("2001:db8::5",)):
        m = tlsmgr.TLSManager(lambda: host, lambda: list(alt))
        m.mode = "letsencrypt"
        return m

    def test_cloudflare(self):
        tlsconf.update(domain="panel.example.com", challenge="cloudflare", cf_token=TOKEN)
        m = self.mgr()
        self.assertEqual(m.cf_token(), TOKEN)
        self.assertFalse(m._lego())
        cmd, env = self.runs[-1]
        self.assertIn("--dns", cmd)
        self.assertEqual(cmd[cmd.index("--dns") + 1], "cloudflare")
        self.assertNotIn("--http", cmd)
        self.assertNotIn("--profile", cmd)
        self.assertEqual([cmd[i + 1] for i, x in enumerate(cmd) if x == "-d"], ["panel.example.com"])
        self.assertNotIn(TOKEN, " ".join(cmd))
        self.assertEqual(env["CF_DNS_API_TOKEN"], TOKEN)
        self.assertIsNone(m.port80)                      # порт 80 занят nginx — DNS-01 это не мешает
        with mock.patch.object(tlsmgr, "ACME_PROFILE_EXPLICIT", True):
            m._lego()
        self.assertIn("--profile", self.runs[-1][0])
        st = m.status()
        self.assertEqual((st["challenge"], st["cf_token"]), ("cloudflare", True))
        self.assertNotIn(TOKEN, json.dumps(st, default=str))

    def test_ip_or_no_token_is_port80(self):
        """Адрес — IP или токена нет: проверка через порт 80, как раньше (порт занят — подсказка про веб-сервер)."""
        tlsconf.update(challenge="cloudflare", cf_token=TOKEN)
        m = self.mgr()
        self.assertEqual(m.cf_token(), "")
        self.assertFalse(m._lego())
        self.assertEqual(self.runs, [])
        self.assertEqual(m.error.key, "tls.port80")
        tlsconf.update(domain="panel.example.com", cf_token=None)
        self.assertEqual((tlsconf.challenge(), m.cf_token()), ("http", ""))

    def test_settings_file_is_private(self):
        tlsconf.update(cf_token=TOKEN)
        self.assertEqual(stat.S_IMODE(os.stat(tlsconf.path()).st_mode), 0o600)


class CloudflareCheckTest(unittest.TestCase):
    """Проверка токена перед сохранением: зона домена (или родителя) видна, записи DNS читаются."""

    def answer(self, routes):
        def get(path, token):
            for prefix, resp in routes:
                if path.startswith(prefix):
                    return resp
            return 200, {"success": True, "result": []}
        return mock.patch.object(tlsmgr, "_cf_get", side_effect=get)

    def test_zone_of_parent(self):
        seen = []
        ok = {"success": True, "result": [{"id": "z1", "name": "example.com"}]}
        with self.answer([("/zones?name=example.com", (200, ok)), ("/zones/z1/dns_records", (200, {"success": True}))]) as g:
            self.assertIsNone(tlsmgr.cf_check(TOKEN, "a.panel.example.com"))
            seen = [c.args[0] for c in g.call_args_list]
        self.assertEqual(seen, ["/zones?name=a.panel.example.com", "/zones?name=panel.example.com",
                                "/zones?name=example.com", "/zones/z1/dns_records?per_page=1"])

    def test_errors(self):
        bad = (403, {"success": False, "errors": [{"code": 9109, "message": "Invalid access token"}]})
        with self.answer([("/zones?", bad)]):
            m = tlsmgr.cf_check(TOKEN, "panel.example.com")
        self.assertEqual((m.key, m.p["error"]), ("tls.cf_rejected", "Invalid access token"))
        with self.answer([]):
            self.assertEqual(tlsmgr.cf_check(TOKEN, "panel.example.com").key, "tls.cf_no_zone")
        ok = {"success": True, "result": [{"id": "z1", "name": "example.com"}]}
        with self.answer([("/zones?name=example.com", (200, ok)), ("/zones/z1/", (403, {"success": False}))]):
            self.assertEqual(tlsmgr.cf_check(TOKEN, "panel.example.com").key, "tls.cf_no_dns")
        with mock.patch.object(tlsmgr, "_cf_get", side_effect=OSError("timed out")):
            self.assertEqual(tlsmgr.cf_check(TOKEN, "panel.example.com").key, "tls.cf_unreachable")

    def test_http_error_body(self):
        """Ответ 4xx с JSON — код и тело, не исключение."""
        e = urllib.error.HTTPError(tlsmgr.CF_API, 401, "x", {}, io.BytesIO(b'{"success":false,"errors":[]}'))
        with mock.patch.object(tlsmgr.urllib.request, "urlopen", side_effect=e):
            self.assertEqual(tlsmgr._cf_get("/zones", TOKEN), (401, {"success": False, "errors": []}))


class ApiTest(unittest.TestCase):
    def setUp(self):
        for p in (mock.patch.object(panel.tls, "mode", "letsencrypt"), mock.patch.object(panel.tls, "reconfigure"),
                  mock.patch.object(tlsmgr, "resolve", return_value=["203.0.113.5"]),
                  mock.patch.object(server, "_server_ips", return_value=["203.0.113.5"])):
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(reset)

    def err(self, body):
        with self.assertRaises(web.HTTPError) as cm:
            server.tls_set(Req(body))
        d = cm.exception.detail
        return (d.key if hasattr(d, "key") else d), cm.exception.field

    def body(self, **kw):
        return {"domain": "panel.example.com", "source": "letsencrypt", "challenge": "cloudflare", **kw}

    def test_save_keep_and_drop(self):
        """Вход: токен, затем сохранение с пустым полем, затем переход на порт 80. Ожидание: токен сохранён и в ответе
        не виден; пустое поле — прежний токен; порт 80 — токена на сервере больше нет; вопроса о веб-сервере на порту 80
        при Cloudflare нет."""
        r = server.tls_set(Req(self.body(cf_token=TOKEN)))
        self.assertTrue(r["ok"])
        self.assertIsNone(r["web"])
        self.assertEqual((tlsconf.challenge(), tlsconf.cf_token()), ("cloudflare", TOKEN))
        self.assertNotIn(TOKEN, json.dumps(r, default=str))
        server.tls_set(Req(self.body(cf_token="")))
        self.assertEqual(tlsconf.cf_token(), TOKEN)
        r = server.tls_set(Req(self.body(challenge="http")))
        self.assertEqual((tlsconf.challenge(), tlsconf.cf_token()), ("http", ""))
        self.assertEqual(r["web"]["kind"], "nginx")

    def test_errors_point_at_fields(self):
        self.assertEqual(self.err(self.body()), ("tls.cf_token_empty", "cf_token"))
        self.assertEqual(self.err(self.body(cf_token="short")), ("tls.cf_token_bad", "cf_token"))
        with mock.patch.object(server.engine.srv, "public_host", return_value="203.0.113.5"):
            self.assertEqual(self.err(self.body(domain="", cf_token=TOKEN)), ("tls.cf_need_domain", "tls_domain"))
        self.assertEqual(self.err(self.body(domain="203.0.113.5", cf_token=TOKEN)), ("tls.cf_need_domain", "tls_domain"))
        self.assertEqual(self.err(self.body(challenge="dns")), ("err.bad_value", None))
        with mock.patch.object(config, "DRY_RUN", False), \
                mock.patch.object(tlsmgr, "cf_check", return_value=tlsmgr.Msg("tls.cf_no_zone", domain="x")):
            self.assertEqual(self.err(self.body(cf_token=TOKEN)), ("tls.cf_no_zone", "cf_token"))
        self.assertEqual(tlsconf.cf_token(), "")                 # ошибка — ничего не сохранено

    def test_own_certificate_drops_token(self):
        server.tls_set(Req(self.body(cf_token=TOKEN)))
        with mock.patch.object(tlsmgr, "check_custom", return_value=None):
            server.tls_set(Req(self.body(source="custom", cert="/etc/c.pem", key="/etc/k.pem")))
        self.assertEqual(tlsconf.cf_token(), "")


if __name__ == "__main__":
    unittest.main()
