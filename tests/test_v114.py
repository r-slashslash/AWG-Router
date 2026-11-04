"""1.14.0: домен и свой сертификат панели, проверка Let's Encrypt через веб-сервер на порту 80.

python3 -m unittest discover tests
"""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import config, main, tlsconf, tlsmgr, web, webfront  # noqa: E402


def make_cert(d: str, name: str, san: str) -> tuple[str, str]:
    cert, key = os.path.join(d, name + ".crt"), os.path.join(d, name + ".key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-days", "30", "-subj", "/CN=test", "-addext", f"subjectAltName={san}",
                    "-keyout", key, "-out", cert], capture_output=True, check=True)
    return cert, key


class Req:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class HostPathTest(unittest.TestCase):
    """Файлы хоста через /proc/1/root: ссылки certbot (относительные и абсолютные) ведут на хост."""

    def test_links_resolve_inside_host_root(self):
        root = tempfile.mkdtemp()
        os.makedirs(f"{root}/etc/letsencrypt/archive/x")
        os.makedirs(f"{root}/etc/letsencrypt/live/x")
        open(f"{root}/etc/letsencrypt/archive/x/fullchain1.pem", "w").write("A")
        open(f"{root}/etc/letsencrypt/archive/x/privkey1.pem", "w").write("B")
        os.symlink("../../archive/x/fullchain1.pem", f"{root}/etc/letsencrypt/live/x/fullchain.pem")
        os.symlink("/etc/letsencrypt/archive/x/privkey1.pem", f"{root}/etc/letsencrypt/live/x/privkey.pem")
        with mock.patch.object(config, "HOST_ROOT", root):
            with open(webfront.host_path("/etc/letsencrypt/live/x/fullchain.pem")) as f:
                self.assertEqual(f.read(), "A")
            # абсолютная ссылка — от корня хоста, а не панели
            self.assertEqual(webfront.host_path("/etc/letsencrypt/live/x/privkey.pem"),
                             f"{root}/etc/letsencrypt/archive/x/privkey1.pem")

    def test_no_root_means_plain_path(self):
        with mock.patch.object(config, "HOST_ROOT", ""):
            self.assertEqual(webfront.host_path("/etc/x"), "/etc/x")


class NginxTest(unittest.TestCase):
    DUMP = """# configuration file /etc/nginx/nginx.conf:
include /etc/nginx/modules-enabled/*.conf;
http {
    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
# configuration file /etc/nginx/sites-enabled/default:
server {
    listen 80 default_server;
    listen [::]:80 default_server;
}
"""

    def test_include_dir_prefers_http_folders(self):
        self.assertEqual(webfront._include_dir(self.DUMP), "/etc/nginx/conf.d")
        only_sites = self.DUMP.replace("include /etc/nginx/conf.d/*.conf;\n", "")
        self.assertEqual(webfront._include_dir(only_sites), "/etc/nginx/sites-enabled")
        self.assertIsNone(webfront._include_dir("include /etc/nginx/modules-enabled/*.conf;"))

    def test_detect_host_nginx(self):
        done = webfront._Done(0, self.DUMP, "")
        with mock.patch.object(webfront, "_cmd", return_value=done):
            det = webfront._detect_nginx({"where": "host", "container": ""}, "nginx")
        self.assertTrue(det["auto"])
        self.assertEqual(det["file"], "/etc/nginx/conf.d/awg-router-acme.conf")
        self.assertTrue(det["ipv6"])
        self.assertEqual(det["test"], ["nginx", "-t"])

    def test_docker_nginx_mounted_conf(self):
        info = {"Mounts": [{"Source": "/srv/web/conf.d", "Destination": "/etc/nginx/conf.d", "RW": True}]}
        done = webfront._Done(0, self.DUMP, "")
        with mock.patch.object(webfront, "_cmd", return_value=done):
            det = webfront._detect_docker({"where": "docker", "container": "web"}, info)
        self.assertTrue(det["auto"])
        self.assertEqual(det["file"], "/srv/web/conf.d/awg-router-acme.conf")
        self.assertEqual(det["webroot"], "/srv/web/conf.d/awg-router-acme")      # видна и nginx в контейнере
        self.assertEqual(det["root_in"], "/etc/nginx/conf.d/awg-router-acme")

    def test_docker_nginx_config_in_image(self):
        done = webfront._Done(0, self.DUMP, "")
        with mock.patch.object(webfront, "_cmd", return_value=done):
            det = webfront._detect_docker({"where": "docker", "container": "web", "auto": False}, {"Mounts": []})
        self.assertFalse(det["auto"])
        self.assertEqual(det["reason"].key, "web.in_image")

    def test_snippet_only_panel_host_and_path(self):
        det = {"kind": "nginx", "root_in": webfront.WEBROOT, "ipv6": True}
        s = webfront.snippet(det, "203.0.113.5")
        self.assertIn("server_name 203.0.113.5;", s)
        self.assertIn("location /.well-known/acme-challenge/", s)
        self.assertIn(f"root {webfront.WEBROOT};", s)
        self.assertIn("listen [::]:80;", s)
        self.assertNotIn("default_server", s)                 # не перехватываем чужие адреса
        s = webfront.snippet({"kind": "apache", "root_in": webfront.WEBROOT}, "panel.example.com")
        self.assertIn("ServerName panel.example.com", s)
        self.assertIn("Options None", s)


class InstallTest(unittest.TestCase):
    """Наш файл: проверка конфига, перезагрузка, запрос к себе; при ошибке файла не остаётся."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(f"{self.root}/etc/nginx/conf.d")
        self.det = {"kind": "nginx", "process": "nginx", "where": "host", "container": "", "auto": True,
                    "binary": "nginx", "file": f"/etc/nginx/conf.d/{webfront.FILE}", "webroot": webfront.WEBROOT,
                    "root_in": webfront.WEBROOT, "test": ["nginx", "-t"], "reload": ["nginx", "-s", "reload"]}
        self.patches = [mock.patch.object(config, "HOST_ROOT", self.root), mock.patch.object(config, "DRY_RUN", False)]
        for p in self.patches:
            p.start()
        tlsconf.update(web=None)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        tlsconf.update(web=None)

    def conf(self):
        return f"{self.root}/etc/nginx/conf.d/{webfront.FILE}"

    def test_ok(self):
        ran = []
        with mock.patch.object(webfront, "_cmd", side_effect=lambda d, a, **k: ran.append(a) or webfront._Done(0, "", "")), \
                mock.patch.object(webfront, "self_test", return_value=(True, "")):
            web_ = webfront.install("203.0.113.5", self.det)
        self.assertEqual(ran, [["nginx", "-t"], ["nginx", "-s", "reload"]])
        with open(self.conf()) as f:
            self.assertIn("server_name 203.0.113.5;", f.read())
        self.assertTrue(os.path.isdir(f"{self.root}{webfront.WEBROOT}/.well-known/acme-challenge"))
        self.assertEqual(tlsconf.load()["web"]["host"], web_["host"])
        with mock.patch.object(webfront, "_cmd", return_value=webfront._Done(0, "", "")):
            webfront.remove()
        self.assertFalse(os.path.exists(self.conf()))
        self.assertFalse(os.path.exists(f"{self.root}{webfront.WEBROOT}"))
        self.assertNotIn("web", tlsconf.load())

    def test_config_rejected_rolls_back(self):
        with mock.patch.object(webfront, "_cmd", return_value=webfront._Done(1, "", "nginx: [emerg] bad")):
            with self.assertRaises(webfront.WebError) as cm:
                webfront.install("203.0.113.5", self.det)
        self.assertEqual(cm.exception.msg.key, "web.test_failed")
        self.assertFalse(os.path.exists(self.conf()))
        self.assertNotIn("web", tlsconf.load())

    def test_self_test_failure_rolls_back_and_reloads(self):
        ran = []
        with mock.patch.object(webfront, "_cmd", side_effect=lambda d, a, **k: ran.append(a) or webfront._Done(0, "", "")), \
                mock.patch.object(webfront, "self_test", return_value=(False, "HTTP 404")):
            with self.assertRaises(webfront.WebError) as cm:
                webfront.install("203.0.113.5", self.det)
        self.assertEqual(cm.exception.msg.key, "web.check_failed")
        self.assertFalse(os.path.exists(self.conf()))
        self.assertEqual(ran[-1], ["nginx", "-s", "reload"])     # вернули прежние настройки

    def test_new_host_rewrites_file(self):
        ok = mock.patch.object(webfront, "_cmd", return_value=webfront._Done(0, "", ""))
        st = mock.patch.object(webfront, "self_test", return_value=(True, ""))
        with ok, st, mock.patch.object(webfront, "detect", return_value=self.det):
            webfront.install("203.0.113.5", self.det)
            webfront.reinstall_for("panel.example.com")
        with open(self.conf()) as f:
            self.assertIn("server_name panel.example.com;", f.read())
        self.assertEqual(tlsconf.load()["web"]["host"], "panel.example.com")


class CertTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.p = mock.patch.object(config, "HOST_ROOT", "")
        self.p.start()

    def tearDown(self):
        self.p.stop()

    def test_names(self):
        self.assertTrue(tlsmgr.name_matches(["*.example.com"], "panel.example.com"))
        self.assertFalse(tlsmgr.name_matches(["*.example.com"], "a.b.example.com"))
        self.assertFalse(tlsmgr.name_matches(["*.example.com"], "example.com"))
        self.assertTrue(tlsmgr.name_matches(["2001:db8::1"], "2001:0db8::0001"))

    def test_check_custom(self):
        cert, key = make_cert(self.d, "a", "DNS:panel.example.com")
        _, other_key = make_cert(self.d, "b", "DNS:panel.example.com")
        self.assertIsNone(tlsmgr.check_custom(cert, key, "panel.example.com"))
        self.assertEqual(tlsmgr.check_custom(cert, key, "other.example.com").key, "tls.cert_name")
        self.assertEqual(tlsmgr.check_custom(cert, other_key, "panel.example.com").key, "tls.cert_key")
        self.assertEqual(tlsmgr.check_custom(cert + "x", key, "panel.example.com").key, "tls.file_missing")
        self.assertEqual(tlsmgr.check_custom("relative.pem", key, "panel.example.com").key, "tls.bad_path")
        self.assertEqual(tlsmgr.check_custom(key, key, "panel.example.com").key, "tls.not_cert")

    def test_custom_loaded_and_reloaded(self):
        cert, key = make_cert(self.d, "a", "DNS:panel.example.com")
        tlsconf.update(domain="panel.example.com", source="custom", cert=cert, key=key)
        try:
            m = tlsmgr.TLSManager(lambda: "203.0.113.5")
            m.mode = "letsencrypt"
            m._apply()
            self.assertEqual(m.active, "custom")
            self.assertIsNotNone(m.context())
            first = m.expires
            # certbot продлил: новый файл на том же месте
            time.sleep(0.01)
            make_cert(self.d, "a", "DNS:panel.example.com")
            os.utime(cert, ns=(time.time_ns() + 10**9, time.time_ns() + 10**9))
            self.assertNotEqual(m._sig(cert, key), m._custom_sig)
            m._apply()
            self.assertEqual(m.active, "custom")
            self.assertGreaterEqual(m.expires, first)
        finally:
            tlsconf.update(domain=None, source=None, cert=None, key=None)

    def test_dns(self):
        with mock.patch.object(tlsmgr, "resolve", return_value=["198.51.100.7"]):
            self.assertEqual(tlsmgr.check_dns("p.example.com", ["203.0.113.5"]).key, "tls.dns_other")
            self.assertIsNone(tlsmgr.check_dns("p.example.com", ["198.51.100.7"]))
        with mock.patch.object(tlsmgr, "resolve", return_value=[]):
            self.assertEqual(tlsmgr.check_dns("p.example.com", ["203.0.113.5"]).key, "tls.dns_none")


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.p = mock.patch.object(main.tls, "mode", "letsencrypt")
        self.p.start()

    def tearDown(self):
        self.p.stop()
        tlsconf.update(domain=None, source=None, cert=None, key=None, web=None)

    def err(self, body):
        with self.assertRaises(web.HTTPError) as cm:
            main.tls_set(Req(body))
        d = cm.exception.detail
        return d.key if hasattr(d, "key") else d

    def test_validation(self):
        self.assertEqual(self.err({"domain": "bad domain", "source": "letsencrypt"}), "tls.bad_domain")
        self.assertEqual(self.err({"domain": "", "source": "nope"}), "err.bad_value")
        self.assertEqual(self.err({"domain": "203.0.113.5", "source": "custom", "cert": "x", "key": "y"}),
                         "tls.bad_path")

    def test_dns_asks_first(self):
        with mock.patch.object(tlsmgr, "resolve", return_value=["198.51.100.7"]), \
                mock.patch.object(main, "_server_ips", return_value=["203.0.113.5"]):
            r = main.tls_set(Req({"domain": "panel.example.com", "source": "letsencrypt"}))
            self.assertFalse(r["ok"])
            self.assertEqual(r["confirm"].key, "tls.dns_other")
            self.assertNotIn("domain", tlsconf.load())                       # ничего не сохранено
            with mock.patch.object(main.tls, "reconfigure"):
                r = main.tls_set(Req({"domain": "panel.example.com", "source": "letsencrypt", "force": True}))
        self.assertTrue(r["ok"])
        self.assertEqual(tlsconf.load()["domain"], "panel.example.com")
        self.assertEqual(main.tls.host(), "panel.example.com")
        self.assertIn("https://panel.example.com:", main.panel_url().replace("http://", "https://"))
        self.assertEqual(r["web"]["kind"], "nginx")                           # демо: порт 80 «занят» nginx

    def test_ssh_mode_has_no_certificate(self):
        with mock.patch.object(main.tls, "mode", "off"):
            self.assertEqual(self.err({"domain": "", "source": "letsencrypt"}), "tls.off")

    def test_settings_not_in_backup(self):
        """Домен и пути к сертификату — свои у сервера: в state.json их нет, восстановление их не трогает."""
        tlsconf.update(domain="panel.example.com")
        self.assertNotIn("tls", main.store.snapshot()["settings"])


class CliTest(unittest.TestCase):
    def test_domain(self):
        try:
            with mock.patch("sys.stdout"):
                self.assertEqual(webfront.cli(["domain", "Panel.Example.com"]), 0)
            self.assertEqual(tlsconf.domain(), "panel.example.com")
            with mock.patch("sys.stdout"):
                webfront.cli(["domain", ""])
            self.assertEqual(tlsconf.domain(), "")                      # пусто — по IP, TLS_DOMAIN не действует
        finally:
            tlsconf.update(domain=None)

    def test_check_codes(self):
        with mock.patch("sys.stdout"):
            with mock.patch.object(webfront, "detect", return_value={"kind": "none"}):
                self.assertEqual(webfront.cli(["check", "203.0.113.5"]), 1)
            self.assertEqual(webfront.cli(["check", "203.0.113.5"]), 0)                 # демо: nginx
            other = {"kind": "other", "process": "caddy", "where": "host", "auto": False,
                     "reason": webfront.Msg("web.manual_only", server="Caddy")}
            with mock.patch.object(webfront, "detect", return_value=other):
                self.assertEqual(webfront.cli(["check", "203.0.113.5"]), 2)


if __name__ == "__main__":
    unittest.main()
