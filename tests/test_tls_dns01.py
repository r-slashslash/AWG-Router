"""Tests for Cloudflare DNS-01 challenge support in tlsmgr."""
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app.config as config  # noqa: E402
import app.tlsmgr as tlsmgr  # noqa: E402


def _mgr(host="panel.example.com"):
    return tlsmgr.TLSManager(get_host=lambda: host)


class TestCloudflareDNS01(unittest.TestCase):
    def test_use_dns_challenge_requires_token_and_domain(self):
        with patch.object(config, "CF_DNS_API_TOKEN", ""):
            self.assertFalse(_mgr("panel.example.com").use_dns_challenge())

        with patch.object(config, "CF_DNS_API_TOKEN", "cf-secret-token"):
            self.assertTrue(_mgr("panel.example.com").use_dns_challenge())
            self.assertFalse(_mgr("1.2.3.4").use_dns_challenge())
            self.assertFalse(_mgr("2001:db8::1").use_dns_challenge())
            self.assertFalse(_mgr("").use_dns_challenge())

    def test_lego_uses_dns_cloudflare_without_port80(self):
        env_without_profile = {k: v for k, v in os.environ.items() if k != "ACME_PROFILE"}
        with (
            patch.dict(os.environ, env_without_profile, clear=True),
            patch.object(config, "CF_DNS_API_TOKEN", "cf-secret-token"),
            patch.object(config, "DRY_RUN", False),
            patch.object(config, "ACME_EMAIL", "admin@example.com"),
            patch.object(tlsmgr, "ACME_PROFILE_EXPLICIT", False),
            patch.object(tlsmgr.tlsconf, "domain", return_value=""),
            patch.object(tlsmgr.webfront, "listeners", side_effect=AssertionError("must not check port 80")),
        ):
            m = _mgr("panel.example.com")
            seen = {}

            def fake_issue(cmd, names):
                seen["cmd"] = cmd
                seen["names"] = names
                return True

            m._issue = fake_issue
            self.assertTrue(m._lego())

        self.assertIn("--dns", seen["cmd"])
        self.assertIn("cloudflare", seen["cmd"])
        self.assertNotIn("--http", seen["cmd"])
        self.assertNotIn("--http.address", seen["cmd"])
        self.assertNotIn("--profile", seen["cmd"])
        self.assertIn("--email", seen["cmd"])
        self.assertIn("admin@example.com", seen["cmd"])
        self.assertEqual(seen["names"], ["panel.example.com"])

    def test_lego_dns_cloudflare_respects_explicit_acme_profile(self):
        with (
            patch.dict(os.environ, {"ACME_PROFILE": "classic"}),
            patch.object(config, "CF_DNS_API_TOKEN", "cf-secret-token"),
            patch.object(config, "DRY_RUN", False),
            patch.object(tlsmgr, "ACME_PROFILE_EXPLICIT", True),
            patch.object(tlsmgr, "ACME_PROFILE", "classic"),
            patch.object(tlsmgr.tlsconf, "domain", return_value=""),
            patch.object(tlsmgr.webfront, "listeners", side_effect=AssertionError("must not check port 80")),
        ):
            m = _mgr("panel.example.com")
            seen = {}
            m._issue = lambda cmd, names: seen.update({"cmd": cmd, "names": names}) or True
            self.assertTrue(m._lego())

        self.assertIn("--profile", seen["cmd"])
        self.assertIn("classic", seen["cmd"])

    def test_lego_falls_back_to_http_for_ip_even_with_token(self):
        with (
            patch.object(config, "CF_DNS_API_TOKEN", "cf-secret-token"),
            patch.object(config, "DRY_RUN", False),
            patch.object(tlsmgr.tlsconf, "domain", return_value=""),
            patch.object(tlsmgr.webfront, "listeners", return_value=[]),
        ):
            m = _mgr("1.2.3.4")
            seen = {}
            m._issue = lambda cmd, names: seen.update({"cmd": cmd, "names": names}) or True
            self.assertTrue(m._lego())

        self.assertIn("--http", seen["cmd"])
        self.assertNotIn("--dns", seen["cmd"])

    def test_status_reports_challenge(self):
        with patch.object(config, "CF_DNS_API_TOKEN", "cf-secret-token"):
            st = _mgr("panel.example.com").status()
            self.assertEqual(st["challenge"], "dns-01")
            self.assertEqual(st["dns_provider"], "cloudflare")
            self.assertTrue(st["dns_configured"])

            st_ip = _mgr("1.2.3.4").status()
            self.assertEqual(st_ip["challenge"], "http-01")
            self.assertIsNone(st_ip["dns_provider"])
            self.assertTrue(st_ip["dns_configured"])

        with patch.object(config, "CF_DNS_API_TOKEN", ""):
            st_no_tok = _mgr("panel.example.com").status()
            self.assertEqual(st_no_tok["challenge"], "http-01")
            self.assertIsNone(st_no_tok["dns_provider"])
            self.assertFalse(st_no_tok["dns_configured"])

    def test_issue_passes_cf_dns_api_token_in_env(self):
        m = _mgr("panel.example.com")
        proc = MagicMock(returncode=0, stdout="", stderr="")
        with (
            patch.object(config, "CF_DNS_API_TOKEN", "cf-secret-token"),
            patch.object(tlsmgr.subprocess, "run", return_value=proc) as run_mock,
            patch.object(m, "_load", return_value=True),
        ):
            self.assertTrue(m._issue(["lego", "run"], ["panel.example.com"]))

        run_mock.assert_called_once()
        env = run_mock.call_args.kwargs.get("env")
        self.assertIsNotNone(env)
        self.assertEqual(env["CF_DNS_API_TOKEN"], "cf-secret-token")

    def test_cf_token_popped_from_os_environ_on_import(self):
        import importlib

        with patch.dict(os.environ, {"CF_DNS_API_TOKEN": "cf-temp-secret"}):
            importlib.reload(config)
            self.assertEqual(config.CF_DNS_API_TOKEN, "cf-temp-secret")
            self.assertNotIn("CF_DNS_API_TOKEN", os.environ)
        importlib.reload(config)

    def test_tls_set_skips_webfront_when_dns01(self):
        import app.api.server as api_srv

        req = MagicMock()
        req.json.return_value = {"domain": "panel.example.com", "source": "letsencrypt", "force": True}

        with (
            patch.object(config, "CF_DNS_API_TOKEN", "cf-secret-token"),
            patch.object(api_srv.tls, "mode", "letsencrypt"),
            patch.object(api_srv.tls, "use_dns_challenge", return_value=True) as dns_mock,
            patch.object(api_srv, "_need_web", side_effect=AssertionError("should not call _need_web")),
            patch.object(api_srv.tlsconf, "update", return_value={}),
            patch.object(api_srv.tls, "reconfigure"),
            patch.object(api_srv.tls, "status", return_value={"challenge": "dns-01"}),
            patch.object(api_srv, "write_status"),
            patch.object(api_srv, "panel_url", return_value="https://panel.example.com"),
            patch.object(api_srv, "_server_ips", return_value=["1.2.3.4"]),
            patch.object(api_srv.tlsmgr, "check_dns", return_value=None),
            patch.object(api_srv.webfront, "reinstall_for"),
            patch.object(api_srv.engine, "event"),
        ):
            res = api_srv.tls_set(req)

        dns_mock.assert_called_once_with("panel.example.com")
        self.assertTrue(res["ok"])
        self.assertIsNone(res["web"])

    def test_tls_set_calls_need_web_when_not_dns01(self):
        import app.api.server as api_srv

        req = MagicMock()
        req.json.return_value = {"domain": "panel.example.com", "source": "letsencrypt", "force": True}

        with (
            patch.object(config, "CF_DNS_API_TOKEN", ""),
            patch.object(api_srv.tls, "mode", "letsencrypt"),
            patch.object(api_srv.tls, "use_dns_challenge", return_value=False) as dns_mock,
            patch.object(api_srv, "_need_web", return_value=({"kind": "none"}, None)) as web_mock,
            patch.object(api_srv.tlsconf, "update", return_value={}),
            patch.object(api_srv.tls, "reconfigure"),
            patch.object(api_srv.tls, "status", return_value={"challenge": "http-01"}),
            patch.object(api_srv, "write_status"),
            patch.object(api_srv, "panel_url", return_value="https://panel.example.com"),
            patch.object(api_srv, "_server_ips", return_value=["1.2.3.4"]),
            patch.object(api_srv.tlsmgr, "check_dns", return_value=None),
            patch.object(api_srv.webfront, "reinstall_for"),
            patch.object(api_srv.engine, "event"),
        ):
            res = api_srv.tls_set(req)

        dns_mock.assert_called_once_with("panel.example.com")
        web_mock.assert_called_once_with("panel.example.com")
        self.assertTrue(res["ok"])


if __name__ == "__main__":
    unittest.main()
