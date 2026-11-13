"""PUBLIC_HOST может быть доменом: проверка DNS в install.sh — по IP, предупреждение о настройке панели;
панель не сохраняет как свою настройку адрес, равный PUBLIC_HOST.

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

from app import config, main  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


STUBS = r"""
B=; N=; DIR="$TMP"; ENV_FILE="$TMP/.env"
step() { :; }; ok() { echo "OK $1"; }; warn() { echo "WARN $1"; }; die() { echo "DIE $1"; exit 1; }
envget() { [ -f "$ENV_FILE" ] && grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true; }
ask() { REPLY="${ANSWER:-$2}"; }
public_ip() { echo 203.0.113.5; }
getent() { [ -n "$FAKE_DNS" ] && echo "$FAKE_DNS STREAM $3"; }
random_port() { echo 4821; }; unsafe_port() { return 1; }; panel_port_problem() { :; }
"""


class InstallerTest(unittest.TestCase):
    """Адрес в конфигах из install.sh: настоящий кусок скрипта с заглушками сети и вопросов."""

    def setUp(self):
        with open(os.path.join(ROOT, "install.sh")) as f:
            self.sh = f.read()
        a = self.sh.index('step "Preparing settings"')
        b = self.sh.index("\n", self.sh.index('TLS_HOST="${PANEL_DOMAIN:-$PUBLIC_HOST}"'))
        self.assertIn("state.json", self.sh[a:b])
        c = self.sh.index("choose() {")
        self.part = self.sh[c:self.sh.index("\n}\n", c) + 3] + self.sh[a:b]
        self.tmp = tempfile.mkdtemp()

    def run_part(self, env_public, *, domain="", tls_domain=None, dns="203.0.113.5", reconf=0,
                 answer="", ask_domain=1, panel_host=None):
        with open(os.path.join(self.tmp, ".env"), "w") as f:
            f.write(f"AWGR_VERSION=2\nPANEL_PORT=4821\nPANEL_PASSWORD=x\nPANEL_BASE_PATH=/x\n"
                    f"PUBLIC_HOST={env_public}\n")
        os.makedirs(os.path.join(self.tmp, "data"), exist_ok=True)
        tls = os.path.join(self.tmp, "data", "tls.json")
        if tls_domain is None:
            if os.path.exists(tls):
                os.remove(tls)
        else:
            with open(tls, "w") as f:
                f.write(f'{{"domain": "{tls_domain}"}}')
        state = os.path.join(self.tmp, "data", "state.json")
        with open(state, "w") as f:
            json.dump({"settings": {} if panel_host is None else {"public_host": panel_host}}, f)
        env = dict(os.environ, TMP=self.tmp, FAKE_DNS=dns, ANSWER=answer, AWGR_PORT="4821")
        if domain is not None:
            env["AWGR_DOMAIN"] = domain
        script = (STUBS + f"RECONF={reconf}; ACCESS=public; ASK_DOMAIN={ask_domain}\n" + self.part +
                  '\necho "PUBLIC_HOST=$PUBLIC_HOST"; echo "TLS_HOST=$TLS_HOST"\n')
        out = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30).stdout
        vals = dict(l.split("=", 1) for l in out.splitlines() if l.startswith(("PUBLIC_HOST=", "TLS_HOST=")))
        return vals, out

    def test_syntax(self):
        subprocess.run(["bash", "-n", os.path.join(ROOT, "install.sh")], check=True)

    def test_new_install_with_domain_uses_it_for_clients(self):
        v, out = self.run_part("", domain="vpn.example.com")
        self.assertEqual(v["PUBLIC_HOST"], "vpn.example.com")
        self.assertEqual(v["TLS_HOST"], "vpn.example.com")
        self.assertNotIn("WARN", out)

    def test_answer_no_keeps_ip(self):
        v, _ = self.run_part("", domain="vpn.example.com", answer="2")
        self.assertEqual(v["PUBLIC_HOST"], "203.0.113.5")

    def test_domain_elsewhere_can_still_be_chosen(self):
        v, out = self.run_part("", domain="vpn.example.com", dns="198.51.100.1", answer="2")
        self.assertEqual(v["PUBLIC_HOST"], "vpn.example.com")
        self.assertIn("1) 203.0.113.5 (recommended)", out)

    def test_numbered_choice_with_domain_first(self):
        _, out = self.run_part("", domain="vpn.example.com")
        self.assertIn("Which address should client configs use?", out)
        self.assertIn("1) vpn.example.com — configs keep working if the IP changes (recommended)", out)
        self.assertIn("2) 203.0.113.5", out)

    def test_env_answer_skips_question(self):
        os.environ["AWGR_CLIENT_DOMAIN"] = "no"
        try:
            v, out = self.run_part("", domain="vpn.example.com")
        finally:
            del os.environ["AWGR_CLIENT_DOMAIN"]
        self.assertEqual(v["PUBLIC_HOST"], "203.0.113.5")
        self.assertNotIn("Which address", out)

    def test_domain_elsewhere_defaults_to_ip(self):
        # домен за прокси (другой адрес): по умолчанию клиенты остаются на IP
        v, out = self.run_part("", domain="vpn.example.com", dns="198.51.100.1")
        self.assertEqual(v["PUBLIC_HOST"], "203.0.113.5")
        self.assertIn("points to 198.51.100.1, this server is 203.0.113.5", out)

    def test_domain_in_public_host_passes_dns_check(self):
        # ошибка из жалобы: PUBLIC_HOST=домен давал «this server is <домен>»
        v, out = self.run_part("vpn.example.com", domain=None, tls_domain="vpn.example.com", ask_domain=0)
        self.assertEqual(v["PUBLIC_HOST"], "vpn.example.com")
        self.assertNotIn("WARN", out)

    def test_reconfigure_keeps_domain(self):
        v, _ = self.run_part("vpn.example.com", domain=None, tls_domain="vpn.example.com", reconf=1, ask_domain=0)
        self.assertEqual(v["PUBLIC_HOST"], "vpn.example.com")

    def test_reconfigure_refreshes_ip(self):
        v, _ = self.run_part("198.51.100.99", domain="", reconf=1)
        self.assertEqual(v["PUBLIC_HOST"], "203.0.113.5")

    def test_panel_domain_removed_returns_to_ip(self):
        v, _ = self.run_part("vpn.example.com", domain="", tls_domain="vpn.example.com")
        self.assertEqual(v["PUBLIC_HOST"], "203.0.113.5")
        self.assertEqual(v["TLS_HOST"], "203.0.113.5")

    def test_warns_when_panel_address_overrides(self):
        _, out = self.run_part("", domain="vpn.example.com", panel_host="203.0.113.5")
        self.assertIn("WARN The panel has its own server address 203.0.113.5", out)
        self.assertIn("Server → Server public address", out)

    def test_no_warning_when_panel_address_matches(self):
        _, out = self.run_part("", domain="vpn.example.com", panel_host="vpn.example.com")
        self.assertNotIn("WARN", out)


class PanelAddressTest(unittest.TestCase):
    """Сохранение вкладки «Сервер» не должна превращать адрес из .env в свою настройку панели."""

    def setUp(self):
        main.engine.reconcile()
        self.saved = main.store.snapshot()["settings"].get("public_host")

    def tearDown(self):
        def restore(st):
            st["settings"].pop("public_host", None)
            if self.saved is not None:
                st["settings"]["public_host"] = self.saved
        main.store.mutate(restore)

    def save(self, host, env="vpn.example.com"):
        with mock.patch.object(config, "PUBLIC_HOST", env):
            main.engine.srv.update_server({"public_host": host})
            st = main.store.snapshot()
            return st["settings"].get("public_host"), main.engine.srv.public_host(st)

    def test_same_as_env_not_stored(self):
        self.assertEqual(self.save("vpn.example.com"), (None, "vpn.example.com"))
        self.assertEqual(self.save("VPN.Example.com"), (None, "vpn.example.com"))

    def test_env_change_then_applies(self):
        self.save("vpn.example.com")
        with mock.patch.object(config, "PUBLIC_HOST", "new.example.com"):
            self.assertEqual(main.engine.srv.public_host(main.store.snapshot()), "new.example.com")

    def test_other_address_overrides(self):
        self.assertEqual(self.save("203.0.113.9"), ("203.0.113.9", "203.0.113.9"))

    def test_empty_falls_back_to_env(self):
        self.save("203.0.113.9")
        self.assertEqual(self.save(""), (None, "vpn.example.com"))


if __name__ == "__main__":
    unittest.main()
