import copy
import unittest

from app import proxy_clients
from app.web import HTTPError


class ProxyClientSettingsTest(unittest.TestCase):
    def setUp(self):
        self.state = {"upstreams": [{"id": "u1"}, {"id": "u2"}]}
        self.input = {"username": "anton", "password": "long-test-password", "port": 3128,
                      "upstream": "u1", "enabled": True}

    def test_password_hidden_and_disable_independent(self):
        a = proxy_clients.save(self.state, self.input)
        b = proxy_clients.save(self.state, {**self.input, "username": "two", "port": 3129})
        self.assertNotIn("password", a)
        changed = proxy_clients.save(self.state, {"enabled": False}, a["id"])
        self.assertFalse(changed["enabled"])
        self.assertTrue(self.state["proxy_clients"][1]["enabled"])
        self.assertEqual(self.state["proxy_clients"][1]["id"], b["id"])

    def test_uniqueness_and_missing_exit(self):
        proxy_clients.save(self.state, self.input)
        for changes in ({"username": "two"}, {"port": 3129}, {"port": 3130, "username": "z", "upstream": "missing"}):
            with self.subTest(changes=changes), self.assertRaises(HTTPError):
                proxy_clients.save(self.state, {**self.input, **changes})

    def test_duplicate_port_and_username_report_distinct_errors(self):
        proxy_clients.save(self.state, self.input)
        with self.assertRaisesRegex(HTTPError, r"^px\.port_taken$"):
            proxy_clients.save(self.state, {**self.input, "username": "another"})
        with self.assertRaisesRegex(HTTPError, r"^px\.username_taken$"):
            proxy_clients.save(self.state, {**self.input, "port": 3129})

    def test_new_proxy_disabled_by_default(self):
        data = {k: v for k, v in self.input.items() if k != "enabled"}
        self.assertFalse(proxy_clients.save(self.state, data)["enabled"])

    def test_update_keeps_hash_until_password_changed(self):
        entry = proxy_clients.save(self.state, self.input)
        before = self.state["proxy_clients"][0]["password"]
        proxy_clients.save(self.state, {"port": 3129}, entry["id"])
        self.assertEqual(self.state["proxy_clients"][0]["password"], before)
        proxy_clients.save(self.state, {"password": "another-test-password"}, entry["id"])
        self.assertNotEqual(self.state["proxy_clients"][0]["password"], before)

    def test_backup_preserves_clients_and_rejects_corruption(self):
        proxy_clients.save(self.state, self.input)
        saved = copy.deepcopy(self.state["proxy_clients"])
        restored = {"upstreams": [{"id": "u1"}]}
        proxy_clients.restore(restored, saved)
        self.assertEqual(restored["proxy_clients"], saved)
        saved[0]["password"]["hash"] = "invalid"
        with self.assertRaises(HTTPError):
            proxy_clients.restore(restored, saved)
        self.assertNotEqual(restored["proxy_clients"], saved)

    def test_protocol_defaults_to_https_and_legacy_backups_remain_https(self):
        entry = proxy_clients.save(self.state, self.input)
        self.assertEqual(entry["protocol"], "https")
        legacy = copy.deepcopy(self.state["proxy_clients"])
        del legacy[0]["protocol"]
        restored = {"upstreams": [{"id": "u1"}]}
        proxy_clients.restore(restored, legacy)
        self.assertEqual(proxy_clients.public(restored["proxy_clients"][0])["protocol"], "https")
        self.assertEqual(proxy_clients.save(restored, {"enabled": False}, entry["id"])["protocol"], "https")

    def test_http_protocol_persists_and_invalid_protocol_is_rejected(self):
        entry = proxy_clients.save(self.state, {**self.input, "protocol": "http"})
        self.assertEqual(entry["protocol"], "http")
        restored = {"upstreams": [{"id": "u1"}]}
        proxy_clients.restore(restored, copy.deepcopy(self.state["proxy_clients"]))
        self.assertEqual(restored["proxy_clients"][0]["protocol"], "http")
        with self.assertRaises(HTTPError):
            proxy_clients.save(self.state, {"protocol": "socks5"}, entry["id"])
        restored["proxy_clients"][0]["protocol"] = "invalid"
        with self.assertRaises(HTTPError):
            proxy_clients.restore({"upstreams": [{"id": "u1"}]}, restored["proxy_clients"])



if __name__ == "__main__":
    unittest.main()
