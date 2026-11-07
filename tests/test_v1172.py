"""1.17.2: в названии подключения в AmneziaVPN (vpn://) — только имя клиента, без адреса сервера (#7).

python3 -m unittest discover tests
"""
import base64
import json
import threading
import unittest
import zlib
from unittest import mock

from app import awgserver
from app.users import ServerManager
from tests.test_core import AMNEZIA_SERVER, PRIV, PUB


def description(link: str) -> str:
    return json.loads(zlib.decompress(base64.urlsafe_b64decode(link[6:] + "==")[4:]))["description"]


class ConnectionNameTest(unittest.TestCase):
    def config(self, client_name):
        sc = awgserver.parse(AMNEZIA_SERVER)
        peer = sc.peers[0]
        rows = [{"clientId": peer.public_key, "userData": {"clientName": client_name}}] if client_name else []
        m = ServerManager.__new__(ServerManager)
        m.e = mock.Mock(lock=threading.Lock())
        m.e.store.snapshot.return_value = {"keys": {peer.public_key: PRIV}, "cps": {}}
        m._target = lambda: object()
        m.load = lambda t: (sc, rows)
        m.profile = lambda st, sc_: awgserver.ClientProfile("203.0.113.5", 47823, PUB, ["1.1.1.1"], 1376, "25-35")
        m.client_host = lambda st: "203.0.113.5"
        return m.client_config(peer.public_key)

    def test_only_the_client_name(self):
        cfg = self.config("Phone")
        self.assertEqual(description(cfg["link"]), "Phone")
        self.assertNotIn("203.0.113.5", description(cfg["link"]))
        self.assertEqual(cfg["filename"], "Phone.conf")

    def test_name_with_spaces_and_cyrillic_stays_as_is(self):
        self.assertEqual(description(self.config("Мой телефон")["link"]), "Мой телефон")

    def test_unnamed_client(self):
        cfg = self.config(None)
        self.assertEqual(description(cfg["link"]), cfg["name"])
        self.assertNotIn("·", description(cfg["link"]))


if __name__ == "__main__":
    unittest.main()
