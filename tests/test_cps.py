"""Сигнатурные пакеты I1–I5: проверка тегов, шаблоны, свои значения клиента.

python3 -m unittest discover tests
"""
import os
import random
import string
import struct
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import awgserver, cps  # noqa: E402

PUB = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
PRIV = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="


def expand(v: str) -> bytes:
    """Пакет, как его соберёт клиент (случайные части — случайные)."""
    out = b""
    for tok in cps.TOKEN_RE.findall(v):
        name, _, arg = tok[1:-1].strip().partition(" ")
        if name == "b":
            out += bytes.fromhex(arg[2:])
        elif name == "r":
            out += os.urandom(int(arg))
        elif name == "rc":
            out += "".join(random.choice(string.ascii_letters) for _ in range(int(arg))).encode()
        elif name == "rd":
            out += "".join(random.choice(string.digits) for _ in range(int(arg))).encode()
        elif name == "t":
            out += struct.pack(">I", 1_800_000_000)
    return out


class Req:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class SizeTest(unittest.TestCase):
    def test_valid(self):
        for v, n in (("<b 0x0102><r 4>", 6), ("<rc 5> <rd 3><t>", 12), ("<b 0xAABB>", 2),
                     (cps.AMNEZIA_I1, 44), ("", 0)):
            self.assertEqual(cps.size(v), n, v)

    def test_invalid(self):
        for v, key in (("<b 0x012>", "srv.cps_hex"), ("<b 012>", "srv.cps_hex"), ("<b 0X01>", "srv.cps_hex"),
                       ("<c>", "srv.cps_unsupported"), ("<d>", "srv.cps_unsupported"),
                       ("<ds>", "srv.cps_unsupported"), ("<x 1>", "srv.cps_tag"),
                       ("text <r 3>", "srv.cps_text"), ("<r 3", "srv.cps_text"), ("<>", "srv.cps_text"),
                       ("<r 0>", "srv.cps_num"), ("<r 2000>", "srv.cps_num"), ("<r>", "srv.cps_num"),
                       ("<t 5>", "srv.cps_num"), ("<r 1000><r 500>", "srv.cps_size")):
            with self.assertRaises(cps.CPSError, msg=v) as cm:
                cps.size(v, "I2")
            self.assertEqual(cm.exception.msg.key, key, v)
            self.assertEqual(cm.exception.msg.p["key"], "I2")

    def test_server_params(self):
        self.assertEqual(awgserver.validate_params({"I1": "<b 0xAA>   <r 4>"})["I1"], "<b 0xAA> <r 4>")
        with self.assertRaises(awgserver.ServerConfError) as cm:
            awgserver.validate_params({"I3": "<c>"})
        self.assertEqual(cm.exception.msg.key, "srv.cps_unsupported")
        self.assertEqual(awgserver.DEFAULT_I1, cps.AMNEZIA_I1)


class PresetTest(unittest.TestCase):
    def test_all_valid(self):
        sizes = {p["id"]: p["sizes"] for p in cps.catalog()}
        self.assertEqual(list(sizes), ["amnezia", "stun", "quic", "dns", "sip", "none"])
        self.assertEqual((sizes["quic"]["I1"], sizes["dns"]["I1"], sizes["stun"]["I1"]), (1200, 128, 88))
        self.assertEqual(sizes["none"], {})
        for name in cps.PRESETS:
            self.assertEqual(cps.validate(cps.preset(name)), cps.preset(name))
            self.assertEqual(cps.match(cps.preset(name)), name)
        self.assertIsNone(cps.match({"I1": "<r 5>"}))

    def test_quic_initial(self):
        q = expand(cps.PRESETS["quic"]["I1"])
        self.assertEqual(len(q), 1200)                       # RFC 9000: Initial клиента ≥ 1200
        self.assertEqual(q[0] & 0xF0, 0xC0)                  # long header, Initial
        self.assertEqual(q[1:5], b"\x00\x00\x00\x01")        # QUIC v1
        self.assertEqual((q[5], q[14], q[15]), (8, 0, 0))    # DCID 8, SCID 0, токен 0
        self.assertEqual(int.from_bytes(q[16:18], "big") & 0x3FFF, len(q) - 18)

    def test_dns_query(self):
        d = expand(cps.PRESETS["dns"]["I1"])
        self.assertEqual(len(d), 128)
        flags, qd, an, ns, ar = struct.unpack(">5H", d[2:12])
        self.assertEqual((flags, qd, an, ns, ar), (0x0100, 1, 0, 0, 1))
        p, labels = 12, []
        while d[p]:
            labels.append(d[p + 1:p + 1 + d[p]])
            p += 1 + d[p]
        self.assertEqual((len(labels[0]), labels[1]), (12, b"com"))
        qtype, qclass = struct.unpack(">HH", d[p + 1:p + 5])
        self.assertEqual((qtype, qclass), (1, 1))
        p += 5
        name, typ, udp, _, _, _, rdlen = struct.unpack(">BHHBBHH", d[p:p + 11])
        self.assertEqual((name, typ, udp), (0, 41, 1232))     # EDNS0 OPT
        self.assertEqual(p + 11 + rdlen, len(d))
        self.assertEqual(struct.unpack(">HH", d[p + 11:p + 15]), (12, rdlen - 4))  # padding

    def test_stun_binding(self):
        s = expand(cps.PRESETS["stun"]["I1"])
        typ, length, cookie = struct.unpack(">HHI", s[:8])
        self.assertEqual((typ, length, cookie), (0x0001, len(s) - 20, 0x2112A442))
        p, attrs = 20, []
        while p < len(s):
            at, al = struct.unpack(">HH", s[p:p + 4])
            attrs.append(at)
            p += 4 + al + (-al % 4)
        self.assertEqual(p, len(s))
        self.assertEqual(attrs, [0x0006, 0x802A, 0x0024, 0x0008, 0x8028])

    def test_sip_invite(self):
        text = expand(cps.PRESETS["sip"]["I1"]).decode()
        lines = text.split("\r\n")
        self.assertRegex(lines[0], r"^INVITE sip:\d{10}@[A-Za-z]{8}\.com SIP/2\.0$")
        self.assertTrue(text.endswith("Content-Length: 0\r\n\r\n"))
        for h in ("Via:", "From:", "To:", "Call-ID:", "CSeq: 1 INVITE", "Contact:"):
            self.assertTrue(any(ln.startswith(h) for ln in lines), h)

    def test_random_parts_differ(self):
        for name in ("stun", "quic", "dns", "sip"):
            v = cps.PRESETS[name]["I1"]
            self.assertNotEqual(expand(v), expand(v), name)


class ClientOverrideTest(unittest.TestCase):
    def conf(self, override):
        sc = awgserver.ServerConf()
        sc.iface = [("PrivateKey", PRIV), ("Address", "10.8.1.0/24"), ("ListenPort", "47823")]
        for k, v in {"Jc": "5", "I1": cps.AMNEZIA_I1, "I2": "<r 10>"}.items():
            sc.set(k, v)
        prof = awgserver.ClientProfile("203.0.113.5", 47823, PUB, ["1.1.1.1"])
        peer = awgserver.Peer(PUB, "", "10.8.1.2/32")
        return awgserver.client_conf(sc, prof, peer, PRIV, override), \
            awgserver.vpn_link(sc, prof, peer, PRIV, "", "x", override)

    def test_override(self):
        conf, _ = self.conf(None)
        self.assertIn("I1 = " + cps.AMNEZIA_I1, conf)
        self.assertIn("I2 = <r 10>", conf)
        conf, link = self.conf(cps.for_client({"preset": "stun"}))
        self.assertIn("I1 = " + cps.PRESETS["stun"]["I1"], conf)
        self.assertNotIn("I2 =", conf)                        # шаблон заменяет все пять
        self.assertIn("Jc = 5", conf)                         # остальное — как на сервере
        conf, _ = self.conf(cps.for_client({"preset": "none"}))
        self.assertNotIn("I1 =", conf)

    def test_for_client(self):
        self.assertIsNone(cps.for_client(None))
        self.assertIsNone(cps.for_client({"preset": "weird"}))
        self.assertIsNone(cps.for_client({"preset": "custom", "values": {"I1": "<c>"}}))
        self.assertEqual(cps.for_client({"preset": "custom", "values": {"I3": "<r 4>"}})["I3"], "<r 4>")


class ApiTest(unittest.TestCase):
    def test_put_client_cps(self):
        from app import main, web
        with mock.patch.object(main.engine, "clients", [{"public_key": PUB}]):
            self.assertEqual(main.put_client_cps(Req({"preset": "quic"}), PUB)["cps"],
                             {"preset": "quic", "values": None})
            self.assertEqual(main.store.snapshot()["cps"][PUB], {"preset": "quic"})
            r = main.put_client_cps(Req({"preset": "custom", "values": {"I1": "<rc 8>"}}), PUB)
            self.assertEqual(r["cps"]["values"]["I1"], "<rc 8>")
            for bad in ({"preset": "custom", "values": {"I1": "<c>"}}, {"preset": "nope"}):
                with self.assertRaises(web.HTTPError):
                    main.put_client_cps(Req(bad), PUB)
            main.put_client_cps(Req({"preset": "server"}), PUB)
            self.assertNotIn(PUB, main.store.snapshot()["cps"])
        with self.assertRaises(web.HTTPError):
            main.put_client_cps(Req({"preset": "quic"}), PUB)     # нет такого клиента

    def test_restore(self):
        from app import main, web
        import test_api
        s = test_api.good_state()
        s["cps"] = {PUB: {"preset": "sip", "junk": 1}}
        self.assertEqual(main.clean_backup_state(s)["cps"], {PUB: {"preset": "sip"}})
        for bad in ({PUB: {"preset": "custom", "values": {"I1": "<c>"}}}, {PUB: {"preset": "x"}},
                    {"not-a-key": {"preset": "sip"}}):
            s["cps"] = bad
            with self.assertRaises(web.HTTPError):
                main.clean_backup_state(s)


if __name__ == "__main__":
    unittest.main()
