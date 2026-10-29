"""Тесты разбора конфигов и генерации правил: python3 -m unittest discover tests"""
import base64
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import awgconf, lists, nftgen  # noqa: E402

PRIV = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
PUB = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="

CONF = f"""[Interface]
Address = 10.8.1.3/32
DNS = 1.1.1.1, 1.0.0.1
PrivateKey = {PRIV}
Jc = 4
Jmin = 10
Jmax = 50
S1 = 86
S2 = 74
S3 = 17
S4 = 9
H1 = 1023441523-1023441600
H2 = 1810120232
H3 = 1477306744
H4 = 1405262434
I1 = <b 0xc2000000011419fa4bb3599f336777de79f81ca9a8d80d91eeec000044c635cef024a885dcb66d1420a91a8c427e87d6cf8e08b563932f449412cddf77d3e2594ea1c7a183c238a89e9adb7ffa57c133e55c59bec101634db90afb83f75b19fe703179e26a31902324c73f82d9354e1ed8da39af610afcb27e6590a44341a0828e5a3d2f0e0f7b0945d7bf3402feea0ee6332e19bdf48ffc387a97227aa97b205a485d282cd66d1c384bafd63dc42f822c4df2109db5b5646c458236ddcc01ae1c493482128bc0830c9e1f1>
RekeyAfterTime = 300
MTU = 1376

[Peer]
PublicKey = {PUB}
PresharedKey = {PUB}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.10:47823
PersistentKeepalive = 0
"""


def qcompress(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + zlib.compress(data, 8)


class AwgConfTest(unittest.TestCase):
    def check(self, pc):
        self.assertEqual(pc.address, "10.8.1.3")
        self.assertEqual(pc.mtu, 1376)
        self.assertEqual(pc.endpoint, "203.0.113.10:47823")
        self.assertEqual(pc.rekey_after, 300)
        self.assertNotIn("Address", pc.setconf)
        self.assertNotIn("DNS", pc.setconf)
        self.assertNotIn("MTU", pc.setconf)
        self.assertIn("AllowedIPs = 0.0.0.0/0\n", pc.setconf)
        self.assertIn("PersistentKeepalive = 25", pc.setconf)
        self.assertIn("I1 = <b 0xc2", pc.setconf)
        self.assertIn("H1 = 1023441523-1023441600", pc.setconf)

    def test_plain(self):
        self.check(awgconf.parse_upstream(CONF))

    def test_vpn_link(self):
        exported = {"containers": [{"container": "amnezia-awg2", "awg": {
            "last_config": json.dumps({"config": CONF, "hostName": "203.0.113.10"})}}],
            "defaultContainer": "amnezia-awg2", "description": "test"}
        link = "vpn://" + base64.urlsafe_b64encode(qcompress(json.dumps(exported).encode())).decode().rstrip("=")
        self.check(awgconf.parse_upstream(link))

    def test_errors(self):
        with self.assertRaises(awgconf.ConfigError):
            awgconf.parse_upstream("[Interface]\nPrivateKey = bad\n[Peer]\nPublicKey = x\n")
        with self.assertRaises(awgconf.ConfigError):
            awgconf.parse_upstream(CONF.replace("Address = 10.8.1.3/32", "Address = fd00::2/128"))
        with self.assertRaises(awgconf.ConfigError):
            awgconf.parse_upstream("vpn://AAAA")

    def test_server_conf(self):
        srv = awgconf.parse_server_conf(f"""[Interface]
PrivateKey = {PRIV}
Address = 10.8.1.0/24
ListenPort = 47823

[Peer]
PublicKey = {PUB}
PresharedKey = {PUB}
AllowedIPs = 10.8.1.2/32
""")
        self.assertEqual(srv["peers"], [{"public_key": PUB, "ip": "10.8.1.2"}])


class ListsTest(unittest.TestCase):
    def test_asn(self):
        self.assertEqual(lists.parse_asns("AS13238, 15169 as47541;AS13238 junk 0"), [13238, 15169, 47541])

    def test_awg_versions(self):
        self.assertEqual(awgconf.parse_upstream(CONF).version, "3")
        v2 = "\n".join(l for l in CONF.splitlines() if not l.startswith("RekeyAfterTime"))
        self.assertEqual(awgconf.parse_upstream(v2).version, "2")
        v1 = "\n".join(l for l in v2.splitlines() if not l.startswith(("S3", "S4", "I1")))
        self.assertEqual(awgconf.parse_upstream(v1).version, "1")

    def test_keepalive_range(self):
        pc = awgconf.parse_upstream(CONF.replace("PersistentKeepalive = 0", "PersistentKeepalive = 22-30"))
        self.assertIn("PersistentKeepalive = 22-30", pc.setconf)
        pc = awgconf.parse_upstream(CONF.replace("PersistentKeepalive = 0", "PersistentKeepalive = (off)"))
        self.assertIn("PersistentKeepalive = 25", pc.setconf)

    def test_error_is_key(self):
        with self.assertRaises(awgconf.ConfigError) as cm:
            awgconf.parse_upstream("vpn://AAAA")
        self.assertTrue(cm.exception.msg.key.startswith("cfg."))

    def test_parse(self):
        nets = lists.parse_cidrs("# c\n1.2.3.0/24\n1.2.3.4\n2001:db8::/32\n10.0.0.1/8, 5.5.5.5 ; x\nmusor\n")
        self.assertEqual([str(n) for n in nets], ["1.2.3.0/24", "5.5.5.5/32", "10.0.0.0/8"])

    def test_matcher(self):
        lists.save_cidrs("t", lists.parse_cidrs("1.2.3.0/24\n8.8.8.0/24"))
        m = lists.Matcher()
        self.assertEqual(m.contains("t", "8.8.8.8"), "8.8.8.0/24")
        self.assertIsNone(m.contains("t", "8.8.9.1"))


class NftTest(unittest.TestCase):
    def ruleset(self):
        return nftgen.generate(
            "awg0",
            {"ru": ["5.3.0.0/16", "77.88.0.0/18"], "cn": ["1.0.1.0/24"], "empty": []},
            [{"num": 1, "snat": "10.8.1.3", "mtu": 1376}, {"num": 2, "snat": "10.9.9.2", "mtu": 1280}],
            {"rules": [(["ru", "cn", "empty"], "direct")], "default": 1},
            {"10.8.1.5": {"rules": [], "default": "direct"},
             "10.8.1.6": {"rules": [(["ru"], "direct")], "default": 2},
             "10.8.1.7": {"rules": [(["ru", "cn", "empty"], "direct")], "default": 1},  # = глобальной
             "10.8.1.8": {"rules": [], "default": 7}})  # несуществующий туннель → блок

    def test_structure(self):
        t = self.ruleset()
        self.assertIn("10.8.1.5 : goto p_1", t)
        self.assertIn("10.8.1.6 : goto p_2", t)
        self.assertNotIn("10.8.1.7 :", t)
        self.assertIn("10.8.1.8 : goto p_3", t)
        self.assertIn("goto o_block", t.split("chain p_3")[1].split("}")[0])
        self.assertNotIn("@l_empty", t)
        self.assertIn('oifname "awgr1" snat to 10.8.1.3', t)
        self.assertIn("maxseg size set 1336", t)

    @unittest.skipUnless(shutil.which("nft") and os.geteuid() == 0, "нужен nft и root")
    def test_nft_accepts(self):
        with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
            f.write(self.ruleset())
        p = subprocess.run(["nft", "-c", "-f", f.name], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)


if __name__ == "__main__":
    unittest.main()


# ------------------------------------------------------------------ сервер
from app import awgserver  # noqa: E402

AMNEZIA_SERVER = f"""[Interface]
PrivateKey = {PRIV}
Address = 10.8.1.0/24
ListenPort = 47823
Jc = 4
Jmin = 10
Jmax = 50
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = {PUB}
RekeyAfterTime = 100-120
RandomTrailers = on
# I1 = <r 2><b 0x8580>
# I2 = $SPECIAL_JUNK_2

[Peer]
PublicKey = {PUB}
PresharedKey = {PUB}
AllowedIPs = 10.8.1.1/32

[Peer]
PublicKey = {PRIV}
PresharedKey = {PUB}
AllowedIPs = 10.8.1.2/32

"""


class ServerConfTest(unittest.TestCase):
    def test_amnezia_roundtrip(self):
        sc = awgserver.parse(AMNEZIA_SERVER)
        self.assertEqual(sc.port, 47823)
        self.assertEqual(sc.get("I1"), "<r 2><b 0x8580>")
        self.assertEqual(len(sc.peers), 2)
        out = sc.render()
        # формат, который читает приложение AmneziaVPN
        self.assertIn("# I1 = <r 2><b 0x8580>", out)
        self.assertIn("Jc = 4\n", out)
        self.assertNotIn("I1 = <r 2>", out.replace("# I1", ""))
        again = awgserver.parse(out)
        self.assertEqual(again.render(), out)
        # stripped: без Address и комментариев
        st = sc.stripped()
        self.assertNotIn("Address", st)
        self.assertNotIn("#", st)

    def test_next_ip_amnezia_style(self):
        sc = awgserver.parse(AMNEZIA_SERVER)
        self.assertEqual(sc.next_ip(), "10.8.1.3")   # .0 — адрес сервера, .1 и .2 заняты

    def test_disable_keeps_address(self):
        sc = awgserver.parse(AMNEZIA_SERVER)
        sc.peers[0].enabled = False
        out = sc.render()
        self.assertIn(awgserver.DISABLED_MARK, out)
        again = awgserver.parse(out)
        self.assertFalse(again.peers[0].enabled)
        self.assertEqual(again.peers[0].ip, "10.8.1.1")
        self.assertEqual(again.next_ip(), "10.8.1.3")   # адрес отключённого не отдаётся
        self.assertNotIn(PUB + "\nPresharedKey", again.stripped().split("[Peer]")[0])
        self.assertEqual(again.stripped().count("[Peer]"), 1)

    def test_validate(self):
        ok = awgserver.validate_params({"Jc": "5", "H1": "100-200", "H2": "300", "RandomTrailers": "true",
                                        "I2": "<b 0xabcd><r 16><t>", "S1": ""})
        self.assertEqual(ok["RandomTrailers"], "on")
        self.assertEqual(ok["S1"], "")
        for bad in ({"Jmin": "60", "Jmax": "50"}, {"H1": "1-10", "H2": "5"}, {"S1": "20", "S2": "76"},
                    {"Jc": "x"}, {"I1": "rubbish"}, {"Foo": "1"}, {"HeaderProtectionKey": "short"}):
            with self.assertRaises(awgserver.ServerConfError, msg=bad):
                awgserver.validate_params(bad)

    def test_generate(self):
        for hp in (True, False):
            p = awgserver.generate_params(hp)
            self.assertEqual(awgserver.validate_params(p).keys(), p.keys())
        self.assertEqual(awgserver.protocol_version(awgserver.generate_params(True)), "3.1")

    def test_server_side_change(self):
        a = {"Jc": "4", "S1": "12"}
        self.assertFalse(awgserver.server_side_changed(a, {"Jc": "6", "S1": "12"}))
        self.assertTrue(awgserver.server_side_changed(a, {"Jc": "4", "S1": "20"}))

    def test_vpn_link_roundtrip(self):
        sc = awgserver.parse(AMNEZIA_SERVER)
        prof = awgserver.ClientProfile("203.0.113.5", 47823, PUB, ["1.1.1.1"], 1376, "25-35")
        conf = awgserver.client_conf(sc, prof, sc.peers[0], PRIV)
        self.assertIn("I1 = <r 2><b 0x8580>", conf)
        link = awgserver.vpn_link(sc, prof, sc.peers[0], PRIV, conf, "test")
        pc = awgconf.parse_upstream(link)
        self.assertEqual(pc.address, "10.8.1.1")
        self.assertEqual(pc.endpoint, "203.0.113.5:47823")
        raw = zlib.decompress(base64.urlsafe_b64decode(link[6:] + "==")[4:])
        doc = json.loads(raw)
        self.assertEqual(doc["containers"][0]["container"], "amnezia-awg2")
        self.assertEqual(json.loads(doc["containers"][0]["awg"]["last_config"])["client_ip"], "10.8.1.1")


class InitServerTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("awg"), "нужен awg")
    def test_amnezia_layout(self):
        from app import initserver
        d = tempfile.mkdtemp()
        self.assertEqual(initserver.main(["--out", d, "--port", "47001"]), 0)
        for f in ("awg0.conf", "wireguard_server_private_key.key", "wireguard_server_public_key.key",
                  "wireguard_psk.key", "clientsTable"):
            self.assertTrue(os.path.exists(os.path.join(d, f)), f)
        sc = awgserver.parse(open(os.path.join(d, "awg0.conf")).read())
        self.assertEqual(sc.get("Address"), "10.8.1.0/24")
        self.assertEqual(sc.port, 47001)
        self.assertEqual(sc.next_ip(), "10.8.1.1")          # как первый клиент у AmneziaVPN
        self.assertFalse(any(k == "PostUp" for k, _ in sc.iface))
        self.assertEqual(os.stat(os.path.join(d, "awg0.conf")).st_mode & 0o777, 0o600)
        # повторный запуск не перезаписывает
        before = open(os.path.join(d, "awg0.conf")).read()
        initserver.main(["--out", d, "--port", "1234"])
        self.assertEqual(open(os.path.join(d, "awg0.conf")).read(), before)


class TotpTest(unittest.TestCase):
    SECRET = base64.b32encode(b"12345678901234567890").decode()

    def test_rfc6238_vectors(self):
        from app import totp
        # RFC 6238, SHA-1: последние 6 цифр восьмизначных кодов
        for ts, code in ((59, "287082"), (1111111109, "081804"), (1234567890, "005924"),
                         (2000000000, "279037")):
            self.assertEqual(totp.code_at(self.SECRET, ts // 30), code)

    def test_match_window_and_replay(self):
        from app import totp
        now = 1234567890
        c = totp.code_at(self.SECRET, now // 30)
        self.assertEqual(totp.match(self.SECRET, c, now), now // 30)
        self.assertEqual(totp.match(self.SECRET, c[:3] + " " + c[3:], now + 30), now // 30)
        self.assertIsNone(totp.match(self.SECRET, c, now + 90))
        self.assertIsNone(totp.match(self.SECRET, c, now, after=now // 30))
        self.assertIsNone(totp.match(self.SECRET, "12345", now))

    def test_store_and_use_once(self):
        from app import totp
        totp.save({"secret": self.SECRET, "since": 0, "last_step": -1})
        try:
            import time
            c = totp.code_at(self.SECRET, int(time.time() // 30))
            self.assertTrue(totp.check_and_use(c))
            self.assertFalse(totp.check_and_use(c))       # повтор того же кода
            self.assertIn("secret=" + self.SECRET, totp.uri(self.SECRET, "1.2.3.4"))
        finally:
            totp.save(None)
        self.assertIsNone(totp.load())


class NotifyTest(unittest.TestCase):
    def test_texts_complete(self):
        from app import notify
        keys = set(notify.TEXTS["en"])
        for lang in notify.LANGS:
            self.assertEqual(set(notify.TEXTS[lang]), keys, lang)
            for k in keys:
                self.assertEqual(sorted(set(__import__("re").findall(r"\{\w+\}", notify.TEXTS[lang][k]))),
                                 sorted(set(__import__("re").findall(r"\{\w+\}", notify.TEXTS["en"][k]))), (lang, k))
        for _, key in notify.ENGINE_EVENTS.values():
            self.assertIn(key, keys)

    def test_render_and_view(self):
        from app import notify
        self.assertEqual(notify.render("ru", "exit_up", "1.2.3.4", name="de"),
                         "AWG Router · 1.2.3.4\n✅ Выход «de» снова работает.")
        c = notify.cfg_of({"settings": {"telegram": {"enabled": True, "token": "123456:" + "A" * 35,
                                                     "events": {"login": False}}}})
        self.assertTrue(c["events"]["exit"])
        self.assertFalse(c["events"]["login"])
        v = notify.public_view(c)
        self.assertNotIn("token", v)
        self.assertTrue(v["token_set"])
        self.assertEqual(v["token_hint"], "123456:…AAAA")


class TrafficTest(unittest.TestCase):
    def test_accumulate_and_reset(self):
        from app.traffic import Traffic, month_key
        tr = Traffic(os.path.join(tempfile.mkdtemp(), "t.json"))
        c = {"public_key": "K", "enabled": True, "live": {"rx": 100, "tx": 1000}}
        tr.update([c], now=1_000_000)
        c["live"] = {"rx": 150, "tx": 1500}
        tr.update([c], now=1_000_010)
        c["live"] = {"rx": 20, "tx": 30}            # счётчики обнулились (перезапуск)
        tr.update([c], now=1_000_020)
        self.assertEqual(tr.total("K"), [170, 1530])
        self.assertEqual(tr.month("K", month_key(1_000_000)), [170, 1530])
        tr.update([{"public_key": "K", "enabled": False, "live": None}], now=1_000_030)
        self.assertEqual(tr.used("K", "total"), 1700)
        tr.save()
        tr2 = Traffic(tr.path)
        self.assertEqual(tr2.total("K"), [170, 1530])


class LimitsTest(unittest.TestCase):
    def _engine(self, limits_state, used):
        from app import limits as lim

        class Store:
            def __init__(s):
                s.st = {"limits": limits_state}

            def snapshot(s):
                return json.loads(json.dumps(s.st))

            def mutate(s, fn):
                fn(s.st)

        class Srv:
            def __init__(s, eng):
                s.e = eng

            def update_client(s, pk, enabled=None):
                for c in s.e.clients:
                    if c["public_key"] == pk:
                        c["enabled"] = enabled

        class Tr:
            def used(s, pk, period):
                return used

        class Eng:
            pass
        e = Eng()
        e.store, e.traffic, e.events = Store(), Tr(), []
        e.clients = [{"public_key": "K", "name": "n", "enabled": True}]
        e.srv = Srv(e)
        e.event = lambda lvl, m: e.events.append(m.key)
        return e, lim

    def test_quota_and_new_month(self):
        e, lim = self._engine({"K": {"quota": 100, "period": "month"}}, used=150)
        lim.enforce(e, now=1_000_000)
        self.assertFalse(e.clients[0]["enabled"])
        self.assertTrue(e.store.st["limits"]["K"]["auto_off"].startswith("quota:"))
        lim.enforce(e, now=1_000_000 + 40 * 86400)           # следующий месяц
        self.assertTrue(e.clients[0]["enabled"])
        self.assertIn("ev.client_quota_reset", e.events)

    def test_expiry_and_manual_enable(self):
        e, lim = self._engine({"K": {"expires": 1_000_000}}, used=0)
        lim.enforce(e, now=1_000_001)
        self.assertFalse(e.clients[0]["enabled"])
        self.assertEqual(e.store.st["limits"]["K"]["auto_off"], "exp")
        e.clients[0]["enabled"] = True                      # включили вручную
        lim.enforce(e, now=1_000_100)
        self.assertTrue(e.clients[0]["enabled"])            # повторно не отключаем
        self.assertIsNone(e.store.st["limits"]["K"]["auto_off"])
