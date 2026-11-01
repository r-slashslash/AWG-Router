"""1.12.0: выходы SOCKS5 и правила по доменам для них (sniproxy.py: имя сайта из TLS/HTTP).

python3 -m unittest discover tests
Сквозная проверка с настоящими nftables, sniproxy.py и hev-socks5-tunnel — tests/domains_socks_e2e.py.
"""
import asyncio
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.store import Store  # noqa: E402
from app import awgconf, config, domains, lists, nftgen, sniproxy, socks, web  # noqa: E402
from app import main  # noqa: E402
from tests import e2e_servers  # noqa: E402


class Req:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


# ------------------------------------------------------------------ домены
class DomainsTest(unittest.TestCase):
    def test_formats(self):
        text = """
# комментарий
YouTube.com
*.googlevideo.com
.ytimg.com
server=/a.example/b.example/1.1.1.1
nftset=/c.example/4#inet#fw4#vpn
||ads.example^
||bad.example/path^
0.0.0.0 tracker.example
domain:v2.example
full:exact.example
regexp:.*\\.re$
keyword:google
DOMAIN-SUFFIX,clash.example
https://www.url.example/some/page
пример.рф
1.2.3.4
not_a@domain
www.youtube.com
"""
        self.assertEqual(domains.parse(text), [
            "youtube.com", "googlevideo.com", "ytimg.com", "a.example", "b.example", "c.example",
            "ads.example", "tracker.example", "v2.example", "exact.example", "clash.example",
            "www.url.example", "xn--e1afmkfd.xn--p1ai"])

    def test_match(self):
        s = {"youtube.com", "ru"}
        self.assertEqual(domains.matches("www.YouTube.com.", s), "youtube.com")
        self.assertEqual(domains.matches("youtube.com", s), "youtube.com")
        self.assertIsNone(domains.matches("notyoutube.com", s))
        self.assertEqual(domains.matches("ya.ru", s), "ru")             # запись-зона

    def test_split_source(self):
        urls, text = domains.split_source("a.com\nhttps://x.example/list.txt\n b.com ")
        self.assertEqual(urls, ["https://x.example/list.txt"])
        self.assertEqual(domains.parse(text), ["a.com", "b.com"])

    def test_refresh_with_urls(self):
        lst = {"id": "ldtest1", "kind": "domains", "source": "a.com\nhttps://x.example/l.txt\nhttps://y.example/l.txt"}
        with mock.patch.object(lists, "_fetch", side_effect=["b.com\nsub.a.com\n", OSError("timeout")]):
            r = lists.refresh(lst)
        self.assertIsNone(r["error"])               # одна ссылка не скачалась, но домены есть
        self.assertEqual(r["count"], 2)
        self.assertEqual(domains.load("ldtest1"), ["a.com", "b.com"])
        with mock.patch.object(lists, "_fetch", side_effect=OSError("down")):
            r = lists.refresh({"id": "ldtest2", "kind": "domains", "source": "https://x.example/l.txt"})
        self.assertEqual(r["error"]["$t"], "list.fetch_failed")
        lists.delete_cidrs("ldtest1")
        self.assertFalse(os.path.exists(domains.path_for("ldtest1")))


# ------------------------------------------------------------------ SOCKS5
class SocksParseTest(unittest.TestCase):
    def test_formats(self):
        cases = {
            "socks5://1.2.3.4:1080": ("1.2.3.4", 1080, "", ""),
            "socks5h://u:p%40ss@Proxy.Example.com:1080": ("proxy.example.com", 1080, "u", "p@ss"),
            "socks://u:p@[2001:db8::1]:9050": ("2001:db8::1", 9050, "u", "p"),
            "proxy.example.com:1080:user:pa:ss": ("proxy.example.com", 1080, "user", "pa:ss"),
            "user:pass@1.2.3.4:9050": ("1.2.3.4", 9050, "user", "pass"),
        }
        for text, (h, p, u, pw) in cases.items():
            pc = awgconf.parse_upstream(text)
            self.assertEqual(pc.kind, "socks5", text)
            self.assertEqual((pc.socks["host"], pc.socks["port"], pc.socks["user"], pc.socks["password"]),
                             (h, p, u, pw), text)
            self.assertEqual(awgconf.parse_upstream(pc.raw).socks, pc.socks, text)   # raw разбирается так же

    def test_errors(self):
        for text, key in (("socks5://h:0", "cfg.socks_port"), ("socks5://bad_host:10", "cfg.socks_host"),
                          ("socks5://:p@1.2.3.4:10", "cfg.socks_auth"), ("socks5://1.2.3.4:10/x", "cfg.socks_bad")):
            with self.assertRaises(awgconf.ConfigError) as cm:
                awgconf.parse_upstream(text)
            self.assertEqual(cm.exception.msg.key, key, text)

    def test_awg_configs_unaffected(self):
        self.assertFalse(awgconf.is_socks("vpn://AAAAeJyrVkrLz1eyUkpKLFKqBQAb"))
        self.assertFalse(awgconf.is_socks("[Interface]\nPrivateKey = x\n"))

    def test_hev_config(self):
        y = socks.hev_config("awgr3", 3, "203.0.113.9", {"port": 1080, "user": "a'b", "password": "p: #1"})
        self.assertIn("name: 'awgr3'", y)
        self.assertIn("ipv4: '169.254.200.3'", y)
        self.assertIn("address: '203.0.113.9'", y)
        self.assertIn("username: 'a''b'", y)                 # кавычка в YAML удваивается
        self.assertIn("password: 'p: #1'", y)
        self.assertNotIn("username", socks.hev_config("awgr1", 1, "1.2.3.4", {"port": 1}))


class SocksCheckTest(unittest.TestCase):
    """socks.check против настоящего (тестового) сервера SOCKS5 на 127.0.0.1."""

    @classmethod
    def setUpClass(cls):
        cls.target = socket.socket()
        cls.target.bind(("127.0.0.1", 0))
        cls.target.listen(8)
        threading.Thread(target=lambda: [cls.target.accept()[0].close() for _ in iter(int, 1)], daemon=True).start()
        cls.srv = socket.socket()
        cls.srv.bind(("127.0.0.1", 0))
        cls.srv.listen(8)
        cls.port = cls.srv.getsockname()[1]

        def loop():
            while True:
                c, _ = cls.srv.accept()
                threading.Thread(target=e2e_servers.socks_client, args=(c, "alice", "pw"), daemon=True).start()
        threading.Thread(target=loop, daemon=True).start()

    def test_ok_and_errors(self):
        tgt = ("127.0.0.1", self.target.getsockname()[1])
        ms = socks.connect_check("127.0.0.1", self.port, "alice", "pw", tgt)
        self.assertGreaterEqual(ms, 0)
        for user, pw, key in (("alice", "bad", "socks.auth_failed"), ("", "", "socks.auth_required")):
            with self.assertRaises(socks.SocksError) as cm:
                socks.connect_check("127.0.0.1", self.port, user, pw, tgt)
            self.assertEqual(cm.exception.msg.key, key)
        with self.assertRaises(socks.SocksError) as cm:                  # цель не отвечает
            socks.connect_check("127.0.0.1", self.port, "alice", "pw", ("127.0.0.1", 9))
        self.assertEqual(cm.exception.msg.key, "socks.connect_failed")
        with self.assertRaises(socks.SocksError) as cm:                  # прокси нет
            socks.connect_check("127.0.0.1", 9, "", "", tgt, timeout=2)
        self.assertEqual(cm.exception.msg.key, "socks.unreachable")


# ------------------------------------------------------------------ nftables
class NftTest(unittest.TestCase):
    UPS = [{"num": 1, "snat": "", "mtu": 8500}, {"num": 2, "snat": "10.9.0.2", "mtu": 1280}]
    POL = {"rules": [(["ru"], "direct")], "default": 2, "domain": [(["yt"], "up:u1")]}

    def gen(self, port=10443, clients=None):
        return nftgen.generate("awg0", {"ru": ["5.3.0.0/16"]}, self.UPS, self.POL, clients or {}, port)

    def test_sniff_chains(self):
        text = self.gen()
        self.assertIn(f"udp dport 443 goto o_block", text)
        self.assertIn(f"tcp dport {{ 80, 443 }} meta mark set {config.SNIFF_MARK:#x} accept", text)
        self.assertIn(f'iifname "awg0" meta mark {config.SNIFF_MARK:#x} meta l4proto tcp redirect to :10443', text)
        self.assertIn("type route hook output priority mangle", text)
        self.assertIn(f"meta mark vmap {{ {config.SNIFF_OUT_BASE:#x} : goto q_p_global }}", text)
        q = text[text.index("chain q_p_global {"):]
        q = q[:q.index("}")]
        self.assertIn("ip daddr @local4 goto oq_direct", q)
        self.assertIn("ip daddr @l_ru goto oq_direct", q)
        self.assertIn("goto oq_u2", q)
        self.assertNotIn("SNIFF", q)
        self.assertNotIn('oifname "awgr1" snat', text)                  # SOCKS5 — без SNAT
        # домены проверяются раньше правил по адресам
        p = text[text.index("chain p_global {"):]
        self.assertLess(p.index("tcp dport { 80, 443 }"), p.index("@l_ru"))

    def test_without_sniffer(self):
        text = self.gen(None)
        self.assertNotIn("c_sniff", text)
        self.assertNotIn("c_output", text)
        self.assertNotIn("udp dport 443", text)

    def test_only_policies_with_domain_rules(self):
        plain = {"rules": [], "default": "direct"}
        text = nftgen.generate("awg0", {}, self.UPS, plain, {"10.8.1.7": self.POL}, 10443)
        g = text[text.index("chain p_global {"):]
        g = g[:g.index("}")]
        self.assertNotIn("dport", g)                                     # у остальных клиентов — как раньше
        self.assertIn("10.8.1.7 : goto p_1", text)
        self.assertIn(f"{config.SNIFF_OUT_BASE:#x} : goto q_p_1", text)
        policies, cmap = nftgen.layout(plain, {"10.8.1.7": self.POL}, {1, 2})
        self.assertEqual(cmap, {"10.8.1.7": "p_1"})
        self.assertEqual(nftgen.sniff_marks(policies), {"p_1": config.SNIFF_OUT_BASE})

    @unittest.skipUnless(os.geteuid() == 0 and subprocess.run(["which", "nft"], capture_output=True).returncode == 0, "root + nft")
    def test_ruleset_loads(self):
        p = subprocess.run(["unshare", "-n", "nft", "-c", "-f", "-"], input=self.gen(), capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)


# ------------------------------------------------------------------ имя сайта
def client_hello(name: str | None) -> bytes:
    """Настоящий ClientHello из модуля ssl (как у браузера: с расширениями)."""
    ctx = ssl.create_default_context()
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=name) if name else \
        ssl._create_unverified_context().wrap_bio(inc, out)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


class SniTest(unittest.TestCase):
    def test_tls(self):
        ch = client_hello("www.YouTube.com")
        self.assertEqual(sniproxy.tls_sni(ch), "www.youtube.com")
        self.assertIs(sniproxy.tls_sni(ch[:40]), False)                  # мало данных — ждать ещё
        self.assertIsNone(sniproxy.tls_sni(client_hello(None)))         # без имени
        self.assertIsNone(sniproxy.tls_sni(b"SSH-2.0-OpenSSH\r\n"))
        # ClientHello, разрезанный на две записи TLS
        body = ch[5:]
        split = b"\x16\x03\x01" + len(body[:100]).to_bytes(2, "big") + body[:100] + \
                b"\x16\x03\x01" + len(body[100:]).to_bytes(2, "big") + body[100:]
        self.assertEqual(sniproxy.tls_sni(split), "www.youtube.com")

    def test_http(self):
        self.assertEqual(sniproxy.name_of(b"GET / HTTP/1.1\r\nHost: Example.COM:8080\r\nX: y\r\n\r\n", 80), "example.com")
        self.assertIs(sniproxy.name_of(b"GET / HTTP/1.1\r\nHo", 80), False)
        self.assertIsNone(sniproxy.name_of(b"GET / HTTP/1.1\r\nX: y\r\n\r\n", 80))
        self.assertIsNone(sniproxy.name_of(b"\x00\x01binary", 443))

    def test_decide(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "yt.domains"), "w") as f:
            f.write("youtube.com\n")
        cfg = os.path.join(d, "sni.json")
        socks_to = {"socks": {"ip": "198.51.100.20", "port": 1080}}
        with open(cfg, "w") as f:
            f.write('{"listen":"10.8.1.0","clients":"10.8.1.0/24","lists":{"yt":"%s/yt.domains"},'
                    '"client_policy":{"10.8.1.9":"p_1"},'
                    '"policies":{"p_global":{"mark":53504,"rules":[{"lists":["yt"],"to":%s}]},'
                    '"p_1":{"mark":53505,"rules":[]}}}' % (d, __import__("json").dumps(socks_to)))
        s = sniproxy.Sniffer(cfg)
        self.assertEqual(s.decide("10.8.1.2", "m.youtube.com"), (socks_to, "yt"))
        self.assertEqual(s.decide("10.8.1.2", "notyoutube.com"), ({"mark": 53504}, None))
        self.assertEqual(s.decide("10.8.1.2", None), ({"mark": 53504}, None))
        self.assertEqual(s.decide("10.8.1.9", "youtube.com"), ({"mark": 53505}, None))   # у клиента своя политика


class SocksConnectByNameTest(SocksCheckTest):
    """sniproxy.socks_connect: CONNECT с именем сайта к тестовому SOCKS5."""

    def test_connect_by_name(self):
        tport = self.target.getsockname()[1]
        with mock.patch.dict(e2e_servers.HOSTS, {"site.test": "127.0.0.1"}):
            async def go():
                r, w = await sniproxy.socks_connect({"ip": "127.0.0.1", "port": self.port, "user": "alice",
                                                     "password": "pw"}, "site.test", "192.0.2.1", tport)
                w.close()
            asyncio.run(go())
        with self.assertRaises(OSError):
            asyncio.run(sniproxy.socks_connect({"ip": "127.0.0.1", "port": self.port, "user": "alice",
                                                "password": "bad"}, "site.test", "192.0.2.1", tport))


# ------------------------------------------------------------------ панель (демо-режим)
class PanelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.engine.reconcile()

    def setUp(self):
        st = main.store.snapshot()
        self._routing = {"default": st["routing"]["default"], "rules": list(st["routing"]["rules"])}
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            self.lid = main.add_list(Req({"kind": "domains", "source": "youtube.com\n*.googlevideo.com"}))["id"]
        self.socks = main.add_upstream(Req({"name": "Proxy", "config": "socks5://bob:secret@198.51.100.20:1080"}))["id"]
        self.awg = next((u["id"] for u in main.store.snapshot()["upstreams"]
                         if main.engine.parsed(u).kind == "awg"), None)

    def tearDown(self):
        r = self._routing
        main.store.mutate(lambda st: st.update(routing={"default": r["default"], "rules": r["rules"]}))
        main.del_upstream(Req({"replace": "direct"}), self.socks)
        main.del_list(None, self.lid)
        main.engine.reconcile()

    def rules(self, *rules):
        return main.put_routing(Req({"default": "direct", "rules": [
            {"lists": l, "outbound": o, "enabled": True, "comment": ""} for l, o in rules]}))

    def test_list_named_by_first_domain(self):
        self.assertEqual(main.get_list(None, self.lid)["name"], "youtube.com")
        self.assertIsNone(next(l for l in main.get_state(None)["lists"] if l["id"] == self.lid)["source"])

    def test_domain_rules_only_to_socks(self):
        self.rules(([self.lid], "up:" + self.socks))
        for out in ["direct", "block"] + (["up:" + self.awg] if self.awg else []):
            with self.assertRaises(web.HTTPError) as cm:
                self.rules(([self.lid], out))
            self.assertIn("err.domains_need_socks", str(cm.exception))
        with self.assertRaises(web.HTTPError) as cm:
            self.rules(([self.lid, "ru"], "up:" + self.socks))
        self.assertIn("err.rule_mixed_domains", str(cm.exception))

    def test_sniffer_in_ruleset_and_trace(self):
        self.rules((["ru"], "direct"), ([self.lid], "up:" + self.socks))
        main.engine.reconcile()
        self.assertEqual(main.engine.sni_view()["state"], "on")
        self.assertIn("c_sniff", main.engine.ruleset)
        with mock.patch.object(socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("142.250.74.110", 0))]):
            t = main.trace_target(None, "rr1.googlevideo.com")
        self.assertEqual(t["result"], "up:" + self.socks)
        self.assertEqual(t["domain"], "googlevideo.com")
        self.assertIn("tr.match_domain", [m.key for m in t["steps"]])
        t = main.trace_target(None, "142.250.74.110")                    # по одному IP домен не узнать
        self.assertNotIn("domain", t)
        self.rules((["ru"], "direct"))
        main.engine.reconcile()
        self.assertIsNone(main.engine.sni_view())
        self.assertNotIn("c_sniff", main.engine.ruleset)

    def test_sniffer_config_targets(self):
        self.rules(([self.lid], "up:" + self.socks))
        main.engine.reconcile()
        st = main.store.snapshot()
        to = main.engine._sni_target(st, "up:" + self.socks)
        u = next(u for u in st["upstreams"] if u["id"] == self.socks)
        if main.engine.health.get(self.socks, {}).get("healthy"):
            self.assertEqual(to["socks"]["port"], 1080)
            self.assertEqual(to["socks"]["user"], "bob")
            self.assertEqual(to["acct"], self.socks)                      # байты — на счёт этого выхода
        else:                                                             # демо: «нерабочий» выход → резерв
            self.assertEqual(to, {"mark": 0, "acct": "direct"})
        self.assertEqual(main.engine._sni_target(st, "block"), {"block": True})
        self.assertEqual(main.engine._sni_target(st, "direct"), {"mark": 0, "acct": "direct"})
        self.assertTrue(u)

    def test_socks_exit_view(self):
        main.engine.reconcile()
        v = next(u for u in main.get_state(None)["upstreams"] if u["id"] == self.socks)
        self.assertEqual(v["kind"], "socks5")
        self.assertEqual(v["endpoint"], "198.51.100.20:1080")
        self.assertEqual(v["socks_user"], "bob")
        self.assertNotIn("secret", str(v))                               # пароль в состояние не попадает
        self.assertEqual(main.get_upstream_config(None, self.socks)["config"], "socks5://bob:secret@198.51.100.20:1080")
        self.assertEqual(v["health"]["kind"], "socks5")
        self.assertNotIn(f'oifname "awgr{v["num"]}" snat', main.engine.ruleset)
        with self.assertRaises(web.HTTPError):
            main.edit_upstream(Req({"config": "socks5://h:99999"}), self.socks)

    def test_sni_hung(self):
        from app import engine as eng
        e = main.engine
        old = e.sni
        e.sni = eng.HelperRT(mock.Mock(pid=4242), "k", "h")
        try:
            e.sni.started = time.time() - 600
            with open(eng.SNI_STATS, "w") as f:
                f.write('{"pid": 4242, "at": %f}' % (time.time() - 300))
            self.assertTrue(e._sni_hung())
            with open(eng.SNI_STATS, "w") as f:
                f.write('{"pid": 4242, "at": %f}' % time.time())
            self.assertFalse(e._sni_hung())
        finally:
            e.sni = old


# ------------------------------------------------------------------ бот: всё в одном сообщении
class ExitDialogRoutingTest(unittest.TestCase):
    """Маршрутизация SOCKS5-выхода прямо из его окна (POST/PUT /api/upstreams с routing)."""

    @classmethod
    def setUpClass(cls):
        main.engine.reconcile()

    def setUp(self):
        st = main.store.snapshot()
        self._routing = {"default": st["routing"]["default"], "rules": list(st["routing"]["rules"])}
        self._lists = {l["id"] for l in st["lists"]}
        self.ids = []

    def tearDown(self):
        r = self._routing
        main.store.mutate(lambda st: st.update(routing={"default": r["default"], "rules": r["rules"]}))
        for uid in self.ids:
            if Store.upstream(main.store.snapshot(), uid):
                main.del_upstream(Req({"replace": "direct"}), uid)
        for l in main.store.snapshot()["lists"]:
            if l["id"] not in self._lists:
                main.del_list(None, l["id"])
        main.engine.reconcile()

    def add(self, routing, name="Seller"):
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            uid = main.add_upstream(Req({"name": name, "config": "socks5://u:p@198.51.100.30:1080",
                                         "routing": routing}))["id"]
        self.ids.append(uid)
        return uid

    def mine(self, uid):
        return [r for r in main.store.snapshot()["routing"]["rules"] if r["outbound"] == "up:" + uid]

    def test_own_sites_list_and_rules(self):
        uid = self.add({"domains": "youtube.com\nInstagram.com", "net_lists": ["ru"], "default": False})
        st = main.store.snapshot()
        u = Store.upstream(st, uid)
        own = Store.lst(st, u["own_list"])
        self.assertEqual((own["kind"], own["name"]), ("domains", "Seller"))
        self.assertEqual([r["lists"] for r in self.mine(uid)], [[own["id"]], ["ru"]])
        self.assertEqual(main.get_state(None)["upstreams"][-1]["own_list"], own["id"])

    def test_edit_keeps_position_and_default(self):
        uid = self.add({"domains": "a.example"})
        main.put_routing(Req({"default": "direct", "rules": [
            {"lists": ["ru"], "outbound": "block", "enabled": True, "comment": ""},
            *self.mine(uid)]}))
        main.edit_upstream(Req({"name": "Seller", "routing": {"domains": "a.example\nb.example",
                                                             "net_lists": ["ru"], "default": True}}), uid)
        st = main.store.snapshot()
        self.assertEqual(st["routing"]["default"], "up:" + uid)
        self.assertEqual(st["routing"]["rules"][0]["outbound"], "block")    # чужое правило осталось первым
        self.assertIn("b.example", Store.lst(st, Store.upstream(st, uid)["own_list"])["source"])
        main.edit_upstream(Req({"name": "Seller", "routing": {"domains": "", "default": False}}), uid)
        st = main.store.snapshot()
        self.assertEqual(st["routing"]["default"], "direct")
        self.assertEqual(self.mine(uid), [])
        self.assertNotIn("own_list", Store.upstream(st, uid))              # свой список удалён
        self.assertFalse(any(l["name"] == "Seller" and l["kind"] == "domains" for l in st["lists"]))

    def test_edit_without_routing_changes_nothing(self):
        uid = self.add({"domains": "a.example"})
        before = self.mine(uid)
        main.edit_upstream(Req({"name": "Renamed"}), uid)
        self.assertEqual(self.mine(uid), before)
        st = main.store.snapshot()
        self.assertEqual(Store.lst(st, Store.upstream(st, uid)["own_list"])["name"], "Renamed")

    def test_bad_input(self):
        with self.assertRaises(web.HTTPError) as cm:
            self.add({"domains": "!!! ???"})
        self.assertIn("err.no_domains", str(cm.exception))

    def test_delete_drops_own_list_and_domain_rules(self):
        uid = self.add({"domains": "a.example"})
        own = Store.upstream(main.store.snapshot(), uid)["own_list"]
        main.del_upstream(Req({"replace": "direct"}), uid)
        st = main.store.snapshot()
        self.assertIsNone(Store.lst(st, own))
        self.assertFalse(any(own in r["lists"] for r in st["routing"]["rules"]))


class RoutingTabTest(unittest.TestCase):
    """1.12.1: «Правила» и «Списки» — одна вкладка «Маршрутизация»."""

    def read(self, name):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "static", name)) as f:
            return f.read()

    def test_one_tab(self):
        html = self.read("index.html")
        self.assertIn('data-tab="routing"', html)
        self.assertNotIn('data-tab="lists"', html)
        js = self.read("app.js")
        self.assertIn('if (tab === "lists")', js)            # старые закладки #lists
        self.assertIn('id="lists-sec"', js)

    def test_texts(self):
        js = self.read("i18n.js")
        for key in ("re.new_list", "ls.col_used", "ls.unused", "ex.route_hint"):
            self.assertEqual(js.count(f'"{key}":'), 4, key)
        self.assertNotIn("«Правила»", js)


class BotMenuTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.engine.reconcile()
        if not any(c.get("has_config") for c in main.engine.clients):
            main.bot_ops.add_client("Menu test")             # клиент с конфигом (QR и файл)
            main.engine.reconcile()

    def setUp(self):
        from app import notify, tgbot
        from tests.test_v19 import FakeTG, cfg
        self.notify, self.tgbot = notify, tgbot
        self.tg = FakeTG()
        p = mock.patch.object(notify, "_post", self.tg)
        p.start()
        self.addCleanup(p.stop)
        tgbot.STATE = os.path.join(tempfile.mkdtemp(), "tgbot.json")
        self.bot = tgbot.Bot(main.store, main.bot_ops)
        self.c = cfg()
        self.pk = next(c["public_key"] for c in main.engine.clients if c.get("has_config"))

    def run_updates(self, *ups):
        self.tg.updates = list(ups)
        self.bot.poll_once(self.c, timeout=0)

    def menu_id(self):
        self.assertEqual(len(self.bot._panel_msgs), 1)
        return self.bot._panel_msgs[0]

    def press(self, data, uid=1):
        from tests.test_v19 import button
        self.run_updates(button(data, uid=uid, mid=self.menu_id()))

    def last_screen(self):
        return next(p for m, p in reversed(self.tg.calls) if m in ("sendMessage", "editMessageText"))

    def test_navigation_edits_one_message(self):
        from tests.test_v19 import msg
        self.run_updates(msg("/start"))
        mid = self.menu_id()
        n_sent = self.tg.methods().count("sendMessage")
        for i, data in enumerate(("cl:0", "c:" + self.pk, "cl:0", "m", "st", "m", "ex", "m")):
            self.press(data, uid=i + 2)
            self.assertEqual(self.tg.last("editMessageText")["message_id"], mid, data)
        self.assertEqual(self.tg.methods().count("sendMessage"), n_sent)    # ни одного нового сообщения
        self.assertEqual(self.menu_id(), mid)

    def test_back_buttons(self):
        from tests.test_v19 import msg
        self.run_updates(msg("/start"))
        for i, data in enumerate(("st", "cl:0", "ex", "pn", "up")):
            self.press(data, uid=i + 2)
            kb = self.last_screen()["reply_markup"]["inline_keyboard"]
            cbs = [b.get("callback_data") for row in kb for b in row]
            self.assertTrue("m" in cbs, (data, cbs))
        self.press("c:" + self.pk, uid=9)
        cbs = [b.get("callback_data") for row in self.last_screen()["reply_markup"]["inline_keyboard"] for b in row]
        self.assertIn("cl:0", cbs)
        self.assertIn("m", cbs)

    def test_new_menu_replaces_old(self):
        from tests.test_v19 import msg
        self.run_updates(msg("/start"))
        old = self.menu_id()
        self.run_updates(msg("/clients", uid=2))
        self.assertNotEqual(self.menu_id(), old)
        self.assertEqual(self.tg.last("deleteMessage")["message_id"], old)
        # меню помнит себя после перезапуска панели
        bot2 = self.tgbot.Bot(main.store, main.bot_ops)
        self.assertEqual(bot2._panel_msgs, self.bot._panel_msgs)

    def test_share_and_probe_stay_in_message(self):
        from tests.test_v19 import msg
        self.run_updates(msg("/start"))
        mid = self.menu_id()
        self.press("sh:" + self.pk, uid=2)
        e = self.tg.last("editMessageText")
        self.assertEqual(e["message_id"], mid)
        self.assertIn("/s/", e["text"])                                  # личная ссылка — в карточке
        uid = main.store.snapshot()["upstreams"][0]["id"] if main.store.snapshot()["upstreams"] else None
        if uid:
            self.press("pr:" + uid, uid=3)
            e = self.tg.last("editMessageText")
            self.assertEqual(e["message_id"], mid)
            self.assertIn("🔍", e["text"])

    def test_files_then_menu_below(self):
        from tests.test_v19 import msg
        self.run_updates(msg("/start"))
        old = self.menu_id()
        self.press("cfg:" + self.pk, uid=2)
        m = self.tg.methods()
        self.assertLess(m.index("sendDocument"), len(m) - 1 - m[::-1].index("sendMessage"))  # карточка — после файла
        self.assertNotEqual(self.menu_id(), old)
        self.assertIn(old, [p["message_id"] for x, p in self.tg.calls if x == "deleteMessage"])
        self.assertIn("QR", self.tg.last("sendMessage")["text"])

    def test_add_question_removed(self):
        from tests.test_v19 import msg
        self.run_updates(msg("/start"))
        self.press("add", uid=2)
        ask_id = self.tg.next_id
        self.run_updates(msg("Menu friend", uid=3, reply_to_message={"message_id": ask_id}))
        self.assertIn(ask_id, [p["message_id"] for x, p in self.tg.calls if x == "deleteMessage"])
        self.assertTrue(any(c["name"] == "Menu friend" for c in main.engine.clients))
        self.assertIn("Menu friend", self.tg.last("sendMessage")["text"])   # карточка нового клиента внизу


if __name__ == "__main__":
    unittest.main()
