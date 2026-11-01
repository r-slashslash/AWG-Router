"""1.12.0: правила по доменам (списки доменов, DNS через сервер — dnsproxy.py) и выходы SOCKS5.

python3 -m unittest discover tests
Сквозная проверка с настоящими nftables, dnsproxy.py и hev-socks5-tunnel — tests/domains_socks_e2e.py.
"""
import asyncio
import os
import socket
import struct
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

from app import awgconf, config, dnsproxy, domains, lists, nftgen, socks, web  # noqa: E402
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
    POL = {"rules": [(["yt"], 1), (["ru"], "direct")], "default": 2}
    UPS = [{"num": 1, "snat": "", "mtu": 8500}, {"num": 2, "snat": "10.9.0.2", "mtu": 1280}]

    def test_domain_sets_and_redirect(self):
        text = nftgen.generate("awg0", {"yt": [], "ru": ["5.3.0.0/16"]}, self.UPS, self.POL, {},
                               {"yt"}, ("proxy", 10053))
        self.assertIn("set l_yt {\n\t\ttype ipv4_addr\n\t\tflags timeout", text)
        self.assertIn("ip daddr @l_yt goto o_u1", text)
        self.assertIn('iifname "awg0" udp dport 53 redirect to :10053', text)
        self.assertIn('iifname "awg0" tcp dport 53 redirect to :10053', text)
        self.assertNotIn('oifname "awgr1" snat', text)                  # SOCKS5 — без SNAT
        self.assertIn('oifname "awgr2" snat to 10.9.0.2', text)

    def test_without_dns_proxy(self):
        text = nftgen.generate("awg0", {"yt": [], "ru": ["5.3.0.0/16"]}, self.UPS, self.POL, {}, {"yt"}, None)
        self.assertNotIn("l_yt", text)                                  # без посредника набор всегда пуст
        self.assertNotIn("c_dns", text)
        text = nftgen.generate("awg0", {"yt": []}, self.UPS, self.POL, {}, {"yt"}, ("dnat", "1.1.1.1"))
        self.assertIn('udp dport 53 dnat to 1.1.1.1', text)
        self.assertNotIn("l_yt", text)

    def test_fallback_ruleset(self):
        text = nftgen.dns_fallback_ruleset("awg0", "1.1.1.1")
        self.assertIn("table ip awgr_dns {", text)
        self.assertIn('iifname "awg0" tcp dport 53 dnat to 1.1.1.1', text)
        with self.assertRaises(ValueError):
            nftgen.dns_fallback_ruleset("awg0", "1.1.1.1; drop")

    @unittest.skipUnless(os.geteuid() == 0 and subprocess.run(["which", "nft"], capture_output=True).returncode == 0, "root + nft")
    def test_ruleset_loads(self):
        text = nftgen.generate("awg0", {"yt": [], "ru": ["5.3.0.0/16"]}, self.UPS, self.POL, {},
                               {"yt"}, ("proxy", 10053))
        p = subprocess.run(["unshare", "-n", "nft", "-c", "-f", "-"], input=text, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)


# ------------------------------------------------------------------ DNS
def query(name, qtype=1, qid=0x1234):
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return q + b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0" + struct.pack("!HH", qtype, 1)


class DnsMessageTest(unittest.TestCase):
    ZONE = {"a.test": "CNAME:b.cdn.test", "b.cdn.test": "203.0.113.7", "x.test": "198.51.100.1"}

    def test_answers_with_cname_and_compression(self):
        r = e2e_servers.dns_answer(query("a.test"), self.ZONE)
        self.assertEqual(dnsproxy.question(r)[:2], ("a.test", 1))
        names, ips = dnsproxy.answers(r)
        self.assertEqual(names, {"a.test", "b.cdn.test"})
        self.assertEqual(ips, ["203.0.113.7"])
        # сжатие имён (указатель на имя вопроса)
        q = query("x.test")
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("198.51.100.1")
        r = q[:6] + b"\x00\x01" + q[8:] + rr
        self.assertEqual(dnsproxy.answers(r), ({"x.test"}, ["198.51.100.1"]))

    def test_empty_reply(self):
        q = query("a.test", 28, qid=0xBEEF)
        r = dnsproxy.empty_reply(q)
        self.assertEqual(r[:2], b"\xbe\xef")
        self.assertTrue(r[2] & 0x80)                    # QR
        self.assertTrue(r[2] & 0x01)                    # RD скопирован
        self.assertEqual(r[3] & 0x0F, 0)
        self.assertEqual(dnsproxy.answers(r), (set(), []))
        self.assertEqual(dnsproxy.empty_reply(q, 2)[3] & 0x0F, 2)

    def test_bad_messages(self):
        for bad in (b"", b"\x00" * 11, query("a.test")[:-3], b"\x00" * 4 + b"\x00\x02" + b"\x00" * 6,
                    b"\x00" * 12 + b"\xc0\x0c"):
            with self.assertRaises(dnsproxy.BadMessage):
                dnsproxy.question(bad)


class ProxyTest(unittest.TestCase):
    """dnsproxy.Proxy без сети: ответы DNS подставляются, команды nft перехватываются."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, "yt.domains"), "w") as f:
            f.write("youtube.com\ncdn.test\n")
        self.cfg = os.path.join(self.dir, "dns.json")
        with open(self.cfg, "w") as f:
            f.write('{"listen":"10.8.1.0","clients":"10.8.1.0/24","table":"awgr","timeout":3600,'
                    f'"lists":{{"yt":"{self.dir}/yt.domains"}}}}')
        self.p = dnsproxy.Proxy(self.cfg)
        self.scripts = []

        async def nft(script):
            self.scripts.append(script)
            return True
        self.p.nft = nft
        zone = {"www.youtube.com": "CNAME:edge.cdn.test", "edge.cdn.test": "203.0.113.7", "ya.ru": "198.51.100.1"}

        async def upstream(q, tcp):
            return e2e_servers.dns_answer(q, zone)
        self.p.upstream = upstream

    def ask(self, name, qtype=1, src="10.8.1.5"):
        return asyncio.run(self.p.handle(query(name, qtype), src, False))

    def test_match_adds_before_answer(self):
        r = self.ask("www.youtube.com")
        self.assertEqual(dnsproxy.answers(r)[1], ["203.0.113.7"])
        self.assertEqual(self.scripts, ["add element ip awgr l_yt { 203.0.113.7 timeout 3600s }\n"])
        self.ask("www.youtube.com")                       # свежий — повторно не добавляем
        self.assertEqual(len(self.scripts), 1)
        self.p.live[("yt", "203.0.113.7")] = time.time() + 100   # почти истёк — удалить и добавить
        self.ask("www.youtube.com")
        self.assertEqual(self.scripts[-1], "delete element ip awgr l_yt { 203.0.113.7 }\n"
                                           "add element ip awgr l_yt { 203.0.113.7 timeout 3600s }\n")

    def test_other_names_untouched(self):
        self.assertEqual(dnsproxy.answers(self.ask("ya.ru"))[1], ["198.51.100.1"])
        self.assertEqual(self.scripts, [])

    def test_aaaa_and_https(self):
        self.assertEqual(dnsproxy.answers(self.ask("ya.ru", 28)), (set(), []))       # AAAA — пусто
        self.assertEqual(dnsproxy.answers(self.ask("youtube.com", 65)), (set(), []))  # HTTPS домена из списка
        self.assertIsNotNone(self.ask("ya.ru", 65))

    def test_foreign_source_ignored(self):
        self.assertIsNone(self.ask("ya.ru", src="203.0.113.50"))

    def test_upstream_down(self):
        async def down(q, tcp):
            raise OSError("no upstream")
        self.p.upstream = down
        self.assertEqual(self.ask("ya.ru")[3] & 0x0F, 2)                            # SERVFAIL

    def test_resync_and_reload(self):
        self.ask("www.youtube.com")
        self.scripts.clear()
        asyncio.run(self.p.resync())
        self.assertEqual(len(self.scripts), 1)
        self.assertRegex(self.scripts[0], r"^add element ip awgr l_yt \{ 203\.0\.113\.7 timeout \d+s \}")
        with open(self.cfg, "w") as f:                    # список убрали из правил
            f.write('{"listen":"10.8.1.0","clients":"10.8.1.0/24","lists":{}}')
        self.p.reload()
        self.assertEqual(self.p.live, {})


# ------------------------------------------------------------------ панель (демо-режим)
class PanelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.engine.reconcile()

    def setUp(self):
        self._settings = dict(main.store.snapshot()["settings"])

    def tearDown(self):
        s = self._settings
        main.store.mutate(lambda st: (st["settings"].clear(), st["settings"].update(s)))

    def test_domains_list_turns_dns_on_once(self):
        main.store.mutate(lambda st: st["settings"].pop("dns_proxy", None))
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            r = main.add_list(Req({"kind": "domains", "name": "YT", "source": "youtube.com\n*.googlevideo.com"}))
        self.assertTrue(r["dns_enabled"])
        self.assertEqual(r["count"], 2)
        self.assertIsNone(r.get("source"))                  # текст не уходит в /api/state
        self.assertEqual(main.get_list(None, r["id"])["source"], "youtube.com\n*.googlevideo.com")
        self.assertTrue(main.store.snapshot()["settings"]["dns_proxy"])
        main.store.mutate(lambda st: st["settings"].update(dns_proxy=False))   # выключили вручную
        r2 = main.add_list(Req({"kind": "domains", "source": "example.com"}))
        self.assertFalse(r2["dns_enabled"])
        self.assertFalse(main.store.snapshot()["settings"]["dns_proxy"])
        with self.assertRaises(web.HTTPError):
            main.add_list(Req({"kind": "domains", "source": "# только комментарий"}))
        for lid in (r["id"], r2["id"]):
            main.del_list(None, lid)

    def test_trace_by_domain(self):
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            r = main.add_list(Req({"kind": "domains", "source": "example.org"}))
        lid = r["id"]
        st = main.store.snapshot()
        old_rules = st["routing"]["rules"]
        main.store.mutate(lambda s: (s["routing"].update(rules=[{"id": "rdom", "lists": [lid], "outbound": "block",
                                                                  "enabled": True, "comment": ""}] + old_rules),
                                     s["settings"].update(dns_proxy=True)))
        try:
            with mock.patch.object(socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.215.14", 0))]):
                t = main.trace_target(None, "www.example.org")
            self.assertEqual(t["result"], "block")
            self.assertEqual(t["domain"], "example.org")
            self.assertIn("tr.match_domain", [m.key for m in t["steps"]])
            t = main.trace_target(None, "93.184.215.14")      # по одному IP домен не узнать
            self.assertNotEqual(t.get("domain"), "example.org")
        finally:
            main.store.mutate(lambda s: s["routing"].update(rules=old_rules))
            main.del_list(None, lid)

    def test_client_dns_follows_setting(self):
        from app import awgserver
        sc = awgserver.ServerConf()
        sc.iface = [("Address", "10.8.1.0/24")]
        st = {"settings": {"client_dns": ["9.9.9.9"], "dns_proxy": True}}
        self.assertEqual(main.engine.srv.dns_for_clients(st, sc), ["10.8.1.0"])
        st["settings"]["dns_proxy"] = False
        self.assertEqual(main.engine.srv.dns_for_clients(st, sc), ["9.9.9.9"])

    def test_dns_state_in_demo(self):
        main.store.mutate(lambda s: s["settings"].update(dns_proxy=True))
        main.engine.reconcile()
        self.assertEqual(main.engine.dns_view()["state"], "on")
        self.assertIn("c_dns", main.engine.ruleset)
        main.store.mutate(lambda s: s["settings"].update(dns_proxy=False))
        main.engine.reconcile()
        self.assertIsNone(main.engine.dns_view())
        self.assertNotIn("c_dns", main.engine.ruleset)

    def test_socks_exit(self):
        r = main.add_upstream(Req({"name": "Proxy", "config": "socks5://bob:secret@198.51.100.20:1080"}))
        uid = r["id"]
        try:
            main.engine.reconcile()
            v = next(u for u in main.get_state(None)["upstreams"] if u["id"] == uid)
            self.assertEqual(v["kind"], "socks5")
            self.assertEqual(v["endpoint"], "198.51.100.20:1080")
            self.assertEqual(v["socks_user"], "bob")
            self.assertNotIn("secret", str(v))                  # пароль в состояние не попадает
            self.assertEqual(main.get_upstream_config(None, uid)["config"], "socks5://bob:secret@198.51.100.20:1080")
            self.assertEqual(v["health"]["kind"], "socks5")
            num = v["num"]
            expect = num != 2                                   # в демо выход №2 «не работает»
            self.assertEqual(v["health"]["healthy"], expect)
            self.assertNotIn(f'oifname "awgr{num}" snat', main.engine.ruleset)
            with self.assertRaises(web.HTTPError):
                main.edit_upstream(Req({"config": "socks5://h:99999"}), uid)
        finally:
            main.del_upstream(Req({"replace": "direct"}), uid)

    def test_dns_fallback_table(self):
        t = main.engine.target
        main.store.mutate(lambda s: s["settings"].update(dns_proxy=True, client_dns=["9.9.9.9"]))
        main.engine._dns_fb = None
        main.engine.reconcile()
        from app import engine as eng
        with open(os.path.join(eng.RUN_DIR, "dns-fallback.nft")) as f:
            text = f.read()
        self.assertIn('udp dport 53 dnat to 9.9.9.9', text)
        self.assertIn("priority dstnat + 10", text)
        self.assertTrue(main.engine._dns_fb.startswith(t.key))
        main.store.mutate(lambda s: s["settings"].update(dns_proxy=False))
        main.engine.reconcile()
        self.assertEqual(main.engine._dns_fb, "off:" + t.key)

    def test_dns_hung(self):
        from app import engine as eng
        e = main.engine
        proc = mock.Mock(pid=4242)
        e.dns = eng.DnsRT(proc, "k", "h")
        try:
            e.dns.started = time.time() - 600
            with open(eng.DNS_STATS, "w") as f:
                f.write('{"pid": 4242, "at": %f}' % (time.time() - 300))
            self.assertTrue(e._dns_hung())
            with open(eng.DNS_STATS, "w") as f:
                f.write('{"pid": 4242, "at": %f}' % time.time())
            self.assertFalse(e._dns_hung())
            with open(eng.DNS_STATS, "w") as f:                 # счётчики другого процесса
                f.write('{"pid": 1, "at": 0}')
            self.assertFalse(e._dns_hung())
        finally:
            e.dns = None

    def test_restore_keeps_dns_proxy(self):
        out = main.clean_backup_state({"settings": {"dns_proxy": True}, "lists": [
            {"id": "lrestor", "kind": "domains", "source": "a.com"}]})
        self.assertTrue(out["settings"]["dns_proxy"])
        self.assertEqual(out["lists"][-1]["kind"], "domains")


if __name__ == "__main__":
    unittest.main()
