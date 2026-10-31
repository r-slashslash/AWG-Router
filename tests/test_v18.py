"""1.8.0: запросы к Telegram через выход (там, где Telegram заблокирован) и удаление
используемого выхода — ссылки переходят на выбранную замену.

python3 -m unittest discover tests
"""
import copy
import json
import os
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import config, main, notify, tgreq, web  # noqa: E402
from app.store import Store  # noqa: E402
from tests.test_api import PUB, UPSTREAM, good_state  # noqa: E402

TOKEN = "123456789:" + "A" * 35


class Proc:
    def __init__(self, out=b"", err=b"", rc=0):
        self.stdout, self.stderr, self.returncode = out, err, rc


class DnsTest(unittest.TestCase):
    def answer(self, qid, ips, rcode=0):
        q = tgreq.dns_query("api.telegram.org", qid)
        head = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, len(ips) + 1, 0, 0)
        # сначала CNAME (его надо пропустить), потом записи A со ссылкой на имя из вопроса
        rr = struct.pack(">HHHIH", 0xC00C, 5, 1, 60, 4) + b"\x01x\xc0\x0c"
        for ip in ips:
            rr += struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip)
        return head + q[12:] + rr

    def test_query(self):
        q = tgreq.dns_query("api.telegram.org", 0x1234)
        self.assertEqual(q[:4], b"\x12\x34\x01\x00")
        self.assertIn(b"\x03api\x08telegram\x03org\x00\x00\x01\x00\x01", q)

    def test_answer(self):
        ips = ["149.154.167.220", "149.154.167.221"]
        self.assertEqual(tgreq.dns_answer(self.answer(7, ips), 7), ips)
        self.assertEqual(tgreq.dns_answer(self.answer(7, ips), 8), [])       # чужой id
        self.assertEqual(tgreq.dns_answer(self.answer(7, ips, rcode=3), 7), [])  # NXDOMAIN
        self.assertEqual(tgreq.dns_answer(self.answer(7, ips)[:-3], 7), ips[:1])  # обрезан
        self.assertEqual(tgreq.dns_answer(b"\x00", 7), [])


class PostViaTest(unittest.TestCase):
    def tearDown(self):
        notify.router = None

    def test_direct_is_default(self):
        notify.router = mock.Mock()
        with mock.patch.object(notify, "_post_direct", return_value=(200, b'{"ok":true,"result":{}}')) as d:
            notify.send(TOKEN, "42", "hi")
        notify.router.assert_not_called()
        self.assertTrue(d.call_args[0][0].endswith("/sendMessage"))

    def test_through_exit(self):
        notify.router = lambda via: (4321, 0x2003)
        out = json.dumps({"status": 200, "body": '{"ok": true, "result": {"message_id": 1}}'}).encode()
        with mock.patch.object(notify.subprocess, "run", return_value=Proc(out)) as run:
            notify.send(TOKEN, "42", "hi", via="up:u1")
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[:5], ["nsenter", "-t", "4321", "-n", "--"])
        self.assertEqual((cmd[-2], cmd[-1]), (notify.TGREQ, str(0x2003)))
        head, _, body = run.call_args[1]["input"].partition(b"\n")
        self.assertTrue(json.loads(head)["url"].startswith("https://api.telegram.org/bot"))
        self.assertEqual(json.loads(body)["chat_id"], "42")

    def test_errors(self):
        notify.router = lambda via: (1, 0x2001)
        cases = [(Proc(b'{"err": "timed out"}'), "api.telegram.org: timed out"),
                 (Proc(b"", b"nsenter: failed", 1), "api.telegram.org: nsenter: failed"),
                 (Proc(json.dumps({"status": 401, "body": '{"ok": false, "description": "Unauthorized"}'})
                       .encode()), "Unauthorized"),
                 (Proc(b'{"status": 502, "body": "<html>"}'), "api.telegram.org: HTTP 502")]
        for proc, want in cases:
            with mock.patch.object(notify.subprocess, "run", return_value=proc):
                with self.assertRaises(notify.NotifyError) as cm:
                    notify.send(TOKEN, "42", "hi", via="up:u1")
            self.assertEqual(str(cm.exception), want)

    def test_router_error_has_msg(self):
        main_route = main._tg_route
        notify.router = main_route
        with mock.patch.object(main.engine, "own_route",
                               side_effect=main.system.SysError(main.Msg("tg.via_down", name="NL"))):
            with self.assertRaises(notify.NotifyError) as cm:
                notify.send(TOKEN, "42", "hi", via="up:u1")
        self.assertEqual(cm.exception.msg.key, "tg.via_down")
        self.assertEqual(main.msg_of(cm.exception).p, {"name": "NL"})


class OwnRouteTest(unittest.TestCase):
    def setUp(self):
        st = good_state()
        st["upstreams"][0]["fallback"] = "block"
        self.p = [mock.patch.object(config, "DRY_RUN", False),
                  mock.patch.object(main.engine.store, "snapshot", return_value=st),
                  mock.patch.object(main.engine, "target", mock.Mock(pid=777)),
                  mock.patch.object(main.engine, "rt", {"u000001": mock.Mock(num=1)}),
                  mock.patch.object(main.engine, "health", {"u000001": {"healthy": True}})]
        for p in self.p:
            p.start()

    def tearDown(self):
        for p in self.p:
            p.stop()

    def test_route(self):
        e = main.engine
        self.assertIsNone(e.own_route("direct"))
        self.assertEqual(e.own_route("up:u000001"), (777, 0x2001))
        e.health["u000001"] = {"healthy": False}             # не работает → резерв «блок»
        with self.assertRaises(main.system.SysError) as cm:
            e.own_route("up:u000001")
        self.assertEqual((cm.exception.msg.key, cm.exception.msg.p), ("tg.via_blocked", {"name": "NL"}))
        e.health["u000001"] = {"healthy": True}
        e.rt.clear()                                         # туннель не запущен
        with self.assertRaises(main.system.SysError) as cm:
            e.own_route("up:u000001")
        self.assertEqual(cm.exception.msg.key, "tg.via_down")


class SettingsTest(unittest.TestCase):
    def setUp(self):
        main.store.mutate(lambda st: (
            st["upstreams"].__setitem__(slice(None), [{"id": "u000001", "name": "NL", "num": 1,
                                                       "config": UPSTREAM, "enabled": True,
                                                       "fallback": "direct"}]),
            st["settings"].__setitem__("telegram", {**notify.defaults(), "token": TOKEN, "chat_id": "42"})))

    def tearDown(self):
        main.store.mutate(lambda st: (st["upstreams"].clear(),
                                      st["settings"].__setitem__("telegram", notify.defaults())))

    def test_draft(self):
        self.assertEqual(main._tg_draft({})["via"], "direct")
        self.assertEqual(main._tg_draft({"via": "up:u000001"})["via"], "up:u000001")
        for bad in ("block", "up:nope", 5):
            with self.assertRaises(web.HTTPError):
                main._tg_draft({"via": bad})
        self.assertEqual(notify.public_view(main._tg_draft({"via": "up:u000001"}))["via"], "up:u000001")

    def test_exit_in_use(self):
        main.store.mutate(lambda st: st["settings"]["telegram"].update(via="up:u000001"))
        refs = Store.outbound_refs(main.store.snapshot(), "up:u000001")
        self.assertIn("ref.telegram", [r.key for r in refs])
        with self.assertRaises(web.HTTPError):
            main.del_upstream(None, "u000001")

    def test_notifier_passes_via(self):
        main.store.mutate(lambda st: st["settings"]["telegram"].update(enabled=True, via="up:u000001"))
        n = notify.Notifier.__new__(notify.Notifier)
        n.store, n.host_fn, n._sent = main.store, lambda st: "h", {}
        n.q = notify.queue.Queue()
        n.event("login", "login_ok", ip="1.2.3.4")
        self.assertEqual(n.q.get_nowait()[3], "up:u000001")

    def test_backup_restore(self):
        st = good_state()
        st["settings"]["telegram"]["via"] = "up:u000001"
        self.assertEqual(main.clean_backup_state(st)["settings"]["telegram"]["via"], "up:u000001")
        self.assertEqual(main.clean_backup_state(good_state())["settings"]["telegram"]["via"], "direct")
        for bad in ("up:nope", "block"):
            st["settings"]["telegram"]["via"] = bad
            with self.assertRaises(web.HTTPError):
                main.clean_backup_state(st)

    def test_backup_error_translatable(self):
        main._backup_try = 0.0
        main.store.mutate(lambda st: st["settings"]["telegram"].update(enabled=True, backup="daily"))
        err = notify.NotifyError("x", main.Msg("tg.via_down", name="NL"))
        with mock.patch.object(main, "send_backup", side_effect=err):
            self.assertFalse(main.backup_tick(now=10_000.0))
        self.assertEqual(notify.cfg_of(main.store.snapshot())["backup_error"],
                         {"$t": "tg.via_down", "p": {"name": "NL"}})



# ------------------------------------------------ удаление выхода с заменой
class Req:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


def up(uid, num, fallback="direct", quota_action="notify"):
    return {"id": uid, "name": uid.upper(), "num": num, "config": UPSTREAM, "enabled": True,
            "fallback": fallback, "quota": None, "quota_action": quota_action}


def state():
    """Выход u_del используется везде, где можно сослаться на выход."""
    return {
        "routing": {"default": "up:u_del", "rules": [
            {"id": "r1", "lists": ["ru"], "outbound": "up:u_del", "enabled": True, "comment": ""},
            {"id": "r2", "lists": ["ru"], "outbound": "direct", "enabled": True, "comment": ""}]},
        "upstreams": [up("u_del", 1, fallback="up:u_a"),
                      up("u_a", 2, fallback="up:u_del", quota_action="up:u_del"),
                      up("u_b", 3, fallback="up:u_del", quota_action="up:u_del")],
        "clients": {PUB: {"outbound": "up:u_del", "rules_mode": "inherit",
                          "rules": [{"lists": ["ru"], "outbound": "up:u_del"}]}},
        "settings": {"telegram": {**notify.defaults(), "via": "up:u_del"}},
    }


class ReplaceTest(unittest.TestCase):
    def test_to_other_exit(self):
        st = state()
        Store.replace_outbound(st, "up:u_del", "up:u_a", "up:u_a")
        self.assertEqual(st["routing"]["default"], "up:u_a")
        self.assertEqual([r["outbound"] for r in st["routing"]["rules"]], ["up:u_a", "direct"])
        a, b = st["upstreams"][1], st["upstreams"][2]
        # у самого u_a резерв и лимит не могут указывать на u_a
        self.assertEqual((a["fallback"], a["quota_action"]), ("direct", "notify"))
        self.assertEqual((b["fallback"], b["quota_action"]), ("up:u_a", "up:u_a"))
        c = st["clients"][PUB]
        self.assertEqual((c["outbound"], c["rules"][0]["outbound"]), ("up:u_a", "up:u_a"))
        self.assertEqual(st["settings"]["telegram"]["via"], "up:u_a")
        self.assertEqual(Store.outbound_refs(st, "up:u_del"), [])

    def test_to_block(self):
        st = state()
        Store.replace_outbound(st, "up:u_del", "block", "up:u_a")
        self.assertEqual(st["routing"]["default"], "block")
        self.assertEqual(st["upstreams"][2]["quota_action"], "block")
        # Telegram не блокируется: берётся резерв удаляемого выхода
        self.assertEqual(st["settings"]["telegram"]["via"], "up:u_a")
        st = state()
        Store.replace_outbound(st, "up:u_del", "block", "block")
        self.assertEqual(st["settings"]["telegram"]["via"], "direct")

    def test_spare_for_own_exit(self):
        st = state()
        Store.replace_outbound(st, "up:u_del", "up:u_b", "up:u_a")
        self.assertEqual(st["upstreams"][2]["fallback"], "up:u_a")    # не сам u_b, а резерв удаляемого
        self.assertEqual(st["upstreams"][2]["quota_action"], "notify")
        self.assertEqual(st["upstreams"][1]["fallback"], "up:u_b")

    def test_untouched(self):
        st = state()
        st["routing"]["default"] = "direct"
        before = copy.deepcopy(st)
        Store.replace_outbound(st, "up:u_zzz", "block")
        self.assertEqual(st, before)


class DeleteApiTest(unittest.TestCase):
    def setUp(self):
        def fn(s):
            s["upstreams"][:] = [up("u000001", 1, fallback="up:u000002"), up("u000002", 2)]
            s["routing"]["default"] = "up:u000001"
            s["settings"]["telegram"] = {**notify.defaults(), "via": "up:u000001"}
        main.store.mutate(fn)

    def tearDown(self):
        def fn(s):
            s["upstreams"].clear()
            s["routing"]["default"] = "direct"
            s["settings"]["telegram"] = notify.defaults()
        main.store.mutate(fn)

    def test_in_use_needs_replace(self):
        with self.assertRaises(web.HTTPError) as cm:
            main.del_upstream(Req({}), "u000001")
        self.assertEqual(cm.exception.detail.key, "err.upstream_in_use")
        self.assertEqual(len(main.store.snapshot()["upstreams"]), 2)       # ничего не изменилось

    def test_bad_replace(self):
        for bad in ("up:u000001", "up:nope", "elsewhere", 1):
            with self.assertRaises(web.HTTPError):
                main.del_upstream(Req({"replace": bad}), "u000001")
        self.assertEqual(main.store.snapshot()["routing"]["default"], "up:u000001")

    def test_replace(self):
        main.del_upstream(Req({"replace": "up:u000002"}), "u000001")
        st = main.store.snapshot()
        self.assertEqual([u["id"] for u in st["upstreams"]], ["u000002"])
        self.assertEqual(st["routing"]["default"], "up:u000002")
        self.assertEqual(st["settings"]["telegram"]["via"], "up:u000002")

    def test_unused_without_body(self):
        main.del_upstream(Req({"replace": "direct"}), "u000001")
        main.del_upstream(None, "u000002")
        self.assertEqual(main.store.snapshot()["upstreams"], [])



if __name__ == "__main__":
    unittest.main()
