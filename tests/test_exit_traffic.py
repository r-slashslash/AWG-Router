"""Трафик по выходам и квоты выходов: python3 -m unittest discover tests"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import nftgen  # noqa: E402
from app.traffic import Traffic, month_key  # noqa: E402

NOW = 1_790_000_000          # 2026-09
MK = month_key(NOW)


def acct_json(elems: dict, iface: str = "awg0", marker: str | None = None) -> dict:
    """{(ip, ifname): [up, down]} → то, что отдаёт `nft -j list table`."""
    items = [{"metainfo": {}}, {"rule": {"comment": marker or nftgen.acct_marker(iface)}}]
    for i, name in enumerate(("up", "down")):
        items.append({"set": {"table": nftgen.ACCT_TABLE, "name": name, "elem": [
            {"elem": {"val": {"concat": [ip, ifn]}, "counter": {"packets": 1, "bytes": v[i]}}}
            for (ip, ifn), v in elems.items()]}})
    return {"nftables": items}


def out_of(ifn):
    return {"awgr1": "u1", "eth0": "direct"}.get(ifn, "direct" if not ifn.startswith("awgr") else None)


class ParseAcctTest(unittest.TestCase):
    def test_parse(self):
        d = acct_json({("10.8.1.2", "eth0"): [10, 20], ("10.8.1.2", "awgr1"): [5, 7]})
        self.assertEqual(nftgen.parse_acct(d, "awg0"),
                         {("10.8.1.2", "eth0"): [10, 20], ("10.8.1.2", "awgr1"): [5, 7]})

    def test_foreign_or_old_table(self):
        d = acct_json({("10.8.1.2", "eth0"): [1, 1]})
        self.assertIsNone(nftgen.parse_acct(d, "wg0"))          # другой интерфейс сервера
        self.assertIsNone(nftgen.parse_acct(acct_json({}, marker="awgr-acct 0 awg0"), "awg0"))
        self.assertIsNone(nftgen.parse_acct({"nftables": "x"}, "awg0"))

    def test_junk_elements_skipped(self):
        d = acct_json({})
        d["nftables"][2]["set"]["elem"] = [{"elem": {"val": "x"}}, {"elem": {"val": {"concat": ["a", "b"]},
                                                                             "counter": {"bytes": -1}}}, 5]
        self.assertEqual(nftgen.parse_acct(d, "awg0"), {})

    def test_ruleset_only_counts(self):
        r = nftgen.acct_ruleset("awg0")
        self.assertIn("hook forward priority filter + 10", r)
        self.assertNotIn("mark", r)          # ничего не помечает — на маршруты не влияет
        self.assertNotIn("drop", r)
        self.assertNotIn("reject", r)

    @unittest.skipUnless(shutil.which("nft") and shutil.which("unshare") and os.geteuid() == 0,
                         "нужен nft, unshare и root")
    def test_nft_real(self):
        """Таблица загружается, повторная загрузка — атомарная замена, маркер читается."""
        script = (f"import json,subprocess,sys; sys.path.insert(0,{os.getcwd()!r}); from app import nftgen\n"
                  "r = nftgen.acct_ruleset('awg0')\n"
                  "for _ in range(2): subprocess.run(['nft','-f','-'], input=r, text=True, check=True)\n"
                  "d = json.loads(subprocess.run(['nft','-j','list','table','ip',nftgen.ACCT_TABLE],"
                  " capture_output=True, text=True, check=True).stdout)\n"
                  "print(json.dumps(nftgen.parse_acct(d, 'awg0')))")
        p = subprocess.run(["unshare", "-n", sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), {})


class TrafficOutsTest(unittest.TestCase):
    def tr(self):
        t = Traffic(os.path.join(tempfile.mkdtemp(), "t.json"))
        t.data["K"] = {"total": [0, 0], "months": {}, "last": None}
        return t

    def test_fresh_table_counts_from_zero(self):
        t = self.tr()
        t.update_outs({}, out_of, {}, fresh=True, now=NOW)
        t.update_outs({("10.8.1.2", "eth0"): [100, 1000], ("10.8.1.2", "awgr1"): [10, 50]},
                      out_of, {"10.8.1.2": "K"}, now=NOW + 10)
        self.assertEqual(t.out_month("direct", MK), [100, 1000])
        self.assertEqual(t.out_month("u1", MK), [10, 50])
        self.assertEqual(t.view("K")["by_out"] if MK == month_key() else t.data["K"]["by_out"][MK],
                         {"direct": [100, 1000], "u1": [10, 50]})

    def test_new_pair_later_counts_whole(self):
        t = self.tr()
        t.update_outs({("10.8.1.2", "eth0"): [100, 100]}, out_of, {}, fresh=True, now=NOW)
        t.update_outs({("10.8.1.2", "eth0"): [150, 100], ("10.8.1.3", "awgr1"): [7, 9]},
                      out_of, {}, now=NOW + 10)
        self.assertEqual(t.out_month("direct", MK), [150, 100])
        self.assertEqual(t.out_month("u1", MK), [7, 9])

    def test_unknown_table_is_baseline(self):
        """Панель впервые видит чужие для неё счётчики (например, удалили traffic.json)."""
        t = self.tr()
        t.update_outs({("10.8.1.2", "eth0"): [10 ** 12, 10 ** 12]}, out_of, {}, now=NOW)
        self.assertEqual(t.out_month("direct", MK), [0, 0])
        t.update_outs({("10.8.1.2", "eth0"): [10 ** 12 + 5, 10 ** 12]}, out_of, {}, now=NOW + 10)
        self.assertEqual(t.out_month("direct", MK), [5, 0])

    def test_reset_and_removed_exit(self):
        t = self.tr()
        t.update_outs({}, out_of, {}, fresh=True, now=NOW)
        t.update_outs({("10.8.1.2", "awgr1"): [100, 100]}, out_of, {}, now=NOW + 10)
        t.update_outs({("10.8.1.2", "awgr1"): [30, 40]}, out_of, {}, now=NOW + 20)   # обнулилось
        self.assertEqual(t.out_month("u1", MK), [130, 140])
        t.update_outs({("10.8.1.2", "awgr7"): [99, 99]}, out_of, {}, now=NOW + 30)   # выхода 7 нет
        self.assertEqual(set(t.outs), {"u1"})

    def test_quota_survives_client_delete_and_forget_out(self):
        t = self.tr()
        t.update_outs({}, out_of, {}, fresh=True, now=NOW)
        t.update_outs({("10.8.1.2", "awgr1"): [5, 5]}, out_of, {"10.8.1.2": "K"}, now=NOW + 10)
        t.forget("K")
        self.assertEqual(t.out_month("u1", MK), [5, 5])      # квота выхода не «отыгрывается»
        t.data["K2"] = {"total": [0, 0], "months": {}, "by_out": {MK: {"u1": [1, 1], "direct": [2, 2]}}}
        t.forget_out("u1")
        self.assertNotIn("u1", t.outs)
        self.assertEqual(t.data["K2"]["by_out"][MK], {"direct": [2, 2]})

    def test_persist_and_downgrade_safe(self):
        t = self.tr()
        t.update_outs({}, out_of, {}, fresh=True, now=NOW)
        t.update_outs({("10.8.1.2", "awgr1"): [5, 6]}, out_of, {"10.8.1.2": "K"}, now=NOW + 10)
        t.save()
        with open(t.path) as f:
            raw = json.load(f)
        self.assertEqual(raw["_v"], 2)       # старые версии читают файл как раньше
        t2 = Traffic(t.path)
        self.assertEqual(t2.out_month("u1", MK), [5, 6])
        self.assertTrue(t2.acct_synced)
        t2.update_outs({("10.8.1.2", "awgr1"): [8, 6]}, out_of, {}, now=NOW + 20)   # продолжаем с места
        self.assertEqual(t2.out_month("u1", MK), [8, 6])

    def test_backup_roundtrip_keeps_counters(self):
        t = self.tr()
        t.update_outs({}, out_of, {}, fresh=True, now=NOW)
        t.update_outs({("10.8.1.2", "awgr1"): [5, 6]}, out_of, {"10.8.1.2": "K"}, now=NOW + 10)
        b = t.export()
        b["outs"]["bad id!"] = {"total": [1, 1], "months": {}}
        b["clients"]["K"]["by_out"]["junk"] = {"u1": [1, 1]}
        t.replace(b)
        self.assertEqual(set(t.outs), {"u1"})
        self.assertEqual(list(t.data["K"]["by_out"]), [MK])
        t.update_outs({("10.8.1.2", "awgr1"): [7, 6]}, out_of, {}, now=NOW + 20)
        self.assertEqual(t.out_month("u1", MK), [7, 6])     # точки отсчёта не сброшены


class ExitQuotaTest(unittest.TestCase):
    def engine(self, used, quota=100, action="fallback", flags=None):
        from app.engine import Engine
        from app.i18n import Msg  # noqa: F401

        class Store:
            def __init__(s):
                s.st = {"upstreams": [{"id": "u1", "num": 1, "name": "NL", "quota": quota,
                                       "quota_action": action, **(flags or {})}]}

            def snapshot(s):
                return json.loads(json.dumps(s.st))

            def mutate(s, fn):
                fn(s.st)

        class Tr:
            def out_used(s, out):
                return used

        class E:
            over_quota = Engine.over_quota
            _exit_quotas = Engine._exit_quotas
        e = E()
        e.store, e.traffic, e.acct_state, e.events = Store(), Tr(), "ok", []
        e.event = lambda lvl, m: e.events.append(m.key)
        return e

    def test_over_quota(self):
        u = {"id": "u1", "quota": 100, "quota_action": "fallback"}
        self.assertTrue(self.engine(100).over_quota(u))
        self.assertFalse(self.engine(99).over_quota(u))
        self.assertFalse(self.engine(500).over_quota({**u, "quota_action": "notify"}))
        self.assertFalse(self.engine(500).over_quota({**u, "quota": None}))

    def test_events_once_per_month(self):
        e = self.engine(95)
        e._exit_quotas(e.store.snapshot())
        e._exit_quotas(e.store.snapshot())
        self.assertEqual(e.events, ["ev.upstream_quota_warn"])
        e.traffic.out_used = lambda out: 100
        e._exit_quotas(e.store.snapshot())
        e._exit_quotas(e.store.snapshot())
        self.assertEqual(e.events, ["ev.upstream_quota_warn", "ev.upstream_quota"])

    def test_notify_only_and_new_month(self):
        e = self.engine(150, action="notify")
        e._exit_quotas(e.store.snapshot())
        self.assertEqual(e.events, ["ev.upstream_quota_notify"])
        e = self.engine(0, flags={"quota_hit": "2000-01", "quota_warned": "2000-01"})
        e._exit_quotas(e.store.snapshot())
        self.assertEqual(e.events, ["ev.upstream_quota_reset"])
        self.assertIsNone(e.store.st["upstreams"][0]["quota_hit"])

    def test_no_events_without_accounting(self):
        e = self.engine(500)
        e.acct_state = "off"
        e._exit_quotas(e.store.snapshot())
        self.assertEqual(e.events, [])


class AccountTest(unittest.TestCase):
    """Engine._account с поддельной целью: создание таблицы, чтение, отказ ядра."""

    def engine(self, ns):
        from app import engine as eng_mod
        os.makedirs(eng_mod.RUN_DIR, exist_ok=True)

        class T:
            key, iface = "k1", "awg0"

            def ns(s, cmd, **kw):
                return ns(cmd)

        class E:
            _account = eng_mod.Engine._account
        e = E()
        e.traffic = Traffic(os.path.join(tempfile.mkdtemp(), "t.json"))
        e.clients = [{"ip": "10.8.1.2", "public_key": "K"}]
        e.traffic.data["K"] = {"total": [0, 0], "months": {}, "last": None}
        e.acct_state = e.acct_error = e._acct_key = None
        e._acct_retry = 0.0
        e.events = []
        e.event = lambda lvl, m: e.events.append(m.key)
        return e, T()

    def test_create_then_count(self):
        calls, table = [], {"data": None}

        def ns(cmd):
            calls.append(cmd[:3])
            if cmd[:3] == ["nft", "-j", "list"]:
                d = table["data"]
                return subprocess.CompletedProcess(cmd, 0 if d else 1, json.dumps(d or {}), "")
            table["data"] = acct_json({})           # nft -f создал таблицу
            return subprocess.CompletedProcess(cmd, 0, "", "")
        e, t = self.engine(ns)
        st = {"upstreams": [{"id": "u1", "num": 1}]}
        e._account(t, st)
        self.assertEqual(e.acct_state, "ok")
        self.assertIn(["nft", "-f", os.path.join(__import__("app.engine").engine.RUN_DIR, "acct.nft")], calls)
        table["data"] = acct_json({("10.8.1.2", "awgr1"): [10, 20], ("10.8.1.2", "eth0"): [1, 2]})
        e._account(t, st)
        self.assertEqual(e.traffic.data["K"]["by_out"][month_key()], {"u1": [10, 20], "direct": [1, 2]})

    def test_kernel_refuses(self):
        n = {"create": 0}

        def ns(cmd):
            if cmd[:2] == ["nft", "-f"]:
                n["create"] += 1
                return subprocess.CompletedProcess(cmd, 1, "", "Error: Could not process rule")
            return subprocess.CompletedProcess(cmd, 1, "", "No such file or directory")
        e, t = self.engine(ns)
        for _ in range(3):
            e._account(t, {"upstreams": []})
        self.assertEqual(e.acct_state, "off")
        self.assertEqual(n["create"], 1)                 # не долбим ядро каждый цикл
        self.assertEqual(e.events, ["ev.acct_off"])      # и не засоряем журнал
        t.key = "k2"                                     # контейнер перезапустился — пробуем снова
        e._account(t, {"upstreams": []})
        self.assertEqual(n["create"], 2)


class Req:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class ExitQuotaApiTest(unittest.TestCase):
    UP = ("[Interface]\nAddress = 10.9.0.2/32\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\n"
          "[Peer]\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\nAllowedIPs = 0.0.0.0/0\n"
          "Endpoint = 198.51.100.1:51820\n")

    def test_add_edit_delete(self):
        from app import main, web
        uid = main.add_upstream(Req({"name": "NL", "config": self.UP, "quota_gb": "1.5",
                                     "quota_action": "notify"}))["id"]
        u = main.Store.upstream(main.store.snapshot(), uid)
        self.assertEqual((u["quota"], u["quota_action"]), (int(1.5 * 1024 ** 3), "notify"))
        main.store.mutate(lambda s: main.Store.upstream(s, uid).update(quota_hit="2026-10"))
        main.edit_upstream(Req({"name": "NL2"}), uid)                     # без квоты — не трогаем
        self.assertEqual(main.Store.upstream(main.store.snapshot(), uid)["quota_hit"], "2026-10")
        main.edit_upstream(Req({"quota_gb": "", "quota_action": "fallback"}), uid)
        u = main.Store.upstream(main.store.snapshot(), uid)
        self.assertEqual((u["quota"], u["quota_hit"]), (None, None))
        for bad in ({"quota_gb": "-1"}, {"quota_gb": "x"}, {"quota_gb": "5", "quota_action": "drop"}):
            with self.assertRaises(web.HTTPError):
                main.edit_upstream(Req(bad), uid)
        view = main._upstream_view(main.store.snapshot(), main.Store.upstream(main.store.snapshot(), uid))
        self.assertIn("month_rx", view["traffic"])
        self.assertFalse(view["over_quota"])
        main.engine.traffic.outs[uid] = {"total": [1, 1], "months": {}}
        main.del_upstream(None, uid)
        self.assertNotIn(uid, main.engine.traffic.outs)

    def test_restore_validates_quota(self):
        from app import main, web
        import test_api
        s = test_api.good_state()
        s["upstreams"][0].update(quota=10 ** 9, quota_action="notify", quota_hit="2026-10",
                                 quota_warned="rm -rf")
        u = main.clean_backup_state(s)["upstreams"][0]
        self.assertEqual((u["quota"], u["quota_action"], u["quota_hit"], u["quota_warned"]),
                         (10 ** 9, "notify", "2026-10", None))
        s["upstreams"][0]["quota_action"] = "explode"
        with self.assertRaises(web.HTTPError):
            main.clean_backup_state(s)


if __name__ == "__main__":
    unittest.main()
