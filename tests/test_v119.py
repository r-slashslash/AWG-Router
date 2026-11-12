"""1.19.0: балансировка клиентов между выходами и ограничение скорости (клиенты, все вместе, выходы).

python3 -m unittest discover tests
"""
import asyncio
import json
import os
import random
import resource
import select
import shutil
import socket
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

from app import balance, nftgen, shaping, sniproxy  # noqa: E402

MB = 1_000_000 / 8          # байт/с в 1 Мбит/с
UP = ("[Interface]\nAddress = 10.9.0.{n}/32\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\n"
      "[Peer]\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\nAllowedIPs = 0.0.0.0/0\n"
      "Endpoint = 198.51.100.{n}:51820\n")


class Req:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


# ----------------------------------------------------------------- tc
class ShapingPlanTest(unittest.TestCase):
    def test_nothing_set_nothing_to_do(self):
        p = shaping.plan("awg0", {}, {"10.8.1.2": {}, "10.8.1.3": {"down": None}}, [{"num": 1, "iface": "awgr1"}])
        self.assertEqual(p, {"roots": {}, "ingress": {}})

    def test_total_gives_every_client_a_class(self):
        p = shaping.plan("awg0", {"down": 100}, {"10.8.1.2": {}, "10.8.1.3": {"down": 10}}, [])
        self.assertEqual(set(p["roots"]), {"awg0"})           # только загрузка: ifb не нужен
        self.assertEqual(p["ingress"], {})
        cmds = p["roots"]["awg0"]
        self.assertTrue(cmds[0].startswith(f"qdisc add dev awg0 root handle {shaping.HANDLE}: htb default 2"))
        self.assertIn("rate 100000kbit ceil 100000kbit", cmds[1])
        # оба клиента — со своим классом; у ограниченного потолок 10 Мбит/с
        flt = [c for c in cmds if " ht 2:" in c]
        self.assertEqual(len(flt), 2)
        self.assertIn("ht 2:2: match ip dst 10.8.1.2/32", flt[0])
        self.assertIn("ht 2:3: match ip dst 10.8.1.3/32", flt[1])
        self.assertTrue(any("ceil 10000kbit" in c for c in cmds))
        self.assertTrue(any("hashkey mask 0x000000ff at 16 link 2:" in c for c in cmds))

    def test_only_own_limits_without_total(self):
        p = shaping.plan("awg0", {}, {"10.8.1.2": {}, "10.8.1.200": {"up": 5}}, [])
        self.assertEqual(set(p["roots"]), {"awgq0"})          # только отдача — через ifb
        self.assertEqual(p["ingress"], {"awg0": "awgq0"})
        cmds = p["roots"]["awgq0"]
        flt = [c for c in cmds if " ht 2:" in c]
        self.assertEqual(len(flt), 1)                          # класс только у ограниченного
        self.assertIn("ht 2:c8: match ip src 10.8.1.200/32", flt[0])
        self.assertTrue(any("at 12 link 2:" in c for c in cmds))

    def test_exit_caps(self):
        p = shaping.plan("awg0", {}, {}, [{"num": 3, "iface": "awgr3", "down": 80, "up": 20},
                                          {"num": 4, "iface": "awgr4"}])
        self.assertEqual(set(p["roots"]), {"awgr3", "awgq3"})
        self.assertEqual(p["ingress"], {"awgr3": "awgq3"})
        self.assertIn("rate 20000kbit", p["roots"]["awgr3"][1])
        self.assertIn("rate 80000kbit", p["roots"]["awgq3"][1])
        self.assertIn("matchall action mirred egress redirect dev awgq3", shaping.redirect("awgr3", "awgq3")[1])

    def test_bad_values_ignored(self):
        self.assertIsNone(shaping.mbit(True))
        self.assertIsNone(shaping.mbit(0))
        self.assertIsNone(shaping.mbit(10 ** 9))
        self.assertEqual(shaping.mbit(2.5), 2.5)

    def test_parse_qdiscs(self):
        text = json.dumps([{"kind": "htb", "handle": shaping.HANDLE + ":", "root": True, "dev": "awg0"},
                           {"kind": "htb", "handle": "1:", "root": True, "dev": "eth0"},
                           {"kind": "ingress", "handle": "ffff:", "parent": "ffff:fff1", "dev": "awg0"},
                           {"kind": "fq_codel", "handle": "8001:", "parent": shaping.HANDLE + ":2", "dev": "awg0"}])
        self.assertEqual(shaping.parse_qdiscs(text), ({"awg0"}, {"awg0"}))
        self.assertEqual(shaping.parse_qdiscs("oops"), (set(), set()))


class FakeTarget:
    """Цель с записью команд: tc и ip отвечают как ядро, в котором ничего не стоит."""
    key, iface = "k1", "awg0"

    def __init__(self, fail=()):
        self.calls, self.qdiscs, self.links, self.fail = [], [], {"awg0", "awgr1"}, set(fail)

    def ns(self, cmd, **kw):
        self.calls.append(cmd)
        out, rc = "", 0
        if cmd[:3] == ["tc", "-j", "qdisc"]:
            out = json.dumps(self.qdiscs)
        elif cmd[:2] == ["ip", "-j"]:
            out = json.dumps([{"ifname": x} for x in sorted(self.links)])
        elif cmd[:3] == ["ip", "link", "add"]:
            if "ifb" in self.fail:
                return subprocess.CompletedProcess(cmd, 2, "", "Error: Unknown device type.")
            self.links.add(cmd[3])
        elif cmd[:3] == ["ip", "link", "del"]:
            self.links.discard(cmd[3])
        elif cmd[:2] == ["tc", "-batch"]:
            with open(cmd[2]) as f:
                lines = f.read().split("\n")
            dev = lines[0].split()[3]
            if lines[0].startswith("qdisc add dev") and " root " in lines[0]:
                self.qdiscs.append({"kind": "htb", "handle": shaping.HANDLE + ":", "root": True, "dev": dev})
            if " ingress" in lines[0]:
                self.qdiscs.append({"kind": "ingress", "handle": "ffff:", "dev": dev})
        elif cmd[:3] == ["tc", "qdisc", "del"]:
            kind = cmd[-1]
            self.qdiscs = [q for q in self.qdiscs if not (q["dev"] == cmd[4] and (
                (kind == "root" and q.get("root")) or (kind == "ingress" and q["kind"] == "ingress")))]
        return subprocess.CompletedProcess(cmd, rc, out, "")


class SyncShapingTest(unittest.TestCase):
    def engine(self):
        from app import engine as eng_mod
        os.makedirs(eng_mod.RUN_DIR, exist_ok=True)

        class E:
            _sync_shaping = eng_mod.Engine._sync_shaping
            _shape_failed = eng_mod.Engine._shape_failed
            _tc_batch = eng_mod.Engine._tc_batch
            _ifb_source = eng_mod.Engine._ifb_source
            _clear_shaping = eng_mod.Engine._clear_shaping
            shaping_plan = eng_mod.Engine.shaping_plan

            def _links(self, t):
                return set(t.links)
        e = E()
        e.rt, e.clients, e.events = {}, [{"ip": "10.8.1.2", "public_key": "K"}], []
        e.event = lambda lvl, m: e.events.append(m.key)
        e.shape_state, e._shape, e._shape_key, e._shape_retry = None, {}, None, 0.0
        return e

    def st(self, shaping_=None, limits=None):
        return {"settings": {"shaping": shaping_} if shaping_ else {}, "limits": limits or {}, "upstreams": []}

    def test_dry_run_flag_off_for_this_test(self):
        from app import config
        self.assertTrue(config.DRY_RUN)       # остальные тесты этого класса подменяют его на время вызова

    def run_sync(self, e, t, st):
        from app import config
        old, config.DRY_RUN = config.DRY_RUN, False
        try:
            e._sync_shaping(t, st)
        finally:
            config.DRY_RUN = old

    def test_apply_keep_remove(self):
        e, t = self.engine(), FakeTarget()
        self.run_sync(e, t, self.st({"down": 100, "up": 50}))
        self.assertEqual(e.shape_state, {"state": "on"})
        self.assertIn("awgq0", t.links)                                   # ifb создан
        self.assertIn(["ip", "link", "add", "awgq0", "type", "ifb"], t.calls)
        batches = [c for c in t.calls if c[:2] == ["tc", "-batch"]]
        self.assertEqual(len(batches), 3)                                 # awg0, awgq0, перенаправление
        # второй цикл: всё на месте — ничего не пересоздаётся
        t.calls.clear()
        self.run_sync(e, t, self.st({"down": 100, "up": 50}))
        self.assertFalse([c for c in t.calls if c[:2] == ["tc", "-batch"]])
        # интерфейс пересоздали (очередь пропала) — ставится снова
        t.qdiscs = [q for q in t.qdiscs if q["dev"] != "awg0" or q["kind"] != "htb"]
        self.run_sync(e, t, self.st({"down": 100, "up": 50}))
        self.assertTrue([c for c in t.calls if c[:2] == ["tc", "-batch"]])
        # выключили — убрано всё: перенаправление раньше ifb
        t.calls.clear()
        self.run_sync(e, t, self.st())
        self.assertIsNone(e.shape_state)
        self.assertNotIn("awgq0", t.links)
        i_ing = t.calls.index(["tc", "qdisc", "del", "dev", "awg0", "ingress"])
        i_ifb = t.calls.index(["ip", "link", "del", "awgq0"])
        self.assertLess(i_ing, i_ifb)
        self.assertEqual(t.qdiscs, [])
        # и дальше tc не вызывается вовсе
        t.calls.clear()
        self.run_sync(e, t, self.st())
        self.assertEqual(t.calls, [])

    def test_no_ifb_is_reported_once(self):
        e, t = self.engine(), FakeTarget(fail={"ifb"})
        self.run_sync(e, t, self.st({"up": 50}))
        self.assertEqual(e.shape_state["state"], "error")
        self.assertEqual(e.shape_state["error"].key, "sh.no_ifb")
        self.assertEqual(e.events, ["ev.shaping_failed"])
        self.assertFalse([c for c in t.calls if c[:2] == ["tc", "-batch"]])   # без ifb не перенаправляем
        t.calls.clear()
        self.run_sync(e, t, self.st({"up": 50}))
        self.assertEqual(t.calls, [])                                     # та же ошибка — пауза
        self.assertEqual(e.events, ["ev.shaping_failed"])

    def test_foreign_qdisc_untouched(self):
        e, t = self.engine(), FakeTarget()
        t.qdiscs = [{"kind": "htb", "handle": "1:", "root": True, "dev": "eth0"}]
        self.run_sync(e, t, self.st())                                   # уборка на новой цели
        self.assertFalse([c for c in t.calls if c[:3] == ["tc", "qdisc", "del"]])


# ----------------------------------------------------------------- nft
class StickyRulesetTest(unittest.TestCase):
    UPS = [{"num": 1, "snat": "10.0.0.2", "mtu": 1280}, {"num": 2, "snat": "10.0.0.3", "mtu": 1280}]

    def test_sticky_chains(self):
        S = nftgen.Sticky
        text = nftgen.generate("awg0", {}, self.UPS, {"rules": [], "default": S(1)},
                               {"10.8.1.5": {"rules": [], "default": S(2)},
                                "10.8.1.6": {"rules": [], "default": 2}}, balance={1, 2})
        self.assertIn("chain ob_u1 {\n\t\tct mark { 0x2001, 0x2002 } meta mark set ct mark accept\n"
                      "\t\tmeta mark set 0x2001 ct mark set 0x2001 accept", text)
        self.assertIn("goto ob_u2", text)
        self.assertIn("goto o_u2", text)                 # Sticky(2) и 2 — разные политики
        self.assertEqual(text.count("chain p_"), 3)

    def test_sticky_outside_balance_is_plain(self):
        S = nftgen.Sticky
        pol, cmap = nftgen.layout({"rules": [], "default": S(2)}, {}, {1, 2}, {1})
        self.assertIs(type(pol["p_global"]["default"]), int)
        text = nftgen.generate("awg0", {}, self.UPS, {"rules": [], "default": S(2)}, {}, balance={1})
        self.assertNotIn("goto ob_u2", text)
        self.assertNotIn("chain ob_u2", text)

    @unittest.skipUnless(shutil.which("nft"), "nft")
    def test_nft_accepts(self):
        S = nftgen.Sticky
        g = {"rules": [(["ru"], "direct")], "default": S(1), "domain": [(["d"], "up:x")]}
        text = nftgen.generate("awg0", {"ru": ["77.88.0.0/18"]}, self.UPS, g,
                               {"10.8.1.5": {"rules": [], "default": S(2)}}, 10443, {1, 2})
        self.assertIn("chain oqb_u1", text)
        with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
            f.write(text)
        p = subprocess.run(["nft", "-c", "-f", f.name], capture_output=True, text=True)
        os.unlink(f.name)
        if p.returncode and "Operation not permitted" in p.stderr:
            self.skipTest("nft -c needs CAP_NET_ADMIN")
        self.assertEqual(p.returncode, 0, p.stderr)


# ----------------------------------------------------------------- балансировка
def feed_rates(b, rates: dict, now: float):
    """Установившиеся скорости: {(клиент, выход): (отдача, загрузка) в Мбит/с}."""
    b.client_rate = {k: [v[0] * MB, v[1] * MB] for k, v in rates.items()}
    per = {}
    for (pk, out), v in rates.items():
        e = per.setdefault(out, [0.0, 0.0])
        e[0] += v[0] * MB
        e[1] += v[1] * MB
    b.exit_rate = per
    b._last = now


class BalancerTest(unittest.TestCase):
    M = [{"id": "a", "up": None, "down": None}, {"id": "b", "up": None, "down": None}]

    def test_new_clients_spread(self):
        b = balance.Balancer()
        got = b.plan(self.M, ["k1", "k2", "k3", "k4"], 1000)
        self.assertEqual(sorted(got.values()), ["a", "a", "b", "b"])

    def test_capacity_weights_new_clients(self):
        b = balance.Balancer()
        m = [{"id": "a", "up": None, "down": 300}, {"id": "b", "up": None, "down": 100}]
        got = b.plan(m, [f"k{i}" for i in range(8)], 1000)
        self.assertEqual(list(got.values()).count("a"), 6)       # втрое мощнее — втрое больше клиентов

    def test_busy_exit_avoided(self):
        b = balance.Balancer()
        b.plan(self.M, ["k1", "k2"], 1000)
        on_a = next(k for k, v in b.assign.items() if v == "a")
        feed_rates(b, {(on_a, "a"): (1, 40)}, 1000)
        self.assertEqual(b.plan(self.M, ["k1", "k2", "k3"], 1010)["k3"], "b")

    def test_lost_exit_moves_clients_at_once(self):
        b = balance.Balancer()
        b.plan(self.M, ["k1", "k2"], 1000)
        got = b.plan(self.M[1:], ["k1", "k2"], 1010)
        self.assertEqual(set(got.values()), {"b"})
        got = b.plan([], ["k1", "k2"], 1020)                   # все лежат — назначений нет
        self.assertEqual(got, {})

    def test_rebalance_after_sustain(self):
        b = balance.Balancer()
        b.assign = {"k1": "a", "k2": "a", "k3": "b"}
        rates = {("k1", "a"): (1, 30), ("k2", "a"): (1, 30)}
        t = 10_000.0
        feed_rates(b, rates, t)
        self.assertEqual(b.plan(self.M, ["k1", "k2", "k3"], t)["k1"], "a")     # перекос только начался
        feed_rates(b, rates, t + 60)
        self.assertEqual(b.plan(self.M, ["k1", "k2", "k3"], t + 60), {"k1": "a", "k2": "a", "k3": "b"})
        feed_rates(b, rates, t + balance.SUSTAIN + 1)
        got = b.plan(self.M, ["k1", "k2", "k3"], t + balance.SUSTAIN + 1)
        self.assertEqual(list(got.values()).count("b"), 2)                     # один активный переехал
        self.assertEqual(b.last_move["from"], "a")
        moved = b.last_move["pk"]
        # перекос не ушёл (старые соединения доживают) — следующий перенос не раньше STEP,
        # и того же клиента обратно — не раньше CLIENT_PAUSE
        later = t + balance.SUSTAIN + 1 + balance.SUSTAIN + 5
        b.assign[moved] = "a"
        feed_rates(b, rates, later)
        b.plan(self.M, ["k1", "k2", "k3"], later - balance.SUSTAIN)
        got = b.plan(self.M, ["k1", "k2", "k3"], later)
        self.assertEqual(got[moved], "a")

    def test_no_move_when_quiet_or_no_gain(self):
        b = balance.Balancer()
        b.assign = {"k1": "a", "k2": "b"}
        feed_rates(b, {("k1", "a"): (0.1, 1)}, 0)               # меньше BUSY_BPS
        for t in (0, 500, 1000):
            self.assertEqual(b.plan(self.M, ["k1", "k2"], t), {"k1": "a", "k2": "b"})
        # один тяжёлый клиент: перенос ничего не даст (на другом станет так же)
        feed_rates(b, {("k1", "a"): (1, 50)}, 0)
        for t in (0, 500, 1000):
            self.assertEqual(b.plan(self.M, ["k1", "k2"], t)["k1"], "a")

    def test_feed_smooths(self):
        b = balance.Balancer()
        b.feed({}, 0)
        b.feed({("a", "k1"): [0, int(10 * MB * 10)]}, 10)       # 10 Мбит/с за 10 с
        r = b.rate("a")[1] / MB
        self.assertTrue(2 < r < 10, r)                           # сглажено, но заметно
        for i in range(2, 40):
            b.feed({("a", "k1"): [0, int(10 * MB * 10)]}, i * 10)
        self.assertAlmostEqual(b.rate("a")[1] / MB, 10, delta=0.1)
        b.feed({("a", "k1"): [0, int(10 * MB * 10)]}, 10_000)   # панель стояла — замер не считается
        self.assertAlmostEqual(b.rate("a")[1] / MB, 10, delta=0.1)


# ----------------------------------------------------------------- движок и API
class EngineBalanceTest(unittest.TestCase):
    def setUp(self):
        from app import main
        self.main = main
        main.engine.reconcile()
        self.ids = [main.add_upstream(Req({"name": f"E{n}", "config": UP.format(n=n)}))["id"] for n in (21, 22)]
        main.engine.reconcile()
        st = main.store.snapshot()
        for uid in self.ids:          # в демо второй туннель «мёртвый» — делаем оба рабочими
            main.engine.health[uid] = {"state": "up", "healthy": True}
        self.st = st

    def tearDown(self):
        m = self.main
        m.store.mutate(lambda s: s["routing"].pop("balance", None))
        for uid in self.ids:
            m.del_upstream(Req({"replace": "direct"}), uid)
        m.engine.bal, m.engine.bal_new, m.engine.bal_nums = {}, None, set()
        m.engine.balancer = balance.Balancer()

    def nums(self):
        st = self.main.store.snapshot()
        return {self.main.Store.upstream(st, u)["num"] for u in self.ids}

    def test_balance_rules_trace_state(self):
        m = self.main
        st0 = m.store.snapshot()
        m.put_routing(Req({"default": "direct", "rules": st0["routing"]["rules"],
                           "balance": {"on": True, "skip": ["nope"]}}))
        st = m.store.snapshot()
        self.assertEqual(st["routing"]["balance"], {"on": True, "skip": []})   # неизвестный id отброшен
        others = [u["id"] for u in st["upstreams"] if u["id"] not in self.ids]
        m.put_routing(Req({"default": "direct", "rules": st["routing"]["rules"],
                           "balance": {"on": True, "skip": others}}))
        st = m.store.snapshot()
        for uid in self.ids:
            m.engine.health[uid] = {"state": "up", "healthy": True}
        m.engine._balance(st)
        self.assertEqual(m.engine.bal_nums, self.nums())
        pks = [c["public_key"] for c in m.engine.clients if c.get("ip")
               and m.engine.policy_for(st, c["public_key"])["balanced"]]
        self.assertTrue(pks)
        self.assertEqual(set(m.engine.bal), set(pks))
        gp, cps = m.engine._policies(st)
        self.assertIsInstance(gp["default"], nftgen.Sticky)
        text = m.engine.build_ruleset(m.engine.target, st)
        for n in self.nums():
            self.assertIn(f"chain ob_u{n}", text)
        # трассировка и состояние для браузера показывают назначенный выход
        pk = pks[0]
        tr = m.engine.trace(pk, "8.8.8.8")
        self.assertEqual(tr["result"], "up:" + m.engine.bal[pk])
        self.assertEqual(tr["steps"][-1].key, "tr.balance")
        s = m.get_state(None)
        c = next(x for x in s["clients"] if x["public_key"] == pk)
        self.assertTrue(c["balanced"])
        self.assertEqual(c["default"], "up:" + m.engine.bal[pk])
        self.assertEqual(sorted(s["balance"]["members"]), sorted(self.ids))
        v = next(u for u in s["upstreams"] if u["id"] == self.ids[0])
        self.assertTrue(v["balance"])
        self.assertEqual(sum(next(u for u in s["upstreams"] if u["id"] == i)["bal_clients"] for i in self.ids),
                         len(pks))
        # оба выхода упали — запасной путь (выход по умолчанию), без Sticky
        for uid in self.ids:
            m.engine.health[uid] = {"state": "stale", "healthy": False}
        m.engine._balance(st)
        self.assertEqual(m.engine.bal, {})
        gp, _ = m.engine._policies(st)
        self.assertEqual(gp["default"], "direct")
        self.assertEqual(m.engine.trace(pk, "8.8.8.8")["steps"][-1].key, "tr.balance_down")

    def test_client_with_own_exit_not_balanced(self):
        m = self.main
        st = m.store.snapshot()
        m.put_routing(Req({"default": "direct", "rules": st["routing"]["rules"], "balance": {"on": True}}))
        pk = m.engine.clients[0]["public_key"]
        old = st["clients"].get(pk)
        try:
            m.put_client(Req({"outbound": "block"}), pk)
            self.assertFalse(m.engine.policy_for(m.store.snapshot(), pk)["balanced"])
        finally:
            m.store.mutate(lambda s: s["clients"].pop(pk, None) if old is None else s["clients"].update({pk: old}))

    def test_bot_make_default_turns_balance_off(self):
        m = self.main
        st = m.store.snapshot()
        m.put_routing(Req({"default": "direct", "rules": st["routing"]["rules"], "balance": {"on": True}}))
        m.set_default_outbound("up:" + self.ids[0])
        r = m.store.snapshot()["routing"]
        self.assertEqual((r["default"], r["balance"]["on"]), ("up:" + self.ids[0], False))

    def test_delete_exit_leaves_skip(self):
        m = self.main
        st = m.store.snapshot()
        m.put_routing(Req({"default": "direct", "rules": st["routing"]["rules"],
                           "balance": {"on": True, "skip": [self.ids[0]]}}))
        uid = self.ids.pop(0)
        m.del_upstream(Req({"replace": "direct"}), uid)
        self.assertEqual(m.store.snapshot()["routing"]["balance"]["skip"], [])

    def test_routing_without_balance_keeps_it(self):
        m = self.main
        st = m.store.snapshot()
        m.put_routing(Req({"default": "direct", "rules": st["routing"]["rules"], "balance": {"on": True}}))
        m.put_routing(Req({"default": "block", "rules": st["routing"]["rules"]}))   # старый интерфейс
        self.assertTrue(m.store.snapshot()["routing"]["balance"]["on"])
        m.put_routing(Req({"default": "direct", "rules": st["routing"]["rules"]}))


class RatesApiTest(unittest.TestCase):
    def test_exit_rates(self):
        from app import main, web
        uid = main.add_upstream(Req({"name": "R", "config": UP.format(n=31), "rate_down": "80", "rate_up": ""}))["id"]
        try:
            u = main.Store.upstream(main.store.snapshot(), uid)
            self.assertEqual((u.get("rate_down"), "rate_up" in u), (80.0, False))
            main.edit_upstream(Req({"name": "R2"}), uid)                    # без полей — не трогаем
            self.assertEqual(main.Store.upstream(main.store.snapshot(), uid)["rate_down"], 80.0)
            main.edit_upstream(Req({"rate_down": None, "rate_up": 12.5}), uid)
            u = main.Store.upstream(main.store.snapshot(), uid)
            self.assertEqual(("rate_down" in u, u["rate_up"]), (False, 12.5))
            for bad in ("x", -1, 0.01, 10 ** 7):
                with self.assertRaises(web.HTTPError):
                    main.edit_upstream(Req({"rate_up": bad}), uid)
            v = main._upstream_view(main.store.snapshot(), u)
            self.assertEqual((v["rate_up"], v["speed"]), (12.5, [0, 0]))
        finally:
            main.del_upstream(Req({"replace": "direct"}), uid)

    def test_client_and_total(self):
        from app import main
        main.engine.reconcile()
        pk = main.engine.clients[0]["public_key"]
        st0 = main.store.snapshot()
        try:
            main.put_limits(Req({"rate_down": 10}), pk)
            self.assertEqual(main.store.snapshot()["limits"][pk]["rate_down"], 10.0)
            # срок и лимит трафика из Telegram не стирают ограничение скорости
            main.apply_limits(pk, None, None, "month")
            self.assertEqual(main.store.snapshot()["limits"][pk]["rate_down"], 10.0)
            main.put_limits(Req({"rate_down": None}), pk)
            self.assertNotIn(pk, main.store.snapshot()["limits"])            # ничего не осталось
            main.put_settings(Req({"shaping": {"down": "100", "up": None}}))
            self.assertEqual(main.store.snapshot()["settings"]["shaping"], {"down": 100.0})
            main.put_settings(Req({"shaping": {"down": "", "up": ""}}))
            self.assertNotIn("shaping", main.store.snapshot()["settings"])
        finally:
            main.store.mutate(lambda s: s.update(limits=st0["limits"]))
            main.store.mutate(lambda s: s["settings"].pop("shaping", None))

    def test_restore_checks_rates(self):
        from app import main, web
        st = main.store.snapshot()
        for bad in ({"settings": {**st["settings"], "shaping": {"down": "fast"}}},
                    {"routing": {**st["routing"], "balance": "on"}}):
            with self.assertRaises(web.HTTPError):
                main.clean_backup_state({**st, **bad})


# ----------------------------------------------------------------- sniproxy
class BucketTest(unittest.TestCase):
    def test_rate_and_shared(self):
        async def go():
            b = sniproxy.Bucket(4_000_000)              # 4 МБ/с, запас 200 КБ
            t0 = time.monotonic()
            # два соединения берут по 600 КБ кусками по 100 КБ из одного бака
            async def conn():
                for _ in range(6):
                    await b.take(100_000)
            await asyncio.gather(conn(), conn())
            return time.monotonic() - t0
        dt = asyncio.run(go())
        self.assertGreater(dt, 0.2)                      # (1,2 МБ − запас) / 4 МБ/с ≈ 0,25 с
        self.assertLess(dt, 1.0)

    def test_reload_keeps_buckets(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "sni.json")
        with open(p, "w") as f:
            json.dump({"listen": "127.0.0.1", "rates": {"u1": [125000, 0]}}, f)
        s = sniproxy.Sniffer(p)
        self.assertEqual(set(s.buckets), {("u1", 0)})
        b = s.buckets[("u1", 0)]
        s.reload()
        self.assertIs(s.buckets[("u1", 0)], b)            # та же скорость — бак тот же
        with open(p, "w") as f:
            json.dump({"listen": "127.0.0.1", "rates": {}}, f)
        s.reload()
        self.assertEqual(s.buckets, {})


class NetsTest(unittest.TestCase):
    """Nets: поиск адреса соединения в списке CIDR панели (учёт трафика без совпадения по домену)."""

    def test_ranges_like_nftables_set(self):
        """Адреса списка ищутся так же, как в наборе nftables: подсеть целиком, границы включены.

        Вход: подсеть с битами узла (10.1.2.3/8), адрес без длины, /32, соседние и вложенные подсети
        не по порядку, IPv6, мусор, испорченная строка с нулевым байтом, пустые строки и длины
        префикса, которые отвергает ipaddress ("/33", "/" без числа, "/+24", "/ 24").
        Ожидание: плохие строки пропущены, остальные действуют; вложенная /30 не обрезает
        объемлющую /25; первый и последний адрес внутри, соседние с ними снаружи.
        """
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = os.path.join(d, "c.txt")
        with open(p, "w") as f:
            f.write("192.0.2.128/25\n10.1.2.3/8\n\n2001:db8::/32\nnot an address\n198.51.100.7\n1.2.3.8\0\n"
                    "203.0.113.9/32\n192.0.2.0/25\n192.0.2.10/30\n1.2.3.4/33\n1.2.3.5/\n1.2.3.6/+24\n1.2.3.7/ 24\n")
        n = sniproxy.Nets(p)
        inside = ["10.0.0.0", "10.255.255.255", "192.0.2.0", "192.0.2.12", "192.0.2.100", "192.0.2.255",
                  "198.51.100.7", "203.0.113.9"]
        outside = ["9.255.255.255", "11.0.0.0", "192.0.1.255", "192.0.3.0", "198.51.100.6", "203.0.113.10",
                   "1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7", "1.2.3.8"]
        self.assertEqual([ip for ip in inside if ip not in n], [])
        self.assertEqual([ip for ip in outside if ip in n], [])


class ReloadTest(unittest.TestCase):
    """Перечитывание настроек по SIGHUP (Sniffer.on_hup) не останавливает соединения."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = os.path.join(self.dir, "sni.json")
        self.write({"listen": "127.0.0.1"})
        self.sniffer = sniproxy.Sniffer(self.path)

    def write(self, cfg) -> None:
        """Новый sni.json, как его пишет панель перед SIGHUP."""
        with open(self.path, "w") as f:
            f.write(cfg if isinstance(cfg, str) else json.dumps(cfg))

    @staticmethod
    async def until(cond, timeout=20.0) -> bool:
        """Ждёт, пока перечитывание в фоне не даст нужное состояние."""
        deadline = time.monotonic() + timeout
        while not cond() and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        return cond()

    def test_loop_runs_during_reload(self):
        """Разбор 100 000 CIDR не держит цикл событий.

        Вход: sni.json со списком cidrs на 100 000 строк; задача-пульс с шагом 10 мс.
        Ожидание: список применён; разбор шёл не в потоке цикла событий; самый большой разрыв пульса
        меньше 200 мс (запас против дрожания CI).
        """
        cidrs = os.path.join(self.dir, "cidrs.txt")
        rnd = random.Random(1)
        with open(cidrs, "w") as f:
            for _ in range(100_000):
                f.write(f"{rnd.randrange(1, 224)}.{rnd.randrange(256)}.{rnd.randrange(256)}.0/24\n")
        s = self.sniffer
        threads = []
        real_load = sniproxy.load

        def traced_load(path, prev=None):
            """Запоминает поток, в котором идёт разбор."""
            threads.append(threading.current_thread())
            return real_load(path, prev)

        async def go():
            """SIGHUP на фоне пульса. -> (список применён, самый большой разрыв пульса)."""
            gaps = []

            async def pulse():
                """Просыпается каждые 10 мс; разрыв больше шага значит, что цикл событий стоял."""
                t = time.monotonic()
                while True:
                    await asyncio.sleep(0.01)
                    now = time.monotonic()
                    gaps.append(now - t)
                    t = now
            beat = asyncio.ensure_future(pulse())
            await asyncio.sleep(0.05)
            self.write({"listen": "127.0.0.1", "cidrs": {"big": cidrs}})
            with mock.patch.object(sniproxy, "load", side_effect=traced_load):
                s.on_hup()
                applied = await self.until(lambda: "big" in s.nets)
            beat.cancel()
            return applied, max(gaps)
        applied, gap = asyncio.run(go())
        self.assertTrue(applied)
        self.assertEqual(len(threads), 1)
        self.assertIsNot(threads[0], threading.main_thread())
        self.assertLess(gap, 0.2)

    def test_hup_during_reload_is_not_lost(self):
        """SIGHUP, пришедший во время перечитывания, даёт ещё одно перечитывание с последним файлом.

        Вход: первый разбор задержан, пока тест не пришлёт второй SIGHUP с другим sni.json.
        Ожидание: файл разобран дважды и не одновременно (иначе старый разбор мог бы закончиться
        позже нового); в итоге действуют настройки второго SIGHUP.
        """
        s = self.sniffer
        first, second = {"listen": "127.0.0.1", "clients": "10.8.0.0/24"}, {"listen": "127.0.0.1", "clients": "10.8.1.0/24"}
        started, release = threading.Event(), threading.Event()
        lock = threading.Lock()
        running = [0, 0]                                # [идёт сейчас, наибольшее число одновременно]
        real_load = sniproxy.load

        def slow_first_load(path, prev=None):
            """Первый разбор прочитал файл и ещё идёт, когда приходит второй SIGHUP; остальные сразу."""
            with lock:
                running[0] += 1
                running[1] = max(running)
            try:
                conf = real_load(path, prev)
                if not started.is_set():
                    started.set()
                    release.wait(10)
                return conf
            finally:
                with lock:
                    running[0] -= 1

        async def go():
            """Второй SIGHUP во время первого разбора."""
            with mock.patch.object(sniproxy, "load", side_effect=slow_first_load) as load:
                try:
                    self.write(first)
                    s.on_hup()
                    in_progress = await self.until(started.is_set)
                    self.write(second)
                    s.on_hup()
                finally:
                    release.set()
                applied = await self.until(lambda: s.cfg == second and load.call_count == 2 and not running[0])
                await asyncio.sleep(0.05)               # опоздавший старый разбор успел бы всё испортить
                return in_progress, applied, s.cfg == second, load.call_count
        in_progress, applied, still, calls = asyncio.run(go())
        self.assertTrue(in_progress)
        self.assertTrue(applied)
        self.assertTrue(still)
        self.assertEqual(calls, 2)
        self.assertEqual(running[1], 1)

    def test_unchanged_lists_are_not_parsed_again(self):
        """Перечитывание не разбирает заново списки, файлы которых не менялись.

        Панель шлёт SIGHUP при каждом изменении настроек, а большие списки при этом обычно прежние.
        Вход: sni.json со списком доменов и списком CIDR; перечитывание без изменений; затем панель
        заменяет файл CIDR (os.replace, как lists.save_cidrs) файлом того же размера; затем список доменов
        уходит из настроек.
        Ожидание: без изменений — те же объекты; новый файл CIDR разобран заново (новые адреса), домены
        прежние; ушедший список не остаётся в кэше.
        """
        dom, nets = os.path.join(self.dir, "d.txt"), os.path.join(self.dir, "n.txt")
        with open(dom, "w") as f:
            f.write("example.com\n")
        with open(nets, "w") as f:
            f.write("203.0.113.0/24\n")
        cfg = {"listen": "127.0.0.1", "lists": {"d": dom}, "cidrs": {"n": nets}}
        s = self.sniffer
        self.write(cfg)
        s.reload()
        d1, n1 = s.lists["d"], s.nets["n"]
        s.reload()
        self.assertIs(s.lists["d"], d1)
        self.assertIs(s.nets["n"], n1)
        with open(nets + ".tmp", "w") as f:
            f.write("203.0.113.0/25\n")                # тот же размер: замену выдают inode и время
        os.replace(nets + ".tmp", nets)
        s.reload()
        self.assertIs(s.lists["d"], d1)
        self.assertIsNot(s.nets["n"], n1)
        self.assertIn("203.0.113.7", s.nets["n"])
        self.assertNotIn("203.0.113.200", s.nets["n"])
        self.write({"listen": "127.0.0.1", "cidrs": {"n": nets}})
        s.reload()
        self.assertEqual(s.lists, {})
        self.assertEqual(set(s.files), {("cidrs", nets)})

    def test_bad_config_keeps_old_and_next_hup_works(self):
        """Неверный sni.json: старые настройки остаются, ошибка в журнале, следующий SIGHUP применяется.

        Вход: SIGHUP с битым JSON, затем SIGHUP с верным файлом.
        Ожидание: после первого прежние настройки и запись "reload: ..."; после второго новые.
        """
        s = self.sniffer
        good = {"listen": "127.0.0.1", "clients": "10.8.1.0/24"}

        async def go():
            """Битый файл, затем верный."""
            with mock.patch.object(sniproxy, "log") as log:
                self.write("{not json")
                s.on_hup()
                logged = await self.until(lambda: log.called)
                kept = s.cfg == {"listen": "127.0.0.1"}
                self.write(good)
                s.on_hup()
                return logged, kept, await self.until(lambda: s.cfg == good), log.call_args_list[0].args[0]
        logged, kept, applied, msg = asyncio.run(go())
        self.assertTrue(logged)
        self.assertTrue(kept)
        self.assertTrue(applied)
        self.assertTrue(msg.startswith("reload:"), msg)


@unittest.skipUnless(os.path.isfile("/proc/self/limits"), "нужен /proc (Linux)")
class SniproxyProcessTest(unittest.TestCase):
    """sniproxy.py как отдельный процесс, как его запускает панель."""

    def test_raises_open_files_limit(self):
        """Соединение держит 6 дескрипторов (2 сокета и 2 канала splice): мягкий предел 1024 у панели
        дал бы около 170 соединений. Посредник поднимает мягкий предел до жёсткого.

        Вход: процесс запущен с мягким пределом 256.
        Ожидание: после запуска ("listening" в журнале) мягкий предел процесса равен жёсткому.
        """
        _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard <= 256:
            self.skipTest("жёсткий предел дескрипторов не выше 256")
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with socket.socket() as probe:                  # свободный порт для посредника
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        p = os.path.join(d, "sni.json")
        with open(p, "w") as f:
            json.dump({"listen": "127.0.0.1", "port": port}, f)
        # Низкий мягкий предел ставит сам дочерний процесс до запуска посредника: fork с preexec_fn
        # небезопасен, когда другие тесты уже запустили потоки.
        start = ("import resource, runpy, sys; "
                 "resource.setrlimit(resource.RLIMIT_NOFILE, (256, resource.getrlimit(resource.RLIMIT_NOFILE)[1])); "
                 "sys.argv = sys.argv[1:]; runpy.run_path(sys.argv[0], run_name='__main__')")
        proc = subprocess.Popen([sys.executable, "-c", start, sniproxy.__file__, p], stderr=subprocess.PIPE)
        self.addCleanup(proc.wait, 10)
        self.addCleanup(proc.stderr.close)
        self.addCleanup(proc.terminate)
        ready, _, _ = select.select([proc.stderr], [], [], 10)    # не висеть, если журнал молчит
        self.assertTrue(ready, "sniproxy.py ничего не написал за 10 с")
        self.assertIn(b"listening", proc.stderr.readline())
        with open(f"/proc/{proc.pid}/limits") as f:
            soft_now = next(x.split()[3] for x in f if x.startswith("Max open files"))
        self.assertEqual(soft_now, str(hard))


class SharedLimitTest(unittest.TestCase):
    """Предел выхода SOCKS5 общий для туннеля (hev) и соединений посредника через прокси."""
    CAP = 2_500_000.0            # 20 Мбит/с

    def test_share(self):
        self.assertEqual(sniproxy.share(self.CAP, 0), self.CAP)               # другая дорога молчит — всё
        self.assertEqual(sniproxy.share(self.CAP, self.CAP), self.CAP / 2)    # обе качают — пополам
        self.assertEqual(sniproxy.share(self.CAP, self.CAP * 0.3), self.CAP * 0.7)

    def test_net_dev(self):
        text = ("Inter-|   Receive                            |  Transmit\n"
                " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets\n"
                "    lo:     100       1    0    0    0     0          0         0      100       1 0 0 0 0 0 0\n"
                " awgr1: 5000000    3000    0    0    0     0          0         0   200000    1500 0 0 0 0 0 0\n")
        self.assertEqual(sniproxy.net_dev(text), {"lo": (100, 100), "awgr1": (5_000_000, 200_000)})

    def sniffer(self, shared=True):
        """Посредник с пределом загрузки u1 (shared: делится с туннелем) -> (посредник, путь sni.json)."""
        return sniproxy.Sniffer(self.conf(self.conf_dict(shared))), self.path

    def conf_dict(self, shared=True, rates=None, entries=None) -> dict:
        """sni.json: rates по умолчанию — предел загрузки u1; entries — свои записи shared для u1."""
        cfg = {"listen": "127.0.0.1", "rates": {"u1": rates or [0, self.CAP]}}
        if shared:
            cfg["shared"] = {"u1": entries or {"1": {"iface": "awgr1", "dev": "awgq1", "cap": self.CAP,
                                                     "tc": shaping.cap_change("awgq1", 20)}}}
        return cfg

    def conf(self, cfg: dict) -> str:
        """Пишет sni.json во временный каталог теста (один на тест) -> путь."""
        if not hasattr(self, "path"):
            d = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, d)
            self.path = os.path.join(d, "sni.json")
        with open(self.path, "w") as f:
            json.dump(cfg, f)
        return self.path

    def test_tick_splits(self):
        s, _ = self.sniffer()
        b = s.buckets[("u1", 1)]
        todo = s.share_tick({"awgr1": (0, 0)}, 0.0)
        self.assertEqual([x[1] for x in todo], [self.CAP])                  # сначала туннелю весь предел
        # туннель качает 20 Мбит/с, посредник молчит: баку — половина, туннелю — всё
        rx = 0
        for t in range(1, 12):
            rx += int(self.CAP)
            todo = s.share_tick({"awgr1": (rx, 0)}, float(t))
        self.assertAlmostEqual(b.rate, self.CAP / 2, delta=self.CAP * 0.02)
        # посредник тоже качает 10 Мбит/с — туннелю остаётся половина
        for t in range(12, 24):
            rx += int(self.CAP / 2)
            b.total += int(self.CAP / 2)
            todo = s.share_tick({"awgr1": (rx, 0)}, float(t))
        st = s.share_state[("u1", 1)]
        self.assertAlmostEqual(st["tc"], self.CAP / 2, delta=self.CAP * 0.05)
        argv = [x.replace("{kbit}", "10000") for x in shaping.cap_change("awgq1", 20)]
        self.assertEqual(argv[:9], ["tc", "class", "change", "dev", "awgq1", "parent", f"{shaping.HANDLE}:",
                                    "classid", f"{shaping.HANDLE}:1"])
        self.assertIn("10000kbit", argv)

    def test_restore_on_reload_and_stop(self):
        s, p = self.sniffer()
        calls = []
        s.tc_set = lambda d, bps, wait=True: calls.append((d["dev"], bps))
        with open(p, "w") as f:
            json.dump({"listen": "127.0.0.1", "rates": {"u1": [0, self.CAP]}}, f)
        s.reload()                                              # выход больше не делится — весь предел туннелю
        self.assertEqual(calls, [("awgq1", self.CAP)])
        self.assertEqual(s.shared, {})
        s2, _ = self.sniffer()
        calls2 = []
        s2.tc_set = lambda d, bps, wait=True: calls2.append((d["dev"], bps))
        s2.restore()
        self.assertEqual(calls2, [("awgq1", self.CAP)])

    def test_no_bucket_no_sharing(self):
        s, _ = self.sniffer()
        self.assertIn(("u1", 1), s.shared)
        d = tempfile.mkdtemp()
        p = os.path.join(d, "sni.json")
        with open(p, "w") as f:
            json.dump({"listen": "127.0.0.1", "shared": {"u1": {"1": {"iface": "awgr1", "cap": 1, "tc": ["true"]}}}}, f)
        self.assertEqual(sniproxy.Sniffer(p).shared, {})        # без предела в rates делить нечего

    def test_shared_without_numeric_cap_ignored(self):
        """Выход без числового предела не делится: иначе возврат предела туннелю упал бы на нём.

        Вход: shared без cap, со строковым, логическим, нулевым и отрицательным cap.
        Ожидание: ни один выход не попал в деление.
        """
        for cap in (None, "20", True, 0, -1):
            with self.subTest(cap=cap):
                entry = {"iface": "awgr1", "tc": ["true"], **({} if cap is None else {"cap": cap})}
                p = self.conf(self.conf_dict(entries={"1": entry}))
                self.assertEqual(sniproxy.Sniffer(p).shared, {})

    def test_restore_on_hup(self):
        """SIGHUP убрал выход из деления: туннель получает весь предел, tc ждётся вне цикла событий.

        Вход: посредник делит предел u1; новый sni.json без shared; on_hup.
        Ожидание: tc поставлен на весь предел, процесс tc дождались не в потоке цикла, деления больше нет.
        """
        s, _ = self.sniffer()
        proc = object()
        reaped = []
        self.conf(self.conf_dict(shared=False))

        async def go():
            """SIGHUP и ожидание, пока процесс tc не дождутся."""
            with mock.patch.object(s, "tc_set", return_value=proc) as tc_set, \
                    mock.patch.object(s, "_reap", side_effect=lambda p: reaped.append((p, threading.current_thread()))):
                s.on_hup()
                await ReloadTest.until(lambda: reaped)
            return tc_set.call_args_list
        calls = asyncio.run(go())
        self.assertEqual([(c.args[0]["dev"], c.args[1]) for c in calls], [("awgq1", self.CAP)])
        self.assertEqual([p for p, _ in reaped], [proc])
        self.assertIsNot(reaped[0][1], threading.main_thread())
        self.assertEqual(s.shared, {})

    def test_share_skips_exit_dropped_during_tc(self):
        """Пока деление ждёт tc одного выхода, SIGHUP убрал из деления другой: ему доля уже не ставится.

        Вход: делятся обе стороны u1; во время ожидания первого tc настройки меняются на «без shared»
        (туннель второй стороны уже получил весь предел от перечитывания).
        Ожидание: поставлена доля только первой стороне; запоздалая доля второй не урезает туннель.
        """
        entries = {str(i): {"iface": "awgr1", "dev": f"awgq{i}", "cap": self.CAP, "tc": shaping.cap_change(f"awgq{i}", 20)}
                   for i in (0, 1)}
        s = sniproxy.Sniffer(self.conf(self.conf_dict(rates=[self.CAP, self.CAP], entries=entries)))
        dropped = sniproxy.load(self.conf(self.conf_dict(shared=False, rates=[self.CAP, self.CAP])))
        proc = object()

        async def go():
            """Одно деление; перечитывание случается во время ожидания первого tc."""
            with mock.patch.object(s, "tc_set", return_value=proc) as tc_set, \
                    mock.patch.object(s, "_reap", side_effect=lambda p: s.apply(dropped)):
                await s.share_once({"awgr1": (0, 0)}, 0.0)
            return [c.args[0]["dev"] for c in tc_set.call_args_list]
        self.assertEqual(asyncio.run(go()), ["awgq0"])

    def test_changed_share_restarts_rate_state(self):
        """Предел выхода изменился: скорости для деления считаются заново, а не от старого бака.

        Вход: одно деление; затем те же настройки (состояние остаётся) и настройки с другим пределом.
        Ожидание: при тех же настройках состояние деления сохранено, при новом пределе сброшено
        (новый бак начинает счёт с нуля, старое состояние дало бы отрицательную скорость).
        """
        s, _ = self.sniffer()
        s.share_tick({"awgr1": (0, 0)}, 0.0)
        s.apply(sniproxy.load(self.conf(self.conf_dict())))
        self.assertIn(("u1", 1), s.share_state)
        half = {"1": {"iface": "awgr1", "dev": "awgq1", "cap": self.CAP / 2, "tc": shaping.cap_change("awgq1", 10)}}
        s.apply(sniproxy.load(self.conf(self.conf_dict(rates=[0, self.CAP / 2], entries=half))))
        self.assertNotIn(("u1", 1), s.share_state)

    def test_engine_passes_only_socks_with_limits(self):
        from app import main
        from types import SimpleNamespace
        st = main.store.snapshot()
        socks_id = main.add_upstream(Req({"name": "S", "config": "socks5://198.51.100.77:1080",
                                          "rate_down": 20}))["id"]
        awg_id = main.add_upstream(Req({"name": "A", "config": UP.format(n=41), "rate_down": 20}))["id"]
        try:
            st = main.store.snapshot()
            e = main.engine
            saved = dict(e.rt)
            for uid in (socks_id, awg_id):
                u = main.Store.upstream(st, uid)
                e.rt[uid] = SimpleNamespace(num=u["num"], iface=f"awgr{u['num']}", target_key="k")
            rates = {socks_id: [0, 2_500_000], awg_id: [0, 2_500_000]}
            got = e._sni_shared(st, rates)
            self.assertEqual(set(got), {socks_id})
            n = main.Store.upstream(st, socks_id)["num"]
            self.assertEqual(got[socks_id]["1"]["dev"], f"awgq{n}")
            self.assertEqual(got[socks_id]["1"]["iface"], f"awgr{n}")
            self.assertNotIn("0", got[socks_id])                 # отдача без предела — не делится
            e._sni_shared_devs = {f"awgq{n}"}
            e._shape[f"awgq{n}"] = "h"
            e._stop_sni()                                        # посредник остановлен — очередь заново
            self.assertNotIn(f"awgq{n}", e._shape)
        finally:
            e.rt.clear()
            e.rt.update(saved)
            for uid in (socks_id, awg_id):
                main.del_upstream(Req({"replace": "direct"}), uid)


ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def install_part(start: str, end: str) -> str:
    """Кусок install.sh от строки, начинающейся со start, до строки, начинающейся с end, включительно."""
    with open(os.path.join(ROOT, "install.sh"), encoding="utf-8") as f:
        lines = f.read().split("\n")
    i = next(n for n, x in enumerate(lines) if x.startswith(start))
    j = next(n for n in range(i, len(lines)) if lines[n].startswith(end))
    return "\n".join(lines[i:j + 1]) + "\n"


def install_line(start: str) -> str:
    """Однострочная функция из install.sh (`f() { …; }`)."""
    with open(os.path.join(ROOT, "install.sh"), encoding="utf-8") as f:
        return next(x for x in f if x.startswith(start))


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class InstallerIfbTest(unittest.TestCase):
    """install.sh ставит linux-modules-extra, если в ядре нет модуля ifb (ограничение скорости)."""
    FAKES = {
        # модуль есть, если он «встроен» (IFB=yes) или пакет для этого ядра уже поставили
        "modprobe": '[ "${IFB:-}" = yes ] || [ -f "$T/extra-$KR" ]',
        "modinfo": "exit 1",
        "uname": 'echo "$KR"',
        "apt-cache": 'for p in $CANDS; do [ "$2" = "$p" ] && { echo "  Candidate: 1.0"; exit 0; }; done; '
                     'echo "  Candidate: (none)"',
        "apt-get": 'echo "apt-get $*" >> "$T/apt.log"; for a in "$@"; do case "$a" in '
                   'linux-modules-extra-$KR) touch "$T/extra-$KR" ;; esac; done',
    }

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        b = os.path.join(self.tmp, "bin")
        os.makedirs(b)
        for name, body in self.FAKES.items():
            with open(os.path.join(b, name), "w") as f:
                f.write("#!/usr/bin/env bash\n" + body + "\n")
            os.chmod(os.path.join(b, name), 0o755)
        self.env = {**os.environ, "PATH": f"{b}:{os.environ['PATH']}", "T": self.tmp, "KR": "6.8.0-1015-aws"}
        self.code = ("ok() { echo \"OK $1\"; }\nwarn() { echo \"WARN $1\"; }\n"
                     f'APT_LOG="{self.tmp}/apt-out.log"\nAPT_UPDATED=0\n'
                     + install_part("apt_update() {", "}") + install_part("apt_install() {", "}")
                     + install_line("apt_has() {")
                     + install_part("ifb_ok() {", "else warn \"Kernel module ifb"))

    def run_sh(self, **env):
        r = subprocess.run(["bash", "-uo", "pipefail", "-c", self.code], env={**self.env, **env},
                           capture_output=True, text=True, timeout=30)
        try:
            with open(os.path.join(self.tmp, "apt.log")) as f:
                apt = [x.strip() for x in f if x.strip()]
        except OSError:
            apt = []
        return r, apt

    def test_module_present_no_apt(self):
        r, apt = self.run_sh(IFB="yes", CANDS="linux-modules-extra-6.8.0-1015-aws")
        self.assertIn("OK Kernel module ifb", r.stdout)
        self.assertEqual(apt, [])                       # ничего не ставим и даже не обновляем списки

    def test_cloud_kernel_gets_extra_modules(self):
        r, apt = self.run_sh(CANDS="linux-modules-extra-6.8.0-1015-aws linux-modules-extra-aws")
        self.assertIn("OK Kernel module ifb", r.stdout, r.stderr)
        inst = [a for a in apt if " install " in a]
        self.assertEqual(len(inst), 1)
        self.assertIn("linux-modules-extra-6.8.0-1015-aws", inst[0])
        self.assertIn("linux-modules-extra-aws", inst[0])   # и для будущих ядер этой линейки

    def test_no_package_warns(self):
        r, apt = self.run_sh(CANDS="")
        self.assertIn("WARN Kernel module ifb is not available", r.stdout)
        self.assertEqual(r.returncode, 0)                # установка идёт дальше
        self.assertFalse([a for a in apt if " install " in a])


if __name__ == "__main__":
    unittest.main()
