"""1.19.0: балансировка клиентов между выходами и ограничение скорости (клиенты, все вместе, выходы).

python3 -m unittest discover tests
"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

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


if __name__ == "__main__":
    unittest.main()
