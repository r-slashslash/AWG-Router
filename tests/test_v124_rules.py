"""1.24.0: трафик по правилам (#54) — метки соединений, таблица учёта, хранение, посредник, API.
python3 -m unittest tests.test_v124_rules"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import balance, checks, config, nftgen, sniproxy, system  # noqa: E402
from app.web import HTTPError  # noqa: E402
from tests.seed import legacy_lists  # noqa: E402
from app.store import Store  # noqa: E402
from app.traffic import Traffic, month_key  # noqa: E402
from app import panel  # noqa: E402
from app.api import clients as api_clients, exits as api_exits, routing as api_routing, state as api_state  # noqa: E402

UP = ("[Interface]\nAddress = 10.9.0.{n}/32\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\n"
      "[Peer]\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\nAllowedIPs = 0.0.0.0/0\n"
      "Endpoint = 198.51.100.{n}:51820\n")


class Req:
    def __init__(self, body):
        self.body = body

    def json(self, limit=None):
        return self.body

D = config.RULE_DEFAULT_SLOT


def pol(rules, default="direct", slots=None, domain=(), dslots=()):
    p = {"rules": rules, "default": default, "domain": list(domain)}
    if slots is not None:
        p["slots"], p["dslots"] = slots, list(dslots)
    return p


class LabelsInRulesetTest(unittest.TestCase):
    def test_rule_lines_mark_connections(self):
        """Вход: политика из двух правил по адресам с номерами 0 и 2 (между ними — правило по доменам).
        Ожидание: строка правила ставит метку соединения со своим номером, «По умолчанию» — свою."""
        text = nftgen.generate("awg0", {"ru": ["5.0.0.0/8"], "of": ["10.20.0.0/16"]}, [{"num": 1}],
                               pol([(["ru"], "direct"), (["of"], 1)], slots=[0, 2]), {}, labels=True)
        self.assertIn("ip daddr @l_ru ct label set 0 goto o_direct", text)
        self.assertIn("ip daddr @l_of ct label set 2 goto o_u1", text)
        self.assertIn(f"ct label set {D} goto o_direct", text)

    def test_without_labels_as_before(self):
        """Вход: та же политика без учёта по правилам. Ожидание: ни одной метки соединения, как в 1.23.x."""
        text = nftgen.generate("awg0", {"ru": ["5.0.0.0/8"]}, [], pol([(["ru"], "direct")]), {})
        self.assertNotIn("ct label", text)
        self.assertNotIn("q_lab", text)

    def test_trailing_rule_kept_for_counting(self):
        """Вход: последнее правило ведёт туда же, куда «По умолчанию». Ожидание: без учёта строку убирают (она ничего не
        меняет), с учётом — оставляют: её трафик считается отдельно."""
        plain = nftgen.layout(pol([(["ru"], "direct")]), {}, set())[0]["p_global"]
        counted = nftgen.layout(pol([(["ru"], "direct")], slots=[0]), {}, set())[0]["p_global"]
        self.assertEqual(plain["rules"], [])
        self.assertEqual(counted["rules"], [(["ru"], "direct")])

    def test_same_rules_other_order_other_policy(self):
        """Вход: два клиента с одинаковыми правилами, но у второго правило по доменам стоит раньше (номера другие).
        Ожидание: разные политики — метка одной цепочки иначе значила бы разное правило у разных клиентов."""
        a = pol([(["ru"], "direct")], slots=[0], domain=[(["yt"], "up:x")], dslots=[1])
        b = pol([(["ru"], "direct")], slots=[1], domain=[(["yt"], "up:x")], dslots=[0])
        _, cmap = nftgen.layout(pol([]), {"10.8.1.2": a, "10.8.1.3": b}, set())
        self.assertNotEqual(cmap["10.8.1.2"], cmap["10.8.1.3"])

    def test_quic_slot_bits_stripped_before_routing(self):
        """Вход: QUIC через очередь и правило по доменам с номером 3. Ожидание: цепочка q_lab ставит метку 3 по битам
        вердикта и снимает биты номера до маршрутизации; в c_forward — отказ пакету клиента, если биты всё же дошли."""
        p = pol([], slots=[], domain=[(["yt"], "up:x")], dslots=[3])
        text = nftgen.generate("awg0", {}, [{"num": 1}], p, {}, sniff_port=10443, quic=True, labels=True)
        strip = 0xFFFFFFFF ^ config.QUIC_SLOT_MASK
        self.assertIn(f"meta mark & {config.QUIC_SLOT_MASK:#x} == {4 << config.QUIC_SLOT_SHIFT:#x} ct label set 3 "
                      f"meta mark set meta mark & {strip:#x} return", text)
        self.assertIn(f"udp dport 443 meta mark & {config.QUIC_SLOT_MASK:#x} != 0x0 jump q_lab", text)
        self.assertLess(text.index("jump q_lab"), text.index("ct mark set meta mark |"))
        self.assertIn(f'iifname "awg0" meta mark & {config.QUIC_SLOT_MASK:#x} != 0x0 reject', text)

    def test_quic_strip_even_without_labels(self):
        """Вход: QUIC без учёта по правилам. Ожидание: q_lab всё равно снимает биты номера (вердикт посредника мог
        прийти от настройки, сделанной при учёте) — без меток соединений."""
        text = nftgen.generate("awg0", {}, [{"num": 1}], pol([], domain=[(["yt"], 1)]), {}, sniff_port=10443,
                               quic=True)
        self.assertIn("chain q_lab {\n\t\tmeta mark set meta mark &", text)
        self.assertNotIn("ct label", text)

    @unittest.skipUnless(shutil.which("nft") and os.geteuid() == 0, "nft -c — только от root")
    def test_kernel_accepts_ruleset_with_labels(self):
        """Вход: набор с метками и правилом по доменам (без очереди QUIC: её нет в песочнице, проверяют net-tests).
        Ожидание: ядро и nft его принимают (nft -c)."""
        p = pol([(["ru"], "direct"), (["of"], 1)], slots=[0, 2], domain=[(["yt"], 1)], dslots=[1])
        text = nftgen.generate("awg0", {"ru": ["5.0.0.0/8"], "of": ["10.20.0.0/16"]}, [{"num": 1, "snat": "10.9.0.2"}],
                               p, {"10.8.1.5": pol([(["ru"], 1)], slots=[0])}, sniff_port=10443,
                               balance={1}, labels=True)
        with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
            f.write(text)
        try:
            r = subprocess.run(["nft", "-c", "-f", f.name], capture_output=True, text=True)
        finally:
            os.unlink(f.name)
        self.assertEqual(r.returncode, 0, r.stderr)


class RacctTableTest(unittest.TestCase):
    def test_ruleset_keeps_sets(self):
        """Вход: таблица учёта по правилам с номерами 0, 1 и «По умолчанию». Ожидание: наборы — через add (остаются со
        счётчиками), цепочки очищаются и пишутся заново, по строке на номер и направление."""
        text = nftgen.racct_ruleset("awg0", [1, 0, D])
        self.assertNotIn("delete table", text)
        self.assertIn("add set ip awgr_racct up { type ipv4_addr . mark;", text)
        self.assertIn("flush chain ip awgr_racct r_up", text)
        self.assertEqual(text.count("update @up"), 3)
        self.assertIn(f"ct label {D} update @down {{ ip daddr . {D:#x} counter }} return", text)

    def test_parse(self):
        """Вход: ответ nft -j с нашей отметкой и двумя наборами. Ожидание: пары «адрес + номер» с байтами двух сторон;
        чужая таблица — None."""
        data = {"nftables": [
            {"rule": {"table": "awgr_racct", "chain": "c_racct", "comment": nftgen.racct_marker("awg0")}},
            {"set": {"table": "awgr_racct", "name": "up", "elem": [
                {"elem": {"val": {"concat": ["10.8.1.2", 3]}, "counter": {"bytes": 100}}}]}},
            {"set": {"table": "awgr_racct", "name": "down", "elem": [
                {"elem": {"val": {"concat": ["10.8.1.2", 3]}, "counter": {"bytes": 900}}},
                {"elem": {"val": {"concat": ["10.8.1.2", 99]}, "counter": {"bytes": 5}}}]}}]}
        self.assertEqual(nftgen.parse_racct(data, "awg0"), {("10.8.1.2", 3): [100, 900]})
        self.assertIsNone(nftgen.parse_racct(data, "wg0"))

    @unittest.skipUnless(shutil.which("nft") and os.geteuid() == 0, "nft — только от root")
    def test_counters_survive_new_slots(self):
        """Вход: таблица стоит, в наборе есть счётчик; правил стало больше — таблица ставится заново.
        Ожидание: счётчик на месте (иначе учёт по правилам обнулялся бы при каждой новой строке правила)."""
        name = "awgr_racct"
        subprocess.run(["nft", "delete", "table", "ip", name], capture_output=True)
        try:
            for slots, extra in (([0, D], "add element ip awgr_racct up { 10.8.1.2 . 0x0 counter packets 1 bytes 77 }"),
                                 ([0, 1, 2, D], "")):
                with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
                    f.write(nftgen.racct_ruleset("awg0", slots) + (extra + "\n" if extra else ""))
                r = subprocess.run(["nft", "-f", f.name], capture_output=True, text=True)
                os.unlink(f.name)
                self.assertEqual(r.returncode, 0, r.stderr)
            out = subprocess.run(["nft", "-j", "list", "table", "ip", name], capture_output=True, text=True).stdout
            self.assertEqual(nftgen.parse_racct(json.loads(out), "awg0"), {("10.8.1.2", 0): [77, 0]})
        finally:
            subprocess.run(["nft", "delete", "table", "ip", name], capture_output=True)


class TrafficByRuleTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.t = Traffic(os.path.join(self.d, "traffic.json"))
        self.t.data["PK"] = {"total": [0, 0], "months": {}, "last": None}
        self.of = lambda ip, slot: {0: ("r_yt", "r_yt"), D: ("_d", "_default")}.get(slot)

    def test_first_read_is_baseline(self):
        """Вход: таблица уже была (traffic.json без её счётчиков), затем прирост. Ожидание: первое чтение — только точка
        отсчёта; второе — прирост к правилу у клиента и в итоге правила."""
        self.t.update_rules({("10.8.1.2", 0): [10, 100]}, self.of, {"10.8.1.2": "PK"})
        self.assertEqual(self.t.client_rules("PK"), {})
        self.t.update_rules({("10.8.1.2", 0): [15, 160], ("10.8.1.2", D): [1, 2]}, self.of, {"10.8.1.2": "PK"})
        self.assertEqual(self.t.client_rules("PK"), {"r_yt": [5, 60], "_d": [1, 2]})
        self.assertEqual(self.t.rules_month(), {"r_yt": [5, 60], "_default": [1, 2]})
        self.assertEqual(self.t.rule_used("r_yt"), 65)

    def test_fresh_table_counts_all(self):
        """Вход: таблицу только что поставили (fresh). Ожидание: всё в её счётчиках — новый трафик."""
        self.t.update_rules({("10.8.1.2", 0): [10, 100]}, self.of, {"10.8.1.2": "PK"}, fresh=True)
        self.assertEqual(self.t.client_rules("PK"), {"r_yt": [10, 100]})

    def test_unknown_slot_not_counted(self):
        """Вход: номер правила, которого у клиента уже нет (rule_of → None). Ожидание: не считается."""
        self.t.update_rules({("10.8.1.2", 5): [10, 100]}, self.of, {"10.8.1.2": "PK"}, fresh=True)
        self.assertEqual(self.t.client_rules("PK"), {})
        self.assertEqual(self.t.rules_month(), {})

    def test_keeps_two_months_per_client(self):
        """Вход: трафик клиента по правилам за три месяца. Ожидание: у клиента — два последних (файл не растёт на
        клиентах × правилах), итоги правила — все."""
        for i, mk_ts in enumerate((1767225600, 1769904000, 1772323200)):      # янв, фев, мар 2026
            self.t.update_rules({("10.8.1.2", 0): [i + 1, 0]}, self.of, {"10.8.1.2": "PK"}, fresh=(i == 0), now=mk_ts)
        self.assertEqual(sorted(self.t.data["PK"]["by_rule"]), ["2026-02", "2026-03"])
        self.assertEqual(len(self.t.rules["r_yt"]["months"]), 3)

    def test_sniproxy_keys_with_rule_number(self):
        """Вход: байты посредника «клиент|выход|номер» и старого вида «клиент|выход». Ожидание: выход считается по обоим,
        правило — только по ключу с номером."""
        self.t.update_sni(7, {"10.8.1.2|u1|0": [3, 30], "10.8.1.2|u1": [1, 1]}, {"u1"}, {"10.8.1.2": "PK"},
                          rule_of=self.of)
        self.assertEqual(self.t.out_month("u1"), [4, 31])
        self.assertEqual(self.t.client_rules("PK"), {"r_yt": [3, 30]})

    def test_top_and_round_trip(self):
        """Вход: два клиента по одному правилу, сохранение и новая загрузка, копия и восстановление.
        Ожидание: «больше всех» — по убыванию; после загрузки и восстановления цифры те же."""
        self.t.data["PK2"] = {"total": [0, 0], "months": {}, "last": None}
        self.t.update_rules({("10.8.1.2", 0): [1, 10], ("10.8.1.3", 0): [5, 50]}, self.of,
                            {"10.8.1.2": "PK", "10.8.1.3": "PK2"}, fresh=True)
        self.assertEqual([pk for pk, _ in self.t.rule_top("r_yt")], ["PK2", "PK"])
        self.t.save()
        t2 = Traffic(self.t.path)
        self.assertEqual(t2.client_rules("PK2"), {"r_yt": [5, 50]})
        self.assertEqual(t2.rules_month(), {"r_yt": [6, 60]})
        self.assertTrue(t2.racct_synced)
        t3 = Traffic(os.path.join(self.d, "other.json"))
        t3.replace(self.t.export())
        self.assertEqual(t3.client_rules("PK"), {"r_yt": [1, 10]})
        self.assertEqual(t3.rules_month(), {"r_yt": [6, 60]})


class SniproxyRuleNumberTest(unittest.TestCase):
    def test_decide_and_miss_carry_rule_number(self):
        """Вход: настройка посредника с номерами правил (1.24.0). Ожидание: совпало правило по доменам — его номер;
        без совпадения — номер правила по адресам или «По умолчанию»; ключ счётчика — «клиент|выход|номер»."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for name, text in (("dom.txt", "youtube.com\n"), ("nets.txt", "5.0.0.0/8\n")):
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        cfg = {"listen": "127.0.0.1", "clients": "10.8.1.0/24",
               "lists": {"yt": os.path.join(d, "dom.txt")}, "cidrs": {"ru": os.path.join(d, "nets.txt")},
               "policies": {"p_global": {"mark": 1, "rules": [{"lists": ["yt"], "to": {"mark": 0x2001, "acct": "u1"},
                                                                 "slot": 0}],
                                         "acct": {"rules": [[["ru"], "direct", 1]], "default": "u1", "slot": D}}}}
        p = os.path.join(d, "sni.json")
        with open(p, "w") as f:
            json.dump(cfg, f)
        s = sniproxy.Sniffer(p)
        self.assertEqual(s.decide_rule("10.8.1.2", "www.youtube.com")[2], 0)
        self.assertEqual(s.decide("10.8.1.2", "www.youtube.com")[1], "yt")         # прежний вид ответа — как был
        self.assertEqual(s.miss("10.8.1.2", "5.6.7.8"), ("direct", 1))
        self.assertEqual(s.miss("10.8.1.2", "8.8.8.8"), ("u1", D))
        s.counter("10.8.1.2", "u1", 0)[1] += 7
        s.counter("10.8.1.2", "u1")[1] += 1
        self.assertEqual(s.bytes, {"10.8.1.2|u1|0": [0, 7], "10.8.1.2|u1": [0, 1]})


class EngineRulesTest(unittest.TestCase):
    def setUp(self):
        self.e = panel.engine
        self.st = panel.store.snapshot()
        self.st["lists"] = [{"id": "ru", "kind": "country"}, {"id": "yt", "kind": "domains"}]
        self.st["routing"]["rules"] = [
            {"id": "r_ru", "lists": ["ru"], "outbound": "direct", "enabled": True},
            {"id": "r_off", "lists": ["ru"], "outbound": "block", "enabled": False},
            {"id": "r_yt", "lists": ["yt"], "outbound": "block", "enabled": True}]
        self.st["routing"]["default"] = "block"
        self.st["clients"] = {"PKC": {"rules_mode": "custom", "outbound": "inherit",
                                      "rules": [{"id": "r_c1", "lists": ["yt"], "outbound": "direct"}]}}
        self.clients, self.e.clients = self.e.clients, [{"public_key": "PKG", "ip": "10.8.1.2"},
                                                          {"public_key": "PKC", "ip": "10.8.1.3"}]
        self.addCleanup(setattr, self.e, "clients", self.clients)

    def test_rule_keys(self):
        """Вход: клиент с общими правилами (одно из них выключено) и клиент со своими. Ожидание: номер — место среди
        включённых правил; общие правила и «По умолчанию» общего клиента — ещё и в итоги, свои — только у клиента."""
        of = self.e.rule_keys(self.st)
        self.assertEqual(of("10.8.1.2", 0), ("r_ru", "r_ru"))
        self.assertEqual(of("10.8.1.2", 1), ("r_yt", "r_yt"))
        self.assertIsNone(of("10.8.1.2", 2))
        self.assertEqual(of("10.8.1.2", D), ("_d", "_default"))
        self.assertEqual(of("10.8.1.3", 0), ("r_c1", None))       # свои правила — не в итоги общих
        self.assertEqual(of("10.8.1.3", D), ("_d", None))
        self.assertIsNone(of("10.8.1.9", 0))
        self.assertEqual(self.e.rule_slots(self.st), [0, 1, D])

    def test_policies_carry_numbers(self):
        """Вход: правила по адресам и по доменам вперемешку, учёт по правилам включён. Ожидание: у политики номера в
        том же порядке, что у правил клиента; без учёта — номеров нет."""
        with mock.patch.object(self.e, "_labels", True):
            gp, _ = self.e._policies(self.st)
        self.assertEqual((gp["slots"], gp["dslots"]), ([0], [1]))
        with mock.patch.object(self.e, "_labels", False):
            gp, _ = self.e._policies(self.st)
        self.assertNotIn("slots", gp)

    def test_hold_ruleset_without_labels(self):
        """Вход: правила «до панели» при включённом учёте. Ожидание: без меток соединений — их ставит nft самого
        сервера, который их может не знать."""
        t = mock.Mock(iface="awg0", key="k")
        with mock.patch.object(self.e, "_labels", True), mock.patch.object(self.e, "_up_list", return_value=[]), \
                mock.patch.object(self.e, "_cidrs", return_value=["5.0.0.0/8"]):
            self.assertIn("ct label set", self.e.build_ruleset(t, self.st))
            self.assertNotIn("ct label", self.e.build_ruleset(t, self.st, hold=True))

    def test_demo_counts_by_rule(self):
        """Вход: демо-цель (DRY_RUN), два прохода учёта. Ожидание: таблица учёта по правилам ставится, трафик правил
        растёт, состояние — ok."""
        t = system.DemoTarget() if hasattr(system, "DemoTarget") else None
        if t is None:
            self.skipTest("нет демо-цели")
        with mock.patch.object(self.e, "_labels", True):
            self.e._account_rules(t, self.st)
            self.assertEqual(self.e.racct_state, "ok")


class RuleTrafficApiTest(unittest.TestCase):
    def test_endpoints(self):
        """Вход: трафик клиента по правилу. Ожидание: /api/rule-traffic отдаёт его правила за месяц, /api/rule-top —
        клиентов по убыванию с именами; /api/state — итоги правил и состояние учёта."""
        e = panel.engine
        clients, e.clients = e.clients, [{"public_key": "PKX", "ip": "10.8.1.7", "name": "Phone"}]
        self.addCleanup(setattr, e, "clients", clients)
        e.traffic.data.setdefault("PKX", {"total": [0, 0], "months": {}, "last": None})
        e.traffic._add_rule("PKX", ("r_t", "r_t"), [3, 30], month_key())
        self.assertEqual(api_clients.rule_traffic(None, "PKX")["rules"], {"r_t": [3, 30]})
        self.assertEqual(api_routing.rule_top(None, "r_t")["top"], [{"pk": "PKX", "name": "Phone", "rx": 3, "tx": 30}])
        self.assertIn("r_t", api_state._state_view()["rule_traffic"]["rules"])


class RuleBalanceTest(unittest.TestCase):
    """#53: балансировка между выходами в одном правиле."""

    def setUp(self):
        legacy_lists(panel.store)                 # страны, как в новой установке до 1.22.0
        self.e = panel.engine
        self.e.reconcile()
        self.ids = [api_exits.add_upstream(Req({"name": f"B{n}", "config": UP.format(n=n)}))["id"] for n in (31, 32)]
        self.e.reconcile()
        for uid in self.ids:
            self.e.health[uid] = {"state": "up", "healthy": True}
        self.st0 = panel.store.snapshot()

    def tearDown(self):
        panel.store.mutate(lambda s: s.update(routing=self.st0["routing"], clients=self.st0["clients"]))
        for uid in self.ids:
            api_exits.del_upstream(Req({"replace": "direct"}), uid)
        self.e.rbal, self.e.rbal_plan, self.e.rbal_new, self.e.rbal_nums = {}, {}, {}, set()

    def put_rule(self, **kw):
        rule = {"id": "r_bal", "lists": ["ru"], "outbound": "direct", "enabled": True, "comment": "YouTube",
                "balance": list(self.ids), "balance_fb": "block", **kw}
        panel.store.mutate(lambda s: s["routing"].update(rules=[rule], default="direct"))
        return panel.store.snapshot()

    def test_check_fields(self):
        """Вход: правило с балансировкой из панели. Ожидание: outbound — первый выход группы (так его поведёт панель до
        1.24.0), резерв по умолчанию — «Блокировать»; неизвестный выход — ошибка у поля правила."""
        st = self.e.store.snapshot()
        out = checks.rules(st, [{"lists": ["ru"], "outbound": "direct", "balance": [self.ids[1], self.ids[0]]}])[0]
        self.assertEqual((out["outbound"], out["balance"], out["balance_fb"]),
                         ("up:" + self.ids[1], [self.ids[1], self.ids[0]], "block"))
        with self.assertRaises(HTTPError):
            checks.rules(st, [{"lists": ["ru"], "outbound": "direct", "balance": ["nope"]}])
        plain = checks.rules(st, [{"lists": ["ru"], "outbound": "direct", "balance": []}])[0]
        self.assertNotIn("balance", plain)

    def test_clients_spread_and_sticky(self):
        """Вход: правило по адресам с двумя рабочими выходами, несколько клиентов. Ожидание: клиенты распределены по
        обоим выходам; в политике клиента — Sticky на его выход (открытые соединения не переезжают)."""
        st = self.put_rule()
        self.e._balance(st)
        plan = self.e.rbal_plan["r_bal"]
        pks = [c["public_key"] for c in self.e.clients if c.get("ip")]
        self.assertEqual(set(plan), set(pks))
        self.assertEqual(set(plan.values()), set(self.ids))
        nums = {Store.upstream(st, u)["num"] for u in self.ids}
        self.assertEqual(self.e.rbal_nums, nums)
        _, cps = self.e._policies(st)
        c = next(x for x in self.e.clients if x.get("ip"))
        out = cps[c["ip"]]["rules"][0][1]
        self.assertIsInstance(out, nftgen.Sticky)
        self.assertEqual(int(out), Store.upstream(st, plan[c["public_key"]])["num"])

    def test_fallback_and_pending(self):
        """Вход: оба выхода группы лежат; затем один только подключается. Ожидание: сначала — резерв правила, пока
        выход подключается — блок, а не резерв (Н1, Г1)."""
        st = self.put_rule(balance_fb="direct")
        for uid in self.ids:
            self.e.health[uid] = {"state": "stale", "healthy": False}
        self.e._balance(st)
        r = st["routing"]["rules"][0]
        pk = next(x["public_key"] for x in self.e.clients if x.get("ip"))
        self.assertEqual(self.e.rule_out(st, r, pk), ("direct", False))
        self.e.health[self.ids[0]] = {"state": "connecting", "healthy": False}
        self.assertEqual(self.e.rule_out(st, r, pk), ("block", False))

    def test_domain_rule_gets_assigned_exit(self):
        """Вход: правило по доменам с балансировкой. Ожидание: в политике клиента у правила — назначенный ему выход
        (его разрешит sniproxy.py), у нового клиента (общая политика) — выход для нового."""
        panel.store.mutate(lambda s: s["lists"].append({"id": "ytb", "kind": "domains", "name": "yt", "source": ""})
                           if not Store.lst(s, "ytb") else None)
        st = self.put_rule(lists=["ytb"])
        self.e._balance(st)
        gp, cps = self.e._policies(st)
        c = next(x for x in self.e.clients if x.get("ip"))
        self.assertEqual(cps[c["ip"]]["domain"][0][1], "up:" + self.e.rbal_plan["r_bal"][c["public_key"]])
        self.assertEqual(gp["domain"][0][1], "up:" + self.e.rbal_new["r_bal"])

    def test_trace_and_state(self):
        """Вход: проверка маршрута к адресу из правила, состояние панели. Ожидание: шаг «балансировка в правиле» с
        выходом клиента; в состоянии — сколько клиентов правила на каждом выходе; /api/rule-traffic — выход клиента."""
        st = self.put_rule()
        self.e._balance(st)
        c = next(x for x in self.e.clients if x.get("ip"))
        with mock.patch.object(self.e.matcher, "contains", return_value="5.0.0.0/8"):
            res = self.e.trace(c["public_key"], "5.6.7.8")
        self.assertTrue(any(getattr(m, "key", None) == "tr.rule_balance" for m in res["steps"]), res["steps"])
        self.assertEqual(res["result"], "up:" + self.e.rbal_plan["r_bal"][c["public_key"]])
        counts = api_state._state_view()["rule_balance"]["r_bal"]
        self.assertEqual(sum(counts.values()), len(self.e.rbal_plan["r_bal"]))
        self.assertEqual(api_clients.rule_traffic(None, c["public_key"])["assign"],
                         {"r_bal": self.e.rbal_plan["r_bal"][c["public_key"]]})

    def test_default_balance_blocks_while_exit_connects(self):
        """Вход: балансировка «По умолчанию» с запасным «Напрямую», выход только что запущен (проверки ещё не было).
        Ожидание: блок, а не «Напрямую» (до 1.24.0 после запуска панели клиенты 1–2 с шли мимо выходов, как в Г1)."""
        panel.store.mutate(lambda s: s["routing"].update(default="direct", balance={"on": True, "skip": []}))
        st = panel.store.snapshot()
        for uid in self.ids:
            self.e.health.pop(uid, None)
        bal, new = self.e.bal, self.e.bal_new
        self.addCleanup(setattr, self.e, "bal", bal)
        self.addCleanup(setattr, self.e, "bal_new", new)
        self.e.bal, self.e.bal_new = {}, None
        self.assertEqual(self.e.default_out(st, None), "block")
        for uid in self.ids:
            self.e.health[uid] = {"state": "stale", "healthy": False}
        self.assertEqual(self.e.default_out(st, None), "direct")       # все упали — запасной, как раньше

    def test_feed_clients_only_client_rates(self):
        """Вход: прирост трафика правила у клиента. Ожидание: растёт скорость клиента на его выходе, скорости выходов
        не трогаются (они общие с основной балансировкой)."""
        b = balance.Balancer()
        b.exit_rate = {"u1": [1.0, 1.0]}
        b.feed_clients({("u1", "PK"): [0, 0]}, 100.0)
        b.feed_clients({("u1", "PK"): [1000, 900000]}, 110.0)
        self.assertGreater(b.client_rate[("PK", "u1")][1], 0)
        self.assertEqual(b.exit_rate, {"u1": [1.0, 1.0]})


class RuleQuotaTest(unittest.TestCase):
    """Месячный лимит правила: как у выхода — что делать, когда исчерпан, события 90 % и «исчерпан»."""

    def setUp(self):
        legacy_lists(panel.store)
        self.e = panel.engine
        self.st0 = panel.store.snapshot()
        self.racct = self.e.racct_state
        self.e.racct_state = "ok"

    def tearDown(self):
        panel.store.mutate(lambda s: s.update(routing=self.st0["routing"]))
        self.e.racct_state = self.racct
        self.e.traffic.rules.pop("r_q", None)

    def test_check(self):
        """Вход: лимит из окна правила в ГБ и действие. Ожидание: в правиле байты и действие; лимит без действия —
        «только сообщить»; неизвестный выход в действии — ошибка у поля."""
        st = panel.store.snapshot()
        r = checks.rules(st, [{"lists": ["ru"], "outbound": "direct", "quota_gb": "1.5",
                               "quota_action": "block"}])[0]
        self.assertEqual((r["quota"], r["quota_action"]), (int(1.5 * 1024 ** 3), "block"))
        r = checks.rules(st, [{"lists": ["ru"], "outbound": "direct", "quota_gb": 2}])[0]
        self.assertEqual(r["quota_action"], "notify")
        self.assertNotIn("quota", checks.rules(st, [{"lists": ["ru"], "outbound": "direct", "quota_gb": ""}])[0])
        with self.assertRaises(HTTPError):
            checks.rules(st, [{"lists": ["ru"], "outbound": "direct", "quota_gb": 1, "quota_action": "up:nope"}])

    def test_over_quota_routes_by_action_and_events(self):
        """Вход: правило «напрямую» с лимитом 1 ГБ и действием «блокировать», трафик правила 0,95 ГБ, затем 1,1 ГБ.
        Ожидание: сначала событие 90 %, путь прежний; потом «исчерпан» — правило идёт в блок, отметка в правиле, и
        повторного события нет."""
        gb = 1024 ** 3
        rule = {"id": "r_q", "lists": ["ru"], "outbound": "direct", "enabled": True, "comment": "Видео",
                "quota": gb, "quota_action": "block"}
        panel.store.mutate(lambda s: s["routing"].update(rules=[rule]))
        mk = month_key()
        self.e.traffic.rules["r_q"] = {"months": {mk: [0, int(0.95 * gb)]}}
        events = []
        with mock.patch.object(self.e, "event", side_effect=lambda lv, m: events.append(m.key)):
            self.e._rule_quotas(panel.store.snapshot())
            st = panel.store.snapshot()
            self.assertEqual(self.e.rule_out(st, st["routing"]["rules"][0], None), ("direct", False))
            self.e.traffic.rules["r_q"] = {"months": {mk: [0, int(1.1 * gb)]}}
            self.e._rule_quotas(panel.store.snapshot())
            self.e._rule_quotas(panel.store.snapshot())
        st = panel.store.snapshot()
        self.assertEqual(events, ["ev.rule_quota_warn", "ev.rule_quota_block"])
        self.assertEqual(st["routing"]["rules"][0]["quota_hit"], mk)
        self.assertEqual(self.e.rule_out(st, st["routing"]["rules"][0], None), ("block", False))
        gp, _ = self.e._policies(st)
        self.assertEqual(gp["rules"][0][1], "block")


class MonthlyReportTest(unittest.TestCase):
    def test_once_per_month_and_text(self):
        """Вход: первый проход после обновления, затем новый месяц. Ожидание: сначала только запомнить месяц (за неполный
        месяц итогов нет); в новом месяце — одна сводка с итогом сервера и выходами, повторный проход ничего не шлёт;
        по умолчанию «Итоги месяца» выключены."""
        from app import notify
        e = panel.engine
        self.assertFalse(notify.defaults()["events"]["monthly"])
        sent = []
        n = mock.Mock(report=lambda kind, build: sent.append((kind, build("ru"))) or True)
        old_n, old_r = e.notifier, e.traffic.reported
        self.addCleanup(setattr, e, "notifier", old_n)
        self.addCleanup(setattr, e.traffic, "reported", old_r)
        e.notifier, e.traffic.reported = n, None
        st = panel.store.snapshot()
        with mock.patch("app.engine.tunnels.month_key", return_value="2026-11"):
            e._monthly_report(st)
        self.assertEqual((sent, e.traffic.reported), ([], "2026-10"))
        e.traffic.server.setdefault("months", {})["2026-11"] = [3 * 1024 ** 3, 30 * 1024 ** 3]
        with mock.patch("app.engine.tunnels.month_key", return_value="2026-12"):
            e._monthly_report(st)
            e._monthly_report(st)
        self.assertEqual(len(sent), 1)
        kind, text = sent[0]
        self.assertEqual(kind, "monthly")
        self.assertIn("📊 Итоги за ноябрь 2026", text)
        self.assertIn("Всего: ↓ 30 ГБ ↑ 3 ГБ", text)
        self.assertEqual(e.traffic.reported, "2026-11")


if __name__ == "__main__":
    unittest.main()
