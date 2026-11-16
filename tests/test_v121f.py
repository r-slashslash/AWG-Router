"""1.21.0, исправления по второй проверке (2026-11-16): утечки мимо выходов (этап 1).

python3 -m unittest discover tests
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from app import config, engine, movehost, nftgen, sniproxy, store, system  # noqa: E402
from app.engine.common import UpRT  # noqa: E402

UP = ("[Interface]\nAddress = 10.9.0.2/32\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\n"
      "[Peer]\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\nAllowedIPs = 0.0.0.0/0\n"
      "Endpoint = 198.51.100.1:51820\n")
BASE = config.RULE_PRIO_BASE


class ReconcileOrderTest(unittest.TestCase):
    """Настоящий проход движка на поддельной цели, которая записывает команды в своей сети."""

    def setUp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        s = store.Store(os.path.join(d, "state.json"))
        s.mutate(lambda st: (st["upstreams"].append({"id": "u1", "name": "NL", "num": 1, "config": UP,
                                                      "enabled": True, "fallback": "block"}),
                             st["routing"].update(default="up:u1")))
        self.e = engine.Engine(s)
        self.log, self.table = [], {"present": True}
        self.t = self.target("container:amnezia-awg2:4242:a")

    def target(self, key):
        t = mock.Mock(kind="container", iface="awg0", exists=True, key=key, pid=4242,
                      conf_path="/opt/amnezia/awg/awg0.conf")
        t.ns.side_effect = self.ns
        t.read_file.return_value = "HOLD=awgr-hold"
        t.is_up.return_value = True
        return t

    def ns(self, cmd, **kw):
        ok = lambda out="", rc=0: subprocess.CompletedProcess(cmd, rc, out, "")  # noqa: E731
        if cmd[:2] == ["nft", "-f"]:
            with open(cmd[2]) as f:
                self.log.append(("nft", "chain o_u1 {" in f.read()))
            self.table["present"] = True
        elif cmd[:3] == ["nft", "list", "chain"]:
            return ok(rc=0 if self.table["present"] else 1)
        elif cmd[:3] == ["ip", "-force", "-batch"]:
            self.log.append(("ip", "rule add fwmark 0x2001" in kw.get("input", "")))
        elif cmd[:3] == ["awg", "show", "all"]:
            return ok(f"awgr1\tPRIV\tPUB\t0\toff\nawgr1\tPEER\t(none)\t198.51.100.1:51820\t0.0.0.0/0\t"
                      f"{int(time.time())}\t1\t1\toff\n")
        elif cmd[:4] == ["ip", "-j", "link", "show"]:
            return ok(json.dumps([{"ifname": "awg0"}, {"ifname": "awgr1"}]))
        elif cmd[:4] == ["ip", "-j", "rule", "show"]:
            return ok("[]")
        return ok()

    def start_up(self, t, uid, u, pc, h):
        self.e.rt[uid] = UpRT(u["num"], h, t.key)
        self.log.append(("tunnel", u["num"]))

    def reconcile(self, t, clients=None):
        e = self.e
        lc = mock.Mock(return_value=[], side_effect=clients)
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(system, "discover", return_value=t), \
                mock.patch.object(e.srv, "list_clients", lc), mock.patch.object(e.srv, "upgrade_masking"), \
                mock.patch.object(e, "_start_up", side_effect=self.start_up), \
                mock.patch.object(e, "module_info", return_value={"loaded": False, "version": None, "ok": False}), \
                mock.patch.object(e, "_watch_module"), mock.patch.object(e, "_account"), \
                mock.patch.object(e, "_sni_account"), mock.patch.object(e, "_sync_shaping"), \
                mock.patch.object(e, "_input_rule"):
            e.reconcile()

    def test_pass_sets_ip_rules(self):
        """Вход: проход с одним выходом AWG. Ожидание: ip rule его метки поставлен (без него — напрямую)."""
        self.reconcile(self.t)
        self.assertIn(("ip", True), self.log)

    def test_ip_rule_before_exit_marks(self):
        """Н3. Вход: новая цель, выход ответил в первом же проходе.
        Ожидание: ip rule метки выхода — раньше правил nftables, которые эту метку ставят: помеченный пакет
        без своего ip rule ушёл бы по основной таблице, мимо выхода. На 4caa3ac этот тест падал."""
        self.reconcile(self.t)
        self.assertLess(self.log.index(("ip", True)), self.log.index(("nft", True)), self.log)

    def test_restarted_container_is_a_new_target(self):
        """Вход: контейнер перезапустился (новый PID). Ожидание: правила без выхода — до запуска туннеля."""
        self.reconcile(self.t)
        self.log.clear()
        self.reconcile(self.target("container:amnezia-awg2:5151:b"))
        self.assertEqual(self.log[:2], [("nft", False), ("tunnel", 1)])

    def test_table_gone_is_put_back(self):
        """Вход: кто-то сделал nft flush ruleset. Ожидание: следующий проход ставит правила заново."""
        self.reconcile(self.t)
        self.table["present"] = False
        self.log.clear()
        self.reconcile(self.t)
        self.assertIn(("nft", True), self.log)

    def test_hold_rules_before_traffic(self):
        """Н2. Вход: новая цель. Ожидание: правила «до панели» — сразу после списка клиентов, раньше учёта
        трафика и лимитов (сервер в контейнере AmneziaVPN сам их не ставит, и всё это время клиенты шли
        напрямую). И когда список клиентов не прочитался, правила всё равно ставятся."""
        seen = []
        orig = self.e._hold_rules
        self.e._hold_rules = lambda t, st: (seen.append("hold"), orig(t, st))
        self.e.traffic.update = lambda c: seen.append("traffic")
        self.reconcile(self.t)
        self.assertEqual(seen[:2], ["hold", "traffic"])
        seen.clear()
        self.reconcile(self.target("container:amnezia-awg2:6161:c"), clients=OSError("docker"))
        self.assertEqual(seen, ["hold"])                  # клиентов нет — учёта нет, а правила есть


class EarlyRulesTest(unittest.TestCase):
    """_sync_rules(add_only=True) — сразу после запуска туннелей, до правил nftables."""

    def _eng(self, nums):
        e = engine.Engine.__new__(engine.Engine)
        e.rt = {f"u{n}": UpRT(n, "h", "k") for n in nums}
        return e

    def _t(self, rules):
        t = mock.Mock(key="k1")
        calls = []

        def ns(cmd, check=True, input=None, **kw):
            calls.append((cmd, input))
            if cmd[:3] == ["ip", "-j", "rule"]:
                return mock.Mock(returncode=0, stdout=json.dumps(rules))
            return mock.Mock(returncode=0, stdout="", stderr="")
        t.ns = ns
        return t, calls

    @staticmethod
    def rule(num, table=None, mark=None):
        return {"priority": BASE + num, "table": str(table or config.TABLE_BASE + num),
                "fwmark": hex(mark or nftgen.mark_for(num))}

    def batch(self, calls):
        return [ln for c in calls if "-batch" in c[0] for ln in c[1].splitlines()]

    def test_stopped_exit_rule_kept_until_the_end(self):
        """Вход: выход 3 остановлен (туннеля нет), его ip rule ещё есть; выход 1 запущен, правила нет.
        Ожидание: ранний вызов только добавляет правило выхода 1, а правило выхода 3 не трогает: прежние
        правила nftables ещё ставят метку 3, и без ip rule (там unreachable) она ушла бы напрямую.
        Обычный вызов в конце прохода его убирает."""
        e = self._eng([1])
        t, calls = self._t([self.rule(3)])
        e._sync_rules(t, add_only=True)
        lines = self.batch(calls)
        self.assertIn(f"rule add fwmark {hex(nftgen.mark_for(1))} lookup {config.TABLE_BASE + 1} "
                      f"priority {BASE + 1}", lines)
        self.assertFalse([ln for ln in lines if "del" in ln or "flush" in ln], lines)
        calls.clear()
        e._sync_rules(t)
        self.assertIn(f"rule del priority {BASE + 3}", self.batch(calls))

    def test_wrong_rule_of_running_exit_replaced_early(self):
        """Вход: у запущенного выхода 1 правило ведёт не в ту таблицу. Ожидание: заменяется сразу."""
        e = self._eng([1])
        t, calls = self._t([self.rule(1, table=999)])
        e._sync_rules(t, add_only=True)
        lines = self.batch(calls)
        self.assertLess(lines.index(f"rule del priority {BASE + 1}"),
                        next(i for i, ln in enumerate(lines) if ln.startswith("rule add")))

    def test_early_call_free_when_nothing_changed(self):
        """Вход: туннели те же, что при прошлой сверке. Ожидание: ранний вызов ничего не запускает
        (проход каждые 10 секунд), а после перезапуска туннеля — сверяет и ставит маршрут сразу."""
        e = self._eng([1])
        t, calls = self._t([self.rule(1)])
        e._sync_rules(t)
        calls.clear()
        e._sync_rules(t, add_only=True)
        self.assertEqual(calls, [])
        e.rt["u1"].started += 5
        e._sync_rules(t, add_only=True)
        self.assertIn(f"route replace default dev {e.rt['u1'].iface} table {config.TABLE_BASE + 1}",
                      self.batch(calls))


class GuardTest(unittest.TestCase):
    """Страховочные строки nftables: пакет с меткой выхода — только в туннель (Н3, Н4)."""

    def ruleset(self, sniff=None):
        gp = {"rules": [], "default": 1, "domain": [(["yt"], "direct")] if sniff else []}
        return nftgen.generate("awg0", {}, [{"num": 1, "snat": "10.9.0.2", "mtu": 1376}], gp, {}, sniff)

    def test_forward_and_output_guard(self):
        t = self.ruleset()
        fwd = t.split("chain c_forward {")[1].split("}")[0]
        self.assertIn(f'meta mark & 0xffffff00 == {config.MARK_BASE:#x} oifname != "awgr*" reject', fwd)
        out = t.split("chain c_guard_out {")[1].split("}")[0]
        self.assertIn("type filter hook output priority filter", out)
        self.assertIn(f'meta mark & 0xffffff00 == {config.MARK_BASE:#x} oifname != "lo" oifname != "awgr*" reject', out)
        self.assertIn(f"meta mark & 0xffffff00 == {config.SNIFF_OUT_BASE:#x} reject", out)

    def test_masks_cover_all_marks(self):
        """Метки выходов 1…MAX_UPSTREAMS и политик sniproxy.py попадают под маску, другие метки — нет."""
        m = nftgen.EXIT_MASK
        self.assertTrue(all(nftgen.mark_for(n) & m == config.MARK_BASE for n in range(1, config.MAX_UPSTREAMS + 1)))
        for other in (config.MARK_BLOCK, config.SNIFF_MARK, config.QUIC_PASS_MARK, config.QUIC_DIRECT_MARK):
            self.assertNotIn(other & m, (config.MARK_BASE, config.SNIFF_OUT_BASE), hex(other))

    @unittest.skipUnless(shutil.which("nft") and os.geteuid() == 0, "нужен nft и root")
    def test_nft_accepts(self):
        for sniff in (None, 4433):
            with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
                f.write(self.ruleset(sniff))
            self.addCleanup(os.unlink, f.name)
            p = subprocess.run(["nft", "-c", "-f", f.name], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)


class SniffMarksTest(unittest.TestCase):
    """Н4. Метки sniproxy.py не сдвигаются, когда добавляют клиента с правилами по доменам."""

    @staticmethod
    def pols(*names):
        return {n: {"rules": [], "default": "direct", "domain": [([n], "block")]} for n in names}

    def test_same_policy_same_mark(self):
        slots = {}
        first = nftgen.sniff_marks(self.pols("p_global", "p_2"), slots)
        # новый клиент со своими правилами встал в середину по имени: прежние политики — с прежними метками
        p = self.pols("p_global", "p_2")
        p["p_1"] = {"rules": [], "default": "direct", "domain": [(["new"], "block")]}
        second = nftgen.sniff_marks(p, slots)
        self.assertEqual((second["p_global"], second["p_2"]), (first["p_global"], first["p_2"]))
        self.assertNotIn(second["p_1"], first.values())
        self.assertEqual(nftgen.sniff_marks(p, slots), second)       # второй вызов в том же проходе — то же

    def test_freed_number_waits_one_pass(self):
        """Номер ушедшей политики в этом проходе ещё в прежних правилах nftables: занимается со следующего."""
        slots = {}
        a = nftgen.sniff_marks(self.pols("p_global", "p_1"), slots)
        b = nftgen.sniff_marks(self.pols("p_global", "p_9"), slots)
        self.assertNotEqual(b["p_9"], a["p_1"])
        c = nftgen.sniff_marks(self.pols("p_global", "p_9", "p_7"), slots)
        self.assertEqual(c["p_7"], a["p_1"])

    def test_without_slots_as_before(self):
        self.assertEqual(nftgen.sniff_marks(self.pols("p_global", "p_1")),
                         {"p_global": config.SNIFF_OUT_BASE, "p_1": config.SNIFF_OUT_BASE + 1})


class SniUnknownClientTest(unittest.TestCase):
    def test_unknown_client_blocked(self):
        """Н4. Вход: клиента нет в настройках sniproxy.py (они на миг разошлись с nftables).
        Ожидание: соединение закрыто, а не отпущено с меткой 0 по основной таблице."""
        s = sniproxy.Sniffer.__new__(sniproxy.Sniffer)
        s.lists = {}
        s.cfg = {"client_policy": {"10.8.1.9": "p_1"}, "policies": {"p_1": {"mark": 0xD101, "rules": []}}}
        self.assertEqual(s.decide("10.8.1.5", "site.test"), ({"block": True}, None))
        self.assertEqual(s.decide("10.8.1.9", "site.test"), ({"mark": 0xD101}, None))


class HoldFileTest(unittest.TestCase):
    def test_strict_rewrites_hold_file(self):
        """Н5. Вход: галочку «правила по доменам не работают — блокировать» включили, а применённые правила
        те же (обработчик работает). Ожидание: файл правил «до панели» переписан."""
        e = engine.Engine.__new__(engine.Engine)
        e._hold_key, e._hold_ok, e.applied_hash = None, {}, "h1"
        t = mock.Mock(kind="host", iface="awg0", key="host:1", conf_path="/etc/amnezia/amneziawg/awg0.conf")
        e.build_ruleset = mock.Mock(return_value="table ip awgr\n")
        with mock.patch.object(engine.config, "DRY_RUN", False):
            e._save_hold(t, {"settings": {}, "routing": {}})
            e._save_hold(t, {"settings": {}, "routing": {"strict": True}})
        self.assertEqual(t.write_file.call_count, 2)


class MoveHostHoldTest(unittest.TestCase):
    def test_hold_file_moved_to_host(self):
        """Н5. Вход: перенос сервера из своего контейнера на хост, в папке контейнера есть файл правил «до
        панели». Ожидание: он на хосте рядом с конфигом — служба ставит его до подъёма сервера."""
        root, src = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        self.addCleanup(shutil.rmtree, src)
        key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
        with open(os.path.join(src, "awg0.conf"), "w") as f:
            f.write(f"[Interface]\nPrivateKey = {key}\nAddress = 10.8.1.0/24\nListenPort = 41234\n")
        with open(os.path.join(src, "clientsTable"), "w") as f:
            f.write("[]")
        with open(os.path.join(src, "awgr-hold-awg0.nft"), "w") as f:
            f.write("table ip awgr {}\n")

        class FakeHost(system.HostTarget):
            def host_path(s, p):
                return root + p

            def native(s, cmd, **kw):
                return subprocess.CompletedProcess(cmd, 0, "", "")

            def is_up(s):
                return True
        with mock.patch.object(movehost, "host_target", lambda: FakeHost(movehost.IFACE)), \
                mock.patch.object(system, "install_host_runtime"), mock.patch.object(system, "open_firewall_udp"):
            movehost.install(src)
        with open(f"{root}{config.HOST_AWG_DIR}/awgr-hold-awg0.nft") as f:
            self.assertEqual(f.read(), "table ip awgr {}\n")


if __name__ == "__main__":
    unittest.main()
