"""1.21.0, исправления по второй проверке (2026-11-16): утечки мимо выходов (этап 1), безопасность (этап 2),
правила по доменам, QUIC, DNS и списки (этап 3), бот Telegram (этап 4), интерфейс и тексты (этап 5), установщик, выпуск и возврат на 1.20.0 (этап 6), скорость (этап 7), тесты и код (этап 8).

python3 -m unittest discover tests
"""
import asyncio
import collections
import http.client
import io
import json
import os
import queue
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from app import (awgconf, awgserver, checks, config, cps, dnsproxy, domains, engine, lists, movehost, nftgen,  # noqa: E402
                 notify, panel, quic, sniproxy, store, system, tgbot, totp, traffic, users, web)
from app import api  # noqa: E402,F401  — импорт app.api регистрирует все адреса
from app.api import auth, backup  # noqa: E402
from app.engine.common import UpRT  # noqa: E402
from app.web import HTTPError  # noqa: E402

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
        # своё соединение: в postrouting — там интерфейс уже после смены метки в c_output (type route)
        out = t.split("chain c_guard_post {")[1].split("}")[0]
        self.assertIn("type filter hook postrouting priority filter", out)
        self.assertIn(f'meta mark & 0xffffff00 == {config.MARK_BASE:#x} oifname != "lo" oifname != "awgr*" drop', out)
        self.assertIn(f"meta mark & 0xffffff00 == {config.SNIFF_OUT_BASE:#x} drop", out)

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


# ============================================================ этап 2: безопасность
KEY_A, KEY_B = "vi/nAVhRyygoxanOEgqMkzuiAN+IXPqD2iUIsPD7Ic0=", "5CGlM5pfPLczA6z3kWb4rcWyIt7+A45iSoqJaRv+Hlk="
SRV = f"[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.8.1.1/24\nListenPort = 51820\n"
PEER = f"\n[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.8.1.2/32\n"


class BackupServerConfTest(unittest.TestCase):
    """Н6. Конфиг сервера из резервной копии: то, что awg-quick прочтёт как команду, — отказ."""

    def clean(self, conf):
        return backup.clean_server_files({"conf": "awg0.conf", "files": {"awg0.conf": conf}}, "host")

    def test_hidden_hooks_refused(self):
        """Вход: PostUp с NUL внутри (bash его выбрасывает), с невидимым пробелом, раздел [Interface], заново
        открытый строкой клиента, — в том числе у отключённого клиента. Ожидание: отказ, поле server.conf."""
        for conf in (SRV + "Post\x00Up = id\n" + PEER, SRV + "Post\u200bUp = id\n" + PEER,
                     SRV + PEER + "[Interface] = x\nPreUp = id\n",
                     SRV + f"\n#awgr:disabled\n# [Peer]\n# PublicKey = {KEY_B}\n# [Interface] = x\n"):
            with self.assertRaises(HTTPError) as cm:
                self.clean(conf)
            self.assertEqual(cm.exception.detail.p, {"field": "server.conf"}, repr(conf))

    def test_ordinary_config_kept(self):
        """Вход: эмодзи в комментарии, у клиента PersistentKeepalive и незнакомое поле. Ожидание: копия
        принимается, незнакомое поле клиента убрано, команды — только NAT панели."""
        sc, _ = self.clean(SRV + "# Мама 👩\u200d👧\n" + PEER + "PersistentKeepalive = 25\nFoo = bar\n")
        self.assertEqual(sc.peers[0].extra, [("PersistentKeepalive", "25")])
        self.assertIn("MASQUERADE", sc.get("PostUp"))

    def test_bash_sees_no_foreign_hook(self):
        """Принятый конфиг, прочитанный так же, как awg-quick (bash), не содержит чужих команд."""
        if not shutil.which("bash"):
            self.skipTest("нужен bash")
        sc, _ = self.clean(SRV + "PostUp = evil\n" + PEER + "Endpoint = 198.51.100.1:51820\n")
        script = r'''shopt -s extglob nocasematch; s=0
while read -r line || [[ -n $line ]]; do st="${line%%\#*}"; k="${st%%=*}"; k="${k##*([[:space:]])}"
k="${k%%*([[:space:]])}"; v="${st#*=}"; v="${v##*([[:space:]])}"
[[ $k == "["* ]] && s=0; [[ $k == "[Interface]" ]] && s=1
[[ $s -eq 1 && $k == @(PreUp|PostUp|PreDown|PostDown) ]] && echo "$v"; done'''
        out = subprocess.run(["bash", "-c", script], input=sc.render(), capture_output=True, text=True).stdout
        self.assertNotIn("evil", out)
        self.assertIn("MASQUERADE", out)

    def test_foreign_ok_alone(self):
        sc = awgserver.parse(SRV + PEER)
        self.assertTrue(awgserver.foreign_ok(SRV + PEER, sc))


class CookieTest(unittest.TestCase):
    def test_foreign_bad_cookie_keeps_session(self):
        """Н9. Вход: рядом с сессией панели — чужая cookie с пробелом и запятой (другой сайт на том же адресе).
        Ожидание: сессия на месте (SimpleCookie бросал разбор и терял её)."""
        c = web.parse_cookies('other=a b, c; awgr_session=1.2.3; x="q v"; awgr_session=late')
        self.assertEqual(c["awgr_session"], "1.2.3")
        self.assertEqual(c["x"], "q v")
        self.assertEqual(web.parse_cookies(""), {})
        self.assertEqual(web.parse_cookies("junk; =v; k="), {"k": ""})


class ServerTest(unittest.TestCase):
    """Настоящий HTTP-сервер панели на 127.0.0.1."""

    def setUp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        for p in (mock.patch.object(auth, "PW_FILE", os.path.join(d, "pw.json")),
                  mock.patch.object(totp, "PATH", os.path.join(d, "totp.json")),
                  mock.patch.object(auth, "time", types.SimpleNamespace(time=time.time, sleep=lambda s: None)),
                  mock.patch.object(auth.notifier, "event")):
            p.start()
            self.addCleanup(p.stop)
        auth._pw_cache = (None, None)
        totp._cache = (None, None)
        auth._fails.clear()
        self.addCleanup(auth._fails.clear)
        self.srv = panel.app.serve("127.0.0.1", 0)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def call(self, method, path, body=b"", conn=None, headers=None):
        c = conn or http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=10)
        if conn is None:
            self.addCleanup(c.close)
        h = {"Content-Type": "application/json", **(headers or {})}
        c.request(method, auth.BASE + path, body=body, headers=h)
        r = c.getresponse()
        return r.status, r.read(), c

    def test_trust_only_after_sign_in(self):
        """Н9. Вход: неверный пароль, потом верный. Ожидание: «запасные места» адрес получает только после
        верного (раньше — сразу, ещё до проверки пароля)."""
        st, _, _ = self.call("POST", "/api/login", b'{"password": "wrong"}')
        self.assertEqual(st, 403)
        self.assertEqual(self.srv._trusted, {})
        st, _, _ = self.call("POST", "/api/login", json.dumps({"password": os.environ["PANEL_PASSWORD"]}).encode())
        self.assertEqual(st, 200)
        self.assertIn("127.0.0.1", self.srv._trusted)

    def test_login_body_capped(self):
        """Н8. Вход: тело запроса входа больше 64 КБ. Ожидание: 413, тело не читается в память."""
        st, _, _ = self.call("POST", "/api/login", b"{" + b" " * (auth.LOGIN_BODY + 10) + b"}")
        self.assertEqual(st, 413)

    def test_unread_body_skipped_in_chunks(self):
        """Н8. Вход: 1 МБ на адрес, где нужен вход. Ожидание: 401, тело прочитано кусками не больше 64 КБ, а
        соединение годится для следующего запроса."""
        sizes = []
        real = web._skip_body

        def spy(h, n):
            orig = h.rfile.read
            h.rfile.read = lambda k: (sizes.append(k), orig(k))[1]
            try:
                real(h, n)
            finally:
                h.rfile.read = orig
        with mock.patch.object(web, "_skip_body", spy):
            st, _, c = self.call("POST", "/api/users", b"{" + b" " * (1 << 20) + b"}")
            self.assertEqual(st, 401)
            st, _, _ = self.call("GET", "/api/state", conn=c)
        self.assertEqual(st, 401)
        self.assertTrue(sizes and max(sizes) <= 65536, sizes[:3])


class SurrogateTest(unittest.TestCase):
    def test_lone_surrogate_is_bad_request(self):
        """Н9. Вход: «\\ud800» в JSON (одиночная половинка пары UTF-16). Ожидание: 400, а не 500 при записи."""
        h = mock.Mock(command="POST", client_address=("127.0.0.1", 1))
        h.rfile.read.return_value = b'{"name":"\\ud800"}'
        h.headers = {"Content-Length": str(len(h.rfile.read.return_value))}
        r = web.Request(h, "/api/x", {})
        with self.assertRaises(HTTPError) as cm:
            r.json()
        self.assertEqual(cm.exception.code, 400)
        h.rfile.read.return_value = b'{"name":"\\ud83d\\ude00"}'           # пара — обычный символ
        h.headers = {"Content-Length": str(len(h.rfile.read.return_value))}
        self.assertEqual(web.Request(h, "/api/x", {}).json(), {"name": "😀"})


class SecretFilesFsyncTest(unittest.TestCase):
    def test_password_and_totp_reach_disk(self):
        """Н9. Свой пароль и 2FA сбрасываются на диск до замены файла и вместе с папкой."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with mock.patch.object(auth, "PW_FILE", os.path.join(d, "pw.json")), \
                mock.patch.object(totp, "PATH", os.path.join(d, "totp.json")), \
                mock.patch("os.fsync", wraps=os.fsync) as fs:
            auth.set_password("a-new-password-1")
            self.assertGreaterEqual(fs.call_count, 2)            # файл и папка
            fs.reset_mock()
            totp.save({"secret": "JBSWY3DPEHPK3PXP", "since": 1, "last_step": 0})
            self.assertGreaterEqual(fs.call_count, 2)
        auth._pw_cache = (None, None)
        totp._cache = (None, None)


# ============================================================ этап 3: правила по доменам, QUIC, DNS и списки
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_v112 import client_hello  # noqa: E402
from test_v121 import chromium  # noqa: E402


class LongNameTest(unittest.TestCase):
    def test_long_names_never_match_and_are_quick(self):
        """Н11. Вход: имя из 32 000 меток «a.» (так клиент VPN останавливал обработчик доменов и DNS на секунды).
        Ожидание: не совпадает и проверяется мгновенно."""
        name = "a." * 32000 + "listed.test"
        t = time.monotonic()
        self.assertFalse(sniproxy.match(name, {"listed.test"}))
        self.assertFalse(dnsproxy.match(name + ".", {"listed.test"}))
        self.assertIsNone(domains.matches(name, {"listed.test"}))
        self.assertLess(time.monotonic() - t, 0.1)
        self.assertTrue(sniproxy.match("www.listed.test", {"listed.test"}))

    def test_long_sni_and_dns_name_refused(self):
        ch = client_hello("a" * 60 + "." + "b" * 60 + ".test")
        self.assertTrue(sniproxy.tls_sni(ch))
        long = b"\x01a" * 200 + b"\x00\x00\x01\x00\x01"
        with self.assertRaises(ValueError):
            dnsproxy.read_name(struct.pack("!6H", 1, 0x100, 1, 0, 0, 0) + long, 12)


class PartialHelloTest(unittest.TestCase):
    def peek(self, data, close=True):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        b.setblocking(False)
        if data:
            a.sendall(data)
        if close:
            a.shutdown(socket.SHUT_WR)
        with mock.patch.object(sniproxy, "PEEK_TIMEOUT", 0.3):
            return asyncio.run(sniproxy.peek_name(b, 443))

    def test_partial_hello_is_false(self):
        """Н12. Вход: половина ClientHello, дальше тишина или обрыв. Ожидание: False — соединение закроется,
        как QUIC без имени (раньше — по правилам по адресам, мимо выхода сайта из списка)."""
        ch = client_hello("www.listed.test")
        self.assertEqual(self.peek(ch[:60])[1], False)
        self.assertEqual(self.peek(ch[:60], close=False)[1], False)
        self.assertEqual(self.peek(ch)[1], "www.listed.test")
        self.assertIsNone(self.peek(b"", close=False)[1])          # клиент молчит: сервер говорит первым
        self.assertIsNone(self.peek(b"SSH-2.0-x\r\n")[1])            # не TLS и не HTTP

    def test_partial_hello_closed(self):
        s = sniproxy.Sniffer.__new__(sniproxy.Sniffer)
        s.stats = {"conns": 0, "active": 0, "matched": 0, "errors": 0, "no_name": 0, "by_list": {}}
        s.net = __import__("ipaddress").ip_network("127.0.0.0/8")
        s.cfg = {"policies": {"p_global": {"mark": 0, "rules": []}}}
        s.lists = {}
        sock = mock.Mock()
        sock.getpeername.return_value = ("127.0.0.5", 5)
        sock.getsockname.return_value = ("127.0.0.1", 4433)
        sock.getsockopt.return_value = b"\x02\x00\x01\xbb" + socket.inet_aton("192.0.2.1") + bytes(8)

        async def peek(sk, port):
            return b"\x16\x03\x01\x02\x00", False
        with mock.patch.object(sniproxy, "peek_name", peek), mock.patch.object(s, "open_upstream") as up:
            asyncio.run(s.client(sock))
        up.assert_not_called()
        self.assertEqual(s.stats["partial"], 1)


class QuicFixedBitTest(unittest.TestCase):
    def test_initial_without_fixed_bit(self):
        """Н13. Initial со сброшенным битом «фиксированный» (RFC 9287) — тоже Initial, а не «не QUIC»."""
        d = chromium()[0]
        self.assertEqual(quic.kind(d), "initial")
        self.assertEqual(quic.kind(bytes([d[0] & ~0x40]) + d[1:]), "initial")
        self.assertEqual(quic.kind(b"\x01\x00\x00\x00" + bytes(40)), "other")      # WireGuard
        self.assertEqual(quic.kind(b"\x16\xfe\xfd" + bytes(40)), "other")          # DTLS
        self.assertEqual(quic.kind(b"\x40" + bytes(40)), "quic")                   # короткий заголовок


class HttpHostDotTest(unittest.TestCase):
    def test_trailing_dot(self):
        """Н14. «Host: site.test.» в HTTP — то же, что site.test (в HTTPS так и было)."""
        self.assertEqual(sniproxy.http_host(b"GET / HTTP/1.1\r\nHost: Site.Test.:80\r\n\r\n"), "site.test")
        self.assertEqual(sniproxy.http_host(b"GET / HTTP/1.1\r\nHost: site.test.\r\n\r\n"), "site.test")


class ListFetchTest(unittest.TestCase):
    def resp(self, data, headers):
        r = mock.MagicMock()
        r.status = 200
        body = io.BytesIO(data)
        r.read, r.read1 = body.read, body.read1
        r.headers = headers
        r.__enter__ = lambda s: r
        r.__exit__ = lambda s, *a: False
        return r

    def test_cut_short_refused(self):
        """Н16. Вход: Content-Length 1000, пришло 110 байт. Ожидание: ошибка, а не обрезанный список."""
        with mock.patch("urllib.request.urlopen", return_value=self.resp(b"9.9.9.0/24\n" * 10, {"Content-Length": "1000"})):
            with self.assertRaisesRegex(RuntimeError, "cut short"):
                lists._fetch_direct("https://x.example/l")
        with mock.patch("urllib.request.urlopen", return_value=self.resp(b"9.9.9.0/24\n", {"Content-Length": "11"})):
            self.assertEqual(lists._fetch_direct("https://x.example/l"), ("9.9.9.0/24\n", True))

    def test_overall_deadline(self):
        """Н22. Вход: сервер шлёт по байту. Ожидание: скачивание обрывается по общему сроку, а не держит все
        списки до перезапуска панели."""
        r = self.resp(b"", {})
        r.read1 = lambda n: (time.sleep(0.02), b"x")[1]
        with mock.patch.object(lists, "FETCH_DEADLINE", 0.1), mock.patch("urllib.request.urlopen", return_value=r):
            with self.assertRaisesRegex(RuntimeError, "too slow"):
                lists._fetch_direct("https://x.example/l")

    def test_domain_list_not_fetched_every_round(self):
        """Н17. Вход: список доменов по ссылке, скачан минуту назад, файл на месте. Ожидание: круг обновления
        (раз в 5 минут) его не скачивает — раньше скачивал каждый раз (искал файл списка сетей)."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        s = store.Store(os.path.join(d, "state.json"))
        s.mutate(lambda st: st["lists"].append({"id": "dl1", "name": "d", "kind": "domains", "source": "https://x.example/d",
                                                  "updated": time.time() - 60, "checked": time.time() - 60}))
        e = engine.Engine(s)
        with mock.patch.object(domains, "LISTS_DIR", d):
            with open(domains.path_for("dl1"), "w") as f:
                f.write("a.test\n")
            with mock.patch.object(lists, "refresh") as rf:
                e.refresh_lists(ids=["dl1"])
            rf.assert_not_called()
            os.unlink(domains.path_for("dl1"))
            with mock.patch.object(lists, "refresh", return_value={"error": None, "updated": time.time()}) as rf:
                e.refresh_lists(ids=["dl1"])
            rf.assert_called_once()                                 # файла нет — скачать


class DnsCacheTest(unittest.TestCase):
    def proxy(self):
        p = dnsproxy.Proxy.__new__(dnsproxy.Proxy)
        p.cache, p.cache_bytes, p.inflight = {}, 0, 0
        p.stats = {"queries": 0, "cached": 0, "errors": 0, "refused": 0}
        return p

    @staticmethod
    def q(name: bytes, qid=1):
        wire = b"".join(bytes([len(x)]) + x for x in name.split(b".")) + b"\x00"
        return struct.pack("!6H", qid, 0x0100, 1, 0, 0, 0) + wire + b"\x00\x01\x00\x01"

    @staticmethod
    def answer(query: bytes, size=0):
        """Ответ «есть адрес» на вопрос query (TTL 300), с хвостом size байт в записи TXT-подобного вида."""
        rr = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x01\x02\x03\x04"
        return query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:] + rr + bytes(size)

    def test_dotted_label_refused(self):
        """Н19. Метка «victim.site» + «test» — не то же имя, что victim.site.test: вопрос отклоняется, и ответ
        «нет такого имени» на него не попадёт в кэш для других клиентов."""
        raw = struct.pack("!6H", 1, 0x0100, 1, 0, 0, 0) + b"\x0bvictim.site\x04test\x00\x00\x01\x00\x01"
        self.assertIsNone(dnsproxy.parse_query(raw))
        self.assertEqual(dnsproxy.parse_query(self.q(b"victim.site.test"))["name"], "victim.site.test.")

    def test_cache_bounded_by_bytes_and_question_echoed(self):
        """Н19. Кэш — не больше CACHE_BYTES; из кэша вопрос — как задал этот клиент (регистр букв)."""
        p = self.proxy()
        sent = []

        async def forward(query, q, mark, tcp):
            sent.append(q["name"])
            return self.answer(query, 4000)
        p.forward = forward
        with mock.patch.object(dnsproxy, "CACHE_BYTES", 20000):
            for i in range(20):
                q = self.q(b"n%d.test" % i)
                asyncio.run(p._resolve(q, dnsproxy.parse_query(q), {"mark": 0}))
        self.assertLessEqual(p.cache_bytes, 20000)
        self.assertEqual(p.cache_bytes, sum(len(v[2]) for v in p.cache.values()))
        a = self.q(b"CaSe.test", 1)
        b = self.q(b"cAsE.test", 2)
        asyncio.run(p._resolve(a, dnsproxy.parse_query(a), {"mark": 0}))
        r = asyncio.run(p._resolve(b, dnsproxy.parse_query(b), {"mark": 0}))
        self.assertEqual(sent.count("case.test."), 1)               # второй — из кэша
        self.assertEqual(r[:2], b"\x00\x02")
        self.assertIn(b"\x04cAsE\x04test", r)


class SlowListTextTest(unittest.TestCase):
    def test_spaces_do_not_freeze(self):
        """Н20. Строка из 40 000 пробелов в списке доменов разбиралась 9 секунд (и стояла вся панель)."""
        t = time.monotonic()
        self.assertEqual(domains.parse("a.test" + " " * 40000 + "x\nb.test  # c\n"), ["b.test"])
        self.assertLess(time.monotonic() - t, 0.5)


class AsciiDigitsTest(unittest.TestCase):
    def test_persian_digits_refused(self):
        """Н21. Персидские цифры в I1–I5, PersistentKeepalive и номере чата не принимаются: приложения и
        Telegram их не понимают."""
        fa = "۱۰"
        with self.assertRaises(cps.CPSError):
            cps.size(f"<r {fa}>")
        self.assertIsNotNone(cps.kernel_problem({"I1": f"<r {fa}>"}))
        self.assertEqual(cps.size("<r 10>"), 10)
        with self.assertRaises(users.UserError):
            users.check_keepalive(fa)
        self.assertIsNone(checks.TG_CHAT_RE.match(fa))
        self.assertTrue(checks.TG_CHAT_RE.match("-100123"))


# ============================================================ этап 4: бот Telegram
TG_TOKEN = "123456789:" + "A" * 35


def tg_cfg(**kw):
    return {**notify.defaults(), "enabled": True, "token": TG_TOKEN, "chat_id": "42", "control": True, **kw}


class FlappingTest(unittest.TestCase):
    def test_last_message_is_the_real_state(self):
        """Н23. Вход: выход лёг, поднялся, лёг, поднялся, лёг — за 4 минуты. Ожидание: последнее сообщение в
        чате — «лёг» (раньше третье «лёг» глушилось, и в чате оставалось «снова работает»). Повтор того же
        состояния в пределах 5 минут по-прежнему не уходит."""
        n = notify.Notifier.__new__(notify.Notifier)
        n.store = mock.Mock(snapshot=lambda: {"settings": {"telegram": tg_cfg()}})
        n.host_fn, n.buttons_fn, n._target_lost = (lambda st: "h"), None, False
        n.q, n.pending, n._sent, n.last_error = queue.Queue(), collections.deque(), {}, None
        now = [1_000_000.0]
        with mock.patch.object(notify.time, "time", lambda: now[0]):
            for t, key in ((0, "ev.upstream_failed"), (60, "ev.upstream_ok"), (120, "ev.upstream_failed"),
                           (180, "ev.upstream_ok"), (240, "ev.upstream_failed"), (250, "ev.upstream_failed")):
                now[0] = 1_000_000.0 + t
                n.engine_event(notify.Msg(key, name="NL", uid="u1"))
        sent = [n.q.get_nowait()[2] for _ in range(n.q.qsize())]
        self.assertEqual(len(sent), 5)
        self.assertEqual(sent[-1], notify.render("en", "exit_down", "h", name="NL"))


class BotFixesTest(unittest.TestCase):
    def setUp(self):
        tgbot.STATE = os.path.join(tempfile.mkdtemp(), "tgbot.json")

    def test_name_with_bracket_in_caption(self):
        """Н25. Вход: клиент «Мама <3». Ожидание: подпись к файлу экранирована (иначе Telegram не примет
        разметку и файл не придёт, а «<a href=…>» в имени стал бы ссылкой)."""
        ops = mock.Mock()
        ops.client_config.return_value = {"name": "Мама <3", "conf": "[Interface]\\n", "filename": "m.conf"}
        b = tgbot.Bot(mock.Mock(), ops)
        with mock.patch.object(notify, "send_photo"), mock.patch.object(notify, "send_document") as sd:
            b.send_config(tg_cfg(), "pk")
        self.assertEqual(sd.call_args.args[4], "Мама &lt;3")

    def test_control_off_while_waiting(self):
        """Н26. Вход: пока бот ждал команды (до 25 секунд), управление выключили. Ожидание: пришедшие команды
        не выполняются, но отмечены прочитанными."""
        b = tgbot.Bot(mock.Mock(), mock.Mock())
        ups = [{"update_id": 7, "message": {"chat": {"id": 42, "type": "private"}, "date": int(time.time()),
                                             "text": "/status"}}]
        with mock.patch.object(notify, "_call", side_effect=lambda tok, m, p=None, **kw: ups if m == "getUpdates" else {}), \
                mock.patch.object(b, "handle") as h:
            b.poll_once(tg_cfg(), timeout=0, fresh=lambda: tg_cfg(control=False))
            h.assert_not_called()
            self.assertEqual(b._st["offset"], 8)
            b.poll_once(tg_cfg(), timeout=0, fresh=lambda: tg_cfg())
            h.assert_called_once()

    def test_cut_answer_is_a_network_error(self):
        """Н27. Вход: ответ Telegram оборвался (IncompleteRead). Ожидание: обычная сетевая ошибка, а не
        исключение, которое останавливало поток бота до перезапуска панели."""
        with mock.patch.object(notify, "_post_direct", side_effect=http.client.IncompleteRead(b"{", 90)):
            with self.assertRaises(notify.NotifyError) as cm:
                notify._call(TG_TOKEN, "deleteMyCommands", {})
        self.assertTrue(cm.exception.net)

    def test_bot_thread_survives(self):
        b = tgbot.Bot(mock.Mock(snapshot=lambda: {"settings": {"telegram": tg_cfg(control=False)}}), mock.Mock())
        b._st["cmds"] = "x"
        with mock.patch.object(notify, "_post_direct", side_effect=RuntimeError("odd")):
            t = threading.Thread(target=b._loop, daemon=True)
            t.start()
            time.sleep(0.3)
            self.assertTrue(t.is_alive())
            b.stop_ev.set()
            b.wake.set()


# ============================================================ этап 5: интерфейс и тексты
import panel_js  # noqa: E402

I18N = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app", "static", "i18n.js")


def i18n_text():
    with open(I18N, encoding="utf-8") as f:
        return f.read()


class InterfaceTest(unittest.TestCase):
    """Проверено и в Chromium (4 языка, 375 и 1280 px); здесь — чтобы правки не потерялись."""

    def setUp(self):
        self.js = panel_js.source()

    def test_toasts_inside_open_window(self):
        """Н31. Сообщения — внутри открытого окна (оно в верхнем слое), после закрытия — снова на странице."""
        self.assertIn('document.querySelector("dialog[open]") || document.body', self.js)
        self.assertIn('document.body.append($("#toasts"))', self.js)

    def test_dns_filter_shows_save_bar(self):
        """Н32. Галочка «только для адресов из ответов этого DNS» показывает «Сохранить»."""
        self.assertIn('["#s-pdns", "#s-domf"].forEach', self.js)

    def test_lower_buttons_keep_edits(self):
        """Н33. «Сохранить» скорости и «Перезапустить сервер» не выбрасывают несохранённое выше."""
        self.assertEqual(self.js.count("saveFirst()"), 2)
        self.assertEqual(i18n_text().count('"srv.save_first":'), 4)

    def test_first_request_retried(self):
        """Н34. Первый запрос после входа не прошёл — страница пробует снова, а не остаётся пустой."""
        self.assertIn("setTimeout(() => boot(true), 3000)", self.js)

    def test_host_port_proxy(self):
        """Н35. «хост:порт» без логина — SOCKS5, как его понимает форма выхода."""
        self.assertTrue(awgconf.is_socks("198.51.100.9:1080"))
        self.assertEqual(awgconf.parse_upstream("proxy.example.com:1080").kind, "socks5")
        self.assertFalse(awgconf.is_socks("vpn://AAAA"))

    def test_small_things(self):
        """Н37: двойной Enter, выделение мышью за край окна, сообщение «нет связи» вместо «Failed to fetch»,
        курсор в поиске, стрелка справа налево, разделитель даты и времени."""
        self.assertIn('if ($("#n-save").disabled) return;', self.js)
        self.assertIn('e.target.id === "modal" && downOnBackdrop', self.js)
        self.assertIn('new Error(t("status.offline"))', self.js)
        self.assertIn("setSelectionRange(...keepCaret)", self.js)
        self.assertIn('LANGS[LANG].dir === "rtl" ? "←" : "→"', self.js)
        self.assertNotIn('+ ", " +', self.js)
        self.assertEqual(i18n_text().count('"btn.retry":'), 4)


class TextsTest(unittest.TestCase):
    def test_wording(self):
        """Тексты из раздела об удобстве: одно название общих правил, понятная галочка strict, честная подсказка
        о том, где она действует до запуска панели, AWG 3.1 в подсказке выхода."""
        import re
        s = i18n_text()
        self.assertIn('"rt.strict": "Если правила по доменам не работают', s)
        self.assertNotIn("Глобальная политика", s)
        self.assertNotIn("Global policy", s)
        self.assertIn('"err.fallback_self": "Выход не может быть резервом самому себе"', s)
        self.assertIsNone(re.search(r"(до|up to) AWG 3(?!\.1)", s))
        self.assertIn("не в контейнере приложения AmneziaVPN", s)

    def test_zh_and_fa_consistency(self):
        """zh: кнопка «Проверить» называется так же, как в README, кавычки одного вида. fa: одно слово для
        порта, правила, шифрования и кэша; свой знак процента."""
        import re
        s = i18n_text()
        zh = "\n".join(ln for ln in s.split("\n") if re.search(r"[一-鿿]", ln))
        fa = "\n".join(ln for ln in s.split("\n") if re.search(r"[؀-ۿ]", ln))
        self.assertIn('"btn.check": "检查"', zh)
        self.assertNotIn("“", zh)
        for w in ("پورت", "قاعده", "رمزنگاری", "حافظهٔ نهان", "{pct}%"):
            self.assertNotIn(w, fa, w)


# ============================================================ этап 6: установщик, выпуск, возврат на 1.20.0
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def install_sh():
    with open(os.path.join(ROOT, "install.sh"), encoding="utf-8") as f:
        return f.read()


def sh_funcs(*names):
    """Функции install.sh по именам — для проверки по отдельности."""
    src = install_sh()
    out = []
    for n in names:
        a = src.index(f"\n{n}() {{") + 1
        out.append(src[a:src.index("\n}\n", a) + 3])
    return "\n".join(out)


class InstallerTest(unittest.TestCase):
    def bash(self, script, env=None):
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env={**os.environ, **(env or {})})
        return p.stdout

    def test_ports_with_leading_zeros(self):
        """Н55. «0080», «053» не проходят мимо проверок «не 80/443», «не 53», «занят»."""
        src = install_sh()
        defs = "\n".join(ln for ln in src.split("\n") if ln.startswith(("UNSAFE_PORTS=", "unsafe_port()", "port_busy()")))
        script = defs + "\n" + sh_funcs("panel_port_problem", "awg_port_problem") + """
ss() { :; }
for p in 0080 0443 053 080 0 8080; do echo "$p:$(panel_port_problem $p '')|$(awg_port_problem $p)"; done"""
        out = dict(ln.split(":", 1) for ln in self.bash(script).strip().split("\n"))
        for p in ("0080", "0443", "053", "080", "0"):
            self.assertIn("1 to 65535", out[p], p)
        self.assertEqual(out["8080"], "|")

    def test_kept_config_keeps_its_port(self):
        """Н51. Контейнер своего сервера создаётся заново, а конфиг в $SRV_DATA остался: порт — из конфига, иначе
        Docker открыл бы порт, на котором никто не слушает."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        os.makedirs(os.path.join(d, "data"))
        with open(os.path.join(d, "data", "awg0.conf"), "w") as f:
            f.write("[Interface]\nPrivateKey = x\nAddress = 10.8.1.0/24\nListenPort = 4782\n")
        out = self.bash(f'SRV_DATA="{d}/data"\n' + sh_funcs("saved_port") + "\nsaved_port; SRV_DATA=/nonexistent; echo \"[$(saved_port)]\"")
        self.assertEqual(out.split(), ["4782", "[]"])
        self.assertIn('[ "$how" = container ] && keep="$(saved_port)"', install_sh())

    def test_uninstall_says_what_is_left(self):
        """Н56. После удаления — список того, что панель оставила: запрет модуля, модуль, PPA, правило ufw."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        block = os.path.join(d, "block.conf")
        open(block, "w").close()
        script = sh_funcs("leftovers") + f"""
MODBLOCK="{block}"; MODLOAD=/etc/modules-load.d/amneziawg.conf
envget() {{ echo 4894; }}
dpkg() {{ return 1; }}
ufw() {{ [ "$1" = status ] && printf 'Status: active\\n4894/tcp ALLOW Anywhere\\n'; }}
leftovers"""
        out = self.bash(script)
        self.assertIn(f"rm -f {block}", out)
        self.assertIn("ufw delete allow 4894/tcp", out)
        self.assertRegex(install_sh(), r"\n  leftovers  [^\n]*\n  if \[ \"\$purge\" = 1 \]")   # до удаления папки


class ReleaseWorkflowTest(unittest.TestCase):
    def test_manual_run_guarded(self):
        """Н54. Ручной запуск выпуска: черновик — только из main, «check» — только для выпущенной версии."""
        with open(os.path.join(ROOT, ".github", "workflows", "release.yml"), encoding="utf-8") as f:
            y = f.read()
        self.assertIn('if [ "$CHECK" = true ] && [ "$state" != published ]; then', y)
        self.assertIn('if [ "$CHECK" != true ] && [ "$GITHUB_REF" != refs/heads/main ]; then', y)
        self.assertFalse("cache-from:" in y or "cache-to:" in y)       # Н10: без общего кэша


class EmptyTextListTest(unittest.TestCase):
    def test_rebuilt_at_start(self):
        """Н42. Список, набранный руками, с текстом, а собранный файл пуст (после «Обновить сейчас» в 1.20.0) —
        собирается заново при запуске. Со ссылками и с собранным файлом — нет."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        s = store.Store(os.path.join(d, "state.json"))
        s.mutate(lambda st: st["lists"].extend([
            {"id": "lm1", "name": "a", "kind": "manual", "source": "203.0.113.0/24", "updated": 1},
            {"id": "lm2", "name": "b", "kind": "manual", "source": "198.51.100.0/24", "updated": 1},
            {"id": "ld1", "name": "c", "kind": "domains", "source": "a.test", "updated": 1},
            {"id": "ld2", "name": "d", "kind": "domains", "source": "b.test\nhttps://x.example/l", "updated": 1}]))
        e = engine.Engine(s)
        with mock.patch.object(lists, "LISTS_DIR", d), mock.patch.object(domains, "LISTS_DIR", d):
            open(lists.path_for("lm1"), "w").close()                 # пустой — как после 1.20.0
            with open(lists.path_for("lm2"), "w") as f:
                f.write("198.51.100.0/24\n")
            with mock.patch.object(e, "refresh_lists") as rf:
                e._rebuild_empty_texts()
        rf.assert_called_once_with(False, ["lm1", "ld1"])


# ============================================================ этап 7: скорость
class SpeedTest(unittest.TestCase):
    def test_traffic_file_not_rewritten_when_idle(self):
        """Н50. Счётчики клиентов не изменились — файл учёта не переписывается (раньше — каждую минуту: на
        тысяче клиентов до 2 ГБ записи в сутки)."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        tr = traffic.Traffic(os.path.join(d, "traffic.json"))
        cl = [{"public_key": "k1", "enabled": True, "live": {"rx": 10, "tx": 20}}]
        t0 = time.time()
        tr.update(cl, now=t0)
        tr.save()                                   # запоминает время записи по часам
        with mock.patch.object(tr, "save") as sv:
            tr.update(cl, now=t0 + traffic.SAVE_EVERY + 1)
            sv.assert_not_called()
            self.assertFalse(tr._dirty)
            tr.update([{**cl[0], "live": {"rx": 11, "tx": 20}}], now=t0 + 2 * traffic.SAVE_EVERY + 2)
            sv.assert_called_once()

    def test_state_without_history_and_state_copies(self):
        """Н48. /api/state без помесячной истории трафика клиентов (интерфейс её не читает); адрес панели и
        сертификата — без копии всего состояния."""
        tr = traffic.Traffic(os.path.join(tempfile.mkdtemp(), "t.json"))
        self.assertNotIn("history", tr.view("k1", history=False))
        self.assertIn("history", tr.view("k1"))
        with open(os.path.join(ROOT, "app", "api", "state.py"), encoding="utf-8") as f:
            self.assertIn('engine.traffic.view(c["public_key"], history=False)', f.read())
        with mock.patch.object(panel.store, "snapshot", side_effect=AssertionError("full copy")):
            self.assertTrue(panel.panel_url().endswith("/"))
            panel._tls_alt()

    def test_formatters_reused(self):
        """Н49. Числа и даты — через общие форматировщики Intl, а не новый на каждое значение."""
        js = panel_js.source() + i18n_text()
        for old in ("toLocaleString(LANG", "toLocaleDateString(LANG", "toLocaleTimeString(LANG",
                    "new Intl.RelativeTimeFormat(LANG"):
            self.assertFalse(old in js, old)


# ============================================================ этап 8: тесты и код
class RoutesTest(unittest.TestCase):
    def test_every_route_takes_its_path_parameters(self):
        """Н40. Каждый адрес API вызывает функцию, которая принимает ровно параметры своего пути. В v1.21.0-audit
        пометка PUT /api/upstreams/{uid} стояла на соседней функции (_exit_rates(body)), и любая правка выхода
        давала ошибку 500, а тесты и E2E были зелёными."""
        import inspect
        seen = set()
        for method, rx, fn in panel.app.routes:
            params = {p for p in inspect.signature(fn).parameters if p != "req"}
            self.assertEqual(params, set(rx.groupindex), f"{method} {rx.pattern} → {fn.__name__}")
            self.assertNotIn((method, rx.pattern), seen)
            seen.add((method, rx.pattern))
        self.assertGreater(len(seen), 50)


class DeadCodeTest(unittest.TestCase):
    def test_removed(self):
        """Неиспользуемые функции и константа убраны (их звали только тесты)."""
        self.assertFalse(hasattr(awgconf, "parse_server_conf"))
        self.assertFalse(hasattr(awgconf, "setconf_resolved"))
        self.assertFalse(hasattr(cps, "WARN_PACKET"))
        self.assertFalse(hasattr(engine.Engine, "_resolved"))
        self.assertFalse(hasattr(tgbot.Bot, "_move"))

    def test_no_old_file_names_in_comments(self):
        """Комментарии называют файлы, которые есть: main.py с 1.21.0 — только запуск, app.js разделён."""
        import re
        for root, _, files in os.walk(os.path.join(ROOT, "app")):
            for n in files:
                if n.endswith((".py", ".js")) and n != "main.py":
                    with open(os.path.join(root, n), encoding="utf-8") as f:
                        txt = f.read()
                    self.assertIsNone(re.search(r"\b(main\.py|app\.js)\b", txt), n)



# ------------------------------------------------------------------ этап 9: документы и имя правила
from app.store import Store  # noqa: E402


class RuleNameKeptTest(unittest.TestCase):
    """Н45: имя правила, совпадающее с именем выхода, стиралось при каждом запуске панели. Теперь
    подписи прежних выпусков убираются один раз; своё такое имя потом остаётся."""

    def state(self, upgraded=None):
        st = {"upstreams": [{"id": "u1", "name": "mobile"}],
              "routing": {"rules": [{"lists": ["l1"], "outbound": "up:u1", "comment": "mobile"}]}, "clients": {}}
        if upgraded is not None:
            st["upgraded"] = upgraded
        return st

    def test_store_start(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.json")
            with open(path, "w") as f:
                json.dump(self.state(), f)                         # state.json 1.20.0: отметки нет
            s = Store(path)
            self.assertEqual(s.state["routing"]["rules"][0]["comment"], "")
            self.assertEqual(s.state["upgraded"], ["rule_names"])
            s.state["routing"]["rules"][0]["comment"] = "mobile"   # своё название, как у выхода
            s._write()
            s = Store(path)                                        # следующий запуск
            self.assertEqual(s.state["routing"]["rules"][0]["comment"], "mobile")

    def test_new_install(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(Store(os.path.join(d, "state.json")).state["upgraded"], ["rule_names"])

    def test_backup(self):
        old = self.state()
        st = json.loads(json.dumps(old))
        self.assertTrue(Store.drop_auto_comments_once(st, old))       # копия 1.20.0 — подпись убрана
        self.assertEqual(st["routing"]["rules"][0]["comment"], "")
        new = self.state(["rule_names", "<script>", 5])
        st = json.loads(json.dumps(new))
        Store.drop_auto_comments_once(st, new)                        # копия 1.21.0 — имя своё
        self.assertEqual(st["routing"]["rules"][0]["comment"], "mobile")
        self.assertEqual(st["upgraded"], ["rule_names"])              # из копии — только известные отметки
        self.assertIn("drop_auto_comments_once(st, new)", read_src("app", "api", "backup.py"))


import test_v120  # noqa: E402


class PpaRetryTest(unittest.TestCase):
    """Launchpad иногда обрывает ответ (IncompleteRead в add-apt-repository): установщик пробует трижды,
    а не сразу оставляет сервер на amneziawg-go."""

    def stub(self, name, body):
        path = os.path.join(self.k.bin, name)
        with open(path, "w") as f:
            f.write("#!/bin/bash\n" + body + "\n")
        os.chmod(path, 0o755)

    def setUp(self):
        self.k = test_v120.KernelInstallTest("test_already_new_enough")     # его настоящий кусок install.sh
        self.k.setUp()
        self.addCleanup(shutil.rmtree, self.k.tmp, ignore_errors=True)
        self.stub("sleep", 'echo "sleep $*" >> "$LOG"')
        n = os.path.join(self.k.tmp, "tries")
        self.stub("add-apt-repository", f'echo "add-apt-repository $*" >> "$LOG"; echo x >> {n}; '
                                        f'[ "$(wc -l < {n})" -ge "$OK_ON" ]')
        self.run_sh = self.k.run_sh

    def test_third_try(self):
        rc, out, calls = self.run_sh(OK_ON="3")
        self.assertEqual(rc, 0, out)
        self.assertEqual(calls.count("add-apt-repository -y ppa:amnezia/ppa"), 3)
        self.assertIn("sleep 10", calls)
        self.assertIn("OK Kernel module loaded", out)

    def test_gives_up(self):
        rc, out, calls = self.run_sh(OK_ON="9")
        self.assertEqual(rc, 1)
        self.assertEqual(calls.count("add-apt-repository -y ppa:amnezia/ppa"), 3)
        self.assertIn("Could not add ppa:amnezia/ppa", out)

    def test_first_try_no_wait(self):
        rc, out, calls = self.run_sh(OK_ON="1")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("sleep", calls)



# ------------------------------------------------------------------ Н1: выход только что запущен — блок, а не резерв
from app.engine import tunnels as tunnels_mod  # noqa: E402


class StartingExitTest(unittest.TestCase):
    """Н1 (решение владельца 2026-11-17): после запуска или обновления панели первый проход видел только что
    поднятый выход без рукопожатия и пускал его клиентов по резерву — с «Напрямую» (по умолчанию) это 9–12 с мимо
    выхода. Теперь такие клиенты в блоке, а отдельный поток будит проход, как только выход ответил."""

    def eng(self, state, healthy=False, enabled=True, started=None):
        e = engine.Engine.__new__(engine.Engine)
        r = UpRT(1, "h", "k")
        if started is not None:
            r.started = started
        e.rt = {"u1": r}
        e.health = {"u1": {"state": state, "healthy": healthy, "since": r.started}}
        e.over_quota = lambda u: False
        st = {"upstreams": [{"id": "u1", "num": 1, "name": "x", "enabled": enabled, "fallback": "direct"}]}
        return e, st, r

    def test_resolve(self):
        for state, healthy, enabled, want in (("connecting", False, True, "block"),
                                               ("up", True, True, 1),
                                               ("stale", False, True, "direct"),       # не ответил за 30 с
                                               ("down", False, True, "direct"),        # не запустился
                                               ("connecting", False, False, "direct")):  # выключен
            e, st, _ = self.eng(state, healthy, enabled)
            self.assertEqual(e.resolve("up:u1", st), want, (state, enabled))

    def test_new_tunnel_is_connecting(self):
        e, st, r = self.eng("down")
        e._fake, e.event = None, lambda *a, **kw: None
        e.parsed = lambda u: mock.Mock(kind="awg", rekey_after=120)
        t = mock.Mock()
        t.ns.return_value = mock.Mock(returncode=0, stdout="")          # рукопожатия ещё нет
        with mock.patch.object(engine.config, "DRY_RUN", False):
            e._update_health(t, st)
        self.assertEqual(e.health["u1"]["state"], "connecting")
        self.assertEqual(e.resolve("up:u1", st), "block")
        r.started -= tunnels_mod.CONNECTING_SECS                         # 30 с без ответа — резерв
        with mock.patch.object(engine.config, "DRY_RUN", False):
            e._update_health(t, st)
        self.assertEqual(e.health["u1"]["state"], "stale")
        self.assertEqual(e.resolve("up:u1", st), "direct")

    def test_watch_wakes_pass(self):
        e, st, r = self.eng("connecting")
        t = mock.Mock()
        t.ns.return_value = mock.Mock(stdout="PUBKEY\t0\n")
        self.assertFalse(e._connecting_due(t, time.time()))              # ещё не ответил — ждём
        t.ns.return_value = mock.Mock(stdout="PUBKEY\t1794842579\n")
        self.assertTrue(e._connecting_due(t, time.time()))               # ответил — проход сразу
        self.assertEqual(t.ns.call_args.args[0], ["awg", "show", "awgr1", "latest-handshakes"])
        t.ns.reset_mock()
        t.ns.return_value = mock.Mock(stdout="PUBKEY\t0\n")
        self.assertTrue(e._connecting_due(t, r.started + tunnels_mod.CONNECTING_SECS))   # срок вышел
        self.assertFalse(e._connecting_due(None, time.time()))

    def test_watch_skips(self):
        t = mock.Mock()
        t.ns.return_value = mock.Mock(stdout="PUBKEY\t1794842579\n")
        for state, extra in (("up", {}), ("connecting", {"kind": "socks5"}), ("connecting", {"since": 1.0})):
            e, st, r = self.eng(state)
            e.health["u1"].update(extra)
            self.assertFalse(e._connecting_due(t, time.time()), (state, extra))
        t.ns.assert_not_called()                                        # смотреть нечего — без процессов

    def test_thread_started(self):
        src = read_src("app", "engine", "__init__.py")
        self.assertIn('target=self._watch_connecting, name="exit-connecting"', src)
        self.assertLess(tunnels_mod.HANDSHAKE_POLL, 1)



# ------------------------------------------------------------------ служебный адрес облака (решение владельца 2026-11-17)
class CloudMetadataTest(unittest.TestCase):
    """Клиенты VPN доходили до 169.254.169.254 — служебного адреса облака (данные сервера, у AWS — ключи доступа к
    облаку): link-local — «местная сеть» (local4) и шла с самого сервера при любом выходе. Теперь вся сеть
    link-local клиентам закрыта, в обычных правилах и в правилах «до панели». Сам путь проверяет netns_e2e.py."""

    def rules(self, **kw):
        return nftgen.generate("awg0", {}, [{"num": 1, "snat": "10.9.0.2", "mtu": 1280}],
                               {"rules": [], "default": kw.get("default", 1)}, {})

    def test_forward_rejects(self):
        for default in (1, "direct", "block"):
            fwd = self.rules(default=default).split("chain c_forward {")[1].split("}")[0]
            line = 'iifname "awg0" ip daddr 169.254.0.0/16 reject with icmp type admin-prohibited'
            self.assertIn(line, fwd, default)
            self.assertLess(fwd.index(line), fwd.index("meta mark"))         # раньше любых других решений

    @unittest.skipUnless(shutil.which("nft") and os.geteuid() == 0, "nft -c — только от root")
    def test_nft_accepts(self):
        with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
            f.write(self.rules())
        self.addCleanup(os.unlink, f.name)
        p = subprocess.run(["nft", "-c", "-f", f.name], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_network_test_checks_it(self):
        src = read_src("tests", "netns_e2e.py")
        self.assertIn('"metadata": "169.254.169.254"', src)
        self.assertIn('"metadata", "FAIL"', src)



# ------------------------------------------------------------------ удаление: и настройки панели (решение владельца 2026-11-17)
import test_movehost  # noqa: E402


class UninstallPurgeTest(unittest.TestCase):
    """awg-router uninstall спрашивает и о настройках панели (/opt/awg-router): прежде папка оставалась всегда, и новая
    установка молча брала из неё старые настройки (например, доступ только через SSH-туннель). Пока в папке ключи
    оставленного сервера (свой контейнер), вопроса нет."""

    def setUp(self):
        self.h = test_movehost.InstallerMoveTest("test_uninstall_needs_yes")       # его заглушки docker и systemctl
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.panel = tempfile.mkdtemp()                                           # папка панели — отдельно от заглушек
        self.addCleanup(shutil.rmtree, self.panel, ignore_errors=True)
        for f in ("docker-compose.yml", ".env", "data/state.json"):
            os.makedirs(os.path.dirname(os.path.join(self.panel, f)), exist_ok=True)
            with open(os.path.join(self.panel, f), "w") as fh:
                fh.write("PANEL_ACCESS=ssh\n" if f == ".env" else "x")

    def run_un(self, answers, ours=False, kind="amnezia"):
        if kind:
            self.h.container("amnezia-awg2", ours=False)
            if ours:                                    # контейнер сервера смонтирован из папки этой панели
                with open(os.path.join(self.h.state, "mounts-amnezia-awg2"), "w") as f:
                    f.write(f"{self.panel}/awg-server/data\n")
        body = (f'DIR="{self.panel}"; ENV_FILE="$DIR/.env"; SRV_DATA="$DIR/awg-server/data"\n'
                'MODBLOCK=/nonexistent; MODLOAD=/nonexistent; dpkg() { return 1; }; ufw() { return 1; }\n'
                + self.h.uninstall_block())
        return self.h.run_sh(body, answers=answers)

    def test_remove_settings(self):
        out, log = self.run_un("yes,2")                 # сервер — контейнер приложения AmneziaVPN: о нём не спрашивают
        self.assertIn("Panel settings in", out)
        self.assertIn("Panel settings removed", out)
        self.assertFalse(os.path.exists(self.panel))
        self.assertIn("belongs to the AmneziaVPN app", out)

    def test_keep_settings_by_default(self):
        out, log = self.run_un("yes")                   # Enter — «оставить»
        self.assertTrue(os.path.exists(os.path.join(self.panel, ".env")))
        self.assertIn("a new install picks them up", out)

    def test_own_server_kept_no_question(self):
        out, log = self.run_un("yes,1", ours=True)      # свой сервер остаётся — его ключи в этой папке
        self.assertNotIn("Panel settings in", out)
        self.assertTrue(os.path.exists(os.path.join(self.panel, ".env")))
        self.assertIn("do not delete", out)

    def test_own_server_removed_then_settings(self):
        out, log = self.run_un("yes,2,2", ours=True)
        self.assertIn("docker rm -f amnezia-awg2", log)
        self.assertFalse(os.path.exists(self.panel))
        self.assertLess(out.index("what should happen to it"), out.index("Panel settings in"))

    def test_not_a_panel_folder_stays(self):
        os.unlink(os.path.join(self.panel, "docker-compose.yml"))
        self.run_un("yes,2")
        self.assertTrue(os.path.exists(os.path.join(self.panel, ".env")))       # без файла панели — не трогаем


def read_src(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()

if __name__ == "__main__":
    unittest.main()
