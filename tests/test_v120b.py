"""1.20.0, вторая проверка: посредник не соединяется сам с собой; правила ставятся до запуска туннелей; выходы
ждут движок сервера; имена выходов разбираются разом; сбой `awg syncconf` возвращает файлы, а отключение по
сроку и лимиту повторяется; ссылка vpn:// распаковывается с пределом; `1e999` — 400; запасная копия
state.json; /api/state не копирует состояние на каждого клиента; keep-alive и сжатие; `.env` при обновлении.

python3 -m unittest discover tests
"""
import asyncio
import base64
import gzip
import http.client
import io
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zlib
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from app import awgconf, config, engine, limits, main, sniproxy, store, system, web  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


def ok(cmd=(), out=""):
    return subprocess.CompletedProcess(list(cmd), 0, out, "")


class SniDirectTest(unittest.TestCase):
    """Клиент открыл порт посредника напрямую, а не был перенаправлен nftables: исходный адрес такого
    соединения — сам посредник. Раньше он соединялся с этим адресом, то есть сам с собой, и так по кругу,
    пока не кончались дескрипторы: одно соединение клиента останавливало правила по доменам у всех."""

    def sniffer(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = os.path.join(d, "sni.json")
        with open(p, "w") as f:
            json.dump({"listen": "127.0.0.1"}, f)
        return sniproxy.Sniffer(p)

    def test_direct_connection_is_dropped(self):
        """Вход: соединение, у которого SO_ORIGINAL_DST равен его же локальному адресу (как отвечает
        conntrack для соединения без перенаправления).
        Ожидание: посредник никуда не соединяется и закрывает соединение; счётчик `direct` — 1."""
        from test_v1122 import _tcp_pair
        s = self.sniffer()
        browser, conn = _tcp_pair()
        self.addCleanup(browser.close)

        class Direct(socket.socket):
            def getsockopt(self, level, opt, *args):
                if opt == sniproxy.SO_ORIGINAL_DST:
                    ip, port = self.getsockname()[:2]
                    return b"\x02\x00" + struct.pack("!H", port) + socket.inet_aton(ip) + bytes(8)
                return super().getsockopt(level, opt, *args)

        sock = Direct(fileno=conn.detach())
        browser.sendall(b"GET / HTTP/1.1\r\nHost: site.test\r\n\r\n")
        with mock.patch.object(sniproxy, "direct_socket") as ds, mock.patch.object(sniproxy, "socks_connect") as sc:
            asyncio.run(s.client(sock))
        ds.assert_not_called()
        sc.assert_not_called()
        self.assertEqual((s.stats["conns"], s.stats["active"], s.stats["errors"]), (0, 0, 0))
        self.assertEqual(s.stats["direct"], 1)
        browser.settimeout(3)
        try:
            self.assertEqual(browser.recv(1), b"")          # соединение закрыто
        except ConnectionResetError:
            pass                                            # закрыто с непрочитанным запросом — сброс


class HoldRulesTest(unittest.TestCase):
    """Новая цель (контейнер перезапустился): правила ставятся до запуска туннелей. Раньше в новой сети
    контейнера правил не было до конца прохода, и клиенты шли напрямую даже с резервом «Блокировать»."""

    def setUp(self):
        self.e = main.engine
        self.saved = (self.e.target, self.e.applied_hash, dict(self.e.rt), dict(self.e.health), list(self.e.clients))

    def tearDown(self):
        e = self.e
        e.target, e.applied_hash, e.rt, e.health, e.clients = self.saved
        e.wake.clear()
        e._srv_down, e._srv_tries, e._srv_next = None, 0, 0.0

    def test_rules_before_tunnels_on_a_new_target(self):
        """Вход: два прохода reconcile с поддельной целью, первый — на новой цели.
        Ожидание: в первом `_hold_rules` идёт раньше `_sync_upstreams`; во втором (цель та же) его нет."""
        e, order = self.e, []
        t = mock.Mock(kind="container", iface="awg0", exists=True, key="container:x:1:a", pid=1)
        t.ns.return_value = ok()
        names = ("_watch_resources", "_watch_engine", "_account", "_sni_account", "_exit_quotas", "_update_health",
                 "_balance", "_sync_dns", "_sync_rules", "_sync_shaping", "_sysctl", "_stop_all", "_stop_sni",
                 "_stop_dns")
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(e, "event"), \
                mock.patch.object(engine.system, "discover", return_value=t), \
                mock.patch.object(e, "_watch_server", return_value=False), \
                mock.patch.object(e.srv, "list_clients", return_value=[]), \
                mock.patch.object(e.srv, "upgrade_masking"), \
                mock.patch.object(e, "_sync_sni", return_value=None), \
                mock.patch.object(e, "build_ruleset", return_value="table ip awgr {}\n"), \
                mock.patch.object(e, "_hold_rules", side_effect=lambda *a: order.append("hold")), \
                mock.patch.object(e, "_sync_upstreams", side_effect=lambda *a: order.append("tunnels")), \
                mock.patch("builtins.open", mock.mock_open()):
            patches = [mock.patch.object(e, n) for n in names]
            for p in patches:
                p.start()
            try:
                e.target = None
                e.reconcile()
                self.assertEqual(order, ["hold", "tunnels"])
                e.reconcile()
                self.assertEqual(order, ["hold", "tunnels", "tunnels"])
            finally:
                for p in patches:
                    p.stop()

    def test_exit_without_tunnel_is_blocked(self):
        """Вход: выход по умолчанию числится рабочим (так он выглядел до перезапуска контейнера), а его
        туннеля ещё нет.
        Ожидание: в правилах, поставленных до запуска туннелей, политика ведёт в блок, а не напрямую;
        `applied_hash` не меняется — обычное применение в конце прохода заменит эти правила."""
        from test_api import good_state
        e = self.e
        st = main.store.snapshot()
        g = good_state()
        st["upstreams"], st["routing"] = g["upstreams"], {"default": "up:u000001", "rules": []}
        written = []
        t = mock.Mock(kind="container", iface="awg0", key="k", pid=1)

        def nft(cmd, **kw):
            with open(cmd[-1]) as f:
                written.append(f.read())
            return ok(cmd)
        t.ns.side_effect = nft
        e.rt, e.health, e.clients, e.applied_hash = {}, {"u000001": {"healthy": True}}, [], "before"
        with mock.patch.object(config, "DRY_RUN", False):
            e._hold_rules(t, st)
        self.assertEqual(len(written), 1)
        chain = written[0].split("chain p_global {", 1)[1].split("}", 1)[0]
        self.assertIn("goto o_block", chain)
        self.assertNotIn("o_u1", written[0])
        self.assertEqual(e.applied_hash, "before")

    def test_failure_does_not_stop_the_pass(self):
        e = self.e
        t = mock.Mock(kind="container", iface="awg0", key="k", pid=1)
        t.ns.side_effect = system.SysError("nft: syntax error")
        with mock.patch.object(config, "DRY_RUN", False):
            e._hold_rules(t, main.store.snapshot())             # не бросает: ошибку покажет обычное применение

    def test_next_pass_right_after_auto_restart(self):
        """После автоперезапуска сервера следующий проход идёт сразу, а не через RECONCILE_INTERVAL."""
        e = self.e
        t = mock.Mock(kind="host", iface="awg0", exists=True)
        t.is_up = lambda: False
        e._srv_down, e._srv_tries, e._srv_next = None, 0, 0.0
        e.wake.clear()
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(e, "event"):
            self.assertTrue(e._watch_server(t))
        self.assertTrue(e.wake.is_set())


class EnginePendingTest(unittest.TestCase):
    """Модуль ядра 3.x загружен, а интерфейса сервера ещё нет (контейнер только что перезапущен): выходы AWG
    ждут. Раньше они поднимались на amneziawg-go, а следующим проходом пересоздавались на модуле."""

    def setUp(self):
        self.e = main.engine
        self.saved = (self.e.server_engine, self.e._srv_iface, self.e.kernel_fallback, dict(self.e.rt),
                      dict(self.e._up_fail), dict(self.e.health))

    def tearDown(self):
        e = self.e
        e.server_engine, e._srv_iface, e.kernel_fallback, e.rt, e._up_fail, e.health = self.saved

    def test_pending_only_without_interface(self):
        e = self.e
        mod = {"loaded": True, "version": "3.1.20260812", "ok": True}
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(e, "module_info", return_value=mod):
            e.server_engine, e._srv_iface, e.kernel_fallback = None, False, None
            self.assertTrue(e.engine_pending())
            e._srv_iface = True                      # интерфейс есть, тип не распознан — amneziawg-go, не ждём
            self.assertFalse(e.engine_pending())
            e._srv_iface, e.server_engine = False, "kernel"
            self.assertFalse(e.engine_pending())
            e.server_engine, e.kernel_fallback = None, {"error": "x", "at": 0}
            self.assertFalse(e.engine_pending())     # модуль отказал — всё равно amneziawg-go
            e.kernel_fallback = None
            with mock.patch.object(config, "EXIT_ENGINE", "go"):
                self.assertFalse(e.engine_pending())
        old = {"loaded": False, "version": None, "ok": False}
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(e, "module_info", return_value=old):
            e.server_engine, e._srv_iface = None, False
            self.assertFalse(e.engine_pending())     # модуля нет — выходы на amneziawg-go, ждать нечего

    def test_watch_engine_notes_missing_interface(self):
        e = engine.Engine.__new__(engine.Engine)
        e.server_engine, e._srv_engine_at, e.module_warn, e._module_warned = None, ("", 0.0), None, None
        e.kernel_fallback, e._srv_iface = None, True
        t = mock.Mock(key="k", iface="awg0", conf_path="/c")
        t.ns = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "Cannot find device")
        t.read_file = lambda p: ""
        with mock.patch.object(config, "DRY_RUN", False), \
                mock.patch.object(e, "module_info", return_value={"loaded": True, "version": "3.1", "ok": True},
                                  create=True):
            e._watch_engine(t)
            self.assertFalse(e._srv_iface)
            t.ns = lambda cmd, **kw: ok(cmd, "5: awg0: <UP>\n    link/none\n    amneziawg \n")
            e._watch_engine(t)
        self.assertTrue(e._srv_iface)
        self.assertEqual(e.server_engine, "kernel")

    def test_awg_exits_wait_and_socks_do_not(self):
        from test_v115 import conf
        e = self.e
        st = {"upstreams": [{"id": "ua", "name": "A", "num": 1, "config": conf("203.0.113.7:51820")},
                            {"id": "us", "name": "S", "num": 2, "config": "socks5://203.0.113.8:1080"}]}
        t = mock.Mock(key="k", pid=1)
        e.rt, e._up_fail = {}, {}
        for pending, started in ((True, ["us"]), (False, ["ua", "us"])):
            with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(e, "_links", return_value=set()), \
                    mock.patch.object(e, "exit_engine", return_value="go"), \
                    mock.patch.object(e, "engine_pending", return_value=pending), \
                    mock.patch.object(e, "_start_up") as su:
                e._sync_upstreams(t, st)
            self.assertEqual([c.args[1] for c in su.call_args_list], started)


class PrefetchTest(unittest.TestCase):
    """Имена из Endpoint нескольких выходов разбираются разом: по очереди три неразрешимых имени держали бы
    проход — и блокировку движка, а с ней выдачу конфигов и личные страницы — 3 × RESOLVE_TIMEOUT секунд."""

    def setUp(self):
        self.e = main.engine
        self.saved = (dict(self.e.rt), dict(self.e._up_fail), dict(self.e.health))

    def tearDown(self):
        self.e.rt, self.e._up_fail, self.e.health = self.saved
        self.e._pre, self.e._pre_failed = {}, set()

    def state(self, *endpoints):
        from test_v115 import conf
        return {"upstreams": [{"id": f"u{i}", "name": f"E{i}", "num": i + 1, "config": conf(ep)}
                              for i, ep in enumerate(endpoints)]}

    @staticmethod
    def only_addresses(host):
        """Адрес отдаётся как есть; имя здесь разбираться не должно — его уже разобрали разом."""
        import ipaddress
        ipaddress.ip_address(host)
        return host

    def sync(self, st, answers):
        e = self.e
        t = mock.Mock(key="k", pid=1)
        e.rt, e._up_fail = {}, {}
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(e, "_links", return_value=set()), \
                mock.patch.object(e, "exit_engine", return_value="go"), \
                mock.patch.object(e, "engine_pending", return_value=False), mock.patch.object(e, "event"), \
                mock.patch.object(awgconf, "resolve_many", return_value=answers) as rm, \
                mock.patch.object(awgconf, "resolve_host", side_effect=self.only_addresses) as rh, \
                mock.patch.object(e, "_v6_route"), mock.patch.object(e, "_setconf"), \
                mock.patch.object(engine.subprocess, "Popen") as po, \
                mock.patch.object(engine.os.path, "exists", return_value=True), \
                mock.patch.object(engine.os, "makedirs"), mock.patch.object(engine.os, "remove"), \
                mock.patch("builtins.open", mock.mock_open()):
            po.return_value.poll.return_value = None
            t.ns.return_value = ok()
            e._sync_upstreams(t, st)
        return rm, rh

    def test_names_are_resolved_together(self):
        st = self.state("a.example.net:51820", "b.example.net:51820", "203.0.113.7:51820")
        rm, _ = self.sync(st, {"a.example.net": "198.51.100.1"})
        rm.assert_called_once()
        self.assertEqual(sorted(rm.call_args.args[0]), ["a.example.net", "b.example.net"])
        self.assertIn("u0", self.e.rt)                               # разобралось — запущен
        self.assertIn("u2", self.e.rt)                               # адрес — разбирать нечего
        self.assertNotIn("u1", self.e.rt)                            # не разобралось — ошибка без второго ожидания
        self.assertEqual(self.e.health["u1"]["error"].key, "cfg.endpoint_resolve")

    def test_single_name_goes_the_old_way(self):
        e = self.e
        e.rt, e._up_fail = {}, {}
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(awgconf, "resolve_many") as rm:
            e._prefetch_hosts({u["id"]: u for u in self.state("a.example.net:51820")["upstreams"]}, time.time())
        rm.assert_not_called()
        self.assertEqual((e._pre, e._pre_failed), ({}, set()))


class SyncRollbackTest(unittest.TestCase):
    """`awg syncconf` не прошёл: файлы сервера возвращаются к прежним. Раньше конфиг оставался изменённым —
    панель показывала клиента отключённым, а его пир работал до перезапуска сервера; отметка «отключён по
    сроку» при этом уже стояла, и вторая попытка не делалась."""

    def setUp(self):
        self.e = main.engine
        self.e.reconcile()
        self.t = self.e.target
        self.pk = self.e.clients[0]["public_key"]
        self.conf = self.t.read_file(self.t.conf_path)
        self.table = self.t.read_file(self.t.clients_table_path)
        self.limits = main.store.snapshot().get("limits") or {}
        limits._warned.clear()

    def tearDown(self):
        self.t.write_file(self.t.conf_path, self.conf)
        self.t.write_file(self.t.clients_table_path, self.table, 0o644)
        main.store.mutate(lambda st: st.__setitem__("limits", self.limits))
        self.e.reconcile()

    def test_failed_sync_puts_files_back(self):
        with mock.patch.object(self.t, "sync", side_effect=system.SysError("Device or resource busy")), \
                mock.patch.object(self.e, "event") as ev:
            with self.assertRaises(system.SysError):
                self.e.srv.update_client(self.pk, name="Other", enabled=False)
        ev.assert_not_called()                                   # об отключении, которого не было, не сообщаем
        self.assertEqual(self.t.read_file(self.t.conf_path), self.conf)
        self.assertEqual(self.t.read_file(self.t.clients_table_path), self.table)

    def test_expired_client_is_retried(self):
        """Вход: срок клиента истёк, первая попытка отключить его падает на `awg syncconf`.
        Ожидание: отметки `exp_done` нет и клиент включён; на следующем проходе он отключён, отметка и
        событие есть."""
        e, pk = self.e, self.pk
        exp = int(time.time()) - 60
        main.store.mutate(lambda st: st.setdefault("limits", {}).__setitem__(
            pk, {"expires": exp, "quota": None, "period": "month"}))
        events = []
        with mock.patch.object(e, "event", side_effect=lambda lvl, m: events.append(m.key)):
            with mock.patch.object(self.t, "sync", side_effect=system.SysError("Device or resource busy")):
                e.reconcile()
            L = main.store.snapshot()["limits"][pk]
            self.assertIsNone(L.get("exp_done"))
            self.assertNotIn("ev.client_expired", events)
            self.assertEqual(self.t.read_file(self.t.conf_path), self.conf)        # файл возвращён
            e.reconcile()
        L = main.store.snapshot()["limits"][pk]
        self.assertEqual((L.get("exp_done"), L.get("auto_off")), (exp, "exp"))
        self.assertEqual(events.count("ev.client_expired"), 1)
        self.assertFalse(next(c for c in e.clients if c["public_key"] == pk)["enabled"])

    def test_quota_is_retried(self):
        e, pk = self.e, self.pk
        main.store.mutate(lambda st: st.setdefault("limits", {}).__setitem__(
            pk, {"expires": None, "quota": 1, "period": "total"}))
        with mock.patch.object(e.traffic, "used", return_value=10), mock.patch.object(e, "event"):
            with mock.patch.object(self.t, "sync", side_effect=system.SysError("busy")):
                limits.enforce(e)
            self.assertIsNone(main.store.snapshot()["limits"][pk].get("quota_done"))
            limits.enforce(e)
        L = main.store.snapshot()["limits"][pk]
        self.assertEqual((L.get("quota_done"), L.get("auto_off")), ("total", "quota:total"))


class LinkLimitTest(unittest.TestCase):
    """Ссылка vpn:// распаковывается с пределом: zlib сжимает нули в тысячу раз, и ссылка в полмегабайта
    занимала гигабайт памяти."""

    @staticmethod
    def link(doc: bytes) -> str:
        return "vpn://" + base64.urlsafe_b64encode(struct.pack(">I", len(doc)) + zlib.compress(doc, 9)).decode()

    def test_bomb_is_refused(self):
        with self.assertRaises(awgconf.ConfigError) as cm:
            awgconf.extract_conf_text(self.link(b"\0" * (awgconf.LINK_MAX * 4)))
        self.assertEqual(cm.exception.msg.key, "cfg.bad_vpn_link")

    def test_normal_link_still_opens(self):
        from test_v115 import conf
        text = conf("203.0.113.7:51820")
        doc = json.dumps({"containers": [{"awg": {"last_config": json.dumps({"config": text})}}]}).encode()
        self.assertEqual(awgconf.extract_conf_text(self.link(doc)), text)
        self.assertEqual(awgconf.parse_upstream(self.link(doc)).endpoint, "203.0.113.7:51820")

    def test_not_zlib_and_truncated(self):
        self.assertIsNone(awgconf._inflate(b"not a zlib stream"))
        self.assertIsNone(awgconf._inflate(zlib.compress(b"x" * 1000)[:-4]))        # оборван

    def test_deep_json_is_not_a_config(self):
        with self.assertRaises(awgconf.ConfigError):
            awgconf.extract_conf_text("{" + '"a":{' * 5000 + '"b":1' + "}" * 5000 + "}")


class FiniteNumbersTest(unittest.TestCase):
    """`1e999` — правильный JSON, но в Python это бесконечность: int() на ней падал, и запрос получал 500."""

    @staticmethod
    def req(raw):
        r = web.Request.__new__(web.Request)
        r.h, r.headers, r._body = mock.Mock(rfile=io.BytesIO(raw)), {"Content-Length": str(len(raw))}, None
        return r

    def test_out_of_range_number_is_400(self):
        for raw in (b'{"expires": 1e999}', b'{"port": -1e999}', b'{"a": [1, {"b": 1e400}]}'):
            with self.assertRaises(web.HTTPError) as cm:
                self.req(raw).json()
            self.assertEqual(cm.exception.code, 400, raw)

    def test_ordinary_numbers_pass(self):
        self.assertEqual(self.req(b'{"a": 1.5, "b": 2, "c": 1e3, "d": -0.25}').json(),
                         {"a": 1.5, "b": 2, "c": 1000.0, "d": -0.25})


class StateBackupTest(unittest.TestCase):
    """state.json пишется с fsync, прежняя версия остаётся рядом: с оборванным файлом панель раньше не
    запускалась вовсе."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.p = os.path.join(self.d, "state.json")

    def test_previous_version_is_kept(self):
        s = store.Store(self.p)
        s.mutate(lambda st: st["settings"].update(mark=1))
        s.mutate(lambda st: st["settings"].update(mark=2))
        with open(self.p + ".bak") as f:
            self.assertEqual(json.load(f)["settings"]["mark"], 1)
        self.assertEqual(os.stat(self.p + ".bak").st_mode & 0o777, 0o600)

    def test_damaged_file_falls_back(self):
        s = store.Store(self.p)
        s.mutate(lambda st: st["settings"].update(mark=1))
        s.mutate(lambda st: st["settings"].update(mark=2))
        with open(self.p, "w") as f:
            f.write('{"version": 1, "routing": {"default": "dir')          # оборван
        with self.assertLogs("awgr.store", "WARNING"):
            s2 = store.Store(self.p)
        self.assertEqual(s2.state["settings"]["mark"], 1)
        self.assertTrue(os.path.exists(self.p + ".broken"))
        with open(self.p) as f:
            self.assertEqual(json.load(f)["settings"]["mark"], 1)           # файл снова целый

    def test_both_damaged_is_an_error(self):
        for name in ("state.json", "state.json.bak"):
            with open(os.path.join(self.d, name), "w") as f:
                f.write("{oops")
        with self.assertRaises(ValueError):
            store.Store(self.p)              # не запускаемся с пустыми настройками: все клиенты пошли бы напрямую

    def test_deleted_state_is_not_resurrected(self):
        s = store.Store(self.p)
        s.mutate(lambda st: st["settings"].update(mark=1))
        s.mutate(lambda st: st["settings"].update(mark=2))
        os.remove(self.p)                    # настройки сбросили нарочно
        self.assertNotIn("mark", store.Store(self.p).state["settings"])


class StateSpeedTest(unittest.TestCase):
    """/api/state: адрес панели и ссылки клиентов считаются один раз на запрос. Раньше `share_url` для каждого
    клиента со ссылкой заново копировал всё состояние: тысяча клиентов — полторы секунды на каждый опрос."""

    def test_snapshots_do_not_grow_with_clients(self):
        e = main.engine
        e.reconcile()
        pks = [c["public_key"] for c in e.clients]
        self.assertGreater(len(pks), 3)
        saved = main.store.snapshot().get("shares") or {}
        main.store.mutate(lambda st: st.__setitem__("shares", {f"{i:024d}": {"pk": pk, "created": 1.0}
                                                               for i, pk in enumerate(pks)}))
        try:
            real, n = main.store.snapshot, [0]

            def snap():
                n[0] += 1
                return real()
            with mock.patch.object(main.store, "snapshot", side_effect=snap):
                st = main.get_state(None)
            with_links, n[0] = n[0], 0
            main.store.mutate(lambda st: st.__setitem__("shares", {}))
            with mock.patch.object(main.store, "snapshot", side_effect=snap):
                main.get_state(None)
            self.assertEqual(with_links, n[0])                     # ссылки не добавляют ни одного снимка
            main.store.mutate(lambda st: st.__setitem__("shares", {f"{i:024d}": {"pk": pk, "created": 1.0}
                                                                   for i, pk in enumerate(pks)}))
            by_pk = {c["public_key"]: c["share_url"] for c in st["clients"]}
            for i, pk in enumerate(pks):
                self.assertEqual(by_pk[pk], main.share_url(f"{i:024d}"))
        finally:
            main.store.mutate(lambda st: st.__setitem__("shares", saved))

    def test_first_link_wins_and_none_without(self):
        e = main.engine
        e.reconcile()
        pk, other = e.clients[0]["public_key"], e.clients[1]["public_key"]
        saved = main.store.snapshot().get("shares") or {}
        main.store.mutate(lambda st: st.__setitem__("shares", {"A" * 24: {"pk": pk}, "B" * 24: {"pk": pk}}))
        try:
            by_pk = {c["public_key"]: c["share_url"] for c in main.get_state(None)["clients"]}
            self.assertTrue(by_pk[pk].endswith("/s/" + "A" * 24))
            self.assertIsNone(by_pk[other])
        finally:
            main.store.mutate(lambda st: st.__setitem__("shares", saved))


class KeepAliveGzipTest(unittest.TestCase):
    """Соединение остаётся открытым между запросами (раньше каждый опрос /api/state был новым соединением с
    рукопожатием TLS), а большие текстовые ответы сжимаются."""

    @classmethod
    def setUpClass(cls):
        app = web.App()

        @app.get("/big")
        def big(req):
            return {"text": "состояние " * 2000}

        @app.get("/small")
        def small(req):
            return {"ok": True}

        @app.post("/echo")
        def echo(req):
            return req.json()

        cls.srv = app.serve("127.0.0.1", 0)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def conn(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        self.addCleanup(c.close)
        return c

    def test_connection_is_reused(self):
        c = self.conn()
        c.request("GET", "/small")
        r = c.getresponse()
        self.assertEqual((r.version, r.read()), (11, b'{"ok": true}'))
        sock = c.sock
        self.assertIsNotNone(sock)                                  # сервер соединение не закрыл
        c.request("POST", "/echo", body=b'{"a": 1}', headers={"Content-Type": "application/json"})
        self.assertEqual(json.loads(c.getresponse().read()), {"a": 1})
        c.request("GET", "/nope")                                   # ошибка соединение тоже не рвёт
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 404)
        c.request("GET", "/small")
        self.assertEqual(c.getresponse().read(), b'{"ok": true}')
        self.assertIs(c.sock, sock)

    def test_unread_body_does_not_become_the_next_request(self):
        c = self.conn()
        c.request("POST", "/nope", body=b'GET /small HTTP/1.1\r\n\r\n')     # 404 раньше, чем тело прочитано
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 404)
        c.request("GET", "/small")
        self.assertEqual(c.getresponse().read(), b'{"ok": true}')

    def test_big_text_is_compressed(self):
        c = self.conn()
        c.request("GET", "/big", headers={"Accept-Encoding": "gzip, deflate, br"})
        r = c.getresponse()
        body = r.read()
        self.assertEqual(r.getheader("Content-Encoding"), "gzip")
        self.assertIn("Accept-Encoding", r.getheader("Vary"))
        self.assertEqual(int(r.getheader("Content-Length")), len(body))
        plain = gzip.decompress(body)
        self.assertEqual(json.loads(plain)["text"], "состояние " * 2000)
        self.assertLess(len(body) * 10, len(plain))
        c.request("GET", "/big")                                    # без Accept-Encoding — как есть
        r = c.getresponse()
        self.assertIsNone(r.getheader("Content-Encoding"))
        self.assertEqual(r.read(), plain)

    def test_small_answer_is_not_compressed(self):
        c = self.conn()
        c.request("GET", "/small", headers={"Accept-Encoding": "gzip"})
        r = c.getresponse()
        self.assertIsNone(r.getheader("Content-Encoding"))
        self.assertEqual(r.read(), b'{"ok": true}')

    def test_idle_connection_is_closed_sooner(self):
        """Ожидание следующего запроса короче чтения начатого: простаивающее соединение не держит место."""
        with mock.patch.object(web, "KEEP_IDLE", 0.3):
            s = socket.create_connection(("127.0.0.1", self.port), 5)
            self.addCleanup(s.close)
            s.settimeout(5)
            s.sendall(b"GET /small HTTP/1.1\r\nHost: x\r\n\r\n")
            data, t0 = b"", time.monotonic()
            while chunk := s.recv(4096):
                data += chunk
            self.assertLess(time.monotonic() - t0, 3)
        self.assertTrue(data.endswith(b'{"ok": true}'))
        s = socket.create_connection(("127.0.0.1", self.port), 5)       # первый запрос ждут дольше
        self.addCleanup(s.close)
        s.settimeout(1)
        with mock.patch.object(web, "KEEP_IDLE", 0.3), self.assertRaises(TimeoutError):
            s.recv(1)

    def test_crowded_server_closes_connections(self):
        """Занята половина мест с одного адреса — ответ приходит с `Connection: close`, как до keep-alive."""
        held = [socket.create_connection(("127.0.0.1", self.port), 5) for _ in range(web.MAX_PER_IP // 2)]
        try:
            deadline = time.monotonic() + 5
            while not self.srv.crowded("127.0.0.1") and time.monotonic() < deadline:
                time.sleep(0.02)
            c = self.conn()
            c.request("GET", "/small")
            r = c.getresponse()
            self.assertEqual((r.getheader("Connection"), r.read()), ("close", b'{"ok": true}'))
        finally:
            for h in held:
                h.close()
        deadline = time.monotonic() + 5
        while self.srv.crowded("127.0.0.1") and time.monotonic() < deadline:
            time.sleep(0.02)
        c = self.conn()
        c.request("GET", "/small")
        r = c.getresponse()
        r.read()
        self.assertIsNone(r.getheader("Connection"))

    def test_chunked_body_is_refused_and_closed(self):
        """Тело читается только по Content-Length: запрос с Transfer-Encoding получает 411, и соединение
        закрывается — иначе его тело разбиралось бы как следующий запрос."""
        s = socket.create_connection(("127.0.0.1", self.port), 5)
        self.addCleanup(s.close)
        s.sendall(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                  b"Transfer-Encoding: chunked\r\n\r\n8\r\n{\"a\": 1}\r\n0\r\n\r\n")
        s.settimeout(5)
        data = b""
        while chunk := s.recv(4096):
            data += chunk                                           # до закрытия соединения сервером
        self.assertTrue(data.startswith(b"HTTP/1.1 411"), data[:40])
        self.assertEqual(data.count(b"HTTP/1.1 "), 1)


class EnvKeepTest(unittest.TestCase):
    """install.sh пишет `.env` заново при каждой установке и обновлении: всё, что вписано руками
    (EXIT_ENGINE, AWG_CONTAINER, свой TLS_MODE …), раньше пропадало или молча менялось."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.env = os.path.join(self.d, ".env")
        with open(os.path.join(ROOT, "install.sh")) as f:
            sh = f.read()
        a = sh.index('if [ "$ACCESS" = ssh ]; then PANEL_HOST=127.0.0.1')
        self.modes = sh[a:sh.index('ok "Panel port:', a)]
        b = sh.index('HAD_ENV=0')
        self.write = sh[b:sh.index("# ------------------------------------------------------------------ Docker", b)]
        e = sh.index("envget() {")
        self.envget = sh[e:sh.index("\n", e) + 1]

    def run_sh(self, old: str, access: str = "public") -> dict:
        with open(self.env, "w") as f:
            f.write(old)
        os.chmod(self.env, 0o600)
        script = (f'set -uo pipefail\nENV_FILE="{self.env}"\n{self.envget}'
                  f'ACCESS={access}; PANEL_PASSWORD=pw; PANEL_PORT=4821; PANEL_BASE_PATH=/abc; '
                  f'PUBLIC_HOST=198.51.100.5; TLS_DOMAIN=; ACME_EMAIL=; AWG_MODE=container; AWG_INIT_PORT=\n'
                  + self.modes + self.write)
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(self.env) as f:
            lines = [ln for ln in f.read().splitlines() if "=" in ln and not ln.startswith("#")]
        keys = [ln.split("=", 1)[0] for ln in lines]
        self.assertEqual(len(keys), len(set(keys)), keys)                   # ни одно имя не записано дважды
        return dict(ln.split("=", 1) for ln in lines)

    BASE = ("AWGR_VERSION=2\nPANEL_PASSWORD=pw\nPANEL_PORT=4821\nPANEL_HOST=0.0.0.0\nPANEL_BASE_PATH=/abc\n"
            "PANEL_ACCESS=public\nPUBLIC_HOST=198.51.100.5\nTLS_MODE=letsencrypt\nTLS_DOMAIN=\nACME_EMAIL=\n"
            "AWG_MODE=container\nAWG_INIT_PORT=\nUPSTREAM_BACKEND=userspace\nRECONCILE_INTERVAL=10\n")

    def test_hand_written_settings_survive(self):
        env = self.run_sh(self.BASE + "# my notes\nEXIT_ENGINE=kernel\nAWG_CONTAINER=my-awg\nSNI_PROXY_PORT=10444\n"
                                      "ACME_HTTP_PORT=8081\nEXIT_ENGINE=go\nnot a setting\nWITH_EQ=a=b c\n")
        self.assertEqual(env["EXIT_ENGINE"], "go")                          # записано дважды — действует последнее
        self.assertEqual((env["AWG_CONTAINER"], env["SNI_PROXY_PORT"], env["ACME_HTTP_PORT"]),
                         ("my-awg", "10444", "8081"))
        self.assertEqual(env["WITH_EQ"], "a=b c")
        self.assertEqual(env["PANEL_PORT"], "4821")
        self.assertNotIn("UPSTREAM_BACKEND", env)                       # старая строка, ни на что не влияла
        self.assertEqual(os.stat(self.env).st_mode & 0o777, 0o600)

    def test_own_tls_mode_host_and_interval_stay(self):
        env = self.run_sh(self.BASE.replace("TLS_MODE=letsencrypt", "TLS_MODE=selfsigned")
                          .replace("PANEL_HOST=0.0.0.0", "PANEL_HOST=::")
                          .replace("RECONCILE_INTERVAL=10", "RECONCILE_INTERVAL=30"))
        self.assertEqual((env["TLS_MODE"], env["PANEL_HOST"], env["RECONCILE_INTERVAL"]), ("selfsigned", "::", "30"))

    def test_access_change_and_first_version_are_set_anew(self):
        ssh = self.BASE.replace("PANEL_ACCESS=public", "PANEL_ACCESS=ssh").replace("TLS_MODE=letsencrypt", "TLS_MODE=off") \
            .replace("PANEL_HOST=0.0.0.0", "PANEL_HOST=127.0.0.1")
        env = self.run_sh(ssh)                                               # был SSH-туннель, стал общий доступ
        self.assertEqual((env["TLS_MODE"], env["PANEL_HOST"]), ("letsencrypt", "0.0.0.0"))
        env = self.run_sh(self.BASE.replace("TLS_MODE=letsencrypt", "TLS_MODE=selfsigned"), access="ssh")
        self.assertEqual((env["TLS_MODE"], env["PANEL_HOST"]), ("off", "127.0.0.1"))
        v1 = self.BASE.replace("AWGR_VERSION=2\n", "").replace("TLS_MODE=letsencrypt", "TLS_MODE=off") \
            .replace("RECONCILE_INTERVAL=10", "RECONCILE_INTERVAL=abc")
        env = self.run_sh(v1)                                                # .env первой версии — как раньше
        self.assertEqual((env["TLS_MODE"], env["RECONCILE_INTERVAL"]), ("letsencrypt", "10"))

    def test_fresh_install(self):
        os.path.exists(self.env) and os.remove(self.env)
        script = (f'set -uo pipefail\nENV_FILE="{self.env}"\n{self.envget}'
                  'ACCESS=public; PANEL_PASSWORD=pw; PANEL_PORT=4821; PANEL_BASE_PATH=/abc; PUBLIC_HOST=198.51.100.5; '
                  'TLS_DOMAIN=; ACME_EMAIL=; AWG_MODE=host; AWG_INIT_PORT=47823\n' + self.modes + self.write)
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(self.env) as f:
            text = f.read()
        self.assertIn("TLS_MODE=letsencrypt\n", text)
        self.assertIn("RECONCILE_INTERVAL=10\n", text)
        self.assertIn("AWG_INIT_PORT=47823\n", text)


if __name__ == "__main__":
    unittest.main()
