"""1.25.0: входящие и исходящие адреса сервера — данные: «Напрямую — адрес» в памяти и на диске, проверки ввода,
резервные копии (адреса — свои у сервера), входящий адрес отдельно от адреса панели.
python3 -m unittest tests.test_v125"""
import json
import os
import sys
import tempfile
import unittest

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import checks, panel, srcaddr  # noqa: E402
from app.api import backup  # noqa: E402
from app.store import DEFAULT_STATE, Store  # noqa: E402
from app.web import HTTPError  # noqa: E402

A, B, C = "198.51.100.7", "198.51.100.8", "192.0.2.99"


class Req:
    def __init__(self, body):
        self.body = body

    def json(self, limit=None):
        return self.body


def state(**settings) -> dict:
    st = json.loads(json.dumps(DEFAULT_STATE))
    st["settings"].update(settings)
    st["lists"] = [{"id": "l1", "kind": "manual", "name": "l1", "source": "203.0.113.0/24"}]
    st["upstreams"] = [{"id": "u1", "name": "Germany", "num": 1, "config": "socks5://198.51.100.9:1080", "enabled": True,
                        "fallback": "block", "quota_action": "notify"}]
    return st


class DiskFormTest(unittest.TestCase):
    """В памяти — "direct@адрес", на диске и в копии — "direct" и адрес рядом («_src»): панель 1.24.0 прочтёт
    такой выход как «Напрямую» (с адреса системы), а не как неизвестный (он стал бы «блоком»)."""

    def test_round_trip_through_state_json(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "state.json")
        s = Store(p)
        s.mutate(lambda st: st["settings"].update(out_hosts=[A]))
        s.mutate(lambda st: st["routing"].update(default="direct@" + A))
        s.mutate(lambda st: st["routing"]["rules"].append(
            {"id": "r1", "lists": ["l1"], "outbound": "direct@system", "enabled": True, "comment": ""}))
        with open(p) as f:
            disk = json.load(f)
        self.assertEqual(disk["routing"]["default"], "direct")
        self.assertEqual(disk["routing"]["default_src"], A)
        self.assertEqual(disk["routing"]["rules"][0]["outbound"], "direct")
        self.assertNotIn("direct@", json.dumps(disk))
        again = Store(p)
        self.assertEqual(again.state["routing"]["default"], "direct@" + A)
        # «Напрямую — адрес системы», когда основной и есть адрес системы, — просто «Напрямую»
        self.assertEqual(again.state["routing"]["rules"][0]["outbound"], "direct")

    def test_backup_has_disk_form(self):
        d = tempfile.mkdtemp()
        s = Store(os.path.join(d, "state.json"))
        s.mutate(lambda st: st["settings"].update(out_hosts=[A]))
        s.mutate(lambda st: st["routing"].update(default="direct@" + A))
        b = s.snapshot(texts=True)
        self.assertEqual((b["routing"]["default"], b["routing"]["default_src"]), ("direct", A))
        self.assertEqual(s.snapshot()["routing"]["default"], "direct@" + A)

    def test_no_addresses_same_object(self):
        st = state()
        self.assertIs(srcaddr.to_disk(st), st)     # без адресов — без копии на каждую запись

    def test_bad_src_on_disk_dropped(self):
        st = state()
        st["routing"].update(default="up:u1", default_src=A)       # адрес у выхода, который не «Напрямую»
        st["upstreams"][0].update(fallback="direct", fallback_src="not-an-ip")
        srcaddr.from_disk(st)
        self.assertEqual(st["routing"]["default"], "up:u1")
        self.assertEqual(st["upstreams"][0]["fallback"], "direct")
        self.assertNotIn("default_src", st["routing"])


class OutboundCheckTest(unittest.TestCase):
    def test_known_addresses(self):
        st = state(out_hosts=[A, B])
        self.assertEqual(checks.outbound(st, "direct@" + A), "direct@" + A)
        self.assertEqual(checks.outbound(st, "direct@system"), "direct")     # основной — адрес системы
        st["settings"]["out_main"] = A
        self.assertEqual(checks.outbound(st, "direct@" + A), "direct")       # основной записывается просто direct
        self.assertEqual(checks.outbound(st, "direct@system"), "direct@system")
        with self.assertRaises(HTTPError) as e:
            checks.outbound(st, "direct@" + C)
        self.assertEqual(e.exception.detail.key, "err.unknown_address")

    def test_backup_takes_any_address_by_form(self):
        st = state()
        with checks.any_address():
            self.assertEqual(checks.outbound(st, "direct@" + C), "direct@" + C)
            with self.assertRaises(HTTPError):
                checks.outbound(st, "direct@vpn.example.com")

    def test_bind(self):
        st = state(out_hosts=[A], out_main=A)
        self.assertEqual(checks.bind(st, A), "")             # основной — пусто: переезжает вместе с ним
        self.assertEqual(checks.bind(st, "system"), "system")
        with self.assertRaises(HTTPError):
            checks.bind(st, C)

    def test_out_hosts_only_ipv4(self):
        self.assertEqual(srcaddr.parse_out_hosts(f"{A}, {B} {A}"), [A, B])
        for bad in ("vpn.example.com", "2001:db8::1", "127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1"):
            with self.subTest(bad=bad), self.assertRaises(srcaddr.AddrError) as e:
                srcaddr.parse_out_hosts(bad)
            self.assertEqual(e.exception.msg.key, "srv.bad_out_host")
        with self.assertRaises(srcaddr.AddrError):
            srcaddr.parse_out_hosts([f"198.51.100.{i}" for i in range(1, srcaddr.OUT_HOSTS_MAX + 2)])


class NormalizeTest(unittest.TestCase):
    def test_gone_address_goes_to_main(self):
        st = state(out_hosts=[A])
        st["routing"]["rules"] = [{"id": "r1", "lists": ["l1"], "outbound": "direct@" + B, "enabled": True,
                                   "comment": "RU"}]
        st["upstreams"][0]["bind"] = B
        st["settings"]["telegram"] = {"via": "direct@" + A}
        moved = []
        self.assertTrue(srcaddr.normalize(st, moved))
        self.assertEqual(st["routing"]["rules"][0]["outbound"], "direct")
        self.assertNotIn("bind", st["upstreams"][0])
        self.assertEqual([m.key for m in moved], ["ref.rule", "ref.exit_bind"])
        self.assertEqual(st["settings"]["telegram"]["via"], "direct@" + A)      # этот адрес у сервера есть

    def test_new_main_becomes_plain_direct(self):
        """Переезд: всё на новом основном — просто «Напрямую», значит переедет и при следующей смене."""
        st = state(out_hosts=[A, B])
        st["routing"]["default"] = "direct@" + B
        st["upstreams"][0]["bind"] = B
        st["settings"]["out_main"] = B
        srcaddr.normalize(st)
        self.assertEqual(st["routing"]["default"], "direct")
        self.assertNotIn("bind", st["upstreams"][0])

    def test_refs(self):
        st = state(out_hosts=[A])
        st["clients"] = {"k" * 43 + "=": {"name": "Anna", "outbound": "direct@" + A}}
        self.assertEqual([m.key for m in srcaddr.refs(st, A)], ["ref.client"])
        # основной (адрес системы): «По умолчанию» на «Напрямую» и выход без своего адреса подключения
        self.assertEqual([m.key for m in srcaddr.refs(st, "system")], ["ref.default", "ref.exit_bind"])


class SplitHostsTest(unittest.TestCase):
    """Входящий адрес — отдельно от адреса панели: у обновившихся — прежний внешний адрес."""

    def test_public_host_becomes_inbound(self):
        st = state(public_host="vpn.example.com")
        self.assertTrue(Store.split_hosts(st))
        self.assertEqual(st["settings"]["client_host"], "vpn.example.com")
        self.assertEqual(st["settings"]["extra_hosts"], ["vpn.example.com"])     # домен остаётся в выборе
        self.assertFalse(Store.split_hosts(st))

    def test_own_client_host_kept(self):
        st = state(public_host="203.0.113.5", client_host="198.51.100.20")
        self.assertFalse(Store.split_hosts(st))
        st2 = state(public_host="203.0.113.5")
        Store.split_hosts(st2)
        self.assertEqual(st2["settings"]["client_host"], "203.0.113.5")
        self.assertNotIn("extra_hosts", st2["settings"])     # IP и так в выборе


class BackupAddressesTest(unittest.TestCase):
    """Адреса — свои у сервера: из копии не берутся; места с чужим адресом — на основной и сообщение."""

    def setUp(self):
        self.st0 = panel.store.snapshot()

    def tearDown(self):
        panel.store.mutate(lambda s: (s.clear(), s.update(self.st0)))

    def test_restore_keeps_own_addresses(self):
        src = state(out_hosts=[A, C], out_main=C, own_src=C)
        src["routing"]["default"] = "direct@" + A
        src["routing"]["rules"] = [{"id": "r1", "lists": ["l1"], "outbound": "direct@" + C, "enabled": True,
                                    "comment": "RU"}]
        src["upstreams"][0].update(bind=A, fallback="direct@system")
        disk = srcaddr.to_disk(src)
        new = backup.clean_backup_state(json.loads(json.dumps(disk)))
        self.assertEqual(new["routing"]["default"], "direct@" + A)       # по записи — как в копии
        self.assertEqual(new["upstreams"][0]["bind"], A)
        self.assertNotIn("out_hosts", new["settings"])                   # адресов копии здесь нет
        panel.store.mutate(lambda s: s["settings"].update(out_hosts=[A]))
        moved = panel.store.mutate(lambda s: backup.restore_state(s, new))
        st = panel.store.snapshot()
        self.assertEqual(st["settings"]["out_hosts"], [A])
        self.assertNotIn("out_main", st["settings"])
        self.assertNotIn("own_src", st["settings"])
        self.assertEqual(st["routing"]["default"], "direct@" + A)         # этот адрес у сервера есть
        self.assertEqual(st["routing"]["rules"][0]["outbound"], "direct")  # C — нет: основной
        self.assertEqual(st["upstreams"][0]["fallback"], "direct")         # адрес системы — он и основной
        self.assertEqual([m.key for m in moved], ["ref.rule"])


class ServerSettingsTest(unittest.TestCase):
    def setUp(self):
        self.st0 = panel.store.snapshot()
        panel.engine.reconcile()

    def tearDown(self):
        panel.store.mutate(lambda s: (s.clear(), s.update(self.st0)))

    def test_out_hosts_saved_and_main_checked(self):
        srv = panel.engine.srv
        srv.update_server({"out_hosts": f"{A}, {B}"})
        self.assertEqual(panel.store.snapshot()["settings"]["out_hosts"], [A, B])
        srv.update_server({"out_main": B})
        self.assertEqual(srcaddr.main(panel.store.snapshot()), B)
        with self.assertRaises(Exception) as e:
            srv.update_server({"out_hosts": A})               # основной убрать нельзя, пока не выбран другой
        self.assertEqual(e.exception.msg.key, "srv.out_main_removed")
        with self.assertRaises(Exception) as e:
            srv.update_server({"out_main": C})
        self.assertEqual(e.exception.msg.key, "srv.bad_out_main")
        with self.assertRaises(Exception) as e:
            srv.update_server({"out_hosts": "vpn.example.com"})
        self.assertEqual(e.exception.msg.key, "srv.bad_out_host")

    def test_confirm_before_moving(self):
        """Браузер 1.25.0 сначала спрашивает: что переедет со старого основного, что стоит на убранном адресе."""
        srv = panel.engine.srv
        srv.update_server({"out_hosts": [A, B]})
        panel.store.mutate(lambda s: s["routing"].update(default="direct@" + A))
        r = srv.update_server({"out_hosts": [B], "confirm": False})
        self.assertEqual([m.key for m in r["confirm"]["removed"]], ["ref.default"])
        self.assertEqual(panel.store.snapshot()["settings"]["out_hosts"], [A, B])     # ещё не сохранено
        srv.update_server({"out_hosts": [B], "confirm": True})
        st = panel.store.snapshot()
        self.assertEqual((st["settings"]["out_hosts"], st["routing"]["default"]), ([B], "direct"))
        r = srv.update_server({"out_main": B, "confirm": False})
        self.assertIn("moved", r["confirm"])
        self.assertEqual(r["confirm"]["to"], B)


if __name__ == "__main__":
    unittest.main()


class FakeHost:
    """Сеть хоста для адресов: какие IPv4 на интерфейсах, что добавлено и убрано, что отвечают проверки."""

    def __init__(self, eng, present=None):
        self.addrs = {"203.0.113.5": {"dev": "eth0", "label": "eth0"}, **(present or {})}
        self.added, self.removed, self.probe = [], [], {}
        self.boot = "boot-1"
        eng._host_v4 = lambda: dict(self.addrs)
        eng._wan = lambda: {"dev": "eth0", "gw": "203.0.113.1", "src": "203.0.113.5"}
        eng._addr_add = self.add
        eng._addr_del = self.delete
        eng._addr_probe = lambda ip, k=None: self.probe.get(ip, {"ok": True, "ip": ip, "cc": "DE"})
        self.paths = []

    def add(self, ip, dev):
        self.added.append(ip)
        self.addrs[ip] = {"dev": dev, "label": dev + ":awgr"}
        return True

    def delete(self, ip, dev):
        self.removed.append(ip)
        self.addrs.pop(ip, None)


class AddressesInSystemTest(unittest.TestCase):
    """Адрес, которого нет в системе, панель добавляет сама и проверяет; не работает — убирает; только свои."""

    def setUp(self):
        from app.engine import Engine
        from app.engine import addrs as addrs_mod
        self.addrs_mod = addrs_mod
        self.dir = tempfile.mkdtemp()
        self._data = config_patch(self.dir)
        self.store = Store(os.path.join(self.dir, "state.json"))
        self.eng = Engine(self.store)
        self.events = []
        self.eng.event = lambda level, msg: self.events.append(msg.key)
        self.host = FakeHost(self.eng)
        self.boot = mock_boot(self.host)
        from app import system
        self.t = system.DemoTarget()

    def tearDown(self):
        self.boot.stop()
        self._data.stop()

    def tick(self, **settings):
        """Круг адресов и проход движка (пути адресов): исходящий адрес «работает» после проверки своим путём."""
        if settings:
            self.store.mutate(lambda s: s["settings"].update(settings))
        for _ in range(2):
            self.eng._addr_tick(self.store.snapshot())
            self.eng._addr_pass(self.t, self.store.snapshot())

    def test_added_checked_and_removed(self):
        self.tick(out_hosts=[A])
        self.assertEqual(self.host.added, [A])
        self.assertTrue(self.eng.addr_ok(A))
        with open(os.path.join(self.dir, "own-addrs")) as f:
            self.assertEqual(f.read(), f"eth0 {A}\n")      # для awg-router uninstall
        self.tick(out_hosts=[])
        self.assertEqual(self.host.removed, [A])

    def test_bad_on_first_check_is_removed(self):
        self.host.probe[C] = {"ok": False, "err": "no_connection", "detail": "timed out"}
        self.tick(out_hosts=[C])
        self.assertEqual(self.eng.addr_state(C), "bad")
        self.assertIn("ev.addr_bad", self.events)
        self.tick()
        self.assertEqual(self.host.removed, [C])            # не работает — сразу убран
        self.tick()
        self.assertEqual(self.host.added, [C])              # и не добавляется снова, пока его не впишут заново
        self.eng.addrs_wake(retry=[C])
        self.host.probe.pop(C)
        self.tick()
        self.assertTrue(self.eng.addr_ok(C))

    def test_bad_retried_after_15_minutes(self):
        """Не заработавший адрес — снова в систему и на проверку через ADDR_BAD_RETRY (владелец 2026-11-26): хостинг
        подключил его позже, чем его вписали в панели. Повтор без успеха — без нового события в журнале."""
        self.host.probe[C] = {"ok": False, "err": "no_connection", "detail": "timed out"}
        self.tick(out_hosts=[C])
        self.tick()
        self.assertEqual(self.eng.addr_state(C), "bad")
        self.assertEqual(self.host.added, [C])
        self.eng.addr_rt()[C]["at"] -= self.addrs_mod.ADDR_BAD_RETRY - 60      # ещё не пора
        self.tick()
        self.assertEqual(self.host.added, [C])
        self.eng.addr_rt()[C]["at"] -= 120                                     # пора: снова добавлен и проверен
        self.tick()
        self.assertEqual(self.host.added, [C, C])
        self.assertEqual(self.eng.addr_state(C), "bad")                        # всё ещё не работает
        self.assertEqual(self.events.count("ev.addr_bad"), 1)
        self.tick()
        self.assertEqual(self.host.removed, [C, C])                             # и снова убран
        self.host.probe.pop(C)                                                  # хостинг подключил адрес
        self.eng.addr_rt()[C]["at"] -= self.addrs_mod.ADDR_BAD_RETRY + 1
        self.tick()
        self.assertTrue(self.eng.addr_ok(C))
        self.assertNotIn("retry", self.eng.addr_rt()[C])

    def test_down_and_up_after_two_failures(self):
        self.tick(out_hosts=[A])
        self.host.probe[A] = {"ok": False, "err": "no_connection"}
        rt = self.eng.addr_rt()[A]
        rt["at"] = 0
        self.tick()
        self.assertTrue(self.eng.addr_ok(A))                 # одна неудача — ещё работает
        rt["at"] = 0
        self.tick()
        self.assertEqual(self.eng.addr_state(A), "failed")
        self.assertIn("ev.addr_down", self.events)
        self.assertIn(A, self.host.addrs)                    # работал: остаётся в системе, проверяется дальше
        self.host.probe.pop(A)
        rt["at"] = 0
        self.tick()
        self.assertTrue(self.eng.addr_ok(A))
        self.assertIn("ev.addr_up", self.events)

    def test_human_address_never_touched(self):
        self.host.addrs[B] = {"dev": "eth0", "label": "eth0"}
        self.tick(out_hosts=[B])
        self.assertEqual(self.host.added, [])
        self.tick(out_hosts=[])
        self.assertEqual(self.host.removed, [])

    def test_reboot_readds_own_only(self):
        self.tick(out_hosts=[A, B])
        self.host.addrs.pop(A)                       # перезагрузка: своих адресов нет
        self.host.addrs[B] = {"dev": "eth0", "label": "eth0"}     # B теперь в настройках сети системы (без метки)
        self.host.boot = "boot-2"
        self.tick()
        self.assertEqual(self.host.added.count(A), 2)
        self.assertIn("ev.addr_readded", self.events)
        self.tick(out_hosts=[])
        self.assertEqual(sorted(self.host.removed), [A])     # B — уже не наш

    def test_network_restart_readds(self):
        self.tick(out_hosts=[A])
        self.host.addrs.pop(A)                       # перезапустили сеть системы — та же загрузка
        self.tick()
        self.assertEqual(self.host.added, [A, A])

    def test_inbound_public_face_not_added(self):
        """Облако с 1:1 NAT (AWS): входящий IP = адрес, который видят сайты, — он уже «на сервере»."""
        self.eng.public_v4 = "54.0.0.10"
        self.tick(extra_hosts=["54.0.0.10", "vpn2.example.com", B])
        self.assertEqual(self.host.added, [B])              # домен — нет; IP, видный снаружи, — тоже нет
        self.assertTrue(self.eng.addr_ok("54.0.0.10"))

    def test_uninstall_removes_own(self):
        self.host.addrs[B] = {"dev": "eth0", "label": "eth0"}
        self.tick(out_hosts=[A, B])
        self.assertEqual(self.eng.remove_own_addrs(), [A])
        self.assertEqual(self.host.removed, [A])

    def test_view(self):
        self.tick(out_hosts=[A], out_main=A)
        v = self.eng.addrs_view(self.store.snapshot())
        self.assertEqual(v["main"], A)
        self.assertEqual(v["system"]["ip"], "203.0.113.5")
        self.assertEqual(v["out"][0]["state"], "ok")
        self.assertTrue(v["out"][0]["ours"])


def config_patch(d):
    from unittest import mock
    from app import config
    p = mock.patch.object(config, "DATA_DIR", d)
    p.start()
    return p


def mock_boot(host):
    from unittest import mock
    from app.engine import addrs
    p = mock.patch.object(addrs, "boot_id", lambda: host.boot)
    p.start()
    return p


class AddrNotifyTest(unittest.TestCase):
    def test_texts(self):
        from app import notify
        for lang in notify.LANGS:
            self.assertIn("{addr}", notify.TEXTS[lang]["addr_down"])
            self.assertIn("{addr}", notify.TEXTS[lang]["addr_up"])
        self.assertIn(A, notify.render("ru", "addr_down", addr=A))
        self.assertEqual(notify.ENGINE_EVENTS["ev.addr_down"], ("exit", "addr_down"))


class RulesetAddrTest(unittest.TestCase):
    """nftgen: «Напрямую — адрес» — своя метка, подмена адреса раньше MASQUERADE сервера, защита после подмены."""
    INFRA = {1: {"ip": A, "dev": "eth0", "gw": "203.0.113.1", "nat": "snat"}}

    def gen(self, gp, cps=None, **kw):
        from app import nftgen
        return nftgen.generate("awg0", {"l1": ["203.0.113.0/24"]}, [{"num": 1, "snat": "10.9.0.2", "mtu": 1280}],
                               gp, cps or {}, kw.pop("sniff", None), **kw)

    def test_chains_and_guard(self):
        from app import nftgen
        a = nftgen.Addr(A, 1)
        txt = self.gen({"rules": [(["l1"], a)], "default": "direct", "domain": []}, addrs=self.INFRA)
        self.assertIn("ip daddr @l_l1 goto o_a1", txt)
        self.assertIn("chain o_a1 {\n\t\tmeta mark set 0x2101 accept", txt)
        self.assertIn("type nat hook postrouting priority srcnat - 1", txt)
        self.assertIn(f'meta mark 0x2101 oifname "eth0" snat to {A}', txt)
        self.assertIn(f"meta mark 0x2101 ip saddr != {A} drop", txt)                   # после подмены — только с него
        self.assertIn('meta mark 0x2101 oifname != "eth0" reject', txt)               # пересылка — только этим путём
        self.assertIn("meta mark 0x2101-0x2110 meta mark != { 0x2101 } drop", txt)     # номер без пути — никуда

    def test_address_without_path_is_block(self):
        from app import config, nftgen
        txt = self.gen({"rules": [], "default": nftgen.Addr(A, 3), "domain": []}, addrs={})
        self.assertIn(f"chain o_a3 {{\n\t\tmeta mark set {config.MARK_BLOCK:#x} accept", txt)
        self.assertNotIn("c_addr_nat", txt)
        self.assertIn("meta mark 0x2101-0x2110 drop", txt)

    def test_hold_rules_block_addresses(self):
        """Правила «до панели» (после перезагрузки ip rule адресов ещё нет): адрес — блок, а не адрес системы."""
        from app import nftgen
        txt = self.gen({"rules": [], "default": nftgen.Addr(A, 1), "domain": []}, addrs=None)
        self.assertNotIn("meta mark set 0x2101", txt)

    def test_container_masquerade(self):
        from app import nftgen
        txt = self.gen({"rules": [], "default": nftgen.Addr(A, 1), "domain": []},
                       addrs={1: {"ip": A, "dev": "eth1", "gw": "172.18.0.1", "nat": "masq"}})
        self.assertIn('meta mark 0x2101 oifname "eth1" masquerade', txt)
        self.assertNotIn("ip saddr != ", txt)

    def test_quic_and_sniproxy_paths(self):
        from app import nftgen
        a = nftgen.Addr(A, 1)
        txt = self.gen({"rules": [(["l1"], a)], "default": "direct", "domain": [(["d1"], "direct@" + A)]},
                       sniff=10443, quic=True, addrs=self.INFRA)
        self.assertIn("chain oq_a1 {\n\t\tmeta mark set 0x2101 accept", txt)
        self.assertIn("0x40002101", txt)          # решение QUIC «этот адрес» берётся из conntrack, пока путь есть

    def test_policy_key_by_slot(self):
        from app import nftgen
        p1, _ = nftgen.layout({"rules": [], "default": nftgen.Addr(A, 1)}, {"10.8.1.2": {"rules": [],
                              "default": nftgen.Addr(A, 1)}}, set())
        self.assertEqual(list(p1), ["p_global"])          # тот же адрес — та же политика

    @unittest.skipUnless(__import__("shutil").which("nft") and os.geteuid() == 0, "nft -c — только от root")
    def test_kernel_accepts(self):
        import subprocess
        from app import nftgen
        a = nftgen.Addr(A, 1)
        txt = self.gen({"rules": [(["l1"], a)], "default": a, "domain": [(["d1"], "direct@" + A)],
                        "slots": [0], "dslots": [1]}, sniff=10443, labels=True, addrs=self.INFRA,
                       limits={0: (125000, 0)})     # QUIC — в net-tests: в песочнице нет nft_queue
        p = subprocess.run(["unshare", "-n", "nft", "-c", "-f", "-"], input=txt, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)


class ResolveAddrTest(unittest.TestCase):
    """Engine.resolve: «Напрямую — адрес» — Addr, только если адрес работает и его путь стоит; иначе блок."""

    def eng(self, **settings):
        from app.engine import Engine
        e = Engine.__new__(Engine)
        e.health, e.rt = {"u1": {"healthy": True}}, {}
        e._addr_rt = {A: {"state": "ok"}, B: {"state": "failed"}}
        e._addr_live = {1: {"ip": A, "dev": "eth0"}, 2: {"ip": B, "dev": "eth0"}}
        e.over_quota = lambda u: False
        st = state(out_hosts=[A, B], **settings)
        return e, st

    def test_direct_paths(self):
        from app import nftgen
        e, st = self.eng()
        self.assertEqual(e.resolve("direct", st), "direct")                 # основной — адрес системы
        self.assertEqual(e.resolve("direct@" + A, st), nftgen.Addr(A, 1))
        self.assertEqual(e.resolve("direct@" + B, st), "block")             # не работает — блок, не адрес системы
        e._addr_live.pop(1)
        self.assertEqual(e.resolve("direct@" + A, st), "block")             # путь не встал — тоже блок
        e2, st2 = self.eng(out_main=A)
        self.assertEqual(e2.resolve("direct", st2), nftgen.Addr(A, 1))        # основной — второй адрес
        self.assertEqual(e2.resolve("direct@system", st2), "direct")

    def test_exit_from_failed_address_is_down(self):
        e, st = self.eng()
        st["upstreams"][0]["bind"] = B
        st["upstreams"][0]["fallback"] = "direct"
        self.assertEqual(e.resolve("up:u1", st), "direct")      # выход с неработающего адреса — его резерв
        st["upstreams"][0]["bind"] = A
        self.assertEqual(e.resolve("up:u1", st), 1)

    def test_exit_mark(self):
        from app import nftgen
        e, st = self.eng()
        e._addr_rec_cache = {"slots": {A: 1, B: 2}, "ours": {}, "ever": []}
        self.assertEqual(e.exit_mark(st, st["upstreams"][0]), 0)
        st["upstreams"][0]["bind"] = B
        self.assertEqual(e.exit_mark(st, st["upstreams"][0]), nftgen.addr_mark(2))


class ExitBindTest(unittest.TestCase):
    def test_fwmark_in_setconf(self):
        from app import awgconf
        conf = "[Interface]\nPrivateKey = x\nFwMark = 51820\n\n[Peer]\nPublicKey = y\n"
        out = awgconf.with_fwmark(conf, 0x2101)
        self.assertEqual(out.count("FwMark"), 1)
        self.assertIn("[Interface]\nFwMark = 0x2101\n", out)
        self.assertNotIn("FwMark", awgconf.with_fwmark(conf, 0))

    def test_hev_mark(self):
        from app import socks
        self.assertIn("  mark: 8449\n", socks.hev_config("awgr1", 1, "198.51.100.9", {"port": 1080}, mark=0x2101))
        self.assertNotIn("mark:", socks.hev_config("awgr1", 1, "198.51.100.9", {"port": 1080}))

    def test_helper_paths(self):
        """Посредник правил по доменам и DNS на сервере ведут «Напрямую — адрес» с меткой адреса; учёт — «Напрямую»."""
        from app import nftgen
        from app.engine import Engine
        e = Engine.__new__(Engine)
        e.resolve = lambda out, st: nftgen.Addr(A, 1)
        self.assertEqual(Engine._sni_target(e, {}, "direct@" + A), {"mark": 0x2101, "acct": "direct"})
        self.assertEqual(Engine._quic_mark(e, {}, "direct@" + A), 0x2101)
        self.assertEqual(Engine._acct_label({}, nftgen.Addr(A, 1)), "direct")
        e.rt, e.parsed = {}, None
        route = Engine._dns_route_fn(e, {"upstreams": []})
        self.assertEqual(route(nftgen.Addr(A, 1)), {"mark": 0x2101, "tcp": False})


class CtFlushTest(unittest.TestCase):
    """ctflush.py: записи conntrack из ctnetlink и какие из них удалять при ручной смене пути."""

    @staticmethod
    def nla(typ, data, nested=False):
        import struct
        ln = 4 + len(data)
        return struct.pack("=HH", ln, typ | (0x8000 if nested else 0)) + data + b"\0" * ((4 - ln % 4) % 4)

    def message(self, src, dst, proto=6, dport=443, mark=0):
        import socket
        import struct
        ip = self.nla(1, self.nla(1, socket.inet_aton(src)) + self.nla(2, socket.inet_aton(dst)), True)
        pr = self.nla(2, self.nla(1, bytes([proto])) + self.nla(2, struct.pack("!H", 50000))
                      + self.nla(3, struct.pack("!H", dport)), True)
        return self.nla(1, ip + pr, True) + self.nla(8, struct.pack("!I", mark)) + self.nla(12, struct.pack("!I", 7))

    def test_entry(self):
        from app import ctflush
        e = ctflush.entry(self.message("10.8.1.2", "8.8.8.8", 17, 443, 0x40002001))
        self.assertEqual((e["src"], e["dst"], e["proto"], e["dport"], e["mark"]), ("10.8.1.2", "8.8.8.8", 17, 443,
                                                                                    0x40002001))
        self.assertTrue(e["tuple"].startswith(b"\x00") or e["tuple"])
        self.assertIn(b"\x07", e["extra"])          # номер записи — в запросе на удаление (не удалить чужую)

    def test_changed(self):
        from app import ctflush
        E = lambda src, dst, **kw: ctflush.entry(self.message(src, dst, **kw))  # noqa: E731
        job = {"clients": {"10.8.1.2": {"old": {"rules": [[["ru"], "direct@system"]], "default": "up:u1"},
                                        "new": {"rules": [[["ru"], "direct@" + A]], "default": "up:u1"}}},
               "lists": {"ru": ["77.88.0.0/18"]}, "skip": ["10.0.0.0/8"], "quic": ["10.8.1.3"]}
        entries = [E("10.8.1.2", "77.88.55.242"), E("10.8.1.2", "8.8.8.8"), E("10.8.1.2", "10.8.1.1"),
                   E("10.8.1.9", "77.88.55.242"),
                   E("10.8.1.3", "1.1.1.1", proto=17, dport=443, mark=0x4000E101),
                   E("10.8.1.3", "1.1.1.1", proto=17, dport=443, mark=0)]
        got = [(e["src"], e["dst"], e["mark"]) for e in ctflush.changed(job, entries)]
        # путь RU сменился — его соединение; «По умолчанию» тот же; сам сервер — нет; чужой клиент — нет;
        # решение QUIC клиента со сменой правил по доменам — да, просто UDP 443 без решения — нет
        self.assertEqual(got, [("10.8.1.2", "77.88.55.242", 0), ("10.8.1.3", "1.1.1.1", 0x4000E101)])

    def test_nets(self):
        from app import ctflush
        import ipaddress
        n = ctflush.Nets(["10.0.0.0/24", "10.0.1.0/24", "bad", "192.0.2.7/32"])
        self.assertIn(int(ipaddress.IPv4Address("10.0.1.200")), n)
        self.assertNotIn(int(ipaddress.IPv4Address("10.0.2.1")), n)
        self.assertEqual(len(n.lo), 2)              # соседние сети слиты


class NoteChangeTest(unittest.TestCase):
    """Engine.note_change: что поменял человек — обрыв; перенос балансировкой и резерв — нет."""

    def setUp(self):
        from app.engine import Engine
        self.e = Engine.__new__(Engine)
        self.e.clients = [{"ip": "10.8.1.2", "public_key": "k" * 43 + "="}]
        self.e.bal, self.e.bal_new = {}, None
        self.e.trigger = lambda: None
        self.st = state(out_hosts=[A])
        self.st["routing"]["rules"] = [{"id": "r1", "lists": ["l1"], "outbound": "direct", "enabled": True,
                                        "comment": ""}]

    def test_outbound_change(self):
        import copy
        new = copy.deepcopy(self.st)
        new["routing"]["rules"][0]["outbound"] = "direct@" + A
        self.assertTrue(self.e.note_change(self.st, new))
        self.assertEqual(self.e._drop_sni["clients"]["10.8.1.2"]["new"]["rules"], [[["l1"], "direct@" + A]])

    def test_comment_only_no_change(self):
        import copy
        new = copy.deepcopy(self.st)
        new["routing"]["rules"][0]["comment"] = "RU"
        self.assertFalse(self.e.note_change(self.st, new))

    def test_main_address_change_is_a_change(self):
        """Переезд на другой основной: «Напрямую» теперь с другого адреса — открытые соединения оборвутся."""
        import copy
        new = copy.deepcopy(self.st)
        new["settings"]["out_main"] = A
        self.assertTrue(self.e.note_change(self.st, new))

    def test_balancing_assignment_is_not_a_change(self):
        st = state()
        st["routing"].update(default="up:u1", balance={"on": True, "skip": []})
        before = self.e.paths(st)
        self.e.bal = {"k" * 43 + "=": "u2"}        # балансировка перенесла клиента — настройки те же
        self.assertEqual(self.e.paths(st), before)


class SniDropTest(unittest.TestCase):
    """sniproxy.py: ручная смена пути закрывает только соединения, у которых путь стал другим."""

    def test_drop(self):
        from app import sniproxy

        class Sock:
            def __init__(self):
                self.shut = False

            def shutdown(self, how):
                self.shut = True
        s = sniproxy.Sniffer.__new__(sniproxy.Sniffer)
        socks = {k: (Sock(), Sock()) for k in ("ru", "other", "site")}
        s.live = {1: ("10.8.1.2", None, "77.88.55.242", *socks["ru"]),
                  2: ("10.8.1.2", None, "8.8.8.8", *socks["other"]),
                  3: ("10.8.1.2", "youtube.com", "142.250.1.1", *socks["site"])}
        s.qdone = {("10.8.1.2", 5000, "1.1.1.1", 443): (1, 0)}
        nets = {"ru": sniproxy.Nets(["77.88.0.0/18"])}
        doms = {"yt": {"youtube.com"}}
        s.lists, s.nets = doms, nets
        s.cfg = {"drop": {"gen": 1, "clients": {"10.8.1.2": {
            "old": {"rules": [[["ru"], "direct@system"]], "drules": [[["yt"], "up:u1"]], "default": "up:u1"},
            "new": {"rules": [[["ru"], "direct@" + A]], "drules": [[["yt"], "up:u1"]], "default": "up:u1"}}}}}
        self.assertEqual(s.drop((doms, nets)), 1)
        self.assertTrue(socks["ru"][0].shut and socks["ru"][1].shut)
        self.assertFalse(socks["other"][0].shut or socks["site"][0].shut)
        self.assertEqual(s.qdone, {})
        self.assertEqual(s.drop((doms, nets)), 0)         # тот же номер — уже сделано


class ReconnectApiTest(unittest.TestCase):
    """После сохранения, которое сменило путь, браузер получает reconnect и говорит «Открытые соединения
    переподключатся по новому пути»; правка без смены пути — нет."""

    def setUp(self):
        self.st0 = panel.store.snapshot()
        panel.engine.reconcile()

    def tearDown(self):
        panel.store.mutate(lambda s: (s.clear(), s.update(self.st0)))
        panel.engine._drops = {}

    def test_put_routing(self):
        from app.api import routing
        lid = routing.add_list(Req({"kind": "manual", "name": "n", "source": "203.0.113.0/24"}))["id"]
        r1 = {"lists": [lid], "outbound": "direct", "enabled": True, "comment": ""}
        routing.put_routing(Req({"default": "direct", "rules": [r1]}))
        self.assertNotIn("reconnect", routing.put_routing(Req({"default": "direct", "rules": [{**r1, "comment": "x"}]})))
        self.assertTrue(routing.put_routing(Req({"default": "direct", "rules": [{**r1, "outbound": "block"}]}))
                        .get("reconnect"))


class OwnConnectionsTest(unittest.TestCase):
    """Свои соединения сервера — с выбранного адреса; перестал работать — адрес системы (не блок)."""

    def test_own_src_falls_back(self):
        from app.engine import Engine
        e = Engine.__new__(Engine)
        e._addr_rt = {A: {"state": "ok"}, B: {"state": "failed"}}
        self.assertEqual(e.own_src(A), A)
        self.assertIsNone(e.own_src(B))
        self.assertIsNone(e.own_src(""))

    def test_urlopen_binds_source(self):
        from unittest import mock
        from app import srcnet
        seen = {}

        class Conn(srcnet.http.client.HTTPSConnection):
            def __init__(self, host, **kw):
                seen.update(kw)
                raise OSError("stop")
        with mock.patch.object(srcnet, "source_fn", lambda: A), \
                mock.patch.object(srcnet.http.client, "HTTPSConnection", Conn):
            with self.assertRaises(OSError):
                srcnet.urlopen("https://example.com/", 5)
        self.assertEqual(seen.get("source_address"), (A, 0))

    def test_urlopen_without_source_as_before(self):
        from unittest import mock
        from app import srcnet
        with mock.patch.object(srcnet, "source_fn", lambda: None), \
                mock.patch.object(srcnet.urllib.request, "urlopen", return_value="r") as u:
            self.assertEqual(srcnet.urlopen("https://example.com/", 5), "r")
        u.assert_called_once()

    def test_connect_proxy(self):
        """Посредник для lego: CONNECT с привязанным адресом (здесь — 127.0.0.1) и пересылка в обе стороны."""
        import socket
        import threading
        from app import srcnet
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        def echo():
            c, a = srv.accept()
            c.sendall(b"from " + a[0].encode() + b":" + c.recv(10))
            c.close()
        threading.Thread(target=echo, daemon=True).start()
        with srcnet.ConnectProxy("127.0.0.1") as px:
            c = socket.create_connection(("127.0.0.1", px.port), timeout=5)
            c.sendall(f"CONNECT 127.0.0.1:{srv.getsockname()[1]} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            self.assertIn(b"200", c.recv(100))
            c.sendall(b"hi")
            self.assertEqual(c.recv(100), b"from 127.0.0.1:hi")
            c.close()
        srv.close()

    def test_installer_curl_from_address(self):
        """install.sh из панели качает с выбранного адреса (AWGR_FROM), а свой IP узнаёт как раньше."""
        root = os.path.join(os.path.dirname(__file__), "..")
        with open(os.path.join(root, "install.sh")) as f:
            sh = f.read()
        self.assertIn('curl() { command curl ${AWGR_FROM:+--interface "$AWGR_FROM"} "$@"; }', sh)
        pub = sh[sh.index("public_ip() {"):sh.index("\n}\n", sh.index("public_ip() {"))]
        self.assertIn("command curl -4fsS", pub)


class InterfaceBackendTest(unittest.TestCase):
    """Интерфейс 1.25.0: адрес панели на вкладке «Система» (IP — адрес сервера в настройках, не домен сертификата),
    новый сервер — входящий адрес клиентов записан явно, подписи мест в окне исходящего адреса."""

    def test_panel_ip_is_server_setting(self):
        from app.api import server
        st = state(public_host="203.0.113.5", client_host="203.0.113.5")
        server._set_panel_ip(st, "198.51.100.30")
        self.assertEqual(st["settings"]["public_host"], "198.51.100.30")
        self.assertEqual(st["settings"]["client_host"], "203.0.113.5")      # клиентов адрес панели не трогает
        st2 = state()
        server._set_panel_ip(st2, "198.51.100.30")
        self.assertEqual(st2["settings"]["public_host"], "198.51.100.30")

    def test_fresh_store_has_inbound(self):
        d = tempfile.mkdtemp()
        import app.config as cfg
        old = cfg.PUBLIC_HOST
        cfg.PUBLIC_HOST = "203.0.113.5"
        try:
            s = Store(os.path.join(d, "state.json"))
        finally:
            cfg.PUBLIC_HOST = old
        self.assertEqual(s.snapshot()["settings"]["client_host"], "203.0.113.5")

    def test_place_labels(self):
        st = state()
        st["routing"]["default"] = "direct"
        self.assertEqual(srcaddr.places(st)[0][3].key, "ra.p_default")
        st["routing"]["balance"] = {"on": True, "skip": []}      # при балансировке — выход, когда все недоступны
        self.assertEqual(srcaddr.places(st)[0][3].key, "ra.p_default_bal")

    def test_ui_keys_in_four_languages(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "static", "i18n.js"), encoding="utf-8") as f:
            src = f.read()
        for k in ("ra.p_default", "ra.p_default_bal", "ra.p_rule", "ra.p_rule_fb", "ra.p_rule_q", "ra.p_client",
                  "ra.p_crule", "ra.p_crule_fb", "ra.p_crule_q", "ra.p_exit_fb", "ra.p_exit_q", "ra.p_tg", "ra.list",
                  "out.direct_at", "toast.reconnect", "ex.bind", "sy.panel_host", "sy.own_src", "srv.out_extra"):
            self.assertEqual(src.count(f'"{k}":'), 4, k)


class AddrWindowsApiTest(unittest.TestCase):
    """Окна «Адресов сервера»: галочка у места «Напрямую» — адрес перед выходом, у выхода — «Подключаться с адреса»;
    снятая — снова основной. Входящий: отмеченные клиенты — к этому адресу, снятые — к основному."""

    def setUp(self):
        self.st0 = panel.store.snapshot()

    def tearDown(self):
        panel.store.mutate(lambda s: (s.clear(), s.update(self.st0)))

    def test_out_window(self):
        from app.api import addrs
        uid = "u_t1"

        def prep(st):
            st["settings"]["out_hosts"] = [A]
            st["routing"]["default"] = "direct"
            st["upstreams"].append({"id": uid, "name": "T", "num": 99, "config": "socks5://198.51.100.9:1080",
                                    "enabled": False, "fallback": "block", "quota_action": "notify"})
        panel.store.mutate(prep)
        p = addrs.addr_places(Req({}))
        self.assertIn("default", [x["key"] for x in p["direct"]])
        self.assertEqual(p["main"], "system")
        addrs.put_addr_out(Req({"addr": A, "direct": ["default"], "exits": [uid]}))
        st = panel.store.snapshot()
        self.assertEqual(st["routing"]["default"], "direct@" + A)
        self.assertEqual(next(u for u in st["upstreams"] if u["id"] == uid)["bind"], A)
        addrs.put_addr_out(Req({"addr": A, "direct": [], "exits": []}))      # сняли — снова основной
        st = panel.store.snapshot()
        self.assertEqual(st["routing"]["default"], "direct")
        self.assertNotIn("bind", next(u for u in st["upstreams"] if u["id"] == uid))
        with self.assertRaises(HTTPError):
            addrs.put_addr_out(Req({"addr": C, "direct": ["default"], "exits": []}))   # такого адреса нет

    def test_in_window(self):
        from app.api import addrs
        panel.store.mutate(lambda st: st["settings"].update(client_host="203.0.113.5", extra_hosts=[A]))
        pk = "addrInTestKey" + "A" * 30 + "="
        old = panel.engine.clients
        panel.engine.clients = [{"public_key": pk, "name": "Dad", "ip": "10.8.1.3"}]
        self.addCleanup(setattr, panel.engine, "clients", old)
        r = addrs.put_addr_in(Req({"host": A, "clients": [pk]}))
        self.assertEqual(len(r["moved"]), 1)
        self.assertEqual(panel.store.snapshot()["chost"][pk], A)
        addrs.put_addr_in(Req({"host": A, "clients": []}))
        self.assertNotIn(pk, panel.store.snapshot().get("chost") or {})
        with self.assertRaises(HTTPError):
            addrs.put_addr_in(Req({"host": "198.51.100.99", "clients": [pk]}))


class InstallerHostTest(unittest.TestCase):
    """install.sh сменил адрес сервера: конфиги на прежнем адресе переходят на новый (как до 1.25.0), выбранный в
    панели другой адрес остаётся; файл client-host — один раз."""

    def _store(self, settings, old, new):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "state.json")
        st = json.loads(json.dumps(DEFAULT_STATE))
        st["settings"].update(settings)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(st, f)
        with open(os.path.join(d, "client-host"), "w", encoding="utf-8") as f:
            f.write(f"{old}\n{new}\n")
        s = Store(p)
        self.assertFalse(os.path.exists(os.path.join(d, "client-host")))
        return s.snapshot()["settings"]

    def test_follows_installer(self):
        s = self._store({"client_host": "203.0.113.5"}, "203.0.113.5", "vpn.example.com")
        self.assertEqual(s["client_host"], "vpn.example.com")
        self.assertIn("vpn.example.com", s["extra_hosts"])

    def test_own_choice_kept(self):
        s = self._store({"client_host": "198.51.100.20"}, "203.0.113.5", "203.0.113.9")
        self.assertEqual(s["client_host"], "198.51.100.20")

    def test_bad_file_ignored(self):
        s = self._store({"client_host": "203.0.113.5"}, "203.0.113.5", "bad host!")
        self.assertEqual(s["client_host"], "203.0.113.5")


class AddrDirectDnsTest(unittest.TestCase):
    """Запасной местный DNS и у «Напрямую — адрес» (владелец 2026-11-26): шифрованный DNS из России, Китая, Ирана не
    отвечает — имена клиентов на втором адресе спрашиваются у местного DNS страны сервера тем же путём (с того же адреса,
    метка адреса), у каждого пути своё «не отвечает»; путь через выход — по-прежнему никогда."""

    AM = 0x2101                     # метка адреса 1

    def _proxy(self):
        from app import dnsproxy, nftgen
        d = tempfile.mkdtemp()
        conf = os.path.join(d, "dns.json")
        with open(conf, "w") as f:
            json.dump({"listen": "10.8.1.1", "port": 53, "clients": "10.8.1.0/24", "upstreams": ["1.1.1.1"],
                       "encrypt": "doh", "direct_fallback": ["77.88.8.8"], "default": {"mark": 0, "tcp": False},
                       "addr_marks": [nftgen.ADDR_LO, nftgen.ADDR_HI],
                       "routes": {"10.8.1.5": {"mark": self.AM, "tcp": False},
                                  "10.8.1.7": {"mark": 0x2001, "tcp": False}}}, f)
        return dnsproxy.Proxy(conf)

    def _run(self, p, ip, name):
        import asyncio
        from app import dnsproxy
        from tests.test_v115 import q_msg

        async def go():
            query = q_msg(name)
            r = await p.resolve(query, dnsproxy.parse_query(query), ip)
            pr = p._dp(p.route(ip)["mark"]).probe
            if pr:
                await pr
            return r
        return asyncio.run(go())

    def test_address_path_falls_back_from_the_same_address(self):
        import socket
        from tests.test_v115 import a_reply
        p = self._proxy()
        enc, plain = [], []

        async def blocked(msg, server, mark, mode):
            enc.append((server, mark))
            raise OSError("reset")

        async def udp(msg, server, mark):
            plain.append((server, mark))
            return a_reply(msg, ["203.0.113.7"])
        p._enc, p._udp = blocked, udp
        out = self._run(p, "10.8.1.5", "google.com")
        self.assertIn(socket.inet_aton("203.0.113.7"), out)
        self.assertEqual(enc, [("1.1.1.1", self.AM)])
        self.assertEqual(plain, [("77.88.8.8", self.AM)])          # местный — с того же адреса, не с адреса системы
        self.assertTrue(p._dp(self.AM).down)
        self.assertFalse(p.direct_down)                            # путь адреса системы о сбое не знает
        self._run(p, "10.8.1.5", "example.org")
        self.assertEqual(len(enc), 1)                              # второе имя — сразу у местного
        self.assertEqual(plain[-1], ("77.88.8.8", self.AM))
        # путь через выход (метка выхода) — никогда к местному
        plain.clear()
        self._run(p, "10.8.1.7", "example.net")
        self.assertEqual(plain, [])
        # проба шифрованного в фоне — тем же путём
        p._dp(self.AM).retry_at = 0
        self._run(p, "10.8.1.5", "example.com")
        self.assertEqual(enc[-1], ("1.1.1.1", self.AM))

    def test_server_tab_warns_for_an_address_path(self):
        import time
        import types
        from unittest import mock
        from app import config
        from app.engine import Engine
        from app.engine import dns as edns
        e = Engine.__new__(Engine)
        e.dns_state = {"state": "on", "listen": "10.8.1.1", "encrypt": "doh"}
        e.dns = types.SimpleNamespace(proc=types.SimpleNamespace(pid=4242))
        path = os.path.join(tempfile.mkdtemp(), "dns-stats.json")
        now = time.time()
        with open(path, "w") as f:
            json.dump({"pid": 4242, "at": now, "direct_ok_at": now - 1, "direct_fail_at": 0, "fallback": ["77.88.8.8"],
                       "addr_direct": {str(self.AM): [now - 60, now - 5]}}, f)
        with mock.patch.object(edns, "DNS_STATS", path), mock.patch.object(config, "DRY_RUN", False):
            self.assertEqual(e.dns_view().get("direct_down"), {"fallback": ["77.88.8.8"]})
        with open(path, "w") as f:
            json.dump({"pid": 4242, "at": now, "direct_ok_at": now - 1, "fallback": ["77.88.8.8"],
                       "addr_direct": {str(self.AM): [now - 1, now - 5]}}, f)     # снова отвечает
        with mock.patch.object(edns, "DNS_STATS", path), mock.patch.object(config, "DRY_RUN", False):
            self.assertNotIn("direct_down", e.dns_view())


class LocalEncryptedDnsTest(unittest.TestCase):
    """Запасной DNS пути «напрямую» (владелец 2026-11-26): общий шифрованный не отвечает из страны сервера — сначала
    местный DNS страны с шифрованием (Яндекс, Alibaba, DNSPod), и только если и он не отвечает — местный без шифрования."""

    def _proxy(self, mode="doh"):
        from app import dnsproxy
        d = tempfile.mkdtemp()
        conf = os.path.join(d, "dns.json")
        with open(conf, "w") as f:
            json.dump({"listen": "10.8.1.1", "port": 53, "clients": "10.8.1.0/24", "upstreams": ["1.1.1.1"],
                       "encrypt": mode, "direct_fallback": ["77.88.8.8", "77.88.8.1"],
                       "direct_fallback_enc": ["77.88.8.8"], "default": {"mark": 0, "tcp": False},
                       "routes": {"10.8.1.7": {"mark": 0x2001, "tcp": False}}}, f)
        return dnsproxy.Proxy(conf)

    def _run(self, p, name, ip="10.8.1.5"):
        import asyncio
        from app import dnsproxy
        from tests.test_v115 import q_msg

        async def go():
            query = q_msg(name)
            r = await p.resolve(query, dnsproxy.parse_query(query), ip)
            dp = p._dp(0)
            for t in (dp.probe, dp.loc_probe):
                if t:
                    await t
            return r
        return asyncio.run(go())

    def _wire(self, p, local_enc_ok=True):
        from tests.test_v115 import a_reply
        calls = []

        async def enc(msg, server, mark, mode):
            calls.append(("enc", server, mode, mark))
            if server == "77.88.8.8" and local_enc_ok:
                return a_reply(msg, ["203.0.113.8"])
            raise OSError("reset")

        async def udp(msg, server, mark):
            calls.append(("plain", server, mark))
            return a_reply(msg, ["203.0.113.9"])
        p._enc, p._udp = enc, udp
        return calls

    def test_local_encrypted_before_plain(self):
        import socket
        p = self._proxy()
        calls = self._wire(p)
        out = self._run(p, "yandex.ru")
        self.assertIn(socket.inet_aton("203.0.113.8"), out)
        self.assertEqual(calls, [("enc", "1.1.1.1", "doh", 0), ("enc", "77.88.8.8", "doh", 0)])   # обычного — нет
        calls.clear()
        self._run(p, "vk.com")                       # общий «не отвечает» — сразу местный с шифрованием
        self.assertEqual(calls, [("enc", "77.88.8.8", "doh", 0)])
        self.assertEqual(p.stats["direct_local_enc"], 2)

    def test_plain_only_when_local_encrypted_fails_too(self):
        p = self._proxy("dot")
        calls = self._wire(p, local_enc_ok=False)
        self._run(p, "yandex.ru")
        self.assertEqual(calls, [("enc", "1.1.1.1", "dot", 0), ("enc", "77.88.8.8", "dot", 0),
                                 ("enc", "77.88.8.8", "doh", 0), ("plain", "77.88.8.8", 0)])
        self.assertTrue(p._dp(0).loc_down)
        calls.clear()
        self._run(p, "vk.com")                       # оба не отвечают — клиент не ждёт, сразу обычный
        self.assertEqual(calls, [("plain", "77.88.8.8", 0)])
        p._dp(0).loc_retry_at = 0                    # прошло DIRECT_RETRY — местный с шифрованием пробуется в фоне
        calls.clear()
        self._run(p, "mail.ru")
        self.assertEqual(calls[0], ("plain", "77.88.8.8", 0))
        self.assertIn(("enc", "77.88.8.8", "dot", 0), calls)

    def test_other_method_when_the_first_fails(self):
        """Яндекс по DoH (HTTP/1.1) не отвечает, по DoT — да (проверка 2026-11-26): местный сервер пробуется и другим
        способом, и сработавший запоминается — следующие имена сразу им."""
        from tests.test_v115 import a_reply
        p = self._proxy("doh")
        calls = []

        async def enc(msg, server, mark, mode):
            calls.append((server, mode))
            if server == "77.88.8.8" and mode == "dot":
                return a_reply(msg, ["203.0.113.8"])
            raise OSError("DoH: no answer")

        async def udp(msg, server, mark):
            calls.append((server, "plain"))
            return a_reply(msg, ["203.0.113.9"])
        p._enc, p._udp = enc, udp
        self._run(p, "yandex.ru")
        self.assertEqual(calls, [("1.1.1.1", "doh"), ("77.88.8.8", "doh"), ("77.88.8.8", "dot")])
        calls.clear()
        self._run(p, "vk.com")
        self.assertEqual(calls, [("77.88.8.8", "dot")])          # запомнил DoT
        self.assertFalse(p._dp(0).loc_down)

    def test_exit_path_never_asks_local(self):
        p = self._proxy()
        calls = self._wire(p)
        self._run(p, "example.org", ip="10.8.1.7")
        self.assertEqual([c for c in calls if c[1] != "1.1.1.1"], [])

    def test_tls_names(self):
        from app import dnsproxy
        self.assertEqual(dnsproxy.tls_name("77.88.8.8", "doh"), "common.dot.dns.yandex.net")
        self.assertEqual(dnsproxy.tls_name("1.12.12.12", "doh"), "doh.pub")
        self.assertEqual(dnsproxy.tls_name("1.12.12.12", "dot"), "dot.pub")
        self.assertEqual(dnsproxy.tls_name("192.0.2.53", "dot"), "192.0.2.53")

    def test_presets_and_engine_config(self):
        from app import countries
        self.assertEqual(countries.local_dns_enc("RU"), ["77.88.8.8"])
        self.assertEqual(countries.local_dns_enc("ir"), [])
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "engine", "dns.py"), encoding="utf-8") as f:
            self.assertIn('"direct_fallback_enc": countries.local_dns_enc(', f.read())

    def test_server_tab_says_encrypted(self):
        import time
        import types
        from unittest import mock
        from app import config
        from app.engine import Engine
        from app.engine import dns as edns
        e = Engine.__new__(Engine)
        e.dns_state = {"state": "on", "listen": "10.8.1.1", "encrypt": "doh"}
        e.dns = types.SimpleNamespace(proc=types.SimpleNamespace(pid=4242))
        path = os.path.join(tempfile.mkdtemp(), "dns-stats.json")
        now = time.time()
        for loc_ok, want in ((now - 2, {"fallback": ["77.88.8.8"], "encrypted": True}),
                             (now - 3600, {"fallback": ["77.88.8.8", "77.88.8.1"]})):
            with open(path, "w") as f:
                json.dump({"pid": 4242, "at": now, "direct_ok_at": now - 60, "direct_fail_at": now - 5,
                           "fallback": ["77.88.8.8", "77.88.8.1"], "fallback_enc": ["77.88.8.8"],
                           "local_enc_ok_at": loc_ok}, f)
            with mock.patch.object(edns, "DNS_STATS", path), mock.patch.object(config, "DRY_RUN", False):
                self.assertEqual(e.dns_view().get("direct_down"), want)


class OwnDnsEncryptedTest(unittest.TestCase):
    """Свой DNS правила (владелец 2026-11-26): известный сервер с шифрованием (Яндекс, Alibaba, DNSPod, Cloudflare,
    Google, Quad9) — сначала шифрованным тем же путём, другим способом, если первый не отвечает; не ответил — обычным,
    как раньше. Остальные серверы и «Без шифрования» в настройках — обычным DNS."""

    def _proxy(self, own, mode="doh"):
        from app import dnsproxy
        d = tempfile.mkdtemp()
        lst = os.path.join(d, "ru.txt")
        with open(lst, "w") as f:
            f.write("ru\n")
        conf = os.path.join(d, "dns.json")
        with open(conf, "w") as f:
            json.dump({"listen": "10.8.1.1", "port": 53, "clients": "10.8.1.0/24", "upstreams": ["1.1.1.1"],
                       "encrypt": mode, "default": {"mark": 0x2001, "tcp": False}, "routes": {},
                       "dom": {"lists": {"l1": lst}, "policies": {"p_global": [[["l1"], {"mark": 0, "tcp": False},
                                                                                  own, False]]},
                               "clients": {}, "set": None}}, f)
        return dnsproxy.Proxy(conf)

    def _run(self, p, name):
        import asyncio
        from app import dnsproxy
        from tests.test_v115 import q_msg

        async def go():
            query = q_msg(name)
            r = await p.resolve(query, dnsproxy.parse_query(query), "10.8.1.5")
            for st in p.own_paths.values():
                if st.loc_probe:
                    await st.loc_probe
            return r
        return asyncio.run(go())

    def _wire(self, p, enc_ok=lambda server, mode: server == "77.88.8.8" and mode == "dot"):
        from tests.test_v115 import a_reply
        calls = []

        async def enc(msg, server, mark, mode):
            calls.append((server, mode, mark))
            if enc_ok(server, mode):
                return a_reply(msg, ["203.0.113.8"])
            raise OSError("no answer")

        async def udp(msg, server, mark):
            calls.append((server, "plain", mark))
            return a_reply(msg, ["203.0.113.9"])
        p._enc, p._udp = enc, udp
        return calls

    def test_yandex_encrypted_first(self):
        import socket
        p = self._proxy(["77.88.8.8", "77.88.8.1"])
        calls = self._wire(p)
        out = self._run(p, "yandex.ru")
        self.assertIn(socket.inet_aton("203.0.113.8"), out)
        self.assertEqual(calls, [("77.88.8.8", "doh", 0), ("77.88.8.8", "dot", 0)])     # 77.88.8.1 — не известен
        calls.clear()
        self._run(p, "mail.ru")
        self.assertEqual(calls, [("77.88.8.8", "dot", 0)])
        self.assertEqual(p.stats["own_enc"], 2)

    def test_plain_when_encrypted_fails(self):
        p = self._proxy(["77.88.8.8", "77.88.8.1"])
        calls = self._wire(p, enc_ok=lambda server, mode: False)
        self._run(p, "yandex.ru")
        self.assertEqual(calls[-1], ("77.88.8.8", "plain", 0))
        calls.clear()
        self._run(p, "mail.ru")                      # шифрованный «не отвечает» — сразу обычный, не ждём
        self.assertEqual(calls, [("77.88.8.8", "plain", 0)])

    def test_unknown_servers_and_plain_setting_stay_plain(self):
        p = self._proxy(["178.22.122.100"])
        calls = self._wire(p)
        self._run(p, "a.ru")
        self.assertEqual(calls, [("178.22.122.100", "plain", 0)])
        p = self._proxy(["77.88.8.8"], mode="plain")
        calls = self._wire(p)
        self._run(p, "b.ru")
        self.assertEqual(calls, [("77.88.8.8", "plain", 0)])
