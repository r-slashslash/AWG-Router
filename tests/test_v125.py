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
        eng._addr_probe = lambda ip: self.probe.get(ip, {"ok": True, "ip": ip, "cc": "DE"})

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

    def tearDown(self):
        self.boot.stop()
        self._data.stop()

    def tick(self, **settings):
        if settings:
            self.store.mutate(lambda s: s["settings"].update(settings))
        self.eng._addr_tick(self.store.snapshot())

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
