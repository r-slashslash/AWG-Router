"""1.21.0: понятные ошибки команд в сети сервера и отказа модуля ядра (#24), дополнительные внешние адреса
сервера и свой адрес у клиента (#37).

python3 -m unittest discover tests
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import engine, main, system, users  # noqa: E402
from app.web import HTTPError  # noqa: E402


class Req:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


def code(fn, *a):
    try:
        fn(*a)
    except HTTPError as e:
        return e.code
    return 200


# ------------------------------------------------------------------ ошибки команд (#24)
class CmdLabelTest(unittest.TestCase):
    def test_without_nsenter_and_paths(self):
        """Было «-n -- awg setconf awgr3 /run/awgr/awgr3.conf»: человек шёл искать файл, которого на хосте нет."""
        self.assertEqual(system.cmd_label(["nsenter", "-t", "4242", "-n", "--", "awg", "setconf", "awgr3",
                                           "/run/awgr/awgr3.conf"]), "awg setconf awgr3")
        self.assertEqual(system.cmd_label(["ip", "link", "add", "awgr3", "type", "amneziawg"]),
                         "ip link add awgr3 type amneziawg")

    def test_run_error_text(self):
        with self.assertRaises(system.SysError) as cm:
            system.run(["sh", "-c", "echo 'Unable to modify interface: Invalid argument' >&2; exit 1", "/tmp/x"])
        self.assertTrue(str(cm.exception.msg).startswith("sh -c "), cm.exception.msg)
        self.assertNotIn("/tmp/x", cm.exception.msg)
        self.assertIn("Invalid argument", cm.exception.msg)


class KernelConfMessageTest(unittest.TestCase):
    def test_conf_rejected_says_only_reason(self):
        e = engine.Engine.__new__(engine.Engine)
        events = []
        e.event = lambda lvl, m: events.append((m.key, m.p))
        e._kernel_failed("awgr3", "awg setconf awgr3: Unable to modify interface: Invalid argument", conf=True)
        self.assertEqual(events, [("ev.kernel_conf", {"iface": "awgr3",
                                                       "error": "Unable to modify interface: Invalid argument"})])
        self.assertTrue(e.kernel_fallback["conf"])
        self.assertEqual(e.kernel_fallback["iface"], "awgr3")

    def test_module_failure_keeps_old_event(self):
        e = engine.Engine.__new__(engine.Engine)
        events = []
        e.event = lambda lvl, m: events.append(m.key)
        e._kernel_failed("awgr3", "RTNETLINK answers: Operation not supported")
        self.assertEqual(events, ["ev.kernel_fallback"])
        self.assertFalse(e.kernel_fallback["conf"])


# ------------------------------------------------------------------ дополнительные адреса (#37)
class ExtraHostsParseTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(users.parse_extra_hosts("203.0.113.20, VPN2.example.com\n[2001:db8::5] 203.0.113.20"),
                         ["203.0.113.20", "vpn2.example.com", "2001:db8::5"])
        self.assertEqual(users.parse_extra_hosts(["198.51.100.1", " "]), ["198.51.100.1"])
        self.assertEqual(users.parse_extra_hosts(""), [])

    def test_bad(self):
        for v in ("bad host", "-x.example.com", "a..b", "localhost", "1.2.3.4:51820", None, 5, [1], {"a": 1}):
            with self.assertRaises(users.UserError, msg=repr(v)):
                users.parse_extra_hosts(v)
        with self.assertRaises(users.UserError):
            users.parse_extra_hosts([f"198.51.100.{i}" for i in range(users.EXTRA_HOSTS_MAX + 1)])


class ClientHostTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.engine.reconcile()

    def setUp(self):
        self.pk = main.add_user(Req({"name": "Host test"}))["public_key"]
        main.engine.reconcile()

    def tearDown(self):
        main.del_user(None, self.pk)
        main.store.mutate(lambda st: [st["settings"].pop(k, None) for k in ("extra_hosts", "client_host")])
        main.engine.reconcile()

    def endpoint(self, pk):
        conf = main.engine.srv.client_config(pk)["conf"]
        return next(ln.split("=", 1)[1].strip() for ln in conf.splitlines() if ln.startswith("Endpoint"))

    def test_choose_for_client(self):
        main.put_server(Req({"extra_hosts": "198.51.100.20, vpn2.example.com"}))
        st = main.get_state(None)
        self.assertEqual(st["hosts"]["choices"][-2:], ["198.51.100.20", "vpn2.example.com"])
        default = self.endpoint(self.pk)
        main.put_client_host(Req({"host": "vpn2.example.com"}), self.pk)
        self.assertTrue(self.endpoint(self.pk).startswith("vpn2.example.com:"), self.endpoint(self.pk))
        c = next(x for x in main.get_state(None)["clients"] if x["public_key"] == self.pk)
        self.assertEqual(c["host"], "vpn2.example.com")
        main.put_client_host(Req({"host": ""}), self.pk)                      # снова как у всех
        self.assertEqual(self.endpoint(self.pk), default)

    def test_ipv6_in_brackets(self):
        main.put_server(Req({"extra_hosts": ["2001:db8::5"]}))
        main.put_client_host(Req({"host": "2001:db8::5"}), self.pk)
        self.assertTrue(self.endpoint(self.pk).startswith("[2001:db8::5]:"), self.endpoint(self.pk))

    def test_bad_values(self):
        main.put_server(Req({"extra_hosts": "198.51.100.20"}))
        for v in ("203.0.113.99", 5, ["198.51.100.20"], {"a": 1}, True):
            self.assertEqual(code(main.put_client_host, Req({"host": v}), self.pk), 400, v)
        self.assertEqual(code(main.put_client_host, Req({"host": "198.51.100.20"}), "A" * 43 + "="), 404)
        self.assertEqual(code(main.put_server, Req({"extra_hosts": "bad host"})), 400)
        self.assertEqual(code(main.put_server, Req({"extra_hosts": 7})), 400)
        self.assertEqual(code(main.add_user, Req({"name": "X", "host": "203.0.113.99"})), 400)

    def test_removed_address_falls_back(self):
        """Адрес убрали из дополнительных — у клиента он снимается, конфиг снова с общим адресом."""
        main.put_server(Req({"extra_hosts": "198.51.100.20"}))
        main.put_client_host(Req({"host": "198.51.100.20"}), self.pk)
        main.put_server(Req({"extra_hosts": ""}))
        self.assertNotIn(self.pk, main.store.snapshot().get("chost", {}))
        self.assertNotIn("extra_hosts", main.store.snapshot()["settings"])

    def test_domain_for_everyone(self):
        """Домен из дополнительных можно выбрать и «для всех»; произвольный домен — нет (только IP)."""
        main.put_server(Req({"extra_hosts": "vpn2.example.com", "client_host": "vpn2.example.com"}))
        self.assertTrue(self.endpoint(self.pk).startswith("vpn2.example.com:"))
        self.assertEqual(code(main.put_server, Req({"client_host": "other.example.com"})), 400)

    def test_new_client_with_host_and_delete(self):
        main.put_server(Req({"extra_hosts": "198.51.100.20"}))
        pk = main.add_user(Req({"name": "With host", "host": "198.51.100.20"}))["public_key"]
        main.engine.reconcile()
        self.assertTrue(self.endpoint(pk).startswith("198.51.100.20:"))
        main.del_user(None, pk)
        self.assertNotIn(pk, main.store.snapshot().get("chost", {}))

    def test_restore_keeps_only_own_addresses(self):
        """Копия с другого сервера: его дополнительные адреса не берутся, адрес клиента — только если он есть
        и у этого сервера."""
        main.put_server(Req({"extra_hosts": "198.51.100.20"}))
        main.put_client_host(Req({"host": "198.51.100.20"}), self.pk)
        b = main.clean_backup_state(main.store.snapshot())
        self.assertNotIn("extra_hosts", b["settings"])
        self.assertEqual(b["chost"][self.pk], "198.51.100.20")
        bad = dict(main.store.snapshot(), chost={self.pk: ["x"]})
        self.assertEqual(code(main.clean_backup_state, bad), 400)
        # restore_state: свои дополнительные адреса остаются, чужие и адрес клиента не из них — нет
        other = main.clean_backup_state(main.store.snapshot())
        other["settings"]["extra_hosts"] = ["203.0.113.250"]
        other["chost"] = {self.pk: "203.0.113.250"}
        cur = main.store.snapshot()
        main.restore_state(cur, other)
        self.assertEqual(cur["settings"]["extra_hosts"], ["198.51.100.20"])
        self.assertEqual(cur["chost"], {})
        other["chost"] = {self.pk: "198.51.100.20"}
        main.restore_state(cur, other)
        self.assertEqual(cur["chost"], {self.pk: "198.51.100.20"})

    def test_restore_backup_end_to_end(self):
        """Через настоящий restore_backup: свои дополнительные адреса остаются, адрес клиента из копии — если есть."""
        main.put_server(Req({"extra_hosts": "198.51.100.20"}))
        main.put_client_host(Req({"host": "198.51.100.20"}), self.pk)
        st0 = main.store.snapshot()
        try:
            g = main.clean_backup_state(main.store.snapshot())
            g["settings"]["extra_hosts"] = ["203.0.113.250"]          # чужой сервер
            g["chost"] = {self.pk: "198.51.100.20"}
            main.restore_backup(Req({"backup": {"format": main.BACKUP_FORMAT, "state": g}}))
            s = main.store.snapshot()
            self.assertEqual(s["settings"]["extra_hosts"], ["198.51.100.20"])
            self.assertEqual(s["chost"], {self.pk: "198.51.100.20"})
        finally:
            main.store.mutate(lambda st: (st.clear(), st.update(st0)))


if __name__ == "__main__":
    unittest.main()
