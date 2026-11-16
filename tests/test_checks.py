"""Одна проверка на каждую вещь (app/checks.py): форма в панели и резервная копия отвечают по одному правилу.
python3 -m unittest tests.test_checks"""
import copy
import os
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from app import checks, limits, lists, users  # noqa: E402
from app.i18n import MsgError  # noqa: E402
from app.web import HTTPError  # noqa: E402
from app import notify  # noqa: E402
from app import panel  # noqa: E402
from app import store as store_mod  # noqa: E402
from app.api import backup, clients, exits, state  # noqa: E402

PK = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
PRIV = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
R = lambda body: type("R", (), {"json": lambda self: body})()


def base() -> dict:
    """Копия с одним выходом, списком, клиентом, сроком и Telegram — каждый тест портит в ней одно поле."""
    return {
        "routing": {"default": "direct", "rules": [{"id": "r_a", "lists": ["l1"], "outbound": "up:u1"}]},
        "upstreams": [{"id": "u1", "name": "NL", "num": 1, "config": "socks5://198.51.100.9:1080",
                       "enabled": True, "fallback": "direct", "quota": 5 * limits.GB}],
        "lists": [{"id": "l1", "kind": "manual", "source": "203.0.113.0/24", "name": "Office"}],
        "clients": {PK: {"outbound": "inherit", "rules_mode": "inherit", "note": ""}},
        "keys": {PK: PRIV},
        "limits": {PK: {"expires": 1900000000, "quota": limits.GB, "period": "month"}},
        "settings": {"list_update_hours": 24, "client_dns": ["1.1.1.1"],
                     "telegram": {"token": "12345:" + "a" * 35, "chat_id": "-100", "enabled": True,
                                  "backup_pw": "long-enough"}},
    }


def code(fn):
    try:
        fn()
    except HTTPError as e:
        return e.code, e.detail.key, e.field or e.detail.p.get("field")
    except MsgError as e:
        return 400, e.msg.key, None
    return None


class SameRuleTest(unittest.TestCase):
    """Неверное значение: форма — ошибка о поле, копия — «неверное поле <путь>» (а не молча что-то другое)."""

    def backup_error(self, patch) -> str | None:
        b = base()
        patch(b)
        r = code(lambda: backup.clean_backup_state(b))
        if r:
            self.assertEqual(r[:2], (400, "err.backup_field"))
            return r[2]
        return None

    def test_backup_base_is_valid(self):
        self.assertIsNone(self.backup_error(lambda b: None))

    def test_exit(self):
        st = backup.clean_backup_state(base())
        for form, patch, path in (
            (lambda: checks.name("  "), lambda b: b["upstreams"][0].update(name=" "), "upstreams[0].name"),
            (lambda: checks.exit_config("nonsense"), lambda b: b["upstreams"][0].update(config="nonsense"),
             "upstreams[0].config"),
            (lambda: checks.rate(10 ** 7), lambda b: b["upstreams"][0].update(rate_down=10 ** 7), "upstreams[0].rate_down"),
            (lambda: checks.fallback(st, "u1", "up:u1"), lambda b: b["upstreams"][0].update(fallback="up:u1"),
             "upstreams[0].fallback"),
            (lambda: checks.quota_action(st, "up:u1", "u1"), lambda b: b["upstreams"][0].update(quota_action="up:u1"),
             "upstreams[0].quota_action"),
            (lambda: checks.flag("no"), lambda b: b["upstreams"][0].update(enabled="no"), "upstreams[0].enabled"),
        ):
            with self.subTest(path=path):
                self.assertIsNotNone(code(form))
                self.assertEqual(self.backup_error(patch), path)

    def test_list_and_rule(self):
        st = backup.clean_backup_state(base())
        self.assertEqual(code(lambda: checks.list_fields({"kind": "manual", "source": "no nets", "name": "x"}))[1],
                         "err.no_cidr")
        self.assertEqual(self.backup_error(lambda b: b["lists"][0].update(source="no nets")), "lists[0]")
        self.assertEqual(code(lambda: checks.rules(st, [{"lists": ["l1"], "outbound": "up:zz"}]))[1],
                         "err.unknown_outbound")
        self.assertEqual(self.backup_error(lambda b: b["routing"]["rules"][0].update(outbound="up:zz")),
                         "routing.rules")

    def test_client_and_limits(self):
        st = backup.clean_backup_state(base())
        self.assertIsNotNone(code(lambda: checks.client_policy(st, {"rules_mode": "own"})))
        self.assertEqual(self.backup_error(lambda b: b["clients"][PK].update(rules_mode="own")), "clients." + PK[:12])
        self.assertIsNotNone(code(lambda: checks.rate(0.01)))
        self.assertEqual(self.backup_error(lambda b: b["limits"][PK].update(rate_up=0.01)),
                         f"limits.{PK[:12]}.rate_up")
        self.assertIsNotNone(code(lambda: checks.cps_entry("custom", {"I1": "<zz>"})))
        self.assertEqual(self.backup_error(lambda b: b.update(cps={PK: {"preset": "custom", "values": {"I1": "<zz>"}}})),
                         "cps." + PK[:12])

    def test_server_settings(self):
        for form, patch, path in (
            (lambda: users.check_mtu(2000), lambda b: b["settings"].update(client_mtu=2000), "settings.client_mtu"),
            (lambda: users.check_keepalive("abc"), lambda b: b["settings"].update(client_keepalive="abc"),
             "settings.client_keepalive"),
            (lambda: users.check_client_dns("x"), lambda b: b["settings"].update(client_dns=["x"]),
             "settings.client_dns"),
            (lambda: checks.list_update_hours("soon"), lambda b: b["settings"].update(list_update_hours="soon"),
             "settings.list_update_hours"),
        ):
            with self.subTest(path=path):
                self.assertIsNotNone(code(form))
                self.assertEqual(self.backup_error(patch), path)

    def test_telegram(self):
        st = backup.clean_backup_state(base())
        for body, key, path in (({"token": "nope"}, "err.tg_token", "settings.telegram"),
                                ({"backup_pw": "short"}, "err.backup_pw", "settings.telegram"),
                                ({"backup_pw": "x" * 129}, "err.backup_pw", "settings.telegram"),
                                ({"via": "block"}, "err.bad_value", "settings.telegram.via")):
            with self.subTest(body=body):
                self.assertEqual(code(lambda: checks.telegram(st, notify.defaults(), body))[1], key)
                self.assertEqual(self.backup_error(lambda b: b["settings"]["telegram"].update(body)), path)


class BackupForgivesTest(unittest.TestCase):
    """Где копия прощала и раньше, она прощает и теперь: неверное — значение по умолчанию, копия загружается."""

    def test_defaults_instead_of_errors(self):
        b = base()
        b["settings"].update(on_stop="sometimes", panel_dns="yes", panel_dns_enc="tls")
        b["settings"]["telegram"].update(lang="xx", backup="hourly", events={"login": "no"})
        b["limits"][PK].update(period="week", expires="soon", quota=-1)
        b["routing"]["strict"] = "yes"
        b["upstreams"][0].update(quic="yes", quota="lots")
        st = backup.clean_backup_state(b)
        s, tg = st["settings"], st["settings"]["telegram"]
        self.assertNotIn("on_stop", s)
        self.assertNotIn("panel_dns", s)
        self.assertNotIn("panel_dns_enc", s)
        self.assertEqual((tg["lang"], tg["backup"], tg["events"]["login"]), ("en", "off", True))
        self.assertEqual(st["limits"][PK]["period"], "month")
        self.assertIsNone(st["limits"][PK]["expires"])
        self.assertIsNone(st["limits"][PK]["quota"])
        self.assertNotIn("strict", st["routing"])
        self.assertNotIn("quic", st["upstreams"][0])
        self.assertIsNone(st["upstreams"][0]["quota"])
        # уведомления и управление без чата — выключены, а не ошибка
        b = base()
        b["settings"]["telegram"].update(chat_id="", control=True)
        tg = backup.clean_backup_state(b)["settings"]["telegram"]
        self.assertEqual((tg["enabled"], tg["control"]), (False, False))
        # форма на то же отвечает ошибкой
        self.assertEqual(code(lambda: state.put_settings(R({"on_stop": "sometimes"})))[1], "err.bad_value")


class AgreedChangesTest(unittest.TestCase):
    """Где правила формы и копии расходились, теперь правило одно — как в форме (решение владельца 2026-11-16)."""

    def test_quota_over_a_million_gb_is_no_limit(self):
        b = base()
        b["upstreams"][0]["quota"] = checks.QUOTA_MAX + 1
        b["limits"][PK]["quota"] = checks.QUOTA_MAX * 2
        st = backup.clean_backup_state(b)
        self.assertIsNone(st["upstreams"][0]["quota"])
        self.assertIsNone(st["limits"][PK]["quota"])
        self.assertEqual(code(lambda: checks.quota_gb(1_000_001))[1], "err.quota")
        self.assertEqual(checks.quota_gb(1_000_000), checks.QUOTA_MAX)

    def test_dns_first_four(self):
        b = base()
        b["settings"]["client_dns"] = ["1.1.1.1", "2001:db8::1", "8.8.8.8", "9.9.9.9", "8.8.4.4", "1.0.0.1"]
        self.assertEqual(backup.clean_backup_state(b)["settings"]["client_dns"],
                         ["1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"])       # IPv6 из старых копий — молча нет
        self.assertEqual(users.check_client_dns("1.1.1.1 8.8.8.8, 9.9.9.9 8.8.4.4 1.0.0.1"),
                         ["1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"])
        self.assertEqual(code(lambda: users.check_client_dns("2001:db8::1"))[1], "srv.dns_v6")

    def test_numbers_as_text(self):
        b = base()
        b["settings"].update(list_update_hours="12", client_mtu="1380", client_keepalive=25)
        b["limits"][PK]["expires"] = "1900000000"
        st = backup.clean_backup_state(b)
        self.assertEqual((st["settings"]["list_update_hours"], st["settings"]["client_mtu"],
                          st["settings"]["client_keepalive"]), (12, 1380, "25"))
        self.assertEqual(st["limits"][PK]["expires"], 1900000000)

    def test_expires_true_is_an_error(self):
        """Срок «true» раньше сохранялся как 1 (1 января 1970), и клиент сразу отключался по сроку."""
        self.assertEqual(code(lambda: checks.expires(True))[1], "err.bad_value")
        self.assertIsNone(checks.expires(0))
        self.assertEqual(checks.expires("1900000000"), 1900000000)
        self.assertEqual(code(lambda: checks.expires(limits.EXPIRES_MAX + 1))[1], "err.bad_value")


class FormStillWorksTest(unittest.TestCase):
    """Обработчики API идут через те же проверки: ошибка называет поле формы, правильное сохраняется."""

    def test_exit_form(self):
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            panel.engine.reconcile()
        self.assertEqual(code(lambda: exits.add_upstream(R({"name": "X", "config": "socks5://198.51.100.9:1080",
                                                            "quota_gb": 0}))), (400, "err.quota", "quota_gb"))
        self.assertEqual(code(lambda: exits.add_upstream(R({"name": "", "config": "socks5://198.51.100.9:1080"}))),
                         (400, "err.name_required", "name"))
        self.assertEqual(code(lambda: exits.add_upstream(R({"name": "X", "config": "x"})))[2], "config")
        uid = exits.add_upstream(R({"name": "X", "config": "socks5://198.51.100.9:1080", "quota_gb": 2.5}))["id"]
        try:
            u = store_mod.Store.upstream(panel.store.snapshot(), uid)
            self.assertEqual(u["quota"], int(2.5 * limits.GB))
            self.assertEqual(code(lambda: exits.edit_upstream(R({"fallback": "up:" + uid}), uid)),
                             (400, "err.fallback_self", "fallback"))
        finally:
            exits.del_upstream(R({}), uid)

    def test_limits_form(self):
        pk = panel.engine.clients[0]["public_key"] if panel.engine.clients else None
        if not pk:
            self.skipTest("нет клиента в демо")
        L0 = copy.deepcopy(panel.store.snapshot()["limits"])
        try:
            self.assertEqual(code(lambda: clients.put_limits(R({"expires": True}), pk))[1], "err.bad_value")
            self.assertEqual(code(lambda: clients.put_limits(R({"period": "week"}), pk))[1], "err.bad_value")
            clients.put_limits(R({"expires": 1900000000, "quota_gb": 3, "period": "total"}), pk)
            L = panel.store.snapshot()["limits"][pk]
            self.assertEqual((L["expires"], L["quota"], L["period"]), (1900000000, 3 * limits.GB, "total"))
        finally:
            panel.store.mutate(lambda st: st.update(limits=L0))


if __name__ == "__main__":
    unittest.main()
