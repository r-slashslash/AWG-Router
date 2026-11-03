"""1.13.0: общий трафик сервера (шапка панели и бот) и новое меню бота: «Сервер» (состояние, выходы),
«Клиенты» с «Новым клиентом» сверху, «Обновить».

python3 -m unittest discover tests
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import hostnet, lists, main, notify, tgbot  # noqa: E402
from app.traffic import FORMAT, Traffic, month_key  # noqa: E402
from tests.test_v19 import FakeTG, button, cfg, msg  # noqa: E402

STATIC = os.path.join(os.path.dirname(__file__), "..", "app", "static")


def peer(pk, rx, tx, enabled=True):
    return {"public_key": pk, "enabled": enabled, "live": {"rx": rx, "tx": tx}}


class ServerTrafficTest(unittest.TestCase):
    def new(self):
        return Traffic(os.path.join(tempfile.mkdtemp(), "t.json"))

    def test_sums_clients_and_survives_delete(self):
        tr = self.new()
        tr.update([peer("A", 100, 1000), peer("B", 5, 50)])          # точки отсчёта
        tr.update([peer("A", 300, 1500), peer("B", 15, 150)])
        self.assertEqual(tr.server_view()["total_rx"], 210)
        self.assertEqual(tr.server_view()["total_tx"], 600)
        tr.forget("A")                                               # клиента удалили — итог сервера тот же
        self.assertEqual(tr.server_view()["total_rx"] + tr.server_view()["total_tx"], 810)
        tr.update([peer("B", 3, 30)])                                # счётчик B обнулился: весь — новый
        v = tr.server_view()
        self.assertEqual([v["total_rx"], v["total_tx"]], [213, 630])
        self.assertEqual([v["month_rx"], v["month_tx"]], [213, 630])

    def test_saved_with_same_format(self):
        tr = self.new()
        tr.update([peer("A", 0, 0)])
        tr.update([peer("A", 7, 9)])
        tr._dirty = True
        tr.save()
        with open(tr.path) as f:
            d = json.load(f)
        self.assertEqual(d["_v"], FORMAT)                           # старые панели читают тот же файл
        self.assertEqual(d["server"]["total"], [7, 9])
        self.assertEqual(Traffic(tr.path).server_view()["total_tx"], 9)

    def test_seeded_from_clients_when_missing(self):
        """Файл прежней версии без "server": итог сервера — сумма итогов клиентов."""
        path = os.path.join(tempfile.mkdtemp(), "t.json")
        mk = month_key()
        with open(path, "w") as f:
            json.dump({"_v": FORMAT, "clients": {
                "A": {"total": [10, 100], "months": {mk: [1, 10]}, "last": [0, 0]},
                "B": {"total": [20, 200], "months": {mk: [2, 20]}, "last": [0, 0]}}}, f)
        v = Traffic(path).server_view()
        self.assertEqual([v["total_rx"], v["total_tx"], v["month_rx"], v["month_tx"]], [30, 300, 3, 30])

    def test_restore_keeps_server_total(self):
        tr = self.new()
        tr.replace({"_v": FORMAT, "clients": {}, "server": {"total": [5, 6], "months": {}}})
        self.assertEqual(tr.server_view()["total_tx"], 6)
        tr.replace({"_v": FORMAT, "clients": {"A": {"total": [1, 2], "months": {}}}})
        self.assertEqual(tr.server_view()["total_tx"], 2)           # копия без "server" — сумма клиентов

    def test_in_state(self):
        self.assertIn("server_traffic", json.dumps(main.get_state(None), default=str))


class PanelHeaderTest(unittest.TestCase):
    def read(self, name):
        with open(os.path.join(STATIC, name), encoding="utf-8") as f:
            return f.read()

    def test_header_shows_traffic_not_applied(self):
        js = self.read("app.js")
        body = js[js.index("function renderStatus()"):]
        body = body[:body.index("\n}\n")]
        self.assertNotIn("status.applied", body)
        self.assertIn("renderBrandTraffic()", body)
        with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as f:
            self.assertIn('AWG Router<span id="brand-traffic"', f.read())       # справа от названия

    def test_texts(self):
        js = self.read("i18n.js")
        for key in ("status.traffic", "status.traffic_hint"):
            self.assertEqual(js.count(f'"{key}":'), 4, key)


class HostInfoTest(unittest.TestCase):
    def test_uptime_and_memory(self):
        d = tempfile.mkdtemp()
        up, mem = os.path.join(d, "uptime"), os.path.join(d, "meminfo")
        with open(up, "w") as f:
            f.write("93784.51 1000.00\n")
        with open(mem, "w") as f:
            f.write("MemTotal:        2000 kB\nMemFree:          100 kB\nMemAvailable:     500 kB\n")
        self.assertEqual(hostnet.uptime(up), 93784)
        self.assertEqual(hostnet.memory(mem), (1500 * 1024, 2000 * 1024))
        self.assertIsNone(hostnet.uptime(os.path.join(d, "none")))
        self.assertIsNone(hostnet.memory(up))

    def test_fmt_uptime(self):
        self.assertEqual(tgbot.fmt_uptime(93784, "ru"), "1 дн. 2 ч")
        self.assertEqual(tgbot.fmt_uptime(3 * 3600 + 120, "en"), "3 h 2 min")
        self.assertEqual(tgbot.fmt_uptime(None, "en"), "—")


class BotMenuV113Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.engine.reconcile()
        if not main.engine.clients:
            main.bot_ops.add_client("v113")
            main.engine.reconcile()
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            cls.uid = main.add_upstream(type("R", (), {"json": lambda self: {
                "name": "Exit113", "config": "socks5://u:p@198.51.100.31:1080"}})())["id"]

    @classmethod
    def tearDownClass(cls):
        main.del_upstream(type("R", (), {"json": lambda self: {"replace": "direct"}})(), cls.uid)

    def setUp(self):
        self.tg = FakeTG()
        p = mock.patch.object(notify, "_post", self.tg)
        p.start()
        self.addCleanup(p.stop)
        tgbot.STATE = os.path.join(tempfile.mkdtemp(), "tgbot.json")
        self.bot = tgbot.Bot(main.store, main.bot_ops)
        self.c = cfg()
        self.upd(msg("/start"))

    def upd(self, *ups):
        self.tg.updates = list(ups)
        self.bot.poll_once(self.c, timeout=0)

    def press(self, data):
        self.upd(button(data, uid=len(self.tg.calls) + 2, mid=self.bot._panel_msgs[0]))
        return self.tg.screen()

    @staticmethod
    def cbs(p):
        return [b.get("callback_data") or b.get("url") for row in p["reply_markup"]["inline_keyboard"] for b in row]

    def test_menu_header(self):
        p = self.tg.screen()
        n = len(main.engine.clients)
        self.assertIn(f"Clients: {n}\n", p["text"])
        for line in ("Host:", "Panel version: " + main.VERSION, "Clients online:", "Total traffic:"):
            self.assertIn(line, p["text"])
        self.assertNotIn("remote", p["text"])

    def test_server_screen(self):
        p = self.press("sv")
        self.assertEqual(self.cbs(p), ["st", "ex", "m"])

    def test_status_lines(self):
        p = self.press("st")
        for line in ("Panel › Server", "Host:", "Panel version:", "AWG version:", "IPv4:", "IPv6:",
                     "Server uptime:", "RAM:", "Clients online:", "Traffic this month:", "Status:"):
            self.assertIn(line, p["text"])
        self.assertEqual(self.cbs(p)[-2:], ["st", "sv"])

    def test_exits_list_and_exit_screen(self):
        p = self.press("ex")
        cbs = self.cbs(p)
        self.assertEqual(cbs[0], "eo:direct")
        self.assertIn("eo:" + self.uid, cbs)
        self.assertNotIn("pr:" + self.uid, cbs)                     # проверка — на экране выхода
        self.assertEqual(cbs[-1], "sv")
        p = self.press("eo:" + self.uid)
        self.assertIn("Exit113", p["text"])
        self.assertEqual(self.cbs(p), ["pr:" + self.uid, "df:up:" + self.uid, "ex", "m"])
        p = self.press("pr:" + self.uid)
        self.assertIn("🔍", p["text"])
        self.assertIn("pr:" + self.uid, self.cbs(p))                # остаёмся на экране выхода
        p = self.press("df:up:" + self.uid)
        self.assertEqual(main.store.snapshot()["routing"]["default"], "up:" + self.uid)
        self.assertIn("Default exit", p["text"])
        p = self.press("df:direct")
        self.assertEqual(main.store.snapshot()["routing"]["default"], "direct")
        self.assertIn("pr:direct", self.cbs(p))

    def test_clients_new_client_first(self):
        p = self.press("cl:0")
        cbs = self.cbs(p)
        self.assertEqual(cbs[0], "add")
        self.assertTrue(cbs[1].startswith("c:"))
        self.assertEqual(cbs[-1], "m")

    def test_refresh_redraws_menu(self):
        mid = self.bot._panel_msgs[0]
        p = self.press("m")
        self.assertEqual(p.get("message_id"), mid)
        self.assertIn("Total traffic", p["text"])

    def test_menu_is_logo_photo(self):
        """Меню — фото с логотипом, информация в подписи; файл загружается один раз."""
        m, p = next((m, p) for m, p in reversed(self.tg.calls) if m == "sendPhoto")
        self.assertIn("multipart", p)                               # первый раз — сам файл
        self.assertIn("Total traffic", p["caption"])
        self.assertEqual(self.bot._st["photo"], self.bot._panel_msgs[0])
        self.upd(msg("/start", uid=50))
        p = self.tg.last("sendPhoto")
        self.assertNotIn("multipart", p)                            # дальше — по file_id
        self.assertTrue(p["photo"].startswith("photo-"))
        with open(tgbot.LOGO, "rb") as f:
            self.assertEqual(f.read(8), b"\x89PNG\r\n\x1a\n")

    def test_screens_edit_caption_under_logo(self):
        mid = self.bot._panel_msgs[0]
        self.press("sv")
        e = self.tg.last("editMessageCaption")
        self.assertEqual(e["message_id"], mid)
        self.assertIn("Server", e["caption"])
        self.press("m")
        self.assertEqual(self.tg.last("editMessageCaption")["message_id"], mid)

    def test_long_screen_goes_as_text(self):
        """Подпись к фото — до 1024 знаков: длинный экран приходит текстом, меню вернёт фото."""
        mid = self.bot._panel_msgs[0]
        self.bot._show(self.c, "x" * 1100, None, {"message_id": mid})
        self.assertEqual(len(self.tg.last("sendMessage")["text"]), 1100)
        self.assertEqual(self.tg.last("deleteMessage")["message_id"], mid)
        self.assertNotIn("photo", self.bot._st)
        n = self.tg.methods().count("sendPhoto")
        self.press("m")                                              # из текстового экрана — снова фото
        self.assertEqual(self.tg.methods().count("sendPhoto"), n + 1)

    def test_texts_in_every_language(self):
        keys = set(tgbot.TEXTS["en"])
        for lang, tx in tgbot.TEXTS.items():
            self.assertEqual(set(tx), keys, lang)
            for k in ("start", "st_title", "st_awg", "b_server", "b_probe_one", "b_make_default"):
                self.assertIn(k, tx, (lang, k))


if __name__ == "__main__":
    unittest.main()
