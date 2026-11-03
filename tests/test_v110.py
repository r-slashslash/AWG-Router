"""1.10.0: кнопка «Маршрут» в меню бота, постоянная кнопка «Меню» внизу экрана и уведомление
о первом подключении нового клиента.

python3 -m unittest discover tests
"""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import limits, main, notify, tgbot  # noqa: E402
from tests.test_v19 import FakeTG, button, cfg, msg  # noqa: E402


class BotUiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.engine.reconcile()

    def setUp(self):
        self.tg = FakeTG()
        p = mock.patch.object(notify, "_post", self.tg)
        p.start()
        self.addCleanup(p.stop)
        tgbot.STATE = os.path.join(tempfile.mkdtemp(), "tgbot.json")
        self.bot = tgbot.Bot(main.store, main.bot_ops)
        self.c = cfg()

    def run_updates(self, *ups):
        self.tg.updates = list(ups)
        self.bot.poll_once(self.c, timeout=0)

    def sent(self):
        return self.tg.sent()

    def menu(self):
        """Кнопки меню из последнего сообщения: [[(текст, данные или ссылка)]]."""
        p = self.sent()[-1]
        return [[(b["text"], b.get("callback_data") or b.get("url")) for b in row]
                for row in p["reply_markup"]["inline_keyboard"]]

    def test_start_opens_full_menu(self):
        """/start — меню кнопками в одном сообщении (1.12.0), без клавиатуры внизу экрана."""
        self.run_updates(msg("/start"))
        self.assertIn("Total traffic", self.sent()[-1]["text"])
        self.assertNotIn("keyboard", self.sent()[-1]["reply_markup"])
        m = self.menu()
        self.assertEqual([[t for t, _ in row] for row in m],
                         [["🗄 Server", "👥 Clients"], ["🖥 Panel", "💾 Backup"], ["🔄 Refresh"]])   # 1.13.0
        self.assertEqual(m[1][0][1], main.panel_url())          # «Панель» — сразу ссылка
        self.assertEqual(m[2][0][1], "m")                        # «Обновить» — заново рисует меню
        self.c["lang"] = "ru"
        self.run_updates(msg("/start", uid=2))
        self.assertEqual(self.menu()[0][0][0], "🗄 Сервер")

    def test_keyboard_buttons(self):
        """Надписи старой клавиатуры (1.10–1.11) понятны, а сама клавиатура убирается один раз."""
        self.bot._st["kbd"] = "en"
        self.run_updates(msg("👥 Clients"))
        removed = [p for m, p in self.tg.calls if m == "sendMessage" and (p.get("reply_markup") or {}).get("remove_keyboard")]
        self.assertEqual(len(removed), 1)
        self.assertIn("deleteMessage", self.tg.methods())       # служебное сообщение сразу удалено
        self.assertNotIn("kbd", self.bot._st)
        self.assertIn("Clients", self.sent()[-1]["text"])
        self.run_updates(msg("📊 Состояние", uid=2))          # надпись на другом языке тоже понятна
        self.assertIn("Panel version", self.sent()[-1]["text"])
        self.run_updates(msg("🧭 Route", uid=3))
        self.assertTrue(self.sent()[-1]["reply_markup"]["force_reply"])
        self.run_updates(msg("192.168.0.5", uid=4, reply_to_message={"message_id": self.tg.next_id}))
        self.assertIn("local address", self.sent()[-1]["text"])
        n = len([p for m, p in self.tg.calls if m == "sendMessage" and (p.get("reply_markup") or {}).get("remove_keyboard")])
        self.assertEqual(n, 1)

    def test_inline_route_button_still_works(self):
        self.run_updates(button("rt"))
        self.assertTrue(self.sent()[-1]["reply_markup"]["force_reply"])

    def test_old_menu_button(self):
        self.run_updates(msg("☰ Меню"))           # кнопка из 1.10.0
        self.assertIn("Total traffic", self.sent()[-1]["text"])
        self.assertIn("inline_keyboard", self.sent()[-1]["reply_markup"])

    def test_menu_button_cancels_question(self):
        self.run_updates(msg("/add"))
        self.run_updates(msg("☰ Menu", uid=2))
        self.assertIsNone(self.bot._ask)
        before = len(main.engine.clients)
        self.run_updates(msg("Not a name", uid=3))
        self.assertEqual(len(main.engine.clients), before)

    def test_keyboard_removed_when_control_off(self):
        self.run_updates(msg("/help"))
        self.bot._st["kbd"] = "en"                  # клавиатура осталась от 1.11.0
        self.bot._drop_commands(cfg(control=False))
        self.assertIn("deleteMyCommands", self.tg.methods())
        self.assertTrue(self.sent()[-1]["reply_markup"]["remove_keyboard"])
        self.assertNotIn("kbd", self.bot._st)
        n = len(self.tg.calls)
        self.bot._drop_commands(cfg(control=False))  # второй раз — ничего не шлёт
        self.assertEqual(len(self.tg.calls), n)

class FirstSeenTest(unittest.TestCase):
    def setUp(self):
        main.engine.reconcile()
        self.events = []
        p = mock.patch.object(main.engine, "event",
                              lambda lvl, m: self.events.append(m) if m.key == "ev.client_first" else None)
        p.start()
        self.addCleanup(p.stop)
        self.pk = main.engine.srv.add_client("First timer")
        # список клиентов без reconcile: тот сам вызвал бы first_seen раньше теста
        main.engine.clients = main.engine.srv.list_clients(main.engine.target)
        self.addCleanup(lambda: main.engine.srv.delete_client(self.pk)
                        if any(c["public_key"] == self.pk for c in main.engine.clients) else None)

    def client(self):
        return next(c for c in main.engine.clients if c["public_key"] == self.pk)

    def test_waits_then_fires_once(self):
        self.assertIn(self.pk, main.store.snapshot()["await_first"])
        self.client()["live"] = {"handshake": 0}
        limits.first_seen(main.engine)
        self.assertEqual(self.events, [])
        self.client()["live"] = {"handshake": int(time.time())}
        limits.first_seen(main.engine)
        limits.first_seen(main.engine)
        self.assertEqual([m.key for m in self.events], ["ev.client_first"])
        self.assertEqual(self.events[0].p["pk"], self.pk)
        self.assertNotIn(self.pk, main.store.snapshot().get("await_first", {}))

    def test_old_or_deleted_is_dropped(self):
        self.client()["live"] = {"handshake": 0}
        limits.first_seen(main.engine, now=time.time() + limits.FIRST_WAIT + 10)
        self.assertNotIn(self.pk, main.store.snapshot().get("await_first", {}))
        self.assertEqual(self.events, [])
        pk2 = main.engine.srv.add_client("Gone")
        main.engine.srv.delete_client(pk2)
        self.assertNotIn(pk2, main.store.snapshot().get("await_first", {}))

    def test_notification_and_button(self):
        self.assertEqual(notify.ENGINE_EVENTS["ev.client_first"], ("clients", "client_first"))
        b = tgbot.notify_buttons("client_first", {"pk": self.pk}, "ru")
        self.assertEqual(b["inline_keyboard"][0][0]["callback_data"], "c:" + self.pk)
        self.assertIn("First timer", notify.render("en", "client_first", name="First timer"))


if __name__ == "__main__":
    unittest.main()
