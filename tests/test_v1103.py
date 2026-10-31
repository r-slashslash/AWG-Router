"""1.10.3: управление из Telegram работает и при выключенных уведомлениях.

Раньше бот слушал команды, только если включены и «Принимать команды», и «Присылать
уведомления»; без уведомлений он молчал, а панель не показывала его состояние.

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

from app import main, notify, tgbot, web  # noqa: E402
from tests.test_v19 import CHAT, TOKEN, FakeTG, cfg, msg  # noqa: E402


class ControlWithoutNotificationsTest(unittest.TestCase):
    def setUp(self):
        self.tg = FakeTG()
        p = mock.patch.object(notify, "_post", self.tg)
        p.start()
        self.addCleanup(p.stop)
        tgbot.STATE = os.path.join(tempfile.mkdtemp(), "tgbot.json")
        self.bot = tgbot.Bot(main.store, main.bot_ops)

    def run_loop_once(self, c):
        main.store.mutate(lambda st: st["settings"].__setitem__("telegram", c))
        self.tg.updates = [msg("/start")]

        def post(*a):
            r = self.tg(*a)
            if a[1] == "getUpdates":
                self.bot.stop_ev.set()       # один круг опроса
            return r
        with mock.patch.object(notify, "_post", post), mock.patch.object(self.bot.wake, "wait"):
            self.bot._loop()

    def test_polls_with_notifications_off(self):
        self.run_loop_once(cfg(enabled=False, control=True))
        self.assertIn("getUpdates", self.tg.methods())
        self.assertTrue(any("AWG Router remote" in t for t in self.tg.texts()))
        self.assertEqual(self.bot.state, "ok")

    def test_off_without_control(self):
        self.bot.stop_ev.clear()
        main.store.mutate(lambda st: st["settings"].__setitem__("telegram", cfg(enabled=True, control=False)))
        with mock.patch.object(self.bot.wake, "wait", side_effect=lambda t: self.bot.stop_ev.set()):
            self.bot._loop()
        self.assertNotIn("getUpdates", self.tg.methods())
        self.assertEqual(self.bot.state, "off")

    def test_control_needs_token_and_chat(self):
        main.store.mutate(lambda st: st["settings"].__setitem__("telegram", notify.defaults()))
        req = mock.Mock(json=lambda: {"enabled": False, "control": True, "chat_id": ""})
        with self.assertRaises(web.HTTPError) as cm:
            main.put_telegram(req)
        self.assertEqual(cm.exception.detail.key, "err.tg_incomplete")
        req = mock.Mock(json=lambda: {"enabled": False, "control": True, "token": TOKEN, "chat_id": CHAT})
        main.put_telegram(req)
        c = notify.cfg_of(main.store.snapshot())
        self.assertEqual((c["enabled"], c["control"]), (False, True))

    def test_panel_shows_state_without_notifications(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "static", "app.js"), encoding="utf-8") as f:
            src = f.read()
        self.assertIn("${c.control && S.tg_bot ? viewBotState(S.tg_bot)", src)

    def test_logs_helper_does_not_hang_in_a_pipe(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "install.sh"), encoding="utf-8") as f:
            src = f.read()
        line = next(ln for ln in src.splitlines() if ln.strip().startswith("logs)"))
        self.assertIn("[ -t 1 ]", line)                      # -f только в терминале
        self.assertIn("docker logs --tail 2000 awg-router 2>&1", line)


class NoDuplicateMenuTest(unittest.TestCase):
    """1.10.4: главное меню — только на клавиатуре внизу, под сообщениями — только их кнопки."""

    def setUp(self):
        main.engine.reconcile()
        self.tg = FakeTG()
        p = mock.patch.object(notify, "_post", self.tg)
        p.start()
        self.addCleanup(p.stop)
        tgbot.STATE = os.path.join(tempfile.mkdtemp(), "tgbot.json")
        self.bot = tgbot.Bot(main.store, main.bot_ops)

    def inline(self, p):
        return [b["callback_data"] for row in (p.get("reply_markup") or {}).get("inline_keyboard", []) for b in row]

    def test_screens_have_only_their_buttons(self):
        for i, cmd in enumerate(("/status", "/clients", "/exits")):
            self.tg.updates = [msg(cmd, uid=i + 1)]
            self.bot.poll_once(cfg(), timeout=0)
            cbs = self.inline(self.tg.last("sendMessage"))
            menu = {"m", "add", "rt", "bk", "cl:0"} | ({"ex"} if cmd != "/exits" else set())  # «ex» в выходах — «Обновить»
            self.assertFalse(menu & set(cbs), (cmd, cbs))
        self.tg.updates = [msg("/status", uid=9)]
        self.bot.poll_once(cfg(), timeout=0)
        self.assertEqual(self.inline(self.tg.last("sendMessage")), ["st"])

    def test_start_is_short_help_is_full(self):
        self.tg.updates = [msg("/start"), msg("/help", uid=2)]
        self.bot.poll_once(cfg(), timeout=0)
        start, full = [p for m, p in self.tg.calls if m == "sendMessage"][-2:]
        self.assertNotIn("/clients", start["text"])
        self.assertIn("/clients", full["text"])
        for p in (start, full):
            self.assertIn("keyboard", p["reply_markup"])
            self.assertNotIn("inline_keyboard", p["reply_markup"])

    def test_old_menu_button_shows_no_second_menu(self):
        self.tg.updates = [{"update_id": 1, "callback_query": {"id": "q", "data": "m",
                            "message": {"message_id": 5, "chat": {"id": int(CHAT)}}}}]
        self.bot.poll_once(cfg(), timeout=0)
        self.assertEqual(self.inline(self.tg.last("sendMessage")), [])


if __name__ == "__main__":
    unittest.main()
