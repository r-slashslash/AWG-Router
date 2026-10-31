"""1.10.1: бот молчал на команды при сбитых часах сервера; панель показывает команды из чужого чата.

python3 -m unittest discover tests
"""
import email.utils
import json
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

from app import main, notify, tgbot, tgreq  # noqa: E402
from tests.test_v19 import CHAT, FakeTG, button, cfg, msg  # noqa: E402


class ClockTest(unittest.TestCase):
    def tearDown(self):
        notify.clock_skew = 0.0

    def test_note_date(self):
        now = 1_800_000_000
        notify.note_date(email.utils.formatdate(now - 3600, usegmt=True), now=now)
        self.assertAlmostEqual(notify.clock_skew, 3600, delta=1)
        notify.note_date("not a date", now=now)            # мусор не сбивает уже известное
        self.assertAlmostEqual(notify.clock_skew, 3600, delta=1)
        notify.note_date(None)
        self.assertAlmostEqual(notify.clock_skew, 3600, delta=1)

    def test_direct_and_via_read_date(self):
        class Resp:
            status = 200
            headers = {"Date": email.utils.formatdate(time.time() - 7200, usegmt=True)}

            def read(self):
                return b'{"ok":true,"result":[]}'

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        with mock.patch("urllib.request.urlopen", return_value=Resp()):
            notify._post_direct("https://api.telegram.org/x", b"{}", "application/json", 5)
        self.assertAlmostEqual(notify.clock_skew, 7200, delta=2)
        out = json.dumps({"status": 200, "body": "{}", "date": email.utils.formatdate(time.time() - 60,
                                                                                         usegmt=True)})
        with mock.patch("subprocess.run", return_value=mock.Mock(stdout=out.encode(), stderr=b"")):
            notify._post_via((1, 0x2001), "https://api.telegram.org/x", b"{}", "application/json", 5)
        self.assertAlmostEqual(notify.clock_skew, 60, delta=2)

    def test_tgreq_prints_date(self):
        with mock.patch.object(tgreq, "request", return_value=(200, b"{}", "Sun, 01 Nov 2026 00:00:00 GMT")), \
                mock.patch("sys.stdin", mock.Mock(buffer=mock.Mock(read=lambda: b'{"url":"https://x/y"}\n'))), \
                mock.patch("sys.argv", ["tgreq.py", "0"]), mock.patch("builtins.print") as pr:
            tgreq.main()
        self.assertEqual(json.loads(pr.call_args[0][0])["date"], "Sun, 01 Nov 2026 00:00:00 GMT")


class BotTest(unittest.TestCase):
    def setUp(self):
        self.tg = FakeTG()
        p = mock.patch.object(notify, "_post", self.tg)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(lambda: setattr(notify, "clock_skew", 0.0))
        tgbot.STATE = os.path.join(tempfile.mkdtemp(), "tgbot.json")
        self.bot = tgbot.Bot(main.store, main.bot_ops)

    def run_updates(self, *ups):
        self.tg.updates = list(ups)
        self.bot.poll_once(cfg(), timeout=0)

    def test_server_clock_ahead(self):
        """Часы сервера на час впереди: свежая команда не считается устаревшей."""
        notify.clock_skew = 3600
        self.run_updates(msg("/status", date=int(time.time() - 3600)))
        self.assertTrue(any("Panel version" in t for t in self.tg.texts()))
        self.assertEqual(self.bot.view()["skew"], 3600)

    def test_really_old_still_skipped(self):
        notify.clock_skew = 0
        self.run_updates(msg("/status", date=int(time.time() - 3600)))
        self.assertNotIn("sendMessage", self.tg.methods())
        self.assertIsNone(self.bot.view()["skew"])

    def test_foreign_chat_reported(self):
        u = msg("/status", chat="777")
        u["message"]["chat"].update(type="private", first_name="Ivan")
        self.run_updates(u)
        self.assertNotIn("sendMessage", self.tg.methods())
        ign = self.bot.view()["ignored"]
        self.assertEqual((ign["chat"], ign["title"]), ("777", "Ivan"))

    def test_foreign_button_and_chatter(self):
        self.run_updates(msg("hello", chat="778"))           # просто текст — не команда, не отмечаем
        self.assertIsNone(self.bot.view()["ignored"])
        self.run_updates(button("st", chat="779", uid=2))
        self.assertEqual(self.bot.view()["ignored"]["chat"], "779")

    def test_old_ignored_entry_expires(self):
        self.bot.ignored = {"t": time.time() - 2 * 86400, "chat": "1", "title": "", "type": "private"}
        self.assertIsNone(self.bot.view()["ignored"])


class PanelTest(unittest.TestCase):
    def test_switch_chat_keeps_other_settings(self):
        main.store.mutate(lambda st: st["settings"].__setitem__("telegram", {
            **notify.defaults(), "enabled": True, "token": "123456789:" + "A" * 35, "chat_id": "-100",
            "control": True, "lang": "ru"}))
        c = main._tg_draft({"chat_id": CHAT})
        self.assertEqual((c["chat_id"], c["control"], c["lang"], c["enabled"]), (CHAT, True, "ru", True))

    def test_i18n(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "static", "i18n.js"), encoding="utf-8") as f:
            src = f.read()
        for key in ("tg.bot_last", "tg.bot_foreign", "tg.bot_use_chat", "tg.bot_use_chat_done", "tg.bot_skew"):
            self.assertEqual(src.count(f'"{key}":'), 4, key)


if __name__ == "__main__":
    unittest.main()
