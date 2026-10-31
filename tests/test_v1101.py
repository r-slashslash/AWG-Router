"""1.10.1–1.10.2: бот молчал на команды при сбитых часах сервера; «нет доступа» в чужом чате; webhook.

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

    def test_deny_once_in_private_only(self):
        self.run_updates(msg("/status", chat="777"), msg("/clients", chat="777", uid=2))
        to777 = [p for m, p in self.tg.calls if m == "sendMessage" and p["chat_id"] == "777"]
        self.assertEqual(len(to777), 1)                       # не чаще раза в 10 минут
        self.assertTrue(to777[0]["reply_markup"]["remove_keyboard"])
        g = msg("/status", chat="-1009", uid=3)
        g["message"]["chat"]["type"] = "supergroup"
        self.run_updates(g)                                   # в группе — молча
        self.assertFalse(any(p["chat_id"] == "-1009" for m, p in self.tg.calls if m == "sendMessage"))
        self.run_updates(msg("hello", chat="778", uid=4))     # не команда — не отвечаем
        self.assertFalse(any(p["chat_id"] == "778" for m, p in self.tg.calls if m == "sendMessage"))

    def test_webhook_removed_once(self):
        self.assertTrue(self.bot._drop_webhook(cfg()))
        self.assertFalse(self.bot._drop_webhook(cfg()))
        self.assertEqual(self.tg.methods().count("deleteWebhook"), 1)

    def test_loop_drops_webhook_and_polls(self):
        """getUpdates отвечает «webhook is active» — бот снимает webhook и опрашивает снова."""
        calls = {"n": 0}

        def post(token, method, data, ctype, timeout, via):
            if method == "getUpdates":
                calls["n"] += 1
                if calls["n"] == 1:
                    raise notify.NotifyError("Conflict: can't use getUpdates method while webhook is active")
                self.bot.stop_ev.set()
            return self.tg(token, method, data, ctype, timeout, via)
        main.store.mutate(lambda st: st["settings"].__setitem__("telegram", cfg()))
        with mock.patch.object(notify, "_post", post):
            self.bot._loop()
        self.assertIn("deleteWebhook", self.tg.methods())
        self.assertEqual(calls["n"], 2)
        self.assertEqual(self.bot.state, "ok")


class PanelTest(unittest.TestCase):
    def test_i18n(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "static", "i18n.js"), encoding="utf-8") as f:
            src = f.read()
        for key in ("tg.bot_last", "tg.bot_skew"):
            self.assertEqual(src.count(f'"{key}":'), 4, key)
        for key in ("tg.bot_foreign", "tg.bot_use_chat"):       # подсказки о чужом чате убраны из панели
            self.assertNotIn(f'"{key}":', src)


if __name__ == "__main__":
    unittest.main()
