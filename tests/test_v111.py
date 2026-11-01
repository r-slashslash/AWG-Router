"""1.11.0: короткое приветствие бота, новое меню (Панель вместо Маршрута), удаление клиента
из бота с подтверждением, ссылка на панель; резервная копия с паролем.

python3 -m unittest discover tests
"""
import base64
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import config, main, notify, tgbot, web  # noqa: E402
from tests.test_v19 import FakeTG, button, cfg, msg  # noqa: E402


class Req:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class BotTest(unittest.TestCase):
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
        return [p for m, p in self.tg.calls if m == "sendMessage"]

    def inline(self, p):
        return [b.get("callback_data") or b.get("url") for row in (p.get("reply_markup") or {}).get(
            "inline_keyboard", []) for b in row]

    # ---------------------------------------------------------------- меню
    def test_start_is_short(self):
        for lang, title in (("ru", "Пульт AWG Router"), ("en", "AWG Router remote")):
            self.c["lang"] = lang
            self.run_updates(msg("/start", uid=len(self.tg.calls) + 1))
            p = self.sent()[-1]
            self.assertEqual(p["text"].count("\n"), 1, p["text"])
            self.assertIn(title, p["text"])
            self.assertIn("/help", p["text"])
            self.assertIn("keyboard", p["reply_markup"])

    def test_menu_layout_in_every_language(self):
        rows = {"ru": [["📊 Состояние", "👥 Клиенты"], ["🌐 Выходы", "➕ Новый клиент"], ["🖥 Панель", "💾 Копия"]]}
        for i, lang in enumerate(tgbot.TEXTS):
            self.c["lang"] = lang
            self.run_updates(msg("/start", uid=i + 1))
            kbd = [[b["text"] for b in row] for row in self.sent()[-1]["reply_markup"]["keyboard"]]
            self.assertEqual([len(r) for r in kbd], [2, 2, 2])
            flat = [t for r in kbd for t in r]
            self.assertNotIn(tgbot.TEXTS[lang]["b_route"], flat)
            self.assertIn(tgbot.TEXTS[lang]["b_panel"], flat)
            if lang in rows:
                self.assertEqual(kbd, rows[lang])

    def test_help_lists_commands(self):
        self.run_updates(msg("/help"))
        text = self.sent()[-1]["text"]
        for cmd in ("/status", "/clients", "/add", "/exits", "/backup", "/panel"):
            self.assertIn(cmd, text)

    def test_old_route_button_still_understood(self):
        self.run_updates(msg("🧭 Маршрут"))                  # клавиатура 1.10.5 у людей ещё на экране
        self.assertTrue(self.sent()[-1]["reply_markup"]["force_reply"])

    def test_every_language_has_new_keys(self):
        en = set(tgbot.TEXTS["en"])
        for lang, tx in tgbot.TEXTS.items():
            self.assertEqual(set(tx), en, lang)

    # ---------------------------------------------------------------- панель
    def test_panel_link(self):
        self.run_updates(msg("🖥 Panel"))
        p = self.sent()[-1]
        url = main.panel_url()
        self.assertIn(url, p["text"])
        self.assertEqual(self.inline(p), [url])
        self.assertTrue(p["disable_web_page_preview"])        # Telegram не ходит по секретному адресу сам

    def test_panel_link_button_refused(self):
        real = self.tg

        def picky(token, method, data, ctype, timeout, via):
            if method == "sendMessage" and b'"url"' in data:
                raise notify.NotifyError("Bad Request: BUTTON_URL_INVALID")
            return real(token, method, data, ctype, timeout, via)
        with mock.patch.object(notify, "_post", picky):
            self.run_updates(msg("/panel"))
        p = self.sent()[-1]
        self.assertIn(main.panel_url(), p["text"])
        self.assertNotIn("reply_markup", p)

    def test_panel_ssh_mode(self):
        with mock.patch.object(config, "PANEL_HOST", "127.0.0.1"):
            self.run_updates(msg("/panel"))
        p = self.sent()[-1]
        self.assertIn("ssh -N -L", p["text"])
        self.assertIn("127.0.0.1", p["text"])
        self.assertEqual(self.inline(p), [])                   # кнопка-ссылка на 127.0.0.1 бесполезна

    # ---------------------------------------------------------------- удаление
    def _new_client(self, name):
        pk = main.bot_ops.add_client(name)
        self.assertIsNotNone(self.bot._client_wait(pk))
        return pk

    def test_delete_asks_first(self):
        pk = self._new_client("Удалить меня")
        self.run_updates(button("c:" + pk))
        self.assertIn("dl:" + pk, self.inline(self.sent()[-1]))
        self.run_updates(button("dl:" + pk, uid=2))
        ask = [p for m, p in self.tg.calls if m in ("sendMessage", "editMessageText")][-1]
        self.assertIn("Удалить меня", ask["text"])
        self.assertEqual(self.inline(ask), ["dlgo:" + pk, "c:" + pk])
        self.assertTrue(any(x["public_key"] == pk for x in main.engine.clients))   # ещё не удалён
        self.run_updates(button("c:" + pk, uid=3))                                # «Отмена» — снова карточка
        self.assertTrue(any(x["public_key"] == pk for x in main.engine.clients))

    def test_delete(self):
        pk = self._new_client("Gone soon")
        main.ensure_share(pk)
        self.run_updates(button("dlgo:" + pk))
        self.assertFalse(any(x["public_key"] == pk for x in main.engine.clients))
        st = main.store.snapshot()
        self.assertNotIn(pk, st.get("limits", {}))
        self.assertFalse(any(v.get("pk") == pk for v in st.get("shares", {}).values()))
        toast = self.tg.last("answerCallbackQuery")["text"]
        self.assertIn("Gone soon", toast)
        self.assertIn("deleted", toast)
        self.assertIn("tg.act_delete", [getattr(e["msg"], "key", "") for e in main.engine.events])
        self.run_updates(button("dlgo:" + pk, uid=2))         # второй раз — «такого клиента больше нет»
        self.assertIn("no longer", self.tg.last("answerCallbackQuery")["text"].lower())

    def test_callback_data_fits(self):
        pk = "A" * 43 + "="
        self.assertLessEqual(len(("dlgo:" + pk).encode()), 64)


@unittest.skipUnless(shutil.which("openssl"), "openssl")
class BackupPasswordTest(unittest.TestCase):
    def test_encrypted_download_opens_with_restore(self):
        r = main.get_backup_encrypted(Req({"password": "password1"}))
        data = base64.b64decode(r["data"])
        self.assertTrue(data.startswith(notify.ENC_MAGIC))
        self.assertNotIn(b"awg-router-backup", data)
        b = main.decrypt_backup(Req({"data": r["data"], "password": "password1"}))["backup"]
        self.assertEqual(b["format"], "awg-router-backup")
        self.assertIn("state", b)
        self.assertIn("host", r)

    def test_password_rules(self):
        for pw in ("", "short", "x" * 129):
            with self.assertRaises(web.HTTPError):
                main.get_backup_encrypted(Req({"password": pw}))

    def test_wrong_password(self):
        r = main.get_backup_encrypted(Req({"password": "password1"}))
        with self.assertRaises(web.HTTPError):
            main.decrypt_backup(Req({"data": r["data"], "password": "password2"}))


class UiTextsTest(unittest.TestCase):
    def test_new_keys_in_all_languages(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "static", "i18n.js")) as f:
            js = f.read()
        for key in ("bk.pw", "bk.pw_repeat", "bk.pw_hint", "bk.saved_enc", "app.btn", "app.scan",
                    "app.android", "app.ios", "tg.act_delete"):
            self.assertEqual(js.count(f'"{key}":'), 4, key)


if __name__ == "__main__":
    unittest.main()
