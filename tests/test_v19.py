"""1.9.0: управление панелью из Telegram (команды и кнопки) и QR-код конфига в PNG.

Telegram подменён: запросы бота складываются в список, ответы getUpdates задаёт тест.
Действия — настоящие, панели в демо-режиме (DRY_RUN).

python3 -m unittest discover tests
"""
import json
import os
import re
import struct
import sys
import tempfile
import time
import unittest
import zlib
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import main, notify, qr, tgbot  # noqa: E402
from app.i18n import Msg  # noqa: E402

TOKEN = "123456789:" + "A" * 35
CHAT = "424242"


class FakeTG:
    """Подмена notify._post: запоминает вызовы, getUpdates отдаёт заготовленные события."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.updates: list[dict] = []
        self.next_id = 100

    def __call__(self, token, method, data, ctype, timeout, via):
        p = json.loads(data) if ctype == "application/json" else self.form(data, ctype)
        self.calls.append((method, p))
        if method == "getUpdates":
            ups, self.updates = self.updates, []
            return ups
        if method in ("sendMessage", "sendPhoto", "sendDocument"):
            self.next_id += 1
            r = {"message_id": self.next_id}
            if method == "sendPhoto":
                r["photo"] = [{"file_id": "small"}, {"file_id": f"photo-{self.next_id}"}]
            return r
        return True

    @staticmethod
    def form(data, ctype):
        """Текстовые поля multipart (caption, reply_markup…); у файла — только размер."""
        p = {"multipart": len(data)}
        boundary = ctype.split("boundary=", 1)[1].encode()
        for part in data.split(b"--" + boundary):
            head, _, body = part.partition(b"\r\n\r\n")
            m = re.search(rb'name="([^"]+)"', head)
            if not m or b"filename=" in head:
                continue
            v = body[:-2].decode()
            p[m.group(1).decode()] = json.loads(v) if m.group(1) == b"reply_markup" else v
        return p

    # экраны меню: текстом или (1.13.0) подписью к фото с логотипом; подпись — в "text"
    SENT = ("sendMessage", "sendPhoto")
    EDITS = ("editMessageText", "editMessageCaption")

    def screens(self, kinds=SENT + EDITS):
        return [{**p, "text": p.get("text") or p.get("caption") or ""} for m, p in self.calls if m in kinds]

    def screen(self):
        return self.screens()[-1]

    def sent(self):
        return self.screens(self.SENT)

    def edited(self):
        return self.screens(self.EDITS)[-1]

    def methods(self):
        return [m for m, _ in self.calls]

    def texts(self):
        return [p.get("text") or p.get("caption") or "" for m, p in self.calls
                if m in ("sendMessage", "editMessageText", "sendPhoto", "editMessageCaption")]

    def last(self, method):
        return next(p for m, p in reversed(self.calls) if m == method)


def cfg(**kw):
    c = notify.defaults()
    c.update(enabled=True, token=TOKEN, chat_id=CHAT, lang="en", control=True)
    c.update(kw)
    return c


def msg(text, chat=CHAT, uid=1, **extra):
    m = {"message_id": 1, "chat": {"id": int(chat), "type": "private"}, "from": {"id": int(chat)},
         "date": int(time.time()), "text": text, **extra}
    return {"update_id": uid, "message": m}


def button(data, chat=CHAT, uid=1, mid=50):
    return {"update_id": uid, "callback_query": {"id": "q1", "data": data,
                                                 "message": {"message_id": mid, "chat": {"id": int(chat)}}}}


class QRTest(unittest.TestCase):
    def test_sizes_and_png(self):
        self.assertEqual(len(qr.matrix("hi")), 21)                 # версия 1
        self.assertGreater(len(qr.matrix("x" * 1000)), 4 * 7 + 17)  # длинный конфиг: версия больше 7
        data = qr.png("[Interface]\nPrivateKey = abc\n")
        self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))
        w, h = struct.unpack(">II", data[16:24])
        self.assertEqual(w, h)
        raw = zlib.decompress(data[data.index(b"IDAT") + 4:data.index(b"IEND") - 8])
        self.assertEqual(len(raw), h * (w + 1))

    def test_finder_and_format(self):
        g = qr.matrix("AWG Router")
        n = len(g)
        for x0, y0 in ((0, 0), (n - 7, 0), (0, n - 7)):     # три квадрата по углам
            self.assertTrue(all(g[y0][x0 + i] and g[y0 + 6][x0 + i] for i in range(7)))
            self.assertFalse(g[y0 + 1][x0 + 1])
            self.assertTrue(g[y0 + 3][x0 + 3])
        self.assertTrue(g[n - 8][8])                          # тёмный модуль у формата

    def test_too_big(self):
        with self.assertRaises(qr.QRTooBig):
            qr.matrix("x" * 3000)


class TextsTest(unittest.TestCase):
    def test_same_keys_and_placeholders(self):
        keys = set(tgbot.TEXTS["en"])
        for lang in notify.LANGS:
            self.assertEqual(set(tgbot.TEXTS[lang]), keys, lang)
            for k in keys:
                self.assertEqual(sorted(set(re.findall(r"\{\w+\}", tgbot.TEXTS[lang][k]))),
                                 sorted(set(re.findall(r"\{\w+\}", tgbot.TEXTS["en"][k]))), (lang, k))
        for k in tgbot.COMMANDS:
            self.assertIn("cmd_" + k, keys)

    def test_escape_and_sizes(self):
        self.assertEqual(tgbot.tr("en", "ok_on", name="<b>"), "▶️ “&lt;b&gt;” is on")
        self.assertEqual(tgbot.tr("en", "ok_on", False, name="<b>"), "▶️ “<b>” is on")
        self.assertEqual(tgbot.fmt_size(1.5 * tgbot.GB, "ru"), "1,5 ГБ")
        self.assertEqual(tgbot.fmt_size(300 * 1024 ** 2, "en"), "300 MB")
        self.assertEqual(tgbot.fmt_size(250 * tgbot.GB, "en"), "250 GB")

    def test_i18n_js_keys(self):
        """Новые ключи браузера есть на всех четырёх языках."""
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "static", "i18n.js"),
                  encoding="utf-8") as f:
            src = f.read()
        for key in ("tg.control", "tg.control_hint", "tg.bot_ok", "tg.bot_error", "tg.act_on", "tg.act_off",
                    "tg.act_days", "tg.act_gb", "tg.act_config", "tg.act_share", "tg.act_default",
                    "tg.act_backup", "tg.act_update", "tg.act_default_direct", "tg.control_title"):
            self.assertEqual(src.count(f'"{key}":'), 4, key)


class ButtonsTest(unittest.TestCase):
    def test_notify_buttons(self):
        b = tgbot.notify_buttons("client_expired", {"pk": "PK", "name": "Bob"}, "en")
        self.assertEqual([x["callback_data"] for x in b["inline_keyboard"][0]], ["d30:PK", "c:PK"])
        b = tgbot.notify_buttons("exit_down", {"uid": "u1", "name": "NL"}, "ru")
        self.assertEqual(b["inline_keyboard"][0][0]["callback_data"], "pr:u1")
        self.assertIn("NL", b["inline_keyboard"][0][0]["text"])
        self.assertEqual(tgbot.notify_buttons("update_available", {"version": "9.9.9"}, "en")
                         ["inline_keyboard"][0][0]["callback_data"], "up")
        self.assertIsNone(tgbot.notify_buttons("login_ok", {"ip": "1.2.3.4"}, "en"))
        for key, p in (("client_quota", {"pk": "P" * 44}), ("exit_down", {"uid": "u" * 8})):
            for row in tgbot.notify_buttons(key, p, "fa")["inline_keyboard"]:
                for x in row:
                    self.assertLessEqual(len(x["callback_data"].encode()), 64)

    def test_events_carry_refs(self):
        """Кнопки под уведомлением есть, только если управление включено."""
        n = notify.Notifier.__new__(notify.Notifier)
        n.q, n._sent, n._target_lost = __import__("queue").Queue(), {}, False
        n.host_fn = lambda st: "203.0.113.5"
        n.buttons_fn = tgbot.notify_buttons
        for control, want in ((True, True), (False, False)):
            n._sent.clear()
            st = {"settings": {"telegram": cfg(control=control)}}
            n.store = mock.Mock(snapshot=lambda st=st: st)
            n.engine_event(Msg("ev.client_quota", name="Bob", pk="PK", gb=10))
            item = n.q.get_nowait()
            self.assertEqual(bool(item[4]), want)
            self.assertNotIn("PK", item[2])       # ссылки — только в кнопках, не в тексте


class BotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.engine.reconcile()
        cls.pk = main.engine.clients[0]["public_key"]

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

    def test_other_chat_not_run(self):
        """Команды из чужого чата не выполняются; в личный чат бот отвечает «нет доступа»."""
        self.run_updates(msg("/status", chat="777"), button("off:" + self.pk, chat="777", uid=2))
        sent = [p for m, p in self.tg.calls if m == "sendMessage"]
        self.assertEqual([p["chat_id"] for p in sent], ["777"])
        self.assertIn("No access", sent[0]["text"])
        self.assertIn("<code>777</code>", sent[0]["text"])
        self.assertIn("No access", self.tg.last("answerCallbackQuery")["text"])
        self.assertEqual(self.bot._st["offset"], 3)
        self.assertTrue(any(c["public_key"] == self.pk and c["enabled"] for c in main.engine.clients))

    def test_old_message_and_offset_saved(self):
        self.run_updates(msg("/status", uid=7, date=int(time.time()) - 3600))
        self.assertNotIn("sendMessage", self.tg.methods())
        with open(tgbot.STATE) as f:
            self.assertEqual(json.load(f)["offset"], 8)
        self.assertIn("setMyCommands", self.tg.methods())
        self.assertEqual(self.tg.last("getUpdates")["offset"], 0)

    def test_status_and_clients(self):
        self.run_updates(msg("/status"), msg("/clients@my_bot", uid=2))
        status, clients = self.tg.texts()[-2:]
        self.assertIn("Panel version", status)
        self.assertIn("Clients", clients)
        cbs = [b["callback_data"] for row in self.tg.last("sendMessage")["reply_markup"]["inline_keyboard"]
               for b in row]
        self.assertTrue(any(d.startswith("c:") for d in cbs))
        self.assertIn("m", cbs)                           # 1.12.0: «‹ Меню» — назад в меню
        self.assertFalse({"ex"} & set(cbs))
        self.assertEqual(cbs[0], "add")                   # 1.13.0: «Новый клиент» — над списком

    def test_turn_off_and_on(self):
        self.run_updates(button("off:" + self.pk))
        main.engine.reconcile()
        self.assertFalse(next(c for c in main.engine.clients if c["public_key"] == self.pk)["enabled"])
        self.assertIn("is off", self.tg.last("answerCallbackQuery")["text"])
        self.run_updates(button("on:" + self.pk, uid=2))
        main.engine.reconcile()
        self.assertTrue(next(c for c in main.engine.clients if c["public_key"] == self.pk)["enabled"])
        self.assertTrue(any(e["msg"].key == "tg.act_on" for e in main.engine.events))

    def test_extend_and_quota(self):
        exp = int(time.time()) + 86400
        main.apply_limits(self.pk, exp, 5 * tgbot.GB, "month")
        self.addCleanup(lambda: main.apply_limits(self.pk, None, None, "month"))
        self.run_updates(button("d30:" + self.pk), button("g10:" + self.pk, uid=2))
        L = main.store.snapshot()["limits"][self.pk]
        self.assertEqual(L["expires"], exp + 30 * 86400)
        self.assertEqual(L["quota"], 15 * tgbot.GB)
        self.assertIn("15 GB", self.tg.last("answerCallbackQuery")["text"])

    def test_add_client_sends_qr_and_file(self):
        self.run_updates(msg("/add Telegram friend"))
        self.assertIn("sendPhoto", self.tg.methods())
        self.assertIn("sendDocument", self.tg.methods())
        self.assertTrue(any("vpn://" in t for t in self.tg.texts()))
        self.assertTrue(any(c["name"] == "Telegram friend" for c in main.engine.clients))

    def test_add_by_reply(self):
        self.run_updates(msg("/add"))
        ask = self.tg.last("sendMessage")
        self.assertTrue(ask["reply_markup"]["force_reply"])
        mid = self.tg.next_id
        self.run_updates(msg("Reply friend", uid=2, reply_to_message={"message_id": mid}))
        self.assertTrue(any(c["name"] == "Reply friend" for c in main.engine.clients))

    def test_route(self):
        self.run_updates(msg("/route 192.168.1.10"), msg("/route not a host!", uid=2))
        local, badtext = self.tg.texts()[-2:]
        self.assertIn("local address", local)
        self.assertIn("doesn't look like", badtext)

    def test_unknown_button_target(self):
        self.run_updates(button("c:" + "Z" * 43 + "="))
        self.assertIn("no longer exists", self.tg.last("answerCallbackQuery")["text"])

    def test_panel_message_edited_in_place(self):
        self.run_updates(msg("/clients"))
        mid = self.tg.next_id
        self.run_updates(button("cl:0", uid=2, mid=mid))
        self.assertEqual(self.tg.last("editMessageText")["message_id"], mid)

    def test_update_announced_after_restart(self):
        self.bot._st["update"] = {"to": main.VERSION, "t": time.time()}
        with mock.patch.object(main.bot_ops, "update_state", return_value={"state": "done"}):
            self.run_updates()
        self.assertIn(main.VERSION, self.tg.texts()[-1])
        self.assertNotIn("update", self.bot._st)


class SettingsTest(unittest.TestCase):
    def test_control_saved_and_restored(self):
        c = main._tg_draft({"token": TOKEN, "chat_id": CHAT, "control": True, "enabled": True})
        self.assertTrue(c["control"])
        self.assertFalse(notify.public_view(notify.defaults())["control"])
        from tests.test_api import good_state
        st = good_state()
        st["settings"]["telegram"]["control"] = True
        self.assertTrue(main.clean_backup_state(st)["settings"]["telegram"]["control"])


if __name__ == "__main__":
    unittest.main()
