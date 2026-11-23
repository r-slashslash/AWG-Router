"""1.24.0: картинки бота — главное меню и «Состояние» с цифрами (app/tgcard.py, атлас tools/tgcard_atlas.py)."""
import json
import os
import re
import struct
import sys
import tempfile
import time
import unittest
import zlib
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import notify, tgbot, tgcard  # noqa: E402
from tests.test_v19 import FakeTG, button, cfg, msg  # noqa: E402
from app import panel  # noqa: E402
from app.api import telegram  # noqa: E402

MENU = {"host": "203.0.113.5", "exits": (3, 3), "version": "1.24.0", "clients": 4, "online": 2,
        "traffic": ("44,5", "u_gb")}
STATUS = {"ok": True, "version": "1.24.0", "latest": None, "awg": "3.1", "engine": ("kernel", "3.1.20260812"),
          "v4": "203.0.113.5", "v4_state": "ok", "v6": None,
          "dns": {"state": "on", "listen": "10.8.1.1", "encrypt": "doh", "queries": 12345, "cached": 8210},
          "uptime": 12 * 86400 + 4 * 3600, "memory": (("412", "u_mb"), ("961", "u_mb")), "online": 2, "total": 4,
          "month": ("12,3", "u_gb")}


def decode(png: bytes):
    """PNG этого модуля (RGB, 8 бит, фильтр 0) → (ширина, высота, строки точек)."""
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    pos, idat, w = 8, b"", None
    while pos < len(png):
        n = struct.unpack(">I", png[pos:pos + 4])[0]
        kind, data = png[pos + 4:pos + 8], png[pos + 8:pos + 8 + n]
        if kind == b"IHDR":
            w, h, depth, ctype = struct.unpack(">IIBB", data[:10])
            assert (depth, ctype) == (8, 2)
        elif kind == b"IDAT":
            idat += data
        assert zlib.crc32(kind + data) == struct.unpack(">I", png[pos + 8 + n:pos + 12 + n])[0]
        pos += 12 + n
    raw = zlib.decompress(idat)
    stride = w * 3 + 1
    assert len(raw) == h * stride
    assert all(raw[y * stride] == 0 for y in range(h))
    return w, h, [raw[y * stride + 1:(y + 1) * stride] for y in range(h)]


def count(rows, color, box, tol=40):
    """Сколько точек в прямоугольнике (x0, y0, x1, y1) близки к цвету."""
    x0, y0, x1, y1 = box
    n = 0
    for y in range(y0, y1):
        r = rows[y]
        for x in range(x0, x1):
            if sum(abs(r[x * 3 + i] - color[i]) for i in range(3)) <= tol:
                n += 1
    return n


def ink(rows, box):
    """Точек не белого цвета в прямоугольнике."""
    x0, y0, x1, y1 = box
    return sum(1 for y in range(y0, y1) for x in range(x0, x1) if rows[y][x * 3:x * 3 + 3] != b"\xff\xff\xff")


MENU_TOP = (tgcard.MENU_H - tgcard.HEAD - 6 * tgcard.ROW_H) // 2 + tgcard.HEAD


def row_box(i, x0=0, x1=tgcard.W, top=MENU_TOP):
    y = top + i * tgcard.ROW_H
    return (x0, y + 4, x1, y + tgcard.ROW_H - 2)


class AtlasTest(unittest.TestCase):
    def test_atlas_matches_texts(self):
        """Тексты картинок поменяли — атлас нужно нарисовать заново: python3 tools/tgcard_atlas.py."""
        at = tgcard.Atlas()
        need = tgcard.needed(tgbot.TEXTS)
        missing = sorted(set(need) - set(at.items))
        self.assertEqual(missing, [], "run: python3 tools/tgcard_atlas.py")
        self.assertEqual(at.head["spec"], tgcard.spec_sum(tgbot.TEXTS), "run: python3 tools/tgcard_atlas.py")

    def test_atlas_is_small(self):
        self.assertLess(os.path.getsize(tgcard.ATLAS), 1024 * 1024)

    def test_picture_texts_in_every_language(self):
        keys = [k for k in tgbot.TEXTS["en"] if k.startswith(("pc_", "ps_"))]
        self.assertGreaterEqual(len(keys), 25)
        for k in keys:
            want = set(re.findall(r"\{\w+\}", tgbot.TEXTS["en"][k]))
            for lang in tgcard.LANGS:
                self.assertEqual(set(re.findall(r"\{\w+\}", tgbot.TEXTS[lang][k])), want, (lang, k))
        for lang in tgcard.LANGS:
            self.assertNotIn("st_host", tgbot.TEXTS[lang])          # «Хост» убран из «Состояния»

    def test_no_atlas_or_word_is_card_error(self):
        with self.assertRaises(tgcard.CardError):
            tgcard.Atlas(os.path.join(tempfile.mkdtemp(), "none.atlas"))
        at = tgcard.Atlas()
        del at.items["lab|en|Exits online"]
        with self.assertRaises(tgcard.CardError):
            tgcard.menu(tgbot.TEXTS["en"], "en", MENU, at)


class CardTest(unittest.TestCase):
    def menu(self, lang="en", **kw):
        return decode(tgcard.menu(tgbot.TEXTS[lang], lang, {**MENU, **kw}))

    def status(self, lang="en", **kw):
        return decode(tgcard.status(tgbot.TEXTS[lang], lang, {**STATUS, **kw}))

    def test_sizes_in_every_language(self):
        for lang in tgcard.LANGS:
            w, h, _ = self.menu(lang)
            self.assertEqual((w, h), (1280, 800), lang)
            w, h, _ = self.status(lang)
            self.assertEqual((w, h), (1280, 1150), lang)

    def test_fast_enough_for_one_vcpu(self):
        t = time.perf_counter()
        tgcard.menu(tgbot.TEXTS["fa"], "fa", MENU)
        tgcard.status(tgbot.TEXTS["fa"], "fa", STATUS)
        self.assertLess(time.perf_counter() - t, 2.0)              # здесь ~50 мс; запас на медленный CI

    def test_icons_and_values_mirror_in_persian(self):
        """fa — справа налево: значки у правого края, значения у левого; en — наоборот."""
        _, _, en = self.menu("en")
        _, _, fa = self.menu("fa")
        icon_l = row_box(0, tgcard.PAD_X, tgcard.PAD_X + 44)
        icon_r = row_box(0, tgcard.W - tgcard.PAD_X - 44, tgcard.W - tgcard.PAD_X)
        self.assertGreater(count(en, tgcard.BLUE, icon_l), 50)
        self.assertEqual(count(en, tgcard.BLUE, icon_r), 0)
        self.assertGreater(count(fa, tgcard.BLUE, icon_r), 50)
        self.assertEqual(count(fa, tgcard.BLUE, icon_l), 0)
        left, right = row_box(2, tgcard.PAD_X, 400), row_box(2, tgcard.W - 400, tgcard.W - tgcard.PAD_X)
        self.assertGreater(count(en, tgcard.INK, right), 100)        # версия у правого края
        self.assertGreater(count(fa, tgcard.INK, left), 100)         # у левого

    def test_exits_color(self):
        """«Выходы онлайн»: все работают — зелёным, часть — оранжевым, ни одного — красным, выходов нет — «нет»."""
        box = row_box(1, 900, tgcard.W - tgcard.PAD_X)
        _, _, rows = self.menu(exits=(3, 3))
        self.assertGreater(count(rows, tgcard.GREEN_TEXT, box), 100)
        _, _, rows = self.menu(exits=(2, 3))
        self.assertGreater(count(rows, tgcard.ORANGE, box), 100)
        self.assertEqual(count(rows, tgcard.GREEN_TEXT, box), 0)
        _, _, rows = self.menu(exits=(0, 3))
        self.assertGreater(count(rows, tgcard.RED, box), 100)
        _, _, rows = self.menu(exits=(0, 0))
        for color in (tgcard.GREEN_TEXT, tgcard.ORANGE, tgcard.RED):
            self.assertEqual(count(rows, color, box), 0)
        self.assertGreater(count(rows, tgcard.GRAY, box), 50)

    def test_long_address_shrinks_and_is_cut(self):
        p = tgcard.Painter(tgcard.Atlas(), "en", tgcard.MENU_H)
        room = 600
        segs = p.fit("nl-ams-1.vpn.example.org", tgcard.HOST_STYLES, room)
        self.assertNotEqual(segs[0].style, "val")                    # мельче, но целиком
        self.assertNotIn("…", segs[0].pieces[0][1])
        self.assertLessEqual(p.width(segs), room)
        segs = p.fit("a" * 30 + ".very-long-subdomain.vpn.example.org", tgcard.HOST_STYLES, room)
        self.assertTrue(segs[0].pieces[0][1].endswith("…"))
        self.assertLessEqual(p.width(segs), room)
        # и на картинке адрес не налезает на название: между ними — пустая полоса
        _, _, rows = self.menu(host="2001:db8:85a3:8d3:1319:8a2e:370:7348")
        label = p.width([tgcard.Seg("lab", tgcard.GRAY, [("p", "VPN server")])])
        x = round(tgcard.PAD_X + 44 + tgcard.GAP + label)
        self.assertEqual(ink(rows, row_box(0, x + 4, x + tgcard.VALUE_GAP - 4)), 0)

    def test_not_ascii_host_is_question_marks(self):
        self.assertEqual(tgcard._ascii("пример.рф"), "??????.??")
        self.menu(host="пример.рф")                                  # рисуется, а не падает

    def test_status_pill_and_problems(self):
        """«Работает» — зелёная пометка; сервер недоступен — красная; есть новая версия и DNS не отвечает — строки
        под названиями, синяя и оранжевая."""
        _, _, ok = self.status()
        head = (tgcard.W // 2, tgcard.PAD_Y, tgcard.W - tgcard.PAD_X, tgcard.PAD_Y + 64)
        self.assertGreater(count(ok, tgcard.PILL[True][0], head, tol=6), 2000)
        _, _, bad = self.status(ok=False, latest="1.25.0", engine=("go",), v6="2001:db8::5",
                                dns={"state": "on", "listen": "10.8.1.1", "encrypt": "doh", "upstream_error": True})
        self.assertGreater(count(bad, tgcard.PILL[False][0], head, tol=6), 2000)
        self.assertEqual(count(bad, tgcard.PILL[True][0], head, tol=6), 0)
        top = tgcard.PAD_Y + tgcard.HEAD
        sub = lambda i: row_box(i, tgcard.PAD_X + 40, 700, top)
        self.assertGreater(count(bad, tgcard.BLUE, sub(0)), 100)      # «available 1.25.0»
        self.assertGreater(count(bad, tgcard.ORANGE, sub(5)), 100)    # «DNS servers don't answer»

    def test_status_missing_values(self):
        """Чего сервер не сообщил (память, время работы, движок, DNS выключен) — «—» или «off», а не ошибка."""
        self.status(memory=None, uptime=None, engine=None, dns=None, v4=None, v4_state="failed", awg="")
        self.status(lang="fa", dns={"state": "error"})
        self.status(lang="zh", uptime=59, online=0, total=0)


class FileTG(FakeTG):
    """FakeTG, который запоминает и сам файл из multipart (картинку)."""

    @staticmethod
    def form(data, ctype):
        p = FakeTG.form(data, ctype)
        boundary = ctype.split("boundary=", 1)[1].encode()
        for part in data.split(b"--" + boundary):
            head, _, body = part.partition(b"\r\n\r\n")
            if b"filename=" in head:
                p["file"] = body[:-2]
                p["field"] = re.search(rb'name="([^"]+)"', head).group(1).decode()
        return p


class BotPictureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        panel.engine.reconcile()
        if not panel.engine.clients:
            telegram.bot_ops.add_client("v124")
            panel.engine.reconcile()

    def setUp(self):
        self.tg = FileTG()
        p = mock.patch.object(notify, "_post", self.tg)
        p.start()
        self.addCleanup(p.stop)
        tgbot.STATE = os.path.join(tempfile.mkdtemp(), "tgbot.json")
        self.bot = tgbot.Bot(panel.store, telegram.bot_ops)
        self.c = cfg()
        self.upd(msg("/start"))

    def upd(self, *ups):
        self.tg.updates = list(ups)
        self.bot.poll_once(self.c, timeout=0)

    def press(self, data):
        self.upd(button(data, uid=len(self.tg.calls) + 2, mid=self.bot._panel_msgs[0]))

    def test_menu_is_picture_without_caption(self):
        p = self.tg.last("sendPhoto")
        self.assertEqual(p["caption"], "")
        self.assertEqual(p["field"], "photo")
        self.assertEqual(decode(p["file"])[:2], (1280, 800))
        self.assertEqual(self.bot._st["pic"], "menu")
        self.assertTrue(self.bot._st["menu_pic"]["fid"].startswith("photo-"))

    def test_status_replaces_picture_and_menu_comes_back(self):
        """«Состояние» меняет картинку в том же сообщении; следующий экран («‹ Сервер») возвращает картинку меню
        по file_id, без новой загрузки, а текст экрана — в подписи."""
        mid = self.bot._panel_msgs[0]
        fid = self.bot._st["menu_pic"]["fid"]
        self.press("st")
        p = self.tg.last("editMessageMedia")
        self.assertEqual(p["message_id"], str(mid))
        self.assertEqual(json.loads(p["media"])["media"], "attach://card")
        self.assertEqual(decode(p["file"])[:2], (1280, 1150))
        self.assertEqual(self.bot._st["pic"], "status")
        self.assertEqual(self.bot._panel_msgs, [mid])
        self.press("sv")
        p = self.tg.last("editMessageMedia")
        self.assertNotIn("file", p)
        self.assertEqual(p["media"]["media"], fid)
        self.assertIn("Server", p["media"]["caption"])
        self.assertEqual(self.bot._st["pic"], "menu")
        n = self.tg.methods().count("editMessageMedia")
        self.press("cl:0")                                          # дальше — подпись под той же картинкой
        self.assertEqual(self.tg.methods().count("editMessageMedia"), n)
        self.assertEqual(self.tg.last("editMessageCaption")["message_id"], mid)

    def test_refresh_with_same_numbers_keeps_picture(self):
        self.press("m")
        self.assertNotIn("editMessageMedia", self.tg.methods())
        self.assertEqual(self.tg.methods()[-2], "editMessageCaption")

    def test_refresh_after_status_draws_menu(self):
        self.press("st")
        self.press("m")
        p = self.tg.last("editMessageMedia")
        self.assertEqual(decode(p["file"])[:2], (1280, 800))
        self.assertEqual(self.bot._st["pic"], "menu")

    def test_note_is_the_caption(self):
        self.bot.show_menu(self.c, None, "💾 Backup sent")
        self.assertEqual(self.tg.last("sendPhoto")["caption"], "💾 Backup sent")

    def test_status_command_sends_picture(self):
        self.upd(msg("/status", uid=40))
        p = self.tg.last("sendPhoto")
        self.assertEqual(decode(p["file"])[:2], (1280, 1150))
        self.assertEqual(self.bot._st["pic"], "status")
        self.assertEqual(self.bot._panel_msgs, [self.tg.next_id])

    def test_no_picture_falls_back_to_text(self):
        with mock.patch.object(tgcard, "status", side_effect=OSError("disk")):
            self.press("st")
        p = self.tg.screen()
        self.assertIn("Panel version", p["text"])
        self.assertNotIn("Host:", p["text"])

    def test_edit_refused_sends_new_message(self):
        """Сообщение уже не изменить (старше 48 часов) — картинка приходит новым сообщением."""
        orig = self.tg.__call__

        def tg(token, method, data, ctype, timeout, via):
            if method == "editMessageMedia":
                raise notify.NotifyError("Bad Request: message can't be edited")
            return orig(token, method, data, ctype, timeout, via)
        with mock.patch.object(notify, "_post", tg):
            self.press("st")
        p = self.tg.last("sendPhoto")
        self.assertEqual(decode(p["file"])[:2], (1280, 1150))


class MenuInfoTest(unittest.TestCase):
    def bot(self, **ops):
        b = tgbot.Bot.__new__(tgbot.Bot)
        ups = [{"id": "a", "enabled": True}, {"id": "b", "enabled": True}, {"id": "c", "enabled": False},
               {"id": "d", "enabled": True}]
        base = dict(status=lambda: {"server_traffic": {"total_rx": 3 * tgbot.GB, "total_tx": tgbot.GB}},
                    clients=lambda: [], snapshot=lambda: {"upstreams": ups},
                    health=lambda uid: {"healthy": uid in ("a", "c", "d")}, over_quota=lambda u: u["id"] == "d",
                    panel=lambda: {"host": "panel.example"}, version="1.24.0", vpn_host=lambda: "203.0.113.9")
        base.update(ops)
        b.ops = SimpleNamespace(**base)
        return b

    def test_exits_online_of_enabled(self):
        """Онлайн — включённый, рабочий и не исчерпавший лимит; выключенный не считается совсем."""
        d = self.bot()._menu_info()
        self.assertEqual(d["exits"], (1, 3))
        self.assertEqual(d["bytes"], 4 * tgbot.GB)

    def test_vpn_server_is_client_address(self):
        self.assertEqual(self.bot()._menu_info()["host"], "203.0.113.9")
        self.assertEqual(self.bot(vpn_host=lambda: "")._menu_info()["host"], "panel.example")

    def test_real_ops_give_client_host(self):
        st = panel.store.snapshot()
        self.assertEqual(telegram.bot_ops.vpn_host(), panel.engine.srv.client_host(st))


class EditPhotoTest(unittest.TestCase):
    def test_upload_and_file_id(self):
        tg = FileTG()
        with mock.patch.object(notify, "_post", tg):
            notify.edit_photo("t", "1", 5, b"PNG", "cap", {"inline_keyboard": []})
            notify.edit_photo("t", "1", 5, None, "cap2", None, fid="F")
        m, p = tg.calls[0]
        self.assertEqual((m, p["field"], p["file"]), ("editMessageMedia", "card", b"PNG"))
        self.assertEqual(json.loads(p["media"]), {"type": "photo", "media": "attach://card", "caption": "cap",
                                                  "parse_mode": "HTML"})
        m, p = tg.calls[1]
        self.assertEqual(p["media"]["media"], "F")
        self.assertNotIn("reply_markup", p)


if __name__ == "__main__":
    unittest.main()
