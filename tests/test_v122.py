"""1.22.0: приглашение клиента в бота и личная ссылка сразу, супергруппа и два бота, фразы вместо кодов в боте,
2FA, большой список сетей, название сервера во вкладке, кнопка «день/ночь», своя коробка сервера при обновлении.

python3 -m unittest discover tests
"""
import array
import ipaddress
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import tracemalloc
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import checks, config, lists, notify, socks, tgbot, uitext, web  # noqa: E402
from app.i18n import Msg  # noqa: E402
from app.store import CLIENT_BOT, Store  # noqa: E402
from app import panel  # noqa: E402
from app.api import auth, backup, clients, state, telegram  # noqa: E402
from tests.test_v19 import CHAT, TOKEN, FakeTG, cfg, msg  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


def code(fn):
    try:
        fn()
    except web.HTTPError as e:
        return e.code, getattr(e.detail, "key", e.detail)
    return None


class Req:
    def __init__(self, body=None, ip="198.51.100.7"):
        self._b, self.client_ip, self.headers, self.authed = body or {}, ip, {}, False

    def json(self, limit=None):
        return self._b

    def cookie(self, *a, **kw):
        pass


class FakeBot(FakeTG):
    """Telegram с именем бота (getMe) и ошибкой на заданный метод."""

    def __init__(self):
        super().__init__()
        self.fail: dict = {}

    def __call__(self, token, method, data, ctype, timeout, via):
        if method in self.fail:
            err = self.fail[method]
            if callable(err):
                err = err(json.loads(data) if ctype == "application/json" else self.form(data, ctype))
            if err:
                self.calls.append((method, json.loads(data) if ctype == "application/json" else self.form(data, ctype)))
                raise err
        if method == "getMe":
            self.calls.append((method, {}))
            return {"id": 1, "username": "awgr_test_bot"}
        return super().__call__(token, method, data, ctype, timeout, via)


def bot_setup(tc, **kw):
    tc.tg = FakeBot()
    p = mock.patch.object(notify, "_post", tc.tg)
    p.start()
    tc.addCleanup(p.stop)
    tgbot.STATE = os.path.join(tempfile.mkdtemp(), "tgbot.json")
    tc.bot = tgbot.Bot(panel.store, telegram.bot_ops)
    tc.c = cfg(**kw)


# ======================================================================== личная ссылка и приглашение
class ShareAtCreateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        panel.engine.reconcile()

    def test_new_client_has_link_and_renew_replaces_it(self):
        pk = clients.add_user(Req({"name": "share-new"}))["public_key"]
        panel.engine.reconcile()
        toks = [k for k, v in panel.store.snapshot()["shares"].items() if v["pk"] == pk]
        self.assertEqual(len(toks), 1)                                   # ссылка — сразу при создании
        self.assertTrue(checks.TOKEN_RE.match(toks[0]))
        self.assertEqual(clients.share_pk(toks[0]), pk)
        r = clients.renew_share(Req(), pk)
        new = [k for k, v in panel.store.snapshot()["shares"].items() if v["pk"] == pk]
        self.assertEqual(len(new), 1)
        self.assertNotEqual(new[0], toks[0])                              # прежняя больше не открывается
        self.assertIsNone(clients.share_pk(toks[0]))
        self.assertTrue(r["url"].endswith("/s/" + new[0]))
        self.assertEqual(code(lambda: clients.renew_share(Req(), "A" * 43 + "=")), (404, "err.not_found"))

    def test_route_does_not_clash_with_create(self):
        """Ключ клиента бывает с «/» ({pk:path}), поэтому «обновить» — свой адрес, а не …/shares/<pk>/renew."""
        src = read("app", "api", "clients.py")
        self.assertIn('@app.post("/api/shares-renew/{pk:path}")', src)
        self.assertIn('"shares-renew/"', read("app", "static", "js", "clients.js"))

    def test_invite_needs_bot_name(self):
        tok = "x" * 24
        with mock.patch.object(telegram.bot, "username", return_value=None):
            self.assertIsNone(clients.bot_invite(tok))
        with mock.patch.object(telegram.bot, "username", return_value="my_bot"):
            self.assertEqual(clients.bot_invite(tok), "https://t.me/my_bot?start=" + tok)
            self.assertIsNone(clients.bot_invite("bad token!"))
            view = state._state_view()
        row = next(r for r in view["clients"] if r.get("share_url"))
        self.assertEqual(row["bot_url"], "https://t.me/my_bot?start=" + row["share_url"].rsplit("/", 1)[1])

    def test_share_info_without_config(self):
        pk = clients.add_user(Req({"name": "share-info"}))["public_key"]
        panel.engine.reconcile()
        tok = next(k for k, v in panel.store.snapshot()["shares"].items() if v["pk"] == pk)
        d = clients.share_info(tok, config=False)
        self.assertNotIn("name", d)                                   # имя клиента ему не показывается (1.22.0)
        self.assertIsNone(d["config"])
        cfg = clients.share_info(tok)["config"]
        if cfg:                                                       # в демо у клиента панели ключ есть
            self.assertNotIn("name", cfg)
            self.assertRegex(cfg["filename"], r"^\d{8}\.conf$")
        self.assertIsNone(clients.share_info("y" * 24))


class ClientBotTest(unittest.TestCase):
    """Клиент по приглашению видит в боте только своё; команды панели из его чата не выполняются."""

    @classmethod
    def setUpClass(cls):
        panel.engine.reconcile()
        cls.pk = clients.add_user(Req({"name": "bot-client"}))["public_key"]
        panel.engine.reconcile()

    def setUp(self):
        bot_setup(self, clients=True)
        self.tok = next(k for k, v in panel.store.snapshot()["shares"].items() if v["pk"] == self.pk)

    def send(self, *ups):
        self.tg.updates = list(ups)
        self.bot._client_t.clear()
        self.bot.poll_once(self.c, timeout=0)

    def to(self, chat):
        return [p for m, p in self.tg.calls if m in ("sendMessage", "editMessageText", "sendPhoto", "sendDocument")
                and str(p.get("chat_id")) == chat]

    def test_invite_binds_chat_and_shows_card(self):
        start = msg("/start " + self.tok, chat="5005")
        start["message"]["from"]["language_code"] = "ru"
        self.send(start)
        out = self.to("5005")
        self.assertIn("Ваш доступ", out[-1]["text"])
        self.assertNotIn("bot-client", out[-1]["text"])
        self.assertIn("Трафик", out[-1]["text"])                         # язык — как у Telegram клиента
        data = [b["callback_data"] for row in out[-1]["reply_markup"]["inline_keyboard"] for b in row]
        self.assertEqual(data, ["me:r", "me:c"])
        self.assertEqual(self.bot._st["links"]["5005"]["pk"], self.pk)
        # обычная фраза — снова карточка; команда панели — тоже только карточка
        self.send(msg("/clients", chat="5005", uid=2))
        self.assertIn("Your access", self.to("5005")[-1]["text"])
        self.assertFalse(any("👥" in p.get("text", "") for p in self.to("5005")))

    def test_bad_and_renewed_invitation(self):
        self.send(msg("/start " + "z" * 24, chat="5006"))
        self.assertIn("didn't work", self.to("5006")[-1]["text"])
        self.send(msg("hello", chat="5007", uid=2))
        self.assertIn("<code>5007</code>", self.to("5007")[-1]["text"])  # номер чата — для владельца
        self.send(msg("/start " + self.tok, chat="5008", uid=3))
        clients.renew_share(Req(), self.pk)                               # «Обновить» в окне клиента
        self.send(msg("hi", chat="5008", uid=4))
        self.assertIn("no longer works", self.to("5008")[-1]["text"])
        self.assertNotIn("5008", self.bot._st["links"])

    def test_stranger_told_once_in_10_minutes(self):
        """Проверка 1.22.0 (Н8): незнакомцу (чат без приглашения) бот отвечает не чаще раза в 10 минут, как «нет
        доступа» до 1.22.0, — а не на каждое сообщение. Приглашение, открытое следом, работает сразу."""
        for uid in range(1, 4):
            self.send(msg("hello", chat="5010", uid=uid))
            self.send(msg("/start " + "z" * 24, chat="5010", uid=uid + 10))
        self.assertEqual(len(self.to("5010")), 1)
        self.bot._denied["5010"] -= tgbot.DENY_EVERY                          # прошло 10 минут
        self.send(msg("hello", chat="5010", uid=20))
        self.assertEqual(len(self.to("5010")), 2)
        self.send(msg("/start " + self.tok, chat="5010", uid=21))
        self.assertIn("5010", self.bot._st["links"])
        self.assertGreater(len(self.to("5010")), 2)                            # карточка — сразу

    def test_config_button_throttled(self):
        self.send(msg("/start " + self.tok, chat="5009"))
        q = {"update_id": 2, "callback_query": {"id": "q", "data": "me:c", "from": {"id": 5009},
                                                 "message": {"message_id": 9, "chat": {"id": 5009, "type": "private"}}}}
        self.send(q)
        self.send({**q, "update_id": 3})
        methods = [m for m, p in self.tg.calls if str(p.get("chat_id")) == "5009"]
        self.assertEqual(methods.count("sendDocument"), 1)                 # второй раз — «подождите»
        self.assertTrue(any("wait" in p.get("text", "") for p in self.to("5009")))

    def test_admin_button_from_client_chat_ignored(self):
        self.send(msg("/start " + self.tok, chat="5010"))
        q = {"update_id": 2, "callback_query": {"id": "q", "data": "off:" + self.pk, "from": {"id": 5010},
                                                 "message": {"message_id": 9, "chat": {"id": 5010, "type": "private"}}}}
        self.send(q)
        self.assertTrue(any(c["public_key"] == self.pk and c["enabled"] for c in panel.engine.clients))

    def test_clients_only_polls_without_control(self):
        c = cfg(control=False, clients=True)
        panel.store.mutate(lambda st: st["settings"].__setitem__("telegram", c))
        self.addCleanup(lambda: panel.store.mutate(lambda st: st["settings"].pop("telegram", None)))
        self.tg.updates = [msg("/start " + self.tok, chat="5011")]

        def post(*a):
            r = self.tg(*a)
            if a[1] == "getUpdates":
                self.bot.stop_ev.set()
            return r
        with mock.patch.object(notify, "_post", post), mock.patch.object(self.bot.wake, "wait"):
            self.bot._loop()
        self.assertIn("getUpdates", self.tg.methods())
        self.assertIn("Your access", self.to("5011")[-1]["text"])
        self.assertNotIn("bot-client", self.to("5011")[-1]["text"])     # имя клиента в его чате не нужно
        self.assertNotIn("setMyCommands", self.tg.methods())             # без управления — меню панели нет
        self.assertEqual(self.bot.username(), "awgr_test_bot")

    def test_commands_only_in_owner_chat(self):
        c = cfg(control=True, clients=True)
        self.bot._st["cmds"] = "123456789:AA|en"                          # меню до 1.22.0 — у всех чатов
        self.bot._set_commands(c)
        self.assertEqual(self.tg.calls[0], ("deleteMyCommands", {}))
        p = self.tg.last("setMyCommands")
        self.assertEqual(p["scope"], {"type": "chat", "chat_id": int(CHAT)})
        self.bot._set_commands(cfg(control=False, clients=True))          # управление выключили
        self.assertEqual(self.tg.last("deleteMyCommands"), {"scope": {"type": "chat", "chat_id": int(CHAT)}})

    def test_menu_refused_does_not_stop_the_bot(self):
        """Глубокая проверка 1.23.0: канал в «Chat ID» — Telegram отказывает в меню команд для канала, и раньше
        исключение из setMyCommands обрывало опрос: бот не работал совсем. Отказ Telegram — без меню, но дальше;
        сбой сети — снова на следующем опросе."""
        c = cfg(control=True, clients=True)
        self.tg.fail["setMyCommands"] = notify.NotifyError("Bad Request: can't change commands in channel chats", code=400)
        self.bot._set_commands(c)                                         # не бросает
        self.assertTrue(self.bot._st["cmds"].startswith("v2|"))           # и не повторяет каждый опрос
        self.bot._st["cmds"] = ""
        self.tg.fail["setMyCommands"] = notify.NotifyError("timeout", net=True)
        with self.assertRaises(notify.NotifyError):
            self.bot._set_commands(c)

    def test_language(self):
        for code_, lang in (("ru", "ru"), ("zh-hans", "zh"), ("fa", "fa"), ("de", "en"), (None, "en")):
            self.assertEqual(tgbot.client_lang({"language_code": code_}), lang)


# ======================================================================== супергруппа, два бота, фразы
class SupergroupTest(unittest.TestCase):
    def setUp(self):
        bot_setup(self)
        panel.store.mutate(lambda st: st["settings"].__setitem__("telegram", cfg(chat_id="-100")))
        self.addCleanup(lambda: panel.store.mutate(lambda st: st["settings"].pop("telegram", None)))

    def test_send_follows_new_chat(self):
        def upgraded(p):
            if str(p.get("chat_id")) == "-100":
                return notify.NotifyError("Bad Request: group chat was upgraded to a supergroup chat",
                                          migrate_to="-1009999")
            return None
        self.tg.fail["sendMessage"] = upgraded
        notify.send(TOKEN, "-100", "hi")
        self.assertEqual(self.tg.last("sendMessage")["chat_id"], "-1009999")
        self.assertEqual(panel.store.snapshot()["settings"]["telegram"]["chat_id"], "-1009999")

    def test_service_message(self):
        c = cfg(chat_id="-100")
        m = {"update_id": 1, "message": {"message_id": 1, "chat": {"id": -100, "type": "group"},
                                         "migrate_to_chat_id": -1005555, "date": int(time.time())}}
        self.bot.handle(m, c)
        self.assertEqual(panel.store.snapshot()["settings"]["telegram"]["chat_id"], "-1005555")

    def test_other_chat_not_migrated(self):
        self.assertFalse(panel.notifier.migrate("-777", "-1001"))
        self.assertEqual(panel.store.snapshot()["settings"]["telegram"]["chat_id"], "-100")


class MigrateAnswerTest(unittest.TestCase):
    def test_parse_migrate_answer(self):
        body = json.dumps({"ok": False, "error_code": 400, "description": "upgraded",
                           "parameters": {"migrate_to_chat_id": -1001234}}).encode()
        with mock.patch.object(notify, "_post_direct", return_value=(400, body)):
            with self.assertRaises(notify.NotifyError) as cm:
                notify._post(TOKEN, "sendMessage", b"{}", "application/json", 5, "direct")
        self.assertEqual(cm.exception.migrate_to, "-1001234")
        self.assertEqual(cm.exception.code, 400)


class ConflictTest(unittest.TestCase):
    def test_two_panels_one_bot(self):
        bot_setup(self)
        panel.store.mutate(lambda st: st["settings"].__setitem__("telegram", cfg()))
        self.addCleanup(lambda: panel.store.mutate(lambda st: st["settings"].pop("telegram", None)))
        self.tg.fail["getUpdates"] = notify.NotifyError(
            "Conflict: terminated by other getUpdates request; make sure that only one bot instance is running",
            code=409)
        with mock.patch.object(self.bot.wake, "wait", side_effect=lambda t: self.bot.stop_ev.set()):
            self.bot._loop()
        self.assertEqual(self.bot.state, "error")
        self.assertEqual(self.bot.error.key, "err.tg_conflict")


class BotPhrasesTest(unittest.TestCase):
    def test_panel_messages_become_phrases(self):
        self.assertEqual(uitext.text("en", Msg("err.wrong_password")), "Wrong password")
        self.assertEqual(uitext.text("xx", Msg("err.wrong_password")), "Wrong password")    # нет языка — en
        self.assertEqual(uitext.text("en", Msg("no.such.key")), "no.such.key")
        self.assertIn("10", uitext.text("ru", Msg("err.panel_name_long", max=10)))
        self.assertEqual(tgbot.Bot._err(Msg("err.wrong_password"), "ru"), "Неверный пароль")
        d = uitext.dicts()
        for lang in uitext.LANGS:
            self.assertGreater(len(d[lang]), 500, lang)
            self.assertIn("n.clients", d[lang])                          # формы числа — тоже

    def test_no_bare_keys_in_bot_errors(self):
        self.assertNotIn("m.key", read("app", "tgbot.py").split("def _err", 1)[1].split("def ", 1)[0])


# ======================================================================== 2FA
class TwoFactorTest(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        for name in ("TOTP_FILE",):
            if hasattr(auth.totp, name):
                p = mock.patch.object(auth.totp, name, os.path.join(d, "totp.json"))
                p.start()
                self.addCleanup(p.stop)
        auth._fails.clear()
        auth._code_fails.clear()
        self.addCleanup(auth._code_fails.clear)
        self.addCleanup(auth._fails.clear)
        p = mock.patch.object(auth.time, "sleep")
        p.start()
        self.addCleanup(p.stop)
        self.events = []
        p = mock.patch.object(auth.notifier, "event", lambda kind, key, **kw: self.events.append(key))
        p.start()
        self.addCleanup(p.stop)
        self.secret = auth.totp.new_secret()
        auth.totp.save({"secret": self.secret, "since": time.time(), "last_step": 0})
        self.addCleanup(auth.totp.save, None)

    def test_wrong_codes_from_many_addresses(self):
        for i in range(auth.CODE_MAX):
            r = code(lambda i=i: auth.login(Req({"password": auth.PASSWORD, "code": "000000"},
                                                ip=f"203.0.113.{i}")))
            self.assertEqual(r, (403, "err.wrong_code"))
        self.assertEqual(self.events.count("login_code_wrong"), auth.CODE_MAX - 1)
        self.assertEqual(self.events[-1], "login_code_locked")
        good = auth.totp.code_at(self.secret, int(time.time() // auth.totp.STEP))
        r = code(lambda: auth.login(Req({"password": auth.PASSWORD, "code": good}, ip="192.0.2.99")))
        self.assertEqual(r, (429, "err.code_locked"))                      # закрыто для всех адресов
        with mock.patch.object(auth.time, "time", return_value=time.time() + auth.CODE_WINDOW + 1):
            self.assertFalse(auth._code_locked())

    def test_wrong_password_is_not_a_code_failure(self):
        code(lambda: auth.login(Req({"password": "nope", "code": "000000"})))
        self.assertEqual(auth._code_fails, [])

    def test_enable_needs_password(self):
        auth.totp.save(None)
        auth._totp_pending.clear()
        auth._totp_pending.update(secret=self.secret, t=time.time())
        good = auth.totp.code_at(self.secret, int(time.time() // auth.totp.STEP))
        self.assertEqual(code(lambda: auth.totp_enable(Req({"code": good}))), (403, "err.wrong_password"))
        self.assertIsNone(auth.totp.load())
        self.assertIsNone(code(lambda: auth.totp_enable(Req({"code": good, "password": auth.PASSWORD}))))
        self.assertTrue(auth.totp.load())
        self.assertIn('password', read("app", "static", "js", "settings.js").split("totp/enable", 1)[1][:40])


# ======================================================================== большой список сетей
class NetsTest(unittest.TestCase):
    def test_same_as_collapse(self):
        rnd = random.Random(5)
        for _ in range(150):
            nets = [f"{ipaddress.IPv4Address(rnd.getrandbits(32))}/{rnd.choice([8, 16, 24, 31, 32, rnd.randint(0, 32)])}"
                    for _ in range(rnd.randint(0, 50))]
            ref = [str(n) for n in ipaddress.collapse_addresses(ipaddress.IPv4Network(x, strict=False) for x in nets)]
            got = lists.parse_cidrs("\n".join(nets) + "\n# x\nbad\n2001:db8::/32\n")
            self.assertEqual([str(n) for n in got], ref)
            self.assertEqual(list(got.cidrs()), ref)
            self.assertEqual(len(got), len(ref))
            self.assertEqual(got.addresses, sum(ipaddress.IPv4Network(r).num_addresses for r in ref))
        self.assertEqual(list(lists.parse_cidrs("0.0.0.0/0").cidrs()), ["0.0.0.0/0"])
        self.assertEqual(list(lists.parse_cidrs("255.255.255.255").cidrs()), ["255.255.255.255/32"])
        self.assertFalse(lists.parse_cidrs("# пусто\n"))

    def test_merge_asn_parts(self):
        m = lists.merge([lists.parse_cidrs("10.0.0.0/25"), lists.parse_cidrs("10.0.0.128/25\n1.1.1.1")])
        self.assertEqual(list(m.cidrs()), ["1.1.1.1/32", "10.0.0.0/24"])

    def test_memory_of_big_list(self):
        """300 тысяч строк разбирались объектами IPv4Network: ~300 МБ. Теперь — числа: десятки мегабайт."""
        rnd = random.Random(1)
        text = "\n".join(f"{rnd.randint(1, 223)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.0/24"
                         for _ in range(200_000))
        tracemalloc.start()
        try:
            nets = lists.parse_nets(text, min_prefix=lists.WIDE_MIN)
            n = sum(1 for _ in nets.cidrs())
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertGreater(n, 150_000)
        self.assertLess(peak, 60 * 1024 * 1024, peak)
        self.assertIsInstance(nets.starts, array.array)

    def test_url_list_saved_as_text(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(lists, "LISTS_DIR", d), \
                mock.patch.object(lists, "_fetch", return_value="1.2.3.0/24\n1.2.2.0/24\n9.9.9.9\n"):
            r = lists.refresh({"id": "lurl", "kind": "url", "source": "https://example.com/a.txt"})
            self.assertEqual(lists.load_cidrs("lurl"), ["1.2.2.0/23", "9.9.9.9/32"])
        self.assertEqual((r["count"], r["addresses"]), (2, 513))


# ======================================================================== название сервера, тема, колонка
class PanelNameTest(unittest.TestCase):
    def test_check(self):
        self.assertEqual(checks.panel_name("  Германия   1 "), "Германия 1")
        self.assertEqual(checks.panel_name(None), "")
        for bad in (5, "a\x00b", "x" * 41):
            self.assertIsNotNone(code(lambda bad=bad: checks.panel_name(bad)))

    def test_saved_and_kept_on_restore(self):
        state.put_settings(Req({"panel_name": "Frankfurt"}))
        self.assertEqual(panel.store.snapshot()["settings"]["panel_name"], "Frankfurt")
        new = panel.store.snapshot()
        new["settings"]["panel_name"] = "из копии"
        st = panel.store.snapshot()
        backup.restore_state(st, new)
        self.assertEqual(st["settings"]["panel_name"], "Frankfurt")         # название — этого сервера
        state.put_settings(Req({"panel_name": ""}))
        self.assertNotIn("panel_name", panel.store.snapshot()["settings"])

    def test_title_in_browser(self):
        core = read("app", "static", "js", "core.js")
        self.assertIn("S.settings.panel_name) || (S.panel && S.panel.ip)", core)
        self.assertIn("renderTitle();", core)


class ThemeTest(unittest.TestCase):
    def test_theme_script_before_styles(self):
        for page, pre in (("index.html", "static/"), ("share.html", "/s/assets/")):
            html = read("app", "static", page)
            self.assertLess(html.index(f'<script src="{pre}theme.js">'), html.index(f'href="{pre}app.css"'), page)
        self.assertIn("theme.js", panel.app.public_files)
        css = read("app", "static", "app.css")
        self.assertNotIn("prefers-color-scheme", css)                        # тему решает theme.js
        self.assertIn(':root[data-theme="dark"]', css)
        self.assertIn('id="theme-btn"', read("app", "static", "index.html"))
        for f in (("js", "clients.js"), ("share.js",)):
            self.assertIn("themeDark()", read("app", "static", *f))         # QR — по выбранной теме

    def test_mobile_right_column(self):
        css = read("app", "static", "app.css")
        self.assertRegex(css, r'td\[data-m="right"\] \{[^}]*justify-self: end; text-align: end;')


class HevTest(unittest.TestCase):
    def test_log_to_stderr(self):
        """Новые hev по умолчанию не пишут никуда, а причину отказа панель берёт из его вывода."""
        self.assertIn("  log-file: stderr", socks.hev_config("awgr1", 1, "192.0.2.1", {"port": 1080}))
        self.assertRegex(read("Dockerfile"), r"ARG HEV_SHA=[0-9a-f]{40}\n")


# ======================================================================== приглашения у старых установок
class ClientReminderTest(unittest.TestCase):
    """Напоминания клиенту в его чат с ботом (1.22.0): срок скоро, 90% лимита, отключён, снова включён — по тому,
    что у клиента сейчас; только в чаты, привязанные приглашением; с галочкой «Напоминать клиентам»."""

    PK, TOK = "PK_remind", "tok_remind"

    def setUp(self):
        bot_setup(self, clients=True)
        self.tg_cfg = cfg(clients=True, control=False)
        self.info = {"enabled": True, "traffic": {"month_rx": 9 * 2 ** 30, "month_tx": 0},
                     "limits": {"expires": time.time() + 2.5 * 86400, "quota": 10 * 2 ** 30, "period": "month"}}
        ops = mock.Mock()
        ops.share_pk = lambda tok: self.PK if tok == self.TOK else None
        ops.share_info = lambda tok, config=True: dict(self.info) if tok == self.TOK else None
        self.bot.ops = ops
        self.bot.store = mock.Mock()
        self.bot.store.snapshot = lambda: {"settings": {"telegram": self.tg_cfg}}
        self.bot._st["links"] = {"7001": {"pk": self.PK, "tok": self.TOK, "lang": "ru", "t": 1},
                                 "7002": {"pk": self.PK, "tok": "old", "lang": "en", "t": 2},     # приглашение обновили
                                 "7003": {"pk": "PK_other", "tok": "x", "lang": "en", "t": 3}}

    def flush(self, *keys):
        for k in keys:
            self.bot.remind(k, self.PK)
        while not self.bot._remind_q.empty():
            self.bot._reminders.append(list(self.bot._remind_q.get_nowait()) + [set()])
        return self.bot.remind_flush(now=time.time())

    def sent(self):
        return [(str(p["chat_id"]), p["text"]) for m, p in self.tg.calls if m == "sendMessage"]

    def test_expiring_and_quota_go_to_the_clients_chat_only(self):
        self.assertTrue(self.flush("ev.client_expiring", "ev.client_quota_warn", "ev.client_first", "ev.exit_down"))
        out = self.sent()
        self.assertEqual([c for c, _ in out], ["7001", "7001"])
        self.assertIn("закончится", out[0][1])
        self.assertIn("через 3 дн.", out[0][1])
        self.assertIn("9 ГБ из 10 ГБ", out[1][1])
        markup = [p["reply_markup"] for m, p in self.tg.calls if m == "sendMessage"][0]
        self.assertEqual(markup["inline_keyboard"][0][0]["callback_data"], "me:r")

    def test_stale_reminder_not_sent(self):
        """Пока ждали связи, клиента продлили или снова включили — устаревшее не уходит."""
        self.assertTrue(self.flush("ev.client_expired", "ev.client_quota"))      # клиент включён: уже не к месту
        self.assertEqual(self.sent(), [])
        self.info["enabled"] = False
        self.info["limits"] = {**self.info["limits"], "period": "total"}
        self.bot._reminded.clear()                                 # другой срок/лимит — новое событие (REMIND_REPEAT)
        self.assertTrue(self.flush("ev.client_quota", "ev.client_quota_reset"))
        out = self.sent()
        self.assertEqual(len(out), 1)
        self.assertIn("напишите тому, кто выдал вам доступ", out[0][1])
        # второй круг проверки: срок продлили на месяц, лимит подняли — «скоро закончится» и «90%» уже не к месту
        self.tg.calls.clear()
        self.bot._reminded.clear()
        self.info = {"enabled": True, "traffic": {"month_rx": 9 * 2 ** 30, "month_tx": 0},
                     "limits": {"expires": time.time() + 30 * 86400, "quota": 100 * 2 ** 30, "period": "month"}}
        self.assertTrue(self.flush("ev.client_expiring", "ev.client_quota_warn"))
        self.assertEqual(self.sent(), [])

    def test_once_an_hour_and_only_for_linked_clients(self):
        """Второй круг проверки: отметки limits.py не записались (диск полон) — событие о сроке приходило бы каждый
        проход (10 с), и клиент получал бы его каждый раз; клиент без чата с ботом очередь не занимает."""
        for _ in range(3):
            self.assertTrue(self.flush("ev.client_expiring"))
        self.assertEqual(len(self.sent()), 1)
        self.bot.remind("ev.client_expiring", "PK_nobody")         # чата нет — в очередь не ставится
        self.assertTrue(self.bot._remind_q.empty())

    def test_pause_kept_while_events_keep_coming(self):
        """Telegram недоступен: пауза между повторами держится, даже если события идут одно за другим."""
        import threading
        calls = []
        self.bot.remind_flush = lambda now=None: calls.append(time.monotonic()) or False
        self.bot.stop_ev = threading.Event()
        with mock.patch.object(tgbot, "REMIND_PAUSES", (0.5,)):
            th = threading.Thread(target=self.bot._remind_loop, daemon=True)
            th.start()
            for i in range(15):                                    # 0,3 с событий подряд
                self.bot._remind_q.put(("rm_expiring", f"PK{i}", time.time()))
                time.sleep(0.02)
            time.sleep(0.1)
            self.bot.stop_ev.set()
            self.bot._remind_q.put(("rm_expiring", "PKx", time.time()))      # разбудить, чтобы поток вышел
            th.join(2)
        self.assertEqual(len(calls), 1, calls)                     # раньше — повтор на каждое новое событие

    def test_switch_off_or_no_clients_bot(self):
        # 1.23.0: напоминания — та же галочка, что клиенты в боте; «Включить бот» выключает и их
        for kw in ({"enabled": False}, {"clients": False}, {"token": ""}):
            self.tg_cfg = cfg(**{"clients": True, "control": False, **kw})
            self.assertTrue(self.flush("ev.client_expiring"))
            self.assertEqual(self.sent(), [], kw)
            self.assertFalse(self.bot._reminders)

    def test_kept_while_telegram_is_down_and_not_sent_twice(self):
        self.bot._st["links"]["7004"] = {"pk": self.PK, "tok": self.TOK, "lang": "en", "t": 4}
        n = {"calls": 0}

        def down(p):
            n["calls"] += 1
            return notify.NotifyError("timed out", net=True) if n["calls"] == 2 else None
        self.tg.fail["sendMessage"] = down
        self.assertFalse(self.flush("ev.client_expiring"))           # первый чат получил, второй — нет связи
        self.assertEqual(len(self.bot._reminders), 1)
        self.assertTrue(self.bot.remind_flush(now=time.time()))
        chats = [c for c, _ in self.sent()]                              # неудачная попытка тоже в списке
        self.assertEqual((chats.count("7001"), chats[-1]), (1, "7004"))  # первому — не повторно
        self.assertFalse(self.bot._reminders)
        self.tg.calls.clear()                                             # сутки без связи — уже не новость
        self.bot._reminders.append(["rm_expiring", self.PK, time.time() - tgbot.REMIND_AGE - 1, set()])
        self.assertTrue(self.bot.remind_flush(now=time.time()))
        self.assertEqual(self.sent(), [])

    def test_notifier_passes_client_events(self):
        got = []
        n = notify.Notifier.__new__(notify.Notifier)
        n.__dict__.update(_target_lost=False, client_fn=lambda k, pk: got.append((k, pk)), event=lambda *a, **kw: None)
        n.engine_event(Msg("ev.client_expiring", name="x", pk="PK1", date="2026-11-22", days=3))
        n.engine_event(Msg("ev.exit_down", name="e", uid="u1"))
        self.assertEqual(got, [("ev.client_expiring", "PK1")])

    def test_setting_saved_and_on_by_default(self):
        self.assertTrue(notify.defaults()["client_notify"])
        st = panel.store.snapshot()
        c = checks.telegram(st, notify.cfg_of(st), {"client_notify": False})
        self.assertFalse(c["client_notify"])
        js = read("app", "static", "js", "settings.js")
        self.assertIn('client_notify: $("#tg-clients").checked', js)      # 1.23.0: одна галочка с клиентами
        self.assertIn("notifier.client_fn = bot.remind", read("app", "api", "telegram.py"))


class ClientBotUpgradeTest(unittest.TestCase):
    def state(self, **tg):
        return {"settings": {"telegram": {"token": TOKEN, "chat_id": "1", **tg}}, "upgraded": ["rule_names"]}

    def test_notifications_only_stay_quiet(self):
        st = self.state(control=False)
        self.assertTrue(Store.client_bot_once(st))
        self.assertIs(st["settings"]["telegram"]["clients"], False)
        self.assertEqual(st["upgraded"], ["rule_names", CLIENT_BOT])
        st["settings"]["telegram"]["clients"] = True                         # человек включил сам
        self.assertFalse(Store.client_bot_once(st))
        self.assertIs(st["settings"]["telegram"]["clients"], True)

    def test_control_on_gets_invitations(self):
        st = self.state(control=True)
        Store.client_bot_once(st)
        self.assertNotIn("clients", st["settings"]["telegram"])               # по умолчанию — включено
        self.assertTrue(notify.cfg_of(st)["clients"])

    def test_old_backup(self):
        old = self.state(control=False)
        st = {"settings": {"telegram": {**notify.defaults(), "token": TOKEN}}, "upgraded": []}
        Store.client_bot_once(st, old)
        self.assertIs(st["settings"]["telegram"]["clients"], False)
        self.assertIn("client_bot_once(st, new)", read("app", "api", "backup.py"))

    def test_new_install(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIn(CLIENT_BOT, Store(os.path.join(d, "state.json")).state["upgraded"])


# ======================================================================== своя коробка сервера при обновлении
DOCKER = r"""#!/usr/bin/env bash
echo "docker $*" >> "$DOCKER_LOG"
case "$1" in
  pull) exit "${PULL_RC:-0}" ;;
  tag|update|stop|rm|start) exit 0 ;;
  rename) exit "${RENAME_RC:-0}" ;;
  run) exit "${RUN_RC:-0}" ;;
  build) exit 0 ;;
  exec) exit "${UP_RC:-0}" ;;
  image) case "$2" in
           inspect) case "$*" in
                      *Architecture*) echo "${IMG_ARCH:-amd64}" ;;
                      *) echo "${NEW_IMG:-sha256:new}" ;;
                    esac ;;
           *) exit 0 ;;
         esac ;;
  info) case "$*" in
          *Architecture*) echo "${HOST_ARCH:-x86_64}" ;;
          *DockerRootDir*) echo "${DOCKER_ROOT:-/var/lib/docker}" ;;
        esac ;;
  inspect) case "$3" in
             *Mounts*) echo "$MOUNT" ;;
             *Image*) echo sha256:old ;;
             *) echo running ;;
           esac ;;
esac
exit 0
"""


# df: свободное место (МБ) — из FREE_MB, по умолчанию с запасом
DF = r"""#!/bin/sh
echo "Filesystem 1048576-blocks Used Available Capacity Mounted on"
echo "/dev/x 100000 1 ${FREE_MB:-50000} 1% /"
"""


class RefreshOwnServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir)
        for name, body in (("docker", DOCKER), ("sleep", "#!/bin/sh\nexit 0\n"), ("df", DF)):
            with open(os.path.join(bindir, name), "w") as f:
                f.write(body)
            os.chmod(os.path.join(bindir, name), 0o755)
        os.makedirs(os.path.join(self.tmp, "awg-server", "data"))
        with open(os.path.join(self.tmp, "awg-server", "data", "awg0.conf"), "w") as f:
            f.write("[Interface]\nListenPort = 41234\n")
        with open(os.path.join(self.tmp, "IMAGES"), "w") as f:
            f.write("SERVER_IMAGE=ghcr.io/r-slashslash/awg-router@sha256:" + "a" * 64 + "\n")
        os.makedirs(os.path.join(self.tmp, "data"))
        self.log = os.path.join(self.tmp, "docker.log")
        self.env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "DOCKER_LOG": self.log,
                    "MOUNT": f"{self.tmp}/awg-server/data"}
        self.sh = read("install.sh")

    def fn(self, name):
        a = self.sh.index(name + "() {")
        return self.sh[a:self.sh.index("\n}\n", a) + 3]

    def run_sh(self, **env):
        open(self.log, "w").close()
        script = textwrap.dedent(f"""\
            DIR="{self.tmp}"; SRV_DATA="$DIR/awg-server/data"; SRV_NAME=amnezia-awg2
            AWG_MODE=container; INSTALL_AWG=""; AMN=amnezia-awg2
            step() {{ echo "STEP $1"; }}; ok() {{ echo "OK $1"; }}; warn() {{ echo "WARN $1"; }}
            buildx_ver() {{ :; }}
            """) + "".join(self.fn(n) for n in ("our_container", "image_ref", "no_ready_image", "docker_arch", "pull_image",
                                                 "build_image", "last_line", "saved_port", "run_server_container",
                                                 "refresh_own_server")) + "refresh_own_server\n"
        r = subprocess.run(["bash", "-uo", "pipefail", "-c", script], env={**self.env, **env},
                           capture_output=True, text=True, timeout=30)
        with open(self.log) as f:
            return r.stdout + r.stderr, f.read()

    def test_new_image_recreates_container(self):
        out, log = self.run_sh()
        self.assertIn("docker pull ghcr.io/r-slashslash/awg-router@sha256:" + "a" * 64, log)
        self.assertRegex(log, r"docker rename amnezia-awg2 amnezia-awg2-prev-\d{8}-\d{6}")
        self.assertIn("-p 41234:41234/udp", log)                            # тот же порт — конфиги клиентов те же
        self.assertIn(f"-v {self.tmp}/awg-server/data:/opt/amnezia/awg", log)
        self.assertRegex(log, r"docker rm -f amnezia-awg2-prev-")
        self.assertIn("AmneziaWG runs on the new image", out)

    def test_same_image_does_nothing(self):
        out, log = self.run_sh(NEW_IMG="sha256:old")
        self.assertNotIn("docker stop", log)
        self.assertNotIn("docker run", log)

    def test_failure_brings_old_back(self):
        out, log = self.run_sh(UP_RC="1")
        self.assertIn("the old one is running again", out)
        self.assertRegex(log, r"docker rename amnezia-awg2-prev-\S+ amnezia-awg2")
        self.assertIn("docker start amnezia-awg2", log)

    def test_amnezia_app_container_untouched(self):
        out, log = self.run_sh(MOUNT="/opt/amnezia/awg")
        self.assertNotIn("docker pull", log)
        self.assertNotIn("docker stop", log)

    def test_called_on_update(self):
        a = self.sh.index("refresh_own_server() {")
        self.assertIn("\nrefresh_own_server\n", self.sh[a:])
        self.assertLess(self.sh.index("\nrefresh_own_server\n"), self.sh.index('step "Starting"'))



class SshCommandTest(unittest.TestCase):
    """Команда SSH-туннеля в боте — с тем же пользователем и портом, что у установщика (SSH_USER и SSH_PORT в .env),
    а не всегда root@ без порта."""

    def setUp(self):
        bot_setup(self)

    def text(self, lang, **conf):
        with mock.patch.object(config, "PANEL_HOST", "127.0.0.1"), mock.patch.multiple(config, **conf), \
                mock.patch.object(self.bot, "_show") as show:
            self.bot.show_panel({"lang": lang}, None)
        return show.call_args[0][1]

    def test_user_and_port(self):
        port = config.PANEL_PORT
        for lang in ("ru", "en", "zh", "fa"):
            self.assertIn(f"ssh -N -L {port}:127.0.0.1:{port} -p 2222 debian@",
                          self.text(lang, SSH_USER="debian", SSH_PORT=2222), lang)
            self.assertIn(f"ssh -N -L {port}:127.0.0.1:{port} root@", self.text(lang, SSH_USER="root", SSH_PORT=0))

    def test_env_checked(self):
        """Непохожее на имя пользователя или порт в .env — как без них: root и 22."""
        cases = [({"SSH_USER": "debian", "SSH_PORT": "2222"}, "debian 2222"),
                 ({"SSH_USER": "x; rm -rf /", "SSH_PORT": "22"}, "root 0"),
                 ({"SSH_USER": "", "SSH_PORT": "70000"}, "root 0"),
                 ({"SSH_PORT": "abc"}, "root 0")]
        for env, want in cases:
            e = {k: v for k, v in os.environ.items() if k not in ("SSH_USER", "SSH_PORT")}
            r = subprocess.run([sys.executable, "-c", "from app import config as c; print(c.SSH_USER, c.SSH_PORT)"],
                               cwd=ROOT, env={**e, **env}, capture_output=True, text=True, timeout=30)
            self.assertEqual(r.stdout.strip(), want, env)


# ======================================================================== вторая часть 1.22.0: 7, 8, 9, 10, 5
class DetectSeenChatTest(unittest.TestCase):
    """«Найти» Chat ID, когда бот уже сам читает сообщения (управление или приглашения клиентов)."""

    def test_chat_the_bot_saw(self):
        bot_setup(self, clients=True)
        self.tg.updates = [msg("hi", chat="6006")]
        self.bot.poll_once(self.c, timeout=0)
        self.assertEqual(self.bot.last_chat["id"], "6006")
        self.tg.fail["getUpdates"] = notify.NotifyError("Conflict: terminated by other getUpdates request", code=409)
        with mock.patch.object(telegram, "bot", self.bot):
            r = telegram.telegram_detect(Req({"token": TOKEN}))
        self.assertEqual(r["id"], "6006")
        with mock.patch.object(telegram, "bot", self.bot):                # другой бот — не его чат
            self.assertIsNotNone(code(lambda: telegram.telegram_detect(Req({"token": "987654321:" + "B" * 35}))))

    def test_client_chat_not_found(self):
        """Проверка 1.22.0 (Н1): «Найти» не подставляет чат клиента — ни приглашение «/start <ключ>», ни его
        кнопки, ни сообщения из привязанного чата. Иначе уведомления, управление и копии с ключами ушли бы ему."""
        from tests.test_v19 import button
        panel.engine.reconcile()
        pk = clients.add_user(Req({"name": "find-client"}))["public_key"]
        panel.engine.reconcile()
        tok = next(k for k, v in panel.store.snapshot()["shares"].items() if v["pk"] == pk)
        bot_setup(self, clients=True)
        self.tg.updates = [msg("hi", chat="1001", uid=1), msg("/start " + tok, chat="7007", uid=2)]
        self.bot.poll_once(self.c, timeout=0)
        self.assertIn("7007", self.bot._st.get("links") or {})               # клиент привязан
        self.tg.updates = [button("me:r", chat="7007", uid=3), msg("привет", chat="7007", uid=4)]
        self.bot.poll_once(self.c, timeout=0)
        with mock.patch.object(telegram, "bot", self.bot):
            self.assertEqual(telegram.telegram_detect(Req({"token": TOKEN}))["id"], "1001")
        self.bot.last_chat["t"] -= telegram.DETECT_SEEN                         # давнее сообщение — не годится
        with mock.patch.object(telegram, "bot", self.bot):
            self.assertEqual(code(lambda: telegram.telegram_detect(Req({"token": TOKEN}))), (404, "err.tg_no_chat"))
        # второй круг проверки: события, которые бот ещё не забрал (не читает сообщения или ждёт после 409), «Найти»
        # получает от Telegram само — и там последним может быть клиент; берётся только чат, который годится
        self.tg.updates = [msg("hi", chat="1002", uid=5), msg("привет", chat="7007", uid=6),
                           button("me:r", chat="8008", uid=7), msg("/start " + tok, chat="9009", uid=8)]
        with mock.patch.object(telegram, "bot", self.bot):
            self.assertEqual(telegram.telegram_detect(Req({"token": TOKEN}))["id"], "1002")

    def test_chat_of_update(self):
        self.assertEqual(notify.chat_of({"channel_post": {"chat": {"id": -5, "title": "News"}}}),
                         {"id": "-5", "title": "News"})
        self.assertIsNone(notify.chat_of({"edited_message": {}}))


class GroupQuietTest(unittest.TestCase):
    def setUp(self):
        bot_setup(self, chat_id="-1001")
        self.bot._st["me"] = {"bot": TOKEN.split(":")[0], "username": "awgr_test_bot"}

    def group(self, text, uid=1, **extra):
        m = msg(text, chat="-1001", uid=uid, **extra)
        m["message"]["chat"]["type"] = "supergroup"
        return m

    def test_talk_in_group_is_ignored(self):
        self.tg.updates = [self.group("привет всем")]
        self.bot.poll_once(self.c, timeout=0)
        self.assertEqual(self.tg.texts(), [])
        self.tg.updates = [self.group("@AWGR_test_bot меню", uid=2)]
        self.bot.poll_once(self.c, timeout=0)
        self.assertTrue(self.tg.texts())                                       # обращение — меню
        n = len(self.tg.texts())
        self.tg.updates = [self.group("/status", uid=3)]
        self.bot.poll_once(self.c, timeout=0)
        self.assertGreater(len(self.tg.texts()), n)                           # команды — как раньше

    def test_reply_to_bot(self):
        self.tg.updates = [self.group("ну?", reply_to_message={"message_id": 5, "from": {"is_bot": True}})]
        self.bot.poll_once(self.c, timeout=0)
        self.assertTrue(self.tg.texts())


class ListNameKeptTest(unittest.TestCase):
    def test_text_only_edit(self):
        old = {"kind": "manual", "source": "10.0.0.0/8", "name": "Office"}
        self.assertEqual(checks.list_fields({"source": "192.0.2.0/24"}, old)["name"], "Office")
        self.assertEqual(checks.list_fields({"source": "192.0.2.0/24", "name": "New"}, old)["name"], "New")
        self.assertEqual(code(lambda: checks.list_fields({"source": "192.0.2.0/24", "name": ""}, old)),
                         (400, "err.name_required"))                          # явно пустое — по-прежнему отказ


class BatchSwitchTest(unittest.TestCase):
    """Срок кончился у многих клиентов разом — одна запись файлов сервера, а не по клиенту."""

    def test_one_write_for_many(self):
        panel.engine.reconcile()
        pks = [clients.add_user(Req({"name": f"batch-{i}"}))["public_key"] for i in range(5)]
        panel.engine.reconcile()
        writes = []
        orig = panel.engine.srv._write
        with mock.patch.object(panel.engine.srv, "_write", side_effect=lambda *a, **kw: (writes.append(1), orig(*a, **kw))):
            done = panel.engine.srv.set_enabled_many({pk: False for pk in pks} | {"Z" * 43 + "=": False})
        self.assertEqual(done, set(pks))
        self.assertEqual(len(writes), 1)
        self.assertTrue(all(not c["enabled"] for c in panel.engine.clients if c["public_key"] in pks))
        with mock.patch.object(panel.engine.srv, "_write") as w:
            self.assertEqual(panel.engine.srv.set_enabled_many({pk: False for pk in pks}), set(pks))
            w.assert_not_called()                                              # уже выключены — писать нечего
        panel.engine.srv.set_enabled_many({pk: True for pk in pks})

    def test_enforce_uses_batch(self):
        src = read("app", "limits.py")
        self.assertNotIn("update_client(", src)
        self.assertIn("set_enabled_many", src)


class SocksCheckInTest(unittest.TestCase):
    """Здоровье выхода SOCKS5 — из сети сервера AWG (как hev), пароль — не в командной строке."""

    def test_runs_in_server_network(self):
        seen = {}

        class T:
            def ns(self, cmd, input=None, timeout=30, check=True):
                seen.update(cmd=cmd, input=input)
                return subprocess.CompletedProcess(cmd, 0, json.dumps(
                    {"ok": False, "ms": None, "error": {"$t": "socks.auth_failed", "p": {}}}), "")
        r = socks.check_in(T(), {"host": "proxy.example", "port": 1080, "user": "u", "password": "s3cret"},
                           "192.0.2.80")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"].key, "socks.auth_failed")
        self.assertNotIn("s3cret", " ".join(seen["cmd"]))
        self.assertEqual(json.loads(seen["input"])["host"], "192.0.2.80")      # адрес, а не имя

    def test_broken_answer_is_down(self):
        class T:
            def ns(self, cmd, **kw):
                return subprocess.CompletedProcess(cmd, 1, "", "Traceback")
        r = socks.check_in(T(), {"port": 1080}, "192.0.2.80")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"].key, "socks.unreachable")

    def test_main_round_trip(self):
        out = subprocess.run([sys.executable, "-c", f"import sys;sys.path.insert(0,{ROOT!r});from app import socks;"
                              "socks.check=lambda c: {'ok': False, 'ms': None, 'error': socks.Msg('socks.timeout'), 'at': 1};"
                              "socks.main()"], input='{"host": "x", "port": 1}', capture_output=True, text=True,
                             timeout=30)
        self.assertEqual(json.loads(out.stdout)["error"], {"$t": "socks.timeout", "p": {}})
        self.assertIn("socks.check_in(t, conf, ip)", read("app", "engine", "tunnels.py"))


class ContainerPortTest(unittest.TestCase):
    """Смена порта контейнера сервера: пересоздание с тем же содержимым, возврат прежнего при сбое."""
    INFO = {
        "Id": "abcdef1234567890", "Image": "sha256:old",
        "Config": {"Hostname": "abcdef123456", "Image": "amnezia-awg2", "Cmd": ["sh", "start.sh"],
                   "ExposedPorts": {"2098/udp": {}}, "Labels": {"x": "1"}},
        "HostConfig": {"NetworkMode": "bridge", "Privileged": True, "RestartPolicy": {"Name": "always"},
                       "PortBindings": {"2098/udp": [{"HostIp": "", "HostPort": "2098"},
                                                     {"HostIp": "::", "HostPort": "2098"}]}},
        "NetworkSettings": {"Networks": {"bridge": {"Aliases": None},
                                         "amnezia-dns-net": {"Aliases": ["abcdef123456", "awg"],
                                                             "IPAMConfig": {"IPv4Address": "172.29.172.3"}}}},
        "Mounts": [{"Destination": "/lib/modules"}],
    }

    def test_body_keeps_everything_but_port(self):
        from app import system
        b = system.recreate_body(self.INFO, "awg-router-port:1", 2098, 40000)
        self.assertEqual(b["Image"], "awg-router-port:1")
        self.assertNotIn("Hostname", b)                          # имя по Id — у нового своё
        self.assertEqual(b["Cmd"], ["sh", "start.sh"])
        self.assertEqual(b["Labels"], {"x": "1"})
        self.assertEqual(b["ExposedPorts"], {"40000/udp": {}})
        self.assertEqual(b["HostConfig"]["PortBindings"],
                         {"40000/udp": [{"HostIp": "", "HostPort": "40000"}, {"HostIp": "::", "HostPort": "40000"}]})
        self.assertTrue(b["HostConfig"]["Privileged"])
        self.assertEqual(system.extra_networks(self.INFO),
                         {"amnezia-dns-net": {"Aliases": ["awg"], "IPAMConfig": {"IPv4Address": "172.29.172.3"}}})
        self.assertEqual(self.INFO["Config"]["ExposedPorts"], {"2098/udp": {}})   # исходник не тронут

    def test_anonymous_volume_carried(self):
        from app import system
        info = {**self.INFO, "HostConfig": {**self.INFO["HostConfig"], "Binds": ["/lib/modules:/lib/modules"]},
                "Mounts": [{"Type": "bind", "Destination": "/lib/modules"},
                           {"Type": "volume", "Name": "f00d", "Destination": "/opt/amnezia/awg"}]}
        b = system.recreate_body(info, "x", 2098, 40000)
        self.assertEqual(b["HostConfig"]["Binds"], ["/lib/modules:/lib/modules", "f00d:/opt/amnezia/awg"])

    def run_change(self, info, up=True):
        from app import system
        calls = []

        def api(method, path, timeout=10, body=None):
            calls.append((method, path.split("?")[0], path, body))
            if method == "GET":
                return info
            if path.startswith("/containers/create"):
                return {"Id": "new1"}
            return {}
        with mock.patch.object(system, "docker_api", api), mock.patch.object(system, "docker_get",
                                                                             lambda p: info), \
                mock.patch.object(system, "_wait_iface", lambda n, i: up), mock.patch.object(system, "_stamp", lambda: "T"):
            try:
                system.recreate_with_port("amnezia-awg2", "/opt/amnezia/awg", "awg0", 2098, 40000, "OLD CONF")
                return None, calls
            except system.SysError as e:
                return e, calls

    def test_app_container_committed_and_old_removed(self):
        err, calls = self.run_change(self.INFO)
        self.assertIsNone(err)
        paths = [(m, p) for m, p, _, _ in calls]
        # остановка до переименования (порт свободен), снимок, создание, вторая сеть, запуск, удаление старого
        order = [("POST", "/containers/amnezia-awg2/stop"), ("POST", "/containers/amnezia-awg2/rename"),
                 ("POST", "/commit"), ("POST", "/containers/create"), ("POST", "/networks/amnezia-dns-net/connect"),
                 ("POST", "/containers/amnezia-awg2/start"), ("DELETE", "/containers/amnezia-awg2-old-T")]
        self.assertEqual([x for x in paths if x in order], order)
        create = next(b for m, p, _, b in calls if p == "/containers/create")
        self.assertEqual(create["Image"], "awg-router-port:T")
        self.assertNotIn(("PUT", "/containers/amnezia-awg2-old-T/archive"), paths)

    def test_mark_kept_only_while_the_change_runs(self):
        """port-change.json — пока идёт смена (с прежним конфигом, только для root); после успеха и после возврата
        прежнего — нет: по нему recover_renamed отличает прерванную смену и возвращает конфиг с прежним портом."""
        from app import system
        real = system._port_mark
        for up in (True, False):
            seen = []

            def rec(mark):
                real(mark)
                seen.append((system._port_mark_get(), mark and os.stat(system._port_mark_path()).st_mode & 0o777))
            with mock.patch.object(system, "_port_mark", rec):
                err, calls = self.run_change(self.INFO, up=up)
            self.assertEqual(seen, [({"old": "amnezia-awg2-old-T", "dir": "/opt/amnezia/awg", "iface": "awg0",
                                      "conf": "OLD CONF"}, 0o600), ({}, None)], up)
            self.assertFalse(os.path.exists(system._port_mark_path()), up)
            self.assertEqual(err is None, up)

    def test_own_container_folder_on_disk_no_commit(self):
        info = {**self.INFO, "Mounts": [{"Destination": "/opt/amnezia/awg"}]}
        err, calls = self.run_change(info)
        self.assertIsNone(err)
        self.assertNotIn("/commit", [p for _, p, _, _ in calls])
        create = next(b for m, p, _, b in calls if p == "/containers/create")
        self.assertEqual(create["Image"], "sha256:old")

    def test_not_up_puts_old_back(self):
        import tarfile
        import io
        err, calls = self.run_change(self.INFO, up=False)
        self.assertIsNotNone(err)
        paths = [(m, p) for m, p, _, _ in calls]
        back = [("DELETE", "/containers/new1"), ("PUT", "/containers/amnezia-awg2-old-T/archive"),
                ("POST", "/containers/amnezia-awg2-old-T/rename"), ("POST", "/containers/amnezia-awg2/update"),
                ("POST", "/containers/amnezia-awg2/restart")]
        tail = paths[paths.index(back[0]):]
        self.assertEqual([x for x in tail if x in back], back)
        self.assertNotIn(("DELETE", "/containers/amnezia-awg2-old-T"), paths)
        tar = next(b for m, p, _, b in calls if p.endswith("/archive"))
        with tarfile.open(fileobj=io.BytesIO(tar)) as tf:
            self.assertEqual(tf.extractfile("awg0.conf").read(), b"OLD CONF")
        policy = [b for m, p, _, b in calls if p == "/containers/amnezia-awg2/update"]
        self.assertEqual(policy[-1], {"RestartPolicy": {"Name": "always"}})

    def test_settings_failure_is_a_field_error(self):
        from app import panel, system, users
        t = system.DemoTarget()
        t.kind = "container"
        t.conf_path = "/etc/test1/awg0.conf"
        t.write_file(t.conf_path, "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n"
                                  "Address = 10.8.1.1/24\nListenPort = 2098\n")
        old, panel.engine.target = panel.engine.target, t
        try:
            with mock.patch.object(system.DemoTarget, "change_port", side_effect=system.SysError("no")):
                with self.assertRaises(users.UserError) as cm:
                    panel.engine.srv.update_server({"port": 40000})
            self.assertEqual(cm.exception.msg.key, "srv.port_failed")
        finally:
            panel.engine.target = old
        from app.api import server as api_server
        self.assertEqual(api_server.SERVER_FIELDS["srv.port_failed"], "port")

    def test_hint_and_icons(self):
        js = read("app", "static", "js", "core.js")
        self.assertIn("THEME_SUN", js)
        self.assertNotIn('"☀"', js)                              # символ шрифта на Android ниже середины
        self.assertNotIn("port_locked", read("app", "static", "js", "server.js"))


class ClientLabelTest(unittest.TestCase):
    """Файл конфига и описание в vpn:// — 8 цифр клиента, а не его имя (1.22.0), и в панели тоже."""

    @classmethod
    def setUpClass(cls):
        panel.engine.reconcile()

    def test_vpn_link_and_file(self):
        import base64
        import json as _json
        import zlib
        from app import users
        pk = clients.add_user(Req({"name": "label-name"}))["public_key"]
        cfg = panel.engine.srv.client_config(pk)
        self.assertEqual(cfg["filename"], users.conf_filename(pk))
        self.assertEqual(cfg["name"], "label-name")                   # панели имя по-прежнему нужно
        raw = base64.urlsafe_b64decode(cfg["link"][len("vpn://"):] + "==")
        doc = _json.loads(zlib.decompress(raw[4:]))
        self.assertEqual(doc["description"], users.conf_label(pk))
        self.assertNotIn("label-name", cfg["conf"])
        self.assertNotIn("label-name", zlib.decompress(raw[4:]).decode())

    def test_no_period_after_a_command(self):
        """Точка сразу за командой копируется вместе с ней — и команда не работает."""
        import re
        src = read("app", "static", "i18n.js")
        self.assertEqual(re.findall(r'"([\w.]+)": "[^"]*\{cmd\}[.。]', src), [])

    def test_share_page_has_no_name(self):
        js = read("app", "static", "share.js")
        self.assertNotIn("D.name", js)
        self.assertIn('t("share.title")', js)


class RuleDnsTest(unittest.TestCase):
    """Свой DNS правила по сайтам (1.22.0): проверка, путь до dnsproxy.py и сам запрос к своему серверу."""

    def test_check(self):
        from app import checks
        self.assertEqual(checks.rule_dns("77.88.8.8, 77.88.8.1"), ["77.88.8.8", "77.88.8.1"])
        self.assertEqual(checks.rule_dns(["223.5.5.5", "223.5.5.5"]), ["223.5.5.5"])
        self.assertEqual(checks.rule_dns(""), [])
        for bad_v, key in (("2a02:6b8::feed:0ff", "err.rule_dns_bad"), ("1.1.1.1 8.8.8.8 9.9.9.9", "err.rule_dns_many"),
                           ("yandex", "err.rule_dns_bad"), ("0.0.0.0", "err.rule_dns_bad")):
            with self.assertRaises(Exception) as cm:
                checks.rule_dns(bad_v)
            self.assertIn(key, str(getattr(cm.exception, "msg", cm.exception)) + repr(cm.exception.__dict__), bad_v)

    def test_rules_keep_dns_only_for_sites(self):
        from app import checks
        st = {**panel.store.snapshot(), "lists": [{"id": "l_dom", "kind": "domains", "name": "ru"},
                                                  {"id": "l_net", "kind": "manual", "name": "nets"}]}
        dom, net = "l_dom", "l_net"
        out = checks.rules(st, [{"lists": [dom], "outbound": "direct", "dns": "77.88.8.8"},
                                {"lists": [net], "outbound": "direct", "dns": "77.88.8.8"},
                                {"lists": [dom], "outbound": "direct"}])
        self.assertEqual(out[0]["dns"], ["77.88.8.8"])
        self.assertNotIn("dns", out[1])                 # у правила по адресам свой DNS не имеет смысла
        self.assertNotIn("dns", out[2])                 # не задан — поля нет, состояние как до 1.22.0

    def test_own_server_address_refused_at_the_field(self):
        """Адрес самого DNS на сервере в своём DNS правила бесполезен: при сохранении из панели — ошибка у поля
        этого правила (rule_dns_<номер>); копии и выходы проверяют без адреса — как до 1.22.0."""
        from app import checks
        st = {**panel.store.snapshot(), "lists": [{"id": "l_dom", "kind": "domains", "name": "ru"}]}
        rules = [{"lists": ["l_dom"], "outbound": "direct"},
                 {"lists": ["l_dom"], "outbound": "direct", "dns": "77.88.8.8, 10.8.1.1"}]
        with self.assertRaises(Exception) as cm:
            checks.rules(st, rules, "10.8.1.1")
        self.assertEqual(cm.exception.field, "rule_dns_1")
        self.assertIn("err.rule_dns_self", repr(cm.exception.__dict__))
        self.assertEqual(checks.rules(st, rules)[1]["dns"], ["77.88.8.8", "10.8.1.1"])
        self.assertEqual(checks.rules(st, rules, "10.8.2.1")[1]["dns"], ["77.88.8.8", "10.8.1.1"])
        with self.assertRaises(Exception) as cm:                 # и у своих правил клиента
            checks.client_policy(st, {"rules_mode": "custom", "rules": rules}, "10.8.1.1")
        self.assertEqual(cm.exception.field, "rule_dns_1")
        with self.assertRaises(Exception) as cm:                 # прочие ошибки своего DNS — тоже у поля
            checks.rules(st, [{"lists": ["l_dom"], "outbound": "direct", "dns": "yandex"}])
        self.assertEqual(cm.exception.field, "rule_dns_0")
        js = read("app", "static", "js", "routing.js")
        self.assertIn('data-field="rule_dns_${at}"', js)        # 1.23.0: поле — в окне правила
        self.assertIn("markField(err, m)", js)

    def test_zone_with_leading_dot(self):
        """«.cn» в списке — вся зона, как и «cn»: точка в начале не мешает (так подсказывает окно списка)."""
        from app import dnsproxy, domains
        self.assertEqual(domains.parse(".cn\n*.ru\nnet"), ["cn", "ru", "net"])
        self.assertTrue(dnsproxy.match("www.baidu.cn.", {"cn"}))
        self.assertFalse(dnsproxy.match("baidu.com.", {"cn"}))

    def test_policy_key_unchanged_without_dns(self):
        from app import nftgen
        p = {"rules": [], "default": "direct", "domain": [(["d1"], "direct")]}
        base = nftgen._policy_key(p)
        self.assertEqual(len(base), 3)
        self.assertEqual(len(nftgen._policy_key({**p, "dns": [(["d1"], "direct", ["77.88.8.8"])]})), 4)

    def test_engine_passes_own_dns(self):
        """Правило «сайты → напрямую, свой DNS» при «всё остальное — напрямую»: для nftables и sniproxy.py оно
        ничего не меняет и выбрасывается, а dnsproxy.py получает его со своим DNS и без записи в набор."""
        from tests.test_v121 import DomainsAnyExitTest
        from app.api import routing as api_routing
        t = DomainsAnyExitTest("setUp")
        t.setUp()
        self.addCleanup(t.tearDown)
        api_routing.put_routing(Req({"default": "direct", "rules": [{"lists": [t.lid], "outbound": "direct",
                                                                      "dns": "77.88.8.8"}]}))
        st = panel.store.snapshot()
        self.assertEqual(st["routing"]["rules"][0]["dns"], ["77.88.8.8"])
        gp, _ = panel.engine._policies(st)
        self.assertEqual(gp["domain"], [])                       # трафик не перехватывается
        d = panel.engine.dns_domains(st, with_set=True)
        self.assertEqual(d["policies"]["p_global"], [[[t.lid], {"mark": 0, "tcp": False}, ["77.88.8.8"], False]])

    def _proxy(self, policies, clients=None):
        import json as _json
        import tempfile
        from app import dnsproxy
        d = tempfile.mkdtemp()
        lp = os.path.join(d, "ru.domains")
        with open(lp, "w") as f:
            f.write("ru\n")
        conf = os.path.join(d, "dns.json")
        with open(conf, "w") as f:
            _json.dump({"listen": "10.8.1.1", "port": 53, "clients": "10.8.1.0/24", "upstreams": ["1.1.1.1"], "encrypt": "doh",
                        "default": {"mark": 0, "tcp": False}, "routes": {},
                        "dom": {"lists": {"ru": lp}, "clients": clients or {}, "policies": policies}}, f)
        return dnsproxy.Proxy(conf)

    def test_down_exit_keeps_names_off_plain_dns(self):
        """Проверка 1.22.0 (Н2): выход правила подключается или лежит (пути нет) — свой DNS правила не
        спрашивается. Иначе имена сайтов правила шли бы путём клиента («напрямую») обычным DNS без шифрования —
        мимо выхода. Как до 1.22.0: общие серверы (DoH) путём клиента."""
        p = self._proxy({"p_global": [[["ru"], None, ["1.1.1.1"], False]]})
        self.assertEqual(p.domain_route("10.8.1.5", "mail.yandex.ru."), (None, (), False))
        up = {"mark": 0x1000, "tcp": False}
        p = self._proxy({"p_global": [[["ru"], up, ["1.1.1.1"], False]]})
        self.assertEqual(p.domain_route("10.8.1.5", "mail.yandex.ru."), (up, ("1.1.1.1",), False))

    def test_own_address_not_asked(self):
        """Проверка 1.22.0 (Н5): свой DNS — адрес, на котором слушает этот DNS (сервер в туннеле): он спрашивал
        бы сам себя, один запрос клиента порождал 512 внутренних и ошибку. Такой адрес пропускается."""
        p = self._proxy({"p_global": [[["ru"], {"mark": 0, "tcp": False}, ["10.8.1.1", "77.88.8.8"], False]]})
        self.assertEqual(p.domain_route("10.8.1.5", "ya.ru.")[1], ("77.88.8.8",))
        p = self._proxy({"p_global": [[["ru"], {"mark": 0, "tcp": False}, ["10.8.1.1"], False]]})
        self.assertEqual(p.domain_route("10.8.1.5", "ya.ru.")[1], ())

    def test_cache_keeps_own_dns_apart(self):
        """Проверка 1.22.0 (Н7): у двух клиентов один путь и одно имя, но у одного свой DNS правила — ответы в
        кэше не смешиваются (без серверов в ключе кэша второй получил бы ответ первого)."""
        import asyncio
        import socket
        from app import dnsproxy
        from tests.test_v115 import a_reply, q_msg
        direct = {"mark": 0, "tcp": False}
        p = self._proxy({"p_global": [[["ru"], direct, [], False]], "p_1": [[["ru"], direct, ["77.88.8.8"], False]]},
                        clients={"10.8.1.6": "p_1"})
        asked = []

        async def forward(query, q, mark, tcp, servers=()):
            asked.append(servers)
            return a_reply(query, ["198.51.100.2" if servers else "203.0.113.2"])
        p.forward = forward

        async def go():
            out = []
            for ip in ("10.8.1.5", "10.8.1.6", "10.8.1.5", "10.8.1.6"):
                query = q_msg("ya.ru")
                out.append(await p.resolve(query, dnsproxy.parse_query(query), ip))
            return out
        replies = asyncio.run(go())
        self.assertEqual(asked, [(), ("77.88.8.8",)])                           # по разу: дальше — кэш
        self.assertIn(socket.inet_aton("203.0.113.2"), replies[2])
        self.assertIn(socket.inet_aton("198.51.100.2"), replies[3])

    def test_proxy_asks_own_server_plain(self):
        """Общий сервер не отвечает и стоит DoT, а свой DNS правила — обычный и живой: ответ приходит."""
        import json as _json
        import socket
        import subprocess
        import sys
        import tempfile
        import time
        from app import engine
        from tests.test_v115 import FakeUpstream, free_port, q_msg
        up = FakeUpstream()
        self.addCleanup(up.close)
        d = tempfile.mkdtemp()
        lp = os.path.join(d, "ru.domains")
        with open(lp, "w") as f:
            f.write("ru\n")
        port = free_port()
        cfg = {"listen": "127.0.0.1", "port": port, "clients": "127.0.0.0/8", "stats": os.path.join(d, "s.json"),
               "upstreams": ["127.0.0.2"], "encrypt": "dot", "upstream_port": up.port,
               "default": {"mark": 0, "tcp": False}, "routes": {},
               "dom": {"lists": {"ru": lp}, "clients": {},
                       "policies": {"p_global": [[["ru"], {"mark": 0, "tcp": False}, ["127.0.0.1"], False]]}}}
        conf = os.path.join(d, "dns.json")
        with open(conf, "w") as f:
            _json.dump(cfg, f)
        proc = subprocess.Popen([sys.executable, "-I", engine.dns.DNSPROXY, conf],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(proc.wait, 5)
        self.addCleanup(proc.terminate)
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.sendto(q_msg("mail.yandex.ru", qid=0x4242), ("127.0.0.1", port))
            r = s.recv(65535)
        self.assertEqual(r[:2], b"\x42\x42")
        self.assertIn(socket.inet_aton("203.0.113.1"), r)


class ServerCountryTest(unittest.TestCase):
    """Страна сервера (1.22.0) — из проверки «напрямую», для запасного местного DNS пути «напрямую»."""

    def test_country_from_direct_check(self):
        import threading
        e = panel.engine
        ev = threading.Event()
        ev.wait = lambda t=None: ev.set()            # один круг поиска адреса
        old = (e.stop_ev, e.public_v4, e.public_v4_state, e.public_cc)
        try:
            e.stop_ev = ev
            with mock.patch.object(e, "target", mock.Mock(exists=True)), \
                    mock.patch.object(e.srv, "public_host", return_value="198.51.100.1"), \
                    mock.patch.object(e, "probe", return_value={"ok": True, "ip": "203.0.113.9", "cc": "ru"}):
                e._detect_host()
            self.assertEqual(e.public_cc, "RU")
            ev.clear()
            with mock.patch.object(e, "target", mock.Mock(exists=True)), \
                    mock.patch.object(e.srv, "public_host", return_value="198.51.100.1"), \
                    mock.patch.object(e, "probe", return_value={"ok": True, "ip": "203.0.113.9", "cc": "<b>"}):
                e._detect_host()
            self.assertEqual(e.public_cc, "RU")                    # не код страны — прежний остаётся
            # второй круг проверки: адрес нашёлся, а страна нет (ответил только ifconfig.me) — снова через 10 минут
            waits = []
            ev.clear()
            ev.wait = lambda t=None: (waits.append(t), ev.set())
            e.public_cc = None
            with mock.patch.object(e, "target", mock.Mock(exists=True)), \
                    mock.patch.object(e.srv, "public_host", return_value="198.51.100.1"), \
                    mock.patch.object(e, "probe", return_value={"ok": True, "ip": "203.0.113.9"}):
                e._detect_host()
            from app import engine as eng
            self.assertEqual(waits, [eng.HOST_SLOW_WAIT])
        finally:
            e.stop_ev, e.public_v4, e.public_v4_state, e.public_cc = old
        from app import countries
        self.assertEqual(countries.preset("RU")["dns"], ("77.88.8.8", "77.88.8.1"))
        # запасной DNS по стране сервера сам больше не включается (1.25.0, владелец 2026-11-26): галочка «Запасной DNS
        # для «Напрямую»» и кнопки «Применить для …»
        self.assertNotIn("public_cc", read("app", "engine", "dns.py"))


class CountryPresetTest(unittest.TestCase):
    """Готовые правила стран (1.22.0, решение владельца 2026-11-19): новая установка — без правил и списков;
    «Применить для …» в «Обзоре», пока правил нет; выбор страны в правиле добавляет правило её доменов."""

    def setUp(self):
        st = panel.store.snapshot()
        self._routing = {k: st["routing"][k] for k in ("default", "rules")}
        self._lists = {l["id"] for l in st["lists"]}
        p = mock.patch.object(lists, "_fetch", side_effect=OSError("offline"))
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        from app.api import routing
        r = self._routing
        panel.store.mutate(lambda st: st.update(routing={"default": r["default"], "rules": r["rules"]}))
        for l in panel.store.snapshot()["lists"]:
            if l["id"] not in self._lists:
                routing.del_list(None, l["id"])

    def test_new_install_is_empty(self):
        d = tempfile.mkdtemp()
        st = Store(os.path.join(d, "state.json")).snapshot()
        self.assertEqual((st["routing"]["rules"], st["lists"], st["routing"]["default"]), ([], [], "direct"))

    def test_lists_once_and_apply_adds_two_direct_rules(self):
        from app.api import routing
        panel.store.mutate(lambda st: st["routing"].update(rules=[]))
        a = routing.country_preset(Req({"cc": "ru", "name": "Россия"}))
        b = routing.country_preset(Req({"cc": "RU", "name": "Россия"}))
        self.assertEqual((a["country"], a["domains"]), (b["country"], b["domains"]))   # второй раз — те же списки
        self.assertEqual(b["made"], [])                            # новых нет (окно правила удаляет только новые)
        self.assertEqual(a["country"], "ru")
        st = panel.store.snapshot()
        self.assertEqual([l["id"] for l in st["lists"]].count("ru"), 1)
        dom = Store.lst(st, a["domains"])
        self.assertEqual((dom["kind"], dom["name"]), ("domains", ".ru .su .рф"))      # не спутать со страной
        self.assertEqual(panel.store.list_text(a["domains"]), ".ru\n.su\n.рф")
        self.assertEqual(st["routing"]["rules"], [])              # без apply — правил нет
        routing.country_preset(Req({"cc": "ru", "name": "Россия", "apply": True}))
        rules = panel.store.snapshot()["routing"]["rules"]
        self.assertEqual([(r["lists"], r["outbound"], r.get("dns")) for r in rules],
                         [([a["domains"]], "direct", ["77.88.8.8", "77.88.8.1"]), (["ru"], "direct", None)])
        routing.country_preset(Req({"cc": "ru", "apply": True}))   # второй раз (другая вкладка) — без повторов
        self.assertEqual(panel.store.snapshot()["routing"]["rules"], rules)
        self.assertEqual(code(lambda: routing.country_preset(Req({"cc": "de"}))), (400, "err.bad_value"))

    def test_panel_code(self):
        ov = read("app", "static", "js", "overview.js")
        self.assertIn("if (S.routing.rules.length || !S.country_presets) return \"\";", ov)   # пока правил нет
        self.assertIn('{ ru: ["ru", "cn", "ir"], zh: ["cn", "ru", "ir"], fa: ["ir", "ru", "cn"] }', ov)
        self.assertIn('api("POST", "country-preset", { cc, apply: true })', ov)
        rt = read("app", "static", "js", "routing.js")
        self.assertIn('return !S.clients.length || ask(t("cp.dns_confirm"), { from, warn: true });', rt)   # клиенты есть — спросить
        self.assertIn('await api("PUT", "server", { panel_dns: true });', rt)
        # 1.23.0 (владелец, 2026-11-20): готовые правила страны — только кнопки «Применить для …» (вопрос про DNS на
        # сервере — до запроса); в окне правила список страны — просто список, правила её доменов он не добавляет
        self.assertIn("if (!await panelDnsAsk(pseudo, b)) return;", ov)
        self.assertLess(ov.index("if (!await panelDnsAsk(pseudo, b)) return;"), ov.index('api("POST", "country-preset", { cc, apply: true })'))
        self.assertNotIn("countryPick", rt)
        self.assertNotIn("panelDnsAsk", read("app", "static", "js", "clients.js"))
        self.assertNotIn("cascade", read("app", "static", "js", "server.js").replace("srv.panel_dns_cascade", ""))
        self.assertIn('"country_presets": countries.view()', read("app", "api", "state.py"))


class DirectFallbackTest(unittest.TestCase):
    """Шифрованный DNS не проходит напрямую из страны сервера (Россия, Китай, Иран, 2026): путь «напрямую» спрашивает
    местный DNS обычным DNS и DIRECT_RETRY не ждёт шифрованного; путь через выход — никогда (мимо выхода)."""

    def _proxy(self, fallback):
        import json as _json
        from app import dnsproxy
        d = tempfile.mkdtemp()
        conf = os.path.join(d, "dns.json")
        with open(conf, "w") as f:
            _json.dump({"listen": "10.8.1.1", "port": 53, "clients": "10.8.1.0/24", "upstreams": ["1.1.1.1"],
                        "encrypt": "doh", "direct_fallback": fallback, "default": {"mark": 0, "tcp": False},
                        "routes": {"10.8.1.7": {"mark": 0x1000, "tcp": False}}}, f)
        return dnsproxy.Proxy(conf)

    def run_q(self, p, names, ip="10.8.1.5", wait_probe=False):
        import asyncio
        from app import dnsproxy
        from tests.test_v115 import q_msg

        async def go():
            out = []
            for n in names:
                query = q_msg(n)
                t0 = time.monotonic()
                out.append(await p.resolve(query, dnsproxy.parse_query(query), ip))
                p._waited = time.monotonic() - t0
            if wait_probe and p._direct_probe:
                await p._direct_probe                 # фоновая проба шифрованного DNS
            return out
        return asyncio.run(go())

    def test_direct_asks_local_dns(self):
        import socket
        from tests.test_v115 import a_reply
        p = self._proxy(["77.88.8.8"])
        enc, plain = [], []

        async def blocked(msg, server, mark, mode):
            enc.append((server, mark))
            raise OSError("reset")

        async def udp(msg, server, mark):
            plain.append((server, mark))
            return a_reply(msg, ["203.0.113.7"])
        p._enc, p._udp = blocked, udp
        out = self.run_q(p, ["google.com", "example.org"])
        self.assertIn(socket.inet_aton("203.0.113.7"), out[0])
        self.assertEqual(enc, [("1.1.1.1", 0)])                       # второе имя — сразу у местного
        self.assertEqual(plain, [("77.88.8.8", 0), ("77.88.8.8", 0)])
        self.assertEqual(p.stats["direct_fallback"], 2)
        self.assertGreater(p.direct_fail_at, p.direct_ok_at)
        self.assertTrue(p.direct_down)
        p.direct_retry_at = 0                                         # прошло DIRECT_RETRY — снова шифрованный (в фоне)
        self.run_q(p, ["example.net"], wait_probe=True)
        self.assertEqual(len(enc), 2)
        self.assertEqual(plain[-1], ("77.88.8.8", 0))                 # клиенту ответил местный, не дожидаясь пробы

    def test_client_never_waits_for_the_retry(self):
        """Проверка 1.22.0, второй круг: DoH из России «зависает» до таймаута. Проба шифрованного раз в DIRECT_RETRY
        шла с запросом клиента — и раз в две минуты имена «напрямую» стояли ~10 с. Теперь проба — в фоне."""
        import asyncio
        from tests.test_v115 import a_reply
        p = self._proxy(["77.88.8.8"])
        state = {"enc_ok": False}

        async def enc(msg, server, mark, mode):
            await asyncio.sleep(0.3)                                  # «зависший» DoH
            if state["enc_ok"]:
                return a_reply(msg, ["198.51.100.1"])
            raise asyncio.TimeoutError()

        async def udp(msg, server, mark):
            return a_reply(msg, ["203.0.113.7"])
        p._enc, p._udp = enc, udp
        self.run_q(p, ["a.example"])                                  # первый раз — ждёт и уходит к местному
        self.assertTrue(p.direct_down)
        p.direct_retry_at, state["enc_ok"] = 0, True
        t0 = time.monotonic()
        self.run_q(p, ["b.example"], wait_probe=True)
        self.assertLess(p._waited, 0.2)                               # клиент ответ получил сразу
        self.assertGreater(time.monotonic() - t0, 0.25)               # а проба отработала в фоне
        self.assertFalse(p.direct_down)                               # шифрованный снова отвечает
        self.assertGreater(p.direct_ok_at, p.direct_fail_at)

    def test_servfail_is_an_answer(self):
        """SERVFAIL общего сервера — сломан сам сайт, а не шифрованный DNS: местный не включается и предупреждения нет."""
        from app import dnsproxy
        from tests.test_v115 import a_reply
        p = self._proxy(["77.88.8.8"])
        plain = []

        async def enc(msg, server, mark, mode):
            return a_reply(msg, [], rcode=dnsproxy.RC_SERVFAIL)

        async def udp(msg, server, mark):
            plain.append(server)
            return a_reply(msg, ["203.0.113.7"])
        p._enc, p._udp = enc, udp
        out = self.run_q(p, ["broken.example"])
        self.assertEqual(out[0][3] & 0xF, dnsproxy.RC_SERVFAIL)
        self.assertEqual(plain, [])
        self.assertFalse(p.direct_down)
        self.assertGreater(p.direct_ok_at, p.direct_fail_at)
        self.assertEqual(p.stats["errors"], 1)

    def test_rule_without_path_never_falls_back(self):
        """Имя из правила по доменам, у которого выход подключается, лежит или «блок» (путь None), у клиента
        «напрямую»: к местному DNS открытым текстом оно не уходит — сайт должен идти через выход."""
        import json as _json
        from app import dnsproxy
        for rule in ([["l1"], None], [["l1"], None, ["8.8.4.4"], False]):
            d = tempfile.mkdtemp()
            lst = os.path.join(d, "l1.txt")
            with open(lst, "w") as f:
                f.write("youtube.com\n")
            conf = os.path.join(d, "dns.json")
            with open(conf, "w") as f:
                _json.dump({"listen": "10.8.1.1", "port": 53, "clients": "10.8.1.0/24", "upstreams": ["1.1.1.1"],
                            "encrypt": "doh", "direct_fallback": ["77.88.8.8"], "default": {"mark": 0, "tcp": False},
                            "routes": {}, "dom": {"lists": {"l1": lst}, "policies": {"p_global": [rule]},
                                                  "clients": {}, "set": None}}, f)
            p = dnsproxy.Proxy(conf)
            plain = []

            async def blocked(msg, server, mark, mode):
                raise OSError("reset")

            async def udp(msg, server, mark):
                plain.append(server)
                return None
            p._enc, p._udp = blocked, udp
            out = self.run_q(p, ["www.youtube.com", "example.org"])
            self.assertEqual(out[0][3] & 0xF, dnsproxy.RC_SERVFAIL, rule)
            self.assertEqual(plain, ["77.88.8.8"], rule)             # только второе имя — оно не из правила

    def test_direct_down_shown_on_the_server_tab(self):
        import json as _json
        import types
        from app.engine import Engine
        from app.engine import dns as edns
        e = Engine.__new__(Engine)
        e.dns_state = {"state": "on", "listen": "10.8.1.1", "encrypt": "doh"}
        e.dns = types.SimpleNamespace(proc=types.SimpleNamespace(pid=4242))
        path = os.path.join(tempfile.mkdtemp(), "dns-stats.json")
        now = time.time()
        for ok_at, fail_at, fb, want in ((now - 60, now - 5, ["77.88.8.8"], True),
                                         (now - 60, now - 5, [], True),
                                         (now - 1, now - 5, ["77.88.8.8"], None),          # снова отвечает
                                         (0, now - 1000, ["77.88.8.8"], None)):            # давно — не тревожим
            with open(path, "w") as f:
                _json.dump({"pid": 4242, "at": now, "direct_ok_at": ok_at, "direct_fail_at": fail_at,
                            "fallback": fb}, f)
            with mock.patch.object(edns, "DNS_STATS", path), mock.patch.object(config, "DRY_RUN", False):
                self.assertEqual(e.dns_view().get("direct_down"), want)
        # 1.25.0: «Серверы DNS не отвечают напрямую» — и без шифрования (запасной работает при любом)
        with open(path, "w") as f:
            _json.dump({"pid": 4242, "at": now, "direct_ok_at": now - 60, "direct_fail_at": now - 5, "fallback": [],
                        "encrypt": "plain"}, f)
        with mock.patch.object(edns, "DNS_STATS", path), mock.patch.object(config, "DRY_RUN", False):
            self.assertTrue(e.dns_view().get("direct_down"))

    def test_new_servers_forget_the_old_failure(self):
        """Другие серверы DNS или шифрование (SIGHUP): прежнее «шифрованный не отвечает» к ним не относится."""
        import json as _json
        p = self._proxy(["77.88.8.8"])
        p._direct_seen(False, True)
        self.assertTrue(p.direct_down)
        with open(p.conf_path) as f:
            cfg = _json.load(f)
        cfg["upstreams"] = ["9.9.9.9"]
        with open(p.conf_path, "w") as f:
            _json.dump(cfg, f)
        p.load()
        self.assertFalse(p.direct_down)
        self.assertEqual((p.direct_ok_at, p.direct_fail_at, p.direct_retry_at), (0.0, 0.0, 0.0))

    def test_exit_path_never_falls_back(self):
        from app import dnsproxy
        p = self._proxy(["77.88.8.8"])
        plain = []

        async def blocked(msg, server, mark, mode):
            raise OSError("reset")

        async def udp(msg, server, mark):
            plain.append(server)
            return None
        p._enc, p._udp = blocked, udp
        out = self.run_q(p, ["google.com"], ip="10.8.1.7")              # клиент идёт через выход
        self.assertEqual(out[0][3] & 0xF, dnsproxy.RC_SERVFAIL)
        self.assertEqual(plain, [])
        p = self._proxy([])                                             # без запасного DNS — только ошибка
        p._enc, p._udp = blocked, udp
        self.assertEqual(self.run_q(p, ["google.com"])[0][3] & 0xF, dnsproxy.RC_SERVFAIL)
        self.assertEqual(plain, [])
        self.assertIn('v["direct_down"]', read("app", "engine", "dns.py"))
        self.assertIn('t("srv.pdns_direct_down"', read("app", "static", "js", "server.js"))
        self.assertIn('t("srv.pdns_fb_used")', read("app", "static", "js", "server.js"))


class RecoverRenamedTest(unittest.TestCase):
    """Проверка 1.22.0 (Н3): смену порта или обновление своего контейнера прервали (панель упала, VPS выключился,
    оборвался SSH) — контейнер сервера остался выключенным под именем «-old-» или «-prev-» и без автозапуска, VPN
    не работал бы. Панель возвращает ему имя и автозапуск и запускает — но не во время работы установщика и не
    сразу (идущую замену не спутать с прерванной)."""

    def run_recover(self, names, finished_ago=300, running=False, mode="container", installing=False, mark="auto",
                    policy="no"):
        from app import selfupdate, system
        calls = []
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S.123456789Z", time.gmtime(time.time() - finished_ago))
        if mark == "auto":            # «-old-» оставила смена порта панели: её отметка с прежним конфигом
            old = next((n for n in names if "-old-" in n), None)
            mark = {"old": old, "dir": "/opt/amnezia/awg", "iface": "awg0", "conf": "OLD CONF"} if old else None
        system._port_mark(mark)

        def get(path):
            if path.startswith("/containers/json"):
                return [{"Names": ["/" + n]} for n in names]
            return {"State": {"Running": running, "FinishedAt": stamp}, "HostConfig": {"RestartPolicy": {"Name": policy}}}

        def api(method, path, timeout=10, body=None):
            calls.append((method, path, body))
            return {}
        system.recovered.clear()
        with mock.patch.object(system, "docker_get", get), mock.patch.object(system, "docker_api", api), \
                mock.patch.object(config, "AWG_MODE", mode), mock.patch.object(config, "AWG_CONTAINER", ""), \
                mock.patch.object(selfupdate, "installer_running", lambda: installing):
            return system.recover_renamed(), calls

    def test_interrupted_port_change_brought_back(self):
        """Второй круг проверки 1.22.0: в прежнем контейнере уже конфиг с новым портом, а Docker открывает прежний —
        без возврата конфига вернувшийся сервер слушал бы не тот порт, и VPN так и не работал бы."""
        import io
        import tarfile
        from app import system
        name, calls = self.run_recover(["awg-router", "amnezia-awg2-old-20261119-045800"])
        self.assertEqual(name, "amnezia-awg2")
        self.assertEqual([(m, p.split("?")[0]) for m, p, _ in calls],
                         [("PUT", "/containers/amnezia-awg2-old-20261119-045800/archive"),
                          ("POST", "/containers/amnezia-awg2-old-20261119-045800/rename"),
                          ("POST", "/containers/amnezia-awg2/update"), ("POST", "/containers/amnezia-awg2/start")])
        self.assertIn("path=/opt/amnezia/awg", calls[0][1].replace("%2F", "/"))
        with tarfile.open(fileobj=io.BytesIO(calls[0][2])) as tf:
            self.assertEqual(tf.extractfile("awg0.conf").read(), b"OLD CONF")     # прежний конфиг — прежний порт
        self.assertIn("name=amnezia-awg2", calls[1][1])
        self.assertEqual(calls[2][2], {"RestartPolicy": {"Name": "always"}})
        self.assertEqual(system.recovered, ["amnezia-awg2"])
        self.assertEqual(system._port_mark_get(), {})                           # отметка смены порта снята
        system.recovered.clear()

    def test_latest_of_two_and_installer_prev(self):
        name, calls = self.run_recover(["amnezia-awg2-old-20261101-100000", "amnezia-awg2-prev-20261119-050000"])
        self.assertEqual(name, "amnezia-awg2")
        self.assertIn("/containers/amnezia-awg2-prev-20261119-050000/rename", calls[0][1])

    def test_left_alone(self):
        cases = {
            "контейнер с обычным именем есть": dict(names=["amnezia-awg2", "amnezia-awg2-old-20261119-045800"]),
            "замена идёт сейчас": dict(names=["amnezia-awg2-old-20261119-045800"], finished_ago=10),
            "прежний работает": dict(names=["amnezia-awg2-old-20261119-045800"], running=True),
            "работает установщик": dict(names=["amnezia-awg2-prev-20261119-050000"], installing=True),
            "сервер на хосте": dict(names=["amnezia-awg2-old-20261119-045800"], mode="auto"),
            "отложенный установщиком пустой": dict(names=["amnezia-awg2-empty-20261119-045800"]),
            # установщик, ставя новый сервер вместо неисправного, оставляет прежний «-old-» нарочно
            "«-old-» без отметки смены порта": dict(names=["amnezia-awg2-old-20261119-045800"], mark=None),
            "отметка о другом контейнере": dict(names=["amnezia-awg2-old-20261119-045800"],
                                               mark={"old": "amnezia-awg2-old-20261118-010101", "conf": "X"}),
        }
        for what, kw in cases.items():
            with self.subTest(what):
                name, calls = self.run_recover(**kw)
                self.assertIsNone(name)
                self.assertEqual(calls, [])

    def test_cut_off_before_the_rename(self):
        """Смену порта прервали раньше переименования: контейнер с обычным именем выключен, автозапуск «no», а в нём
        уже конфиг с новым портом. Его — тоже: прежний конфиг, автозапуск, запуск (без переименования). Выключенный
        руками (автозапуск остался) не трогаем."""
        mk = {"old": "amnezia-awg2-old-20261119-045800", "dir": "/opt/amnezia/awg", "iface": "awg0", "conf": "OLD"}
        name, calls = self.run_recover(["amnezia-awg2"], mark=mk)
        self.assertEqual(name, "amnezia-awg2")
        self.assertEqual([(m, p.split("?")[0]) for m, p, _ in calls],
                         [("PUT", "/containers/amnezia-awg2/archive"), ("POST", "/containers/amnezia-awg2/update"),
                          ("POST", "/containers/amnezia-awg2/start")])
        from app import system
        system.recovered.clear()
        for kw in (dict(policy="always"), dict(mark=None), dict(finished_ago=10)):
            name, calls = self.run_recover(["amnezia-awg2"], **{"mark": mk, **kw})
            self.assertIsNone(name, kw)
            self.assertEqual([c for c in calls if c[0] != "GET"], [], kw)

    def test_other_family_does_not_block(self):
        """Рядом контейнер приложения другого протокола (amnezia-awg, выключен) — прерванная смена порта amnezia-awg2
        всё равно возвращается."""
        name, calls = self.run_recover(["amnezia-awg", "amnezia-awg2-old-20261119-045800"])
        self.assertEqual(name, "amnezia-awg2")
        from app import system
        system.recovered.clear()

    def test_stale_mark_dropped_when_the_server_runs(self):
        """Панель упала уже после смены порта (новый контейнер работает) — отметка снимается при следующем проходе:
        иначе, пропади потом контейнер, вернулся бы давний «-old-», а в общую папку лёг бы прежний конфиг."""
        from app import system
        for running, mark_old, kept in (("amnezia-awg2", "amnezia-awg2-old-20261119-045800", False),
                                        ("amnezia-awg", "amnezia-awg2-old-20261119-045800", True)):
            system._port_mark({"old": mark_old, "dir": "/opt/amnezia/awg", "iface": "awg0", "conf": "OLD"})
            with mock.patch.object(config, "AWG_MODE", "container"), mock.patch.object(config, "AWG_CONTAINER", ""), \
                    mock.patch.object(system, "docker_containers", lambda: [running]), \
                    mock.patch.object(system, "_container_target", lambda n: n):
                self.assertEqual(system.discover(), running)
            self.assertEqual(bool(system._port_mark_get()), kept, running)
        system._port_mark(None)

    def test_discover_uses_it(self):
        from app import system
        src = read("app", "system.py")
        self.assertIn("find_amnezia_container() or recover_renamed()", src)
        self.assertIn('Msg("ev.container_recovered"', read("app", "engine", "__init__.py"))
        for s in ("0001-01-01T00:00:00Z", "", None, "bad"):       # не останавливался или непонятно — «давно»
            self.assertLess(system._docker_time(s), time.time() - 3600)
        self.assertAlmostEqual(system._docker_time("2026-11-19T04:58:02.123456789Z"), 1795064282, delta=1)


class BotLogoTest(unittest.TestCase):
    """Новая картинка меню бота: file_id прежней (сохранённый до обновления) не берётся."""

    def test_logo_white_and_taller(self):
        with open(tgbot.LOGO, "rb") as f:
            head = f.read(24)
        self.assertEqual(head[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(int.from_bytes(head[16:20], "big"), 1200)
        self.assertEqual(int.from_bytes(head[20:24], "big"), 780)

    def test_cached_id_of_old_picture_not_used(self):
        src = read("app", "tgbot.py")
        self.assertIn('self._st.get("logo_sum") == logo_sum()', src)
        self.assertIn('self._st["logo_sum"] = logo_sum()', src)
        self.assertEqual(len(tgbot.logo_sum()), 16)


if __name__ == "__main__":
    unittest.main()
