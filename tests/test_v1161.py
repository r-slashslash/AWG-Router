"""1.16.1: выход SOCKS5 без связи за прокси считается неработающим (issue #9) и уведомления
в Telegram не зависят от одного выхода: другие пути, очередь, заметная ошибка (issue #10).

python3 -m unittest discover tests
"""
import collections
import json
import os
import queue
import socket
import struct
import sys
import tempfile
import threading
import unittest
import urllib.error
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import notify, socks  # noqa: E402
from app.engine import Engine  # noqa: E402
from app.i18n import Msg  # noqa: E402

TOKEN = "123456789:" + "A" * 35


# ------------------------------------------------------------------ #9: прокси, за которым ничего нет
def lying_socks(mode):
    """Прокси SOCKS5 без входа, который отвечает «соединение открыто» сразу, не дозвонившись
    до цели (так отвечает локальный Xray, когда зарубежный сервер недоступен).
    mode: dead — потом закрывает соединение, hang — молчит, alive — отвечает байтами TLS."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def recvn(c, n):
        buf = b""
        while len(buf) < n:
            chunk = c.recv(n - len(buf))
            if not chunk:
                raise OSError("closed")
            buf += chunk
        return buf

    def client(c):
        try:
            _, n = recvn(c, 2)
            recvn(c, n)
            c.sendall(b"\x05\x00")
            recvn(c, 10)                                    # CONNECT к IPv4-адресу
            c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            if mode == "dead":
                return
            if mode == "alive":
                recvn(c, 5)                                 # заголовок записи TLS
                c.sendall(b"\x15\x03\x03\x00\x02\x02\x28")  # alert handshake_failure — тоже ответ
            else:
                threading.Event().wait(5)
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=client, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1]


class SocksDataCheckTest(unittest.TestCase):
    def setUp(self):
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.close()

    def proxy(self, mode):
        srv, port = lying_socks(mode)
        self.servers.append(srv)
        return port

    def test_client_hello_is_well_formed(self):
        h = socks.client_hello()
        self.assertEqual(h[:3], b"\x16\x03\x01")
        self.assertEqual(struct.unpack("!H", h[3:5])[0], len(h) - 5)       # длина записи
        self.assertEqual(h[5], 1)                                           # ClientHello
        self.assertEqual(int.from_bytes(h[6:9], "big"), len(h) - 9)         # длина рукопожатия
        self.assertNotEqual(socks.client_hello(), h)                        # random каждый раз новый

    def test_plain_connect_is_fooled(self):
        """Без данных такой прокси выглядит рабочим: так и было в #9."""
        port = self.proxy("dead")
        self.assertGreaterEqual(socks.connect_check("127.0.0.1", port, target=("1.1.1.1", 443)), 0)

    def test_nothing_behind_proxy(self):
        for mode in ("dead", "hang"):
            with self.subTest(mode=mode):
                port = self.proxy(mode)
                with self.assertRaises(socks.SocksError) as cm:
                    socks.connect_check("127.0.0.1", port, target=("1.1.1.1", 443), timeout=1, data=True)
                self.assertEqual(cm.exception.msg.key, "socks.no_data")

    def test_answer_behind_proxy(self):
        port = self.proxy("alive")
        ms = socks.connect_check("127.0.0.1", port, target=("1.1.1.1", 443), timeout=3, data=True)
        self.assertGreaterEqual(ms, 0)

    def test_check_result(self):
        """socks.check: нет ответа за прокси — не работает, и ошибка понятна человеку."""
        with mock.patch.object(socks, "CHECK_TARGETS", (("1.1.1.1", 443), ("8.8.8.8", 443))):
            dead = socks.check({"host": "127.0.0.1", "port": self.proxy("dead")})
            self.assertFalse(dead["ok"])
            self.assertEqual(dead["error"].key, "socks.no_data")
            alive = socks.check({"host": "127.0.0.1", "port": self.proxy("alive")})
            self.assertTrue(alive["ok"])
            self.assertIsNone(alive["error"])


# ------------------------------------------------------------------ #10: уведомления
def cfg_state(via="up:a", enabled=True, lang="en"):
    c = notify.defaults()
    c.update(enabled=enabled, token=TOKEN, chat_id="42", via=via, lang=lang)
    return {"settings": {"telegram": c}}


def make_notifier(state):
    n = notify.Notifier.__new__(notify.Notifier)
    n.store = mock.Mock(snapshot=lambda: state)
    n.host_fn = lambda st: "h"
    n.q, n.pending, n._sent, n.last_error = queue.Queue(), collections.deque(), {}, None
    n.buttons_fn = None
    n._target_lost = False
    return n


class FakeSend:
    """notify.send: пути из down и вне ok не работают, остальные доставляют."""

    def __init__(self, down=(), refused=()):
        self.down, self.refused, self.calls, self.delivered = set(down), set(refused), [], []

    def __call__(self, token, chat, text, via="direct", markup=None, html=False):
        self.calls.append(via)
        if via in self.refused:
            raise notify.NotifyError("Unauthorized")
        if via in self.down:
            raise notify.NotifyError("api.telegram.org: timed out", net=True)
        self.delivered.append((via, text))
        return {}


class NotifyErrorKindTest(unittest.TestCase):
    def post(self, **kw):
        with mock.patch.object(notify, "_post_direct", **kw):
            return notify._post(TOKEN, "sendMessage", b"{}", "application/json", 1, "direct")

    def test_network_failure_is_net(self):
        with self.assertRaises(notify.NotifyError) as cm:
            self.post(side_effect=urllib.error.URLError("timed out"))
        self.assertTrue(cm.exception.net)

    def test_telegram_refusal_is_not_net(self):
        body = json.dumps({"ok": False, "error_code": 401, "description": "Unauthorized"}).encode()
        with self.assertRaises(notify.NotifyError) as cm:
            self.post(return_value=(401, body))
        self.assertFalse(cm.exception.net)

    def test_server_trouble_is_net(self):
        for code in (429, 502):
            body = json.dumps({"ok": False, "error_code": code, "description": "x"}).encode()
            with self.subTest(code=code), self.assertRaises(notify.NotifyError) as cm:
                self.post(return_value=(code, body))
            self.assertTrue(cm.exception.net)


class NotifyFallbackTest(unittest.TestCase):
    def setUp(self):
        self.alt = mock.patch.object(notify, "alt_routes", lambda via: ["up:b", "up:c"])
        self.alt.start()

    def tearDown(self):
        self.alt.stop()

    def test_routes_order(self):
        n = make_notifier(cfg_state())
        self.assertEqual(n.routes("up:a"), ["up:a", "up:b", "up:c", "direct"])
        self.assertEqual(n.routes("direct"), ["direct"])        # «напрямую» человек выбрал сам

    def test_other_exit_when_selected_is_down(self):
        n, fake = make_notifier(cfg_state()), FakeSend(down={"up:a"})
        with mock.patch.object(notify, "send", fake):
            n.deliver(TOKEN, "42", "text", "up:a", None)
        self.assertEqual(fake.calls, ["up:a", "up:b"])

    def test_direct_is_the_last_resort(self):
        n, fake = make_notifier(cfg_state()), FakeSend(down={"up:a", "up:b", "up:c"})
        with mock.patch.object(notify, "send", fake):
            n.deliver(TOKEN, "42", "text", "up:a", None)
        self.assertEqual(fake.calls, ["up:a", "up:b", "up:c", "direct"])

    def test_error_of_selected_route_is_reported(self):
        n = make_notifier(cfg_state())
        errors = [notify.NotifyError(w, net=True) for w in ("first", "second", "third", "fourth")]
        with mock.patch.object(notify, "send", side_effect=errors):
            with self.assertRaises(notify.NotifyError) as cm:
                n.deliver(TOKEN, "42", "text", "up:a", None)
        self.assertEqual(str(cm.exception), "first")

    def test_telegram_refusal_does_not_try_other_routes(self):
        n, fake = make_notifier(cfg_state()), FakeSend(refused={"up:a"})
        with mock.patch.object(notify, "send", fake):
            with self.assertRaises(notify.NotifyError):
                n.deliver(TOKEN, "42", "text", "up:a", None)
        self.assertEqual(fake.calls, ["up:a"])


class NotifyQueueTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(notify, "alt_routes", lambda via: [])
        p.start()
        self.addCleanup(p.stop)

    def item(self, text, ts):
        return (TOKEN, "42", text, "up:a", None, ts)

    def test_kept_until_route_comes_back(self):
        n = make_notifier(cfg_state())
        n.pending.extend([self.item("one", 1000.0), self.item("two", 1001.0)])
        down = FakeSend(down={"up:a", "direct"})
        with mock.patch.object(notify, "send", down):
            self.assertFalse(n.flush(now=1002.0))
        self.assertEqual(len(n.pending), 2)                       # ничего не потеряно
        self.assertIn("timed out", str(n.last_error))
        up = FakeSend()
        with mock.patch.object(notify, "send", up):
            self.assertTrue(n.flush(now=1003.0))
        self.assertEqual([t for _, t in up.delivered], ["one", "two"])    # по порядку
        self.assertFalse(n.pending)
        self.assertIsNone(n.last_error)

    def test_late_message_says_when_it_happened(self):
        n = make_notifier(cfg_state())
        n.pending.append(self.item("exit down", 1000.0))
        fake = FakeSend()
        with mock.patch.object(notify, "send", fake):
            n.flush(now=1000.0 + 3600)
        text = fake.delivered[0][1]
        self.assertTrue(text.endswith("exit down"))
        self.assertIn("01.01 00:16 UTC", text)                    # 1000 с от начала эпохи

    def test_fresh_message_has_no_note(self):
        n = make_notifier(cfg_state())
        n.pending.append(self.item("exit down", 1000.0))
        fake = FakeSend()
        with mock.patch.object(notify, "send", fake):
            n.flush(now=1010.0)
        self.assertEqual(fake.delivered[0][1], "exit down")

    def test_old_messages_are_dropped(self):
        n = make_notifier(cfg_state())
        n.pending.append(self.item("ancient", 1000.0))
        fake = FakeSend()
        with mock.patch.object(notify, "send", fake):
            self.assertTrue(n.flush(now=1000.0 + notify.Notifier.MAX_AGE + 1))
        self.assertEqual(fake.calls, [])
        self.assertFalse(n.pending)

    def test_refused_message_is_dropped_but_next_goes(self):
        n = make_notifier(cfg_state())
        n.pending.extend([self.item("bad", 1000.0), self.item("good", 1000.0)])

        def send(token, chat, text, via="direct", markup=None, html=False):
            if text == "bad":
                raise notify.NotifyError("Bad Request: chat not found")
            return {}
        with mock.patch.object(notify, "send", side_effect=send) as m:
            self.assertTrue(n.flush(now=1001.0))
        self.assertEqual(m.call_count, 2)
        self.assertFalse(n.pending)
        self.assertIsNone(n.last_error)

    def test_uses_current_route_setting(self):
        """Человек поправил «Отправлять через» — ждущие сообщения идут уже по новому пути."""
        state = cfg_state(via="direct")
        n = make_notifier(state)
        n.pending.append(self.item("queued", 1000.0))            # поставлено, когда был up:a
        fake = FakeSend(down={"up:a"})
        with mock.patch.object(notify, "send", fake):
            n.flush(now=1001.0)
        self.assertEqual(fake.calls, ["direct"])

    def test_disabled_notifications_clear_the_queue(self):
        n = make_notifier(cfg_state(enabled=False))
        n.pending.append(self.item("x", 1000.0))
        self.assertTrue(n.flush(now=1001.0))
        self.assertFalse(n.pending)

    def test_take_keeps_order_and_limit(self):
        n = make_notifier(cfg_state())
        for i in range(notify.Notifier.MAX_PENDING + 5):
            n.q.put((TOKEN, "42", str(i), "up:a", None, 1000.0))
        n._take(0.01)
        self.assertEqual(len(n.pending), notify.Notifier.MAX_PENDING)
        self.assertEqual(n.pending[-1][2], str(notify.Notifier.MAX_PENDING + 4))   # новые сохранены
        self.assertEqual(n.pending[0][2], "5")                                     # старые выброшены

    def test_event_stamps_time(self):
        n = make_notifier(cfg_state())
        n.event("exit", "exit_down", name="NL")
        item = n.q.get_nowait()
        self.assertEqual(len(item), 6)
        self.assertGreater(item[5], 0)


class AltRoutesTest(unittest.TestCase):
    def test_only_working_exits_except_selected(self):
        ups = [{"id": i, "enabled": e} for i, e in (("a", True), ("b", True), ("c", True), ("d", False))]
        fake = mock.Mock(store=mock.Mock(snapshot=lambda: {"upstreams": ups}),
                         health={"a": {"healthy": True}, "b": {"healthy": True},
                                 "c": {"healthy": False}, "d": {"healthy": True}})
        self.assertEqual(Engine.alt_routes(fake, "up:a"), ["up:b"])        # c лежит, d выключен


class TextsTest(unittest.TestCase):
    def test_late_text_in_all_languages(self):
        for lang in notify.LANGS:
            with self.subTest(lang=lang):
                self.assertIn("{time}", notify.TEXTS[lang]["late"])
        self.assertEqual(Msg("socks.no_data").key, "socks.no_data")


if __name__ == "__main__":
    unittest.main()
