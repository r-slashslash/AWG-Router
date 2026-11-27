"""DoH по HTTP/2 и HTTP/3 (app/dohttp.py; проверка 1.25.0, А1, владелец 2026-11-27): Quad9 и Яндекс по HTTP/1.1 больше
не отвечают. Здесь — настоящий dnsproxy.py против своих серверов: HTTP/2 поверх настоящего TLS с ALPN h2 (кадры
сервера — свои, как у nghttp2), HTTP/3 — настоящий QUIC из OpenSSL (сервер на его же API). HTTP/3 нужен OpenSSL 3.5+
(в образе панели он есть; на машине CI — нет): без него тест пропускается, путь к libssl можно задать
AWGR_TEST_LIBSSL."""
import ctypes
import json
import os
import select
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import dnsaddr, dnsproxy, dohttp  # noqa: E402
from tests.test_v115 import a_reply, q_msg  # noqa: E402


def cert(d: str, name: str = "dns.test", ips: tuple = ()) -> tuple[str, str]:
    crt, key = os.path.join(d, "c.crt"), os.path.join(d, "c.key")
    san = ",".join([f"DNS:{name}"] + [f"IP:{ip}" for ip in ips])
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-days", "2", "-subj", "/CN=dns-test", "-addext", f"subjectAltName={san}",
                    "-keyout", key, "-out", crt], capture_output=True, check=True)
    return crt, key


class H2Server:
    """Сервер DoH по HTTP/2: TLS с ALPN h2, свои SETTINGS, PING, ответ — заголовки и данные (по выбору теста:
    код, Хаффман в коде, паддинг, CONTINUATION, сброс потока, GOAWAY). Клиент без ALPN — DoT. slow — имя → через
    сколько секунд ответ (у имени молчат его серверы имён); frozen — соединения и запросы принимаются, ответа нет (DoH
    «замерзает» после рукопожатия)."""

    def __init__(self, crt: str, key: str, addr: str = "127.0.0.1"):
        self.ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ctx.load_cert_chain(crt, key)
        self.ctx.set_alpn_protocols(["h2"])
        self.sock = socket.socket()
        self.sock.bind((addr, 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.mode, self.seen, self.conns = "ok", [], 0
        self.slow, self.frozen = {}, False
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    @staticmethod
    def recv(s, n):
        b = b""
        while len(b) < n:
            d = s.recv(n - len(b))
            if not d:
                raise ConnectionError
            b += d
        return b

    def delay(self, msg: bytes) -> bool:
        """Медленное имя — подождать; «замёрз» — False (не отвечать)."""
        if self.frozen:
            return False
        time.sleep(self.slow.get(dnsproxy.read_name(msg, 12), 0))
        return not self.frozen

    def one(self, raw):
        s = raw
        try:
            s = self.ctx.wrap_socket(raw, server_side=True)
            self.conns += 1
            if s.selected_alpn_protocol() != "h2":       # DoT: длина и запрос, ответ — так же
                while True:
                    q = self.recv(s, struct.unpack("!H", self.recv(s, 2))[0])
                    self.seen.append(q)
                    if self.delay(q):
                        body = a_reply(q, ["203.0.113.9"])
                        s.sendall(struct.pack("!H", len(body)) + body)
            assert self.recv(s, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            s.sendall(dohttp.h2_frame(4, 0, 0, struct.pack("!HI", 3, 100)) + dohttp.h2_frame(6, 0, 0, b"12345678"))
            streams = {}
            while True:
                head = self.recv(s, 9)
                n = int.from_bytes(head[:3], "big")
                typ, flags, sid = head[3], head[4], struct.unpack("!I", head[5:])[0]
                payload = self.recv(s, n) if n else b""
                if typ == 1:
                    streams[sid] = {"head": payload, "data": b""}
                elif typ == 0:
                    streams[sid]["data"] += payload
                    if flags & 1:
                        self.answer(s, sid, streams.pop(sid))
                elif typ == 6 and flags & 1:
                    self.seen.append("pong")
        except (OSError, ConnectionError, AssertionError, ssl.SSLError):
            pass
        finally:
            s.close()

    def answer(self, s, sid, req):
        self.seen.append(req["head"])
        if not self.delay(req["data"]):
            return
        body = a_reply(req["data"], ["203.0.113.9"])
        mode = self.mode
        if mode == "goaway":
            s.sendall(dohttp.h2_frame(7, 0, 0, struct.pack("!II", 0, 0)))
            return
        if mode == "reset":
            s.sendall(dohttp.h2_frame(3, 0, sid, struct.pack("!I", 2)))
            return
        hdr = {"ok": b"\x88", "404": b"\x8d", "huffman": b"\x48\x82\x10\x01", "table": b"\x3f\xe1\x1f\x88",
               "cut": b"\x48"}.get(mode, b"\x88")
        if mode == "badpad":                        # паддинг длиннее кадра
            s.sendall(dohttp.h2_frame(1, 0x8 | 0x4, sid, b"\x05\x88") + dohttp.h2_frame(0, 0x1, sid, body))
            return
        if mode == "split":                         # HEADERS с паддингом без END_HEADERS + CONTINUATION, данные с паддингом
            s.sendall(dohttp.h2_frame(1, 0x8, sid, b"\x02" + b"\x00\x00")
                      + dohttp.h2_frame(9, 0x4, sid, b"\x88")
                      + dohttp.h2_frame(8, 0, 0, struct.pack("!I", 1000))
                      + dohttp.h2_frame(0, 0x8 | 0x1, sid, b"\x03" + body + b"\0\0\0"))
            return
        s.sendall(dohttp.h2_frame(1, 0x4, sid, hdr) + dohttp.h2_frame(0, 0x1, sid, body))

    def close(self):
        self.sock.close()


class Proc:
    """Настоящий dnsproxy.py отдельным процессом (как у людей): правило по домену site.example со своим DNS entries;
    сервер DoH — на 127.0.0.1:port (upstream_port), сертификат — ca. env — окружение процесса (путь к libssl с QUIC)."""

    def __init__(self, entries: list, ca: str, port: int, libssl: str | None = None):
        from tests.test_v115 import free_port
        d = tempfile.mkdtemp()
        lst = os.path.join(d, "l.txt")
        with open(lst, "w") as f:
            f.write("site.example\n")
        self.port = free_port()
        conf = os.path.join(d, "dns.json")
        with open(conf, "w") as f:
            json.dump({"listen": "127.0.0.1", "port": self.port, "clients": "127.0.0.0/8", "upstreams": ["192.0.2.1"],
                       "encrypt": "plain", "default": {"mark": 0, "tcp": False}, "routes": {}, "ca_file": ca,
                       "upstream_port": port, "libssl": libssl, "dom": {"lists": {"l": lst}, "clients": {}, "set": None,
                                                                    "policies": {"p_global": [[["l"], {"mark": 0, "tcp": False},
                                                                                               entries, False]]}}}, f)
        self.proc = subprocess.Popen([sys.executable, "-I", os.path.join(os.path.dirname(dnsproxy.__file__),
                                                                         "dnsproxy.py"), conf],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", self.port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)

    def ask(self, name="site.example", n=1):
        out = []
        for i in range(n):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(20)
                s.sendto(q_msg(f"x{i}." + name if i else name), ("127.0.0.1", self.port))
                out.append(s.recv(4096))
        return out

    def close(self):
        self.proc.terminate()
        self.proc.wait(5)
        self.proc.stdout.close()


class PlainServer:
    """Обычный DNS по UDP на addr:port: на всё — адрес ip (по нему видно, что ответил запасной)."""

    def __init__(self, addr: str, port: int, ip: str):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((addr, port))
        self.ip = ip
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                data, peer = self.sock.recvfrom(4096)
                self.sock.sendto(a_reply(data, [self.ip]), peer)
            except OSError:
                return

    def close(self):
        self.sock.close()


class DirectProc(Proc):
    """dnsproxy.py отдельным процессом с путём «напрямую»: общий сервер upstream (шифрование encrypt), запасной DNS
    fallback — как у людей с галочкой «Запасной DNS для «Напрямую»». Все серверы — на одном порту port."""

    def __init__(self, upstream: str, encrypt: str, fallback: list, ca: str, port: int, libssl: str | None = None):
        from tests.test_v115 import free_port
        d = tempfile.mkdtemp()
        self.port = free_port()
        conf = os.path.join(d, "dns.json")
        with open(conf, "w") as f:
            json.dump({"listen": "127.0.0.1", "port": self.port, "clients": "127.0.0.0/8", "upstreams": [upstream],
                       "encrypt": encrypt, "direct_fallback": fallback, "default": {"mark": 0, "tcp": False},
                       "routes": {}, "ca_file": ca, "upstream_port": port, "libssl": libssl}, f)
        self.proc = subprocess.Popen([sys.executable, "-I", os.path.join(os.path.dirname(dnsproxy.__file__),
                                                                         "dnsproxy.py"), conf],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", self.port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)

    def who(self, name: str) -> tuple[str, float]:
        """→ (кто ответил: shared — общий сервер, fb — запасной, SF — SERVFAIL; секунды)."""
        t0 = time.monotonic()
        r = self.ask(name)[0]
        dt = time.monotonic() - t0
        if r[3] & 0xF == dnsproxy.RC_SERVFAIL:
            return "SF", dt
        return ("shared" if socket.inet_aton("203.0.113.9") in r else
                "fb" if socket.inet_aton("203.0.113.77") in r else f"rc{r[3] & 0xF}"), dt


class SlowNameRealTest(unittest.TestCase):
    """П31 полной проверки 1.25.0 на настоящих сокетах и настоящих сроках (ENC_TIMEOUT 5 с): сервер отвечает на всё,
    кроме одного имени (ему — через 7 с), или «замерзает» после рукопожатия. Одно медленное имя не отправляет к
    запасному следующие; замёрзший сервер — отправляет сразу. До исправления (6a8c54f) медленное имя отправляло к
    запасному всех на 2 минуты, а у запасного — давало всем SERVFAIL."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.crt, key = cert(cls.d, ips=("127.0.0.1",))
        cls.srv = H2Server(cls.crt, key)
        cls.fb = PlainServer("127.0.0.2", cls.srv.port, "203.0.113.77")

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()
        cls.fb.close()

    def setUp(self):
        self.srv.mode, self.srv.slow, self.srv.frozen = "ok", {}, False

    def _slow(self, encrypt):
        self.srv.slow = {"slow.example.": 7.0}
        p = DirectProc("127.0.0.1", encrypt, ["127.0.0.2"], self.crt, self.srv.port)
        self.addCleanup(p.close)
        self.assertEqual(p.who("a.example")[0], "shared")
        self.assertEqual(p.who("slow.example")[0], "fb")         # само имя — у запасного, как раньше
        time.sleep(0.5)                                           # проверка пути (контрольный запрос) — меньше 0,5 с
        out = [p.who(f"n{i}.example") for i in range(3)]
        self.assertEqual([w for w, _ in out], ["shared"] * 3, encrypt)

    def test_h2_slow_name(self):
        self._slow("doh")

    def test_dot_slow_name(self):
        self._slow("dot")

    def test_h2_frozen_switches_at_once(self):
        self.srv.frozen = True
        p = DirectProc("127.0.0.1", "doh", ["127.0.0.2"], self.crt, self.srv.port)
        self.addCleanup(p.close)
        first = p.who("a.example")
        self.assertEqual(first[0], "fb")
        self.assertLess(first[1], 6.0)                           # один срок ответа, как раньше
        nxt = [p.who(f"n{i}.example") for i in range(3)]          # проверка идёт или не прошла — сразу у запасного
        self.assertEqual([w for w, _ in nxt], ["fb"] * 3)
        self.assertLess(max(t for _, t in nxt), 0.5)
        time.sleep(getattr(dnsproxy, "CHECK_TIMEOUT", 5.0) + 0.5)    # проверка не прошла — «не отвечают»
        later = p.who("later.example")
        self.assertEqual(later[0], "fb")
        self.assertLess(later[1], 0.5)


class SlowNameH3RealTest(unittest.TestCase):
    """Зеркальный случай П31 на настоящем QUIC: общие серверы недоступны, запасной — «h3://…». Одно имя без его ответа
    не даёт всем SERVFAIL; замёрзший запасной пропускается сразу."""

    @classmethod
    def setUpClass(cls):
        cls.lib = quic_lib()
        if cls.lib is None:
            if os.environ.get("AWGR_TEST_H3") == "1":
                raise AssertionError("OpenSSL 3.5+ с QUIC не найден")
            raise unittest.SkipTest("OpenSSL 3.5+ с QUIC не найден (AWGR_TEST_LIBSSL)")
        cls.d = tempfile.mkdtemp()
        cls.crt, key = cert(cls.d)
        cls.srv = H3Server(cls.lib, cls.crt, key)

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def setUp(self):
        self.srv.slow, self.srv.frozen = {}, False

    def _proc(self):
        # общий сервер 127.0.0.3: на этом порту по TCP никто не слушает — соединение сбрасывается (как RST)
        p = DirectProc("127.0.0.3", "doh", ["h3://dns.test/dns-query#127.0.0.1"], self.crt, self.srv.port,
                       os.environ.get("AWGR_TEST_LIBSSL"))
        self.addCleanup(p.close)
        return p

    def test_one_slow_name_at_the_fallback(self):
        self.srv.slow = {"slow.example.": 7.0}
        p = self._proc()
        self.assertEqual(p.who("a.example")[0], "shared")        # ответ запасного (h3; H3Server — тем же адресом)
        self.assertEqual(p.who("slow.example")[0], "SF")
        time.sleep(0.5)
        self.assertEqual([p.who(f"n{i}.example")[0] for i in range(3)], ["shared"] * 3)

    def test_frozen_fallback_skipped_at_once(self):
        self.srv.frozen = True
        p = self._proc()
        self.assertEqual(p.who("a.example")[0], "SF")
        nxt = [p.who(f"n{i}.example") for i in range(3)]
        self.assertEqual([w for w, _ in nxt], ["SF"] * 3)
        self.assertLess(max(t for _, t in nxt), 0.5)


class FramesTest(unittest.TestCase):
    def test_hpack_request_and_status(self):
        b = dohttp.h2_request("dns.test", "/dns-query", 33)
        self.assertTrue(b.startswith(b"\x83\x87\x04\x0a/dns-query\x01\x08dns.test"))
        self.assertIn(b"\x0f\x10\x17application/dns-message", b)            # content-type, индекс 31
        self.assertEqual(dohttp.h2_status(b"\x88"), 200)
        self.assertEqual(dohttp.h2_status(b"\x8d"), 404)
        self.assertEqual(dohttp.h2_status(b"\x3f\xe1\x1f\x88"), 200)          # смена размера таблицы — пропускается
        self.assertEqual(dohttp.h2_status(b"\x48\x03503"), 503)               # строка без Хаффмана
        self.assertIsNone(dohttp.h2_status(b"\x48\x82\x10\x01"))              # Хаффман — код не узнаём
        for cut in (b"\x48", b"\x3f", b"\x48\x05"):                            # обрезанный блок — не падение
            self.assertIsNone(dohttp.h2_status(cut))
        self.assertEqual(dohttp._int(1337, 5), b"\x1f\x9a\x0a")               # пример RFC 7541, C.1.2

    def test_qpack_request_and_status(self):
        b = dohttp.h3_request("dns.test", "/dns-query", 33)
        self.assertTrue(b.startswith(b"\x00\x00\xd4\xd7\x51\x0a/dns-query\x50\x08dns.test\xec\xde"))
        self.assertEqual(dohttp.h3_status(b"\x00\x00\xd9"), 200)
        self.assertEqual(dohttp.h3_status(b"\x00\x00\xdb"), 404)
        self.assertEqual(dohttp.h3_status(b"\x00\x00\x5f\x09\x03503"), 503)
        self.assertEqual(dohttp.h3_status(b"\x00\x00\x7f\x09\x03503"), 503)   # бит N
        body = dohttp.varint(1) + dohttp.varint(3) + b"\x00\x00\xd9" + dohttp.varint(0x21) + dohttp.varint(0) \
            + dohttp.varint(0) + dohttp.varint(4) + b"abcd"
        self.assertEqual(dohttp.h3_body(body), b"abcd")
        with self.assertRaises(dohttp.DohError):
            dohttp.h3_body(dohttp.varint(1) + dohttp.varint(3) + b"\x00\x00\xdb")
        for cut in (b"\x40", b"\x01\x80"):                                     # обрезанное целое QUIC
            with self.assertRaises(dohttp.DohError):
                dohttp.h3_body(cut)
        self.assertEqual([dohttp._is_ip(n) for n in ("1.1.1.1", "dns.google", "1.1.1", "1")], [True, False, False, False])
        for v in (0, 63, 64, 16383, 16384, 1 << 30):
            self.assertEqual(dohttp.read_varint(dohttp.varint(v), 0), (v, len(dohttp.varint(v))))

    def test_entries(self):
        self.assertEqual(dnsaddr.entries(["H3://dns.google/dns-query{?dns}"]), ["h3://dns.google/dns-query"])
        self.assertEqual(dnsproxy.srv("h3://dns.google:8443/q#8.8.8.8")[:4], ("doh3", "8.8.8.8", "dns.google", 8443))
        st = {"routing": {"rules": [{"dns": ["h3://dns.google/dns-query", "77.88.8.8"]}]}}
        disk = dnsaddr.to_disk(st)["routing"]["rules"][0]                     # 1.24 видит только обычный адрес
        self.assertEqual((disk["dns"], disk["dns_all"]), (["77.88.8.8"], ["h3://dns.google/dns-query", "77.88.8.8"]))

    def test_h3_refused_at_save_without_quic(self):
        from unittest import mock
        from app import checks
        with mock.patch.object(dohttp, "h3_supported", return_value=False):
            with self.assertRaises(Exception) as cm:
                checks.dns_names_known(["h3://1.1.1.1/dns-query"], lambda n, o: {}, "direct", {})
            self.assertEqual(cm.exception.detail.key, "err.h3_unsupported")
            checks.dns_names_known(["h3://1.1.1.1/dns-query"], None, "direct", {})    # копия — без проверки


class H2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.crt, key = cert(cls.d)
        cls.srv = H2Server(cls.crt, key)

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_answers_over_h2(self):
        self.srv.mode = "ok"
        p = Proc(["https://dns.test/dns-query#127.0.0.1"], self.crt, self.srv.port)
        self.addCleanup(p.close)
        out = p.ask(n=3)
        self.assertTrue(all(socket.inet_aton("203.0.113.9") in r for r in out))
        self.assertEqual(self.srv.conns, 1)                  # одно соединение, три потока по очереди
        self.assertIn(b"\x01\x08dns.test", self.srv.seen[-1])     # :authority — имя сервиса
        for mode in ("huffman", "table", "split"):
            self.srv.mode = mode
            self.assertIn(socket.inet_aton("203.0.113.9"), p.ask("m-" + mode + ".site.example")[0], mode)

    def test_errors(self):
        p = Proc(["https://dns.test/dns-query#127.0.0.1"], self.crt, self.srv.port)
        self.addCleanup(p.close)
        for mode in ("404", "reset", "goaway", "badpad"):
            self.srv.mode = mode
            r = p.ask("e-" + mode + ".site.example")[0]
            self.assertEqual(r[3] & 0xF, dnsproxy.RC_SERVFAIL, mode)         # не ответ — запись не ответила
        self.srv.mode = "cut"                                                   # блок заголовков обрезан: код не узнали,
        self.assertIn(socket.inet_aton("203.0.113.9"), p.ask("cut.site.example")[0])      # ответ DNS проверен сам
        self.srv.mode = "ok"
        self.assertIn(socket.inet_aton("203.0.113.9"), p.ask("after.site.example")[0])    # потом — снова


def quic_lib():
    """libssl с QUIC и сервера, и клиента (OpenSSL 3.5+): из AWGR_TEST_LIBSSL или системная."""
    path = os.environ.get("AWGR_TEST_LIBSSL")
    if path:
        dohttp.LIBSSL = (path,)
        dohttp._lib, dohttp._lib_tried = None, False
    lib = dohttp.libssl()
    return lib if lib is not None and hasattr(lib, "OSSL_QUIC_server_method") else None


ALPN_CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                           ctypes.POINTER(ctypes.c_ubyte), ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p)


class H3Server:
    """Сервер HTTP/3 на QUIC из OpenSSL: неблокирующий, один поток (блокирующие вызовы OpenSSL в нескольких потоках
    теряли пробуждение: поток запроса не принимался секундами). Пропускает однонаправленные потоки клиента
    (управляющий), на поток запроса отвечает HEADERS (:status 200 из таблицы QPACK) и DATA."""

    def __init__(self, lib, crt: str, key: str):
        P, I = ctypes.c_void_p, ctypes.c_int
        for fn, res, args in (("OSSL_QUIC_server_method", P, []), ("SSL_new_listener", P, [P, ctypes.c_uint64]),
                              ("SSL_listen", I, [P]), ("SSL_accept_connection", P, [P, ctypes.c_uint64]),
                              ("SSL_accept_stream", P, [P, ctypes.c_uint64]), ("SSL_get_stream_type", I, [P]),
                              ("SSL_set_incoming_stream_policy", I, [P, I, ctypes.c_uint64]),
                              ("SSL_CTX_use_certificate_chain_file", I, [P, ctypes.c_char_p]),
                              ("SSL_CTX_use_PrivateKey_file", I, [P, ctypes.c_char_p, I]),
                              ("SSL_CTX_set_alpn_select_cb", None, [P, ALPN_CB, P])):
            f = getattr(lib, fn)
            f.restype, f.argtypes = res, args
        self.lib, self.answers, self.stop = lib, 0, False
        self.slow, self.frozen = {}, False           # как у H2Server: имя → секунды до ответа; без ответа вовсе
        self.ctx = lib.SSL_CTX_new(lib.OSSL_QUIC_server_method())
        assert lib.SSL_CTX_use_certificate_chain_file(self.ctx, crt.encode()) == 1
        assert lib.SSL_CTX_use_PrivateKey_file(self.ctx, key.encode(), 1) == 1
        self.h3 = ctypes.create_string_buffer(b"h3", 2)

        def select_(ssl_, out, outlen, inp, inlen, arg):
            out[0] = ctypes.cast(self.h3, ctypes.c_void_p)
            outlen[0] = 2
            return 0
        self.cb = ALPN_CB(select_)
        lib.SSL_CTX_set_alpn_select_cb(self.ctx, self.cb, None)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.setblocking(False)
        self.port = self.sock.getsockname()[1]
        self.listener = lib.SSL_new_listener(self.ctx, 0)
        bio = lib.BIO_new_dgram(self.sock.fileno(), 0)
        lib.SSL_set_bio(self.listener, bio, bio)
        lib.SSL_set_blocking_mode(self.listener, 0)
        assert lib.SSL_listen(self.listener) == 1
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        lib = self.lib
        conns, streams, later = [], {}, []                          # поток запроса → прочитанное; отложенные ответы
        buf, got = ctypes.create_string_buffer(65536), ctypes.c_size_t(0)
        while not self.stop:
            select.select([self.sock], [], [], 0.005)
            lib.SSL_handle_events(self.listener)
            while True:
                conn = lib.SSL_accept_connection(self.listener, 1)  # SSL_ACCEPT_CONNECTION_NO_BLOCK
                if not conn:
                    break
                lib.SSL_set_blocking_mode(conn, 0)
                lib.SSL_set_incoming_stream_policy(conn, 1, 0)      # ACCEPT: потоки клиента — в очередь
                conns.append(conn)
            for conn in conns:
                lib.SSL_handle_events(conn)
                while True:
                    st = lib.SSL_accept_stream(conn, 1)             # SSL_ACCEPT_STREAM_NO_BLOCK
                    if not st:
                        break
                    if lib.SSL_get_stream_type(st) == 3:            # двунаправленный — запрос; управляющий не читаем
                        streams[st] = b""
            for st in list(streams):
                while lib.SSL_read_ex(st, buf, len(buf), ctypes.byref(got)) == 1:
                    streams[st] += buf.raw[:got.value]
                if lib.SSL_get_error(st, 0) != 6:                   # не SSL_ERROR_ZERO_RETURN: запрос ещё не весь
                    continue
                frames = dict(dohttp.h3_frames(streams.pop(st)))
                if self.frozen:
                    continue
                body = a_reply(frames[0], ["203.0.113.9"])
                out = (dohttp.varint(1) + dohttp.varint(3) + b"\x00\x00\xd9" + dohttp.varint(0)
                       + dohttp.varint(len(body)) + body)
                later.append((time.monotonic() + self.slow.get(dnsproxy.read_name(frames[0], 12), 0), st, out))
            for item in [x for x in later if x[0] <= time.monotonic()]:
                later.remove(item)
                _, st, out = item
                lib.SSL_write_ex(st, out, len(out), ctypes.byref(got))
                lib.SSL_stream_conclude(st, 0)
                self.answers += 1
        for st in streams:
            lib.SSL_free(st)
        for conn in conns:
            lib.SSL_free(conn)
        lib.SSL_free(self.listener)
        lib.SSL_CTX_free(self.ctx)

    def close(self):
        self.stop = True
        self.thread.join(5)
        self.sock.close()


class H3Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib = quic_lib()
        if cls.lib is None:
            if os.environ.get("AWGR_TEST_H3") == "1":                 # net-tests.yml, образ панели: QUIC обязан быть
                raise AssertionError("OpenSSL 3.5+ с QUIC не найден")
            raise unittest.SkipTest("OpenSSL 3.5+ с QUIC не найден (AWGR_TEST_LIBSSL)")
        cls.d = tempfile.mkdtemp()
        cls.crt, key = cert(cls.d)
        cls.srv = H3Server(cls.lib, cls.crt, key)

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_answers_over_h3(self):
        p = Proc(["h3://dns.test/dns-query#127.0.0.1"], self.crt, self.srv.port, os.environ.get("AWGR_TEST_LIBSSL"))
        self.addCleanup(p.close)
        t0 = time.monotonic()
        out = p.ask(n=3)
        self.assertTrue(all(socket.inet_aton("203.0.113.9") in r for r in out), out)
        self.assertEqual(self.srv.answers, 3)
        self.assertLess(time.monotonic() - t0, 5)

    def test_wrong_name_refused(self):
        p = Proc(["h3://other.test/dns-query#127.0.0.1"], self.crt, self.srv.port, os.environ.get("AWGR_TEST_LIBSSL"))
        self.addCleanup(p.close)
        before = self.srv.answers
        r = p.ask("w.site.example")[0]
        self.assertEqual(r[3] & 0xF, dnsproxy.RC_SERVFAIL)       # сертификат не на это имя — не спрашиваем
        self.assertEqual(self.srv.answers, before)

    def test_replaced_pool_keeps_nothing(self):
        pool = dohttp.H3Pool(lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM), "127.0.0.1", self.srv.port,
                             "dns.test", 2, 50, self.crt)
        self.assertTrue(pool.query(q_msg("a.site.example"), "dns.test", "/dns-query", 3))
        self.assertEqual(len(pool.free), 1)                                     # соединение ждёт следующего запроса
        pool.close()                                                            # настройки перечитаны — пул заменён
        self.assertTrue(pool.query(q_msg("b.site.example"), "dns.test", "/dns-query", 3))
        self.assertEqual(pool.free, [])                                         # запрос, бывший в пути, не копит

    def test_silent_server_times_out(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        try:
            pool = dohttp.H3Pool(lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM), "127.0.0.1",
                                 s.getsockname()[1], "dns.test", 2, 50, self.crt)
            t0 = time.monotonic()
            with self.assertRaises((TimeoutError, dohttp.DohError)):
                pool.query(q_msg("a.example"), "dns.test", "/dns-query", 1.0)
            self.assertLess(time.monotonic() - t0, 2.5)              # QUIC режут — не дольше срока
        finally:
            s.close()


class DohFixTest(unittest.TestCase):
    """Исправления полной проверки 1.25.0 в DoH (П3, П30, П43–П45, П47)."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.crt, key = cert(cls.d)
        cls.srv = H2Server(cls.crt, key)

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_h2_queries_do_not_wait_for_acks(self):
        """П3: 20 запросов подряд на одно соединение HTTP/2 — без ожидания подтверждения сервера (Нейгл): медиана
        меньше 10 мс (без TCP_NODELAY — ~44 мс и на loopback)."""
        self.srv.mode = "ok"
        p = Proc(["https://dns.test/dns-query#127.0.0.1"], self.crt, self.srv.port)
        self.addCleanup(p.close)
        p.ask("warm.site.example")
        times = []
        for i in range(20):
            t0 = time.monotonic()
            p.ask(f"n{i}.site.example")
            times.append(time.monotonic() - t0)
        self.assertLess(sorted(times)[10], 0.010, times)

    def test_dead_first_entry_is_asked_last(self):
        """П30: первая запись своего DNS молчит — первое имя ждёт её, следующие сразу идут ко второй."""
        self.srv.mode = "ok"
        silent = socket.socket()
        silent.bind(("127.0.0.2", self.srv.port))        # соединение принимает ядро, TLS не отвечает
        silent.listen(64)
        self.addCleanup(silent.close)
        p = Proc(["https://dns.test/dns-query#127.0.0.2", "https://dns.test/dns-query#127.0.0.1"], self.crt,
                 self.srv.port)
        self.addCleanup(p.close)
        self.assertIn(socket.inet_aton("203.0.113.9"), p.ask("first.site.example")[0])
        t0 = time.monotonic()
        self.assertIn(socket.inet_aton("203.0.113.9"), p.ask("second.site.example")[0])
        self.assertLess(time.monotonic() - t0, 1.0)

    def test_control_frame_flood(self):
        """П44: сервер шлёт SETTINGS и PING потоком вместо ответа (или PING не той длины) — ошибка, а не буфер в
        сотни МБ."""
        import asyncio

        class W:
            def write(self, b):
                pass

            async def drain(self):
                pass

        def conn(frames):
            r = asyncio.StreamReader()
            r.feed_data(frames)
            r.feed_eof()
            return type("C", (), {"h2": dohttp.H2(), "reader": r, "writer": W()})()

        async def run(frames):
            return await dohttp.h2_query(conn(frames), q_msg("a.example"), "dns.test", "/dns-query")
        with self.assertRaises(dohttp.DohError):
            asyncio.run(run(dohttp.h2_frame(4, 0, 0) * 200))
        with self.assertRaises(dohttp.DohError):
            asyncio.run(run(dohttp.h2_frame(6, 0, 0, b"1234")))

    def test_huge_http1_answer_refused(self):
        """П44: HTTP/1.1 с огромной длиной ответа — ошибка, а не чтение сколько скажет сервер."""
        import asyncio

        class W:
            def write(self, b):
                pass

            async def drain(self):
                pass
        async def run(head):
            r = asyncio.StreamReader()
            r.feed_data(b"HTTP/1.1 200 OK\r\n" + head + b"\r\nfffffff\r\n")
            r.feed_eof()
            c = type("C", (), {"reader": r, "writer": W(), "reusable": True})()
            return await dnsproxy.doh_query(c, q_msg("a.example"), "dns.test")
        for head in (b"Content-Length: 999999999\r\n", b"Transfer-Encoding: chunked\r\n"):
            with self.assertRaises(OSError):
                asyncio.run(run(head))

    def test_h3_connection_replaced_after_many_queries(self):
        """П45: соединение HTTP/3 — не дольше H3_CONN_QUERIES запросов (память OpenSSL растёт, пока оно живо)."""
        made = []

        class Conn:
            def __init__(self, *a):
                self.used = time.monotonic()
                made.append(self)

            def query(self, *a):
                self.used = time.monotonic()
                return b"ok"

            def close(self):
                pass
        orig = dohttp.H3Conn
        dohttp.H3Conn = Conn
        self.addCleanup(setattr, dohttp, "H3Conn", orig)
        pool = dohttp.H3Pool(lambda: None, "127.0.0.1", 443, "dns.test", 2, 50)
        for _ in range(dohttp.H3_CONN_QUERIES + 1):
            pool.query(b"q", "dns.test", "/dns-query", 1.0)
        self.assertEqual(len(made), 2)

    def test_one_client_cannot_take_all_tcp(self):
        """П43: соединений по TCP с одного адреса — не больше CLIENT_TCP_MAX; мягкий предел файлов поднят."""
        import asyncio
        import resource
        p = dnsproxy.Proxy.__new__(dnsproxy.Proxy)
        p.allowed = lambda ip: True
        p.tcp_conns = {"10.8.1.2": dnsproxy.CLIENT_TCP_MAX}

        class R:
            async def readexactly(self, n):
                raise AssertionError("лишнее соединение не читается")

        class W:
            closed = False

            def get_extra_info(self, k):
                return ("10.8.1.2", 5353)

            def close(self):
                self.closed = True
        w = W()
        asyncio.run(p.handle_tcp(R(), w))
        self.assertTrue(w.closed)
        self.assertEqual(p.tcp_conns, {"10.8.1.2": dnsproxy.CLIENT_TCP_MAX})
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(256, hard), hard))
            dnsproxy.raise_open_files_limit()
            self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE)[0], hard)
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

    def test_name_address_is_stable(self):
        """П47: порядок адресов в ответе меняется — запись «#адрес» для dnsproxy.py та же."""
        from unittest import mock
        answers = [[("10.0.0.2",), ("10.0.0.1",)], [("10.0.0.1",), ("10.0.0.2",)]]
        for order in answers:
            gai = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", a) for a in order]
            with mock.patch.object(dnsaddr.socket, "getaddrinfo", lambda *a, **k: gai):
                self.assertEqual(dnsaddr.lookup(["dns.test"]), {"dns.test": "10.0.0.1"})


if __name__ == "__main__":
    unittest.main()
