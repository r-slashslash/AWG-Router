"""DoH по HTTP/2 и HTTP/3 для DNS на сервере (dnsproxy.py; проверка 1.25.0, А1: владелец 2026-11-27).

HTTP/1.1 есть в самом dnsproxy.py (doh_query). Часть серверов DoH на HTTP/1.1 больше не отвечает: Quad9 — «505 версия
HTTP не поддерживается», Яндекс закрывает соединение; по HTTP/2 отвечают оба. Адрес «https://…» спрашивается так, как
договорились при соединении (ALPN: h2, затем http/1.1 — выбирает сервер), адрес «h3://…» — только по HTTP/3 (QUIC, UDP):
его провайдер может резать отдельно от HTTPS, поэтому он пишется явно, а второй адрес поля — запасной.

Только стандартная библиотека Python: HTTP/2 — свои кадры поверх ssl; HTTP/3 — QUIC из OpenSSL (3.2 и новее; в образе
панели — системный libssl Alpine), через ctypes, как AES в quic.py. Заголовки ответа не разбираются целиком: хватает
«:status» (из таблицы заголовков HPACK/QPACK, без Хаффмана); остальное — тело, которое dnsproxy.py проверяет как ответ
DNS (номер запроса и вопрос). Таблица заголовков на нашей стороне не заводится: QPACK с ёмкостью 0, в HPACK — только
строки «без индексации»."""
from __future__ import annotations

import asyncio
import ctypes
import ctypes.util
import os
import select
import socket
import ssl
import struct
import threading
import time

# ---------------------------------------------------------------- общее
STATUS_H2 = {0x88: 200, 0x89: 204, 0x8A: 206, 0x8B: 304, 0x8C: 400, 0x8D: 404, 0x8E: 500}   # HPACK, индексы 8–14
STATUS_H3 = {24: 103, 25: 200, 26: 304, 27: 404, 28: 503, 63: 100, 64: 204, 65: 206, 66: 302, 67: 400, 68: 403,
             69: 421, 70: 425, 71: 500}                                                         # QPACK, статическая
H2_WINDOW = 1 << 20          # наше окно приёма: ответ DNS до 64 КБ, с запасом


class DohError(OSError):
    """Сервер ответил не так, как ждали (код HTTP не 200, поток сброшен, соединение закрыто)."""


def _int(value: int, prefix: int, first: int = 0) -> bytes:
    """Целое HPACK/QPACK с префиксом из prefix битов (RFC 7541, 5.1); first — старшие биты первого байта."""
    top = (1 << prefix) - 1
    if value < top:
        return bytes([first | value])
    out = [first | top]
    value -= top
    while value >= 128:
        out.append(value % 128 + 128)
        value //= 128
    out.append(value)
    return bytes(out)


def _str(s: str | bytes) -> bytes:
    """Строка без Хаффмана: длина с 7-битным префиксом, затем байты."""
    b = s.encode("ascii") if isinstance(s, str) else s
    return _int(len(b), 7) + b


def _read_int(b: bytes, i: int, prefix: int) -> tuple[int, int]:
    top = (1 << prefix) - 1
    v = b[i] & top
    i += 1
    if v < top:
        return v, i
    m = 0
    while True:
        c = b[i]
        i += 1
        v += (c & 127) << m
        m += 7
        if not c & 128:
            return v, i


def _digits(b: bytes, i: int) -> int | None:
    """Значение «:status» строкой без Хаффмана; с Хаффманом — None (код не узнаём, решает проверка ответа DNS)."""
    huff = b[i] & 0x80
    n, i = _read_int(b, i, 7)
    raw = b[i:i + n]
    return int(raw) if not huff and raw.isdigit() else None


# ---------------------------------------------------------------- HTTP/2
def h2_request(host: str, path: str, length: int) -> bytes:
    """Блок заголовков HPACK запроса POST (RFC 8484): индексы статической таблицы и строки «без индексации»."""
    return (b"\x83\x87"                                  # :method POST, :scheme https
            + _int(4, 4) + _str(path)                    # :path
            + _int(1, 4) + _str(host)                    # :authority
            + _int(31, 4) + _str("application/dns-message")      # content-type
            + _int(19, 4) + _str("application/dns-message")      # accept
            + _int(28, 4) + _str(str(length))            # content-length
            + _int(58, 4) + _str("awg-router"))          # user-agent


def h2_status(block: bytes) -> int | None:
    """«:status» из блока заголовков ответа (первое поле; перед ним бывают смены размера таблицы). Обрезанный блок —
    None: код не узнали, решает проверка ответа DNS."""
    try:
        return _h2_status(block)
    except IndexError:
        return None


def _h2_status(block: bytes) -> int | None:
    i = 0
    while i < len(block) and block[i] & 0xE0 == 0x20:    # смена размера таблицы заголовков
        _, i = _read_int(block, i, 5)
    if i >= len(block):
        return None
    c = block[i]
    if c & 0x80:                                         # поле из таблицы целиком
        return STATUS_H2.get(c)
    for prefix, mask in ((6, 0x40), (4, 0x00), (4, 0x10)):           # строка с именем из таблицы
        if c & (0xC0 if mask == 0x40 else 0xF0) == mask:
            idx, j = _read_int(block, i, prefix)
            return _digits(block, j) if 8 <= idx <= 14 else None
    return None


def h2_frame(typ: int, flags: int, sid: int, payload: bytes = b"") -> bytes:
    return struct.pack("!I", len(payload))[1:] + bytes([typ, flags]) + struct.pack("!I", sid) + payload


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + h2_frame(4, 0, 0, struct.pack("!HI", 2, 0) + struct.pack("!HI", 4, H2_WINDOW)) \
    + h2_frame(8, 0, 0, struct.pack("!I", H2_WINDOW - 65535))      # без push, своё окно потока и соединения


H2_CTL_MAX = 100        # кадров SETTINGS и PING на один запрос; больше — сервер сломан или злой


class H2:
    """Состояние соединения HTTP/2: следующий номер потока. Один запрос за раз (как пул dnsproxy.py: по одному на
    соединение), поэтому без очередей потоков."""

    def __init__(self):
        self.sid = 1


async def h2_query(conn, msg: bytes, host: str, path: str) -> bytes:
    """Запрос DoH по HTTP/2 на открытом соединении (conn.reader / conn.writer, conn.h2). Кадры соединения (SETTINGS,
    PING, WINDOW_UPDATE, GOAWAY) обслуживаются здесь же; окно приёма возвращается после каждого кадра данных."""
    st, r, w = conn.h2, conn.reader, conn.writer
    sid = st.sid
    if sid > 0x7FFFFFF0:
        raise DohError("HTTP/2: streams used up")
    st.sid += 2
    w.write(h2_frame(1, 0x4, sid, h2_request(host, path, len(msg))) + h2_frame(0, 0x1, sid, msg))
    await w.drain()
    status, body, block, ctl = None, b"", b"", 0
    while True:
        head = await r.readexactly(9)
        n = int.from_bytes(head[:3], "big")
        typ, flags, s = head[3], head[4], struct.unpack("!I", head[5:])[0] & 0x7FFFFFFF
        payload = await r.readexactly(n) if n else b""
        if typ in (4, 6):
            # служебные кадры на каждый ответ пишутся в буфер без drain: сервер, который шлёт их потоком и не читает,
            # раздул бы память (П44 полной проверки 1.25.0)
            ctl += 1
            if ctl > H2_CTL_MAX or (typ == 6 and n != 8):
                raise DohError("HTTP/2: too many control frames")
        if typ == 4:                                     # SETTINGS
            if not flags & 0x1:
                w.write(h2_frame(4, 0x1, 0))
            continue
        if typ == 6:                                     # PING
            if not flags & 0x1:
                w.write(h2_frame(6, 0x1, 0, payload))
            continue
        if typ == 7:                                     # GOAWAY: новых потоков на этом соединении не будет
            conn.reusable = False
            last = struct.unpack("!I", payload[:4])[0] & 0x7FFFFFFF if len(payload) >= 4 else 0
            if last < sid:
                raise DohError("HTTP/2: GOAWAY")
            continue
        if s != sid:
            continue                                     # WINDOW_UPDATE, PRIORITY, чужие потоки
        if typ == 3:                                     # RST_STREAM
            raise DohError("HTTP/2: stream reset")
        if typ in (0, 1) and flags & 0x8 and (not payload or payload[0] >= len(payload)):
            raise DohError("HTTP/2: bad padding")
        if typ in (1, 9):                                # HEADERS, CONTINUATION
            p = payload
            if typ == 1:
                pad = p[0] if flags & 0x8 else 0
                p = p[(1 if flags & 0x8 else 0) + (5 if flags & 0x20 else 0):len(p) - pad]
            block += p
            if len(block) > 16384:
                raise DohError("HTTP/2: headers too long")
            if flags & 0x4:                              # END_HEADERS
                code = h2_status(block)
                block = b""
                if code is not None and 100 <= code < 200:
                    continue                             # промежуточный ответ
                status = code if code is not None else status
        elif typ == 0:                                   # DATA
            pad = payload[0] if flags & 0x8 else 0
            body += payload[(1 if flags & 0x8 else 0):len(payload) - pad]
            if len(body) > 70000:
                raise DohError("HTTP/2: answer too long")
            if n:
                w.write(h2_frame(8, 0, 0, struct.pack("!I", n)))     # окно соединения — обратно
        if flags & 0x1 and typ in (0, 1):               # END_STREAM
            break
    await w.drain()
    if status is not None and status != 200:
        raise DohError(f"DoH: HTTP {status}")
    return body


# ---------------------------------------------------------------- HTTP/3 (QUIC из OpenSSL)
def varint(v: int) -> bytes:
    """Целое QUIC (RFC 9000, 16): 1, 2, 4 или 8 байт."""
    if v < 64:
        return bytes([v])
    if v < 16384:
        return struct.pack("!H", 0x4000 | v)
    if v < 1 << 30:
        return struct.pack("!I", 0x80000000 | v)
    return struct.pack("!Q", 0xC000000000000000 | v)


def read_varint(b: bytes, i: int) -> tuple[int, int]:
    n = 1 << (b[i] >> 6)
    if i + n > len(b):
        raise IndexError("varint")
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


def h3_request(host: str, path: str, length: int) -> bytes:
    """Поля QPACK запроса POST: без динамической таблицы (префикс 0, 0), статические индексы и строки."""
    return (b"\x00\x00"
            + bytes([0xC0 | 20, 0xC0 | 23])              # :method POST, :scheme https
            + _int(1, 4, 0x50) + _str(path)              # :path (имя из таблицы)
            + _int(0, 4, 0x50) + _str(host)              # :authority
            + _int(44, 6, 0xC0)                          # content-type: application/dns-message
            + _int(30, 6, 0xC0)                          # accept: application/dns-message
            + _int(4, 4, 0x50) + _str(str(length)))      # content-length


def h3_status(block: bytes) -> int | None:
    """«:status» из полей QPACK ответа (первое поле после префикса)."""
    try:
        _, i = _read_int(block, 0, 8)                    # Required Insert Count
        _, i = _read_int(block, i, 7)                    # Base
        c = block[i]
        if c & 0xC0 == 0xC0:                             # поле статической таблицы целиком
            idx, _ = _read_int(block, i, 6)
            return STATUS_H3.get(idx)
        if c & 0xD0 == 0x50:                             # строка с именем статической таблицы (бит N — любой)
            idx, j = _read_int(block, i, 4)
            return _digits(block, j) if idx in STATUS_H3 else None
    except IndexError:
        pass
    return None


def h3_frames(data: bytes) -> list[tuple[int, bytes]]:
    """Кадры HTTP/3 потока: [(тип, содержимое)]. Неполный последний кадр — ошибка (поток уже закончился)."""
    out, i = [], 0
    while i < len(data):
        try:
            typ, i = read_varint(data, i)
            n, i = read_varint(data, i)
        except IndexError:
            raise DohError("HTTP/3: frame cut") from None
        if i + n > len(data):
            raise DohError("HTTP/3: frame cut")
        out.append((typ, data[i:i + n]))
        i += n
    return out


def h3_body(data: bytes) -> bytes:
    """Тело ответа из потока запроса: HEADERS (код), DATA; неизвестные кадры (в том числе «смазка») пропускаются."""
    status, body = None, b""
    for typ, payload in h3_frames(data):
        if typ == 0x1:
            code = h3_status(payload)
            if code is not None and 100 <= code < 200:
                continue
            status = code if code is not None else status
        elif typ == 0x0:
            body += payload
    if status is not None and status != 200:
        raise DohError(f"DoH: HTTP {status}")
    return body


SSL_VERIFY_PEER = 1
SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE, SSL_ERROR_ZERO_RETURN = 2, 3, 6
SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
SSL_STREAM_FLAG_UNI = 1
SSL_DEFAULT_STREAM_MODE_NONE = 0
LIBSSL = ("libssl.so.3", "libssl.so")       # тесты подменяют путь к libssl с QUIC


def _is_ip(name: str) -> bool:
    try:
        socket.inet_aton(name)
        return name.count(".") == 3
    except OSError:
        return False


class _Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


_lib = None
_lib_tried = False
_lib_lock = threading.Lock()


def libssl():
    """libssl с QUIC клиента (OpenSSL 3.2+), с объявленными функциями; нет такой — None (HTTP/3 не работает)."""
    global _lib, _lib_tried
    with _lib_lock:
        if _lib_tried:
            return _lib
        _lib_tried = True
        names = list(LIBSSL)
        found = ctypes.util.find_library("ssl")
        if found and found not in names:
            names.append(found)
        for name in names:
            try:
                lib = ctypes.CDLL(name)
            except OSError:
                continue
            if not hasattr(lib, "OSSL_QUIC_client_method"):
                continue
            P, I, S = ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t
            U64 = ctypes.c_uint64
            proto = {
                "OSSL_QUIC_client_method": (P, []), "SSL_CTX_new": (P, [P]), "SSL_CTX_free": (None, [P]),
                "SSL_CTX_set_verify": (None, [P, I, P]), "SSL_CTX_set_default_verify_paths": (I, [P]),
                "SSL_CTX_load_verify_locations": (I, [P, ctypes.c_char_p, ctypes.c_char_p]),
                "SSL_new": (P, [P]), "SSL_free": (None, [P]), "SSL_set_bio": (None, [P, P, P]),
                "BIO_new_dgram": (P, [I, I]), "BIO_ADDR_new": (P, []), "BIO_ADDR_free": (None, [P]),
                "BIO_ADDR_rawmake": (I, [P, I, ctypes.c_char_p, S, ctypes.c_ushort]),
                "SSL_set1_initial_peer_addr": (I, [P, P]), "SSL_ctrl": (ctypes.c_long, [P, I, ctypes.c_long, P]),
                "SSL_set1_host": (I, [P, ctypes.c_char_p]), "SSL_set_alpn_protos": (I, [P, ctypes.c_char_p, ctypes.c_uint]),
                "SSL_set_blocking_mode": (I, [P, I]), "SSL_set_default_stream_mode": (I, [P, ctypes.c_uint32]),
                "SSL_connect": (I, [P]), "SSL_get_error": (I, [P, I]), "SSL_handle_events": (I, [P]),
                "SSL_get_event_timeout": (I, [P, ctypes.POINTER(_Timeval), ctypes.POINTER(I)]),
                "SSL_new_stream": (P, [P, U64]), "SSL_stream_conclude": (I, [P, U64]),
                "SSL_write_ex": (I, [P, ctypes.c_char_p, S, ctypes.POINTER(S)]),
                "SSL_read_ex": (I, [P, ctypes.c_void_p, S, ctypes.POINTER(S)]),
            }
            try:
                for fn, (res, args) in proto.items():
                    f = getattr(lib, fn)
                    f.restype, f.argtypes = res, args
            except AttributeError:
                continue
            _lib = lib
            break
        return _lib


def h3_supported() -> bool:
    return libssl() is not None


class H3Conn:
    """Соединение QUIC с ALPN h3 и открытый управляющий поток. Не потокобезопасно: им пользуется один запрос за раз
    (H3Pool). Неблокирующее: ожидание — select по сокету и таймерам QUIC (SSL_get_event_timeout), с общим сроком."""

    def __init__(self, sock: socket.socket, ip: str, port: int, name: str, cafile: str | None, deadline: float):
        lib = libssl()
        if lib is None:
            raise DohError("HTTP/3: OpenSSL without QUIC")
        self.lib, self.sock, self.ctx, self.ssl, self.ctrl = lib, sock, None, None, None
        self.used = time.monotonic()
        try:
            self.ctx = lib.SSL_CTX_new(lib.OSSL_QUIC_client_method())
            if not self.ctx:
                raise DohError("HTTP/3: SSL_CTX_new")
            lib.SSL_CTX_set_verify(self.ctx, SSL_VERIFY_PEER, None)
            if cafile:
                ok = lib.SSL_CTX_load_verify_locations(self.ctx, cafile.encode(), None)
            else:
                dp = ssl.get_default_verify_paths()
                ok = 0
                if dp.cafile and os.path.exists(dp.cafile):
                    ok = lib.SSL_CTX_load_verify_locations(self.ctx, dp.cafile.encode(), None)
                if dp.capath and os.path.isdir(dp.capath):
                    ok = lib.SSL_CTX_load_verify_locations(self.ctx, None, dp.capath.encode()) or ok
                if not ok:
                    ok = lib.SSL_CTX_set_default_verify_paths(self.ctx)
            if not ok:
                raise DohError("HTTP/3: no CA certificates")
            self.ssl = lib.SSL_new(self.ctx)
            if not self.ssl:
                raise DohError("HTTP/3: SSL_new")
            bio = lib.BIO_new_dgram(sock.fileno(), 0)    # BIO_NOCLOSE: сокет закрывает close()
            if not bio:
                raise DohError("HTTP/3: BIO_new_dgram")
            lib.SSL_set_bio(self.ssl, bio, bio)
            addr = lib.BIO_ADDR_new()
            try:
                if not lib.BIO_ADDR_rawmake(addr, socket.AF_INET, socket.inet_aton(ip), 4, socket.htons(port)) \
                        or not lib.SSL_set1_initial_peer_addr(self.ssl, addr):
                    raise DohError("HTTP/3: peer address")
            finally:
                lib.BIO_ADDR_free(addr)
            sni = name.encode("idna")
            if not _is_ip(name):                         # адрес в SNI не пишут (RFC 6066), как и ssl Python
                lib.SSL_ctrl(self.ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, ctypes.c_char_p(sni))
            if not lib.SSL_set1_host(self.ssl, sni):    # сертификат — по имени сервиса (или адресу)
                raise DohError("HTTP/3: SSL_set1_host")
            if lib.SSL_set_alpn_protos(self.ssl, b"\x02h3", 3) != 0:
                raise DohError("HTTP/3: ALPN")
            lib.SSL_set_blocking_mode(self.ssl, 0)
            lib.SSL_set_default_stream_mode(self.ssl, SSL_DEFAULT_STREAM_MODE_NONE)
            self._until(lambda: lib.SSL_connect(self.ssl), self.ssl, deadline, "handshake")
            # управляющий поток: тип 0 и SETTINGS (пустые — значения по умолчанию: QPACK без динамической таблицы)
            self.ctrl = lib.SSL_new_stream(self.ssl, SSL_STREAM_FLAG_UNI)
            if not self.ctrl:
                raise DohError("HTTP/3: control stream")
            self._write(self.ctrl, varint(0) + varint(0x4) + varint(0), deadline)
        except BaseException:
            self.close()
            raise

    def _wait(self, deadline: float) -> None:
        lib = self.lib
        tv, inf = _Timeval(), ctypes.c_int(0)
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("HTTP/3: timeout")
        if lib.SSL_get_event_timeout(self.ssl, ctypes.byref(tv), ctypes.byref(inf)) and not inf.value:
            left = min(left, tv.tv_sec + tv.tv_usec / 1e6)
        if left > 0:
            select.select([self.sock], [], [], left)
        lib.SSL_handle_events(self.ssl)

    def _until(self, op, obj, deadline: float, what: str) -> int:
        """Повторять неблокирующую операцию OpenSSL, пока она не пройдёт; WANT_READ/WRITE — ждать сеть или таймер."""
        while True:
            ret = op()
            if ret > 0:
                return ret
            err = self.lib.SSL_get_error(obj, ret)
            if err in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
                self._wait(deadline)
                continue
            if err == SSL_ERROR_ZERO_RETURN:
                return 0
            raise DohError(f"HTTP/3: {what} failed ({err})")

    def _write(self, stream, data: bytes, deadline: float) -> None:
        done = ctypes.c_size_t(0)
        while data:
            self._until(lambda: self.lib.SSL_write_ex(stream, data, len(data), ctypes.byref(done)), stream, deadline,
                        "write")
            data = data[done.value:]

    def query(self, msg: bytes, host: str, path: str, deadline: float) -> bytes:
        lib = self.lib
        st = lib.SSL_new_stream(self.ssl, 0)
        if not st:
            raise DohError("HTTP/3: request stream")
        try:
            head = h3_request(host, path, len(msg))
            self._write(st, varint(0x1) + varint(len(head)) + head + varint(0x0) + varint(len(msg)) + msg, deadline)
            self._until(lambda: lib.SSL_stream_conclude(st, 0), st, deadline, "conclude")
            buf, data, got = ctypes.create_string_buffer(65536), b"", ctypes.c_size_t(0)
            while True:
                n = self._until(lambda: lib.SSL_read_ex(st, buf, len(buf), ctypes.byref(got)), st, deadline, "read")
                if n == 0:
                    break                                # FIN: ответ целиком
                data += buf.raw[:got.value]
                if len(data) > 70000:
                    raise DohError("HTTP/3: answer too long")
            if not data:
                raise DohError("HTTP/3: empty answer")   # соединение уже закрыто сервером — пул повторит на новом
            self.used = time.monotonic()
            return h3_body(data)
        finally:
            lib.SSL_free(st)

    def close(self) -> None:
        lib = self.lib
        if self.ctrl:
            lib.SSL_free(self.ctrl)
            self.ctrl = None
        if self.ssl:
            lib.SSL_free(self.ssl)                       # и BIO вместе с ним
            self.ssl = None
        if self.ctx:
            lib.SSL_CTX_free(self.ctx)
            self.ctx = None
        try:
            self.sock.close()
        except OSError:
            pass


H3_CONN_QUERIES = 1000                              # запросов на одно соединение HTTP/3, потом новое


class H3Pool:
    """Соединения HTTP/3 к одному серверу по одному пути (как Pool в dnsproxy.py): не больше size, по одному запросу на
    соединение; простаивавшее дольше idle — закрывается. Работа — в отдельных потоках (QUIC OpenSSL синхронный): цикл
    событий DNS на сервере не ждёт рукопожатия."""

    def __init__(self, make_sock, ip: str, port: int, name: str, size: int, idle: float, cafile: str | None = None):
        self.make_sock, self.ip, self.port, self.name, self.idle = make_sock, ip, port, name, idle
        self.cafile = cafile
        self.closed = False                              # пул заменён (настройки перечитаны): соединения не копить
        self.free: list[H3Conn] = []
        self.lock = threading.Lock()
        self.sem = threading.BoundedSemaphore(size)

    def query(self, msg: bytes, host: str, path: str, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        if not self.sem.acquire(timeout=timeout):
            raise TimeoutError("HTTP/3: busy")
        try:
            conn = None
            with self.lock:
                while self.free and conn is None:
                    c = self.free.pop()
                    if time.monotonic() - c.used < self.idle:
                        conn = c
                    else:
                        c.close()
            for attempt in (0, 1):
                fresh = conn is None
                if fresh:
                    conn = H3Conn(self.make_sock(), self.ip, self.port, self.name, self.cafile, deadline)
                try:
                    out = conn.query(msg, host, path, deadline)
                except DohError as e:
                    conn.close()
                    conn = None
                    if fresh or attempt or "HTTP " in str(e):
                        raise
                    continue                             # старое соединение закрыл сервер — один раз на новом
                except BaseException:
                    conn.close()
                    raise
                conn.queries = getattr(conn, "queries", 0) + 1
                with self.lock:
                    # не дольше H3_CONN_QUERIES запросов: пока соединение QUIC OpenSSL живо, память процесса растёт
                    # ~300 байт на запрос (полная проверка 1.25.0, П45)
                    if self.closed or conn.queries >= H3_CONN_QUERIES:
                        conn.close()
                    else:
                        self.free.append(conn)
                return out
            raise DohError("HTTP/3: no connection")
        finally:
            self.sem.release()

    def once(self, msg: bytes, host: str, path: str, timeout: float) -> bytes:
        """Запрос на своём новом соединении — мимо очереди (size) и свободных соединений пула; соединение потом
        закрывается. Так dnsproxy.py проверяет путь (П31): соединения пула могут быть заняты медленными именами."""
        deadline = time.monotonic() + timeout
        conn = H3Conn(self.make_sock(), self.ip, self.port, self.name, self.cafile, deadline)
        try:
            return conn.query(msg, host, path, deadline)
        finally:
            conn.close()

    def close(self) -> None:
        with self.lock:
            self.closed = True
            for c in self.free:
                c.close()
            self.free.clear()


_EXEC = None
_CHECK_EXEC = None


def run_h3(pool: H3Pool, msg: bytes, host: str, path: str, timeout: float, own: bool = False):
    """Запрос HTTP/3 из цикла событий: в своём наборе потоков (не в общем — там nft добавляет адреса в набор). own —
    проверка пути (П31): на своём соединении (H3Pool.once) и в своих потоках — все 8 общих могут ждать медленные имена."""
    global _EXEC, _CHECK_EXEC
    from concurrent.futures import ThreadPoolExecutor
    if own:
        if _CHECK_EXEC is None:
            # проверка — одна на путь (адрес системы и адреса «Напрямую — адрес»), у общих серверов и у запасного
            _CHECK_EXEC = ThreadPoolExecutor(max_workers=4, thread_name_prefix="doh3-check")
        return asyncio.get_running_loop().run_in_executor(_CHECK_EXEC, pool.once, msg, host, path, timeout)
    if _EXEC is None:
        _EXEC = ThreadPoolExecutor(max_workers=8, thread_name_prefix="doh3")
    return asyncio.get_running_loop().run_in_executor(_EXEC, pool.query, msg, host, path, timeout)
