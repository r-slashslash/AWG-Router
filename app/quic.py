"""Имя сайта из первых пакетов QUIC (Initial). Только стандартная библиотека, без импорта панели:
файл работает внутри sniproxy.py в сети сервера AWG.

Первые пакеты соединения QUIC (Initial) зашифрованы ключами, которые выводятся из открытого в
заголовке идентификатора соединения (DCID) и известной соли версии (RFC 9001 §5.2 — v1, RFC 9369 —
v2): их может расшифровать кто угодно, это не секрет, а защита от случайного вмешательства. Внутри —
кадры CRYPTO с началом TLS ClientHello, в нём имя сайта (SNI).

Особенности:
  * Chrome с постквантовым обменом ключей (ML-KEM) кладёт ClientHello в несколько пакетов и ещё
    режет и перемешивает куски (CRYPTO со смещениями, PING, PADDING между ними) — собираем по
    смещению, как сам сервер (Assembler);
  * тег GCM не проверяется: для выбора маршрута подлинность не нужна (клиент и так может написать
    любое имя), а GHASH на чистом Python — самая медленная часть. Расшифровка — AES-CTR со счётчиком
    nonce‖2, как в GCM;
  * AES берётся из libcrypto через ctypes (она уже есть: на ней работает модуль ssl), без неё —
    своя реализация на Python (в десятки раз медленнее, но это несколько блоков на соединение).
"""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import struct

V1, V2 = 0x00000001, 0x6B3343CF
SALT = {V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
        V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")}
LABELS = {V1: ("quic key", "quic iv", "quic hp"), V2: ("quicv2 key", "quicv2 iv", "quicv2 hp")}
INITIAL_TYPE = {V1: 0, V2: 1}                # тип длинного заголовка Initial: в v2 значения сдвинуты
HELLO_MAX = 64 * 1024                        # длиннее ClientHello не собираем
PARTS_MAX = 64                               # кусков CRYPTO на соединение (у Chrome — с десяток)
KEYS_MAX = 4096                              # ключей Initial в памяти (на DCID)


class NotInitial(Exception):
    """Это не пакет Initial поддерживаемой версии (или он испорчен)."""


# ---------------------------------------------------------------- AES-128 (только шифрование)
def _libcrypto():
    for name in ("libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"):
        try:
            lib = ctypes.CDLL(name)
            lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
            lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
            lib.EVP_aes_128_ecb.restype = lib.EVP_aes_128_ctr.restype = ctypes.c_void_p
            lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                               ctypes.c_char_p, ctypes.c_char_p]
            lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
                                              ctypes.c_char_p, ctypes.c_int]
            lib.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]
            return lib
        except (OSError, AttributeError):
            continue
    return None


_LIB = _libcrypto()


def _evp(cipher, key: bytes, iv: bytes | None, data: bytes) -> bytes:
    ctx = _LIB.EVP_CIPHER_CTX_new()
    if not ctx:
        raise MemoryError("EVP_CIPHER_CTX_new")
    try:
        if _LIB.EVP_EncryptInit_ex(ctx, cipher, None, key, iv) != 1:
            raise ValueError("EVP_EncryptInit_ex")
        _LIB.EVP_CIPHER_CTX_set_padding(ctx, 0)
        out = ctypes.create_string_buffer(len(data) + 16)
        n = ctypes.c_int(0)
        if _LIB.EVP_EncryptUpdate(ctx, out, ctypes.byref(n), data, len(data)) != 1:
            raise ValueError("EVP_EncryptUpdate")
        return out.raw[:n.value]
    finally:
        _LIB.EVP_CIPHER_CTX_free(ctx)


# своя реализация: таблица замен и расширение ключа по FIPS-197
def _sbox() -> bytes:
    sbox, p, q = [0] * 256, 1, 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)      # p * 3 в GF(2^8)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09                                               # q / 3
        x = q ^ ((q << 1 | q >> 7) & 0xFF) ^ ((q << 2 | q >> 6) & 0xFF) ^ \
            ((q << 3 | q >> 5) & 0xFF) ^ ((q << 4 | q >> 4) & 0xFF)
        sbox[p] = x ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return bytes(sbox)


_S = _sbox()


def _xt(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _expand(key: bytes) -> list[list[int]]:
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rc = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_S[t[1]] ^ rc, _S[t[2]], _S[t[3]], _S[t[0]]]
            rc = _xt(rc)
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


def _block_py(rk: list[list[int]], b: bytes) -> bytes:
    s = [b[i] ^ rk[0][i] for i in range(16)]
    for r in range(1, 11):
        s = [_S[x] for x in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]                 # ShiftRows (по столбцам)
        if r < 10:
            m = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                m += [a[i] ^ t ^ _xt(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = m
        s = [s[i] ^ rk[r][i] for i in range(16)]
    return bytes(s)


def aes_ecb(key: bytes, block: bytes) -> bytes:
    """Один блок AES-128 (маска заголовка)."""
    if _LIB is not None:
        return _evp(_LIB.EVP_aes_128_ecb(), key, None, block)
    return _block_py(_expand(key), block)


def aes_ctr(key: bytes, counter: bytes, data: bytes) -> bytes:
    """AES-128-CTR, счётчик — 16 байт, младшие 4 растут (как в GCM)."""
    if _LIB is not None:
        return _evp(_LIB.EVP_aes_128_ctr(), key, counter, data)
    rk = _expand(key)
    head, n = counter[:12], struct.unpack("!I", counter[12:])[0]
    out = bytearray()
    for i in range(0, len(data), 16):
        ks = _block_py(rk, head + struct.pack("!I", (n + i // 16) & 0xFFFFFFFF))
        out += bytes(x ^ y for x, y in zip(data[i:i + 16], ks))
    return bytes(out)


# ---------------------------------------------------------------- ключи Initial
def _expand_label(secret: bytes, label: str, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack("!HB", length, len(full)) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


_keys: dict[tuple[int, bytes], tuple[bytes, bytes, bytes]] = {}


def client_keys(version: int, dcid: bytes) -> tuple[bytes, bytes, bytes]:
    """(key, iv, hp) клиента для пакетов Initial этой версии и DCID."""
    k = (version, dcid)
    hit = _keys.get(k)
    if hit:
        return hit
    initial = hmac.new(SALT[version], dcid, hashlib.sha256).digest()      # HKDF-Extract
    secret = _expand_label(initial, "client in", 32)
    kl, il, hl = LABELS[version]
    res = (_expand_label(secret, kl, 16), _expand_label(secret, il, 12), _expand_label(secret, hl, 16))
    if len(_keys) >= KEYS_MAX:
        _keys.pop(next(iter(_keys)))
    _keys[k] = res
    return res


# ---------------------------------------------------------------- разбор
def varint(b: bytes, p: int) -> tuple[int, int]:
    if p >= len(b):
        raise NotInitial("varint")
    n = 1 << (b[p] >> 6)
    if p + n > len(b):
        raise NotInitial("varint")
    v = b[p] & 0x3F
    for x in b[p + 1:p + n]:
        v = (v << 8) | x
    return v, p + n


def kind(datagram: bytes) -> str:
    """Что за датаграмма UDP: initial — длинный заголовок QUIC с Initial поддерживаемой версии;
    quic — похожа на QUIC, но не она (другой тип или версия, короткий заголовок); other — не QUIC
    (DTLS, WireGuard, OpenVPN и т. п. на порту 443)."""
    if len(datagram) < 7 or not datagram[0] & 0x40:
        return "other"                       # без бита «фиксированный» — не QUIC (RFC 9000 §17.2)
    if not datagram[0] & 0x80:
        return "quic"                        # короткий заголовок: соединение уже идёт
    version = struct.unpack("!I", datagram[1:5])[0]
    if version in INITIAL_TYPE and (datagram[0] >> 4) & 3 == INITIAL_TYPE[version]:
        return "initial"
    return "quic"


def initial_frames(datagram: bytes) -> tuple[bytes, list[tuple[int, bytes]]]:
    """Пакеты Initial датаграммы (их бывает несколько подряд) → (DCID, [(смещение, данные CRYPTO)]).
    Пакеты других типов в той же датаграмме пропускаются."""
    p, dcid, crypto = 0, None, []
    while p < len(datagram):
        b = datagram[p:]
        if len(b) < 7 or not b[0] & 0x80:
            break
        version = struct.unpack("!I", b[1:5])[0]
        if version not in INITIAL_TYPE:
            raise NotInitial("version")
        q = 5
        dl = b[q]
        cid = b[q + 1:q + 1 + dl]
        q += 1 + dl
        if q >= len(b):
            raise NotInitial("short")
        q += 1 + b[q]                                         # SCID
        ptype = (b[0] >> 4) & 3
        if ptype == INITIAL_TYPE[version]:
            tlen, q = varint(b, q)
            q += tlen                                         # токен
        length, q = varint(b, q)
        end = q + length
        if end > len(b) or length < 20:
            raise NotInitial("length")
        if ptype != INITIAL_TYPE[version]:
            p += end                                          # 0-RTT, Handshake — не наше
            continue
        if dcid is None:
            dcid = cid
        crypto += _decrypt(b[:end], version, cid, q)
        p += end
    if dcid is None:
        raise NotInitial("no initial")
    return dcid, crypto


def _decrypt(pkt: bytes, version: int, dcid: bytes, pn_off: int) -> list[tuple[int, bytes]]:
    key, iv, hp = client_keys(version, dcid)
    sample = pkt[pn_off + 4:pn_off + 20]
    if len(sample) < 16:
        raise NotInitial("sample")
    mask = aes_ecb(hp, sample)
    first = pkt[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 3) + 1
    pn = int.from_bytes(bytes(x ^ y for x, y in zip(pkt[pn_off:pn_off + pn_len], mask[1:1 + pn_len])), "big")
    nonce = (int.from_bytes(iv, "big") ^ pn).to_bytes(12, "big")
    body = pkt[pn_off + pn_len:len(pkt) - 16]                         # без тега GCM
    return _frames(aes_ctr(key, nonce + b"\x00\x00\x00\x02", body))


def _frames(plain: bytes) -> list[tuple[int, bytes]]:
    """Кадры CRYPTO из расшифрованного Initial. PADDING, PING и ACK пропускаются; другие кадры в
    Initial клиента не бывают — на них разбор останавливается."""
    p, out = 0, []
    while p < len(plain):
        t = plain[p]
        if t == 0x00 or t == 0x01:                                    # PADDING, PING
            p += 1
        elif t == 0x06:                                               # CRYPTO
            off, p = varint(plain, p + 1)
            ln, p = varint(plain, p)
            if p + ln > len(plain):
                raise NotInitial("crypto")
            out.append((off, plain[p:p + ln]))
            p += ln
        elif t in (0x02, 0x03):                                       # ACK
            _, p = varint(plain, p + 1)
            _, p = varint(plain, p)
            n, p = varint(plain, p)
            _, p = varint(plain, p)
            for _ in range(n):
                _, p = varint(plain, p)
                _, p = varint(plain, p)
            if t == 0x03:
                for _ in range(3):
                    _, p = varint(plain, p)
        else:
            break
    return out


class Assembler:
    """Начало потока CRYPTO по кускам из разных пакетов: hello() → тело ClientHello (без 4 байт
    заголовка сообщения TLS), когда оно собрано целиком, иначе None."""

    def __init__(self):
        self.parts: dict[int, bytes] = {}
        self.size = 0

    def add(self, pieces: list[tuple[int, bytes]]) -> None:
        for off, data in pieces:
            if off + len(data) > HELLO_MAX or not data:
                continue
            if off not in self.parts and len(self.parts) >= PARTS_MAX:
                continue                     # поток пакетов с новыми смещениями не растит память и разбор
            if len(data) > len(self.parts.get(off, b"")):
                self.parts[off] = data
                self.size += len(data)

    def stream(self) -> bytes:
        """Непрерывное начало потока (куски могут перекрываться)."""
        buf, pos = bytearray(), 0
        for off in sorted(self.parts):
            data = self.parts[off]
            if off > pos:
                break
            if off + len(data) > pos:
                buf += data[pos - off:]
                pos = off + len(data)
        return bytes(buf)

    def hello(self) -> bytes | None:
        s = self.stream()
        if len(s) < 4:
            return None
        if s[0] != 1:                                                 # не ClientHello
            raise NotInitial("not client hello")
        need = 4 + int.from_bytes(s[1:4], "big")
        if need > HELLO_MAX:
            raise NotInitial("hello too long")
        return s[4:need] if len(s) >= need else None
