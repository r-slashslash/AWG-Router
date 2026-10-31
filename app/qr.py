"""QR-код в PNG без сторонних библиотек (ISO/IEC 18004): для конфига клиента в Telegram.

Только байтовый режим и уровни коррекции M и L — как в браузере (static/qrcode.js):
сначала M, если не влезает — L. Картинка — 8-битный PNG в оттенках серого (zlib есть в stdlib).
"""
from __future__ import annotations

import struct
import zlib

# по версиям 1..40 (индекс 0 не используется): длина кода коррекции в блоке и число блоков
ECC_PER_BLOCK = {
    "L": (None, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
          28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    "M": (None, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
          26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
}
NUM_BLOCKS = {
    "L": (None, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
          8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25),
    "M": (None, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
          17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49),
}
FORMAT_BITS = {"L": 1, "M": 0}


class QRTooBig(ValueError):
    pass


def _raw_modules(ver: int) -> int:
    """Сколько модулей версии остаётся под данные и коррекцию."""
    n = (16 * ver + 128) * ver + 64
    if ver >= 2:
        k = ver // 7 + 2
        n -= (25 * k - 10) * k - 55
        if ver >= 7:
            n -= 36
    return n


def _data_codewords(ver: int, ecl: str) -> int:
    return _raw_modules(ver) // 8 - ECC_PER_BLOCK[ecl][ver] * NUM_BLOCKS[ecl][ver]


def _gf_mul(x: int, y: int) -> int:
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree: int) -> list[int]:
    r = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            r[j] = _gf_mul(r[j], root)
            if j + 1 < degree:
                r[j] ^= r[j + 1]
        root = _gf_mul(root, 2)
    return r


def _rs_remainder(data: list[int], div: list[int]) -> list[int]:
    r = [0] * len(div)
    for b in data:
        f = b ^ r.pop(0)
        r.append(0)
        for i, c in enumerate(div):
            r[i] ^= _gf_mul(c, f)
    return r


def _codewords(data: bytes, ver: int, ecl: str) -> list[int]:
    """Данные в байтовом режиме + коррекция, перемешанные по блокам."""
    cap = _data_codewords(ver, ecl) * 8
    bits: list[int] = []

    def put(v: int, n: int) -> None:
        bits.extend((v >> i) & 1 for i in reversed(range(n)))
    put(0b0100, 4)
    put(len(data), 8 if ver <= 9 else 16)
    for b in data:
        put(b, 8)
    put(0, min(4, cap - len(bits)))
    put(0, -len(bits) % 8)
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(words) < cap // 8:
        words.append(pad)
        pad ^= 0xEC ^ 0x11
    nb, ecc_len = NUM_BLOCKS[ecl][ver], ECC_PER_BLOCK[ecl][ver]
    raw = _raw_modules(ver) // 8
    short = nb - raw % nb
    short_len = raw // nb
    div = _rs_divisor(ecc_len)
    blocks, k = [], 0
    for i in range(nb):
        n = short_len - ecc_len + (0 if i < short else 1)
        dat = words[k:k + n]
        k += n
        ecc = _rs_remainder(dat, div)
        if i < short:
            dat = dat + [0]
        blocks.append(dat + ecc)
    out = []
    for i in range(len(blocks[0])):
        for j, blk in enumerate(blocks):
            if i != short_len - ecc_len or j >= short:
                out.append(blk[i])
    return out


def _align_positions(ver: int, size: int) -> list[int]:
    if ver == 1:
        return []
    k = ver // 7 + 2
    step = (ver * 8 + k * 3 + 5) // (k * 4 - 4) * 2
    return [6] + sorted(size - 7 - i * step for i in range(k - 1))


MASKS = (
    lambda x, y: (x + y) % 2 == 0,
    lambda x, y: y % 2 == 0,
    lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
)


class _Matrix:
    def __init__(self, ver: int, ecl: str):
        self.ver, self.ecl = ver, ecl
        self.size = n = ver * 4 + 17
        self.m = [[False] * n for _ in range(n)]
        self.fn = [[False] * n for _ in range(n)]
        self._function_patterns()

    def _set(self, x: int, y: int, dark: bool) -> None:
        self.m[y][x] = dark
        self.fn[y][x] = True

    def _function_patterns(self) -> None:
        n = self.size
        for i in range(n):
            self._set(6, i, i % 2 == 0)
            self._set(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (n - 4, 3), (3, n - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < n and 0 <= y < n:
                        self._set(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        pos = _align_positions(self.ver, n)
        last = len(pos) - 1
        for i, ay in enumerate(pos):
            for j, ax in enumerate(pos):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self._set(ax + dx, ay + dy, max(abs(dx), abs(dy)) != 1)
        self._format(0)          # место под формат; настоящие биты — после выбора маски
        if self.ver >= 7:
            rem = self.ver
            for _ in range(12):
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
            bits = self.ver << 12 | rem
            for i in range(18):
                bit = bool((bits >> i) & 1)
                a, b = n - 11 + i % 3, i // 3
                self._set(a, b, bit)
                self._set(b, a, bit)

    def _format(self, mask: int) -> None:
        n = self.size
        data = FORMAT_BITS[self.ecl] << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412

        def bit(i: int) -> bool:
            return bool((bits >> i) & 1)
        for i in range(6):
            self._set(8, i, bit(i))
        self._set(8, 7, bit(6))
        self._set(8, 8, bit(7))
        self._set(7, 8, bit(8))
        for i in range(9, 15):
            self._set(14 - i, 8, bit(i))
        for i in range(8):
            self._set(n - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self._set(8, n - 15 + i, bit(i))
        self._set(8, n - 8, True)

    def place(self, words: list[int]) -> None:
        n, i, total = self.size, 0, len(words) * 8
        right = n - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(n):
                for j in range(2):
                    x = right - j
                    y = n - 1 - vert if (right + 1) & 2 == 0 else vert
                    if not self.fn[y][x] and i < total:
                        self.m[y][x] = bool((words[i >> 3] >> (7 - (i & 7))) & 1)
                        i += 1
            right -= 2

    def masked(self, mask: int) -> list[list[bool]]:
        f = MASKS[mask]
        return [[v ^ (not self.fn[y][x] and f(x, y)) for x, v in enumerate(row)]
                for y, row in enumerate(self.m)]


def _penalty(g: list[list[bool]]) -> int:
    n = len(g)
    score = 0
    lines = g + [list(col) for col in zip(*g)]
    finder = ([1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0], [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1])
    for line in lines:
        run, prev = 0, None
        for v in line:
            run = run + 1 if v == prev else 1
            prev = v
            if run == 5:
                score += 3
            elif run > 5:
                score += 1
        ints = [int(v) for v in line]
        for i in range(n - 10):
            if ints[i:i + 11] in finder:
                score += 40
    for y in range(n - 1):
        for x in range(n - 1):
            v = g[y][x]
            if v == g[y][x + 1] == g[y + 1][x] == g[y + 1][x + 1]:
                score += 3
    dark = sum(map(sum, g))
    k = (abs(dark * 20 - n * n * 10) + n * n - 1) // (n * n) - 1
    return score + k * 10


def matrix(text: str | bytes) -> list[list[bool]]:
    """Матрица модулей (True — тёмный). QRTooBig — не влезает даже в версию 40-L."""
    data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    for ecl in ("M", "L"):
        for ver in range(1, 41):
            head = 4 + (8 if ver <= 9 else 16)
            if head + len(data) * 8 <= _data_codewords(ver, ecl) * 8:
                mx = _Matrix(ver, ecl)
                mx.place(_codewords(data, ver, ecl))
                best = None
                for mask in range(8):
                    mx._format(mask)
                    g = mx.masked(mask)
                    p = _penalty(g)
                    if best is None or p < best[0]:
                        best = (p, mask)
                mx._format(best[1])
                return mx.masked(best[1])
    raise QRTooBig("too much data for a QR code")


def png(text: str | bytes, target: int = 900, border: int = 4) -> bytes:
    """PNG с QR-кодом: белое поле в 4 модуля, сторона около target пикселей."""
    g = matrix(text)
    n = len(g) + 2 * border
    scale = max(3, target // n)
    rows = []
    white = b"\xff" * (n * scale)
    for y in range(-border, len(g) + border):
        if 0 <= y < len(g):
            px = b"".join((b"\x00" if g[y][x] else b"\xff") * scale if 0 <= x < len(g)
                          else b"\xff" * scale for x in range(-border, len(g) + border))
        else:
            px = white
        rows.extend([b"\x00" + px] * scale)

    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    side = n * scale
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", side, side, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b""))
