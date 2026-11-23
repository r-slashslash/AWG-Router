"""Картинки бота (1.24.0): главное меню и «Состояние» — PNG с цифрами вместо подписи под логотипом.

Шрифтов в стандартной библиотеке нет, поэтому надписи заготовлены заранее: tools/tgcard_atlas.py рисует в Chrome
все постоянные слова на четырёх языках (персидские — уже справа налево и со связанными буквами), знаки ASCII
нужных размеров, значки и логотип и кладёт их маски (прозрачность, 8 бит на точку) в tgcard.atlas. Здесь маски
только раскладываются и красятся. Меняющиеся части — адрес, числа, версии — собираются из знаков ASCII.

Чего нет в атласе (текст в TEXTS поменяли, а инструмент не запустили), — CardError: бот шлёт меню текстом, как до
1.24.0. Тест AtlasTest сверяет атлас с TEXTS и говорит, что инструмент нужно запустить.

Под надписью фон однотонный: краска кладётся таблицами bytes.translate, а не по точке на Python, — картинка меню
рисуется за десятки миллисекунд и на 1 vCPU.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import zlib

ATLAS = os.path.join(os.path.dirname(__file__), "tgcard.atlas")
MAGIC = b"AWGRATLAS1\n"

W = 1280                   # ширина картинки: столько Telegram и хранит, мельче на телефоне — буквы мельче
MENU_H = 800
STATUS_H = 1150
PAD_X = 88
PAD_Y = 64
ROW_H = 92                 # строка: 2 точки линии сверху и 90 под текст
HEAD = 65 + 36             # логотип и отступ до первой строки
GAP = 28                   # значок — название
VALUE_GAP = 40             # название — значение (меньше нельзя: длинный адрес уменьшается, чтобы его не задеть)

# Стили надписей: (размер, толщина). Шрифт — по языку (tools/tgcard_atlas.py, FONTS).
STYLES = {
    "logo60": (60, 800), "logo52": (52, 800),
    # значения — 550, а не жирнее: рядом с названиями (500) жирные цифры спорили с ними (владелец, 2026-11-23)
    "lab": (44, 500), "val": (54, 550), "of": (44, 500),
    "slab": (42, 500), "sval": (48, 550), "sof": (40, 500), "sub": (30, 500), "pill": (32, 600),
    # мельче — только для адреса, который не влез (одни знаки ASCII)
    "val48": (48, 550), "val42": (42, 550), "val36": (36, 550), "val30": (30, 550),
    "sval42": (42, 550), "sval36": (36, 550), "sval30": (30, 550),
}
# знаки, из которых собираются меняющиеся значения (адреса, числа, версии)
CHARS = "".join(chr(i) for i in range(32, 127)) + "·—…"
GLYPH_STYLES = ("val", "of", "sval", "sof", "sub", "val48", "val42", "val36", "val30", "sval42", "sval36", "sval30")
HOST_STYLES = ("val", "val48", "val42", "val36", "val30")
SHOST_STYLES = ("sval", "sval42", "sval36", "sval30")
# Постоянные слова: стиль → ключи TEXTS бота. Из шаблона («{n} из {total}») берутся куски между {…}.
PHRASES = {
    "logo60": (), "logo52": (),
    "lab": ("pc_server", "pc_exits", "pc_version", "pc_clients", "pc_online", "pc_traffic"),
    "val": ("u_mb", "u_gb", "u_tb"),
    "of": ("pc_of", "pc_none"),
    "slab": ("pc_version", "ps_awg", "ps_engine", "ps_v4", "ps_v6", "ps_dns", "ps_uptime", "ps_ram", "ps_online",
             "ps_month"),
    "sval": ("ps_kernel", "st_dns_plain", "ps_dns_off", "ps_dns_err", "ps_v4_wait", "ps_v4_fail", "up_dh", "up_hm",
             "u_mb", "u_gb", "u_tb", "pc_of"),
    "sof": ("pc_of", "ps_v6_none"),
    "sub": ("ps_upd", "st_dns_stats", "ps_dns_upfail", "ps_dns_err_sub"),
    "pill": ("ps_ok", "ps_bad"),
}
LANGS = ("ru", "en", "zh", "fa")
# Значки — линии в квадрате 24×24, как в макете (рисует инструмент атласа)
ICONS = {
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/>'
             '<path d="M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>',
    "exit": '<path d="M10 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h5"/><path d="M14 8l4 4-4 4"/><path d="M18 12H9"/>',
    "tag": '<path d="M20.6 13.4l-7.2 7.2a2 2 0 0 1-2.8 0L3 13V3h10l7.6 7.6a2 2 0 0 1 0 2.8z"/>'
           '<circle cx="7.5" cy="7.5" r="1.5"/>',
    "users": '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.6-3.6 3.2-5.5 6.5-5.5s5.9 1.9 6.5 5.5"/>'
             '<path d="M16 4.8a3.5 3.5 0 0 1 0 6.4"/><path d="M18.5 14.8c1.7.8 2.7 2.5 3 5.2"/>',
    "online": '<circle cx="12" cy="12" r="9" opacity="0.35"/><circle cx="12" cy="12" r="5" fill="#fff" stroke="none"/>',
    "traffic": '<path d="M7 20V5"/><path d="M3 9l4-4 4 4"/><path d="M17 4v15"/><path d="M13 15l4 4 4-4"/>',
    "shield": '<path d="M12 3l7 3v6c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6l7-3z"/>',
    "chip": '<rect x="6" y="6" width="12" height="12" rx="2"/>'
            '<path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
    "compass": '<circle cx="12" cy="12" r="9"/><path d="M15.5 8.5l-2 5-5 2 2-5 5-2z"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "ram": '<rect x="3" y="7" width="18" height="10" rx="1.5"/><path d="M7 17v3M12 17v3M17 17v3M7 10v4M12 10v4M17 10v4"/>',
}
ICON_SIZES = (44, 40)
# значок логотипа — готовые точки RGB на белом (кольцо поверх перемычки без шва); (ширина, высота) и стиль слова
LOGOS = {"menu": (160, 65, "logo60"), "status": (138, 56, "logo52")}
LOGO_SVG = ('<circle cx="44" cy="44" r="44" fill="#2F6FED"/><rect x="80" y="36" width="56" height="16" fill="#2F6FED"/>'
            '<circle cx="172" cy="44" r="35" fill="none" stroke="#0E9F6E" stroke-width="18"/>')
DOT = 16                   # точка в пометке «Работает»

INK = (22, 27, 38)
GRAY = (90, 100, 120)
LINE = (230, 234, 240)
WHITE = (255, 255, 255)
BLUE = (47, 111, 237)
GREEN = (14, 159, 110)       # значки
GREEN_TEXT = (11, 138, 95)   # цифры: темнее — читаются на белом
ORANGE = (180, 83, 9)
RED = (200, 30, 30)
PILL = {True: ((227, 245, 236), (11, 107, 74), (14, 159, 110)),     # фон, текст, точка
        False: ((253, 236, 236), (180, 35, 24), (217, 45, 32))}

SP = (" ", "")              # пробел между кусками: шириной пробела своего стиля


class CardError(Exception):
    """Картинку не нарисовать (нет атласа или в нём нет слова) — бот покажет экран текстом."""


# ---------------------------------------------------------------- какие слова нужны (и для инструмента атласа)
def literals(s: str) -> list[str]:
    """Постоянные куски шаблона: «{d} дн. {h} ч» → ['дн.', 'ч']."""
    return [p.strip() for p in re.split(r"\{\w+\}", s) if p.strip()]


def needed(texts: dict) -> dict[str, list[str]]:
    """Всё, что должно быть в атласе: ключ → что нарисовать. texts — tgbot.TEXTS."""
    out: dict[str, list[str]] = {}
    for style, keys in PHRASES.items():
        for lang in LANGS:
            for k in keys:
                for p in literals(texts[lang][k]):
                    out[f"{style}|{lang}|{p}"] = ["p", style, lang, p]
    for style in GLYPH_STYLES:
        for ch in CHARS:
            out[f"{style}|*|{ch}"] = ["g", style, "", ch]
    for word in {s for _, _, s in LOGOS.values()}:
        out[f"{word}|*|AWG Router"] = ["p", word, "", "AWG Router"]
    for name in ICONS:
        for size in ICON_SIZES:
            out[f"icon{size}|{name}"] = ["i", name, size]
    for kind, (w, h, _) in LOGOS.items():
        out[f"logo|{kind}"] = ["l", kind, w, h]
    out[f"dot|{DOT}"] = ["d", DOT]
    return out


def spec_sum(texts: dict) -> str:
    """Отпечаток того, что нужно атласу: другой — атлас устарел (тест AtlasTest)."""
    raw = json.dumps([STYLES, sorted(needed(texts)), ICONS, LOGOS, LOGO_SVG], sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------- атлас
class Mask:
    __slots__ = ("a", "w", "h", "x0", "y0", "adv")

    def __init__(self, a: bytes, w: int, h: int, x0: int, y0: int, adv: float):
        self.a, self.w, self.h, self.x0, self.y0, self.adv = a, w, h, x0, y0, adv


class Atlas:
    """Файл атласа: MAGIC, длина и JSON оглавления, затем маски, каждая сжата отдельно. Читается на каждую
    картинку (бот рисует их по нажатию): в памяти панели между картинками ничего не остаётся."""

    def __init__(self, path: str = ATLAS):
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError as e:
            raise CardError(f"atlas: {e}") from None
        if not raw.startswith(MAGIC):
            raise CardError("atlas: bad file")
        n = struct.unpack(">I", raw[len(MAGIC):len(MAGIC) + 4])[0]
        start = len(MAGIC) + 4
        try:
            self.head = json.loads(raw[start:start + n])
        except ValueError:
            raise CardError("atlas: bad index") from None
        self.raw = memoryview(raw)[start + n:]
        self.items = self.head["items"]
        self.cache: dict[str, Mask] = {}

    def get(self, key: str) -> Mask:
        m = self.cache.get(key)
        if m is None:
            it = self.items.get(key)
            if it is None:
                raise CardError(f"atlas: no {key!r}")
            off, size, w, h, x0, y0, adv = it
            a = zlib.decompress(self.raw[off:off + size]) if size else b""
            m = self.cache[key] = Mask(a, w, h, x0, y0, adv)
        return m

    def glyph(self, style: str, ch: str) -> Mask:
        key = f"{style}|*|{ch}"
        return self.get(key if key in self.items else f"{style}|*|?")

    def phrase(self, style: str, lang: str, text: str) -> Mask:
        key = f"{style}|{lang}|{text}"
        return self.get(key if key in self.items else f"{style}|*|{text}")


# ---------------------------------------------------------------- холст
class Canvas:
    """Картинка RGB в bytearray. Маска кладётся на известный однотонный фон: три таблицы bytes.translate на пару
    цветов — и строка маски красится целиком, без цикла по точкам."""

    def __init__(self, w: int, h: int, bg=WHITE):
        self.w, self.h = w, h
        self.buf = bytearray(bytes(bg) * (w * h))
        self._tables: dict = {}

    def rect(self, x: int, y: int, w: int, h: int, color) -> None:
        x, w = max(0, x), min(w, self.w - max(0, x))
        line = bytes(color) * w
        for yy in range(max(0, y), min(self.h, y + h)):
            s = (yy * self.w + x) * 3
            self.buf[s:s + 3 * w] = line

    def _table(self, fg, bg):
        t = self._tables.get((fg, bg))
        if t is None:
            t = self._tables[(fg, bg)] = tuple(
                bytes(b + ((f - b) * a + 127) // 255 for a in range(256)) for f, b in zip(fg, bg))
        return t

    def mask(self, m: Mask, x: int, y: int, fg, bg=WHITE) -> None:
        if not m.w or not m.h:
            return
        tr, tg, tb = self._table(fg, bg)
        cut_l = max(0, -x)
        cut_r = max(0, x + m.w - self.w)
        w = m.w - cut_l - cut_r
        if w <= 0:
            return
        for r in range(m.h):
            yy = y + r
            if not 0 <= yy < self.h:
                continue
            row = m.a[r * m.w + cut_l:r * m.w + cut_l + w]
            if not any(row):
                continue
            s = (yy * self.w + x + cut_l) * 3
            self.buf[s:s + 3 * w:3] = row.translate(tr)
            self.buf[s + 1:s + 3 * w:3] = row.translate(tg)
            self.buf[s + 2:s + 3 * w:3] = row.translate(tb)

    def rgb(self, m: Mask, x: int, y: int) -> None:
        """Готовые точки RGB (значок логотипа), без краски."""
        for r in range(m.h):
            s = ((y + r) * self.w + x) * 3
            self.buf[s:s + 3 * m.w] = m.a[r * m.w * 3:(r + 1) * m.w * 3]

    def pill(self, x: int, y: int, w: int, h: int, color, bg=WHITE) -> None:
        """Скруглённый прямоугольник (радиус — половина высоты), край сглажен."""
        r = h / 2
        tables = self._table(color, bg)
        for i in range(h):
            dy = abs(i + 0.5 - r)
            half = (r * r - dy * dy) ** 0.5 if dy < r else 0.0
            inset = r - half
            full_l = int(inset + 1)
            self.rect(x + full_l, y + i, w - 2 * full_l, 1, color)
            edge = full_l - inset           # доля краевой точки внутри фигуры
            a = max(0, min(255, int(edge * 255)))
            for xx in (x + full_l - 1, x + w - full_l):
                if 0 <= xx < self.w and 0 <= y + i < self.h:
                    s = ((y + i) * self.w + xx) * 3
                    self.buf[s:s + 3] = bytes(t[a] for t in tables)

    def png(self) -> bytes:
        stride = self.w * 3
        mv = memoryview(self.buf)
        raw = b"".join(b"\x00" + mv[y * stride:(y + 1) * stride].tobytes() for y in range(self.h))

        def chunk(kind: bytes, data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
        return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", self.w, self.h, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


# ---------------------------------------------------------------- строки из кусков
def tpl(text: str, **slots) -> list:
    """Шаблон TEXTS → куски: ('p', слово) — постоянное слово, ('a', текст) — знаки ASCII, SP — пробел.
    Значение слота — строка (знаки ASCII) или список кусков."""
    out: list = []
    pos = 0
    text = text.strip()           # «   запросов {q}…» в TEXTS — с отступом для текста, на картинке он не нужен
    for m in re.finditer(r"\{(\w+)\}", text):
        _lit(out, text[pos:m.start()])
        v = slots[m.group(1)]
        out.extend([("a", v)] if isinstance(v, str) else v)
        pos = m.end()
    _lit(out, text[pos:])
    return out


def _lit(out: list, s: str) -> None:
    if not s:
        return
    core = s.strip()
    if s[0].isspace():
        out.append(SP)
    if core:
        out.append(("p", core))
        if s[-1].isspace():
            out.append(SP)


class Seg:
    """Кусок значения одним стилем и цветом."""
    __slots__ = ("style", "color", "pieces")

    def __init__(self, style: str, color, pieces: list):
        self.style, self.color, self.pieces = style, color, pieces


def styled(text: str, main: Seg, rest: Seg, first: str, **slots) -> list[Seg]:
    """Шаблон, у которого слот first — крупно своим цветом (main), остальное — мельче (rest): «2 из 3»."""
    segs: list[Seg] = []
    pos = 0

    def add(style, color, pieces):
        if not pieces:
            return
        if segs and segs[-1].style == style and segs[-1].color == color:
            segs[-1].pieces.extend(pieces)
        else:
            segs.append(Seg(style, color, list(pieces)))
    for m in re.finditer(r"\{(\w+)\}", text):
        lit: list = []
        _lit(lit, text[pos:m.start()])
        add(rest.style, rest.color, lit)
        v = slots[m.group(1)]
        pieces = [("a", v)] if isinstance(v, str) else v
        if m.group(1) == first:
            add(main.style, main.color, pieces)
        else:
            add(rest.style, rest.color, pieces)
        pos = m.end()
    lit = []
    _lit(lit, text[pos:])
    add(rest.style, rest.color, lit)
    return segs


class Painter:
    def __init__(self, atlas: Atlas, lang: str, h: int):
        self.at, self.lang = atlas, lang
        self.rtl = lang == "fa"
        self.cv = Canvas(W, h)

    def run(self, style: str, pieces: list) -> Mask:
        """Куски одной строкой → одна маска (перекрытия складываются через OR). Справа налево (fa) куски
        идут от правого края: «412 مگابایت» читается справа налево, знаки ASCII внутри — слева направо."""
        seq = list(reversed(pieces)) if self.rtl else pieces
        placed = []
        pen = 0.0
        for kind, text in seq:
            if kind == " ":
                pen += self.at.glyph(style, " ").adv
            elif kind == "p":
                m = self.at.phrase(style, self.lang, text)
                placed.append((pen, m))
                pen += m.adv
            else:
                for ch in text:
                    m = self.at.glyph(style, ch)
                    if m.w:
                        placed.append((pen, m))
                    pen += m.adv
        if not placed:
            return Mask(b"", 0, 0, 0, 0, pen)
        left = min(round(px) + m.x0 for px, m in placed)
        right = max(round(px) + m.x0 + m.w for px, m in placed)
        top = min(m.y0 for _, m in placed)
        bottom = max(m.y0 + m.h for _, m in placed)
        w, h = right - left, bottom - top
        buf = bytearray(w * h)
        for px, m in placed:
            x = round(px) + m.x0 - left
            for r in range(m.h):
                s = (m.y0 - top + r) * w + x
                src = m.a[r * m.w:(r + 1) * m.w]
                old = buf[s:s + m.w]
                if any(old):
                    src = (int.from_bytes(old, "big") | int.from_bytes(src, "big")).to_bytes(m.w, "big")
                buf[s:s + m.w] = src
        return Mask(bytes(buf), w, h, left, top, pen)

    def width(self, segs: list[Seg]) -> float:
        return sum(self.run(s.style, s.pieces).adv for s in segs)

    def text(self, segs: list[Seg], x: float, base: int, end: bool = False, bg=WHITE) -> float:
        """Значение из кусков. x — левый край (end=True — правый) в раскладке слева направо; справа налево
        всё зеркально. Возвращает ширину."""
        runs = [(s, self.run(s.style, s.pieces)) for s in segs]
        total = sum(m.adv for _, m in runs)
        left = x - total if end else x
        if self.rtl:
            left = W - left - total
            runs.reverse()
        pen = left
        for s, m in runs:
            self.cv.mask(m, round(pen) + m.x0, base + m.y0, s.color, bg)
            pen += m.adv
        return total

    def icon(self, name: str, size: int, x: int, y: int, color) -> None:
        m = self.at.get(f"icon{size}|{name}")
        if self.rtl:
            x = W - x - size
        self.cv.mask(m, x + m.x0, y + m.y0, color)

    def logo(self, kind: str, x: int, y: int) -> int:
        """Логотип слева направо и в персидском (имя продукта); x — левый край в раскладке слева направо."""
        w, h, word = LOGOS[kind]
        wm = self.at.get(f"{word}|*|AWG Router")
        total = w + 20 + round(wm.adv)
        if self.rtl:
            x = W - x - total
        self.cv.rgb(self.at.get(f"logo|{kind}"), x, y)
        size = STYLES[word][0]
        base = y + h // 2 + round(size * 0.36)
        self.cv.mask(wm, x + w + 20 + wm.x0, base + wm.y0, INK)
        return total

    def row(self, y: int, icon: str, label: list[Seg], value: list[Seg], sub: list[Seg] | None = None,
            icon_size: int = 44, icon_color=BLUE) -> None:
        """Строка списка: линия сверху, значок, название (и мелкая строка под ним), значение у другого края."""
        self.cv.rect(PAD_X, y, W - 2 * PAD_X, 2, LINE)
        mid = y + 2 + (ROW_H - 2) // 2
        self.icon(icon, icon_size, PAD_X, mid - icon_size // 2, icon_color)
        lx = PAD_X + icon_size + GAP
        lsize = STYLES[label[0].style][0]
        if sub:
            ssize = STYLES[sub[0].style][0]
            block = round(lsize * 0.72) + 16 + round(ssize * 0.72)
            lbase = mid - block // 2 + round(lsize * 0.72)
            self.text(label, lx, lbase)
            self.text(sub, lx, lbase + 16 + round(ssize * 0.72))
        else:
            self.text(label, lx, mid + round(lsize * 0.36))
        vsize = STYLES[value[0].style][0]
        self.text(value, W - PAD_X, mid + round(vsize * 0.36), end=True)

    def fit(self, text: str, styles: tuple, room: float, color=INK) -> list[Seg]:
        """Адрес — самым крупным стилем, которым он влезает; не влез и самым мелким — обрезается с «…»."""
        for st in styles:
            segs = [Seg(st, color, [("a", text)])]
            if self.width(segs) <= room:
                return segs
        st = styles[-1]
        while len(text) > 4:
            text = text[:-1]
            segs = [Seg(st, color, [("a", text + "…")])]
            if self.width(segs) <= room:
                return segs
        return segs


def _ascii(s) -> str:
    """Значение для знаков ASCII: остальное (домен не латиницей) — «?»."""
    return "".join(ch if ch in CHARS else "?" for ch in str(s)) or "—"


def _p(tx: dict, key: str) -> tuple:
    """Постоянное слово из TEXTS (как его берёт needed: без пробелов по краям)."""
    return ("p", tx[key].strip())


def _size(tx: dict, n: tuple) -> list:
    """(число, ключ единицы) → куски «44,5 ГБ»."""
    return [("a", _ascii(n[0])), SP, _p(tx, n[1])]


# ---------------------------------------------------------------- картинки
def menu(tx: dict, lang: str, d: dict, atlas: Atlas | None = None) -> bytes:
    """Главное меню. tx — тексты бота на языке lang (tgbot.TEXTS[lang]); d: host, exits (работают, всего
    включённых), version, clients, online, traffic (число, ключ единицы)."""
    p = Painter(atlas or Atlas(), lang, MENU_H)
    top = (MENU_H - HEAD - 6 * ROW_H) // 2          # строк меньше, чем в «Состоянии», — по середине высоты
    p.logo("menu", PAD_X, top)
    lab = lambda key: [Seg("lab", GRAY, [_p(tx, key)])]
    y = top + HEAD
    room = W - 2 * PAD_X - 44 - GAP - VALUE_GAP - p.width(lab("pc_server"))
    up, total = d["exits"]
    if total:
        color = GREEN_TEXT if up == total else (RED if up == 0 else ORANGE)
        exits = styled(tx["pc_of"], Seg("val", color, []), Seg("of", GRAY, []), "n", n=str(up), total=str(total))
    else:
        exits = [Seg("of", GRAY, [_p(tx, "pc_none")])]
    rows = [
        ("globe", "pc_server", p.fit(_ascii(d["host"]), HOST_STYLES, room)),
        ("exit", "pc_exits", exits),
        ("tag", "pc_version", [Seg("val", INK, [("a", _ascii(d["version"]))])]),
        ("users", "pc_clients", [Seg("val", INK, [("a", str(d["clients"]))])]),
        ("online", "pc_online", [Seg("val", GREEN_TEXT, [("a", str(d["online"]))])]),
        ("traffic", "pc_traffic", [Seg("val", INK, _size(tx, d["traffic"]))]),
    ]
    for icon, key, value in rows:
        p.row(y, icon, lab(key), value, icon_color=GREEN if icon == "online" else BLUE)
        y += ROW_H
    return p.cv.png()


def status(tx: dict, lang: str, d: dict, atlas: Atlas | None = None) -> bytes:
    """«Состояние» без строки «Хост». d: ok, version, latest, awg, engine ("kernel", версия) | ("go",) | None,
    v4, v4_state, v6, dns (None — выключен; state, listen, encrypt, queries, cached, upstream_error), uptime (с),
    memory (занято, всего в байтах — уже (число, ключ) у каждого), online, total, month (число, ключ)."""
    p = Painter(atlas or Atlas(), lang, STATUS_H)
    p.logo("status", PAD_X, PAD_Y + 4)
    # пометка «Работает» / «Сервер AmneziaWG недоступен» — у другого края шапки
    bg, fg, dot = PILL[bool(d["ok"])]
    label = p.run("pill", [_p(tx, "ps_ok" if d["ok"] else "ps_bad")])
    pw, ph = 28 + DOT + 14 + round(label.adv) + 28, 64
    px = W - PAD_X - pw
    if p.rtl:
        px = PAD_X
    py = PAD_Y
    p.cv.pill(px, py, pw, ph, bg)
    dm = p.at.get(f"dot|{DOT}")
    dx = px + 28 if not p.rtl else px + pw - 28 - DOT
    p.cv.mask(dm, dx + dm.x0, py + (ph - DOT) // 2 + dm.y0, dot, bg)
    tx_x = dx + DOT + 14 if not p.rtl else px + 28
    p.cv.mask(label, tx_x + label.x0, py + ph // 2 + round(32 * 0.36) + label.y0, fg, bg)

    lab = lambda key: [Seg("slab", GRAY, [_p(tx, key)])]
    sval = lambda pieces, color=INK: [Seg("sval", color, pieces)]
    a = lambda v: [("a", _ascii(v))]
    room = lambda key: W - 2 * PAD_X - 40 - GAP - VALUE_GAP - p.width(lab(key))
    rows = []
    sub = [Seg("sub", BLUE, tpl(tx["ps_upd"], version=_ascii(d["latest"])))] if d.get("latest") else None
    rows.append(("tag", "pc_version", sval(a(d["version"])), sub))
    rows.append(("shield", "ps_awg", sval(a(d.get("awg") or "—")), None))
    e = d.get("engine")
    if e and e[0] == "kernel":
        eng = sval(tpl(tx["ps_kernel"], version=_ascii(e[1] or "?")))
    elif e and e[0] == "go":
        eng = sval(a("amneziawg-go"))
    else:
        eng = sval(a("—"))
    rows.append(("chip", "ps_engine", eng, None))
    if d.get("v4"):
        v4 = p.fit(_ascii(d["v4"]), SHOST_STYLES, room("ps_v4"))
    else:
        v4 = sval([_p(tx, "ps_v4_fail" if d.get("v4_state") == "failed" else "ps_v4_wait")], GRAY)
    rows.append(("globe", "ps_v4", v4, None))
    v6 = p.fit(_ascii(d["v6"]), SHOST_STYLES, room("ps_v6")) if d.get("v6") else \
        [Seg("sof", GRAY, [_p(tx, "ps_v6_none")])]
    rows.append(("globe", "ps_v6", v6, None))
    dns, dsub = d.get("dns"), None
    if not dns:
        dval = sval([_p(tx, "ps_dns_off")], GRAY)
    elif dns.get("state") != "on":
        dval = sval([_p(tx, "ps_dns_err")], RED)
        dsub = [Seg("sub", GRAY, [_p(tx, "ps_dns_err_sub")])]
    else:
        mode = {"doh": "DoH", "dot": "DoT"}.get(dns.get("encrypt") or "plain")
        addr = _ascii(dns.get("listen") or "—") + " · "
        dval = sval([("a", addr + mode)] if mode else [("a", addr), _p(tx, "st_dns_plain")])
        if dns.get("upstream_error"):
            dsub = [Seg("sub", ORANGE, [_p(tx, "ps_dns_upfail")])]
        elif dns.get("queries") is not None:
            dsub = [Seg("sub", GRAY, tpl(tx["st_dns_stats"], q=str(dns["queries"]), c=str(dns.get("cached") or 0)))]
    rows.append(("compass", "ps_dns", dval, dsub))
    up = d.get("uptime")
    if up is None:
        upv = sval(a("—"))
    elif up >= 86400:
        upv = sval(tpl(tx["up_dh"], d=str(up // 86400), h=str(up % 86400 // 3600)))
    else:
        upv = sval(tpl(tx["up_hm"], h=str(up // 3600), m=str(up % 3600 // 60)))
    rows.append(("clock", "ps_uptime", upv, None))
    mem = d.get("memory")
    ram = sval(tpl(tx["pc_of"], n=_size(tx, mem[0]), total=_size(tx, mem[1]))) if mem else sval(a("—"))
    rows.append(("ram", "ps_ram", ram, None))
    on = styled(tx["pc_of"], Seg("sval", GREEN_TEXT if d["online"] else GRAY, []), Seg("sof", GRAY, []), "n",
                n=str(d["online"]), total=str(d["total"]))
    rows.append(("online", "ps_online", on, None))
    rows.append(("traffic", "ps_month", sval(_size(tx, d["month"])), None))
    y = PAD_Y + HEAD
    for icon, key, value, s in rows:
        p.row(y, icon, lab(key), value, s, icon_size=40, icon_color=GREEN if icon == "online" else BLUE)
        y += ROW_H
    return p.cv.png()
