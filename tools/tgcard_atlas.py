"""Атлас надписей для картинок бота (app/tgcard.atlas): запускать после правки текстов картинок в app/tgbot.py.

    python3 tools/tgcard_atlas.py

Нужны Chrome (/usr/bin/google-chrome), Playwright для Python и шрифт Noto Sans CJK SC в системе (китайский);
Golos Text и Vazirmatn берутся из app/static/fonts. Chrome рисует каждое слово на холсте (персидское — справа налево,
со связанными буквами), отсюда берётся прозрачность точек, обрезается по краю букв и пишется в атлас. Сама панель
шрифтов не читает: у неё только маски (app/tgcard.py).
"""
from __future__ import annotations

import base64
import json
import os
import struct
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import tgbot, tgcard  # noqa: E402

CHROME = "/usr/bin/google-chrome"
FONTS = os.path.join(ROOT, "app", "static", "fonts")
# семейство шрифтов по языку; знаки ASCII и логотип — «*» (Golos Text для всех языков)
FAMILY = {"*": "AWGGolos", "ru": "AWGGolos", "en": "AWGGolos", "zh": "AWGGolos, 'Noto Sans CJK SC'",
          "fa": "AWGVazir, AWGGolos"}

PAGE = """<!doctype html><html><body><canvas id="c"></canvas><script>
const cv = document.getElementById("c");
const ctx = cv.getContext("2d", {willReadFrequently: true});
function crop(w, h, alphaOf) {
  let top = h, bottom = -1, left = w, right = -1;
  const a = new Uint8Array(w * h);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const v = alphaOf(x, y); a[y * w + x] = v;
    if (v) { if (y < top) top = y; if (y > bottom) bottom = y; if (x < left) left = x; if (x > right) right = x; }
  }
  if (bottom < 0) return {w: 0, h: 0, x: 0, y: 0, a: ""};
  const cw = right - left + 1, ch = bottom - top + 1, out = new Uint8Array(cw * ch);
  for (let y = 0; y < ch; y++) out.set(a.subarray((top + y) * w + left, (top + y) * w + left + cw), y * cw);
  let s = ""; for (let i = 0; i < out.length; i++) s += String.fromCharCode(out[i]);
  return {w: cw, h: ch, x: left, y: top, a: btoa(s)};
}
window.text = (t, font, size, rtl) => {
  ctx.font = font; const adv = ctx.measureText(t).width;
  const pad = Math.ceil(size * 0.6), base = Math.ceil(size * 1.6);
  cv.width = Math.ceil(adv) + 2 * pad; cv.height = Math.ceil(size * 2.4);
  ctx.font = font; ctx.direction = rtl ? "rtl" : "ltr"; ctx.textAlign = "left"; ctx.textBaseline = "alphabetic";
  ctx.clearRect(0, 0, cv.width, cv.height); ctx.fillStyle = "#fff"; ctx.fillText(t, pad, base);
  const d = ctx.getImageData(0, 0, cv.width, cv.height).data;
  const r = crop(cv.width, cv.height, (x, y) => d[(y * cv.width + x) * 4 + 3]);
  return {...r, x: r.x - pad, y: r.y - base, adv: adv};
};
window.svg = async (body, vb, w, h, rgb) => {
  const paint = rgb ? '' : ' fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
  const src = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="' + vb + '" width="' + w + '" height="' + h + '"' +
    paint + '>' + body + '</svg>';
  const img = new Image(); img.src = "data:image/svg+xml;base64," + btoa(src); await img.decode();
  cv.width = w; cv.height = h;
  ctx.clearRect(0, 0, w, h);
  if (rgb) { ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, w, h); }
  ctx.drawImage(img, 0, 0, w, h);
  const d = ctx.getImageData(0, 0, w, h).data;
  if (rgb) {
    let s = ""; for (let i = 0; i < w * h; i++) s += String.fromCharCode(d[i * 4], d[i * 4 + 1], d[i * 4 + 2]);
    return {w: w, h: h, x: 0, y: 0, a: btoa(s), adv: w};
  }
  return {...crop(w, h, (x, y) => d[(y * w + x) * 4 + 3]), adv: w};
};
window.fonts = async (list) => {
  for (const [name, url, weight] of list) {
    const f = new FontFace(name, "url(" + url + ")", {weight: weight}); await f.load(); document.fonts.add(f);
  }
  return true;
};
</script></body></html>"""


def font_url(name: str, mime: str) -> str:
    with open(os.path.join(FONTS, name), "rb") as f:
        return f"data:{mime};base64," + base64.b64encode(f.read()).decode()


def main() -> int:
    from playwright.sync_api import sync_playwright

    need = tgcard.needed(tgbot.TEXTS)
    items: dict[str, list] = {}
    blob = bytearray()
    with sync_playwright() as pw:
        br = pw.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
        pg = br.new_page()
        pg.set_content(PAGE)
        pg.evaluate("l => fonts(l)", [["AWGGolos", font_url("GolosText.woff", "font/woff"), "400 900"],
                                      ["AWGVazir", font_url("Vazirmatn.woff2", "font/woff2"), "100 900"]])
        pg.evaluate("() => document.fonts.load('500 40px \"Noto Sans CJK SC\"', '中')")
        for key, spec in sorted(need.items()):
            kind = spec[0]
            if kind in ("p", "g"):
                _, style, lang, text = spec
                size, weight = tgcard.STYLES[style]
                font = f"{weight} {size}px {FAMILY[lang or '*']}"
                r = pg.evaluate("a => text(...a)", [text, font, size, lang == "fa"])
            elif kind == "i":
                _, name, size = spec
                r = pg.evaluate("a => svg(...a)", [tgcard.ICONS[name], "0 0 24 24", size, size, False])
            elif kind == "l":
                _, _, w, h = spec
                r = pg.evaluate("a => svg(...a)", [tgcard.LOGO_SVG, "0 0 216 88", w, h, True])
            else:
                _, size = spec
                r = pg.evaluate("a => svg(...a)", ['<circle cx="12" cy="12" r="12" fill="#fff" stroke="none"/>',
                                                   "0 0 24 24", size, size, False])
            data = base64.b64decode(r["a"]) if r["a"] else b""
            packed = zlib.compress(data, 9) if data else b""
            items[key] = [len(blob), len(packed), r["w"], r["h"], r["x"], r["y"], round(r["adv"], 2)]
            blob += packed
        br.close()
    head = json.dumps({"v": 1, "spec": tgcard.spec_sum(tgbot.TEXTS), "items": items},
                      ensure_ascii=False, separators=(",", ":")).encode()
    with open(tgcard.ATLAS + ".tmp", "wb") as f:
        f.write(tgcard.MAGIC + struct.pack(">I", len(head)) + head + bytes(blob))
    os.replace(tgcard.ATLAS + ".tmp", tgcard.ATLAS)
    print(f"{tgcard.ATLAS}: {len(items)} items, {os.path.getsize(tgcard.ATLAS) // 1024} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
