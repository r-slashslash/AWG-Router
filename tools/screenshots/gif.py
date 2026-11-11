"""GIF установки для README (docs/screenshots/install.gif): установщик в терминале, затем демо-панель.

    python3 tools/screenshots/gif.py            # docs/screenshots/install.gif
    python3 tools/screenshots/gif.py --out DIR  # в другую папку

Терминал — настоящий вывод install.sh с сервера владельца (Ubuntu 24.04, контейнер AmneziaVPN), только
адрес, секретный путь, пароль и имя машины заменены выдуманными. Вывод «проигрывается» строками, с
паузами примерно там, где их делает установщик. Поменялся вывод install.sh — поменяй INSTALL ниже.

Панель — та же демо-панель и тот же набор, что у скриншотов (make.py): вход, «Обзор», клиенты,
новый клиент с QR-кодом, выходы, маршрутизация. Кадры снимаются по одному (не видеозапись), у каждого
своя длительность; палитра общая на все кадры, поэтому цвета не прыгают.
Нужны Playwright и Pillow, как для make.py.
"""
from __future__ import annotations

import argparse
import base64
import html
import io
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import make  # noqa: E402

W, H, BAR = 1100, 700, 38                 # кадр, полоса «окна» сверху
HOST, PORT, SECRET = "203.0.113.5", 8900, "5f2a9c01e7b4"
PASSWORD = "Q7mVx2LpR9tKw4Ns"
URL = f"https://{HOST}:{PORT}/{SECRET}/"
PROMPT = "root@server:~# "
COMMAND = "curl -fsSL https://raw.githubusercontent.com/r-slashslash/AWG-Router/main/install.sh | bash"
FONT = os.path.join(make.ROOT, "app", "static", "fonts", "JetBrainsMono.woff2")

# (строка, пауза после неё в мс). Разметка: [b]жирный[/], [g]зелёный[/], [c]голубой жирный[/]
INSTALL = [
    ("Downloading AWG Router from github.com/r-slashslash/AWG-Router into /opt/awg-router …", 900),
    ("", 0), ("[b]▸ Checking the system[/]", 400),
    ("  [g]✓[/] Ubuntu 24.04.4 LTS", 250),
    ("  [g]✓[/] Kernel module ifb (speed limits)", 250),
    ("  [g]✓[/] Amnezia container: amnezia-awg2", 500),
    ("", 0), ("[b]▸ Preparing settings[/]", 400),
    (f"  [g]✓[/] Public address: {HOST}", 250),
    (f"  [g]✓[/] Panel port: {PORT}", 500),
    ("", 0), ("[b]▸ Docker[/]", 400),
    ("  [g]✓[/] Docker 29.1.3, Compose 5.7.0, buildx 0.38.2", 600),
    ("", 0), ("[b]▸ Downloading the panel[/]", 1300),
    ("  [g]✓[/] Done", 500),
    ("", 0), ("[b]▸ Starting[/]", 300),
    ("  Waiting for start-up and the certificate (up to 5 minutes)…", 2200),
    ("", 0), ("[g]" + "═" * 56 + "[/]", 0),
    ("[b]  AWG Router is ready[/]", 0),
    ("[g]" + "═" * 56 + "[/]", 0),
    (f"  Link:     [c]{URL}[/]", 0),
    (f"  Password: [b]{PASSWORD}[/]", 0),
    ("  Let's Encrypt certificate valid until 2026-11-16 11:03, renews automatically", 0),
    ("  Show this again: awg-router info", 0),
    ("", 0), (PROMPT, 4000),
]

TERM_PAGE = """<!doctype html><meta charset="utf-8"><style>
@font-face { font-family: jb; src: url("data:font/woff2;base64,%(font)s"); font-weight: 100 900; }
html, body { margin: 0; background: #0d1117; }
#t { box-sizing: border-box; width: %(w)dpx; height: %(h)dpx; padding: 18px 22px; overflow: hidden;
     font: 15px/1.38 jb, monospace; color: #e6edf3; white-space: pre-wrap; word-break: break-all; }
b { color: #fff; } .g { color: #3fb950; } .c { color: #39c5cf; font-weight: bold; }
.cur { background: #e6edf3; color: #0d1117; }
</style><div id="t"></div>"""


def line_html(s: str) -> str:
    # [b]…[/] закрывается </b>, остальные — </span>
    out, stack, i = [], [], 0
    s = html.escape(s)
    while i < len(s):
        for tag, open_, close in (("[b]", "<b>", "</b>"), ("[g]", '<span class="g">', "</span>"),
                                  ("[c]", '<span class="c">', "</span>")):
            if s.startswith(tag, i):
                out.append(open_); stack.append(close); i += len(tag); break
        else:
            if s.startswith("[/]", i):
                out.append(stack.pop()); i += 3
            else:
                out.append(s[i]); i += 1
    return "".join(out)


class Frames:
    def __init__(self):
        from PIL import Image, ImageDraw, ImageFont
        self.Image, self.Draw = Image, ImageDraw
        self.font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)
        self.items: list[tuple[object, int]] = []

    def window(self, shot: bytes, title: str, dark: bool):
        """Кадр с полосой окна: у терминала — заголовок, у браузера — адресная строка."""
        Image, Draw = self.Image, self.Draw
        im = Image.new("RGB", (W, H), "#1f2328" if dark else "#e9ebee")
        im.paste(Image.open(io.BytesIO(shot)).convert("RGB"), (0, BAR))
        d = Draw.Draw(im)
        for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
            d.ellipse((16 + i * 20, 13, 28 + i * 20, 25), fill=c)
        if dark:
            d.text((W // 2, BAR // 2), title, fill="#9198a1", font=self.font, anchor="mm")
        else:
            d.rounded_rectangle((90, 7, W - 90, BAR - 7), 8, fill="#ffffff", outline="#d0d7de")
            d.text((106, BAR // 2), title, fill="#1f2328", font=self.font, anchor="lm")
        return im

    def add(self, im, ms: int) -> None:
        self.items.append((im, ms))

    def save(self, path: str) -> None:
        Image = self.Image
        # общая палитра из нескольких разных кадров
        picks = [self.items[i][0] for i in range(0, len(self.items), max(1, len(self.items) // 12))]
        sheet = Image.new("RGB", (W, H * len(picks)))
        for i, im in enumerate(picks):
            sheet.paste(im, (0, H * i))
        pal = sheet.quantize(255, method=Image.MEDIANCUT, dither=Image.NONE)
        frames = [im.quantize(palette=pal, dither=Image.NONE) for im, _ in self.items]
        frames[0].save(path, save_all=True, append_images=frames[1:], loop=0, optimize=False,
                       duration=[ms for _, ms in self.items], disposal=1)
        print(f"  {path}: {len(frames)} frames, {sum(ms for _, ms in self.items) / 1000:.1f} s, "
              f"{os.path.getsize(path) / 1e6:.2f} MB")


def terminal(b, fr: Frames) -> None:
    pg = b.new_page(viewport={"width": W, "height": H - BAR})
    pg.set_content(TERM_PAGE % {"font": base64.b64encode(open(FONT, "rb").read()).decode(), "w": W, "h": H - BAR})
    pg.evaluate("document.fonts.ready")
    pg.wait_for_timeout(300)
    title = "root@server: ~"

    def show(lines: list[str], ms: int) -> None:
        pg.evaluate("h => { const t = document.getElementById('t'); t.innerHTML = h; t.scrollTop = t.scrollHeight; }",
                    "\n".join(lines))
        fr.add(fr.window(pg.screenshot(), title, True), ms)

    cur = '<span class="cur"> </span>'
    show([html.escape(PROMPT) + cur], 700)
    for n in range(4, len(COMMAND) + 4, 4):        # набор команды
        show([html.escape(PROMPT + COMMAND[:n]) + cur], 45)
    show([html.escape(PROMPT + COMMAND) + cur], 600)
    done = [html.escape(PROMPT + COMMAND)]
    for text, ms in INSTALL:
        done.append(line_html(text))
        if ms or text == PROMPT:
            show(done[:-1] + [done[-1] + (cur if text == PROMPT else "")], ms)
    pg.close()


def panel(b, url: str, fr: Frames) -> None:
    ctx = b.new_context(viewport={"width": W, "height": H - BAR}, locale="en-US", color_scheme="light",
                        timezone_id="UTC")
    pg = ctx.new_page()

    def snap(ms: int) -> None:
        pg.evaluate(make.CLEAN)
        fr.add(fr.window(pg.screenshot(), URL, False), ms)

    def tab(name: str, ms: int) -> None:
        pg.click(f"#tabs [data-tab={name}]")
        pg.wait_for_timeout(900)
        snap(ms)

    pg.goto(url + "/")
    pg.wait_for_selector("#login-pass")
    pg.wait_for_timeout(500)
    snap(900)
    for n in range(2, len(PASSWORD) + 1, 2):        # ввод пароля
        pg.fill("#login-pass", PASSWORD[:n])
        snap(60)
    snap(400)
    pg.click("#login-form button[type=submit]")
    pg.wait_for_selector("#brand-traffic b", timeout=15000)
    pg.wait_for_timeout(2000)
    snap(3200)
    tab("clients", 2200)
    pg.click("#add-client")
    pg.wait_for_selector("#n-name")
    pg.wait_for_timeout(400)
    snap(500)
    name = "Laptop"
    for n in range(1, len(name) + 1):
        pg.fill("#n-name", name[:n])
        snap(110)
    snap(500)
    pg.press("#n-name", "Enter")
    pg.wait_for_selector("#modal[open] .connect img.qr[src]", timeout=15000)
    pg.wait_for_timeout(1200)
    snap(3500)
    pg.keyboard.press("Escape")
    pg.wait_for_timeout(600)
    snap(1500)
    tab("exits", 2800)
    tab("routing", 3500)
    ctx.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="README install GIF")
    ap.add_argument("--out", default=os.path.join(make.ROOT, "docs", "screenshots"))
    a = ap.parse_args()
    from playwright.sync_api import sync_playwright

    make.PASSWORD, make.BASE_PATH = PASSWORD, "/" + SECRET
    os.makedirs(a.out, exist_ok=True)
    data_dir = tempfile.mkdtemp(prefix="awgr-gif-")
    pnl = make.Panel(data_dir, make.free_port())
    fr = Frames()
    try:
        print("demo panel:", data_dir)
        pnl.start()
        ids = make.build(make.Api(pnl.url))
        time.sleep(3)
        pnl.stop()
        make.write_traffic(data_dir, ids)
        pnl.start()
        time.sleep(15)
        with sync_playwright() as p:
            b = p.chromium.launch()
            terminal(b, fr)
            panel(b, pnl.url, fr)
            b.close()
        fr.save(os.path.join(a.out, "install.gif"))
    finally:
        pnl.stop()


if __name__ == "__main__":
    main()
