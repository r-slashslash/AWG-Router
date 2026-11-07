"""Скриншоты README (docs/screenshots) из демо-панели одной командой.

    pip install playwright pillow && python3 -m playwright install chromium
    python3 tools/screenshots/make.py            # снимки в docs/screenshots
    python3 tools/screenshots/make.py --out DIR  # в другую папку (посмотреть, не трогая репозиторий)

Что делает:
1. запускает панель в демо-режиме (DRY_RUN) с пустой папкой данных; списки стран не скачиваются,
   а собираются синтетически — так снимки не зависят от интернета и всегда одинаковые;
2. через API панели собирает набор: выходы Netherlands, Germany (в демо второй туннель «мёртвый»)
   и USA proxy (SOCKS5 со своими сайтами), три общих правила, клиенты с ручными выходами,
   своими правилами, заметкой, сроком и лимитами, плюс клиент My phone;
3. останавливает панель и записывает traffic.json с правдоподобными итогами клиентов, выходов
   и сервера, снова запускает панель;
4. снимает вкладки в Chromium: английский, светлая тема, 1280×860 ×1.25 и телефон 390×844 ×3,
   без демо-баннера и «(demo)», 256 цветов (правила снимков — в CLAUDE.md).

Нужны Playwright и Pillow — только для этого скрипта, панели они не нужны.
"""
from __future__ import annotations

import argparse
import base64
import http.cookiejar
import io
import ipaddress
import json
import os
import random
import re
import runpy
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PASSWORD = "demo-password"
BASE_PATH = "/p"
GB = 1024 ** 3
COUNTRIES = {"ru": 11840, "cn": 8960, "ir": 1720}    # число сетей в синтетических списках стран


# ------------------------------------------------------------------ панель
def run_panel() -> None:
    """Режим --panel: панель с синтетическими списками стран вместо скачивания."""
    sys.path.insert(0, ROOT)
    from app import lists

    def fake_fetch(url: str, timeout: int = 30) -> str:
        cc = next((c for c in COUNTRIES if f"/{c}/" in url or f"/{c}-" in url or f"/{c}." in url), None)
        if not cc:
            raise OSError("offline (screenshots)")
        rnd = random.Random(cc)
        nets: set[str] = set()
        while len(nets) < COUNTRIES[cc]:
            pref = rnd.choice([24, 24, 24, 23, 22, 21, 20])
            n = ipaddress.IPv4Network((rnd.randrange(16777216, 3758096384) >> (32 - pref) << (32 - pref), pref))
            if n.is_global:
                nets.add(str(n))
        return "\n".join(sorted(nets))

    lists._fetch = fake_fetch
    sys.argv = ["awg-router"]
    runpy.run_module("app.main", run_name="__main__")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Panel:
    def __init__(self, data_dir: str, port: int):
        self.data_dir, self.port = data_dir, port
        self.url = f"http://127.0.0.1:{port}{BASE_PATH}"
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        env = {**os.environ, "DRY_RUN": "1", "DATA_DIR": self.data_dir, "PANEL_PORT": str(self.port),
               "PANEL_HOST": "127.0.0.1", "PANEL_PASSWORD": PASSWORD, "TLS_MODE": "off",
               "PANEL_BASE_PATH": BASE_PATH, "PUBLIC_HOST": "203.0.113.5", "TZ": "UTC"}
        log = open(os.path.join(self.data_dir, "panel.log"), "a")
        self.proc = subprocess.Popen([sys.executable, os.path.abspath(__file__), "--panel"], env=env,
                                     stdout=log, stderr=subprocess.STDOUT)
        for _ in range(60):
            try:
                urllib.request.urlopen(self.url + "/", timeout=2)
                return
            except (urllib.error.URLError, OSError):
                time.sleep(0.5)
        raise SystemExit("panel did not start: " + os.path.join(self.data_dir, "panel.log"))

    def stop(self) -> None:
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=20)
            self.proc = None


# ------------------------------------------------------------------ набор
class Api:
    def __init__(self, url: str):
        self.url = url
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def __call__(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self.url}/api/{path}", data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with self.op.open(req, timeout=60) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise SystemExit(f"{method} {path}: {e.code} {e.read()[:300]!r}")


def build(api: Api) -> dict:
    """Выходы, правила, клиенты и лимиты через API. → ключи клиентов и id выходов."""
    api("POST", "login", {"password": PASSWORD})
    api("POST", "users", {"name": "My phone"})
    for _ in range(40):
        st = api("GET", "state")
        if any(c["name"] == "My phone" for c in st["clients"]):
            break
        time.sleep(0.5)
    pk = {c["name"]: c["public_key"] for c in st["clients"]}
    q = lambda name: urllib.parse.quote(pk[name], safe="")
    # конфиг выхода AWG 3 — конфиг демо-клиента со своим ключом сервера, адресом и сервером
    base = api("GET", f"users/{q('My phone')}/config")["conf"]

    def awg(addr: str, endpoint: str) -> str:
        c = re.sub(r"(?m)^PublicKey\s*=.*$", "PublicKey = " + base64.b64encode(os.urandom(32)).decode(), base)
        c = re.sub(r"(?m)^Address\s*=.*$", f"Address = {addr}", c)
        return re.sub(r"(?m)^Endpoint\s*=.*$", f"Endpoint = {endpoint}", c)

    nl = api("POST", "upstreams", {"name": "Netherlands", "config": awg("10.9.0.2/32", "203.0.113.10:47823"),
                                   "fallback": "direct", "quota_gb": 1000, "quota_action": "direct",
                                   "rate_down": 500, "rate_up": 100})["id"]
    de = api("POST", "upstreams", {"name": "Germany", "config": awg("10.7.0.5/32", "198.51.100.44:47823"),
                                   "fallback": "block", "quota_gb": 300, "quota_action": "notify"})["id"]
    us = api("POST", "upstreams", {"name": "USA proxy", "config": "socks5://alice:wonderland@192.0.2.80:1080",
                                   "fallback": "up:" + nl, "rate_down": 100,
                                   "routing": {"domains": "chatgpt.com\nopenai.com\nclaude.ai\nnetflix.com",
                                               "default": False}})["id"]
    office = api("POST", "lists", {"kind": "manual", "name": "Office",
                                   "source": "10.20.0.0/16\n192.168.50.0/24"})["id"]
    own = next(l["id"] for l in api("GET", "state")["lists"] if l["kind"] == "domains")
    # балансировка вместо одного выхода по умолчанию; «напрямую» — если все её выходы лежат
    api("PUT", "routing", {"default": "direct", "balance": {"on": True, "skip": []}, "rules": [
        {"lists": [own], "outbound": "up:" + us, "comment": "USA proxy"},
        {"lists": ["ru", "cn", "ir"], "outbound": "direct", "comment": "Local sites"},
        {"lists": [office], "outbound": "direct", "comment": "Office"}]})
    api("PUT", f"clients/{q('Dad')}", {"outbound": "up:" + de})
    api("PUT", f"clients/{q('Office router')}", {"outbound": "direct", "note": "office"})
    api("PUT", f"clients/{q('Living room TV')}", {"outbound": "up:" + de, "rules_mode": "custom",
                                                  "rules": [{"lists": ["ru"], "outbound": "direct"}]})
    api("PUT", f"limits/{q('Guest')}", {"expires": int(time.time()) + 86400 + 3600, "quota_gb": 20,
                                        "period": "month", "rate_down": 10, "rate_up": 5})
    api("PUT", "settings", {"shaping": {"down": 900, "up": 200}})
    api("PUT", f"limits/{q('Anna MacBook')}", {"quota_gb": 150, "period": "month"})
    return {"pk": pk, "nl": nl, "de": de, "us": us}


def write_traffic(data_dir: str, ids: dict) -> None:
    """traffic.json (панель остановлена): итоги клиентов, выходов и сервера."""
    mk = time.strftime("%Y-%m", time.gmtime())
    prev = time.strftime("%Y-%m", time.gmtime(time.time() - 40 * 86400))
    pair = lambda down, up: [int(up * GB), int(down * GB)]      # [от клиента, к клиенту]
    # клиент: (за месяц ГБ, всего ГБ); 89% — загрузка. Guest — ниже лимита, но больше 90%
    clients = {"Anna iPhone": (123, 1180), "Anna MacBook": (87.3, 912), "Dad": (47.6, 433),
               "Office router": (71.5, 1290), "Living room TV": (43.7, 388), "Guest": (18.6, 18.6),
               "My phone": (4, 4)}
    out = {"_v": 2, "clients": {}, "outs": {}}
    for name, (m, t) in clients.items():
        old = (t - m) / 2
        out["clients"][ids["pk"][name]] = {"total": pair(t * .89, t * .11), "last": None,
                                           "months": {mk: pair(m * .89, m * .11), prev: pair(old * .89, old * .11)}}
    # выход: ((за месяц ↓, ↑), (всего ↓, ↑)) ГБ
    outs = {ids["nl"]: ((128.4, 14.5), (2355, 264.9)), ids["de"]: ((35.7, 4.0), (650.9, 73.6)),
            ids["us"]: ((21.4, 2.4), (390.5, 44.1)), "direct": ((171.2, 19.4), (1720, 196))}
    total, month = [0, 0], [0, 0]
    for k, ((md, mu), (td, tu)) in outs.items():
        out["outs"][k] = {"total": pair(td, tu), "months": {mk: pair(md, mu)}}
        total = [total[0] + int(tu * GB), total[1] + int(td * GB)]
        month = [month[0] + int(mu * GB), month[1] + int(md * GB)]
    out["server"] = {"total": total, "months": {mk: month}}
    with open(os.path.join(data_dir, "traffic.json"), "w") as f:
        json.dump(out, f)


# ------------------------------------------------------------------ снимки
CLEAN = """() => {
  document.querySelectorAll('.banner.info').forEach((b) => b.remove());
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let n; (n = w.nextNode());) if (n.nodeValue.includes(' (demo)')) n.nodeValue = n.nodeValue.replace(' (demo)', '');
}"""


def shoot(url: str, out_dir: str) -> None:
    from PIL import Image
    from playwright.sync_api import sync_playwright

    def save(pg, name: str) -> None:
        pg.evaluate(CLEAN)
        pg.wait_for_timeout(150)
        im = Image.open(io.BytesIO(pg.screenshot())).convert("RGB")
        im.quantize(256, method=Image.MEDIANCUT, dither=Image.NONE).save(os.path.join(out_dir, name + ".png"),
                                                                          optimize=True)
        print(f"  {name}.png {im.size[0]}×{im.size[1]}")

    def tab(pg, name: str) -> None:
        pg.click(f"#tabs [data-tab={name}]")
        pg.wait_for_timeout(900)
        pg.evaluate("window.scrollTo(0, 0)")

    with sync_playwright() as p:
        b = p.chromium.launch()

        def page(w: int, h: int, scale: float, mobile: bool):
            ctx = b.new_context(viewport={"width": w, "height": h}, device_scale_factor=scale, is_mobile=mobile,
                                has_touch=mobile, locale="en-US", color_scheme="light", timezone_id="UTC")
            pg = ctx.new_page()
            pg.goto(url + "/")
            pg.fill("#login-pass", PASSWORD)
            pg.click("#login-form button[type=submit]")
            pg.wait_for_selector("#brand-traffic b", timeout=15000)
            pg.wait_for_timeout(2500)
            return pg

        pg = page(1280, 860, 1.25, False)
        save(pg, "overview")
        for name in ("clients", "exits", "routing", "server"):
            tab(pg, name)
            save(pg, name)
        tab(pg, "clients")
        pg.click("tr[data-pk]:has-text('My phone')")
        pg.wait_for_selector("#modal[open] .connect", timeout=10000)
        pg.wait_for_timeout(800)
        save(pg, "client-connect")
        pg.context.close()

        pg = page(390, 844, 3, True)
        save(pg, "mobile")
        b.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="README screenshots from a demo panel")
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "screenshots"))
    ap.add_argument("--panel", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.panel:
        run_panel()
        return
    os.makedirs(a.out, exist_ok=True)
    data_dir = tempfile.mkdtemp(prefix="awgr-shots-")
    panel = Panel(data_dir, free_port())
    try:
        print("demo panel:", data_dir)
        panel.start()
        ids = build(Api(panel.url))
        time.sleep(3)                    # пусть движок применит набор и сохранит состояние
        panel.stop()
        write_traffic(data_dir, ids)
        panel.start()
        time.sleep(15)                   # проверки выходов, рукопожатия, предупреждение о лимите Guest
        print("screenshots →", a.out)
        shoot(panel.url, a.out)
    finally:
        panel.stop()


if __name__ == "__main__":
    main()
