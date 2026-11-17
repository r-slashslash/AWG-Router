"""Общие части панели: состояние (store), движок (engine), HTTPS (tls), уведомления (notifier), проверка
обновлений (updates) и веб-приложение (app), к которому модули app/api добавляют свои адреса."""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import time

from . import config, lists, notify, proxy_manager, tgbot
from .engine import Engine
from .i18n import MsgError, to_json
from .store import Store
from .tlsmgr import TLSManager
from .updates import UpdateChecker
from .users import UserError
from .web import App
from .checks import bad

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("awgr")

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
BASE = config.PANEL_BASE_PATH

# -------------------------------------------------------------------- приложение
store = Store()
engine = Engine(store)


def _tls_alt() -> list[str]:
    """Второй адрес сервера для сертификата панели, если IPv6 в ходу: у IPv6 во «Внешнем адресе» — внешний
    IPv4, у IPv4 — IPv6, выбранный в «Адрес в конфигах». Иначе [] — сертификат на один адрес, как раньше:
    лишняя проверка Let's Encrypt по IPv6, до которого порт 80 закрыт, только тратила бы попытки."""
    # без копии всего состояния (store.peek): на тысяче клиентов копия — десятки миллисекунд на каждый вопрос
    host, ch = store.peek(lambda s: (engine.srv.public_host(s), s["settings"].get("client_host") or ""))
    try:
        a = ipaddress.ip_address(host)
    except ValueError:
        return []                      # домен — сертификат на него
    if a.version == 6:
        v4 = config.PUBLIC_HOST if re.fullmatch(r"[0-9.]+", config.PUBLIC_HOST or "") else engine.public_v4
        return [v4] if v4 else []
    return [ch] if ":" in ch else []


tls = TLSManager(lambda: store.peek(engine.srv.public_host), _tls_alt)
proxies = proxy_manager.Manager(store, engine, tls)
notifier = notify.Notifier(store, lambda st: tls.host() if tls.enabled else engine.srv.public_host(st))
notifier.buttons_fn = tgbot.notify_buttons
engine.notifier = notifier


def _tg_route(via: str):
    """Путь к api.telegram.org: напрямую или через туннель выбранного выхода."""
    try:
        return engine.own_route(via)
    except MsgError as e:
        raise notify.NotifyError(str(e.msg), e.msg, net=True) from None


notify.router = _tg_route
notify.alt_routes = engine.alt_routes


def _fetch_via_exit(url: str) -> tuple[str, bool]:
    """Список, который не скачался напрямую, — через рабочие выходы по очереди (как Telegram): на серверах
    в КНР и Иране raw.githubusercontent.com часто закрыт. Имя сайта разбирается через тот же выход."""
    errors = []
    for via in engine.alt_routes("direct")[:2]:        # не больше двух: каждая попытка — до полуминуты
        try:
            route = engine.own_route(via)
        except Exception as e:  # noqa: BLE001  — выход только что перестал работать
            errors.append(str(getattr(e, "msg", e))[:80])
            continue
        if route is None:
            continue
        try:
            code, text, framed = notify.get_via(route, url, 30, lists.FETCH_MAX)
        except OSError as e:
            errors.append(str(e)[:120])
            continue
        if code == 200:
            return text, framed
        errors.append(f"HTTP {code}")
    raise OSError("; ".join(errors) or "no working exit")


lists.alt_fetch = None if config.DRY_RUN else _fetch_via_exit
tls.on_fail = lambda exp: notifier.event(
    "tls", "tls_fail", cooldown=12 * 3600,
    date=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(exp or 0)))
updates = UpdateChecker(lambda v: notifier.event("update", "update_available", cooldown=86400, version=v))
app = App(BASE)
app.static = (BASE + "/static", STATIC)
app.public_static = ("/s/assets", STATIC)   # для личных страниц клиентов (без секретного пути)
app.public_files = {"share.js", "i18n.js", "qrcode.js", "app.css", "fonts/GolosText.woff",
                    "fonts/JetBrainsMono.woff2", "fonts/Vazirmatn.woff2"}
app.index_file = os.path.join(STATIC, "index.html")


# ------------------------------------------------------------- адрес панели
def panel_origin() -> str:
    u = panel_url()
    return u[: len(u) - len(BASE) - 1] if BASE else u.rstrip("/")


def share_url(token: str) -> str:
    return f"{panel_origin()}/s/{token}"


def user_errors(fn):
    """Ошибка движка или сервера AWG (UserError, MsgError) — ответ 400 с её текстом."""
    try:
        return fn()
    except (UserError, MsgError) as e:
        bad(e.msg)


def panel_url() -> str:
    if config.PANEL_HOST.startswith("127."):
        host = "127.0.0.1"
    else:
        host = tls.host() if tls.enabled else (store.peek(engine.srv.public_host) or "SERVER_IP")
    if ":" in host:
        host = f"[{host}]"
    scheme = "https" if tls.context() else "http"
    return f"{scheme}://{host}:{config.PANEL_PORT}{BASE}/"


def write_status() -> None:
    """data/status.json — для установщика и `awg-router info`: панель запущена, её адрес и HTTPS."""
    p = os.path.join(config.DATA_DIR, "status.json")
    with open(p + ".tmp", "w") as f:
        json.dump(to_json({"ready": True, "url": panel_url(), "tls": tls.status(),
                           "time": time.time()}), f)
    os.replace(p + ".tmp", p)
