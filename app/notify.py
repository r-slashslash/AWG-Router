"""Уведомления в Telegram (включаются вручную в настройках панели).

Это единственное место, где бэкенд сам переводит тексты: сообщение уходит в Telegram,
а не в браузер, поэтому каталог на четырёх языках лежит здесь (TEXTS).
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
import urllib.error
import urllib.request

from .i18n import Msg

log = logging.getLogger("awgr.notify")

API = "https://api.telegram.org"
LANGS = ("ru", "en", "zh", "fa")
# категории событий, которые можно включать по отдельности
KINDS = ("exit", "server", "clients", "login", "tls", "update")

TEXTS = {
    "ru": {
        "test": "✅ Тестовое сообщение. Уведомления работают.",
        "exit_down": "⚠️ Выход «{name}» перестал работать. Клиенты, которые шли через него, переключены на резервный выход.",
        "exit_up": "✅ Выход «{name}» снова работает.",
        "exit_quota": "📦 Выход «{name}»: исчерпан лимит {gb} ГБ за месяц. Трафик переключён на резервный выход до начала следующего месяца.",
        "exit_quota_notify": "📦 Выход «{name}»: исчерпан лимит {gb} ГБ за месяц. Трафик продолжает идти через него.",
        "exit_quota_warn": "⚠️ Выход «{name}»: израсходовано 90% лимита {gb} ГБ за месяц.",
        "exit_quota_reset": "✅ Выход «{name}» снова используется: начался новый месяц.",
        "target_lost": "⚠️ Сервер AmneziaWG недоступен — проверьте контейнер или службу.",
        "target_back": "✅ Сервер AmneziaWG снова доступен.",
        "target_restarted": "ℹ️ Сервер AmneziaWG перезапустился, правила применены заново.",
        "server_start_failed": "⚠️ Сервер AmneziaWG не запускается.",
        "login_ok": "🔑 Вход в панель с адреса {ip}.",
        "login_blocked": "🚫 Много неверных попыток входа с адреса {ip}. Вход с него заблокирован на 10 минут.",
        "tls_fail": "⚠️ Не удаётся продлить сертификат HTTPS панели. Текущий действует до {date}.",
        "client_expired": "⏰ Клиент «{name}» отключён: истёк срок действия.",
        "client_quota": "📦 Клиент «{name}» отключён: исчерпан лимит трафика {gb} ГБ.",
        "client_quota_reset": "✅ Клиент «{name}» снова включён: начался новый месяц.",
        "update_available": "🆕 Доступна новая версия панели {version}. Обновить на сервере: awg-router update",
        "pw_changed": "🔑 Пароль панели изменён (с адреса {ip}).",
    },
    "en": {
        "test": "✅ Test message. Notifications are working.",
        "exit_down": "⚠️ Exit “{name}” stopped working. Clients that used it have been switched to the fallback exit.",
        "exit_up": "✅ Exit “{name}” is working again.",
        "exit_quota": "📦 Exit “{name}”: the monthly {gb} GB limit is used up. Traffic goes to the fallback exit until next month.",
        "exit_quota_notify": "📦 Exit “{name}”: the monthly {gb} GB limit is used up. Traffic still goes through it.",
        "exit_quota_warn": "⚠️ Exit “{name}”: 90% of the monthly {gb} GB limit is used.",
        "exit_quota_reset": "✅ Exit “{name}” is in use again: a new month has started.",
        "target_lost": "⚠️ The AmneziaWG server is unreachable — check the container or service.",
        "target_back": "✅ The AmneziaWG server is reachable again.",
        "target_restarted": "ℹ️ The AmneziaWG server restarted; rules were re-applied.",
        "server_start_failed": "⚠️ The AmneziaWG server fails to start.",
        "login_ok": "🔑 Panel sign-in from {ip}.",
        "login_blocked": "🚫 Too many failed sign-in attempts from {ip}. It is blocked for 10 minutes.",
        "tls_fail": "⚠️ The panel's HTTPS certificate can't be renewed. The current one is valid until {date}.",
        "client_expired": "⏰ Client “{name}” was turned off: its access period ended.",
        "client_quota": "📦 Client “{name}” was turned off: the {gb} GB traffic limit is used up.",
        "client_quota_reset": "✅ Client “{name}” is on again: a new month has started.",
        "update_available": "🆕 Panel version {version} is available. Update on the server: awg-router update",
        "pw_changed": "🔑 The panel password was changed (from {ip}).",
    },
    "zh": {
        "test": "✅ 测试消息。通知功能正常。",
        "exit_down": "⚠️ 出口“{name}”已停止工作。经由它的客户端已切换到备用出口。",
        "exit_up": "✅ 出口“{name}”已恢复工作。",
        "exit_quota": "📦 出口“{name}”：本月 {gb} GB 流量限额已用完。下个月之前流量改走备用出口。",
        "exit_quota_notify": "📦 出口“{name}”：本月 {gb} GB 流量限额已用完。流量仍经由它转发。",
        "exit_quota_warn": "⚠️ 出口“{name}”：本月 {gb} GB 限额已用掉 90%。",
        "exit_quota_reset": "✅ 出口“{name}”已重新启用：新的月份开始了。",
        "target_lost": "⚠️ 无法访问 AmneziaWG 服务器——请检查容器或服务。",
        "target_back": "✅ AmneziaWG 服务器已恢复访问。",
        "target_restarted": "ℹ️ AmneziaWG 服务器已重启，规则已重新应用。",
        "server_start_failed": "⚠️ AmneziaWG 服务器无法启动。",
        "login_ok": "🔑 来自 {ip} 的面板登录。",
        "login_blocked": "🚫 来自 {ip} 的错误登录尝试过多，已封锁 10 分钟。",
        "tls_fail": "⚠️ 无法续期面板的 HTTPS 证书。当前证书有效期至 {date}。",
        "client_expired": "⏰ 客户端“{name}”已停用：使用期限已到。",
        "client_quota": "📦 客户端“{name}”已停用：{gb} GB 流量限额已用完。",
        "client_quota_reset": "✅ 客户端“{name}”已重新启用：新的月份开始了。",
        "update_available": "🆕 面板新版本 {version} 可用。在服务器上更新：awg-router update",
        "pw_changed": "🔑 面板密码已更改（来自 {ip}）。",
    },
    "fa": {
        "test": "✅ پیام آزمایشی. اعلان‌ها کار می‌کنند.",
        "exit_down": "⚠️ خروجی «{name}» از کار افتاد. کلاینت‌هایی که از آن می‌رفتند به خروجی پشتیبان منتقل شدند.",
        "exit_up": "✅ خروجی «{name}» دوباره کار می‌کند.",
        "exit_quota": "📦 خروجی «{name}»: سقف ماهانهٔ {gb} گیگابایت تمام شد. تا ماه بعد ترافیک از خروجی پشتیبان می‌رود.",
        "exit_quota_notify": "📦 خروجی «{name}»: سقف ماهانهٔ {gb} گیگابایت تمام شد. ترافیک همچنان از آن می‌رود.",
        "exit_quota_warn": "⚠️ خروجی «{name}»: ۹۰٪ سقف ماهانهٔ {gb} گیگابایت مصرف شد.",
        "exit_quota_reset": "✅ خروجی «{name}» دوباره استفاده می‌شود: ماه تازه شروع شد.",
        "target_lost": "⚠️ سرور AmneziaWG در دسترس نیست — کانتینر یا سرویس را بررسی کنید.",
        "target_back": "✅ سرور AmneziaWG دوباره در دسترس است.",
        "target_restarted": "ℹ️ سرور AmneziaWG دوباره راه‌اندازی شد و قوانین دوباره اعمال شدند.",
        "server_start_failed": "⚠️ سرور AmneziaWG راه‌اندازی نمی‌شود.",
        "login_ok": "🔑 ورود به پنل از نشانی {ip}.",
        "login_blocked": "🚫 تلاش‌های ناموفق زیاد برای ورود از نشانی {ip}. ورود از آن ۱۰ دقیقه مسدود شد.",
        "tls_fail": "⚠️ تمدید گواهی HTTPS پنل ممکن نیست. گواهی فعلی تا {date} معتبر است.",
        "client_expired": "⏰ کلاینت «{name}» غیرفعال شد: مدت اعتبارش تمام شد.",
        "client_quota": "📦 کلاینت «{name}» غیرفعال شد: سقف ترافیک {gb} گیگابایت تمام شد.",
        "client_quota_reset": "✅ کلاینت «{name}» دوباره فعال شد: ماه تازه شروع شد.",
        "update_available": "🆕 نسخهٔ تازهٔ پنل {version} آماده است. به‌روزرسانی روی سرور: awg-router update",
        "pw_changed": "🔑 رمز پنل تغییر کرد (از نشانی {ip}).",
    },
}

# событие движка → (категория, текст)
ENGINE_EVENTS = {
    "ev.upstream_failed": ("exit", "exit_down"),
    "ev.upstream_ok": ("exit", "exit_up"),
    "ev.upstream_quota": ("exit", "exit_quota"),
    "ev.upstream_quota_notify": ("exit", "exit_quota_notify"),
    "ev.upstream_quota_warn": ("exit", "exit_quota_warn"),
    "ev.upstream_quota_reset": ("exit", "exit_quota_reset"),
    "ev.target_lost": ("server", "target_lost"),
    "ev.target_restarted": ("server", "target_restarted"),
    "ev.server_start_failed": ("server", "server_start_failed"),
    "ev.client_expired": ("clients", "client_expired"),
    "ev.client_quota": ("clients", "client_quota"),
    "ev.client_quota_reset": ("clients", "client_quota_reset"),
}


class NotifyError(Exception):
    pass


def defaults() -> dict:
    return {"enabled": False, "token": "", "chat_id": "", "lang": "en",
            "events": {k: True for k in KINDS}}


def cfg_of(st: dict) -> dict:
    c = defaults()
    c.update({k: v for k, v in (st.get("settings", {}).get("telegram") or {}).items() if k in c})
    c["events"] = {**defaults()["events"], **(c.get("events") or {})}
    return c


def public_view(c: dict) -> dict:
    """Настройки для браузера: токен целиком не отдаём."""
    tok = c.get("token") or ""
    return {**{k: v for k, v in c.items() if k != "token"},
            "token_set": bool(tok), "token_hint": (tok.split(":")[0] + ":…" + tok[-4:]) if tok else ""}


def render(lang: str, key: str, host: str = "", **params) -> str:
    tx = TEXTS.get(lang) or TEXTS["en"]
    body = tx.get(key) or TEXTS["en"][key]
    for k, v in params.items():
        body = body.replace("{" + k + "}", str(v))
    return (f"AWG Router · {host}\n" if host else "AWG Router\n") + body


def _call(token: str, method: str, payload: dict | None = None, timeout: float = 15) -> dict:
    url = f"{API}/bot{token}/{method}"
    data = json.dumps(payload or {}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res = json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            res = json.loads(e.read().decode() or "{}")
        except ValueError:
            raise NotifyError(f"HTTP {e.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        reason = getattr(e, "reason", e)
        raise NotifyError(f"api.telegram.org: {reason}"[:300]) from None
    if not res.get("ok"):
        raise NotifyError(str(res.get("description") or "Telegram error")[:300])
    return res.get("result") or {}


def send(token: str, chat_id: str, text: str) -> None:
    _call(token, "sendMessage", {"chat_id": chat_id, "text": text,
                                 "disable_web_page_preview": True})


def detect_chat(token: str) -> dict | None:
    """Чат, из которого боту писали последним (чтобы не искать chat id вручную)."""
    upd = _call(token, "getUpdates", {"limit": 50, "timeout": 0})
    for u in reversed(upd if isinstance(upd, list) else []):
        m = u.get("message") or u.get("channel_post") or u.get("my_chat_member") or {}
        ch = m.get("chat")
        if ch and "id" in ch:
            title = ch.get("title") or " ".join(x for x in (ch.get("first_name"), ch.get("last_name")) if x) \
                or ch.get("username") or ""
            return {"id": str(ch["id"]), "title": title}
    return None


class Notifier:
    """Очередь отправки: события ставятся мгновенно, сеть — в отдельном потоке."""

    COOLDOWN = 300          # одинаковые сообщения — не чаще раза в 5 минут

    def __init__(self, store, host_fn):
        self.store = store
        self.host_fn = host_fn
        self.q: queue.Queue = queue.Queue(maxsize=100)
        self._sent: dict[str, float] = {}
        self.last_error: str | None = None
        self._target_lost = False
        threading.Thread(target=self._worker, name="notify", daemon=True).start()

    def event(self, kind: str, key: str, cooldown: float | None = None, **params) -> None:
        st = self.store.snapshot()
        c = cfg_of(st)
        if not (c["enabled"] and c["token"] and c["chat_id"] and c["events"].get(kind)):
            return
        sig = key + json.dumps(params, sort_keys=True, default=str)
        now = time.time()
        if now - self._sent.get(sig, 0) < (self.COOLDOWN if cooldown is None else cooldown):
            return
        self._sent[sig] = now
        try:
            host = self.host_fn(st)
        except Exception:  # noqa: BLE001
            host = ""
        try:
            self.q.put_nowait((c["token"], c["chat_id"], render(c["lang"], key, host, **params)))
        except queue.Full:
            log.warning("notify queue is full, message dropped")

    def engine_event(self, msg: Msg) -> None:
        """Событие движка (ev.*) → уведомление, если оно из нужных."""
        if msg.key == "ev.target_lost":
            if self._target_lost:
                return
            self._target_lost = True
        m = ENGINE_EVENTS.get(msg.key)
        if m:
            self.event(m[0], m[1], **{k: v for k, v in msg.p.items() if k in ("name", "gb")})

    def target_ok(self) -> None:
        if self._target_lost:
            self._target_lost = False
            self.event("server", "target_back")

    def _worker(self) -> None:
        while True:
            token, chat, text = self.q.get()
            for attempt in range(3):
                try:
                    send(token, chat, text)
                    self.last_error = None
                    break
                except NotifyError as e:
                    self.last_error = str(e)
                    log.warning("telegram: %s", e)
                    time.sleep(5 * (attempt + 1))
