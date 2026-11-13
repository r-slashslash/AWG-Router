"""Уведомления в Telegram (включаются вручную в настройках панели).

Это единственное место, где бэкенд сам переводит тексты: сообщение уходит в Telegram,
а не в браузер, поэтому каталог на четырёх языках лежит здесь (TEXTS).
"""
from __future__ import annotations

import collections
import email.utils
import json
import logging
import os
import queue
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

from .i18n import Msg

log = logging.getLogger("awgr.notify")

API = "https://api.telegram.org"
TGREQ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tgreq.py")
# Путь запросов: via ("direct" | "up:<id>") → None (напрямую из панели) или (PID, fwmark) —
# через туннель выхода в сети сервера AWG. Задаёт main.py; может бросить NotifyError.
router = None
# Другие пути к Telegram, когда выбранный выход не работает: alt_routes(via) → список «up:<id>»
alt_routes = None
LANGS = ("ru", "en", "zh", "fa")
# категории событий, которые можно включать по отдельности
KINDS = ("exit", "server", "system", "clients", "login", "tls", "update")

TEXTS = {
    "ru": {
        "test": "✅ Тестовое сообщение. Уведомления работают.",
        "late": "🕓 Событие произошло {time}: сообщение ждало, пока появится связь с Telegram.",
        "exit_down": "⚠️ Выход «{name}» перестал работать. Клиенты, которые шли через него, переключены на резервный выход.",
        "exit_up": "✅ Выход «{name}» снова работает.",
        "exit_quota": "📦 Выход «{name}»: исчерпан лимит {gb} ГБ за месяц. До начала следующего месяца трафик идёт через «{to}».",
        "exit_quota_direct": "📦 Выход «{name}»: исчерпан лимит {gb} ГБ за месяц. До начала следующего месяца трафик идёт напрямую.",
        "exit_quota_block": "📦 Выход «{name}»: исчерпан лимит {gb} ГБ за месяц. До начала следующего месяца трафик заблокирован.",
        "exit_quota_notify": "📦 Выход «{name}»: исчерпан лимит {gb} ГБ за месяц. Трафик продолжает идти через него.",
        "exit_quota_warn": "⚠️ Выход «{name}»: израсходовано 90% лимита {gb} ГБ за месяц.",
        "exit_quota_reset": "✅ Выход «{name}» снова используется: начался новый месяц.",
        "target_lost": "⚠️ Сервер AmneziaWG недоступен — проверьте контейнер или службу.",
        "target_back": "✅ Сервер AmneziaWG снова доступен.",
        "target_restarted": "ℹ️ Сервер AmneziaWG перезапустился, правила применены заново.",
        "server_start_failed": "⚠️ Сервер AmneziaWG не запускается.",
        "server_iface_gone": "⚠️ Интерфейс {iface} сервера AmneziaWG пропал — например, ядро завершило amneziawg-go из-за нехватки памяти. Панель перезапускает сервер.",
        "mem_high": "⚠️ Память сервера занята на {pct}% уже {min} мин. Если она кончится, ядро начнёт завершать процессы и туннели могут упасть.",
        "mem_ok": "✅ Память сервера снова в норме: занято {pct}%.",
        "cpu_high": "⚠️ Процессор сервера загружен на {pct}% уже {min} мин.",
        "cpu_ok": "✅ Процессор сервера снова в норме: {pct}%.",
        "kernel_old": "⚠️ На сервере загружен модуль ядра AmneziaWG {version}: параметры AWG 3.1 он не понимает, и сервер может не подняться. Нужен модуль {min}.x — обновите его (awg-router install-kernel) или удалите.",
        "kernel_fallback": "⚠️ Модуль ядра не запустил туннель {iface}. Туннели к выходам работают на amneziawg-go.",
        "login_ok": "🔑 Вход в панель с адреса {ip}.",
        "login_blocked": "🚫 Много неверных попыток входа с адреса {ip}. Вход с него заблокирован на 10 минут.",
        "tls_fail": "⚠️ Не удаётся продлить сертификат HTTPS панели. Текущий действует до {date}.",
        "client_expired": "⏰ Клиент «{name}» отключён: истёк срок действия.",
        "client_quota": "📦 Клиент «{name}» отключён: исчерпан лимит трафика {gb} ГБ.",
        "client_quota_reset": "✅ Клиент «{name}» снова включён: начался новый месяц.",
        "update_available": "🆕 Доступна новая версия панели {version}. Обновить можно в панели («Система») или на сервере: awg-router update",
        "backup": "💾 Резервная копия панели. Восстановить: «Система» → «Резервная копия» → «Восстановить из файла».",
        "backup_enc": "💾 Резервная копия панели, зашифрована паролем копии. Восстановить: «Система» → «Резервная копия» → «Восстановить из файла».",
        "client_expiring": "⏳ Клиент «{name}»: срок действия закончится {date} (через {days} дн.).",
        "client_quota_warn": "⚠️ Клиент «{name}»: израсходовано 90% лимита {gb} ГБ.",
        "client_first": "🎉 Клиент «{name}» подключился впервые — конфиг работает.",
        "pw_changed": "🔑 Пароль панели изменён (с адреса {ip}).",
    },
    "en": {
        "test": "✅ Test message. Notifications are working.",
        "late": "🕓 This happened at {time}: the message waited until Telegram became reachable.",
        "exit_down": "⚠️ Exit “{name}” stopped working. Clients that used it have been switched to the fallback exit.",
        "exit_up": "✅ Exit “{name}” is working again.",
        "exit_quota": "📦 Exit “{name}”: the monthly {gb} GB limit is used up. Until next month traffic goes through “{to}”.",
        "exit_quota_direct": "📦 Exit “{name}”: the monthly {gb} GB limit is used up. Until next month traffic goes direct.",
        "exit_quota_block": "📦 Exit “{name}”: the monthly {gb} GB limit is used up. Until next month traffic is blocked.",
        "exit_quota_notify": "📦 Exit “{name}”: the monthly {gb} GB limit is used up. Traffic still goes through it.",
        "exit_quota_warn": "⚠️ Exit “{name}”: 90% of the monthly {gb} GB limit is used.",
        "exit_quota_reset": "✅ Exit “{name}” is in use again: a new month has started.",
        "target_lost": "⚠️ The AmneziaWG server is unreachable — check the container or service.",
        "target_back": "✅ The AmneziaWG server is reachable again.",
        "target_restarted": "ℹ️ The AmneziaWG server restarted; rules were re-applied.",
        "server_start_failed": "⚠️ The AmneziaWG server fails to start.",
        "server_iface_gone": "⚠️ The AmneziaWG server's {iface} interface is gone — for example, the kernel killed amneziawg-go when memory ran out. The panel is restarting the server.",
        "mem_high": "⚠️ Server memory has been {pct}% full for {min} min. If it runs out, the kernel starts killing processes and tunnels may go down.",
        "mem_ok": "✅ Server memory is back to normal: {pct}% in use.",
        "cpu_high": "⚠️ Server CPU has been at {pct}% for {min} min.",
        "cpu_ok": "✅ Server CPU is back to normal: {pct}%.",
        "kernel_old": "⚠️ The server has AmneziaWG kernel module {version} loaded: it doesn't understand AWG 3.1 parameters, and the server may not come up. Module {min}.x is needed — update it (awg-router install-kernel) or remove it.",
        "kernel_fallback": "⚠️ The kernel module couldn't start tunnel {iface}. Tunnels to exits run on amneziawg-go.",
        "login_ok": "🔑 Panel sign-in from {ip}.",
        "login_blocked": "🚫 Too many failed sign-in attempts from {ip}. It is blocked for 10 minutes.",
        "tls_fail": "⚠️ The panel's HTTPS certificate can't be renewed. The current one is valid until {date}.",
        "client_expired": "⏰ Client “{name}” was turned off: its access period ended.",
        "client_quota": "📦 Client “{name}” was turned off: the {gb} GB traffic limit is used up.",
        "client_quota_reset": "✅ Client “{name}” is on again: a new month has started.",
        "update_available": "🆕 Panel version {version} is available. Update in the panel (System) or on the server: awg-router update",
        "backup": "💾 Panel backup. To restore: System → Backup → Restore from file.",
        "backup_enc": "💾 Panel backup, encrypted with the backup password. To restore: System → Backup → Restore from file.",
        "client_expiring": "⏳ Client “{name}” ends on {date} (in {days} d).",
        "client_quota_warn": "⚠️ Client “{name}”: 90% of the {gb} GB limit is used.",
        "client_first": "🎉 Client “{name}” connected for the first time — the config works.",
        "pw_changed": "🔑 The panel password was changed (from {ip}).",
    },
    "zh": {
        "test": "✅ 测试消息。通知功能正常。",
        "late": "🕓 事件发生于 {time}：消息一直等到能连上 Telegram 才发出。",
        "exit_down": "⚠️ 出口“{name}”已停止工作。经由它的客户端已切换到备用出口。",
        "exit_up": "✅ 出口“{name}”已恢复工作。",
        "exit_quota": "📦 出口“{name}”：本月 {gb} GB 流量限额已用完。下个月之前流量经由“{to}”。",
        "exit_quota_direct": "📦 出口“{name}”：本月 {gb} GB 流量限额已用完。下个月之前流量直连。",
        "exit_quota_block": "📦 出口“{name}”：本月 {gb} GB 流量限额已用完。下个月之前流量被阻止。",
        "exit_quota_notify": "📦 出口“{name}”：本月 {gb} GB 流量限额已用完。流量仍经由它转发。",
        "exit_quota_warn": "⚠️ 出口“{name}”：本月 {gb} GB 限额已用掉 90%。",
        "exit_quota_reset": "✅ 出口“{name}”已重新启用：新的月份开始了。",
        "target_lost": "⚠️ 无法访问 AmneziaWG 服务器——请检查容器或服务。",
        "target_back": "✅ AmneziaWG 服务器已恢复访问。",
        "target_restarted": "ℹ️ AmneziaWG 服务器已重启，规则已重新应用。",
        "server_start_failed": "⚠️ AmneziaWG 服务器无法启动。",
        "server_iface_gone": "⚠️ AmneziaWG 服务器的 {iface} 接口消失了——例如内存不足时内核终止了 amneziawg-go。面板正在重启服务器。",
        "mem_high": "⚠️ 服务器内存占用已达 {pct}%，持续 {min} 分钟。内存耗尽时内核会开始终止进程，隧道可能中断。",
        "mem_ok": "✅ 服务器内存已恢复正常：已用 {pct}%。",
        "cpu_high": "⚠️ 服务器 CPU 负载已达 {pct}%，持续 {min} 分钟。",
        "cpu_ok": "✅ 服务器 CPU 已恢复正常：{pct}%。",
        "kernel_old": "⚠️ 服务器加载了 AmneziaWG 内核模块 {version}：它不支持 AWG 3.1 参数，服务器可能无法启动。需要 {min}.x 版本的模块——请更新（awg-router install-kernel）或将其删除。",
        "kernel_fallback": "⚠️ 内核模块无法启动隧道 {iface}。通往出口的隧道改用 amneziawg-go 运行。",
        "login_ok": "🔑 来自 {ip} 的面板登录。",
        "login_blocked": "🚫 来自 {ip} 的错误登录尝试过多，已封锁 10 分钟。",
        "tls_fail": "⚠️ 无法续期面板的 HTTPS 证书。当前证书有效期至 {date}。",
        "client_expired": "⏰ 客户端“{name}”已停用：使用期限已到。",
        "client_quota": "📦 客户端“{name}”已停用：{gb} GB 流量限额已用完。",
        "client_quota_reset": "✅ 客户端“{name}”已重新启用：新的月份开始了。",
        "update_available": "🆕 面板新版本 {version} 可用。可在面板（系统）中更新，或在服务器上运行：awg-router update",
        "backup": "💾 面板备份。恢复方法：系统 → 备份 → 从文件恢复。",
        "backup_enc": "💾 面板备份，已用备份密码加密。恢复方法：系统 → 备份 → 从文件恢复。",
        "client_expiring": "⏳ 客户端“{name}”将于 {date} 到期（还剩 {days} 天）。",
        "client_quota_warn": "⚠️ 客户端“{name}”：{gb} GB 限额已用掉 90%。",
        "client_first": "🎉 客户端“{name}”首次连接成功——配置可用。",
        "pw_changed": "🔑 面板密码已更改（来自 {ip}）。",
    },
    "fa": {
        "test": "✅ پیام آزمایشی. اعلان‌ها کار می‌کنند.",
        "late": "🕓 این رویداد در {time} رخ داد: پیام تا برقراری ارتباط با تلگرام منتظر ماند.",
        "exit_down": "⚠️ خروجی «{name}» از کار افتاد. کلاینت‌هایی که از آن می‌رفتند به خروجی پشتیبان منتقل شدند.",
        "exit_up": "✅ خروجی «{name}» دوباره کار می‌کند.",
        "exit_quota": "📦 خروجی «{name}»: سقف ماهانهٔ {gb} گیگابایت تمام شد. تا ماه بعد ترافیک از «{to}» می‌رود.",
        "exit_quota_direct": "📦 خروجی «{name}»: سقف ماهانهٔ {gb} گیگابایت تمام شد. تا ماه بعد ترافیک مستقیم می‌رود.",
        "exit_quota_block": "📦 خروجی «{name}»: سقف ماهانهٔ {gb} گیگابایت تمام شد. تا ماه بعد ترافیک مسدود است.",
        "exit_quota_notify": "📦 خروجی «{name}»: سقف ماهانهٔ {gb} گیگابایت تمام شد. ترافیک همچنان از آن می‌رود.",
        "exit_quota_warn": "⚠️ خروجی «{name}»: ۹۰٪ سقف ماهانهٔ {gb} گیگابایت مصرف شد.",
        "exit_quota_reset": "✅ خروجی «{name}» دوباره استفاده می‌شود: ماه تازه شروع شد.",
        "target_lost": "⚠️ سرور AmneziaWG در دسترس نیست — کانتینر یا سرویس را بررسی کنید.",
        "target_back": "✅ سرور AmneziaWG دوباره در دسترس است.",
        "target_restarted": "ℹ️ سرور AmneziaWG دوباره راه‌اندازی شد و قوانین دوباره اعمال شدند.",
        "server_start_failed": "⚠️ سرور AmneziaWG راه‌اندازی نمی‌شود.",
        "server_iface_gone": "⚠️ رابط {iface} سرور AmneziaWG از بین رفت — مثلاً هسته به دلیل کمبود حافظه amneziawg-go را بست. پنل سرور را دوباره راه‌اندازی می‌کند.",
        "mem_high": "⚠️ حافظهٔ سرور {min} دقیقه است که {pct}% پر است. اگر تمام شود، هسته شروع به بستن پردازه‌ها می‌کند و ممکن است تونل‌ها قطع شوند.",
        "mem_ok": "✅ حافظهٔ سرور دوباره عادی است: {pct}% در حال استفاده.",
        "cpu_high": "⚠️ پردازندهٔ سرور {min} دقیقه است که روی {pct}% است.",
        "cpu_ok": "✅ پردازندهٔ سرور دوباره عادی است: {pct}%.",
        "kernel_old": "⚠️ ماژول هستهٔ AmneziaWG نسخهٔ {version} روی سرور بارگذاری شده است: پارامترهای AWG 3.1 را نمی‌فهمد و ممکن است سرور بالا نیاید. ماژول {min}.x لازم است — آن را به‌روز کنید (awg-router install-kernel) یا حذفش کنید.",
        "kernel_fallback": "⚠️ ماژول هسته نتوانست تونل {iface} را راه بیندازد. تونل‌ها به خروجی‌ها با amneziawg-go کار می‌کنند.",
        "login_ok": "🔑 ورود به پنل از نشانی {ip}.",
        "login_blocked": "🚫 تلاش‌های ناموفق زیاد برای ورود از نشانی {ip}. ورود از آن ۱۰ دقیقه مسدود شد.",
        "tls_fail": "⚠️ تمدید گواهی HTTPS پنل ممکن نیست. گواهی فعلی تا {date} معتبر است.",
        "client_expired": "⏰ کلاینت «{name}» غیرفعال شد: مدت اعتبارش تمام شد.",
        "client_quota": "📦 کلاینت «{name}» غیرفعال شد: سقف ترافیک {gb} گیگابایت تمام شد.",
        "client_quota_reset": "✅ کلاینت «{name}» دوباره فعال شد: ماه تازه شروع شد.",
        "update_available": "🆕 نسخهٔ تازهٔ پنل {version} آماده است. در پنل (سیستم) یا روی سرور به‌روزرسانی کنید: awg-router update",
        "backup": "💾 پشتیبان پنل. بازیابی: سیستم ← پشتیبان ← بازیابی از فایل.",
        "backup_enc": "💾 پشتیبان پنل، رمزگذاری‌شده با رمز پشتیبان. بازیابی: سیستم ← پشتیبان ← بازیابی از فایل.",
        "client_expiring": "⏳ کلاینت «{name}»: اعتبار در {date} تمام می‌شود ({days} روز دیگر).",
        "client_quota_warn": "⚠️ کلاینت «{name}»: ۹۰٪ سقف {gb} گیگابایت مصرف شد.",
        "client_first": "🎉 کلاینت «{name}» برای نخستین بار وصل شد — پیکربندی کار می‌کند.",
        "pw_changed": "🔑 رمز پنل تغییر کرد (از نشانی {ip}).",
    },
}

# событие движка → (категория, текст)
ENGINE_EVENTS = {
    "ev.upstream_failed": ("exit", "exit_down"),
    "ev.upstream_ok": ("exit", "exit_up"),
    "ev.upstream_quota": ("exit", "exit_quota"),
    "ev.upstream_quota_notify": ("exit", "exit_quota_notify"),
    "ev.upstream_quota_direct": ("exit", "exit_quota_direct"),
    "ev.upstream_quota_block": ("exit", "exit_quota_block"),
    "ev.upstream_quota_warn": ("exit", "exit_quota_warn"),
    "ev.upstream_quota_reset": ("exit", "exit_quota_reset"),
    "ev.target_lost": ("server", "target_lost"),
    "ev.target_restarted": ("server", "target_restarted"),
    "ev.server_start_failed": ("server", "server_start_failed"),
    "ev.server_iface_gone": ("server", "server_iface_gone"),
    "ev.mem_high": ("system", "mem_high"),
    "ev.mem_ok": ("system", "mem_ok"),
    "ev.cpu_high": ("system", "cpu_high"),
    "ev.cpu_ok": ("system", "cpu_ok"),
    "ev.kernel_old": ("server", "kernel_old"),
    "ev.kernel_fallback": ("exit", "kernel_fallback"),
    "ev.client_expired": ("clients", "client_expired"),
    "ev.client_quota": ("clients", "client_quota"),
    "ev.client_quota_reset": ("clients", "client_quota_reset"),
    "ev.client_expiring": ("clients", "client_expiring"),
    "ev.client_quota_warn": ("clients", "client_quota_warn"),
    "ev.client_first": ("clients", "client_first"),
}


class NotifyError(Exception):
    """Ошибка отправки. msg — Msg для интерфейса (переводит браузер), если она наша,
    а не техническая строка от сети или Telegram. net — сбой пути, а не отказ Telegram (нет
    маршрута, таймаут, 429/5xx): можно пробовать другой путь и повторить позже. Отказ вроде
    неверного токена или чата повтором не лечится."""

    def __init__(self, text: str, msg: Msg | None = None, net: bool = False):
        super().__init__(text)
        self.msg = msg
        self.net = net


BACKUP_PERIODS = {"off": 0, "daily": 86400, "weekly": 7 * 86400}


def defaults() -> dict:
    return {"enabled": False, "token": "", "chat_id": "", "lang": "en",
            "events": {k: True for k in KINDS},
            # как ходить к api.telegram.org: direct | up:<id> (через выход, если Telegram заблокирован)
            "via": "direct",
            # управление из Telegram: команды и кнопки (только из этого чата), см. tgbot.py
            "control": False,
            # резервная копия в чат: off | daily | weekly; пароль — шифровать файл (пусто — нет)
            "backup": "off", "backup_pw": "", "backup_last": None, "backup_error": None}


def cfg_of(st: dict) -> dict:
    c = defaults()
    c.update({k: v for k, v in (st.get("settings", {}).get("telegram") or {}).items() if k in c})
    c["events"] = {**defaults()["events"], **(c.get("events") or {})}
    return c


def public_view(c: dict) -> dict:
    """Настройки для браузера: токен целиком не отдаём."""
    tok = c.get("token") or ""
    return {**{k: v for k, v in c.items() if k not in ("token", "backup_pw")},
            "token_set": bool(tok), "token_hint": (tok.split(":")[0] + ":…" + tok[-4:]) if tok else "",
            "backup_pw_set": bool(c.get("backup_pw"))}


def render(lang: str, key: str, host: str = "", **params) -> str:
    tx = TEXTS.get(lang) or TEXTS["en"]
    body = tx.get(key) or TEXTS["en"][key]
    for k, v in params.items():
        body = body.replace("{" + k + "}", str(v))
    return (f"AWG Router · {host}\n" if host else "AWG Router\n") + body


# Насколько часы сервера впереди часов Telegram (по заголовку Date его ответов), в секундах.
# Часы VPS бывают сбиты на минуты и часы: бот сверяет «старые» команды по времени Telegram.
clock_skew = 0.0


def note_date(value: str | None, now: float | None = None) -> None:
    global clock_skew
    try:
        tg = email.utils.parsedate_to_datetime(value).timestamp() if value else None
    except (TypeError, ValueError, IndexError):
        tg = None
    if tg:
        clock_skew = (time.time() if now is None else now) - tg


def _post_direct(url: str, data: bytes, ctype: str, timeout: float) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            note_date((getattr(r, "headers", None) or {}).get("Date"))
            return getattr(r, "status", 200), r.read()
    except urllib.error.HTTPError as e:
        note_date((getattr(e, "headers", None) or {}).get("Date"))
        return e.code, e.read()


def _post_via(route: tuple[int, int], url: str, data: bytes, ctype: str,
              timeout: float) -> tuple[int, bytes]:
    """Запрос из сети сервера AWG через туннель выхода (метка fwmark, как у probe.py)."""
    pid, mark = route
    head = json.dumps({"url": url, "ctype": ctype, "timeout": timeout}).encode()
    try:
        p = subprocess.run(["nsenter", "-t", str(pid), "-n", "--", sys.executable, TGREQ, str(mark)],
                           input=head + b"\n" + data, capture_output=True, timeout=timeout * 2 + 15)
    except subprocess.TimeoutExpired:
        raise OSError("timed out") from None
    try:
        res = json.loads(p.stdout.decode(errors="replace"))
    except ValueError:
        raise OSError((p.stderr or p.stdout).decode(errors="replace").strip()[:200] or "no answer") from None
    if res.get("err"):
        raise OSError(res["err"])
    note_date(res.get("date"))
    return int(res.get("status") or 0), str(res.get("body") or "").encode()


def _post(token: str, method: str, data: bytes, ctype: str, timeout: float, via: str) -> dict:
    url = f"{API}/bot{token}/{method}"
    route = router(via) if router and via and via != "direct" else None
    try:
        if route is None:
            code, raw = _post_direct(url, data, ctype, timeout)
        else:
            code, raw = _post_via(route, url, data, ctype, timeout)
    except (urllib.error.URLError, OSError) as e:
        raise NotifyError(f"api.telegram.org: {getattr(e, 'reason', e)}"[:300], net=True) from None
    try:
        res = json.loads(raw.decode(errors="replace") or "{}")
    except ValueError:
        res = None
    if not isinstance(res, dict):
        raise NotifyError(f"api.telegram.org: HTTP {code}", net=True)
    if not res.get("ok"):
        ec = res.get("error_code") or 0
        raise NotifyError(str(res.get("description") or "Telegram error")[:300],
                          net=ec == 429 or (isinstance(ec, int) and ec >= 500))
    return res.get("result") or {}


def _call(token: str, method: str, payload: dict | None = None, timeout: float = 15,
          via: str = "direct") -> dict:
    return _post(token, method, json.dumps(payload or {}).encode(), "application/json", timeout, via)


def send(token: str, chat_id: str, text: str, via: str = "direct", markup: dict | None = None,
         html: bool = False) -> dict:
    """sendMessage. markup — кнопки под сообщением (reply_markup), html — разметка HTML."""
    p = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    if markup:
        p["reply_markup"] = markup
    if html:
        p["parse_mode"] = "HTML"
    return _call(token, "sendMessage", p, via=via)


def _send_file(method: str, field: str, token: str, chat_id: str, filename: str, data: bytes,
               caption: str, via: str, markup: dict | None = None, html: bool = False,
               ctype: str = "application/octet-stream") -> dict:
    """Файл multipart/form-data (urllib сам этого не умеет)."""
    boundary = "awgr" + uuid.uuid4().hex
    fields = [("chat_id", chat_id), ("caption", caption[:1000])]
    if markup:
        fields.append(("reply_markup", json.dumps(markup, ensure_ascii=False)))
    if html:
        fields.append(("parse_mode", "HTML"))
    parts = []
    for k, v in fields:
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
                 f'Content-Type: {ctype}\r\n\r\n'.encode() + data + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return _post(token, method, b"".join(parts), f"multipart/form-data; boundary={boundary}", 120, via)


def send_document(token: str, chat_id: str, filename: str, data: bytes, caption: str,
                  via: str = "direct", markup: dict | None = None, html: bool = False) -> None:
    _send_file("sendDocument", "document", token, chat_id, filename, data, caption, via, markup, html)


def send_photo(token: str, chat_id: str, png: bytes, caption: str, via: str = "direct",
               html: bool = False, markup: dict | None = None, filename: str = "qr.png") -> dict:
    return _send_file("sendPhoto", "photo", token, chat_id, filename, png, caption, via, markup, html=html,
                      ctype="image/png")


# Шифрование копии: openssl есть в образе, а AES в стандартной библиотеке Python нет.
# Расшифровать вручную: openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in файл -out копия.json
ENC = ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt", "-pass", "env:AWGR_BACKUP_PW"]
ENC_MAGIC = b"Salted__"


def encrypt(data: bytes, password: str) -> bytes:
    p = subprocess.run(ENC, input=data, capture_output=True, timeout=60,
                       env={**os.environ, "AWGR_BACKUP_PW": password})
    if p.returncode != 0 or not p.stdout.startswith(ENC_MAGIC):
        raise NotifyError("openssl: " + p.stderr.decode(errors="replace").strip()[:200])
    return p.stdout


def decrypt(data: bytes, password: str) -> bytes | None:
    """None — неверный пароль или повреждённый файл."""
    p = subprocess.run(ENC[:3] + ["-d"] + ENC[3:], input=data, capture_output=True, timeout=60,
                       env={**os.environ, "AWGR_BACKUP_PW": password})
    return p.stdout if p.returncode == 0 else None


def detect_chat(token: str, via: str = "direct") -> dict | None:
    """Чат, из которого боту писали последним (чтобы не искать chat id вручную)."""
    upd = _call(token, "getUpdates", {"limit": 50, "timeout": 0}, via=via)
    for u in reversed(upd if isinstance(upd, list) else []):
        m = u.get("message") or u.get("channel_post") or u.get("my_chat_member") or {}
        ch = m.get("chat")
        if ch and "id" in ch:
            title = ch.get("title") or " ".join(x for x in (ch.get("first_name"), ch.get("last_name")) if x) \
                or ch.get("username") or ""
            return {"id": str(ch["id"]), "title": title}
    return None


class Notifier:
    """Очередь отправки: события ставятся мгновенно, сеть — в отдельном потоке.
    Если путь к Telegram не работает, сообщение пробует другие пути (остальные рабочие выходы,
    затем «напрямую»), а не дошедшее копится и уходит, когда связь вернётся: канал оповещения
    не должен отказывать именно тогда, когда рассказывает о поломке."""

    COOLDOWN = 300          # одинаковые сообщения — не чаще раза в 5 минут
    RETRY_PAUSES = (30, 60, 120, 300)   # паузы между повторами, когда путь не работает
    MAX_PENDING = 50                    # сколько не дошедших сообщений храним (старые выбрасываем)
    MAX_AGE = 86400                     # старше суток не отправляем: новости протухли
    LATE_AFTER = 90                     # опоздавшее дольше этого — с пометкой о времени события

    def __init__(self, store, host_fn):
        self.store = store
        self.host_fn = host_fn
        self.q: queue.Queue = queue.Queue(maxsize=100)
        self.pending: collections.deque = collections.deque()    # не дошедшее: (…, markup, время события)
        self._sent: dict[str, float] = {}
        self.last_error: str | None = None
        self._target_lost = False
        # кнопки под уведомлением (tgbot.notify_buttons): (ключ текста, ссылки, язык) → reply_markup
        self.buttons_fn = None
        threading.Thread(target=self._worker, name="notify", daemon=True).start()

    def event(self, kind: str, key: str, cooldown: float | None = None, refs: dict | None = None,
              **params) -> None:
        """refs — к чему относится событие ({"pk": …} или {"uid": …}): для кнопок под ним."""
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
        markup = None
        if c["control"] and self.buttons_fn:
            try:
                markup = self.buttons_fn(key, {**params, **(refs or {})}, c["lang"])
            except Exception:  # noqa: BLE001  — без кнопок уведомление всё равно нужно
                log.exception("notify buttons")
        try:
            self.q.put_nowait((c["token"], c["chat_id"], render(c["lang"], key, host, **params),
                               c["via"], markup, now))
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
            self.event(m[0], m[1], refs={k: v for k, v in msg.p.items() if k in ("pk", "uid")},
                       **{k: v for k, v in msg.p.items() if k in ("name", "gb", "to", "date", "days", "iface", "pct", "min", "version", "error")})

    def target_ok(self) -> None:
        if self._target_lost:
            self._target_lost = False
            self.event("server", "target_back")

    def routes(self, via: str) -> list[str]:
        """Пути по порядку: выбранный, затем (если это выход) остальные работающие выходы и
        «напрямую». Выбранный «напрямую» остаётся единственным: его человек выбрал сам."""
        out = [via]
        if via != "direct":
            try:
                out += [v for v in (alt_routes(via) if alt_routes else []) if v not in out]
            except Exception:  # noqa: BLE001
                log.exception("notify alt routes")
            out.append("direct")
        return out

    def deliver(self, token: str, chat: str, text: str, via: str, markup: dict | None) -> None:
        """Отправка по очереди путей. Если сбой пути на всех, бросает ошибку первого (выбранного)
        пути: она лучше всего объясняет, что не так. Отказ Telegram (токен, чат) — сразу."""
        first = None
        for v in self.routes(via):
            try:
                send(token, chat, text, v, markup)
                return
            except NotifyError as e:
                if not e.net:
                    raise
                first = first or e
                log.warning("telegram via %s: %s", v, e)
        raise first or NotifyError("no route", net=True)

    def _take(self, wait: float | None) -> None:
        """Забрать новые сообщения в хвост очереди отложенных (ждать не дольше wait секунд)."""
        try:
            self.pending.append(self.q.get(timeout=wait))
        except queue.Empty:
            return
        while True:
            try:
                self.pending.append(self.q.get_nowait())
            except queue.Empty:
                break
        while len(self.pending) > self.MAX_PENDING:
            self.pending.popleft()

    def flush(self, now: float | None = None) -> bool:
        """Отправить накопленное по порядку. True — очередь пуста, False — путь не работает,
        остаток ждёт следующей попытки. Токен, чат и путь берутся из текущих настроек:
        так сообщение уходит и после того, как человек поправил «Отправлять через»."""
        c = cfg_of(self.store.snapshot())
        if not (c["enabled"] and c["token"] and c["chat_id"]):
            self.pending.clear()
            return True
        while self.pending:
            item = self.pending[0]
            text, markup, ts = item[2], item[4], (item[5] if len(item) > 5 else 0.0)
            t = time.time() if now is None else now
            if ts and t - ts > self.MAX_AGE:
                self.pending.popleft()
                log.warning("telegram: message is older than a day, dropped")
                continue
            if ts and t - ts > self.LATE_AFTER:
                note = (TEXTS.get(c["lang"]) or TEXTS["en"])["late"].replace(
                    "{time}", time.strftime("%d.%m %H:%M UTC", time.gmtime(ts)))
                text = note + "\n\n" + text
            try:
                self.deliver(c["token"], c["chat_id"], text, c["via"], markup)
            except NotifyError as e:
                self.last_error = e.msg or str(e)
                log.warning("telegram: %s", e)
                if e.net:
                    return False
                self.pending.popleft()       # Telegram отказал: повтор не поможет, пропускаем
                continue
            self.pending.popleft()
            self.last_error = None
        return True

    def _worker(self) -> None:
        fails = 0
        while True:
            pause = self.RETRY_PAUSES[min(fails, len(self.RETRY_PAUSES) - 1)] if self.pending else None
            self._take(pause)           # новое сообщение будит и повтор: вдруг связь уже есть
            try:
                fails = 0 if self.flush() else fails + 1
            except Exception:  # noqa: BLE001
                log.exception("notify flush")
                fails += 1
