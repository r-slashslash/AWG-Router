"""Уведомления в Telegram (включаются вручную в настройках панели).

Это единственное место, где бэкенд сам переводит тексты: сообщение уходит в Telegram,
а не в браузер, поэтому каталог на четырёх языках лежит здесь (TEXTS).
"""
from __future__ import annotations

import collections
import email.utils
import http.client
import json
import logging
import re
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
# через туннель выхода в сети сервера AWG. Задаёт app/panel.py; может бросить NotifyError.
router = None
# Другие пути к Telegram, когда выбранный не работает: alt_routes(via) → работающие выходы «up:<id>», кроме via
alt_routes = None
# Галочка «Если не получается — пробовать другие пути» (1.23.0) из сохранённых настроек: fallback_on() → bool.
# Задаёт app/panel.py; нет — только выбранный путь
fallback_on = None
PATH_RETRY = 600         # с: бот идёт запасным путём — выбранный пробуется снова раз в столько секунд
LANGS = ("ru", "en", "zh", "fa")
# категории событий, которые можно включать по отдельности
KINDS = ("exit", "server", "system", "clients", "login", "tls", "update", "monthly")
# «Итоги месяца» (1.24.0) — по желанию: у всех, и у тех, кто обновился, выключено
OFF_KINDS = ("monthly",)
MONTHS = {
    "ru": "январь февраль март апрель май июнь июль август сентябрь октябрь ноябрь декабрь".split(),
    "en": "January February March April May June July August September October November December".split(),
    "fa": "ژانویه فوریه مارس آوریل مه ژوئن ژوئیه اوت سپتامبر اکتبر نوامبر دسامبر".split(),
}


def month_title(mk: str, lang: str) -> str:
    """«2026-11» → «ноябрь 2026» / «November 2026» / «2026年11月»."""
    y, m = mk.split("-")
    if lang == "zh":
        return f"{y}年{int(m)}月"
    return f"{(MONTHS.get(lang) or MONTHS['en'])[int(m) - 1]} {y}"

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
        "rule_quota": "📦 Правило «{name}»: исчерпан лимит {gb} ГБ за месяц. До начала следующего месяца его трафик идёт через «{to}».",
        "rule_quota_direct": "📦 Правило «{name}»: исчерпан лимит {gb} ГБ за месяц. До начала следующего месяца его трафик идёт напрямую.",
        "rule_quota_block": "📦 Правило «{name}»: исчерпан лимит {gb} ГБ за месяц. До начала следующего месяца его трафик заблокирован.",
        "rule_quota_notify": "📦 Правило «{name}»: исчерпан лимит {gb} ГБ за месяц. Трафик идёт как раньше.",
        "rule_quota_warn": "⚠️ Правило «{name}»: израсходовано 90% лимита {gb} ГБ за месяц.",
        "rule_quota_reset": "✅ Правило «{name}» снова работает как обычно: начался новый месяц.",
        "monthly": "📊 Итоги за {month}",
        "monthly_total": "Всего",
        "monthly_exits": "Выходы",
        "monthly_rules": "Правила",
        "monthly_direct": "Напрямую",
        "monthly_default": "По умолчанию",
        "target_lost": "⚠️ Сервер AmneziaWG недоступен — проверьте контейнер или службу.",
        "target_back": "✅ Сервер AmneziaWG снова доступен.",
        "container_recovered": "🔁 Контейнер сервера AmneziaWG ({name}) остался выключенным после прерванной смены порта или обновления. Панель вернула его и запустила.",
        "target_restarted": "ℹ️ Сервер AmneziaWG перезапустился, правила применены заново.",
        "server_start_failed": "⚠️ Сервер AmneziaWG не запускается.",
        "server_iface_gone": "⚠️ Интерфейс {iface} сервера AmneziaWG пропал — например, ядро завершило amneziawg-go из-за нехватки памяти. Панель перезапускает сервер.",
        "mem_high": "⚠️ Память сервера занята на {pct}% уже {min} мин. Если она кончится, ядро начнёт завершать процессы и туннели могут упасть.",
        "mem_ok": "✅ Память сервера снова в норме: занято {pct}%.",
        "cpu_high": "⚠️ Процессор сервера загружен на {pct}% уже {min} мин.",
        "cpu_ok": "✅ Процессор сервера снова в норме: {pct}%.",
        "kernel_old": "⚠️ На сервере загружен модуль ядра AmneziaWG {version}: параметры AWG 3.1 он не понимает, и сервер может не подняться. Нужен модуль {min}.x — обновите его (awg-router install-kernel) или удалите.",
        "kernel_fallback": "⚠️ Модуль ядра не запустил туннель {iface}. Туннели к выходам работают на amneziawg-go.",
        "kernel_conf": "⚠️ Модуль ядра не принял конфиг выхода {iface} ({error}). Туннели к выходам работают на amneziawg-go до перезапуска сервера AWG.",
        "kernel_conf_i": "⚠️ Модуль ядра не принял конфиг выхода {iface}: I1–I5 записаны в формате, который он не понимает (подробности — в панели). Туннели к выходам работают на amneziawg-go до перезапуска сервера AWG.",
        "kernel_on": "✅ Сервер AmneziaWG работает на модуле ядра {version}.",
        "dom_strict_on": "⛔ Правила по доменам не работают — трафик их клиентов заблокирован, пока обработчик не заработает.",
        "dom_strict_off": "✅ Правила по доменам снова работают — блок снят.",
        "kernel_gone": "⚠️ Модуль ядра AmneziaWG {version} больше не загружается (обновилось ядро?). Сервер работает на amneziawg-go; поставить модуль снова — в панели, «Сервер» → «Движок AmneziaWG».",
        "kernel_disabled": "⚠️ Сервер AmneziaWG не поднялся на модуле ядра после {n} перезапусков. Панель отключила модуль и перевела сервер на amneziawg-go — клиенты снова подключаются.",
        "kernel_disabled_reboot": "⚠️ Сервер AmneziaWG не поднялся на модуле ядра после {n} перезапусков. Панель отключила модуль, но выгрузить его не смогла — перезагрузите сервер, и он поднимется на amneziawg-go.",
        "login_ok": "🔑 Вход в панель с адреса {ip}.",
        "login_blocked": "🚫 Много неверных попыток входа с адреса {ip}. Вход с него заблокирован на 10 минут.",
        "login_code_wrong": "⚠️ Вход в панель с адреса {ip}: пароль верный, а код из приложения — нет. Если это были не вы, пароль панели знает кто-то ещё — смените его.",
        "login_code_locked": "🚫 Слишком много неверных кодов при верном пароле (последний — с адреса {ip}). Вход по коду закрыт для всех на 10 минут. Смените пароль панели.",
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
        "rule_quota": "📦 Rule “{name}”: the monthly {gb} GB limit is used up. Until next month its traffic goes through “{to}”.",
        "rule_quota_direct": "📦 Rule “{name}”: the monthly {gb} GB limit is used up. Until next month its traffic goes direct.",
        "rule_quota_block": "📦 Rule “{name}”: the monthly {gb} GB limit is used up. Until next month its traffic is blocked.",
        "rule_quota_notify": "📦 Rule “{name}”: the monthly {gb} GB limit is used up. Traffic goes as before.",
        "rule_quota_warn": "⚠️ Rule “{name}”: 90% of the monthly {gb} GB limit is used.",
        "rule_quota_reset": "✅ Rule “{name}” works as usual again: a new month has started.",
        "monthly": "📊 Totals for {month}",
        "monthly_total": "Total",
        "monthly_exits": "Exits",
        "monthly_rules": "Rules",
        "monthly_direct": "Direct",
        "monthly_default": "Default",
        "target_lost": "⚠️ The AmneziaWG server is unreachable — check the container or service.",
        "target_back": "✅ The AmneziaWG server is reachable again.",
        "container_recovered": "🔁 The AmneziaWG server container ({name}) was left off by an interrupted port change or update. The panel brought it back and started it.",
        "target_restarted": "ℹ️ The AmneziaWG server restarted; rules were re-applied.",
        "server_start_failed": "⚠️ The AmneziaWG server fails to start.",
        "server_iface_gone": "⚠️ The AmneziaWG server's {iface} interface is gone — for example, the kernel killed amneziawg-go when memory ran out. The panel is restarting the server.",
        "mem_high": "⚠️ Server memory has been {pct}% full for {min} min. If it runs out, the kernel starts killing processes and tunnels may go down.",
        "mem_ok": "✅ Server memory is back to normal: {pct}% in use.",
        "cpu_high": "⚠️ Server CPU has been at {pct}% for {min} min.",
        "cpu_ok": "✅ Server CPU is back to normal: {pct}%.",
        "kernel_old": "⚠️ The server has AmneziaWG kernel module {version} loaded: it doesn't understand AWG 3.1 parameters, and the server may not come up. Module {min}.x is needed — update it (awg-router install-kernel) or remove it.",
        "kernel_fallback": "⚠️ The kernel module couldn't start tunnel {iface}. Tunnels to exits run on amneziawg-go.",
        "kernel_conf": "⚠️ The kernel module didn't accept the config of exit {iface} ({error}). Tunnels to exits run on amneziawg-go until the AWG server restarts.",
        "kernel_conf_i": "⚠️ The kernel module didn't accept the config of exit {iface}: its I1–I5 are written in a form the module doesn't understand (details in the panel). Tunnels to exits run on amneziawg-go until the AWG server restarts.",
        "kernel_on": "✅ The AmneziaWG server runs on kernel module {version}.",
        "dom_strict_on": "⛔ Domain rules aren't working — their clients' traffic is blocked until the handler works.",
        "dom_strict_off": "✅ Domain rules work again — the block is lifted.",
        "kernel_gone": "⚠️ AmneziaWG kernel module {version} no longer loads (a kernel update?). The server runs on amneziawg-go; to install the module again: Server → AmneziaWG engine in the panel.",
        "kernel_disabled": "⚠️ The AmneziaWG server didn't come up on the kernel module after {n} restarts. The panel switched the module off and moved the server to amneziawg-go — clients are connecting again.",
        "kernel_disabled_reboot": "⚠️ The AmneziaWG server didn't come up on the kernel module after {n} restarts. The panel switched the module off but couldn't unload it — reboot the server, and it comes up on amneziawg-go.",
        "login_ok": "🔑 Panel sign-in from {ip}.",
        "login_blocked": "🚫 Too many failed sign-in attempts from {ip}. It is blocked for 10 minutes.",
        "login_code_wrong": "⚠️ Panel sign-in from {ip}: the password was right, the app code was not. If it wasn't you, someone else knows the panel password — change it.",
        "login_code_locked": "🚫 Too many wrong codes with the right password (the last one from {ip}). Sign-in with a code is closed for everyone for 10 minutes. Change the panel password.",
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
        "rule_quota": "📦 规则“{name}”：本月 {gb} GB 流量限额已用完。下个月之前其流量经由“{to}”。",
        "rule_quota_direct": "📦 规则“{name}”：本月 {gb} GB 流量限额已用完。下个月之前其流量直连。",
        "rule_quota_block": "📦 规则“{name}”：本月 {gb} GB 流量限额已用完。下个月之前其流量被阻止。",
        "rule_quota_notify": "📦 规则“{name}”：本月 {gb} GB 流量限额已用完。流量照常转发。",
        "rule_quota_warn": "⚠️ 规则“{name}”：本月 {gb} GB 限额已用掉 90%。",
        "rule_quota_reset": "✅ 规则“{name}”已恢复正常：新的月份开始了。",
        "monthly": "📊 {month}汇总",
        "monthly_total": "合计",
        "monthly_exits": "出口",
        "monthly_rules": "规则",
        "monthly_direct": "直连",
        "monthly_default": "默认",
        "target_lost": "⚠️ 无法访问 AmneziaWG 服务器——请检查容器或服务。",
        "target_back": "✅ AmneziaWG 服务器已恢复访问。",
        "container_recovered": "🔁 AmneziaWG 服务器容器（{name}）因端口更改或更新中断而一直处于停止状态。面板已将其恢复并启动。",
        "target_restarted": "ℹ️ AmneziaWG 服务器已重启，规则已重新应用。",
        "server_start_failed": "⚠️ AmneziaWG 服务器无法启动。",
        "server_iface_gone": "⚠️ AmneziaWG 服务器的 {iface} 接口消失了——例如内存不足时内核终止了 amneziawg-go。面板正在重启服务器。",
        "mem_high": "⚠️ 服务器内存占用已达 {pct}%，持续 {min} 分钟。内存耗尽时内核会开始终止进程，隧道可能中断。",
        "mem_ok": "✅ 服务器内存已恢复正常：已用 {pct}%。",
        "cpu_high": "⚠️ 服务器 CPU 负载已达 {pct}%，持续 {min} 分钟。",
        "cpu_ok": "✅ 服务器 CPU 已恢复正常：{pct}%。",
        "kernel_old": "⚠️ 服务器加载了 AmneziaWG 内核模块 {version}：它不支持 AWG 3.1 参数，服务器可能无法启动。需要 {min}.x 版本的模块——请更新（awg-router install-kernel）或将其删除。",
        "kernel_fallback": "⚠️ 内核模块无法启动隧道 {iface}。通往出口的隧道改用 amneziawg-go 运行。",
        "kernel_conf": "⚠️ 内核模块不接受出口 {iface} 的配置（{error}）。在 AWG 服务器重启之前，通往出口的隧道改用 amneziawg-go 运行。",
        "kernel_conf_i": "⚠️ 内核模块不接受出口 {iface} 的配置：其 I1–I5 的写法模块无法识别（详情见面板）。在 AWG 服务器重启之前，通往出口的隧道改用 amneziawg-go 运行。",
        "kernel_on": "✅ AmneziaWG 服务器正在内核模块 {version} 上运行。",
        "dom_strict_on": "⛔ 域名规则未工作——在处理程序恢复前，其客户端的流量已被阻止。",
        "dom_strict_off": "✅ 域名规则已恢复工作——阻止已解除。",
        "kernel_gone": "⚠️ AmneziaWG 内核模块 {version} 已无法加载（内核更新了？）。服务器改用 amneziawg-go 运行；如需重新安装模块：面板中的「服务器」→「AmneziaWG 引擎」。",
        "kernel_disabled": "⚠️ AmneziaWG 服务器在内核模块上重启 {n} 次后仍未启动。面板已停用该模块并将服务器切换到 amneziawg-go——客户端正在重新连接。",
        "kernel_disabled_reboot": "⚠️ AmneziaWG 服务器在内核模块上重启 {n} 次后仍未启动。面板已停用该模块，但无法将其卸载——请重启服务器，它将以 amneziawg-go 启动。",
        "login_ok": "🔑 来自 {ip} 的面板登录。",
        "login_blocked": "🚫 来自 {ip} 的错误登录尝试过多，已封锁 10 分钟。",
        "login_code_wrong": "⚠️ 来自 {ip} 的面板登录：密码正确，但应用验证码错误。如果不是你本人，说明有人知道面板密码——请更改密码。",
        "login_code_locked": "🚫 密码正确但验证码错误的次数过多（最后一次来自 {ip}）。验证码登录对所有人关闭 10 分钟。请更改面板密码。",
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
        "rule_quota": "📦 قانون «{name}»: سقف ماهانهٔ {gb} گیگابایت تمام شد. تا ماه بعد ترافیک آن از «{to}» می‌رود.",
        "rule_quota_direct": "📦 قانون «{name}»: سقف ماهانهٔ {gb} گیگابایت تمام شد. تا ماه بعد ترافیک آن مستقیم می‌رود.",
        "rule_quota_block": "📦 قانون «{name}»: سقف ماهانهٔ {gb} گیگابایت تمام شد. تا ماه بعد ترافیک آن مسدود است.",
        "rule_quota_notify": "📦 قانون «{name}»: سقف ماهانهٔ {gb} گیگابایت تمام شد. ترافیک مثل قبل می‌رود.",
        "rule_quota_warn": "⚠️ قانون «{name}»: ۹۰٪ سقف ماهانهٔ {gb} گیگابایت مصرف شد.",
        "rule_quota_reset": "✅ قانون «{name}» دوباره عادی کار می‌کند: ماه تازه شروع شد.",
        "monthly": "📊 جمع‌بندی {month}",
        "monthly_total": "مجموع",
        "monthly_exits": "خروجی‌ها",
        "monthly_rules": "قانون‌ها",
        "monthly_direct": "مستقیم",
        "monthly_default": "پیش‌فرض",
        "target_lost": "⚠️ سرور AmneziaWG در دسترس نیست — کانتینر یا سرویس را بررسی کنید.",
        "target_back": "✅ سرور AmneziaWG دوباره در دسترس است.",
        "container_recovered": "🔁 کانتینر سرور AmneziaWG ({name}) پس از قطع شدن تغییر درگاه یا به‌روزرسانی خاموش مانده بود. پنل آن را برگرداند و راه‌اندازی کرد.",
        "target_restarted": "ℹ️ سرور AmneziaWG دوباره راه‌اندازی شد و قوانین دوباره اعمال شدند.",
        "server_start_failed": "⚠️ سرور AmneziaWG راه‌اندازی نمی‌شود.",
        "server_iface_gone": "⚠️ رابط {iface} سرور AmneziaWG از بین رفت — مثلاً هسته به دلیل کمبود حافظه amneziawg-go را بست. پنل سرور را دوباره راه‌اندازی می‌کند.",
        "mem_high": "⚠️ حافظهٔ سرور {min} دقیقه است که {pct}٪ پر است. اگر تمام شود، هسته شروع به بستن پردازه‌ها می‌کند و ممکن است تونل‌ها قطع شوند.",
        "mem_ok": "✅ حافظهٔ سرور دوباره عادی است: {pct}٪ در حال استفاده.",
        "cpu_high": "⚠️ پردازندهٔ سرور {min} دقیقه است که روی {pct}٪ است.",
        "cpu_ok": "✅ پردازندهٔ سرور دوباره عادی است: {pct}٪.",
        "kernel_old": "⚠️ ماژول هستهٔ AmneziaWG نسخهٔ {version} روی سرور بارگذاری شده است: پارامترهای AWG 3.1 را نمی‌فهمد و ممکن است سرور بالا نیاید. ماژول {min}.x لازم است — آن را به‌روز کنید (awg-router install-kernel) یا حذفش کنید.",
        "kernel_fallback": "⚠️ ماژول هسته نتوانست تونل {iface} را راه بیندازد. تونل‌ها به خروجی‌ها با amneziawg-go کار می‌کنند.",
        "kernel_conf": "⚠️ ماژول هسته پیکربندی خروجی {iface} را نپذیرفت ({error}). تا راه‌اندازی دوبارهٔ سرور AWG تونل‌ها به خروجی‌ها با amneziawg-go کار می‌کنند.",
        "kernel_conf_i": "⚠️ ماژول هسته پیکربندی خروجی {iface} را نپذیرفت: I1–I5 آن به شکلی نوشته شده که ماژول نمی‌فهمد (جزئیات در پنل). تا راه‌اندازی دوبارهٔ سرور AWG تونل‌ها به خروجی‌ها با amneziawg-go کار می‌کنند.",
        "kernel_on": "✅ سرور AmneziaWG روی ماژول هستهٔ {version} کار می‌کند.",
        "dom_strict_on": "⛔ قانون‌های دامنه کار نمی‌کنند — تا پردازشگر کار کند، ترافیک کلاینت‌هایشان مسدود است.",
        "dom_strict_off": "✅ قانون‌های دامنه دوباره کار می‌کنند — مسدودی برداشته شد.",
        "kernel_gone": "⚠️ ماژول هستهٔ AmneziaWG نسخهٔ {version} دیگر بارگذاری نمی‌شود (هسته به‌روز شده؟). سرور با amneziawg-go کار می‌کند؛ برای نصب دوبارهٔ ماژول: در پنل، «سرور» ← «موتور AmneziaWG».",
        "kernel_disabled": "⚠️ سرور AmneziaWG پس از {n} بار راه‌اندازی دوباره روی ماژول هسته بالا نیامد. پنل ماژول را غیرفعال کرد و سرور را به amneziawg-go برد — کلاینت‌ها دوباره وصل می‌شوند.",
        "kernel_disabled_reboot": "⚠️ سرور AmneziaWG پس از {n} بار راه‌اندازی دوباره روی ماژول هسته بالا نیامد. پنل ماژول را غیرفعال کرد اما نتوانست آن را بیرون بکشد — سرور را دوباره راه‌اندازی کنید تا با amneziawg-go بالا بیاید.",
        "login_ok": "🔑 ورود به پنل از نشانی {ip}.",
        "login_blocked": "🚫 تلاش‌های ناموفق زیاد برای ورود از نشانی {ip}. ورود از آن ۱۰ دقیقه مسدود شد.",
        "login_code_wrong": "⚠️ ورود به پنل از نشانی {ip}: گذرواژه درست بود، اما کد برنامه نه. اگر شما نبودید، کس دیگری گذرواژهٔ پنل را می‌داند — آن را عوض کنید.",
        "login_code_locked": "🚫 کدهای نادرست زیادی با گذرواژهٔ درست وارد شد (آخرین از نشانی {ip}). ورود با کد برای همه ۱۰ دقیقه بسته است. گذرواژهٔ پنل را عوض کنید.",
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
STATE_PAIRS = {k: p for p in (("exit_down", "exit_up"), ("mem_high", "mem_ok"), ("cpu_high", "cpu_ok"),
                                ("dom_strict_on", "dom_strict_off")) for k in p}
ENGINE_EVENTS = {
    "ev.container_recovered": ("server", "container_recovered"),
    "ev.upstream_failed": ("exit", "exit_down"),
    "ev.upstream_ok": ("exit", "exit_up"),
    "ev.upstream_quota": ("exit", "exit_quota"),
    "ev.upstream_quota_notify": ("exit", "exit_quota_notify"),
    "ev.upstream_quota_direct": ("exit", "exit_quota_direct"),
    "ev.upstream_quota_block": ("exit", "exit_quota_block"),
    "ev.upstream_quota_warn": ("exit", "exit_quota_warn"),
    "ev.upstream_quota_reset": ("exit", "exit_quota_reset"),
    "ev.rule_quota": ("exit", "rule_quota"),
    "ev.rule_quota_direct": ("exit", "rule_quota_direct"),
    "ev.rule_quota_block": ("exit", "rule_quota_block"),
    "ev.rule_quota_notify": ("exit", "rule_quota_notify"),
    "ev.rule_quota_warn": ("exit", "rule_quota_warn"),
    "ev.rule_quota_reset": ("exit", "rule_quota_reset"),
    "ev.target_lost": ("server", "target_lost"),
    "ev.target_restarted": ("server", "target_restarted"),
    "ev.server_start_failed": ("server", "server_start_failed"),
    "ev.server_iface_gone": ("server", "server_iface_gone"),
    "ev.mem_high": ("system", "mem_high"),
    "ev.mem_ok": ("system", "mem_ok"),
    "ev.cpu_high": ("system", "cpu_high"),
    "ev.cpu_ok": ("system", "cpu_ok"),
    "ev.kernel_old": ("server", "kernel_old"),
    "ev.kernel_gone": ("server", "kernel_gone"),
    "ev.kernel_on": ("server", "kernel_on"),
    "ev.dom_strict_on": ("server", "dom_strict_on"),
    "ev.dom_strict_off": ("server", "dom_strict_off"),
    "ev.kernel_disabled": ("server", "kernel_disabled"),
    "ev.kernel_disabled_reboot": ("server", "kernel_disabled_reboot"),
    "ev.kernel_fallback": ("exit", "kernel_fallback"),
    "ev.kernel_conf": ("exit", "kernel_conf"),
    "ev.kernel_conf_i": ("exit", "kernel_conf_i"),
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

    def __init__(self, text: str, msg: Msg | None = None, net: bool = False, migrate_to: str | None = None,
                 code: int = 0):
        super().__init__(text)
        self.code = code                # error_code ответа Telegram (409 — бота читает кто-то ещё)
        self.msg = msg
        self.net = net
        self.migrate_to = migrate_to    # группа стала супергруппой: новый номер чата (ответ Telegram)


BACKUP_PERIODS = {"off": 0, "daily": 86400, "weekly": 7 * 86400}


def defaults() -> dict:
    # enabled — «Включить бот» (1.23.0): главный выключатель — уведомления, управление, клиенты и копии
    return {"enabled": False, "token": "", "chat_id": "", "lang": "en",
            "events": {k: k not in OFF_KINDS for k in KINDS},
            # как ходить к api.telegram.org: direct | up:<id> (через выход, если Telegram заблокирован)
            "via": "direct",
            # управление из Telegram: команды и кнопки (только из этого чата), см. tgbot.py
            "control": False,
            # выбранный путь не работает — запасные (1.23.0, включено у всех): «напрямую» → работающие выходы по
            # очереди; выход → другие выходы, напрямую никогда. Paths ниже
            "fallback": True,
            # клиенты открывают приглашение в бота и смотрят там свой доступ (1.22.0); бот читает сообщения и
            # при выключенном управлении. У установок до 1.22.0 без управления — выключено (store.CLIENT_BOT)
            "clients": True,
            # напоминания клиенту в его чат с ботом: срок скоро, 90% лимита, отключён, снова включён (1.22.0). С 1.23.0
            # идут вместе с clients (одна галочка); поле пишется так же, как clients, — для отката на 1.22.0
            "client_notify": True,
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
    # за один проход: «{date}» в имени клиента раньше заменялся датой следующего параметра
    body = re.sub(r"\{(\w+)\}", lambda m: str(params[m.group(1)]) if m.group(1) in params else m.group(0), body)
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


def get_via(route: tuple[int, int], url: str, timeout: float, limit: int) -> tuple[int, str, bool]:
    """GET из сети сервера AWG через туннель выхода (tgreq.py): списки сетей и доменов, если напрямую их
    не скачать. → (код, текст, framed — у ответа есть Content-Length или chunked)."""
    pid, mark = route
    head = json.dumps({"url": url, "method": "GET", "timeout": timeout, "limit": limit}).encode()
    try:
        p = subprocess.run(["nsenter", "-t", str(pid), "-n", "--", sys.executable, TGREQ, str(mark)],
                           input=head + b"\n", capture_output=True, timeout=timeout * 3 + 15)
    except subprocess.TimeoutExpired:
        raise OSError("timed out") from None
    try:
        res = json.loads(p.stdout.decode(errors="replace"))
    except ValueError:
        raise OSError((p.stderr or p.stdout).decode(errors="replace").strip()[:200] or "no answer") from None
    if res.get("err"):
        raise OSError(res["err"])
    return int(res.get("status") or 0), str(res.get("body") or ""), bool(res.get("framed"))


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


class Paths:
    """Запасные пути к Telegram (1.23.0, решение владельца 2026-11-19). Выбран «Напрямую» и не вышло — работающие
    выходы по очереди; выбран выход — другие работающие выходы, а напрямую никогда (раз выбрали выход, напрямую
    Telegram, скорее всего, закрыт, а попытка выдала бы, что сервер ходит в Telegram). Сработавший запасной путь
    держится: следующие запросы идут сначала им, выбранный пробуется снова раз в PATH_RETRY. Касается всего, что
    шлёт бот: уведомлений, управления, сообщений клиентам и копий."""

    def __init__(self):
        self.lock = threading.Lock()
        self.now: dict | None = None      # {"chosen": выбранный, "via": запасной, "since": когда перешли}

    def order(self, via: str, now: float | None = None) -> list[str]:
        if not (fallback_on and alt_routes):
            return [via]
        try:
            if not fallback_on():
                return [via]
            alts = [v for v in alt_routes(via) if v != via and v != "direct"]
        except Exception:  # noqa: BLE001
            log.exception("telegram paths")
            return [via]
        out = [via] + alts
        cur, now = self.now, time.time() if now is None else now
        if cur and cur["chosen"] == via and cur["via"] in alts and now - cur["since"] < PATH_RETRY:
            out = [cur["via"]] + [v for v in out if v != cur["via"]]
        return out

    def ok(self, via: str, used: str, now: float | None = None) -> None:
        """Запрос дошёл до Telegram путём used (выбран via)."""
        now = time.time() if now is None else now
        with self.lock:
            if used == via:
                self.now = None
            elif not (self.now and self.now["chosen"] == via and self.now["via"] == used
                      and now - self.now["since"] < PATH_RETRY):
                self.now = {"chosen": via, "via": used, "since": now}

    def view(self, via: str) -> dict | None:
        """Для браузера: бот сейчас идёт запасным путём ({"via": …}) или выбранным (None)."""
        cur = self.now
        return {"via": cur["via"], "since": cur["since"]} if cur and cur["chosen"] == via else None


paths = Paths()


def _post(token: str, method: str, data: bytes, ctype: str, timeout: float, via: str) -> dict:
    """Запрос к Bot API выбранным путём, а если он не работает — запасными (Paths). Ответил сам Telegram — отказ
    (токен, чат) или «слишком много запросов» и его сбой (429, 5xx: e.code) — сразу: путь до него работает, а другой путь
    тот же ответ и получит (проверка 1.23.0). Сбой на всех путях — ошибка выбранного: она лучше объясняет, что не так."""
    first = None
    order = paths.order(via)
    for v in order:
        try:
            res = _post_once(token, method, data, ctype, timeout, v)
        except NotifyError as e:
            if not e.net or e.code:
                paths.ok(via, v)
                raise
            first = first or e
            if v != via or len(order) > 1:
                log.warning("telegram via %s: %s", v, e)
            continue
        paths.ok(via, v)
        return res
    raise first or NotifyError("no route", net=True)


def _post_once(token: str, method: str, data: bytes, ctype: str, timeout: float, via: str) -> dict:
    url = f"{API}/bot{token}/{method}"
    route = router(via) if router and via and via != "direct" else None
    try:
        if route is None:
            code, raw = _post_direct(url, data, ctype, timeout)
        else:
            code, raw = _post_via(route, url, data, ctype, timeout)
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        # HTTPException — ответ оборвался (IncompleteRead) или не разобрался: та же сетевая ошибка. Раньше она
        # проходила мимо и в потоке бота (выключение меню команд) останавливала его до перезапуска панели
        raise NotifyError(f"api.telegram.org: {getattr(e, 'reason', e)!s}"[:300], net=True) from None
    try:
        res = json.loads(raw.decode(errors="replace") or "{}")
    except ValueError:
        res = None
    if not isinstance(res, dict):
        raise NotifyError(f"api.telegram.org: HTTP {code}", net=True)
    if not res.get("ok"):
        ec = res.get("error_code") or 0
        mig = (res.get("parameters") or {}).get("migrate_to_chat_id") if isinstance(res.get("parameters"), dict) else None
        raise NotifyError(str(res.get("description") or "Telegram error")[:300],
                          net=ec == 429 or (isinstance(ec, int) and ec >= 500),
                          migrate_to=str(mig) if isinstance(mig, int) and not isinstance(mig, bool) else None,
                          code=ec if isinstance(ec, int) else 0)
    return res.get("result") or {}


def _call(token: str, method: str, payload: dict | None = None, timeout: float = 15,
          via: str = "direct") -> dict:
    return _post(token, method, json.dumps(payload or {}).encode(), "application/json", timeout, via)


# Группа стала супергруппой — у чата новый номер, и Telegram отвечает на старый ошибкой с этим номером.
# on_migrate(старый, новый) запоминает новый номер в настройках (его ставит Notifier); отправка повторяется
# один раз уже на новый. Без этого уведомления молча переставали доходить.
on_migrate = None


def _migrated(chat_id: str, e: NotifyError) -> str | None:
    if not e.migrate_to or e.migrate_to == str(chat_id):
        return None
    if on_migrate:
        try:
            on_migrate(str(chat_id), e.migrate_to)
        except Exception:  # noqa: BLE001
            log.exception("telegram chat migration")
    return e.migrate_to


def send(token: str, chat_id: str, text: str, via: str = "direct", markup: dict | None = None,
         html: bool = False) -> dict:
    """sendMessage. markup — кнопки под сообщением (reply_markup), html — разметка HTML."""
    p = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    if markup:
        p["reply_markup"] = markup
    if html:
        p["parse_mode"] = "HTML"
    try:
        return _call(token, "sendMessage", p, via=via)
    except NotifyError as e:
        new = _migrated(chat_id, e)
        if not new:
            raise
        return _call(token, "sendMessage", {**p, "chat_id": new}, via=via)


def _send_file(method: str, field: str, token: str, chat_id: str, filename: str, data: bytes,
               caption: str, via: str, markup: dict | None = None, html: bool = False,
               ctype: str = "application/octet-stream") -> dict:
    """Файл multipart/form-data (urllib сам этого не умеет)."""
    try:
        return _send_file_once(method, field, token, chat_id, filename, data, caption, via, markup, html, ctype)
    except NotifyError as e:
        new = _migrated(chat_id, e)
        if not new:
            raise
        return _send_file_once(method, field, token, new, filename, data, caption, via, markup, html, ctype)


def _multipart(fields: list[tuple[str, str]], field: str, filename: str, data: bytes, ctype: str) -> tuple[bytes, str]:
    """Тело multipart/form-data: текстовые поля и один файл. Возвращает (тело, Content-Type)."""
    boundary = "awgr" + uuid.uuid4().hex
    parts = []
    for k, v in fields:
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
                 f'Content-Type: {ctype}\r\n\r\n'.encode() + data + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def _send_file_once(method: str, field: str, token: str, chat_id: str, filename: str, data: bytes,
                    caption: str, via: str, markup: dict | None, html: bool, ctype: str) -> dict:
    fields = [("chat_id", chat_id), ("caption", caption[:1000])]
    if markup:
        fields.append(("reply_markup", json.dumps(markup, ensure_ascii=False)))
    if html:
        fields.append(("parse_mode", "HTML"))
    body, btype = _multipart(fields, field, filename, data, ctype)
    return _post(token, method, body, btype, 120, via)


def send_document(token: str, chat_id: str, filename: str, data: bytes, caption: str,
                  via: str = "direct", markup: dict | None = None, html: bool = False) -> None:
    _send_file("sendDocument", "document", token, chat_id, filename, data, caption, via, markup, html)


def send_photo(token: str, chat_id: str, png: bytes, caption: str, via: str = "direct",
               html: bool = False, markup: dict | None = None, filename: str = "qr.png") -> dict:
    return _send_file("sendPhoto", "photo", token, chat_id, filename, png, caption, via, markup, html=html,
                      ctype="image/png")


def edit_photo(token: str, chat_id: str, message_id, png: bytes | None, caption: str, markup: dict | None,
               via: str = "direct", fid: str = "", filename: str = "card.png") -> dict:
    """editMessageMedia (1.24.0): другая картинка в том же сообщении — меню и «Состояние» бота. png — загрузить
    файл, fid — уже загруженный (file_id). Подпись — разметка HTML."""
    media = {"type": "photo", "media": fid or "attach://card", "caption": caption[:1000], "parse_mode": "HTML"}
    if fid:
        p = {"chat_id": chat_id, "message_id": message_id, "media": media}
        if markup:
            p["reply_markup"] = markup
        return _call(token, "editMessageMedia", p, via=via)
    fields = [("chat_id", str(chat_id)), ("message_id", str(message_id)),
              ("media", json.dumps(media, ensure_ascii=False))]
    if markup:
        fields.append(("reply_markup", json.dumps(markup, ensure_ascii=False)))
    body, btype = _multipart(fields, "card", filename, png or b"", "image/png")
    return _post(token, "editMessageMedia", body, btype, 120, via)


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


def chat_of(u: dict) -> dict | None:
    """Чат события getUpdates: {id, title} или None."""
    m = u.get("message") or u.get("channel_post") or u.get("my_chat_member") \
        or (u.get("callback_query") or {}).get("message") or {}
    ch = m.get("chat") if isinstance(m, dict) else None
    if not (isinstance(ch, dict) and "id" in ch):
        return None
    title = ch.get("title") or " ".join(x for x in (ch.get("first_name"), ch.get("last_name")) if x) \
        or ch.get("username") or ""
    return {"id": str(ch["id"]), "title": title}


def detect_chat(token: str, via: str = "direct", accept=None) -> dict | None:
    """Чат, из которого боту писали последним (чтобы не искать chat id вручную). accept(update) → чат или None —
    какие годятся (tgbot.Bot._seen: не нажатия кнопок и не чаты клиентов по приглашению); без него — любой."""
    upd = _call(token, "getUpdates", {"limit": 50, "timeout": 0}, via=via)
    for u in reversed(upd if isinstance(upd, list) else []):
        if ch := (accept or chat_of)(u):
            return ch
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
        self._state: dict[tuple, str] = {}        # (пара, выход или ресурс) → последнее отправленное состояние
        self.last_error: str | None = None
        self._target_lost = False
        # кнопки под уведомлением (tgbot.notify_buttons): (ключ текста, ссылки, язык) → reply_markup
        self.buttons_fn = None
        # напоминания клиентам (tgbot.Bot.remind): (ключ события, ключ клиента) — бот решает сам, кому и что
        self.client_fn = None
        global on_migrate
        on_migrate = self.migrate
        threading.Thread(target=self._worker, name="notify", daemon=True).start()

    def migrate(self, old: str, new: str) -> bool:
        """Чат из настроек стал супергруппой: новый номер — в настройки (только если там был старый)."""
        def fn(st):
            tg = st.setdefault("settings", {}).setdefault("telegram", {})
            if str(tg.get("chat_id") or "") != old:
                return False
            tg["chat_id"] = new
            return True
        done = self.store.mutate(fn)
        if done:
            log.warning("telegram: the group became a supergroup, chat %s → %s", old, new)
        return done

    def event(self, kind: str, key: str, cooldown: float | None = None, refs: dict | None = None,
              **params) -> None:
        """refs — к чему относится событие ({"pk": …} или {"uid": …}): для кнопок под ним."""
        st = self.store.snapshot()
        c = cfg_of(st)
        if not (c["enabled"] and c["token"] and c["chat_id"] and c["events"].get(kind)):
            return
        sig = key + json.dumps(params, sort_keys=True, default=str)
        now = time.time()
        # пара состояний («выход лёг» / «снова работает»): смена состояния после последнего отправленного
        # сообщения уходит всегда, иначе у «мигающего» выхода последним в чате осталось бы «снова работает»
        pair = STATE_PAIRS.get(key)
        subj = (pair, (refs or {}).get("uid") or params.get("name")) if pair else None
        last = self.__dict__.setdefault("_state", {})
        changed = subj is not None and last.get(subj, key) != key
        if now - self._sent.get(sig, 0) < (self.COOLDOWN if cooldown is None else cooldown) and not changed:
            return
        self._sent[sig] = now
        if subj is not None:
            last[subj] = key
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

    def report(self, kind: str, build) -> bool:
        """Сводка (итоги месяца, 1.24.0): build(язык бота) → текст. Как event — только при включённом боте и галочке
        kind, без кнопок и без защиты от повторов (её держит тот, кто зовёт). → поставлено ли в очередь."""
        st = self.store.snapshot()
        c = cfg_of(st)
        if not (c["enabled"] and c["token"] and c["chat_id"] and c["events"].get(kind)):
            return False
        try:
            host = self.host_fn(st)
        except Exception:  # noqa: BLE001
            host = ""
        try:
            self.q.put_nowait((c["token"], c["chat_id"], (f"AWG Router · {host}\n" if host else "AWG Router\n")
                               + build(c["lang"]), c["via"], None, time.time()))
        except queue.Full:
            log.warning("notify queue is full, message dropped")
            return False
        return True

    def engine_event(self, msg: Msg) -> None:
        """Событие движка (ev.*) → уведомление, если оно из нужных."""
        if msg.key == "ev.target_lost":
            if self._target_lost:
                return
            self._target_lost = True
        m = ENGINE_EVENTS.get(msg.key)
        if m:
            self.event(m[0], m[1], refs={k: v for k, v in msg.p.items() if k in ("pk", "uid")},
                       **{k: v for k, v in msg.p.items() if k in ("name", "gb", "to", "date", "days", "iface", "pct", "min", "version", "error", "n")})
        fn = getattr(self, "client_fn", None)
        if fn and msg.p.get("pk"):
            try:
                fn(msg.key, msg.p["pk"])
            except Exception:  # noqa: BLE001  — уведомление владельцу важнее напоминания клиенту
                log.exception("client reminder")

    def target_ok(self) -> None:
        if self._target_lost:
            self._target_lost = False
            self.event("server", "target_back")

    def deliver(self, token: str, chat: str, text: str, via: str, markup: dict | None) -> None:
        """Отправка выбранным путём; запасные пути (галочка «пробовать другие пути») — в _post (Paths), общие
        для всего, что шлёт бот. Сбой на всех путях — ошибка выбранного, отказ Telegram (токен, чат) — сразу."""
        send(token, chat, text, via, markup)

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
