"""Управление панелью из Telegram: команды и кнопки (включается в настройках уведомлений).

Бот слушает getUpdates (long polling) тем же путём, что и уведомления: напрямую или через
туннель выхода. Команды принимаются только из чата, указанного в настройках; всё остальное
молча пропускается. Удалять что-либо и менять параметры сервера из бота нельзя: токен бота —
это доступ к серверу, поэтому здесь только то, что легко вернуть назад.

Тексты бота уходят в Telegram, а не в браузер, поэтому, как и в notify.py, каталог на четырёх
языках лежит здесь (TEXTS). Действия из бота пишутся в журнал событий панели (tg.act_*).
"""
from __future__ import annotations

import html
import json
import logging
import math
import os
import threading
import time

from . import config, notify, qr
from .i18n import Msg

log = logging.getLogger("awgr.tgbot")

STATE = os.path.join(config.DATA_DIR, "tgbot.json")
POLL = 25                 # long polling: столько секунд Telegram держит запрос
PAGE = 8                  # клиентов на странице списка
ONLINE = 180              # handshake не старше — «в сети»
OLD = 600                 # сообщения старше (например, пока панель была выключена) не выполняем
ASK_TTL = 900             # сколько ждём ответа на «как назвать клиента?»
DAY = 86400
GB = 1024 ** 3
COMMANDS = ("status", "clients", "add", "exits", "route", "backup", "help")

TEXTS = {
    "ru": {
        "help": "🤖 <b>Пульт AWG Router</b>\n"
                "/status — сервер, клиенты и выходы\n"
                "/clients — клиенты: включить, выключить, QR, продлить\n"
                "/add — новый клиент\n"
                "/exits — выходы: проверить, сменить основной\n"
                "/route — куда пойдёт трафик до адреса или домена\n"
                "/backup — резервная копия сейчас",
        "cmd_status": "Сервер, клиенты и выходы", "cmd_clients": "Клиенты", "cmd_add": "Новый клиент",
        "cmd_exits": "Выходы", "cmd_route": "Куда пойдёт трафик до адреса",
        "cmd_backup": "Резервная копия сейчас", "cmd_help": "Что умеет бот",
        "b_status": "📊 Состояние", "b_clients": "👥 Клиенты", "b_exits": "🌐 Выходы",
        "b_route": "🧭 Маршрут", "kbd_menu": "☰ Меню",
        "kbd_off": "Управление из Telegram выключено в панели.",
        "b_add": "➕ Новый клиент", "b_backup": "💾 Копия", "b_list": "‹ Клиенты",
        "b_refresh": "🔄 Обновить", "b_on": "▶️ Включить", "b_off": "⏸ Выключить",
        "b_config": "📱 QR и файл", "b_share": "🔗 Личная ссылка", "b_days": "+30 дней",
        "b_gb": "+10 ГБ", "b_client": "👤 Клиент", "b_check": "🔍 Проверить «{name}»",
        "b_probe": "🔍 {name}", "b_default": "⭐ {name}", "b_direct": "⭐ Напрямую",
        "b_update": "⬆️ Обновить до {version}", "b_update_go": "✅ Да, обновить", "b_cancel": "Отмена",
        "st_server_ok": "Сервер AmneziaWG: ✅ работает", "st_server_bad": "Сервер AmneziaWG: ⚠️ недоступен",
        "st_clients": "Клиенты: {online} в сети из {total}",
        "st_month": "Трафик клиентов за месяц: {size}",
        "st_default": "Основной выход: {out}", "st_default_now": "Основной выход: {out}, сейчас: {now}",
        "st_exits": "Выходы:", "st_version": "Версия панели: {version}",
        "st_update": "Версия панели: {version}, доступна {latest}",
        "st_cert": "Сертификат HTTPS до {date}",
        "ex_title": "<b>🌐 Выходы</b>", "ex_up": "🟢 {name}", "ex_off": "⚪ {name} — выключен",
        "ex_down": "🔴 {name} — не работает, его трафик: {to}",
        "ex_quota": "📦 {name} — лимит исчерпан, его трафик: {to}",
        "ex_none": "Выходов пока нет: весь трафик идёт напрямую. Выходы добавляются в панели.",
        "ex_hint": "🔍 — проверить выход, ⭐ — сделать основным.",
        "o_direct": "напрямую", "o_block": "блокируется", "o_exit": "«{name}»",
        "cl_title": "<b>👥 Клиенты</b> · {n}", "cl_empty": "Клиентов пока нет.",
        "cl_legend": "🟢 в сети · ⚪ не в сети · ⏸ выключен",
        "cd_online": "🟢 В сети", "cd_seen": "⚪ Был в сети {ago} назад", "cd_never": "⚪ Ещё не подключался",
        "cd_off": "⏸ Выключен", "cd_off_exp": "⏸ Выключен: истёк срок",
        "cd_off_quota": "⏸ Выключен: исчерпан лимит трафика",
        "cd_ip": "Адрес в туннеле: {ip}", "cd_traffic": "Трафик: {month} за месяц, {total} всего",
        "cd_until": "Действует до {date}", "cd_quota_month": "Лимит: {used} из {quota} за месяц",
        "cd_quota_total": "Лимит: {used} из {quota} всего", "cd_exit": "Выход: {out}",
        "cd_app": "Создан в приложении AmneziaVPN: конфиг есть только на устройстве.",
        "ago_m": "{n} мин", "ago_h": "{n} ч", "ago_d": "{n} дн.",
        "u_mb": "МБ", "u_gb": "ГБ", "u_tb": "ТБ",
        "ok_on": "▶️ «{name}» включён", "ok_off": "⏸ «{name}» выключен",
        "ok_days": "✅ «{name}» действует до {date}", "ok_gb": "✅ «{name}»: лимит {gb} ГБ",
        "cfg_caption": "<b>{name}</b>: отсканируйте QR в AmneziaWG или AmneziaVPN или импортируйте файл.",
        "cfg_link": "Ключ для приложения AmneziaVPN (вставьте его при добавлении сервера):",
        "cfg_qr_big": "Конфиг слишком длинный для QR-кода — используйте файл.",
        "share": "🔗 Личная ссылка <b>{name}</b>:\n{url}\n\nПо ней можно скачать конфиг, отсканировать QR и "
                 "посмотреть свой трафик без входа в панель.",
        "add_ask": "Как назвать нового клиента? Ответьте на это сообщение именем.",
        "add_ok": "✅ Клиент <b>{name}</b> создан.",
        "rt_ask": "Какой IP-адрес или домен проверить? Ответьте на это сообщение.",
        "rt_res": "🧭 {target} ({ip}) → {out}", "rt_res_ip": "🧭 {ip} → {out}",
        "rt_rule": "Правило: список {list} ({net})", "rt_default": "Ни одно правило не подошло: основной выход",
        "rt_now": "Сейчас: {out} (выход не работает)", "rt_local": "Локальный адрес: через выходы не идёт.",
        "rt_bad": "Это не похоже на IPv4-адрес или домен.", "rt_v6": "IPv6 внутри туннеля не маршрутизируется.",
        "pr_wait": "Проверяю «{name}»…", "pr_ok": "🔍 «{name}»: выход в интернет с {ip} {cc}, {ms} мс",
        "pr_fail": "🔍 «{name}» не отвечает: {error}",
        "df_ok": "⭐ Основной выход: {out}",
        "bk_wait": "Готовлю копию…", "bk_fail": "⚠️ Копия не отправлена: {error}",
        "up_ask": "Обновить панель до {version}? Она перезапустится, это займёт несколько минут. "
                  "Когда панель вернётся, бот напишет.",
        "up_started": "⬆️ Обновляю до {version}…", "up_none": "Новой версии нет: {version} — последняя.",
        "up_done": "✅ Панель обновлена до {version}.",
        "up_failed": "⚠️ Обновление не удалось, работает версия {version}. Подробности — в панели, «Система».",
        "deny": "⛔ Нет доступа: бот выполняет команды только из чата, указанного в его панели.\nChat ID этого чата: <code>{chat}</code>. Если бот ваш, впишите этот номер в панели: «Система» → «Уведомления в Telegram» → Chat ID.", "deny_toast": "⛔ Нет доступа",
        "gone": "Такого клиента больше нет.", "gone_exit": "Такого выхода больше нет.",
        "fail": "⚠️ Не получилось: {error}", "cancelled": "Отменено.",
        "unknown": "Не знаю такой команды. /help — что я умею.",
    },
    "en": {
        "help": "🤖 <b>AWG Router remote</b>\n"
                "/status — server, clients and exits\n"
                "/clients — clients: turn on or off, QR, extend\n"
                "/add — new client\n"
                "/exits — exits: check, change the default\n"
                "/route — where traffic to an address or domain goes\n"
                "/backup — backup now",
        "cmd_status": "Server, clients and exits", "cmd_clients": "Clients", "cmd_add": "New client",
        "cmd_exits": "Exits", "cmd_route": "Where traffic to an address goes",
        "cmd_backup": "Backup now", "cmd_help": "What the bot can do",
        "b_status": "📊 Status", "b_clients": "👥 Clients", "b_exits": "🌐 Exits",
        "b_route": "🧭 Route", "kbd_menu": "☰ Menu",
        "kbd_off": "Control from Telegram is turned off in the panel.",
        "b_add": "➕ New client", "b_backup": "💾 Backup", "b_list": "‹ Clients",
        "b_refresh": "🔄 Refresh", "b_on": "▶️ Turn on", "b_off": "⏸ Turn off",
        "b_config": "📱 QR and file", "b_share": "🔗 Personal link", "b_days": "+30 days",
        "b_gb": "+10 GB", "b_client": "👤 Client", "b_check": "🔍 Check “{name}”",
        "b_probe": "🔍 {name}", "b_default": "⭐ {name}", "b_direct": "⭐ Direct",
        "b_update": "⬆️ Update to {version}", "b_update_go": "✅ Yes, update", "b_cancel": "Cancel",
        "st_server_ok": "AmneziaWG server: ✅ running", "st_server_bad": "AmneziaWG server: ⚠️ unreachable",
        "st_clients": "Clients: {online} online of {total}",
        "st_month": "Clients' traffic this month: {size}",
        "st_default": "Default exit: {out}", "st_default_now": "Default exit: {out}, now: {now}",
        "st_exits": "Exits:", "st_version": "Panel version: {version}",
        "st_update": "Panel version: {version}, {latest} is available",
        "st_cert": "HTTPS certificate until {date}",
        "ex_title": "<b>🌐 Exits</b>", "ex_up": "🟢 {name}", "ex_off": "⚪ {name} — turned off",
        "ex_down": "🔴 {name} — not working, its traffic: {to}",
        "ex_quota": "📦 {name} — limit used up, its traffic: {to}",
        "ex_none": "No exits yet: all traffic goes direct. Exits are added in the panel.",
        "ex_hint": "🔍 — check an exit, ⭐ — make it the default.",
        "o_direct": "direct", "o_block": "blocked", "o_exit": "“{name}”",
        "cl_title": "<b>👥 Clients</b> · {n}", "cl_empty": "No clients yet.",
        "cl_legend": "🟢 online · ⚪ offline · ⏸ turned off",
        "cd_online": "🟢 Online", "cd_seen": "⚪ Last seen {ago} ago", "cd_never": "⚪ Never connected",
        "cd_off": "⏸ Turned off", "cd_off_exp": "⏸ Turned off: access period ended",
        "cd_off_quota": "⏸ Turned off: traffic limit used up",
        "cd_ip": "Tunnel address: {ip}", "cd_traffic": "Traffic: {month} this month, {total} in all",
        "cd_until": "Access until {date}", "cd_quota_month": "Limit: {used} of {quota} this month",
        "cd_quota_total": "Limit: {used} of {quota} in all", "cd_exit": "Exit: {out}",
        "cd_app": "Created in the AmneziaVPN app: the config exists only on the device.",
        "ago_m": "{n} min", "ago_h": "{n} h", "ago_d": "{n} d",
        "u_mb": "MB", "u_gb": "GB", "u_tb": "TB",
        "ok_on": "▶️ “{name}” is on", "ok_off": "⏸ “{name}” is off",
        "ok_days": "✅ “{name}” works until {date}", "ok_gb": "✅ “{name}”: limit {gb} GB",
        "cfg_caption": "<b>{name}</b>: scan the QR code in AmneziaWG or AmneziaVPN, or import the file.",
        "cfg_link": "Key for the AmneziaVPN app (paste it when adding a server):",
        "cfg_qr_big": "The config is too long for a QR code — use the file.",
        "share": "🔗 Personal link for <b>{name}</b>:\n{url}\n\nIt lets them download the config, scan the QR "
                 "code and see their traffic without signing in to the panel.",
        "add_ask": "What should the new client be called? Reply to this message with a name.",
        "add_ok": "✅ Client <b>{name}</b> created.",
        "rt_ask": "Which IP address or domain should I check? Reply to this message.",
        "rt_res": "🧭 {target} ({ip}) → {out}", "rt_res_ip": "🧭 {ip} → {out}",
        "rt_rule": "Rule: list {list} ({net})", "rt_default": "No rule matched: the default exit",
        "rt_now": "Right now: {out} (the exit isn't working)", "rt_local": "A local address: it doesn't go through exits.",
        "rt_bad": "That doesn't look like an IPv4 address or a domain.", "rt_v6": "IPv6 isn't routed inside the tunnel.",
        "pr_wait": "Checking “{name}”…", "pr_ok": "🔍 “{name}”: internet via {ip} {cc}, {ms} ms",
        "pr_fail": "🔍 “{name}” doesn't answer: {error}",
        "df_ok": "⭐ Default exit: {out}",
        "bk_wait": "Preparing a backup…", "bk_fail": "⚠️ The backup wasn't sent: {error}",
        "up_ask": "Update the panel to {version}? It will restart, which takes a few minutes. "
                  "The bot will write when the panel is back.",
        "up_started": "⬆️ Updating to {version}…", "up_none": "No new version: {version} is the latest.",
        "up_done": "✅ The panel is updated to {version}.",
        "up_failed": "⚠️ The update failed; version {version} keeps running. Details are in the panel, System.",
        "deny": "⛔ No access: the bot runs commands only from the chat set in its panel.\nThis chat's Chat ID: <code>{chat}</code>. If the bot is yours, put this number in the panel: System → Telegram notifications → Chat ID.", "deny_toast": "⛔ No access",
        "gone": "This client no longer exists.", "gone_exit": "This exit no longer exists.",
        "fail": "⚠️ That didn't work: {error}", "cancelled": "Cancelled.",
        "unknown": "I don't know this command. /help — what I can do.",
    },
    "zh": {
        "help": "🤖 <b>AWG Router 遥控</b>\n"
                "/status — 服务器、客户端和出口\n"
                "/clients — 客户端：启用、停用、二维码、延期\n"
                "/add — 新建客户端\n"
                "/exits — 出口：检查、更换默认出口\n"
                "/route — 访问某地址或域名的流量走哪里\n"
                "/backup — 立即备份",
        "cmd_status": "服务器、客户端和出口", "cmd_clients": "客户端", "cmd_add": "新建客户端",
        "cmd_exits": "出口", "cmd_route": "访问某地址的流量走哪里",
        "cmd_backup": "立即备份", "cmd_help": "机器人能做什么",
        "b_status": "📊 状态", "b_clients": "👥 客户端", "b_exits": "🌐 出口",
        "b_route": "🧭 路由", "kbd_menu": "☰ 菜单",
        "kbd_off": "已在面板中关闭通过 Telegram 控制。",
        "b_add": "➕ 新建客户端", "b_backup": "💾 备份", "b_list": "‹ 客户端",
        "b_refresh": "🔄 刷新", "b_on": "▶️ 启用", "b_off": "⏸ 停用",
        "b_config": "📱 二维码和文件", "b_share": "🔗 个人链接", "b_days": "+30 天",
        "b_gb": "+10 GB", "b_client": "👤 客户端", "b_check": "🔍 检查“{name}”",
        "b_probe": "🔍 {name}", "b_default": "⭐ {name}", "b_direct": "⭐ 直连",
        "b_update": "⬆️ 更新到 {version}", "b_update_go": "✅ 是的，更新", "b_cancel": "取消",
        "st_server_ok": "AmneziaWG 服务器：✅ 运行中", "st_server_bad": "AmneziaWG 服务器：⚠️ 无法访问",
        "st_clients": "客户端：{total} 个中 {online} 个在线",
        "st_month": "客户端本月流量：{size}",
        "st_default": "默认出口：{out}", "st_default_now": "默认出口：{out}，当前：{now}",
        "st_exits": "出口：", "st_version": "面板版本：{version}",
        "st_update": "面板版本：{version}，可更新到 {latest}",
        "st_cert": "HTTPS 证书有效期至 {date}",
        "ex_title": "<b>🌐 出口</b>", "ex_up": "🟢 {name}", "ex_off": "⚪ {name} — 已停用",
        "ex_down": "🔴 {name} — 无法工作，其流量：{to}",
        "ex_quota": "📦 {name} — 限额已用完，其流量：{to}",
        "ex_none": "还没有出口：所有流量直连。出口在面板中添加。",
        "ex_hint": "🔍 — 检查出口，⭐ — 设为默认。",
        "o_direct": "直连", "o_block": "被阻止", "o_exit": "“{name}”",
        "cl_title": "<b>👥 客户端</b> · {n}", "cl_empty": "还没有客户端。",
        "cl_legend": "🟢 在线 · ⚪ 离线 · ⏸ 已停用",
        "cd_online": "🟢 在线", "cd_seen": "⚪ {ago}前在线", "cd_never": "⚪ 从未连接",
        "cd_off": "⏸ 已停用", "cd_off_exp": "⏸ 已停用：使用期限已到",
        "cd_off_quota": "⏸ 已停用：流量限额已用完",
        "cd_ip": "隧道地址：{ip}", "cd_traffic": "流量：本月 {month}，总计 {total}",
        "cd_until": "有效期至 {date}", "cd_quota_month": "限额：本月已用 {used}，共 {quota}",
        "cd_quota_total": "限额：总计已用 {used}，共 {quota}", "cd_exit": "出口：{out}",
        "cd_app": "在 AmneziaVPN 应用中创建：配置只存在于设备上。",
        "ago_m": "{n} 分钟", "ago_h": "{n} 小时", "ago_d": "{n} 天",
        "u_mb": "MB", "u_gb": "GB", "u_tb": "TB",
        "ok_on": "▶️ “{name}”已启用", "ok_off": "⏸ “{name}”已停用",
        "ok_days": "✅ “{name}”有效期至 {date}", "ok_gb": "✅ “{name}”：限额 {gb} GB",
        "cfg_caption": "<b>{name}</b>：在 AmneziaWG 或 AmneziaVPN 中扫描二维码，或导入文件。",
        "cfg_link": "AmneziaVPN 应用的密钥（添加服务器时粘贴）：",
        "cfg_qr_big": "配置太长，无法生成二维码——请使用文件。",
        "share": "🔗 <b>{name}</b> 的个人链接：\n{url}\n\n无需登录面板，即可通过它下载配置、扫描二维码并查看自己的流量。",
        "add_ask": "新客户端叫什么名字？请回复此消息并输入名称。",
        "add_ok": "✅ 客户端 <b>{name}</b> 已创建。",
        "rt_ask": "要检查哪个 IP 地址或域名？请回复此消息。",
        "rt_res": "🧭 {target}（{ip}）→ {out}", "rt_res_ip": "🧭 {ip} → {out}",
        "rt_rule": "规则：列表 {list}（{net}）", "rt_default": "没有匹配的规则：默认出口",
        "rt_now": "当前：{out}（该出口无法工作）", "rt_local": "本地地址：不经过出口。",
        "rt_bad": "这看起来不像 IPv4 地址或域名。", "rt_v6": "隧道内不路由 IPv6。",
        "pr_wait": "正在检查“{name}”…", "pr_ok": "🔍 “{name}”：经由 {ip} {cc} 访问互联网，{ms} 毫秒",
        "pr_fail": "🔍 “{name}”无响应：{error}",
        "df_ok": "⭐ 默认出口：{out}",
        "bk_wait": "正在准备备份…", "bk_fail": "⚠️ 备份未发送：{error}",
        "up_ask": "将面板更新到 {version}？面板会重启，需要几分钟。面板恢复后机器人会通知你。",
        "up_started": "⬆️ 正在更新到 {version}…", "up_none": "没有新版本：{version} 已是最新。",
        "up_done": "✅ 面板已更新到 {version}。",
        "up_failed": "⚠️ 更新失败，仍在运行 {version} 版本。详情见面板的“系统”。",
        "deny": "⛔ 无权访问：机器人只执行其面板中所设置聊天的命令。\n此聊天的 Chat ID：<code>{chat}</code>。如果这是你的机器人，请在面板中填写该号码：系统 → Telegram 通知 → Chat ID。", "deny_toast": "⛔ 无权访问",
        "gone": "该客户端已不存在。", "gone_exit": "该出口已不存在。",
        "fail": "⚠️ 操作失败：{error}", "cancelled": "已取消。",
        "unknown": "不认识这个命令。/help — 我能做什么。",
    },
    "fa": {
        "help": "🤖 <b>کنترل از راه دور AWG Router</b>\n"
                "/status — سرور، کلاینت‌ها و خروجی‌ها\n"
                "/clients — کلاینت‌ها: فعال و غیرفعال کردن، QR، تمدید\n"
                "/add — کلاینت تازه\n"
                "/exits — خروجی‌ها: بررسی، تغییر خروجی اصلی\n"
                "/route — ترافیک به یک نشانی یا دامنه از کجا می‌رود\n"
                "/backup — پشتیبان‌گیری همین حالا",
        "cmd_status": "سرور، کلاینت‌ها و خروجی‌ها", "cmd_clients": "کلاینت‌ها", "cmd_add": "کلاینت تازه",
        "cmd_exits": "خروجی‌ها", "cmd_route": "ترافیک به یک نشانی از کجا می‌رود",
        "cmd_backup": "پشتیبان‌گیری همین حالا", "cmd_help": "ربات چه کارهایی می‌کند",
        "b_status": "📊 وضعیت", "b_clients": "👥 کلاینت‌ها", "b_exits": "🌐 خروجی‌ها",
        "b_route": "🧭 مسیر", "kbd_menu": "☰ منو",
        "kbd_off": "کنترل از تلگرام در پنل خاموش شد.",
        "b_add": "➕ کلاینت تازه", "b_backup": "💾 پشتیبان", "b_list": "کلاینت‌ها ›",
        "b_refresh": "🔄 تازه‌سازی", "b_on": "▶️ فعال کردن", "b_off": "⏸ غیرفعال کردن",
        "b_config": "📱 QR و فایل", "b_share": "🔗 پیوند شخصی", "b_days": "+۳۰ روز",
        "b_gb": "+۱۰ گیگابایت", "b_client": "👤 کلاینت", "b_check": "🔍 بررسی «{name}»",
        "b_probe": "🔍 {name}", "b_default": "⭐ {name}", "b_direct": "⭐ مستقیم",
        "b_update": "⬆️ به‌روزرسانی به {version}", "b_update_go": "✅ بله، به‌روزرسانی کن", "b_cancel": "لغو",
        "st_server_ok": "سرور AmneziaWG: ✅ کار می‌کند", "st_server_bad": "سرور AmneziaWG: ⚠️ در دسترس نیست",
        "st_clients": "کلاینت‌ها: {online} آنلاین از {total}",
        "st_month": "ترافیک کلاینت‌ها در این ماه: {size}",
        "st_default": "خروجی اصلی: {out}", "st_default_now": "خروجی اصلی: {out}، اکنون: {now}",
        "st_exits": "خروجی‌ها:", "st_version": "نسخهٔ پنل: {version}",
        "st_update": "نسخهٔ پنل: {version}، نسخهٔ {latest} آماده است",
        "st_cert": "گواهی HTTPS تا {date}",
        "ex_title": "<b>🌐 خروجی‌ها</b>", "ex_up": "🟢 {name}", "ex_off": "⚪ {name} — خاموش",
        "ex_down": "🔴 {name} — کار نمی‌کند، ترافیک آن: {to}",
        "ex_quota": "📦 {name} — سقف تمام شده، ترافیک آن: {to}",
        "ex_none": "هنوز خروجی‌ای نیست: همهٔ ترافیک مستقیم می‌رود. خروجی‌ها در پنل اضافه می‌شوند.",
        "ex_hint": "🔍 — بررسی خروجی، ⭐ — خروجی اصلی کردن آن.",
        "o_direct": "مستقیم", "o_block": "مسدود", "o_exit": "«{name}»",
        "cl_title": "<b>👥 کلاینت‌ها</b> · {n}", "cl_empty": "هنوز کلاینتی نیست.",
        "cl_legend": "🟢 آنلاین · ⚪ آفلاین · ⏸ غیرفعال",
        "cd_online": "🟢 آنلاین", "cd_seen": "⚪ آخرین اتصال {ago} پیش", "cd_never": "⚪ هنوز وصل نشده",
        "cd_off": "⏸ غیرفعال", "cd_off_exp": "⏸ غیرفعال: مدت اعتبار تمام شد",
        "cd_off_quota": "⏸ غیرفعال: سقف ترافیک تمام شد",
        "cd_ip": "نشانی در تونل: {ip}", "cd_traffic": "ترافیک: {month} در این ماه، {total} در کل",
        "cd_until": "معتبر تا {date}", "cd_quota_month": "سقف: {used} از {quota} در این ماه",
        "cd_quota_total": "سقف: {used} از {quota} در کل", "cd_exit": "خروجی: {out}",
        "cd_app": "در برنامهٔ AmneziaVPN ساخته شده: پیکربندی فقط روی دستگاه است.",
        "ago_m": "{n} دقیقه", "ago_h": "{n} ساعت", "ago_d": "{n} روز",
        "u_mb": "مگابایت", "u_gb": "گیگابایت", "u_tb": "ترابایت",
        "ok_on": "▶️ «{name}» فعال شد", "ok_off": "⏸ «{name}» غیرفعال شد",
        "ok_days": "✅ «{name}» تا {date} معتبر است", "ok_gb": "✅ «{name}»: سقف {gb} گیگابایت",
        "cfg_caption": "<b>{name}</b>: QR را در AmneziaWG یا AmneziaVPN اسکن کنید یا فایل را وارد کنید.",
        "cfg_link": "کلید برای برنامهٔ AmneziaVPN (هنگام افزودن سرور آن را بچسبانید):",
        "cfg_qr_big": "پیکربندی برای QR بیش از حد بلند است — از فایل استفاده کنید.",
        "share": "🔗 پیوند شخصی <b>{name}</b>:\n{url}\n\nبا آن می‌توان بدون ورود به پنل پیکربندی را دریافت کرد، "
                 "QR را اسکن کرد و ترافیک خود را دید.",
        "add_ask": "نام کلاینت تازه چه باشد؟ در پاسخ به این پیام نام را بفرستید.",
        "add_ok": "✅ کلاینت <b>{name}</b> ساخته شد.",
        "rt_ask": "کدام نشانی IP یا دامنه بررسی شود؟ در پاسخ به این پیام بفرستید.",
        "rt_res": "🧭 {target} ({ip}) ← {out}", "rt_res_ip": "🧭 {ip} ← {out}",
        "rt_rule": "قانون: فهرست {list} ({net})", "rt_default": "هیچ قانونی جور نشد: خروجی اصلی",
        "rt_now": "اکنون: {out} (خروجی کار نمی‌کند)", "rt_local": "نشانی محلی: از خروجی‌ها نمی‌رود.",
        "rt_bad": "این شبیه نشانی IPv4 یا دامنه نیست.", "rt_v6": "IPv6 درون تونل مسیریابی نمی‌شود.",
        "pr_wait": "در حال بررسی «{name}»…", "pr_ok": "🔍 «{name}»: اینترنت از {ip} {cc}، {ms} میلی‌ثانیه",
        "pr_fail": "🔍 «{name}» پاسخ نمی‌دهد: {error}",
        "df_ok": "⭐ خروجی اصلی: {out}",
        "bk_wait": "در حال آماده کردن پشتیبان…", "bk_fail": "⚠️ پشتیبان فرستاده نشد: {error}",
        "up_ask": "پنل به {version} به‌روزرسانی شود؟ پنل دوباره راه‌اندازی می‌شود و چند دقیقه طول می‌کشد. "
                  "وقتی پنل برگردد، ربات خبر می‌دهد.",
        "up_started": "⬆️ در حال به‌روزرسانی به {version}…", "up_none": "نسخهٔ تازه‌ای نیست: {version} آخرین نسخه است.",
        "up_done": "✅ پنل به {version} به‌روزرسانی شد.",
        "up_failed": "⚠️ به‌روزرسانی انجام نشد؛ نسخهٔ {version} همچنان کار می‌کند. جزئیات در پنل، بخش سیستم.",
        "deny": "⛔ دسترسی ندارید: ربات فقط از چتی که در پنلش تعیین شده فرمان می‌برد.\nChat ID این چت: <code>{chat}</code>. اگر ربات مال شماست، این عدد را در پنل وارد کنید: سیستم ← اعلان‌های تلگرام ← Chat ID.", "deny_toast": "⛔ دسترسی ندارید",
        "gone": "این کلاینت دیگر وجود ندارد.", "gone_exit": "این خروجی دیگر وجود ندارد.",
        "fail": "⚠️ انجام نشد: {error}", "cancelled": "لغو شد.",
        "unknown": "این دستور را نمی‌شناسم. ‎/help — کارهایی که می‌کنم.",
    },
}


def tr(lang: str, key: str, html_safe: bool = True, **params) -> str:
    """Текст бота. Параметры экранируются для parse_mode=HTML (html_safe=False — для всплывающих
    подсказок, там разметки нет)."""
    tx = TEXTS.get(lang) or TEXTS["en"]
    s = tx.get(key) or TEXTS["en"][key]
    for k, v in params.items():
        v = str(v)
        s = s.replace("{" + k + "}", html.escape(v, quote=False) if html_safe else v)
    return s


def fmt_size(n: int | float, lang: str) -> str:
    n = float(n or 0)
    if n >= 1024 ** 4:
        v, u = n / 1024 ** 4, "u_tb"
    elif n >= GB:
        v, u = n / GB, "u_gb"
    else:
        v, u = n / 1024 ** 2, "u_mb"
    s = f"{v:.0f}" if v >= 100 or u == "u_mb" else f"{v:.1f}".rstrip("0").rstrip(".")
    if lang == "ru":
        s = s.replace(".", ",")
    return f"{s} {tr(lang, u)}"


def fmt_ago(sec: float, lang: str) -> str:
    sec = max(0, sec)
    if sec < 3600:
        return tr(lang, "ago_m", n=max(1, int(sec // 60)))
    if sec < 2 * DAY:
        return tr(lang, "ago_h", n=int(sec // 3600))
    return tr(lang, "ago_d", n=int(sec // DAY))


def fmt_date(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


# Клавиатура внизу экрана после /start: (текст, команда). Нажатие присылает текст кнопки.
MENU = (("b_status", "status"), ("b_clients", "clients"), ("b_exits", "exits"), ("b_add", "add"),
        ("b_route", "route"), ("b_backup", "backup"))
DENY_EVERY = 600          # «нет доступа» в один и тот же чужой чат — не чаще раза в 10 минут


def menu_action(text: str) -> str | None:
    """Кнопка клавиатуры → команда. Надписи на всех языках: язык могли сменить после её отправки;
    «☰ Меню» — кнопка из 1.10.0."""
    for tx in TEXTS.values():
        if text == tx["kbd_menu"]:
            return "menu"
        for key, cmd in MENU:
            if text == tx[key]:
                return cmd
    return None


def kb(*rows) -> dict:
    """Кнопки: строки из пар (текст, данные). Пустые строки пропускаются."""
    return {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in rows if row]}


def notify_buttons(key: str, p: dict, lang: str) -> dict | None:
    """Кнопки под уведомлением (notify.Notifier.buttons_fn)."""
    pk, uid = p.get("pk"), p.get("uid")
    if key == "exit_down" and uid:
        return kb([(tr(lang, "b_check", False, name=p.get("name", "")), "pr:" + uid)],
                  [(tr(lang, "b_exits"), "ex")])
    if key.startswith("exit_quota") and uid:
        return kb([(tr(lang, "b_exits"), "ex")])
    if key in ("client_expired", "client_expiring") and pk:
        return kb([(tr(lang, "b_days"), "d30:" + pk), (tr(lang, "b_client"), "c:" + pk)])
    if key in ("client_quota", "client_quota_warn") and pk:
        return kb([(tr(lang, "b_gb"), "g10:" + pk), (tr(lang, "b_client"), "c:" + pk)])
    if key in ("client_quota_reset", "client_first") and pk:
        return kb([(tr(lang, "b_client"), "c:" + pk)])
    if key == "update_available" and p.get("version"):
        return kb([(tr(lang, "b_update", False, version=p["version"]), "up")])
    if key in ("target_lost", "server_start_failed", "target_restarted"):
        return kb([(tr(lang, "b_status"), "st")])
    return None


class BotError(Exception):
    """Ошибка действия, понятная человеку: ключ текста бота и параметры."""

    def __init__(self, key: str, **params):
        super().__init__(key)
        self.key, self.params = key, params


class Bot:
    """Цикл getUpdates и разбор команд. ops — действия панели (их собирает main.py):
    тот же код, что за кнопками в браузере."""

    def __init__(self, store, ops, stop_ev: threading.Event | None = None):
        self.store = store
        self.ops = ops
        self.stop_ev = stop_ev or threading.Event()
        self.wake = threading.Event()
        self.state = "off"                     # off | ok | error
        self.error = None                      # str | Msg — последняя ошибка опроса
        self.last_cmd: float | None = None
        self._ask: dict | None = None          # ждём ответа: {"kind": add|route, "msg": id, "t": …}
        self._panel_msgs: list[int] = []       # сообщения меню/списков: их можно редактировать
        self._denied: dict[str, float] = {}       # чужой чат → когда ответили «нет доступа»
        self._webhook_dropped = False
        self._st = self._load()

    # ------------------------------------------------------------- состояние
    def _load(self) -> dict:
        try:
            with open(STATE) as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        try:
            with open(STATE + ".tmp", "w") as f:
                json.dump(self._st, f)
            os.replace(STATE + ".tmp", STATE)
        except OSError as e:
            log.warning("tgbot state: %s", e)

    def view(self) -> dict:
        skew = notify.clock_skew
        return {"state": self.state, "error": self.error, "last": self.last_cmd,
                # часы сервера сбиты: на это стоит обратить внимание (вход по коду тоже от них зависит)
                "skew": round(skew) if abs(skew) >= 120 else None}

    def _foreign(self, chat: dict, c: dict, qid: str = "") -> None:
        """Команда из чата, которого нет в настройках: не выполняем. В личном чате отвечаем
        «нет доступа» и номером этого чата — чтобы владелец сразу видел, что вписать в панель."""
        cid = str(chat.get("id", ""))
        log.info("telegram: a command from chat %s is not run: the panel listens to chat %s", cid, c.get("chat_id"))
        if qid:
            self._toast(c, qid, tr(c["lang"], "deny_toast", False))
        if chat.get("type") != "private" or time.time() - self._denied.get(cid, 0) < DENY_EVERY:
            return
        self._denied[cid] = time.time()
        try:
            notify.send(c["token"], cid, tr(c["lang"], "deny", chat=cid), c["via"],
                        {"remove_keyboard": True}, html=True)
        except notify.NotifyError as e:
            log.info("telegram: %s", e)

    def start(self) -> None:
        threading.Thread(target=self._loop, name="tgbot", daemon=True).start()

    # ------------------------------------------------------------- опрос
    def _loop(self) -> None:
        while not self.stop_ev.is_set():
            c = notify.cfg_of(self.store.snapshot())
            # управление не зависит от уведомлений: можно командовать ботом и без них
            if not (c["token"] and c["chat_id"] and c["control"]):
                self.state, self.error = "off", None
                self._drop_commands(c)
                self.wake.wait(10)
                self.wake.clear()
                continue
            try:
                self.poll_once(c)
                self.state, self.error = "ok", None
            except notify.NotifyError as e:
                if "webhook" in str(e).lower() and self._drop_webhook(c):
                    continue
                self.state, self.error = "error", e.msg or str(e)
                log.warning("telegram bot: %s", e)
                self.wake.wait(30)
                self.wake.clear()
            except Exception as e:  # noqa: BLE001
                self.state, self.error = "error", str(e)[:300]
                log.exception("telegram bot")
                self.wake.wait(30)
                self.wake.clear()

    def poll_once(self, c: dict, timeout: int = POLL) -> None:
        self._set_commands(c)
        self._announce_update(c)
        ups = notify._call(c["token"], "getUpdates",
                           {"offset": int(self._st.get("offset") or 0), "timeout": timeout,
                            "allowed_updates": ["message", "callback_query"]},
                           timeout=timeout + 15, via=c["via"])
        for u in ups if isinstance(ups, list) else []:
            # отметку сохраняем до выполнения: после перезапуска команда не повторится
            self._st["offset"] = int(u.get("update_id", 0)) + 1
            self._save()
            try:
                self.handle(u, c)
            except Exception:  # noqa: BLE001
                log.exception("telegram update")

    def _drop_webhook(self, c: dict) -> bool:
        """На токене висит webhook (бота раньше подключали к другому сервису): пока он есть,
        Telegram не отдаёт команды через getUpdates. Управление включили в панели — значит,
        бот теперь её: снимаем webhook один раз. True — сняли, можно опрашивать снова."""
        if self._webhook_dropped:
            return False
        self._webhook_dropped = True
        try:
            notify._call(c["token"], "deleteWebhook", {"drop_pending_updates": False}, via=c["via"])
        except notify.NotifyError as e:
            log.warning("telegram: deleteWebhook: %s", e)
            return False
        log.warning("telegram: the bot had a webhook set by another service; removed it to receive commands")
        return True

    def _set_commands(self, c: dict) -> None:
        sig = f'{c["token"][:12]}|{c["lang"]}'
        if self._st.get("cmds") == sig:
            return
        cmds = [{"command": k, "description": tr(c["lang"], "cmd_" + k, False)} for k in COMMANDS]
        notify._call(c["token"], "setMyCommands", {"commands": cmds}, via=c["via"])
        self._st["cmds"] = sig
        self._save()

    def _drop_commands(self, c: dict) -> None:
        """Управление выключили — убираем меню команд и кнопку «Меню», чтобы бот не обещал лишнего."""
        if not (self._st.get("cmds") or self._st.get("kbd")) or not c["token"]:
            return
        try:
            notify._call(c["token"], "deleteMyCommands", {}, via=c["via"])
            if self._st.get("kbd") and c["chat_id"]:
                self._send(c, tr(c["lang"], "kbd_off"), {"remove_keyboard": True})
        except notify.NotifyError as e:
            log.info("telegram: %s", e)
        self._st.pop("cmds", None)
        self._st.pop("kbd", None)
        self._save()

    def _announce_update(self, c: dict) -> None:
        """После обновления, запущенного из бота, — сообщить, чем оно кончилось."""
        a = self._st.get("update")
        if not a:
            return
        s = self.ops.update_state()
        if s.get("state") == "running" and time.time() - a.get("t", 0) < 3600:
            return
        self._st.pop("update", None)
        self._save()
        if s.get("state") == "done" and self.ops.version == a.get("to"):
            self._send(c, tr(c["lang"], "up_done", version=self.ops.version))
        elif s.get("state") in ("failed", "done"):
            self._send(c, tr(c["lang"], "up_failed", version=self.ops.version))

    # ------------------------------------------------------------- отправка
    def _send(self, c: dict, text: str, markup: dict | None = None, panel: bool = False) -> dict:
        r = notify.send(c["token"], c["chat_id"], text, c["via"], markup, html=True)
        if panel and isinstance(r, dict) and r.get("message_id"):
            self._panel_msgs = (self._panel_msgs + [r["message_id"]])[-20:]
        return r

    def _show(self, c: dict, text: str, markup: dict | None, msg: dict | None) -> None:
        """Меню и списки: если нажали кнопку в таком же сообщении — меняем его на месте."""
        mid = (msg or {}).get("message_id")
        if mid and mid in self._panel_msgs:
            p = {"chat_id": c["chat_id"], "message_id": mid, "text": text, "parse_mode": "HTML",
                 "disable_web_page_preview": True, "reply_markup": markup or {"inline_keyboard": []}}
            try:
                notify._call(c["token"], "editMessageText", p, via=c["via"])
                return
            except notify.NotifyError as e:
                if "not modified" in str(e):
                    return
        self._send(c, text, markup, panel=True)

    def _toast(self, c: dict, qid: str, text: str = "") -> None:
        try:
            notify._call(c["token"], "answerCallbackQuery",
                         {"callback_query_id": qid, "text": text[:190]}, via=c["via"])
        except notify.NotifyError:
            pass       # кнопку нажали давно — подсказка уже не нужна

    # ------------------------------------------------------------- разбор
    @staticmethod
    def allowed(chat: dict, c: dict) -> bool:
        want = str(c.get("chat_id") or "")
        if not want or not chat:
            return False
        if str(chat.get("id")) == want:
            return True
        un = chat.get("username")
        return bool(un) and want.startswith("@") and want[1:].lower() == un.lower()

    def handle(self, u: dict, c: dict) -> None:
        if "callback_query" in u:
            q = u["callback_query"]
            msg = q.get("message") or {}
            if not self.allowed(msg.get("chat") or {}, c):
                if msg.get("chat"):
                    self._foreign(msg["chat"], c, q.get("id", ""))
                return
            self.last_cmd = time.time()
            self.on_button(c, str(q.get("data") or ""), q.get("id", ""), msg)
            return
        m = u.get("message") or {}
        if (m.get("from") or {}).get("is_bot") or not m.get("chat"):
            return
        if not self.allowed(m["chat"], c):
            if (m.get("text") or "").startswith("/") or menu_action((m.get("text") or "").strip()):
                self._foreign(m["chat"], c)
            return
        # возраст — по часам Telegram (Date его ответа), а не сервера: те бывают сбиты
        age = time.time() - notify.clock_skew - (m.get("date") or 0)
        if m.get("date") and age > OLD:
            log.info("telegram: a message from %d s ago is skipped (sent while the panel was off)", int(age))
            return
        text = (m.get("text") or "").strip()
        if not text:
            return
        self.last_cmd = time.time()
        action = menu_action(text)
        if action:
            self._ask = None
            self.on_command(c, action, "")
            return
        if text.startswith("/"):
            cmd, _, arg = text[1:].partition(" ")
            self._ask = None
            self.on_command(c, cmd.split("@", 1)[0].lower(), arg.strip())
            return
        ask = self._ask
        reply_to = (m.get("reply_to_message") or {}).get("message_id")
        if ask and time.time() - ask["t"] < ASK_TTL and (reply_to in (None, ask["msg"])):
            self._ask = None
            if ask["kind"] == "add":
                self.do_add(c, text)
            else:
                self.do_route(c, text)
            return
        self.on_command(c, "help", "")

    def _guard(self, c: dict, fn, *args) -> None:
        try:
            fn(c, *args)
        except BotError as e:
            self._send(c, tr(c["lang"], e.key, **e.params))
        except Exception as e:  # noqa: BLE001
            log.warning("telegram action: %s", e)
            self._send(c, tr(c["lang"], "fail", error=self._err(e)))

    @staticmethod
    def _err(e) -> str:
        """Ошибка для человека. Ключи панели переводит браузер, здесь — ключ и подробности."""
        m = e if isinstance(e, Msg) else getattr(e, "detail", None) or getattr(e, "msg", None)
        if isinstance(m, Msg):
            extra = m.p.get("error") or m.p.get("detail") or ""
            return f"{m.key} {extra}".strip()[:300]
        return str(e)[:300]

    def on_command(self, c: dict, cmd: str, arg: str) -> None:
        if cmd in ("start", "help", "menu"):
            self._send(c, tr(c["lang"], "help"), self._keyboard(c))
        elif cmd == "status":
            self._guard(c, self.show_status, None)
        elif cmd == "clients":
            self._guard(c, self.show_clients, 0, None)
        elif cmd == "exits":
            self._guard(c, self.show_exits, None)
        elif cmd == "add":
            if arg:
                self._guard(c, self.do_add, arg)
            else:
                self.ask(c, "add")
        elif cmd == "route":
            if arg:
                self._guard(c, self.do_route, arg)
            else:
                self.ask(c, "route")
        elif cmd == "backup":
            self._guard(c, self.do_backup)
        else:
            self._send(c, tr(c["lang"], "unknown"), self._keyboard(c))

    def ask(self, c: dict, kind: str) -> None:
        r = notify.send(c["token"], c["chat_id"], tr(c["lang"], "add_ask" if kind == "add" else "rt_ask"),
                        c["via"], {"force_reply": True, "input_field_placeholder": "…"}, html=True)
        self._ask = {"kind": kind, "msg": (r or {}).get("message_id"), "t": time.time()}

    def on_button(self, c: dict, data: str, qid: str, msg: dict) -> None:
        L = c["lang"]
        op, _, arg = data.partition(":")
        toast = ""
        try:
            if op == "m":                      # «‹ Меню» в старых сообщениях: меню теперь внизу
                self._show(c, tr(L, "help"), None, msg)
            elif op == "st":
                self.show_status(c, msg)
            elif op == "cl":
                self.show_clients(c, int(arg or 0), msg)
            elif op == "c":
                self.show_client(c, arg, msg)
            elif op in ("on", "off"):
                cl = self._client(arg)
                self.ops.set_enabled(arg, op == "on")
                self.ops.audit(Msg("tg.act_" + op, name=self._name(cl)))
                toast = tr(L, "ok_" + op, False, name=self._name(cl))
                self.show_client(c, arg, msg)
            elif op == "d30":
                toast = self.do_days(c, arg)
                self.show_client(c, arg, msg)
            elif op == "g10":
                toast = self.do_gb(c, arg)
                self.show_client(c, arg, msg)
            elif op == "cfg":
                self._toast(c, qid)
                qid = ""
                self.send_config(c, arg)
            elif op == "sh":
                self.do_share(c, arg)
            elif op == "add":
                self.ask(c, "add")
            elif op == "rt":
                self.ask(c, "route")
            elif op == "ex":
                self.show_exits(c, msg)
            elif op == "pr":
                self._toast(c, qid, tr(L, "pr_wait", False, name=self._exit_name(arg)))
                qid = ""
                self.do_probe(c, arg)
            elif op == "df":
                toast = self.do_default(c, arg)
                self.show_exits(c, msg)
            elif op == "bk":
                self._toast(c, qid, tr(L, "bk_wait", False))
                qid = ""
                self.do_backup(c)
            elif op == "up":
                self.ask_update(c)
            elif op == "upgo":
                self.do_update(c)
            elif op == "x":
                toast = tr(L, "cancelled", False)
        except BotError as e:
            toast = tr(L, e.key, False, **e.params)
            if not qid:              # на кнопку уже ответили — ошибку пишем сообщением
                self._send(c, tr(L, e.key, **e.params))
        except Exception as e:  # noqa: BLE001
            log.warning("telegram button %s: %s", op, e)
            toast = tr(L, "fail", False, error=self._err(e))
            if not qid:
                self._send(c, tr(L, "fail", error=self._err(e)))
        if qid:
            self._toast(c, qid, toast)

    # ------------------------------------------------------------- экраны
    def _keyboard(self, c: dict) -> dict:
        """Всё меню на клавиатуре внизу экрана: остаётся там, пока его не уберут."""
        L = c["lang"]
        names = [tr(L, key) for key, _ in MENU]
        self._st["kbd"] = L
        self._save()
        return {"keyboard": [[{"text": n} for n in names[i:i + 2]] for i in range(0, len(names), 2)],
                "resize_keyboard": True, "is_persistent": True}

    def out_label(self, c: dict, out, st: dict) -> str:
        """Выход из настроек ('direct' | 'block' | 'up:<id>') или фактический (номер туннеля)."""
        L = c["lang"]
        if out == "direct":
            return tr(L, "o_direct")
        if out == "block":
            return tr(L, "o_block")
        for u in st.get("upstreams", []):
            if out == "up:" + u["id"] or out == u.get("num"):
                return tr(L, "o_exit", name=u["name"])
        return str(out)

    def show_status(self, c: dict, msg: dict | None) -> None:
        L = c["lang"]
        st = self.ops.snapshot()
        s = self.ops.status()
        lines = [f"<b>📊 {html.escape(s.get('host') or 'AWG Router')}</b>",
                 tr(L, "st_server_ok" if s.get("server_ok") else "st_server_bad")]
        clients = self.ops.clients()
        now = time.time()
        online = sum(1 for x in clients if self._online(x, now))
        lines.append(tr(L, "st_clients", online=online, total=len(clients)))
        lines.append(tr(L, "st_month", size=fmt_size(s.get("month_bytes", 0), L)))
        d = st["routing"]["default"]
        eff = self.ops.resolve(d, st)
        want, now_l = self.out_label(c, d, st), self.out_label(c, eff, st)
        if d.startswith("up:") and (_tunnel_num(st, d) != eff):
            lines.append(tr(L, "st_default_now", out=want, now=now_l))
        else:
            lines.append(tr(L, "st_default", out=want))
        if st.get("upstreams"):
            lines.append("")
            lines.append(tr(L, "st_exits"))
            lines += [self._exit_line(c, u, st) for u in st["upstreams"]]
        lines.append("")
        v = s.get("version") or {}
        if v.get("available") and v.get("latest"):
            lines.append(tr(L, "st_update", version=v.get("current"), latest=v["latest"]))
        else:
            lines.append(tr(L, "st_version", version=v.get("current", self.ops.version)))
        if s.get("cert_until"):
            lines.append(tr(L, "st_cert", date=fmt_date(s["cert_until"])))
        # меню — на клавиатуре внизу; здесь только то, что относится к этому сообщению
        rows = [[(tr(L, "b_refresh"), "st")]]
        if v.get("available") and v.get("latest"):
            rows.append([(tr(L, "b_update", False, version=v["latest"]), "up")])
        self._show(c, "\n".join(lines), kb(*rows), msg)

    def _exit_line(self, c: dict, u: dict, st: dict) -> str:
        L = c["lang"]
        h = self.ops.health(u["id"])
        if not u.get("enabled", True):
            return tr(L, "ex_off", name=u["name"])
        eff = self.ops.resolve("up:" + u["id"], st)
        to = self.out_label(c, eff, st)
        if h.get("healthy"):
            if self.ops.over_quota(u):
                return tr(L, "ex_quota", name=u["name"], to=to)
            return tr(L, "ex_up", name=u["name"])
        return tr(L, "ex_down", name=u["name"], to=to)

    @staticmethod
    def _online(x: dict, now: float) -> bool:
        hs = (x.get("live") or {}).get("handshake") or 0
        return bool(x.get("enabled")) and hs > 0 and now - hs < ONLINE

    @staticmethod
    def _name(x: dict) -> str:
        return x.get("name") or x.get("ip") or x["public_key"][:8]

    def _icon(self, x: dict, now: float) -> str:
        if not x.get("enabled"):
            return "⏸"
        return "🟢" if self._online(x, now) else "⚪"

    def show_clients(self, c: dict, page: int, msg: dict | None) -> None:
        L = c["lang"]
        clients = sorted(self.ops.clients(), key=lambda x: self._name(x).casefold())
        if not clients:
            self._show(c, tr(L, "cl_empty"), None, msg)
            return
        pages = max(1, math.ceil(len(clients) / PAGE))
        page = min(max(0, page), pages - 1)
        now = time.time()
        rows = []
        for x in clients[page * PAGE:(page + 1) * PAGE]:
            month = self.ops.traffic_month(x["public_key"])
            rows.append([(f"{self._icon(x, now)} {self._name(x)} · {fmt_size(month, L)}",
                          "c:" + x["public_key"])])
        if pages > 1:
            nav = []
            if page > 0:
                nav.append(("‹", f"cl:{page - 1}"))
            nav.append((f"{page + 1}/{pages}", f"cl:{page}"))
            if page < pages - 1:
                nav.append(("›", f"cl:{page + 1}"))
            rows.append(nav)
        text = tr(L, "cl_title", n=len(clients)) + "\n" + tr(L, "cl_legend")
        self._show(c, text, kb(*rows), msg)

    def _client(self, pk: str) -> dict:
        x = next((x for x in self.ops.clients() if x["public_key"] == pk), None)
        if not x:
            raise BotError("gone")
        return x

    def show_client(self, c: dict, pk: str, msg: dict | None) -> None:
        L = c["lang"]
        x = self._client(pk)
        st = self.ops.snapshot()
        lim = (st.get("limits") or {}).get(pk) or {}
        now = time.time()
        lines = [f"<b>{html.escape(self._name(x))}</b>"]
        if not x.get("enabled"):
            ao = lim.get("auto_off") or ""
            lines.append(tr(L, "cd_off_exp" if ao == "exp" else "cd_off_quota" if ao.startswith("quota:")
                            else "cd_off"))
        elif self._online(x, now):
            lines.append(tr(L, "cd_online"))
        else:
            hs = (x.get("live") or {}).get("handshake") or 0
            lines.append(tr(L, "cd_seen", ago=fmt_ago(now - hs, L)) if hs else tr(L, "cd_never"))
        lines.append(tr(L, "cd_ip", ip=x.get("ip") or "—"))
        tv = self.ops.traffic_view(pk)
        lines.append(tr(L, "cd_traffic", month=fmt_size(tv.get("month_rx", 0) + tv.get("month_tx", 0), L),
                        total=fmt_size(tv.get("total_rx", 0) + tv.get("total_tx", 0), L)))
        if lim.get("expires"):
            lines.append(tr(L, "cd_until", date=fmt_date(lim["expires"])))
        if lim.get("quota"):
            period = lim.get("period") or "month"
            lines.append(tr(L, "cd_quota_" + period, used=fmt_size(self.ops.used(pk, period), L),
                            quota=fmt_size(lim["quota"], L)))
        lines.append(tr(L, "cd_exit", out=self.out_label(c, self.ops.client_out(pk), st)))
        if not x.get("has_config"):
            lines.append("")
            lines.append(tr(L, "cd_app"))
        row1 = [(tr(L, "b_off"), "off:" + pk) if x.get("enabled") else (tr(L, "b_on"), "on:" + pk)]
        if x.get("has_config"):
            row1.append((tr(L, "b_config"), "cfg:" + pk))
        row2 = [(tr(L, "b_share"), "sh:" + pk)]
        row3 = []
        if lim.get("expires"):
            row3.append((tr(L, "b_days"), "d30:" + pk))
        if lim.get("quota"):
            row3.append((tr(L, "b_gb"), "g10:" + pk))
        self._show(c, "\n".join(lines), kb(row1, row2, row3, [(tr(L, "b_list"), "cl:0")]), msg)

    def show_exits(self, c: dict, msg: dict | None) -> None:
        L = c["lang"]
        st = self.ops.snapshot()
        ups = st.get("upstreams") or []
        if not ups:
            self._show(c, tr(L, "ex_title") + "\n\n" + tr(L, "ex_none"), None, msg)
            return
        d = st["routing"]["default"]
        lines = [tr(L, "ex_title"), tr(L, "st_default", out=self.out_label(c, d, st)), ""]
        lines += [self._exit_line(c, u, st) for u in ups]
        lines += ["", tr(L, "ex_hint")]
        rows = []
        for u in ups:
            row = [(tr(L, "b_probe", False, name=u["name"]), "pr:" + u["id"])]
            if d != "up:" + u["id"]:
                row.append((tr(L, "b_default", False, name=u["name"]), "df:up:" + u["id"]))
            rows.append(row)
        if d != "direct":
            rows.append([(tr(L, "b_direct"), "df:direct")])
        rows.append([(tr(L, "b_refresh"), "ex")])
        self._show(c, "\n".join(lines), kb(*rows), msg)

    # ------------------------------------------------------------- действия
    def do_days(self, c: dict, pk: str) -> str:
        x = self._client(pk)
        L = (self.ops.snapshot().get("limits") or {}).get(pk) or {}
        exp = int(max(time.time(), L.get("expires") or 0) + 30 * DAY)
        self.ops.apply_limits(pk, exp, L.get("quota"), L.get("period") or "month")
        self.ops.audit(Msg("tg.act_days", name=self._name(x), date=fmt_date(exp)))
        return tr(c["lang"], "ok_days", False, name=self._name(x), date=fmt_date(exp))

    def do_gb(self, c: dict, pk: str) -> str:
        x = self._client(pk)
        L = (self.ops.snapshot().get("limits") or {}).get(pk) or {}
        quota = int((L.get("quota") or 0) + 10 * GB)
        self.ops.apply_limits(pk, L.get("expires"), quota, L.get("period") or "month")
        gb = f"{quota / GB:.3g}"
        self.ops.audit(Msg("tg.act_gb", name=self._name(x), gb=gb))
        return tr(c["lang"], "ok_gb", False, name=self._name(x), gb=gb)

    def do_add(self, c: dict, name: str) -> None:
        pk = self.ops.add_client(name.strip()[:60])
        x = self._client_wait(pk)
        self._send(c, tr(c["lang"], "add_ok", name=self._name(x) if x else name))
        self.send_config(c, pk)
        if x:
            self.show_client(c, pk, None)

    def _client_wait(self, pk: str) -> dict | None:
        """Новый клиент появляется в списке движка после следующего опроса сервера."""
        for _ in range(20):
            x = next((x for x in self.ops.clients() if x["public_key"] == pk), None)
            if x:
                return x
            self.ops.refresh_clients()
            time.sleep(0.5)
        return None

    def send_config(self, c: dict, pk: str) -> None:
        L = c["lang"]
        try:
            cfg = self.ops.client_config(pk)
        except Exception as e:  # noqa: BLE001
            key = getattr(getattr(e, "detail", None) or getattr(e, "msg", None), "key", "")
            if key == "usr.no_key":
                raise BotError("cd_app") from None
            if key == "err.not_found":
                raise BotError("gone") from None
            raise
        name = cfg.get("name") or pk[:8]
        caption = tr(L, "cfg_caption", name=name)
        try:
            notify.send_photo(c["token"], c["chat_id"], qr.png(cfg["conf"]), caption, c["via"], html=True)
            caption = name
        except qr.QRTooBig:
            caption += "\n" + tr(L, "cfg_qr_big")
        notify.send_document(c["token"], c["chat_id"], cfg.get("filename") or "awg.conf",
                             cfg["conf"].encode(), caption, c["via"], html=True)
        if cfg.get("link"):
            self._send(c, tr(L, "cfg_link") + "\n<code>" + html.escape(cfg["link"]) + "</code>")
        self.ops.audit(Msg("tg.act_config", name=name))

    def do_share(self, c: dict, pk: str) -> None:
        x = self._client(pk)
        url = self.ops.share(pk)
        self._send(c, tr(c["lang"], "share", name=self._name(x), url=url))
        self.ops.audit(Msg("tg.act_share", name=self._name(x)))

    def _exit_name(self, uid: str) -> str:
        u = next((u for u in self.ops.snapshot().get("upstreams", []) if u["id"] == uid), None)
        if not u:
            raise BotError("gone_exit")
        return u["name"]

    def do_probe(self, c: dict, uid: str) -> None:
        L = c["lang"]
        name = self._exit_name(uid)
        r = self.ops.probe("up:" + uid)
        if r.get("ok"):
            cc = r.get("cc") or ""
            text = tr(L, "pr_ok", name=name, ip=r.get("ip") or "?", cc=f"({cc})" if cc else "",
                      ms=r.get("latency_ms") if r.get("latency_ms") is not None else "?")
        else:
            err = r.get("error")
            text = tr(L, "pr_fail", name=name, error=self._err(err) if isinstance(err, Msg) else (err or "?"))
        self._send(c, text.replace("  ", " "))

    def do_default(self, c: dict, out: str) -> str:
        st = self.ops.snapshot()
        if out != "direct" and not any(out == "up:" + u["id"] for u in st.get("upstreams", [])):
            raise BotError("gone_exit")
        self.ops.set_default(out)
        label = self.out_label(c, out, st)
        # в журнал панели — сообщением: его переводит браузер на язык панели, а не бота
        name = next((u["name"] for u in st.get("upstreams", []) if out == "up:" + u["id"]), "")
        self.ops.audit(Msg("tg.act_default", name=name) if name else Msg("tg.act_default_direct"))
        return tr(c["lang"], "df_ok", False, out=label)

    def do_route(self, c: dict, text: str) -> None:
        L = c["lang"]
        target = text.strip().split()[0][:253] if text.strip() else ""
        try:
            r = self.ops.trace(target)
        except Exception as e:  # noqa: BLE001
            key = getattr(getattr(e, "detail", None), "key", "")
            if key in ("tr.ipv6", "tr.ipv6_only"):
                raise BotError("rt_v6") from None
            if key == "err.ip_or_domain":
                raise BotError("rt_bad") from None
            raise
        st = self.ops.snapshot()
        ip = r.get("ip") or target
        out = self.out_label(c, r.get("result"), st)
        lines = [tr(L, "rt_res_ip", ip=ip, out=out) if ip == target
                 else tr(L, "rt_res", target=target, ip=ip, out=out)]
        steps = r.get("steps") or []
        match = next((s for s in steps if isinstance(s, Msg) and s.key == "tr.match"), None)
        if any(isinstance(s, Msg) and s.key == "tr.local" for s in steps):
            lines = [tr(L, "rt_res_ip", ip=ip, out=tr(L, "o_direct")), tr(L, "rt_local")]
        elif match:
            lines.append(tr(L, "rt_rule", list=self.ops.list_name(match.p.get("list")),
                            net=match.p.get("net")))
        else:
            lines.append(tr(L, "rt_default"))
        eff, res = r.get("effective"), r.get("result")
        if res and res.startswith("up:") and _tunnel_num(st, res) != eff:
            lines.append(tr(L, "rt_now", out=self.out_label(c, eff, st)))
        self._send(c, "\n".join(lines), self._keyboard(c))

    def do_backup(self, c: dict) -> None:
        try:
            self.ops.backup(c)
        except Exception as e:  # noqa: BLE001
            raise BotError("bk_fail", error=self._err(e)) from None
        self.ops.audit(Msg("tg.act_backup"))

    def ask_update(self, c: dict) -> None:
        L = c["lang"]
        v = self.ops.update_info()
        if not v.get("available") or not v.get("latest"):
            self._send(c, tr(L, "up_none", version=v.get("current") or self.ops.version))
            return
        self._send(c, tr(L, "up_ask", version=v["latest"]),
                   kb([(tr(L, "b_update_go"), "upgo"), (tr(L, "b_cancel"), "x")]))

    def do_update(self, c: dict) -> None:
        L = c["lang"]
        v = self.ops.update_info()
        if not v.get("available") or not v.get("latest"):
            self._send(c, tr(L, "up_none", version=v.get("current") or self.ops.version))
            return
        self.ops.start_update(v["latest"])
        self._st["update"] = {"to": v["latest"], "t": time.time()}
        self._save()
        self.ops.audit(Msg("tg.act_update", version=v["latest"]))
        self._send(c, tr(L, "up_started", version=v["latest"]))


def _tunnel_num(st: dict, out: str):
    """'up:<id>' → номер туннеля выхода (так выход выглядит после resolve, когда он работает)."""
    u = next((u for u in st.get("upstreams", []) if "up:" + u["id"] == out), None)
    return u.get("num") if u else None
