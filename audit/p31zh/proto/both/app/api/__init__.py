"""Адреса API панели по темам. Импорт пакета регистрирует их все в panel.app (порядок не важен: у адресов нет
пересечений). ROUTES — имена модулей, для проверки, что ни один не забыт."""
from . import addrs, auth, backup, clients, exits, routing, server, state, telegram

ROUTES = (addrs, auth, backup, clients, exits, routing, server, state, telegram)
