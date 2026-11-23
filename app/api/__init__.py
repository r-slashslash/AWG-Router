"""Адреса API панели по темам. Импорт пакета регистрирует их все в panel.app (порядок не важен: у адресов нет
пересечений). ROUTES — имена модулей, для проверки, что ни один не забыт."""
from . import auth, backup, clients, exits, routing, server, socks, state, telegram

ROUTES = (auth, backup, clients, exits, routing, server, socks, state, telegram)
