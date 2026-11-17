"""Изменение записей прокси-клиентов и восстановление из копии."""
from __future__ import annotations

from . import checks, proxy_auth
from .store import ID_RE, new_id

MAX_CLIENTS = 64


def public(client: dict) -> dict:
    """Пароль и его хеш никогда не попадают в ответ панели."""
    return {**{k: client[k] for k in ("id", "username", "port", "upstream", "enabled")},
            "protocol": client.get("protocol", "https")}


def save(state: dict, body: dict, uid: str | None = None) -> dict:
    clients = state.setdefault("proxy_clients", [])
    old = next((c for c in clients if c["id"] == uid), None) if uid else None
    if uid and not old:
        checks.bad("err.not_found", 404)
    if not uid and len(clients) >= MAX_CLIENTS:
        checks.bad("err.bad_value")
    entry = dict(old or {"enabled": False, "protocol": "https"})
    entry.update({k: v for k, v in body.items() if k in ("username", "port", "upstream", "enabled", "protocol")})
    password = body.get("password")
    if password:
        try:
            entry["password"] = proxy_auth.password_record(password)
        except ValueError:
            checks.bad("err.bad_value", field="password")
    entry = {"id": uid or new_id("px"), **checks.proxy_client(state, entry, uid)}
    if old:
        clients[clients.index(old)] = entry
    else:
        clients.append(entry)
    return public(entry)


def delete(state: dict, uid: str) -> bool:
    clients = state.setdefault("proxy_clients", [])
    n = len(clients)
    clients[:] = [c for c in clients if c["id"] != uid]
    return len(clients) != n


def restore(state: dict, entries) -> None:
    """Проверить всю копию до применения."""
    if not isinstance(entries, list) or len(entries) > MAX_CLIENTS:
        checks.bad("err.bad_value")
    restored = []
    validation = {**state, "proxy_clients": restored}
    for entry in entries:
        if not isinstance(entry, dict):
            checks.bad("err.bad_value")
        uid = entry.get("id")
        if not isinstance(uid, str) or not ID_RE.fullmatch(uid) or any(c["id"] == uid for c in restored):
            checks.bad("err.bad_value")
        restored.append({"id": uid, **checks.proxy_client(validation, entry)})
    state["proxy_clients"] = restored
