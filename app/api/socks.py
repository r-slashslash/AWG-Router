"""Настройки и пользователи публичного входящего SOCKS5-прокси (/api/socks/...)."""
from __future__ import annotations

from .. import checks, config
from ..checks import bad
from ..i18n import Msg
from ..panel import app, engine, store, tls


def _busy_tcp_ports() -> set[int]:
    """TCP-порты, занятые самой панелью, SNI-прокси, SSH и HTTPS/ACME."""
    busy = {config.PANEL_PORT, config.SNI_PROXY_PORT, config.SSH_PORT or 22}
    if (tls.status() or {}).get("mode") in ("letsencrypt", "selfsigned"):
        busy.add(443)
        if config.ACME_HTTP_PORT == 80:
            busy.add(80)
    return busy


def _check_socks_exit(st: dict, v) -> str:
    ex = checks.outbound(st, v)
    if ex == "block":
        bad("err.bad_outbound", field="exit")
    return ex


@app.put("/api/socks/settings")
def put_socks_settings(req):
    body = req.json()
    has_enabled = "enabled" in body
    has_port = "port" in body
    new_enabled = checks.flag(body.get("enabled"), False) if has_enabled else None
    new_port = checks.validate_socks_port(body["port"]) if has_port else None
    if new_port is not None and new_port in _busy_tcp_ports():
        bad(Msg("sp.port_conflict", port=new_port), field="port")

    def fn(st):
        cur = (st.get("settings") or {}).get("socks_proxy") or {}
        enabled = new_enabled if has_enabled else bool(cur.get("enabled", False))
        port = new_port if new_port is not None else int(cur.get("port", 1080))
        if port in _busy_tcp_ports():
            bad(Msg("sp.port_conflict", port=port), field="port")
        st["settings"]["socks_proxy"] = {"enabled": enabled, "port": port}

    store.mutate(fn)
    engine.trigger()
    return {"ok": True}


@app.post("/api/socks/users")
def add_socks_user(req):
    body = req.json()
    username = checks.validate_socks_username(body.get("username"))
    password = checks.validate_socks_password(body.get("password"))
    enabled = checks.flag(body.get("enabled"), True)
    raw_exit = body.get("exit") or "direct"

    def fn(st):
        users = st.setdefault("socks_users", {})
        if username in users:
            bad(Msg("sp.user_exists", name=username), field="username")
        ex = _check_socks_exit(st, raw_exit)
        users[username] = {"password": password, "exit": ex, "enabled": enabled}

    store.mutate(fn)
    engine.trigger()
    return {"ok": True, "username": username}


@app.put("/api/socks/users/{uid}")
def put_socks_user(req, uid):
    body = req.json()
    new_pw = checks.validate_socks_password(body["password"]) if body.get("password") not in (None, "") else None
    has_enabled = "enabled" in body
    new_enabled = checks.flag(body.get("enabled"), True) if has_enabled else None

    def fn(st):
        u = (st.get("socks_users") or {}).get(uid)
        if not u:
            bad("err.not_found", 404)
        if new_pw is not None:
            u["password"] = new_pw
        if "exit" in body:
            u["exit"] = _check_socks_exit(st, body["exit"])
        if has_enabled:
            u["enabled"] = new_enabled

    store.mutate(fn)
    engine.trigger()
    return {"ok": True}


@app.get("/api/socks/users/{uid}/uri")
def get_socks_user_uri(req, uid):
    st = store.snapshot()
    u = (st.get("socks_users") or {}).get(uid)
    if not u:
        bad("err.not_found", 404)
    sp = (st.get("settings") or {}).get("socks_proxy") or {}
    return {
        "username": uid,
        "password": u.get("password", ""),
        "port": int(sp.get("port") or 1080),
        "host": engine.srv.public_host(st) or "",
    }


@app.delete("/api/socks/users/{uid}")
def del_socks_user(req, uid):
    def fn(st):
        users = st.get("socks_users") or {}
        if uid not in users:
            bad("err.not_found", 404)
        del users[uid]

    store.mutate(fn)
    engine.trigger()
    return {"ok": True}
