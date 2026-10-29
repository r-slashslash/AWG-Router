"""Веб-панель AWG Router: API + статика (только стандартная библиотека Python)."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import signal
import socket
import threading
import time

from . import awgconf, config, lists, system
from .engine import Engine
from .i18n import Msg, MsgError
from .store import ID_RE, Store, new_id
from .tlsmgr import TLSManager
from .users import UserError
from .web import App, HTTPError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("awgr")

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
COOKIE = "awgr_session"
SESSION_TTL = 4 * 3600  # вход в панель действует 4 часа
BASE = config.PANEL_BASE_PATH


# ------------------------------------------------------------------ секреты
def _secret_file(name: str, gen) -> str:
    p = os.path.join(config.DATA_DIR, name)
    if os.path.exists(p):
        return open(p).read().strip()
    v = gen()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(v)
    return v


os.makedirs(config.DATA_DIR, exist_ok=True)
SECRET = _secret_file("session.key", lambda: secrets.token_hex(32)).encode()
if config.PANEL_PASSWORD:
    PASSWORD = config.PANEL_PASSWORD
else:
    PASSWORD = _secret_file("panel_password", lambda: secrets.token_urlsafe(12))
    log.warning("PANEL_PASSWORD is not set. Panel password: %s (file data/panel_password)", PASSWORD)
PW_TAG = hashlib.sha256(PASSWORD.encode()).hexdigest()[:8]  # смена пароля = выход везде


def _sign(payload: str) -> str:
    return hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()[:32]


def make_session() -> str:
    exp = str(int(time.time()) + SESSION_TTL)
    return f"{exp}.{PW_TAG}.{_sign(exp + PW_TAG)}"


def check_session(v: str | None) -> bool:
    if not v or v.count(".") != 2:
        return False
    exp, pw, sig = v.split(".")
    if not hmac.compare_digest(sig, _sign(exp + pw)):
        return False
    if not exp.isdigit():
        return False
    now = time.time()
    # срок не дольше SESSION_TTL: старые длинные сессии (раньше было 7 дней) тоже перестают действовать
    return now < int(exp) <= now + SESSION_TTL and pw == PW_TAG


_fails: dict[str, list[float]] = {}

# -------------------------------------------------------------------- приложение
store = Store()
engine = Engine(store)
tls = TLSManager(lambda: engine.srv.public_host(store.snapshot()))
app = App(BASE)
app.static = (BASE + "/static", STATIC)
app.index_file = os.path.join(STATIC, "index.html")


def auth_mw(req) -> None:
    if req.path == BASE + "/api/login":
        return
    if not check_session(req.cookies.get(COOKIE)):
        raise HTTPError(401, "auth")
    # тело запроса — только JSON (простые формы с чужих сайтов так не отправить)
    if int(req.headers.get("Content-Length") or 0) > 0 and \
            "application/json" not in req.headers.get("Content-Type", ""):
        raise HTTPError(415, "err.json_required")


app.middleware = auth_mw


def bad(msg: str, code: int = 400):
    raise HTTPError(code, msg)


# ---------------------------------------------------------------- валидация
def v_outbound(st: dict, v, allow_inherit: bool = False) -> str:
    if not isinstance(v, str):
        bad("err.bad_outbound")
    if v in ("direct", "block") or (allow_inherit and v == "inherit"):
        return v
    if v.startswith("up:") and Store.upstream(st, v[3:]):
        return v
    bad(Msg("err.unknown_outbound", value=v))


def v_rules(st: dict, rules) -> list[dict]:
    if not isinstance(rules, list) or len(rules) > 50:
        bad("err.bad_rules")
    out = []
    for r in rules:
        if not isinstance(r, dict):
            bad("err.bad_rules")
        ls = r.get("lists") or []
        if not isinstance(ls, list) or not ls:
            bad("err.rule_no_lists")
        for lid in ls:
            if not Store.lst(st, lid):
                bad(Msg("err.unknown_list", id=lid))
        rid = r.get("id") if isinstance(r.get("id"), str) and ID_RE.match(r.get("id", "")) else new_id("r_")
        out.append({"id": rid, "lists": list(dict.fromkeys(ls)),
                    "outbound": v_outbound(st, r.get("outbound")),
                    "enabled": bool(r.get("enabled", True)),
                    "comment": str(r.get("comment") or "")[:80]})
    return out


def v_name(v, maxlen: int = 40) -> str:
    v = str(v or "").strip()
    if not v:
        bad("err.name_required")
    return v[:maxlen]


# --------------------------------------------------------------------- auth
@app.post("/api/login")
def login(req):
    ip = req.client_ip
    now = time.time()
    fails = [t for t in _fails.get(ip, []) if now - t < 600]
    if len(fails) >= 8:
        bad("err.too_many_attempts", 429)
    body = req.json()
    if not hmac.compare_digest(str(body.get("password", "")).encode(), PASSWORD.encode()):
        fails.append(now)
        _fails[ip] = fails
        time.sleep(1)
        bad("err.wrong_password", 403)
    _fails.pop(ip, None)
    req.cookie(COOKIE, make_session(), max_age=SESSION_TTL, path=BASE or "/",
               secure=bool(tls.context()) or req.headers.get("X-Forwarded-Proto") == "https")
    return {"ok": True}


@app.post("/api/logout")
def logout(req):
    req.cookie(COOKIE, "", max_age=0, path=BASE or "/")
    return {"ok": True}


# -------------------------------------------------------------------- state
def _upstream_view(st: dict, u: dict) -> dict:
    try:
        pc = engine.parsed(u)
        info = {"endpoint": pc.endpoint, "address": pc.address, "mtu": pc.mtu,
                "version": pc.version,
                "config_error": None}
    except awgconf.ConfigError as e:
        info = {"config_error": str(e)}
    eff = engine.resolve("up:" + u["id"], st)
    return {"id": u["id"], "name": u["name"], "num": u["num"],
            "iface": f"{config.IFACE_PREFIX}{u['num']}", "enabled": u.get("enabled", True),
            "fallback": u.get("fallback", "direct"), "created": u.get("created"),
            **info, "health": engine.health.get(u["id"], {"state": "down"}), "effective": eff,
            "refs": Store.outbound_refs(st, "up:" + u["id"])}


@app.get("/api/state")
def get_state(req):
    st = store.snapshot()
    t = engine.target
    clients = []
    for c in engine.clients:
        cp = st["clients"].get(c["public_key"], {})
        pol = engine.policy_for(st, c["public_key"])
        clients.append({
            **c,
            "policy": {"outbound": cp.get("outbound", "inherit"),
                       "rules_mode": cp.get("rules_mode", "inherit"),
                       "rules": cp.get("rules") or [], "note": cp.get("note", "")},
            "default": pol["default"],
            "effective": engine.resolve(pol["default"], st),
        })
    clients.sort(key=lambda c: tuple(int(x) for x in (c.get("ip") or "255.255.255.255").split(".")))
    return {
        "demo": config.DRY_RUN,
        "now": time.time(),
        "target": {"container": t.container, "kind": t.kind, "pid": t.pid, "iface": t.iface,
                   "conf": t.conf_path, "exists": t.exists} if t else None,
        "panel": {"url": panel_url(), "access": "ssh" if config.PANEL_HOST.startswith("127.") else "public",
                  "tls": tls.status(), "mode": config.AWG_MODE},
        "target_error": engine.target_error,
        "backend": config.UPSTREAM_BACKEND,
        "engine": {"last_apply": engine.last_apply, "last_reconcile": engine.last_reconcile,
                   "last_error": engine.last_error, "ruleset_size": len(engine.ruleset)},
        "routing": st["routing"],
        "global_effective": engine.resolve(st["routing"]["default"], st),
        "settings": st["settings"],
        "upstreams": [_upstream_view(st, u) for u in st["upstreams"]],
        "lists": [{**l, "refs": Store.list_refs(st, l["id"])} for l in st["lists"]],
        "clients": clients,
        "events": engine.events[-40:][::-1],
        "country_codes": lists.COUNTRY_CODES,
    }


# ---------------------------------------------------------------- upstreams
@app.post("/api/upstreams")
def add_upstream(req):
    body = req.json()
    try:
        pc = awgconf.parse_upstream(str(body.get("config", "")))
    except awgconf.ConfigError as e:
        bad(e.msg)
    name = v_name(body.get("name"))

    def fn(st):
        fb = v_outbound(st, body.get("fallback") or "direct")
        u = {"id": new_id("u"), "name": name, "num": Store.free_num(st), "config": pc.raw,
             "enabled": True, "fallback": fb, "created": time.time()}
        st["upstreams"].append(u)
        if body.get("make_default") and st["routing"]["default"] in ("direct", "block"):
            st["routing"]["default"] = "up:" + u["id"]
        return u["id"]
    uid = store.mutate(fn)
    engine.trigger()
    return {"id": uid}


@app.get("/api/upstreams/{uid}/config")
def get_upstream_config(req, uid):
    u = Store.upstream(store.snapshot(), uid)
    if not u:
        bad("err.not_found", 404)
    return {"config": u["config"]}


@app.put("/api/upstreams/{uid}")
def edit_upstream(req, uid):
    body = req.json()

    def fn(st):
        u = Store.upstream(st, uid)
        if not u:
            bad("err.not_found", 404)
        if "name" in body:
            u["name"] = v_name(body["name"])
        if "enabled" in body:
            u["enabled"] = bool(body["enabled"])
        if "fallback" in body:
            fb = v_outbound(st, body["fallback"])
            if fb == "up:" + uid:
                bad("err.fallback_self")
            u["fallback"] = fb
        if body.get("config"):
            try:
                u["config"] = awgconf.parse_upstream(str(body["config"])).raw
            except awgconf.ConfigError as e:
                bad(e.msg)
    store.mutate(fn)
    engine.trigger()
    return {"ok": True}


@app.delete("/api/upstreams/{uid}")
def del_upstream(req, uid):
    def fn(st):
        if not Store.upstream(st, uid):
            bad("err.not_found", 404)
        refs = Store.outbound_refs(st, "up:" + uid)
        if refs:
            bad(Msg("err.upstream_in_use", refs=refs[:6]))
        st["upstreams"] = [u for u in st["upstreams"] if u["id"] != uid]
    store.mutate(fn)
    engine.trigger()
    return {"ok": True}


@app.post("/api/probe")
def probe(req):
    body = req.json()
    st = store.snapshot()
    out = v_outbound(st, body.get("outbound"))
    try:
        return engine.probe(out)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:300]}


# ------------------------------------------------------------------ routing
@app.put("/api/routing")
def put_routing(req):
    body = req.json()

    def fn(st):
        st["routing"] = {"default": v_outbound(st, body.get("default")),
                         "rules": v_rules(st, body.get("rules", []))}
    store.mutate(fn)
    engine.trigger()
    return {"ok": True}


@app.put("/api/clients/{pk:path}")
def put_client(req, pk):
    if not awgconf.KEY_RE.match(pk) and not (config.DRY_RUN and pk.startswith("DEMO")):
        bad("err.bad_client_key")
    body = req.json()

    def fn(st):
        mode = body.get("rules_mode", "inherit")
        if mode not in ("inherit", "custom"):
            bad("err.bad_value")
        c = {"outbound": v_outbound(st, body.get("outbound", "inherit"), allow_inherit=True),
             "rules_mode": mode,
             "rules": v_rules(st, body.get("rules") or []) if mode == "custom" else [],
             "note": str(body.get("note") or "")[:120],
             "name": next((x.get("name") for x in engine.clients
                           if x["public_key"] == pk), "")}
        if c["outbound"] == "inherit" and mode == "inherit" and not c["note"]:
            st["clients"].pop(pk, None)
        else:
            st["clients"][pk] = c
    store.mutate(fn)
    engine.trigger()
    return {"ok": True}


@app.post("/api/trace")
def trace(req):
    body = req.json()
    ip = str(body.get("ip", "")).strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        try:
            infos = socket.getaddrinfo(ip, None, socket.AF_INET)
            resolved = infos[0][4][0]
        except Exception:  # noqa: BLE001
            bad("err.ip_or_domain")
        res = engine.trace(body.get("client") or None, resolved)
        res["steps"].insert(0, Msg("tr.resolved", host=ip, ip=resolved))
        res["ip"] = resolved
        return res
    try:
        res = engine.trace(body.get("client") or None, ip)
    except ValueError:
        bad("err.ip_or_domain")
    res["ip"] = ip
    return res


# -------------------------------------------------------------------- lists
def _list_body(st: dict, body: dict, existing: dict | None = None) -> dict:
    kind = body.get("kind", existing["kind"] if existing else None)
    if kind not in ("country", "asn", "url", "manual"):
        bad("err.list_kind")
    src = str(body.get("source", existing["source"] if existing else "")).strip()
    if kind == "country":
        src = src.lower()
        if not re.match(r"^[a-z]{2}$", src):
            bad("err.country_code")
        return {"kind": kind, "source": src, "name": str(body.get("name") or "")[:40]}
    elif kind == "asn":
        asns = lists.parse_asns(src)
        if not asns:
            bad("err.asn_format")
        src = " ".join(f"AS{a}" for a in asns)
        name = body.get("name") or src
    elif kind == "url":
        urls = src.split()
        if not urls or not all(re.match(r"^https?://\S+$", u) for u in urls):
            bad("err.urls")
        name = body.get("name")
    else:
        if len(src) > 2_000_000:
            bad("err.list_too_big")
        if not lists.parse_cidrs(src):
            bad("err.no_cidr")
        name = body.get("name")
    return {"kind": kind, "source": src, "name": v_name(name)}


@app.post("/api/lists")
def add_list(req):
    body = req.json()

    def fn(st):
        d = _list_body(st, body)
        lid = d["source"] if d["kind"] == "country" else new_id("l")
        if d["kind"] == "country" and Store.lst(st, lid):
            bad("err.country_exists")
        st["lists"].append({"id": lid, **d})
        return lid
    lid = store.mutate(fn)
    engine.refresh_lists(False, [lid])
    return {"id": lid, **(Store.lst(store.snapshot(), lid) or {})}


@app.put("/api/lists/{lid}")
def edit_list(req, lid):
    body = req.json()

    def fn(st):
        l = Store.lst(st, lid)
        if not l:
            bad("err.not_found", 404)
        d = _list_body(st, body, l)
        if l["kind"] == "country":
            d["source"] = l["source"]  # страну у существующего списка не меняем
        l.update(d)
    store.mutate(fn)
    engine.refresh_lists(False, [lid])
    return Store.lst(store.snapshot(), lid)


@app.delete("/api/lists/{lid}")
def del_list(req, lid):
    def fn(st):
        if not Store.lst(st, lid):
            bad("err.not_found", 404)
        refs = Store.list_refs(st, lid)
        if refs:
            bad(Msg("err.list_in_use", refs=refs[:6]))
        st["lists"] = [l for l in st["lists"] if l["id"] != lid]
    store.mutate(fn)
    lists.delete_cidrs(lid)
    engine.trigger()
    return {"ok": True}


@app.post("/api/lists/{lid}/refresh")
def refresh_list(req, lid):
    if not Store.lst(store.snapshot(), lid):
        bad("err.not_found", 404)
    engine.refresh_lists(False, [lid])
    return Store.lst(store.snapshot(), lid)


@app.get("/api/lists/{lid}/cidrs")
def list_cidrs(req, lid):
    c = lists.load_cidrs(lid)
    return {"count": len(c), "sample": c[:300]}


# ----------------------------------------------------------------- settings
@app.put("/api/settings")
def put_settings(req):
    body = req.json()

    def fn(st):
        s = st["settings"]
        if "list_update_hours" in body:
            try:
                s["list_update_hours"] = max(1, min(int(body["list_update_hours"]), 24 * 30))
            except (TypeError, ValueError):
                bad("err.hours")
        if "on_stop" in body:
            if body["on_stop"] not in ("keep", "restore"):
                bad("err.bad_value")
            s["on_stop"] = body["on_stop"]
    store.mutate(fn)
    return {"ok": True}


@app.post("/api/reapply")
def reapply(req):
    engine.applied_hash = None
    engine.trigger()
    return {"ok": True}


@app.get("/api/debug")
def debug(req):
    t = engine.target
    rules = routes = ""
    if t and not config.DRY_RUN:
        rules = (t.ns(["ip", "rule", "show"], check=False)).stdout
        parts = []
        for r in list(engine.rt.values()):
            table = str(config.TABLE_BASE + r.num)
            out = (t.ns(["ip", "route", "show", "table", table],
                                           check=False)).stdout
            parts.append(f"# table {table} ({r.iface})\n{out}")
        routes = "\n".join(parts)
    # большие наборы адресов сокращаем, чтобы страница не тормозила
    short, skip = [], 0
    for line in engine.ruleset.splitlines():
        if line.startswith("\t\t\t") and "goto" not in line:
            skip += 1
            if skip <= 2:
                short.append(line)
            elif skip == 3:
                short.append("\t\t\t…")
            continue
        skip = 0
        short.append(line)
    return {"ruleset": "\n".join(short), "ip_rules": rules, "routes": routes,
            "commands": getattr(engine._fake, "log", [])[-60:] if config.DRY_RUN else []}


# -------------------------------------------------------------------- users
def _pk(pk: str) -> str:
    if not awgconf.KEY_RE.match(pk):
        bad("err.bad_client_key")
    return pk


def _user_errors(fn):
    try:
        return fn()
    except (UserError, MsgError) as e:
        bad(e.msg)


@app.post("/api/users")
def add_user(req):
    body = req.json()
    pk = _user_errors(lambda: engine.srv.add_client(str(body.get("name") or "")))
    engine.reconcile_soon()
    return {"public_key": pk}


@app.put("/api/users/{pk:path}")
def edit_user(req, pk):
    body = req.json()
    _user_errors(lambda: engine.srv.update_client(
        _pk(pk), name=body.get("name"), enabled=body.get("enabled")))
    engine.reconcile_soon()
    return {"ok": True}


@app.delete("/api/users/{pk:path}")
def del_user(req, pk):
    _user_errors(lambda: engine.srv.delete_client(_pk(pk)))
    engine.reconcile_soon()
    return {"ok": True}


@app.get("/api/users/{pk:path}/config")
def user_config(req, pk):
    return _user_errors(lambda: engine.srv.client_config(_pk(pk)))


# ------------------------------------------------------------------- server
@app.get("/api/server")
def get_server(req):
    return _user_errors(engine.srv.server_view)


@app.put("/api/server")
def put_server(req):
    body = req.json()
    res = _user_errors(lambda: engine.srv.update_server(body))
    engine.reconcile_soon()
    return res


@app.post("/api/server/generate")
def gen_server_params(req):
    return {"params": engine.srv.regenerate_params()}


@app.post("/api/server/init")
def init_server(req):
    body = req.json()
    try:
        port = int(body.get("port") or system.random_udp_port())
    except (TypeError, ValueError):
        bad("srv.bad_port")
    _user_errors(lambda: engine.srv.init_host(port, str(body.get("subnet") or "10.8.1.0/24")))
    engine.reconcile_soon()
    return {"ok": True}


@app.post("/api/tls/renew")
def tls_renew(req):
    if tls.mode != "letsencrypt":
        bad("err.bad_value")
    ok = tls.renew_now()
    return {"ok": ok, "tls": tls.status()}


# ---------------------------------------------------------------------- run
def panel_url() -> str:
    if config.PANEL_HOST.startswith("127."):
        host = "127.0.0.1"
    else:
        host = tls.host() if tls.enabled else (engine.srv.public_host(store.snapshot()) or "SERVER_IP")
    if ":" in host:
        host = f"[{host}]"
    scheme = "https" if tls.context() else "http"
    return f"{scheme}://{host}:{config.PANEL_PORT}{BASE}/"


def write_status() -> None:
    p = os.path.join(config.DATA_DIR, "status.json")
    with open(p + ".tmp", "w") as f:
        json.dump({"ready": True, "url": panel_url(), "tls": tls.status(),
                   "time": time.time()}, f)
    os.replace(p + ".tmp", p)


def run():
    try:
        os.remove(os.path.join(config.DATA_DIR, "status.json"))
    except OSError:
        pass
    engine.start()
    if tls.enabled:
        # адрес для сертификата: из настроек или определённый автоматически
        for _ in range(30):
            if tls.host():
                break
            time.sleep(1)
        tls.start()
    srv = app.serve(config.PANEL_HOST, config.PANEL_PORT, tls=tls.context if tls.enabled else None)
    write_status()
    log.info("Panel: %s", panel_url())

    def stop(*_):
        log.info("Stopping")
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        srv.serve_forever(poll_interval=0.5)
    finally:
        tls.stop_ev.set()
        engine.shutdown()
        log.info("Stopped")


if __name__ == "__main__":
    run()
