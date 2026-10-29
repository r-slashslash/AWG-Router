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

from . import awgconf, awgserver, config, limits, lists, notify, system, totp
from .store import DEFAULT_STATE
from .traffic import month_key
from .updates import UpdateChecker
from .version import VERSION
from .engine import Engine
from .i18n import Msg, MsgError
from .store import ID_RE, Store, new_id
from .tlsmgr import TLSManager
from .users import UserError
from .web import App, HTTPError, Page

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

# Пароль, заданный в панели, хранится хешем и важнее PANEL_PASSWORD из .env.
# `awg-router password` удаляет этот файл и задаёт новый пароль в .env.
PW_FILE = os.path.join(config.DATA_DIR, "panel_password.json")
PW_ITER = 200_000
_pw_cache: tuple = (None, None)


def custom_password() -> dict | None:
    global _pw_cache
    try:
        mt = os.stat(PW_FILE).st_mtime
    except OSError:
        return None
    if _pw_cache[0] != mt:
        try:
            with open(PW_FILE) as f:
                d = json.load(f)
            ok = isinstance(d, dict) and d.get("hash") and d.get("salt")
        except (OSError, ValueError):
            ok = False
        _pw_cache = (mt, d if ok else None)
    return _pw_cache[1]


def _pw_hash(pw: str, salt: str, it: int = PW_ITER) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), it).hex()


def check_password(pw: str) -> bool:
    c = custom_password()
    if c:
        return hmac.compare_digest(_pw_hash(pw, c["salt"], int(c.get("iter") or PW_ITER)), c["hash"])
    return hmac.compare_digest(pw.encode(), PASSWORD.encode())


def set_password(pw: str) -> None:
    salt = secrets.token_hex(16)
    d = {"salt": salt, "iter": PW_ITER, "hash": _pw_hash(pw, salt), "set_at": time.time()}
    tmp = PW_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f)
    os.replace(tmp, PW_FILE)


def _sign(payload: str) -> str:
    return hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()[:32]


def sec_tag() -> str:
    """Метка в сессии: смена пароля или включение/выключение входа по коду = выход везде."""
    c = custom_password()
    t = totp.load()
    if not c and not t:
        return PW_TAG
    material = ("h:" + c["hash"]) if c else PASSWORD
    return hashlib.sha256(f"{material}|{t['secret'] if t else ''}".encode()).hexdigest()[:8]


def make_session() -> str:
    exp = str(int(time.time()) + SESSION_TTL)
    tag = sec_tag()
    return f"{exp}.{tag}.{_sign(exp + tag)}"


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
    return now < int(exp) <= now + SESSION_TTL and pw == sec_tag()


_fails: dict[str, list[float]] = {}

# -------------------------------------------------------------------- приложение
store = Store()
engine = Engine(store)
tls = TLSManager(lambda: engine.srv.public_host(store.snapshot()))
notifier = notify.Notifier(store, lambda st: tls.host() if tls.enabled else engine.srv.public_host(st))
engine.notifier = notifier
tls.on_fail = lambda exp: notifier.event(
    "tls", "tls_fail", cooldown=12 * 3600,
    date=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(exp or 0)))
updates = UpdateChecker(lambda v: notifier.event("update", "update_available", cooldown=86400, version=v))
app = App(BASE)
app.static = (BASE + "/static", STATIC)
app.public_static = ("/s/assets", STATIC)   # для личных страниц клиентов (без секретного пути)
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
def _check_blocked(ip: str) -> None:
    now = time.time()
    _fails[ip] = [t for t in _fails.get(ip, []) if now - t < 600]
    if len(_fails[ip]) >= 8:
        bad("err.too_many_attempts", 429)


def _failed(ip: str, msg: str) -> None:
    _fails.setdefault(ip, []).append(time.time())
    if len(_fails[ip]) == 8:
        notifier.event("login", "login_blocked", cooldown=600, ip=ip)
    time.sleep(1)
    bad(msg, 403)


def _set_session(req) -> None:
    req.cookie(COOKIE, make_session(), max_age=SESSION_TTL, path=BASE or "/",
               secure=bool(tls.context()) or req.headers.get("X-Forwarded-Proto") == "https")


@app.post("/api/login")
def login(req):
    ip = req.client_ip
    _check_blocked(ip)
    body = req.json()
    if not check_password(str(body.get("password", ""))):
        _failed(ip, "err.wrong_password")
    if totp.load():
        # второй шаг: пароль верный, нужен код из приложения
        if not str(body.get("code") or "").strip():
            return {"ok": False, "need_code": True}
        if not totp.check_and_use(body.get("code")):
            _failed(ip, "err.wrong_code")
    _fails.pop(ip, None)
    _set_session(req)
    notifier.event("login", "login_ok", cooldown=60, ip=ip)
    return {"ok": True}


@app.post("/api/logout")
def logout(req):
    req.cookie(COOKIE, "", max_age=0, path=BASE or "/")
    return {"ok": True}


# -------------------------------------------------------- вход по коду (2FA)
_totp_pending: dict = {}


@app.post("/api/totp/setup")
def totp_setup(req):
    if totp.load():
        bad("err.totp_already")
    secret = totp.new_secret()
    _totp_pending.clear()
    _totp_pending.update(secret=secret, t=time.time())
    label = tls.host() if tls.enabled else engine.srv.public_host(store.snapshot())
    return {"secret": secret, "uri": totp.uri(secret, label or "")}


@app.post("/api/totp/enable")
def totp_enable(req):
    body = req.json()
    p = dict(_totp_pending)
    if not p or time.time() - p["t"] > 1800:
        bad("err.totp_expired")
    st = totp.match(p["secret"], body.get("code"))
    if st is None:
        bad("err.wrong_code", 403)
    totp.save({"secret": p["secret"], "since": time.time(), "last_step": st})
    _totp_pending.clear()
    _set_session(req)          # остальные сессии больше не действуют, текущая — новая
    log.info("Two-factor sign-in enabled")
    return {"ok": True}


@app.post("/api/totp/disable")
def totp_disable(req):
    ip = req.client_ip
    _check_blocked(ip)
    body = req.json()
    if not totp.load():
        return {"ok": True}
    if not totp.check_and_use(body.get("code")):
        _failed(ip, "err.wrong_code")
    totp.save(None)
    _set_session(req)
    log.info("Two-factor sign-in disabled")
    return {"ok": True}


# ---------------------------------------------------------------- telegram
TG_TOKEN_RE = re.compile(r"^\d{5,15}:[A-Za-z0-9_-]{30,60}$")
TG_CHAT_RE = re.compile(r"^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$")


def _tg_draft(body: dict) -> dict:
    """Настройки из формы поверх сохранённых (пустой токен = оставить прежний)."""
    c = notify.cfg_of(store.snapshot())
    tok = str(body.get("token") or "").strip()
    if tok:
        if not TG_TOKEN_RE.match(tok):
            bad("err.tg_token")
        c["token"] = tok
    if "chat_id" in body:
        chat = str(body.get("chat_id") or "").strip()
        if chat and not TG_CHAT_RE.match(chat):
            bad("err.tg_chat")
        c["chat_id"] = chat
    if "lang" in body:
        if body["lang"] not in notify.LANGS:
            bad("err.bad_value")
        c["lang"] = body["lang"]
    if isinstance(body.get("events"), dict):
        c["events"] = {k: bool(body["events"].get(k, c["events"].get(k, True))) for k in notify.KINDS}
    if "enabled" in body:
        c["enabled"] = bool(body["enabled"])
    return c


@app.put("/api/telegram")
def put_telegram(req):
    c = _tg_draft(req.json())
    if c["enabled"] and not (c["token"] and c["chat_id"]):
        bad("err.tg_incomplete")
    store.mutate(lambda st: st["settings"].__setitem__("telegram", c))
    return {"ok": True}


@app.post("/api/telegram/test")
def telegram_test(req):
    c = _tg_draft(req.json())
    if not (c["token"] and c["chat_id"]):
        bad("err.tg_incomplete")
    try:
        notify.send(c["token"], c["chat_id"], notify.render(c["lang"], "test", notifier.host_fn(store.snapshot())))
    except notify.NotifyError as e:
        bad(Msg("err.tg_failed", error=str(e)), 502)
    return {"ok": True}


@app.post("/api/telegram/detect")
def telegram_detect(req):
    c = _tg_draft(req.json())
    if not c["token"]:
        bad("err.tg_token")
    try:
        chat = notify.detect_chat(c["token"])
    except notify.NotifyError as e:
        bad(Msg("err.tg_failed", error=str(e)), 502)
    if not chat:
        bad("err.tg_no_chat", 404)
    return chat


# ------------------------------------------------------------- смена пароля
@app.post("/api/password")
def change_password(req):
    ip = req.client_ip
    _check_blocked(ip)
    body = req.json()
    if not check_password(str(body.get("current", ""))):
        _failed(ip, "err.wrong_password")
    new = str(body.get("new", ""))
    if len(new) < 10 or len(new) > 128:
        bad("err.pw_length")
    if check_password(new):
        bad("err.pw_same")
    set_password(new)
    _set_session(req)          # остальные сессии больше не действуют
    notifier.event("login", "pw_changed", cooldown=0, ip=ip)
    log.info("Panel password changed in the panel")
    return {"ok": True}


# ------------------------------------------------------- резервная копия
BACKUP_FORMAT = "awg-router-backup"
SERVER_FILES = ("clientsTable", "wireguard_psk.key", "wireguard_server_public_key.key")


@app.get("/api/backup")
def get_backup(req):
    st = store.snapshot()
    srv = None
    t = engine.target
    if t and t.exists:
        files = {}
        with engine.lock:
            for name in (os.path.basename(t.conf_path),) + SERVER_FILES:
                text = t.read_file(f"{t.dir}/{name}")
                if text is not None:
                    files[name] = text
        srv = {"kind": t.kind, "conf": os.path.basename(t.conf_path), "files": files}
    return {"format": BACKUP_FORMAT, "version": 1, "panel_version": VERSION, "created": time.time(),
            "host": engine.srv.public_host(st), "state": st, "traffic": engine.traffic.export(),
            "server": srv}


@app.post("/api/restore")
def restore_backup(req):
    body = req.json()
    b = body.get("backup")
    if not isinstance(b, dict) or b.get("format") != BACKUP_FORMAT or not isinstance(b.get("state"), dict):
        bad("err.backup_format")
    new = b["state"]
    if not isinstance(new.get("routing"), dict) or not isinstance(new.get("upstreams"), list) \
            or not isinstance(new.get("lists"), list) or not isinstance(new.get("settings"), dict):
        bad("err.backup_format")
    srv = b.get("server") if body.get("server") else None
    t = engine.target
    sc = None
    if srv:
        if not t or not t.exists:
            bad("srv.no_server")
        if srv.get("kind") != t.kind:
            bad("err.backup_kind")
        conf = (srv.get("files") or {}).get(srv.get("conf") or "")
        if not isinstance(conf, str):
            bad("err.backup_format")
        sc = awgserver.parse(conf)
        if not sc.get("PrivateKey") or not sc.get("Address"):
            bad("err.backup_format")

    def fn(st):
        keep_host = st["settings"].get("public_host")
        st.clear()
        st.update(json.loads(json.dumps(new)))
        for k, v in DEFAULT_STATE.items():
            st.setdefault(k, json.loads(json.dumps(v)))
        if keep_host:      # адрес этого сервера важнее адреса из копии (переезд)
            st["settings"]["public_host"] = keep_host
    store.mutate(fn)
    engine.traffic.replace(b.get("traffic") or {})
    restarted = False
    if sc is not None:
        with engine.lock:
            cur = engine.srv.load(t)[0] if t.read_file(t.conf_path) else None
            if t.kind != "host" and cur is not None:
                sc.set("ListenPort", str(cur.port))   # порт контейнера задан Docker'ом
            t.write_file(t.conf_path, sc.render())
            for name in SERVER_FILES:
                text = srv["files"].get(name)
                if isinstance(text, str):
                    t.write_file(f"{t.dir}/{name}", text, 0o644 if name == "clientsTable" else 0o600)
            if isinstance(t, system.HostTarget):
                system.open_firewall_udp(t, sc.port)
            t.restart()
            restarted = True
        engine.event("warn", Msg("ev.restored_server"))
    else:
        engine.event("info", Msg("ev.restored"))
    engine.applied_hash = None
    engine.trigger()
    threading.Thread(target=lambda: engine.refresh_lists(False), daemon=True).start()
    return {"ok": True, "restarted": restarted}


# ----------------------------------------------- срок и лимит трафика клиента
@app.put("/api/limits/{pk:path}")
def put_limits(req, pk):
    _pk(pk)
    body = req.json()
    exp = body.get("expires")
    if exp is not None:
        try:
            exp = int(exp)
        except (TypeError, ValueError):
            bad("err.bad_value")
        if exp <= 0:
            exp = None
    quota = body.get("quota_gb")
    if quota not in (None, ""):
        try:
            quota = float(quota)
        except (TypeError, ValueError):
            bad("err.quota")
        if not 0 < quota <= 1_000_000:
            bad("err.quota")
        quota = int(quota * limits.GB)
    else:
        quota = None
    period = body.get("period") or "month"
    if period not in ("month", "total"):
        bad("err.bad_value")
    c = next((x for x in engine.clients if x["public_key"] == pk), None)
    if not c:
        bad("err.not_found", 404)
    now = time.time()
    enable = False

    def fn(st):
        nonlocal enable
        L = st.setdefault("limits", {}).get(pk) or {}
        if quota != L.get("quota") or period != L.get("period", "month"):
            L["quota_done"] = None
        ao = L.get("auto_off") or ""
        if not c["enabled"] and ao == "exp" and (exp is None or exp > now):
            enable = True
        if not c["enabled"] and ao.startswith("quota:") and \
                (quota is None or engine.traffic.used(pk, period) < quota):
            enable = True
        if enable:
            L["auto_off"] = None
        L.update(expires=exp, quota=quota, period=period)
        if exp is None and quota is None and not L.get("auto_off"):
            st["limits"].pop(pk, None)
        else:
            st["limits"][pk] = L
    store.mutate(fn)
    if enable:
        _user_errors(lambda: engine.srv.update_client(pk, enabled=True))
    engine.reconcile_soon()
    return {"ok": True, "enabled": enable}


# ------------------------------------------------- личные ссылки клиентов
def panel_origin() -> str:
    u = panel_url()
    return u[: len(u) - len(BASE) - 1] if BASE else u.rstrip("/")


def share_url(token: str) -> str:
    return f"{panel_origin()}/s/{token}"


@app.post("/api/shares/{pk:path}")
def create_share(req, pk):
    _pk(pk)
    if not any(c["public_key"] == pk for c in engine.clients):
        bad("err.not_found", 404)

    def fn(st):
        sh = st.setdefault("shares", {})
        tok = next((k for k, v in sh.items() if v.get("pk") == pk), None)
        if not tok:
            tok = secrets.token_urlsafe(18)
            sh[tok] = {"pk": pk, "created": time.time()}
        return tok
    return {"url": share_url(store.mutate(fn))}


@app.delete("/api/shares/{pk:path}")
def delete_share(req, pk):
    def fn(st):
        st["shares"] = {k: v for k, v in st.get("shares", {}).items() if v.get("pk") != pk}
    store.mutate(fn)
    return {"ok": True}


SHARE_HTML = os.path.join(STATIC, "share.html")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,40}$")


@app.get("/s/{token}", public=True)
def share_page(req, token):
    with open(SHARE_HTML, "rb") as f:
        return Page(f.read())


@app.get("/s/api/{token}", public=True)
def share_data(req, token):
    st = store.snapshot()
    sh = st.get("shares", {}).get(token) if TOKEN_RE.match(token) else None
    c = next((x for x in engine.clients if x["public_key"] == (sh or {}).get("pk")), None)
    if not c:
        bad("err.share_gone", 404)
    pk = c["public_key"]
    cfg = None
    if pk in st.get("keys", {}):
        try:
            cfg = engine.srv.client_config(pk)
            cfg.pop("warn_host", None)
        except Exception as e:  # noqa: BLE001
            log.warning("share %s…: config failed: %s", pk[:8], e, exc_info=True)
            cfg = None
    else:
        log.info("share %s…: no private key stored (client created outside the panel)", pk[:8])
    live = c.get("live") or {}
    return {"name": c.get("name") or "", "enabled": c["enabled"], "now": time.time(),
            "handshake": live.get("handshake") or None, "config": cfg,
            "traffic": engine.traffic.view(pk), "limits": limits.view(st.get("limits", {}).get(pk))}


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
            "traffic": engine.traffic.view(c["public_key"]),
            "limits": limits.view(st.get("limits", {}).get(c["public_key"])),
            "share_url": next((share_url(k) for k, v in st.get("shares", {}).items()
                               if v.get("pk") == c["public_key"]), None),
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
        "settings": {**st["settings"], "telegram": notify.public_view(notify.cfg_of(st))},
        "security": {"totp": bool(totp.load()), "session_hours": SESSION_TTL // 3600,
                     "password_custom": bool(custom_password())},
        "version": updates.status(),
        "month": month_key(),
        "notify_error": notifier.last_error,
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
    if body.get("enabled") is not None:
        # включили или выключили вручную — автоматическое отключение больше не наше
        def fn(st):
            L = st.get("limits", {}).get(pk)
            if L and L.get("auto_off"):
                L["auto_off"] = None
        store.mutate(fn)
    engine.reconcile_soon()
    return {"ok": True}


@app.delete("/api/users/{pk:path}")
def del_user(req, pk):
    _user_errors(lambda: engine.srv.delete_client(_pk(pk)))
    engine.traffic.forget(pk)
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
    if not config.DRY_RUN:
        updates.start(engine.stop_ev)
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
