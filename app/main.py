"""Веб-панель AWG Router: API + статика (только стандартная библиотека Python)."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import signal
import socket
import threading
import time

from . import awgconf, awgserver, config, cps, limits, lists, notify, selfupdate, system, totp
from .traffic import month_key
from .updates import UpdateChecker
from .version import VERSION
from .engine import Engine
from .i18n import Msg, MsgError
from .store import DEFAULT_STATE, ID_RE, Store, new_id
from .tlsmgr import TLSManager
from .users import UserError
from .web import App, HTTPError, Page, content_length

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
app.public_files = {"share.js", "i18n.js", "qrcode.js", "app.css", "fonts/GolosText.woff",
                    "fonts/JetBrainsMono.woff2", "fonts/Vazirmatn.woff2"}
app.index_file = os.path.join(STATIC, "index.html")


def auth_mw(req) -> None:
    if req.path == BASE + "/api/login":
        return
    if not check_session(req.cookies.get(COOKIE)):
        raise HTTPError(401, "auth")
    # тело запроса — только JSON (простые формы с чужих сайтов так не отправить)
    ctype = req.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if content_length(req.headers) > 0 and ctype != "application/json":
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
    if "backup" in body:
        if body["backup"] not in notify.BACKUP_PERIODS:
            bad("err.bad_value")
        c["backup"] = body["backup"]
    pw = str(body.get("backup_pw") or "")
    if pw:
        if not 8 <= len(pw) <= 128:
            bad("err.backup_pw")
        c["backup_pw"] = pw
    if body.get("backup_pw_clear"):
        c["backup_pw"] = ""
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


@app.post("/api/telegram/backup")
def telegram_backup(req):
    """Отправить резервную копию в чат сейчас (с настройками из формы)."""
    c = _tg_draft(req.json())
    if not (c["token"] and c["chat_id"]):
        bad("err.tg_incomplete")
    try:
        send_backup(c)
    except notify.NotifyError as e:
        bad(Msg("err.tg_failed", error=str(e)), 502)
    now = time.time()
    store.mutate(lambda st: st["settings"].setdefault("telegram", notify.defaults())
                 .update(backup_last=now, backup_error=None))
    return {"ok": True, "encrypted": bool(c["backup_pw"])}


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


# ------------------------------------------------------- обновление панели
_last_check = 0.0


@app.post("/api/update/check")
def update_check(req):
    """Проверить новую версию сейчас, не дожидаясь проверки раз в 6 часов."""
    global _last_check
    if time.time() - _last_check > 10:
        _last_check = time.time()
        updates.check()
    return updates.status()


@app.post("/api/update/run")
def update_run(req):
    st = updates.status()
    if not st["available"] and not config.DRY_RUN:
        bad("err.update_none")
    try:
        return selfupdate.start(VERSION, st["latest"])
    except MsgError as e:
        bad(e.msg)


@app.get("/api/update/status")
def update_status(req):
    return {**selfupdate.status(), "current": VERSION, "log": selfupdate.log_lines(20)}


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
    return make_backup()


def make_backup() -> dict:
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


def send_backup(c: dict) -> None:
    """Копия в Telegram: тот же JSON, что «Скачать копию»; с паролем — зашифрованный openssl."""
    b = make_backup()
    data = json.dumps(b, ensure_ascii=False, indent=1).encode()
    host = re.sub(r"[^\w.-]+", "_", str(b.get("host") or "server"))
    name = f"awg-router-backup-{host}-{time.strftime('%Y-%m-%d')}.json"
    key = "backup"
    if c.get("backup_pw"):
        data, name, key = notify.encrypt(data, c["backup_pw"]), name + ".enc", "backup_enc"
    notify.send_document(c["token"], c["chat_id"], name, data,
                         notify.render(c["lang"], key, notifier.host_fn(store.snapshot())))


_backup_try = 0.0


def backup_tick(now: float | None = None) -> bool:
    """Плановая копия, если пора. Неудача — повтор не раньше чем через час. True — отправлено."""
    global _backup_try
    now = time.time() if now is None else now
    c = notify.cfg_of(store.snapshot())
    period = notify.BACKUP_PERIODS.get(c["backup"], 0)
    if not (period and c["enabled"] and c["token"] and c["chat_id"]):
        return False
    # запас 10 минут: проверка раз в 15 минут не должна сдвигать расписание на сутки вперёд
    last = c.get("backup_last")
    if (last and now - last < period - 600) or now - _backup_try < 3600:
        return False
    _backup_try = now
    err = None
    try:
        send_backup(c)
    except Exception as e:  # noqa: BLE001
        err = str(e)[:300]
        log.warning("telegram backup: %s", err)
    store.mutate(lambda st: st["settings"].setdefault("telegram", notify.defaults()).update(
        {"backup_error": err} if err else {"backup_last": now, "backup_error": None}))
    return err is None


def _backup_loop() -> None:
    engine.stop_ev.wait(120)
    while not engine.stop_ev.is_set():
        try:
            backup_tick()
        except Exception:  # noqa: BLE001
            log.exception("backup")
        engine.stop_ev.wait(900)


@app.post("/api/backup/decrypt")
def decrypt_backup(req):
    """Зашифрованная копия из Telegram → JSON для обычного восстановления."""
    body = req.json()
    try:
        data = base64.b64decode(str(body.get("data") or ""), validate=True)
    except (ValueError, binascii.Error):
        bad("err.backup_format")
    if not data.startswith(notify.ENC_MAGIC):
        bad("err.backup_format")
    plain = notify.decrypt(data, str(body.get("password") or ""))
    try:
        b = json.loads(plain) if plain is not None else None
    except ValueError:
        b = None
    if not isinstance(b, dict):
        bad("err.backup_password")
    return {"backup": b}


def _num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _int_or_none(v):
    return int(v) if _num(v) and v > 0 else None


QUOTA_KEY_RE = re.compile(r"^(\d{4}-\d{2}|total)$")
MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


def clean_backup_state(new: dict) -> dict:
    """Состояние из резервной копии → проверенное состояние.

    Каждое поле проходит те же проверки, что и при вводе в панели: идентификаторы
    из файла попадают в имена наборов nftables, интерфейсов и файлов, поэтому
    ничего не берём «как есть». Неверное поле — ошибка с его именем."""
    def fail(field: str):
        bad(Msg("err.backup_field", field=field))

    def check(field: str, fn):
        try:
            return fn()
        except HTTPError:
            fail(field)

    def arr(key: str) -> list:
        v = new.get(key, [])
        if not isinstance(v, list):
            fail(key)
        return v

    def obj(key: str) -> dict:
        v = new.get(key, {})
        if not isinstance(v, dict):
            fail(key)
        return v

    st = json.loads(json.dumps(DEFAULT_STATE))
    st["lists"], st["upstreams"] = [], []

    # списки сетей
    for i, l in enumerate(arr("lists")):
        f = f"lists[{i}]"
        if not isinstance(l, dict) or not isinstance(l.get("id"), str) or not ID_RE.match(l["id"]) \
                or Store.lst(st, l["id"]):
            fail(f)
        d = check(f, lambda: _list_body(st, {k: l.get(k) for k in ("kind", "source", "name")}))
        if d["kind"] == "country" and d["source"] != l["id"]:
            fail(f)
        st["lists"].append({"id": l["id"], **d})

    # выходы: сначала все, потом резервные выходы (могут ссылаться друг на друга)
    raw_ups = arr("upstreams")
    for i, u in enumerate(raw_ups):
        f = f"upstreams[{i}]"
        if not isinstance(u, dict) or not isinstance(u.get("id"), str) or not ID_RE.match(u["id"]) \
                or Store.upstream(st, u["id"]):
            fail(f)
        num = u.get("num")
        if not isinstance(num, int) or isinstance(num, bool) or not 1 <= num <= config.MAX_UPSTREAMS \
                or any(x["num"] == num for x in st["upstreams"]):
            fail(f + ".num")
        try:
            pc = awgconf.parse_upstream(str(u.get("config") or ""))
        except awgconf.ConfigError:
            fail(f + ".config")
        flags = {k: u.get(k) if isinstance(u.get(k), str) and MONTH_RE.match(u[k]) else None
                 for k in ("quota_hit", "quota_warned")}
        st["upstreams"].append({"id": u["id"], "name": check(f + ".name", lambda: v_name(u.get("name"))),
                                "num": num, "config": pc.raw, "enabled": bool(u.get("enabled", True)),
                                "fallback": "direct", "created": u.get("created") if _num(u.get("created")) else None,
                                "quota": _int_or_none(u.get("quota")), "quota_action": "notify", **flags})
    for i, u in enumerate(raw_ups):
        fb = check(f"upstreams[{i}].fallback", lambda: v_outbound(st, u.get("fallback") or "direct"))
        if fb == "up:" + u["id"]:
            fail(f"upstreams[{i}].fallback")
        st["upstreams"][i]["fallback"] = fb
        qa = u.get("quota_action") or "notify"
        if qa == "fallback":          # первые сборки 1.3.0: «как резерв»
            qa = fb
        if qa != "notify":
            qa = check(f"upstreams[{i}].quota_action", lambda: v_outbound(st, qa))
            if qa == "up:" + u["id"]:
                fail(f"upstreams[{i}].quota_action")
        st["upstreams"][i]["quota_action"] = qa

    # маршрутизация
    r = obj("routing")
    st["routing"] = {"default": check("routing.default", lambda: v_outbound(st, r.get("default", "direct"))),
                     "rules": check("routing.rules", lambda: v_rules(st, r.get("rules", [])))}

    # политики клиентов
    for pk, c in obj("clients").items():
        f = f"clients.{pk[:12]}"
        if not awgconf.KEY_RE.match(pk) or not isinstance(c, dict):
            fail(f)
        mode = c.get("rules_mode", "inherit")
        if mode not in ("inherit", "custom"):
            fail(f)
        st["clients"][pk] = {
            "outbound": check(f, lambda: v_outbound(st, c.get("outbound", "inherit"), allow_inherit=True)),
            "rules_mode": mode,
            "rules": check(f, lambda: v_rules(st, c.get("rules") or [])) if mode == "custom" else [],
            "note": str(c.get("note") or "")[:120], "name": str(c.get("name") or "")[:60]}

    # закрытые ключи клиентов
    for pk, priv in obj("keys").items():
        if not awgconf.KEY_RE.match(pk) or not isinstance(priv, str) or not awgconf.KEY_RE.match(priv):
            fail(f"keys.{pk[:12]}")
        st["keys"][pk] = priv

    # сроки и лимиты
    for pk, L in obj("limits").items():
        if not awgconf.KEY_RE.match(pk) or not isinstance(L, dict):
            fail(f"limits.{pk[:12]}")
        ao = L.get("auto_off")
        qd, qw = L.get("quota_done"), L.get("quota_warned")
        st["limits"][pk] = {
            "expires": _int_or_none(L.get("expires")), "quota": _int_or_none(L.get("quota")),
            "period": L.get("period") if L.get("period") in ("month", "total") else "month",
            "auto_off": ao if ao == "exp" or (isinstance(ao, str) and ao.startswith("quota:")
                                              and QUOTA_KEY_RE.match(ao[6:])) else None,
            "exp_done": _int_or_none(L.get("exp_done")),
            "quota_done": qd if isinstance(qd, str) and QUOTA_KEY_RE.match(qd) else None,
            "exp_warned": _int_or_none(L.get("exp_warned")),
            "quota_warned": qw if isinstance(qw, str) and QUOTA_KEY_RE.match(qw) else None}

    # свои I1–I5 клиентов
    for pk, e in obj("cps").items():
        if not awgconf.KEY_RE.match(pk) or not isinstance(e, dict):
            fail(f"cps.{pk[:12]}")
        if e.get("preset") in cps.PRESETS:
            st["cps"][pk] = {"preset": e["preset"]}
        elif e.get("preset") == "custom":
            try:
                st["cps"][pk] = {"preset": "custom", "values": cps.validate(e.get("values") or {})}
            except cps.CPSError:
                fail(f"cps.{pk[:12]}")
        else:
            fail(f"cps.{pk[:12]}")

    # личные ссылки
    for tok, sh in obj("shares").items():
        if not TOKEN_RE.match(tok) or not isinstance(sh, dict) or not awgconf.KEY_RE.match(str(sh.get("pk"))):
            fail("shares")
        st["shares"][tok] = {"pk": sh["pk"], "created": sh.get("created") if _num(sh.get("created")) else None}

    # настройки: только известные поля
    s, out = obj("settings"), st["settings"]
    if "list_update_hours" in s:
        if not _num(s["list_update_hours"]):
            fail("settings.list_update_hours")
        out["list_update_hours"] = max(1, min(int(s["list_update_hours"]), 24 * 30))
    if s.get("on_stop") in ("keep", "restore"):
        out["on_stop"] = s["on_stop"]
    h = s.get("public_host")
    if isinstance(h, str) and re.fullmatch(r"[A-Za-z0-9.\-:]{1,253}", h):
        out["public_host"] = h
    dns = s.get("client_dns")
    if dns is not None:
        if not isinstance(dns, list) or len(dns) > 4:
            fail("settings.client_dns")
        for d in dns:
            try:
                ipaddress.ip_address(str(d))
            except ValueError:
                fail("settings.client_dns")
        out["client_dns"] = [str(d) for d in dns]
    mtu = s.get("client_mtu")
    if mtu not in (None, ""):
        if not isinstance(mtu, int) or isinstance(mtu, bool) or not 1100 <= mtu <= 1500:
            fail("settings.client_mtu")
        out["client_mtu"] = mtu
    ka = s.get("client_keepalive")
    if ka not in (None, ""):
        if not isinstance(ka, str) or not re.fullmatch(r"\d{1,5}(-\d{1,5})?", ka):
            fail("settings.client_keepalive")
        out["client_keepalive"] = ka
    tg = s.get("telegram")
    if tg is not None:
        if not isinstance(tg, dict):
            fail("settings.telegram")
        c = notify.defaults()
        tok, chat = str(tg.get("token") or ""), str(tg.get("chat_id") or "")
        if (tok and not TG_TOKEN_RE.match(tok)) or (chat and not TG_CHAT_RE.match(chat)):
            fail("settings.telegram")
        c.update(token=tok, chat_id=chat, lang=tg.get("lang") if tg.get("lang") in notify.LANGS else "en",
                 enabled=bool(tg.get("enabled")) and bool(tok and chat))
        ev = tg.get("events") if isinstance(tg.get("events"), dict) else {}
        c["events"] = {k: bool(ev.get(k, True)) for k in notify.KINDS}
        if tg.get("backup") in notify.BACKUP_PERIODS:
            c["backup"] = tg["backup"]
        if isinstance(tg.get("backup_pw"), str) and len(tg["backup_pw"]) <= 128:
            c["backup_pw"] = tg["backup_pw"]
        out["telegram"] = c
    return st


def clean_server_files(srv: dict, kind: str) -> tuple[awgserver.ServerConf, dict[str, str]]:
    """Файлы сервера из резервной копии → проверенный конфиг и служебные файлы."""
    files = srv.get("files")
    if not isinstance(files, dict):
        bad("err.backup_format")
    conf = files.get(srv.get("conf") or "")
    if not isinstance(conf, str):
        bad("err.backup_format")
    sc = awgserver.parse(conf)
    if not awgconf.KEY_RE.match(sc.get("PrivateKey")) or not sc.network:
        bad("err.backup_format")
    for p in sc.peers:
        if not awgconf.KEY_RE.match(p.public_key) or (p.psk and not awgconf.KEY_RE.match(p.psk)):
            bad(Msg("err.backup_field", field="server.peers"))
    awgserver.safe_hooks(sc, kind == "host")
    out = {}
    for name in ("wireguard_psk.key", "wireguard_server_public_key.key"):
        text = files.get(name)
        if text is None:
            continue
        if not isinstance(text, str) or not awgconf.KEY_RE.match(text.strip()):
            bad(Msg("err.backup_field", field=f"server.{name}"))
        out[name] = text.strip() + "\n"
    if isinstance(files.get("clientsTable"), str):
        out["clientsTable"] = awgserver.render_clients_table(
            awgserver.parse_clients_table(files["clientsTable"]))
    return sc, out


@app.post("/api/restore")
def restore_backup(req):
    body = req.json()
    b = body.get("backup")
    if not isinstance(b, dict) or b.get("format") != BACKUP_FORMAT or not isinstance(b.get("state"), dict):
        bad("err.backup_format")
    if not all(k in b["state"] for k in ("routing", "upstreams", "lists", "settings")):
        bad("err.backup_format")
    new = clean_backup_state(b["state"])
    srv = b.get("server") if body.get("server") else None
    t = engine.target
    sc = None
    srv_files: dict[str, str] = {}
    if srv:
        if not isinstance(srv, dict):
            bad("err.backup_format")
        if not t or not t.exists:
            bad("srv.no_server")
        if srv.get("kind") != t.kind:
            bad("err.backup_kind")
        sc, srv_files = clean_server_files(srv, t.kind)

    def fn(st):
        keep_host = st["settings"].get("public_host")
        st.clear()
        st.update(new)
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
            for name, text in srv_files.items():
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
            L["quota_done"] = L["quota_warned"] = None
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


def _share_exists(token: str) -> bool:
    return bool(TOKEN_RE.match(token)) and token in store.snapshot().get("shares", {})


@app.get("/s/{token}", public=True)
def share_page(req, token):
    if not _share_exists(token):       # на чужие адреса — как будто страницы нет
        bad("err.not_found", 404)
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
        except Exception:  # noqa: BLE001
            cfg = None
    live = c.get("live") or {}
    return {"name": c.get("name") or "", "enabled": c["enabled"], "now": time.time(),
            "handshake": live.get("handshake") or None, "config": cfg,
            # разбивка по выходам — только в панели: на публичной странице она ни к чему
            "traffic": {k: v for k, v in engine.traffic.view(pk).items() if k != "by_out"},
            "limits": limits.view(st.get("limits", {}).get(pk))}


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
            "refs": Store.outbound_refs(st, "up:" + u["id"]),
            "quota": u.get("quota"), "quota_action": engine.quota_target(u) or "notify",
            "over_quota": bool(u.get("quota")) and engine.traffic.out_used(u["id"]) >= u["quota"],
            "traffic": engine.traffic.out_view(u["id"])}


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
            "cps": cps_view(st.get("cps", {}).get(c["public_key"])),
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
        "version": {**updates.status(), "update": selfupdate.status()},
        "month": month_key(),
        "notify_error": notifier.last_error,
        "upstreams": [_upstream_view(st, u) for u in st["upstreams"]],
        "direct_traffic": engine.traffic.out_view("direct"),
        "acct": {"state": engine.acct_state, "error": engine.acct_error},
        "lists": [{**_list_view(l), "refs": Store.list_refs(st, l["id"])} for l in st["lists"]],
        "clients": clients,
        "events": engine.events[-40:][::-1],
        "country_codes": lists.COUNTRY_CODES,
    }


# ---------------------------------------------------------------- upstreams
def v_exit_quota(body: dict) -> int | None:
    """quota_gb из формы выхода ("" / None — без лимита) → байты."""
    q = body.get("quota_gb")
    if q in (None, ""):
        quota = None
    else:
        try:
            q = float(q)
        except (TypeError, ValueError):
            bad("err.quota")
        if not 0 < q <= 1_000_000:
            bad("err.quota")
        quota = int(q * limits.GB)
    return quota


def v_quota_action(st: dict, v, uid: str | None) -> str:
    """Что делать при исчерпании квоты: 'notify' или выход (direct / block / up:<id>, не сам)."""
    if v in (None, "", "notify"):
        return "notify"
    out = v_outbound(st, v)
    if uid and out == "up:" + uid:
        bad("err.quota_self")
    return out


@app.post("/api/upstreams")
def add_upstream(req):
    body = req.json()
    quota = v_exit_quota(body)
    try:
        pc = awgconf.parse_upstream(str(body.get("config", "")))
    except awgconf.ConfigError as e:
        bad(e.msg)
    name = v_name(body.get("name"))

    def fn(st):
        fb = v_outbound(st, body.get("fallback") or "direct")
        u = {"id": new_id("u"), "name": name, "num": Store.free_num(st), "config": pc.raw,
             "enabled": True, "fallback": fb, "created": time.time(),
             "quota": quota, "quota_action": v_quota_action(st, body.get("quota_action"), None)}
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
    quota = None
    if "quota_gb" in body:
        quota = v_exit_quota(body)

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
        if "quota_gb" in body:
            action = v_quota_action(st, body.get("quota_action"), uid)
            if quota != u.get("quota") or action != (engine.quota_target(u) or "notify"):
                u["quota_hit"] = u["quota_warned"] = None   # события квоты — заново
            u["quota"], u["quota_action"] = quota, action
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
    engine.traffic.forget_out(uid)
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


# ------------------------------------------- свои сигнатурные пакеты I1–I5 клиента
def cps_view(entry) -> dict | None:
    if not isinstance(entry, dict) or entry.get("preset") not in (*cps.PRESETS, "custom"):
        return None
    return {"preset": entry["preset"],
            "values": cps.for_client(entry) if entry["preset"] == "custom" else None}


@app.get("/api/cps")
def get_cps(req):
    """Шаблоны и текущие I1–I5 сервера — для выбора маскировки в окне клиента."""
    try:
        sv = engine.srv.server_view()
    except Exception:  # noqa: BLE001  — сервер недоступен: шаблоны всё равно нужны
        sv = {}
    params = sv.get("params") or {}
    return {"presets": cps.catalog(), "server": {k: params.get(k) or "" for k in cps.KEYS},
            "server_match": sv.get("cps_server")}


@app.put("/api/cps/{pk:path}")
def put_client_cps(req, pk):
    """preset: "server" (как на сервере) | имя шаблона | "custom" + values {I1..I5}."""
    if not awgconf.KEY_RE.match(pk) and not (config.DRY_RUN and pk.startswith("DEMO")):
        bad("err.bad_client_key")
    if not any(c["public_key"] == pk for c in engine.clients):
        bad("err.not_found", 404)
    body = req.json()
    p = body.get("preset") or "server"
    if p not in (*cps.PRESETS, "custom", "server"):
        bad("err.bad_value")
    entry = None
    if p == "custom":
        try:
            entry = {"preset": "custom", "values": cps.validate(body.get("values") or {})}
        except cps.CPSError as e:
            bad(e.msg)
    elif p != "server":
        entry = {"preset": p}

    def fn(st):
        m = st.setdefault("cps", {})
        if entry:
            m[pk] = entry
        else:
            m.pop(pk, None)
    store.mutate(fn)
    return {"ok": True, "cps": cps_view(entry)}


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
def _list_view(l: dict | None) -> dict | None:
    """Список для браузера. Текст ручного списка (до 2 МБ) не отдаём в /api/state,
    который опрашивается каждые 5 секунд, — только по /api/lists/<id>."""
    if l is None or l.get("kind") != "manual":
        return l
    return {**l, "source": None}


@app.get("/api/lists/{lid}")
def get_list(req, lid):
    l = Store.lst(store.snapshot(), lid)
    if not l:
        bad("err.not_found", 404)
    return l


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
    return {"id": lid, **(_list_view(Store.lst(store.snapshot(), lid)) or {})}


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
    return _list_view(Store.lst(store.snapshot(), lid))


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
    return _list_view(Store.lst(store.snapshot(), lid))


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
        threading.Thread(target=_backup_loop, name="backup", daemon=True).start()
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
