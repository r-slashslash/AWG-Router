"""Вход в панель: пароль, сессии, вход по коду (TOTP), защита от перебора паролей и от запросов
с чужих страниц (same_origin)."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time

from .. import (config, totp)
from ..checks import bad
from ..panel import (BASE, app, engine, notifier, store, tls)
from ..store import fsync_dir
from ..web import HTTPError, content_length

log = logging.getLogger("awgr")
COOKIE = "awgr_session"
SESSION_TTL = 4 * 3600  # вход в панель действует 4 часа


# ------------------------------------------------------------------ секреты
def _secret_file(name: str, gen) -> str:
    p = os.path.join(config.DATA_DIR, name)
    if os.path.exists(p):
        with open(p) as f:
            return f.read().strip()
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
    # сам пароль — в журнал только при первом запуске, когда файл создаётся: журнал контейнера живёт
    # долго и попадает в отчёты, а пароль и так лежит в data/panel_password
    _first = not os.path.exists(os.path.join(config.DATA_DIR, "panel_password"))
    PASSWORD = _secret_file("panel_password", lambda: secrets.token_urlsafe(12))
    if _first:
        log.warning("PANEL_PASSWORD is not set. Panel password: %s (file data/panel_password)", PASSWORD)
    else:
        log.warning("PANEL_PASSWORD is not set: the panel password is in data/panel_password")


def _tag(material: str) -> str:
    """Метка сессии из пароля: HMAC с ключом панели, а не голый SHA-256.

    Метка лежит в cookie открытым текстом; без ключа по ней нельзя перебирать пароли.
    """
    return hmac.new(SECRET, material.encode(), hashlib.sha256).hexdigest()[:8]


PW_TAG = _tag(PASSWORD)  # смена пароля = выход везде

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
        f.flush()
        os.fsync(f.fileno())        # после сбоя питания — новый пароль, а не пустой файл или прежний
    os.replace(tmp, PW_FILE)
    fsync_dir(os.path.dirname(PW_FILE))


def _sign(payload: str) -> str:
    return hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()[:32]


def sec_tag() -> str:
    """Метка в сессии: смена пароля или включение/выключение входа по коду = выход везде."""
    c = custom_password()
    t = totp.load()
    if not c and not t:
        return PW_TAG
    material = ("h:" + c["hash"]) if c else PASSWORD
    return _tag(f"{material}|{t['secret'] if t else ''}")


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


def same_origin(req) -> bool:
    """Запрос, меняющий что-то, пришёл со страницы самой панели. Cookie с SameSite=Strict не уходит с чужих
    сайтов, но уходит со страниц того же сайта: другой порт этого IP, соседний поддомен. Форма оттуда отправит
    POST без тела — его не останавливает проверка JSON. Браузер говорит, откуда запрос (Sec-Fetch-Site), а
    без этого заголовка — Origin; нет ни того, ни другого (curl, старый браузер) — пропускаем, как раньше."""
    if req.method in ("GET", "HEAD"):
        return True
    site = (req.headers.get("Sec-Fetch-Site") or "").strip().lower()
    if site:
        return site in ("same-origin", "none")
    origin = (req.headers.get("Origin") or "").strip()
    if not origin or origin == "null":
        return not origin
    host = (req.headers.get("Host") or "").strip().lower()
    return origin.split("://", 1)[-1].rstrip("/").lower() == host


def auth_mw(req) -> None:
    if not same_origin(req):
        raise HTTPError(403, "err.cross_site")
    if req.path == BASE + "/api/login":
        return
    if not check_session(req.cookies.get(COOKIE)):
        raise HTTPError(401, "auth")
    req.authed = True
    # тело запроса — только JSON (простые формы с чужих сайтов так не отправить)
    ctype = req.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if content_length(req.headers) > 0 and ctype != "application/json":
        raise HTTPError(415, "err.json_required")


app.middleware = auth_mw


# --------------------------------------------------------------------- auth
FAIL_WINDOW, FAIL_MAX = 600, 8      # не больше FAIL_MAX неудачных попыток за FAIL_WINDOW секунд с адреса
LOGIN_BODY = 64 * 1024              # тело запроса входа: пароль и код, а не мегабайты от кого угодно
_fails_lock = threading.Lock()
_inflight: dict[str, int] = {}     # проверки пароля, которые идут сейчас (ещё не засчитаны)


def _check_blocked(ip: str) -> None:
    """Попытка входа с адреса: идущие сейчас проверки считаются вместе с неудачными. Иначе 24 соединения
    с одного адреса проверяли бы 24 пароля разом, хотя предел — 8 за 10 минут. Старые адреса забываются."""
    now = time.time()
    with _fails_lock:
        for k in [k for k, v in _fails.items() if not v or now - v[-1] >= FAIL_WINDOW]:
            _fails.pop(k, None)
        recent = [t for t in _fails.get(ip, []) if now - t < FAIL_WINDOW]
        if recent:
            _fails[ip] = recent
        if len(recent) + _inflight.get(ip, 0) >= FAIL_MAX:
            bad("err.too_many_attempts", 429)
        _inflight[ip] = _inflight.get(ip, 0) + 1


def _done(ip: str) -> None:
    """Проверка с адреса закончилась (успехом или отказом) — она больше не «идёт»."""
    with _fails_lock:
        n = _inflight.get(ip, 0) - 1
        if n > 0:
            _inflight[ip] = n
        else:
            _inflight.pop(ip, None)


def _failed(ip: str, msg: str) -> None:
    with _fails_lock:
        _fails.setdefault(ip, []).append(time.time())
        n = len(_fails[ip])
    if n == FAIL_MAX:
        notifier.event("login", "login_blocked", cooldown=600, ip=ip)
    time.sleep(1)
    bad(msg, 403)


def _set_session(req) -> None:
    req.cookie(COOKIE, make_session(), max_age=SESSION_TTL, path=BASE or "/",
               secure=bool(tls.context()) or req.headers.get("X-Forwarded-Proto") == "https")
    req.authed = True               # вход прошёл: адресу — запасные места (web.RESERVE)


@app.post("/api/login")
def login(req):
    ip = req.client_ip
    _check_blocked(ip)
    try:
        return _login(req, ip)
    finally:
        _done(ip)


def _login(req, ip: str):
    body = req.json(limit=LOGIN_BODY)
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
    try:
        return _totp_disable(req, ip)
    finally:
        _done(ip)


def _totp_disable(req, ip: str):
    body = req.json()
    if not totp.load():
        return {"ok": True}
    if not totp.check_and_use(body.get("code")):
        _failed(ip, "err.wrong_code")
    totp.save(None)
    _set_session(req)
    log.info("Two-factor sign-in disabled")
    return {"ok": True}


# ------------------------------------------------------------- смена пароля
@app.post("/api/password")
def change_password(req):
    ip = req.client_ip
    _check_blocked(ip)
    try:
        return _change_password(req, ip)
    finally:
        _done(ip)


def _change_password(req, ip: str):
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
