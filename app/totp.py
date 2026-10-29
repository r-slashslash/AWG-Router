"""Второй фактор входа: одноразовые коды TOTP (RFC 6238) из приложения-аутентификатора.

Секрет лежит в data/totp.json. Файл читается при каждой проверке (с учётом mtime),
поэтому `awg-router 2fa-off` (удаление файла) действует сразу, без перезапуска панели.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
from urllib.parse import quote

from . import config

PATH = os.path.join(config.DATA_DIR, "totp.json")
STEP = 30
DIGITS = 6
WINDOW = 1          # допускаем соседние 30-секундные интервалы (расхождение часов)

_lock = threading.RLock()
_cache: tuple[float | None, dict | None] = (None, None)


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    s = secret.upper().replace(" ", "")
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret: str, step: int) -> str:
    d = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    v = (struct.unpack(">I", d[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(v).zfill(DIGITS)


def match(secret: str, code: str, now: float | None = None, after: int = -1) -> int | None:
    """Номер интервала, которому соответствует код, или None. after — уже использованный интервал."""
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != DIGITS:
        return None
    cur = int((time.time() if now is None else now) // STEP)
    for st in range(cur - WINDOW, cur + WINDOW + 1):
        if st > after and hmac.compare_digest(code_at(secret, st), code):
            return st
    return None


def uri(secret: str, label: str) -> str:
    """Ссылка otpauth:// для QR-кода."""
    name = quote(f"AWG Router:{label}" if label else "AWG Router")
    return f"otpauth://totp/{name}?secret={secret}&issuer=AWG%20Router&digits={DIGITS}&period={STEP}"


# ------------------------------------------------------------------ хранение
def load() -> dict | None:
    """{"secret", "since", "last_step"} или None, если вход по коду выключен."""
    global _cache
    try:
        mt = os.stat(PATH).st_mtime
    except OSError:
        _cache = (None, None)
        return None
    if _cache[0] == mt and _cache[1] is not None:
        return dict(_cache[1])
    try:
        with open(PATH) as f:
            d = json.load(f)
        if not isinstance(d, dict) or not d.get("secret"):
            return None
        _key(d["secret"])
    except (OSError, ValueError):
        return None
    _cache = (mt, d)
    return dict(d)


def save(d: dict | None) -> None:
    global _cache
    with _lock:
        if d is None:
            try:
                os.remove(PATH)
            except FileNotFoundError:
                pass
            _cache = (None, None)
            return
        tmp = PATH + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(d, f)
        os.replace(tmp, PATH)
        _cache = (None, None)


def check_and_use(code: str) -> bool:
    """Проверяет код включённого второго фактора; использованный код повторно не примется."""
    with _lock:
        d = load()
        if not d:
            return False
        st = match(d["secret"], code, after=int(d.get("last_step", -1)))
        if st is None:
            return False
        d["last_step"] = st
        save(d)
    return True
