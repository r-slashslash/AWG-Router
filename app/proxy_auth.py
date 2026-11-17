"""Проверка учётных данных и адресов будущего HTTPS-прокси."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import secrets

ITERATIONS = 200_000
MAX_HEADER = 4096


def password_record(password: str) -> dict:
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise ValueError("password must contain 12–256 characters")
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS).hex()
    return {"salt": salt, "hash": digest, "iterations": ITERATIONS}


def authenticate(header: str, username: str, record: dict) -> bool:
    """Принимает Basic только в пределах уже установленного TLS-соединения."""
    if not isinstance(header, str) or len(header) > MAX_HEADER:
        return False
    scheme, sep, token = header.partition(" ")
    if not sep or scheme.lower() != "basic":
        return False
    try:
        raw = base64.b64decode(token, validate=True).decode("utf-8")
        login, colon, password = raw.partition(":")
        iterations = record["iterations"]
        if not colon or not isinstance(iterations, int) or iterations != ITERATIONS:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(record["salt"]), iterations).hex()
        return hmac.compare_digest(login.encode(), username.encode()) and hmac.compare_digest(digest, record["hash"])
    except (ValueError, UnicodeError, TypeError, KeyError, binascii.Error):
        return False


def public_address(value: str) -> bool:
    """Проверять фактический адрес после DNS, а не только имя из запроса."""
    try:
        ip = ipaddress.ip_address(value)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return ip.is_global
    except ValueError:
        return False
