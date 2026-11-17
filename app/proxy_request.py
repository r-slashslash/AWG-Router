"""Разбор CONNECT-запроса HTTPS-прокси до открытия исходящего соединения."""
from __future__ import annotations

import ipaddress
import re
import urllib.parse

MAX_HEAD = 16384
_HOST = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
MAX_BODY = 64 * 1024 * 1024


def parse_connect(head: bytes) -> tuple[str, int, str]:
    """Вернуть host, port и Proxy-Authorization; другие методы пока не поддерживаются."""
    if not isinstance(head, bytes) or len(head) > MAX_HEAD or not head.endswith(b"\r\n\r\n"):
        raise ValueError("invalid request headers")
    try:
        lines = head[:-4].decode("ascii").split("\r\n")
        method, authority, version = lines[0].split(" ")
        if method != "CONNECT" or version not in ("HTTP/1.0", "HTTP/1.1"):
            raise ValueError("unsupported request")
        host, sep, port = authority.rpartition(":")
        if not sep or not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise ValueError("invalid port")
        if host.startswith("[") and host.endswith("]"):
            host = str(ipaddress.IPv6Address(host[1:-1]))
        elif not _HOST.fullmatch(host):
            raise ValueError("invalid hostname")
        headers = {}
        for line in lines[1:]:
            key, sep, value = line.partition(":")
            if not sep or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
                raise ValueError("invalid header")
            key = key.lower()
            if key in headers or any(ord(c) < 32 and c != "\t" for c in value):
                raise ValueError("duplicate or invalid header")
            headers[key] = value.strip()
        if "content-length" in headers or "transfer-encoding" in headers:
            raise ValueError("request body is not allowed")
        return host.lower(), int(port), headers.get("proxy-authorization", "")
    except (UnicodeError, IndexError) as exc:
        raise ValueError("invalid request") from exc


def parse_http(head: bytes) -> tuple[str, int, str, bytes, int]:
    """Один HTTP-запрос с Content-Length, без повторного использования соединения."""
    if not isinstance(head, bytes) or len(head) > MAX_HEAD or not head.endswith(b"\r\n\r\n"):
        raise ValueError("invalid request headers")
    try:
        lines = head[:-4].decode("ascii").split("\r\n")
        method, target, version = lines[0].split(" ")
        if method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS") \
                or version not in ("HTTP/1.0", "HTTP/1.1") or any(ord(c) <= 32 or ord(c) == 127 for c in target):
            raise ValueError("unsupported request")
        url = urllib.parse.urlsplit(target)
        if url.scheme != "http" or not url.hostname or url.username is not None or url.password is not None or url.fragment:
            raise ValueError("invalid target")
        host = url.hostname.lower()
        port = url.port if url.port is not None else 80
        if not _HOST.fullmatch(host) or not 1 <= port <= 65535:
            raise ValueError("invalid host")
        headers = {}
        for line in lines[1:]:
            key, sep, value = line.partition(":")
            if not sep or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
                raise ValueError("invalid header")
            key = key.lower()
            if key in headers or any(ord(c) < 32 and c != "\t" for c in value):
                raise ValueError("duplicate or invalid header")
            headers[key] = value.strip()
        if "transfer-encoding" in headers or "expect" in headers:
            raise ValueError("unsupported body encoding")
        raw_len = headers.get("content-length", "0")
        if not raw_len.isascii() or not raw_len.isdecimal() or int(raw_len) > MAX_BODY:
            raise ValueError("invalid body length")
        auth = headers.pop("proxy-authorization", "")
        nominated = [x.strip().lower() for x in headers.get("connection", "").split(",")]
        if any(x in ("host", "content-length", "transfer-encoding") for x in nominated):
            raise ValueError("invalid connection header")
        for key in nominated + ["connection", "proxy-connection", "host", "keep-alive", "upgrade", "te", "trailer"]:
            headers.pop(key, None)
        path = urllib.parse.urlunsplit(("", "", url.path or "/", url.query, ""))
        address = host if port == 80 else f"{host}:{port}"
        start = f"{method} {path} {version}\r\nHost: {address}\r\nConnection: close\r\n"
        rest = "".join(f"{key}: {value}\r\n" for key, value in headers.items())
        return host, port, auth, (start + rest + "\r\n").encode("ascii"), int(raw_len)
    except (UnicodeError, IndexError) as exc:
        raise ValueError("invalid request") from exc
