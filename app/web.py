"""Минимальный HTTP-фреймворк на стандартной библиотеке (без внешних зависимостей)."""
from __future__ import annotations

import json
import logging
import mimetypes
import os
import re
import socket
import ssl
import traceback
from http import cookies as httpcookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from .i18n import Msg, to_json

log = logging.getLogger("awgr.web")
MAX_BODY = 4 * 1024 * 1024


class HTTPError(Exception):
    def __init__(self, code: int, detail):
        if isinstance(detail, str):
            detail = Msg(detail)
        super().__init__(str(detail))
        self.code = code
        self.detail = detail


class Request:
    def __init__(self, h: BaseHTTPRequestHandler, path: str, params: dict):
        self.h = h
        self.method = h.command
        self.path = path
        self.params = params
        self.headers = h.headers
        self.client_ip = h.client_address[0]
        c = httpcookies.SimpleCookie()
        try:
            c.load(h.headers.get("Cookie", ""))
        except httpcookies.CookieError:
            pass
        self.cookies = {k: m.value for k, m in c.items()}
        self.set_cookies: list[str] = []
        self._body = None

    def json(self) -> dict:
        if self._body is None:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise HTTPError(413, "err.too_large")
            raw = self.h.rfile.read(n) if n else b"{}"
            self.h.body_read = True
            try:
                self._body = json.loads(raw or b"{}")
            except ValueError:
                raise HTTPError(400, "err.bad_json")
            if not isinstance(self._body, dict):
                raise HTTPError(400, "err.bad_json")
        return self._body

    def cookie(self, name: str, value: str, *, max_age: int, path: str, secure: bool = False):
        parts = [f"{name}={value}", f"Max-Age={max_age}", f"Path={path}", "HttpOnly", "SameSite=Strict"]
        if secure:
            parts.append("Secure")
        self.set_cookies.append("; ".join(parts))


class App:
    def __init__(self, base: str = ""):
        self.base = base
        self.routes: list[tuple[str, re.Pattern, callable]] = []
        self.middleware = None
        self.static: tuple[str, str] | None = None
        self.index_file: str | None = None

    def route(self, method: str, pattern: str):
        # /lists/{lid} → именованные группы; {pk:path} — с косыми чертами
        rx = re.sub(r"\{(\w+):path\}", r"(?P<\1>.+)", pattern)
        rx = re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", rx)
        compiled = re.compile("^" + re.escape(self.base) + rx + "$")

        def deco(fn):
            self.routes.append((method, compiled, fn))
            return fn
        return deco

    def get(self, p): return self.route("GET", p)
    def post(self, p): return self.route("POST", p)
    def put(self, p): return self.route("PUT", p)
    def delete(self, p): return self.route("DELETE", p)

    def handler(self):
        app = self

        class H(BaseHTTPRequestHandler):
            server_version = "awg-router"
            sys_version = ""

            def log_message(self, fmt, *args):  # тихо
                pass

            def _send(self, code: int, body: bytes, ctype: str, extra: list[tuple[str, str]] = ()):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                for k, v in extra:
                    self.send_header(k, v)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _json(self, code: int, obj, extra=()):
                self._send(code, json.dumps(to_json(obj), ensure_ascii=False).encode(),
                           "application/json; charset=utf-8", [("Cache-Control", "no-store"), *extra])

            def _dispatch(self):
                self.body_read = False
                try:
                    self._dispatch_inner()
                finally:
                    self._drain_body()

            def _drain_body(self):
                # Непрочитанное тело запроса (ответ 401/404/413 раньше json()) иначе
                # будет разобрано как следующий запрос на keep-alive соединении
                if self.body_read:
                    return
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    n = -1
                if n == 0:
                    return
                if 0 < n <= MAX_BODY:
                    try:
                        self.rfile.read(n)
                        return
                    except OSError:
                        pass
                self.close_connection = True

            def _dispatch_inner(self):
                path = unquote(urlsplit(self.path).path)
                try:
                    # статика
                    if app.static and path.startswith(app.static[0] + "/") and self.command in ("GET", "HEAD"):
                        return self._static(path[len(app.static[0]) + 1:])
                    if app.index_file and self.command in ("GET", "HEAD"):
                        if path == app.base + "/" or path == "/" and not app.base:
                            body = open(app.index_file, "rb").read()
                            return self._send(200, body, "text/html; charset=utf-8",
                                              [("Cache-Control", "no-store")])
                        if app.base and path == app.base:
                            return self._send(301, b"", "text/plain", [("Location", app.base + "/")])
                    allowed = False
                    for method, rx, fn in app.routes:
                        m = rx.match(path)
                        if not m:
                            continue
                        allowed = True
                        if method != self.command:
                            continue
                        req = Request(self, path, m.groupdict())
                        if app.middleware:
                            app.middleware(req)
                        res = fn(req, **m.groupdict())
                        return self._json(200, res if res is not None else {"ok": True},
                                          [("Set-Cookie", c) for c in req.set_cookies])
                    if allowed:
                        raise HTTPError(405, "err.method")
                    raise HTTPError(404, "err.not_found")
                except HTTPError as e:
                    extra = ()
                    if e.code == 413:
                        self.close_connection = True
                        extra = [("Connection", "close")]
                    self._json(e.code, {"detail": e.detail}, extra)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except Exception as e:  # noqa: BLE001
                    log.error("%s %s: %s\n%s", self.command, path, e, traceback.format_exc())
                    try:
                        self._json(500, {"detail": Msg("err.internal", detail=str(e)[:300])})
                    except Exception:  # noqa: BLE001
                        pass

            def _static(self, rel: str):
                root = os.path.realpath(app.static[1])
                p = os.path.realpath(os.path.join(root, rel))
                if not p.startswith(root + os.sep) or not os.path.isfile(p):
                    raise HTTPError(404, "err.not_found")
                ctype = mimetypes.guess_type(p)[0] or "application/octet-stream"
                if ctype.startswith("text/") or ctype in ("application/javascript",):
                    ctype += "; charset=utf-8"
                with open(p, "rb") as f:
                    self._send(200, f.read(), ctype, [("Cache-Control", "no-cache")])

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _dispatch

        return H

    def serve(self, host: str, port: int, tls=None) -> ThreadingHTTPServer:
        """tls — функция, возвращающая текущий SSLContext (или None для HTTP)."""
        srv = Server((host, port), self.handler())
        srv.tls = tls
        return srv


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    tls = None
    request_queue_size = 64

    def finish_request(self, request, client_address):
        ctx = self.tls() if self.tls else None
        if not ctx:
            return super().finish_request(request, client_address)
        request.settimeout(15)
        try:
            first = request.recv(1, socket.MSG_PEEK)
        except OSError:
            return
        if not first:
            return
        if first[0] != 0x16:            # не TLS: кто-то открыл http:// — перенаправим на https://
            return _redirect_plain(request)
        try:
            tls_sock = ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            tls_sock.settimeout(120)
            self.RequestHandlerClass(tls_sock, client_address, self)
        finally:
            try:
                tls_sock.close()
            except OSError:
                pass

    def handle_error(self, request, client_address):  # без трассировок на каждый обрыв
        log.debug("connection error from %s", client_address)


def _redirect_plain(sock) -> None:
    try:
        data = sock.recv(8192).decode("latin-1", "replace")
        m = re.search(r"^Host:\s*([^\r\n]+)", data, re.I | re.M)
        path = data.split(" ", 2)[1] if data.count(" ") >= 2 else "/"
        if not path.startswith("/"):
            path = "/"
        if not m:
            return
        loc = f"https://{m.group(1).strip()}{path}"
        sock.sendall((f"HTTP/1.1 301 Moved Permanently\r\nLocation: {loc}\r\n"
                      "Content-Length: 0\r\nConnection: close\r\n\r\n").encode())
    except OSError:
        pass
