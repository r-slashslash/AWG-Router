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


class Page:
    """Ответ-страница (HTML) вместо JSON."""

    def __init__(self, body: bytes, ctype: str = "text/html; charset=utf-8"):
        self.body = body
        self.ctype = ctype


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
        self.public_static: tuple[str, str] | None = None   # без секретного пути и без входа
        self.public_files: set[str] = set()                  # какие файлы отдавать по public_static
        self.index_file: str | None = None
        self.public: set = set()                             # обработчики без проверки входа

    def route(self, method: str, pattern: str, public: bool = False):
        # /lists/{lid} → именованные группы; {pk:path} — с косыми чертами
        # public=True: адрес без секретного префикса и без проверки входа
        rx = re.sub(r"\{(\w+):path\}", r"(?P<\1>.+)", pattern)
        rx = re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", rx)
        compiled = re.compile("^" + ("" if public else re.escape(self.base)) + rx + "$")

        def deco(fn):
            self.routes.append((method, compiled, fn))
            if public:
                self.public.add(fn)
            return fn
        return deco

    def get(self, p, public=False): return self.route("GET", p, public)
    def post(self, p, public=False): return self.route("POST", p, public)
    def put(self, p, public=False): return self.route("PUT", p, public)
    def delete(self, p, public=False): return self.route("DELETE", p, public)

    def handler(self):
        app = self

        class H(BaseHTTPRequestHandler):
            server_version = "awg-router"
            sys_version = ""

            def version_string(self):  # заголовок Server не выдаёт панель сканерам
                return "httpd"

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
                    for mount in (app.static, app.public_static):
                        if mount and path.startswith(mount[0] + "/") and self.command in ("GET", "HEAD"):
                            rel = path[len(mount[0]) + 1:]
                            if mount is app.public_static and rel not in app.public_files:
                                raise HTTPError(404, "err.not_found")
                            return self._static(mount[1], rel)
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
                        if app.middleware and fn not in app.public:
                            app.middleware(req)
                        res = fn(req, **m.groupdict())
                        if isinstance(res, Page):
                            return self._send(200, res.body, res.ctype, [("Cache-Control", "no-store")])
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

            def _static(self, root: str, rel: str):
                root = os.path.realpath(root)
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
