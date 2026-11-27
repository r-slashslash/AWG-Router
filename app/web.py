"""Минимальный HTTP-фреймворк на стандартной библиотеке (без внешних зависимостей)."""
from __future__ import annotations

import errno
import gzip
import hashlib
import ipaddress
import json
import logging
import math
import mimetypes
import os
import re
import socket
import ssl
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from .i18n import Msg


def _msg_json(v):
    """Msg в ответе — {"$t": …}: кодировщик на C зовёт Python только для них (раньше весь ответ сначала копировался
    на Python, to_json: на 1000 клиентах 16 мс на ответ вместо 6). Байты ответа те же."""
    if isinstance(v, Msg):
        return v.to_json()
    raise TypeError(f"{type(v).__name__} is not JSON serializable")

mimetypes.add_type("application/manifest+json", ".webmanifest")   # иконка на главный экран

log = logging.getLogger("awgr.web")
MAX_BODY = 4 * 1024 * 1024
MAX_CONNECTIONS = 128      # одновременных соединений; лишние закрываются сразу
MAX_PER_IP = 24            # с одного адреса: один источник не займёт все места
MAX_PER_NET = 48           # с одной сети IPv6 /48 (столько обычно у одного абонента или сервера): смена /64 не поможет
RESERVE = 16               # мест сверх MAX_CONNECTIONS — адресам, с которых недавно входили в панель
TRUST_TTL = 24 * 3600      # сколько адрес после входа считается своим (RESERVE)
IDLE_TIMEOUT = 60          # секунд на заголовки и тело запроса
KEEP_IDLE = 15             # секунд ожидания следующего запроса в том же соединении (панель опрашивает раз в 5)
# Предел времени на весь запрос, а не на одно чтение: клиент, присылающий по байту раз в 59 секунд,
# иначе держал бы место бесконечно («медленные» соединения занимали бы все MAX_CONNECTIONS)
HEAD_DEADLINE = 30         # секунд на рукопожатие TLS, строку запроса и заголовки
BODY_DEADLINE = 120        # секунд на тело запроса (до MAX_BODY: копия настроек)
GZIP_MIN = 1024            # байт: ответы короче не сжимаются
GZIP_TYPES = ("text/", "application/json", "application/javascript", "application/manifest+json",
              "image/svg+xml")
# Страницы панели берут скрипты, стили и шрифты только у самой панели (сторонних хостов нет по правилам
# проекта). CSP закрепляет это в браузере: даже если где-то забудут экранировать имя клиента, чужой
# скрипт не выполнится. style 'unsafe-inline' — у разметки есть атрибуты style; data: и blob: —
# значок страницы, QR-код и скачивание копии.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
       "font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
       "form-action 'self'")
_gz_cache: dict[str, tuple[str, bytes]] = {}     # путь файла статики → (ETag, сжатое тело)
_gz_lock = threading.Lock()
# Адреса статики в страницах — с отпечатком всех её файлов (static/v-<отпечаток>/…, App.static_tag): такой файл
# браузер берёт из своего кэша без перепроверки, пока отпечаток тот же. Раньше каждое открытие панели перепроверяло
# 13 файлов (ответ 304): по связи с задержкой 300 мс — 1,6 с (оптимизация 2026-11-21). Новый выпуск или правка файла —
# новый отпечаток, новые адреса. Файл манифеста — без отпечатка: адрес манифеста — часть установленного приложения.
STATIC_TAG = re.compile(r"v-([0-9a-f]{12})/")
STATIC_TAG_TTL = 2.0       # с: отпечаток считается заново не чаще (обход папки статики)
IMMUTABLE = "private, max-age=31536000, immutable"
_STATIC_REF = re.compile(rb'((?:src|href)=")(static/|/s/assets/)(?!manifest\.webmanifest")')


def gzip_static(path: str, etag: str, body: bytes) -> bytes:
    """Сжатый файл статики — один раз на версию файла (ETag): сжатие `i18n.js` стоит несколько миллисекунд
    процессора, а `/s/assets/*` открыт без входа — каждый запрос заново сжимал бы его за счёт панели."""
    with _gz_lock:
        hit = _gz_cache.get(path)
    if hit and hit[0] == etag:
        return hit[1]
    z = gzip.compress(body, 6, mtime=0)
    with _gz_lock:
        _gz_cache[path] = (etag, z)
    return z


def _no_constant(name: str):
    raise ValueError(f"{name} is not allowed")


def _finite(text: str) -> float:
    """Число из JSON. `1e999` — правильный JSON, но в Python это бесконечность, и int() на ней падает:
    такой запрос неверен (400), как Infinity и NaN."""
    v = float(text)
    if not math.isfinite(v):
        raise ValueError("number out of range")
    return v


def client_key(addr: str) -> str:
    """Адрес клиента для пределов и блокировки подбора пароля. IPv4 из сокета IPv6 (`::ffff:a.b.c.d`) — как
    IPv4; IPv6 — его сеть /64: у одного абонента обычно целая /64, и по отдельным адресам блокировку
    обошли бы сменой адреса."""
    try:
        a = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return addr
    if a.version == 6:
        if a.ipv4_mapped:
            return str(a.ipv4_mapped)
        return str(ipaddress.ip_network(f"{a}/64", strict=False))
    return str(a)


def net_key(addr: str) -> str | None:
    """Сеть /48 адреса IPv6 (для MAX_PER_NET); IPv4 — None: за одним адресом IPv4 бывают тысячи абонентов,
    а соседние адреса — разные люди."""
    try:
        a = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return None
    if a.version == 6 and not a.ipv4_mapped:
        return str(ipaddress.ip_network(f"{a}/48", strict=False))
    return None


def content_length(headers, limit: int = MAX_BODY) -> int:
    """Длина тела из заголовка; отрицательная, нечисловая или больше лимита — ошибка."""
    raw = (headers.get("Content-Length") or "0").strip()
    if not (raw.isascii() and raw.isdigit()):
        raise HTTPError(400, "err.bad_json")
    n = int(raw)
    if n > limit:
        raise HTTPError(413, "err.too_large")
    return n


class HTTPError(Exception):
    """field — поле запроса, о котором ошибка: браузер выделяет его в форме (markField в js/core.js)."""

    def __init__(self, code: int, detail, field: str | None = None):
        if isinstance(detail, str):
            detail = Msg(detail)
        super().__init__(str(detail))
        self.code = code
        self.detail = detail
        self.field = field


class Page:
    """Ответ-страница (HTML) вместо JSON."""

    def __init__(self, body: bytes, ctype: str = "text/html; charset=utf-8", status: int = 200):
        self.body = body
        self.ctype = ctype
        self.status = status


def parse_cookies(header: str) -> dict[str, str]:
    """Заголовок Cookie → {имя: значение}. Не SimpleCookie: на одной чужой cookie, которую он не принимает
    (пробел или запятая в значении — так их ставят другие сайты на том же адресе), он бросает разбор и
    теряет остальные, вместе с сессией панели — и владельца выбрасывает из панели по кругу. Из одинаковых имён —
    первое (браузер ставит раньше cookie с более длинным путём, то есть панели)."""
    out: dict[str, str] = {}
    for part in header.split(";"):
        k, sep, v = part.partition("=")
        k, v = k.strip(), v.strip()
        if sep and k and k not in out:
            out[k] = v[1:-1] if len(v) > 1 and v[0] == v[-1] == '"' else v
    return out


class Request:
    def __init__(self, h: BaseHTTPRequestHandler, path: str, params: dict):
        self.h = h
        self.method = h.command
        self.path = path
        self.params = params
        self.headers = h.headers
        self.client_ip = client_key(h.client_address[0])     # IPv6 — сетью /64 (client_key)
        self.cookies = parse_cookies(h.headers.get("Cookie", ""))
        self.set_cookies: list[str] = []
        self._body = None
        self.authed = False             # вход проверен (auth_mw) или только что выдан (вход в панель)

    def json(self, limit: int = MAX_BODY) -> dict:
        """limit — для запросов без входа (вход в панель): тело до MAX_BODY читается в память целиком."""
        if self._body is None:
            n = content_length(self.headers, limit)
            raw = _read_body(self.h, n) if n else b"{}"
            self.h.body_read = True
            try:
                # Infinity и NaN — не JSON по стандарту, а int() на них падает; слишком глубокая
                # вложенность — RecursionError: всё это неверный запрос (400), а не ошибка панели (500)
                self._body = json.loads(raw or b"{}", parse_constant=_no_constant, parse_float=_finite)
            except (ValueError, RecursionError):
                raise HTTPError(400, "err.bad_json") from None
            if not isinstance(self._body, dict):
                raise HTTPError(400, "err.bad_json")
            try:
                # одиночная половинка пары UTF-16 («\\ud800») — не текст: запись в файл упала бы ошибкой 500. Глубокая
                # вложенность: Python 3.14+ разбирает её без RecursionError (предел — по стеку), а обратно не собирает
                json.dumps(self._body, ensure_ascii=False).encode()
            except (UnicodeEncodeError, RecursionError):
                self._body = None
                raise HTTPError(400, "err.bad_json") from None
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
        self._tag: tuple[float, str] | None = None           # (когда посчитан, отпечаток статики)

    def static_tag(self) -> str:
        """Отпечаток статики: имена, время изменения и размеры всех её файлов (STATIC_TAG). Считается заново не чаще
        STATIC_TAG_TTL: его спрашивает каждый запрос файла с отпечатком в адресе."""
        now = time.monotonic()
        hit = self._tag
        if hit and now - hit[0] < STATIC_TAG_TTL:
            return hit[1]
        h = hashlib.sha256()
        root = self.static[1] if self.static else ""
        for d, dirs, names in os.walk(root):
            dirs.sort()
            for n in sorted(names):
                p = os.path.join(d, n)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                h.update(f"{os.path.relpath(p, root)}\0{st.st_mtime_ns}\0{st.st_size}\n".encode())
        tag = h.hexdigest()[:12]
        self._tag = (now, tag)
        return tag

    def versioned(self, html: bytes) -> bytes:
        """Страница с отпечатком статики в адресах её файлов (`static/…`, `/s/assets/…` → `…/v-<отпечаток>/…`)."""
        if not self.static:
            return html
        mark = b"v-" + self.static_tag().encode() + b"/"
        return _STATIC_REF.sub(lambda m: m.group(1) + m.group(2) + mark, html)

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
            timeout = IDLE_TIMEOUT    # медленный или молчащий клиент не держит поток вечно
            # Соединение остаётся открытым между запросами: панель опрашивает /api/state каждые несколько
            # секунд, и с HTTP/1.0 каждый опрос был новым соединением с рукопожатием TLS. У каждого ответа
            # есть Content-Length (_send); заголовки и тело уходят двумя записями, поэтому без алгоритма
            # Нейгла — иначе тело ждало бы подтверждения заголовков.
            protocol_version = "HTTP/1.1"
            disable_nagle_algorithm = True
            served = False

            def handle_one_request(self):
                # Следующего запроса ждём меньше, чем читаем начатый: простаивающее соединение занимает
                # место из MAX_CONNECTIONS и MAX_PER_IP.
                self.connection.settimeout(KEEP_IDLE if self.served else IDLE_TIMEOUT)
                if self.served:                 # первый запрос — в пределе, заданном при подключении
                    _arm(self.server, self.connection, KEEP_IDLE + HEAD_DEADLINE)
                super().handle_one_request()
                self.served = True

            def parse_request(self):
                self.connection.settimeout(IDLE_TIMEOUT)        # строка запроса пришла — читаем остальное
                ok = super().parse_request()
                _disarm(self.server, self.connection)          # заголовки прочитаны: обработка — без предела
                return ok

            def version_string(self):  # заголовок Server не выдаёт панель сканерам
                return "httpd"

            def log_message(self, fmt, *args):  # тихо
                pass

            def _send(self, code: int, body: bytes, ctype: str, extra: list[tuple[str, str]] = (),
                      cached: tuple[str, str] | None = None):
                # сжатие: состояние панели и её скрипты — текст, который сжимается в несколько раз;
                # cached — (путь, ETag) файла статики: его сжатая копия берётся из памяти (gzip_static)
                if len(body) >= GZIP_MIN and ctype.startswith(GZIP_TYPES) \
                        and "gzip" in (self.headers.get("Accept-Encoding") or "").lower():
                    body = gzip_static(*cached, body) if cached else gzip.compress(body, 5, mtime=0)
                    extra = [*extra, ("Content-Encoding", "gzip"), ("Vary", "Accept-Encoding")]
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Frame-Options", "DENY")
                if ctype.startswith("text/html"):
                    self.send_header("Content-Security-Policy", CSP)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                for k, v in extra:
                    self.send_header(k, v)
                crowded = getattr(self.server, "crowded", None)
                if not self.close_connection and crowded and crowded(client_key(self.client_address[0])):
                    # мест осталось мало — соединения не держим: как до keep-alive, одно на запрос
                    self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _json(self, code: int, obj, extra=()):
                self._send(code, json.dumps(obj, ensure_ascii=False, default=_msg_json).encode(),
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
                        _skip_body(self, n)
                        return
                    except OSError:
                        pass
                self.close_connection = True

            def _dispatch_inner(self):
                path = unquote(urlsplit(self.path).path)
                try:
                    if self.headers.get("Transfer-Encoding"):
                        # тело читается только по Content-Length: нечитаемое оставалось бы в соединении
                        # и разбиралось как следующий запрос
                        raise HTTPError(411, "err.bad_json")
                    # статика
                    for mount in (app.static, app.public_static):
                        if mount and path.startswith(mount[0] + "/") and self.command in ("GET", "HEAD"):
                            rel = path[len(mount[0]) + 1:]
                            # адрес с отпечатком статики (App.versioned): нынешний — файл в кэш браузера надолго;
                            # прежний (страница открыта до обновления) — тот же файл, как без отпечатка
                            tagged = STATIC_TAG.match(rel)
                            if tagged:
                                rel = rel[tagged.end():]
                            if mount is app.public_static and rel not in app.public_files:
                                raise HTTPError(404, "err.not_found")
                            return self._static(mount[1], rel,
                                                keep=bool(tagged) and tagged.group(1) == app.static_tag())
                    if app.index_file and self.command in ("GET", "HEAD"):
                        if path == app.base + "/" or path == "/" and not app.base:
                            with open(app.index_file, "rb") as f:
                                body = app.versioned(f.read())
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
                        trust = getattr(self.server, "trust", None)
                        if app.middleware and fn not in app.public:
                            app.middleware(req)
                            if trust and req.authed:     # вход проверен: адресу — запасные места (RESERVE)
                                trust(self.client_address[0])
                        was = req.authed
                        res = fn(req, **m.groupdict())
                        if trust and req.authed and not was:     # вход в панель прошёл
                            trust(self.client_address[0])
                        if isinstance(res, Page):
                            return self._send(res.status, res.body, res.ctype, [("Cache-Control", "no-store")])
                        return self._json(200, res if res is not None else {"ok": True},
                                          [("Set-Cookie", c) for c in req.set_cookies])
                    if allowed:
                        raise HTTPError(405, "err.method")
                    raise HTTPError(404, "err.not_found")
                except HTTPError as e:
                    extra = ()
                    if e.code in (411, 413):
                        self.close_connection = True
                        extra = [("Connection", "close")]
                    body = {"detail": e.detail}
                    if getattr(e, "field", None):
                        body["field"] = e.field
                    self._json(e.code, body, extra)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except OSError as e:
                    if e.errno == errno.ENOSPC:
                        # сохранение не применилось (прежнее состояние цело): сказать, что делать, а не «внутренняя
                        # ошибка: [Errno 28]» (П56)
                        log.warning("%s %s: %s", self.command, path, e)
                        self._json(507, {"detail": Msg("err.disk_full")})
                    elif isinstance(e, TimeoutError) and getattr(self, "body_read", True) is False:
                        # тело запроса не дошло за срок (медленная связь или нарочно): отказ, а не 500 с трассировкой
                        self.close_connection = True
                        self._json(408, {"detail": Msg("err.timeout")}, [("Connection", "close")])
                    else:
                        log.error("%s %s: %s\n%s", self.command, path, e, traceback.format_exc())
                        try:
                            self._json(500, {"detail": Msg("err.internal", detail=str(e)[:300])})
                        except Exception:  # noqa: BLE001
                            pass
                except Exception as e:  # noqa: BLE001
                    log.error("%s %s: %s\n%s", self.command, path, e, traceback.format_exc())
                    try:
                        self._json(500, {"detail": Msg("err.internal", detail=str(e)[:300])})
                    except Exception:  # noqa: BLE001
                        pass

            def _static(self, root: str, rel: str, keep: bool = False):
                """keep — в адресе нынешний отпечаток статики: файл не перепроверяется (IMMUTABLE)."""
                root = os.path.realpath(root)
                try:
                    p = os.path.realpath(os.path.join(root, rel))
                    found = p.startswith(root + os.sep) and os.path.isfile(p)
                except ValueError:          # NUL в пути (%00): realpath падает — как будто файла нет, а не 500
                    found = False
                if not found:
                    raise HTTPError(404, "err.not_found")
                ctype = mimetypes.guess_type(p)[0] or "application/octet-stream"
                if ctype.startswith("text/") or ctype in ("application/javascript",):
                    ctype += "; charset=utf-8"
                st = os.stat(p)
                etag = f'"{int(st.st_mtime)}-{st.st_size}"'
                hdrs = [("Cache-Control", IMMUTABLE if keep else "no-cache"), ("ETag", etag)]
                # браузер перепроверяет файл, но не скачивает заново, если он не менялся
                if self.headers.get("If-None-Match") == etag:
                    self.send_response(304)
                    for k, v in hdrs:
                        self.send_header(k, v)
                    self.end_headers()
                    return
                with open(p, "rb") as f:
                    self._send(200, f.read(), ctype, hdrs, cached=(p, etag))

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _dispatch

        return H

    def serve(self, host: str, port: int, tls=None) -> ThreadingHTTPServer:
        """tls — функция, возвращающая текущий SSLContext (или None для HTTP).
        «Все адреса» (`0.0.0.0`, `::`) — один сокет IPv6, который принимает и IPv4; без IPv6 в ядре
        (`ipv6.disable=1`) — только IPv4. Конкретный адрес (127.0.0.1 для SSH-туннеля) — как есть."""
        if host in ("", "0.0.0.0", "::"):
            try:
                srv = DualServer(("::", port), self.handler())
            except OSError as e:
                if e.errno != errno.EAFNOSUPPORT:
                    raise
                srv = Server(("0.0.0.0", port), self.handler())
        else:
            srv = (DualServer if ":" in host else Server)((host, port), self.handler())
        srv.tls = tls
        return srv


def _arm(server, sock, seconds: float) -> None:
    arm = getattr(server, "arm", None)
    if arm:
        arm(sock, seconds)


def _disarm(server, sock) -> None:
    disarm = getattr(server, "disarm", None)
    if disarm:
        disarm(sock)


def _read_body(h, n: int) -> bytes:
    """Тело запроса — в пределе BODY_DEADLINE на всё тело (а не на одно чтение)."""
    _arm(h.server, h.connection, BODY_DEADLINE)
    try:
        return h.rfile.read(n)
    finally:
        _disarm(h.server, h.connection)


def _skip_body(h, n: int) -> None:
    """Ненужное тело (ответ раньше json(): 401, 404…) — кусками и в никуда: целиком в памяти тела до MAX_BODY
    от кого угодно без пароля заняли бы сотни мегабайт, и Python их системе не возвращает."""
    _arm(h.server, h.connection, BODY_DEADLINE)
    try:
        while n > 0:
            got = h.rfile.read(min(n, 65536))
            if not got:
                raise OSError("body cut short")
            n -= len(got)
    finally:
        _disarm(h.server, h.connection)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    tls = None
    request_queue_size = 64

    def __init__(self, *a, **kw):
        self._conn_lock = threading.Lock()
        self._conns = 0
        self._per_ip: dict[str, int] = {}
        self._per_net: dict[str, int] = {}
        self._trusted: dict[str, float] = {}        # адрес (client_key) → до какого времени свой
        self._warned = 0.0
        self._deadlines: dict[int, tuple[socket.socket, float]] = {}
        self._reaper: threading.Thread | None = None
        super().__init__(*a, **kw)

    # ------------------------------------------------ предел времени на запрос
    def arm(self, sock, seconds: float) -> None:
        """Соединение закрывается, если к сроку не дочитано то, что читается сейчас (заголовки, тело)."""
        with self._conn_lock:
            self._deadlines[id(sock)] = (sock, time.monotonic() + seconds)
            if self._reaper is None:
                self._reaper = threading.Thread(target=self._reap, name="http-deadline", daemon=True)
                self._reaper.start()

    def disarm(self, sock) -> None:
        with self._conn_lock:
            self._deadlines.pop(id(sock), None)

    def _reap(self) -> None:
        while True:
            time.sleep(1)
            now = time.monotonic()
            with self._conn_lock:
                late = [k for k, (_, t) in self._deadlines.items() if t <= now]
                for k in late:
                    sock = self._deadlines.pop(k)[0]
                    try:
                        # чтение в потоке соединения сразу закончится; у сокета TLS — его дескриптор, а не
                        # SSLSocket.shutdown (тот ещё и снимает TLS с объекта, которым пользуется поток)
                        socket.socket.shutdown(sock, socket.SHUT_RDWR)
                    except OSError:
                        pass

    # ------------------------------------------------ места
    def trust(self, addr: str) -> None:
        now = time.time()
        with self._conn_lock:
            if len(self._trusted) > 1000:
                self._trusted = {k: v for k, v in self._trusted.items() if v > now}
            if len(self._trusted) <= 1000:
                self._trusted[client_key(addr)] = now + TRUST_TTL

    def _take(self, ip: str, net: str | None = None) -> bool:
        with self._conn_lock:
            cap = MAX_CONNECTIONS + (RESERVE if self._trusted.get(ip, 0) > time.time() else 0)
            if self._conns >= cap or self._per_ip.get(ip, 0) >= MAX_PER_IP \
                    or (net and self._per_net.get(net, 0) >= MAX_PER_NET):
                return False
            self._conns += 1
            self._per_ip[ip] = self._per_ip.get(ip, 0) + 1
            if net:
                self._per_net[net] = self._per_net.get(net, 0) + 1
            return True

    def crowded(self, ip: str) -> bool:
        """Занята половина мест (всех или этого адреса): ответы закрывают соединение."""
        with self._conn_lock:
            return self._conns * 2 >= MAX_CONNECTIONS or self._per_ip.get(ip, 0) * 2 >= MAX_PER_IP

    def _give(self, ip: str, net: str | None = None) -> None:
        with self._conn_lock:
            self._conns -= 1
            for d, k in ((self._per_ip, ip), (self._per_net, net)):
                if k is None:
                    continue
                n = d.get(k, 1) - 1
                if n > 0:
                    d[k] = n
                else:
                    d.pop(k, None)

    def process_request(self, request, client_address):
        # Поток на соединение, но с пределом: иначе тысячи «висящих» соединений
        # без пароля съедят память, а один адрес (для IPv6 — сеть /64, и /48 вместе) не должен занять все места
        ip, net = client_key(client_address[0]), net_key(client_address[0])
        if not self._take(ip, net):
            now = time.monotonic()
            if now - self._warned > 60:          # не засоряем журнал при наплыве
                self._warned = now
                log.warning("connection limit reached (%s), dropping new connections", ip)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._give(ip, net)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._give(client_key(client_address[0]), net_key(client_address[0]))

    def finish_request(self, request, client_address):
        ctx = self.tls() if self.tls else None
        if not ctx:
            self.arm(request, HEAD_DEADLINE)
            try:
                return super().finish_request(request, client_address)
            finally:
                self.disarm(request)
        request.settimeout(15)
        self.arm(request, HEAD_DEADLINE)
        try:
            first = request.recv(1, socket.MSG_PEEK)
        except OSError:
            self.disarm(request)
            return
        if not first:
            self.disarm(request)
            return
        if first[0] != 0x16:            # не TLS: кто-то открыл http:// — перенаправим на https://
            try:
                return _redirect_plain(request)
            finally:
                self.disarm(request)
        self.disarm(request)
        try:
            # рукопожатие — отдельно, когда сокет TLS уже есть: его и закроет предел времени
            tls_sock = ctx.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
        except (ssl.SSLError, OSError):
            return
        self.arm(tls_sock, HEAD_DEADLINE)
        try:
            tls_sock.do_handshake()
            tls_sock.settimeout(120)
            self.RequestHandlerClass(tls_sock, client_address, self)
        except (ssl.SSLError, OSError):
            pass
        finally:
            self.disarm(tls_sock)
            try:
                tls_sock.close()
            except OSError:
                pass

    def handle_error(self, request, client_address):  # без трассировок на каждый обрыв
        log.debug("connection error from %s", client_address)


class DualServer(Server):
    """Сокет IPv6 с IPV6_V6ONLY = 0: те же порт и сокет принимают и IPv4 (адреса `::ffff:a.b.c.d`)."""
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


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
