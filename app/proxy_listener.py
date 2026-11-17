"""HTTP(S)-приёмник для одного прокси-клиента.

Запуск и остановка управляются панелью; исходящий сокет создаёт proxy_bridge.
"""
from __future__ import annotations

import socket
import socketserver
import ssl
import threading
import time

from . import proxy_auth, proxy_request

MAX_CONNECTIONS = 32
HEADER_TIMEOUT = 10
IDLE_TIMEOUT = 300
FAIL_WINDOW = 600
FAIL_LIMIT = 8
MAX_FAIL_IPS = 10000
_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
_fail_lock = threading.Lock()
_failures: dict[str, list[float]] = {}
_inflight: dict[str, int] = {}


def _blocked(ip: str) -> bool:
    now = time.monotonic()
    with _fail_lock:
        recent = [t for t in _failures.get(ip, []) if now - t < FAIL_WINDOW]
        if recent:
            _failures[ip] = recent
        else:
            _failures.pop(ip, None)
        return len(recent) >= FAIL_LIMIT


def _failed(ip: str) -> None:
    now = time.monotonic()
    with _fail_lock:
        if ip not in _failures and len(_failures) >= MAX_FAIL_IPS:
            oldest = min(_failures, key=lambda key: _failures[key][-1])
            _failures.pop(oldest, None)
        recent = [t for t in _failures.get(ip, []) if now - t < FAIL_WINDOW]
        _failures[ip] = (recent + [now])[-FAIL_LIMIT:]


def _begin_auth(ip: str) -> bool:
    """Резервировать попытку до PBKDF2, включая параллельные запросы."""
    with _fail_lock:
        now = time.monotonic()
        recent = [t for t in _failures.get(ip, []) if now - t < FAIL_WINDOW]
        if recent:
            _failures[ip] = recent
        else:
            _failures.pop(ip, None)
        if len(recent) + _inflight.get(ip, 0) >= FAIL_LIMIT:
            return False
        if ip not in _inflight and len(_inflight) >= MAX_FAIL_IPS:
            return False
        _inflight[ip] = _inflight.get(ip, 0) + 1
        return True


def _end_auth(ip: str, success: bool) -> None:
    with _fail_lock:
        count = _inflight[ip] - 1
        if count:
            _inflight[ip] = count
        else:
            _inflight.pop(ip, None)
        if not success:
            if ip not in _failures and len(_failures) >= MAX_FAIL_IPS:
                _failures.pop(min(_failures, key=lambda key: _failures[key][-1]), None)
            _failures[ip] = (_failures.get(ip, []) + [time.monotonic()])[-FAIL_LIMIT:]


def _head(sock: ssl.SSLSocket) -> bytes:
    """Читать без захвата байтов после заголовка CONNECT."""
    data = bytearray()
    deadline = time.monotonic() + HEADER_TIMEOUT
    while len(data) < proxy_request.MAX_HEAD:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("request header timeout")
        sock.settimeout(left)
        chunk = sock.recv(1)
        if not chunk:
            raise OSError("request closed")
        data += chunk
        if data.endswith(b"\r\n\r\n"):
            return bytes(data)
    raise ValueError("request too large")


def _copy(source: socket.socket, destination: socket.socket, stopped: threading.Event, account, direction: int) -> None:
    try:
        while not stopped.is_set():
            data = source.recv(65536)
            if not data:
                break
            if not account(direction, len(data)):
                break
            destination.sendall(data)
    except (OSError, ssl.SSLError):
        pass
    finally:
        stopped.set()
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _copy_body(source, destination, stopped, account, remaining):
    """Переслать только тело одного HTTP-запроса, не пропуская следующий запрос к другому хосту."""
    try:
        while remaining and not stopped.is_set():
            data = source.recv(min(65536, remaining))
            if not data or not account(0, len(data)):
                raise OSError("body interrupted")
            destination.sendall(data)
            remaining -= len(data)
    except (OSError, ssl.SSLError):
        stopped.set()
        try:
            destination.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


class _Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, address, context, credentials, opener, account):
        self.context = context
        self.credentials = credentials  # callback: запись либо None, если клиент отключён
        self.opener = opener            # callback: открыть сокет через выбранный выход
        self.account = account          # callback: учёт и проверка квоты выбранного выхода
        self.slots = _slots             # общий предел для всех портов прокси
        self.active = set()
        self.active_lock = threading.Lock()
        super().__init__(address, _Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self.active_lock:
            self.active.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.active_lock:
                self.active.discard(request)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.active_lock:
                self.active.discard(request)
            self.slots.release()

    def close_active(self):
        with self.active_lock:
            for conn in list(self.active):
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(HEADER_TIMEOUT)
        try:
            if self.server.context is None:
                self._handle_request(self.request)
                return
            ctx = self.server.context()
            if ctx is None:
                return
            with ctx.wrap_socket(self.request, server_side=True) as client:
                with self.server.active_lock:
                    self.server.active.discard(self.request)
                    self.server.active.add(client)
                try:
                    self._handle_request(client)
                finally:
                    with self.server.active_lock:
                        self.server.active.discard(client)
        except (OSError, ssl.SSLError, ValueError):
            return

    def _handle_request(self, client):
        try:
            head = _head(client)
            tunnel = head.startswith(b"CONNECT ")
            if tunnel:
                host, port, auth = proxy_request.parse_connect(head)
                prefix, body_len = b"", 0
            else:
                host, port, auth, prefix, body_len = proxy_request.parse_http(head)
        except ValueError:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return
        ip = self.client_address[0]
        if not _begin_auth(ip):
            client.sendall(b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n")
            return
        ok = False
        try:
            creds = self.server.credentials()
            ok = bool(creds and proxy_auth.authenticate(auth, creds["username"], creds["password"]))
        finally:
            _end_auth(ip, ok)
        if not ok:
            client.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                           b'Proxy-Authenticate: Basic realm="AWG Router"\r\nConnection: close\r\n\r\n')
            return
        try:
            outbound = self.server.opener(host, port)
        except (OSError, ValueError, TimeoutError):
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            return
        with outbound:
            outbound.setblocking(True)
            outbound.settimeout(IDLE_TIMEOUT)
            client.settimeout(IDLE_TIMEOUT)
            stopped = threading.Event()
            account = lambda direction, count: self.server.account(creds.get("upstream"), direction, count)
            if tunnel:
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                upstream = threading.Thread(target=_copy, args=(client, outbound, stopped, account, 0), daemon=True)
                upstream.start()
            else:
                if not account(0, len(prefix)):
                    return
                outbound.sendall(prefix)
                upstream = None
                if body_len:
                    upstream = threading.Thread(target=_copy_body, args=(client, outbound, stopped, account, body_len),
                                                daemon=True)
                    upstream.start()
            _copy(outbound, client, stopped, account, 1)
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            if upstream:
                upstream.join(timeout=2)


def create(address, context, credentials, opener, account=lambda _uid, _direction, _count: True):
    return _Server(address, context, credentials, opener, account)
