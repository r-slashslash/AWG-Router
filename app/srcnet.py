"""Свои соединения сервера с выбранного адреса (1.25.0, «Система» → «С какого адреса выходит сам сервер»).

Скачивание списков, проверка обновлений и само обновление, получение сертификата идут с этого адреса: сокет
привязывается к нему (source_address), маршруты системы не меняются — на сервере живут чужие программы. Адрес не
задан или перестал работать — адрес системы, как раньше (source() → None): без адреса сервер не должен остаться без
обновлений и сертификата. Какой адрес, решает панель (source_fn, Engine.own_src).

lego — отдельная программа на Go, к адресу её не привязать: ей даётся HTTPS_PROXY — свой маленький посредник CONNECT
на 127.0.0.1 (connect_proxy), который соединяется с адреса. Проверки Let's Encrypt приходят к серверу сами (порт 80,
запись в DNS) — их это не касается."""
from __future__ import annotations

import functools
import http.client
import logging
import select
import socket
import threading
import urllib.request

log = logging.getLogger("awgr.srcnet")

source_fn = None        # () → IPv4 или None; задаёт panel.py


def source() -> str | None:
    try:
        return source_fn() if source_fn else None
    except Exception:  # noqa: BLE001  — адрес не узнать: как раньше, адрес системы
        return None


class _HTTP(urllib.request.HTTPHandler):
    def __init__(self, src: str):
        super().__init__()
        self.src = src

    def http_open(self, req):
        return self.do_open(functools.partial(http.client.HTTPConnection, source_address=(self.src, 0)), req)


class _HTTPS(urllib.request.HTTPSHandler):
    def __init__(self, src: str, context=None):
        super().__init__(context=context)
        self.src = src

    def https_open(self, req):
        return self.do_open(functools.partial(http.client.HTTPSConnection, source_address=(self.src, 0)), req,
                            context=self._context)


def urlopen(req, timeout: float, context=None):
    """urllib.request.urlopen с адреса source() (или как раньше, без него)."""
    src = source()
    if not src:
        return urllib.request.urlopen(req, timeout=timeout, **({"context": context} if context else {}))
    return urllib.request.build_opener(_HTTP(src), _HTTPS(src, context)).open(req, timeout=timeout)


class ConnectProxy:
    """Посредник CONNECT для lego на 127.0.0.1 (свободный порт): соединение с сайтом — с адреса src. Только CONNECT
    (lego ходит только по HTTPS), только на время одного запуска lego (with)."""

    def __init__(self, src: str):
        self.src = src
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()

    def __enter__(self):
        threading.Thread(target=self._loop, name="lego-proxy", daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _loop(self) -> None:
        while not self.stop.is_set():
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c: socket.socket) -> None:
        up = None
        try:
            c.settimeout(30)
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                d = c.recv(4096)
                if not d:
                    return
                head += d
            line = head.split(b"\r\n", 1)[0].decode("latin-1").split()
            if len(line) < 2 or line[0] != "CONNECT" or ":" not in line[1]:
                c.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                return
            host, port = line[1].rsplit(":", 1)
            up = socket.create_connection((host.strip("[]"), int(port)), timeout=30, source_address=(self.src, 0))
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            rest = head.split(b"\r\n\r\n", 1)[1]
            if rest:
                up.sendall(rest)
            c.settimeout(None)
            up.settimeout(None)
            pair = {c: up, up: c}
            while True:
                r, _, _ = select.select(list(pair), [], [], 300)
                if not r:
                    return
                for s in r:
                    d = s.recv(65536)
                    if not d:
                        return
                    pair[s].sendall(d)
        except (OSError, ValueError) as e:
            log.info("lego proxy: %s", e)
            try:
                c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
        finally:
            for s in (c, up):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
