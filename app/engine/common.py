"""Общее для частей движка: каталоги, журнал, состояние запущенного туннеля и помощника."""
from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import time

from .. import config

log = logging.getLogger("awgr.engine")

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))     # app/: там лежат sniproxy.py и др.
RUN_DIR = "/run/awgr" if not config.DRY_RUN else os.path.join(config.DATA_DIR, "run")
LOG_DIR = os.path.join(config.DATA_DIR, "logs")
DNS_PORT = 53
KERNEL_MIN = 3           # старший номер версии модуля ядра, с которой он понимает AWG 3.1


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def server_ifaces(t) -> list[str]:
    """Активные интерфейсы WireGuard сервера: основной (t.iface) и классический wg0, если включён."""
    wg = getattr(t, "wg_exists", None)
    return [t.iface, "wg0"] if callable(wg) and wg() is True and t.iface != "wg0" else [t.iface]


LOG_MAX, LOG_KEEP = 5 * 2**20, 2**20     # журнал помощника больше LOG_MAX — при запуске остаётся его хвост LOG_KEEP


def _trim_log(path: str) -> None:
    """Журналы sniproxy.py и dnsproxy.py дописываются при каждом запуске, и их никто не чистил: на сервере,
    где помощник часто перезапускается или пишет ошибки, файл рос бы без предела. Последнее остаётся."""
    try:
        if os.path.getsize(path) <= LOG_MAX:
            return
        with open(path, "rb") as f:
            f.seek(-LOG_KEEP, os.SEEK_END)
            tail = f.read()
        tail = tail[tail.find(b"\n") + 1:]
        with open(path, "wb") as f:
            f.write(tail)
    except OSError:
        pass


class UpRT:
    """Состояние запущенного туннеля."""

    def __init__(self, num: int, conf_hash: str, target_key: str):
        self.num = num
        self.iface = f"{config.IFACE_PREFIX}{num}"
        self.conf_hash = conf_hash
        self.target_key = target_key
        self.proc: subprocess.Popen | None = None
        self.started = time.time()
        self.socks_ip: str | None = None        # адрес прокси SOCKS5 (имя разрешает панель)
        self.engine = "go"                      # go (amneziawg-go) | kernel (модуль ядра amneziawg)
        self.reresolved = 0.0                   # когда последний раз заново разбирали имя из Endpoint


class HelperRT:
    """Запущенный вспомогательный процесс (sniproxy.py)."""

    def __init__(self, proc: subprocess.Popen, key: str, cfg_hash: str):
        self.proc, self.key, self.cfg_hash = proc, key, cfg_hash
        self.started = time.time()
