"""Проверка новой версии на GitHub (раз в 6 часов).

Ветка main: версия — тег последнего релиза (github.com/…/releases/latest переадресует на
/releases/tag/vX.Y.Z), потому что install.sh ставит архив этого релиза. Если релиза нет или
GitHub не ответил — app/version.py из ветки, как install.sh, который тогда берёт архив ветки.
Другая ветка (AWGR_BRANCH): только app/version.py из неё.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
import urllib.request

from .version import VERSION

log = logging.getLogger("awgr.updates")

REPO = os.environ.get("AWGR_REPO", "r-slashslash/AWG-Router")
BRANCH = os.environ.get("AWGR_BRANCH", "main")
URL = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/app/version.py"
RELEASE_URL = f"https://github.com/{REPO}/releases/latest"
INTERVAL = 6 * 3600


def release_version() -> str:
    """Версия последнего релиза по адресу, на который переадресует /releases/latest."""
    req = urllib.request.Request(RELEASE_URL, method="HEAD")
    with urllib.request.urlopen(req, timeout=20) as r:
        final = r.geturl()
    m = re.search(r"/releases/tag/v?(\d+(?:\.\d+)+)/?$", final)
    if not m:
        raise ValueError("no release")
    return m.group(1)


def branch_version() -> str:
    req = urllib.request.Request(URL, headers={"Cache-Control": "no-cache"})
    with urllib.request.urlopen(req, timeout=20) as r:
        text = r.read(4096).decode("utf-8", "replace")
    m = re.search(r'VERSION\s*=\s*"([\d.]+)"', text)
    if not m:
        raise ValueError("no VERSION")
    return m.group(1)


def latest_version() -> str:
    if BRANCH == "main":
        try:
            return release_version()
        except Exception as e:  # noqa: BLE001
            log.info("latest release: %s", str(e)[:200])
    return branch_version()


def parse(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.strip().split("."))
    except ValueError:
        return (0,)


class UpdateChecker:
    def __init__(self, on_new=None):
        self.latest: str | None = None
        self.checked: float | None = None
        self.error: str | None = None
        self.on_new = on_new          # вызов(версия) — один раз на каждую новую версию
        self._announced: str | None = None

    @property
    def available(self) -> bool:
        return bool(self.latest) and parse(self.latest) > parse(VERSION)

    def status(self) -> dict:
        return {"current": VERSION, "latest": self.latest, "available": self.available,
                "checked": self.checked, "error": self.error}

    def check(self) -> None:
        try:
            self.latest = latest_version()
            self.error = None
        except Exception as e:  # noqa: BLE001
            self.error = str(e)[:200]
            log.info("update check: %s", self.error)
        self.checked = time.time()
        if self.available and self._announced != self.latest and self.on_new:
            self._announced = self.latest
            try:
                self.on_new(self.latest)
            except Exception:  # noqa: BLE001
                log.exception("on_new")

    def start(self, stop_ev: threading.Event) -> None:
        def loop():
            stop_ev.wait(60)            # не мешаем запуску
            while not stop_ev.is_set():
                self.check()
                stop_ev.wait(INTERVAL)
        threading.Thread(target=loop, name="updates", daemon=True).start()
