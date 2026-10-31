"""Обновление панели из браузера.

Панель живёт в контейнере, а обновление пересоздаёт этот контейнер. Поэтому `install.sh --update`
запускается на хосте отдельной задачей systemd (`systemd-run`, через nsenter в пространства
имён PID 1): задача не входит в cgroup контейнера и переживает его перезапуск. Вывод пишется
в data/update.log (на хосте <каталог установки>/data — это /data внутри контейнера), последняя
строка — `exit=<код>`. Новая панель после запуска видит этот журнал, браузер — новую версию.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time

from . import config, system
from .i18n import Msg, MsgError

log = logging.getLogger("awgr.selfupdate")

UNIT = "awg-router-update"
CONTAINER = "awg-router"
LOG = os.path.join(config.DATA_DIR, "update.log")
STATE = os.path.join(config.DATA_DIR, "update.json")
STALE = 45 * 60                 # дольше этого обновление не идёт — считаем, что оно оборвалось
DIR_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,200}$")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
CMD = "awg-router update"


class UpdateError(MsgError):
    pass


def _host(cmd: list[str], timeout: int = 30):
    """Команда на хосте: все пространства имён PID 1 (у контейнера pid: host)."""
    return system.run(["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--"] + cmd,
                      timeout=timeout, check=False)


def host_dir() -> str:
    """Каталог установки на хосте: из метки Compose или из источника тома /data."""
    try:
        c = system.docker_get(f"/containers/{CONTAINER}/json") or {}
    except OSError:
        c = {}
    d = ((c.get("Config") or {}).get("Labels") or {}).get("com.docker.compose.project.working_dir")
    if not d:
        for m in c.get("Mounts") or []:
            if m.get("Destination") in ("/data", config.DATA_DIR) and m.get("Source"):
                d = os.path.dirname(m["Source"].rstrip("/"))
    if not d or not DIR_RE.match(d) or ".." in d:
        raise UpdateError(Msg("err.update_dir"))
    return d


def _read_state() -> dict:
    try:
        with open(STATE) as f:
            s = json.load(f)
        return s if isinstance(s, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_state(s: dict) -> None:
    with open(STATE + ".tmp", "w") as f:
        json.dump(s, f)
    os.replace(STATE + ".tmp", STATE)


def log_lines(n: int = 30) -> list[str]:
    """Последние строки журнала без цветов и строк с паролем (их печатает итоговая сводка)."""
    try:
        with open(LOG, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 64 * 1024))
            text = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    out = []
    for ln in text.replace("\r", "\n").split("\n"):
        ln = ANSI.sub("", ln).rstrip()
        if not ln.strip() or re.match(r"^\s*[|/\\-]\s*$", ln) or "Password:" in ln:
            continue
        out.append(ln[:300])
    return out[-n:]


def status() -> dict:
    """{state: idle|running|failed|done, to, started, exit}. Без журнала — он большой."""
    s = _read_state()
    if not s.get("started"):
        return {"state": "idle"}
    code = None
    for ln in reversed(log_lines(5)):
        m = re.match(r"^exit=(\d+)$", ln.strip())
        if m:
            code = int(m.group(1))
            break
    if code is None:
        state = "running" if time.time() - s["started"] < STALE else "failed"
    else:
        state = "done" if code == 0 else "failed"
    return {"state": state, "to": s.get("to"), "from": s.get("from"),
            "started": s["started"], "exit": code}


def start(current: str, target: str | None) -> dict:
    if status()["state"] == "running":
        raise UpdateError(Msg("err.update_running"))
    s = {"started": time.time(), "from": current, "to": target}
    if config.DRY_RUN:
        _write_state(s)
        _demo_run()
        return status()
    d = host_dir()
    if _host(["sh", "-c", "command -v systemd-run"]).returncode != 0:
        raise UpdateError(Msg("err.update_no_systemd", cmd=CMD))
    if _host(["test", "-f", f"{d}/install.sh"]).returncode != 0:
        raise UpdateError(Msg("err.update_dir"))
    if _host(["systemctl", "is-active", "--quiet", UNIT]).returncode == 0:
        raise UpdateError(Msg("err.update_running"))
    _write_state(s)
    with open(LOG, "w") as f:
        f.write(f"Update from the panel: {current} -> {target or '?'}\n")
    script = (f'cd "{d}" && bash "{d}/install.sh" --update >>"{d}/data/update.log" 2>&1; '
              f'echo "exit=$?" >>"{d}/data/update.log"')
    p = _host(["systemd-run", "--unit", UNIT, "--collect", "--quiet",
               "--description", "AWG Router update", "/bin/bash", "-c", script])
    if p.returncode != 0:
        _write_state({})
        raise UpdateError(Msg("err.update_start", error=(p.stderr or p.stdout).strip()[:300]))
    log.info("Update started on the host (%s): %s -> %s", d, current, target)
    return status()


def _demo_run() -> None:
    """DRY_RUN: журнал как у настоящего обновления, без сборки."""
    def run():
        steps = ["Downloading AWG Router from github.com/r-slashslash/AWG-Router …",
                 "▸ Checking the system", "  ✓ Ubuntu 24.04 LTS", "▸ Docker",
                 "  ✓ Docker 29.9.2, Compose 5.6.1, buildx 0.38.1",
                 "▸ Building the panel (first time takes 3–10 minutes)", "  ✓ Done", "▸ Starting"]
        with open(LOG, "w") as f:
            f.write("Update from the panel (demo)\n")
        for ln in steps:
            time.sleep(1.5)
            with open(LOG, "a") as f:
                f.write(ln + "\n")
        with open(LOG, "a") as f:
            f.write("exit=0\n")
    threading.Thread(target=run, name="demo-update", daemon=True).start()
