"""Модуль ядра AmneziaWG из панели (рекомендуемый движок: в разы меньше системных ресурсов, чем amneziawg-go).

* `fit()` — подходит ли сервер (те же условия, что `kernel_fit` в install.sh): не контейнер OpenVZ/LXC,
  x86_64/aarch64, Ubuntu 22.04+ или Debian 12+.
* Кнопка «Установить модуль» — `start()`: `install.sh --install-kernel` на хосте отдельной задачей systemd
  (как обновление в selfupdate.py), журнал — data/kernel.log, последняя строка — `exit=<код>`.
* Своё состояние — data/engine.json, а не state.json: модуль принадлежит этому серверу, в резервную копию и
  восстановление он не входит. Поля: `seen` — версия модуля, на котором сервер работал (чтобы заметить, что
  модуль пропал, например после обновления ядра); `lost` — когда заметили; `disabled` — панель сама перевела
  сервер на amneziawg-go, потому что он не поднимался на модуле (`block`); `hidden` — какое оповещение скрыли.
* `block()` — запрет модуля на хосте (MODBLOCK) и выгрузка: без запрета следующий `ip link add … type amneziawg`
  загрузил бы модуль снова, и сервер опять не поднялся бы. `install.sh --install-kernel` запрет снимает.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time

from . import config, selfupdate, webfront
from .i18n import Msg, MsgError

log = logging.getLogger("awgr.kernelmod")

UNIT = "awg-router-kernel"
STATE = os.path.join(config.DATA_DIR, "engine.json")
LOG = os.path.join(config.DATA_DIR, "kernel.log")
STALE = 30 * 60               # дольше сборка не идёт — считаем, что она оборвалась
MODBLOCK = "/etc/modprobe.d/awg-router-amneziawg.conf"     # те же пути, что в install.sh
MODLOAD = "/etc/modules-load.d/amneziawg.conf"
BLOCK_TEXT = ("# AWG Router: the AmneziaWG server did not come up on this kernel module, so the panel switched it\n"
              "# to amneziawg-go. `awg-router install-kernel` (or the panel's button) removes this file.\n"
              "blacklist amneziawg\ninstall amneziawg /bin/false\n")
_lock = threading.Lock()
_fit: dict | None = None


class KernelError(MsgError):
    pass


# ------------------------------------------------------------------ своё состояние
def load() -> dict:
    try:
        with open(STATE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def update(**kw) -> dict:
    """Поля engine.json (None — убрать); → новое состояние."""
    with _lock:
        d = load()
        for k, v in kw.items():
            if v is None:
                d.pop(k, None)
            else:
                d[k] = v
        tmp = STATE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, STATE)
        return d


# ------------------------------------------------------------------ подходит ли сервер
def _os_release() -> dict:
    out = {}
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(webfront.host_path(p)) as f:
                for ln in f:
                    k, _, v = ln.strip().partition("=")
                    if k:
                        out[k] = v.strip().strip('"\'')
            return out
        except OSError:
            continue
    return out


def fit() -> dict:
    """{"ok": bool, "why": Msg | None} — один раз на запуск панели: ни система, ни процессор не меняются."""
    global _fit
    if _fit is not None:
        return _fit
    if config.DRY_RUN:
        _fit = {"ok": True, "why": None}
        return _fit
    p = selfupdate._host(["systemd-detect-virt", "-c"], timeout=10)
    virt = (p.stdout or "").strip()
    arch = os.uname().machine
    rel = _os_release()
    os_id, ver = rel.get("ID", ""), rel.get("VERSION_ID", "0")
    try:
        major = int(ver.split(".", 1)[0])
    except ValueError:
        major = 0
    if virt and virt != "none":
        why = Msg("eng.fit_container", virt=virt)
    elif arch not in ("x86_64", "aarch64"):
        why = Msg("eng.fit_arch", arch=arch)
    elif not ((os_id == "ubuntu" and major >= 22) or (os_id == "debian" and major >= 12)):
        why = Msg("eng.fit_os", os=(rel.get("PRETTY_NAME") or f"{os_id} {ver}").strip() or "?")
    else:
        why = None
    _fit = {"ok": why is None, "why": why}
    return _fit


# ------------------------------------------------------------------ установка кнопкой
def status() -> dict:
    """{state: idle|running|done|failed, started, exit} — как у обновления (selfupdate.status)."""
    s = load().get("job") or {}
    if not s.get("started"):
        return {"state": "idle"}
    code = None
    for ln in reversed(selfupdate.log_lines(5, LOG)):
        m = re.match(r"^exit=(\d+)$", ln.strip())
        if m:
            code = int(m.group(1))
            break
    if code is None:
        state = "running" if time.time() - s["started"] < STALE else "failed"
    else:
        state = "done" if code == 0 else "failed"
    return {"state": state, "started": s["started"], "exit": code}


def log_lines(n: int = 40) -> list[str]:
    """Журнал установки для браузера — без служебной строки `exit=<код>`."""
    return [ln for ln in selfupdate.log_lines(n + 1, LOG) if not re.match(r"^exit=\d+$", ln.strip())][-n:]


def start() -> dict:
    if status()["state"] == "running":
        raise KernelError(Msg("eng.inst_running"))
    if not fit()["ok"]:
        raise KernelError(fit()["why"])
    job = {"started": time.time()}
    if config.DRY_RUN:
        update(job=job)
        _demo_run()
        return status()
    try:
        d = selfupdate.host_dir()
    except MsgError as e:
        raise KernelError(e.msg) from None
    if selfupdate._host(["sh", "-c", "command -v systemd-run"]).returncode != 0:
        raise KernelError(Msg("err.update_no_systemd", cmd="awg-router install-kernel"))
    if selfupdate._host(["test", "-f", f"{d}/install.sh"]).returncode != 0:
        raise KernelError(Msg("err.update_dir"))
    if selfupdate._host(["systemctl", "is-active", "--quiet", UNIT]).returncode == 0:
        raise KernelError(Msg("eng.inst_running"))
    update(job=job)
    with open(LOG, "w") as f:
        f.write("Kernel module from the panel\n")
    script = (f'cd "{d}" && AWGR_YES=y bash "{d}/install.sh" --install-kernel >>"{d}/data/kernel.log" 2>&1; '
              f'echo "exit=$?" >>"{d}/data/kernel.log"')
    p = selfupdate._host(["systemd-run", "--unit", UNIT, "--collect", "--quiet",
                          "--description", "AWG Router kernel module", "/bin/bash", "-c", script])
    if p.returncode != 0:
        update(job=None)
        raise KernelError(Msg("err.update_start", error=(p.stderr or p.stdout).strip()[:300]))
    log.info("Kernel module install started on the host (%s)", d)
    return status()


def _demo_run() -> None:
    """DRY_RUN: журнал как у настоящей установки, без сборки."""
    def run():
        steps = ["▸ AmneziaWG kernel module", "  The module is built for kernel 6.8.0-45-generic from the Amnezia PPA; "
                 "this takes a few minutes.", "  Building the module (amneziawg-dkms) …",
                 "  ✓ Kernel module loaded: version 3.1.20261113",
                 "  ✓ Loaded at boot too (/etc/modules-load.d/amneziawg.conf)"]
        with open(LOG, "w") as f:
            f.write("Kernel module from the panel (demo)\n")
        for ln in steps:
            time.sleep(1.0)
            with open(LOG, "a") as f:
                f.write(ln + "\n")
        with open(LOG, "a") as f:
            f.write("exit=0\n")
    threading.Thread(target=run, name="demo-kernel", daemon=True).start()


# ------------------------------------------------------------------ отключение после сбоя
def block() -> str | None:
    """Запретить модуль на хосте, убрать его автозагрузку и выгрузить. → ошибка выгрузки (None — выгружен).
    Не выгрузился (его ещё держит интерфейс) — запрет всё равно действует со следующей загрузки системы."""
    path = webfront.host_path(MODBLOCK)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(BLOCK_TEXT)
    try:
        os.remove(webfront.host_path(MODLOAD))
    except FileNotFoundError:
        pass
    p = selfupdate._host(["rmmod", "amneziawg"], timeout=30)
    if p.returncode != 0:
        return (p.stderr or p.stdout or "rmmod").strip()[:200]
    return None
