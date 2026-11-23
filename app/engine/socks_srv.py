"""Входящий SOCKS5-прокси (socksproxy.py): настройки пользователей, запуск и перезагрузка по SIGHUP."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time

from .. import config, nftgen, system
from ..i18n import Msg
from .common import APP_DIR, LOG_DIR, RUN_DIR, HelperRT, _sha, _trim_log

SOCKSPROXY = os.path.join(APP_DIR, "socksproxy.py")
SOCKS_CONF = "/run/awgr-socks.json" if not config.DRY_RUN else os.path.join(RUN_DIR, "awgr-socks.json")


class SocksProxyMixin:
    """Публичный входящий SOCKS5-прокси: socksproxy.py (часть Engine)."""

    def _socks_config(self, st: dict) -> dict:
        """Собрать конфиг socksproxy.py: {listen, port, users: {name: {password, mark}}}."""
        sp = (st.get("settings") or {}).get("socks_proxy") or {}
        port = int(sp.get("port") or 1080)
        up_nums = {
            u["id"]: u["num"]
            for u in (st.get("upstreams") or [])
            if isinstance(u, dict) and "id" in u and "num" in u
        }
        users = {}
        for name, u in (st.get("socks_users") or {}).items():
            if not isinstance(u, dict) or not u.get("enabled", True):
                continue
            ex = u.get("exit") or "direct"
            uid = ex[3:] if isinstance(ex, str) and ex.startswith("up:") else ex
            exit_up = uid in self.rt and uid in up_nums
            mark = nftgen.mark_for(up_nums[uid]) if ex != "direct" and exit_up else 0
            users[name] = {"password": u.get("password") or "", "mark": mark}
        return {"listen": "0.0.0.0", "port": port, "users": users}

    def _stop_socks(self) -> None:
        """Остановить процесс socksproxy.py, если запущен."""
        d, self.socks_srv = self.socks_srv, None
        if d and d.proc.poll() is None:
            d.proc.terminate()
            try:
                d.proc.wait(5)
            except subprocess.TimeoutExpired:
                d.proc.kill()

    def _sync_socks(self, t: system.Target, st: dict) -> None:
        """Держит socksproxy.py запущенным, пока входящий SOCKS5-прокси включён."""
        sp = (st.get("settings") or {}).get("socks_proxy") or {}
        if not sp.get("enabled"):
            self._stop_socks()
            self._socks_retry = 0.0
            self.socks_state = None
            return
        cfg = self._socks_config(st)
        port = cfg["port"]
        if config.DRY_RUN:
            self.socks_state = {"state": "on", "port": port, "users": len(cfg["users"])}
            return
        h = _sha(json.dumps(cfg, sort_keys=True))
        key = f"{t.key}|{port}"
        d = self.socks_srv
        if d and (d.key != key or d.proc.poll() is not None):
            if d.key != key:
                self._socks_retry = 0.0
            self._stop_socks()
            d = None
        if d is None or d.cfg_hash != h:
            os.makedirs(os.path.dirname(SOCKS_CONF) or ".", exist_ok=True)
            fd = os.open(SOCKS_CONF + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(cfg, f)
            os.replace(SOCKS_CONF + ".tmp", SOCKS_CONF)
        if d is None:
            if time.time() - self._socks_retry < 60:
                return
            self._socks_retry = time.time()
            logp = os.path.join(LOG_DIR, "socksproxy.log")
            _trim_log(logp)
            with open(logp, "a", encoding="utf-8") as logf:
                proc = subprocess.Popen(
                    ["nsenter", "-t", str(t.pid), "-n", "--", "python3", SOCKSPROXY, SOCKS_CONF],
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            time.sleep(0.5)
            if proc.poll() is not None:
                try:
                    with open(logp, encoding="utf-8") as f:
                        tail = f.read()[-300:].strip()
                except OSError:
                    tail = ""
                err = Msg("err.internal", detail=tail)
                self.socks_state = {"state": "error", "port": port, "error": err}
                self.event("error", err)
                return
            self.socks_srv = HelperRT(proc, key, h)
            system.open_firewall_tcp(t, port)
        elif d.cfg_hash != h:
            d.proc.send_signal(signal.SIGHUP)
            d.cfg_hash = h
        self.socks_state = {"state": "on", "port": port, "users": len(cfg["users"])}
