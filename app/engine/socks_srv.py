"""Входящий SOCKS5-прокси (socksproxy.py): настройки пользователей, запуск и перезагрузка по SIGHUP."""
from __future__ import annotations

import ipaddress
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
SOCKS_DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]


def _host_ips(t: system.Target | None, st: dict, extra: list[str] | None = None) -> list[str]:
    """Собственные IP хоста/контейнера для защиты от SSRF через SOCKS5."""
    ips: set[str] = set()
    s = st.get("settings") or {}
    candidates = [
        config.PUBLIC_HOST,
        s.get("public_host"),
        s.get("client_host"),
        *(extra or []),
    ]
    for c in candidates:
        if isinstance(c, str) and c.strip():
            try:
                ips.add(str(ipaddress.ip_address(c.strip())))
            except ValueError:
                pass
    if t is not None and not config.DRY_RUN and not isinstance(t, system.FakeTarget) and callable(getattr(t, "ns", None)):
        try:
            p = t.ns(["ip", "-j", "addr", "show"], check=False, timeout=5)
            for iface in json.loads(p.stdout or "[]"):
                for info in iface.get("addr_info") or []:
                    loc = info.get("local")
                    if loc:
                        try:
                            ips.add(str(ipaddress.ip_address(loc)))
                        except ValueError:
                            pass
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    return sorted(ips)


class SocksProxyMixin:
    """Публичный входящий SOCKS5-прокси: socksproxy.py (часть Engine)."""

    def _resolve_socks_exit(self, out: str, st: dict, up_map: dict[str, dict], depth: int = 0) -> int:
        """Разрешить выход SOCKS5-пользователя в SO_MARK: 0 — напрямую, >0 — туннель, -1 — блок."""
        if out == "direct":
            return 0
        if out == "block" or depth > 6 or not isinstance(out, str):
            return -1
        uid = out[3:] if out.startswith("up:") else out
        u = up_map.get(uid)
        if not u:
            return -1
        in_rt = uid in getattr(self, "rt", {})
        health = getattr(self, "health", None)
        if isinstance(health, dict) and uid in health:
            h = health[uid]
            if u.get("enabled", True) and h.get("healthy") and in_rt:
                if hasattr(self, "over_quota") and self.over_quota(u):
                    fb = self.quota_target(u) if hasattr(self, "quota_target") else (u.get("fallback") or "direct")
                    return self._resolve_socks_exit(fb, st, up_map, depth + 1)
                return nftgen.mark_for(u["num"])
            if u.get("enabled", True) and h.get("state") == "connecting":
                return -1
        elif u.get("enabled", True) and in_rt:
            return nftgen.mark_for(u["num"])
        return self._resolve_socks_exit(u.get("fallback") or "direct", st, up_map, depth + 1)

    def _socks_config(self, st: dict, t: system.Target | None = None) -> dict:
        """Собрать конфиг socksproxy.py: {listen, port, users, blocked_ips, dns_servers}."""
        sp = (st.get("settings") or {}).get("socks_proxy") or {}
        port = int(sp.get("port") or 1080)
        up_map = {
            u["id"]: u
            for u in (st.get("upstreams") or [])
            if isinstance(u, dict) and "id" in u and "num" in u
        }
        users = {}
        for name, u in (st.get("socks_users") or {}).items():
            if not isinstance(u, dict) or not u.get("enabled", True):
                continue
            mark = self._resolve_socks_exit(u.get("exit") or "direct", st, up_map)
            users[name] = {"password": u.get("password") or "", "mark": mark}
        extra = [getattr(self, "public_v4", None), getattr(self, "public_v6", None)]
        cfg: dict = {
            "listen": "0.0.0.0",
            "port": port,
            "users": users,
            "blocked_ips": _host_ips(t, st, [x for x in extra if isinstance(x, str)]),
        }
        if not config.DRY_RUN:
            cfg["dns_servers"] = list(SOCKS_DNS_SERVERS)
        return cfg

    def _stop_socks(self) -> None:
        """Остановить процесс socksproxy.py, если запущен."""
        d, self.socks_srv = self.socks_srv, None
        fw = getattr(self, "_socks_fw", None)
        self._socks_fw = None
        if fw is not None:
            fw_t, fw_port = fw
            if not config.DRY_RUN and not isinstance(fw_t, system.FakeTarget):
                system.close_firewall_tcp(fw_t, fw_port)
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
        cfg = self._socks_config(st, t)
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
            self._socks_fw = (t, port)
        elif d.cfg_hash != h:
            d.proc.send_signal(signal.SIGHUP)
            d.cfg_hash = h
        self.socks_state = {"state": "on", "port": port, "users": len(cfg["users"])}
