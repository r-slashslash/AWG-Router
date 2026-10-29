"""HTTPS панели: сертификат Let's Encrypt на 6 дней (профиль shortlived) для IP или домена.

* При запуске: если действующего сертификата нет — выпускаем (lego, проверка HTTP-01 на
  порту 80). Если не получилось — временный самоподписанный, попытки продолжаются.
* Каждые ~6 часов `lego run` проверяет, не пора ли продлевать (для 6-дневного — на
  середине срока), и продлевает. Новый сертификат подхватывается без перезапуска.
"""
from __future__ import annotations

import logging
import os
import random
import ssl
import subprocess
import threading
import time
from datetime import datetime, timezone

from . import config

log = logging.getLogger("awgr.tls")

TLS_DIR = os.path.join(config.DATA_DIR, "tls")
ACME_DIR = os.path.join(config.DATA_DIR, "acme")
ACME_PROFILE = os.environ.get("ACME_PROFILE", "shortlived")


def cert_not_after(path: str) -> float | None:
    try:
        d = ssl._ssl._test_decode_cert(path)  # noqa: SLF001 — стандартный способ без зависимостей
        return datetime.strptime(d["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc).timestamp()
    except Exception:  # noqa: BLE001
        try:
            out = subprocess.run(["openssl", "x509", "-enddate", "-noout", "-in", path],
                                 capture_output=True, text=True, timeout=10).stdout
            v = out.strip().split("=", 1)[1]
            return datetime.strptime(v, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc).timestamp()
        except Exception:  # noqa: BLE001
            return None


class TLSManager:
    def __init__(self, get_host):
        self.mode = config.TLS_MODE
        self._get_host = get_host
        self._ctx: ssl.SSLContext | None = None
        self._lock = threading.Lock()
        self.active: str | None = None     # letsencrypt | selfsigned
        self.expires: float | None = None
        self.error: str | None = None
        self.last_try: float | None = None
        self.stop_ev = threading.Event()
        self.on_fail = None   # вызов(expires), если продлить не удаётся, а срок подходит
        os.makedirs(TLS_DIR, exist_ok=True)

    @property
    def enabled(self) -> bool:
        return self.mode in ("letsencrypt", "selfsigned")

    def host(self) -> str:
        return config.TLS_DOMAIN or self._get_host() or ""

    def context(self) -> ssl.SSLContext | None:
        return self._ctx

    def status(self) -> dict:
        return {"mode": self.mode, "active": self.active, "expires": self.expires,
                "error": self.error, "host": self.host(), "last_try": self.last_try}

    # ------------------------------------------------------------ загрузка
    def _load(self, cert: str, key: str, kind: str) -> bool:
        exp = cert_not_after(cert)
        if not exp or exp < time.time() + 300:
            return False
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        with self._lock:
            changed = self.expires != exp or self.active != kind
            self._ctx, self.active, self.expires = ctx, kind, exp
        if changed:
            log.info("TLS: %s certificate valid until %s", kind,
                     datetime.fromtimestamp(exp, timezone.utc).isoformat())
        return True

    def _le_paths(self) -> tuple[str, str]:
        base = os.path.join(ACME_DIR, "certificates", self.host())
        return base + ".crt", base + ".key"

    def _selfsigned(self) -> None:
        cert, key = os.path.join(TLS_DIR, "self.crt"), os.path.join(TLS_DIR, "self.key")
        host = self.host() or "localhost"
        if not self._load(cert, key, "selfsigned") or not _san_matches(cert, host):
            san = f"IP:{host}" if _is_ip(host) else f"DNS:{host}"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                            "ec_paramgen_curve:prime256v1", "-nodes", "-days", "825",
                            "-subj", f"/CN={host}", "-addext", f"subjectAltName={san}",
                            "-keyout", key, "-out", cert], capture_output=True, timeout=30, check=True)
            os.chmod(key, 0o600)
            self._load(cert, key, "selfsigned")

    # -------------------------------------------------------- Let's Encrypt
    def _lego(self) -> bool:
        host = self.host()
        if not host:
            self.error = "no public address"
            return False
        cmd = ["lego", "run", "--accept-tos", "--path", ACME_DIR, "--server", config.ACME_SERVER,
               "--key-type", "ec256", "--http", "--http.address", f":{config.ACME_HTTP_PORT}",
               "-d", host, "--no-random-sleep"]
        if ACME_PROFILE:
            cmd += ["--profile", ACME_PROFILE]
        if config.ACME_EMAIL:
            cmd += ["--email", config.ACME_EMAIL]
        self.last_try = time.time()
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        except (OSError, subprocess.TimeoutExpired) as e:
            self.error = str(e)[:300]
            log.warning("lego: %s", e)
            return False
        if p.returncode != 0:
            tail = (p.stderr or p.stdout).strip().splitlines()[-3:]
            self.error = " ".join(tail)[-400:] or f"lego exit {p.returncode}"
            log.warning("lego failed: %s", self.error)
            return False
        cert, key = self._le_paths()
        if self._load(cert, key, "letsencrypt"):
            self.error = None
            return True
        self.error = "certificate not found after lego run"
        return False

    def start(self) -> None:
        """Первичная настройка (блокирующая, ограничена по времени)."""
        if not self.enabled:
            return
        if self.mode == "letsencrypt" and self.host():
            cert, key = self._le_paths()
            if not self._load(cert, key, "letsencrypt"):
                self._lego()
        if not self._ctx:
            self._selfsigned()
        if self.mode == "letsencrypt":
            threading.Thread(target=self._loop, name="acme", daemon=True).start()

    def _loop(self) -> None:
        while not self.stop_ev.is_set():
            if self.active != "letsencrypt":
                wait = 1800          # пока на временном сертификате — пробуем чаще
            else:
                wait = 6 * 3600 + random.randint(0, 1800)
                left = (self.expires or 0) - time.time()
                if left < 3 * 86400:  # срок подходит — проверим раньше
                    wait = min(wait, 3600)
            if self.stop_ev.wait(wait):
                return
            ok = self._lego()
            if not ok and self.active == "letsencrypt" and self.on_fail and \
                    (self.expires or 0) < time.time() + 2 * 86400:
                self.on_fail(self.expires)   # до конца срока меньше двух суток — сообщаем
            if not ok and self.active == "letsencrypt" and (self.expires or 0) < time.time() + 600:
                self._selfsigned()   # сертификат вот-вот истечёт, а продлить не удалось

    def renew_now(self) -> bool:
        ok = self._lego()
        return ok


def _is_ip(h: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _san_matches(cert: str, host: str) -> bool:
    try:
        d = ssl._ssl._test_decode_cert(cert)  # noqa: SLF001
        return any(v == host for _, v in d.get("subjectAltName", ()))
    except Exception:  # noqa: BLE001
        return False
