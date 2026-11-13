"""HTTPS панели: Let's Encrypt (на 6 дней, профиль shortlived) для IP или домена, либо свой сертификат.

* Адрес сертификата: домен из настроек (tlsconf: «Система» или установщик), иначе адрес сервера. Адрес
  сервера — IP: в сертификат идёт и второй адрес сервера (IPv4 и IPv6, `alt`), чтобы панель открывалась
  без предупреждения по обоим. Не выдали на оба — сертификат на один основной, вторую попытку — через ALT_RETRY.
* Let's Encrypt: при запуске, если действующего сертификата нет, выпускаем (lego, проверка HTTP-01).
  Порт 80 свободен — lego слушает его сам; занят веб-сервером — токены кладутся в папку, которую
  этот веб-сервер отдаёт (webfront.py). Не получилось — временный самоподписанный, попытки идут.
  Каждые ~6 часов `lego run` проверяет, не пора ли продлевать (для 6-дневного — на середине срока).
* Свой сертификат: файлы на хосте (например, от certbot). Раз в несколько минут смотрим, не
  сменились ли они, и подхватываем новые.
* Новый сертификат подхватывается без перезапуска: сервер берёт контекст при каждом соединении.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import random
import socket
import ssl
import subprocess
import threading
import time
from datetime import datetime, timezone

from . import config, tlsconf, webfront
from .i18n import Msg

log = logging.getLogger("awgr.tls")

TLS_DIR = os.path.join(config.DATA_DIR, "tls")
ACME_DIR = os.path.join(config.DATA_DIR, "acme")
ACME_PROFILE = os.environ.get("ACME_PROFILE", "shortlived")
CUSTOM_CHECK = 300            # с, как часто смотреть, не сменил ли certbot файлы своего сертификата
ALT_RETRY = 24 * 3600         # с: Let's Encrypt не проверил второй адрес — столько не просим его снова


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
    def __init__(self, get_host, get_alt=None):
        self.mode = config.TLS_MODE          # letsencrypt | selfsigned | off — из .env
        self._get_host = get_host
        self._get_alt = get_alt or (lambda: [])   # второй адрес сервера (IP другого семейства) или []
        self._alt_failed: dict[tuple, float] = {}  # набор адресов → когда Let's Encrypt его не выдал
        self._ctx: ssl.SSLContext | None = None
        self._lock = threading.Lock()
        self._run = threading.Lock()        # один выпуск за раз (цикл, кнопка, смена настроек)
        self._wake = threading.Event()
        self.active: str | None = None     # letsencrypt | custom | selfsigned
        self.expires: float | None = None
        self.loaded_for: str | None = None  # адрес, на который загружен сертификат
        self.loaded_names: list[str] = []   # все адреса загруженного (второй — у IPv4 и IPv6, names())
        self.error = None                  # Msg или строка lego
        self.last_try: float | None = None
        self.busy = False
        self.port80: dict | None = None    # порт 80 занят, а проверка через веб-сервер не настроена
        self._custom_sig = None
        self.stop_ev = threading.Event()
        self.on_fail = None   # вызов(expires), если продлить не удаётся, а срок подходит
        os.makedirs(TLS_DIR, exist_ok=True)

    @property
    def enabled(self) -> bool:
        return self.mode in ("letsencrypt", "selfsigned")

    def source(self) -> str:
        src = tlsconf.source()
        return src if src == "custom" or self.mode == "letsencrypt" else "selfsigned"

    def host(self) -> str:
        return tlsconf.domain() or self._get_host() or ""

    def names(self) -> list[str]:
        """Адреса сертификата: основной первым (по нему lego называет файлы), второй — только у IP."""
        host = self.host()
        if not host or not _is_ip(host) or tlsconf.domain():
            return [host] if host else []
        out = [host]
        for a in self._get_alt() or []:
            if a and _is_ip(a) and ipaddress.ip_address(a).version != ipaddress.ip_address(host).version \
                    and str(ipaddress.ip_address(a)) not in out:
                out.append(str(ipaddress.ip_address(a)))
                break
        return out

    def _want(self) -> list[str]:
        """Адреса для выпуска Let's Encrypt: второй — если недавно на нём не было отказа."""
        names = self.names()
        if len(names) > 1 and time.time() - self._alt_failed.get(tuple(names), 0) < ALT_RETRY:
            return names[:1]
        return names

    def context(self) -> ssl.SSLContext | None:
        return self._ctx

    def status(self) -> dict:
        c = tlsconf.load()
        web = c.get("web")
        return {"mode": self.mode, "source": self.source(), "active": self.active, "expires": self.expires,
                "error": self.error, "host": self.host(), "last_try": self.last_try, "busy": self.busy,
                "domain": tlsconf.domain(c), "cert": c.get("cert") or "", "key": c.get("key") or "",
                "web": {k: web.get(k) for k in ("kind", "process", "where", "container", "file", "host")}
                if web else None,
                "port80": self.port80}

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
            self.loaded_for = self.host()
            self.loaded_names = self.names()
        if changed:
            log.info("TLS: %s certificate valid until %s", kind,
                     datetime.fromtimestamp(exp, timezone.utc).isoformat())
        return True

    def _le_paths(self) -> tuple[str, str]:
        d, host = os.path.join(ACME_DIR, "certificates"), self.host()
        base = os.path.join(d, host)
        if os.path.exists(base + ".crt") or not host:
            return base + ".crt", base + ".key"
        # lego меняет в имени файла «:» на «-» (адрес IPv6) и «*» на «_»: правило не угадываем, а берём
        # самый свежий сертификат, выданный на этот адрес (иначе «certificate not found after lego run»)
        found = []
        try:
            names = os.listdir(d)
        except OSError:
            names = []
        for n in names:
            c = os.path.join(d, n)
            if n.endswith(".crt") and not n.endswith(".issuer.crt") and os.path.exists(c[:-4] + ".key") \
                    and _san_matches(c, host):
                found.append((os.path.getmtime(c), c))
        if found:
            c = max(found)[1]
            return c, c[:-4] + ".key"
        return base + ".crt", base + ".key"

    def _selfsigned(self) -> None:
        cert, key = os.path.join(TLS_DIR, "self.crt"), os.path.join(TLS_DIR, "self.key")
        host = self.host() or "localhost"
        names = self.names() or [host]
        if not self._load(cert, key, "selfsigned") or not all(_san_matches(cert, n) for n in names):
            san = ",".join(f"IP:{n}" if _is_ip(n) else f"DNS:{n}" for n in names)
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                            "ec_paramgen_curve:prime256v1", "-nodes", "-days", "825",
                            "-subj", f"/CN={host}", "-addext", f"subjectAltName={san}",
                            "-keyout", key, "-out", cert], capture_output=True, timeout=30, check=True)
            os.chmod(key, 0o600)
            self._load(cert, key, "selfsigned")

    # --------------------------------------------------------- свой сертификат
    def _custom_files(self) -> tuple[str, str]:
        c = tlsconf.load()
        return c.get("cert") or "", c.get("key") or ""

    def _sig(self, cert: str, key: str):
        try:
            return tuple(os.stat(webfront.host_path(p)).st_mtime_ns for p in (cert, key))
        except OSError:
            return None

    def _load_custom(self) -> bool:
        cert, key = self._custom_files()
        err = check_custom(cert, key, self.host())
        if err:
            self.error = err
            log.warning("TLS: own certificate: %s", err)
            return False
        if self._load(webfront.host_path(cert), webfront.host_path(key), "custom"):
            self.error = None
            self._custom_sig = self._sig(cert, key)
            return True
        return False

    # -------------------------------------------------------- Let's Encrypt
    def _lego(self, keep: bool = False) -> bool:
        """Выпуск или продление на адреса `_want()`. Не выдали на оба — на один основной. keep: действующий
        сертификат есть, нужен только второй адрес — при отказе остаёмся на прежнем, лишний не выпускаем."""
        host = self.host()
        if not host:
            self.error = "no public address"
            return False
        names = self._want()
        web = tlsconf.load().get("web")
        if web and web.get("host") == host:
            names = [host]          # блок веб-сервера отвечает только на основной адрес (server_name)
        if keep and len(names) < 2:
            return False
        cmd = ["lego", "run", "--accept-tos", "--path", ACME_DIR, "--server", config.ACME_SERVER,
               "--key-type", "ec256", "--http", "--no-random-sleep"]
        if web and web.get("host") == host:
            cmd += ["--http.webroot", webfront.host_path(web["webroot"])]
            self.port80 = None
        else:
            busy = config.ACME_HTTP_PORT == 80 and (config.DRY_RUN or webfront.listeners())
            if busy:
                det = webfront.detect()
                self.port80 = webfront.public(det)
                self.error = Msg("tls.port80", server=det.get("process") or "?")
                self.last_try = time.time()
                return False
            self.port80 = None
            cmd += ["--http.address", f":{config.ACME_HTTP_PORT}"]
        if config.DRY_RUN:
            self.error = "demo: no Let's Encrypt"
            self.last_try = time.time()
            return False
        if ACME_PROFILE:
            cmd += ["--profile", ACME_PROFILE]
        if config.ACME_EMAIL:
            cmd += ["--email", config.ACME_EMAIL]
        if len(names) > 1:
            if self._issue(cmd, names):
                return True
            self._alt_failed[tuple(names)] = time.time()
            log.warning("Let's Encrypt for %s failed, using %s only", ", ".join(names), host)
            if keep:
                return False
        return self._issue(cmd, [host])

    def _issue(self, cmd: list[str], names: list[str]) -> bool:
        """Один запуск lego на эти адреса. Файлы сертификата не покрывают их (добавили второй адрес) —
        `--renew-force`: иначе lego решил бы, что продлевать ещё рано."""
        cur = self._le_paths()[0]
        if os.path.exists(cur) and not all(_san_matches(cur, n) for n in names):
            cmd = cmd + ["--renew-force"]
        for n in names:
            cmd = cmd + ["-d", n]
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

    # ------------------------------------------------------------ работа
    def _apply(self) -> None:
        """Сертификат по текущим настройкам: свой, Let's Encrypt или временный."""
        with self._run:
            self.busy = True
            try:
                src, host = self.source(), self.host()
                ok = False
                if src == "custom":
                    ok = self._load_custom()
                elif src == "letsencrypt" and host:
                    self.error = None
                    cert, key = self._le_paths()
                    if self._load(cert, key, "letsencrypt") and _san_matches(cert, host):
                        ok = True
                        if not all(_san_matches(cert, n) for n in self._want()):
                            # действующий сертификат без второго адреса: дополнить, при отказе остаться на нём
                            err, p80 = self.error, self.port80
                            if not self._lego(keep=True):
                                self.error, self.port80 = err, p80
                    else:
                        ok = self._lego()
                if src != "letsencrypt":
                    self.port80 = None
                if not ok and (not self._ctx or self.active != src or self.loaded_for != host
                               or (self.active == "selfsigned" and self.loaded_names != self.names())):
                    self._selfsigned()
            finally:
                self.busy = False

    def start(self) -> None:
        """Первичная настройка (блокирующая, ограничена по времени)."""
        if not self.enabled:
            return
        self._apply()
        threading.Thread(target=self._loop, name="acme", daemon=True).start()

    def reconfigure(self) -> None:
        """Настройки сменились: применить в фоне (выпуск может занять пару минут)."""
        if self.enabled:
            self.busy = True
            self._wake.set()

    def _wait(self) -> float:
        src = self.source()
        if src == "custom":
            return CUSTOM_CHECK
        if src != "letsencrypt":
            return 3600
        if self.active != "letsencrypt":
            return 1800              # пока на временном сертификате — пробуем чаще
        wait = 6 * 3600 + random.randint(0, 1800)
        if (self.expires or 0) - time.time() < 3 * 86400:
            wait = min(wait, 3600)   # срок подходит — проверим раньше
        return wait

    def _loop(self) -> None:
        while not self.stop_ev.is_set():
            woke = self._wake.wait(self._wait())
            if self.stop_ev.is_set():
                return
            try:
                self._step(woke)
            except Exception as e:  # noqa: BLE001 — иначе поток умрёт и сертификат больше не продлится
                log.exception("tls")
                self.error = str(e)[:300]
                self.busy = False

    def _step(self, woke: bool) -> None:
        if woke:
            self._wake.clear()
            self._apply()
            return
        src = self.source()
        if src == "custom":
            cert, key = self._custom_files()
            if self._sig(cert, key) != self._custom_sig or self.active != "custom":
                self._apply()
            if self.on_fail and self.active == "custom" and (self.expires or 0) < time.time() + 2 * 86400:
                self.on_fail(self.expires)   # certbot не продлил: до конца срока меньше двух суток
            return
        if src != "letsencrypt":
            return
        with self._run:
            ok = self._lego()
        if not ok and self.active == "letsencrypt" and self.on_fail and \
                (self.expires or 0) < time.time() + 2 * 86400:
            self.on_fail(self.expires)   # до конца срока меньше двух суток — сообщаем
        if not ok and self.active == "letsencrypt" and (self.expires or 0) < time.time() + 600:
            self._selfsigned()   # сертификат вот-вот истечёт, а продлить не удалось

    def renew_now(self) -> bool:
        with self._run:
            ok = self._lego()
            if not ok and not self._ctx:
                self._selfsigned()
            return ok


# ---------------------------------------------------------------- проверки
def _is_ip(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def cert_names(cert: str) -> list[str]:
    """Имена и адреса из сертификата (subjectAltName), в нижнем регистре; IP — в обычной записи."""
    try:
        d = ssl._ssl._test_decode_cert(cert)  # noqa: SLF001
    except Exception:  # noqa: BLE001
        return []
    out = []
    for kind, v in d.get("subjectAltName", ()):
        v = v.strip()
        if kind == "IP Address":
            try:
                v = str(ipaddress.ip_address(v))
            except ValueError:
                pass
        out.append(v.lower())
    return out


def name_matches(names: list[str], host: str) -> bool:
    host = host.lower().rstrip(".")
    if _is_ip(host):
        host = str(ipaddress.ip_address(host))
        return host in names
    if host in names:
        return True
    parent = host.split(".", 1)[1] if "." in host else ""
    return bool(parent) and f"*.{parent}" in names


def _san_matches(cert: str, host: str) -> bool:
    return name_matches(cert_names(cert), host)


def check_custom(cert: str, key: str, host: str):
    """Ошибка своего сертификата (Msg) или None. Пути — на хосте."""
    for p in (cert, key):
        if not p or not p.startswith("/") or "\0" in p or len(p) > 1024:
            return Msg("tls.bad_path")
        try:
            hp = webfront.host_path(p)
        except OSError:
            return Msg("tls.file_missing", path=p)
        if not os.path.isfile(hp):
            return Msg("tls.file_missing", path=p)
    cp, kp = webfront.host_path(cert), webfront.host_path(key)
    exp = cert_not_after(cp)
    if not exp:
        return Msg("tls.not_cert", path=cert)
    if exp < time.time() + 300:
        return Msg("tls.cert_expired", date=time.strftime("%Y-%m-%d", time.gmtime(exp)))
    names = cert_names(cp)
    if host and not name_matches(names, host):
        return Msg("tls.cert_name", host=host, names=", ".join(names[:6]) or "—")
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cp, kp)
    except (ssl.SSLError, OSError, ValueError):
        return Msg("tls.cert_key", path=key)
    return None


def resolve(domain: str) -> list[str]:
    try:
        return list(dict.fromkeys(str(ipaddress.ip_address(a[4][0].split("%")[0]))
                                  for a in socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)))
    except (OSError, ValueError):
        return []


def check_dns(domain: str, server_ips: list[str]):
    """Домен указывает на этот сервер? None — да; Msg — нет (или не находится)."""
    ips = resolve(domain)
    if not ips:
        return Msg("tls.dns_none", domain=domain)
    mine = set()
    for a in server_ips:
        try:
            mine.add(str(ipaddress.ip_address(a)))
        except (ValueError, TypeError):
            pass
    if mine and not mine & set(ips):
        return Msg("tls.dns_other", domain=domain, ips=", ".join(ips[:4]), server=", ".join(sorted(mine)[:3]))
    return None
