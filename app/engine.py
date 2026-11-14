"""Движок: приводит сетевое пространство контейнера Amnezia к желаемому состоянию.

Каждые RECONCILE_INTERVAL секунд (и сразу после изменений в панели):
  * находит контейнер Amnezia (если он перезапустился — всё создаётся заново);
  * поднимает/гасит туннели awgrN к выходным серверам (AWG или прокси SOCKS5);
  * держит sniproxy.py для правил по доменам (выходы SOCKS5);
  * проверяет «живость» туннелей по рукопожатиям и переключает на резерв;
  * генерирует и атомарно применяет nftables, синхронизирует ip rule / маршруты.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import subprocess
import threading
import time

from . import awgconf, balance, config, domains, hostnet, kernelmod, limits, lists, nftgen, shaping, socks, system
from .i18n import Msg, msg_of
from .store import Store
from .traffic import Traffic, month_key
from .users import ServerManager, client_dns, dns_encrypt

log = logging.getLogger("awgr.engine")

RUN_DIR = "/run/awgr" if not config.DRY_RUN else os.path.join(config.DATA_DIR, "run")
SOCK_DIR = "/var/run/amneziawg"
LOG_DIR = os.path.join(config.DATA_DIR, "logs")
PROBE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probe.py")
PROBE_HOSTS = ("ip-api.com", "ifconfig.me")     # те же имена, что в probe.py
HOST_FAST_TRIES, HOST_FAST_WAIT = 30, 20     # внешний IPv4: сначала 30 попыток раз в 20 секунд,
HOST_SLOW_WAIT = 600                        # потом раз в 10 минут, пока не найдётся;
HOST_RECHECK = 6 * 3600                     # найденный перепроверяем раз в 6 часов
RERESOLVE_AFTER = 30     # туннель с именем в Endpoint не отвечает столько секунд после запуска — разбираем заново
RERESOLVE_EVERY = 60     # и потом не чаще, чем раз в столько секунд
SNIPROXY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sniproxy.py")
SNI_CONF = os.path.join(RUN_DIR, "sni.json")
SNI_STATS = os.path.join(RUN_DIR, "sni-stats.json")
DNSPROXY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dnsproxy.py")
DNS_CONF = os.path.join(RUN_DIR, "dns.json")
DNS_STATS = os.path.join(RUN_DIR, "dns-stats.json")
DNS_PORT = 53


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


UP_PAUSES = (10, 30, 60, 120, 300)      # пауза перед новой попыткой запустить выход, с
SERVER_GRACE = 30        # с: столько интерфейса сервера в контейнере может не быть, прежде чем панель его поднимет
SERVER_PAUSES = (60, 120, 300, 600, 1800)   # паузы между попытками поднять сервер, если не помогает, с
KERNEL_GIVE_UP = 2       # столько перезапусков сервер не поднялся на модуле ядра — панель переводит его на amneziawg-go
MEM_ALERT, MEM_OK = 90, 85   # % занятой памяти: выше — тревога, ниже — снова норма
CPU_ALERT, CPU_OK = 95, 80   # % загрузки процессора
RES_ALERT_SECS = 300     # с: столько значение должно держаться выше порога, чтобы стать тревогой
KERNEL_MIN = 3           # старший номер версии модуля ядра, с которой он понимает AWG 3.1
# параметры AWG 3.1: модуль ядра старше KERNEL_MIN их не принимает, и сервер не поднимается
AWG31_KEYS = re.compile(r"^\s*(HeaderProtectionKey|ContentPaddingAddition|RandomTrailers|DisableCookies)\s*=",
                        re.M | re.I)
SERVER_ENGINE_EVERY = 60     # с: как часто заново смотреть, чем работает интерфейс сервера
FLAP_SECS = 60                          # туннель упал раньше — считаем неудачным запуском


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


class Engine:
    def __init__(self, store: Store):
        self.store = store
        self.lock = threading.RLock()
        self.wake = threading.Event()
        self.stop_ev = threading.Event()
        self.target: system.Target | None = None
        self.target_error = Msg("sys.not_checked")
        self.rt: dict[str, UpRT] = {}
        self.health: dict[str, dict] = {}
        self.clients: list[dict] = []
        self.applied_hash: str | None = None
        self.ruleset: str = ""
        self.last_apply: float | None = None
        self.last_error: str | None = None
        self.last_reconcile: float | None = None
        self.events: list[dict] = []
        self.notifier = None          # notify.Notifier, задаёт main.py
        self.traffic = Traffic()
        # учёт трафика по выходам (таблица nftables awgr_acct): ok | off | None (ещё не было)
        self.acct_state: str | None = None
        self.acct_error: str | None = None
        self._acct_key: str | None = None      # для какой цели таблица проверена
        self._acct_retry = 0.0
        self.matcher = lists.Matcher()
        self._list_cache: dict[str, tuple[float, list[str]]] = {}
        self._parsed: dict[str, awgconf.UpstreamConf] = {}
        self._fake = system.DemoTarget() if config.DRY_RUN else None
        self.public_v4: str | None = None      # внешний IPv4, найденный проверкой «напрямую»
        self.public_v4_state = "pending"        # pending — ещё ищем, ok — найден, failed — не нашли
        self.srv = ServerManager(self)
        self._runtime_checked = False
        self._masking_checked = None     # Target.key, на котором уже проверен старый I1
        self._srv_down: float | None = None   # с какого момента нет интерфейса сервера (_watch_server)
        self._srv_tries = 0
        self._srv_next = 0.0
        self._res: dict[str, dict] = {}       # тревоги по памяти и процессору (_watch_resources)
        self.kernel_fallback: dict | None = None   # модуль ядра не запустил выход: {"error", "at"}
        self.server_engine: str | None = None      # чем работает сервер AWG: kernel | go | None
        self._srv_engine_at: tuple = ("", 0.0)     # (Target.key, когда смотрели)
        self._srv_iface = True                     # интерфейс сервера был на месте, когда смотрели его тип
        self._pre: dict[str, str] = {}             # имена Endpoint, разобранные заранее в этом проходе
        self._pre_failed: set[str] = set()         # имена, которые заранее разобрать не удалось
        self.module_warn: str | None = None        # загружен модуль старше KERNEL_MIN, а конфиг 3.1
        self._module_warned: tuple | None = None
        self._modinfo: tuple = (0.0, "")              # (когда, версия) от modinfo хоста
        self.domain_matcher = domains.Matcher()
        self.sni: HelperRT | None = None
        self.sni_state: dict | None = None      # для интерфейса: state, listen, error
        self._sni_retry = 0.0
        self.dns: HelperRT | None = None        # dnsproxy.py — DNS панели для клиентов
        self.dns_state: dict | None = None      # для интерфейса: state, listen, error
        self._dns_retry = 0.0
        self._socks_res: dict[str, dict] = {}   # uid → результат последней проверки прокси
        self._socks_busy: set[str] = set()
        self._rr_busy: set[str] = set()          # выходы, у которых сейчас заново разбирается имя
        self._up_fail: dict[str, dict] = {}     # uid → {"n", "next", "sig", "err"}: неудачные запуски
        self.balancer = balance.Balancer()      # скорости выходов и распределение клиентов
        self.bal: dict[str, str] = {}           # балансировка: клиент → id выхода (пусто — выключена)
        self.bal_new: str | None = None         # выход для нового клиента (ещё не в self.bal)
        self.bal_nums: set[int] = set()         # номера рабочих выходов балансировки
        self.shape_state: dict | None = None    # ограничение скорости: {"state": on | error, "error"}
        self._shape: dict[str, str] = {}        # интерфейс → хеш применённой очереди; "ing:<if>" → ifb
        self._shape_key: str | None = None      # цель, на которой уже убрано всё лишнее
        self._shape_retry = 0.0
        self._sni_shared_devs: set[str] = set()  # очереди tc, долю которых сейчас ставит sniproxy.py
        os.makedirs(RUN_DIR, exist_ok=True)
        os.makedirs(LOG_DIR, exist_ok=True)

    # ------------------------------------------------------------------ util
    def event(self, level: str, msg: Msg) -> None:
        log.log(logging.WARNING if level != "info" else logging.INFO, "%s", msg)
        self.events.append({"t": time.time(), "level": level, "msg": msg})
        self.events[:] = self.events[-100:]
        if self.notifier:
            self.notifier.engine_event(msg)

    def trigger(self) -> None:
        self.wake.set()

    def reconcile_soon(self) -> None:
        self.wake.set()

    def start(self) -> None:
        threading.Thread(target=self._loop, name="reconcile", daemon=True).start()
        threading.Thread(target=self._lists_loop, name="lists", daemon=True).start()
        threading.Thread(target=self._detect_host, name="public-ip", daemon=True).start()

    def _detect_host(self) -> None:
        """Внешний IPv4 сервера: показывается на вкладке «Сервер» и в боте и становится внешним
        адресом, если его не задали. Сначала частые попытки, потом — реже, но не сдаёмся (раньше
        после 30 неудач адрес не искался до перезапуска панели). Найденный адрес перепроверяем:
        у VPS он может смениться."""
        tries = 0
        while not self.stop_ev.is_set():
            if self.target and self.target.exists:
                tries += 1
                ip = None
                try:
                    r = self.probe("direct")
                    ip = r.get("ip") if r.get("ok") else None
                except Exception:  # noqa: BLE001
                    pass
                wait = HOST_FAST_WAIT if tries < HOST_FAST_TRIES else HOST_SLOW_WAIT
                if ip:
                    self.public_v4, self.public_v4_state = ip, "ok"
                    if not self.srv.public_host(self.store.snapshot()):
                        self.store.mutate(lambda st: st["settings"].setdefault("public_host", ip))
                    tries, wait = 0, HOST_RECHECK
                elif self.public_v4:
                    wait = HOST_SLOW_WAIT       # перепроверка не прошла — оставляем прежний адрес
                elif tries >= HOST_FAST_TRIES:
                    self.public_v4_state = "failed"
            else:
                wait = HOST_FAST_WAIT             # сервера AWG пока нет — ждём его
            self.stop_ev.wait(wait)

    def _loop(self) -> None:
        while not self.stop_ev.is_set():
            try:
                self.reconcile()
            except Exception as e:  # noqa: BLE001
                self.last_error = msg_of(e)
                log.exception("reconcile")
            self.wake.wait(config.RECONCILE_INTERVAL)
            self.wake.clear()

    def _lists_loop(self) -> None:
        time.sleep(2)
        while not self.stop_ev.is_set():
            try:
                self.refresh_lists(only_due=True)
            except Exception:  # noqa: BLE001
                log.exception("lists")
            self.stop_ev.wait(300)

    # ---------------------------------------------------------------- lists
    def refresh_lists(self, only_due: bool = True, ids: list[str] | None = None) -> None:
        st = self.store.snapshot()
        period = float(st["settings"].get("list_update_hours", 24)) * 3600
        changed = False
        for l in st["lists"]:
            if ids is not None and l["id"] not in ids:
                continue
            if only_due:
                if l["kind"] == "manual" and l.get("updated"):
                    continue
                age = time.time() - (l.get("updated") or 0)
                since_check = time.time() - (l.get("checked") or 0)
                if age < period and os.path.exists(lists.path_for(l["id"])):
                    continue
                if l.get("error") and since_check < 900:
                    continue
            res = lists.refresh(l)
            if res.get("error"):
                self.event("warn", Msg("ev.list_failed", list=l["id"],
                                       error=Msg(res["error"]["$t"], **res["error"]["p"])))
            else:
                changed = True

            def upd(s, lid=l["id"], res=res):
                x = Store.lst(s, lid)
                if x:
                    x.update(res)
            self.store.mutate(upd)
        if changed:
            self.trigger()

    def _cidrs(self, lid: str) -> list[str]:
        p = lists.path_for(lid)
        try:
            m = os.path.getmtime(p)
        except OSError:
            return []
        c = self._list_cache.get(lid)
        if c and c[0] == m:
            return c[1]
        v = lists.load_cidrs(lid)
        self._list_cache[lid] = (m, v)
        return v

    # ----------------------------------------------------------- upstreams
    PARSED_MAX = 256       # разобранных конфигов в кэше; больше — кэш начинается заново

    def parsed(self, u: dict) -> awgconf.UpstreamConf:
        h = _sha(u["config"])
        if h not in self._parsed:
            if len(self._parsed) >= self.PARSED_MAX:
                self._parsed = {}       # каждая правка конфига выхода добавляла запись навсегда
            self._parsed[h] = awgconf.parse_upstream(u["config"])
        return self._parsed[h]

    def _stop_up(self, uid: str) -> None:
        r = self.rt.pop(uid, None)
        if not r:
            return
        if r.proc and r.proc.poll() is None:
            r.proc.terminate()
            try:
                r.proc.wait(5)
            except subprocess.TimeoutExpired:
                r.proc.kill()
        t = self.target
        if t and t.key == r.target_key:
            t.ns(["ip", "link", "del", r.iface], check=False)
        for p in (f"{SOCK_DIR}/{r.iface}.sock", os.path.join(RUN_DIR, f"{r.iface}.yml")):
            try:
                os.remove(p)
            except OSError:
                pass

    def _stop_all(self) -> None:
        for uid in list(self.rt):
            self._stop_up(uid)

    def _start_up(self, t: system.Target, uid: str, u: dict, pc: awgconf.UpstreamConf,
                  conf_hash: str) -> None:
        r = UpRT(u["num"], conf_hash, t.key)
        ifn = r.iface
        t.ns(["ip", "link", "del", ifn], check=False)
        if pc.kind == "socks5":
            self._start_socks(t, r, u, pc)
            self.rt[uid] = r
            self._socks_res.pop(uid, None)
            t.ns(["ip", "addr", "replace", f"169.254.200.{u['num']}/32", "dev", ifn], check=False)
            t.ns(["ip", "link", "set", ifn, "up"], check=False)
            t.ns(["sysctl", "-qw", f"net.ipv4.conf.{ifn}.rp_filter=2"], check=False)
            self.event("info", Msg("ev.tunnel_up", iface=ifn, name=u["name"], endpoint=pc.endpoint))
            return
        setconf = pc.setconf
        if not config.DRY_RUN:
            # имя из Endpoint разбираем здесь, в сети панели, до создания интерфейса: в сети
            # контейнера Amnezia свой резолвер не работает (127.0.0.53 от systemd-resolved)
            host = awgconf.split_endpoint(pc.endpoint)[0]
            if host in getattr(self, "_pre_failed", ()):       # уже ждали его в _prefetch_hosts
                raise system.SysError(Msg("cfg.endpoint_resolve", host=host))
            ip = getattr(self, "_pre", {}).get(host)
            if ip is None:
                try:
                    ip = awgconf.resolve_host(host)
                except awgconf.ConfigError as e:
                    raise system.SysError(e.msg) from None
            self._v6_route(t, ip)
            setconf = awgconf.setconf_for(pc, ip)
        r.engine = self.exit_engine()
        kernel_err = None       # awg setconf на модуле не прошёл: ошибка модуля или самого конфига
        if r.engine == "kernel":
            # Модуль не создал интерфейс — это отказ модуля: amneziawg-go до перезапуска сервера
            # (kernel_fallback). Не принял конфиг — ещё не ясно чей отказ: опечатка в конфиге
            # выхода не должна снимать с модуля все выходы, поэтому тот же конфиг сперва пробуем на amneziawg-go.
            try:
                if not config.DRY_RUN:
                    t.ns(["ip", "link", "add", ifn, "type", "amneziawg"])
            except Exception as e:  # noqa: BLE001
                t.ns(["ip", "link", "del", ifn], check=False)
                self._kernel_failed(ifn, msg_of(e))
                r.engine = "go"
            else:
                try:
                    self._setconf(t, ifn, setconf)
                except Exception as e:  # noqa: BLE001
                    t.ns(["ip", "link", "del", ifn], check=False)
                    kernel_err, r.engine = msg_of(e), "go"
        if r.engine == "go":
            if not config.DRY_RUN:
                sock = f"{SOCK_DIR}/{ifn}.sock"
                try:
                    os.remove(sock)
                except OSError:
                    pass
                os.makedirs(SOCK_DIR, exist_ok=True)
                env = dict(os.environ, LOG_LEVEL="error")
                # у процесса своя копия дескриптора журнала — наш закрываем сразу,
                # иначе каждый перезапуск туннеля оставлял бы открытый файл
                with open(os.path.join(LOG_DIR, f"{ifn}.log"), "w") as logf:
                    r.proc = subprocess.Popen(
                        ["nsenter", "-t", str(t.pid), "-n", "--", "amneziawg-go", "-f", ifn],
                        stdout=logf, stderr=subprocess.STDOUT, env=env, start_new_session=True)
                for _ in range(50):
                    if os.path.exists(sock) or r.proc.poll() is not None:
                        break
                    time.sleep(0.1)
                if not os.path.exists(sock):
                    r.proc.kill()
                    try:
                        r.proc.wait(5)          # не оставлять процесс-зомби
                    except subprocess.TimeoutExpired:
                        pass
                    raise system.SysError(Msg("sys.awg_start_failed", iface=ifn))
            self.rt[uid] = r
            self._setconf(t, ifn, setconf)       # не прошёл и здесь — конфиг плох, модуль ни при чём
            if kernel_err is not None:
                self._kernel_failed(ifn, kernel_err)    # amneziawg-go принял то, что не принял модуль
        else:
            self.rt[uid] = r
        # Служебный link-local адрес: без IPv4-адреса ядро при включённом rp_filter
        # отбрасывает входящие пакеты на интерфейсе. Настоящий адрес туннеля (часто
        # из той же подсети 10.8.1.0/24, что и наши клиенты) подставляется через SNAT.
        t.ns(["ip", "addr", "replace", f"169.254.200.{u['num']}/32", "dev", ifn])
        t.ns(["ip", "link", "set", ifn, "mtu", str(pc.mtu), "up"])
        t.ns(["sysctl", "-qw", f"net.ipv4.conf.{ifn}.rp_filter=2"], check=False)
        self.event("info", Msg("ev.tunnel_up", iface=ifn, name=u["name"], endpoint=pc.endpoint))

    # ------------------------------------------------------------- движок AWG
    def module_info(self) -> dict:
        """Модуль ядра на хосте: {"loaded", "version", "ok"} (ok — версия не меньше KERNEL_MIN)."""
        if config.DRY_RUN:
            # демо: выбор amneziawg-go вручную (switch_engine) «выгружает» модуль, как на настоящем сервере
            m = {"loaded": False, "version": None} if kernelmod.load().get("choice") == "go" else \
                {"loaded": True, "version": "3.1.20260812"}
        else:
            m = hostnet.awg_module()
            if m["loaded"] and not m["version"]:
                # у сборки без /sys/module/amneziawg/version версию знает modinfo хоста (не чаще раза в минуту)
                at, v = self._modinfo
                if time.time() - at > 60:
                    from . import webfront
                    p = webfront.host_run(["modinfo", "-F", "version", "amneziawg"], timeout=10)
                    v = (p.stdout or "").strip() if p.returncode == 0 else ""
                    self._modinfo = (time.time(), v)
                m["version"] = v or None
        return {**m, "ok": m["loaded"] and hostnet.module_major(m["version"]) >= KERNEL_MIN}

    def exit_engine(self, st: dict | None = None) -> str:
        """Чем запускать туннели к выходам: тем же, чем работает сервер (выбора нет, решение владельца
        2026-11-14). Сервер на модуле ядра (его выбрал awg-quick: модуль загружен) — выходы тоже, если модуль
        3.x и не отказал (kernel_fallback держится до перезапуска сервера). EXIT_ENGINE=go|kernel в .env —
        для разбора проблем: всегда amneziawg-go или модуль без оглядки на сервер."""
        forced = config.EXIT_ENGINE
        if forced == "go" or self.kernel_fallback or not self.module_info()["ok"]:
            return "go"
        if forced == "kernel":
            return "kernel"
        return "kernel" if self.server_engine == "kernel" else "go"

    def _watch_engine(self, t: system.Target) -> None:
        """Чем работает интерфейс сервера (тип ссылки: amneziawg/wireguard — ядро, tun — amneziawg-go) и не
        загружен ли модуль старше KERNEL_MIN при конфиге 3.1: awg-quick сам берёт модуль, если он есть, и
        тогда сервер не поднимается — этого не видно ни в приложении AmneziaVPN, ни в панели."""
        now = time.time()
        if config.DRY_RUN:
            self.server_engine = "kernel" if self.module_info()["loaded"] else "go"
            return
        if self._srv_engine_at[0] != t.key or now - self._srv_engine_at[1] >= SERVER_ENGINE_EVERY \
                or self.server_engine is None:
            p = t.ns(["ip", "-d", "link", "show", t.iface], check=False, timeout=10)
            out = p.stdout if p.returncode == 0 else ""
            self._srv_iface = p.returncode == 0
            seen = ("kernel" if re.search(r"^\s+(amneziawg|wireguard)\b", out, re.M) else
                    "go" if re.search(r"^\s+tun\b", out, re.M) else None)
            if seen is not None or self._srv_engine_at[0] != t.key:
                self.server_engine = seen     # не прочиталось у той же цели — прежнее, выходы не дёргаем
            if self._srv_engine_at[0] != t.key and self._srv_engine_at[0]:
                self.kernel_fallback = None   # сервер перезапущен (новая цель): модуль пробуем снова
            self._srv_engine_at = (t.key, now)
        m = self.module_info()
        old = bool(m["loaded"] and m["version"]) and not m["ok"]     # версию не узнать — не пугаем
        if not old:
            self.module_warn = None
            return
        if not AWG31_KEYS.search(t.read_file(t.conf_path) or ""):
            self.module_warn = None
            return
        self.module_warn = m["version"] or "?"
        if self._module_warned != (t.key, self.module_warn):
            self._module_warned = (t.key, self.module_warn)
            self.event("warn", Msg("ev.kernel_old", version=self.module_warn, min=KERNEL_MIN))

    def engine_pending(self) -> bool:
        """Чем запускать выходы, пока не ясно: модуль 3.x загружен, выходы идут за сервером, а его интерфейса
        ещё нет (контейнер только что перезапущен). Запуск сейчас поднял бы их на amneziawg-go, а следующий
        проход, увидев сервер на модуле, пересоздал бы на модуле — два запуска вместо одного. Интерфейс есть,
        но тип не распознан — не ждём: выходы идут на amneziawg-go, как раньше."""
        return (not config.DRY_RUN and config.EXIT_ENGINE == "auto" and not self.kernel_fallback
                and self.server_engine is None and not getattr(self, "_srv_iface", True)
                and self.module_info()["ok"])

    def _prefetch_hosts(self, wanted: dict, now: float) -> None:
        """Имена из Endpoint выходов AWG, которые этот проход будет запускать, разбираются разом
        (`awgconf.resolve_many`): по очереди каждое неразрешимое имя держало бы проход — а с ним блокировку
        движка, выдачу конфигов и личные страницы клиентов — по RESOLVE_TIMEOUT секунд. Одно имя разбирает
        сам `_start_up`, как раньше."""
        self._pre, self._pre_failed = {}, set()
        if config.DRY_RUN:
            return
        hosts = set()
        for uid, u in wanted.items():
            f = self._up_fail.get(uid)
            if uid in self.rt or (f and now < f["next"]):
                continue
            try:
                pc = self.parsed(u)
            except awgconf.ConfigError:
                continue
            if pc.kind != "awg":
                continue
            host = awgconf.split_endpoint(pc.endpoint)[0]
            try:
                ipaddress.ip_address(host)
            except ValueError:
                hosts.add(host)
        if len(hosts) > 1:
            self._pre = awgconf.resolve_many(sorted(hosts), awgconf.RESOLVE_TIMEOUT)
            self._pre_failed = hosts - set(self._pre)

    def _kernel_failed(self, ifn: str, err) -> None:
        self.kernel_fallback = {"error": err, "at": time.time()}
        self.event("warn", Msg("ev.kernel_fallback", iface=ifn, error=err))

    def _setconf(self, t: system.Target, ifn: str, setconf: str) -> None:
        path = os.path.join(RUN_DIR, f"{ifn}.conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(setconf)
        try:
            t.ns(["awg", "setconf", ifn, path])
        finally:
            if not config.DRY_RUN:
                os.remove(path)

    @staticmethod
    def _v6_route(t: system.Target, ip: str) -> None:
        """Выход по адресу IPv6: есть ли до него путь в сети сервера AWG. У сети Docker контейнера
        Amnezia по умолчанию IPv6 нет, и туннель без проверки висел бы «без связи» (issue #20).
        Смотрим сам маршрут, а не режим: у кого IPv6 в Docker включён, выход работает."""
        if ":" not in ip:
            return
        p = t.ns(["ip", "-6", "route", "get", ip], check=False, timeout=10)
        if p.returncode != 0:
            raise system.SysError(Msg("sys.no_v6_container" if t.kind == "container" else "sys.no_v6_route",
                                      ip=ip))

    def _start_socks(self, t: system.Target, r: UpRT, u: dict, pc: awgconf.UpstreamConf) -> None:
        """hev-socks5-tunnel в сети сервера: создаёт TUN awgrN и отправляет всё из него в прокси."""
        if config.DRY_RUN:
            return
        if not os.path.exists("/proc/sys/net/ipv6"):
            # hev-socks5-tunnel открывает сокеты AF_INET6 (IPv4 внутри них): нужна поддержка
            # IPv6 в ядре; выключенный sysctl disable_ipv6 не мешает, мешает загрузка с ipv6.disable=1
            raise system.SysError(Msg("sys.socks_no_ipv6"))
        try:
            ip = socks.resolve(pc.socks["host"])
        except socks.SocksError as e:
            raise system.SysError(e.msg) from None
        self._v6_route(t, ip)
        r.socks_ip = ip
        path = os.path.join(RUN_DIR, f"{r.iface}.yml")      # в нём пароль прокси — только для root
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(socks.hev_config(r.iface, r.num, ip, pc.socks))
        logp = os.path.join(LOG_DIR, f"{r.iface}.log")
        with open(logp, "w") as logf:
            r.proc = subprocess.Popen(["nsenter", "-t", str(t.pid), "-n", "--", socks.HEV, path],
                                      stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
        up = False
        for _ in range(50):
            if r.proc.poll() is not None:
                break
            links = self._links(t)
            if links and r.iface in links:
                up = True
                break
            time.sleep(0.1)
        try:
            os.remove(path)          # hev прочитал настройки при запуске
        except OSError:
            pass
        if not up:
            if r.proc.poll() is None:
                r.proc.kill()
            try:
                r.proc.wait(5)
            except subprocess.TimeoutExpired:
                pass
            try:
                with open(logp) as f:
                    tail = f.read()[-300:].strip()
            except OSError:
                tail = ""
            raise system.SysError(Msg("sys.socks_start_failed", iface=r.iface, detail=tail))

    def _links(self, t: system.Target) -> set[str] | None:
        if config.DRY_RUN:
            return None
        p = t.ns(["ip", "-j", "link", "show"], check=False)
        try:
            return {x["ifname"] for x in json.loads(p.stdout or "[]")}
        except ValueError:
            return set()

    def _sync_upstreams(self, t: system.Target, st: dict) -> None:
        wanted = {u["id"]: u for u in st["upstreams"] if u.get("enabled", True)}
        for uid in list(self.rt):
            r = self.rt[uid]
            if uid not in wanted or wanted[uid]["num"] != r.num or r.target_key != t.key:
                self._stop_up(uid)
        for uid in list(self._up_fail):
            if uid not in wanted:
                self._up_fail.pop(uid, None)
        links = self._links(t)
        now = time.time()
        eng = self.exit_engine()
        wait_engine = self.engine_pending()
        if wait_engine:
            self._pre, self._pre_failed = {}, set()     # выходы AWG ждут сервер: разбирать имена незачем
        else:
            self._prefetch_hosts(wanted, now)
        for uid, u in wanted.items():
            try:
                pc = self.parsed(u)
            except awgconf.ConfigError as e:
                self.health[uid] = {"state": "error", "error": e.msg}
                continue
            h = _sha((pc.setconf if pc.kind == "awg" else pc.raw) + str(pc.mtu))
            sig = f"{h}|{t.key}"
            f = self._up_fail.get(uid)
            if f and f["sig"] != sig:
                self._up_fail.pop(uid, None)            # настройки или сервер сменились — пробуем сразу
                f = None
            r = self.rt.get(uid)
            alive = bool(r) and (links is None or r.iface in links) and \
                (r.proc is None or r.proc.poll() is None)
            if r and alive and f and now - r.started >= FLAP_SECS:
                self._up_fail.pop(uid, None)            # туннель держится — счёт неудач сначала
                f = None
            if r and pc.kind == "awg" and r.engine != eng and alive:
                self._stop_up(uid)                      # выбрали другой движок — перезапуск на нём
                r = None
            if r and (r.conf_hash != h or not alive):
                if not alive:
                    if not f:
                        self.event("warn", Msg("ev.tunnel_down", iface=r.iface, name=u["name"]))
                    if now - r.started < FLAP_SECS:
                        # процесс туннеля падает сразу после запуска — как неудачный запуск
                        f = self._failed_up(uid, sig, Msg("ev.tunnel_down", iface=r.iface, name=u["name"]),
                                            u, quiet=True)
                self._stop_up(uid)
                r = None
            if not r:
                if f and now < f["next"]:
                    continue                            # пауза после неудачи (UP_PAUSES)
                if wait_engine and pc.kind == "awg":
                    continue                            # интерфейса сервера ещё нет: см. engine_pending
                try:
                    self._start_up(t, uid, u, pc, h)
                except Exception as e:  # noqa: BLE001
                    self._stop_up(uid)
                    self._failed_up(uid, sig, msg_of(e), u)

    def _failed_up(self, uid: str, sig: str, err, u: dict, quiet: bool = False) -> dict:
        """Неудачный запуск выхода: следующая попытка — через растущую паузу (10 с … 5 мин),
        событие — только при первой неудаче или другой ошибке, чтобы не засорять журнал и Telegram."""
        prev = self._up_fail.get(uid) or {}
        n = prev.get("n", 0) + 1
        f = {"n": n, "sig": sig, "err": err, "next": time.time() + UP_PAUSES[min(n, len(UP_PAUSES)) - 1]}
        self._up_fail[uid] = f
        self.health[uid] = {"state": "error", "error": err, "retry_at": f["next"]}
        if not quiet and (n == 1 or str(prev.get("err")) != str(err)):
            self.event("error", Msg("ev.upstream_error", name=u["name"], error=err))
        return f

    def _update_health(self, t: system.Target, st: dict) -> None:
        now = time.time()
        for u in st["upstreams"]:
            uid = u["id"]
            if not u.get("enabled", True):
                self.health[uid] = {"state": "disabled"}
                continue
            r = self.rt.get(uid)
            if not r:
                self.health.setdefault(uid, {"state": "down"})
                if self.health[uid].get("state") not in ("error",):
                    self.health[uid] = {"state": "down"}
                continue
            try:
                kind = self.parsed(u).kind
            except Exception:  # noqa: BLE001
                kind = "awg"
            if kind == "socks5":
                self._socks_health(t, u, r, now)
                continue
            if config.DRY_RUN and self._fake and r.iface not in self._fake.handshakes:
                # в демо второй туннель «мёртвый», чтобы было видно резервирование
                self._fake.handshakes[r.iface] = now - (900 if r.num == 2 else 20)
            p = t.ns(["awg", "show", r.iface, "dump"], check=False, timeout=10)
            peers = system._parse_dump(p.stdout) if p.returncode == 0 else {}
            peer = next(iter(peers.values()), None)
            try:
                limit = self.parsed(u).rekey_after + 70
            except Exception:  # noqa: BLE001
                limit = 190
            hs = peer["handshake"] if peer else 0
            age = now - hs if hs else None
            healthy = age is not None and age < limit
            prev = self.health.get(uid, {}).get("healthy")
            if prev is not None and prev != healthy:
                self.event("info" if healthy else "warn",
                           Msg("ev.upstream_ok" if healthy else "ev.upstream_failed",
                               name=u["name"], uid=uid))
            if not healthy and now - r.started >= RERESOLVE_AFTER and peer and not config.DRY_RUN:
                self._reresolve(t, u, r, peer, now)
            self.health[uid] = {
                "state": "up" if healthy else ("connecting" if now - r.started < 30 and not hs else "stale"),
                "healthy": healthy, "handshake_age": age, "iface": r.iface,
                "rx": peer["rx"] if peer else 0, "tx": peer["tx"] if peer else 0,
                "endpoint": peer["endpoint"] if peer else None,
                "since": r.started,
            }

    def _reresolve(self, t: system.Target, u: dict, r: UpRT, peer: dict, now: float) -> None:
        """Туннель с именем в Endpoint не отвечает: разбираем имя заново и, если адрес сменился,
        меняем его у пира (`awg set … endpoint`) без перезапуска. Работающий туннель не трогаем:
        сбой DNS или подменённый ответ не должны уводить живой туннель на чужой адрес.
        Разбор идёт в фоне, чтобы не задерживать цикл, и не чаще раза в RERESOLVE_EVERY."""
        uid = u["id"]
        if now - r.reresolved < RERESOLVE_EVERY or uid in self._rr_busy:
            return
        try:
            pc = self.parsed(u)
        except awgconf.ConfigError:
            return
        host, port = awgconf.split_endpoint(pc.endpoint)
        try:
            ipaddress.ip_address(host)
            return                                  # в конфиге адрес, а не имя — разбирать нечего
        except ValueError:
            pass
        r.reresolved = now
        self._rr_busy.add(uid)

        def run():
            try:
                ip = awgconf.resolve_host(host)
                addr = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
                cur = peer.get("endpoint")
                if cur == addr or uid not in self.rt or self.rt[uid] is not r:
                    return
                # имя стало указывать только на IPv6, а пути туда нет: адрес не меняем. Только журнал —
                # проверка идёт раз в RERESOLVE_EVERY, событие с уведомлением повторялось бы каждую минуту
                self._v6_route(t, ip)
                t.ns(["awg", "set", r.iface, "peer", pc.peer_public_key, "endpoint", addr], timeout=15)
                self.event("info", Msg("ev.endpoint_changed", name=u["name"], host=host,
                                       old=cur or "—", new=addr))
            except Exception as e:  # noqa: BLE001
                log.info("reresolve %s: %s", host, e)
            finally:
                self._rr_busy.discard(uid)
        threading.Thread(target=run, name=f"reresolve-{uid}", daemon=True).start()

    def _socks_health(self, t: system.Target, u: dict, r: UpRT, now: float) -> None:
        """Выход SOCKS5 работает, если жив hev-socks5-tunnel и недавняя проверка прокси прошла.
        Проверка идёт в фоне раз в минуту, чтобы не задерживать цикл."""
        uid = u["id"]
        if config.DRY_RUN:
            self._socks_res[uid] = {"ok": r.num != 2, "ms": 35, "at": now,
                                    "error": None if r.num != 2 else Msg("socks.timeout")}
        res = self._socks_res.get(uid)
        if (not res or now - res["at"] >= socks.CHECK_EVERY) and uid not in self._socks_busy:
            conf = self.parsed(u).socks
            self._socks_busy.add(uid)

            def run(uid=uid, conf=conf):
                try:
                    self._socks_res[uid] = socks.check(conf)
                finally:
                    self._socks_busy.discard(uid)
                    ok = bool((self._socks_res.get(uid) or {}).get("ok"))
                    if ok != bool((self.health.get(uid) or {}).get("healthy")):
                        self.trigger()      # состояние изменилось — пересчитать правила сразу
            threading.Thread(target=run, name=f"socks-{uid}", daemon=True).start()
        alive = r.proc is None or r.proc.poll() is None
        healthy = bool(alive and res and res["ok"] and now - res["at"] < socks.CHECK_FRESH)
        prev = self.health.get(uid, {}).get("healthy")
        if prev is not None and prev != healthy:
            self.event("info" if healthy else "warn",
                       Msg("ev.upstream_ok" if healthy else "ev.upstream_failed", name=u["name"], uid=uid))
        rx = tx = 0
        if not config.DRY_RUN:
            p = t.ns(["ip", "-j", "-s", "link", "show", "dev", r.iface], check=False, timeout=10)
            try:
                st64 = (json.loads(p.stdout or "[]") or [{}])[0].get("stats64") or {}
                # TUN со стороны ядра: rx — пришло от прокси (к клиентам), tx — ушло в прокси
                rx, tx = st64.get("rx", {}).get("bytes", 0), st64.get("tx", {}).get("bytes", 0)
            except (ValueError, IndexError, AttributeError):
                pass
        state = "up" if healthy else ("connecting" if not res and now - r.started < 30 else "stale")
        self.health[uid] = {"state": state, "healthy": healthy, "iface": r.iface, "since": r.started,
                            "kind": "socks5", "check_age": now - res["at"] if res else None,
                            "latency_ms": res["ms"] if res else None,
                            "error": res["error"] if res and not res["ok"] else
                            (None if alive else Msg("socks.tunnel_down")),
                            "rx": rx, "tx": tx}

    # ------------------------------------------------- трафик по выходам
    def _account(self, t: system.Target, st: dict) -> None:
        """Счётчики таблицы учёта → traffic. Ошибка здесь не мешает маршрутизации:
        учёт выключается, и через час (или при смене цели) пробуем снова."""
        now = time.time()
        if self.acct_state == "off" and self._acct_key == t.key and now < self._acct_retry:
            return
        fresh = False
        p = t.ns(["nft", "-j", "list", "table", "ip", nftgen.ACCT_TABLE], check=False, timeout=20)
        counters = None
        if p.returncode == 0:
            try:
                counters = nftgen.parse_acct(json.loads(p.stdout or "{}"), t.iface)
            except ValueError:
                counters = None
        if counters is None:
            path = os.path.join(RUN_DIR, "acct.nft")
            with open(path, "w") as f:
                f.write(nftgen.acct_ruleset(t.iface))
            r = t.ns(["nft", "-f", path], check=False, timeout=60)
            if r.returncode != 0:
                err = (r.stderr or r.stdout or "").strip()[-300:]
                if self.acct_state != "off":
                    log.warning("exit traffic accounting is off: %s", err)
                    self.event("warn", Msg("ev.acct_off", error=err))
                self.acct_state, self.acct_error = "off", err
                self._acct_key, self._acct_retry = t.key, now + 3600
                return
            counters, fresh = {}, True
        self.acct_state, self.acct_error, self._acct_key = "ok", None, t.key
        by_num = {u["num"]: u["id"] for u in st["upstreams"]}
        pfx = config.IFACE_PREFIX

        def out_of(ifn: str):
            if ifn.startswith(pfx) and ifn[len(pfx):].isdigit():
                return by_num.get(int(ifn[len(pfx):]))   # выход удалён — не считаем
            return "direct"
        pk_of = {c["ip"]: c["public_key"] for c in self.clients if c.get("ip")}
        self.traffic.update_outs(counters, out_of, pk_of, fresh=fresh, now=now)

    @staticmethod
    def quota_target(u: dict) -> str | None:
        """Куда идёт трафик выхода, когда его квота исчерпана: 'direct' | 'block' | 'up:<id>';
        None — только уведомить. 'fallback' — значение из первых сборок 1.3.0: как резерв."""
        qa = u.get("quota_action") or "notify"
        if qa == "notify":
            return None
        if qa == "fallback":
            return u.get("fallback") or "direct"
        return qa

    def over_quota(self, u: dict) -> bool:
        """Месячная квота выхода исчерпана и трафик должен уйти на выход из quota_target."""
        q = u.get("quota")
        return bool(q) and self.quota_target(u) is not None and \
            self.traffic.out_used(u["id"]) >= q

    def _exit_quotas(self, st: dict) -> None:
        """События квот выходов: 90 %, исчерпана, новый месяц. Отметки — в state, чтобы
        не повторять событие после перезапуска панели."""
        if self.acct_state != "ok":
            return
        mk = month_key()
        patches: dict[str, dict] = {}
        for u in st["upstreams"]:
            q = u.get("quota")
            if not q:
                continue
            used = self.traffic.out_used(u["id"])
            gb = float(f"{q / limits.GB:.3g}")
            to = self.quota_target(u)
            fb = to is not None
            p = {}
            if used >= q and u.get("quota_hit") != mk:
                p["quota_hit"] = p["quota_warned"] = mk
                if to is None:
                    self.event("warn", Msg("ev.upstream_quota_notify", name=u["name"], gb=gb, uid=u["id"]))
                elif to in ("direct", "block"):
                    self.event("warn", Msg(f"ev.upstream_quota_{to}", name=u["name"], gb=gb, uid=u["id"]))
                else:
                    t = Store.upstream(st, to[3:])
                    self.event("warn", Msg("ev.upstream_quota", name=u["name"], gb=gb, uid=u["id"],
                                           to=t["name"] if t else "?"))
            elif q * 0.9 <= used < q and u.get("quota_warned") != mk:
                p["quota_warned"] = mk
                self.event("warn", Msg("ev.upstream_quota_warn", name=u["name"], gb=gb, uid=u["id"]))
            if u.get("quota_hit") and u["quota_hit"] != mk and used < q and "quota_hit" not in p:
                p["quota_hit"] = None
                if fb:
                    self.event("info", Msg("ev.upstream_quota_reset", name=u["name"], uid=u["id"]))
            if p:
                patches[u["id"]] = p
        if patches:
            def fn(s):
                for x in s["upstreams"]:
                    if x["id"] in patches:
                        x.update(patches[x["id"]])
            self.store.mutate(fn)

    # --------------------------------------------------------------- policy
    def resolve(self, out: str, st: dict, depth: int = 0):
        """Выход из настроек → фактический: 'direct' | 'block' | номер туннеля."""
        if out in ("direct", "block"):
            return out
        if depth > 6:
            return "block"
        if out.startswith("up:"):
            u = Store.upstream(st, out[3:])
            if not u:
                return "block"
            h = self.health.get(u["id"], {})
            if u.get("enabled", True) and h.get("healthy"):
                if not self.over_quota(u):
                    return u["num"]
                return self.resolve(self.quota_target(u), st, depth + 1)
            return self.resolve(u.get("fallback") or "direct", st, depth + 1)
        return "block"

    def policy_for(self, st: dict, pk: str | None) -> dict:
        """Политика в терминах настроек (до резолва), с учётом настроек клиента."""
        g = st["routing"]
        cp = st["clients"].get(pk or "", {})
        rules = g["rules"]
        if cp.get("rules_mode") == "custom":
            rules = cp.get("rules") or []
        default = g["default"]
        if cp.get("outbound") and cp["outbound"] != "inherit":
            default = cp["outbound"]
        return {"rules": [r for r in rules if r.get("enabled", True) and r.get("lists")],
                "default": default, "custom": bool(cp) and (
                    cp.get("rules_mode") == "custom" or cp.get("outbound", "inherit") != "inherit"),
                # выход по умолчанию — общий, и включена балансировка: выход выбирает она
                "balanced": self.balance_on(st) and cp.get("outbound", "inherit") == "inherit"}

    # ---------------------------------------------------------- балансировка
    @staticmethod
    def balance_on(st: dict) -> bool:
        return bool((st["routing"].get("balance") or {}).get("on"))

    def balance_members(self, st: dict) -> list[dict]:
        """Рабочие выходы балансировки: включены, в списке, запущены, работают и не исчерпали квоту
        (иначе resolve вёл бы на их резерв). Ограничения скорости — мощность для расчёта загрузки."""
        if not self.balance_on(st):
            return []
        skip = set((st["routing"].get("balance") or {}).get("skip") or [])
        return [{"id": u["id"], "num": u["num"], "up": shaping.mbit(u.get("rate_up")),
                 "down": shaping.mbit(u.get("rate_down"))}
                for u in st["upstreams"] if u["id"] not in skip and u["id"] in self.rt
                and self.resolve("up:" + u["id"], st) == u["num"]]

    def _balance(self, st: dict) -> None:
        members = self.balance_members(st)
        pks = [c["public_key"] for c in self.clients if c.get("ip")
               and self.policy_for(st, c["public_key"])["balanced"]]
        self.bal = self.balancer.plan(members, pks, time.time())
        self.bal_new = self.balancer.pick(members)
        self.bal_nums = {m["num"] for m in members}
        mv = self.balancer.last_move
        if mv and mv.get("logged") is None:
            mv["logged"] = True
            name = lambda uid: (Store.upstream(st, uid) or {}).get("name", uid)
            c = next((x for x in self.clients if x["public_key"] == mv["pk"]), {})
            self.event("info", Msg("ev.balance_move", client=c.get("name") or c.get("ip") or mv["pk"][:8],
                                   **{"from": name(mv["from"])}, to=name(mv["to"])))

    def default_out(self, st: dict, pk: str | None, pol: dict | None = None) -> str:
        """Выход по умолчанию клиента в терминах настроек: при балансировке — выход, который она
        назначила ('up:<id>'), иначе — из политики (а если все выходы балансировки лежат —
        выход по умолчанию: он же запасной)."""
        pol = pol or self.policy_for(st, pk)
        if pol.get("balanced"):
            uid = self.bal.get(pk) if pk else self.bal_new
            if uid and Store.upstream(st, uid):
                return "up:" + uid
        return pol["default"]

    def _resolved(self, st: dict, pol: dict) -> dict:
        return {"rules": [(r["lists"], self.resolve(r["outbound"], st)) for r in pol["rules"]],
                "default": self.resolve(pol["default"], st)}

    @staticmethod
    def domain_lists(st: dict) -> set[str]:
        return {l["id"] for l in st["lists"] if l.get("kind") == "domains"}

    def _policies(self, st: dict) -> tuple[dict, dict]:
        """Общая и личные политики для nftables и sniproxy.py: правила по адресам — с выходом
        после резолва; правила со списками доменов — отдельно (их выход резолвит sniproxy-конфиг)."""
        dl = self.domain_lists(st)

        def conv(pol: dict, pk: str | None) -> dict:
            ip_rules, dom = [], []
            for r in pol["rules"]:
                if any(lid in dl for lid in r["lists"]):
                    dom.append(([lid for lid in r["lists"] if lid in dl], r["outbound"]))
                else:
                    ip_rules.append((r["lists"], self.resolve(r["outbound"], st)))
            default = self.resolve(self.default_out(st, pk, pol), st)
            if pol.get("balanced") and isinstance(default, int) and default in self.bal_nums:
                default = nftgen.Sticky(default)     # открытые соединения не переезжают
            return {"rules": ip_rules, "default": default, "domain": dom}

        gp = conv(self.policy_for(st, None), None)
        cps = {}
        for c in self.clients:
            if not c.get("ip"):
                continue
            pol = self.policy_for(st, c["public_key"])
            if pol["custom"] or pol["balanced"]:
                cps[c["ip"]] = conv(pol, c["public_key"])
        return gp, cps

    def _up_list(self, st: dict) -> list[dict]:
        ups = []
        for u in st["upstreams"]:
            if u["id"] in self.rt:
                try:
                    pc = self.parsed(u)
                except Exception:  # noqa: BLE001
                    continue
                ups.append({"num": u["num"], "snat": pc.address, "mtu": pc.mtu})
        return ups

    def build_ruleset(self, t: system.Target, st: dict, sniff_port: int | None = None) -> str:
        gp, cps = self._policies(st)
        used = {lid for p in [gp, *cps.values()] for l, _ in p["rules"] for lid in l}
        lst = {lid: self._cidrs(lid) for lid in used}
        return nftgen.generate(t.iface, lst, self._up_list(st), gp, cps, sniff_port, self.bal_nums)

    # ---------------------------------------------- правила по доменам (sniproxy.py)
    def tunnel_addr(self, t: system.Target) -> tuple[str, str] | None:
        """Адрес сервера в туннеле (на нём слушает sniproxy.py) и подсеть клиентов."""
        if config.DRY_RUN:
            return "10.8.1.1", "10.8.1.0/24"
        p = t.ns(["ip", "-j", "-4", "addr", "show", "dev", t.iface], check=False)
        try:
            for x in json.loads(p.stdout or "[]"):
                for a in x.get("addr_info") or []:
                    if a.get("family") == "inet" and a.get("local"):
                        net = ipaddress.ip_interface(f'{a["local"]}/{a.get("prefixlen", 24)}').network
                        return a["local"], str(net)
        except (ValueError, TypeError):
            pass
        return None

    def _sni_target(self, st: dict, out: str) -> dict:
        """Куда sniproxy.py ведёт соединение с совпавшим доменом: SOCKS5 выхода (если он
        работает), иначе — его резервный путь."""
        eff = self.resolve(out, st)
        if eff == "block":
            return {"block": True}
        if eff == "direct":
            return {"mark": 0, "acct": "direct"}
        u = next((x for x in st["upstreams"] if x["num"] == eff), None)
        r = self.rt.get(u["id"]) if u else None
        try:
            pc = self.parsed(u) if u else None
        except Exception:  # noqa: BLE001
            pc = None
        acct = u["id"] if u else None           # для учёта трафика выхода (sniproxy считает байты)
        if pc and pc.kind == "socks5":
            return {"socks": {"ip": (r.socks_ip if r and r.socks_ip else pc.socks["host"]), "port": pc.socks["port"],
                              "user": pc.socks["user"], "password": pc.socks["password"]}, "acct": acct}
        return {"mark": nftgen.mark_for(eff), "acct": acct}

    @staticmethod
    def _acct_label(st: dict, out) -> str | None:
        """Выход после резолва → ключ учёта трафика: "direct" | id выхода | None (блок)."""
        if out == "direct":
            return "direct"
        if out == "block":
            return None
        u = next((x for x in st["upstreams"] if x["num"] == out), None)
        return u["id"] if u else None

    def _sni_account(self) -> None:
        """Байты соединений sniproxy.py (по «клиент|выход») → трафик выходов. Через посредника
        идут TCP 80/443 клиентов с правилами по доменам: для сервера это входящие и исходящие
        соединения, а не транзит, поэтому таблица учёта nftables (hook forward) их не видит."""
        try:
            with open(SNI_STATS) as f:
                s = json.load(f)
        except (OSError, ValueError):
            return
        if not isinstance(s, dict) or not isinstance(s.get("pid"), int) or not isinstance(s.get("bytes"), dict):
            return
        st = self.store.snapshot()
        valid = {"direct"} | {u["id"] for u in st["upstreams"]}
        pk_of = {c["ip"]: c["public_key"] for c in self.clients if c.get("ip")}
        self.traffic.update_sni(s["pid"], s["bytes"], valid, pk_of)

    def _sni_shared(self, st: dict, rates: dict) -> dict:
        """Общий предел туннеля выхода SOCKS5 и соединений sniproxy.py через прокси: {id выхода:
        {"0" — отдача | "1" — загрузка: {"iface", "dev", "cap", "tc"}}}. dev — где стоит очередь tc
        этой стороны (awgrN или его ifb), tc — команда смены её скорости (shaping.cap_change)."""
        out = {}
        for u in st["upstreams"]:
            r = self.rt.get(u["id"])
            if not r or u["id"] not in rates:
                continue
            try:
                if self.parsed(u).kind != "socks5":
                    continue
            except Exception:  # noqa: BLE001
                continue
            dirs = {}
            for i, key, dev in ((0, "rate_up", r.iface), (1, "rate_down", shaping.ifb_for(r.num))):
                m = shaping.mbit(u.get(key))
                if m:
                    dirs[str(i)] = {"iface": r.iface, "dev": dev, "cap": rates[u["id"]][i],
                                    "tc": shaping.cap_change(dev, m)}
            if dirs:
                out[u["id"]] = dirs
        return out

    def _stop_sni(self) -> None:
        # доли туннелей, которые делил посредник, — заново из настроек (панель пересоздаст очереди)
        for dev in self._sni_shared_devs:
            self._shape.pop(dev, None)
        self._sni_shared_devs = set()
        d, self.sni = self.sni, None
        if d and d.proc.poll() is None:
            d.proc.terminate()
            try:
                d.proc.wait(5)
            except subprocess.TimeoutExpired:
                d.proc.kill()
        if d and not config.DRY_RUN:
            try:
                self._sni_account()          # последние байты (процесс пишет их при остановке)
            except Exception:  # noqa: BLE001
                log.exception("sni traffic")

    def _input_rule(self, t: system.Target, op: str, ports=None) -> None:
        """Перенаправленные соединения клиентов и запросы к DNS панели — входящие для сервера
        (а не транзитные). Файрвол на iptables (ufw и т. п.) их бы отбросил: разрешаем порт на
        интерфейсе клиентов. op: "add" | "del"; ports — [(протокол, порт)], по умолчанию порт
        sniproxy.py. Нет iptables — ничего не делаем."""
        ifn = t.iface
        cmds = []
        for proto, port in ports or [("tcp", int(config.SNI_PROXY_PORT))]:
            rule = f"INPUT -i {ifn} -p {proto} --dport {int(port)} -j ACCEPT"
            if op == "add":
                cmds.append(f"{{ iptables -C {rule} 2>/dev/null || iptables -I {rule}; }}")
            else:
                cmds.append(f"while iptables -C {rule} 2>/dev/null; do iptables -D {rule}; done")
        try:
            t.native(["sh", "-c", "command -v iptables >/dev/null 2>&1 || exit 0; " + "; ".join(cmds)],
                     check=False, timeout=30)
        except Exception as e:  # noqa: BLE001
            log.info("input rule: %s", e)

    def _sni_hung(self) -> bool:
        """Процесс жив, но цикл событий стоит: счётчики (пишет каждые 15 с) давно не обновлялись."""
        d = self.sni
        if not d or time.time() - d.started < 120:
            return False
        try:
            with open(SNI_STATS) as f:
                s = json.load(f)
        except (OSError, ValueError):
            return False
        return s.get("pid") == d.proc.pid and time.time() - float(s.get("at") or 0) > 120

    def _sync_sni(self, t: system.Target, st: dict) -> int | None:
        """Держит sniproxy.py запущенным, пока в правилах есть списки доменов.
        → порт для nftables или None (правила по доменам сейчас не действуют)."""
        gp, cps = self._policies(st)
        up_nums = {u["num"] for u in self._up_list(st)}
        policies, client_map = nftgen.layout(gp, cps, up_nums, self.bal_nums)
        marks = nftgen.sniff_marks(policies)
        if not marks:
            self._stop_sni()
            self.sni_state = None
            return None
        la = self.tunnel_addr(t)
        if not la:
            self._stop_sni()
            self.sni_state = {"state": "error", "error": Msg("sni.no_addr", iface=t.iface)}
            return None
        listen, net = la
        if config.DRY_RUN:
            self.sni_state = {"state": "on", "listen": listen}
            return config.SNI_PROXY_PORT
        lids = sorted({lid for n in marks for l, _ in policies[n]["domain"] for lid in l})
        files = {lid: domains.path_for(lid) for lid in lids}
        # правила по адресам этих политик — для учёта: куда ушло соединение без совпадения по
        # домену (те же правила проверяет цепочка q_* в nftables)
        nets = sorted({lid for n in marks for l, _ in policies[n]["rules"] for lid in l})
        cidrs = {lid: lists.path_for(lid) for lid in nets if os.path.exists(lists.path_for(lid))}
        acct = lambda p: {"rules": [[l, self._acct_label(st, o)] for l, o in p["rules"]],
                          "default": self._acct_label(st, p["default"])}
        # ограничения скорости выходов SOCKS5 для соединений через прокси (байт/с; 0 — нет)
        bps = lambda v: int((shaping.mbit(v) or 0) * 125_000)
        rates = {u["id"]: [bps(u.get("rate_up")), bps(u.get("rate_down"))] for u in st["upstreams"]
                 if shaping.mbit(u.get("rate_up")) or shaping.mbit(u.get("rate_down"))}
        shared = self._sni_shared(st, rates)
        self._sni_shared_devs = {d["dev"] for dirs in shared.values() for d in dirs.values()}
        cfg = {"listen": listen, "port": config.SNI_PROXY_PORT, "clients": net, "stats": SNI_STATS,
               "lists": files, "cidrs": cidrs, "rates": rates, "shared": shared,
               "client_policy": {ip: n for ip, n in client_map.items() if n in marks},
               "policies": {n: {"mark": m, "rules": [{"lists": l, "to": self._sni_target(st, o)}
                                                     for l, o in policies[n]["domain"]],
                                "acct": acct(policies[n])}
                            for n, m in marks.items()}}
        mt = {lid: os.path.getmtime(p) if os.path.exists(p) else 0 for lid, p in {**files, **cidrs}.items()}
        h = _sha(json.dumps([cfg, mt], sort_keys=True))
        key = f"{t.key}|{listen}|{config.SNI_PROXY_PORT}"
        d = self.sni
        if d and (d.key != key or d.proc.poll() is not None or self._sni_hung()):
            if d.key == key:
                self.event("warn", Msg("ev.sni_died"))
            self._stop_sni()
            d = None
        if d is None or d.cfg_hash != h:
            fd = os.open(SNI_CONF + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # пароли прокси
            with os.fdopen(fd, "w") as f:
                json.dump(cfg, f)
            os.replace(SNI_CONF + ".tmp", SNI_CONF)
        if d is None:
            if time.time() - self._sni_retry < 60:
                return None
            self._sni_retry = time.time()
            logp = os.path.join(LOG_DIR, "sniproxy.log")
            with open(logp, "a") as logf:
                proc = subprocess.Popen(["nsenter", "-t", str(t.pid), "-n", "--", "python3", SNIPROXY, SNI_CONF],
                                        stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
            time.sleep(0.5)
            if proc.poll() is not None:
                try:
                    with open(logp) as f:
                        tail = f.read()[-300:].strip()
                except OSError:
                    tail = ""
                self.sni_state = {"state": "error", "listen": listen, "error": Msg("sni.start_failed", detail=tail)}
                self.event("error", Msg("ev.sni_failed", detail=tail))
                return None
            self.sni = HelperRT(proc, key, h)
            self._input_rule(t, "add")
        elif d.cfg_hash != h:
            d.proc.send_signal(signal.SIGHUP)       # перечитать настройки и списки
            d.cfg_hash = h
        self.sni_state = {"state": "on", "listen": listen}
        return config.SNI_PROXY_PORT

    # ------------------------------------------------------ DNS для клиентов
    def dns_routes(self, st: dict) -> tuple[dict | None, dict]:
        """Путь запросов DNS: основной выход политики клиента (с резервированием, как у его
        трафика). → (путь по умолчанию, {IP клиента: путь}) — только отличающиеся от общего.
        Путь — {"mark", "tcp"} (метка выхода; через SOCKS5 — по TCP) или None — блок. Выход,
        которого сейчас нет среди запущенных, — тоже блок: метка без правила ip rule ушла бы
        напрямую."""
        gp, cps = self._policies(st)
        running = {r.num for r in self.rt.values()}
        kinds = {}
        for u in st["upstreams"]:
            try:
                kinds[u["num"]] = self.parsed(u).kind
            except Exception:  # noqa: BLE001
                pass

        def route(eff):
            if eff == "direct":
                return {"mark": 0, "tcp": False}
            if isinstance(eff, int) and (eff in running or config.DRY_RUN):
                return {"mark": nftgen.mark_for(eff), "tcp": kinds.get(eff) == "socks5"}
            return None
        default = route(gp["default"])
        routes = {}
        for ip, pol in cps.items():
            r = route(pol["default"])
            if r != default:
                routes[ip] = r
        return default, routes

    def _stop_dns(self) -> None:
        d, self.dns = self.dns, None
        if d and d.proc.poll() is None:
            d.proc.terminate()
            try:
                d.proc.wait(5)
            except subprocess.TimeoutExpired:
                d.proc.kill()

    def _dns_hung(self) -> bool:
        """Процесс жив, но цикл событий стоит: счётчики (пишет каждые 15 с) давно не обновлялись."""
        d = self.dns
        if not d or time.time() - d.started < 120:
            return False
        try:
            with open(DNS_STATS) as f:
                s = json.load(f)
        except (OSError, ValueError):
            return False
        return s.get("pid") == d.proc.pid and time.time() - float(s.get("at") or 0) > 120

    def _sync_dns(self, t: system.Target, st: dict) -> None:
        """Держит dnsproxy.py запущенным, пока DNS панели включён в настройках."""
        if not st["settings"].get("panel_dns"):
            if self.dns:
                self._stop_dns()
                self._input_rule(t, "del", [("udp", DNS_PORT), ("tcp", DNS_PORT)])
            self.dns_state = None
            return
        la = self.tunnel_addr(t)
        if not la:
            self._stop_dns()
            self.dns_state = {"state": "error", "error": Msg("dns.no_addr", iface=t.iface)}
            return
        listen, net = la
        if config.DRY_RUN:
            self.dns_state = {"state": "on", "listen": listen, "encrypt": dns_encrypt(st["settings"])}
            return
        default, routes = self.dns_routes(st)
        cfg = {"listen": listen, "port": DNS_PORT, "clients": net, "stats": DNS_STATS,
               "upstreams": client_dns(st["settings"]), "encrypt": dns_encrypt(st["settings"]),
               "default": default, "routes": routes}
        h = _sha(json.dumps(cfg, sort_keys=True))
        key = f"{t.key}|{listen}"
        d = self.dns
        if d and (d.key != key or d.proc.poll() is not None or self._dns_hung()):
            if d.key == key:
                self.event("warn", Msg("ev.dns_died"))
            self._stop_dns()
            d = None
        if d is None or d.cfg_hash != h:
            with open(DNS_CONF + ".tmp", "w") as f:
                json.dump(cfg, f)
            os.replace(DNS_CONF + ".tmp", DNS_CONF)
        if d is None:
            if time.time() - self._dns_retry < 60:
                return
            self._dns_retry = time.time()
            logp = os.path.join(LOG_DIR, "dnsproxy.log")
            with open(logp, "a") as logf:
                proc = subprocess.Popen(["nsenter", "-t", str(t.pid), "-n", "--", "python3", DNSPROXY, DNS_CONF],
                                        stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
            time.sleep(0.5)
            if proc.poll() is not None:
                try:
                    with open(logp) as f:
                        tail = f.read()[-300:].strip()
                except OSError:
                    tail = ""
                self.dns_state = {"state": "error", "listen": listen, "error": Msg("dns.start_failed", detail=tail)}
                self.event("error", Msg("ev.dns_failed", detail=tail))
                return
            self.dns = HelperRT(proc, key, h)
            self._input_rule(t, "add", [("udp", DNS_PORT), ("tcp", DNS_PORT)])
        elif d.cfg_hash != h:
            d.proc.send_signal(signal.SIGHUP)       # перечитать пути и серверы
            d.cfg_hash = h
        self.dns_state = {"state": "on", "listen": listen, "encrypt": cfg["encrypt"]}

    def dns_view(self) -> dict | None:
        """Для интерфейса: состояние и счётчики dnsproxy.py."""
        if not self.dns_state:
            return None
        v = dict(self.dns_state)
        if self.dns and not config.DRY_RUN:
            try:
                with open(DNS_STATS) as f:
                    s = json.load(f)
                if s.get("pid") == self.dns.proc.pid:
                    v.update({k: s.get(k) for k in ("queries", "cached", "errors", "refused", "cache")})
                    # серверы DNS не отвечают: последняя ошибка свежее последнего ответа (за 5 минут)
                    err_at = float(s.get("last_error_at") or 0)
                    if err_at > float(s.get("last_ok") or 0) and time.time() - err_at < 300:
                        v["upstream_error"] = s.get("last_error") or "?"
            except (OSError, ValueError):
                pass
        return v

    def sni_view(self) -> dict | None:
        """Для интерфейса: состояние и счётчики sniproxy.py."""
        if not self.sni_state:
            return None
        v = dict(self.sni_state)
        if self.sni and not config.DRY_RUN:
            try:
                with open(SNI_STATS) as f:
                    s = json.load(f)
                if s.get("pid") == self.sni.proc.pid:
                    v.update({k: s.get(k) for k in ("conns", "active", "matched", "errors", "by_list")})
            except (OSError, ValueError):
                pass
        return v

    # -------------------------------------------------------- ip rule/route
    def _sync_rules(self, t: system.Target) -> None:
        want = {r.num for r in self.rt.values()}
        lo, hi = config.RULE_PRIO_BASE + 1, config.RULE_PRIO_BASE + config.MAX_UPSTREAMS
        p = t.ns(["ip", "-j", "rule", "show"], check=False)
        try:
            have = json.loads(p.stdout or "[]")
        except ValueError:
            have = []
        present = set()
        for rule in have:
            prio = rule.get("priority", 0)
            if not lo <= prio <= hi:
                continue
            num = prio - config.RULE_PRIO_BASE
            ok = num in want and str(rule.get("table")) == str(config.TABLE_BASE + num) and \
                int(str(rule.get("fwmark", "0")), 0) == nftgen.mark_for(num)
            if ok and num not in present:
                present.add(num)
            else:
                t.ns(["ip", "rule", "del", "priority", str(prio)], check=False)
                if num not in want:
                    t.ns(["ip", "route", "flush", "table", str(config.TABLE_BASE + num)], check=False)
        for num in want:
            table = str(config.TABLE_BASE + num)
            if num not in present:
                t.ns(["ip", "rule", "add", "fwmark", hex(nftgen.mark_for(num)), "lookup", table,
                      "priority", str(config.RULE_PRIO_BASE + num)])
            # Если туннель исчезнет, останется unreachable — трафик не утечёт мимо
            t.ns(["ip", "route", "replace", "unreachable", "default", "metric", "4096",
                  "table", table], check=False)
            t.ns(["ip", "route", "replace", "default", "dev", f"{config.IFACE_PREFIX}{num}",
                  "table", table], check=False)

    def _sysctl(self, t: system.Target) -> None:
        for kv in ("net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=2",
                   "net.ipv4.conf.default.rp_filter=2", "net.ipv4.conf.all.src_valid_mark=1"):
            t.ns(["sysctl", "-qw", kv], check=False)

    # ------------------------------------------------------------ reconcile
    def _watch_server(self, t: system.Target) -> bool:
        """Интерфейса сервера нет, а цель на месте — например, ядро завершило amneziawg-go при нехватке памяти:
        контейнер работает дальше без awg0, служба на хосте числится запущенной, клиенты отваливаются.
        Поднимаем перезапуском (контейнер — docker restart, хост — служба awg-quick). Контейнер — не сразу
        (SERVER_GRACE: при смене порта и S1–S4 интерфейс пропадает ненадолго), дальше с растущими паузами."""
        if config.DRY_RUN:
            return False
        now = time.time()
        if t.is_up():
            self._srv_down, self._srv_tries, self._srv_next = None, 0, 0.0
            return False
        if self._srv_down is None:
            self._srv_down = now
        grace = SERVER_GRACE if t.kind == "container" else 0
        if now - self._srv_down < grace or now < self._srv_next:
            return False
        self._srv_tries += 1
        self._srv_next = now + SERVER_PAUSES[min(self._srv_tries, len(SERVER_PAUSES)) - 1]
        self.event("warn", Msg("ev.server_iface_gone", iface=t.iface))
        if self._srv_tries > KERNEL_GIVE_UP and self.module_info()["loaded"] and not kernelmod.load().get("disabled"):
            self._drop_module()
        try:
            if t.kind == "host":
                t.native(["systemctl", "enable", f"awg-quick@{t.iface}"], check=False, timeout=30)
            t.restart()
        except Exception as e:  # noqa: BLE001
            self.event("error", Msg("ev.server_start_failed", error=msg_of(e)))
        # True: цель перезапущена — у контейнера новый PID, и этот проход работал бы со старым. Следующий —
        # сразу, а не через RECONCILE_INTERVAL: в новой сети контейнера ещё нет наших правил (_hold_rules)
        self.wake.set()
        return True

    def _drop_module(self) -> None:
        """Сервер не поднимается на модуле ядра уже KERNEL_GIVE_UP перезапусков: модуль загружен — awg-quick
        берёт его и не переходит на amneziawg-go сам, клиенты так и остались бы без связи. Панель запрещает и
        выгружает модуль (kernelmod.block), и следующий перезапуск поднимает сервер на amneziawg-go; выходы
        идут следом. Снова — кнопкой «Попробовать снова» (install.sh --install-kernel снимает запрет)."""
        self._stop_all()                       # туннели выходов на модуле держат его
        try:
            err = kernelmod.block()
        except OSError as e:
            err = str(e)[:200]
        kernelmod.update(disabled={"at": time.time(), "error": err}, seen=None, lost=None)
        self.kernel_fallback = None
        if err:
            log.warning("kernel module is blocked but still loaded: %s", err)
            self.event("error", Msg("ev.kernel_disabled_reboot", n=self._srv_tries - 1))
        else:
            self.event("error", Msg("ev.kernel_disabled", n=self._srv_tries - 1))

    def switch_engine(self, choice: str) -> dict:
        """Ручной выбор движка в панели — один на весь сервер (выходы идут следом). → {"action": …}.

        go: модуль загружен — сервер останавливается, модуль запрещается и выгружается (kernelmod.block: иначе
        awg-quick снова взял бы его), сервер запускается на amneziawg-go. Модуль остаётся установленным.
        kernel: модуль уже загружен — перезапуск сервера (он сам возьмёт модуль); нет — установка
        (`install.sh --install-kernel`: снимает запрет и, если пакет уже стоит, просто загружает модуль)."""
        if choice == "go":
            with self.lock:
                t = self.target
                if not t or not t.exists:
                    raise system.SysError(Msg("srv.no_server"))
                err = None
                if self.module_info()["loaded"]:
                    self._stop_all()                       # туннели выходов на модуле держат его
                    t.stop()
                    try:
                        err = None if config.DRY_RUN else kernelmod.block()
                    except OSError as e:
                        err = str(e)[:200]
                    finally:
                        t.start()
                kernelmod.update(choice="go", seen=None, lost=None, disabled=None)
                self.kernel_fallback = None
                self._srv_down, self._srv_tries, self._srv_next = None, 0, 0.0
                self.server_engine = None                  # перечитать после запуска
                self.event("info", Msg("ev.engine_go_reboot" if err else "ev.engine_go"))
            self.reconcile_soon()
            return {"action": "restarted", "reboot": bool(err)}
        if choice != "kernel":
            raise ValueError(choice)
        kernelmod.update(choice=None)
        m = self.module_info()
        if m["loaded"] and m["ok"]:
            self.restart_server()
            return {"action": "restarted"}
        kernelmod.start()
        return {"action": "install"}

    def _watch_module(self) -> None:
        """Модуль, на котором работал сервер, пропал (после обновления ядра не собрался или не загрузился):
        awg-quick сам поднял сервер на amneziawg-go, но об этом надо сказать — событие и Telegram, а в панели
        оповещение с кнопкой «Установить модуль». Версия модуля, на котором работал сервер, — в engine.json
        (`seen`): после перезагрузки сервера память панели пуста. Модуль снова загружен — отметки сняты."""
        if config.DRY_RUN:
            return
        m = self.module_info()
        ks = kernelmod.load()
        if m["loaded"]:
            patch = {}
            if m["ok"] and ks.get("disabled"):
                patch["disabled"] = None       # модуль поставили снова («Попробовать снова»)
            if ks.get("lost"):
                patch["lost"] = None
            seen = m["version"] or "?"
            if m["ok"] and self.server_engine == "kernel" and ks.get("seen") != seen:
                patch["seen"] = seen
                self.event("info", Msg("ev.kernel_on", version=seen))     # сервер перешёл на модуль (или новую версию)
            if patch:
                kernelmod.update(**patch)
            return
        if ks.get("seen") and self.server_engine == "go":
            kernelmod.update(seen=None, lost=time.time())
            self.event("warn", Msg("ev.kernel_gone", version=ks["seen"]))

    def _hold_rules(self, t: system.Target, st: dict) -> None:
        """Новая цель (контейнер перезапустился, панель запустилась): в её сети ещё нет наших правил, и до
        конца прохода — а в нём запуск всех туннелей — клиенты шли бы напрямую, даже с резервом «Блокировать».
        Поэтому правила ставятся до запуска туннелей: выход, туннеля которого ещё нет, `nftgen.layout` ведёт в
        блок. `applied_hash` не меняется: обычное применение в конце прохода заменит эти правила настоящими."""
        if config.DRY_RUN:
            return
        try:
            path = os.path.join(RUN_DIR, "ruleset.nft")
            with open(path, "w") as f:
                f.write(self.build_ruleset(t, st, None))
            t.ns(["nft", "-f", path], timeout=60)
        except Exception as e:  # noqa: BLE001  — обычное применение в конце прохода скажет об ошибке само
            log.warning("rules before tunnels: %s", e)

    def restart_server(self) -> None:
        """Кнопка «Перезапустить сервер AWG». Дальше всё применит reconcile: у контейнера сменится Target.key."""
        with self.lock:
            t = self.target
            if not t or not t.exists:
                raise system.SysError(Msg("srv.no_server"))
            if t.kind == "host" and not config.DRY_RUN:
                t.native(["systemctl", "enable", f"awg-quick@{t.iface}"], check=False, timeout=30)
            t.restart()
            self._srv_down, self._srv_tries, self._srv_next = None, 0, 0.0
            self.kernel_fallback = None     # на хосте Target.key не меняется: модуль пробуем снова здесь
        self.reconcile_soon()

    def _watch_resources(self) -> None:
        """Память или процессор сервера держатся выше порога RES_ALERT_SECS — одно событие (и уведомление
        «Ресурсы сервера»), вернулись ниже MEM_OK / CPU_OK — второе. Нехватка памяти — частая причина
        падения туннелей: ядро завершает amneziawg-go."""
        if config.DRY_RUN:
            return
        mem = hostnet.memory()
        vals = {"mem": (100 * mem[0] / mem[1]) if mem and mem[1] else None, "cpu": hostnet.cpu.percent()}
        now = time.time()
        for kind, (hi, lo) in (("mem", (MEM_ALERT, MEM_OK)), ("cpu", (CPU_ALERT, CPU_OK))):
            v = vals[kind]
            if v is None:
                continue
            s = self._res.setdefault(kind, {"since": None, "alert": False})
            if v >= hi:
                s["since"] = s["since"] or now
                if not s["alert"] and now - s["since"] >= RES_ALERT_SECS:
                    s["alert"] = True
                    self.event("warn", Msg(f"ev.{kind}_high", pct=round(v), min=RES_ALERT_SECS // 60))
            else:
                s["since"] = None
                if s["alert"] and v < lo:
                    s["alert"] = False
                    self.event("info", Msg(f"ev.{kind}_ok", pct=round(v)))

    def reconcile(self) -> None:
        try:
            self._watch_resources()
        except Exception:  # noqa: BLE001  — тревога по ресурсам не должна мешать применению правил
            log.exception("resources")
        with self.lock:
            st = self.store.snapshot()
            try:
                t = self._fake if config.DRY_RUN else system.discover()
            except Exception as e:  # noqa: BLE001
                if self.target is not None:
                    self.event("error", Msg("ev.target_lost", error=msg_of(e)))
                self.target_error = msg_of(e)
                self._stop_all()
                self.target = None
                self.applied_hash = None
                return
            if isinstance(t, system.HostTarget) and not config.DRY_RUN:
                if not self._runtime_checked and t.exists:
                    try:
                        system.install_host_runtime(t)
                    except Exception as e:  # noqa: BLE001
                        self.event("warn", Msg("ev.runtime_failed", error=msg_of(e)))
                    self._runtime_checked = True
                if not t.exists and config.AWG_INIT_PORT:
                    self.target = t
                    self.srv.init_host(config.AWG_INIT_PORT, config.AWG_INIT_SUBNET)
                    self._runtime_checked = True
            if not t.exists:
                self.target = t
                self.target_error = Msg("sys.host_no_server")
                self.clients = []
                return
            if self._watch_server(t):
                # сервер только что перезапущен: у контейнера новый PID, а интерфейс поднимается не сразу —
                # этот проход не применяет ничего к старой цели, следующий (RECONCILE_INTERVAL) найдёт новую
                self.applied_hash = None
                return
            try:
                self._watch_engine(t)
                self._watch_module()
            except Exception:  # noqa: BLE001
                log.exception("engine check")
            self.target_error = None
            if self.notifier:
                self.notifier.target_ok()
            fresh = self.target is None or self.target.key != t.key or not self.target.exists
            if fresh:
                if self.target is not None and self.target.exists:
                    self.event("warn", Msg("ev.target_restarted"))
                self._stop_all()
                self._stop_sni()
                self._stop_dns()
                self.target = t
                self.applied_hash = None
                self._shape = {}
                self._sysctl(t)

            if self._masking_checked != t.key:
                self._masking_checked = t.key
                try:
                    self.srv.upgrade_masking(t)
                except Exception:  # noqa: BLE001
                    log.exception("masking upgrade")
            try:
                self.clients = self.srv.list_clients(t)
            except Exception as e:  # noqa: BLE001
                self.event("warn", Msg("ev.clients_failed", error=msg_of(e)))
            else:
                try:
                    self.traffic.update(self.clients)
                    limits.enforce(self)
                    limits.first_seen(self)
                except Exception:  # noqa: BLE001
                    log.exception("traffic/limits")
            try:
                self._account(t, st)
                if not config.DRY_RUN:
                    self._sni_account()
                self._exit_quotas(st)
            except Exception:  # noqa: BLE001
                log.exception("exit traffic")
            self.balancer.feed(self.traffic.take_recent(), time.time())

            if fresh:
                self._hold_rules(t, st)
            self._sync_upstreams(t, st)
            self._update_health(t, st)
            try:
                self._balance(st)
            except Exception:  # noqa: BLE001
                log.exception("balance")
                self.bal, self.bal_new, self.bal_nums = {}, None, set()
            try:
                sniff = self._sync_sni(t, st)
            except Exception as e:  # noqa: BLE001
                log.exception("sniproxy")
                self.sni_state = {"state": "error", "error": msg_of(e)}
                sniff = None        # правила по доменам не действуют, по адресам — как обычно
            try:
                self._sync_dns(t, st)
            except Exception as e:  # noqa: BLE001
                log.exception("dnsproxy")
                self.dns_state = {"state": "error", "error": msg_of(e)}

            text = self.build_ruleset(t, st, sniff)
            h = _sha(text)
            present = t.ns(["nft", "list", "chain", "ip", config.NFT_TABLE, "c_prerouting"],
                           check=False).returncode == 0
            if h != self.applied_hash or not present:
                path = os.path.join(RUN_DIR, "ruleset.nft")
                with open(path, "w") as f:
                    f.write(text)
                t.ns(["nft", "-f", path], timeout=60)
                if self.applied_hash and present:
                    self.event("info", Msg("ev.rules_applied"))
                self.applied_hash = h
                self.ruleset = text
                self.last_apply = time.time()
            self._sync_rules(t)
            try:
                self._sync_shaping(t, st)
            except Exception as e:  # noqa: BLE001
                log.exception("shaping")
                self.shape_state = {"state": "error", "error": msg_of(e)}
            self.last_error = None
            self.last_reconcile = time.time()

    def teardown(self) -> None:
        """Полностью убирает следы панели (как будто её не было)."""
        with self.lock:
            t = self.target
            self._stop_all()
            self._stop_sni()
            self._stop_dns()
            if t:
                self._clear_shaping(t)
                t.ns(["nft", "delete", "table", "ip", config.NFT_TABLE], check=False)
                t.ns(["nft", "delete", "table", "ip", nftgen.ACCT_TABLE], check=False)
                self._input_rule(t, "del")
                self._input_rule(t, "del", [("udp", DNS_PORT), ("tcp", DNS_PORT)])
                self._acct_key = None
                p = t.ns(["ip", "-j", "rule", "show"], check=False)
                try:
                    for rule in json.loads(p.stdout or "[]"):
                        prio = rule.get("priority", 0)
                        if config.RULE_PRIO_BASE < prio <= config.RULE_PRIO_BASE + config.MAX_UPSTREAMS:
                            t.ns(["ip", "rule", "del", "priority", str(prio)], check=False)
                            t.ns(["ip", "route", "flush", "table",
                                  str(config.TABLE_BASE + prio - config.RULE_PRIO_BASE)], check=False)
                except ValueError:
                    pass
            self.applied_hash = None

    def shutdown(self) -> None:
        self.stop_ev.set()
        self.wake.set()
        self.traffic.save()
        st = self.store.snapshot()
        if st["settings"].get("on_stop") == "restore":
            self.teardown()
        else:
            with self.lock:
                self._stop_all()
                self._stop_dns()        # клиенты переходят на второй DNS из конфига (сервер из настроек)
                if self.sni:
                    self._stop_sni()
                    t = self.target
                    if t:
                        # без sniproxy.py перенаправление в него оборвало бы HTTPS у клиентов с
                        # правилами по доменам: оставляем только правила по адресам
                        try:
                            p = os.path.join(RUN_DIR, "ruleset.nft")
                            with open(p, "w") as f:
                                f.write(self.build_ruleset(t, st, None))
                            t.ns(["nft", "-f", p], check=False, timeout=60)
                        except Exception:  # noqa: BLE001
                            log.exception("ruleset without sniproxy")

    # ------------------------------------------------ ограничение скорости (tc)
    def shaping_plan(self, t: system.Target, st: dict) -> dict:
        lim = st.get("limits") or {}
        clients = {}
        for c in self.clients:
            if c.get("ip"):
                L = lim.get(c["public_key"]) or {}
                clients[c["ip"]] = {"down": L.get("rate_down"), "up": L.get("rate_up")}
        exits = [{"num": r.num, "iface": r.iface, "down": u.get("rate_down"), "up": u.get("rate_up")}
                 for u in st["upstreams"] if (r := self.rt.get(u["id"])) and r.target_key == t.key]
        return shaping.plan(t.iface, st["settings"].get("shaping") or {}, clients, exits)

    def _ifb_source(self, t: system.Target, ifb: str) -> str | None:
        """ifb → интерфейс, входящий трафик которого он ограничивает (awgq0 → awg0, awgqN → awgrN)."""
        m = re.fullmatch(re.escape(shaping.IFB_PREFIX) + r"(\d+)", ifb)
        if not m:
            return None
        return t.iface if m.group(1) == "0" else f"{config.IFACE_PREFIX}{int(m.group(1))}"

    def _sync_shaping(self, t: system.Target, st: dict) -> None:
        """Держит очереди tc такими, как в настройках ограничения скорости. Ничего не задано — tc
        не вызывается вовсе (кроме одной уборки на цель: остатки прошлого запуска панели)."""
        p = self.shaping_plan(t, st)
        roots, ingress = p["roots"], p["ingress"]
        if not roots and self._shape_key == t.key and not self._shape:
            self.shape_state = None
            return
        if config.DRY_RUN:
            self.shape_state = {"state": "on"} if roots else None
            self._shape = {d: shaping.digest(c) for d, c in roots.items()}
            self._shape_key = t.key
            return
        now = time.time()
        sig = shaping.digest([sorted(roots.items()), sorted(ingress.items()), t.key])
        st_ = self.shape_state or {}
        if st_.get("state") == "error" and st_.get("sig") == sig and now < self._shape_retry:
            return                                   # та же ошибка — не чаще раза в минуту
        q = t.ns(["tc", "-j", "qdisc", "show"], check=False, timeout=20)
        if q.returncode != 0:
            if roots:
                self._shape_failed(sig, Msg("sh.no_tc", detail=(q.stderr or q.stdout or "").strip()[-200:]))
            else:
                self.shape_state, self._shape_key = None, t.key
            return
        ours, ing = shaping.parse_qdiscs(q.stdout)
        links = self._links(t) or set()
        # лишнее: сначала перенаправление, потом сам ifb (пакеты в пропавший ifb отбрасывались бы)
        for l in sorted(links):
            src = self._ifb_source(t, l)
            if not src or ingress.get(src) == l:
                continue
            if src in ing and src not in ingress:
                t.ns(["tc", "qdisc", "del", "dev", src, "ingress"], check=False)
            t.ns(["ip", "link", "del", l], check=False)
            self._shape.pop("ing:" + src, None)
            self._shape.pop(l, None)
        for dev in ours - set(roots):
            t.ns(["tc", "qdisc", "del", "dev", dev, "root"], check=False)
            self._shape.pop(dev, None)
        self._shape_key = t.key
        errors = []
        for src, ifb in ingress.items():
            if ifb not in links:
                r = t.ns(["ip", "link", "add", ifb, "type", "ifb"], check=False)
                if r.returncode != 0:
                    errors.append(Msg("sh.no_ifb", detail=(r.stderr or r.stdout or "").strip()[-200:]))
                    continue
                links.add(ifb)
            t.ns(["ip", "link", "set", ifb, "up"], check=False)
        for dev, cmds in roots.items():
            h = shaping.digest(cmds)
            if dev not in links and dev != t.iface:
                continue                              # ifb не создался — ошибка уже есть
            if dev in ours and self._shape.get(dev) == h:
                continue
            if dev in ours:
                t.ns(["tc", "qdisc", "del", "dev", dev, "root"], check=False)
            err = self._tc_batch(t, dev, cmds)
            if err:
                errors.append(Msg("sh.failed", dev=dev, detail=err))
                self._shape.pop(dev, None)
                t.ns(["tc", "qdisc", "del", "dev", dev, "root"], check=False)   # не оставлять половину
            else:
                self._shape[dev] = h
        for src, ifb in ingress.items():
            if ifb not in links:
                continue
            k = "ing:" + src
            if src in ing and self._shape.get(k) == ifb:
                continue
            if src in ing:
                t.ns(["tc", "qdisc", "del", "dev", src, "ingress"], check=False)
            err = self._tc_batch(t, src + "-in", shaping.redirect(src, ifb))
            if err:
                errors.append(Msg("sh.failed", dev=src, detail=err))
                t.ns(["tc", "qdisc", "del", "dev", src, "ingress"], check=False)
                self._shape.pop(k, None)
            else:
                self._shape[k] = ifb
        self._shape = {k: v for k, v in self._shape.items()
                       if k in roots or (k.startswith("ing:") and k[4:] in ingress)}
        if errors:
            self._shape_failed(sig, errors[0])
        else:
            if st_.get("state") == "error":
                self.event("info", Msg("ev.shaping_ok"))
            self.shape_state = {"state": "on"} if roots else None

    def _shape_failed(self, sig: str, err: Msg) -> None:
        prev = self.shape_state or {}
        if prev.get("state") != "error" or str(prev.get("error")) != str(err):
            self.event("warn", Msg("ev.shaping_failed", error=err))
        self.shape_state = {"state": "error", "error": err, "sig": sig}
        self._shape_retry = time.time() + 60

    def _tc_batch(self, t: system.Target, name: str, cmds: list[str]) -> str | None:
        """Команды через tc -batch. → None или текст ошибки."""
        path = os.path.join(RUN_DIR, f"tc-{name}.batch")
        with open(path, "w") as f:
            f.write("\n".join(cmds) + "\n")
        r = t.ns(["tc", "-batch", path], check=False, timeout=30)
        return None if r.returncode == 0 else (r.stderr or r.stdout or "").strip()[-300:] or "tc"

    def _clear_shaping(self, t: system.Target) -> None:
        """Убирает все наши очереди и ifb (удаление панели, «восстановить при остановке»)."""
        if config.DRY_RUN:
            return
        q = t.ns(["tc", "-j", "qdisc", "show"], check=False, timeout=20)
        if q.returncode != 0:
            return
        ours, ing = shaping.parse_qdiscs(q.stdout)
        for l in sorted(self._links(t) or ()):
            src = self._ifb_source(t, l)
            if src:
                if src in ing:
                    t.ns(["tc", "qdisc", "del", "dev", src, "ingress"], check=False)
                t.ns(["ip", "link", "del", l], check=False)
        for dev in ours:
            t.ns(["tc", "qdisc", "del", "dev", dev, "root"], check=False)
        self._shape, self._shape_key, self.shape_state = {}, None, None

    # ---------------------------------------------------------------- tools
    def own_route(self, out: str) -> tuple[int, int] | None:
        """Путь для собственных запросов панели (Telegram): None — напрямую из панели,
        (PID, fwmark) — через туннель выхода в сети сервера AWG. Выход выбирается так же,
        как для клиентов: не работает — его резервный выход."""
        if out == "direct" or config.DRY_RUN:
            return None
        name = (Store.upstream(self.store.snapshot(), out[3:]) or {}).get("name", out) \
            if out.startswith("up:") else out
        eff = self.resolve(out, self.store.snapshot())
        if eff == "direct":
            return None
        if eff == "block":
            raise system.SysError(Msg("tg.via_blocked", name=name))
        t = self.target
        if not t or eff not in {r.num for r in self.rt.values()}:
            raise system.SysError(Msg("tg.via_down", name=name))
        return t.pid, nftgen.mark_for(eff)

    def alt_routes(self, via: str) -> list[str]:
        """Другие пути к Telegram, когда выбранный не работает: выходы, которые сейчас работают
        (кроме выбранного), в порядке списка выходов. «Напрямую» добавляет вызывающий."""
        return [f"up:{u['id']}" for u in self.store.snapshot()["upstreams"]
                if f"up:{u['id']}" != via and u.get("enabled", True)
                and (self.health.get(u["id"]) or {}).get("healthy")]

    def probe(self, out: str) -> dict:
        """Проверка выхода: внешний IP, страна, задержка."""
        t = self.target
        if not t:
            raise system.SysError(self.target_error if isinstance(self.target_error, Msg)
                                  else Msg("sys.no_container"))
        st = self.store.snapshot()
        eff = self.resolve(out, st)
        if eff == "block":
            return {"ok": False, "error": Msg("probe.blocked")}
        mark = 0 if eff == "direct" else nftgen.mark_for(eff)
        if config.DRY_RUN:
            return {"ok": True, "ip": "203.0.113.%d" % (10 + (eff if eff != "direct" else 0)),
                    "cc": "NL" if eff != "direct" else "RU", "latency_ms": 42, "via": eff}
        # имена разбираем в сети панели — в сети контейнера может не быть DNS
        hosts = [f"{h}={ip}" for h, ip in awgconf.resolve_many(PROBE_HOSTS, 4).items()]
        p = t.ns(["python3", PROBE, str(mark), *hosts], check=False, timeout=25)
        try:
            res = json.loads(p.stdout)
        except ValueError:
            res = {"ok": False, "err": "no_answer", "detail": (p.stderr or p.stdout).strip()[:300]}
        if res.get("err"):
            res["error"] = Msg("probe." + res.pop("err"), detail=res.pop("detail", ""))
        if res.get("warn"):
            res["warn"] = Msg("probe." + res["warn"], detail=res.pop("detail", ""))
        res["via"] = eff
        return res

    def trace(self, pk: str | None, ip: str, name: str | None = None) -> dict:
        """Куда пойдёт трафик клиента до ip. name — домен, по которому его нашли: правила со
        списками доменов (HTTPS/HTTP) проверяются по нему первыми — так же, как в sniproxy.py."""
        st = self.store.snapshot()
        dl = self.domain_lists(st)
        sni_on = bool(self.sni_state and self.sni_state.get("state") == "on")
        steps = []
        for net in nftgen.LOCAL_NETS:
            if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(net):
                return {"result": "direct", "effective": "direct",
                        "steps": [Msg("tr.local", ip=ip, net=net)]}
        pol = self.policy_for(st, pk)
        steps.append(Msg("tr.client_rules" if pk and st["clients"].get(pk, {}).get("rules_mode")
                         == "custom" else "tr.global_rules"))
        for r in pol["rules"] if name and sni_on else []:
            for lid in r["lists"]:
                dom = self.domain_matcher.match(lid, name) if lid in dl else None
                if dom:
                    steps.append(Msg("tr.match_domain", list=lid, domain=dom))
                    eff = self.resolve(r["outbound"], st)
                    return {"result": r["outbound"], "effective": eff, "steps": steps,
                            "rule": r.get("comment") or r["id"], "domain": dom}
        for r in pol["rules"]:
            for lid in r["lists"]:
                if lid in dl:
                    continue
                hit = self.matcher.contains(lid, ip)
                if hit:
                    steps.append(Msg("tr.match", list=lid, net=hit))
                    eff = self.resolve(r["outbound"], st)
                    return {"result": r["outbound"], "effective": eff, "steps": steps,
                            "rule": r.get("comment") or r["id"]}
        out = self.default_out(st, pk, pol)
        if out != pol["default"]:
            steps.append(Msg("tr.balance" if pk else "tr.balance_new",
                             exit=(Store.upstream(st, out[3:]) or {}).get("name", out)))
        else:
            steps.append(Msg("tr.default_client" if pk and st["clients"].get(pk, {}).get(
                "outbound", "inherit") != "inherit" else "tr.balance_down" if pol.get("balanced")
                else "tr.default"))
        return {"result": out, "effective": self.resolve(out, st), "steps": steps}
