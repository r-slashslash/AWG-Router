"""Движок: приводит сетевое пространство контейнера Amnezia к желаемому состоянию.

Каждые RECONCILE_INTERVAL секунд (и сразу после изменений в панели):
  * находит контейнер Amnezia (если он перезапустился — всё создаётся заново);
  * поднимает/гасит туннели awgrN к выходным серверам (AWG или прокси SOCKS5);
  * держит sniproxy.py для правил по доменам;
  * проверяет «живость» туннелей по рукопожатиям и переключает на резерв;
  * генерирует и атомарно применяет nftables, синхронизирует ip rule / маршруты.

Части класса Engine — по темам, в соседних модулях: tunnels (выходы), routes (маршрутизация и nftables), sni
(правила по доменам), dns (DNS на сервере), server (сервер AWG и модуль ядра), speed (ограничения скорости), diag
(проверки по запросу); общее — common. Здесь — сам проход (reconcile), циклы, события и остановка.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import signal
import threading
import time

from .. import awgconf, balance, config, domains, hostnet, limits, lists, nftgen, system
from ..i18n import Msg, msg_of
from ..store import TEXT_KINDS, Store
from ..traffic import Traffic
from ..users import ServerManager
from .common import DNS_PORT, LOG_DIR, RUN_DIR, HelperRT, UpRT, _sha, log
from .diag import DiagMixin
from .dns import DnsMixin
from .routes import RoutesMixin
from .server import ServerMixin
from .sni import SniMixin
from .speed import SpeedMixin
from .tunnels import TunnelsMixin

HOST_FAST_TRIES, HOST_FAST_WAIT = 30, 20     # внешний IPv4: сначала 30 попыток раз в 20 секунд,
HOST_SLOW_WAIT = 600                        # потом раз в 10 минут, пока не найдётся;
HOST_RECHECK = 6 * 3600                     # найденный перепроверяем раз в 6 часов
SERVER_DOWN_AFTER = 600  # с: дольше сервер AWG не поднимается — в шапке уже не «Перезапуск…», а ошибка
MEM_ALERT, MEM_OK = 90, 85   # % занятой памяти: выше — тревога, ниже — снова норма
CPU_ALERT, CPU_OK = 95, 80   # % загрузки процессора
RES_ALERT_SECS = 300     # с: столько значение должно держаться выше порога, чтобы стать тревогой


class Engine(TunnelsMixin, RoutesMixin, SniMixin, DnsMixin, ServerMixin, SpeedMixin, DiagMixin):
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
        self._hold_key: tuple | None = None      # с чем записан файл правил «до панели» (_save_hold)
        self._hold_ok: dict[str, bool] = {}      # контейнер сервера сам ставит эти правила при запуске
        self._sniff_slots: dict[tuple, int] = {}  # номера меток sniproxy.py у политик (nftgen.sniff_marks)
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
        self.lists_busy: set[str] = set()          # списки, которые сейчас скачиваются по кнопке (refresh_lists_bg)
        self._parsed: dict[str, awgconf.UpstreamConf] = {}
        self._fake = system.DemoTarget() if config.DRY_RUN else None
        self.public_v4: str | None = None      # внешний IPv4, найденный проверкой «напрямую»
        self.public_v4_state = "pending"        # pending — ещё ищем, ok — найден, failed — не нашли
        self.srv = ServerManager(self)
        self._runtime_checked = False
        self._masking_checked = None     # Target.key, на котором уже проверен старый I1
        self._srv_down: float | None = None   # с какого момента нет интерфейса сервера (_watch_server)
        self.server_restart_at: float | None = None   # перезапуск сервера (кнопка, автоперезапуск): до его интерфейса
        self._quic_nft: bool | None = None       # ядро принимает очередь QUIC (None — ещё не пробовали)
        self._quic_key = None                    # для какой цели это известно
        self.switching = False                         # идёт ручная смена движка (switch_engine)
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
        self.strict_on = False                  # действует блок «правила по доменам не работают»
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
        threading.Thread(target=self._watch_sni, name="sni-watch", daemon=True).start()
        if not config.DRY_RUN and os.path.exists(config.DOCKER_SOCK):
            threading.Thread(target=self._docker_events, name="docker-events", daemon=True).start()

    def _docker_events(self) -> None:
        """Контейнер сервера AWG запустился (перезапуск Docker, сбой, кто-то сделал docker restart) — проход
        сразу, а не через RECONCILE_INTERVAL: в новой сети контейнера правил панели нет, и до прохода клиенты
        шли бы мимо выходов напрямую. Первые правила этот проход ставит до запуска туннелей (_hold_rules)."""
        def on_start(name: str) -> None:
            t = self.target
            if (t is not None and t.kind == "container" and name == t.name) or name.startswith("amnezia-awg"):
                self.wake.set()
        pause = 5
        while not self.stop_ev.is_set():
            t0 = time.time()
            try:
                system.docker_events(on_start)
            except Exception as e:  # noqa: BLE001  — Docker перезапускается; без событий всё работает по-старому
                log.debug("docker events: %s", e)
            pause = 5 if time.time() - t0 > 60 else min(pause * 2, 300)
            self.stop_ev.wait(pause)

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
                    # только IPv4: адрес идёт во «Внешний адрес сервера» и в конфиги клиентов
                    ip = str(ipaddress.IPv4Address(str(ip).strip())) if ip else None
                except Exception:  # noqa: BLE001  — в том числе не адрес (ValueError)
                    ip = None
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
                # файл списка доменов — свой (domains.path_for): с файлом списка сетей его не было никогда, и
                # списки доменов по ссылкам скачивались заново на каждом круге (раз в 5 минут), а не раз в сутки
                path = domains.path_for(l["id"]) if l["kind"] == "domains" else lists.path_for(l["id"])
                if age < period and os.path.exists(path):
                    continue
                if l.get("error") and since_check < 900:
                    continue
            if l["kind"] in TEXT_KINDS:          # текст ручного списка — в своём файле (Store.list_text)
                l = {**l, "source": self.store.list_text(l["id"])}
            res = lists.refresh(l)
            if res.get("error"):
                self.event("warn", Msg("ev.list_failed", list=l["id"],
                                       error=Msg(res["error"]["$t"], **res["error"]["p"])))
            if res.get("updated"):          # файл записан (и тогда, когда одна из ссылок не скачалась)
                changed = True

            def upd(s, lid=l["id"], res=res):
                x = Store.lst(s, lid)
                if x:
                    x.update(res)
            self.store.mutate(upd)
        if changed:
            self.trigger()

    def refresh_lists_bg(self, ids: list[str]) -> None:
        """Скачать списки в фоне (сохранение и кнопка «Обновить» в панели): запрос не ждёт скачивания,
        которое может идти минуты. Пока идёт, список в /api/state помечен busy."""
        ids = [i for i in ids if i not in self.lists_busy]
        if not ids:
            return
        self.lists_busy.update(ids)

        def run():
            try:
                self.refresh_lists(False, ids)
            except Exception:  # noqa: BLE001
                log.exception("lists")
            finally:
                self.lists_busy.difference_update(ids)
        threading.Thread(target=run, name="lists-now", daemon=True).start()

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

    def phase(self) -> str | None:
        """Что панель сейчас делает — для шапки (в браузере): engine — ручная смена движка; server_restart —
        сервер AWG перезапускается (кнопка, автоперезапуск, интерфейс пропал и панель его ждёт); server_down —
        не поднимается дольше SERVER_DOWN_AFTER; starting — панель запущена, а первый проход ещё не применил
        правила, туннели и sniproxy (если проход упал — это уже ошибка, last_error); None — ничего."""
        now = time.time()
        if self.switching:
            return "engine"
        since = self._srv_down if self._srv_down is not None else self.server_restart_at
        if since is not None:
            return "server_restart" if now - since < SERVER_DOWN_AFTER else "server_down"
        if self.last_reconcile is None and self.last_error is None:
            return "starting"
        return None

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
            elif t.kind == "host" and not config.DRY_RUN:
                # интерфейс сервера на хосте пересоздаётся при перезапуске службы — с настройкой по умолчанию
                t.ns(["sysctl", "-qw", f"net.ipv4.conf.{t.iface}.rp_filter=2"], check=False)

            if self._masking_checked != t.key:
                self._masking_checked = t.key
                try:
                    self.srv.upgrade_masking(t)
                except Exception:  # noqa: BLE001
                    log.exception("masking upgrade")
            listed = False
            try:
                self.clients = self.srv.list_clients(t)
                listed = True
            except Exception as e:  # noqa: BLE001
                self.event("warn", Msg("ev.clients_failed", error=msg_of(e)))
            if fresh:
                # в новой сети сервера правил панели нет: ставим их сразу, как только известны клиенты
                # (их личные правила), — до учёта трафика, лимитов и запуска туннелей. Сервер в контейнере
                # приложения AmneziaVPN сам их не ставит, и всё это время клиенты шли бы мимо выходов
                self._hold_rules(t, st)
            if listed:
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

            self._sync_upstreams(t, st)
            # ip rule запущенных выходов — сразу, до DNS на сервере и правил nftables с их метками
            self._sync_rules(t, add_only=True)
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

            if self._quic_key != t.key:              # другое ядро (новая цель) — проверить заново
                self._quic_key, self._quic_nft = t.key, None
            quic = self.quic_wanted(sniff)
            strict = self.strict_blocked(st, sniff)
            if strict != self.strict_on:
                self.strict_on = strict
                self.event("warn" if strict else "info", Msg("ev.dom_strict_on" if strict else "ev.dom_strict_off"))
            text = self.build_ruleset(t, st, sniff, quic)
            h = _sha(text)
            present = t.ns(["nft", "list", "chain", "ip", config.NFT_TABLE, "c_prerouting"],
                           check=False).returncode == 0
            if h != self.applied_hash or not present:
                path = os.path.join(RUN_DIR, "ruleset.nft")
                with open(path, "w") as f:
                    f.write(text)
                try:
                    t.ns(["nft", "-f", path], timeout=60)
                except system.SysError as e:
                    if not quic or "queue" not in str(e):
                        raise
                    # ядро без nft_queue (OpenVZ/LXC, урезанные сборки): QUIC у этих клиентов — блок, как раньше
                    self._quic_nft = False
                    self.event("warn", Msg("ev.quic_no_queue"))
                    text = self.build_ruleset(t, st, sniff, False)
                    h = _sha(text)
                    with open(path, "w") as f:
                        f.write(text)
                    t.ns(["nft", "-f", path], timeout=60)
                if quic and self._quic_nft is None:
                    self._quic_nft = True
                if self.applied_hash and present:
                    self.event("info", Msg("ev.rules_applied"))
                self.applied_hash = h
                self.ruleset = text
                self.last_apply = time.time()
                # таблица пересоздана — набор адресов фильтра по DNS пуст: пусть DNS вернёт живые
                if self.dom_filter_on(st) and self.dns and self.dns.proc.poll() is None:
                    try:
                        self.dns.proc.send_signal(signal.SIGUSR1)
                    except OSError:
                        pass
            self._save_hold(t, st)
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
                self._drop_hold(t)
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
                        # правилами по доменам: оставляем только правила по адресам (с галочкой
                        # routing.strict у этих клиентов — блок до запуска панели)
                        try:
                            p = os.path.join(RUN_DIR, "ruleset.nft")
                            with open(p, "w") as f:
                                f.write(self.build_ruleset(t, st, None))
                            t.ns(["nft", "-f", p], check=False, timeout=60)
                        except Exception:  # noqa: BLE001
                            log.exception("ruleset without sniproxy")
