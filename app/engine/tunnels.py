"""Туннели к выходам (AmneziaWG — awgrN, SOCKS5 — hev-socks5-tunnel): запуск и остановка, движок
выходов (модуль ядра или amneziawg-go), их живость по рукопожатиям, повторный разбор имён, счётчики трафика и квоты."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import threading
import time

from .. import awgconf, config, cps, limits, nftgen, socks, system
from ..i18n import Msg, msg_of
from ..store import Store
from ..traffic import month_key
from .common import KERNEL_MIN, LOG_DIR, RUN_DIR, UpRT, _sha, log, server_ifaces

SOCK_DIR = "/var/run/amneziawg"
RERESOLVE_AFTER = 30     # туннель с именем в Endpoint не отвечает столько секунд после запуска — разбираем заново
RERESOLVE_EVERY = 60     # и потом не чаще, чем раз в столько секунд
UP_PAUSES = (10, 30, 60, 120, 300)      # пауза перед новой попыткой запустить выход, с
# параметры AWG 3.1: модуль ядра старше KERNEL_MIN их не принимает, и сервер не поднимается
AWG31_KEYS = re.compile(r"^\s*(HeaderProtectionKey|ContentPaddingAddition|RandomTrailers|DisableCookies)\s*=",
                        re.M | re.I)
SERVER_ENGINE_EVERY = 60     # с: как часто заново смотреть, чем работает интерфейс сервера
FLAP_SECS = 60                          # туннель упал раньше — считаем неудачным запуском
CONNECTING_SECS = 30     # с после запуска выхода без ответа: «подключается» — его клиенты в блоке, а не на резерве
HANDSHAKE_POLL = 0.5     # с: как часто смотреть, ответил ли только что запущенный выход AWG
CLIENT_SPEED_EVERY = 2.5  # с: скорость клиентов в списке — не чаще одного замера счётчиков сервера за столько секунд
CLIENT_SPEED_GAP = 30    # с: прошлый замер старше (панель никто не смотрел) — скорость считается заново
CLIENT_SPEED_WAIT = 1.0  # с: столько ответ опроса ждёт замер; дольше (сервер завис) — прежняя скорость, замер идёт дальше
CLIENT_SPEED_PAUSE = 10  # с: замер не удался (сервер перезапускается, `awg show` не отвечает) — следующий не раньше
_speed_lock = threading.Lock()


class TunnelsMixin:
    """Туннели выходов: запуск, остановка, живость, трафик и квоты (часть Engine)."""
    # ------------------------------------------------------------ скорость клиентов
    def client_speeds(self) -> dict[str, list[int]]:
        """Скорость клиентов сейчас для списка клиентов (1.23.0): {ключ: [к клиенту, от клиента]}, байт/с — по
        счётчикам сервера (`awg show dump`) между двумя замерами. Замер — по запросу браузера, не чаще
        CLIENT_SPEED_EVERY: панель никто не смотрит — сервер не опрашивается. Без движения — клиента нет в ответе.
        Замер идёт в своём потоке, и опрос ждёт его не дольше CLIENT_SPEED_WAIT: `awg show` завис (сбой
        amneziawg-go, модуля) — панель не кажется отключённой, а остальные опросы берут прежний ответ сразу
        (проверка 1.23.0)."""
        now = time.time()
        with _speed_lock:
            s = self.__dict__.setdefault("_cspeed", {"at": 0.0, "prev": None, "rates": {}, "busy": False})
            if s["busy"] or now - s["at"] < CLIENT_SPEED_EVERY:
                return s["rates"]
            t = self.target
            if t is None or not t.exists:
                s["rates"] = {}
                return s["rates"]
            s["at"], s["busy"] = now, True
        th = threading.Thread(target=self._speed_sample, args=(s, t, now), name="client-speed", daemon=True)
        th.start()
        th.join(CLIENT_SPEED_WAIT)
        return s["rates"]

    def _server_dump(self, t: system.Target) -> dict:
        """Сводка пиров по всем активным интерфейсам сервера (awg0 и, если включён, wg0)."""
        live = dict(t.dump())
        for ifn in server_ifaces(t)[1:]:
            try:
                live.update(t.dump_iface(ifn))
            except Exception as e:  # noqa: BLE001
                log.warning("%s", e)
        return live

    def _speed_sample(self, s: dict, t, now: float) -> None:
        try:
            live = self._server_dump(t)
        except Exception:  # noqa: BLE001  — сервер перезапускается или не отвечает: скорость подождёт
            live = None
        with _speed_lock:
            s["busy"] = False
            if live is None:
                s["at"] = time.time() + CLIENT_SPEED_PAUSE - CLIENT_SPEED_EVERY
                return
            cur = {pk: (p["rx"], p["tx"]) for pk, p in live.items()}
            prev, s["prev"] = s["prev"], (now, t.key, cur)
            rates: dict[str, list[int]] = {}
            if prev and prev[1] == t.key and 0 < now - prev[0] <= CLIENT_SPEED_GAP:
                dt = now - prev[0]
                for pk, (rx, tx) in cur.items():
                    o = prev[2].get(pk)
                    if o and rx >= o[0] and tx >= o[1] and (rx > o[0] or tx > o[1]):
                        rates[pk] = [round((tx - o[1]) / dt), round((rx - o[0]) / dt)]
            s["rates"] = rates

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
            if kernel_err is not None:                  # amneziawg-go принял то, что не принял модуль
                self._kernel_failed(ifn, kernel_err, conf=True, cause=cps.kernel_problem(pc.params))
        else:
            self.rt[uid] = r
        # Служебный link-local адрес: без IPv4-адреса ядро при включённом rp_filter
        # отбрасывает входящие пакеты на интерфейсе. Настоящий адрес туннеля (часто
        # из той же подсети 10.8.1.0/24, что и наши клиенты) подставляется через SNAT.
        t.ns(["ip", "addr", "replace", f"169.254.200.{u['num']}/32", "dev", ifn])
        t.ns(["ip", "link", "set", ifn, "mtu", str(pc.mtu), "up"])
        t.ns(["sysctl", "-qw", f"net.ipv4.conf.{ifn}.rp_filter=2"], check=False)
        self.event("info", Msg("ev.tunnel_up", iface=ifn, name=u["name"], endpoint=pc.endpoint))

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
            # имя прокси SOCKS5 тоже: socks.resolve в _start_socks иначе разбирал бы его отдельно
            host = pc.socks["host"] if pc.kind == "socks5" else awgconf.split_endpoint(pc.endpoint)[0]
            try:
                ipaddress.ip_address(host)
            except ValueError:
                hosts.add(host)
        if len(hosts) > 1:
            self._pre = awgconf.resolve_many(sorted(hosts), awgconf.RESOLVE_TIMEOUT)
            self._pre_failed = hosts - set(self._pre)

    def _kernel_failed(self, ifn: str, err, conf: bool = False, cause: Msg | None = None) -> None:
        """conf — модуль создал интерфейс, но не принял конфиг выхода (amneziawg-go его принял): в тексте
        только причина («Invalid argument»), без команды — иначе человек ищет файл конфига, которого нет.
        cause — что именно в I1–I5 модуль не примет (cps.kernel_problem): тогда оно и показывается."""
        if conf and isinstance(err, str):
            err = err.split(": ", 1)[-1]
        self.kernel_fallback = {"error": cause or err, "at": time.time(), "iface": ifn, "conf": conf}
        if cause is not None:
            self.event("warn", Msg("ev.kernel_conf_i", iface=ifn, error=err, cause=cause))
        else:
            self.event("warn", Msg("ev.kernel_conf" if conf else "ev.kernel_fallback", iface=ifn, error=err))

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
        host = pc.socks["host"]
        if host in getattr(self, "_pre_failed", ()):   # уже ждали его в _prefetch_hosts
            raise system.SysError(Msg("socks.resolve", host=host))
        try:
            ip = getattr(self, "_pre", {}).get(host) or socks.resolve(host)
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
            # hev молчит о части ошибок запуска (все — код 254): хотя бы код, чтобы было с чем разбираться
            if not tail and r.proc.returncode is not None:
                tail = f"exit code {r.proc.returncode}"
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
        self._waiting = set()                       # выходы AWG, которые этот проход не запустил, ожидая сервер
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
                    self._waiting.add(uid)
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

    def _pass_dumps(self, t: system.Target, st: dict) -> tuple[dict | None, dict | None]:
        """Состояние всех туннелей за проход одним вызовом каждого вида (а не по вызову на выход): `awg show
        all dump` — рукопожатия и трафик выходов AWG, `ip -j -s link show` — счётчики туннелей SOCKS5.
        None — не вышло: тогда каждый выход спрашивается отдельно, как раньше."""
        if config.DRY_RUN or not self.rt:
            return None, None
        kinds = set()
        for u in st["upstreams"]:
            if u["id"] in self.rt and u.get("enabled", True):
                try:
                    kinds.add(self.parsed(u).kind)
                except Exception:  # noqa: BLE001
                    kinds.add("awg")
        awg_on, socks_on = len(kinds - {"socks5"}) > 0, "socks5" in kinds
        dumps = links = None
        if awg_on:
            p = t.ns(["awg", "show", "all", "dump"], check=False, timeout=10)
            dumps = system.parse_all_dump(p.stdout) if p.stdout else None
        if socks_on:
            p = t.ns(["ip", "-j", "-s", "link", "show"], check=False, timeout=10)
            try:
                links = {x.get("ifname"): x.get("stats64") or {} for x in json.loads(p.stdout or "[]")}
            except (ValueError, AttributeError):
                links = None
        return dumps, links

    def _update_health(self, t: system.Target, st: dict) -> None:
        now = time.time()
        dumps, links = self._pass_dumps(t, st)
        for u in st["upstreams"]:
            uid = u["id"]
            if not u.get("enabled", True):
                self.health[uid] = {"state": "disabled"}
                continue
            r = self.rt.get(uid)
            if not r and uid in getattr(self, "_waiting", ()):
                # ждёт подъёма сервера (engine_pending), а не упал: как «подключается» — блок, а не резерв, иначе с
                # резервом «Напрямую» после перезапуска контейнера сервера на модуле ядра клиенты шли бы мимо выхода
                self.health[uid] = {"state": "connecting", "waiting": True}
                continue
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
                self._socks_health(t, u, r, now, links)
                continue
            if config.DRY_RUN and self._fake and r.iface not in self._fake.handshakes:
                # в демо второй туннель «мёртвый», чтобы было видно резервирование
                self._fake.handshakes[r.iface] = now - (900 if r.num == 2 else 20)
            peers = (dumps or {}).get(r.iface)
            if peers is None:                   # нет в общем ответе — спросить сам туннель, как раньше
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
            connecting = not healthy and not hs and now - r.started < CONNECTING_SECS
            self.health[uid] = {
                "state": "up" if healthy else ("connecting" if connecting else "stale"),
                "healthy": healthy, "handshake_age": age, "iface": r.iface,
                "rx": peer["rx"] if peer else 0, "tx": peer["tx"] if peer else 0,
                "endpoint": peer["endpoint"] if peer else None,
                "since": r.started,
            }

    def _watch_connecting(self) -> None:
        """Поток: выходы AWG, которые только что запущены и ещё не ответили («подключается»). Их клиенты в блоке
        (resolve), а следующий проход — через RECONCILE_INTERVAL: столько клиенты были бы без связи. Каждые
        HANDSHAKE_POLL смотрим рукопожатие таких выходов и будим проход, как только выход ответил или кончились
        CONNECTING_SECS (тогда его клиенты идут на резерв). Нет таких выходов — только просмотр словаря."""
        while not self.stop_ev.wait(HANDSHAKE_POLL):
            try:
                if self._connecting_due(self.target, time.time()):
                    self.trigger()
            except Exception as e:  # noqa: BLE001
                log.info("connecting exits: %s", e)

    def _connecting_due(self, t: system.Target | None, now: float) -> bool:
        """Есть ли «подключающийся» выход AWG, который уже ответил или чей срок вышел (нужен проход)."""
        if t is None:
            return False
        for uid, r in list(self.rt.items()):
            h = self.health.get(uid) or {}
            if h.get("state") != "connecting" or h.get("kind") == "socks5" or h.get("since") != r.started:
                continue                    # SOCKS5 будит проход сам (проверка прокси); since — тот же запуск
            if now - r.started >= CONNECTING_SECS:
                return True
            p = t.ns(["awg", "show", r.iface, "latest-handshakes"], check=False, timeout=5)
            for line in (p.stdout or "").splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) > 0:
                    return True
        return False

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

    def _socks_health(self, t: system.Target, u: dict, r: UpRT, now: float, links: dict | None = None) -> None:
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

            ip = r.socks_ip if not config.DRY_RUN else None

            def run(uid=uid, conf=conf, ip=ip):
                try:
                    # из сети сервера AWG, как hev: из сети панели прокси может быть виден иначе
                    self._socks_res[uid] = socks.check_in(t, conf, ip) if ip else socks.check(conf)
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
            try:
                if links is not None and r.iface in links:      # из общего ответа прохода (_pass_dumps)
                    st64 = links[r.iface]
                else:
                    p = t.ns(["ip", "-j", "-s", "link", "show", "dev", r.iface], check=False, timeout=10)
                    st64 = (json.loads(p.stdout or "[]") or [{}])[0].get("stats64") or {}
                # TUN со стороны ядра: rx — пришло от прокси (к клиентам), tx — ушло в прокси
                rx, tx = st64.get("rx", {}).get("bytes", 0), st64.get("tx", {}).get("bytes", 0)
            except (ValueError, IndexError, AttributeError):
                pass
        state = "up" if healthy else ("connecting" if not res and now - r.started < CONNECTING_SECS else "stale")
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
                counters = nftgen.parse_acct(json.loads(p.stdout or "{}"), server_ifaces(t))
            except ValueError:
                counters = None
        if counters is None:
            path = os.path.join(RUN_DIR, "acct.nft")
            with open(path, "w") as f:
                f.write(nftgen.acct_ruleset(server_ifaces(t)))
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
