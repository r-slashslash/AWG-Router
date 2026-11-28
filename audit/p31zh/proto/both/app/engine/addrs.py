"""Адреса сервера (1.25.0): IPv4, которые вписали в «Дополнительные исходящие адреса» и «Дополнительные входящие
адреса» на вкладке «Сервер» (и входящий адрес сервера, если это IP).

IP, которого нет в системе сервера, панель добавляет сама — командой `ip addr add <IP>/32 dev <WAN>` (WAN — интерфейс
маршрута по умолчанию), без правки сетевых файлов системы, с меткой (label) `<WAN>:awgr`, когда имя интерфейса
позволяет, — и проверяет: выходит ли с него интернет, какой адрес видят сайты и страна (probe.py, сокет привязан к
этому адресу). Не работает с первой проверки — сразу убирает и запоминает почему (в выборе его нет). После
перезагрузки сервера или перезапуска сети системы (адреса пропали) — добавляет снова. Убрали из списка — убирает.
Только свои: адрес, который был в системе до панели или добавлен человеком (без нашей метки после перезагрузки),
не трогается никогда. Домены и IPv6 в систему не добавляются. Что добавила панель — в data/addrs.json и, для
`awg-router uninstall` (там нет Python), строками «<интерфейс> <IP>» в data/own-addrs.

Всё это — в сети панели: у неё сеть хоста (network_mode: host) в обоих режимах. Исходящий адрес, который работал и
перестал (две неудачные проверки подряд), — «не работает»: трафик через него блокируется (routes), сообщение в
Telegram (ev.addr_down / ev.addr_up, как у выходов).

В режиме контейнера трафик клиентов уходит из сети контейнера сервера AWG, а метка пакета не переживает переход
между сетями: на каждый исходящий адрес — своя сеть Docker с опцией com.docker.network.host_ipv4=<адрес> (Docker сам
подменяет адрес отправителя этой сети на этот), подключённая к контейнеру сервера без перезапуска (_sync_addr_nets).
Имя сети — ADDR_NET_PREFIX + номер: по имени Docker выбирает, через какую сеть у контейнера маршрут по умолчанию
(при равном приоритете), и наша не должна оказаться первой."""
from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .. import awgconf, config, nftgen, srcaddr, system
from ..i18n import Msg
from .common import APP_DIR, log

ADDR_TICK = 15          # с: как часто смотреть, на месте ли адреса (перезапуск сети системы)
ADDR_RECHECK = 300      # с: рабочий адрес проверяется заново
ADDR_RETRY = 60         # с: переставший работать — чаще, чтобы заметить, что снова работает
ADDR_SOON = 20          # с: после первой неудачи — ещё раз скоро, а не через ADDR_RECHECK
# с: адрес, который не заработал ни разу (bad), — снова в систему и на проверку (владелец 2026-11-26): вписали в панели
# раньше, чем хостинг его подключил, — заработает сам, без повторного сохранения «Сервера»
ADDR_BAD_RETRY = 900
ADDR_FAILS = 2          # неудачных проверок подряд — «перестал работать» (не от одного сбоя сети)
ADDR_LABEL = "awgr"     # метка адреса в системе: <интерфейс>:awgr
ADDR_NET_PREFIX = "zz-awgr-out-"
ADDR_NET_LABEL = "awg-router.addr"
PROBE = os.path.join(APP_DIR, "probe.py")
PROBE_HOSTS = ("ipinfo.io", "ifconfig.me")


def srcnet_source(e, st: dict) -> str | None:
    """С какого адреса сейчас выходит сам сервер (None — адрес системы): выбранный, если работает."""
    return e.own_src((st.get("settings") or {}).get("own_src") or "")


def rec_path() -> str:
    return os.path.join(config.DATA_DIR, "addrs.json")


def own_path() -> str:
    return os.path.join(config.DATA_DIR, "own-addrs")


def boot_id() -> str:
    try:
        with open("/proc/sys/kernel/random/boot_id") as f:
            return f.read().strip()
    except OSError:
        return ""


def label_for(dev: str) -> str | None:
    """Метка адреса, добавленного панелью: имя интерфейса и «:awgr», не длиннее 15 знаков (IFNAMSIZ)."""
    lab = f"{dev}:{ADDR_LABEL}"
    return lab if len(lab) <= 15 else None


_REC_LOCK = threading.Lock()


class AddrsMixin:
    """Адреса сервера в системе: добавление, проверка, удаление (часть Engine)."""

    # ------------------------------------------------------------------ запись о своих адресах
    def _addr_rec(self) -> dict:
        r = getattr(self, "_addr_rec_cache", None)
        if r is not None:
            return r
        with _REC_LOCK:             # проход, поток адресов и запросы браузера: один словарь на всех (П52)
            return self._addr_rec_load()

    def _addr_rec_load(self) -> dict:
        r = getattr(self, "_addr_rec_cache", None)
        if r is None:
            try:
                with open(rec_path()) as f:
                    r = json.load(f)
            except (OSError, ValueError):
                r = {}
            if not isinstance(r, dict):
                r = {}
            for k, d in (("slots", {}), ("ours", {}), ("ever", []), ("last", {})):
                if not isinstance(r.get(k), type(d)):
                    r[k] = d
            self._addr_rec_cache = r
        return r

    def _addr_save(self) -> None:
        r = self._addr_rec()
        with _REC_LOCK:             # общий временный файл: при двух записях сразу одна уносила файл другой
            self._addr_write(r)

    @staticmethod
    def _addr_write(r: dict) -> None:
        try:
            os.makedirs(config.DATA_DIR, exist_ok=True)
            tmp = rec_path() + ".tmp"
            with open(tmp, "w") as f:
                json.dump(r, f)
            os.replace(tmp, rec_path())
            tmp = own_path() + ".tmp"
            with open(tmp, "w") as f:
                f.write("".join(f"{dev} {ip}\n" for ip, dev in sorted(r["ours"].items())))
            os.replace(tmp, own_path())
        except OSError as e:
            log.warning("addresses: %s", e)

    def addr_slot(self, ip: str) -> int:
        """Номер исходящего адреса (метка ADDR_MARK_BASE + номер, таблица маршрутов): один и тот же, пока адрес в
        списке, и после перезапуска панели (решение QUIC в conntrack хранит метку). Свободный — с наименьшего."""
        r = self._addr_rec()
        slots = r["slots"]
        if ip in slots:
            return int(slots[ip])
        busy = {int(v) for v in slots.values()}
        k = next((n for n in range(1, srcaddr.OUT_HOSTS_MAX + 1) if n not in busy), 0)
        if k:
            slots[ip] = k
            self._addr_save()
        return k

    def addr_slots(self, st: dict) -> dict[str, int]:
        """{адрес: номер} — исходящих адресов из списка сервера; номера ушедших освобождаются."""
        want = srcaddr.out_hosts(st)
        r = self._addr_rec()
        gone = [ip for ip in r["slots"] if ip not in want]
        for ip in gone:
            r["slots"].pop(ip)
        if gone:
            self._addr_save()
        out = {}
        for ip in want:
            k = self.addr_slot(ip)
            if k:
                out[ip] = k
        return out

    # ------------------------------------------------------------------ система
    @staticmethod
    def _ip_json(args: list[str]) -> list:
        p = system.run(["ip", "-j", *args], check=False, timeout=10)
        try:
            v = json.loads(p.stdout or "[]")
            return v if isinstance(v, list) else []
        except ValueError:
            return []

    def _host_v4(self) -> dict[str, dict]:
        """IPv4 сервера (в сети панели — это сеть хоста): {адрес: {"dev", "label"}}."""
        if config.DRY_RUN:
            d = {"203.0.113.5": {"dev": "eth0", "label": "eth0"}}
            for ip, dev in self._addr_rec()["ours"].items():
                d[ip] = {"dev": dev, "label": label_for(dev) or dev}
            return d
        out = {}
        for x in self._ip_json(["-4", "addr", "show"]):
            for a in x.get("addr_info") or []:
                if a.get("family") == "inet" and a.get("local"):
                    out[a["local"]] = {"dev": x.get("ifname") or "", "label": a.get("label") or x.get("ifname") or ""}
        return out

    def _wan(self) -> dict:
        """Маршрут по умолчанию в сети хоста: {"dev", "gw", "src"} (src — адрес системы)."""
        if config.DRY_RUN:
            return {"dev": "eth0", "gw": "203.0.113.1", "src": "203.0.113.5"}
        out = {}
        for r in self._ip_json(["-4", "route", "show", "default"]):
            if r.get("dev"):
                out = {"dev": r["dev"], "gw": r.get("gateway") or "", "src": r.get("prefsrc") or ""}
                break
        if out and not out["src"]:
            for r in self._ip_json(["-4", "route", "get", "1.1.1.1"]):
                out["src"] = r.get("prefsrc") or ""
        return out

    def system_v4(self) -> str | None:
        """Адрес системы — откуда сервер выходит сам («Как в системе — …»): адрес отправителя маршрута по умолчанию."""
        return getattr(self, "_sys_v4", None) or ((self._wan() or {}).get("src") if config.DRY_RUN else None)

    # ------------------------------------------------------------------ что нужно
    @staticmethod
    def inbound_ips(st: dict) -> list[str]:
        """Входящие IPv4 из «Дополнительных входящих адресов» (домены и IPv6 в систему не добавляются). Сам адрес в
        конфигах — только если он оттуда же: иначе это адрес сервера (адрес системы, внешний адрес облака) или прежний
        IP, и добавлять его в систему нельзя — в облаках с внешним адресом снаружи (AWS, Oracle, Yandex Cloud) панель
        ставила его на интерфейс при каждом запуске и писала «не работает» (проверка 1.25.0, А2)."""
        s = st.get("settings") or {}
        out = []
        for h in s.get("extra_hosts") or []:
            a = srcaddr.ipv4(h) if isinstance(h, str) else None
            if a and a == h and srcaddr.usable(a) and a not in out:
                out.append(a)
        return out

    def addr_rt(self) -> dict[str, dict]:
        d = getattr(self, "_addr_rt", None)
        if d is None:
            d = self._addr_rt = {}
        return d

    def addr_state(self, ip: str) -> str | None:
        """checking | ok | failed (работал и перестал) | bad (не заработал, убран) | None — не проверялся."""
        return (self.addr_rt().get(ip) or {}).get("state")

    def addr_ok(self, ip: str) -> bool:
        return self.addr_state(ip) == "ok"

    def addrs_wake(self, retry: list[str] | None = None) -> None:
        """Список адресов поменялся (сохранили «Сервер»): проверить сейчас, а не через ADDR_TICK. retry — адреса,
        которые снова вписали: прежнее «не работает» не помнится, проверка с начала."""
        for ip in retry or ():
            rt = self.addr_rt().get(ip)
            if rt and rt.get("state") == "bad":
                self.addr_rt().pop(ip, None)
        ev = getattr(self, "_addr_ev", None)
        if ev is not None:
            ev.set()

    # ------------------------------------------------------------------ поток
    def _watch_addrs(self) -> None:
        self._addr_ev = threading.Event()
        while not self.stop_ev.is_set():
            try:
                self._addr_tick(self.store.snapshot())
            except Exception:  # noqa: BLE001
                log.exception("addresses")
            self._addr_ev.wait(ADDR_TICK)
            self._addr_ev.clear()

    def _addr_tick(self, st: dict) -> None:
        """Один круг: адреса на месте (добавить недостающие свои, убрать ненужные свои), проверки, у которых срок."""
        out_ips = srcaddr.out_hosts(st)
        in_ips = [ip for ip in self.inbound_ips(st) if ip not in out_ips]
        wan = self._wan()
        self._sys_v4 = wan.get("src") or None
        host = self._host_v4()
        r = self._addr_rec()
        changed = False
        boot = boot_id()
        if r.get("boot") != boot:
            # перезагрузка: своих адресов в системе нет. Такой же адрес, но без нашей метки, добавил уже кто-то другой
            # (настройки сети системы) — он больше не наш и никогда не убирается
            for ip in list(r["ours"]):
                if ip in host and host[ip]["label"] != label_for(r["ours"][ip]):
                    r["ours"].pop(ip)
            r["boot"] = boot
            changed = True
        rt = self.addr_rt()
        for ip in list(rt):
            if ip not in out_ips and ip not in in_ips:
                rt.pop(ip, None)
        for ip in [ip for ip in r["last"] if ip not in out_ips and ip not in in_ips]:
            r["last"].pop(ip)                   # адрес убрали из списка: его прежнее состояние больше не нужно
            changed = True
        # входящий IP, который виден снаружи как адрес системы или рабочего исходящего (облако с 1:1 NAT, AWS), — уже
        # «на сервере»: добавлять его в систему не нужно (и нельзя: в системе у такого сервера внутренний адрес)
        faces = {getattr(self, "public_v4", None)} | {(rt.get(a) or {}).get("seen") for a in out_ips if self.addr_ok(a)}
        # …а пока внешний адрес сервера и адреса, которые видят сайты, ещё не известны (первые секунды после запуска
        # панели), входящий IP, которого нет в системе, не трогаем: иначе в облаке его внешний адрес ставился бы на
        # интерфейс и «не работал» (А2)
        faces_pending = (getattr(self, "public_v4", None) is None and getattr(self, "public_v4_state", None) != "failed") \
            or any((rt.get(a) or {}).get("state") in (None, "checking") for a in out_ips)
        self._addr_restore(out_ips + in_ips, host)
        want, held = [], set()
        for ip in out_ips + in_ips:
            st_ = (rt.get(ip) or {}).get("state")
            if ip in in_ips and ip not in host and ip in faces:
                rt[ip] = {"state": "ok", "seen": ip, "at": time.time(), "face": True}
                continue
            if ip in in_ips and ip not in host and faces_pending:
                held.add(ip)
                continue
            if st_ == "bad":
                # не заработал: в систему — когда его снова впишут (addrs_wake) или через ADDR_BAD_RETRY. Ошибку
                # прежней проверки показываем, пока идёт новая; событие «не работает» второй раз не пишем (retry)
                if time.time() - float((rt.get(ip) or {}).get("at") or 0) < ADDR_BAD_RETRY:
                    continue
                if getattr((rt.get(ip) or {}).get("error"), "key", None) == "addr.docker_gw":
                    # сеть адреса Docker сделал маршрутом по умолчанию контейнера: сама больше не подключается — каждый
                    # повтор на доли секунды уводил весь «Напрямую» на этот адрес. Снова — когда «Сервер» сохранят
                    continue
                rt[ip] = {**(rt.get(ip) or {}), "state": "checking", "retry": True, "fails": 0}
            want.append(ip)
        for ip in want:
            if ip in host:
                if ip in r["ours"] and host[ip]["dev"] != r["ours"][ip]:
                    r["ours"].pop(ip)       # на другом интерфейсе — не наш
                    changed = True
                continue
            dev = wan.get("dev")
            # адрес, который уже работал: сеть системы перезапускается (маршрута по умолчанию на миг нет, добавить не
            # вышло) — попробовать на следующем круге, а не считать «не заработал» на 15 минут (П29)
            ever = ip in r["ever"]
            if not dev:
                if not ever:
                    rt[ip] = {**(rt.get(ip) or {}), "state": "bad", "error": Msg("addr.no_wan"), "at": time.time()}
                continue
            was = ip in r["ours"]
            if self._addr_add(ip, dev):
                r["ours"][ip] = dev
                changed = True
                host[ip] = {"dev": dev, "label": label_for(dev) or dev}
                if was and (rt.get(ip) or {}).get("state") in ("ok", "failed"):
                    self.event("info", Msg("ev.addr_readded", addr=ip))
            elif not ever:
                rt[ip] = {**(rt.get(ip) or {}), "state": "bad", "error": Msg("addr.add_failed"), "at": time.time()}
        keep = set(want) | held | {ip for ip in out_ips if (rt.get(ip) or {}).get("state") != "bad"}
        for ip, dev in list(r["ours"].items()):
            if ip not in keep:
                self._addr_del(ip, dev)
                r["ours"].pop(ip)
                changed = True
        if changed:
            self._addr_save()
        self._addr_probe_due(st, out_ips, in_ips, host)

    def _addr_add(self, ip: str, dev: str) -> bool:
        if config.DRY_RUN:
            return True
        cmd = ["ip", "addr", "add", f"{ip}/32", "dev", dev]
        if label_for(dev):
            cmd += ["label", label_for(dev)]
        p = system.run(cmd, check=False, timeout=10)
        if p.returncode != 0 and "File exists" not in (p.stderr or ""):
            log.warning("address %s: %s", ip, (p.stderr or "").strip()[:200])
            return False
        log.info("address %s added to %s", ip, dev)
        return True

    def _addr_del(self, ip: str, dev: str) -> None:
        if config.DRY_RUN:
            return
        system.run(["ip", "addr", "del", f"{ip}/32", "dev", dev], check=False, timeout=10)
        log.info("address %s removed from %s", ip, dev)

    def _addr_restore(self, ips: list[str], host: dict) -> None:
        """После перезапуска панели (в памяти состояний нет): адрес, который на месте в системе, берёт последнее
        состояние из data/addrs.json — «работает» (сразу проверяется заново) или «не работает». Иначе после каждого
        обновления панели всё «Напрямую — адрес» стояло в блоке до двух проверок подряд, а первая случайная неудача
        сразу давала «перестал работать» в Telegram (проверка 1.25.0, А8). Защита в nftables от этого не меняется:
        с другого адреса пакет не уйдёт и так."""
        rt, last = self.addr_rt(), self._addr_rec()["last"]
        back = False
        for ip in ips:
            x = last.get(ip)
            if ip in rt or ip not in host or not isinstance(x, dict) or x.get("state") not in ("ok", "failed"):
                continue
            rt[ip] = {"state": x["state"], "seen": x.get("seen"), "cc": x.get("cc"), "error": None, "at": 0.0,
                      "fails": 0}
            back = back or x["state"] == "ok"
        if back:
            self.trigger()                      # проход: «Напрямую — адрес» снова через него, не дожидаясь проверки

    def _addr_last(self, ip: str, x: dict | None) -> None:
        """Последнее состояние адреса — в data/addrs.json (только когда оно сменилось): его берёт _addr_restore."""
        last = self._addr_rec()["last"]
        want = {"state": x["state"], "seen": x.get("seen"), "cc": x.get("cc")} \
            if x and x.get("state") in ("ok", "failed") else None
        if last.get(ip) != want:
            if want:
                last[ip] = want
            else:
                last.pop(ip, None)
            self._addr_save()

    # ------------------------------------------------------------------ проверки
    def _addr_probe_due(self, st: dict, out_ips: list[str], in_ips: list[str], host: dict) -> None:
        rt = self.addr_rt()
        now = time.time()
        due = []
        for ip in out_ips + in_ips:
            x = rt.get(ip) or {}
            s, at = x.get("state"), x.get("at") or 0
            if x.get("face"):
                continue
            if s in (None, "checking") or (s == "ok" and now - at >= (ADDR_SOON if x.get("fails") else ADDR_RECHECK)) \
                    or (s == "failed" and now - at >= ADDR_RETRY):
                if ip in host:
                    due.append(ip)
                elif s in ("ok", "failed"):
                    self._addr_result(ip, ip in out_ips, {"ok": False, "err": "gone"})
        for ip in due:
            if (rt.get(ip) or {}).get("state") is None:
                rt[ip] = {"state": "checking", "at": now}
        if not due:
            return
        # исходящий адрес, чей путь стоит, проверяется этим путём (метка адреса из сети сервера AWG — как трафик
        # клиентов, в контейнере — через сеть Docker адреса); пока пути нет — сокетом, привязанным к адресу
        live = {x.get("ip"): k for k, x in (getattr(self, "_addr_live", None) or {}).items()}
        jobs = [(ip, live.get(ip) if ip in out_ips else None) for ip in due]
        with ThreadPoolExecutor(max_workers=min(8, len(jobs))) as ex:
            for (ip, k), res in zip(jobs, ex.map(lambda j: self._addr_probe(*j), jobs)):
                self._addr_result(ip, ip in out_ips, res, path=k is not None)

    def _addr_probe(self, ip: str, k: int | None = None) -> dict:
        """probe.py: выходит ли с адреса интернет, какой адрес видят сайты, страна. k — путём «Напрямую — адрес» (метка
        адреса в сети сервера AWG); без k — сокетами, привязанными к адресу, в сети панели (это сеть хоста)."""
        if config.DRY_RUN:
            if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network("192.0.2.0/24"):     # демо: так выглядит неработающий
                return {"ok": False, "err": "no_connection", "detail": "timed out"}
            return {"ok": True, "ip": ip, "cc": "DE", "latency_ms": 30}
        try:
            hosts = [f"{h}={a}" for h, a in awgconf.resolve_many(PROBE_HOSTS, 4).items()]
        except Exception:  # noqa: BLE001
            hosts = []
        t = self.target
        if k is not None and t and t.exists:
            p = t.ns(["python3", PROBE, str(nftgen.addr_mark(k)), *hosts], check=False, timeout=40)
        else:
            p = system.run(["python3", PROBE, "0", f"--src={ip}", *hosts], check=False, timeout=40)
        try:
            return json.loads(p.stdout)
        except ValueError:
            return {"ok": False, "err": "no_answer", "detail": (p.stderr or p.stdout or "").strip()[:200]}

    def _addr_result(self, ip: str, outbound: bool, res: dict, path: bool = False) -> None:
        """Итог проверки. Исходящий адрес «работает» только после проверки своим путём: сайты видят то же, что с сокета,
        привязанного к адресу (иначе подмена адреса не сработала: Docker без host_ipv4, чужой NAT раньше нашего)."""
        rt = self.addr_rt()
        x = rt.setdefault(ip, {"state": "checking"})
        now = time.time()
        r = self._addr_rec()
        ever = ip in r["ever"]
        seen = res.get("ip")
        if res.get("ok") and path and x.get("bind_seen") and seen and seen != x["bind_seen"]:
            res = {"ok": False, "err": "path", "detail": f"{seen} ≠ {x['bind_seen']}"}
        if res.get("ok") and outbound and not path:
            x["bind_seen"] = seen
            x.update(seen=seen or x.get("seen"), cc=res.get("cc") or x.get("cc"), at=now)
            if x.get("state") in (None, "checking"):
                x["state"] = "checking"         # интернет с адреса есть; «работает» — после проверки своим путём
                self.trigger()
                return
        if res.get("ok"):
            was = x.get("state")
            x.update(state="ok", seen=seen or x.get("seen"), cc=res.get("cc") or x.get("cc"), error=None,
                     at=now, fails=0)
            x.pop("retry", None)
            if not ever:
                r["ever"].append(ip)
                r["ever"][:] = r["ever"][-64:]
                self._addr_save()
            if outbound and was == "failed":
                self.event("info", Msg("ev.addr_up", addr=ip))
            self._addr_last(ip, x)
            if was != "ok":
                self.trigger()          # правила: «Напрямую — адрес» снова через него
            return
        if res.get("err") == "gone":
            err = Msg("addr.gone")
        elif res.get("err") == "path":
            err = Msg("addr.path", detail=res.get("detail") or "")
        else:
            err = Msg("addr.no_internet", detail=str(res.get("detail") or res.get("err") or "")[:120])
        x["fails"] = int(x.get("fails") or 0) + 1
        x["at"], x["error"] = now, err
        if not ever and x.get("state") in (None, "checking"):
            # не заработал ни разу: убрать из системы (если добавила панель) и не предлагать в выборе; повтор через
            # ADDR_BAD_RETRY не заработал — без нового события в журнале
            x["state"] = "bad"
            self._addr_last(ip, None)
            if not x.pop("retry", False):
                self.event("warn", Msg("ev.addr_bad", addr=ip, error=err))
            self.addrs_wake()
            return
        if x.get("state") == "ok" and x["fails"] < ADDR_FAILS:
            return                      # одна неудача — ещё раз через ADDR_SOON
        if x.get("state") != "failed":
            x["state"] = "failed"
            self._addr_last(ip, x)
            if outbound:
                self.event("error", Msg("ev.addr_down", addr=ip, error=err))
            self.trigger()              # всё через этот адрес — в блок

    # ------------------------------------------------------------------ путь «Напрямую — адрес» (проход движка)
    def _addr_pass(self, t: system.Target, st: dict, add_only: bool = True) -> None:
        """add_only (до правил nftables с метками адресов): пути адресов — сеть Docker (контейнер), ip rule и таблица с
        маршрутом по умолчанию через свой интерфейс (на хосте — с этим адресом отправителя); _addr_live — адреса, чей
        путь стоит (только их Engine.resolve отдаёт как Addr). Иначе (конец прохода) — убрать ip rule и таблицы
        номеров, которых больше нет: метку ушедшего адреса прежние правила nftables ставили до этого прохода."""
        slots = self.addr_slots(st)
        if not add_only:
            self._sync_addr_routes(t, slots, {}, add_only=False)
            return
        infra: dict[int, dict] = {}
        if t.kind == "container":
            for k, n in self._sync_addr_nets(t, st).items():
                infra[k] = {"ip": n["ip"], "dev": n["dev"], "gw": n["gw"], "nat": "masq"}
        else:
            wan = self._wan()
            host = self._host_v4()
            for ip, k in slots.items():
                if ip in host and wan.get("dev") and self.addr_state(ip) != "bad":
                    infra[k] = {"ip": ip, "dev": wan["dev"], "gw": wan.get("gw") or "", "nat": "snat"}
        ok = self._sync_addr_routes(t, slots, infra, add_only=True)
        live = {k: v for k, v in infra.items() if k in ok}
        if set(live) != set(getattr(self, "_addr_live", None) or {}):
            self.addrs_wake()           # путь появился или пропал — проверить адрес этим путём сейчас
        self._addr_live = live

    def _sync_addr_routes(self, t: system.Target, slots: dict[str, int], infra: dict[int, dict],
                          add_only: bool) -> set[int]:
        """ip rule «метка адреса K → таблица ADDR_TABLE_BASE + K» для всех номеров из списка и в таблице — unreachable
        (адрес пропал — блок, а не основная таблица) и маршрут по умолчанию пути (infra). → номера, чей маршрут встал.
        Маршруты заново — когда поменялись пути или прошло ROUTES_EVERY (адрес исчезает с маршрутом вместе)."""
        want = set(slots.values())
        lo, hi = config.ADDR_PRIO_BASE + 1, config.ADDR_PRIO_BASE + config.ADDR_MAX
        cmds = []
        present = set()
        for rule in self._ip_rules(t):
            prio = rule.get("priority", 0)
            if not lo <= prio <= hi:
                continue
            k = prio - config.ADDR_PRIO_BASE
            ok = k in want and str(rule.get("table")) == str(config.ADDR_TABLE_BASE + k) and \
                int(str(rule.get("fwmark", "0")), 0) == nftgen.addr_mark(k)
            if ok and k not in present:
                present.add(k)
            elif not add_only or k in want:
                cmds.append(["rule", "del", "priority", str(prio)])
                if k not in want:
                    cmds.append(["route", "flush", "table", str(config.ADDR_TABLE_BASE + k)])
        if not add_only:
            for c in cmds:
                t.ns(["ip", *c], check=False)
            return set()
        for k in sorted(want - present):
            cmds.append(["rule", "add", "fwmark", hex(nftgen.addr_mark(k)), "lookup", str(config.ADDR_TABLE_BASE + k),
                         "priority", str(config.ADDR_PRIO_BASE + k)])
        key = (t.key, tuple(sorted((k, tuple(sorted(v.items()))) for k, v in infra.items())), tuple(sorted(want)))
        cache = getattr(self, "_addr_routes", None)
        if not cmds and cache and cache[0] == key and time.time() - cache[1] < 60:
            return cache[2]
        for c in cmds:
            t.ns(["ip", *c], check=False)
        ok = set()
        for k in sorted(want):
            table = str(config.ADDR_TABLE_BASE + k)
            t.ns(["ip", "route", "replace", "unreachable", "default", "metric", "4096", "table", table], check=False)
            a = infra.get(k)
            if not a:
                t.ns(["ip", "route", "del", "default", "metric", "0", "table", table], check=False)
                continue
            cmd = ["ip", "route", "replace", "default", *(["via", a["gw"]] if a.get("gw") else []), "dev", a["dev"]]
            if a.get("nat") == "snat":
                cmd += ["src", a["ip"]]
            p = t.ns([*cmd, "table", table], check=False)
            if p.returncode == 0:
                ok.add(k)
            else:
                log.warning("address %s: route: %s", a["ip"], (p.stderr or "").strip()[:200])
        self._addr_routes = (key, time.time(), ok)
        return ok

    # ------------------------------------------------------------------ для браузера
    def addrs_view(self, st: dict) -> dict:
        """Адреса для вкладок «Сервер», «Маршрутизация» и выбора выхода: адрес системы, исходящие и входящие (IP), а у
        исходящих — где стоят (uses: места «Напрямую» и выходы, которые подключаются с адреса; ключ — IP или system)."""
        rt = self.addr_rt()
        own = self._addr_rec()["ours"]

        def one(ip: str) -> dict:
            x = rt.get(ip) or {}
            return {"ip": ip, "state": x.get("state") or "checking", "seen": x.get("seen"), "cc": x.get("cc"),
                    "error": x.get("error"), "ours": ip in own}
        uses: dict[str, dict] = {}
        if srcaddr.out_hosts(st):
            for _, o, f, label in srcaddr.places(st):
                u = uses.setdefault(srcaddr.addr_of(st, o[f]), {"direct": [], "direct_n": 0, "exits": []})
                u["direct_n"] += 1
                if len(u["direct"]) < 4:
                    u["direct"].append(label)
            for x in st["upstreams"]:
                uses.setdefault(srcaddr.bind_of(st, x), {"direct": [], "direct_n": 0, "exits": []})["exits"].append(
                    x["name"])
        return {"system": {"ip": self.system_v4(), "seen": getattr(self, "public_v4", None),
                           "cc": getattr(self, "public_cc", None)},
                "main": srcaddr.main(st), "own_src": (st.get("settings") or {}).get("own_src") or "",
                "own_now": srcnet_source(self, st),
                "out": [one(ip) for ip in srcaddr.out_hosts(st)],
                "in": [one(ip) for ip in self.inbound_ips(st) if ip not in srcaddr.out_hosts(st)], "uses": uses}

    # ------------------------------------------------------------------ режим контейнера: сети Docker
    ADDR_NETS_EVERY = 60    # с: сверка сетей Docker не чаще (и сразу, когда поменялись адреса или контейнер)

    def _sync_addr_nets(self, t: system.Target, st: dict) -> dict[int, dict]:
        """Сети Docker исходящих адресов у контейнера сервера AWG → {номер: {"ip", "dev", "gw"}}: dev и gw — интерфейс и
        шлюз этой сети внутри контейнера (туда маршрут по метке адреса). Сеть создаётся с host_ipv4 = адрес (Docker
        сам ставит правило подмены адреса отправителя), подключается без перезапуска контейнера. Подключение сменило
        маршрут по умолчанию контейнера (Docker выбрал нашу сеть основной) — отключить, адрес «не работает»: иначе всё
        «Напрямую» молча пошло бы с этого адреса. Ненужные сети панели отключаются и удаляются."""
        if t.kind != "container" or config.DRY_RUN or not os.path.exists(config.DOCKER_SOCK):
            return {}
        slots = {ip: k for ip, k in self.addr_slots(st).items() if self.addr_state(ip) != "bad"}
        key = (t.key, tuple(sorted(slots.items())))
        cache = getattr(self, "_addr_nets", None)
        if cache and cache[0] == key and time.time() - cache[1] < self.ADDR_NETS_EVERY:
            return cache[2]
        import urllib.parse
        flt = urllib.parse.quote(json.dumps({"label": [ADDR_NET_LABEL]}))
        nets = {n.get("Name"): n for n in (system.docker_get(f"/networks?filters={flt}") or [])}
        info = system.docker_get(f"/containers/{t.name}/json") or {}
        attached = ((info.get("NetworkSettings") or {}).get("Networks") or {})
        out: dict[int, dict] = {}
        for ip, k in sorted(slots.items(), key=lambda x: x[1]):
            name = f"{ADDR_NET_PREFIX}{k}"
            try:
                n = nets.get(name)
                if n and (n.get("Options") or {}).get("com.docker.network.host_ipv4") != ip:
                    self._net_drop(t, name, name in attached)       # номер теперь у другого адреса
                    attached.pop(name, None)
                    n = None
                if not n:
                    system.docker_api("POST", "/networks/create", body={
                        "Name": name, "Driver": "bridge", "CheckDuplicate": True,
                        "Options": {"com.docker.network.host_ipv4": ip}, "Labels": {ADDR_NET_LABEL: ip}})
                if name not in attached:
                    before = self._ct_default(t)
                    # GwPriority (Docker 28+): эта сеть — никогда не маршрут по умолчанию контейнера
                    system.docker_api("POST", f"/networks/{name}/connect", body={
                        "Container": t.name, "EndpointConfig": {"GwPriority": -1000}})
                    if before and self._ct_default(t) != before:
                        self._net_drop(t, name, True)
                        self.addr_rt()[ip] = {**(self.addr_rt().get(ip) or {}), "state": "bad",
                                              "error": Msg("addr.docker_gw"), "at": time.time()}
                        continue
                    info = system.docker_get(f"/containers/{t.name}/json") or {}
                    attached = ((info.get("NetworkSettings") or {}).get("Networks") or {})
                ep = attached.get(name) or {}
                if ep.get("Gateway") and f"/{ep['Gateway']}" in self._ct_default(t).split(",")[0]:
                    # маршрут по умолчанию контейнера уже в сети адреса (смена порта без GwPriority, старый Docker после
                    # перезапуска): весь «Напрямую» шёл бы с этого адреса — отключить сеть (П42)
                    self._net_drop(t, name, True)
                    self.addr_rt()[ip] = {**(self.addr_rt().get(ip) or {}), "state": "bad",
                                          "error": Msg("addr.docker_gw"), "at": time.time()}
                    continue
                dev = self._ct_iface(t, ep.get("IPAddress"))
                if dev and ep.get("Gateway"):
                    out[k] = {"ip": ip, "dev": dev, "gw": ep["Gateway"]}
            except (OSError, system.SysError) as e:
                log.warning("address %s: Docker network: %s", ip, e)
                self.addr_rt()[ip] = {**(self.addr_rt().get(ip) or {}), "state": "failed" if ip in
                                      self._addr_rec()["ever"] else "bad", "error": Msg("addr.docker", error=str(e)[:160]),
                                      "at": time.time()}
        want = {f"{ADDR_NET_PREFIX}{k}" for k in slots.values()}
        for name in nets:
            if name not in want:
                self._net_drop(t, name, name in attached)
        self._addr_nets = (key, time.time(), out)
        return out

    @staticmethod
    def _ct_default(t: system.Target) -> str:
        p = t.ns(["ip", "-j", "-4", "route", "show", "default"], check=False)
        try:
            return ",".join(f"{r.get('dev')}/{r.get('gateway')}" for r in json.loads(p.stdout or "[]"))
        except ValueError:
            return ""

    @staticmethod
    def _ct_iface(t: system.Target, ip: str | None) -> str | None:
        if not ip:
            return None
        p = t.ns(["ip", "-j", "-4", "addr", "show"], check=False)
        try:
            for x in json.loads(p.stdout or "[]"):
                if any(a.get("local") == ip for a in x.get("addr_info") or []):
                    return x.get("ifname")
        except ValueError:
            pass
        return None

    @staticmethod
    def _net_drop(t: system.Target, name: str, connected: bool) -> None:
        """Отключить сеть панели от контейнера сервера и удалить её (с другими контейнерами — останется)."""
        try:
            if connected:
                system.docker_api("POST", f"/networks/{name}/disconnect", body={"Container": t.name, "Force": True})
            system.docker_api("DELETE", f"/networks/{name}")
        except (OSError, system.SysError) as e:
            log.info("Docker network %s: %s", name, e)

    # ------------------------------------------------------------------ удаление панели
    def remove_own_addrs(self) -> list[str]:
        """`awg-router uninstall`: убрать из системы адреса, которые добавила панель, и её сети Docker (отключив от
        контейнеров). Адреса, добавленные человеком, — не трогает. → что убрано (для вывода)."""
        done = []
        r = self._addr_rec()
        host = self._host_v4()
        for ip, dev in sorted(r["ours"].items()):
            if ip in host and host[ip]["dev"] == dev:
                self._addr_del(ip, dev)
                done.append(ip)
        r["ours"].clear()
        self._addr_save()
        if not config.DRY_RUN and os.path.exists(config.DOCKER_SOCK):
            import urllib.parse
            flt = urllib.parse.quote(json.dumps({"label": [ADDR_NET_LABEL]}))
            try:
                for n in system.docker_get(f"/networks?filters={flt}") or []:
                    full = system.docker_get(f"/networks/{n.get('Id')}") or {}
                    for cid in (full.get("Containers") or {}):
                        system.docker_api("POST", f"/networks/{n['Id']}/disconnect", body={"Container": cid, "Force": True})
                    system.docker_api("DELETE", f"/networks/{n['Id']}")
                    done.append(n.get("Name") or "")
            except (OSError, system.SysError) as e:
                log.warning("Docker networks: %s", e)
        return done

    # ------------------------------------------------------------------ свои соединения сервера
    def own_src(self, want: str) -> str | None:
        """Адрес для своих соединений сервера («С какого адреса выходит сам сервер»): выбранный, если он работает и есть
        в системе, иначе None — адрес системы (не блок: без обновлений и сертификата сервер оставлять нельзя)."""
        if not want or not self.addr_ok(want):
            return None
        if config.DRY_RUN:
            return want
        return want if want in self._host_v4() else None
