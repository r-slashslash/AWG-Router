"""Обработчик правил по доменам (sniproxy.py): его настройки, запуск, присмотр раз в секунду, разбор QUIC по
имени сайта (метки выходов), счётчики трафика по сайтам."""
from __future__ import annotations

import ipaddress
import json
import os
import signal
import subprocess
import time

from .. import config, domains, lists, nftgen, shaping, system
from ..i18n import Msg
from .common import APP_DIR, LOG_DIR, RUN_DIR, HelperRT, _sha, _trim_log, log, server_ifaces

SNIPROXY = os.path.join(APP_DIR, "sniproxy.py")
SNI_CONF = os.path.join(RUN_DIR, "sni.json")
SNI_STATS = os.path.join(RUN_DIR, "sni-stats.json")
SNI_BEAT = os.path.join(RUN_DIR, "sni-beat")      # пульс sniproxy.py: mtime обновляется раз в секунду
SNI_WATCH_EVERY = 1                               # как часто панель смотрит на sniproxy.py, с
SNI_HANG = 15                                     # пульса нет дольше — цикл событий стоит


class SniMixin:
    """Правила по доменам: sniproxy.py и QUIC по имени (часть Engine)."""

    def _watch_sni(self) -> None:
        """Присмотр за sniproxy.py раз в секунду (а не раз в RECONCILE_INTERVAL): процесс завершился
        или его цикл событий стоит дольше SNI_HANG (не обновляет файл пульса) — сразу новый проход,
        который его перезапустит. Пока посредника нет, перенаправленные к нему соединения клиентов
        с правилами по доменам получают отказ."""
        while not self.stop_ev.wait(SNI_WATCH_EVERY):
            d = self.sni
            if not d or config.DRY_RUN:
                continue
            if d.proc.poll() is None and not self._sni_hung():
                continue
            if d.proc.poll() is None:
                log.warning("sniproxy: no heartbeat for %ss, killing", SNI_HANG)
                d.proc.kill()
            self.wake.set()

    def sni_stats(self) -> dict:
        """Счётчики sniproxy.py текущего процесса ({} — нет или чужие)."""
        if not self.sni:
            return {}
        try:
            with open(SNI_STATS) as f:
                s = json.load(f)
        except (OSError, ValueError):
            return {}
        return s if s.get("pid") == self.sni.proc.pid else {}

    def _quic_mark(self, st: dict, out: str) -> int:
        """Метка вердикта для первого пакета QUIC к сайту из правила: выход AWG — его туннель;
        «напрямую» — метка без ip rule (основная таблица); SOCKS5 — его туннель, только если у выхода
        включён QUIC (иначе отказ: браузер сразу переходит на TCP, где прокси получит имя сайта; UDP
        через прокси часто не работает и шёл бы к адресу из DNS клиента); «блок» — отказ.
        Неработающий выход — его резерв, как у TCP."""
        eff = self.resolve(out, st)
        if eff == "direct":
            return config.QUIC_DIRECT_MARK
        if isinstance(eff, int):
            u = next((x for x in st["upstreams"] if x.get("num") == int(eff)), None)
            try:
                if u and (self.parsed(u).kind != "socks5" or u.get("quic")):
                    return nftgen.mark_for(int(eff))
            except Exception:  # noqa: BLE001
                pass
        return config.MARK_BLOCK

    # ---------------------------------------------- правила по доменам (sniproxy.py)
    def tunnel_addr(self, t: system.Target, iface: str | None = None) -> tuple[str, str] | None:
        """Адрес сервера в туннеле (на нём слушает sniproxy.py) и подсеть клиентов."""
        ifn = iface or t.iface
        if config.DRY_RUN:
            return ("10.8.2.1", "10.8.2.0/24") if ifn == "wg0" and t.iface != "wg0" else ("10.8.1.1", "10.8.1.0/24")
        p = t.ns(["ip", "-j", "-4", "addr", "show", "dev", ifn], check=False)
        try:
            for x in json.loads(p.stdout or "[]"):
                for a in x.get("addr_info") or []:
                    if a.get("family") == "inet" and a.get("local"):
                        net = ipaddress.ip_interface(f'{a["local"]}/{a.get("prefixlen", 24)}').network
                        return a["local"], str(net)
        except (ValueError, TypeError):
            pass
        return None

    def tunnel_addrs(self, t: system.Target) -> list[tuple[str, str]]:
        """Адреса и подсети всех активных интерфейсов WireGuard сервера."""
        out = []
        for ifn in server_ifaces(t):
            la = self.tunnel_addr(t) if ifn == t.iface else self.tunnel_addr(t, ifn)
            if la:
                out.append(la)
        return out

    def _sni_target(self, st: dict, out: str) -> dict:
        """Куда sniproxy.py ведёт соединение с совпавшим доменом: выход SOCKS5 — командой CONNECT
        с именем сайта; выход AWG и «напрямую» — к исходному адресу с меткой выхода (адрес клиент
        получил из своего DNS); «блок» — соединение закрывается. Неработающий выход — его резерв."""
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
        cmds = []
        for ifn in server_ifaces(t):
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
        """Процесс жив, но цикл событий стоит: файл пульса (sniproxy.py обновляет его каждую
        секунду) старше SNI_HANG. Пульса нет вовсе — посредник ещё не дошёл до цикла."""
        d = self.sni
        if not d or time.time() - d.started < SNI_HANG:
            return False
        try:
            return time.time() - os.stat(SNI_BEAT).st_mtime > SNI_HANG
        except OSError:
            return time.time() - d.started > SNI_HANG * 4

    def _sync_sni(self, t: system.Target, st: dict) -> int | None:
        """Держит sniproxy.py запущенным, пока в правилах есть списки доменов.
        → порт для nftables или None (правила по доменам сейчас не действуют)."""
        gp, cps = self._policies(st)
        up_nums = {u["num"] for u in self._up_list(st)}
        policies, client_map = nftgen.layout(gp, cps, up_nums, self.bal_nums)
        marks = nftgen.sniff_marks(policies, self._sniff_slots)
        if not marks:
            self._stop_sni()
            self.sni_state = None
            return None
        addrs = self.tunnel_addrs(t)
        if not addrs:
            self._stop_sni()
            self.sni_state = {"state": "error", "error": Msg("sni.no_addr", iface=t.iface)}
            return None
        listen, net = addrs[0]
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
        cfg = {"listen": listen, "listen_addrs": [ip for ip, _ in addrs],
               "port": config.SNI_PROXY_PORT, "clients": net, "clients_nets": [n for _, n in addrs],
               "stats": SNI_STATS, "beat": SNI_BEAT,
               "lists": files, "cidrs": cidrs, "rates": rates, "shared": shared,
               "client_policy": {ip: n for ip, n in client_map.items() if n in marks},
               "quic": {"queue": config.QUIC_QUEUE, "pass": config.QUIC_PASS_MARK, "block": config.MARK_BLOCK},
               "policies": {n: {"mark": m, "rules": [{"lists": l, "to": self._sni_target(st, o),
                                                      "qmark": self._quic_mark(st, o)}
                                                     for l, o in policies[n]["domain"]],
                                "acct": acct(policies[n])}
                            for n, m in marks.items()}}
        mt = {lid: os.path.getmtime(p) if os.path.exists(p) else 0 for lid, p in {**files, **cidrs}.items()}
        h = _sha(json.dumps([cfg, mt], sort_keys=True))
        key = f"{t.key}|{'|'.join(ip for ip, _ in addrs)}|{config.SNI_PROXY_PORT}"
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
            wait = 60 - (time.time() - self._sni_retry)
            if wait > 0:
                # посредник недавно уже запускали и он остановился: следующая попытка позже
                # (ошибку запуска с подробностями не затираем)
                if not (self.sni_state and self.sni_state.get("state") == "error"
                        and getattr(self.sni_state.get("error"), "key", "") != "sni.restart_wait"):
                    self.sni_state = {"state": "error", "listen": listen,
                                      "error": Msg("sni.restart_wait", s=max(1, round(wait)))}
                return None
            self._sni_retry = time.time()
            # пульс прошлого процесса устарел: с ним присмотр убил бы новый посредник через SNI_HANG,
            # если разбор больших списков при запуске дольше (без файла — только через SNI_HANG × 4)
            try:
                os.unlink(SNI_BEAT)
            except OSError:
                pass
            logp = os.path.join(LOG_DIR, "sniproxy.log")
            _trim_log(logp)
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

    def sni_view(self) -> dict | None:
        """Для интерфейса: состояние и счётчики sniproxy.py."""
        if not self.sni_state:
            return None
        v = dict(self.sni_state)
        v["strict"] = self.strict_on
        if self.sni and not config.DRY_RUN:
            s = self.sni_stats()
            v.update({k: s.get(k) for k in ("conns", "active", "matched", "errors", "by_list", "quic_matched")})
            # QUIC по имени: on — работает; иначе QUIC у этих клиентов блокируется, как раньше
            v["quic"] = "off" if self._quic_nft is False else ("on" if s.get("quic") == "on" else s.get("quic"))
        elif config.DRY_RUN:
            v["quic"] = "on"
        return v
