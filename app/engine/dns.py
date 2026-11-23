"""DNS на сервере (dnsproxy.py): куда идут запросы клиентов (выход клиента, выход правила по доменам),
запуск и присмотр."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time

from .. import config, countries, domains, nftgen, system
from ..i18n import Msg
from ..users import client_dns, dns_encrypt
from .common import APP_DIR, DNS_PORT, LOG_DIR, RUN_DIR, HelperRT, _sha, _trim_log

DNSPROXY = os.path.join(APP_DIR, "dnsproxy.py")
DNS_CONF = os.path.join(RUN_DIR, "dns.json")
DNS_STATS = os.path.join(RUN_DIR, "dns-stats.json")


class DnsMixin:
    """DNS на сервере: dnsproxy.py (часть Engine)."""

    # ------------------------------------------------------ DNS для клиентов
    def dns_routes(self, st: dict) -> tuple[dict | None, dict]:
        """Путь запросов DNS: основной выход политики клиента (с резервированием, как у его
        трафика). → (путь по умолчанию, {IP клиента: путь}) — только отличающиеся от общего.
        Путь — {"mark", "tcp"} (метка выхода; через SOCKS5 — по TCP) или None — блок. Выход,
        которого сейчас нет среди запущенных, — тоже блок: метка без правила ip rule ушла бы
        напрямую."""
        gp, cps = self._policies(st)
        route = self._dns_route_fn(st)
        default = route(gp["default"])
        routes = {}
        for ip, pol in cps.items():
            r = route(pol["default"])
            if r != default:
                routes[ip] = r
        return default, routes

    def _dns_route_fn(self, st: dict):
        """Выход после resolve → путь запроса DNS: {"mark", "tcp"} или None (блок; выход не запущен —
        тоже: метка без правила ip rule ушла бы напрямую)."""
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
        return route

    def dns_domains(self, st: dict, with_set: bool) -> dict:
        """Правила по доменам для dnsproxy.py: имя из правила разбирается через выход правила.
        → {"lists": {id: файл}, "policies": {имя: [[списки, путь|None]]}, "clients": {IP: имя},
        "set": [таблица, набор] | None}. Путь None — обычным путём клиента (правило «блок», выход
        не работает, но без местного DNS: имя не должно уйти мимо выхода) и в набор адресов (with_set — режим
        «фильтр по DNS»).
        Имена политик — из nftgen.layout, как у nftables и sniproxy.py."""
        gp, cps = self._policies(st)
        up_nums = {u["num"] for u in self._up_list(st)}
        policies, client_map = nftgen.layout(gp, cps, up_nums, self.bal_nums)
        route = self._dns_route_fn(st)
        pols = {}
        for n, p in policies.items():
            rules = []
            if p.get("dns"):
                # со своим DNS — все правила по сайтам по порядку: [списки, путь|None, серверы, в набор?].
                # «В набор» — только правила, по которым nftables ведёт адреса в sniproxy.py (p["domain"]):
                # адрес правила, выброшенного там, в наборе увёл бы соединение в обработчик без правила
                in_dom = {tuple(l) for l, _ in p.get("domain") or ()}
                for lids, o, servers in p["dns"]:
                    eff = self.resolve(o, st)
                    r = route(eff) if eff != "block" else None
                    rules.append([list(lids), r, list(servers), with_set and tuple(lids) in in_dom])
            else:
                for lids, o in p.get("domain") or ():
                    eff = self.resolve(o, st)
                    r = route(eff) if eff != "block" else None
                    # и без пути (выход подключается, лежит, «блок»): dnsproxy.py должен знать, что имя — из
                    # правила, иначе спросил бы его у местного DNS «напрямую» мимо выхода (direct_fallback)
                    rules.append([list(lids), r])
            if rules:
                pols[n] = rules
        lids = sorted({lid for rules in pols.values() for rule in rules for lid in rule[0]})
        # все клиенты со своей политикой, а не только с правилами по доменам: клиента, которого здесь
        # нет, dnsproxy.py считает клиентом общей политики и разбирал бы имена через её выходы
        return {"lists": {lid: domains.path_for(lid) for lid in lids}, "policies": pols,
                "clients": dict(client_map),
                "set": [config.NFT_TABLE, nftgen.DOM_SET] if with_set and pols else None}

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
        addrs = self.tunnel_addrs(t)
        if not addrs:
            self._stop_dns()
            self.dns_state = {"state": "error", "error": Msg("dns.no_addr", iface=t.iface)}
            return
        listen, net = addrs[0]
        if config.DRY_RUN:
            self.dns_state = {"state": "on", "listen": listen, "encrypt": dns_encrypt(st["settings"])}
            return
        default, routes = self.dns_routes(st)
        dom = self.dns_domains(st, self.dom_filter(st))
        enc = dns_encrypt(st["settings"])
        cfg = {"listen": listen, "listen_addrs": [ip for ip, _ in addrs],
               "port": DNS_PORT, "clients": net, "clients_nets": [n for _, n in addrs],
               "stats": DNS_STATS,
               "upstreams": client_dns(st["settings"]), "encrypt": enc,
               "default": default, "routes": routes, "dom": dom,
               # запасной DNS для пути «напрямую»: шифрованный DNS из России, Китая и Ирана часто не проходит, а
               # клиенты, которые идут напрямую, и так идут через провайдера сервера (countries.local_dns)
               "direct_fallback": countries.local_dns(getattr(self, "public_cc", None)) if enc != "plain" else []}
        mt = {p: os.path.getmtime(p) if os.path.exists(p) else 0 for p in dom["lists"].values()}
        h = _sha(json.dumps([cfg, mt], sort_keys=True))
        key = f"{t.key}|{'|'.join(ip for ip, _ in addrs)}"
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
            _trim_log(logp)
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

    def dns_listen(self) -> str | None:
        """Адрес, на котором сейчас слушает DNS на сервере (None — выключен или не запустился)."""
        d = self.dns_state or {}
        return d.get("listen") if d.get("state") == "on" else None

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
                    # шифрованный DNS не отвечает на пути «напрямую» (последняя попытка — неудачная, за 15 минут):
                    # клиентам, которые идут напрямую, имена ищет местный DNS или (без него) никто
                    fail_at = float(s.get("direct_fail_at") or 0)
                    if fail_at > float(s.get("direct_ok_at") or 0) and time.time() - fail_at < 900 \
                            and s.get("encrypt") != "plain":         # без шифрования совет «выберите его» ни к чему
                        v["direct_down"] = {"fallback": [str(x) for x in s.get("fallback") or []][:2]}
            except (OSError, ValueError):
                pass
        return v
