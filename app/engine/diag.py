"""Проверки по запросу: путь панели через выход (own_route), разбор имени как у клиента, проверка выхода
(probe.py) и «Проверка маршрута» (trace)."""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys

from .. import awgconf, config, nftgen, srcaddr, system
from ..i18n import Msg
from ..store import Store
from .common import APP_DIR

PROBE = os.path.join(APP_DIR, "probe.py")
PROBE_HOSTS = ("ipinfo.io", "ifconfig.me")      # те же имена, что в probe.py


class DiagMixin:
    """Проверка выхода и маршрута (часть Engine)."""

    # ---------------------------------------------------------------- tools
    def own_route(self, out: str, direct: bool = True) -> tuple[int, int] | None:
        """Путь для собственных запросов панели (Telegram, списки): None — напрямую из панели,
        (PID, fwmark) — через туннель выхода в сети сервера AWG. Выход выбирается так же,
        как для клиентов: не работает — его резервный выход. direct=False (Telegram, 1.23.0): выбранный выход
        не уводит запрос напрямую и резервом «Напрямую» — такой выход считается неработающим."""
        st = self.store.snapshot()
        if (out == "direct" and not srcaddr.main(st)) or config.DRY_RUN:
            return None
        name = (Store.upstream(st, out[3:]) or {}).get("name", out) \
            if out.startswith("up:") else srcaddr.split(out)[1] or out
        eff = self.resolve(out, st)
        if isinstance(eff, nftgen.Addr):
            # «Напрямую — адрес» (1.25.0): из сети сервера AWG с меткой адреса — тем же путём, что клиенты; не работает —
            # блок выше, а не адрес системы
            t = self.target
            if not t:
                raise system.SysError(Msg("tg.via_down", name=name))
            return t.pid, nftgen.addr_mark(eff.k)
        if eff == "direct":
            if not direct and not srcaddr.is_direct(out):
                raise system.SysError(Msg("tg.via_down", name=name))
            return None                 # «Напрямую» с адреса системы (выбран он сам или резерв выхода)
        if eff == "block":
            raise system.SysError(Msg("tg.via_blocked", name=name))
        t = self.target
        if not t or eff not in {r.num for r in self.rt.values()}:
            raise system.SysError(Msg("tg.via_down", name=name))
        return t.pid, nftgen.mark_for(eff)

    def resolve_name(self, pk: str | None, host: str) -> tuple[str, str]:
        """Адрес имени для «Проверки маршрута» — тем путём, которым пойдёт DNS клиента: через его выход
        по умолчанию (запрос к 1.1.1.1 / 8.8.8.8 с меткой выхода), а не резолвером хоста. Местный DNS в РФ,
        КНР и Иране подменяет ответы для закрытых сайтов, и проверка показывала бы путь к чужому адресу.
        → (IPv4, выход: "direct" | "up:<id>"). Блок или нет сервера — исключение (вызывающий берёт резолвер хоста)."""
        st = self.store.snapshot()
        out = self.default_out(st, pk)
        eff = self.resolve(out, st)
        t = self.target
        if config.DRY_RUN or eff == "block" or not t or not t.exists:
            raise system.SysError(Msg("tr.no_dns_path"))
        mark, via = 0, "direct"
        if isinstance(eff, nftgen.Addr):
            mark, via = nftgen.addr_mark(eff.k), str(eff)       # «Напрямую — адрес» (1.25.0)
        elif isinstance(eff, int):
            if eff not in {r.num for r in self.rt.values()}:
                raise system.SysError(Msg("tr.no_dns_path"))
            mark = nftgen.mark_for(eff)
            u = next((x for x in st["upstreams"] if x["num"] == eff), None)
            via = "up:" + u["id"] if u else "direct"
        from .notify import TGREQ
        p = subprocess.run(["nsenter", "-t", str(t.pid), "-n", "--", sys.executable, TGREQ, str(mark)],
                           input=json.dumps({"dns": host}).encode() + b"\n", capture_output=True, timeout=20)
        try:
            ips = json.loads(p.stdout.decode(errors="replace")).get("ips") or []
            ip = str(ipaddress.IPv4Address(ips[0]))
        except (ValueError, IndexError, TypeError, AttributeError):
            raise system.SysError(Msg("tr.no_dns_path")) from None
        return ip, via

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
        mark = 0 if eff == "direct" else nftgen.addr_mark(eff.k) if isinstance(eff, nftgen.Addr) else nftgen.mark_for(eff)
        # у выхода SOCKS5 ещё и UDP: пропускает ли прокси QUIC (галочка выхода)
        socks = False
        if isinstance(eff, int):
            u = next((x for x in st["upstreams"] if x.get("num") == eff), None)
            try:
                socks = bool(u) and self.parsed(u).kind == "socks5"
            except Exception:  # noqa: BLE001
                pass
        if config.DRY_RUN:
            if isinstance(eff, nftgen.Addr):
                return {"ok": True, "ip": eff.ip, "cc": "DE", "latency_ms": 30, "via": eff}
            res = {"ok": True, "ip": "203.0.113.%d" % (10 + (eff if eff != "direct" else 0)),
                   "cc": "NL" if eff != "direct" else "RU", "latency_ms": 42, "via": eff}
            return {**res, "udp": False} if socks else res
        # имена разбираем в сети панели — в сети контейнера может не быть DNS
        hosts = [f"{h}={ip}" for h, ip in awgconf.resolve_many(PROBE_HOSTS, 4).items()]
        p = t.ns(["python3", PROBE, str(mark), *(["--udp"] if socks else []), *hosts],
                 check=False, timeout=35)
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
        def out_of(r: dict) -> str:
            """Выход правила для клиента; с балансировкой (1.24.0) — шаг «балансировка в правиле: выход …»."""
            out, _ = self.rule_out(st, r, pk, pol.get("own", False))
            if r.get("balance"):
                steps.append(Msg("tr.rule_balance" if pk else "tr.rule_balance_new",
                                 exit=(Store.upstream(st, out[3:]) or {}).get("name", out) if out.startswith("up:")
                                 else Msg("out." + out)))
            return out
        for r in pol["rules"] if name and sni_on else []:
            for lid in r["lists"]:
                dom = self.domain_matcher.match(lid, name) if lid in dl else None
                if dom:
                    steps.append(Msg("tr.match_domain", list=lid, domain=dom))
                    out = out_of(r)
                    return {"result": out, "effective": self.resolve(out, st), "steps": steps,
                            "rule": r.get("comment") or r["id"], "domain": dom}
        for r in pol["rules"]:
            for lid in r["lists"]:
                if lid in dl:
                    continue
                hit = self.matcher.contains(lid, ip)
                if hit:
                    steps.append(Msg("tr.match", list=lid, net=hit))
                    out = out_of(r)
                    return {"result": out, "effective": self.resolve(out, st), "steps": steps,
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
