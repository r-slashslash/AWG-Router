"""Куда идёт трафик: выход клиента и резервы (resolve), балансировка, политики для nftables (build_ruleset),
ip rule и маршруты таблиц выходов, sysctl."""
from __future__ import annotations

import json
import time

from .. import config, nftgen, shaping, system
from ..i18n import Msg
from ..store import Store
from .common import server_ifaces

ROUTES_EVERY = 60                                # маршруты таблиц выходов ставятся заново не реже, с


class RoutesMixin:
    """Маршрутизация: решения и правила nftables / ip rule (часть Engine)."""

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
            known = u["id"] in self.health     # нет записи: проверки ещё не было (первый проход после запуска панели)
            h = self.health.get(u["id"], {})
            if u.get("enabled", True) and h.get("healthy"):
                if not self.over_quota(u):
                    return u["num"]
                return self.resolve(self.quota_target(u), st, depth + 1)
            if u.get("enabled", True) and (not known or h.get("state") == "connecting"):
                # выход только что запущен и ещё не ответил (запуск и обновление панели, перезапуск сервера, правка
                # выхода): обычно это доли секунды — блок, а не резерв, иначе с резервом «Напрямую» клиенты до
                # следующего прохода шли бы мимо выхода. Не ответил за CONNECTING_SECS — резерв, как раньше.
                # Выход без записи — тоже блок: правила до запуска туннелей (_hold_rules) ставятся раньше первой
                # проверки, и с резервом «Напрямую» после запуска панели клиенты 1–2 с шли мимо выхода
                return "block"
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

    @staticmethod
    def domain_lists(st: dict) -> set[str]:
        return {l["id"] for l in st["lists"] if l.get("kind") == "domains"}

    def _policies(self, st: dict) -> tuple[dict, dict]:
        """Общая и личные политики для nftables и sniproxy.py: правила по адресам — с выходом
        после резолва; правила со списками доменов — отдельно (их выход резолвит sniproxy-конфиг)."""
        dl = self.domain_lists(st)

        def conv(pol: dict, pk: str | None) -> dict:
            ip_rules, dom, dns = [], [], []
            for r in pol["rules"]:
                if any(lid in dl for lid in r["lists"]):
                    dom.append(([lid for lid in r["lists"] if lid in dl], r["outbound"]))
                    dns.append((dom[-1][0], r["outbound"], list(r.get("dns") or ())))
                else:
                    ip_rules.append((r["lists"], self.resolve(r["outbound"], st)))
            default = self.resolve(self.default_out(st, pk, pol), st)
            # правила по доменам, которые ведут туда же, куда всё остальное, ничего не меняют —
            # но включили бы перехват всего HTTPS/HTTP клиента посредником. Только если и правила по
            # адресам ведут туда же: домен проверяется раньше них и мог бы увести сайт мимо правила по
            # адресу. Так готовые правила страны на новой установке («всё — напрямую») не включают перехват
            plain = int(default) if isinstance(default, int) else default
            if dom and all(self.resolve(o, st) == plain for _, o in dom) and all(o == plain for _, o in ip_rules):
                dom = []
            if pol.get("balanced") and isinstance(default, int) and default in self.bal_nums:
                default = nftgen.Sticky(default)     # открытые соединения не переезжают
            # «dns» — все правила по сайтам по порядку со своим DNS (engine/dns.py), только если он у кого-то
            # задан; не выбрасываются вместе с dom выше: правило, ведущее туда же, нужно ради своего DNS
            return {"rules": ip_rules, "default": default, "domain": dom,
                    "dns": dns if any(x[2] for x in dns) else []}

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
                # QUIC через SOCKS5 — только с галочкой: многие прокси без UDP, и браузер ждал бы
                # QUIC впустую, прежде чем перейти на TCP
                ups.append({"num": u["num"], "snat": pc.address, "mtu": pc.mtu,
                            "no_quic": pc.kind == "socks5" and not u.get("quic")})
        return ups

    def build_ruleset(self, t: system.Target, st: dict, sniff_port: int | None = None, quic: bool = False,
                      hold: bool = False) -> str:
        """quic — первые пакеты QUIC клиентов с правилами по доменам в очередь sniproxy.py (если
        ядро это умеет — иначе QUIC у них блокируется, как раньше). hold — как будто ни одного туннеля
        ещё нет (правила «до панели», _save_hold): трафик на выходы — в блок, «напрямую» — напрямую."""
        gp, cps = self._policies(st)
        used = {lid for p in [gp, *cps.values()] for l, _ in p["rules"] for lid in l}
        lst = {lid: self._cidrs(lid) for lid in used}
        return nftgen.generate(server_ifaces(t), lst, [] if hold else self._up_list(st), gp, cps, sniff_port,
                               frozenset() if hold else self.bal_nums,
                               dom_filter=sniff_port is not None and self.dom_filter_on(st), quic=quic,
                               strict=sniff_port is None and self.strict(st), slots=self._sniff_slots)

    @staticmethod
    def strict(st: dict) -> bool:
        """«Правила по доменам не работают — блокировать весь трафик их клиентов» (routing.strict)."""
        return bool((st.get("routing") or {}).get("strict"))

    def strict_blocked(self, st: dict, sniff: int | None) -> bool:
        """Блок из-за неработающих правил по доменам сейчас действует: галочка, есть клиенты с
        правилами по доменам, а посредника нет."""
        if sniff is not None or not self.strict(st):
            return False
        gp, cps = self._policies(st)
        return any(p.get("domain") for p in [gp, *cps.values()])

    def dom_filter(self, st: dict) -> bool:
        """Режим «фильтр по DNS» выбран (settings.dom_filter) и DNS на сервере включён."""
        s = st["settings"]
        return bool(s.get("dom_filter")) and bool(s.get("panel_dns"))

    def dom_filter_on(self, st: dict) -> bool:
        """…и DNS на сервере работает: без него набор адресов пуст, и правила по доменам не
        действовали бы совсем — тогда перехват, как без фильтра."""
        return self.dom_filter(st) and (self.dns_state or {}).get("state") == "on"

    def quic_wanted(self, sniff: int | None) -> bool:
        """Очередь QUIC в наборе правил: посредник работает и поднял её, а ядро её принимает."""
        if sniff is None or self._quic_nft is False:
            return False
        return config.DRY_RUN or (self.sni_stats().get("quic") == "on")

    # -------------------------------------------------------- ip rule/route
    def _sync_rules(self, t: system.Target, add_only: bool = False) -> None:
        """ip rule и маршруты таблиц выходов — одной командой `ip -batch` (раньше — по два процесса на выход
        каждый проход). Маршруты заново ставятся, когда изменился набор туннелей (новый туннель — новое
        время запуска) или прошло ROUTES_EVERY: исчезнуть сами они могут только вместе с интерфейсом.
        add_only — проход сразу после запуска туннелей, до правил nftables с их метками (метка без своего
        ip rule ушла бы по основной таблице, мимо выхода): только добавить недостающее. Лишнее убирается в
        конце прохода, когда новые правила nftables уже не ставят метку остановленного выхода."""
        want = {r.num: r for r in self.rt.values()}
        key = (t.key, tuple(sorted((n, r.iface, r.started) for n, r in want.items())))
        if add_only and getattr(self, "_rules_ok", None) == key:
            return              # туннели те же, что при прошлой сверке: правила и маршруты уже на месте
        lo, hi = config.RULE_PRIO_BASE + 1, config.RULE_PRIO_BASE + config.MAX_UPSTREAMS
        have = self._ip_rules(t)
        present = set()
        cmds, adds = [], []
        for rule in have:
            prio = rule.get("priority", 0)
            if not lo <= prio <= hi:
                continue
            num = prio - config.RULE_PRIO_BASE
            ok = num in want and str(rule.get("table")) == str(config.TABLE_BASE + num) and \
                int(str(rule.get("fwmark", "0")), 0) == nftgen.mark_for(num)
            if ok and num not in present:
                present.add(num)
            elif not add_only or num in want:
                # add_only не трогает правила остановленных выходов: их метку nftables ещё ставит, и без
                # правила (таблица с unreachable) она ушла бы по основной таблице
                cmds.append(f"rule del priority {prio}")
                if num not in want:
                    cmds.append(f"route flush table {config.TABLE_BASE + num}")
        for num in sorted(want):
            if num not in present:
                adds.append((num, ["rule", "add", "fwmark", hex(nftgen.mark_for(num)), "lookup",
                                   str(config.TABLE_BASE + num), "priority", str(config.RULE_PRIO_BASE + num)]))
        cmds += [" ".join(a) for _, a in adds]
        now = time.time()
        routes = key != getattr(self, "_routes_key", None) or now - getattr(self, "_routes_at", 0) >= ROUTES_EVERY
        if routes:
            for num in sorted(want):
                table = config.TABLE_BASE + num
                # Если туннель исчезнет, останется unreachable — трафик не утечёт мимо
                cmds.append(f"route replace unreachable default metric 4096 table {table}")
                cmds.append(f"route replace default dev {want[num].iface} table {table}")
        if not cmds:
            self._rules_ok = key
            return
        p = t.ns(["ip", "-force", "-batch", "-"], input="\n".join(cmds) + "\n", check=False)
        self._rules_ok = None
        if p.returncode != 0:
            # Что-то не прошло (интерфейс как раз пропал и т. п.). Маршруты — заново на следующем проходе;
            # недостающее правило — отдельной командой, и её ошибка видна, как раньше.
            self._routes_key = None
            if adds:
                got = {r.get("priority", 0) - config.RULE_PRIO_BASE for r in self._ip_rules(t)}
                for num, a in adds:
                    if num not in got:
                        t.ns(["ip", *a])
            return
        if routes:
            self._routes_key, self._routes_at = key, now
        self._rules_ok = key

    @staticmethod
    def _ip_rules(t: system.Target) -> list[dict]:
        p = t.ns(["ip", "-j", "rule", "show"], check=False)
        try:
            return json.loads(p.stdout or "[]")
        except ValueError:
            return []

    def _sysctl(self, t: system.Target) -> None:
        kvs = ["net.ipv4.ip_forward=1", "net.ipv4.conf.all.src_valid_mark=1"]
        if t.kind == "host":
            # На хосте all / default — это проверка обратного пути у всех его интерфейсов (её мог включить
            # администратор): мягкая проверка нужна только интерфейсу сервера и туннелям выходов (им она
            # ставится при запуске). Действует большее из all и своего значения, поэтому своего хватает.
            for ifn in server_ifaces(t):
                kvs.append(f"net.ipv4.conf.{ifn}.rp_filter=2")
        else:
            kvs += ["net.ipv4.conf.all.rp_filter=2", "net.ipv4.conf.default.rp_filter=2"]
        for kv in kvs:
            t.ns(["sysctl", "-qw", kv], check=False)
