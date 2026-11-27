"""Куда идёт трафик: выход клиента и резервы (resolve), балансировка, политики для nftables (build_ruleset),
ip rule и маршруты таблиц выходов, sysctl."""
from __future__ import annotations

import json
import os
import sys
import threading
import time

from .. import balance, config, nftgen, shaping, srcaddr, system
from ..i18n import Msg
from ..store import Store
from .common import RUN_DIR, log

ROUTES_EVERY = 60                                # маршруты таблиц выходов ставятся заново не реже, с
CTFLUSH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ctflush.py")


class RoutesMixin:
    """Маршрутизация: решения и правила nftables / ip rule (часть Engine)."""

    # --------------------------------------------------------------- policy
    def resolve(self, out: str, st: dict, depth: int = 0):
        """Выход из настроек → фактический: 'direct' (с адреса системы) | Addr (с дополнительного исходящего адреса,
        1.25.0) | 'block' | номер туннеля."""
        if out == "block" or (out == "direct" and not srcaddr.main(st)):
            return out                  # «Напрямую» с адреса системы — как до 1.25.0
        if srcaddr.is_direct(out):
            return self.direct_out(out, st)
        if depth > 6:
            return "block"
        if out.startswith("up:"):
            u = Store.upstream(st, out[3:])
            if not u:
                return "block"
            if u.get("enabled", True) and getattr(self, "_holding", None) == threading.get_ident():
                # правила до запуска туннелей (_hold_rules): туннелей в новой сети ещё нет, проверка выхода — о
                # прежней сети (контейнер умер посреди прохода, П17) — блок, а не резерв
                return "block"
            if u.get("enabled", True) and srcaddr.bind_of(st, u) != srcaddr.SYSTEM and not self.bind_ok(st, u):
                if self.bind_pending(st, u):
                    # адрес ещё не проверен или его путь ещё не встал (перезапуск сервера, перезагрузка, первый проход):
                    # выход «подключается» — блок, а не резерв (П12 полной проверки 1.25.0, как решения Н1 и Г1)
                    return "block"
                # адрес, с которого выход подключается к своему серверу, не работает: выход — неработающий, его резерв
                return self.resolve(u.get("fallback") or "direct", st, depth + 1)
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

    def direct_out(self, out: str, st: dict):
        """«Напрямую» (основной исходящий адрес) или «Напрямую — адрес» → 'direct' (адрес системы) | Addr | 'block':
        адрес не работает или его путь ещё не стоит (сеть Docker, ip rule, подмена адреса) — блок, а не адрес системы:
        молча с другого адреса ничего не уходит (решение владельца 2026-11-26)."""
        a = srcaddr.split(out)[1] or srcaddr.main(st) or srcaddr.SYSTEM
        if a == srcaddr.SYSTEM:
            return "direct"
        live = getattr(self, "_addr_live", None) or {}
        k = next((k for k, x in live.items() if x.get("ip") == a), None)
        if k is None or not self.addr_ok(a):
            return "block"
        return nftgen.Addr(a, k)

    def bind_ok(self, st: dict, u: dict) -> bool:
        """Выход может подключиться к своему серверу: с адреса системы — всегда, с исходящего адреса — если тот
        работает и его путь стоит (иначе туннель стучится в никуда: маршрут адреса — unreachable)."""
        b = srcaddr.bind_of(st, u)
        if b == srcaddr.SYSTEM:
            return True
        return isinstance(self.direct_out(srcaddr.PFX + b, st), nftgen.Addr)

    def bind_pending(self, st: dict, u: dict) -> bool:
        """Адрес «Подключаться с адреса» выхода ещё не сказал, работает ли: не проверялся, проверяется, или работает,
        а его путь ещё не встал. Не работает (failed, bad) — нет: тогда выход лежит, и действует его резерв."""
        b = srcaddr.bind_of(st, u)
        return b != srcaddr.SYSTEM and not self.bind_ok(st, u) and self.addr_state(b) not in ("failed", "bad")

    def exit_mark(self, st: dict, u: dict) -> int:
        """Метка внешних пакетов туннеля выхода («Подключаться с адреса»): 0 — адрес системы, иначе метка адреса."""
        b = srcaddr.bind_of(st, u)
        if b == srcaddr.SYSTEM:
            return 0
        k = self.addr_slot(b)
        if not k:                       # адресов больше, чем номеров: не бывает (srcaddr.OUT_HOSTS_MAX = ADDR_MAX)
            raise system.SysError(Msg("addr.no_slot", addr=b))
        return nftgen.addr_mark(k)

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
        rules = [r for r in rules if r.get("enabled", True) and r.get("lists")]
        return {"rules": rules,
                "default": default, "custom": bool(cp) and (
                    cp.get("rules_mode") == "custom" or cp.get("outbound", "inherit") != "inherit"),
                # выход по умолчанию — общий, и включена балансировка: выход выбирает она
                "balanced": self.balance_on(st) and cp.get("outbound", "inherit") == "inherit",
                # правило с балансировкой (1.24.0): выход правила у каждого клиента свой — нужна его политика
                "rbal": any(r.get("balance") for r in rules), "own": cp.get("rules_mode") == "custom"}

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

    # ------------------------------------------------- балансировка в правиле (1.24.0, #53)
    def rule_members(self, st: dict, r: dict) -> list[dict]:
        """Рабочие выходы балансировки правила — как balance_members, в порядке, отмеченном в правиле."""
        ids = r.get("balance") or []
        ups = [u for u in st["upstreams"] if u["id"] in ids and u["id"] in self.rt
               and self.resolve("up:" + u["id"], st) == u["num"]]
        return [{"id": u["id"], "num": u["num"], "up": shaping.mbit(u.get("rate_up")),
                 "down": shaping.mbit(u.get("rate_down"))} for u in sorted(ups, key=lambda u: ids.index(u["id"]))]

    def rule_pending(self, st: dict, ids) -> bool:
        """Среди выходов есть включённый, который ещё не ответил (только что запущен, проверки ещё не было): пока
        рабочих нет — блок, а не резерв (решение Н1 и Г1: с резервом «Напрямую» клиенты шли бы мимо выхода)."""
        return any(u["id"] in ids and u.get("enabled", True) and
                   (u["id"] not in self.health or self.health[u["id"]].get("state") == "connecting"
                    or self.bind_pending(st, u))
                   for u in st["upstreams"])

    @staticmethod
    def rule_group(r: dict, pk: str | None, own: bool) -> str:
        """Ключ балансировки правила: общее правило — его id, своё правило клиента — «клиент|id»."""
        return f"{pk}|{r['id']}" if own else r["id"]

    def rule_used(self, r: dict, pk: str | None, own: bool) -> int:
        """Трафик правила за месяц (оба направления) для его лимита: общее правило — по всем клиентам с общими
        правилами, своё правило клиента — только его."""
        if own and pk:
            return sum(self.traffic.client_rules(pk).get(r["id"]) or [0, 0])
        return self.traffic.rule_used(r["id"])

    def rule_over(self, r: dict, pk: str | None, own: bool) -> bool:
        """Месячный лимит правила исчерпан (1.24.0), и его трафик должен уйти по quota_action (не «только сообщить»)."""
        q = r.get("quota")
        return bool(q) and (r.get("quota_action") or "notify") != "notify" and self.rule_used(r, pk, own) >= q

    def rule_out(self, st: dict, r: dict, pk: str | None, own: bool = False) -> tuple[str, bool]:
        """Выход правила для клиента в терминах настроек и «держать открытые соединения на выходе» (Sticky). С
        балансировкой — назначенный ей выход; рабочих выходов нет — резерв правила (balance_fb), а пока какой-то из
        отмеченных выходов только подключается — блок. Лимит правила исчерпан — его quota_action до нового месяца."""
        if self.rule_over(r, pk, own):
            return r["quota_action"], False
        if not r.get("balance"):
            return r["outbound"], False
        g = self.rule_group(r, pk, own)
        uid = ((getattr(self, "rbal_plan", None) or {}).get(g) or {}).get(pk) if pk else \
            (getattr(self, "rbal_new", None) or {}).get(g)
        if uid and uid in r["balance"] and Store.upstream(st, uid):
            return "up:" + uid, True
        if self.rule_pending(st, r["balance"]):
            return "block", False
        return r.get("balance_fb") or "block", False

    def _balance_rules(self, st: dict, now: float) -> None:
        """Распределение клиентов правил с балансировкой. У каждого правила (у своего правила клиента — у пары
        «клиент, правило») свой Balancer: клиенты — те, кто идёт по этому правилу, скорость клиента — его трафик по
        правилу (учёт по правилам), загрузка выхода — весь трафик выхода (из основной балансировки)."""
        ips = {c["public_key"] for c in self.clients if c.get("ip")}
        own = {pk for pk, cp in st["clients"].items() if cp.get("rules_mode") == "custom"}
        general = sorted(pk for pk in ips if pk not in own)
        groups = {}
        for r in st["routing"]["rules"]:
            if r.get("balance") and r.get("enabled", True) and r.get("lists"):
                groups[r["id"]] = (r, general)
        for pk in sorted(own & ips):
            for r in st["clients"][pk].get("rules") or []:
                if r.get("balance") and r.get("enabled", True) and r.get("lists"):
                    groups[self.rule_group(r, pk, True)] = (r, [pk])
        recent = self.traffic.take_recent_rules()
        old = getattr(self, "rbal", None) or {}
        self.rbal, plans, news, nums = {}, {}, {}, set()
        for g, (r, pks) in groups.items():
            b = old.get(g) or balance.Balancer()
            b.exit_rate = self.balancer.exit_rate
            b.feed_clients({(b.assign.get(pk), pk): d for (rid, pk), d in recent.items()
                            if rid == r["id"] and pk in pks}, now)
            members = self.rule_members(st, r)
            plans[g], news[g] = b.plan(members, pks, now), b.pick(members)
            nums |= {m["num"] for m in members}
            self.rbal[g] = b
            mv = b.last_move
            if mv and mv.get("logged") is None:
                mv["logged"] = True
                name = lambda uid: (Store.upstream(st, uid) or {}).get("name", uid)
                c = next((x for x in self.clients if x["public_key"] == mv["pk"]), {})
                self.event("info", Msg("ev.rule_balance_move", client=c.get("name") or c.get("ip") or mv["pk"][:8],
                                       rule=r.get("comment") or ", ".join(r.get("lists") or []),
                                       **{"from": name(mv["from"])}, to=name(mv["to"])))
        self.rbal_plan, self.rbal_new, self.rbal_nums = plans, news, nums

    def sticky_nums(self) -> set[int]:
        """Выходы, у которых открытые соединения держатся на выходе (Sticky): рабочие выходы основной балансировки и
        балансировок в правилах. Одинаково для nftables, sniproxy.py и DNS на сервере (nftgen.layout)."""
        return set(self.bal_nums) | set(getattr(self, "rbal_nums", None) or ())

    def _balance(self, st: dict) -> None:
        try:
            self._balance_rules(st, time.time())
        except Exception:  # noqa: BLE001  — без распределения правила идут на свой резерв, остальное как обычно
            log.exception("rule balance")
            self.rbal, self.rbal_plan, self.rbal_new, self.rbal_nums = {}, {}, {}, set()
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
            # рабочих выходов балансировки нет, а какой-то из отмеченных только подключается (запуск панели, проверки ещё
            # не было): блок, а не запасной выход — с запасным «Напрямую» клиенты шли бы мимо выходов (решения Н1, Г1)
            skip = set((st["routing"].get("balance") or {}).get("skip") or [])
            if self.rule_pending(st, {u["id"] for u in st["upstreams"] if u["id"] not in skip}):
                return "block"
        return pol["default"]

    @staticmethod
    def domain_lists(st: dict) -> set[str]:
        return {l["id"] for l in st["lists"] if l.get("kind") == "domains"}

    def labels_on(self) -> bool:
        """Учёт трафика по правилам (1.24.0) действует: ядро цели приняло метки соединений (_probe_labels)."""
        return getattr(self, "_labels", None) is True

    def _probe_labels(self, t: system.Target) -> bool:
        """Умеет ли ядро цели метки соединений (ct label) и наборы с номером правила: `nft -c` — проверка ядром без
        применения. Нет (OpenVZ/LXC, урезанные сборки) — учёта по правилам нет, остальное работает как раньше."""
        if config.DRY_RUN:
            return True
        path = os.path.join(RUN_DIR, "labels-probe.nft")
        with open(path, "w") as f:
            f.write("table ip awgr_probe {\n\tset s {\n\t\ttype ipv4_addr . mark\n\t\tflags dynamic\n\t}\n"
                    "\tchain c {\n\t\tct label set 1\n\t\tct label 1 update @s { ip saddr . 0x1 counter }\n\t}\n}\n")
        p = t.ns(["nft", "-c", "-f", path], check=False, timeout=30)
        if p.returncode != 0:
            log.info("rule traffic: no conntrack labels here: %s", (p.stderr or p.stdout or "").strip()[-200:])
        return p.returncode == 0

    def limits_on(self) -> bool:
        """Ограничение скорости правил (1.24.0) действует: метки соединений есть, а ядро не отказало в «limit»."""
        return self.labels_on() and getattr(self, "_rlim_ok", None) is not False

    def rule_limits(self, st: dict) -> dict[str, tuple[int, float | None, float | None]]:
        """Ограничения скорости правил: {ключ правила (rule_group): (номер j, к клиентам, от клиентов — Мбит/с)}.
        Номер у правила тот же, пока оно с ограничением (_rlim_ids между проходами): метка j остаётся на открытых
        соединениях, и новое правило на освободившемся номере ограничивало бы их чужим пределом. Номер ушедшего правила
        занимается снова не раньше следующего прохода. Больше RULE_LIM_MAX правил — у лишних ограничения нет."""
        if not self.limits_on():
            return {}
        want: list[tuple[str, float | None, float | None]] = []

        def add(key: str, r: dict) -> None:
            d, u = shaping.mbit(r.get("rate_down")), shaping.mbit(r.get("rate_up"))
            if (d or u) and r.get("enabled", True) and r.get("lists"):
                want.append((key, d, u))
        for r in st["routing"]["rules"]:
            if r.get("id"):
                add(r["id"], r)
        for pk in sorted(c["public_key"] for c in self.clients if c.get("ip")):
            cp = st["clients"].get(pk) or {}
            if cp.get("rules_mode") == "custom":
                for r in cp.get("rules") or []:
                    if r.get("id"):
                        add(f"{pk}|{r['id']}", r)
        prev = getattr(self, "_rlim_ids", None)
        if prev is None:
            prev = self._rlim_ids = {}
        busy = set(prev.values())
        ids = {k: prev[k] for k, _, _ in want if k in prev}
        # новые номера — по кругу, с места после последнего выданного: освободившийся номер снова выдаётся не скоро, а
        # открытые соединения ушедшего правила (метки соединения не снимаются) не попадают под чужой предел
        start, lost = getattr(self, "_rlim_next", 0), 0
        out = {}
        for k, d, u in want:
            if k not in ids:
                j = next((x for x in ((start + n) % config.RULE_LIM_MAX for n in range(config.RULE_LIM_MAX))
                          if x not in busy), None)
                if j is None:
                    lost += 1
                    continue
                ids[k] = j
                busy.add(j)
                start = (j + 1) % config.RULE_LIM_MAX
            out[k] = (ids[k], d, u)
        self._rlim_next = start
        if lost and not getattr(self, "_rlim_full", False):
            # больше RULE_LIM_MAX ограничений (свои правила многих клиентов): у лишних ограничения нет — сказать один раз
            self.event("warn", Msg("ev.rlim_full", n=lost, max=config.RULE_LIM_MAX))
        self._rlim_full = bool(lost)
        prev.clear()
        prev.update(ids)
        return out

    def _policies(self, st: dict, labels: bool | None = None) -> tuple[dict, dict]:
        """Общая и личные политики для nftables и sniproxy.py: правила по адресам — с выходом
        после резолва; правила со списками доменов — отдельно (их выход резолвит sniproxy-конфиг).
        labels (по умолчанию — labels_on): у политики номера её правил (slots — у правил по адресам, dslots — по
        доменам; номер — место правила среди включённых правил клиента) для учёта трафика по правилам.
        В проходе (reconcile, после балансировки) — один раз на набор входов: посредник, DNS и правила спрашивали их
        3–4 раза (проверка 1.25.0); правила «до панели» (_holding) — всегда заново."""
        if labels is None:
            labels = self.labels_on()
        memo, key = getattr(self, "_pol_memo", None), None
        if memo and memo["st"] is st and memo["tid"] == threading.get_ident() \
                and getattr(self, "_holding", None) is None:
            key = (labels, self.limits_on())
            if key in memo["v"]:
                return memo["v"][key]
        dl = self.domain_lists(st)
        rl = self.rule_limits(st) if labels else {}

        def conv(pol: dict, pk: str | None) -> dict:
            ip_rules, dom, dns, slots, dslots, lims, dlims = [], [], [], [], [], [], []
            keep = False          # правило по сайтам с ограничением скорости или лимитом: посредник нужен, чтобы их считать
            for k, r in enumerate(pol["rules"]):
                own = pol.get("own", False)
                out, sticky = self.rule_out(st, r, pk, own)
                lim = rl.get(self.rule_group(r, pk, own) if r.get("id") else "", (None,))[0]
                if any(lid in dl for lid in r["lists"]):
                    dom.append(([lid for lid in r["lists"] if lid in dl], out))
                    dns.append((dom[-1][0], out, list(r.get("dns") or ())))
                    dslots.append(k)
                    dlims.append(lim)
                    keep = keep or lim is not None or bool(labels and r.get("quota"))
                else:
                    eff = self.resolve(out, st)
                    # балансировка в правиле: соединение держится на выходе, пока тот среди рабочих (как у «По умолчанию»)
                    ip_rules.append((r["lists"], nftgen.Sticky(eff) if sticky and isinstance(eff, int)
                                     and eff in (getattr(self, "rbal_nums", None) or ()) else eff))
                    slots.append(k)
                    lims.append(lim)
            default = self.resolve(self.default_out(st, pk, pol), st)
            # правила по доменам, которые ведут туда же, куда всё остальное, ничего не меняют —
            # но включили бы перехват всего HTTPS/HTTP клиента посредником. Только если и правила по
            # адресам ведут туда же: домен проверяется раньше них и мог бы увести сайт мимо правила по
            # адресу. Так готовые правила страны на новой установке («всё — напрямую») не включают перехват
            plain = int(default) if isinstance(default, int) else default
            if dom and not keep and all(self.resolve(o, st) == plain for _, o in dom) and \
                    all((int(o) if isinstance(o, int) else o) == plain for _, o in ip_rules):
                dom, dslots, dlims = [], [], []
            if pol.get("balanced") and isinstance(default, int) and default in self.bal_nums:
                default = nftgen.Sticky(default)     # открытые соединения не переезжают
            # «dns» — все правила по сайтам по порядку со своим DNS (engine/dns.py), только если он у кого-то
            # задан; не выбрасываются вместе с dom выше: правило, ведущее туда же, нужно ради своего DNS
            out = {"rules": ip_rules, "default": default, "domain": dom,
                   "dns": dns if any(x[2] for x in dns) else []}
            if labels:
                out["slots"], out["dslots"] = slots, dslots
                if any(x is not None for x in lims + dlims):      # без ограничений ключи политик — прежние
                    out["lims"], out["dlims"] = lims, dlims
            return out

        gp = conv(self.policy_for(st, None), None)
        cps = {}
        for c in self.clients:
            if not c.get("ip"):
                continue
            pol = self.policy_for(st, c["public_key"])
            if pol["custom"] or pol["balanced"] or pol.get("rbal"):
                cps[c["ip"]] = conv(pol, c["public_key"])
        if key is not None:
            memo["v"][key] = (gp, cps)
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
        ещё нет (правила «до панели», _save_hold): трафик на выходы — в блок, «напрямую» — напрямую. Правила «до
        панели» — без меток учёта по правилам: их ставит nft самого сервера, а ядро и nft там могут их не знать."""
        labels = self.labels_on() and not hold
        gp, cps = self._policies(st, labels)
        used = {lid for p in [gp, *cps.values()] for l, _ in p["rules"] for lid in l}
        lst = {lid: self._cidrs(lid) for lid in used}
        return nftgen.generate(t.iface, lst, [] if hold else self._up_list(st), gp, cps, sniff_port,
                               frozenset() if hold else self.sticky_nums(),
                               dom_filter=sniff_port is not None and self.dom_filter_on(st), quic=quic,
                               strict=sniff_port is None and self.strict(st), slots=self._sniff_slots, labels=labels,
                               limits=self.limit_rates(st) if labels else None,
                               # правила «до панели» — без путей адресов: после перезагрузки их ip rule ещё нет
                               addrs=None if hold else (getattr(self, "_addr_live", None) or {}),
                               dns_to=self.dns_redirect(t, st))

    def dns_redirect(self, t: system.Target, st: dict) -> str | None:
        """Куда перенаправлять DNS клиентов (П5): адрес сервера в туннеле, пока включён «DNS на сервере», — и когда
        dnsproxy.py сейчас не работает (панель перезапускается): имена тогда не разрешаются, но и мимо не уходят."""
        if not st["settings"].get("panel_dns"):
            return None
        try:
            la = self.tunnel_addr(t)
        except Exception:  # noqa: BLE001 — интерфейса ещё нет (сервер поднимается)
            return None
        return la[0] if la else None

    def limit_rates(self, st: dict) -> dict[int, tuple[int, int]]:
        """Ограничения скорости правил для nftgen: {номер j: (к клиентам, от клиентов) байт/с; 0 — без ограничения}."""
        bps = lambda m: int(m * 125_000) if m else 0  # noqa: E731
        return {j: (bps(d), bps(u)) for j, d, u in self.rule_limits(st).values()}

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

    # ------------------------------------------------- ручная смена пути: обрыв соединений (1.25.0)
    def path_sig(self, st: dict, out: str) -> str:
        """Выход в настройках → строка пути: «Напрямую» — с адресом (основной сейчас), чтобы смена основного тоже была
        сменой пути; балансировка — её выходы и резерв (кого из них выбрала она сама — не смена)."""
        if srcaddr.is_direct(out):
            return srcaddr.PFX + (srcaddr.split(out)[1] or srcaddr.main(st) or srcaddr.SYSTEM)
        return str(out)

    def paths(self, st: dict) -> dict[str, dict]:
        """Пути клиентов в терминах настроек: {IP: {"rules": [[списки, путь]] — по адресам, "drules": — по доменам,
        "default": путь}}. Сравнение «до» и «после» сохранения — что поменял человек (note_change)."""
        dl = self.domain_lists(st)
        out = {}
        for c in getattr(self, "clients", None) or []:
            if not c.get("ip"):
                continue
            pol = self.policy_for(st, c["public_key"])
            rules, drules = [], []
            for r in pol["rules"]:
                if r.get("balance"):
                    sig = f"bal:{','.join(r['balance'])}|{self.path_sig(st, r.get('balance_fb') or 'block')}"
                else:
                    sig = self.path_sig(st, r["outbound"])
                (drules if any(lid in dl for lid in r["lists"]) else rules).append([list(r["lists"]), sig])
            if pol.get("balanced"):
                skip = ",".join(sorted((st["routing"].get("balance") or {}).get("skip") or []))
                default = f"bal:-{skip}|{self.path_sig(st, pol['default'])}"
            else:
                default = self.path_sig(st, pol["default"])
            out[c["ip"]] = {"rules": rules, "drules": drules, "default": default}
        return out

    def note_change(self, old: dict, new: dict) -> bool:
        """Сохранили выход или адрес правила, «По умолчанию», клиента (вручную): соединения, у которых путь стал другим,
        оборвутся после того, как встанут новые правила (_run_drops), — иначе открытые соединения шли бы новым путём с
        прежней подменой адреса (зависали) или доживали на старом (посредник, решения QUIC). Перенос балансировкой и
        переход на резерв сюда не попадают: они не сохраняют настроек. True — такие соединения могут быть."""
        a, b = self.paths(old), self.paths(new)
        changed = {ip: {"old": a[ip], "new": b[ip]} for ip in a.keys() & b.keys() if a[ip] != b[ip]}
        if not changed:
            return False
        pend = getattr(self, "_drops", None)
        if pend is None:
            pend = self._drops = {}
        for ip, x in changed.items():
            pend[ip] = {"old": pend.get(ip, x)["old"], "new": x["new"]}
        self._drop_gen = getattr(self, "_drop_gen", 0) + 1
        self._drop_sni = {"gen": self._drop_gen, "clients": dict(pend)}
        self.trigger()
        return True

    def _run_drops(self, t: system.Target, st: dict) -> None:
        """После новых правил nftables: удалить записи conntrack соединений клиентов, чей путь сменился (ctflush.py в
        сети сервера AWG). Соединения посредника правил по доменам закрывает он сам (_drop_sni в его настройках)."""
        pend = getattr(self, "_drops", None)
        if not pend:
            return
        self._drops = {}
        lids = {lid for x in pend.values() for p in (x["old"], x["new"]) for lids, _ in p["rules"] for lid in lids}
        job = {"clients": {ip: {"old": {"rules": x["old"]["rules"], "default": x["old"]["default"]},
                                "new": {"rules": x["new"]["rules"], "default": x["new"]["default"]}}
                           for ip, x in pend.items()},
               "lists": {lid: self._cidrs(lid) for lid in sorted(lids)},
               "skip": list(nftgen.LOCAL_NETS),
               "quic": sorted(ip for ip, x in pend.items() if x["old"]["drules"] != x["new"]["drules"])}
        if config.DRY_RUN:
            log.info("connections with a new path: %d clients", len(pend))
            return
        p = t.ns([sys.executable, CTFLUSH], input=json.dumps(job), check=False, timeout=60)
        log.info("connections with a new path: %s", (p.stdout or p.stderr or "").strip()[:200])

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
            kvs.append(f"net.ipv4.conf.{t.iface}.rp_filter=2")
        else:
            kvs += ["net.ipv4.conf.all.rp_filter=2", "net.ipv4.conf.default.rp_filter=2"]
        for kv in kvs:
            t.ns(["sysctl", "-qw", kv], check=False)
