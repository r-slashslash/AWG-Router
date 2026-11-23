"""Выходы: добавить, изменить, удалить, проверить. Окно выхода меняет и общие правила
(apply_exit_routing)."""
from __future__ import annotations

import time

from .. import (awgconf, checks, lists)
from ..checks import bad, field
from ..engine import Engine
from ..i18n import Msg
from ..panel import (app, engine, store)
from ..store import Store, new_id
from . import routing

# ---------------------------------------------------------------- upstreams
def apply_exit_routing(st: dict, uid: str, r: dict, name: str) -> tuple[str | None, str | None]:
    """Маршрутизация через выход из его окна: общие правила «списки доменов → выход»
    и «списки сетей → выход» заменяются выбранными; свои домены выхода — его собственный
    список доменов (u["own_list"]); «основной выход». → (список, который нужно обновить;
    список, который нужно удалить)."""
    out = "up:" + uid
    u = Store.upstream(st, uid)
    if not isinstance(r, dict) or not u:
        bad("err.bad_rules")
    pick = lambda key, dom: list(dict.fromkeys(
        lid for lid in (r.get(key) or []) if isinstance(lid, str) and Store.lst(st, lid)
        and (Store.lst(st, lid)["kind"] == "domains") == dom))
    dl, nl = pick("domain_lists", True), pick("net_lists", False)
    text = str(r.get("domains") or "").strip()
    own = u.get("own_list") if Store.lst(st, u.get("own_list") or "") else None
    refresh = drop = None
    if text:
        text = checks.list_fields({"kind": "domains", "source": text, "name": name})["source"]
        if own:
            l = Store.lst(st, own)
            if store.list_text(own) != text or l.get("name") != name:
                l.update(source=text, name=name)
                refresh = own
        else:
            own = new_id("l")
            st["lists"].append({"id": own, "kind": "domains", "source": text, "name": name})
            u["own_list"] = own
            refresh = own
        dl = [own] + [x for x in dl if x != own]
    elif own:
        dl = [x for x in dl if x != own]
        drop = own
    st["routing"]["rules"] = checks.rules(st, merge_exit_rules(st, out, dl, nl, name))
    if r.get("default") is True:
        st["routing"]["default"] = out
    elif r.get("default") is False and st["routing"]["default"] == out:
        st["routing"]["default"] = "direct"
    if drop and not Store.list_refs(st, drop):
        st["lists"] = [x for x in st["lists"] if x["id"] != drop]
        u.pop("own_list", None)
    else:
        drop = None
    return refresh, drop


def merge_exit_rules(st: dict, out: str, dl: list[str], nl: list[str], name: str) -> list[dict]:
    """Общие правила после окна выхода: окно показывает списки ВКЛЮЧЁННЫХ правил на этот выход,
    поэтому меняются только они и только точечно. Снятый список убирается из правила (пустое
    правило — целиком), новый дописывается в первое включённое правило того же вида на этот выход,
    а если такого нет — в новое правило сразу после последнего правила на выход (иначе в начало).
    Выключенные правила, подписи, порядок и правила на другие выходы не меняются."""
    dom = Engine.domain_lists(st)
    want = set(dl) | set(nl)
    rules = [dict(r) for r in st["routing"]["rules"]]
    mine = lambda r: r["outbound"] == out and r.get("enabled", True)
    have = {lid for r in rules if mine(r) for lid in r["lists"]}
    for r in rules:
        if mine(r):
            r["lists"] = [lid for lid in r["lists"] if lid in want]
    keep = [r for r in rules if not (mine(r) and not r["lists"])]
    new_rules = []
    for add in ([x for x in dl if x not in have], [x for x in nl if x not in have]):
        if not add:
            continue
        is_dom = add[0] in dom
        host = next((r for r in keep if mine(r) and (r["lists"][0] in dom) == is_dom), None)
        if host:
            host["lists"] = host["lists"] + add
        else:
            # без подписи: строка правила сама показывает, что ловит правило и куда ведёт
            new_rules.append({"lists": add, "outbound": out, "enabled": True, "comment": ""})
    if new_rules:
        last = max((i for i, r in enumerate(keep) if r["outbound"] == out), default=-1)
        keep[last + 1:last + 1] = new_rules
    return keep


def _after_exit_routing(lists_changed: tuple) -> None:
    refresh, drop = lists_changed
    if drop:
        lists.delete_cidrs(drop)
    if refresh:
        routing.refresh_now_or_bg(refresh)           # свои сайты выхода со ссылками скачиваются в фоне


@app.post("/api/upstreams")
def add_upstream(req):
    body = req.json()
    with field("quota_gb"):
        quota = checks.quota_gb(body.get("quota_gb"))
    rates = _exit_rates(body)
    with field("quic"):
        quic = checks.quic(body["quic"]) if "quic" in body else None
    pc = checks.exit_config(body.get("config", ""))
    with field("name"):
        name = checks.name(body.get("name"))

    def fn(st):
        with field("fallback"):
            fb = checks.fallback(st, None, body.get("fallback") or "block")      # по умолчанию — «Блокировать» (2026-11-21)
        with field("quota_action"):
            action = checks.quota_action(st, body.get("quota_action"), None)
        u = {"id": new_id("u"), "name": name, "num": Store.free_num(st), "config": pc.raw,
             "enabled": True, "fallback": fb, "created": time.time(),
             "quota": quota, "quota_action": action}
        u.update({k: v for k, v in rates.items() if v})
        if quic and pc.kind == "socks5":
            u["quic"] = True
        st["upstreams"].append(u)
        if body.get("make_default") and st["routing"]["default"] in ("direct", "block"):
            st["routing"]["default"] = "up:" + u["id"]
        with field("routing"):
            ch = apply_exit_routing(st, u["id"], body["routing"], name) if body.get("routing") else (None, None)
        return u["id"], ch
    uid, ch = store.mutate(fn)
    _after_exit_routing(ch)
    engine.trigger()
    return {"id": uid}


@app.get("/api/upstreams/{uid}/config")
def get_upstream_config(req, uid):
    u = Store.upstream(store.snapshot(), uid)
    if not u:
        bad("err.not_found", 404)
    return {"config": u["config"]}


def _exit_rates(body: dict) -> dict:
    """Ограничения скорости выхода — каждое со своим полем формы."""
    out = {}
    for k in ("rate_down", "rate_up"):
        with field(k):
            out.update(checks.rates({k: body[k]}) if k in body else {})
    return out


@app.put("/api/upstreams/{uid}")
def edit_upstream(req, uid):
    body = req.json()
    quota = None
    if "quota_gb" in body:
        with field("quota_gb"):
            quota = checks.quota_gb(body.get("quota_gb"))
    rates = _exit_rates(body)
    with field("quic"):
        quic = checks.quic(body["quic"]) if "quic" in body else None

    def fn(st):
        u = Store.upstream(st, uid)
        if not u:
            bad("err.not_found", 404)
        if "name" in body:
            with field("name"):
                u["name"] = checks.name(body["name"])
            own = Store.lst(st, u.get("own_list") or "")
            if own:
                own["name"] = u["name"]          # свой список сайтов выхода называется как выход
        if "enabled" in body:
            u["enabled"] = checks.flag(body["enabled"])
        if "fallback" in body:
            with field("fallback"):
                u["fallback"] = checks.fallback(st, uid, body["fallback"])
        if body.get("config"):
            pc = checks.exit_config(body["config"])
            # тип выхода не меняется: у AWG и SOCKS5 разные туннели, проверки и поля — это новый выход
            try:
                old_kind = engine.parsed(u).kind
            except awgconf.ConfigError:
                old_kind = None
            if old_kind and pc.kind != old_kind:
                bad("err.exit_kind_change", field="config")
            u["config"] = pc.raw
        if "quota_gb" in body:
            with field("quota_action"):
                action = checks.quota_action(st, body.get("quota_action"), uid)
            if quota != u.get("quota") or action != (engine.quota_target(u) or "notify"):
                u["quota_hit"] = u["quota_warned"] = None   # события квоты — заново
            u["quota"], u["quota_action"] = quota, action
        for k, v in rates.items():
            if v:
                u[k] = v
            else:
                u.pop(k, None)
        if quic is not None:
            try:
                socks = engine.parsed(u).kind == "socks5"
            except awgconf.ConfigError:
                socks = False
            if quic and socks:
                u["quic"] = True
            else:
                u.pop("quic", None)
        if body.get("routing"):
            with field("routing"):
                return apply_exit_routing(st, uid, body["routing"], u["name"])
        return None, None
    _after_exit_routing(store.mutate(fn))
    engine.trigger()
    return {"ok": True}


@app.delete("/api/upstreams/{uid}")
def del_upstream(req, uid):
    """Удаление выхода. Если он где-то используется, нужен replace — выход, который
    встанет на его место во всех ссылках (без него — ошибка со списком ссылок)."""
    repl = (req.json() if req else {}).get("replace")

    def fn(st):
        u = Store.upstream(st, uid)
        if not u:
            bad("err.not_found", 404)
        target = "up:" + uid
        refs = Store.outbound_refs(st, target)
        if refs and repl is None:
            bad(Msg("err.upstream_in_use", refs=refs[:6]))
        if repl is not None:
            new = checks.outbound(st, repl)
            if new == target:
                bad("err.bad_outbound")
            Store.replace_outbound(st, target, new, u.get("fallback"))
        st["upstreams"] = [x for x in st["upstreams"] if x["id"] != uid]
        for su in (st.get("socks_users") or {}).values():
            if su.get("exit") == target:
                su["exit"] = "direct"
        bal = st["routing"].get("balance")
        if bal and uid in (bal.get("skip") or []):
            bal["skip"] = [x for x in bal["skip"] if x != uid]
        own = u.get("own_list")
        if own:
            # свои сайты выхода уходят вместе с ним, а не на замену: список назван по выходу и
            # заполнялся в его окне. Правило, где остался только он, удаляется целиком
            def strip(rules):
                out = []
                for r in rules or []:
                    if own in (r.get("lists") or []):
                        r = {**r, "lists": [x for x in r["lists"] if x != own]}
                        if not r["lists"]:
                            continue
                    out.append(r)
                return out
            st["routing"]["rules"] = strip(st["routing"]["rules"])
            for c in st["clients"].values():
                if c.get("rules"):
                    c["rules"] = strip(c["rules"])
        if own and Store.lst(st, own) and not Store.list_refs(st, own):
            st["lists"] = [x for x in st["lists"] if x["id"] != own]
            return own
        return None
    own = store.mutate(fn)
    if own:
        lists.delete_cidrs(own)
    engine.traffic.forget_out(uid)
    engine.trigger()
    return {"ok": True}


@app.post("/api/probe")
def probe(req):
    body = req.json()
    st = store.snapshot()
    out = checks.outbound(st, body.get("outbound"))
    try:
        return engine.probe(out)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:300]}
