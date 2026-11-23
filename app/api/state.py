"""Состояние для браузера (/api/state, опрашивается каждые несколько секунд), общие настройки,
«Применить заново» и отладка."""
from __future__ import annotations

import hashlib
import json
import time

from .. import (awgconf, checks, config, countries, hostnet, limits, lists, notify,
                selfupdate, totp)
from ..i18n import Msg
from ..panel import (app, engine, notifier, panel_origin, panel_url, store, tls, updates)
from ..store import Store
from ..traffic import month_key
from . import auth, clients, routing, server, telegram
from ..engine.common import KERNEL_MIN

# -------------------------------------------------------------------- state
def _upstream_view(st: dict, u: dict, bal_members: set | None = None, bal_counts: dict | None = None) -> dict:
    if bal_members is None:
        bal_members = {m["id"] for m in engine.balance_members(st)}
    if bal_counts is None:
        bal_counts = engine.balancer.counts()
    try:
        pc = engine.parsed(u)
        info = {"endpoint": pc.endpoint, "address": pc.address, "mtu": pc.mtu,
                "version": pc.version, "kind": pc.kind, "own_list": u.get("own_list"),
                "socks_user": pc.socks.get("user") if pc.kind == "socks5" else None,
                "quic": bool(u.get("quic")) if pc.kind == "socks5" else True,
                "config_error": None}
    except awgconf.ConfigError as e:
        info = {"config_error": str(e)}
    eff = engine.resolve("up:" + u["id"], st)
    return {"id": u["id"], "name": u["name"], "num": u["num"],
            "iface": f"{config.IFACE_PREFIX}{u['num']}", "enabled": u.get("enabled", True),
            "fallback": u.get("fallback", "direct"), "created": u.get("created"),
            **info, "health": engine.health.get(u["id"], {"state": "down"}), "effective": eff,
            "refs": Store.outbound_refs(st, "up:" + u["id"]),
            "quota": u.get("quota"), "quota_action": engine.quota_target(u) or "notify",
            "over_quota": bool(u.get("quota")) and engine.traffic.out_used(u["id"]) >= u["quota"],
            "traffic": engine.traffic.out_view(u["id"]),
            "rate_down": u.get("rate_down"), "rate_up": u.get("rate_up"),
            # сейчас, байт/с: [от клиентов, к клиентам]
            "speed": [round(x) for x in engine.balancer.rate(u["id"])],
            "balance": u["id"] in bal_members, "bal_clients": bal_counts.get(u["id"], 0)}


def _state_tag(out: dict) -> str:
    """Отпечаток состояния для опроса браузера: тот же отпечаток — вкладку перерисовывать незачем (тысяча
    клиентов — четверть секунды на компьютере и секунды на телефоне). Время, процессор и память меняются на
    каждом запросе и в отпечаток не входят — их браузер получает всегда."""
    def plain(v):
        return v.to_json() if isinstance(v, Msg) else str(v)
    return hashlib.sha256(json.dumps(out, default=plain).encode()).hexdigest()[:20]


@app.get("/api/state")
def get_state(req):
    """Состояние для браузера. Заголовок X-State-Tag с отпечатком прошлого ответа: ничего не изменилось —
    короткий ответ {"same": true} со временем, процессором, памятью и скоростью клиентов (без сжатия и разбора
    всего состояния)."""
    out = _state_view()
    last = out["engine"].pop("last_reconcile")
    out["tag"] = _state_tag(out)
    out["engine"]["last_reconcile"] = last
    vol = {"now": time.time(),
           # демо: постоянные числа — снимки README не меняются от загрузки машины, где их снимали
           "system": {"cpu": 7.0, "cores": 2, "load": [0.14, 0.11, 0.09], "mem": [770 * 2**20, 2 * 2**30]}
           if config.DRY_RUN else hostnet.system_view(),
           # скорость клиентов сейчас (список клиентов, 1.23.0): меняется на каждом замере — вне отпечатка
           "speeds": engine.client_speeds()}
    seen = req.headers.get("X-State-Tag") if req is not None and getattr(req, "headers", None) else None
    if seen and seen == out["tag"]:
        return {"same": True, "tag": out["tag"], "last_reconcile": last, **vol}
    return {**out, **vol}


def _state_view() -> dict:
    st = store.snapshot()
    t = engine.target
    bal_members = {m["id"] for m in engine.balance_members(st)}
    bal_counts = {}
    for uid in engine.bal.values():
        bal_counts[uid] = bal_counts.get(uid, 0) + 1
    # Адрес панели и ссылки — один раз на запрос: share_url() на каждого клиента заново копировал всё
    # состояние (panel_url → snapshot), и ответ на тысячу клиентов со ссылками занимал полторы секунды.
    origin = panel_origin()
    share_of: dict = {}
    for tok, sh in st.get("shares", {}).items():
        share_of.setdefault(sh.get("pk"), tok)
    bot_name = telegram.bot.username()      # приглашение клиента в бота — по тому же ключу, что личная ссылка
    rows = []
    for c in engine.clients:
        cp = st["clients"].get(c["public_key"], {})
        pol = engine.policy_for(st, c["public_key"])
        out = engine.default_out(st, c["public_key"], pol)
        rows.append({
            **c,
            "traffic": engine.traffic.view(c["public_key"], history=False),
            "limits": limits.view(st.get("limits", {}).get(c["public_key"])),
            "share_url": f"{origin}/s/{share_of[c['public_key']]}" if c["public_key"] in share_of else None,
            "bot_url": f"https://t.me/{bot_name}?start={share_of[c['public_key']]}"
                       if bot_name and c["public_key"] in share_of else None,
            "cps": clients.cps_view(st.get("cps", {}).get(c["public_key"])),
            "host": (st.get("chost") or {}).get(c["public_key"]),
            "policy": {"outbound": cp.get("outbound", "inherit"),
                       "rules_mode": cp.get("rules_mode", "inherit"),
                       "rules": cp.get("rules") or [], "note": cp.get("note", "")},
            "default": out,
            "balanced": pol["balanced"] and out != pol["default"],
            "effective": engine.resolve(out, st),
        })
    rows.sort(key=lambda c: tuple(int(x) for x in (c.get("ip") or "255.255.255.255").split(".")))
    return {
        "demo": config.DRY_RUN,
        "target": {"container": t.container, "kind": t.kind, "pid": t.pid, "iface": t.iface,
                   "conf": t.conf_path, "exists": t.exists, "wg": t.wg_exists()} if t else None,
        "panel": {"url": panel_url(), "access": "ssh" if config.PANEL_HOST.startswith("127.") else "public",
                  "tls": tls.status(), "mode": config.AWG_MODE, "ip": engine.srv.public_host(st)},
        "target_error": engine.target_error,
        "engine": {"last_apply": engine.last_apply, "last_reconcile": engine.last_reconcile,
                   "last_error": engine.last_error, "ruleset_size": len(engine.ruleset)},
        "phase": engine.phase(),
        "routing": st["routing"],
        "hosts": {"default": engine.srv.client_host(st), "choices": engine.srv.host_choices(st)},
        "global_effective": engine.resolve(engine.default_out(st, None), st),
        "settings": {**st["settings"], "telegram": notify.public_view(notify.cfg_of(st))},
        "country_presets": countries.view(),     # «Применить для …» и выбор страны в правиле
        "security": {"totp": bool(totp.load()), "session_hours": auth.SESSION_TTL // 3600,
                     "password_custom": bool(auth.custom_password())},
        "version": {**updates.status(), "update": selfupdate.status()},
        "month": month_key(),
        "notify_error": notifier.last_error,
        "notify_pending": len(notifier.pending),
        "tg_bot": telegram.bot.view(),
        # бот сейчас идёт запасным путём: выбранный не отвечает (notify.Paths, 1.23.0)
        "tg_path": notify.paths.view(notify.cfg_of(st)["via"]),
        "upstreams": [_upstream_view(st, u, bal_members, bal_counts) for u in st["upstreams"]],
        "balance": {"members": sorted(bal_members), "new": engine.bal_new},
        "shaping": engine.shape_state and {k: v for k, v in engine.shape_state.items() if k != "sig"},
        "direct_traffic": engine.traffic.out_view("direct"),
        "server_traffic": engine.traffic.server_view(),
        "awg_engine": {"module": engine.module_info(), "server": engine.server_engine,
                       "exits_now": engine.exit_engine(st), "fallback": engine.kernel_fallback,
                       "forced": None if config.EXIT_ENGINE == "auto" else config.EXIT_ENGINE,
                       "old": engine.module_warn, "min": KERNEL_MIN, **server.engine_offer(t)},
        "acct": {"state": engine.acct_state, "error": engine.acct_error},
        "lists": [{**routing.list_view(l), "refs": Store.list_refs(st, l["id"])} for l in st["lists"]],
        "sni": engine.sni_view(),
        "socks_proxy": {
            **(st["settings"].get("socks_proxy") or {"enabled": False, "port": 1080}),
            "runtime": engine.socks_state,
            "users": [
                {
                    "username": name,
                    "exit": u.get("exit", "direct"),
                    "enabled": u.get("enabled", True),
                    "effective": engine.resolve(u.get("exit", "direct"), st),
                }
                for name, u in sorted((st.get("socks_users") or {}).items())
            ],
        },
        "clients": rows,
        "events": engine.events[-40:][::-1],
        "country_codes": lists.COUNTRY_CODES,
    }


# ----------------------------------------------------------------- settings
@app.put("/api/settings")
def put_settings(req):
    body = req.json()

    def fn(st):
        s = st["settings"]
        if "list_update_hours" in body:
            s["list_update_hours"] = checks.list_update_hours(body["list_update_hours"])
        if "on_stop" in body:
            s["on_stop"] = checks.on_stop(body["on_stop"])
        if "panel_name" in body:
            if v := checks.panel_name(body["panel_name"]):
                s["panel_name"] = v
            else:
                s.pop("panel_name", None)
        if "shaping" in body:
            if v := checks.shaping_limits(body["shaping"]):
                s["shaping"] = v
            else:
                s.pop("shaping", None)
    store.mutate(fn)
    if "shaping" in body:
        engine.trigger()
    return {"ok": True}


@app.post("/api/reapply")
def reapply(req):
    engine.applied_hash = None
    engine._up_fail.clear()          # «Применить заново» — и выходы на паузе после ошибок пробуем сразу
    engine.trigger()
    return {"ok": True}


@app.get("/api/debug")
def debug(req):
    t = engine.target
    rules = routes = ""
    if t and not config.DRY_RUN:
        rules = (t.ns(["ip", "rule", "show"], check=False)).stdout
        parts = []
        for r in list(engine.rt.values()):
            table = str(config.TABLE_BASE + r.num)
            out = (t.ns(["ip", "route", "show", "table", table],
                                           check=False)).stdout
            parts.append(f"# table {table} ({r.iface})\n{out}")
        routes = "\n".join(parts)
    # большие наборы адресов сокращаем, чтобы страница не тормозила
    short, skip = [], 0
    for line in engine.ruleset.splitlines():
        if line.startswith("\t\t\t") and "goto" not in line:
            skip += 1
            if skip <= 2:
                short.append(line)
            elif skip == 3:
                short.append("\t\t\t…")
            continue
        skip = 0
        short.append(line)
    return {"ruleset": "\n".join(short), "ip_rules": rules, "routes": routes,
            "commands": getattr(engine._fake, "log", [])[-60:] if config.DRY_RUN else []}
