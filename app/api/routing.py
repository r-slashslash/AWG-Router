"""Общие правила маршрутизации, списки сетей и доменов и «Проверка маршрута»."""
from __future__ import annotations

import ipaddress
import re
import socket

from .. import (awgconf, checks, domains, lists)
from ..checks import bad
from ..i18n import Msg
from ..panel import (app, engine, store)
from ..store import Store, new_id

# ------------------------------------------------------------------ routing
@app.put("/api/routing")
def put_routing(req):
    body = req.json()

    def fn(st):
        bal = checks.balance(st, body["balance"]) if "balance" in body else st["routing"].get("balance")
        strict = checks.strict(body["strict"] if "strict" in body else st["routing"].get("strict"))
        st["routing"] = {"default": checks.outbound(st, body.get("default")),
                         "rules": checks.rules(st, body.get("rules", []))}
        if bal:
            st["routing"]["balance"] = bal
        if strict:
            st["routing"]["strict"] = True
    store.mutate(fn)
    engine.trigger()
    return {"ok": True}


@app.post("/api/trace")
def trace(req):
    body = req.json()
    return trace_target(body.get("client") or None, str(body.get("ip", "")).strip())


def trace_target(client: str | None, ip: str) -> dict:
    """Куда пойдёт трафик до IP или домена (из панели и из Telegram)."""
    if ":" in ip:
        try:
            ipaddress.IPv6Address(ip.strip("[]").split("/", 1)[0])
        except ValueError:
            bad("err.ip_or_domain")
        bad("tr.ipv6")           # в туннеле только IPv4: такой трафик отбрасывается
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        via = None
        try:
            # как разберёт имя DNS клиента — через его выход (resolve_name), а не DNS провайдера хоста
            if not checks.HOSTNAME_RE.fullmatch(ip.lower().rstrip(".")):
                raise ValueError(ip)            # не имя в интернете (localhost и т. п.) — как раньше
            resolved, via = engine.resolve_name(client if client and awgconf.KEY_RE.match(client) else None, ip)
        except Exception:  # noqa: BLE001  — выхода нет, блок, демо: резолвер панели, как раньше
            try:
                infos = socket.getaddrinfo(ip, None, socket.AF_INET)
                resolved = infos[0][4][0]
            except Exception:  # noqa: BLE001
                try:
                    socket.getaddrinfo(ip, None, socket.AF_INET6)
                except Exception:  # noqa: BLE001
                    bad("err.ip_or_domain")
                bad(Msg("tr.ipv6_only", host=ip))   # у домена только AAAA
        res = engine.trace(client, resolved, ip.lower().rstrip("."))
        if via is None:
            res["steps"].insert(0, Msg("tr.resolved", host=ip, ip=resolved))
        else:
            name = Msg("out.direct") if via == "direct" else \
                (Store.upstream(store.snapshot(), via[3:]) or {}).get("name", via)
            res["steps"].insert(0, Msg("tr.resolved_via", host=ip, ip=resolved, via=name))
        res["ip"] = resolved
        return res
    try:
        res = engine.trace(client, ip)
    except ValueError:
        bad("err.ip_or_domain")
    res["ip"] = ip
    return res


# -------------------------------------------------------------------- lists
def list_view(l: dict | None) -> dict | None:
    """Список для браузера. Текст ручного списка (до 2 МБ) не отдаём в /api/state,
    который опрашивается каждые 5 секунд, — только по /api/lists/<id>. busy — скачивается сейчас."""
    if l is None:
        return None
    v = {**l, "busy": l["id"] in engine.lists_busy}
    if l.get("kind") in ("manual", "domains"):
        v["source"] = None
    return v


def _needs_net(l: dict) -> bool:
    """Списку нужна сеть: страны, ASN, по ссылке и домены со ссылками. Ручной список и домены без ссылок
    разбираются за доли секунды — их по-прежнему готовим сразу, и ответ уже с числом записей."""
    if l["kind"] in ("country", "asn", "url"):
        return True
    return l["kind"] == "domains" and bool(domains.split_source(l.get("source") or "")[0])


def refresh_now_or_bg(lid: str) -> dict | None:
    l = Store.lst(store.snapshot(), lid)
    if l and _needs_net(l):
        engine.refresh_lists_bg([lid])
    else:
        engine.refresh_lists(False, [lid])
    return list_view(Store.lst(store.snapshot(), lid))


@app.get("/api/lists/{lid}")
def get_list(req, lid):
    l = Store.lst(store.snapshot(), lid)
    if not l:
        bad("err.not_found", 404)
    return l


@app.post("/api/lists")
def add_list(req):
    body = req.json()

    def fn(st):
        d = checks.list_fields(body)
        lid = d["source"] if d["kind"] == "country" else new_id("l")
        if d["kind"] == "country" and Store.lst(st, lid):
            bad("err.country_exists")
        st["lists"].append({"id": lid, **d})
        return lid
    lid = store.mutate(fn)
    return {"id": lid, **(refresh_now_or_bg(lid) or {})}


@app.put("/api/lists/{lid}")
def edit_list(req, lid):
    body = req.json()

    def fn(st):
        l = Store.lst(st, lid)
        if not l:
            bad("err.not_found", 404)
        if body.get("kind", l["kind"]) != l["kind"]:
            # вид списка не меняется: от него зависят правила (домены не смешиваются с сетями),
            # а у стран id = код страны
            bad("err.list_kind_change")
        d = checks.list_fields(body, l)
        if l["kind"] == "country":
            d["source"] = l["source"]  # страну у существующего списка не меняем
        l.update(d)
    store.mutate(fn)
    return refresh_now_or_bg(lid)


@app.delete("/api/lists/{lid}")
def del_list(req, lid):
    def fn(st):
        if not Store.lst(st, lid):
            bad("err.not_found", 404)
        refs = Store.list_refs(st, lid)
        if refs:
            bad(Msg("err.list_in_use", refs=refs[:6]))
        st["lists"] = [l for l in st["lists"] if l["id"] != lid]
    store.mutate(fn)
    lists.delete_cidrs(lid)
    engine.trigger()
    return {"ok": True}


@app.post("/api/lists/{lid}/refresh")
def refresh_list(req, lid):
    if not Store.lst(store.snapshot(), lid):
        bad("err.not_found", 404)
    return refresh_now_or_bg(lid)


@app.get("/api/lists/{lid}/cidrs")
def list_cidrs(req, lid):
    c = lists.load_cidrs(lid)
    return {"count": len(c), "sample": c[:300]}
