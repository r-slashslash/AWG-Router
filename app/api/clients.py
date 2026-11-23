"""Клиенты: создание и правка, куда они идут, срок и лимит, маскировка I1–I5, свой адрес сервера и
личная ссылка (страница /s/… без входа)."""
from __future__ import annotations

import os
import secrets
import time

from .. import (awgconf, checks, config, cps, limits)
from ..checks import bad
from ..panel import (STATIC, app, engine, share_url, store, user_errors)
from ..web import Page
from . import routing

# ----------------------------------------------- срок и лимит трафика клиента
@app.put("/api/limits/{pk:path}")
def put_limits(req, pk):
    _pk(pk)
    body = req.json()
    exp = checks.expires(body.get("expires"))
    quota = checks.quota_gb(body.get("quota_gb"))
    period = checks.period(body.get("period"))
    return {"ok": True, "enabled": apply_limits(pk, exp, quota, period, checks.rates(body))}


def apply_limits(pk: str, exp: int | None, quota: int | None, period: str, rates: dict | None = None) -> bool:
    """Срок и лимит клиента (из панели и из Telegram). Если клиента отключили по сроку или
    лимиту, а новые значения это снимают, — включает его. True — включили."""
    c = next((x for x in engine.clients if x["public_key"] == pk), None)
    if not c:
        bad("err.not_found", 404)
    now = time.time()
    enable = False

    def fn(st):
        nonlocal enable
        L = st.setdefault("limits", {}).get(pk) or {}
        if quota != L.get("quota") or period != L.get("period", "month"):
            L["quota_done"] = L["quota_warned"] = None
        ao = L.get("auto_off") or ""
        if not c["enabled"] and ao == "exp" and (exp is None or exp > now):
            enable = True
        if not c["enabled"] and ao.startswith("quota:") and \
                (quota is None or engine.traffic.used(pk, period) < quota):
            enable = True
        if enable:
            L["auto_off"] = None
        L.update(expires=exp, quota=quota, period=period)
        for k, v in (rates or {}).items():      # ограничение скорости: только если пришло
            if v:
                L[k] = v
            else:
                L.pop(k, None)
        if exp is None and quota is None and not L.get("auto_off") and not L.get("rate_down") \
                and not L.get("rate_up"):
            st["limits"].pop(pk, None)
        else:
            st["limits"][pk] = L
    store.mutate(fn)
    if enable:
        user_errors(lambda: engine.srv.update_client(pk, enabled=True))
    engine.reconcile_soon()
    return enable


@app.post("/api/shares/{pk:path}")
def create_share(req, pk):
    _pk(pk)
    return {"url": ensure_share(pk)}


def ensure_share(pk: str) -> str:
    """Личная ссылка клиента: существующая или новая."""
    if not any(c["public_key"] == pk for c in engine.clients):
        bad("err.not_found", 404)

    def fn(st):
        sh = st.setdefault("shares", {})
        tok = next((k for k, v in sh.items() if v.get("pk") == pk), None)
        if not tok:
            tok = secrets.token_urlsafe(18)
            sh[tok] = {"pk": pk, "created": time.time()}
        return tok
    return share_url(store.mutate(fn))


@app.post("/api/shares-renew/{pk:path}")   # не «/shares/{pk}/renew»: ключ клиента с «/» — :path
def renew_share(req, pk):
    """«Обновить»: новая личная ссылка и новое приглашение в бота; прежние перестают работать (и чат Telegram,
    подключённый по прежнему приглашению, — тоже: бот сверяет ключ при каждом сообщении)."""
    _pk(pk)
    if not any(c["public_key"] == pk for c in engine.clients):
        bad("err.not_found", 404)

    def fn(st):
        sh = {k: v for k, v in st.get("shares", {}).items() if v.get("pk") != pk}
        tok = secrets.token_urlsafe(18)
        sh[tok] = {"pk": pk, "created": time.time()}
        st["shares"] = sh
        return tok
    tok = store.mutate(fn)
    return {"url": share_url(tok), "bot_url": bot_invite(tok)}


@app.delete("/api/shares/{pk:path}")
def delete_share(req, pk):
    def fn(st):
        st["shares"] = {k: v for k, v in st.get("shares", {}).items() if v.get("pk") != pk}
    store.mutate(fn)
    return {"ok": True}


def bot_invite(token: str) -> str | None:
    """Приглашение клиента в бота: t.me/<бот>?start=<ключ личной ссылки>. Нет, пока бот для клиентов выключен
    или его имя ещё не известно (бот узнаёт его у Telegram при первом опросе)."""
    from . import telegram          # telegram импортирует этот модуль: здесь — при вызове
    name = telegram.bot.username()
    return f"https://t.me/{name}?start={token}" if name and TOKEN_RE.match(token) else None


def share_pk(token: str) -> str | None:
    """Клиент по ключу личной ссылки — без копии состояния (бот спрашивает это на каждое сообщение клиента)."""
    if not isinstance(token, str) or not TOKEN_RE.match(token):
        return None
    return store.peek(lambda st: (st.get("shares", {}).get(token) or {}).get("pk"))


SHARE_HTML = os.path.join(STATIC, "share.html")
TOKEN_RE = checks.TOKEN_RE


def _share_exists(token: str) -> bool:
    # без копии состояния: адреса /s/… открыты без входа, и чужой запрос не должен стоить панели копии
    # всего state.json (на тысяче клиентов — миллисекунды процессора на каждый)
    return bool(TOKEN_RE.match(token)) and store.peek(lambda st: token in st.get("shares", {}))


def _share_of(token: str) -> tuple[str | None, bool, dict | None]:
    """Клиент личной ссылки: (ключ, есть ли его закрытый ключ, копия его срока и лимита)."""
    if not TOKEN_RE.match(token):
        return None, False, None

    def fn(st):
        pk = (st.get("shares", {}).get(token) or {}).get("pk")
        lim = st.get("limits", {}).get(pk) if pk else None
        return pk, bool(pk) and pk in st.get("keys", {}), dict(lim) if isinstance(lim, dict) else None
    return store.peek(fn)


@app.get("/s/{token}", public=True)
def share_page(req, token):
    """Личная страница. На чужой, устаревший (после «Обновить») или удалённый адрес — та же страница с кодом 404:
    share.js сам пишет «ссылка не действует» на языке человека (раньше тот видел служебный JSON). По ответу не
    отличить, была ли такая ссылка: страница одна на все неверные адреса."""
    with open(SHARE_HTML, "rb") as f:
        return Page(app.versioned(f.read()), status=200 if _share_exists(token) else 404)


@app.get("/s/api/{token}", public=True)
def share_data(req, token):
    d = share_info(token)
    if d is None:
        bad("err.share_gone", 404)
    return d


def share_info(token: str, config: bool = True) -> dict | None:
    """То, что видит клиент по своей личной ссылке (и в боте по приглашению): None — ссылки нет."""
    spk, has_key, lim = _share_of(token)
    c = next((x for x in engine.clients if x["public_key"] == spk), None) if spk else None
    if not c:
        return None
    pk = c["public_key"]
    cfg = None
    if has_key and config:
        try:
            cfg = engine.srv.client_config(pk)
            cfg.pop("warn_host", None)
            cfg.pop("name", None)                  # имя клиента ему не показываем (1.22.0)
        except Exception:  # noqa: BLE001
            cfg = None
    live = c.get("live") or {}
    return {"enabled": c["enabled"], "now": time.time(),
            "handshake": live.get("handshake") or None, "config": cfg,
            # разбивка по выходам — только в панели: на публичной странице она ни к чему
            "traffic": {k: v for k, v in engine.traffic.view(pk).items() if k != "by_out"},
            "limits": limits.view(lim), "has_config": has_key}


@app.put("/api/clients/{pk:path}")
def put_client(req, pk):
    if not awgconf.KEY_RE.match(pk) and not (config.DRY_RUN and pk.startswith("DEMO")):
        bad("err.bad_client_key")
    body = req.json()

    def fn(st):
        # клиента удалили с другого устройства, а окно его осталось открытым: «Сохранить» не должно возвращать его запись
        # (Г29 глубокой проверки 1.23.0) — списки его своих правил считались бы занятыми и не удалялись
        if pk not in st["clients"] and engine.clients and not any(x["public_key"] == pk for x in engine.clients):
            bad("err.client_gone", 404)
        old = st["clients"].get(pk) or {}
        before = routing.rule_lists(old.get("rules") if old.get("rules_mode") == "custom" else [])
        c = {**checks.client_policy(st, body, engine.dns_listen()),
             "name": next((x.get("name") for x in engine.clients if x["public_key"] == pk), "")}
        if old.get("proto") == "wg":
            c["proto"] = "wg"
        if c["outbound"] == "inherit" and c["rules_mode"] == "inherit" and not c["note"] and c.get("proto") != "wg":
            st["clients"].pop(pk, None)
        else:
            st["clients"][pk] = c
        # свои правила клиента: список, который из них ушёл и больше нигде не стоит, удаляется (как на «Маршрутизации»)
        return routing.drop_unused_lists(st, before - routing.rule_lists(c["rules"] if c["rules_mode"] == "custom" else []))
    routing.forget_lists(store.mutate(fn))
    engine.trigger()
    return {"ok": True}


# ------------------------------------------- свои сигнатурные пакеты I1–I5 клиента
def cps_view(entry) -> dict | None:
    if not isinstance(entry, dict) or entry.get("preset") not in (*cps.PRESETS, "custom"):
        return None
    return {"preset": entry["preset"],
            "values": cps.for_client(entry) if entry["preset"] == "custom" else None}


@app.get("/api/cps")
def get_cps(req):
    """Шаблоны и текущие I1–I5 сервера — для выбора маскировки в окне клиента."""
    try:
        sv = engine.srv.server_view()
    except Exception:  # noqa: BLE001  — сервер недоступен: шаблоны всё равно нужны
        sv = {}
    params = sv.get("params") or {}
    return {"presets": cps.catalog(), "server": {k: params.get(k) or "" for k in cps.KEYS},
            "server_match": sv.get("cps_server")}


@app.put("/api/cps/{pk:path}")
def put_client_cps(req, pk):
    """preset: "server" (как на сервере) | имя шаблона | "custom" + values {I1..I5}."""
    if not awgconf.KEY_RE.match(pk) and not (config.DRY_RUN and pk.startswith("DEMO")):
        bad("err.bad_client_key")
    if not any(c["public_key"] == pk for c in engine.clients):
        bad("err.not_found", 404)
    body = req.json()
    entry = checks.cps_entry(body.get("preset"), body.get("values"))

    def fn(st):
        m = st.setdefault("cps", {})
        if entry:
            m[pk] = entry
        else:
            m.pop(pk, None)
    store.mutate(fn)
    return {"ok": True, "cps": cps_view(entry)}


# -------------------------------------------------------------------- users
def _pk(pk: str) -> str:
    return checks.client_key(pk)


def _client_name(v) -> str:
    """Имя клиента из запроса: только строка (true или 5 стали бы именами «True» и «5»)."""
    if v is None:
        return ""
    if not isinstance(v, str):
        bad("err.name_required")
    return v


@app.post("/api/users")
def add_user(req):
    body = req.json()
    host = _client_host_value(body.get("host"))           # проверка до создания: отказ — без клиента
    proto = body.get("proto") if body.get("proto") is not None else "awg"
    if not isinstance(proto, str):
        bad("err.bad_value")
    pk = user_errors(lambda: engine.srv.add_client(_client_name(body.get("name")), proto=proto))
    if host:
        store.mutate(lambda st: st.setdefault("chost", {}).__setitem__(pk, host))
    engine.reconcile_soon()
    return {"public_key": pk}


def _client_host_value(value) -> str:
    """Свой адрес сервера в конфиге клиента: пусто — как у всех, иначе один из host_choices (#37)."""
    if value is None or value == "":
        return ""
    return checks.client_host(value, engine.srv.host_choices(store.snapshot()))


@app.put("/api/hosts/{pk:path}")
def put_client_host(req, pk):
    """host: "" — как у всех, иначе адрес из «Сервер → Дополнительные адреса» (или основной)."""
    _pk(pk)
    if not any(c["public_key"] == pk for c in engine.clients):
        bad("err.not_found", 404)
    host = _client_host_value(req.json().get("host"))

    def fn(st):
        m = st.setdefault("chost", {})
        if host:
            m[pk] = host
        else:
            m.pop(pk, None)
    store.mutate(fn)
    return {"ok": True, "host": host or None}


@app.put("/api/users/{pk:path}")
def edit_user(req, pk):
    body = req.json()
    _pk(pk)
    name = _client_name(body["name"]) if body.get("name") is not None else None
    proto = body.get("proto")
    if proto is not None and not isinstance(proto, str):
        bad("err.bad_value")
    if name is not None or proto is not None:
        user_errors(lambda: engine.srv.update_client(pk, name=name, proto=proto))
    if body.get("enabled") is not None:
        set_client_enabled(pk, checks.flag(body["enabled"]))
    engine.reconcile_soon()
    return {"ok": True}


def set_client_enabled(pk: str, on: bool) -> None:
    """Включить или выключить клиента вручную (из панели и из Telegram)."""
    user_errors(lambda: engine.srv.update_client(pk, enabled=on))

    # включили или выключили вручную — автоматическое отключение больше не наше
    def fn(st):
        L = st.get("limits", {}).get(pk)
        if L and L.get("auto_off"):
            L["auto_off"] = None
    store.mutate(fn)
    engine.reconcile_soon()


@app.delete("/api/users/{pk:path}")
def del_user(req, pk):
    delete_user(pk)
    return {"ok": True}


def delete_user(pk: str) -> None:
    """Удаление клиента: из панели и из бота."""
    user_errors(lambda: engine.srv.delete_client(_pk(pk)))
    engine.traffic.forget(pk)
    engine.reconcile_soon()


@app.get("/api/users/{pk:path}/config")
def user_config(req, pk):
    return user_errors(lambda: engine.srv.client_config(_pk(pk)))
