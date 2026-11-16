"""Telegram: настройки уведомлений и управление панелью из бота. bot_ops — те же действия, что за
кнопками панели в браузере."""
from __future__ import annotations

import logging
import time
from types import SimpleNamespace

from .. import (checks, config, hostnet, notify,
                selfupdate, tgbot)
from ..checks import bad
from ..i18n import Msg, msg_of
from ..panel import (app, engine, notifier, panel_url, store, tls, updates,
                     user_errors)
from ..store import Store
from ..version import VERSION
from . import backup, clients, routing

log = logging.getLogger("awgr")
# ---------------------------------------------------------------- telegram
def _tg_draft(body: dict) -> dict:
    """Настройки из формы поверх сохранённых (пустой токен = оставить прежний)."""
    st = store.snapshot()
    return checks.telegram(st, notify.cfg_of(st), body)


@app.put("/api/telegram")
def put_telegram(req):
    c = _tg_draft(req.json())
    if (c["enabled"] or c["control"]) and not (c["token"] and c["chat_id"]):
        bad("err.tg_incomplete", field="token" if not c["token"] else "chat_id")
    if c["control"] and c["chat_id"].startswith("@"):
        # @имя можно освободить и занять другому человеку, а в публичной группе с этим именем пишут
        # все её участники: команды (выключить клиентов, прислать копию) — только из чата с числовым ID
        bad("err.tg_control_id", field="chat_id")
    store.mutate(lambda st: st["settings"].__setitem__("telegram", c))
    bot.wake.set()             # бот сразу видит новые настройки, не дожидаясь паузы
    return {"ok": True}


@app.post("/api/telegram/test")
def telegram_test(req):
    c = _tg_draft(req.json())
    if not (c["token"] and c["chat_id"]):
        bad("err.tg_incomplete")
    try:
        notify.send(c["token"], c["chat_id"], notify.render(c["lang"], "test", notifier.host_fn(store.snapshot())),
                    c["via"])
    except notify.NotifyError as e:
        bad(Msg("err.tg_failed", error=msg_of(e)), 502)
    return {"ok": True}


@app.post("/api/telegram/backup")
def telegram_backup(req):
    """Отправить резервную копию в чат сейчас (с настройками из формы)."""
    c = _tg_draft(req.json())
    if not (c["token"] and c["chat_id"]):
        bad("err.tg_incomplete")
    try:
        backup.send_backup(c)
    except notify.NotifyError as e:
        bad(Msg("err.tg_failed", error=msg_of(e)), 502)
    now = time.time()
    store.mutate(lambda st: st["settings"].setdefault("telegram", notify.defaults())
                 .update(backup_last=now, backup_error=None))
    return {"ok": True, "encrypted": bool(c["backup_pw"])}


@app.post("/api/telegram/detect")
def telegram_detect(req):
    c = _tg_draft(req.json())
    if not c["token"]:
        bad("err.tg_token")
    try:
        chat = notify.detect_chat(c["token"], c["via"])
    except notify.NotifyError as e:
        bad(Msg("err.tg_failed", error=msg_of(e)), 502)
    if not chat:
        bad("err.tg_no_chat", 404)
    return chat


# --------------------------------------------------- управление из Telegram
def set_default_outbound(out: str) -> None:
    """«Сделать основным» в боте: выход по умолчанию для всех — балансировка выключается."""
    def fn(st):
        st["routing"]["default"] = checks.outbound(st, out)
        if (st["routing"].get("balance") or {}).get("on"):
            st["routing"]["balance"]["on"] = False
    store.mutate(fn)
    engine.trigger()


def _list_name(lid) -> str:
    l = Store.lst(store.snapshot(), lid or "")
    if not l:
        return str(lid or "?")
    return l["source"].upper() if l["kind"] == "country" else (l.get("name") or l["id"])


def _bot_status() -> dict:
    st = store.snapshot()
    t = engine.target
    ts = tls.status()
    return {"host": notifier.host_fn(st), "server_ok": bool(t and t.exists and not engine.target_error),
            "month_bytes": sum(engine.traffic.used(c["public_key"], "month") for c in engine.clients),
            "server_traffic": engine.traffic.server_view(),
            "version": updates.status(),
            "cert_until": ts.get("expires") if ts.get("active") in ("letsencrypt", "custom") else None}


def _bot_host_info() -> dict:
    """Экран бота «Сервер › Состояние»: версия AWG, адреса, время работы и память хоста."""
    awg, v4, v6 = "", None, []
    try:
        sv = engine.srv.server_view()
        awg = sv.get("version") or ""
        addrs = sv.get("addrs") or {}
        v4, v6 = addrs.get("v4"), addrs.get("v6") or []
    except Exception as e:  # noqa: BLE001 — сервер не найден: показываем то, что есть
        log.info("bot host info: %s", e)
    m = engine.module_info()
    return {"awg": awg, "v4": v4 or engine.public_v4, "v4_state": engine.public_v4_state,
            "engine": {"server": engine.server_engine, "version": m.get("version") if m.get("loaded") else None},
            "v6": v6[0] if v6 else None, "dns": engine.dns_view(),
            "uptime": hostnet.uptime(), "memory": hostnet.memory()}


def _bot_backup(c: dict) -> None:
    backup.send_backup(c)
    now = time.time()
    store.mutate(lambda st: st["settings"].setdefault("telegram", notify.defaults())
                 .update(backup_last=now, backup_error=None))


# Действия для бота — те же функции, что за кнопками панели в браузере.
bot_ops = SimpleNamespace(
    version=VERSION,
    snapshot=store.snapshot,
    status=_bot_status,
    host_info=_bot_host_info,
    clients=lambda: list(engine.clients),
    refresh_clients=engine.reconcile_soon,
    resolve=engine.resolve,
    health=lambda uid: engine.health.get(uid, {}),
    over_quota=engine.over_quota,
    traffic_month=lambda pk: engine.traffic.used(pk, "month"),
    traffic_view=engine.traffic.view,
    out_view=engine.traffic.out_view,
    acct_ok=lambda: engine.acct_state == "ok",
    used=engine.traffic.used,
    client_out=lambda pk: engine.default_out(store.snapshot(), pk),
    balanced=lambda pk: engine.policy_for(store.snapshot(), pk)["balanced"] and pk in engine.bal,
    set_enabled=clients.set_client_enabled,
    apply_limits=clients.apply_limits,
    add_client=lambda name: user_errors(lambda: engine.srv.add_client(name)),
    delete_client=clients.delete_user,
    panel=lambda: {"url": panel_url(), "ssh": config.PANEL_HOST.startswith("127."), "port": config.PANEL_PORT,
                   "host": engine.srv.public_host(store.snapshot())},
    client_config=lambda pk: user_errors(lambda: engine.srv.client_config(pk)),
    share=clients.ensure_share,
    set_default=set_default_outbound,
    probe=engine.probe,
    trace=lambda target: routing.trace_target(None, target),
    list_name=_list_name,
    backup=_bot_backup,
    update_info=updates.status,
    update_state=selfupdate.status,
    start_update=lambda latest: selfupdate.start(VERSION, latest),
    audit=lambda msg: engine.event("info", msg),
)
bot = tgbot.Bot(store, bot_ops, engine.stop_ev)
