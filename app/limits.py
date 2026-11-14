"""Срок действия и лимит трафика клиентов (state["limits"][public_key]).

Поля: expires — время окончания (unix) или None; quota — лимит в байтах или None;
period — "month" (календарный месяц, UTC) или "total"; auto_off — почему панель сама
отключила клиента: "exp" (истёк срок) или "quota:<месяц|total>" (исчерпан лимит);
exp_done / quota_done — чтобы не отключать повторно, если клиента включили вручную;
exp_warned / quota_warned — предупреждение заранее (за WARN_DAYS дней, при WARN_SHARE лимита)
уже было: срок (unix) / месяц или "total".
"""
from __future__ import annotations

import logging
import math
import time

from .i18n import Msg
from .traffic import month_key

log = logging.getLogger("awgr.limits")

GB = 1024 ** 3
EXPIRES_MAX = 253402300799    # 9999-12-31 23:59:59 UTC: дальше дату не перевести в текст (time.gmtime)
WARN_DAYS = 3          # предупредить о конце срока заранее
WARN_SHARE = 0.9       # и о лимите трафика


def _name(c: dict) -> str:
    return c.get("name") or c.get("ip") or c["public_key"][:8]


WARN_EVERY = 600       # с: неудачную попытку включить или отключить клиента пишем в журнал не чаще
_warned: dict[str, float] = {}


def _set_enabled(engine, pk: str, on: bool) -> bool:
    try:
        engine.srv.update_client(pk, enabled=on)
        _warned.pop(pk, None)
        return True
    except Exception as e:  # noqa: BLE001
        # попытка повторится на следующем проходе (enforce): журнал не засоряем
        if time.time() - _warned.get(pk, 0) >= WARN_EVERY:
            _warned[pk] = time.time()
            log.warning("limits: %s %s: %s", "enable" if on else "disable", pk[:8], e)
        return False


def enforce(engine, now: float | None = None) -> None:
    """Вызывается движком после каждого опроса клиентов."""
    st = engine.store.snapshot()
    lim = st.get("limits") or {}
    if not lim:
        return
    now = time.time() if now is None else now
    mk = month_key(now)
    patches: dict[str, dict] = {}
    for c in list(engine.clients):
        pk = c["public_key"]
        L = lim.get(pk)
        if not L:
            continue
        p: dict = {}
        exp = L.get("expires")
        expired = bool(exp) and now >= exp
        period = L.get("period") or "month"
        ao = L.get("auto_off")
        if ao and c["enabled"]:
            p["auto_off"] = None            # клиента включили вручную
            ao = None
        # Отметка «сделано» ставится, только когда клиент действительно отключён: сбой отключения (awg
        # syncconf не прошёл) иначе оставил бы клиента работать после срока или сверх лимита насовсем.
        if expired and L.get("exp_done") != exp:
            if not c["enabled"]:
                p["exp_done"] = exp
            elif _set_enabled(engine, pk, False):
                p["exp_done"] = exp
                p["auto_off"] = "exp"
                engine.event("warn", Msg("ev.client_expired", name=_name(c), pk=pk))
        if exp and not expired and c["enabled"] and exp - now <= WARN_DAYS * 86400 \
                and L.get("exp_warned") != exp:
            p["exp_warned"] = exp
            engine.event("warn", Msg("ev.client_expiring", name=_name(c), pk=pk,
                                     date=time.strftime("%Y-%m-%d", time.gmtime(exp)),
                                     days=max(1, math.ceil((exp - now) / 86400))))
        q = L.get("quota")
        key = mk if period == "month" else "total"
        if q and not expired and c["enabled"] and L.get("quota_warned") != key \
                and q * WARN_SHARE <= engine.traffic.used(pk, period) < q:
            p["quota_warned"] = key
            engine.event("warn", Msg("ev.client_quota_warn", name=_name(c), pk=pk, gb=round(q / GB, 2)))
        if q and not expired and engine.traffic.used(pk, period) >= q and L.get("quota_done") != key:
            if not c["enabled"]:
                p["quota_done"] = key
            elif _set_enabled(engine, pk, False):
                p["quota_done"] = key
                p["auto_off"] = "quota:" + key
                engine.event("warn", Msg("ev.client_quota", name=_name(c), pk=pk, gb=round(q / GB, 2)))
        if ao and ao.startswith("quota:") and ao != "quota:" + key and period == "month" \
                and not expired and not c["enabled"]:
            if _set_enabled(engine, pk, True):
                p["auto_off"] = None
                engine.event("info", Msg("ev.client_quota_reset", name=_name(c), pk=pk))
        if p:
            patches[pk] = p
    if patches:
        def fn(s):
            for pk, p in patches.items():
                if pk in s.setdefault("limits", {}):
                    s["limits"][pk].update(p)
        engine.store.mutate(fn)


FIRST_WAIT = 90 * 86400    # столько ждём первого подключения нового клиента


def first_seen(engine, now: float | None = None) -> None:
    """Клиент, созданный в панели или боте, впервые подключился (state["await_first"][pk] —
    когда создан): событие ev.client_first, по нему — уведомление «конфиг работает»."""
    st = engine.store.snapshot()
    wait = st.get("await_first") or {}
    if not wait or not engine.clients:
        return
    now = time.time() if now is None else now
    present = {c["public_key"]: c for c in engine.clients}
    drop = []
    for pk, since in wait.items():
        c = present.get(pk)
        if c is None or now - (since or 0) > FIRST_WAIT:
            drop.append(pk)                   # удалён мимо панели или так и не подключился
        elif c["enabled"] and (c.get("live") or {}).get("handshake"):
            drop.append(pk)
            engine.event("info", Msg("ev.client_first", name=_name(c), pk=pk))
    if drop:
        def fn(s):
            for pk in drop:
                s.get("await_first", {}).pop(pk, None)
        engine.store.mutate(fn)


def view(L: dict | None) -> dict:
    L = L or {}
    return {"expires": L.get("expires"), "quota": L.get("quota"),
            "period": L.get("period") or "month", "auto_off": L.get("auto_off"),
            "rate_down": L.get("rate_down"), "rate_up": L.get("rate_up")}
