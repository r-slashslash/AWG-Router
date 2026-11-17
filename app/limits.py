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


class _Batch:
    """Включения и отключения одного прохода — одной записью сервера в конце (Server.set_enabled_many), а
    не по клиенту. then(pk, on, fn): fn() — что сделать, когда клиент действительно переключён (отметки,
    события). Не вышло — попытка повторится на следующем проходе, журнал не засоряем."""

    def __init__(self):
        self.wanted: dict[str, bool] = {}
        self.after: dict[str, object] = {}

    def then(self, pk: str, on: bool, fn) -> None:
        self.wanted[pk] = on
        self.after[pk] = fn

    def run(self, engine) -> None:
        if not self.wanted:
            return
        try:
            done = engine.srv.set_enabled_many(self.wanted)
            err = None
        except Exception as e:  # noqa: BLE001
            done, err = set(), e
        for pk, on in self.wanted.items():
            if pk in done:
                _warned.pop(pk, None)
                self.after[pk]()
            elif time.time() - _warned.get(pk, 0) >= WARN_EVERY:
                _warned[pk] = time.time()
                log.warning("limits: %s %s: %s", "enable" if on else "disable", pk[:8], err or "no such client")


def _current(engine, pk: str) -> dict:
    """Срок и лимит клиента сейчас, а не в снимке начала прохода: администратор мог только что продлить
    срок или поднять лимит, и отключать клиента по старым значениям нельзя."""
    return engine.store.peek(lambda st: dict((st.get("limits") or {}).get(pk) or {}))


def enforce(engine, now: float | None = None) -> None:
    """Вызывается движком после каждого опроса клиентов."""
    st = engine.store.snapshot()
    lim = st.get("limits") or {}
    if not lim:
        return
    now = time.time() if now is None else now
    mk = month_key(now)
    patches: dict[str, dict] = {}
    batch = _Batch()

    def mark(pk, ev=None, **fields):
        def fn():
            patches.setdefault(pk, {}).update(fields)
            if ev:
                engine.event(*ev)
        return fn
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
            elif _current(engine, pk).get("expires") != exp:
                pass                            # срок только что изменили — решит следующий проход
            else:
                batch.then(pk, False, mark(pk, ("warn", Msg("ev.client_expired", name=_name(c), pk=pk)),
                                           exp_done=exp, auto_off="exp"))
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
            cur = _current(engine, pk)
            if not c["enabled"]:
                p["quota_done"] = key
            elif cur.get("quota") != q or (cur.get("period") or "month") != period:
                pass                            # лимит только что изменили — решит следующий проход
            else:
                batch.then(pk, False, mark(pk, ("warn", Msg("ev.client_quota", name=_name(c), pk=pk,
                                                            gb=round(q / GB, 2))),
                                           quota_done=key, auto_off="quota:" + key))
        if ao and ao.startswith("quota:") and ao != "quota:" + key and period == "month" \
                and not expired and not c["enabled"]:
            batch.then(pk, True, mark(pk, ("info", Msg("ev.client_quota_reset", name=_name(c), pk=pk)),
                                      auto_off=None))
        # Срок продлили или лимит подняли в тот момент, когда проход отключал клиента: сохранение лимитов
        # включает такого клиента само, но отметки «отключён по сроку» тогда ещё не было. Включаем здесь.
        elif not c["enabled"] and not expired and (
                ao == "exp" or (ao == "quota:" + key and (not q or engine.traffic.used(pk, period) < q))):
            batch.then(pk, True, mark(pk, auto_off=None))
        if p:
            patches.setdefault(pk, {}).update(p)
    batch.run(engine)
    if patches:
        def fn(s):
            for pk, p in patches.items():
                cur = s.setdefault("limits", {}).get(pk)
                old = lim.get(pk) or {}
                if cur is None:
                    continue
                if (cur.get("expires"), cur.get("quota"), cur.get("period")) != \
                        (old.get("expires"), old.get("quota"), old.get("period")):
                    # запись поменяли во время прохода — отметки к ней не подходят; но если клиента мы уже
                    # отключили, пометка нужна: по ней следующий проход включит его обратно
                    if p.get("auto_off"):
                        cur["auto_off"] = p["auto_off"]
                    continue
                cur.update(p)
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
