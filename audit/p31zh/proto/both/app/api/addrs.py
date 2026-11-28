"""Адреса сервера на «Маршрутизации» (1.25.0): окна входящего и исходящего адреса («Адреса сервера»).

Входящий: галочка у клиента — он подключается к этому адресу (адрес в его конфиге, chost), снятая — к основному.
Исходящий: галочки у мест, где выход «Напрямую» (правила, «По умолчанию», клиенты, резервы выходов, лимиты, бот) — с
этого адреса; у выходов через другой сервер — «Подключаться с адреса» (один на выход). Галочка выход не меняет, только
адрес перед ним; снятая — снова основной адрес."""
from __future__ import annotations

from .. import checks, srcaddr
from ..checks import bad
from ..i18n import Msg
from ..panel import app, engine, store
from ..store import Store
from . import routing


def _known(st: dict, a) -> str:
    if a != srcaddr.SYSTEM and a not in srcaddr.out_hosts(st):
        bad(Msg("err.unknown_address", value=str(a)[:60]))
    return a


@app.get("/api/addr-places")
def addr_places(req):
    """Для окна исходящего адреса: места «Напрямую» (ключ, подпись, адрес сейчас) и выходы (адрес подключения, где
    стоят). Адрес system — адрес системы (в браузере — его IP)."""
    st = store.snapshot()
    return {"direct": [{"key": k, "label": label, "addr": srcaddr.addr_of(st, o[f])}
                       for k, o, f, label in srcaddr.places(st)],
            "exits": [{"id": u["id"], "name": u["name"], "addr": srcaddr.bind_of(st, u),
                       "refs": Store.outbound_refs(st, "up:" + u["id"])[:4]} for u in st["upstreams"]],
            "main": srcaddr.main(st) or srcaddr.SYSTEM}


@app.put("/api/addr-out")
def put_addr_out(req):
    """{"addr", "direct": [ключи мест], "exits": [id выходов]}: отмеченные — с этого адреса, снятые с него — основной."""
    body = req.json()
    keys = body.get("direct") or []
    ids = body.get("exits") or []
    if not isinstance(keys, list) or not isinstance(ids, list):
        bad("err.bad_value")

    def fn(st):
        a = _known(st, body.get("addr"))
        for k, o, f, _ in srcaddr.places(st):
            if k in keys:
                o[f] = srcaddr.fold(st, srcaddr.PFX + a)
            elif srcaddr.addr_of(st, o[f]) == a:
                o[f] = srcaddr.DIRECT                       # снятая галочка — основной адрес
        for u in st["upstreams"]:
            if u["id"] in ids:
                if b := checks.bind(st, a):
                    u["bind"] = b
                else:
                    u.pop("bind", None)
            elif srcaddr.bind_of(st, u) == a:
                u.pop("bind", None)
        srcaddr.normalize(st)
    _, changed = routing.mutate_paths(fn)
    engine.trigger()
    return {"ok": True, **routing.reconnect(changed)}


@app.put("/api/addr-in")
def put_addr_in(req):
    """{"host", "clients": [ключи]}: отмеченные клиенты подключаются к этому адресу, снятые с него — к основному. →
    у кого адрес в конфиге поменялся (им нужен новый конфиг)."""
    body = req.json()
    pks = body.get("clients") or []
    if not isinstance(pks, list):
        bad("err.bad_value")
    st0 = store.snapshot()
    host = str(body.get("host") or "")
    main = engine.srv.client_host(st0)
    if host != main and host not in engine.srv.host_choices(st0):
        bad("srv.bad_client_host")
    known = {c["public_key"]: c.get("name") or c["public_key"][:8] for c in engine.clients}

    def fn(st):
        m = st.setdefault("chost", {})
        moved = []
        for pk, name in known.items():
            before = m.get(pk) or main
            if pk in pks:
                if host == main:
                    m.pop(pk, None)
                else:
                    m[pk] = host
            elif m.get(pk) == host and host != main:
                m.pop(pk, None)
            if (m.get(pk) or main) != before:
                moved.append(name)
        return moved
    moved = store.mutate(fn)
    return {"ok": True, "moved": moved}
