"""Клиенты HTTP(S)-прокси: изменение настроек и управление приёмниками."""
from .. import proxy_clients
from ..checks import bad
from ..panel import app, proxies, store


@app.post("/api/proxy-clients")
def add_proxy(req):
    result = store.mutate(lambda st: proxy_clients.save(st, req.json()))
    proxies.sync()
    return result


@app.put("/api/proxy-clients/{uid}")
def edit_proxy(req, uid):
    result = store.mutate(lambda st: proxy_clients.save(st, req.json(), uid))
    proxies.sync()
    return result


@app.delete("/api/proxy-clients/{uid}")
def delete_proxy(req, uid):
    if not store.mutate(lambda st: proxy_clients.delete(st, uid)):
        bad("err.not_found", 404)
    proxies.sync()
    return {"ok": True}
