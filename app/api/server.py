"""Сервер AWG: его настройки, движок (модуль ядра или amneziawg-go), перезапуск; HTTPS панели и её
обновление."""
from __future__ import annotations

import re
import time

from .. import (config, hostnet, kernelmod, selfupdate, system, tlsconf, tlsmgr, webfront)
from ..checks import bad
from ..i18n import Msg, MsgError, msg_of
from ..panel import (app, engine, panel_url, store, tls, updates,
                     user_errors, write_status)
from ..users import UserError
from ..store import Store
from ..version import VERSION
from .. import checks, srcaddr

# Ошибки настроек сервера (users.update_server) → поле формы «Сервер»; ошибки параметров AWG — по ключу
SERVER_FIELDS = {"srv.bad_host": "public_host", "srv.bad_extra_host": "extra_hosts",
                 "srv.bad_out_host": "out_hosts", "srv.out_hosts_max": "out_hosts", "srv.bad_out_main": "out_main",
                 "srv.out_main_removed": "out_main",
                 "srv.bad_client_host": "client_host", "srv.bad_dns": "client_dns", "srv.dns_v6": "client_dns",
                 "srv.bad_mtu": "client_mtu", "srv.bad_keepalive": "client_keepalive",
                 "srv.bad_dns_enc": "panel_dns_enc", "srv.bad_fallback_dns": "fallback_dns",
                 "srv.fallback_dns_many": "fallback_dns", "srv.fallback_dns_self": "fallback_dns",
                 "srv.fallback_dns_empty": "fallback_dns", "err.dns_name": "fallback_dns",
                 "srv.bad_port": "port", "srv.port_failed": "port",
                 "srv.port_dns": "port", "srv.bad_subnet": "address",
                 "srv.subnet_locked": "address", "srv.subnet_container": "address"}
PARAM_ERRORS = ("srv.bad_param", "srv.bad_int", "srv.bad_range", "srv.bad_bool", "srv.bad_key", "srv.bad_junk")


def server_field(m) -> str | None:
    if not isinstance(m, Msg):
        return None
    if m.key in PARAM_ERRORS and isinstance(m.p.get("key"), str):
        return "params." + m.p["key"]
    return SERVER_FIELDS.get(m.key)


# ------------------------------------------------------- обновление панели
_last_check = 0.0


@app.post("/api/update/check")
def update_check(req):
    """Проверить новую версию сейчас, не дожидаясь проверки раз в 6 часов."""
    global _last_check
    if time.time() - _last_check > 10:
        _last_check = time.time()
        updates.check()
    return updates.status()


@app.post("/api/update/run")
def update_run(req):
    st = updates.status()
    if not st["available"] and not config.DRY_RUN:
        bad("err.update_none")
    try:
        return selfupdate.start(VERSION, st["latest"])
    except MsgError as e:
        bad(e.msg)


@app.get("/api/update/status")
def update_status(req):
    return {**selfupdate.status(), "current": VERSION, "log": selfupdate.log_lines(20)}


# ------------------------------------------------------------------- server
@app.get("/api/server")
def get_server(req):
    return user_errors(engine.srv.server_view)


@app.put("/api/server")
def put_server(req):
    body = req.json()
    names = tls.names()
    try:
        res = engine.srv.update_server(body)
    except (UserError, MsgError) as e:
        bad(e.msg, field=server_field(e.msg))
    if "confirm" in res:
        return res                     # браузер спросит «Да / Нет» и пришлёт снова (адреса не сохранены)
    # адреса: проверить сейчас; сохранили снова — и неработавшие проверяются с начала
    if "out_hosts" in body or "extra_hosts" in body or "client_host" in body:
        st = store.snapshot()
        engine.addrs_wake(retry=[*srcaddr.out_hosts(st), *engine.inbound_ips(st)])
    engine.reconcile_soon()
    if tls.names() != names:
        tls.reconfigure()              # адрес панели или второй адрес сертификата сменился
    return res


# ------------------------------------------------------- модуль ядра (рекомендуемый движок)
ENGINE_HIDE_RE = re.compile(r"^[a-z]{3,10}(:\d{1,12})?$")
# API-токен Cloudflare: 40 знаков у нынешних, но формат не обещан — латиница, цифры, «_», «-», «.» без пробелов
CF_TOKEN_RE = re.compile(r"[A-Za-z0-9_.-]{20,200}")


def engine_offer(t) -> dict:
    """Модуль ядра в /api/state: подходит ли сервер, идёт ли установка и какое оповещение показать сверху.
    notice — вид оповещения (offer: модуля нет; old: модуль старше 3.x; lost: модуль пропал, сервер на
    amneziawg-go; disabled: панель сама отключила модуль после сбоя; restart: модуль есть, а сервер ещё на
    amneziawg-go; installing). Вид с отметкой времени (lost:…, disabled:…) — новый случай снова показывается,
    даже если прошлый скрыли."""
    f = kernelmod.fit()
    ks = kernelmod.load()
    job = kernelmod.status()
    m = engine.module_info()
    notice = None
    if t and t.exists:
        if job["state"] == "running":
            notice = "installing"
        elif ks.get("disabled"):
            notice = f"disabled:{int((ks['disabled'] or {}).get('at') or 0)}"
        elif ks.get("choice") == "go":
            notice = None                    # amneziawg-go выбран вручную — модуль не навязываем
        elif m["loaded"] and m["ok"]:
            notice = "restart" if engine.server_engine == "go" else None
        elif f["ok"]:
            notice = "old" if m["loaded"] else f"lost:{int(ks['lost'])}" if ks.get("lost") else "offer"
        if notice and notice != "installing" and ks.get("hidden") == notice:
            notice = None
    return {"fit": f["ok"], "fit_why": f["why"], "install": job, "notice": notice,
            "disabled": ks.get("disabled"), "lost": ks.get("lost"), "choice": ks.get("choice")}


@app.post("/api/engine/choose")
def engine_choose(req):
    """Ручной выбор движка: {"engine": "kernel" | "go"} — сервер перезапускается (или ставится модуль)."""
    choice = req.json().get("engine")
    if choice not in ("kernel", "go"):
        bad("err.bad_value")
    try:
        return engine.switch_engine(choice)
    except MsgError as e:
        bad(e.msg, 409)
    except Exception as e:  # noqa: BLE001  — docker или systemctl не смогли: показать почему
        bad(msg_of(e), 409)


@app.post("/api/engine/install")
def engine_install(req):
    """Кнопка «Установить модуль»: install.sh --install-kernel на хосте (kernelmod.start)."""
    try:
        return kernelmod.start()
    except MsgError as e:
        bad(e.msg, 409)


@app.get("/api/engine/install")
def engine_install_status(req):
    return {**kernelmod.status(), "log": kernelmod.log_lines(40)}


@app.put("/api/engine")
def put_engine(req):
    """«Скрыть» у оповещения про модуль ядра: hidden — его вид (engine_offer), пусто — показывать снова."""
    h = req.json().get("hidden")
    if h is not None and not (isinstance(h, str) and ENGINE_HIDE_RE.match(h)):
        bad("err.bad_value")
    kernelmod.update(hidden=h or None)
    return {"ok": True}


@app.post("/api/server/restart")
def restart_server(req):
    """Кнопка «Перезапустить сервер AWG»: клиенты отключатся на несколько секунд."""
    try:
        engine.restart_server()
    except Exception as e:  # noqa: BLE001  — docker или systemctl не смогли: показать почему
        bad(msg_of(e), 409)
    return {"ok": True}


@app.post("/api/server/generate")
def gen_server_params(req):
    return {"params": engine.srv.regenerate_params()}


@app.post("/api/server/init")
def init_server(req):
    body = req.json()
    try:
        port = int(body.get("port") or system.random_udp_port())
    except (TypeError, ValueError):
        bad("srv.bad_port")
    user_errors(lambda: engine.srv.init_host(port, str(body.get("subnet") or "10.8.1.0/24")))
    engine.reconcile_soon()
    return {"ok": True}


@app.post("/api/tls/renew")
def tls_renew(req):
    if tls.source() != "letsencrypt":
        bad("err.bad_value")
    ok = tls.renew_now()
    return {"ok": ok, "tls": tls.status()}




def _server_ips() -> list[str]:
    """Адреса этого сервера: внешний IPv4 (проверка «напрямую»), адрес из настроек, IPv6 интерфейсов."""
    ips = [engine.public_v4, engine.srv.public_host(store.snapshot()), config.PUBLIC_HOST]
    ips += hostnet.global_ipv6()
    return [a for a in ips if a and tlsmgr._is_ip(a)]


def _set_panel_ip(st: dict, ip: str) -> None:
    """Адрес панели — IP: своя настройка, а то же, что PUBLIC_HOST в .env, — без своей (как на вкладке «Сервер»)."""
    s = st["settings"]
    Store.split_hosts(st)                  # адрес клиентов уже записан явно — смена адреса панели его не тронет
    if ip.lower() == (config.PUBLIC_HOST or "").lower():
        s.pop("public_host", None)
    else:
        s["public_host"] = ip


def _need_web(host: str) -> dict | None:
    """Порт 80 занят веб-сервером, а проверка Let's Encrypt через него для host не настроена."""
    web = tlsconf.load().get("web")
    if web and web.get("host") == host:
        return None
    if not (config.DRY_RUN or webfront.listeners()):
        return None
    return webfront.info(host)


@app.put("/api/tls")
def tls_set(req):
    """Домен панели и откуда сертификат: Let's Encrypt или свой (файлы на хосте)."""
    if not tls.enabled:
        bad("tls.off")
    body = req.json()
    domain = str(body.get("domain") or "").strip().lower().rstrip(".")
    # «%» — зона IPv6 (fe80::1%eth0): ipaddress принимает в ней любой текст, а домен уходит в настройки веб-сервера
    if domain and ("%" in domain or not (checks.HOSTNAME_RE.fullmatch(domain) or tlsmgr._is_ip(domain))):
        bad("tls.bad_domain")
    src = body.get("source")
    if src not in tlsconf.SOURCES:
        bad("err.bad_value")
    cert, key = str(body.get("cert") or "").strip(), str(body.get("key") or "").strip()
    host = domain or engine.srv.public_host(store.snapshot())
    if not host:
        bad("tls.no_host")
    # проверка домена через DNS Cloudflare (1.24.0): только Let's Encrypt на домен; пустой токен — оставить сохранённый
    ch = body.get("challenge") or "http"
    if ch not in tlsconf.CHALLENGES:
        bad("err.bad_value")
    token = None
    if ch == "cloudflare" and src == "letsencrypt":
        if not domain or tlsmgr._is_ip(domain):
            bad("tls.cf_need_domain", field="tls_domain")
        token = str(body.get("cf_token") or "").strip() or tlsconf.cf_token()
        if not token:
            bad("tls.cf_token_empty", field="cf_token")
        if not CF_TOKEN_RE.fullmatch(token):
            bad("tls.cf_token_bad", field="cf_token")
    if domain and not tlsmgr._is_ip(domain) and not body.get("force"):
        m = tlsmgr.check_dns(domain, _server_ips())
        if m:
            return {"ok": False, "confirm": m}
    if src == "custom":
        m = tlsmgr.check_custom(cert, key, host)
        if m:
            bad(m)
    if token and not config.DRY_RUN:
        m = tlsmgr.cf_check(token, domain)
        if m:
            bad(m, field="cf_token")
    old_host = tls.host()
    if domain and tlsmgr._is_ip(domain):
        # «Адрес панели» — IP (1.25.0, вкладка «Система»): это адрес сервера в настройках (public_host), а не домен
        # сертификата — так в сертификат по IP попадает и второй адрес (IPv6). Адреса клиентов он не трогает: у них
        # свой «Входящий адрес сервера»
        store.mutate(lambda st: _set_panel_ip(st, domain))
        domain = ""
    # без проверки через Cloudflare токен на сервере не хранится
    tlsconf.update(domain=domain, source=src, cert=cert if src == "custom" else None,
                   key=key if src == "custom" else None, challenge="cloudflare" if token else None, cf_token=token)
    warn = None
    if host != old_host:
        try:
            webfront.reinstall_for(host)
        except webfront.WebError as e:
            warn = e.msg
        engine.event("info", Msg("ev.panel_host", host=host))
    tls.reconfigure()
    write_status()
    return {"ok": True, "tls": tls.status(), "url": panel_url(), "warn": warn,
            "web": _need_web(host) if src == "letsencrypt" and not token else None}


@app.get("/api/tls/web")
def tls_web(req):
    if not tls.enabled:
        bad("tls.off")
    return webfront.info(tls.host())


@app.post("/api/tls/web")
def tls_web_set(req):
    """Проверка Let's Encrypt через веб-сервер на порту 80: add — наш файл, manual — вставили сами."""
    if not tls.enabled:
        bad("tls.off")
    action = req.json().get("action")
    host = tls.host()
    try:
        if action == "add":
            web = webfront.install(host)
        elif action == "manual":
            web = webfront.manual(host)
        elif action == "remove":
            web = None
            webfront.remove()
        else:
            bad("err.bad_value")
    except webfront.WebError as e:
        bad(e.msg)
    if web:
        engine.event("info", Msg("ev.web_added", server=web.get("process") or "web", file=web.get("file") or ""))
    tls.reconfigure()
    return {"ok": True, "tls": tls.status()}
