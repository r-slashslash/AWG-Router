"""Резервная копия: скачать, отправить в Telegram по расписанию, расшифровать и восстановить. Поля копии
проверяют те же функции, что ввод в панели (checks.py)."""
from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import shlex
import threading
import time

from .. import (awgconf, awgserver, checks, config, cps, notify,
                system, users)
from ..checks import bad
from ..i18n import Msg, msg_of, to_json
from ..panel import (app, engine, notifier, store)
from ..store import DEFAULT_STATE, Store
from ..version import VERSION

log = logging.getLogger("awgr")
# ------------------------------------------------------- резервная копия
BACKUP_FORMAT = "awg-router-backup"
SERVER_FILES = ("clientsTable", "wireguard_psk.key", "wireguard_server_public_key.key")


@app.get("/api/backup")
def get_backup(req):
    return make_backup()


@app.post("/api/backup/encrypted")
def get_backup_encrypted(req):
    """«Скачать копию» с паролем: тот же JSON, зашифрованный так же, как копии в Telegram
    (openssl, открывается «Восстановить из файла» с этим паролем)."""
    pw = str(req.json().get("password") or "")
    if not 8 <= len(pw) <= 128:
        bad("err.backup_pw")
    b = make_backup()
    data = json.dumps(b, ensure_ascii=False, indent=1).encode()
    return {"data": base64.b64encode(notify.encrypt(data, pw)).decode(), "host": b.get("host") or ""}


def make_backup() -> dict:
    st = store.snapshot(texts=True)          # тексты ручных списков — в самой копии, как до 1.21.0
    srv = None
    t = engine.target
    if t and t.exists:
        files = {}
        with engine.lock:
            names = [os.path.basename(t.conf_path), *SERVER_FILES]
            if t.wg_exists() and t.iface != "wg0":
                names += ["wg0.conf", "wg0.clientsTable"]
            for name in names:
                text = t.read_file(f"{t.dir}/{name}")
                if text is not None:
                    files[name] = text
        srv = {"kind": t.kind, "conf": os.path.basename(t.conf_path), "files": files}
    return {"format": BACKUP_FORMAT, "version": 1, "panel_version": VERSION, "created": time.time(),
            "host": engine.srv.public_host(st), "state": st, "traffic": engine.traffic.export(),
            "server": srv}


def send_backup(c: dict) -> None:
    """Копия в Telegram: тот же JSON, что «Скачать копию»; с паролем — зашифрованный openssl."""
    b = make_backup()
    data = json.dumps(b, ensure_ascii=False, indent=1).encode()
    host = re.sub(r"[^\w.-]+", "_", str(b.get("host") or "server"))
    name = f"awg-router-backup-{host}-{time.strftime('%Y-%m-%d')}.json"
    key = "backup"
    if c.get("backup_pw"):
        data, name, key = notify.encrypt(data, c["backup_pw"]), name + ".enc", "backup_enc"
    notify.send_document(c["token"], c["chat_id"], name, data,
                         notify.render(c["lang"], key, notifier.host_fn(store.snapshot())), c.get("via", "direct"))


_backup_try = 0.0


def backup_tick(now: float | None = None) -> bool:
    """Плановая копия, если пора. Неудача — повтор не раньше чем через час. True — отправлено."""
    global _backup_try
    now = time.time() if now is None else now
    c = notify.cfg_of(store.snapshot())
    period = notify.BACKUP_PERIODS.get(c["backup"], 0)
    if not (period and c["enabled"] and c["token"] and c["chat_id"]):
        return False
    # запас 10 минут: проверка раз в 15 минут не должна сдвигать расписание на сутки вперёд
    last = c.get("backup_last")
    if (last and now - last < period - 600) or now - _backup_try < 3600:
        return False
    _backup_try = now
    err = None
    try:
        send_backup(c)
    except Exception as e:  # noqa: BLE001
        err = to_json(msg_of(e))       # Msg — в виде {"$t": …}: переведёт браузер
        log.warning("telegram backup: %s", e)
    store.mutate(lambda st: st["settings"].setdefault("telegram", notify.defaults()).update(
        {"backup_error": err} if err else {"backup_last": now, "backup_error": None}))
    return err is None


def backup_loop() -> None:
    engine.stop_ev.wait(120)
    while not engine.stop_ev.is_set():
        try:
            backup_tick()
        except Exception:  # noqa: BLE001
            log.exception("backup")
        engine.stop_ev.wait(900)


# Копия больше обычного предела запроса (web.MAX_BODY, 4 МБ): тысяча клиентов с историей трафика или большие ручные
# списки — 4–5 МБ, а зашифрованная в base64 ещё на треть больше. Только эти два адреса и только после входа
BACKUP_BODY = 24 * 1024 * 1024


@app.post("/api/backup/decrypt")
def decrypt_backup(req):
    """Зашифрованная копия из Telegram → JSON для обычного восстановления."""
    body = req.json(BACKUP_BODY)
    try:
        data = base64.b64decode(str(body.get("data") or ""), validate=True)
    except (ValueError, binascii.Error):
        bad("err.backup_format")
    if not data.startswith(notify.ENC_MAGIC):
        bad("err.backup_format")
    plain = notify.decrypt(data, str(body.get("password") or ""))
    try:
        b = json.loads(plain) if plain is not None else None
    except (ValueError, RecursionError):
        b = None
    if not isinstance(b, dict):
        bad("err.backup_password")
    return {"backup": b}


def restore_state(st: dict, new: dict) -> None:
    """Состояние из копии вместо текущего. Адреса и название этого сервера важнее, чем в копии (переезд): и свои из
    панели, и отсутствие своих — тогда остаётся PUBLIC_HOST из .env, а не IP старого сервера в конфигах, ссылке
    и сертификате. Адрес клиента из копии (#37) остаётся, только если он есть и у этого сервера."""
    own = {k: st["settings"].get(k) for k in ("public_host", "client_host", "extra_hosts", "panel_name")}
    st.clear()
    st.update(new)
    for k, v in own.items():
        st["settings"].pop(k, None)
        if v:
            st["settings"][k] = v
    ok = set(engine.srv.host_choices(st))
    st["chost"] = {k: v for k, v in (st.get("chost") or {}).items() if v in ok}


def clean_backup_state(new: dict) -> dict:
    """Состояние из резервной копии → проверенное состояние.

    Каждое поле проходит те же проверки, что и при вводе в панели (checks.py, для настроек сервера — users.py):
    идентификаторы из файла попадают в имена наборов nftables, интерфейсов и файлов, поэтому ничего не берём «как
    есть». Неверное поле — ошибка с его именем (checks.backup_field); где копии прощалось и раньше — значение по
    умолчанию (checks.forgive). Здесь же чинится то, что прежние выпуски сохраняли иначе: круги резервов, «как
    резерв» у квоты, прежние имена шаблонов маскировки, IPv6 DNS, подписи правил с именем выхода."""
    at, soft = checks.backup_field, checks.forgive

    def fail(path: str):
        bad(Msg("err.backup_field", field=path))

    def arr(key: str) -> list:
        v = new.get(key, [])
        if not isinstance(v, list):
            fail(key)
        return v

    def obj(key: str) -> dict:
        v = new.get(key, {})
        if not isinstance(v, dict):
            fail(key)
        return v

    st = json.loads(json.dumps(DEFAULT_STATE))
    st["lists"], st["upstreams"] = [], []

    # списки сетей и доменов
    for i, l in enumerate(arr("lists")):
        f = f"lists[{i}]"
        if not isinstance(l, dict):
            fail(f)
        d = at(f, lambda: checks.list_fields({k: l.get(k) for k in ("kind", "source", "name")}))
        st["lists"].append({"id": at(f, lambda: checks.list_id(st, l.get("id"), d)), **d})

    # выходы: сначала все, потом резервные выходы (могут ссылаться друг на друга)
    raw_ups = arr("upstreams")
    for i, u in enumerate(raw_ups):
        f = f"upstreams[{i}]"
        if not isinstance(u, dict):
            fail(f)
        uid = at(f, lambda: checks.exit_id(st, u.get("id")))
        num = at(f + ".num", lambda: checks.exit_num(st, u.get("num")))
        pc = at(f + ".config", lambda: checks.exit_config(u.get("config")))
        e = {"id": uid, "name": at(f + ".name", lambda: checks.name(u.get("name"))), "num": num, "config": pc.raw,
             "enabled": at(f + ".enabled", lambda: checks.flag(u.get("enabled"), True)),
             "fallback": "direct", "created": u.get("created") if checks.number(u.get("created")) else None,
             "quota": soft(lambda: checks.quota(u.get("quota")), None), "quota_action": "notify",
             "quota_hit": checks.month(u.get("quota_hit")), "quota_warned": checks.month(u.get("quota_warned"))}
        for k in ("rate_down", "rate_up"):
            if u.get(k) not in (None, "") and (v := at(f"{f}.{k}", lambda: checks.rate(u[k]))):
                e[k] = v
        if "quic" in u and soft(lambda: checks.quic(u["quic"]), False) and pc.kind == "socks5":
            e["quic"] = True
        # свой список сайтов выхода (окно выхода): только если это список доменов из этой же
        # копии и он ещё не принадлежит другому выходу
        own = u.get("own_list")
        ol = Store.lst(st, own) if isinstance(own, str) else None
        if ol and ol["kind"] == "domains" and not any(x.get("own_list") == own for x in st["upstreams"]):
            e["own_list"] = own
        st["upstreams"].append(e)
    for i, u in enumerate(raw_ups):
        st["upstreams"][i]["fallback"] = at(f"upstreams[{i}].fallback", lambda: checks.fallback(
            st, u["id"], u.get("fallback") or "direct", loops_ok=True))
    for u in st["upstreams"]:
        # круг резервов (A → B → A) из копии, сделанной до 1.20.0: в панели его теперь не сохранить, а когда
        # все в круге лежат, клиенты остались бы без связи. Разрываем его резервом «напрямую».
        if checks.fallback_loops(st, u["id"], u["fallback"]):
            u["fallback"] = "direct"
    for i, u in enumerate(raw_ups):
        qa = u.get("quota_action") or "notify"
        if qa == "fallback":          # первые сборки 1.3.0: «как резерв»
            qa = st["upstreams"][i]["fallback"]
        st["upstreams"][i]["quota_action"] = at(f"upstreams[{i}].quota_action",
                                                lambda: checks.quota_action(st, qa, u["id"]))

    # маршрутизация
    r = obj("routing")
    st["routing"] = {"default": at("routing.default", lambda: checks.outbound(st, r.get("default", "direct"))),
                     "rules": at("routing.rules", lambda: checks.rules(st, r.get("rules", [])))}
    if r.get("balance") is not None:
        st["routing"]["balance"] = at("routing.balance", lambda: checks.balance(st, r["balance"]))
    if soft(lambda: checks.strict(r.get("strict")), None):
        st["routing"]["strict"] = True

    # политики клиентов
    for pk, c in obj("clients").items():
        f = f"clients.{pk[:12]}"
        at(f, lambda: checks.client_key(pk))
        if not isinstance(c, dict):
            fail(f)
        pol = at(f, lambda: checks.client_policy(st, c))
        if c.get("proto") == "wg":
            pol["proto"] = "wg"
        st["clients"][pk] = {**pol, "name": str(c.get("name") or "")[:60]}

    # закрытые ключи клиентов
    for pk, priv in obj("keys").items():
        st["keys"][pk] = at(f"keys.{pk[:12]}", lambda: checks.client_key(pk) and checks.client_key(priv))

    # сроки и лимиты
    for pk, L in obj("limits").items():
        f = f"limits.{pk[:12]}"
        at(f, lambda: checks.client_key(pk))
        if not isinstance(L, dict):
            fail(f)
        ao = L.get("auto_off")
        st["limits"][pk] = {
            "expires": soft(lambda: checks.expires(L.get("expires")), None),
            "quota": soft(lambda: checks.quota(L.get("quota")), None),
            "period": soft(lambda: checks.period(L.get("period")), "month"),
            "auto_off": ao if ao == "exp" or (isinstance(ao, str) and ao.startswith("quota:")
                                              and checks.quota_key(ao[6:])) else None,
            "exp_done": soft(lambda: checks.expires(L.get("exp_done")), None),
            "quota_done": checks.quota_key(L.get("quota_done")),
            "exp_warned": soft(lambda: checks.expires(L.get("exp_warned")), None),
            "quota_warned": checks.quota_key(L.get("quota_warned"))}
        for k in ("rate_down", "rate_up"):
            if v := at(f"{f}.{k}", lambda: checks.rate(L.get(k))):
                st["limits"][pk][k] = v

    # свой адрес сервера в конфиге клиента (#37); адреса, которых нет у этого сервера, снимает restore_state
    for pk, h in obj("chost").items():
        st["chost"][pk] = at(f"chost.{pk[:12]}", lambda: checks.client_key(pk) and checks.host_text(h))

    # свои I1–I5 клиентов
    for pk, e in obj("cps").items():
        f = f"cps.{pk[:12]}"
        at(f, lambda: checks.client_key(pk))
        if not isinstance(e, dict):
            fail(f)
        p = e.get("preset")
        p = cps.RENAMED.get(p, p) if isinstance(p, str) else p      # прежние имена шаблонов
        entry = at(f, lambda: checks.cps_entry(p, e.get("values")))
        if entry is None:              # «как на сервере» — это отсутствие записи: в копии её не бывает
            fail(f)
        st["cps"][pk] = entry

    # личные ссылки
    for tok, sh in obj("shares").items():
        if not checks.TOKEN_RE.match(tok) or not isinstance(sh, dict):
            fail("shares")
        st["shares"][tok] = {"pk": at("shares", lambda: checks.client_key(sh.get("pk"))),
                             "created": sh.get("created") if checks.number(sh.get("created")) else None}

    # пользователи входящего SOCKS5-прокси
    if "socks_users" in new:
        su_map = {}
        for uname, su in obj("socks_users").items():
            at("socks_users", lambda: checks.validate_socks_username(uname))
            f = f"socks_users.{uname}"
            if not isinstance(su, dict):
                fail(f)
            pw = at(f + ".password", lambda: checks.validate_socks_password(su.get("password")))
            ex = at(f + ".exit", lambda: checks.outbound(st, su.get("exit", "direct")))
            if ex == "block":
                fail(f + ".exit")
            en = at(f + ".enabled", lambda: checks.flag(su.get("enabled"), True))
            su_map[uname] = {"password": pw, "exit": ex, "enabled": en}
        st["socks_users"] = su_map

    # настройки: только известные поля. Адрес сервера, второй адрес, адрес для клиентов и название сервера во
    # вкладке — этого сервера, а не из копии (restore_state), поэтому из копии не берутся
    s, out = obj("settings"), st["settings"]
    if "list_update_hours" in s:
        out["list_update_hours"] = at("settings.list_update_hours",
                                      lambda: checks.list_update_hours(s["list_update_hours"]))
    if v := soft(lambda: checks.on_stop(s.get("on_stop")), None):
        out["on_stop"] = v
    if s.get("shaping") is not None and (v := at("settings.shaping", lambda: checks.shaping_limits(s["shaping"]))):
        out["shaping"] = v
    if s.get("client_dns") is not None:
        # IPv6 DNS из копий до 1.6.0 не берём: в туннеле только IPv4
        out["client_dns"] = at("settings.client_dns", lambda: users.check_client_dns(s["client_dns"], old_v6=True))
    for k in ("panel_dns", "dom_filter"):
        if (v := soft(lambda: users.check_flag(s.get(k)), None)) is not None:
            out[k] = v
    if v := soft(lambda: users.check_dns_enc(s.get("panel_dns_enc")), None):
        out["panel_dns_enc"] = v
    if out.get("panel_dns") and "panel_dns_enc" not in out:
        out["panel_dns_enc"] = Store.missing_dns_enc(new)     # как при запуске (Store._upgrade): по выпуску копии
    if s.get("client_mtu") not in (None, ""):
        out["client_mtu"] = at("settings.client_mtu", lambda: users.check_mtu(s["client_mtu"]))
    if s.get("client_keepalive") not in (None, "") and \
            (v := at("settings.client_keepalive", lambda: users.check_keepalive(s["client_keepalive"]))):
        out["client_keepalive"] = v
    tg = s.get("telegram")
    if tg is not None:
        if not isinstance(tg, dict):
            fail("settings.telegram")
        out["telegram"] = at("settings.telegram", lambda: checks.telegram(st, notify.defaults(), tg, backup=True),
                             sub=("via",))
    if "socks_proxy" in s:
        from .socks import _busy_tcp_ports

        sp = s["socks_proxy"]
        if not isinstance(sp, dict):
            fail("settings.socks_proxy")
        sp_port = at("settings.socks_proxy.port", lambda: checks.validate_socks_port(sp.get("port", 1080)))
        if sp_port in _busy_tcp_ports():
            fail("settings.socks_proxy.port")
        out["socks_proxy"] = {
            "enabled": at("settings.socks_proxy.enabled", lambda: checks.flag(sp.get("enabled"), False)),
            "port": sp_port,
        }
    Store.drop_auto_comments_once(st, new)    # копия до 1.21.0: правила из окна выхода с его именем
    Store.client_bot_once(st, new)            # копия до 1.22.0: бот только для уведомлений — без приглашений
    Store.bot_switch_once(st, new)            # копия до 1.23.0: бот без уведомлений, но с управлением — включён
    return st


def clean_server_files(srv: dict, kind: str) -> tuple[awgserver.ServerConf, dict[str, str]]:
    """Файлы сервера из резервной копии → проверенный конфиг и служебные файлы."""
    files = srv.get("files")
    if not isinstance(files, dict):
        bad("err.backup_format")
    conf = files.get(srv.get("conf") or "")
    if not isinstance(conf, str):
        bad("err.backup_format")
    sc = awgserver.parse(conf)
    if not awgconf.KEY_RE.match(sc.get("PrivateKey")) or not sc.network:
        bad("err.backup_format")
    if not awgserver.foreign_ok(conf, sc):
        bad(Msg("err.backup_field", field="server.conf"))
    for p in sc.peers:
        if not awgconf.KEY_RE.match(p.public_key) or (p.psk and not awgconf.KEY_RE.match(p.psk)):
            bad(Msg("err.backup_field", field="server.peers"))
    awgserver.safe_hooks(sc, kind == "host")
    out = {}
    for name in ("wireguard_psk.key", "wireguard_server_public_key.key"):
        text = files.get(name)
        if text is None:
            continue
        if not isinstance(text, str) or not awgconf.KEY_RE.match(text.strip()):
            bad(Msg("err.backup_field", field=f"server.{name}"))
        out[name] = text.strip() + "\n"
    if isinstance(files.get("clientsTable"), str):
        out["clientsTable"] = awgserver.render_clients_table(
            awgserver.parse_clients_table(files["clientsTable"]))
    if srv.get("conf") != "wg0.conf" and isinstance(files.get("wg0.conf"), str):
        wg_sc = awgserver.parse(files["wg0.conf"])
        if not awgconf.KEY_RE.match(wg_sc.get("PrivateKey")) or not wg_sc.network:
            bad("err.backup_format")
        if not awgserver.foreign_ok(files["wg0.conf"], wg_sc):
            bad(Msg("err.backup_field", field="server.wg0.conf"))
        for p in wg_sc.peers:
            if not awgconf.KEY_RE.match(p.public_key) or (p.psk and not awgconf.KEY_RE.match(p.psk)):
                bad(Msg("err.backup_field", field="server.peers"))
        awgserver.safe_hooks(wg_sc, kind == "host")
        out["wg0.conf"] = wg_sc.render()
        if isinstance(files.get("wg0.clientsTable"), str):
            out["wg0.clientsTable"] = awgserver.render_clients_table(
                awgserver.parse_clients_table(files["wg0.clientsTable"]))
    return sc, out


@app.post("/api/restore")
def restore_backup(req):
    body = req.json(BACKUP_BODY)
    b = body.get("backup")
    if not isinstance(b, dict) or b.get("format") != BACKUP_FORMAT or not isinstance(b.get("state"), dict):
        bad("err.backup_format")
    if not all(k in b["state"] for k in ("routing", "upstreams", "lists", "settings")):
        bad("err.backup_format")
    new = clean_backup_state(b["state"])
    srv = b.get("server") if body.get("server") else None
    t = engine.target
    sc = None
    srv_files: dict[str, str] = {}
    if srv:
        if not isinstance(srv, dict):
            bad("err.backup_format")
        if not t or not t.exists:
            bad("srv.no_server")
        if srv.get("kind") != t.kind:
            bad("err.backup_kind")
        sc, srv_files = clean_server_files(srv, t.kind)

    has_wg = ("wg0.conf" in srv_files) if sc is not None else bool(t and t.wg_exists())
    if not has_wg:
        for c in new.get("clients", {}).values():
            c.pop("proto", None)

    store.mutate(lambda st: restore_state(st, new))
    engine.traffic.replace(b.get("traffic") or {})
    restarted = False
    if sc is not None:
        with engine.lock:
            cur = engine.srv.load(t)[0] if t.read_file(t.conf_path) else None
            if t.kind != "host" and cur is not None:
                sc.set("ListenPort", str(cur.port))   # порт контейнера задан Docker'ом
            awgserver.upgrade_i1(sc)                  # старый I1 AmneziaVPN в копии
            t.write_file(t.conf_path, sc.render())
            for name, text in srv_files.items():
                mode = 0o644 if name in ("clientsTable", "wg0.clientsTable") else 0o600
                t.write_file(f"{t.dir}/{name}", text, mode)
            if isinstance(t, system.HostTarget):
                system.open_firewall_udp(t, sc.port)
            if "wg0.conf" not in srv_files and t.wg_exists() and t.iface != "wg0":
                t.disable_wg()
            t.restart()
            if "wg0.conf" in srv_files:
                wg_sc = awgserver.parse(srv_files["wg0.conf"])
                if isinstance(t, system.HostTarget):
                    system.open_firewall_udp(t, wg_sc.port)
                if not config.DRY_RUN and not isinstance(t, system.FakeTarget):
                    if t.kind == "container":
                        t = system.discover()
                        if not t.iface_exists("wg0"):
                            p = shlex.quote(t.conf_path_for("wg0"))
                            t.native(["sh", "-c", f"awg-quick down {p} 2>/dev/null || true; awg-quick up {p}"], timeout=60)
                    else:
                        t.native(["sh", "-c", "systemctl restart awg-quick@wg0 2>/dev/null || (awg-quick down wg0 2>/dev/null || true; awg-quick up wg0)"])
            restarted = True
        engine.event("warn", Msg("ev.restored_server"))
    else:
        engine.event("info", Msg("ev.restored"))
    engine.applied_hash = None
    engine.trigger()
    threading.Thread(target=lambda: engine.refresh_lists(False), daemon=True).start()
    return {"ok": True, "restarted": restarted}
