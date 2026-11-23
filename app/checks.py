"""Проверка того, что вводят в панель: одна функция на каждую вещь — выход, список, правило, клиент, срок и лимит,
маскировка, личная ссылка, настройки панели, Telegram.

Эти функции зовут и обработчики API (app/api), и восстановление из резервной копии (api.backup.clean_backup_state):
правило, что можно сохранить, записано один раз. Клиентские настройки сервера (адрес, DNS, MTU, keepalive) так же
один раз проверяет users.py — для формы «Сервер» и для копии.

Неверное значение — HTTPError 400 с текстом (ключ Msg) и, где известно, полем формы: браузер выделит его.
Восстановление превращает ошибку в «err.backup_field» с путём поля в копии (backup_field), а там, где копии
прощалось и раньше (старые копии, файлы, исправленные руками), берёт значение по умолчанию (forgive)."""
from __future__ import annotations

import contextlib
import copy
import math
import re

from . import awgconf, config, cps, domains, limits, lists, notify, shaping
from .i18n import Msg, MsgError
from .store import ID_RE, Store, new_id
from .web import HTTPError


def bad(msg, code: int = 400, field: str | None = None):
    raise HTTPError(code, msg, field)


@contextlib.contextmanager
def field(name: str):
    """Ошибка проверки внутри блока — об этом поле запроса (браузер выделит его в форме)."""
    try:
        yield
    except HTTPError as e:
        if e.field is None:
            e.field = name
        raise


def forgive(fn, default):
    """Для копии: неверное значение — значение по умолчанию, а не отказ (так копии загружались всегда)."""
    try:
        return fn()
    except (HTTPError, MsgError):
        return default


def backup_field(path: str, fn, sub: tuple = ()):
    """Для копии: ошибка проверки — «в копии неверное поле <path>» (восстановление не начинается). sub — поля
    внутри, которые называются отдельно (<path>.<поле>)."""
    try:
        return fn()
    except (HTTPError, MsgError) as e:
        f = getattr(e, "field", None)
        bad(Msg("err.backup_field", field=f"{path}.{f}" if f in sub else path))


# ------------------------------------------------------------ простые значения
def number(v) -> bool:
    """Конечное число (Infinity и NaN из JSON — нет: int() на них падает; true — не число)."""
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def flag(v, default=None) -> bool:
    """Галочка: только true/false. Через bool() строка "false" или "no" включила бы настройку (интерфейс шлёт
    bool, так ломался только запрос, собранный вручную). default — значение, когда поле не прислано (None)."""
    if v is None and default is not None:
        return default
    if not isinstance(v, bool):
        bad("err.bad_value")
    return v


def name(v, maxlen: int = 40) -> str:
    v = str(v or "").strip()
    if not v:
        bad("err.name_required")
    return v[:maxlen]


PANEL_NAME_MAX = 40


def panel_name(v) -> str:
    """Название сервера для вкладки браузера (#38): одна строка без управляющих знаков; пусто — адрес сервера."""
    if v is None:
        return ""
    if not isinstance(v, str):
        bad("err.bad_value", field="panel_name")
    v = " ".join(v.split())
    if any(ord(c) < 32 or 0x7f <= ord(c) < 0xa0 for c in v):
        bad("err.bad_value", field="panel_name")
    if len(v) > PANEL_NAME_MAX:
        bad(Msg("err.panel_name_long", max=PANEL_NAME_MAX), field="panel_name")
    return v


def rate(v) -> float | None:
    """Ограничение скорости, Мбит/с ("" / None / 0 — без ограничения)."""
    if v in (None, "", 0):
        return None
    try:
        v = float(v)
    except (TypeError, ValueError):
        bad(Msg("err.rate", min=shaping.MIN_MBIT, max=shaping.MAX_MBIT))
    if not shaping.MIN_MBIT <= v <= shaping.MAX_MBIT:
        bad(Msg("err.rate", min=shaping.MIN_MBIT, max=shaping.MAX_MBIT))
    return round(v, 3)


def rates(body: dict, prefix: str = "rate_") -> dict:
    """{rate_down, rate_up} из тела запроса — только те, что в нём есть."""
    return {k: rate(body[prefix + k[5:]]) for k in ("rate_down", "rate_up") if prefix + k[5:] in body}


def client_key(pk) -> str:
    """Открытый ключ клиента (в адресе запроса и в копии)."""
    if not isinstance(pk, str) or not awgconf.KEY_RE.match(pk):
        bad("err.bad_client_key")
    return pk


# ----------------------------------------------------------- куда идёт трафик
def outbound(st: dict, v, allow_inherit: bool = False) -> str:
    """Выход: direct | block | up:<id> существующего выхода (у клиента ещё inherit — «как у всех»)."""
    if not isinstance(v, str):
        bad("err.bad_outbound")
    if v in ("direct", "block") or (allow_inherit and v == "inherit"):
        return v
    if v.startswith("up:") and Store.upstream(st, v[3:]):
        return v
    bad(Msg("err.unknown_outbound", value=v))


def rules(st: dict, rules, self_dns: str | None = None) -> list[dict]:
    """Правила «списки → выход» (общие и клиента). self_dns — адрес, на котором слушает DNS на сервере: свой DNS
    правила с ним бесполезен (DNS на сервере не спрашивает сам себя, имена ушли бы к общим серверам), поэтому
    при сохранении из панели он не принимается; копии и выходы проверяют без него, как до 1.22.0."""
    if not isinstance(rules, list) or len(rules) > 50:
        bad("err.bad_rules")
    out = []
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            bad("err.bad_rules")
        ls = r.get("lists") or []
        if not isinstance(ls, list) or not ls:
            bad("err.rule_no_lists")
        for lid in ls:
            if not Store.lst(st, lid):
                bad(Msg("err.unknown_list", id=lid))
        to = outbound(st, r.get("outbound"))
        # списки доменов и списки сетей в одном правиле не смешиваются: домены sniproxy.py
        # проверяет раньше правил по адресам (по имени в начале соединения), выход — любой
        if len({Store.lst(st, lid)["kind"] == "domains" for lid in ls}) > 1:
            bad("err.rule_mixed_domains")
        rid = r.get("id") if isinstance(r.get("id"), str) and ID_RE.match(r.get("id", "")) else new_id("r_")
        out.append({"id": rid, "lists": list(dict.fromkeys(ls)),
                    "outbound": to,
                    "enabled": flag(r.get("enabled"), True),     # "false" строкой — не «включено»
                    "comment": str(r.get("comment") or "")[:80]})
        # свой DNS — только у правила по сайтам (адрес сайта из списка сетей до ответа DNS не известен);
        # поле пишется, только если задано: состояние и копии без него — как до 1.22.0
        if Store.lst(st, ls[0])["kind"] == "domains":
            with field(f"rule_dns_{i}"):
                dns = rule_dns(r.get("dns"))
                if self_dns and self_dns in dns:
                    bad(Msg("err.rule_dns_self", value=self_dns))
            if dns:
                out[-1]["dns"] = dns
    return out


RULE_DNS_MAX = 2


def rule_dns(v) -> list[str]:
    """Свой DNS правила по сайтам: до двух IPv4 — списком или строкой (через запятую или пробел); пусто — []."""
    import ipaddress
    if v in (None, "", []):
        return []
    if isinstance(v, list):
        items = [str(x).strip() for x in v]
    elif isinstance(v, str):
        items = re.split(r"[,\s]+", v)
    else:
        bad("err.bad_value")
    out = []
    for d in filter(None, items):
        try:
            a = ipaddress.ip_address(d)
        except ValueError:
            bad(Msg("srv.bad_dns", value=d[:60]))
        if a.version != 4 or a.is_unspecified or a.is_multicast:
            bad(Msg("err.rule_dns_v4", value=d[:60]))
        if d not in out:
            out.append(d)
    if len(out) > RULE_DNS_MAX:
        bad(Msg("err.rule_dns_many", n=RULE_DNS_MAX))
    return out


def balance(st: dict, b) -> dict:
    """Балансировка: {"on": bool, "skip": [id выходов, которые в ней не участвуют]}."""
    if not isinstance(b, dict) or not isinstance(b.get("skip", []), list):
        bad("err.bad_value")
    skip = [x for x in dict.fromkeys(b.get("skip") or []) if isinstance(x, str) and Store.upstream(st, x)]
    return {"on": flag(b.get("on"), False), "skip": skip}


def strict(v) -> bool | None:
    """«Блокировать, если правила по доменам не работают» (routing.strict): true/false, None — не задано."""
    if v is not None and not isinstance(v, bool):
        bad("err.bad_value")
    return v


# ------------------------------------------------------------------- выход
QUOTA_MAX = 1_000_000 * limits.GB       # лимит трафика выхода и клиента: не больше миллиона ГБ


def quota(v) -> int | None:
    """Лимит трафика в байтах (выхода и клиента). None — без лимита."""
    if v is None:
        return None
    if not number(v) or not 0 < v <= QUOTA_MAX:
        bad("err.quota")
    return int(v)


def quota_gb(v) -> int | None:
    """Лимит из формы, в ГБ ("" / None — без лимита) → байты."""
    if v in (None, ""):
        return None
    try:
        v = float(v)
    except (TypeError, ValueError):
        bad("err.quota")
    if not math.isfinite(v) or v <= 0:
        bad("err.quota")
    return quota(v * limits.GB)


def exit_id(st: dict, uid) -> str:
    """id выхода из копии: короткое имя (оно попадает в имена интерфейсов и наборов nftables), не занятое."""
    if not isinstance(uid, str) or not ID_RE.match(uid) or Store.upstream(st, uid):
        bad("err.bad_value")
    return uid


def exit_num(st: dict, num) -> int:
    """Номер выхода из копии (awgr<номер>, метка и таблица маршрутов): 1 … MAX_UPSTREAMS, не занятый."""
    if not isinstance(num, int) or isinstance(num, bool) or not 1 <= num <= config.MAX_UPSTREAMS \
            or any(x["num"] == num for x in st["upstreams"]):
        bad("err.bad_value")
    return num


def exit_config(text) -> awgconf.UpstreamConf:
    """Конфиг выхода: AmneziaWG (.conf, vpn://) или socks5://."""
    try:
        return awgconf.parse_upstream(str(text or ""))
    except awgconf.ConfigError as e:
        bad(e.msg, field="config")


def fallback_loops(st: dict, uid: str, fb: str) -> bool:
    """Резерв выхода uid по цепочке резервов возвращается к нему же (A → B → A): когда все в цепочке лежат,
    клиенты получили бы «блок» (resolve обрывает цепочку), а человек ждал бы «напрямую»."""
    seen = set()
    while fb.startswith("up:") and fb not in seen:
        if fb == "up:" + uid:
            return True
        seen.add(fb)
        u = Store.upstream(st, fb[3:])
        fb = (u or {}).get("fallback") or "direct"
    return False


def fallback(st: dict, uid: str | None, v, loops_ok: bool = False) -> str:
    """Резервный выход: не сам выход и не круг резервов (loops_ok — круги разрывает вызывающий, см. копию)."""
    fb = outbound(st, v)
    if uid and fb == "up:" + uid:
        bad("err.fallback_self")
    if uid and not loops_ok and fallback_loops(st, uid, fb):
        bad("err.fallback_loop")
    return fb


def quota_action(st: dict, v, uid: str | None) -> str:
    """Что делать при исчерпании квоты: 'notify' или выход (direct / block / up:<id>, не сам)."""
    if v in (None, "", "notify"):
        return "notify"
    out = outbound(st, v)
    if uid and out == "up:" + uid:
        bad("err.quota_self")
    return out


def quic(v) -> bool:
    """Галочка «Пропускать QUIC» выхода SOCKS5."""
    if not isinstance(v, bool):
        bad("err.bad_value")
    return v


MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


def month(v) -> str | None:
    """Месяц «2026-11» (отметки «квота кончилась», «предупредили»), иначе None."""
    return v if isinstance(v, str) and MONTH_RE.match(v) else None


# ------------------------------------------------------------------ список
LIST_KINDS = ("country", "asn", "url", "manual", "domains")
LIST_TEXT_MAX = 2_000_000


def list_fields(body: dict, existing: dict | None = None) -> dict:
    """Вид, текст и название списка ({kind, source, name}); existing — список, который правят. Правка без поля
    «name» (только текст) оставляет прежнее название, а не отказывает «нужно название»."""
    if existing and "name" not in body and existing.get("name"):
        body = {**body, "name": existing["name"]}
    kind = body.get("kind", existing["kind"] if existing else None)
    if kind not in LIST_KINDS:
        bad("err.list_kind")
    src = str(body.get("source", existing["source"] if existing else "")).strip()
    if kind == "country":
        src = src.lower()
        if not re.match(r"^[a-z]{2}$", src):
            bad("err.country_code")
        return {"kind": kind, "source": src, "name": str(body.get("name") or "")[:40]}
    elif kind == "asn":
        asns = lists.parse_asns(src)
        if not asns:
            bad("err.asn_format")
        src = " ".join(f"AS{a}" for a in asns)
        nm = body.get("name") or src
    elif kind == "domains":
        if len(src) > LIST_TEXT_MAX:
            bad("err.list_too_big")
        urls, text = domains.split_source(src)
        found = domains.parse(text)
        if not urls and not found:
            bad("err.no_domains")
        # без названия — первый домен (или сайт первой ссылки)
        nm = body.get("name") or (found[0] if found else urls[0].split("/")[2])[:40]
    elif kind == "url":
        urls = src.split()
        if not urls or not all(re.match(r"^https?://\S+$", u) for u in urls):
            bad("err.urls")
        nm = body.get("name")
    else:
        if len(src) > LIST_TEXT_MAX:
            bad("err.list_too_big")
        if not lists.parse_cidrs(src):
            bad("err.only_v6" if lists.count_ipv6(src) else "err.no_cidr")
        nm = body.get("name")
    return {"kind": kind, "source": src, "name": name(nm)}


def list_id(st: dict, lid, fields: dict) -> str:
    """id списка из копии: короткое имя (оно попадает в имена наборов nftables и файлов), не занятое; у страны
    id — код страны."""
    if not isinstance(lid, str) or not ID_RE.match(lid) or Store.lst(st, lid):
        bad("err.bad_value")
    if fields["kind"] == "country" and fields["source"] != lid:
        bad("err.bad_value")
    return lid


# ------------------------------------------------------------------ клиент
def client_policy(st: dict, body: dict, self_dns: str | None = None) -> dict:
    """Куда идёт клиент: выход («как у всех» — inherit), свои правила или общие, заметка."""
    mode = body.get("rules_mode", "inherit")
    if mode not in ("inherit", "custom"):
        bad("err.bad_value")
    return {"outbound": outbound(st, body.get("outbound", "inherit"), allow_inherit=True),
            "rules_mode": mode,
            "rules": rules(st, body.get("rules") or [], self_dns) if mode == "custom" else [],
            "note": str(body.get("note") or "")[:120]}


# --------------------------------------------------------- срок и лимит клиента
def expires(v) -> int | None:
    """Срок клиента (unix-время): 0 и меньше — без срока; позже limits.EXPIRES_MAX дату не перевести в текст."""
    if v is None:
        return None
    if isinstance(v, bool):                # true — не «1 января 1970»
        bad("err.bad_value")
    try:
        v = int(v)
    except (TypeError, ValueError, OverflowError):
        bad("err.bad_value")
    if v <= 0:
        return None
    if v > limits.EXPIRES_MAX:
        bad("err.bad_value")
    return v


def period(v) -> str:
    """За какой срок считается лимит клиента: month | total."""
    v = v or "month"
    if v not in ("month", "total"):
        bad("err.bad_value")
    return v


QUOTA_KEY_RE = re.compile(r"^(\d{4}-\d{2}|total)$")


def quota_key(v) -> str | None:
    """Отметка лимита клиента: месяц «2026-11» или total, иначе None."""
    return v if isinstance(v, str) and QUOTA_KEY_RE.match(v) else None


# ---------------------------------------------------- маскировка I1–I5 клиента
def cps_entry(preset, values=None) -> dict | None:
    """Маскировка клиента: "server" (как на сервере — своей записи нет, None) | имя шаблона | "custom" + I1–I5."""
    p = preset or "server"
    if p not in (*cps.PRESETS, "custom", "server"):
        bad("err.bad_value")
    if p == "custom":
        if values is not None and not isinstance(values, dict):
            bad("err.bad_value")                                       # раньше — ошибка 500
        try:
            return {"preset": "custom", "values": cps.validate(values or {})}
        except cps.CPSError as e:
            bad(e.msg)
    return None if p == "server" else {"preset": p}


# ----------------------------------------------- свой адрес клиента, ссылка
HOST_RE = re.compile(r"[A-Za-z0-9.\-:]{1,253}")     # адрес сервера в копии: IPv4, IPv6 или домен
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,40}$")    # личная ссылка клиента /s/<токен>
HOSTNAME_RE = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]")    # домен (адрес панели, «Проверка маршрута»)


def host_text(v) -> str:
    """Адрес сервера из копии: IPv4, IPv6 или домен одной строкой (есть ли он у этого сервера, решает restore_state)."""
    if not isinstance(v, str) or not HOST_RE.fullmatch(v):
        bad("err.bad_value")
    return v


def client_host(v, choices) -> str:
    """Свой адрес сервера в конфиге клиента: пусто — как у всех, иначе один из choices (host_choices, #37)."""
    if v is None or v == "":
        return ""
    if not isinstance(v, str) or v not in choices:
        bad("err.bad_value")
    return v


# ---------------------------------------------------------- настройки панели
def list_update_hours(v) -> int:
    """Как часто обновлять списки, часов (1 … 30 суток)."""
    if isinstance(v, bool):                       # true — не «1 час»
        bad("err.hours")
    try:
        return max(1, min(int(v), 24 * 30))
    except (TypeError, ValueError, OverflowError):
        bad("err.hours")


def on_stop(v) -> str:
    """Что делать с правилами, когда панель останавливается: keep | restore."""
    if v not in ("keep", "restore"):
        bad("err.bad_value")
    return v


def shaping_limits(sh) -> dict:
    """Общее ограничение скорости сервера {down, up}: только заданные."""
    if not isinstance(sh, dict):
        bad("err.bad_value")
    v = {k: rate(sh.get(k)) for k in ("down", "up")}
    return {k: x for k, x in v.items() if x}


# ------------------------------------------------------------------ Telegram
TG_TOKEN_RE = re.compile(r"^[0-9]{5,15}:[A-Za-z0-9_-]{30,60}$")
TG_CHAT_RE = re.compile(r"^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$")


def telegram(st: dict, base: dict, body: dict, backup: bool = False) -> dict:
    """Настройки Telegram: body поверх base. Из формы base — сохранённые (пустой токен — оставить прежний), из копии —
    notify.defaults(). Копия прощает непонятный язык, период копий и галочки (остаётся base) и выключает уведомления
    и управление без токена и чата или управление из чата по @имени; форма на это отвечает ошибкой (put_telegram).
    Неверный пароль копий не прощается и в копии: без него копии в Telegram пошли бы без шифрования."""
    c = copy.deepcopy(base)
    soft = (lambda fn, key: forgive(fn, c[key])) if backup else (lambda fn, key: fn())
    tok = str(body.get("token") or "").strip()
    if tok:
        if not TG_TOKEN_RE.match(tok):
            bad("err.tg_token", field="token")
        c["token"] = tok
    if "chat_id" in body:
        chat = str(body.get("chat_id") or "").strip()
        if chat and not TG_CHAT_RE.match(chat):
            bad("err.tg_chat", field="chat_id")
        c["chat_id"] = chat
    if "lang" in body:
        c["lang"] = soft(lambda: body["lang"] if isinstance(body["lang"], str) and body["lang"] in notify.LANGS
                         else bad("err.bad_value"), "lang")
    if "via" in body:
        with field("via"):
            via = outbound(st, (body["via"] or "direct") if backup else body["via"])
            if via == "block":
                bad("err.bad_value")
        c["via"] = via
    ev = body.get("events")
    if isinstance(ev, dict):
        one = (lambda k: forgive(lambda: flag(ev[k]), c["events"].get(k, True))) if backup else (lambda k: flag(ev[k]))
        c["events"] = {k: one(k) if k in ev else c["events"].get(k, True) for k in notify.KINDS}
    for k in ("enabled", "control", "clients", "client_notify", "fallback"):
        if k in body:
            c[k] = soft(lambda: flag(body[k]), k)
    if "backup" in body:
        c["backup"] = soft(lambda: body["backup"] if isinstance(body["backup"], str)
                           and body["backup"] in notify.BACKUP_PERIODS else bad("err.bad_value"), "backup")
    pw = str(body.get("backup_pw") or "")
    if pw:
        if not 8 <= len(pw) <= 128:
            bad("err.backup_pw", field="backup_pw")
        c["backup_pw"] = pw
    if body.get("backup_pw_clear"):
        c["backup_pw"] = ""
    if backup:
        ready = bool(c["token"] and c["chat_id"])
        c["enabled"] = c["enabled"] and bool(c["token"])     # бот только для клиентов работает и без чата
        # @имя можно освободить и занять другому: управление — только из чата с числовым ID
        c["control"] = c["control"] and ready and not c["chat_id"].startswith("@")
    return c


# ------------------------------------------------------- входящий SOCKS5-прокси
SOCKS_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def validate_socks_username(v) -> str:
    """Имя пользователя входящего SOCKS5-прокси: 1–64 символа [A-Za-z0-9_.-]."""
    if not isinstance(v, str) or not SOCKS_USER_RE.match(v):
        bad("err.bad_value", field="username")
    return v


def validate_socks_password(v) -> str:
    """Пароль входящего SOCKS5-прокси: от 8 символов, до 255 байт UTF-8 без управляющих символов."""
    if (
        not isinstance(v, str)
        or len(v) < 8
        or len(v.encode("utf-8")) > 255
        or any(ord(c) < 32 or ord(c) == 0x7F for c in v)
    ):
        bad("err.bad_value", field="password")
    return v


def validate_socks_port(v) -> int:
    """TCP-порт входящего SOCKS5-прокси: целое число 1–65535."""
    if isinstance(v, (bool, float)):
        bad("srv.bad_port", field="port")
    try:
        port = int(v)
    except (TypeError, ValueError, OverflowError):
        bad("srv.bad_port", field="port")
    if not 1 <= port <= 65535:
        bad("srv.bad_port", field="port")
    return port
