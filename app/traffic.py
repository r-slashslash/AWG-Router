"""Учёт трафика клиентов: итоги за всё время и по месяцам (data/traffic.json).

AWG отдаёт счётчики с момента подключения пира к интерфейсу, и они обнуляются при
перезапуске сервера или отключении клиента. Здесь мы копим прирост между опросами:
если счётчик стал меньше прежнего — значит, он обнулился, и весь текущий — новый трафик.
Первое наблюдение пира только запоминает точку отсчёта: трафик до появления панели
(или до обновления на версию с учётом) не считается — иначе в первый месяц попал бы
трафик за всё время работы сервера.
Направления — со стороны сервера: rx — получено от клиента (отдача клиента),
tx — отправлено клиенту (загрузка клиента).

Формат файла: {"_v": 2, "clients": {ключ: {"total", "months", "last", "by_out"}},
"outs": {выход: {"total", "months"}}, "acct": {"ip|интерфейс": [rx, tx]}}.
Файл версии 1.2.0 (без "_v") содержал этот лишний трафик — из него берём только
точки отсчёта.

Трафик по выходам (с 1.3.0) считает отдельная таблица nftables (nftgen.acct_ruleset):
счётчик на каждую пару «адрес клиента + интерфейс». Выход — "direct" или id выхода.
"outs" — итоги выходов по всем клиентам (не уменьшаются при удалении клиента: по ним
работают квоты выходов), "by_out" у клиента — {месяц: {выход: [rx, tx]}}, "acct" —
последние значения счётчиков. Номер формата прежний: новые ключи старые версии
просто не читают, и откат панели не обнуляет итоги клиентов.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time

from . import config

log = logging.getLogger("awgr.traffic")

PATH = os.path.join(config.DATA_DIR, "traffic.json")
MONTH_RE = re.compile(r"^\d{4}-\d{2}$")
OUT_RE = re.compile(r"^(direct|[a-z0-9_]{1,24})$")
ACCT_KEY_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}\|[A-Za-z0-9_.@-]{1,15}$")
FORMAT = 2
KEEP_MONTHS = 24
SAVE_EVERY = 60


def month_key(ts: float | None = None) -> str:
    return time.strftime("%Y-%m", time.gmtime(time.time() if ts is None else ts))


def _rec() -> dict:
    return {"total": [0, 0], "months": {}, "last": None}


def _pair(x) -> list[int] | None:
    ok = isinstance(x, list) and len(x) == 2 and all(
        isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in x)
    return list(x) if ok else None


def _add(d: dict, key: str, delta: list[int]) -> None:
    v = d.get(key) or [0, 0]
    d[key] = [v[0] + delta[0], v[1] + delta[1]]


def _trim(months: dict) -> None:
    if len(months) > KEEP_MONTHS:
        for old in sorted(months)[:-KEEP_MONTHS]:
            months.pop(old, None)


def _clean_months(v) -> dict:
    return {m: _pair(x) for m, x in (v.items() if isinstance(v, dict) else ())
            if isinstance(m, str) and MONTH_RE.match(m) and _pair(x)}


def _clean_by_out(v) -> dict:
    out = {}
    for m, outs in (v.items() if isinstance(v, dict) else ()):
        if isinstance(m, str) and MONTH_RE.match(m) and isinstance(outs, dict):
            o = {k: _pair(x) for k, x in outs.items() if isinstance(k, str) and OUT_RE.match(k) and _pair(x)}
            if o:
                out[m] = o
    return out


class Traffic:
    def __init__(self, path: str = PATH):
        self.path = path
        self.lock = threading.Lock()
        self.data: dict[str, dict] = {}
        self.outs: dict[str, dict] = {}        # итоги выходов: {выход: {"total", "months"}}
        self.acct: dict[str, list[int]] = {}   # последние значения счётчиков nftables
        self.acct_synced = False               # acct соответствует таблице (есть в файле)
        self._saved = 0.0
        self._dirty = False
        try:
            with open(path) as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = None
        if isinstance(d, dict) and d.get("_v") == FORMAT and isinstance(d.get("clients"), dict):
            self.data = {k: v for k, v in d["clients"].items() if isinstance(v, dict)}
            self.outs, self.acct = self._clean_outs(d.get("outs")), self._clean_acct(d.get("acct"))
            self.acct_synced = isinstance(d.get("acct"), dict)
        elif isinstance(d, dict):
            # данные 1.2.0: итоги завышены, оставляем только точки отсчёта
            self.data = {k: {**_rec(), "last": v.get("last")} for k, v in d.items()
                         if isinstance(v, dict) and isinstance(v.get("last"), list)}
            self._dirty = True
            log.info("traffic: counters started over (data from 1.2.0 included pre-panel traffic)")

    # ---------------------------------------------------------------- учёт
    def update(self, clients: list[dict], now: float | None = None) -> None:
        now = time.time() if now is None else now
        mk = month_key(now)
        with self.lock:
            for c in clients:
                pk = c["public_key"]
                if not c.get("enabled"):
                    # отключённый пир убран из интерфейса: после включения счётчик начнётся с нуля
                    d = self.data.get(pk)
                    if d and d.get("last") != [0, 0]:
                        d["last"] = [0, 0]
                        self._dirty = True
                    continue
                live = c.get("live")
                if not live:
                    continue
                cur = [int(live.get("rx") or 0), int(live.get("tx") or 0)]
                d = self.data.setdefault(pk, _rec())
                last = d.get("last")
                d["last"] = cur
                self._dirty = True
                if last is None:
                    continue            # первое наблюдение — только точка отсчёта
                delta = [cur[i] - last[i] if cur[i] >= last[i] else cur[i] for i in (0, 1)]
                if not any(delta):
                    continue
                d["total"] = [d["total"][i] + delta[i] for i in (0, 1)]
                m = d["months"].setdefault(mk, [0, 0])
                d["months"][mk] = [m[i] + delta[i] for i in (0, 1)]
                if len(d["months"]) > KEEP_MONTHS:
                    for old in sorted(d["months"])[:-KEEP_MONTHS]:
                        d["months"].pop(old, None)
        if self._dirty and now - self._saved >= SAVE_EVERY:
            self.save()

    def update_outs(self, counters: dict[tuple[str, str], list[int]], out_of, pk_of: dict[str, str],
                    fresh: bool = False, now: float | None = None) -> None:
        """Прирост счётчиков таблицы учёта → итоги выходов и разбивка клиентов.

        counters: {(ip, интерфейс): [от клиента, к клиенту]} — всё содержимое таблицы;
        out_of(интерфейс) → "direct" | id выхода | None (не считать); pk_of: ip → ключ клиента.
        Таблица наша, и каждый счётчик начинается с нуля, когда появляется пара
        «клиент + интерфейс», поэтому новая пара считается целиком. Исключение — панель
        впервые видит уже существующую таблицу без своих записей (например, удалили
        traffic.json): тогда, как и у клиентов, первое значение — только точка отсчёта.
        fresh — таблицу только что создали (в ней ничего не было)."""
        now = time.time() if now is None else now
        mk = month_key(now)
        with self.lock:
            baseline = not self.acct_synced and not fresh
            seen = {}
            for (ip, ifn), cur in counters.items():
                key = f"{ip}|{ifn}"
                if not ACCT_KEY_RE.match(key):
                    continue
                cur = [int(cur[0]), int(cur[1])]
                seen[key] = cur
                last = self.acct.get(key)
                if last is None:
                    if baseline:
                        continue
                    last = [0, 0]
                delta = [cur[i] - last[i] if cur[i] >= last[i] else cur[i] for i in (0, 1)]
                out = out_of(ifn)
                if not any(delta) or out is None:
                    continue
                o = self.outs.setdefault(out, {"total": [0, 0], "months": {}})
                o["total"] = [o["total"][i] + delta[i] for i in (0, 1)]
                _add(o["months"], mk, delta)
                _trim(o["months"])
                pk = pk_of.get(ip)
                d = self.data.get(pk) if pk else None
                if d is not None:
                    bo = d.setdefault("by_out", {})
                    _add(bo.setdefault(mk, {}), out, delta)
                    _trim(bo)
            # пары, которых больше нет в таблице, забываем: если появятся снова — с нуля
            if seen != self.acct or not self.acct_synced:
                self.acct = seen
                self.acct_synced = True
                self._dirty = True
        if self._dirty and now - self._saved >= SAVE_EVERY:
            self.save()

    def forget_out(self, out: str) -> None:
        """Выход удалён: его итоги и строки в разбивке клиентов больше не нужны."""
        with self.lock:
            hit = self.outs.pop(out, None) is not None
            for d in self.data.values():
                for m in (d.get("by_out") or {}).values():
                    hit = m.pop(out, None) is not None or hit
            if hit:
                self._dirty = True
        self.save()

    def save(self) -> None:
        with self.lock:
            if not self._dirty:
                return
            tmp = self.path + ".tmp"
            try:
                with open(tmp, "w") as f:
                    json.dump({"_v": FORMAT, "clients": self.data, "outs": self.outs, "acct": self.acct}, f)
                os.replace(tmp, self.path)
                self._dirty = False
                self._saved = time.time()
            except OSError as e:
                log.warning("traffic save: %s", e)

    def forget(self, pk: str) -> None:
        with self.lock:
            if self.data.pop(pk, None) is not None:
                self._dirty = True
        self.save()

    def replace(self, data: dict) -> None:
        """Восстановление из резервной копии. Итоги берём из копии, а точки отсчёта —
        текущие: счётчики интерфейса на этом сервере продолжают идти как шли."""
        outs = {}
        if isinstance(data, dict) and data.get("_v") == FORMAT:
            outs = self._clean_outs(data.get("outs"))
            data = data.get("clients") or {}
        elif isinstance(data, dict):
            data = {}                   # копия из 1.2.0: итоги в ней завышены

        with self.lock:
            cur = {k: v.get("last") for k, v in self.data.items()}
            out = {}
            for k, v in (data if isinstance(data, dict) else {}).items():
                if not isinstance(v, dict) or not _pair(v.get("total")):
                    continue
                rec = {"total": _pair(v["total"]), "months": _clean_months(v.get("months")),
                       "last": cur.get(k)}
                bo = _clean_by_out(v.get("by_out"))
                if bo:
                    rec["by_out"] = bo
                out[str(k)[:64]] = rec
            self.data = out
            self.outs = outs
            self._dirty = True
        self.save()

    @staticmethod
    def _clean_outs(v) -> dict:
        out = {}
        for k, o in (v.items() if isinstance(v, dict) else ()):
            if isinstance(k, str) and OUT_RE.match(k) and isinstance(o, dict) and _pair(o.get("total")):
                out[k] = {"total": _pair(o["total"]), "months": _clean_months(o.get("months"))}
        return out

    @staticmethod
    def _clean_acct(v) -> dict:
        return {k: _pair(x) for k, x in (v.items() if isinstance(v, dict) else ())
                if isinstance(k, str) and ACCT_KEY_RE.match(k) and _pair(x)}

    # -------------------------------------------------------------- чтение
    def month(self, pk: str, mk: str | None = None) -> list[int]:
        d = self.data.get(pk) or {}
        return list((d.get("months") or {}).get(mk or month_key(), [0, 0]))

    def total(self, pk: str) -> list[int]:
        return list((self.data.get(pk) or {}).get("total") or [0, 0])

    def used(self, pk: str, period: str) -> int:
        return sum(self.month(pk) if period == "month" else self.total(pk))

    def view(self, pk: str) -> dict:
        m, t = self.month(pk), self.total(pk)
        d = self.data.get(pk) or {}
        hist = sorted((d.get("months") or {}).items())[-12:]
        by_out = (d.get("by_out") or {}).get(month_key()) or {}
        return {"month_rx": m[0], "month_tx": m[1], "total_rx": t[0], "total_tx": t[1],
                "history": [[k, v[0], v[1]] for k, v in hist],
                "by_out": {k: list(v) for k, v in by_out.items()}}

    def out_month(self, out: str, mk: str | None = None) -> list[int]:
        o = self.outs.get(out) or {}
        return list((o.get("months") or {}).get(mk or month_key(), [0, 0]))

    def out_used(self, out: str) -> int:
        """Трафик выхода за текущий месяц (оба направления) — для квоты."""
        return sum(self.out_month(out))

    def out_view(self, out: str) -> dict:
        m = self.out_month(out)
        t = (self.outs.get(out) or {}).get("total") or [0, 0]
        hist = sorted(((self.outs.get(out) or {}).get("months") or {}).items())[-12:]
        return {"month_rx": m[0], "month_tx": m[1], "total_rx": t[0], "total_tx": t[1],
                "history": [[k, v[0], v[1]] for k, v in hist]}

    def export(self) -> dict:
        with self.lock:
            return json.loads(json.dumps({"_v": FORMAT, "clients": self.data, "outs": self.outs}))
