"""Учёт трафика клиентов: итоги за всё время и по месяцам (data/traffic.json).

AWG отдаёт счётчики с момента подключения пира к интерфейсу, и они обнуляются при
перезапуске сервера или отключении клиента. Здесь мы копим прирост между опросами:
если счётчик стал меньше прежнего — значит, он обнулился, и весь текущий — новый трафик.
Первое наблюдение пира только запоминает точку отсчёта: трафик до появления панели
(или до обновления на версию с учётом) не считается — иначе в первый месяц попал бы
трафик за всё время работы сервера.
Направления — со стороны сервера: rx — получено от клиента (отдача клиента),
tx — отправлено клиенту (загрузка клиента).

Формат файла: {"_v": 2, "clients": {ключ: {"total", "months", "last"}}}.
Файл версии 1.2.0 (без "_v") содержал этот лишний трафик — из него берём только
точки отсчёта.
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
FORMAT = 2
KEEP_MONTHS = 24
SAVE_EVERY = 60


def month_key(ts: float | None = None) -> str:
    return time.strftime("%Y-%m", time.gmtime(time.time() if ts is None else ts))


def _rec() -> dict:
    return {"total": [0, 0], "months": {}, "last": None}


class Traffic:
    def __init__(self, path: str = PATH):
        self.path = path
        self.lock = threading.Lock()
        self.data: dict[str, dict] = {}
        self._saved = 0.0
        self._dirty = False
        try:
            with open(path) as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = None
        if isinstance(d, dict) and d.get("_v") == FORMAT and isinstance(d.get("clients"), dict):
            self.data = {k: v for k, v in d["clients"].items() if isinstance(v, dict)}
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

    def save(self) -> None:
        with self.lock:
            if not self._dirty:
                return
            tmp = self.path + ".tmp"
            try:
                with open(tmp, "w") as f:
                    json.dump({"_v": FORMAT, "clients": self.data}, f)
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
        if isinstance(data, dict) and data.get("_v") == FORMAT:
            data = data.get("clients") or {}
        elif isinstance(data, dict):
            data = {}                   # копия из 1.2.0: итоги в ней завышены
        def pair(x):
            ok = isinstance(x, list) and len(x) == 2 and all(
                isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in x)
            return list(x) if ok else None

        with self.lock:
            cur = {k: v.get("last") for k, v in self.data.items()}
            out = {}
            for k, v in (data or {}).items():
                if not isinstance(v, dict) or not pair(v.get("total")):
                    continue
                months = v.get("months") if isinstance(v.get("months"), dict) else {}
                out[str(k)[:64]] = {
                    "total": pair(v["total"]),
                    "months": {m: pair(x) for m, x in months.items()
                               if isinstance(m, str) and MONTH_RE.match(m) and pair(x)},
                    "last": cur.get(k)}
            self.data = out
            self._dirty = True
        self.save()

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
        return {"month_rx": m[0], "month_tx": m[1], "total_rx": t[0], "total_tx": t[1],
                "history": [[k, v[0], v[1]] for k, v in hist]}

    def export(self) -> dict:
        with self.lock:
            return json.loads(json.dumps({"_v": FORMAT, "clients": self.data}))
