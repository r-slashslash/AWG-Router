"""Учёт трафика клиентов: итоги за всё время и по месяцам (data/traffic.json).

AWG отдаёт счётчики с момента подключения пира к интерфейсу, и они обнуляются при
перезапуске сервера или отключении клиента. Здесь мы копим прирост между опросами:
если счётчик стал меньше прежнего — значит, он обнулился, и весь текущий — новый трафик.
Направления — со стороны сервера: rx — получено от клиента (отдача клиента),
tx — отправлено клиенту (загрузка клиента).
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time

from . import config

log = logging.getLogger("awgr.traffic")

PATH = os.path.join(config.DATA_DIR, "traffic.json")
KEEP_MONTHS = 24
SAVE_EVERY = 60


def month_key(ts: float | None = None) -> str:
    return time.strftime("%Y-%m", time.gmtime(time.time() if ts is None else ts))


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
            if isinstance(d, dict):
                self.data = {k: v for k, v in d.items() if isinstance(v, dict)}
        except (OSError, ValueError):
            pass

    # ---------------------------------------------------------------- учёт
    def update(self, clients: list[dict], now: float | None = None) -> None:
        now = time.time() if now is None else now
        mk = month_key(now)
        with self.lock:
            for c in clients:
                live = c.get("live")
                if not live or not c.get("enabled"):
                    continue
                pk = c["public_key"]
                cur = [int(live.get("rx") or 0), int(live.get("tx") or 0)]
                d = self.data.setdefault(pk, {"total": [0, 0], "months": {}, "last": [0, 0]})
                last = d.get("last") or [0, 0]
                delta = [cur[i] - last[i] if cur[i] >= last[i] else cur[i] for i in (0, 1)]
                d["last"] = cur
                if not any(delta):
                    continue
                d["total"] = [d["total"][i] + delta[i] for i in (0, 1)]
                m = d["months"].setdefault(mk, [0, 0])
                d["months"][mk] = [m[i] + delta[i] for i in (0, 1)]
                if len(d["months"]) > KEEP_MONTHS:
                    for old in sorted(d["months"])[:-KEEP_MONTHS]:
                        d["months"].pop(old, None)
                self._dirty = True
        if self._dirty and now - self._saved >= SAVE_EVERY:
            self.save()

    def save(self) -> None:
        with self.lock:
            if not self._dirty:
                return
            tmp = self.path + ".tmp"
            try:
                with open(tmp, "w") as f:
                    json.dump(self.data, f)
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
        """Восстановление из резервной копии: счётчики «последнего опроса» сбрасываем."""
        with self.lock:
            self.data = {k: {**v, "last": [0, 0]} for k, v in (data or {}).items()
                         if isinstance(v, dict) and isinstance(v.get("total"), list)}
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
            return json.loads(json.dumps(self.data))
