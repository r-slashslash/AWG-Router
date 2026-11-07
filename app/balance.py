"""Балансировка: клиенты «как у всех» распределяются по рабочим выходам балансировки вместо выхода
по умолчанию. Только расчёт — без команд; результат движок кладёт в правила nftables (Sticky).

Скорости выходов и клиентов — сглаженные приращения учёта трафика (Traffic.take_recent).
Загрузка выхода — доля от его ограничения скорости (большая из двух сторон). Выход без
ограничения считается таким же мощным, как самый мощный из ограниченных участников; если
ограничений нет ни у кого — у всех одинаковая условная мощность NOMINAL, то есть сравниваются
просто Мбит/с.

  * клиент без выхода (новый или его выход выпал: упал, выключен, исчерпал квоту, снят с
    балансировки) — сразу на самый свободный выход; при равной загрузке (ночью все около нуля) —
    туда, где меньше активных клиентов, затем меньше клиентов вообще (с поправкой на мощность);
  * перекос: перенос одного активного клиента с самого загруженного выхода снизил бы его загрузку
    хотя бы на (1 − GAIN) и не перегрузил бы другой выход. Перекос должен держаться SUSTAIN секунд;
    переносов — не чаще одного за STEP, одного клиента — не чаще раза в CLIENT_PAUSE. Перенос не
    рвёт открытые соединения (ct mark, nftgen.Sticky): через новый выход идут только новые.
"""
from __future__ import annotations

import math

TAU = 30.0               # сглаживание скорости, с
ACTIVE_BPS = 20_000      # клиент активен: больше 20 КБ/с хотя бы в одну сторону
BUSY_BPS = 250_000       # перекос не считаем, пока самый загруженный выход везёт меньше 2 Мбит/с
GAIN = 0.85              # перенос должен снизить загрузку самого загруженного выхода хотя бы на 15 %
SUSTAIN = 120            # перекос держится столько секунд — переносим
STEP = 180               # не чаще одного переноса за столько секунд
CLIENT_PAUSE = 600       # одного клиента — не чаще раза в 10 минут
NOMINAL = 100.0          # Мбит/с: условная мощность, когда ограничений нет ни у одного участника
MAX_GAP = 120            # пауза между замерами больше — замер не считаем (панель стояла)
QUANT = 0.05             # загрузки, отличающиеся меньше чем на 5 %, считаются равными


def _bps(mbit: float) -> float:
    return mbit * 1_000_000 / 8


class Balancer:
    def __init__(self):
        self.exit_rate: dict[str, list[float]] = {}            # выход → [от клиентов, к клиентам], байт/с
        self.client_rate: dict[tuple[str, str], list[float]] = {}   # (клиент, выход) → то же
        self.assign: dict[str, str] = {}       # клиент → id выхода
        self.moved: dict[str, float] = {}      # клиент → когда переносили
        self._last: float | None = None
        self._imb_since: float | None = None
        self._last_move = 0.0
        self.last_move: dict | None = None     # {"pk", "from", "to", "at"} — для журнала

    # ------------------------------------------------------------ скорости
    def feed(self, deltas: dict[tuple[str, str | None], list[int]], now: float) -> None:
        """Прирост байт по (выход, клиент) с прошлого вызова → сглаженные скорости."""
        last, self._last = self._last, now
        if last is None or not 0 < now - last <= MAX_GAP:
            return
        dt = now - last
        a = 1 - math.exp(-dt / TAU)
        per_exit: dict[str, list[int]] = {}
        per_client: dict[tuple[str, str], list[int]] = {}
        for (out, pk), d in deltas.items():
            e = per_exit.setdefault(out, [0, 0])
            e[0] += d[0]
            e[1] += d[1]
            if pk:
                c = per_client.setdefault((pk, out), [0, 0])
                c[0] += d[0]
                c[1] += d[1]
        for rates, src in ((self.exit_rate, per_exit), (self.client_rate, per_client)):
            for k in set(rates) | set(src):
                inst = src.get(k, (0, 0))
                old = rates.get(k, [0.0, 0.0])
                new = [old[i] + a * (inst[i] / dt - old[i]) for i in (0, 1)]
                if k not in src and max(new) < 100:
                    rates.pop(k, None)        # затихло — забываем
                else:
                    rates[k] = new

    def rate(self, out: str) -> list[float]:
        return list(self.exit_rate.get(out, [0.0, 0.0]))

    # ------------------------------------------------------------ загрузка
    @staticmethod
    def capacities(members: list[dict]) -> dict[str, tuple[float, float]]:
        """{id: (мощность отдачи, мощность загрузки)} в байт/с, см. описание модуля."""
        out = {}
        tops = []
        for i in ("up", "down"):
            vals = [m[i] for m in members if m.get(i)]
            tops.append(max(vals) if vals else NOMINAL)
        for m in members:
            out[m["id"]] = (_bps(m.get("up") or tops[0]), _bps(m.get("down") or tops[1]))
        return out

    @staticmethod
    def _load(r, cap) -> float:
        return max(r[0] / cap[0], r[1] / cap[1])

    def loads(self, members: list[dict]) -> dict[str, float]:
        caps = self.capacities(members)
        return {i: self._load(self.rate(i), c) for i, c in caps.items()}

    # ------------------------------------------------------------ назначение
    def pick(self, members: list[dict], loads: dict[str, float] | None = None) -> str | None:
        """Самый свободный выход для нового клиента."""
        if not members:
            return None
        caps = self.capacities(members)
        loads = loads if loads is not None else self.loads(members)
        ids = [m["id"] for m in members]
        active = {i: 0 for i in ids}
        total = {i: 0 for i in ids}
        for pk, uid in self.assign.items():
            if uid in total:
                total[uid] += 1
                if max(self.client_rate.get((pk, uid), (0, 0))) >= ACTIVE_BPS:
                    active[uid] += 1
        w = {i: caps[i][1] for i in ids}
        return min(ids, key=lambda i: (round(loads[i] / QUANT), active[i] / w[i], total[i] / w[i], ids.index(i)))

    def plan(self, members: list[dict], clients: list[str], now: float) -> dict[str, str]:
        """members — [{"id", "up", "down"}] рабочих выходов балансировки (ограничения в Мбит/с или
        None) в порядке списка; clients — ключи клиентов «как у всех». → {клиент: id выхода}."""
        ids = {m["id"] for m in members}
        keep = set(clients)
        self.assign = {pk: u for pk, u in self.assign.items() if pk in keep}
        self.moved = {pk: t for pk, t in self.moved.items() if pk in keep}
        if not members:
            self.assign = {}
            self._imb_since = None
            return {}
        loads = self.loads(members)
        for pk in sorted(clients):
            if self.assign.get(pk) not in ids:
                lost = pk in self.assign
                self.assign.pop(pk, None)
                self.assign[pk] = self.pick(members, loads)
                if lost:
                    self.moved[pk] = now
        self._rebalance(members, loads, now)
        return dict(self.assign)

    def _rebalance(self, members: list[dict], loads: dict[str, float], now: float) -> None:
        if len(members) < 2:
            self._imb_since = None
            return
        caps = self.capacities(members)
        hi = max(loads, key=loads.get)
        if max(self.rate(hi)) < BUSY_BPS:
            self._imb_since = None
            return
        best = None
        for pk, uid in self.assign.items():
            if uid != hi or now - self.moved.get(pk, -1e18) < CLIENT_PAUSE:
                continue
            r = self.client_rate.get((pk, hi))
            if not r or max(r) < ACTIVE_BPS:
                continue
            h = self.rate(hi)
            new_hi = self._load([max(h[0] - r[0], 0), max(h[1] - r[1], 0)], caps[hi])
            for m in members:
                lo = m["id"]
                if lo == hi:
                    continue
                low = self.rate(lo)
                new_max = max(new_hi, self._load([low[0] + r[0], low[1] + r[1]], caps[lo]))
                if new_max <= GAIN * loads[hi] and (best is None or new_max < best[0]):
                    best = (new_max, pk, lo)
        if not best:
            self._imb_since = None
            return
        if self._imb_since is None:
            self._imb_since = now
        if now - self._imb_since < SUSTAIN or now - self._last_move < STEP:
            return
        _, pk, lo = best
        self.assign[pk] = lo
        self.moved[pk] = self._last_move = now
        self._imb_since = None
        self.last_move = {"pk": pk, "from": hi, "to": lo, "at": now}

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for uid in self.assign.values():
            out[uid] = out.get(uid, 0) + 1
        return out
