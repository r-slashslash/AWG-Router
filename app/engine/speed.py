"""Ограничения скорости: план shaping.plan и его применение через tc (HTB, ifb для входящего)."""
from __future__ import annotations

import os
import re
import time

from .. import config, shaping, system
from ..i18n import Msg
from .common import RUN_DIR, server_ifaces


def _ifb_sources(t: system.Target, ifb: str) -> list[str]:
    """ifb → интерфейсы, входящий трафик которых он ограничивает (awgq0 → [awg0, wg0], awgqN → [awgrN])."""
    m = re.fullmatch(re.escape(shaping.IFB_PREFIX) + r"(\d+)", ifb)
    if not m:
        return []
    if m.group(1) == "0":
        return list(dict.fromkeys([*server_ifaces(t), "wg0"]))
    return [f"{config.IFACE_PREFIX}{int(m.group(1))}"]


class SpeedMixin:
    """Ограничения скорости: tc (часть Engine)."""

    # ------------------------------------------------ ограничение скорости (tc)
    def shaping_plan(self, t: system.Target, st: dict) -> dict:
        lim = st.get("limits") or {}
        clients = {}
        for c in self.clients:
            if c.get("ip"):
                L = lim.get(c["public_key"]) or {}
                clients[c["ip"]] = {"down": L.get("rate_down"), "up": L.get("rate_up")}
        exits = [{"num": r.num, "iface": r.iface, "down": u.get("rate_down"), "up": u.get("rate_up")}
                 for u in st["upstreams"] if (r := self.rt.get(u["id"])) and r.target_key == t.key]
        return shaping.plan(server_ifaces(t), st["settings"].get("shaping") or {}, clients, exits)

    def _ifb_source(self, t: system.Target, ifb: str) -> str | None:
        srcs = _ifb_sources(t, ifb)
        return srcs[0] if srcs else None

    def _sync_shaping(self, t: system.Target, st: dict) -> None:
        """Держит очереди tc такими, как в настройках ограничения скорости. Ничего не задано — tc
        не вызывается вовсе (кроме одной уборки на цель: остатки прошлого запуска панели)."""
        p = self.shaping_plan(t, st)
        roots, ingress = p["roots"], p["ingress"]
        if not roots and self._shape_key == t.key and not self._shape:
            self.shape_state = None
            return
        if config.DRY_RUN:
            self.shape_state = {"state": "on"} if roots else None
            self._shape = {d: shaping.digest(c) for d, c in roots.items()}
            self._shape_key = t.key
            return
        now = time.time()
        sig = shaping.digest([sorted(roots.items()), sorted(ingress.items()), t.key])
        st_ = self.shape_state or {}
        if st_.get("state") == "error" and st_.get("sig") == sig and now < self._shape_retry:
            return                                   # та же ошибка — не чаще раза в минуту
        q = t.ns(["tc", "-j", "qdisc", "show"], check=False, timeout=20)
        if q.returncode != 0:
            if roots:
                self._shape_failed(sig, Msg("sh.no_tc", detail=(q.stderr or q.stdout or "").strip()[-200:]))
            else:
                self.shape_state, self._shape_key = None, t.key
            return
        ours, ing = shaping.parse_qdiscs(q.stdout)
        links = self._links(t) or set()
        # лишнее: сначала перенаправление, потом сам ifb (пакеты в пропавший ifb отбрасывались бы)
        for l in sorted(links):
            srcs = _ifb_sources(t, l)
            if not srcs or all(ingress.get(s) == l for s in srcs):
                continue
            for src in srcs:
                if src in ing and src not in ingress:
                    t.ns(["tc", "qdisc", "del", "dev", src, "ingress"], check=False)
                if src not in ingress:
                    self._shape.pop("ing:" + src, None)
            if not any(ingress.get(s) == l for s in srcs):
                t.ns(["ip", "link", "del", l], check=False)
                self._shape.pop(l, None)
        for dev in ours - set(roots):
            t.ns(["tc", "qdisc", "del", "dev", dev, "root"], check=False)
            self._shape.pop(dev, None)
        self._shape_key = t.key
        errors = []
        for ifb in ingress.values():
            if ifb not in links:
                r = t.ns(["ip", "link", "add", ifb, "type", "ifb"], check=False)
                if r.returncode != 0:
                    errors.append(Msg("sh.no_ifb", detail=(r.stderr or r.stdout or "").strip()[-200:]))
                    continue
                links.add(ifb)
            t.ns(["ip", "link", "set", ifb, "up"], check=False)
        for dev, cmds in roots.items():
            h = shaping.digest(cmds)
            if dev not in links and dev not in server_ifaces(t):
                continue                              # ifb не создался — ошибка уже есть
            if dev in ours and self._shape.get(dev) == h:
                continue
            if dev in ours:
                t.ns(["tc", "qdisc", "del", "dev", dev, "root"], check=False)
            err = self._tc_batch(t, dev, cmds)
            if err:
                errors.append(Msg("sh.failed", dev=dev, detail=err))
                self._shape.pop(dev, None)
                t.ns(["tc", "qdisc", "del", "dev", dev, "root"], check=False)   # не оставлять половину
            else:
                self._shape[dev] = h
        for src, ifb in ingress.items():
            if ifb not in links:
                continue
            k = "ing:" + src
            if src in ing and self._shape.get(k) == ifb:
                continue
            if src in ing:
                t.ns(["tc", "qdisc", "del", "dev", src, "ingress"], check=False)
            err = self._tc_batch(t, src + "-in", shaping.redirect(src, ifb))
            if err:
                errors.append(Msg("sh.failed", dev=src, detail=err))
                t.ns(["tc", "qdisc", "del", "dev", src, "ingress"], check=False)
                self._shape.pop(k, None)
            else:
                self._shape[k] = ifb
        self._shape = {k: v for k, v in self._shape.items()
                       if k in roots or (k.startswith("ing:") and k[4:] in ingress)}
        if errors:
            self._shape_failed(sig, errors[0])
        else:
            if st_.get("state") == "error":
                self.event("info", Msg("ev.shaping_ok"))
            self.shape_state = {"state": "on"} if roots else None

    def _shape_failed(self, sig: str, err: Msg) -> None:
        prev = self.shape_state or {}
        if prev.get("state") != "error" or str(prev.get("error")) != str(err):
            self.event("warn", Msg("ev.shaping_failed", error=err))
        self.shape_state = {"state": "error", "error": err, "sig": sig}
        self._shape_retry = time.time() + 60

    def _tc_batch(self, t: system.Target, name: str, cmds: list[str]) -> str | None:
        """Команды через tc -batch. → None или текст ошибки."""
        path = os.path.join(RUN_DIR, f"tc-{name}.batch")
        with open(path, "w") as f:
            f.write("\n".join(cmds) + "\n")
        r = t.ns(["tc", "-batch", path], check=False, timeout=30)
        return None if r.returncode == 0 else (r.stderr or r.stdout or "").strip()[-300:] or "tc"

    def _clear_shaping(self, t: system.Target) -> None:
        """Убирает все наши очереди и ifb (удаление панели, «восстановить при остановке»)."""
        if config.DRY_RUN:
            return
        q = t.ns(["tc", "-j", "qdisc", "show"], check=False, timeout=20)
        if q.returncode != 0:
            return
        ours, ing = shaping.parse_qdiscs(q.stdout)
        for l in sorted(self._links(t) or ()):
            srcs = _ifb_sources(t, l)
            if srcs:
                for src in srcs:
                    if src in ing:
                        t.ns(["tc", "qdisc", "del", "dev", src, "ingress"], check=False)
                t.ns(["ip", "link", "del", l], check=False)
        for dev in ours:
            t.ns(["tc", "qdisc", "del", "dev", dev, "root"], check=False)
        self._shape, self._shape_key, self.shape_state = {}, None, None
