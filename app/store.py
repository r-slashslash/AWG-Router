"""Хранение настроек панели в /data/state.json."""
from __future__ import annotations

import copy
import json
import os
import re
import secrets
import threading
import time

from . import config
from .i18n import Msg, MsgError

STATE_PATH = os.path.join(config.DATA_DIR, "state.json")

DEFAULT_STATE = {
    "version": 1,
    "routing": {
        "default": "direct",
        "rules": [
            {"id": "r_geo", "lists": ["ru", "cn", "ir"], "outbound": "direct",
             "enabled": True, "comment": ""},
        ],
    },
    "upstreams": [],
    "lists": [
        {"id": "ru", "name": "", "kind": "country", "source": "ru"},
        {"id": "cn", "name": "", "kind": "country", "source": "cn"},
        {"id": "ir", "name": "", "kind": "country", "source": "ir"},
    ],
    "clients": {},
    "keys": {},
    "limits": {},     # срок и лимит трафика клиентов (limits.py)
    "shares": {},     # личные ссылки клиентов: токен → {pk, created}
    "cps": {},        # свои I1–I5 клиента: pk → {preset: имя шаблона | "custom", values}
    "settings": {"list_update_hours": 24},
}

ID_RE = re.compile(r"^[a-z0-9_]{1,24}$")


def new_id(prefix: str) -> str:
    return f"{prefix}{secrets.token_hex(3)}"


class Store:
    def __init__(self, path: str = STATE_PATH):
        self.path = path
        self.lock = threading.RLock()
        self.rev = 0
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            with open(path) as f:
                self.state = json.load(f)
            for k, v in DEFAULT_STATE.items():
                self.state.setdefault(k, copy.deepcopy(v))
            if self._upgrade():
                self._write()
        else:
            self.state = copy.deepcopy(DEFAULT_STATE)
            self._write()

    def _upgrade(self) -> bool:
        """Прежние имена шаблонов маскировки у клиентов (cps.RENAMED), шифрование DNS на сервере у тех, кто
        включил его до 1.16.0. True — что-то поменялось."""
        from .cps import RENAMED
        changed = False
        for e in (self.state.get("cps") or {}).values():
            if isinstance(e, dict) and e.get("preset") in RENAMED:
                e["preset"] = RENAMED[e["preset"]]
                changed = True
        s = self.state.get("settings") or {}
        if s.get("panel_dns") and "panel_dns_enc" not in s:
            # DNS на сервере включили в 1.15.0, до шифрования: оставляем как было — DoH по умолчанию
            # сломал бы DNS клиентов, если серверы в настройках его не умеют
            s["panel_dns_enc"] = "plain"
            changed = True
        return changed

    def _write(self) -> None:
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.state, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def snapshot(self) -> dict:
        with self.lock:
            return copy.deepcopy(self.state)

    def mutate(self, fn):
        """fn(state) изменяет состояние; при исключении изменения откатываются."""
        with self.lock:
            draft = copy.deepcopy(self.state)
            result = fn(draft)
            self.state = draft
            self.rev += 1
            self._write()
            return result

    # --- вспомогательные ---------------------------------------------------
    @staticmethod
    def upstream(state: dict, uid: str) -> dict | None:
        return next((u for u in state["upstreams"] if u["id"] == uid), None)

    @staticmethod
    def lst(state: dict, lid: str) -> dict | None:
        return next((l for l in state["lists"] if l["id"] == lid), None)

    @staticmethod
    def free_num(state: dict) -> int:
        used = {u["num"] for u in state["upstreams"]}
        for n in range(1, config.MAX_UPSTREAMS + 1):
            if n not in used:
                return n
        raise MsgError(Msg("err.too_many_upstreams", max=config.MAX_UPSTREAMS))

    @staticmethod
    def _rule_ref(rule: dict, idx: int, client: str | None = None) -> Msg:
        label = rule.get("comment") or f"#{idx + 1}"
        if client is not None:
            return Msg("ref.client_rule", rule=label, client=client)
        return Msg("ref.rule", rule=label)

    @staticmethod
    def outbound_refs(state: dict, target: str) -> list[Msg]:
        """Где используется выход (например 'up:u1a2b3c')."""
        refs = []
        r = state["routing"]
        if r["default"] == target:
            refs.append(Msg("ref.default"))
        for i, rule in enumerate(r["rules"]):
            if rule["outbound"] == target:
                refs.append(Store._rule_ref(rule, i))
        for u in state["upstreams"]:
            if u.get("fallback") == target:
                refs.append(Msg("ref.fallback", name=u["name"]))
            if u.get("quota_action") == target:
                refs.append(Msg("ref.quota", name=u["name"]))
        if (state.get("settings", {}).get("telegram") or {}).get("via") == target:
            refs.append(Msg("ref.telegram"))
        for pk, c in state["clients"].items():
            name = c.get("name") or pk[:8]
            if c.get("outbound") == target:
                refs.append(Msg("ref.client", client=name))
            if c.get("rules_mode") == "custom":
                for i, rule in enumerate(c.get("rules") or []):
                    if rule["outbound"] == target:
                        refs.append(Store._rule_ref(rule, i, name))
        return refs

    @staticmethod
    def replace_outbound(state: dict, target: str, new: str, spare: str | None = None) -> None:
        """Все ссылки на выход target (как в outbound_refs) → new. Там, где new не подходит
        (резерв самого выхода new; Telegram и «блок»), берётся spare, затем «напрямую»;
        лимит выхода, который указал бы на сам выход, становится «только сообщить».
        Правила клиентов меняются и в режиме «как у всех»: иначе при переключении на свои
        правила в них всплыл бы удалённый выход."""
        def pick(own: str | None = None, allow_block: bool = True, last: str = "direct") -> str:
            for c in (new, spare, last):
                if c and c != target and c != own and (allow_block or c != "block"):
                    return c
            return last

        r = state["routing"]
        if r["default"] == target:
            r["default"] = pick()
        for rule in r["rules"]:
            if rule["outbound"] == target:
                rule["outbound"] = pick()
        for u in state["upstreams"]:
            own = "up:" + u["id"]
            if u.get("fallback") == target:
                u["fallback"] = pick(own)
            if u.get("quota_action") == target:
                u["quota_action"] = "notify" if new == own else pick(own, last="notify")
        for c in state["clients"].values():
            if c.get("outbound") == target:
                c["outbound"] = pick()
            for rule in c.get("rules") or []:
                if rule.get("outbound") == target:
                    rule["outbound"] = pick()
        tg = state.get("settings", {}).get("telegram") or {}
        if tg.get("via") == target:
            tg["via"] = pick(allow_block=False)

    @staticmethod
    def list_refs(state: dict, lid: str) -> list[Msg]:
        refs = []
        for i, rule in enumerate(state["routing"]["rules"]):
            if lid in rule["lists"]:
                refs.append(Store._rule_ref(rule, i))
        for pk, c in state["clients"].items():
            if c.get("rules_mode") == "custom":
                for i, rule in enumerate(c.get("rules") or []):
                    if lid in rule["lists"]:
                        refs.append(Store._rule_ref(rule, i, c.get("name") or pk[:8]))
        return refs


def now() -> float:
    return time.time()
