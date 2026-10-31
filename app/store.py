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
        else:
            self.state = copy.deepcopy(DEFAULT_STATE)
            self._write()

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
