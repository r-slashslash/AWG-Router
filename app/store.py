"""Хранение настроек панели в /data/state.json."""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import threading
import time

from . import config
from .i18n import Msg, MsgError

log = logging.getLogger("awgr.store")

STATE_PATH = os.path.join(config.DATA_DIR, "state.json")
# однократные исправления состояния прежних выпусков: сделанные записаны в state["upgraded"]
RULE_NAMES = "rule_names"       # подписи правил именем выхода из окна выхода до 1.21.0 (drop_auto_comments)
# приглашения клиентов в бота (1.22.0): бот начинает читать сообщения и без управления. Где бот был только для
# уведомлений, его же могла читать другая программа (вторая панель) — там приглашения выключены, пока их не включат
CLIENT_BOT = "client_bot"
# «Включить бот» (1.23.0) — главный выключатель: раньше «Присылать уведомления» не трогал управление и клиентов
# в боте. Где бот работал без уведомлений (управление или клиенты), он включается — и уведомления пойдут
# (решение владельца 2026-11-19: «пусть присылает, сами снимут»)
BOT_SWITCH = "bot_switch"
UPGRADES = (RULE_NAMES, CLIENT_BOT, BOT_SWITCH)

DEFAULT_STATE = {
    "version": 1,
    "routing": {
        "default": "direct",
        # новая установка — без правил и списков (решение владельца 2026-11-19): страны — кнопками «Применить для …»
        # в «Обзоре» (countries.py). До 1.22.0 здесь были Россия, Китай и Иран напрямую — у обновившихся они остаются
        "rules": [],
    },
    "upstreams": [],
    "lists": [],
    "clients": {},
    "keys": {},
    "limits": {},     # срок и лимит трафика клиентов (limits.py)
    "shares": {},     # личные ссылки клиентов: токен → {pk, created}
    "cps": {},        # свои I1–I5 клиента: pk → {preset: имя шаблона | "custom", values}
    "chost": {},      # свой адрес сервера в конфиге клиента: pk → адрес из host_choices (с 1.21.0, #37)
    "settings": {
        "list_update_hours": 24,
    },
}

ID_RE = re.compile(r"^[a-z0-9_]{1,24}$")

# Списки, чей текст вводят руками (сети и домены, до LIST_TEXT_MAX): текст лежит в своём файле texts/<id>-<метка>.txt
# рядом с state.json, а в состоянии — только метка файла "text" и пустой "source". Так state.json маленький: он
# пишется целиком при каждом изменении и копируется на каждый запрос. Резервная копия несёт сами тексты
# (snapshot(texts=True)). Прежний выпуск, запущенный на этих файлах, увидит такие списки пустыми — текст вернёт
# загрузка резервной копии.
TEXT_KINDS = ("manual", "domains")
TEXT_RE = re.compile(r"^[0-9a-f]{16}$")


def new_id(prefix: str) -> str:
    return f"{prefix}{secrets.token_hex(3)}"



def fsync_dir(path: str) -> None:
    """Сбросить на диск саму папку: после os.replace новое имя файла иначе может не пережить сбой питания."""
    try:
        d = os.open(path or ".", os.O_RDONLY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    except OSError:
        pass

class Store:
    def __init__(self, path: str = STATE_PATH):
        self.path = path
        self.text_dir = os.path.join(os.path.dirname(path), "texts")
        self.lock = threading.RLock()
        self.rev = 0
        self._texts: set[str] = set()       # файлы текстов, на которые ссылается записанное состояние
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            self.state = self._read()
            for k, v in DEFAULT_STATE.items():
                self.state.setdefault(k, copy.deepcopy(v))
            self._texts = self._text_refs(self.state)
            if self._upgrade() or not os.path.exists(path):     # нет файла — взяли запасную копию (_read)
                self._write()
        else:
            self.state = copy.deepcopy(DEFAULT_STATE)
            self.state["upgraded"] = list(UPGRADES)
            self._write()

    def _upgrade(self) -> bool:
        """Прежние имена шаблонов маскировки у клиентов (cps.RENAMED), шифрование DNS на сервере у тех, кто
        включил его до 1.16.0. True — что-то поменялось."""
        from .cps import RENAMED
        dns_enc = Store.missing_dns_enc(self.state)     # до отметок ниже: по ним видно, какой выпуск писал файл
        changed = False
        for e in (self.state.get("cps") or {}).values():
            if isinstance(e, dict) and e.get("preset") in RENAMED:
                e["preset"] = RENAMED[e["preset"]]
                changed = True
        if Store.drop_auto_comments_once(self.state):
            changed = True
        if Store.client_bot_once(self.state):
            changed = True
        if Store.bot_switch_once(self.state):
            changed = True
        if any(isinstance(l, dict) and l.get("kind") in TEXT_KINDS and l.get("source")
               for l in self.state.get("lists") or []):
            changed = True              # state.json до 1.21.0: тексты списков — в свои файлы (_write)
        if "socks_users" in self.state and not isinstance(self.state.get("socks_users"), dict):
            self.state["socks_users"] = {}
            changed = True
        s = self.state.get("settings")
        if not isinstance(s, dict):
            s = self.state["settings"] = copy.deepcopy(DEFAULT_STATE["settings"])
            changed = True
        elif "socks_proxy" in s:
            if not isinstance(s.get("socks_proxy"), dict):
                s["socks_proxy"] = {"enabled": False, "port": 1080}
                changed = True
            else:
                sp = s["socks_proxy"]
                if "enabled" not in sp:
                    sp["enabled"] = False
                    changed = True
                if "port" not in sp:
                    sp["port"] = 1080
                    changed = True
        if s.get("panel_dns") and "panel_dns_enc" not in s:
            s["panel_dns_enc"] = dns_enc
            changed = True
        return changed

    @staticmethod
    def missing_dns_enc(src: dict) -> str:
        """Шифрование для DNS на сервере, включённого без записанного шифрования, в состоянии или копии src.
        Без отметки RULE_NAMES (файл до 1.21.0) — «plain»: DNS на сервере включили в 1.15.0, до шифрования, и DoH
        по умолчанию сломал бы DNS клиентов, если серверы в настройках его не умеют. С ней — «doh», с которым DNS на
        сервере и работал: так его включала кнопка «Применить для …» 1.22.0, не записывая шифрования, и первый же
        перезапуск панели ставил «Без шифрования»."""
        done = src.get("upgraded")
        return "doh" if isinstance(done, list) and RULE_NAMES in done else "plain"

    @staticmethod
    def client_bot_once(state: dict, source: dict | None = None) -> bool:
        """Один раз для состояния (или копии) до 1.22.0: бот с токеном, но без управления, продолжает только
        присылать уведомления — приглашения клиентов выключены. Дальше галочка — решение человека.
        source — откуда взято состояние (копия), если не оно само. True — что-то поменялось."""
        done = (source if source is not None else state).get("upgraded")
        done = [x for x in done if x in UPGRADES] if isinstance(done, list) else []
        if CLIENT_BOT in done:
            if state.get("upgraded") != done:
                state["upgraded"] = done
                return True
            return False
        src = ((source if source is not None else state).get("settings") or {}).get("telegram")
        tg = (state.get("settings") or {}).get("telegram")
        if isinstance(src, dict) and isinstance(tg, dict) and src.get("token") and not src.get("control") \
                and "clients" not in src:
            tg["clients"] = False
        state["upgraded"] = [x for x in (state.get("upgraded") if isinstance(state.get("upgraded"), list) else [])
                             if x in UPGRADES and x != CLIENT_BOT] + [CLIENT_BOT]
        return True

    @staticmethod
    def bot_switch_once(state: dict, source: dict | None = None) -> bool:
        """Один раз для состояния (или копии) до 1.23.0: бот с токеном, у которого работало управление или клиенты
        по приглашению, а «Присылать уведомления» было выключено, — включается («Включить бот» теперь выключает
        всё). Идёт после client_bot_once: у того бота до 1.22.0 клиенты уже выключены. True — что-то поменялось."""
        done = (source if source is not None else state).get("upgraded")
        done = [x for x in done if x in UPGRADES] if isinstance(done, list) else []
        mine = [x for x in (state.get("upgraded") if isinstance(state.get("upgraded"), list) else [])
                if x in UPGRADES and x != BOT_SWITCH]
        if BOT_SWITCH in done:
            if state.get("upgraded") != mine + [BOT_SWITCH]:
                state["upgraded"] = mine + [BOT_SWITCH]
                return True
            return False
        tg = (state.get("settings") or {}).get("telegram")
        if isinstance(tg, dict) and tg.get("token") and not tg.get("enabled") and (tg.get("control") or tg.get("clients")):
            tg["enabled"] = True
        state["upgraded"] = mine + [BOT_SWITCH]
        return True

    @staticmethod
    def drop_auto_comments_once(state: dict, source: dict | None = None) -> bool:
        """drop_auto_comments один раз: при первом запуске 1.21.0 и для копии прежнего выпуска.
        Потом имя правила, совпадающее с именем выхода, — уже своё название, и его не трогаем.
        source — откуда взято состояние (копия), если не оно само. True — что-то поменялось."""
        done = (source if source is not None else state).get("upgraded")
        done = [x for x in done if x in UPGRADES] if isinstance(done, list) else []    # из копии — только известные
        if RULE_NAMES in done:
            if state.get("upgraded") != done:
                state["upgraded"] = done
                return True
            return False
        Store.drop_auto_comments(state)
        state["upgraded"] = done + [RULE_NAMES]
        return True

    @staticmethod
    def drop_auto_comments(state: dict) -> bool:
        """До 1.21.0 окно выхода подписывало созданное им правило именем выхода, и строка правила
        выглядела как «mobile — ● mobile». Такая подпись ничего не добавляет к выходу справа —
        убираем её (у общих правил и правил клиентов). Своё название, отличное от имени выхода,
        остаётся. True — что-то поменялось."""
        names = {"up:" + u["id"]: u.get("name") for u in state.get("upstreams") or [] if isinstance(u, dict)
                 and isinstance(u.get("id"), str)}
        changed = False
        groups = [(state.get("routing") or {}).get("rules")]
        groups += [c.get("rules") for c in (state.get("clients") or {}).values() if isinstance(c, dict)]
        for rules in groups:
            for r in rules if isinstance(rules, list) else []:
                if isinstance(r, dict) and r.get("comment") and r.get("comment") == names.get(r.get("outbound")):
                    r["comment"] = ""
                    changed = True
        return changed

    def _read(self) -> dict:
        """state.json, а если он повреждён (оборван при сбое питания, диск переполнился) — прежняя версия
        из state.json.bak: раньше панель с таким файлом не запускалась вовсе. Повреждённый файл остаётся
        рядом как state.json.broken. Нет и запасной копии — ошибка, как прежде: запуск с пустыми
        настройками молча пустил бы всех клиентов напрямую."""
        def load(p: str) -> dict:
            with open(p) as f:
                d = json.load(f)
            if not isinstance(d, dict):
                raise ValueError("state is not an object")
            return d
        try:
            return load(self.path)
        except (OSError, ValueError) as e:
            try:
                state = load(self.path + ".bak")
            except (OSError, ValueError):
                raise e from None
            log.warning("state.json is damaged (%s): using the previous version from state.json.bak; "
                        "the damaged file is kept as state.json.broken", e)
            # прежняя версия встаёт на место state.json сразу, а не при первой записи: раньше повреждённый файл
            # переименовывался, и если первая запись не удалась (нет места), следующий запуск видел «нет файла» и
            # начинал с пустых настроек — клиенты мимо выходов (Г6 глубокой проверки 1.23.0). Не вышло скопировать —
            # state.json остаётся повреждённым, и следующий запуск снова возьмёт state.json.bak
            try:
                shutil.copyfile(self.path, self.path + ".broken")
                tmp = self.path + ".restore"
                shutil.copyfile(self.path + ".bak", tmp)
                with open(tmp, "rb") as f:
                    os.fsync(f.fileno())
                os.replace(tmp, self.path)
                fsync_dir(os.path.dirname(self.path))
            except OSError as err:
                log.warning("could not put state.json.bak in place: %s", err)
            return state

    def _write(self, state: dict | None = None) -> None:
        state = self.state if state is None else state
        refs = self._save_texts(state)          # сначала тексты: state.json ссылается только на записанное
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        # прежняя версия — жёсткой ссылкой рядом (тот же файл, без копирования): её читает _read
        bak = self.path + ".bak"
        try:
            if os.path.exists(self.path):
                if os.path.lexists(bak):
                    os.remove(bak)
                os.link(self.path, bak)
        except OSError:
            pass                        # файловая система без жёстких ссылок — живём без запасной копии
        os.replace(tmp, self.path)
        # лишние тексты — после записи; тексты прежнего состояния остаются: оно теперь state.json.bak
        self._drop_texts(refs | self._texts)
        self._texts = refs

    # --- тексты ручных списков (TEXT_KINDS) --------------------------------
    @staticmethod
    def _text_refs(state: dict) -> set[str]:
        return {f"{l['id']}-{l['text']}.txt" for l in state.get("lists") or []
                if isinstance(l, dict) and isinstance(l.get("id"), str) and ID_RE.match(l["id"])
                and isinstance(l.get("text"), str) and TEXT_RE.match(l["text"])}

    def _save_texts(self, state: dict) -> set[str]:
        """Текст, который пришёл в "source" (ввод в панели, резервная копия, state.json до 1.21.0), — в файл
        texts/<id>-<метка>.txt (метка — от содержимого: новый текст — новый файл, старый цел до записи
        state.json); в состоянии остаются пустой "source" и метка "text". → файлы, на которые оно ссылается."""
        wrote = False
        for l in state.get("lists") or []:
            if not (isinstance(l, dict) and l.get("kind") in TEXT_KINDS and isinstance(l.get("id"), str)
                    and ID_RE.match(l["id"]) and l.get("source")):
                continue
            text = str(l["source"])
            h = hashlib.sha256(text.encode()).hexdigest()[:16]
            path = os.path.join(self.text_dir, f"{l['id']}-{h}.txt")
            if not os.path.exists(path):
                os.makedirs(self.text_dir, mode=0o700, exist_ok=True)
                tmp = path + ".tmp"
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(text)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, path)
                wrote = True
            l["source"], l["text"] = "", h
        if wrote:
            fsync_dir(self.text_dir)        # имя нового файла — на диске раньше, чем state.json со ссылкой на него
        return self._text_refs(state)

    def _drop_texts(self, keep: set[str]) -> None:
        try:
            names = os.listdir(self.text_dir)
        except OSError:
            return
        for n in names:
            if n not in keep:
                try:
                    os.remove(os.path.join(self.text_dir, n))
                except OSError:
                    pass

    def list_text(self, lid: str) -> str:
        """Текст ручного списка (сети или домены) — из его файла. Нет файла — "" (и запись в журнал)."""
        with self.lock:
            l = Store.lst(self.state, lid)
            return self._read_text(l) if l else ""

    def _read_text(self, l: dict) -> str:
        if l.get("source") or l.get("kind") not in TEXT_KINDS:
            return l.get("source") or ""
        h = l.get("text")
        if not (isinstance(h, str) and TEXT_RE.match(h) and ID_RE.match(l["id"])):
            return ""
        try:
            with open(os.path.join(self.text_dir, f"{l['id']}-{h}.txt"), encoding="utf-8") as f:
                return f.read()
        except OSError as e:
            log.warning("list %s: its text is lost (%s)", l["id"], e)
            return ""

    def snapshot(self, texts: bool = False) -> dict:
        """Копия состояния. texts — с текстами ручных списков в "source" (резервная копия): так состояние
        выглядело до 1.21.0, и его понимают прежние выпуски."""
        with self.lock:
            st = copy.deepcopy(self.state)
            if texts:
                for l in st.get("lists") or []:
                    if isinstance(l, dict) and l.get("kind") in TEXT_KINDS:
                        l["source"] = self._read_text(l)
                        l.pop("text", None)
            return st

    def peek(self, fn):
        """fn(state) под блокировкой, без копии: для маленьких ответов (есть ли токен ссылки). fn ничего не
        меняет и возвращает только неизменяемое — строку, число, bool, копию нужного куска."""
        with self.lock:
            return fn(self.state)

    def mutate(self, fn):
        """fn(state) изменяет состояние; при исключении изменения откатываются. Новое состояние
        начинает действовать только после записи на диск: если записать не удалось (нет места, ошибка
        диска), панель не применяет то, что после перезапуска пропало бы."""
        with self.lock:
            draft = copy.deepcopy(self.state)
            result = fn(draft)
            self._write(draft)
            self.state = draft
            self.rev += 1
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
