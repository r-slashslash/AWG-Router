"""Правила проекта, которые легко забыть: python3 -m unittest discover tests

Каждый тест здесь — правило, проверяемое автоматически: его нельзя пропустить при чтении.
"""
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from app import lists, main, traffic  # noqa: E402
from app.store import Store  # noqa: E402

LANGS = ("ru", "en", "zh", "fa")
STR = r'"((?:[^"\\]|\\.)*)"'


def read(*path) -> str:
    with open(os.path.join(ROOT, *path), encoding="utf-8") as f:
        return f.read()


def i18n() -> dict[str, dict[str, str | None]]:
    """Словари app/static/i18n.js: язык → {ключ: строка (None — формы множественного числа)}."""
    js = read("app", "static", "i18n.js")
    out = {lang: {} for lang in LANGS}
    main_obj = js[js.index("const I18N = {"):]
    main_obj = main_obj[:main_obj.index("\n};")]
    parts = re.split(r"\n  (ru|en|zh|fa): \{", main_obj)     # основной объект: «  ru: { … },»
    blocks = list(zip(parts[1::2], parts[2::2]))
    for m in re.finditer(r"Object\.assign\(I18N\.(\w+), \{(.*?)\n\}\);", js, re.S):
        blocks.append((m.group(1), m.group(2)))
    for lang, body in blocks:
        for k, v in re.findall(rf'"([a-z][\w.]*)":\s*(?:{STR}|\{{)', body):
            out[lang][k] = v if v or not body.split(f'"{k}":', 1)[1].lstrip().startswith("{") else None
    return out


class I18nTest(unittest.TestCase):
    """Каждая строка интерфейса — на 4 языках, с одинаковыми {плейсхолдерами}."""

    @classmethod
    def setUpClass(cls):
        cls.d = i18n()

    def test_same_keys_in_every_language(self):
        en = set(self.d["en"])
        self.assertGreater(len(en), 500)
        for lang in LANGS:
            self.assertEqual(sorted(en - set(self.d[lang])), [], f"missing in {lang}")
            self.assertEqual(sorted(set(self.d[lang]) - en), [], f"only in {lang}")

    def test_same_placeholders(self):
        ph = lambda s: sorted(set(re.findall(r"\{(\w+)\}", s or "")))
        bad = [(k, lang) for k, v in self.d["en"].items() if v is not None
               for lang in LANGS if self.d[lang].get(k) is not None and ph(self.d[lang][k]) != ph(v)]
        self.assertEqual(bad, [])

    def test_keys_used_in_code_exist(self):
        """Ключи из t("…") / th("…") в браузере и из Msg("…") / bad("…") на сервере."""
        keys = set(self.d["en"])
                # только целые ключи: t("cl.sort_" + x) собирается на лету и здесь не проверяется
        lit = r'\bth?\("([a-z][\w.]*)"\s*[,)]'
        used = set(re.findall(lit, read("app", "static", "app.js") + read("app", "static", "share.js")))
        for name in os.listdir(os.path.join(ROOT, "app")):
            if name.endswith(".py") and name not in ("notify.py", "tgbot.py", "sniproxy.py", "tgreq.py"):
                src = read("app", name)
                used |= set(re.findall(r'\b(?:Msg|bad|UserError|HTTPError\(\d+,)\s*\(?\s*"([a-z]+\.[\w.]+)"\s*[,)]', src))
        self.assertEqual(sorted(k for k in used if k not in keys), [])


class ExitReferencesTest(unittest.TestCase):
    """Каждое место, которое может указывать на выход, есть и в Store.outbound_refs, и в
    Store.replace_outbound: удаление выхода с заменой не оставляет ссылок на него."""

    def test_delete_with_replace_leaves_no_reference(self):
        R = lambda b: type("R", (), {"json": lambda self: b})()
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            main.engine.reconcile()
            x = main.add_upstream(R({"name": "X", "config": "socks5://198.51.100.9:1080"}))["id"]
            y = main.add_upstream(R({"name": "Y", "config": "socks5://198.51.100.10:1080",
                                     "fallback": "up:" + x, "quota_gb": 1, "quota_action": "up:" + x}))["id"]
            pk = main.engine.clients[0]["public_key"]
            out = "up:" + x
            st0 = main.store.snapshot()
            try:
                main.put_routing(R({"default": out, "rules": [{"lists": ["ru"], "outbound": out}]}))
                main.put_client(R({"outbound": out, "rules_mode": "custom",
                                   "rules": [{"lists": ["cn"], "outbound": out}]}), pk)
                main.store.mutate(lambda st: st["settings"].setdefault("telegram", {}).update(via=out))
                # каждое место из outbound_refs: умолчание, правило, резерв и квота Y, Telegram, клиент, его правило
                self.assertEqual(len(Store.outbound_refs(main.store.snapshot(), out)), 7)
                main.del_upstream(R({"replace": "direct"}), x)
                self.assertNotIn(f'"{out}"', json.dumps(main.store.snapshot()))
            finally:
                main.store.mutate(lambda st: st.update(routing=st0["routing"], clients=st0["clients"],
                                                       settings=st0["settings"]))
                for uid in (x, y):
                    if Store.upstream(main.store.snapshot(), uid):
                        main.del_upstream(R({"replace": "direct"}), uid)


class RestoreKeepsFieldsTest(unittest.TestCase):
    """Новое поле в state.json нужно и в clean_backup_state: восстановление отбрасывает незнакомые поля."""

    # поля, которые восстановление не переносит намеренно
    DROPPED = {"lists[].addresses", "lists[].checked", "lists[].count", "lists[].error", "lists[].skipped_v6",
               "lists[].updated",                       # пересчитываются при обновлении списков
               "settings.client_host",                  # адрес этого сервера, а не из копии
               "settings.telegram.backup_last", "settings.telegram.backup_error",
               "await_first"}                           # ждать первого подключения — только на этом сервере

    def test_round_trip(self):
        R = lambda b: type("R", (), {"json": lambda self: b})()
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            main.engine.reconcile()
            x = main.add_upstream(R({"name": "X", "config": "socks5://198.51.100.9:1080", "quota_gb": 5,
                                     "quota_action": "direct", "routing": {"domains": "a.example"},
                                     "rate_down": 80, "rate_up": 20}))["id"]
            pk = main.engine.clients[0]["public_key"]
            st0 = main.store.snapshot()
            try:
                main.put_client(R({"outbound": "up:" + x, "rules_mode": "custom", "note": "n",
                                   "rules": [{"lists": ["ru"], "outbound": "direct"}]}), pk)
                main.put_limits(R({"expires": 2_000_000_000, "quota_gb": 4, "period": "total",
                                   "rate_down": 10, "rate_up": 2.5}), pk)
                main.ensure_share(pk)
                main.put_client_cps(R({"preset": "stun"}), pk)
                main.store.mutate(lambda s: s["settings"].update(panel_dns=True, panel_dns_enc="dot",
                                                                 shaping={"down": 100, "up": 50}))
                main.store.mutate(lambda s: s["routing"].update(balance={"on": True, "skip": [x]}))
                st = main.store.snapshot()
                new = main.clean_backup_state(st)
            finally:
                main.store.mutate(lambda s: s.update(clients=st0["clients"], limits=st0["limits"],
                                                     shares=st0["shares"], cps=st0["cps"]))
                main.store.mutate(lambda s: [s["settings"].pop(k, None) for k in ("panel_dns", "panel_dns_enc", "shaping")])
                main.store.mutate(lambda s: s["routing"].pop("balance", None))
                main.del_upstream(R({"replace": "direct"}), x)

        def walk(a, b, path=""):
            if isinstance(a, dict):
                for k, v in a.items():
                    p = f"{path}.{k}" if path else k
                    if not isinstance(b, dict) or k not in b:
                        yield p
                    else:
                        yield from walk(v, b[k], p)
            elif isinstance(a, list) and isinstance(b, list):
                for i, (u, w) in enumerate(zip(a, b)):
                    yield from walk(u, w, f"{path}[{i}]")
        norm = lambda p: re.sub(r"\[\d+\]", "[]", re.sub(r"\.[A-Za-z0-9+/]{43}=", ".<pk>", re.sub(
            r"shares\.[\w-]{20,}", "shares.<tok>", p)))
        lost = {norm(p) for p in walk(st, new)} - self.DROPPED
        self.assertEqual(sorted(lost), [], "add these fields to clean_backup_state (or to DROPPED with a reason)")


class FormatsTest(unittest.TestCase):
    def test_traffic_format_stays_2(self):
        """Старые панели читают только _v == 2 и игнорируют новые ключи: откат версии не стирает итоги."""
        self.assertEqual(traffic.FORMAT, 2)

    def test_public_assets_whitelist(self):
        """Личная страница клиента (вне секретного пути) грузит только файлы из app.public_files."""
        pages = read("app", "static", "share.html") + read("app", "static", "share.js")
        used = set(re.findall(r'/s/assets/([^"\'?)\s]+)', pages))
        # шрифты из app.css (его грузит и личная страница): адреса относительно /s/assets/
        used |= {u for u in re.findall(r'url\("?([^")]+)"?\)', read("app", "static", "app.css"))
                 if not u.startswith("data:")}
        self.assertTrue(used, "share.html refers to no assets: the pattern above is out of date")
        self.assertEqual(sorted(used - main.app.public_files), [])
        for f in main.app.public_files:
            self.assertTrue(os.path.isfile(os.path.join(ROOT, "app", "static", f)), f)


if __name__ == "__main__":
    unittest.main()
