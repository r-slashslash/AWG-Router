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

from app import lists, traffic  # noqa: E402
from app.store import Store  # noqa: E402
from app import panel  # noqa: E402
from app.api import backup, clients, exits, routing  # noqa: E402
from tests.seed import legacy, legacy_lists  # noqa: E402,F401
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # tests/panel_js.py
import panel_js  # noqa: E402

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
        used = set(re.findall(lit, panel_js.source() + read("app", "static", "share.js")))
        files = [os.path.relpath(os.path.join(d, n), ROOT) for d, _, names in os.walk(os.path.join(ROOT, "app"))
                 for n in names if n.endswith(".py")]
        self.assertIn(os.path.join("app", "api", "exits.py"), files)         # подпапки тоже
        for path in files:
            if os.path.basename(path) not in ("notify.py", "tgbot.py", "sniproxy.py", "tgreq.py"):
                src = read(path)
                used |= set(re.findall(r'\b(?:Msg|bad|UserError|HTTPError\(\d+,)\s*\(?\s*"([a-z]+\.[\w.]+)"\s*[,)]', src))
        self.assertEqual(sorted(k for k in used if k not in keys), [])


class PanelScriptsTest(unittest.TestCase):
    """Код интерфейса разделён на части (app/static/js): все они в index.html, core.js первым, start.js
    последним, и ни одно имя верхнего уровня не объявлено дважды (у let/const это ошибка при загрузке, и
    панель не открылась бы, у function — молча побеждает последняя)."""

    def test_all_parts_loaded_in_order(self):
        names = [os.path.basename(p) for p in panel_js.files()]
        on_disk = sorted(n for n in os.listdir(os.path.join(ROOT, "app", "static", "js")) if n.endswith(".js"))
        self.assertEqual(sorted(names), on_disk)
        self.assertEqual((names[0], names[-1]), ("core.js", "start.js"))

    @staticmethod
    def top_names(src: str) -> list[str]:
        """Имена верхнего уровня: function, class и все имена const/let/var — и после запятой (как top() в
        eslint.config.mjs: объявление читается до «;» вне скобок и строк)."""
        names = re.findall(r"^(?:async\s+)?(?:function\*?|class)\s+([A-Za-z_$][\w$]*)", src, re.M)
        for m in re.finditer(r"^(?:const|let|var)\s+", src, re.M):
            depth, part, quote, i = 0, "", None, m.end()
            while i < len(src):
                c = src[i]
                if quote:
                    i += 2 if c == "\\" else 1
                    quote = None if c == quote else quote
                    continue
                if src.startswith("//", i) or src.startswith("/*", i):
                    end = src.find("\n" if src[i + 1] == "/" else "*/", i)
                    i = len(src) if end < 0 else end + (0 if src[i + 1] == "/" else 2)
                    continue
                if c in "\"'`":
                    quote = c
                elif c in "([{":
                    depth += 1
                elif c in ")]}":
                    depth -= 1
                elif depth == 0 and c in ",;":
                    if mm := re.match(r"\s*([A-Za-z_$][\w$]*)\s*=", part):
                        names.append(mm.group(1))
                    part = ""
                    if c == ";":
                        break
                if depth == 0 and c not in ",;":
                    part += c
                i += 1
        return names

    def test_top_level_names_unique(self):
        seen, dup = {}, []
        # theme.js и qrcode.js — тоже обычные <script> панели в одном глобальном окружении (глубокая проверка 1.23.0)
        for p in panel_js.files() + [os.path.join(ROOT, "app", "static", f) for f in ("i18n.js", "theme.js", "qrcode.js")]:
            for n in self.top_names(read(os.path.relpath(p, ROOT))):
                if n in seen:
                    dup.append(f"{n}: {seen[n]}, {os.path.basename(p)}")
                seen.setdefault(n, os.path.basename(p))
        self.assertEqual(dup, [])
        self.assertIn("clientsShown", seen)          # имя после запятой («let a = …, b = …») тоже видно


class ExitReferencesTest(unittest.TestCase):
    """Каждое место, которое может указывать на выход, есть и в Store.outbound_refs, и в
    Store.replace_outbound: удаление выхода с заменой не оставляет ссылок на него."""

    def test_delete_with_replace_leaves_no_reference(self):
        R = lambda b: type("R", (), {"json": lambda self: b})()
        legacy_lists(panel.store)
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            panel.engine.reconcile()
            x = exits.add_upstream(R({"name": "X", "config": "socks5://198.51.100.9:1080"}))["id"]
            y = exits.add_upstream(R({"name": "Y", "config": "socks5://198.51.100.10:1080",
                                     "fallback": "up:" + x, "quota_gb": 1, "quota_action": "up:" + x}))["id"]
            pk = panel.engine.clients[0]["public_key"]
            out = "up:" + x
            st0 = panel.store.snapshot()
            try:
                routing.put_routing(R({"default": out, "rules": [{"lists": ["ru"], "outbound": out}]}))
                clients.put_client(R({"outbound": out, "rules_mode": "custom",
                                   "rules": [{"lists": ["cn"], "outbound": out}]}), pk)
                panel.store.mutate(lambda st: st["settings"].setdefault("telegram", {}).update(via=out))
                # каждое место из outbound_refs: умолчание, правило, резерв и квота Y, Telegram, клиент, его правило
                self.assertEqual(len(Store.outbound_refs(panel.store.snapshot(), out)), 7)
                exits.del_upstream(R({"replace": "direct"}), x)
                self.assertNotIn(f'"{out}"', json.dumps(panel.store.snapshot()))
            finally:
                panel.store.mutate(lambda st: st.update(routing=st0["routing"], clients=st0["clients"],
                                                       settings=st0["settings"]))
                for uid in (x, y):
                    if Store.upstream(panel.store.snapshot(), uid):
                        exits.del_upstream(R({"replace": "direct"}), uid)


class RestoreKeepsFieldsTest(unittest.TestCase):
    """Новое поле в state.json нужно и в clean_backup_state: восстановление отбрасывает незнакомые поля."""

    # поля, которые восстановление не переносит намеренно
    DROPPED = {"lists[].addresses", "lists[].checked", "lists[].count", "lists[].error", "lists[].skipped_v6",
               "lists[].updated", "lists[].first",      # пересчитываются при обновлении списков
               "settings.public_host",                  # внешний адрес этого сервера, а не из копии (restore_state)
               "settings.client_host",                  # адрес этого сервера, а не из копии
               "settings.extra_hosts",                  # тоже: дополнительные адреса этого сервера (#37)
               "settings.telegram.backup_last", "settings.telegram.backup_error",
               "await_first"}                           # ждать первого подключения — только на этом сервере

    def test_round_trip(self):
        R = lambda b: type("R", (), {"json": lambda self: b})()
        legacy_lists(panel.store)
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            panel.engine.reconcile()
            x = exits.add_upstream(R({"name": "X", "config": "socks5://198.51.100.9:1080", "quota_gb": 5,
                                     "quota_action": "direct", "routing": {"domains": "a.example"},
                                     "rate_down": 80, "rate_up": 20, "quic": True}))["id"]
            pk = panel.engine.clients[0]["public_key"]
            st0 = panel.store.snapshot()
            try:
                clients.put_client(R({"outbound": "up:" + x, "rules_mode": "custom", "note": "n",
                                   "rules": [{"lists": ["ru"], "outbound": "direct"}]}), pk)
                clients.put_limits(R({"expires": 2_000_000_000, "quota_gb": 4, "period": "total",
                                   "rate_down": 10, "rate_up": 2.5}), pk)
                clients.ensure_share(pk)
                clients.put_client_cps(R({"preset": "stun"}), pk)
                panel.store.mutate(lambda s: s["settings"].update(panel_dns=True, panel_dns_enc="dot",
                                                                 shaping={"down": 100, "up": 50},
                                                                 extra_hosts=["198.51.100.20"]))
                clients.put_client_host(R({"host": "198.51.100.20"}), pk)
                panel.store.mutate(lambda s: s["routing"].update(balance={"on": True, "skip": [x]}, strict=True))
                st = panel.store.snapshot(texts=True)          # так состояние выглядит в резервной копии
                new = backup.clean_backup_state(st)
            finally:
                panel.store.mutate(lambda s: s.update(clients=st0["clients"], limits=st0["limits"],
                                                     shares=st0["shares"], cps=st0["cps"], chost=st0.get("chost", {})))
                panel.store.mutate(lambda s: [s["settings"].pop(k, None) for k in ("panel_dns", "panel_dns_enc", "shaping",
                                                                                   "extra_hosts")])
                panel.store.mutate(lambda s: [s["routing"].pop(k, None) for k in ("balance", "strict")])
                exits.del_upstream(R({"replace": "direct"}), x)

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
        self.assertEqual(sorted(used - panel.app.public_files), [])
        for f in panel.app.public_files:
            self.assertTrue(os.path.isfile(os.path.join(ROOT, "app", "static", f)), f)


class ProjectRulesTest(unittest.TestCase):
    """Правила из заметок для разработки, которые раньше держались только на памяти."""

    TEXT = (".py", ".js", ".css", ".html", ".md", ".sh", ".yml", ".yaml", ".txt", ".json")

    def files(self):
        for d, dirs, names in os.walk(ROOT):
            dirs[:] = [x for x in dirs if x not in (".git", "__pycache__", "node_modules", ".ruff_cache", "data")]
            for n in names:
                if n.endswith(self.TEXT):
                    yield os.path.join(d, n)

    def test_no_ai_attribution(self):
        """Никакого упоминания ИИ в файлах репозитория: ни строки соавторства, ни подписи «сделано с помощью»
        (сами строки здесь собраны из частей, чтобы тест не находил себя)."""
        bad = re.compile("co-" + "authored-by|generated " + "with", re.I)
        found = []
        for path in self.files():
            with open(path, encoding="utf-8", errors="replace") as f:
                if bad.search(f.read()):
                    found.append(os.path.relpath(path, ROOT))
        self.assertEqual(found, [])

    def test_actions_pinned_by_sha(self):
        """Каждый uses: в workflow закреплён SHA из 40 знаков с комментарием # vN (Dependabot обновляет сам)."""
        wf = os.path.join(ROOT, ".github", "workflows")
        bad = []
        for n in sorted(os.listdir(wf)):
            for i, line in enumerate(read(".github", "workflows", n).splitlines(), 1):
                m = re.match(r"\s*(?:-\s*)?uses:\s*(\S+)(.*)", line)
                if not m or m.group(1).startswith("./"):
                    continue
                if not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", m.group(1)) \
                        or not re.search(r"#\s*v\d", m.group(2)):
                    bad.append(f"{n}:{i}: {line.strip()}")
        self.assertEqual(bad, [])

    def test_foreign_code_pinned(self):
        """Чужой код в образах — только по отпечатку (1.22.0): FROM — с @sha256, исходники — git fetch по хешу
        коммита из 40 знаков с проверкой rev-parse, без clone по названию версии (его можно переставить на
        другой код). Версии AmneziaWG в образе панели и в образе своего сервера — одни и те же."""
        args = {}
        for name in ("Dockerfile", os.path.join("awg-server", "Dockerfile")):
            text = read(name)
            a = dict(re.findall(r"^ARG (\w+)=(\S+)", text, re.M))
            args[name] = a
            for line in re.findall(r"^FROM (\S+)", text, re.M):
                ref = a.get(line[2:-1], "") if line.startswith("${") else line
                self.assertRegex(ref, r"@sha256:[0-9a-f]{64}$", f"{name}: FROM {line}")
            self.assertNotIn("git clone", text, name)
            for sha_arg in re.findall(r'git fetch -q --depth 1 origin "\$\{(\w+)\}"', text):
                self.assertRegex(a.get(sha_arg, ""), r"^[0-9a-f]{40}$", f"{name}: {sha_arg}")
                self.assertIn(f'test "$(git rev-parse HEAD)" = "${{{sha_arg}}}"', text, f"{name}: {sha_arg}")
            self.assertEqual(text.count("git fetch"), len(re.findall(r'git fetch -q --depth 1 origin "\$\{\w+_SHA\}"', text)))
        panel, server = args["Dockerfile"], args[os.path.join("awg-server", "Dockerfile")]
        for k in ("AWG_GO_REF", "AWG_GO_SHA", "AWG_TOOLS_REF", "AWG_TOOLS_SHA"):
            self.assertEqual(panel[k], server[k], k)

    def test_static_loads_nothing_from_other_hosts(self):
        """Браузер не обращается к сторонним хостам: страницы, стили и скрипты панели ничего не грузят с
        чужих адресов (ссылки для перехода по нажатию и адреса в комментариях — можно)."""
        static = os.path.join(ROOT, "app", "static")
        loads = [
            re.compile(r"<(?:script|img|iframe|audio|video|source|embed)[^>]*\ssrc=[\"']?(?:https?:)?//", re.I),
            re.compile(r"<link[^>]*\shref=[\"']?(?:https?:)?//", re.I),
            re.compile(r"url\(\s*[\"']?(?:https?:)?//", re.I),
            re.compile(r"@import\s", re.I),
            re.compile(r"\b(?:fetch|EventSource|WebSocket|importScripts|import)\s*\(\s*[`\"'](?:https?|wss?):", re.I),
            re.compile(r"\bfrom\s+[\"'](?:https?:)?//", re.I),
            re.compile(r"\.src\s*=\s*[`\"'](?:https?:)?//", re.I),
        ]
        found = []
        for d, _, names in os.walk(static):
            for n in names:
                if not n.endswith((".html", ".js", ".css")):
                    continue
                with open(os.path.join(d, n), encoding="utf-8") as f:
                    text = f.read()
                for rx in loads:
                    for m in rx.finditer(text):
                        found.append(f"{n}: {m.group(0)[:80]}")
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
