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

from app import dnsaddr, lists, srcaddr, traffic  # noqa: E402
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
                # правило с балансировкой (1.24.0): выход в группе и резерв группы — тоже ссылки
                routing.put_routing(R({"default": out, "rules": [
                    {"lists": ["ru"], "outbound": out},
                    {"lists": ["ir"], "outbound": "direct", "balance": [x, y], "balance_fb": out},
                    # куда трафик правила, когда исчерпан его месячный лимит (1.24.0)
                    {"lists": ["cn"], "outbound": "direct", "quota_gb": 5, "quota_action": out}]}))
                clients.put_client(R({"outbound": out, "rules_mode": "custom",
                                   "rules": [{"lists": ["cn"], "outbound": out}]}), pk)
                panel.store.mutate(lambda st: st["settings"].setdefault("telegram", {}).update(via=out))
                # каждое место из outbound_refs: умолчание, правило, правило с балансировкой, правило с лимитом, резерв
                # и квота Y, Telegram, клиент, его правило
                self.assertEqual(len(Store.outbound_refs(panel.store.snapshot(), out)), 9)
                exits.del_upstream(R({"replace": "direct"}), x)
                st = panel.store.snapshot()
                self.assertNotIn(f'"{out}"', json.dumps(st))
                self.assertEqual({k: st["routing"]["rules"][1].get(k) for k in ("balance", "outbound", "balance_fb")},
                                 {"balance": [y], "outbound": "up:" + y, "balance_fb": "direct"})
                self.assertEqual(st["routing"]["rules"][2]["quota_action"], "direct")
                # копия после удаления восстанавливается (до исправления: «Ошибка в копии: routing.rules»)
                backup.clean_backup_state(backup.make_backup()["state"])
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
               "settings.out_hosts", "settings.out_main",   # исходящие адреса — этого сервера (1.25.0)
               "settings.own_src",                      # с какого адреса выходит сам сервер — тоже
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
                                                                 extra_hosts=["198.51.100.20"],
                                                                 out_hosts=["198.51.100.30"], own_src="198.51.100.30"))
                # «Напрямую — второй адрес» у правила клиента и подключение выхода с него (1.25.0)
                exits.edit_upstream(R({"bind": "198.51.100.30"}), x)
                clients.put_client(R({"outbound": "up:" + x, "rules_mode": "custom", "note": "n",
                                      "rules": [{"lists": ["ru"], "outbound": "direct@198.51.100.30"}]}), pk)
                clients.put_client_host(R({"host": "198.51.100.20"}), pk)
                panel.store.mutate(lambda s: s["routing"].update(balance={"on": True, "skip": [x]}, strict=True))
                # правило с балансировкой (1.24.0) — его поля тоже в копии (без put_routing: тот удалил бы списки
                # других правил, а их ждут следующие тесты)
                panel.store.mutate(lambda s: s["routing"]["rules"].append(
                    {"id": "r_baltest", "lists": ["ru"], "outbound": "up:" + x, "enabled": True, "comment": "",
                     "balance": [x], "balance_fb": "direct"}))
                # свой DNS правила с DoT и запасной DNS для «Напрямую» (1.25.0)
                dl = next(l["id"] for l in panel.store.snapshot()["lists"] if l["kind"] == "domains")
                panel.store.mutate(lambda s: s["routing"]["rules"].append(
                    {"id": "r_dnstest", "lists": [dl], "outbound": "direct", "enabled": True, "comment": "",
                     "dns": ["tls://dns.google", "77.88.8.8"]}))
                panel.store.mutate(lambda s: s["settings"].update(fallback_dns=["https://dns.google/dns-query"],
                                                                 fallback_dns_on=True))
                st = panel.store.snapshot(texts=True)          # так состояние выглядит в резервной копии
                new = backup.clean_backup_state(st)
            finally:
                panel.store.mutate(lambda s: s.update(clients=st0["clients"], limits=st0["limits"], routing=st0["routing"],
                                                     shares=st0["shares"], cps=st0["cps"], chost=st0.get("chost", {})))
                panel.store.mutate(lambda s: [s["settings"].pop(k, None) for k in ("panel_dns", "panel_dns_enc", "shaping",
                                                                                   "extra_hosts", "out_hosts", "own_src",
                                                                                   "fallback_dns", "fallback_dns_on")])
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
        self.assertIn("outbound_src", json.dumps(st))       # в копии адрес — рядом с "direct", как поймёт 1.24.0
        self.assertIn('"dns_all"', json.dumps(st))          # и DoT своего DNS — рядом с обычными адресами
        lost = {norm(p) for p in walk(st, dnsaddr.to_disk(srcaddr.to_disk(new)))} - self.DROPPED
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


class FunctionImportsTest(unittest.TestCase):
    """Импорт внутри функции (`from .notify import TGREQ`, `from . import webfront`) проверяется, только когда функция
    выполняется, а широкий `except` вызывающего прячет ошибку: после деления engine.py на пакет (1.21.0) так молча
    сломались «Проверка маршрута» (до 1.25.0) и версия модуля ядра без файла версии (проверка 1.25.0, А4). Здесь каждый
    такой импорт в app/ сверяется с файлами без выполнения кода: модуль есть, имя в нём определено."""

    APP = os.path.join(ROOT, "app")

    @staticmethod
    def defined(path: str) -> set:
        import ast
        with open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        names = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                for t in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    names |= {n.id for n in ast.walk(t) if isinstance(n, ast.Name)}
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                names |= {(a.asname or a.name).split(".")[0] for a in node.names}
        return names

    def module(self, parts: list) -> str | None:
        base = os.path.join(ROOT, *parts)
        for p in (base + ".py", os.path.join(base, "__init__.py")):
            if os.path.exists(p):
                return p
        return None

    def test_imports_inside_functions(self):
        import ast
        import importlib.util
        bad, seen = [], 0
        for d, dirs, names in os.walk(self.APP):
            dirs[:] = [x for x in dirs if x != "__pycache__"]
            for n in names:
                if not n.endswith(".py"):
                    continue
                path = os.path.join(d, n)
                rel = os.path.relpath(path, ROOT)[:-3].split(os.sep)
                pkg = rel[:-1]                          # пакет модуля (у __init__.py — сам пакет)
                with open(path, encoding="utf-8") as f:
                    tree = ast.parse(f.read())
                for fn in ast.walk(tree):
                    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    for node in ast.walk(fn):
                        if isinstance(node, ast.Import):
                            seen += 1
                            for a in node.names:
                                if a.name.split(".")[0] != "app" and importlib.util.find_spec(a.name.split(".")[0]) is None:
                                    bad.append(f"{path}: import {a.name}")
                        elif isinstance(node, ast.ImportFrom):
                            seen += 1
                            if not node.level:
                                if node.module.split(".")[0] != "app":
                                    continue            # стандартная библиотека: её имена здесь не сверяем
                                target = node.module.split(".")
                            else:
                                target = (pkg[:len(pkg) - node.level + 1] if node.level > 1 else pkg) + \
                                    (node.module.split(".") if node.module else [])
                            mod = self.module(target)
                            if mod is None:
                                bad.append(f"{path}: {'.' * node.level}{node.module or ''} — нет модуля {'.'.join(target)}")
                                continue
                            have = self.defined(mod)
                            for a in node.names:
                                if a.name not in have and self.module(target + [a.name]) is None:
                                    bad.append(f"{path}: {'.' * node.level}{node.module or ''} import {a.name} — "
                                               f"нет в {'.'.join(target)}")
        self.assertGreater(seen, 10)
        self.assertEqual(bad, [])


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

    def test_tests_run_on_the_image_python(self):
        """Python в образе панели (FROM python:3.X-alpine) и python-version у setup-python в release.yml и net-tests.yml —
        одна версия: PR Dependabot меняет только Dockerfile (#45), и тесты шли бы на одной версии, а панель у людей — на
        другой."""
        image = re.search(r"^FROM python:(\d+\.\d+)-alpine@", read("Dockerfile"), re.M)
        self.assertIsNotNone(image)
        for n in ("release.yml", "net-tests.yml"):
            got = re.findall(r'python-version:\s*"?([\d.]+)"?', read(".github", "workflows", n))
            self.assertTrue(got, n)
            self.assertEqual(set(got), {image.group(1)}, n)

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


    def test_regex_anchors(self):
        """Проверка ввода регулярным выражением — до конца строки \\Z (или fullmatch), а не $: с match знак $ пропускает
        перевод строки в конце, и «ab\\n» из копии попадал в имена наборов nftables (П14 полной проверки 1.25.0)."""
        found = []
        call = re.compile(r"re\.(?:compile|match|search|fullmatch)\(\s*r?(?:\"([^\"]*)\"|'([^']*)')\s*[,)]")
        for d, _, names in os.walk(os.path.join(ROOT, "app")):
            for n in names:
                if not n.endswith(".py"):
                    continue
                with open(os.path.join(d, n), encoding="utf-8") as f:
                    for i, line in enumerate(f, 1):
                        for m in call.finditer(line):
                            rx = m.group(1) or m.group(2) or ""
                            if re.search(r"(?<!\\)\$", rx):
                                found.append(f"{n}:{i}: {rx[:60]}")
        self.assertEqual(found, [])

    def test_list_id_from_backup_without_newline(self):
        from app import checks
        from app.web import HTTPError
        st = {"lists": []}
        for bad in ("ab\n", "ab\r\n", "AB"):
            with self.assertRaises(HTTPError, msg=repr(bad)):
                checks.list_id(st, bad, {"kind": "domains", "source": ""})
        self.assertEqual(checks.list_id(st, "ab", {"kind": "domains", "source": ""}), "ab")


    def test_helpers_compiled_in_the_image(self):
        """Программы, которые панель запускает отдельным процессом (…/<имя>.py в app/), — в строке импорта Dockerfile:
        python:alpine без .pyc, и каждый запуск компилировал бы их заново (app/ctflush.py в 1.25.0 там не было)."""
        started = set()
        for d, _, names in os.walk(os.path.join(ROOT, "app")):
            for n in names:
                if n.endswith(".py"):
                    with open(os.path.join(d, n), encoding="utf-8") as f:
                        started |= set(re.findall(r'^.*os\.path\.join\(.*"([a-z_]+)\.py"\)', f.read(), re.M))
        with open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8") as f:
            line = next(ln for ln in f if 'python3 -c "import app.main' in ln)
        self.assertTrue(started)
        for m in sorted(started):
            self.assertIn(f"app.{m}", line, m)



class ReadmeFactsTest(unittest.TestCase):
    """README ×4 (полная проверка 1.25.0, П7, П36, D5): «Фаервол» называет UDP-порт AmneziaWG (без него на хостинге со
    своим фаерволом клиенты не подключатся), есть возврат на прошлую версию и раздел «если что-то не работает»;
    шапка install.sh тоже называет AWGR_SRC_URL; release.yml не соберёт черновик без даты выпуска в CHANGELOG."""
    FILES = {"README.md": ("> **Firewall:**", "### If something doesn't work"),
             "README.ru.md": ("> **Фаервол:**", "### Если что-то не работает"),
             "README.zh.md": ("> **防火墙：**", "### 如果出了问题"),
             "README.fa.md": ("> **فایروال:**", "### اگر چیزی کار نکرد")}

    def test_readmes(self):
        for name, (fw, trouble) in self.FILES.items():
            text = read(name)
            line = next(x for x in text.splitlines() if x.startswith(fw))
            self.assertIn("UDP", line, name)
            self.assertIn(trouble, text, name)
            self.assertIn("AWGR_SRC_URL=https://github.com/r-slashslash/AWG-Router/releases/download/vX.Y.Z/", text, name)
            self.assertIn("100.100.100.200", text, name)
        head = read("install.sh")[:3000]
        self.assertIn("AWGR_SRC_URL=", head)

    def test_changelog_date_checked(self):
        rel = read(".github", "workflows", "release.yml")
        self.assertIn('grep -qE "^## ${v#v} — [0-9]{4}-[0-9]{2}-[0-9]{2}', rel)
        from app.version import VERSION
        self.assertRegex(read("CHANGELOG.md"), rf"\n## {re.escape(VERSION)} — (\d{{4}}-\d{{2}}-\d{{2}}|unreleased)\n")


if __name__ == "__main__":
    unittest.main()
