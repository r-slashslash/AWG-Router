"""tools/upstream.py: еженедельная проверка новых версий чужих программ в образах (без сети)."""
import importlib.util
import os
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("upstream", os.path.join(ROOT, "tools", "upstream.py"))
upstream = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(upstream)

A = "a" * 40
B = "b" * 40
C = "c" * 40
LS = (f"{A}\trefs/tags/2.19.3\n{B}\trefs/tags/2.20.0\n{C}\trefs/tags/snapshot\n"
      f"{A}\trefs/tags/2.9.3\n{C}\trefs/tags/2.21.0-rc1\n")


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


class UpstreamTest(unittest.TestCase):
    def test_programs_match_dockerfile(self):
        """Каждая программа списка есть в Dockerfile: её ARG и адрес репозитория, откуда идёт сборка
        (у lego — образ); ARG, по которому собирают чужой код по хешу, все в списке."""
        text = read("Dockerfile")
        args = upstream.pinned(text)
        for name, url, ref, sha in upstream.PROGRAMS:
            self.assertIn(ref, args, name)
            if sha:
                self.assertRegex(args[sha], r"^[0-9a-f]{40}$", name)
                self.assertIn(f"remote add origin {url} ", text, name)
            self.assertIsNotNone(upstream.key(upstream.version_of(args[ref])), name)
        listed = {s for *_, s in upstream.PROGRAMS if s}
        self.assertEqual({a for a in args if a.endswith("_SHA")}, listed)

    def test_version_of(self):
        self.assertEqual(upstream.version_of("v3.1.20260828"), "v3.1.20260828")
        self.assertEqual(upstream.version_of("goacme/lego:v5.6.0@sha256:" + "0" * 64), "v5.6.0")

    def test_tags_prefers_peeled_commit(self):
        """У тега с подписью коммит — из строки ^{}, а не хеш самого тега."""
        out = f"{A}\trefs/tags/v5.6.0\n{B}\trefs/tags/v5.6.0^{{}}\n{C}\trefs/heads/main\n"
        self.assertEqual(upstream.tags(out), {"v5.6.0": B})

    def test_numbers_not_text(self):
        """2.9.3 старше 2.19.3 (по числам, не по буквам); snapshot и -rc — не выпуски."""
        r = upstream.compare("x", "2.19.3", A, upstream.tags(LS))
        self.assertEqual(r, {"newer": ("2.20.0", B)})

    def test_skipped_version(self):
        """Сознательно не взятая hev 2.20.0 не напоминает о себе; более новая — напоминает."""
        remote = upstream.tags(LS)
        self.assertEqual(upstream.compare("hev-socks5-tunnel", "2.19.3", A, remote), {})
        remote["2.20.1"] = C
        self.assertEqual(upstream.compare("hev-socks5-tunnel", "2.19.3", A, remote), {"newer": ("2.20.1", C)})

    def test_moved_tag(self):
        r = upstream.compare("x", "2.20.0", A, upstream.tags(LS))
        self.assertEqual(r, {"moved": B})

    def test_report(self):
        self.assertEqual(upstream.report([("x", "1.0", {})]), ("", ""))
        title, body = upstream.report([("hev-socks5-tunnel", "2.19.3", {"newer": ("2.20.1", C)}),
                                       ("amneziawg-go", "v3.1.1", {"moved": B})])
        self.assertEqual(title, "New upstream versions: hev-socks5-tunnel 2.20.1, amneziawg-go tag moved")
        self.assertIn(f"| hev-socks5-tunnel | 2.19.3 | 2.20.1 | `{C}` |", body)
        self.assertIn("domains_socks_e2e", body)
        self.assertIn(f"amneziawg-go v3.1.1: now `{B}`", body)

    def test_workflow_title_prefix(self):
        """Workflow ищет открытое issue по тому же началу заголовка, что пишет скрипт."""
        self.assertIn(f'startswith("{upstream.TITLE}")', read(".github", "workflows", "upstream.yml"))

    def test_main_files(self):
        """--out: title и body.md — когда есть что сказать; incomplete — когда кто-то не ответил
        (тогда workflow не закрывает issue); никто не ответил — код 1."""
        def ls(url):
            if "lego" in url:
                raise OSError("no network")
            return f"{B}\trefs/tags/v99.0.0\n"

        with tempfile.TemporaryDirectory() as d, mock.patch.object(upstream, "ls_remote", ls), \
                mock.patch("builtins.print"):
            self.assertEqual(upstream.main(["--out", d]), 0)
            self.assertEqual(sorted(os.listdir(d)), ["body.md", "incomplete", "title"])
        with tempfile.TemporaryDirectory() as d, mock.patch("builtins.print"), \
                mock.patch.object(upstream, "ls_remote", side_effect=OSError("down")):
            self.assertEqual(upstream.main(["--out", d]), 1)
            self.assertEqual(os.listdir(d), ["incomplete"])


if __name__ == "__main__":
    unittest.main()
