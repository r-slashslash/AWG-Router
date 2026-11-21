"""1.23.1: оптимизация — страница не копит заменённые строки клиентов, проверка маршрута не держит списки доменов
в памяти панели."""
import os
import random
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())

from app import domains  # noqa: E402


class RowClickTest(unittest.TestCase):
    """Нажатие на строку клиента — одна общая функция. Стрелка внутри patchClients держала всю его область (прежние
    строки и состояние), и каждая заменённая опросом строка оставалась в памяти страницы навсегда: на тысяче клиентов
    ~20 МБ в минуту (замер 2026-11-21, Chromium)."""

    def test_rows_share_one_handler(self):
        from tests import panel_js
        js = panel_js.source()
        body = js[js.index("function patchClients("):js.index("function viewClients(")]
        self.assertIn("tr.onclick = clientRowClick", body)
        self.assertNotRegex(js, r"tr\.onclick\s*=\s*\(")          # ни одной стрелки-обработчика строки
        self.assertRegex(js, r"function clientRowClick\(e\) \{ editClient\(e\.currentTarget\.dataset\.pk\); \}")
        # обработчик не вкладывается в функцию: иначе он снова держал бы её область
        self.assertTrue(re.search(r"(?m)^function clientRowClick\(", js))


class DomainMatcherTest(unittest.TestCase):
    """Проверка маршрута читает файл списка, а не держит множество его доменов (300 000 — ~36 МБ в панели)."""

    def setUp(self):
        self.lid = "t" + str(random.randrange(10**9))
        domains.save(self.lid, ["example.com", "a.b.example.org", "googlevideo.com", "x.y.z.net", "com.ua"])
        self.addCleanup(domains.delete, self.lid)

    def test_same_answer_as_the_set(self):
        names = ["example.com", "www.example.com", "a.example.com.", "EXAMPLE.COM", "b.example.org",
                 "c.a.b.example.org", "rr1---sn.googlevideo.com", "z.net", "q.x.y.z.net", "shop.com.ua", "ua",
                 "", ".", "example.com.evil", "x" * 300, "a..example.com"]
        want = set(domains.load(self.lid))
        m = domains.Matcher()
        for n in names:
            with self.subTest(name=n):
                self.assertEqual(m.match(self.lid, n), domains.matches(n, want))

    def test_nearest_parent_wins(self):
        domains.save(self.lid, ["example.com", "www.example.com"])
        self.assertEqual(domains.Matcher().match(self.lid, "a.www.example.com"), "www.example.com")
        domains.save(self.lid, ["www.example.com", "example.com"])
        self.assertEqual(domains.Matcher().match(self.lid, "a.www.example.com"), "www.example.com")

    def test_missing_list(self):
        self.assertIsNone(domains.Matcher().match("no-such-list", "example.com"))

    def test_nothing_kept(self):
        m = domains.Matcher()
        m.match(self.lid, "example.com")
        self.assertEqual([k for k in vars(m) if not k.startswith("__")], [])     # ни кэша, ни множеств


if __name__ == "__main__":
    unittest.main()
