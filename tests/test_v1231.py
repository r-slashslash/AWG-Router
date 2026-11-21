"""1.23.1: оптимизация — страница не копит заменённые строки клиентов, проверка маршрута не держит списки доменов
в памяти панели, файлы панели — в кэше браузера до следующей их смены (отпечаток статики в адресах)."""
import http.client
import os
import random
import re
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("PANEL_PASSWORD", "test-password")

from app import domains, web  # noqa: E402


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


class StaticTagTest(unittest.TestCase):
    """Файлы страниц — по адресам с отпечатком статики: браузер берёт их из кэша без перепроверки (по связи с задержкой
    300 мс повторное открытие — 1,7 → 1,35 с, 16 запросов → 3). Другой отпечаток — как без него: no-cache."""

    @classmethod
    def setUpClass(cls):
        from app import api, panel
        assert api.ROUTES                   # адреса API, и личная страница /s/…, — в panel.app
        cls.panel = panel
        cls.srv = panel.app.serve("127.0.0.1", 0)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=5)
        try:
            c.request("GET", path)
            r = c.getresponse()
            return r.status, r.getheader("Cache-Control"), r.read()
        finally:
            c.close()

    def test_pages_refer_to_tagged_files(self):
        tag = self.panel.app.static_tag()
        self.assertRegex(tag, r"^[0-9a-f]{12}$")
        st, cc, html = self.get(self.panel.BASE + "/")
        self.assertEqual((st, cc), (200, "no-store"))           # сама страница — всегда свежая
        refs = re.findall(rb'(?:src|href)="(static/[^"]+)"', html)
        self.assertGreater(len(refs), 10)
        for r in refs:
            if r == b"static/manifest.webmanifest":
                continue
            self.assertTrue(r.startswith(b"static/v-" + tag.encode() + b"/"), r)
        self.assertIn(b'href="static/manifest.webmanifest"', html)
        st, _, html = self.get("/s/" + "x" * 24)                 # личная страница (неверный ключ — та же страница)
        self.assertEqual(st, 404)
        refs = re.findall(rb'(?:src|href)="(/s/assets/[^"]+)"', html)
        self.assertTrue(refs)
        for r in refs:
            self.assertTrue(r.startswith(b"/s/assets/v-" + tag.encode() + b"/"), r)

    def test_cache_headers(self):
        tag, base = self.panel.app.static_tag(), self.panel.BASE
        st, cc, body = self.get(f"{base}/static/v-{tag}/js/core.js")
        self.assertEqual((st, cc), (200, web.IMMUTABLE))
        self.assertEqual(self.get(f"{base}/static/js/core.js")[:2], (200, "no-cache"))
        old = self.get(f"{base}/static/v-000000000000/js/core.js")          # страница открыта до обновления
        self.assertEqual(old[:2], (200, "no-cache"))
        self.assertEqual(old[2], body)
        self.assertEqual(self.get(f"{base}/static/v-{tag}/fonts/GolosText.woff")[:2], (200, web.IMMUTABLE))  # из app.css
        self.assertEqual(self.get(f"/s/assets/v-{tag}/share.js")[:2], (200, web.IMMUTABLE))
        self.assertEqual(self.get(f"/s/assets/v-{tag}/index.html")[0], 404)       # только app.public_files

    def test_no_way_out_of_static(self):
        tag, base = self.panel.app.static_tag(), self.panel.BASE
        for path in (f"{base}/static/v-{tag}/../../config.py", f"/s/assets/v-{tag}/../share.js",
                     f"{base}/static/v-{tag}/%00", f"{base}/static/v-{tag}/"):
            self.assertEqual(self.get(path)[0], 404, path)

    def test_tag_follows_files(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "a.js"), "w") as f:
            f.write("1")
        app = web.App()
        app.static = ("/static", d)
        t1 = app.static_tag()
        self.assertEqual(app.versioned(b'<script src="static/a.js"></script>'),
                         b'<script src="static/v-' + t1.encode() + b'/a.js"></script>')
        with open(os.path.join(d, "a.js"), "w") as f:
            f.write("22")                                      # обновление: другой размер
        self.assertEqual(app.static_tag(), t1)                 # до STATIC_TAG_TTL — прежний
        app._tag = None
        self.assertNotEqual(app.static_tag(), t1)
        self.assertEqual(web.App().versioned(b'src="static/a.js"'), b'src="static/a.js"')   # без статики — как есть


if __name__ == "__main__":
    unittest.main()
