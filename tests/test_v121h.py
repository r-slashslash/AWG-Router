"""1.21.0, вторая проверка (2026-11-16): каждый адрес API — только после входа; без входа открыты
только страницы /s/… (личные ссылки клиентов).

python3 -m unittest discover tests
"""
import http.client
import os
import sys
import tempfile
import threading
import unittest

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from app import api, panel  # noqa: E402,F401  — импорт app.api регистрирует все адреса


class AuthRoutesTest(unittest.TestCase):
    def test_only_share_pages_are_public(self):
        public = sorted(rx.pattern for _, rx, fn in panel.app.routes if fn in panel.app.public)
        self.assertEqual(public, ["^/s/(?P<token>[^/]+)$", "^/s/api/(?P<token>[^/]+)$"])

    def test_every_route_without_cookie_is_401(self):
        srv = panel.app.serve("127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        seen = 0
        for method, rx, fn in panel.app.routes:
            if fn in panel.app.public or rx.pattern.endswith("/api/login$"):
                continue
            path = rx.pattern.strip("^$").replace("(?P<pk>.+)", "x").replace("(?P<lid>[^/]+)", "x")
            path = __import__("re").sub(r"\(\?P<\w+>[^)]*\)", "x", path).replace("\\", "")
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
            c.request(method, path, body=b"{}" if method != "GET" else None,
                      headers={"Content-Type": "application/json"})
            r = c.getresponse()
            r.read()
            c.close()
            self.assertEqual(r.status, 401, f"{method} {path}")
            seen += 1
        self.assertGreater(seen, 40)


if __name__ == "__main__":
    unittest.main()
