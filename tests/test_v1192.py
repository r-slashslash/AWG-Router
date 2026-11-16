"""1.19.2: метка сессии через HMAC и вкладка из адреса только из своих ключей.

python3 -m unittest discover tests
"""
import os
import re
import sys
import tempfile
import unittest

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.api import auth  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


class SessionTagTest(unittest.TestCase):
    def test_tag_is_keyed(self):
        # метка зависит от ключа панели: с другим SECRET та же строка даёт другую метку
        saved = auth.SECRET
        try:
            auth.SECRET = b"x" * 64
            other = auth._tag("same material")
        finally:
            auth.SECRET = saved
        self.assertNotEqual(auth._tag("same material"), other)
        self.assertEqual(len(auth.PW_TAG), 8)

    def test_session_roundtrip(self):
        s = auth.make_session()
        self.assertTrue(auth.check_session(s))
        exp, tag, sig = s.split(".")
        self.assertEqual(tag, auth.sec_tag())
        self.assertFalse(auth.check_session(f"{exp}.{'0' * 8}.{sig}"))

    def test_no_bare_password_hash(self):
        with open(os.path.join(ROOT, "app", "api", "auth.py"), encoding="utf-8") as f:
            src = f.read()
        self.assertNotRegex(src, r"hashlib\.sha256\([^)]*PASSWORD")
        self.assertNotRegex(src, r"hashlib\.sha256\(f\"\{material\}")


class TabFromHashTest(unittest.TestCase):
    def test_render_uses_map(self):
        with open(os.path.join(ROOT, "app", "static", "app.js"), encoding="utf-8") as f:
            js = f.read()
        body = js[js.index("function render("):js.index("function banners(")]
        # #toString, #constructor, #__proto__ в адресе не должны доставать свойства Object.prototype
        self.assertNotIn("views[tab]", body)
        self.assertNotIn("bind[tab]", body)
        self.assertIn("const views = new Map(", body)
        self.assertTrue(re.search(r"if \(!views\.has\(tab\)\) tab = \"overview\"", body))

if __name__ == "__main__":
    unittest.main()
