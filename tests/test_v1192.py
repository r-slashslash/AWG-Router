"""1.19.2: метка сессии через HMAC и вкладка из адреса только из своих ключей.

python3 -m unittest discover tests
"""
import hashlib
import hmac
import os
import re
import sys
import tempfile
import unittest

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import main  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


class SessionTagTest(unittest.TestCase):
    def test_tag_is_keyed(self):
        # в cookie не должен лежать кусок голого SHA-256 от пароля: по нему можно перебирать пароли
        plain = hashlib.sha256(main.PASSWORD.encode()).hexdigest()[:8]
        self.assertNotEqual(main.PW_TAG, plain)
        self.assertEqual(main.PW_TAG,
                         hmac.new(main.SECRET, main.PASSWORD.encode(), hashlib.sha256).hexdigest()[:8])

    def test_session_roundtrip(self):
        s = main.make_session()
        self.assertTrue(main.check_session(s))
        exp, tag, sig = s.split(".")
        self.assertEqual(tag, main.sec_tag())
        self.assertFalse(main.check_session(f"{exp}.{'0' * 8}.{sig}"))

    def test_no_bare_password_hash(self):
        with open(os.path.join(ROOT, "app", "main.py"), encoding="utf-8") as f:
            src = f.read()
        self.assertNotRegex(src, r"hashlib\.sha256\([^)]*PASSWORD")
        self.assertNotRegex(src, r"hashlib\.sha256\(f\"\{material\}")


class TabFromHashTest(unittest.TestCase):
    def test_render_uses_own_keys(self):
        with open(os.path.join(ROOT, "app", "static", "app.js"), encoding="utf-8") as f:
            js = f.read()
        body = js[js.index("function render("):js.index("function banners(")]
        # #toString, #constructor, #__proto__ в адресе не должны доставать свойства Object.prototype
        self.assertNotIn("views[tab] ||", body)
        self.assertNotIn("bind[tab] &&", body)
        self.assertIn("hasOwnProperty.call", body)
        self.assertTrue(re.search(r"if \(!own\(views, tab\)\) tab = \"overview\"", body))


if __name__ == "__main__":
    unittest.main()
