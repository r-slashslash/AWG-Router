import base64
import unittest

from app.proxy_auth import authenticate, password_record, public_address


class ProxyCredentialsTest(unittest.TestCase):
    def test_credentials_are_hashed_and_independent(self):
        password = "a-strong-test-password"
        a, b = password_record(password), password_record(password)
        self.assertNotIn(password, str(a))
        self.assertNotEqual(a["salt"], b["salt"])
        header = "Basic " + base64.b64encode(("anton:" + password).encode()).decode()
        self.assertTrue(authenticate(header, "anton", a))
        self.assertFalse(authenticate(header, "other", a))
        self.assertFalse(authenticate(header, "anton", password_record("a-different-password")))

    def test_invalid_headers_are_rejected(self):
        record = password_record("a-strong-test-password")
        for header in ("", "Bearer abc", "Basic !", "Basic " + "x" * 5000):
            self.assertFalse(authenticate(header, "anton", record))

    def test_private_and_mapped_addresses_are_rejected(self):
        for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "invalid"):
            self.assertFalse(public_address(ip), ip)
        self.assertTrue(public_address("1.1.1.1"))


if __name__ == "__main__":
    unittest.main()
