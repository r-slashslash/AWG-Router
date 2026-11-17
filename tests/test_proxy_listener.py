import base64
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from app import proxy_auth, proxy_listener


@unittest.skipUnless(shutil.which("openssl"), "openssl required")
class ProxyListenerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert = cls.tmp.name + "/cert.pem"
        cls.key = cls.tmp.name + "/key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-keyout", cls.key, "-out", cls.cert],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(cls.cert, cls.key)
        cls.record = proxy_auth.password_record("long-test-password")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.opened = []
        def opener(host, port):
            self.opened.append((host, port))
            local, remote = socket.socketpair()
            def echo():
                with remote:
                    data = remote.recv(1024)
                    remote.sendall(data)
            threading.Thread(target=echo, daemon=True).start()
            return local
        self.server = proxy_listener.create(("127.0.0.1", 0), lambda: self.context,
                                            lambda: {"username": "u", "password": self.record}, opener)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        with proxy_listener._fail_lock:
            proxy_listener._failures.clear()

    def client(self):
        ctx = ssl._create_unverified_context()
        return ctx.wrap_socket(socket.create_connection(self.server.server_address), server_hostname="localhost")

    def test_authenticated_tunnel_relay(self):
        token = base64.b64encode(b"u:long-test-password")
        with self.client() as client:
            client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic " + token + b"\r\n\r\n")
            self.assertIn(b"200 Connection Established", client.recv(4096))
            client.sendall(b"hello")
            self.assertEqual(client.recv(5), b"hello")
        self.assertEqual(self.opened, [("example.com", 443)])

    def test_relay_accounts_both_directions(self):
        seen = [0, 0]
        lock = threading.Lock()
        def account(uid, direction, count):
            with lock:
                seen[direction] += count
            return True
        self.server.account = account
        token = base64.b64encode(b"u:long-test-password")
        with self.client() as client:
            client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic " + token + b"\r\n\r\n")
            self.assertIn(b"200 Connection Established", client.recv(4096))
            client.sendall(b"hello")
            self.assertEqual(client.recv(5), b"hello")
            for _ in range(100):
                with lock:
                    if seen == [5, 5]:
                        break
                time.sleep(.01)
        self.assertEqual(seen, [5, 5])

    def test_running_tunnel_closes_when_quota_is_hit(self):
        used = [0]
        def account(uid, direction, count):
            used[0] += count
            return used[0] < 5
        self.server.account = account
        token = base64.b64encode(b"u:long-test-password")
        with self.client() as client:
            client.settimeout(3)
            client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic " + token + b"\r\n\r\n")
            self.assertIn(b"200 Connection Established", client.recv(4096))
            client.sendall(b"hello")
            try:
                self.assertEqual(client.recv(5), b"")
            except (ConnectionResetError, ssl.SSLError):
                pass
        self.assertEqual(used[0], 5)

    def test_bad_credentials_do_not_open_outbound(self):
        with self.client() as client:
            client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dTpiYWQ=\r\n\r\n")
            self.assertIn(b"407 Proxy Authentication Required", client.recv(4096))
        self.assertEqual(self.opened, [])

    def test_http_request_body_is_bounded_and_proxy_auth_is_removed(self):
        observed = []
        def opener(host, port):
            local, remote = socket.socketpair()
            def receive():
                with remote:
                    data = b""
                    while b"\r\n\r\n" not in data:
                        data += remote.recv(4096)
                    head, body = data.split(b"\r\n\r\n", 1)
                    while len(body) < 5:
                        body += remote.recv(5 - len(body))
                    observed.append((host, port, head, body))
                    remote.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            threading.Thread(target=receive, daemon=True).start()
            return local
        self.server.opener = opener
        token = base64.b64encode(b"u:long-test-password")
        with self.client() as client:
            client.sendall(b"POST http://example.com/api HTTP/1.1\r\nContent-Length: 5\r\n"
                           b"Proxy-Authorization: Basic " + token + b"\r\n\r\nhello")
            result = b""
            while True:
                part = client.recv(4096)
                if not part:
                    break
                result += part
            self.assertIn(b"200 OK", result)
        self.assertEqual(observed[0][0:2], ("example.com", 80))
        self.assertNotIn(b"proxy-authorization", observed[0][2].lower())
        self.assertEqual(observed[0][3], b"hello")

    def test_repeated_failed_logins_are_temporarily_blocked(self):
        ip = "203.0.113.99"
        with patch("app.proxy_listener.time.monotonic", return_value=1000):
            for _ in range(proxy_listener.FAIL_LIMIT):
                proxy_listener._failed(ip)
            self.assertTrue(proxy_listener._blocked(ip))
            self.assertFalse(proxy_listener._blocked("203.0.113.100"))
        with patch("app.proxy_listener.time.monotonic", return_value=1601):
            self.assertFalse(proxy_listener._blocked(ip))

    def test_parallel_attempts_are_limited_before_password_hashing(self):
        ip = "203.0.113.98"
        try:
            self.assertTrue(all(proxy_listener._begin_auth(ip) for _ in range(proxy_listener.FAIL_LIMIT)))
            self.assertFalse(proxy_listener._begin_auth(ip))
            for _ in range(proxy_listener.FAIL_LIMIT):
                proxy_listener._end_auth(ip, False)
            self.assertFalse(proxy_listener._begin_auth(ip))
        finally:
            with proxy_listener._fail_lock:
                proxy_listener._inflight.pop(ip, None)
                proxy_listener._failures.pop(ip, None)

    def test_disabled_client_is_rejected(self):
        self.server.credentials = lambda: None
        token = base64.b64encode(b"u:long-test-password")
        with self.client() as client:
            client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic " + token + b"\r\n\r\n")
            self.assertIn(b"407 Proxy Authentication Required", client.recv(4096))
        self.assertEqual(self.opened, [])

    def test_exit_failure_returns_502(self):
        def fail(host, port):
            raise OSError("exit unavailable")
        self.server.opener = fail
        token = base64.b64encode(b"u:long-test-password")
        with self.client() as client:
            client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic " + token + b"\r\n\r\n")
            self.assertIn(b"502 Bad Gateway", client.recv(4096))

    def test_close_active_disconnects_tunnel(self):
        local, remote = socket.socketpair()
        self.server.opener = lambda host, port: local
        token = base64.b64encode(b"u:long-test-password")
        with remote, self.client() as client:
            client.settimeout(2)
            client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic " + token + b"\r\n\r\n")
            self.assertIn(b"200 Connection Established", client.recv(4096))
            self.server.close_active()
            try:
                self.assertEqual(client.recv(1), b"")
            except (ConnectionResetError, ssl.SSLError):
                pass


class PlainHttpProxyListenerTest(ProxyListenerTest):
    def setUp(self):
        super().setUp()
        self.server.context = None

    def client(self):
        return socket.create_connection(self.server.server_address)


if __name__ == "__main__":
    unittest.main()
