"""Совместимость HTTPS-прокси с requests; тестовый сертификат только для localhost."""
import http.server
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

from app import proxy_auth, proxy_listener

try:
    import requests
    import urllib3
except ImportError:
    requests = None
    urllib3 = None


def supports_verified_proxy():
    if not urllib3:
        return False
    try:
        return tuple(int(x) for x in urllib3.__version__.split(".")[:2]) >= (2, 8)
    except ValueError:
        return False


@unittest.skipUnless(requests and shutil.which("openssl") and supports_verified_proxy(),
                     "requests, openssl and urllib3 >= 2.8 required for verified HTTPS proxy")
class RequestsProxyTest(unittest.TestCase):
    def test_https_destination_via_https_proxy(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = tmp + "/cert.pem", tmp + "/key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                            "-keyout", key, "-out", cert],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            other_cert, other_key = tmp + "/other.pem", tmp + "/other-key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=other", "-keyout", other_key, "-out", other_cert],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            untrusted_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            untrusted_ctx.load_cert_chain(other_cert, other_key)

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"ok")

                def log_message(self, *_args):
                    pass

            target = http.server.HTTPServer(("127.0.0.1", 0), Handler)
            target.socket = ctx.wrap_socket(target.socket, server_side=True)
            threading.Thread(target=target.serve_forever, daemon=True).start()
            plain = http.server.HTTPServer(("127.0.0.1", 0), Handler)
            threading.Thread(target=plain.serve_forever, daemon=True).start()
            record = proxy_auth.password_record("local-test-password")
            def connect(_host, port):
                return socket.create_connection(("127.0.0.1", port))
            proxy = proxy_listener.create(("127.0.0.1", 0), lambda: ctx,
                                          lambda: {"username": "test", "password": record}, connect)
            threading.Thread(target=proxy.serve_forever, daemon=True).start()
            try:
                url = f"https://localhost:{target.server_port}/"
                endpoint = f"https://test:local-test-password@localhost:{proxy.server_address[1]}"
                class VerifiedProxyAdapter(requests.adapters.HTTPAdapter):
                    def proxy_manager_for(self, proxy_url, **kwargs):
                        kwargs["proxy_ssl_context"] = ssl.create_default_context(cafile=cert)
                        return super().proxy_manager_for(proxy_url, **kwargs)

                with requests.Session() as session:
                    session.trust_env = False
                    session.mount("http://", VerifiedProxyAdapter())
                    session.mount("https://", VerifiedProxyAdapter())
                    result = session.get(url, proxies={"https": endpoint}, verify=cert, timeout=10)
                    result_plain = session.get(f"http://localhost:{plain.server_port}/",
                                               proxies={"http": endpoint}, verify=cert, timeout=10)
                proxy.context = lambda: untrusted_ctx
                for scheme, target_url in (("http", f"http://localhost:{plain.server_port}/"), ("https", url)):
                    with self.subTest(scheme=scheme), requests.Session() as untrusted:
                        untrusted.trust_env = False
                        untrusted.mount(scheme + "://", VerifiedProxyAdapter())
                        with self.assertRaises((requests.exceptions.SSLError, requests.exceptions.ProxyError)):
                            untrusted.get(target_url, proxies={scheme: endpoint}, verify=cert, timeout=10)
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.text, "ok")
                self.assertEqual(result_plain.status_code, 200)
                self.assertEqual(result_plain.text, "ok")
            finally:
                proxy.close_active()
                proxy.shutdown()
                proxy.server_close()
                target.shutdown()
                target.server_close()
                plain.shutdown()
                plain.server_close()


if __name__ == "__main__":
    unittest.main()
