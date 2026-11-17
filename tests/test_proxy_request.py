import unittest

from app.proxy_request import parse_connect, parse_http


class ProxyRequestTest(unittest.TestCase):
    def test_connect_preserves_target_and_credentials(self):
        self.assertEqual(parse_connect(b"CONNECT api.example.com:443 HTTP/1.1\r\n"
                                       b"Host: api.example.com:443\r\n"
                                       b"Proxy-Authorization: Basic YTpi\r\n\r\n"),
                         ("api.example.com", 443, "Basic YTpi"))

    def test_ipv6_authority(self):
        self.assertEqual(parse_connect(b"CONNECT [2606:4700:4700::1111]:443 HTTP/1.1\r\n\r\n")[:2],
                         ("2606:4700:4700::1111", 443))

    def test_rejects_ambiguous_or_non_connect_requests(self):
        for request in (b"GET http://example.com/ HTTP/1.1\r\n\r\n",
                        b"CONNECT localhost:99999 HTTP/1.1\r\n\r\n",
                        b"CONNECT host:443 HTTP/1.1\r\nProxy-Authorization: a\r\n"
                        b"Proxy-Authorization: b\r\n\r\n",
                        b"CONNECT host:443 HTTP/1.1\r\nContent-Length: 1\r\n\r\n",
                        b"CONNECT host:443 HTTP/1.1\r\nBad Header: x\r\n\r\n"):
            with self.subTest(request=request), self.assertRaises(ValueError):
                parse_connect(request)

    def test_http_rewrites_uri_and_removes_proxy_credentials(self):
        host, port, auth, forwarded, size = parse_http(
            b"POST http://example.com:8080/api?a=1 HTTP/1.1\r\nHost: example.com:8080\r\n"
            b"Proxy-Authorization: Basic YTpi\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n")
        self.assertEqual((host, port, auth, size), ("example.com", 8080, "Basic YTpi", 5))
        self.assertTrue(forwarded.startswith(b"POST /api?a=1 HTTP/1.1\r\n"))
        self.assertNotIn(b"proxy-authorization", forwarded.lower())
        self.assertIn(b"Connection: close", forwarded)

    def test_http_rejects_ambiguous_body_and_credentials_in_url(self):
        for req in (b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                    b"GET http://user:pass@example.com/ HTTP/1.1\r\n\r\n",
                    b"GET http://example.com:0/ HTTP/1.1\r\n\r\n",
                    b"GET http://example.com/ HTTP/1.1\r\nConnection: content-length\r\nContent-Length: 3\r\n\r\n"):
            with self.subTest(req=req), self.assertRaises(ValueError):
                parse_http(req)


if __name__ == "__main__":
    unittest.main()
