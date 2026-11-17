import socket
import unittest
from unittest.mock import MagicMock, patch

from app import proxy_socket


class BoundSocketTest(unittest.TestCase):
    def test_binding_failure_closes_socket_and_does_not_fall_back(self):
        sock = MagicMock()
        sock.setsockopt.side_effect = OSError("no interface")
        with patch.object(proxy_socket.socket, "socket", return_value=sock):
            with self.assertRaises(OSError):
                proxy_socket.bound_socket("awgr1", 0x2001, socket.SOCK_STREAM)
        sock.close.assert_called_once()
        sock.connect.assert_not_called()

    def test_connect_uses_only_exit_bound_socket(self):
        sock = MagicMock()
        with patch.object(proxy_socket, "resolve", return_value=["1.1.1.1"]), \
             patch.object(proxy_socket, "bound_socket", return_value=sock) as bound:
            self.assertIs(proxy_socket.connect("example.com", 443, "awgr1", 0x2001), sock)
        bound.assert_called_once_with("awgr1", 0x2001, socket.SOCK_STREAM)
        sock.connect.assert_called_once_with(("1.1.1.1", 443))

    def test_non_public_literal_is_refused_before_opening_socket(self):
        with patch.object(proxy_socket, "bound_socket") as bound:
            with self.assertRaises(ValueError):
                proxy_socket.resolve("127.0.0.1", "awgr1", 0x2001)
            bound.assert_not_called()

    def test_public_address_of_server_is_refused(self):
        with patch.object(proxy_socket, "bound_socket") as bound:
            with self.assertRaises(ValueError):
                proxy_socket.resolve("1.1.1.1", "awgr1", 0x2001, forbidden=("1.1.1.1",))
            bound.assert_not_called()

    def test_dns_response_pointing_to_server_is_refused(self):
        udp = MagicMock()
        with patch.object(proxy_socket, "bound_socket", return_value=udp), \
             patch.object(proxy_socket.tgreq, "dns_query", return_value=b"query"), \
             patch.object(proxy_socket.tgreq, "dns_answer", return_value=["1.1.1.1"]):
            with self.assertRaises(ValueError):
                proxy_socket.resolve("server.example", "awgr1", 0x2001, forbidden=("1.1.1.1",))


if __name__ == "__main__":
    unittest.main()
