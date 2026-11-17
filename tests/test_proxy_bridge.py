import array
import socket
import unittest
from unittest.mock import patch

from app import proxy_bridge


class ProxyBridgeTest(unittest.TestCase):
    def test_received_connection_remains_usable(self):
        control, sender = socket.socketpair()
        peer, target = socket.socketpair()
        with control, sender, peer, target:
            sender.sendmsg([b"1"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                      array.array("i", [target.fileno()]))])
            with proxy_bridge.receive_socket(control) as passed:
                peer.sendall(b"hello")
                self.assertEqual(passed.recv(5), b"hello")

    def test_worker_failure_never_falls_back(self):
        with patch.object(proxy_bridge.subprocess, "run") as run:
            run.return_value.returncode = 1
            with self.assertRaises(OSError):
                proxy_bridge.connect(42, "awgr1", 0x2001, "example.com", 443)
            self.assertEqual(run.call_count, 1)

    def test_invalid_target_is_rejected(self):
        for iface in ("eth0", "awgr0", "awgr1;id"):
            with self.subTest(iface=iface), self.assertRaises(ValueError):
                proxy_bridge.connect(42, iface, 0x2001, "example.com", 443)


if __name__ == "__main__":
    unittest.main()
