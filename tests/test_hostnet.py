"""Адреса хоста из /proc/net и выбор адреса сервера в конфигах клиентов."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import awgserver, hostnet  # noqa: E402

IF_INET6 = """\
00000000000000000000000000000001 01 80 10 80       lo
fe800000000000000000000000000001 02 40 20 80     eth0
2a0104f8c2c123450000000000000002 02 40 00 80     eth0
2a0104f8c2c12345abcdabcdabcdabcd 02 40 00 01     eth0
2a0104f8c2c12345000000000000dead 02 40 00 a0     eth0
fd000000000000000000000000000002 03 40 00 80    awg0
2a0104f8c2c1aaaa0000000000000001 04 40 00 80  docker0
2001067c2e8c00000000000000000005 05 40 00 80     ens3
"""

UDP6 = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  512: 00000000000000000000000000000000:BAAF 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 0 2 0000000000000000 0
  913: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1 2 0000000000000000 0
"""


def _file(text: str) -> str:
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return path


class HostNetTest(unittest.TestCase):
    def test_global_ipv6(self):
        p = _file(IF_INET6)
        try:
            # без link-local, временного, устаревшего, ULA и адресов туннелей/Docker
            self.assertEqual(hostnet.global_ipv6(p), ["2a01:4f8:c2c1:2345::2", "2001:67c:2e8c::5"])
        finally:
            os.remove(p)

    def test_no_file(self):
        self.assertEqual(hostnet.global_ipv6("/nonexistent/if_inet6"), [])
        self.assertFalse(hostnet.udp6_listening(47823, "/nonexistent/udp6"))

    def test_udp6_listening(self):
        p = _file(UDP6)
        try:
            self.assertTrue(hostnet.udp6_listening(47791, p))     # 0xBAAF
            self.assertFalse(hostnet.udp6_listening(47823, p))
        finally:
            os.remove(p)


class ClientConfHostTest(unittest.TestCase):
    def test_ipv6_endpoint(self):
        sc = awgserver.parse("[Interface]\nPrivateKey = x\nAddress = 10.8.1.0/24\nListenPort = 47823\n")
        peer = awgserver.Peer(public_key="pk", allowed_ips="10.8.1.2/32")
        prof = awgserver.ClientProfile(host="2a01:4f8:c2c1:2345::2", port=47823, server_pub="pub", dns=["1.1.1.1"])
        conf = awgserver.client_conf(sc, prof, peer, "priv")
        self.assertIn("Endpoint = [2a01:4f8:c2c1:2345::2]:47823", conf)
        self.assertIn("Address = 10.8.1.2/32", conf)


if __name__ == "__main__":
    unittest.main()
