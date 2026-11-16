"""1.21.0, вторая проверка (2026-11-16): QUIC, который не удалось разобрать по имени (оборванный
пакет, нет мест, ошибка разбора, сбой), — всегда блок, а не «пропустить».

python3 -m unittest discover tests
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from app import config, quic, sniproxy  # noqa: E402
import test_v121  # noqa: E402
from test_v121 import chromium, ipv4_udp  # noqa: E402

BLOCK, PASS = config.MARK_BLOCK, config.QUIC_PASS_MARK


class QuicNeverPassTest(test_v121.SnifferQuicTest):
    def one(self, s, data):
        return self.run_packets(s, [data])

    def test_broken_initial_blocked(self):
        self.assertEqual(self.one(self.sniffer(0x2005), chromium()[0][:60]), [(1, True, BLOCK)])

    def test_flows_full_blocked(self):
        s = self.sniffer(0x2005)
        s.qflows = {i: {"asm": None, "ids": [], "timer": None} for i in range(sniproxy.QUIC_FLOWS_MAX)}
        self.assertEqual(self.one(s, chromium()[0])[0], (1, True, BLOCK))

    def test_bad_crypto_stream_blocked(self):
        with mock.patch.object(quic.Assembler, "hello", side_effect=quic.NotInitial("x")):
            self.assertEqual(self.one(self.sniffer(0x2005), chromium()[0]), [(1, True, BLOCK)])

    def test_exception_blocked(self):
        s = self.sniffer(0x2005)
        s._quic_logged = 0.0
        s.queue.read = lambda: [(7, ipv4_udp("10.8.1.2", 50000, "8.8.8.8", 443, chromium()[0]))]
        with mock.patch.object(s, "on_packet", side_effect=RuntimeError("boom")):
            s.on_queue()
        self.assertEqual(s.queue.verdicts, [(7, True, BLOCK)])

    # тесты родителя здесь не повторяем
    test_match_gets_rule_mark_for_all_held_packets = test_repeat_of_first_packets_gets_same_decision = None
    test_other_policy_passes = test_incomplete_hello_blocked_after_hold = None
    test_not_quic_passes_short_header_blocked = test_udp_of = None


if __name__ == "__main__":
    unittest.main()
