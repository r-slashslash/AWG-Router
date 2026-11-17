import os
import tempfile
import unittest

from app.traffic import Traffic


class ProxyTrafficTest(unittest.TestCase):
    def test_proxy_counts_to_exit_and_server_and_persists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "traffic.json")
            traffic = Traffic(path)
            traffic.add_proxy("u1", 0, 123)
            traffic.add_proxy("u1", 1, 456)
            traffic.save()
            restored = Traffic(path)
            self.assertEqual(restored.out_month("u1"), [123, 456])
            self.assertEqual(restored.server_view()["total_rx"], 123)
            self.assertEqual(restored.server_view()["total_tx"], 456)
            self.assertEqual(restored.out_used("u1"), 579)


if __name__ == "__main__":
    unittest.main()
