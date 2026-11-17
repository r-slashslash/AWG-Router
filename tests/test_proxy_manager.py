import threading
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.proxy_manager import Manager


class ManagerTest(unittest.TestCase):
    def setUp(self):
        self.state = {"proxy_clients": [{"id": "px1", "username": "a", "port": 3128,
                                          "upstream": "u1", "password": {}, "enabled": True}],
                      "upstreams": [{"id": "u1", "num": 1, "enabled": True}]}
        store = SimpleNamespace(snapshot=lambda: self.state, peek=lambda fn: fn(self.state))
        target = SimpleNamespace(pid=11, key="target", exists=True)
        rt = SimpleNamespace(target_key="target", iface="awgr1", num=1)
        engine = SimpleNamespace(lock=threading.RLock(), rt={"u1": rt}, target=target,
                                 health={"u1": {"healthy": True}}, over_quota=lambda up: False,
                                 traffic=SimpleNamespace(add_proxy=MagicMock(), lock=threading.RLock()))
        engine.resolve = lambda out, st: 1 if engine.health["u1"]["healthy"] else "direct"
        self.manager = Manager(store, engine, SimpleNamespace(context=lambda: None))
        self.manager._server_addresses = lambda: ("203.0.113.1",)

    def test_routes_to_selected_exit(self):
        with patch("app.proxy_manager.proxy_bridge.connect") as connect:
            self.manager._connect("px1", "example.com", 443)
        connect.assert_called_once_with(11, "awgr1", 0x2001, "example.com", 443, ("203.0.113.1",))

    def test_unhealthy_exit_does_not_connect(self):
        self.manager.engine.health["u1"]["healthy"] = False
        with patch("app.proxy_manager.proxy_bridge.connect") as connect:
            with self.assertRaises(OSError):
                self.manager._connect("px1", "example.com", 443)
            connect.assert_not_called()

    def test_connecting_and_alternative_exit_never_fall_back(self):
        for resolved in ("block", "direct", 2):
            with self.subTest(resolved=resolved), patch.object(self.manager.engine, "resolve", return_value=resolved), \
                 patch("app.proxy_manager.proxy_bridge.connect") as connect:
                with self.assertRaises(OSError):
                    self.manager._connect("px1", "example.com", 443)
                connect.assert_not_called()

    def test_connection_and_accounting_do_not_copy_entire_state(self):
        self.manager.store.snapshot = MagicMock(side_effect=AssertionError("snapshot in traffic path"))
        with patch("app.proxy_manager.proxy_bridge.connect"):
            self.manager._connect("px1", "example.com", 443)
        self.assertTrue(self.manager._account("u1", 0, 5))

    def test_server_addresses_include_host_and_public_nat_address(self):
        del self.manager._server_addresses
        self.manager.engine.public_v4 = "8.8.4.4"
        output = '[{"addr_info":[{"family":"inet","local":"8.8.8.8"}]}]'
        with patch("app.proxy_manager.subprocess.run", return_value=SimpleNamespace(stdout=output)):
            self.assertEqual(set(self.manager._server_addresses()), {"8.8.8.8", "8.8.4.4"})

    def test_server_address_lookup_failure_blocks_proxy(self):
        del self.manager._server_addresses
        with patch("app.proxy_manager.subprocess.run", side_effect=OSError("ip unavailable")):
            with self.assertRaises(OSError):
                self.manager._server_addresses()

    def test_exhausted_quota_rejects_and_usage_is_recorded(self):
        self.manager.engine.over_quota = lambda up: True
        with patch("app.proxy_manager.proxy_bridge.connect") as connect:
            with self.assertRaises(OSError):
                self.manager._connect("px1", "example.com", 443)
            connect.assert_not_called()
        self.assertFalse(self.manager._account("u1", 0, 12))
        self.manager.engine.traffic.add_proxy.assert_not_called()

    def test_two_directions_cannot_both_reserve_the_last_bytes(self):
        used = [0]
        traffic = self.manager.engine.traffic
        traffic.add_proxy = lambda uid, direction, count: used.__setitem__(0, used[0] + count)
        self.manager.engine.over_quota = lambda up: used[0] >= 5
        barrier = threading.Barrier(3)
        results = []
        def transfer(direction):
            barrier.wait()
            results.append(self.manager._account("u1", direction, 5))
        threads = [threading.Thread(target=transfer, args=(n,)) for n in (0, 1)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(used[0], 5)

    def test_disable_stops_listener_and_disconnects_active(self):
        server = MagicMock()
        self.manager.listeners["px1"] = (server, 3128)
        self.state["proxy_clients"][0]["enabled"] = False
        with patch("app.proxy_manager.config.DRY_RUN", False):
            self.manager.sync()
        server.close_active.assert_called_once()
        server.shutdown.assert_called_once()
        server.server_close.assert_called_once()
        self.assertFalse(self.manager.listeners)

    def test_protocol_change_restarts_listener_and_closes_active_connections(self):
        server = MagicMock()
        server.proxy_protocol = "https"
        self.manager.listeners["px1"] = (server, 3128)
        self.state["proxy_clients"][0]["protocol"] = "http"
        self.state["proxy_clients"][0]["password"] = {"hash": "test"}
        replacement = MagicMock()
        with patch("app.proxy_manager.config.DRY_RUN", False), \
             patch("app.proxy_manager.proxy_listener.create", return_value=replacement) as create, \
             patch("app.proxy_manager.threading.Thread"):
            self.manager.sync()
        server.close_active.assert_called_once()
        server.shutdown.assert_called_once()
        self.assertIsNone(create.call_args.args[1])
        self.assertEqual(replacement.proxy_protocol, "http")


if __name__ == "__main__":
    unittest.main()
