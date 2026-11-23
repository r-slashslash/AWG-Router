"""Tests for app/socksproxy.py — asyncio SOCKS5 server daemon."""
import asyncio
import json
import os
import socket
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app.socksproxy as socksproxy  # noqa: E402


def _socks5_auth_packet(username: str, password: str) -> bytes:
    u = username.encode("utf-8")
    p = password.encode("utf-8")
    return bytes([0x01, len(u)]) + u + bytes([len(p)]) + p


def _socks5_connect_ipv4(ip: str, port: int) -> bytes:
    return b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack("!H", port)


def _socks5_connect_domain(domain: str, port: int) -> bytes:
    d = domain.encode("ascii")
    return b"\x05\x01\x00\x03" + bytes([len(d)]) + d + struct.pack("!H", port)


class TestSocksProxyHelpers(unittest.TestCase):
    def test_is_blocked_ip(self):
        for blocked in (
            "127.0.0.1",
            "127.0.0.2",
            "::1",
            "::ffff:127.0.0.1",
            "169.254.1.1",
            "fe80::1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
            "10.8.1.1",
            "10.8.2.2",
            "192.168.1.1",
            "172.16.0.1",
            "100.64.0.1",
            "240.0.0.1",
            "not-an-ip",
        ):
            self.assertTrue(socksproxy.is_blocked_ip(blocked), f"expected {blocked} to be blocked")

        for allowed in ("8.8.8.8", "1.1.1.1", "93.184.216.34", "2001:4860:4860::8888"):
            self.assertFalse(socksproxy.is_blocked_ip(allowed), f"expected {allowed} to be allowed")

        extra = socksproxy._parse_blocked_ips(["203.0.113.10", "::ffff:198.51.100.5"])
        self.assertTrue(socksproxy.is_blocked_ip("203.0.113.10", extra))
        self.assertTrue(socksproxy.is_blocked_ip("198.51.100.5", extra))
        self.assertFalse(socksproxy.is_blocked_ip("8.8.8.8", extra))

    def test_auth_limiter_bans_after_failures(self):
        lim = socksproxy._AuthLimiter(max_fails=3, window=60, ban_secs=60)
        self.assertFalse(lim.is_banned("1.2.3.4"))
        self.assertFalse(lim.record_failure("1.2.3.4"))
        self.assertFalse(lim.record_failure("1.2.3.4"))
        self.assertTrue(lim.record_failure("1.2.3.4"))
        self.assertTrue(lim.is_banned("1.2.3.4"))
        self.assertFalse(lim.is_banned("5.6.7.8"))
        lim.record_success("5.6.7.8")

    def test_load_config_and_reload(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "listen": "127.0.0.1",
                    "port": 1080,
                    "users": {"alice": {"password": "secret", "mark": 101}},
                },
                f,
            )
            cfg_path = f.name

        try:
            proxy = socksproxy.SocksProxyServer(cfg_path)
            self.assertEqual(proxy.listen, "127.0.0.1")
            self.assertEqual(proxy.port, 1080)
            self.assertEqual(proxy.users["alice"]["mark"], 101)

            with open(cfg_path, "w") as f:
                json.dump(
                    {
                        "listen": "127.0.0.1",
                        "port": 1081,
                        "users": {"bob": {"password": "pw2", "mark": 202}},
                    },
                    f,
                )

            proxy.reload()
            self.assertEqual(proxy.port, 1081)
            self.assertNotIn("alice", proxy.users)
            self.assertEqual(proxy.users["bob"]["mark"], 202)
        finally:
            os.unlink(cfg_path)


class TestSocksProxyServer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.state = {
            "users": {
                "alice": {"password": "secret", "mark": 123},
                "nomark": {"password": "pw", "mark": 0},
            }
        }
        self.server = await asyncio.start_server(
            lambda r, w: socksproxy.handle_client(r, w, self.state),
            "127.0.0.1",
            0,
        )
        self.port = self.server.sockets[0].getsockname()[1]

        async def _echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                while data := await reader.read(4096):
                    writer.write(data)
                    await writer.drain()
            except OSError:
                pass
            finally:
                writer.close()

        self.echo_server = await asyncio.start_server(_echo, "127.0.0.1", 0)
        self.echo_port = self.echo_server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self.echo_server.close()
        await self.echo_server.wait_closed()

    async def test_no_userpass_method_rejected(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            reply = await asyncio.wait_for(reader.readexactly(2), 2.0)
            self.assertEqual(reply, b"\x05\xff")
            eof = await asyncio.wait_for(reader.read(1), 2.0)
            self.assertEqual(eof, b"")
        finally:
            writer.close()

    async def test_wrong_password_rejected(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(b"\x05\x02\x00\x02")
            await writer.drain()
            method_reply = await asyncio.wait_for(reader.readexactly(2), 2.0)
            self.assertEqual(method_reply, b"\x05\x02")

            writer.write(_socks5_auth_packet("alice", "wrong-pass"))
            await writer.drain()
            auth_reply = await asyncio.wait_for(reader.readexactly(2), 2.0)
            self.assertEqual(auth_reply, b"\x01\x01")
            eof = await asyncio.wait_for(reader.read(1), 2.0)
            self.assertEqual(eof, b"")
        finally:
            writer.close()

    async def test_connect_to_loopback_blocked(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x05\x02")

            writer.write(_socks5_auth_packet("alice", "secret"))
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x01\x00")

            writer.write(_socks5_connect_ipv4("127.0.0.1", self.echo_port))
            await writer.drain()
            rep = await asyncio.wait_for(reader.readexactly(10), 2.0)
            self.assertEqual(rep[0], 0x05)
            self.assertEqual(rep[1], 0x02)
            eof = await asyncio.wait_for(reader.read(1), 2.0)
            self.assertEqual(eof, b"")
        finally:
            writer.close()

    async def test_connect_domain_resolving_to_loopback_blocked(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x05\x02")

            writer.write(_socks5_auth_packet("alice", "secret"))
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x01\x00")

            writer.write(_socks5_connect_domain("localhost", self.echo_port))
            await writer.drain()
            rep = await asyncio.wait_for(reader.readexactly(10), 2.0)
            self.assertEqual(rep[0], 0x05)
            self.assertEqual(rep[1], 0x02)
            eof = await asyncio.wait_for(reader.read(1), 2.0)
            self.assertEqual(eof, b"")
        finally:
            writer.close()

    async def test_unsupported_command_rejected(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x05\x02")

            writer.write(_socks5_auth_packet("alice", "secret"))
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x01\x00")

            # CMD = 0x02 (BIND)
            writer.write(b"\x05\x02\x00\x01" + socket.inet_aton("8.8.8.8") + struct.pack("!H", 80))
            await writer.drain()
            rep = await asyncio.wait_for(reader.readexactly(10), 2.0)
            self.assertEqual(rep[0], 0x05)
            self.assertEqual(rep[1], 0x07)
        finally:
            writer.close()

    async def test_connect_and_relay_with_so_mark(self):
        recorded_marks: list[tuple[int, int, int]] = []
        orig_setsockopt = socket.socket.setsockopt

        def spy_setsockopt(sock_self, level, optname, value, *args):
            if level == socket.SOL_SOCKET and optname == socksproxy.SO_MARK:
                recorded_marks.append((level, optname, value))
            return orig_setsockopt(sock_self, level, optname, value, *args)

        with (
            patch.object(socksproxy, "is_blocked_ip", return_value=False),
            patch.object(socket.socket, "setsockopt", new=spy_setsockopt),
        ):
            reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
            try:
                writer.write(b"\x05\x01\x02")
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x05\x02")

                writer.write(_socks5_auth_packet("alice", "secret"))
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x01\x00")

                writer.write(_socks5_connect_ipv4("127.0.0.1", self.echo_port))
                await writer.drain()
                rep = await asyncio.wait_for(reader.readexactly(10), 2.0)
                self.assertEqual(rep[0], 0x05)
                self.assertEqual(rep[1], 0x00)

                payload = b"hello socks5 bidirectional relay!\n"
                writer.write(payload)
                await writer.drain()
                echoed = await asyncio.wait_for(reader.readexactly(len(payload)), 2.0)
                self.assertEqual(echoed, payload)
            finally:
                writer.close()

        self.assertIn((socket.SOL_SOCKET, socksproxy.SO_MARK, 123), recorded_marks)

    async def test_connect_and_relay_without_so_mark(self):
        recorded_marks: list[tuple[int, int, int]] = []
        orig_setsockopt = socket.socket.setsockopt

        def spy_setsockopt(sock_self, level, optname, value, *args):
            if level == socket.SOL_SOCKET and optname == socksproxy.SO_MARK:
                recorded_marks.append((level, optname, value))
            return orig_setsockopt(sock_self, level, optname, value, *args)

        with (
            patch.object(socksproxy, "is_blocked_ip", return_value=False),
            patch.object(socket.socket, "setsockopt", new=spy_setsockopt),
        ):
            reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
            try:
                writer.write(b"\x05\x01\x02")
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x05\x02")

                writer.write(_socks5_auth_packet("nomark", "pw"))
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x01\x00")

                writer.write(_socks5_connect_ipv4("127.0.0.1", self.echo_port))
                await writer.drain()
                rep = await asyncio.wait_for(reader.readexactly(10), 2.0)
                self.assertEqual(rep[0], 0x05)
                self.assertEqual(rep[1], 0x00)

                payload = b"nomark relay\n"
                writer.write(payload)
                await writer.drain()
                echoed = await asyncio.wait_for(reader.readexactly(len(payload)), 2.0)
                self.assertEqual(echoed, payload)
            finally:
                writer.close()

        self.assertEqual(recorded_marks, [])

    async def test_utf8_password_auth_and_non_utf8_rejection(self):
        self.state["users"]["utf8user"] = {"password": "пароль123", "mark": 0}
        with patch.object(socksproxy, "is_blocked_ip", return_value=False):
            reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
            try:
                writer.write(b"\x05\x01\x02")
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x05\x02")

                writer.write(_socks5_auth_packet("utf8user", "пароль123"))
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x01\x00")

                writer.write(_socks5_connect_ipv4("127.0.0.1", self.echo_port))
                await writer.drain()
                rep = await asyncio.wait_for(reader.readexactly(10), 2.0)
                self.assertEqual(rep[:2], b"\x05\x00")
            finally:
                writer.close()

        # Invalid UTF-8 bytes in password must return AUTH_FAIL cleanly instead of TypeError
        reader2, writer2 = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer2.write(b"\x05\x01\x02")
            await writer2.drain()
            self.assertEqual(await asyncio.wait_for(reader2.readexactly(2), 2.0), b"\x05\x02")

            bad_pkt = b"\x01" + bytes([len(b"utf8user")]) + b"utf8user" + b"\x02\xff\xfe"
            writer2.write(bad_pkt)
            await writer2.drain()
            self.assertEqual(await asyncio.wait_for(reader2.readexactly(2), 2.0), b"\x01\x01")
            self.assertEqual(await asyncio.wait_for(reader2.read(1), 2.0), b"")
        finally:
            writer2.close()

    async def test_blocked_exit_mark_returns_not_allowed(self):
        self.state["users"]["blocked"] = {"password": "pw", "mark": -1}
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x05\x02")

            writer.write(_socks5_auth_packet("blocked", "pw"))
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2.0), b"\x01\x00")

            writer.write(_socks5_connect_ipv4("93.184.216.34", 80))
            await writer.drain()
            rep = await asyncio.wait_for(reader.readexactly(10), 2.0)
            self.assertEqual(rep[:2], b"\x05\x02")
        finally:
            writer.close()


class TestStoreSocksDefaults(unittest.TestCase):
    def test_new_store_has_socks_defaults(self):
        from app.store import Store

        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "state.json")).snapshot()
            self.assertEqual(st.get("socks_users") or {}, {})
            self.assertEqual(st["settings"].get("socks_proxy") or {"enabled": False, "port": 1080},
                             {"enabled": False, "port": 1080})

    def test_existing_store_upgrades_malformed_socks_fields(self):
        from app.store import Store

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "socks_users": "bad",
                           "settings": {"list_update_hours": 12, "socks_proxy": {"port": 2080}}}, f)
            st = Store(path).snapshot()
            self.assertEqual(st["socks_users"], {})
            self.assertEqual(st["settings"]["socks_proxy"], {"enabled": False, "port": 2080})
            self.assertEqual(st["settings"]["list_update_hours"], 12)


class TestChecksSocksValidation(unittest.TestCase):
    def test_validate_socks_username(self):
        from app import checks
        from app.web import HTTPError

        self.assertEqual(checks.validate_socks_username("alice"), "alice")
        self.assertEqual(checks.validate_socks_username("user_1.2-a"), "user_1.2-a")
        for bad in ("", "a b", "alice:bob", "x" * 65, 123, None):
            with self.assertRaises(HTTPError):
                checks.validate_socks_username(bad)

    def test_validate_socks_password(self):
        from app import checks
        from app.web import HTTPError

        self.assertEqual(checks.validate_socks_password("s3cr3t!8"), "s3cr3t!8")
        for bad in ("", "short7", "a" * 256, "bad\npass", 123, None):
            with self.assertRaises(HTTPError):
                checks.validate_socks_password(bad)

    def test_validate_socks_port(self):
        from app import checks
        from app.web import HTTPError

        self.assertEqual(checks.validate_socks_port(1080), 1080)
        self.assertEqual(checks.validate_socks_port("8080"), 8080)
        self.assertEqual(checks.validate_socks_port(1), 1)
        self.assertEqual(checks.validate_socks_port(65535), 65535)
        for bad in (0, 65536, -1, True, False, "abc", None, 1080.5):
            with self.assertRaises(HTTPError):
                checks.validate_socks_port(bad)


class TestSystemOpenFirewallTcp(unittest.TestCase):
    def test_open_firewall_tcp_when_ufw_active(self):
        from app import system

        calls = []

        class FakeTarget:
            def native(self, cmd, **kw):
                calls.append(cmd)
                if cmd == ["ufw", "status"]:
                    return type("P", (), {"returncode": 0, "stdout": "Status: active\n"})()
                return type("P", (), {"returncode": 0, "stdout": ""})()

        system.open_firewall_tcp(FakeTarget(), 1080)
        self.assertEqual(calls, [["ufw", "status"], ["ufw", "allow", "1080/tcp"]])

    def test_open_firewall_tcp_when_ufw_inactive(self):
        from app import system

        calls = []

        class FakeTarget:
            def native(self, cmd, **kw):
                calls.append(cmd)
                return type("P", (), {"returncode": 0, "stdout": "Status: inactive\n"})()

        system.open_firewall_tcp(FakeTarget(), 1080)
        self.assertEqual(calls, [["ufw", "status"]])


class TestSocksProxyMixin(unittest.TestCase):
    def _make_engine(self):
        from app import engine, nftgen

        eng = engine.Engine.__new__(engine.Engine)
        eng.rt = {"u1": type("UpRT", (), {"num": 3})()}
        eng.socks_srv = None
        eng.socks_state = None
        eng._socks_retry = 0.0
        eng.events = []
        eng.event = lambda level, msg: eng.events.append((level, msg))
        return eng, nftgen

    def test_socks_config_and_so_mark_mapping(self):
        eng, nftgen = self._make_engine()
        st = {
            "upstreams": [
                {"id": "u1", "num": 3},
                {"id": "u2", "num": 4},
                {"id": "u3", "num": 5, "fallback": "up:u1"},
                {"id": "u4", "num": 6, "fallback": "block"},
            ],
            "socks_users": {
                "alice": {"password": "pw1", "exit": "direct", "enabled": True},
                "bob": {"password": "pw2", "exit": "up:u1", "enabled": True},
                "carol": {"password": "pw3", "exit": "up:u2", "enabled": True},
                "dave": {"password": "pw4", "exit": "up:u1", "enabled": False},
                "eve": {"password": "pw5", "exit": "up:u3", "enabled": True},
                "frank": {"password": "pw6", "exit": "up:u4", "enabled": True},
            },
            "settings": {"socks_proxy": {"enabled": True, "port": 2080}},
        }
        cfg = eng._socks_config(st)
        self.assertEqual(cfg["listen"], "0.0.0.0")
        self.assertEqual(cfg["port"], 2080)
        self.assertEqual(
            cfg["users"],
            {
                "alice": {"password": "pw1", "mark": 0},
                "bob": {"password": "pw2", "mark": nftgen.mark_for(3)},
                "carol": {"password": "pw3", "mark": 0},
                "eve": {"password": "pw5", "mark": nftgen.mark_for(3)},
                "frank": {"password": "pw6", "mark": -1},
            },
        )
        with self.assertRaises(socksproxy._BlockedTargetError):
            asyncio.run(socksproxy._open_outbound("93.184.216.34", 80, mark=-1))

    def test_sync_socks_start_sighup_restart_and_stop(self):
        import signal
        from app import config, system
        from app.engine import socks_srv

        eng, nftgen = self._make_engine()
        target = type("T", (), {"key": "host:awg0", "pid": 1, "native": lambda *a, **kw: None})()
        st = {
            "upstreams": [{"id": "u1", "num": 3}],
            "socks_users": {"alice": {"password": "pw1", "exit": "up:u1", "enabled": True}},
            "settings": {"socks_proxy": {"enabled": True, "port": 1080}},
        }

        procs = []

        class FakeProc:
            def __init__(self):
                self.signals = []
                self.terminated = False
                self.killed = False
                self._poll = None

            def poll(self):
                return self._poll

            def send_signal(self, sig):
                self.signals.append(sig)

            def terminate(self):
                self.terminated = True
                self._poll = 0

            def wait(self, timeout=None):
                return 0

            def kill(self):
                self.killed = True
                self._poll = -9

        def fake_popen(*args, **kwargs):
            p = FakeProc()
            procs.append((args, p))
            return p

        with tempfile.TemporaryDirectory() as d:
            conf_path = os.path.join(d, "awgr-socks.json")
            log_dir = os.path.join(d, "logs")
            os.makedirs(log_dir, exist_ok=True)
            with (
                patch.object(config, "DRY_RUN", False),
                patch.object(socks_srv, "SOCKS_CONF", conf_path),
                patch.object(socks_srv, "LOG_DIR", log_dir),
                patch.object(socks_srv.subprocess, "Popen", side_effect=fake_popen),
                patch.object(socks_srv.time, "sleep"),
                patch.object(system, "open_firewall_tcp") as fw_mock,
            ):
                # Start
                eng._sync_socks(target, st)
                self.assertEqual(len(procs), 1)
                self.assertEqual(eng.socks_state, {"state": "on", "port": 1080, "users": 1})
                fw_mock.assert_called_once_with(target, 1080)
                self.assertEqual(os.stat(conf_path).st_mode & 0o777, 0o600)
                with open(conf_path, encoding="utf-8") as f:
                    written = json.load(f)
                self.assertEqual(written["users"]["alice"]["mark"], nftgen.mark_for(3))

                # User change -> SIGHUP, no new Popen
                st["socks_users"]["bob"] = {"password": "pw2", "exit": "direct", "enabled": True}
                eng._sync_socks(target, st)
                self.assertEqual(len(procs), 1)
                self.assertEqual(procs[0][1].signals, [signal.SIGHUP])
                self.assertEqual(eng.socks_state, {"state": "on", "port": 1080, "users": 2})

                # Port change -> terminate old, start new
                st["settings"]["socks_proxy"]["port"] = 1081
                eng._sync_socks(target, st)
                self.assertEqual(len(procs), 2)
                self.assertTrue(procs[0][1].terminated)
                self.assertEqual(eng.socks_state, {"state": "on", "port": 1081, "users": 2})

                # Disable -> stop
                st["settings"]["socks_proxy"]["enabled"] = False
                eng._sync_socks(target, st)
                self.assertTrue(procs[1][1].terminated)
                self.assertIsNone(eng.socks_srv)
                self.assertIsNone(eng.socks_state)

    def test_ipv6_rejected_for_marked_exit(self):
        with self.assertRaises(socksproxy._BlockedTargetError):
            asyncio.run(socksproxy._open_outbound("2001:4860:4860::8888", 443, mark=100))


class TestSocksApiAndBackup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
        os.environ.setdefault("PANEL_PASSWORD", "test-password")

    def _req(self, body=None):
        return type("R", (), {"json": lambda self: body if body is not None else {}, "headers": {}})()

    def setUp(self):
        from app import panel

        self._panel = panel
        self._st0 = panel.store.snapshot()

    def tearDown(self):
        st0 = self._st0
        self._panel.store.mutate(lambda st: (st.clear(), st.update(st0)))

    def test_socks_settings_and_port_conflicts(self):
        from app import config
        from app.api import socks
        from app.web import HTTPError

        res = socks.put_socks_settings(self._req({"enabled": True, "port": 1085}))
        self.assertEqual(res, {"ok": True})
        sp = self._panel.store.snapshot()["settings"]["socks_proxy"]
        self.assertEqual(sp, {"enabled": True, "port": 1085})

        for bad_port in (0, 65536, "bad", config.PANEL_PORT, config.SNI_PROXY_PORT, config.SSH_PORT or 22):
            with self.assertRaises(HTTPError, msg=f"port {bad_port} should fail"):
                socks.put_socks_settings(self._req({"enabled": True, "port": bad_port}))

        with patch.object(self._panel.tls, "status", return_value={"mode": "letsencrypt"}):
            with self.assertRaises(HTTPError):
                socks.put_socks_settings(self._req({"enabled": True, "port": 443}))

    def test_socks_users_crud(self):
        from app.api import exits, socks
        from app.web import HTTPError

        up_id = exits.add_upstream(self._req({"name": "Exit1", "config": "socks5://198.51.100.9:1080"}))["id"]
        res = socks.add_socks_user(
            self._req({"username": "alice", "password": "secret12", "exit": f"up:{up_id}", "enabled": True})
        )
        self.assertEqual(res, {"ok": True, "username": "alice"})
        u = self._panel.store.snapshot()["socks_users"]["alice"]
        self.assertEqual(u, {"password": "secret12", "exit": f"up:{up_id}", "enabled": True})

        # Duplicate username rejected
        with self.assertRaises(HTTPError):
            socks.add_socks_user(self._req({"username": "alice", "password": "password2"}))

        # Invalid username / password / unknown exit rejected
        with self.assertRaises(HTTPError):
            socks.add_socks_user(self._req({"username": "bad user", "password": "password2"}))
        with self.assertRaises(HTTPError):
            socks.add_socks_user(self._req({"username": "bob", "password": ""}))
        with self.assertRaises(HTTPError):
            socks.add_socks_user(self._req({"username": "bob", "password": "short"}))
        with self.assertRaises(HTTPError):
            socks.add_socks_user(self._req({"username": "bob", "password": "password2", "exit": "up:nope"}))

        # Update user (empty password preserves existing)
        socks.put_socks_user(self._req({"password": "", "exit": "direct", "enabled": False}), "alice")
        u = self._panel.store.snapshot()["socks_users"]["alice"]
        self.assertEqual(u, {"password": "secret12", "exit": "direct", "enabled": False})

        # Update password
        socks.put_socks_user(self._req({"password": "newpass12"}), "alice")
        self.assertEqual(self._panel.store.snapshot()["socks_users"]["alice"]["password"], "newpass12")

        # URI endpoint returns credentials
        uri = socks.get_socks_user_uri(self._req(), "alice")
        self.assertEqual(uri["username"], "alice")
        self.assertEqual(uri["password"], "newpass12")

        # Update/delete missing user -> 404
        with self.assertRaises(HTTPError) as cm:
            socks.put_socks_user(self._req({"enabled": True}), "missing")
        self.assertEqual(cm.exception.code, 404)
        with self.assertRaises(HTTPError) as cm:
            socks.del_socks_user(self._req(), "missing")
        self.assertEqual(cm.exception.code, 404)

        # Delete user
        self.assertEqual(socks.del_socks_user(self._req(), "alice"), {"ok": True})
        self.assertNotIn("alice", self._panel.store.snapshot()["socks_users"])

    def test_state_includes_socks_proxy_without_passwords(self):
        from app.api import socks, state

        socks.put_socks_settings(self._req({"enabled": True, "port": 1089}))
        socks.add_socks_user(self._req({"username": "bob", "password": "password12", "exit": "direct"}))
        st_view = state.get_state(self._req())
        self.assertIn("socks_proxy", st_view)
        self.assertEqual(st_view["socks_proxy"]["enabled"], True)
        self.assertEqual(st_view["socks_proxy"]["port"], 1089)
        self.assertEqual(len(st_view["socks_proxy"]["users"]), 1)
        self.assertEqual(st_view["socks_proxy"]["users"][0]["username"], "bob")
        self.assertNotIn("password", st_view["socks_proxy"]["users"][0])

    def test_del_upstream_resets_socks_users_to_direct(self):
        from app.api import exits, socks

        up_id = exits.add_upstream(self._req({"name": "Exit2", "config": "socks5://198.51.100.10:1080"}))["id"]
        socks.add_socks_user(self._req({"username": "carol", "password": "password12", "exit": f"up:{up_id}"}))
        exits.del_upstream(self._req({"replace": "direct"}), up_id)
        self.assertEqual(self._panel.store.snapshot()["socks_users"]["carol"]["exit"], "direct")

    def test_backup_round_trip_and_validation(self):
        from app import config
        from app.api import backup, exits, socks
        from app.web import HTTPError

        up_id = exits.add_upstream(self._req({"name": "Exit3", "config": "socks5://198.51.100.11:1080"}))["id"]
        socks.put_socks_settings(self._req({"enabled": True, "port": 2080}))
        socks.add_socks_user(
            self._req({"username": "dave", "password": "password34", "exit": f"up:{up_id}", "enabled": False})
        )
        snap = self._panel.store.snapshot(texts=True)
        cleaned = backup.clean_backup_state(snap)
        self.assertEqual(cleaned["settings"]["socks_proxy"], {"enabled": True, "port": 2080})
        self.assertEqual(
            cleaned["socks_users"],
            {"dave": {"password": "password34", "exit": f"up:{up_id}", "enabled": False}},
        )

        # Invalid socks_users or socks_proxy in backup rejected
        bad_user = json.loads(json.dumps(snap))
        bad_user["socks_users"]["bad user"] = {"password": "password12", "exit": "direct", "enabled": True}
        with self.assertRaises(HTTPError):
            backup.clean_backup_state(bad_user)

        bad_port = json.loads(json.dumps(snap))
        bad_port["settings"]["socks_proxy"]["port"] = 99999
        with self.assertRaises(HTTPError):
            backup.clean_backup_state(bad_port)

        busy_port = json.loads(json.dumps(snap))
        busy_port["settings"]["socks_proxy"]["port"] = config.PANEL_PORT
        with self.assertRaises(HTTPError):
            backup.clean_backup_state(busy_port)


if __name__ == "__main__":
    unittest.main()
