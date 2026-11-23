"""Inbound SOCKS5 proxy daemon (RFC 1928 + RFC 1929 + SO_MARK). Stdlib only."""
from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import os
import signal
import socket
import struct
import sys
import time
from typing import Any

SO_MARK = 36
HANDSHAKE_TIMEOUT = 10.0
CONNECT_TIMEOUT = 10.0
RELAY_BUF = 65536

SOCKS_VERSION = 0x05
AUTH_USERPASS = 0x02
AUTH_NONE_ACCEPTABLE = 0xFF
AUTH_USERPASS_VERSION = 0x01
AUTH_OK = 0x00
AUTH_FAIL = 0x01

CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

REP_OK = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_HOST_UNREACHABLE = 0x04
REP_CONN_REFUSED = 0x05
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08


class _BlockedTargetError(Exception):
    """Raised when a resolved target IP is in a blocked range."""


def log(text: str) -> None:
    print(time.strftime("%Y-%m-%d %H:%M:%S"), text, file=sys.stderr, flush=True)


def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return {
        "listen": str(raw.get("listen") or "0.0.0.0"),
        "port": int(raw.get("port") or 1080),
        "users": dict(raw.get("users") or {}),
    }


def is_blocked_ip(ip: str) -> bool:
    """Return True for loopback, link-local, unspecified, multicast, or invalid IPs."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return bool(
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
    )


def _socks_reply(code: int, bind_addr: tuple[Any, ...] | None = None) -> bytes:
    if bind_addr and len(bind_addr) >= 2:
        try:
            addr = ipaddress.ip_address(bind_addr[0])
            port_bytes = struct.pack("!H", int(bind_addr[1]))
            if addr.version == 4:
                return bytes([SOCKS_VERSION, code, 0x00, ATYP_IPV4]) + addr.packed + port_bytes
            return bytes([SOCKS_VERSION, code, 0x00, ATYP_IPV6]) + addr.packed + port_bytes
        except ValueError:
            pass
    return bytes([SOCKS_VERSION, code, 0x00, ATYP_IPV4]) + b"\x00\x00\x00\x00\x00\x00"


def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    try:
        writer.close()
    except OSError:
        pass


async def _open_outbound(
    host: str, port: int, mark: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
        CONNECT_TIMEOUT,
    )
    if not infos:
        raise OSError(f"getaddrinfo returned no results for {host}:{port}")

    for info in infos:
        if is_blocked_ip(info[4][0]):
            raise _BlockedTargetError(f"blocked target IP: {info[4][0]}")

    last_err: Exception | None = None
    dry_run = os.environ.get("DRY_RUN", "").strip().lower() in ("1", "true", "yes", "on")
    for family, socktype, proto, _canonname, sockaddr in infos:
        sock: socket.socket | None = None
        connected = False
        try:
            sock = socket.socket(family, socktype, proto)
            sock.setblocking(False)
            if mark > 0:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
                except OSError:
                    if not dry_run and sys.platform == "linux":
                        raise
            await asyncio.wait_for(loop.sock_connect(sock, sockaddr), CONNECT_TIMEOUT)
            conn = await asyncio.open_connection(sock=sock)
            connected = True
            return conn
        except Exception as exc:
            last_err = exc
        finally:
            if not connected and sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    assert last_err is not None
    raise last_err


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except (OSError, asyncio.CancelledError):
        _close_writer(writer)


async def _negotiate_auth(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    users: dict[str, dict[str, Any]],
) -> int | None:
    ver, nmethods = await asyncio.wait_for(reader.readexactly(2), HANDSHAKE_TIMEOUT)
    if ver != SOCKS_VERSION:
        return None
    methods = await asyncio.wait_for(reader.readexactly(nmethods), HANDSHAKE_TIMEOUT)
    if AUTH_USERPASS not in methods:
        writer.write(bytes([SOCKS_VERSION, AUTH_NONE_ACCEPTABLE]))
        await writer.drain()
        return None

    writer.write(bytes([SOCKS_VERSION, AUTH_USERPASS]))
    await writer.drain()

    auth_ver, ulen = await asyncio.wait_for(reader.readexactly(2), HANDSHAKE_TIMEOUT)
    if auth_ver != AUTH_USERPASS_VERSION:
        writer.write(bytes([AUTH_USERPASS_VERSION, AUTH_FAIL]))
        await writer.drain()
        return None

    uname_b = await asyncio.wait_for(reader.readexactly(ulen), HANDSHAKE_TIMEOUT)
    (plen,) = await asyncio.wait_for(reader.readexactly(1), HANDSHAKE_TIMEOUT)
    passwd_b = await asyncio.wait_for(reader.readexactly(plen), HANDSHAKE_TIMEOUT)

    username = uname_b.decode("utf-8", "replace")
    password = passwd_b.decode("utf-8", "replace")
    user = users.get(username)
    valid_user = (
        isinstance(user, dict)
        and isinstance(user.get("password"), str)
        and user["password"] != ""
    )
    expected = user["password"] if valid_user else "\x00"
    pw_ok = hmac.compare_digest(expected, password)
    if not (valid_user and pw_ok):
        writer.write(bytes([AUTH_USERPASS_VERSION, AUTH_FAIL]))
        await writer.drain()
        return None

    writer.write(bytes([AUTH_USERPASS_VERSION, AUTH_OK]))
    await writer.drain()
    return int(user.get("mark") or 0)


async def _read_request(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> tuple[str, int] | None:
    ver, cmd, _rsv, atyp = await asyncio.wait_for(reader.readexactly(4), HANDSHAKE_TIMEOUT)
    if ver != SOCKS_VERSION:
        return None

    if atyp == ATYP_IPV4:
        raw_ip = await asyncio.wait_for(reader.readexactly(4), HANDSHAKE_TIMEOUT)
        host = socket.inet_ntoa(raw_ip)
    elif atyp == ATYP_DOMAIN:
        (dlen,) = await asyncio.wait_for(reader.readexactly(1), HANDSHAKE_TIMEOUT)
        domain_b = await asyncio.wait_for(reader.readexactly(dlen), HANDSHAKE_TIMEOUT)
        host = domain_b.decode("ascii", "replace")
    elif atyp == ATYP_IPV6:
        raw_ip6 = await asyncio.wait_for(reader.readexactly(16), HANDSHAKE_TIMEOUT)
        host = socket.inet_ntop(socket.AF_INET6, raw_ip6)
    else:
        writer.write(_socks_reply(REP_ATYP_NOT_SUPPORTED))
        await writer.drain()
        return None

    port = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), HANDSHAKE_TIMEOUT))[0]
    if cmd != CMD_CONNECT:
        writer.write(_socks_reply(REP_CMD_NOT_SUPPORTED))
        await writer.drain()
        return None

    return host, port


async def handle_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, state_ref: Any
) -> None:
    remote_writer: asyncio.StreamWriter | None = None
    try:
        users = state_ref.users if hasattr(state_ref, "users") else state_ref.get("users", {})
        mark = await _negotiate_auth(reader, writer, users)
        if mark is None:
            return

        req = await _read_request(reader, writer)
        if req is None:
            return
        host, port = req

        try:
            remote_reader, remote_writer = await _open_outbound(host, port, mark)
        except _BlockedTargetError:
            writer.write(_socks_reply(REP_NOT_ALLOWED))
            await writer.drain()
            return
        except ConnectionRefusedError:
            writer.write(_socks_reply(REP_CONN_REFUSED))
            await writer.drain()
            return
        except (TimeoutError, asyncio.TimeoutError):
            writer.write(_socks_reply(REP_HOST_UNREACHABLE))
            await writer.drain()
            return
        except OSError:
            writer.write(_socks_reply(REP_GENERAL_FAILURE))
            await writer.drain()
            return

        bind_addr = remote_writer.get_extra_info("sockname")
        writer.write(_socks_reply(REP_OK, bind_addr))
        await writer.drain()

        await asyncio.gather(
            relay(reader, remote_writer),
            relay(remote_reader, writer),
            return_exceptions=True,
        )
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        pass
    finally:
        _close_writer(remote_writer)
        _close_writer(writer)


class SocksProxy:
    """Asyncio SOCKS5 server daemon with SIGHUP config reload."""

    def __init__(self, cfg_path: str) -> None:
        self.cfg_path = cfg_path
        self.cfg: dict[str, Any] = {}
        self.listen = "0.0.0.0"
        self.port = 1080
        self.users: dict[str, dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        cfg = load_config(self.cfg_path)
        self.cfg = cfg
        self.listen = cfg["listen"]
        self.port = cfg["port"]
        self.users = cfg["users"]

    def on_hup(self) -> None:
        try:
            self.reload()
            log(f"reloaded config: {len(self.users)} users")
        except Exception as exc:  # noqa: BLE001
            log(f"reload failed: {exc}")

    async def serve(self) -> None:
        loop = asyncio.get_running_loop()
        server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, self),
            self.listen,
            self.port,
            reuse_address=True,
        )
        stop = asyncio.Event()
        loop.add_signal_handler(signal.SIGHUP, self.on_hup)
        loop.add_signal_handler(signal.SIGTERM, stop.set)
        loop.add_signal_handler(signal.SIGINT, stop.set)
        log(f"listening on {self.listen}:{self.port}, {len(self.users)} users")
        try:
            await stop.wait()
        finally:
            server.close()
            await server.wait_closed()


SocksProxyServer = SocksProxy


async def main(cfg_path: str) -> None:
    proxy = SocksProxy(cfg_path)
    await proxy.serve()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
