"""Inbound SOCKS5 proxy daemon (RFC 1928 + RFC 1929 + SO_MARK). Stdlib only."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import signal
import socket
import struct
import sys
import time
from typing import Any

SO_MARK = getattr(socket, "SO_MARK", 36)
HANDSHAKE_TIMEOUT = 10.0
CONNECT_TIMEOUT = 10.0
RELAY_IDLE_TIMEOUT = 300.0
RELAY_BUF = 65536
MAX_CLIENTS = 512
MAX_CONNS_PER_IP = 64
AUTH_FAIL_WINDOW = 300.0
AUTH_FAIL_MAX = 10
AUTH_BAN_SECS = 300.0
_DRY_RUN_VALUES = ("1", "true", "yes", "on")

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


def _parse_blocked_ips(raw: Any) -> frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    out: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for item in raw or ():
        try:
            addr = ipaddress.ip_address(str(item))
        except ValueError:
            continue
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        out.add(addr)
    return frozenset(out)


def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return {
        "listen": str(raw.get("listen") or "0.0.0.0"),
        "port": int(raw.get("port") or 1080),
        "users": dict(raw.get("users") or {}),
        "blocked_ips": _parse_blocked_ips(raw.get("blocked_ips")),
        "dns_servers": [str(x) for x in (raw.get("dns_servers") or []) if isinstance(x, str)],
    }


def is_blocked_ip(
    ip: str,
    extra_blocked: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] | None = None,
) -> bool:
    """Return True for non-global (loopback, private, CGNAT, link-local, unspecified, reserved), multicast, host-owned, or invalid IPs."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if extra_blocked and addr in extra_blocked:
        return True
    return (not addr.is_global) or addr.is_multicast


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


class _AuthLimiter:
    """Per-IP sliding-window brute-force limiter."""

    def __init__(
        self,
        max_fails: int = AUTH_FAIL_MAX,
        window: float = AUTH_FAIL_WINDOW,
        ban_secs: float = AUTH_BAN_SECS,
    ) -> None:
        self.max_fails = max_fails
        self.window = window
        self.ban_secs = ban_secs
        self._fails: dict[str, list[float]] = {}
        self._banned: dict[str, float] = {}

    def _prune(self, now: float) -> None:
        if len(self._banned) > 4096:
            self._banned = {k: v for k, v in self._banned.items() if v > now}
        if len(self._fails) > 4096:
            cutoff = now - self.window
            self._fails = {
                k: [t for t in ts if t > cutoff]
                for k, ts in self._fails.items()
                if any(t > cutoff for t in ts)
            }

    def is_banned(self, ip: str) -> bool:
        if not ip:
            return False
        now = time.monotonic()
        until = self._banned.get(ip)
        if until is None:
            return False
        if until > now:
            return True
        del self._banned[ip]
        return False

    def record_failure(self, ip: str) -> bool:
        """Record a failed auth attempt; returns True if this triggered a ban."""
        if not ip:
            return False
        now = time.monotonic()
        self._prune(now)
        cutoff = now - self.window
        ts = [t for t in self._fails.get(ip, []) if t > cutoff]
        ts.append(now)
        if len(ts) >= self.max_fails:
            self._fails.pop(ip, None)
            self._banned[ip] = now + self.ban_secs
            return True
        self._fails[ip] = ts
        return False

    def record_success(self, ip: str) -> None:
        if ip:
            self._fails.pop(ip, None)


def _skip_dns_name(pkt: bytes, off: int) -> int:
    while off < len(pkt):
        ln = pkt[off]
        if ln == 0:
            return off + 1
        if (ln & 0xC0) == 0xC0:
            return off + 2
        off += 1 + ln
    raise OSError("truncated DNS name")


def _parse_dns_a_response(pkt: bytes, qid: bytes) -> list[str]:
    if len(pkt) < 12 or pkt[:2] != qid:
        raise OSError("invalid DNS response")
    qdcount, ancount = struct.unpack("!HH", pkt[4:8])
    off = 12
    for _ in range(qdcount):
        off = _skip_dns_name(pkt, off) + 4
    ips: list[str] = []
    for _ in range(ancount):
        off = _skip_dns_name(pkt, off)
        if off + 10 > len(pkt):
            break
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", pkt[off : off + 10])
        off += 10
        if off + rdlen > len(pkt):
            break
        if rtype == 1 and rclass == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(pkt[off : off + 4]))
        off += rdlen
    return ips


async def _resolve_marked(
    host: str, port: int, mark: int, dns_servers: list[str]
) -> list[tuple[Any, ...]]:
    """Resolve A records over a SO_MARK-tagged UDP socket so tunneled DNS does not leak."""
    labels = host.rstrip(".").split(".")
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in labels if p) + b"\x00"
    loop = asyncio.get_running_loop()
    dry_run = os.environ.get("DRY_RUN", "").strip().lower() in _DRY_RUN_VALUES
    last_err: Exception | None = None
    for srv in dns_servers:
        qid = secrets.token_bytes(2)
        pkt = qid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
        sock: socket.socket | None = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            if mark > 0:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
                except OSError:
                    if not dry_run and sys.platform == "linux":
                        raise
            await asyncio.wait_for(loop.sock_connect(sock, (srv, 53)), CONNECT_TIMEOUT)
            await asyncio.wait_for(loop.sock_sendall(sock, pkt), CONNECT_TIMEOUT)
            resp = await asyncio.wait_for(loop.sock_recv(sock, 4096), CONNECT_TIMEOUT)
            ips = _parse_dns_a_response(resp, qid)
            if ips:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]
        except (OSError, TimeoutError, UnicodeEncodeError) as exc:
            last_err = exc
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    if last_err is not None:
        raise last_err
    raise OSError(f"DNS resolution failed for {host}")


async def _open_outbound(
    host: str,
    port: int,
    mark: int,
    blocked_ips: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] | None = None,
    dns_servers: list[str] | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if mark < 0:
        raise _BlockedTargetError("outbound exit is blocked")

    literal_addr = None
    try:
        literal_addr = ipaddress.ip_address(host)
    except ValueError:
        pass

    if mark > 0 and literal_addr is not None and literal_addr.version == 6:
        raise _BlockedTargetError("IPv6 is not supported for tunneled exits")

    loop = asyncio.get_running_loop()
    if mark > 0 and literal_addr is None and dns_servers:
        infos = await _resolve_marked(host, port, mark, dns_servers)
    else:
        family = socket.AF_INET if mark > 0 else 0
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM),
            CONNECT_TIMEOUT,
        )
    if not infos:
        raise OSError(f"getaddrinfo returned no results for {host}:{port}")

    for info in infos:
        if is_blocked_ip(info[4][0], blocked_ips):
            raise _BlockedTargetError(f"blocked target IP: {info[4][0]}")

    last_err: Exception | None = None
    dry_run = os.environ.get("DRY_RUN", "").strip().lower() in _DRY_RUN_VALUES
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
        except (OSError, TimeoutError) as exc:
            last_err = exc
        finally:
            if not connected and sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    if last_err is not None:
        raise last_err
    raise OSError(f"failed to connect to {host}:{port}")


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await asyncio.wait_for(reader.read(RELAY_BUF), RELAY_IDLE_TIMEOUT)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except asyncio.CancelledError:
        _close_writer(writer)
        raise
    except (OSError, TimeoutError):
        _close_writer(writer)


async def _negotiate_auth(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    users: dict[str, dict[str, Any]],
    peer_ip: str = "",
    limiter: _AuthLimiter | None = None,
) -> int | None:
    if limiter and limiter.is_banned(peer_ip):
        return None
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
    user = users.get(username)
    valid_user = (
        isinstance(user, dict)
        and isinstance(user.get("password"), str)
        and user["password"] != ""
    )
    expected_b = user["password"].encode("utf-8") if valid_user else b"\x00"
    pw_ok = hmac.compare_digest(
        hashlib.sha256(expected_b).digest(),
        hashlib.sha256(passwd_b).digest(),
    )
    if not (valid_user and pw_ok):
        if limiter and limiter.record_failure(peer_ip):
            log(f"banned {peer_ip} after {limiter.max_fails} failed auth attempts")
        else:
            log(f"auth failed from {peer_ip or '?'} for user {username!r}")
        writer.write(bytes([AUTH_USERPASS_VERSION, AUTH_FAIL]))
        await writer.drain()
        return None

    if limiter:
        limiter.record_success(peer_ip)
    writer.write(bytes([AUTH_USERPASS_VERSION, AUTH_OK]))
    await writer.drain()
    raw_mark = user.get("mark")
    return int(raw_mark) if raw_mark is not None else 0


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
        blocked_ips = (
            state_ref.blocked_ips
            if hasattr(state_ref, "blocked_ips")
            else _parse_blocked_ips(state_ref.get("blocked_ips"))
        )
        dns_servers = (
            state_ref.dns_servers
            if hasattr(state_ref, "dns_servers")
            else list(state_ref.get("dns_servers") or [])
        )
        limiter = getattr(state_ref, "auth_limiter", None)
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if isinstance(peer, tuple) and peer else ""
        async with asyncio.timeout(HANDSHAKE_TIMEOUT):
            mark = await _negotiate_auth(reader, writer, users, peer_ip=peer_ip, limiter=limiter)
            if mark is None:
                return

            req = await _read_request(reader, writer)
            if req is None:
                return
        host, port = req

        try:
            remote_reader, remote_writer = await _open_outbound(
                host, port, mark, blocked_ips=blocked_ips, dns_servers=dns_servers
            )
        except _BlockedTargetError:
            writer.write(_socks_reply(REP_NOT_ALLOWED))
            await writer.drain()
            return
        except ConnectionRefusedError:
            writer.write(_socks_reply(REP_CONN_REFUSED))
            await writer.drain()
            return
        except TimeoutError:
            writer.write(_socks_reply(REP_HOST_UNREACHABLE))
            await writer.drain()
            return
        except OSError:
            writer.write(_socks_reply(REP_GENERAL_FAILURE))
            await writer.drain()
            return

        writer.write(_socks_reply(REP_OK))
        await writer.drain()

        tasks = (
            asyncio.create_task(relay(reader, remote_writer)),
            asyncio.create_task(relay(remote_reader, writer)),
        )
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    except (asyncio.IncompleteReadError, TimeoutError, OSError):
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
        self.blocked_ips: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] = frozenset()
        self.dns_servers: list[str] = []
        self.auth_limiter = _AuthLimiter()
        self.reload()

    def reload(self) -> None:
        cfg = load_config(self.cfg_path)
        self.cfg = cfg
        self.listen = cfg["listen"]
        self.port = cfg["port"]
        self.users = cfg["users"]
        self.blocked_ips = cfg["blocked_ips"]
        self.dns_servers = cfg["dns_servers"]

    def on_hup(self) -> None:
        try:
            self.reload()
            log(f"reloaded config: {len(self.users)} users")
        except Exception as exc:  # noqa: BLE001
            log(f"reload failed: {exc}")

    async def serve(self) -> None:
        loop = asyncio.get_running_loop()
        tasks: set[asyncio.Task[Any]] = set()
        ip_conns: dict[str, int] = {}

        def _on_connect(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            peer = w.get_extra_info("peername")
            peer_ip = peer[0] if isinstance(peer, tuple) and peer else ""
            if len(tasks) >= MAX_CLIENTS or self.auth_limiter.is_banned(peer_ip):
                _close_writer(w)
                return
            if peer_ip and ip_conns.get(peer_ip, 0) >= MAX_CONNS_PER_IP:
                _close_writer(w)
                return
            if peer_ip:
                ip_conns[peer_ip] = ip_conns.get(peer_ip, 0) + 1

            def _done(t: asyncio.Task[Any]) -> None:
                tasks.discard(t)
                if peer_ip:
                    cnt = ip_conns.get(peer_ip, 1) - 1
                    if cnt <= 0:
                        ip_conns.pop(peer_ip, None)
                    else:
                        ip_conns[peer_ip] = cnt

            task = asyncio.create_task(handle_client(r, w, self))
            tasks.add(task)
            task.add_done_callback(_done)

        server = await asyncio.start_server(
            _on_connect,
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
            for task in list(tasks):
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            await server.wait_closed()


SocksProxyServer = SocksProxy


async def main(cfg_path: str) -> None:
    proxy = SocksProxy(cfg_path)
    await proxy.serve()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
