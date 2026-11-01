"""Выходы через прокси SOCKS5.

Трафик клиентов в SOCKS5 переводит hev-socks5-tunnel (MIT, github.com/heiher/hev-socks5-tunnel):
он создаёт в сети сервера AWG интерфейс awgrN (TUN) и всё, что в него попадает, отправляет
через прокси — TCP командой CONNECT, UDP через UDP ASSOCIATE. Дальше всё как у выходов AWG:
метка fwmark → своя таблица маршрутизации → default dev awgrN. Собственные соединения
hev-socks5-tunnel к прокси без метки и идут напрямую, поэтому в петлю не попадают.

Здоровье выхода: раз в минуту панель подключается к прокси сама, проходит вход по логину
и просит соединение с 1.1.1.1:443 (или 8.8.8.8:443). Ответ «успешно» — выход работает.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import time

from .i18n import Msg

HEV = "hev-socks5-tunnel"
CHECK_TARGETS = (("1.1.1.1", 443), ("8.8.8.8", 443))
CHECK_EVERY = 60
CHECK_FRESH = 200           # результат проверки старше — выход считается неработающим

REPLY = {1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable",
         4: "host unreachable", 5: "connection refused", 6: "TTL expired",
         7: "command not supported", 8: "address type not supported"}


def resolve(host: str) -> str:
    """Адрес прокси для hev-socks5-tunnel (имя он не разрешает): IPv4, если есть."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        return infos[0][4][0]
    except OSError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET6, socket.SOCK_STREAM)
        return infos[0][4][0]
    except OSError:
        raise SocksError(Msg("socks.resolve", host=host)) from None


def _yq(s: str) -> str:
    """Строка для YAML в одинарных кавычках."""
    return "'" + str(s).replace("'", "''") + "'"


def hev_config(iface: str, num: int, server_ip: str, s: dict) -> str:
    lines = [
        "tunnel:",
        f"  name: {_yq(iface)}",
        "  mtu: 8500",
        f"  ipv4: {_yq(f'169.254.200.{num}')}",
        "socks5:",
        f"  address: {_yq(server_ip)}",
        f"  port: {int(s['port'])}",
        "  udp: 'udp'",
    ]
    if s.get("user"):
        lines += [f"  username: {_yq(s['user'])}", f"  password: {_yq(s.get('password', ''))}"]
    lines += ["misc:", "  log-level: warn", "  connect-timeout: 10000", "  limit-nofile: 65535"]
    return "\n".join(lines) + "\n"


class SocksError(Exception):
    def __init__(self, msg: Msg):
        super().__init__(str(msg))
        self.msg = msg


def _recv(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise SocksError(Msg("socks.closed"))
        buf += chunk
    return buf


def connect_check(host: str, port: int, user: str = "", password: str = "",
                  target: tuple[str, int] = CHECK_TARGETS[0], timeout: float = 8) -> float:
    """Вход на прокси и CONNECT к target. Возвращает время в мс или бросает SocksError."""
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        raise SocksError(Msg("socks.unreachable", error=str(e)[:120])) from None
    try:
        s.settimeout(timeout)
        methods = b"\x00\x02" if user else b"\x00"
        s.sendall(b"\x05" + bytes([len(methods)]) + methods)
        ver, method = _recv(s, 2)
        if ver != 5:
            raise SocksError(Msg("socks.not_socks5"))
        if method == 0xFF:
            raise SocksError(Msg("socks.auth_required" if not user else "socks.auth_failed"))
        if method == 0x02:
            u, p = user.encode(), password.encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            if _recv(s, 2)[1] != 0:
                raise SocksError(Msg("socks.auth_failed"))
        elif method != 0x00:
            raise SocksError(Msg("socks.not_socks5"))
        ip, tport = target
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack("!H", tport))
        head = _recv(s, 4)
        if head[1] != 0:
            raise SocksError(Msg("socks.connect_failed", code=head[1], reason=REPLY.get(head[1], "?")))
        atyp = head[3]
        _recv(s, {1: 4, 4: 16}.get(atyp) or _recv(s, 1)[0])
        _recv(s, 2)
        return round((time.monotonic() - t0) * 1000)
    except socket.timeout:
        raise SocksError(Msg("socks.timeout")) from None
    except SocksError:
        raise
    except OSError as e:
        raise SocksError(Msg("socks.unreachable", error=str(e)[:120])) from None
    finally:
        s.close()


def check(conf: dict) -> dict:
    """Проверка выхода: {"ok", "ms", "error", "at"}. Успех — если ответила хоть одна цель."""
    err = None
    for target in CHECK_TARGETS:
        try:
            ms = connect_check(conf["host"], conf["port"], conf.get("user", ""),
                               conf.get("password", ""), target)
            return {"ok": True, "ms": ms, "error": None, "at": time.time()}
        except SocksError as e:
            err = e.msg
            if e.msg.key in ("socks.unreachable", "socks.not_socks5", "socks.auth_failed",
                             "socks.auth_required", "socks.timeout"):
                break                       # до второй цели дело не дойдёт: прокси сам не пускает
    return {"ok": False, "ms": None, "error": err, "at": time.time()}
