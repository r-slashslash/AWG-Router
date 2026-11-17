"""Исходящие соединения прокси только через заданный интерфейс выхода Linux."""
from __future__ import annotations

import ipaddress
import secrets
import socket

from . import proxy_auth, tgreq


def bound_socket(interface: str, mark: int, kind: int) -> socket.socket:
    """Привязка обязательна: отсутствие интерфейса или прав не даёт открыть сокет."""
    if not interface or len(interface.encode()) > 15 or not 0 < mark <= 0xffffffff:
        raise ValueError("invalid exit interface or mark")
    s = socket.socket(socket.AF_INET, kind)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
        s.setsockopt(socket.SOL_SOCKET, tgreq.SO_MARK, mark)
        return s
    except BaseException:
        s.close()
        raise


def resolve(host: str, interface: str, mark: int, timeout: float = 4, forbidden=()) -> list[str]:
    """DNS тоже идёт через выход. Частные ответы не попадают в список адресов."""
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if parsed.version != 4 or not proxy_auth.public_address(host) or str(parsed) in forbidden:
            raise ValueError("non-public address")
        return [host]
    for server in tgreq.DNS_SERVERS:
        qid = secrets.randbelow(65536)
        try:
            with bound_socket(interface, mark, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((server, 53))
                s.send(tgreq.dns_query(host, qid))
                addresses = tgreq.dns_answer(s.recv(4096), qid)
            # Смешанный ответ тоже блокируется: иначе можно обойти проверку через DNS rebinding.
            if addresses and all(proxy_auth.public_address(ip) and ip not in forbidden for ip in addresses):
                return addresses
            if addresses:
                raise ValueError("DNS returned a non-public address")
        except OSError:
            continue
    raise OSError("DNS unavailable through selected exit")


def connect(host: str, port: int, interface: str, mark: int, timeout: float = 10, forbidden=()) -> socket.socket:
    """Открыть TCP по заранее проверенному адресу. Прямого повтора нет."""
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    for address in resolve(host, interface, mark, timeout=min(timeout, 4), forbidden=forbidden):
        s = None
        try:
            s = bound_socket(interface, mark, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((address, port))
            return s
        except OSError:
            if s is not None:
                s.close()
            continue
    raise OSError("connection unavailable through selected exit")
