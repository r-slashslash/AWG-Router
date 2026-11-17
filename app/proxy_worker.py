"""Открывает сокет в пространстве сети AWG и передаёт его процессу панели."""
from __future__ import annotations

import array
import socket
import sys

from . import proxy_socket


def main(args: list[str]) -> int:
    if len(args) not in (5, 6):
        return 2
    fd, iface, mark, host, port = args[:5]
    forbidden = args[5].split(",") if len(args) == 6 else ()
    try:
        with socket.socket(fileno=int(fd)) as channel:
            with proxy_socket.connect(host, int(port), iface, int(mark), forbidden=forbidden) as conn:
                fds = array.array("i", [conn.fileno()])
                channel.sendmsg([b"1"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
        return 0
    except (OSError, ValueError):
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
