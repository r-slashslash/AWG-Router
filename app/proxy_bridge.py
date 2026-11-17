"""Создание сокета выхода в отдельном процессе с входом в сеть AWG."""
from __future__ import annotations

import array
import os
import re
import socket
import subprocess


def receive_socket(channel: socket.socket) -> socket.socket:
    fds = array.array("i")
    data, controls, flags, _ = channel.recvmsg(1, socket.CMSG_SPACE(fds.itemsize))
    found = []
    try:
        for level, kind, content in controls:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                ints = array.array("i")
                ints.frombytes(content[:len(content) - len(content) % ints.itemsize])
                found.extend(ints)
        if flags & socket.MSG_CTRUNC or data != b"1" or len(found) != 1:
            raise OSError("invalid worker response")
        sock = socket.socket(fileno=found.pop())
        sock.setblocking(False)
        return sock
    finally:
        for fd in found:
            os.close(fd)


def connect(pid: int, interface: str, mark: int, host: str, port: int, forbidden=()) -> socket.socket:
    """При сбое работника возвращает ошибку; прямое соединение не создаётся."""
    if not isinstance(pid, int) or pid <= 0 or not re.fullmatch(r"awgr[1-9][0-9]*", interface):
        raise ValueError("invalid target")
    parent, child = socket.socketpair()
    with parent, child:
        cmd = ["nsenter", "-t", str(pid), "-n", "--", "python3", "-m", "app.proxy_worker",
               str(child.fileno()), interface, str(mark), host, str(port)]
        if forbidden:
            cmd.append(",".join(forbidden))
        try:
            proc = subprocess.run(cmd, pass_fds=(child.fileno(),), stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=25, check=False)
        except subprocess.TimeoutExpired as exc:
            raise OSError("exit connection timed out") from exc
        if proc.returncode != 0:
            raise OSError("exit connection unavailable")
        parent.settimeout(2)
        return receive_socket(parent)
