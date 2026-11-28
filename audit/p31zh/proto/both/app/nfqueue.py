"""Очередь пакетов ядра (NFQUEUE, nfnetlink_queue) на сокете netlink. Только стандартная
библиотека, без импорта панели и без libnetfilter_queue: сообщения собираются вручную.

Правило nftables `queue num N bypass` отдаёт пакет сюда; программа отвечает вердиктом — принять
(можно со своей меткой пакета) или отбросить. Пока ответа нет, пакет держит ядро. Флаг
FAIL_OPEN: переполненная очередь пропускает пакеты дальше, а не отбрасывает; bypass в правиле —
то же, когда очередь никто не слушает. Дальше пакет идёт по следующим цепочкам с той меткой,
которую дал вердикт.

Формат — linux/netfilter/nfnetlink_queue.h: nlmsghdr, nfgenmsg (семейство, версия, номер очереди
в порядке сети), затем атрибуты (длина, тип, данные с выравниванием на 4).
"""
from __future__ import annotations

import os
import socket
import struct

NETLINK_NETFILTER = 12
SOL_NETLINK = 270
NETLINK_NO_ENOBUFS = 5
NFNL_SUBSYS_QUEUE = 3
NFQNL_MSG_PACKET, NFQNL_MSG_VERDICT, NFQNL_MSG_CONFIG = 0, 1, 2
NLM_F_REQUEST, NLM_F_ACK = 1, 4
NLMSG_ERROR = 2
NFQA_PACKET_HDR, NFQA_VERDICT_HDR, NFQA_MARK, NFQA_PAYLOAD = 1, 2, 3, 10
NFQA_CFG_CMD, NFQA_CFG_PARAMS, NFQA_CFG_QUEUE_MAXLEN, NFQA_CFG_MASK, NFQA_CFG_FLAGS = 1, 2, 3, 4, 5
NFQNL_CFG_CMD_BIND, NFQNL_CFG_CMD_UNBIND = 1, 2
NFQNL_COPY_PACKET = 2
NFQA_CFG_F_FAIL_OPEN = 1
NF_DROP, NF_ACCEPT = 0, 1


class QueueError(OSError):
    pass


def _attr(t: int, data: bytes) -> bytes:
    a = struct.pack("=HH", 4 + len(data), t) + data
    return a + b"\x00" * (-len(a) % 4)


def _attrs(b: bytes, p: int) -> dict[int, bytes]:
    out = {}
    while p + 4 <= len(b):
        ln, t = struct.unpack_from("=HH", b, p)
        if ln < 4:
            break
        out[t & 0x3FFF] = b[p + 4:p + ln]
        p += (ln + 3) & ~3
    return out


class Queue:
    """Очередь номер num. fileno() — для цикла событий; read() → [(id, пакет IP)];
    verdict(id, accept, mark) — ответ."""

    def __init__(self, num: int, maxlen: int = 2048, copy: int = 0xFFFF):
        self.num = num
        self.seq = 0
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
            try:
                self.sock.setsockopt(SOL_NETLINK, NETLINK_NO_ENOBUFS, 1)
            except OSError:
                pass
            self.sock.bind((0, 0))
            self._config(_attr(NFQA_CFG_CMD, struct.pack("!BxH", NFQNL_CFG_CMD_BIND, 0)))
            self._config(_attr(NFQA_CFG_PARAMS, struct.pack("!IB", copy, NFQNL_COPY_PACKET))
                         + _attr(NFQA_CFG_QUEUE_MAXLEN, struct.pack("!I", maxlen)))
            try:
                self._config(_attr(NFQA_CFG_MASK, struct.pack("!I", NFQA_CFG_F_FAIL_OPEN))
                             + _attr(NFQA_CFG_FLAGS, struct.pack("!I", NFQA_CFG_F_FAIL_OPEN)))
            except QueueError:
                pass                                    # старое ядро без флагов — без FAIL_OPEN
            self.sock.setblocking(False)
        except BaseException:
            self.sock.close()
            raise

    def fileno(self) -> int:
        return self.sock.fileno()

    def close(self) -> None:
        self.sock.close()

    def _msg(self, mtype: int, flags: int, body: bytes) -> bytes:
        self.seq += 1
        nf = struct.pack("!BBH", socket.AF_UNSPEC, 0, self.num)
        return struct.pack("=IHHII", 16 + len(nf) + len(body), (NFNL_SUBSYS_QUEUE << 8) | mtype,
                           NLM_F_REQUEST | flags, self.seq, 0) + nf + body

    def _config(self, body: bytes) -> None:
        """Настройка с подтверждением: ошибка ядра (нет модуля, очередь занята) → QueueError."""
        self.sock.send(self._msg(NFQNL_MSG_CONFIG, NLM_F_ACK, body))
        seq = self.seq
        while True:
            data = self.sock.recv(65536)
            p = 0
            while p + 16 <= len(data):
                ln, mtype, _fl, s, _pid = struct.unpack_from("=IHHII", data, p)
                if ln < 16:
                    return
                if mtype == NLMSG_ERROR and s == seq:
                    err = struct.unpack_from("=i", data, p + 16)[0]
                    if err:
                        raise QueueError(-err, os.strerror(-err))
                    return
                p += (ln + 3) & ~3

    def read(self) -> list[tuple[int, bytes]]:
        """Пакеты, которые уже пришли (сокет неблокирующий): [(id, пакет начиная с заголовка IP)]."""
        out = []
        while True:
            try:
                data = self.sock.recv(1 << 17)
            except (BlockingIOError, InterruptedError):
                return out
            p = 0
            while p + 16 <= len(data):
                ln, mtype, _fl, _s, _pid = struct.unpack_from("=IHHII", data, p)
                if ln < 16:
                    break
                if mtype == (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET:
                    a = _attrs(data[p:p + ln], 20)
                    hdr, payload = a.get(NFQA_PACKET_HDR), a.get(NFQA_PAYLOAD)
                    if hdr and payload is not None:
                        out.append((struct.unpack("!I", hdr[:4])[0], payload))
                p += (ln + 3) & ~3

    def verdict(self, pid: int, accept: bool = True, mark: int | None = None) -> None:
        body = _attr(NFQA_VERDICT_HDR, struct.pack("!II", NF_ACCEPT if accept else NF_DROP, pid))
        if mark is not None:
            body += _attr(NFQA_MARK, struct.pack("!I", mark))
        try:
            self.sock.send(self._msg(NFQNL_MSG_VERDICT, 0, body))
        except BlockingIOError:
            self.sock.setblocking(True)                 # буфер отправки полон: ждём, вердикт важнее
            try:
                self.sock.send(self._msg(NFQNL_MSG_VERDICT, 0, body))
            finally:
                self.sock.setblocking(False)


def udp_of(packet: bytes) -> tuple[str, int, str, int, bytes] | None:
    """Пакет IPv4 с UDP → (источник, порт, назначение, порт, данные UDP); иное — None."""
    if len(packet) < 28 or packet[0] >> 4 != 4 or packet[9] != 17:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if struct.unpack("!H", packet[6:8])[0] & 0x3FFF:
        return None                                     # фрагмент: первый пакет QUIC так не приходит
    sport, dport, ulen = struct.unpack("!HHH", packet[ihl:ihl + 6])
    return (socket.inet_ntoa(packet[12:16]), sport, socket.inet_ntoa(packet[16:20]), dport,
            packet[ihl + 8:ihl + max(8, ulen)])
