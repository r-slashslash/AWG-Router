"""DNS-посредник для правил по доменам. Только стандартная библиотека, без импорта панели.

Запускается панелью в сети сервера AWG (как туннели выходов):
    nsenter -t PID -n -- python3 dnsproxy.py /run/awg-router/dns.json
Все DNS-запросы клиентов (UDP и TCP, порт 53, любой адрес) правило nftables перенаправляет
сюда. Запрос уходит на DNS из настроек сервера (с fwmark выхода, через который туда пошёл бы
и сам клиент: местный DNS часто подменяет ответы для заблокированных доменов). Если имя из
ответа (или из его цепочки CNAME) есть в каком-то списке доменов, адреса A из ответа
добавляются в набор nftables `l_<id>` с таймаутом — до того, как клиент получит ответ,
поэтому первое же соединение идёт по правилу. Повторный ответ продлевает срок.

Таблица правил пересоздаётся при любом изменении настроек, и наборы при этом пустеют:
панель после применения правил шлёт SIGHUP, и посредник заново кладёт в наборы всё, что
ещё не истекло (заодно перечитывает настройки и списки).

AAAA: в туннеле только IPv4, поэтому на запрос AAAA отвечаем «записей нет» — приложения
сразу идут по IPv4 и не ждут IPv6, который всё равно не пройдёт. Записи HTTPS/SVCB для
доменов из списков тоже не отдаём: в них бывают подсказки адресов (ipv4hint), по которым
браузер может подключиться в обход A-записи — а значит, и в обход набора.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import signal
import socket
import struct
import sys
import time

SO_MARK = 36
T_A, T_CNAME, T_AAAA, T_SVCB, T_HTTPS = 1, 5, 28, 64, 65
UPSTREAM_TIMEOUT = 2.5


# ------------------------------------------------------------ разбор DNS
class BadMessage(Exception):
    pass


def read_name(msg: bytes, off: int) -> tuple[str, int]:
    """Имя с учётом сжатия → (имя, смещение после имени в исходном месте)."""
    labels, end, jumps = [], None, 0
    while True:
        if off >= len(msg):
            raise BadMessage("name")
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise BadMessage("pointer")
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | msg[off + 1]
            jumps += 1
            if jumps > 32:
                raise BadMessage("loop")
            continue
        if n & 0xC0:
            raise BadMessage("label")
        off += 1
        labels.append(msg[off:off + n].decode("ascii", "replace").lower())
        off += n
    return ".".join(labels), (end if end is not None else off)


def question(msg: bytes) -> tuple[str, int, int]:
    """(имя, тип, смещение конца вопроса). Ровно один вопрос."""
    if len(msg) < 12:
        raise BadMessage("short")
    qd = struct.unpack("!H", msg[4:6])[0]
    if qd != 1:
        raise BadMessage("qdcount")
    name, off = read_name(msg, 12)
    if off + 4 > len(msg):
        raise BadMessage("question")
    qtype = struct.unpack("!H", msg[off:off + 2])[0]
    return name, qtype, off + 4


def answers(msg: bytes) -> tuple[set[str], list[str]]:
    """Ответ → (все имена из секции ответов, включая цели CNAME; адреса A)."""
    _, _, off = question(msg)
    an = struct.unpack("!H", msg[6:8])[0]
    names, ips = set(), []
    for _ in range(an):
        name, off = read_name(msg, off)
        if off + 10 > len(msg):
            raise BadMessage("rr")
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        if off + rdlen > len(msg):
            raise BadMessage("rdata")
        names.add(name)
        if rtype == T_A and rdlen == 4:
            ips.append(socket.inet_ntoa(msg[off:off + 4]))
        elif rtype == T_CNAME:
            names.add(read_name(msg, off)[0])
        off += rdlen
    return names, ips


def empty_reply(query: bytes, rcode: int = 0) -> bytes:
    """Ответ без записей на этот же вопрос (NOERROR или код ошибки)."""
    _, _, qend = question(query)
    qid, flags = struct.unpack("!HH", query[:4])
    flags = 0x8000 | (flags & 0x7900) | 0x0080 | (rcode & 0xF)   # QR, opcode+RD, RA, RCODE
    return struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0) + query[12:qend]


def match(name: str, lists: dict[str, set[str]]) -> list[str]:
    labels = name.strip(".").split(".")
    hit = []
    for lid, doms in lists.items():
        if any(".".join(labels[i:]) in doms for i in range(len(labels))):
            hit.append(lid)
    return hit


# ------------------------------------------------------------- посредник
class Proxy:
    def __init__(self, path: str):
        self.path = path
        self.cfg: dict = {}
        self.lists: dict[str, set[str]] = {}
        self.live: dict[tuple[str, str], float] = {}     # (список, IP) → когда истечёт
        self.nft_lock = asyncio.Lock()
        self.stats = {"queries": 0, "matched": 0, "upstream_errors": 0, "nft_errors": 0,
                      "started": time.time()}
        self.reload()

    # ---------------------------------------------------------- настройки
    def reload(self) -> None:
        with open(self.path) as f:
            cfg = json.load(f)
        lists = {}
        for lid, p in (cfg.get("lists") or {}).items():
            try:
                with open(p) as f:
                    lists[lid] = {x.strip() for x in f if x.strip()}
            except OSError as e:
                log(f"list {lid}: {e}")
        self.cfg = cfg
        self.lists = lists
        self.net = ipaddress.ip_network(cfg.get("clients") or "0.0.0.0/0", strict=False)
        self.live = {k: v for k, v in self.live.items() if k[0] in lists}

    @property
    def timeout(self) -> int:
        return int(self.cfg.get("timeout") or 43200)

    # ------------------------------------------------------------ nftables
    async def nft(self, script: str) -> bool:
        p = await asyncio.create_subprocess_exec(
            "nft", "-f", "-", stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, err = await p.communicate(script.encode())
        if p.returncode != 0:
            log("nft: " + err.decode(errors="replace").strip()[:300])
        return p.returncode == 0

    def _elem(self, op: str, lid: str, ips: list[str], timeout: int | None = None) -> str:
        t = self.cfg.get("table") or "awgr"
        items = ", ".join(f"{ip} timeout {timeout}s" if timeout else ip for ip in ips)
        return f"{op} element ip {t} l_{lid} {{ {items} }}\n"

    async def add(self, by_list: dict[str, list[str]]) -> None:
        """Положить адреса в наборы. Свежие пропускаем; почти истёкшие — удалить и добавить
        заново (add у существующего элемента его срок не продлевает)."""
        now = time.time()
        tmo = self.timeout
        dels, adds = [], []
        for lid, ips in by_list.items():
            new, renew = [], []
            for ip in dict.fromkeys(ips):
                exp = self.live.get((lid, ip))
                if exp is None or exp <= now:
                    new.append(ip)
                elif exp - now < tmo / 2:
                    renew.append(ip)
            if renew:
                dels.append(self._elem("delete", lid, renew))
            if new or renew:
                adds.append(self._elem("add", lid, new + renew, tmo))
            for ip in new + renew:
                self.live[(lid, ip)] = now + tmo
        if not adds:
            return
        async with self.nft_lock:
            ok = await self.nft("".join(dels + adds))
            if not ok and dels:
                ok = await self.nft("".join(adds))     # кто-то из «живых» уже истёк сам
        if not ok:
            self.stats["nft_errors"] += 1

    async def resync(self) -> None:
        """После пересоздания таблицы: вернуть в наборы всё, что ещё не истекло."""
        now = time.time()
        by_list: dict[str, list[tuple[str, int]]] = {}
        for (lid, ip), exp in list(self.live.items()):
            if exp - now < 30:
                self.live.pop((lid, ip), None)
                continue
            by_list.setdefault(lid, []).append((ip, int(exp - now)))
        async with self.nft_lock:
            for lid, items in by_list.items():
                for i in range(0, len(items), 2000):
                    part = items[i:i + 2000]
                    t = self.cfg.get("table") or "awgr"
                    body = ", ".join(f"{ip} timeout {sec}s" for ip, sec in part)
                    await self.nft(f"add element ip {t} l_{lid} {{ {body} }}\n")
        log(f"resync: {sum(len(v) for v in by_list.values())} addresses")

    # ------------------------------------------------------------- запросы
    async def upstream(self, query: bytes, tcp: bool) -> bytes:
        loop = asyncio.get_running_loop()
        last = None
        for u in self.cfg.get("upstreams") or [{"ip": "1.1.1.1"}]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
            try:
                if u.get("mark"):
                    s.setsockopt(socket.SOL_SOCKET, SO_MARK, int(u["mark"]))
                s.setblocking(False)
                addr = (u["ip"], int(u.get("port") or 53))
                if tcp:
                    await asyncio.wait_for(loop.sock_connect(s, addr), UPSTREAM_TIMEOUT)
                    await loop.sock_sendall(s, struct.pack("!H", len(query)) + query)
                    return await asyncio.wait_for(_read_tcp(loop, s), UPSTREAM_TIMEOUT * 2)
                await loop.sock_connect(s, addr)
                await loop.sock_sendall(s, query)
                qid = query[:2]
                deadline = loop.time() + UPSTREAM_TIMEOUT
                while True:
                    data = await asyncio.wait_for(loop.sock_recv(s, 65535),
                                                  max(0.05, deadline - loop.time()))
                    if data[:2] == qid:
                        return data
            except (OSError, asyncio.TimeoutError, BadMessage) as e:
                last = e
            finally:
                s.close()
        self.stats["upstream_errors"] += 1
        raise OSError(f"no upstream answered: {last!r}")

    async def handle(self, query: bytes, src: str, tcp: bool) -> bytes | None:
        try:
            if ipaddress.ip_address(src) not in self.net:
                return None
            name, qtype, _ = question(query)
        except (BadMessage, ValueError):
            return None
        self.stats["queries"] += 1
        if qtype == T_AAAA and self.cfg.get("strip_aaaa", True):
            return empty_reply(query)
        hit = match(name, self.lists) if self.lists else []
        if hit and qtype in (T_HTTPS, T_SVCB):
            return empty_reply(query)
        try:
            resp = await self.upstream(query, tcp)
        except OSError as e:
            log(str(e))
            return empty_reply(query, 2)                          # SERVFAIL
        if not self.lists or qtype != T_A and not hit:
            return resp
        try:
            names, ips = answers(resp)
        except BadMessage:
            return resp
        if not ips:
            return resp
        lids = set(hit)
        for n in names:
            lids.update(match(n, self.lists))
        if lids:
            self.stats["matched"] += 1
            await self.add({lid: ips for lid in lids})
        return resp

    # ------------------------------------------------------------- серверы
    async def serve(self) -> None:
        loop = asyncio.get_running_loop()
        host, port = self.cfg["listen"], int(self.cfg.get("port") or 10053)
        await loop.create_datagram_endpoint(lambda: UdpServer(self), local_addr=(host, port))
        await asyncio.start_server(self.tcp_client, host, port, reuse_address=True)
        loop.add_signal_handler(signal.SIGHUP, self.on_hup)
        loop.add_signal_handler(signal.SIGTERM, loop.stop)
        log(f"listening on {host}:{port}, {len(self.lists)} domain lists")
        while True:
            self.write_stats()
            self.live = {k: v for k, v in self.live.items() if v > time.time()}
            await asyncio.sleep(30)

    def on_hup(self) -> None:
        try:
            self.reload()
        except Exception as e:  # noqa: BLE001
            log(f"reload: {e}")
        asyncio.get_running_loop().create_task(self.resync())

    async def tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        src = (writer.get_extra_info("peername") or ("0.0.0.0",))[0]
        try:
            while True:
                n = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), 15))[0]
                q = await asyncio.wait_for(reader.readexactly(n), 15)
                r = await self.handle(q, src, True)
                if r is None:
                    break
                writer.write(struct.pack("!H", len(r)) + r)
                await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
            pass
        finally:
            writer.close()

    def write_stats(self) -> None:
        p = self.cfg.get("stats")
        if not p:
            return
        now = time.time()
        per: dict[str, int] = {}
        for (lid, _), exp in self.live.items():
            if exp > now:
                per[lid] = per.get(lid, 0) + 1
        try:
            with open(p + ".tmp", "w") as f:
                json.dump({**self.stats, "pid": os.getpid(), "at": now, "addresses": per}, f)
            os.replace(p + ".tmp", p)
        except OSError:
            pass


class UdpServer(asyncio.DatagramProtocol):
    def __init__(self, proxy: Proxy):
        self.proxy = proxy
        self.transport = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        asyncio.get_running_loop().create_task(self._answer(data, addr))

    async def _answer(self, data: bytes, addr) -> None:
        try:
            r = await self.proxy.handle(data, addr[0], False)
        except Exception as e:  # noqa: BLE001
            log(f"query: {e!r}")
            return
        if r is not None:
            # ответ по UDP не больше, чем позволил клиент (EDNS) — это сделал сам DNS-сервер;
            # если не влез, у него стоит флаг TC, и клиент повторит запрос по TCP
            self.transport.sendto(r, addr)


async def _read_tcp(loop, s) -> bytes:
    buf = b""
    while len(buf) < 2:
        chunk = await loop.sock_recv(s, 2 - len(buf))
        if not chunk:
            raise OSError("closed")
        buf += chunk
    n = struct.unpack("!H", buf)[0]
    out = b""
    while len(out) < n:
        chunk = await loop.sock_recv(s, n - len(out))
        if not chunk:
            raise OSError("closed")
        out += chunk
    return out


def log(text: str) -> None:
    print(time.strftime("%Y-%m-%d %H:%M:%S"), text, file=sys.stderr, flush=True)


def main() -> None:
    proxy = Proxy(sys.argv[1])
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    task = loop.create_task(proxy.serve())
    try:
        loop.run_forever()
    finally:
        task.cancel()
        proxy.write_stats()


if __name__ == "__main__":
    main()
