"""DNS панели для клиентов. Только стандартная библиотека, без импорта панели.

Запускается панелью в сети сервера AWG (как туннели выходов и sniproxy.py):
    nsenter -t PID -n -- python3 dnsproxy.py /run/awgr/dns.json
Слушает UDP и TCP 53 на адресе сервера в туннеле. Клиенты получают этот адрес в строке DNS
своего конфига. Запрос клиента пересылается серверам DNS из настроек (рекурсией занимаются
они) — тем же путём, что и трафик этого клиента: сокет получает метку (fwmark) его основного
выхода, поэтому запрос уходит через туннель выхода, а ответ получен в стране выхода. Клиент,
который ходит напрямую, получает ответ, полученный напрямую с этого сервера; клиент с блоком —
отказ (REFUSED).

Ответы кэшируются отдельно для каждого пути (ответы CDN зависят от страны) на срок их TTL,
отдаются с уменьшенным TTL.

Шифрование (настройка encrypt): «doh» — DNS поверх HTTPS (порт 443, RFC 8484), «dot» — поверх TLS
(порт 853, RFC 7858), «plain» — без шифрования. С шифрованием сертификат сервера проверяется (по имени
сервиса для известных адресов — KNOWN_NAMES — или по IP-адресу), открытый DNS вместо него не
используется: сервер не ответил — клиент получает SERVFAIL и спрашивает второй DNS из конфига.
TLS-соединения держатся открытыми (пул на пару «путь, сервер»), чтобы не делать рукопожатие на
каждый запрос. Без шифрования через выходы SOCKS5 запросы идут по TCP (UDP через прокси часто не
работает), иначе — UDP, а при обрезанном ответе — TCP.

SIGHUP — перечитать настройки. Счётчики — в файл stats раз в 15 секунд (по свежести файла
панель видит, что процесс не завис).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import random
import signal
import socket
import ssl
import struct
import sys
import time

SO_MARK = 36
PORT = 53
UDP_TIMEOUT = 2.0           # ждём ответа сервера по UDP, потом следующий сервер
TCP_TIMEOUT = 5.0
CLIENT_TCP_IDLE = 10.0      # соединение клиента по TCP без новых запросов дольше — закрываем
CACHE_MAX = 20000           # записей в кэше; старые вытесняются
TTL_MAX = 3600              # дольше часа не храним, даже если TTL больше
NEG_TTL_MAX = 300           # «нет такого имени» / «нет записей» — не дольше 5 минут
NEG_TTL_DEFAULT = 30        # если в ответе нет SOA
STATS_EVERY = 15
MAX_INFLIGHT = 512          # одновременных запросов к серверам; больше — отказ (SERVFAIL)

DOT_PORT, DOH_PORT = 853, 443
ENC_TIMEOUT = 5.0           # соединение и ответ по DoT/DoH
POOL_SIZE = 4               # открытых TLS-соединений на пару «путь, сервер»
POOL_IDLE = 50.0            # дольше без запросов — соединение закрываем (серверы сами закрывают через ~60 с)
# Имя сервиса для известных адресов: с ним проверяется сертификат и его ждёт заголовок Host у DoH
# (Google по голому IP DoH может не отвечать). Остальные адреса проверяются по IP в сертификате.
KNOWN_NAMES = {"1.1.1.1": "cloudflare-dns.com", "1.0.0.1": "cloudflare-dns.com",
               "8.8.8.8": "dns.google", "8.8.4.4": "dns.google",
               "9.9.9.9": "dns.quad9.net", "149.112.112.112": "dns.quad9.net"}

T_OPT, T_SOA = 41, 6
RC_SERVFAIL, RC_NXDOMAIN, RC_REFUSED = 2, 3, 5


# ---------------------------------------------------------------- разбор DNS
def skip_name(msg: bytes, off: int) -> int:
    """Смещение сразу после имени (с учётом сжатия: указатель занимает 2 байта)."""
    while True:
        if off >= len(msg):
            raise ValueError("name")
        n = msg[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            return off + 2
        if n & 0xC0:
            raise ValueError("label")
        off += 1 + n


def read_name(msg: bytes, off: int) -> str:
    """Имя из вопроса (без сжатия — в вопросе его не бывает), строчными буквами."""
    labels = []
    while True:
        n = msg[off]
        if n == 0:
            return ".".join(labels).lower() + "."
        if n & 0xC0:
            raise ValueError("label")
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n


def parse_query(msg: bytes) -> dict | None:
    """Запрос клиента → {id, name, qtype, qclass, qend, udp_max} или None, если это не запрос."""
    if len(msg) < 12:
        return None
    qid, flags, qd, an, ns, ar = struct.unpack("!6H", msg[:12])
    if flags & 0x8000 or (flags >> 11) & 0xF != 0 or qd != 1:
        return None                                  # ответ, не QUERY или не один вопрос
    try:
        name = read_name(msg, 12)
        qend = skip_name(msg, 12) + 4
        if qend > len(msg):
            return None
        qtype, qclass = struct.unpack("!HH", msg[qend - 4:qend])
        udp_max = 512
        off = qend
        for _ in range(an + ns + ar):               # ищем OPT (EDNS0): размер UDP клиента
            off = skip_name(msg, off)
            rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
            if rtype == T_OPT:
                udp_max = max(512, min(rclass, 4096))
            off += 10 + rdlen
    except (ValueError, IndexError, struct.error):
        return None
    return {"id": qid, "name": name, "qtype": qtype, "qclass": qclass, "qend": qend, "udp_max": udp_max}


def ttl_fields(msg: bytes) -> tuple[int, list[int], int | None]:
    """→ (rcode, смещения полей TTL всех записей, кроме OPT; TTL для отрицательного ответа из SOA)."""
    _id, flags, qd, an, ns, ar = struct.unpack("!6H", msg[:12])
    off = 12
    for _ in range(qd):
        off = skip_name(msg, off) + 4
    offs, neg = [], None
    for i in range(an + ns + ar):
        off = skip_name(msg, off)
        rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        if rtype != T_OPT:
            offs.append(off + 4)
            if rtype == T_SOA and an <= i < an + ns:
                # отрицательный ответ хранится min(TTL записи SOA, поле MINIMUM) — RFC 2308
                rd = off + 10
                try:
                    p = skip_name(msg, skip_name(msg, rd)) + 16
                    neg = min(ttl, struct.unpack("!I", msg[p:p + 4])[0])
                except (ValueError, struct.error):
                    neg = ttl
        off += 10 + rdlen
    if off > len(msg):
        raise ValueError("short")
    return flags & 0xF, offs, neg


def cache_ttl(msg: bytes) -> tuple[int, list[int]]:
    """Сколько хранить ответ (0 — не хранить) и где в нём поля TTL."""
    rcode, offs, neg = ttl_fields(msg)
    an = struct.unpack("!H", msg[6:8])[0]
    if rcode == RC_NXDOMAIN or (rcode == 0 and an == 0):
        return min(NEG_TTL_MAX, neg if neg is not None else NEG_TTL_DEFAULT), offs
    if rcode != 0:
        return 0, offs                               # SERVFAIL и прочее не храним
    ttls = [struct.unpack("!I", msg[o:o + 4])[0] for o in offs[:an]] or [0]
    return min(min(ttls), TTL_MAX), offs


def with_ttl(msg: bytes, offs: list[int], minus: int) -> bytes:
    """Ответ из кэша: TTL всех записей уменьшены на прошедшее время."""
    b = bytearray(msg)
    for o in offs:
        ttl = struct.unpack("!I", b[o:o + 4])[0]
        b[o:o + 4] = struct.pack("!I", max(0, ttl - minus))
    return bytes(b)


def error_reply(query: bytes, q: dict, rcode: int) -> bytes:
    """Ответ без записей с кодом ошибки: заголовок и вопрос запроса."""
    flags = struct.unpack("!H", query[2:4])[0]
    flags = 0x8000 | (flags & 0x7900) | 0x0080 | rcode       # QR, OPCODE/RD/CD как в запросе, RA
    return struct.pack("!6H", q["id"], flags, 1, 0, 0, 0) + query[12:q["qend"]]


def truncated(reply: bytes, q: dict) -> bytes:
    """Ответ не влезает в UDP клиента: только заголовок и вопрос с флагом TC — клиент спросит по TCP."""
    flags = struct.unpack("!H", reply[2:4])[0] | 0x0200
    return reply[:2] + struct.pack("!H", flags) + struct.pack("!4H", 1, 0, 0, 0) + reply[12:q["qend"]]


# ---------------------------------------------------------------- DoT / DoH
class Conn:
    """Открытое TLS-соединение к серверу DNS."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader, self.writer = reader, writer
        self.used = time.monotonic()
        self.reusable = True

    def close(self) -> None:
        try:
            self.writer.close()
        except Exception:  # noqa: BLE001
            pass


class Pool:
    """Соединения к одному серверу по одному пути: не больше POOL_SIZE, по одному запросу на соединение.
    Сервер мог закрыть простаивавшее соединение — тогда запрос повторяется на новом."""

    def __init__(self, open_fn):
        self.open_fn = open_fn
        self.idle: list[Conn] = []
        self.sem = asyncio.Semaphore(POOL_SIZE)

    async def run(self, fn):
        async with self.sem:
            conn = None
            while self.idle and conn is None:
                c = self.idle.pop()
                if c.reusable and time.monotonic() - c.used < POOL_IDLE and not c.reader.at_eof():
                    conn = c
                else:
                    c.close()
            fresh = conn is None
            if fresh:
                conn = await self.open_fn()
            try:
                result = await fn(conn)
            except Exception:
                conn.close()
                if fresh:
                    raise
                conn = await self.open_fn()          # старое соединение уже закрыто сервером
                try:
                    result = await fn(conn)
                except Exception:
                    conn.close()
                    raise
            conn.used = time.monotonic()
            if conn.reusable:
                self.idle.append(conn)
            else:
                conn.close()
            return result

    def close(self) -> None:
        for c in self.idle:
            c.close()
        self.idle.clear()


async def dot_query(conn: Conn, msg: bytes) -> bytes:
    conn.writer.write(struct.pack("!H", len(msg)) + msg)
    await conn.writer.drain()
    n = struct.unpack("!H", await conn.reader.readexactly(2))[0]
    return await conn.reader.readexactly(n)


async def doh_query(conn: Conn, msg: bytes, host: str) -> bytes:
    """POST /dns-query по HTTP/1.1 с keep-alive (RFC 8484)."""
    conn.writer.write((f"POST /dns-query HTTP/1.1\r\nHost: {host}\r\nUser-Agent: awg-router\r\n"
                       f"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n"
                       f"Content-Length: {len(msg)}\r\n\r\n").encode() + msg)
    await conn.writer.drain()
    status = (await conn.reader.readline()).decode("latin-1").split()
    if len(status) < 2:
        raise OSError("DoH: no answer")
    headers = {}
    while True:
        line = (await conn.reader.readline()).decode("latin-1")
        if line in ("\r\n", "\n", ""):
            break
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    if headers.get("connection", "").lower() == "close":
        conn.reusable = False
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = b""
        while True:
            size = int((await conn.reader.readline()).split(b";")[0].strip() or b"0", 16)
            if size == 0:
                await conn.reader.readline()
                break
            body += await conn.reader.readexactly(size)
            await conn.reader.readline()
    elif "content-length" in headers:
        body = await conn.reader.readexactly(int(headers["content-length"]))
    else:
        conn.reusable = False
        body = await conn.reader.read(65535)
    if status[1] != "200":
        raise OSError(f"DoH: HTTP {status[1]}")
    return body


# ---------------------------------------------------------------- сервер
class Proxy:
    def __init__(self, conf_path: str):
        self.conf_path = conf_path
        self.cfg: dict = {}
        self.net = None
        self.cache: dict[tuple, tuple[float, int, bytes, list[int]]] = {}
        self.stats = {"queries": 0, "cached": 0, "errors": 0, "refused": 0}
        self.last_ok = 0.0                  # когда серверы DNS последний раз ответили
        self.last_error, self.last_error_at = "", 0.0
        self.inflight = 0
        self.pools: dict[tuple, Pool] = {}
        self.load()

    def load(self) -> None:
        with open(self.conf_path) as f:
            cfg = json.load(f)
        self.net = ipaddress.ip_network(cfg["clients"]) if cfg.get("clients") else None
        self.up_port = int(cfg.get("upstream_port") or PORT)     # не 53 — только в тестах
        old = self.cfg
        self.cfg = cfg
        if old and (old.get("upstreams") != cfg.get("upstreams") or old.get("encrypt") != cfg.get("encrypt")):
            self.cache.clear()                       # другие серверы — старые ответы не нужны
        for p in self.pools.values():                # пути, серверы или сертификаты могли смениться
            p.close()
        self.pools.clear()
        self.ctx = ssl.create_default_context(cafile=cfg.get("ca_file") or None)   # ca_file — только в тестах
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    def route(self, ip: str) -> dict | None:
        """Путь запросов клиента: {"mark", "tcp"}; None — блок."""
        r = (self.cfg.get("routes") or {}).get(ip, "default")
        return self.cfg.get("default") if r == "default" else r

    def allowed(self, ip: str) -> bool:
        try:
            return self.net is None or ipaddress.ip_address(ip) in self.net
        except ValueError:
            return False

    async def resolve(self, query: bytes, q: dict, ip: str) -> bytes:
        self.stats["queries"] += 1
        route = self.route(ip)
        if route is None:
            self.stats["refused"] += 1
            return error_reply(query, q, RC_REFUSED)
        mark, tcp = int(route.get("mark") or 0), bool(route.get("tcp"))
        key = (mark, q["name"], q["qtype"], q["qclass"])
        hit = self.cache.get(key)
        now = time.monotonic()
        if hit and hit[0] > now:
            self.stats["cached"] += 1
            reply = with_ttl(hit[2], hit[3], int(now - hit[1]))
            return struct.pack("!H", q["id"]) + reply[2:]
        if self.inflight >= MAX_INFLIGHT:
            self.stats["errors"] += 1
            return error_reply(query, q, RC_SERVFAIL)
        self.inflight += 1
        try:
            reply = await self.forward(query, q, mark, tcp)
        finally:
            self.inflight -= 1
        if reply is None:
            self.stats["errors"] += 1
            return error_reply(query, q, RC_SERVFAIL)
        try:
            ttl, offs = cache_ttl(reply)
        except (ValueError, struct.error):
            ttl, offs = 0, []
        if ttl > 0:
            if len(self.cache) >= CACHE_MAX:
                self.cache.pop(next(iter(self.cache)))
            self.cache[key] = (now + ttl, int(now), reply, offs)
        return struct.pack("!H", q["id"]) + reply[2:]

    async def forward(self, query: bytes, q: dict, mark: int, tcp: bool) -> bytes | None:
        """Запрос к серверам по очереди: первый, кто ответил по делу, — ответ."""
        mode = self.cfg.get("encrypt") or "plain"
        for server in self.cfg.get("upstreams") or []:
            qid = random.randrange(0, 65536)
            out = struct.pack("!H", qid) + query[2:]
            try:
                if mode in ("dot", "doh"):
                    reply = await asyncio.wait_for(self._enc(out, server, mark, mode), ENC_TIMEOUT * 2)
                else:
                    reply = None if tcp else await self._udp(out, server, mark)
                    if reply is None or struct.unpack("!H", reply[2:4])[0] & 0x0200:
                        reply = await self._tcp(out, server, mark)   # нет ответа по UDP или он обрезан
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ssl.SSLError,
                    ValueError, struct.error) as e:
                self._fail(server, e)
                continue
            if not reply or len(reply) < 12 or struct.unpack("!H", reply[:2])[0] != qid \
                    or reply[12:q["qend"]].lower() != query[12:q["qend"]].lower():
                self._fail(server, "bad answer")
                continue
            if reply[3] & 0xF == RC_SERVFAIL:
                continue                                              # спросим следующий сервер
            self.last_ok = time.time()
            return reply
        return None

    def _fail(self, server: str, e) -> None:
        if isinstance(e, asyncio.TimeoutError):
            e = "timeout"
        elif isinstance(e, ssl.SSLCertVerificationError):
            e = f"certificate: {e.verify_message}"
        self.last_error, self.last_error_at = f"{server}: {e}"[:200], time.time()

    async def _enc(self, msg: bytes, server: str, mark: int, mode: str) -> bytes:
        """Запрос по DoT или DoH через пул соединений этого пути и сервера."""
        key = (mode, mark, server)
        pool = self.pools.get(key)
        if pool is None:
            name = KNOWN_NAMES.get(server, server)
            port = self.up_port if self.cfg.get("upstream_port") else (DOH_PORT if mode == "doh" else DOT_PORT)

            async def open_conn():
                loop = asyncio.get_running_loop()
                s = self._sock(socket.SOCK_STREAM, mark)
                try:
                    await asyncio.wait_for(loop.sock_connect(s, (server, port)), ENC_TIMEOUT)
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(sock=s, ssl=self.ctx, server_hostname=name), ENC_TIMEOUT)
                except BaseException:
                    s.close()
                    raise
                return Conn(r, w)
            pool = self.pools[key] = Pool(open_conn)
            pool.host = name
        if mode == "dot":
            return await pool.run(lambda c: asyncio.wait_for(dot_query(c, msg), ENC_TIMEOUT))
        return await pool.run(lambda c: asyncio.wait_for(doh_query(c, msg, pool.host), ENC_TIMEOUT))

    @staticmethod
    def _sock(kind: int, mark: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, kind)
        if mark:
            s.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
        s.setblocking(False)
        return s

    async def _udp(self, msg: bytes, server: str, mark: int) -> bytes | None:
        loop = asyncio.get_running_loop()
        s = self._sock(socket.SOCK_DGRAM, mark)
        try:
            await loop.sock_connect(s, (server, self.up_port))
            await loop.sock_sendall(s, msg)
            try:
                return await asyncio.wait_for(loop.sock_recv(s, 65535), UDP_TIMEOUT)
            except asyncio.TimeoutError:
                return None
        finally:
            s.close()

    async def _tcp(self, msg: bytes, server: str, mark: int) -> bytes | None:
        loop = asyncio.get_running_loop()
        s = self._sock(socket.SOCK_STREAM, mark)
        try:
            await asyncio.wait_for(loop.sock_connect(s, (server, self.up_port)), TCP_TIMEOUT)
            await loop.sock_sendall(s, struct.pack("!H", len(msg)) + msg)
            data = b""
            while len(data) < 2 or len(data) < 2 + struct.unpack("!H", data[:2])[0]:
                chunk = await asyncio.wait_for(loop.sock_recv(s, 65535), TCP_TIMEOUT)
                if not chunk:
                    return None
                data += chunk
            return data[2:2 + struct.unpack("!H", data[:2])[0]]
        finally:
            s.close()

    # ---- приём запросов
    async def handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip = (writer.get_extra_info("peername") or ("",))[0]
        try:
            if not self.allowed(ip):
                return
            while True:
                head = await asyncio.wait_for(reader.readexactly(2), CLIENT_TCP_IDLE)
                query = await asyncio.wait_for(reader.readexactly(struct.unpack("!H", head)[0]), CLIENT_TCP_IDLE)
                q = parse_query(query)
                if not q:
                    return
                reply = await self.resolve(query, q, ip)
                writer.write(struct.pack("!H", len(reply)) + reply)
                await writer.drain()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            writer.close()

    def stats_loop(self) -> None:
        p = self.cfg.get("stats")
        if p:
            try:
                with open(p + ".tmp", "w") as f:
                    json.dump({"pid": os.getpid(), "at": time.time(), "cache": len(self.cache),
                               "encrypt": self.cfg.get("encrypt") or "plain", "last_ok": self.last_ok,
                               "last_error": self.last_error, "last_error_at": self.last_error_at,
                               **self.stats}, f)
                os.replace(p + ".tmp", p)
            except OSError:
                pass
        asyncio.get_running_loop().call_later(STATS_EVERY, self.stats_loop)


class UDPServer(asyncio.DatagramProtocol):
    def __init__(self, proxy: Proxy):
        self.proxy = proxy
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if not self.proxy.allowed(addr[0]):
            return
        q = parse_query(data)
        if q:
            asyncio.get_running_loop().create_task(self._answer(data, q, addr))

    async def _answer(self, data, q, addr):
        try:
            reply = await self.proxy.resolve(data, q, addr[0])
        except Exception:  # noqa: BLE001
            reply = error_reply(data, q, RC_SERVFAIL)
        if len(reply) > q["udp_max"]:
            reply = truncated(reply, q)
        self.transport.sendto(reply, addr)


async def main(conf_path: str) -> None:
    proxy = Proxy(conf_path)
    loop = asyncio.get_running_loop()
    listen, port = proxy.cfg["listen"], int(proxy.cfg.get("port") or PORT)
    await loop.create_datagram_endpoint(lambda: UDPServer(proxy), local_addr=(listen, port))
    server = await asyncio.start_server(proxy.handle_tcp, listen, port, reuse_address=True)
    stop = asyncio.Event()
    loop.add_signal_handler(signal.SIGHUP, proxy.load)
    loop.add_signal_handler(signal.SIGTERM, stop.set)
    loop.add_signal_handler(signal.SIGINT, stop.set)
    print(f"dnsproxy: {listen}:{port}", flush=True)
    proxy.stats_loop()
    async with server:
        await stop.wait()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
