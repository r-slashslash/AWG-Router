"""Стенд независимой проверки П31: свои серверы DNS (обычный UDP, DoT, DoH по HTTP/1.1, HTTP/3) с медленными и
«мёртвыми» именами и настоящие процессы dnsproxy.py — до исправления (6a8c54f) и после (d7a90cc) — в своей сети
(запускать под `unshare -rn`). Блокировки — nftables в хуке input (пакет теряется молча).

Адреса серверов (порт у всех UP_PORT, как cfg upstream_port):
  127.0.0.2, .3  — общие DoH (TCP, TLS) и обычный DNS (UDP) на тех же адресах
  127.0.0.4, .5  — общие DoT и UDP
  127.0.0.6, .7  — общие, только UDP
  127.0.0.10     — запасной обычный (UDP),  .14 — второй запасной обычный
  127.0.0.11     — запасной DoT,  .12 — запасной DoH,  .13 — запасной HTTP/3 (UDP)
Ответ на имя — A 203.0.113.<последний байт адреса сервера>: клиент видит, кто ответил.
Имена: «dead…» — никто не отвечает (у домена молчат его серверы имён), «slowK…» — ответ через K с, «shdead…» — молчат
только общие, «fbdead…» — молчит только запасной, остальные — сразу.
"""
from __future__ import annotations

import asyncio
import ctypes
import fcntl
import json
import os
import random
import re
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
_CD = os.environ.get("LAB_CERT_DIR", HERE)
CRT, KEY = os.path.join(_CD, "c.crt"), os.path.join(_CD, "c.key")
LIBSSL = "/nix/store/8dj39rr9xp8qpl3myqj8i04a8pwhyl60-openssl-3.6.1/lib/libssl.so.3"
UP_PORT = 8053
OLD_APP, NEW_APP = os.environ.get("LAB_OLD", "/tmp/old/app"), os.environ.get("LAB_NEW", "/tmp/new/app")
CODE = {"old": OLD_APP + "/dnsproxy.py", "new": NEW_APP + "/dnsproxy.py",
        "fix": os.environ.get("LAB_FIX", "/tmp/fix/app") + "/dnsproxy.py"}      # Ж: fix — b87eaa5 (код ветки)
LISTEN = {"old": "127.0.1.1", "new": "127.0.1.2", "fix": "127.0.1.3"}
NET = os.environ.get("LAB_NET", "127.0.0.")          # сеть серверов; 10.99.1. — в другой сети за veth (машина GitHub)
SRV_NS = os.environ.get("LAB_SRV_NS")                # файл сети серверов (/run/netns/inet) или пусто — та же сеть
NFT_NS = os.environ.get("LAB_NFT_NS")                # имя сети для правил блокировки (ip netns exec) или пусто
SHARED_DOH, SHARED_DOT, SHARED_UDP = [NET + "2", NET + "3"], [NET + "4", NET + "5"], [NET + "6", NET + "7"]
FB_UDP, FB_DOT, FB_DOH, FB_H3, FB_UDP2 = NET + "10", NET + "11", NET + "12", NET + "13", NET + "14"
LOG: list = []                                       # (время, адрес сервера, отправитель, способ, имя)

sys.path.insert(0, NEW_APP)
import dohttp as _h3tools  # noqa: E402  — только кадры HTTP/3 для своего сервера (инструмент, не проверяемое)


def lo_up() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fcntl.ioctl(s.fileno(), 0x8914, struct.pack("16sH14s", b"lo", 0x49, b""))
    s.close()


def nft(text: str) -> None:
    out = []                                         # nft: «drop }» и «} }» в одной строке — ошибка разбора
    for line in text.split("\n"):
        tail = []
        while line.strip() != "}" and line.rstrip().endswith("}") and line.count("}") > line.count("{"):
            line = line.rstrip()[:-1]
            tail.append("}")
        out += [line] + tail
    text = "\n".join(out)
    pre = ["ip", "netns", "exec", NFT_NS] if NFT_NS else []
    r = subprocess.run([*pre, "nft", "-f", "-"], input=text, text=True, capture_output=True)
    if r.returncode:
        raise RuntimeError(r.stderr)


def nft_out(*args) -> str:
    return subprocess.run(["nft", *args], capture_output=True, text=True).stdout


# ------------------------------------------------------------------ DNS
def qmsg(name: str, qtype: int = 1, qid: int | None = None) -> bytes:
    labels = b"".join(bytes([len(x)]) + x.encode() for x in name.rstrip(".").split(".") if x)
    return struct.pack("!6H", random.randrange(65536) if qid is None else qid, 0x0100, 1, 0, 0, 0) + labels + \
        b"\x00" + struct.pack("!HH", qtype, 1)


def qname(msg: bytes) -> tuple[str, int, int]:
    off, labels = 12, []
    while msg[off]:
        n = msg[off]
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    qtype = struct.unpack("!H", msg[off + 1:off + 3])[0]
    return ".".join(labels).lower() + ".", qtype, off + 5


def answer(query: bytes, ip: str, rcode: int = 0) -> bytes:
    name, qtype, qend = qname(query)
    qid, flags = struct.unpack("!HH", query[:4])
    head = struct.pack("!6H", qid, 0x8180 | (flags & 0x0100) | rcode, 1, 0 if rcode else 1, 0, 0)
    if rcode:
        return head + query[12:qend]
    m = re.match(r"^a(\d+)\.rule\.example\.$", name)
    if m and qtype == 1:                              # setrace2: свой адрес на каждое имя (127.0.0.50+N)
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(f"127.0.0.{50 + int(m.group(1))}")
    elif name == "dns.test.":                         # имя запасного DoT (tls://dns.test) — его адрес
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(FB_DOT)
    elif name == "." and qtype == 2:
        rr = b"\x00" + struct.pack("!HHIH", 2, 1, 518400, 20) + b"\x01a\x0croot-servers\x03net\x00"
    else:
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton(ip)   # TTL 0 — не в кэш
    return head + query[12:qend] + rr


def parse(reply: bytes) -> tuple[int, str | None, bool]:
    """→ (rcode, первый адрес A или None, TC)."""
    flags, qd, an = struct.unpack("!HHH", reply[2:8])
    off = 12
    for _ in range(qd):
        while reply[off]:
            off += 1 + reply[off]
        off += 5
    a = None
    for _ in range(an):
        if reply[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while reply[off]:
                off += 1 + reply[off]
            off += 1
        typ, _cl, _ttl, ln = struct.unpack("!HHIH", reply[off:off + 10])
        off += 10
        if typ == 1 and ln == 4 and a is None:
            a = socket.inet_ntoa(reply[off:off + 4])
        off += ln
    return flags & 0xF, a, bool(flags & 0x0200)


# ------------------------------------------------------------------ поведение серверов
B = {"frozen": set(),        # адреса: соединение и TLS проходят, ответов нет (DoH «замерзает» после рукопожатия)
     "flaky": {},            # адрес → доля новых соединений TLS, которые замерзают
     "udp_dead": set(),      # адреса: обычный DNS не отвечает ничего
     "rate": {},             # адрес → доля запросов, на которые сервер отвечает (отвечает «через раз»)
     "slowall": 0.0,         # задержка всех ответов (медленный путь), с
     "freeze_req": {}}       # адрес → доля запросов (и контрольных), на которых соединение замерзает («мигает»)
SEEN: dict[str, dict] = {}   # адрес → {"ns": n, "names": n, "conns": n}
FALLBACK_IPS = {FB_UDP, FB_DOT, FB_DOH, FB_H3, FB_UDP2}


def delay(name: str, ip: str, qtype: int, src: str = "?", kind: str = "?") -> float | None:
    """Через сколько отвечать (None — никогда)."""
    LOG.append((round(time.time(), 3), ip, src, kind, name if qtype != 2 or name != "." else ". NS"))
    st = SEEN.setdefault(ip, {"ns": 0, "names": 0, "conns": 0})
    if name == "." and qtype == 2:
        st["ns"] += 1
        return B["slowall"]
    st["names"] += 1
    lab = name.split(".", 1)[0]
    if lab.startswith("dead"):
        return None
    if lab.startswith("shdead") and ip not in FALLBACK_IPS:
        return None
    if lab.startswith("fbdead") and ip in FALLBACK_IPS:
        return None
    m = re.match(r"slow(\d+)", lab)
    if m:
        return float(m.group(1))
    if ip in B["rate"] and random.random() > B["rate"][ip]:
        return None
    return B["slowall"]


def last(ip: str) -> str:
    return "203.0.113." + ip.rsplit(".", 1)[1]


class Udp(asyncio.DatagramProtocol):
    def __init__(self, ip):
        self.ip = ip

    def connection_made(self, tr):
        self.tr = tr

    def datagram_received(self, data, addr):
        if self.ip in B["udp_dead"]:
            return
        try:
            name, qt, _ = qname(data)
        except Exception:  # noqa: BLE001
            return
        d = delay(name, self.ip, qt, addr[0], "udp")
        if d is None:
            return
        out = answer(data, last(self.ip))
        asyncio.get_running_loop().call_later(d, self.tr.sendto, out, addr)


def tls_ctx(alpn):
    c = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    c.load_cert_chain(CRT, KEY)
    if alpn:
        c.set_alpn_protocols(alpn)
    return c


async def _hold(reader):
    try:
        while await reader.read(65536):
            pass
    except Exception:  # noqa: BLE001
        pass


def tls_handler(ip: str, kind: str):
    async def h(reader, writer):
        SEEN.setdefault(ip, {"ns": 0, "names": 0, "conns": 0})["conns"] += 1
        frozen_conn = random.random() < B["flaky"].get(ip, 0)
        t_acc = time.time()                          # Ж: Д5 — замерзают только соединения, открытые до B["freeze_old"][ip]
        try:
            while True:
                if kind == "dot":
                    head = await reader.readexactly(2)
                    msg = await reader.readexactly(struct.unpack("!H", head)[0])
                else:
                    line = await reader.readline()
                    if not line:
                        return
                    n = 0
                    while True:
                        h_ = await reader.readline()
                        if h_ in (b"\r\n", b"\n", b""):
                            break
                        if h_.lower().startswith(b"content-length:"):
                            n = int(h_.split(b":", 1)[1])
                    msg = await reader.readexactly(n)
                if frozen_conn or ip in B["frozen"] or random.random() < B["freeze_req"].get(ip, 0) \
                        or B.get("freeze_old", {}).get(ip, 0) > t_acc:
                    await _hold(reader)
                    return
                name, qt, _ = qname(msg)
                d = delay(name, ip, qt, (writer.get_extra_info("peername") or ("?",))[0], kind)
                if d is None:
                    await _hold(reader)
                    return
                if d:
                    await asyncio.sleep(d)
                if ip in B["frozen"]:
                    await _hold(reader)
                    return
                out = answer(msg, last(ip))
                if kind == "dot":
                    writer.write(struct.pack("!H", len(out)) + out)
                else:
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: "
                                 + str(len(out)).encode() + b"\r\n\r\n" + out)
                await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        finally:
            writer.close()
    return h


# ------------------------------------------------------------------ HTTP/3 (QUIC OpenSSL; по образцу тестов, свой адрес)
ALPN_CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                           ctypes.POINTER(ctypes.c_ubyte), ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p)


class H3Server:
    def __init__(self, ip: str, port: int):
        lib = _h3tools.libssl()
        P, I = ctypes.c_void_p, ctypes.c_int
        for fn, res, args in (("OSSL_QUIC_server_method", P, []), ("SSL_new_listener", P, [P, ctypes.c_uint64]),
                              ("SSL_listen", I, [P]), ("SSL_accept_connection", P, [P, ctypes.c_uint64]),
                              ("SSL_accept_stream", P, [P, ctypes.c_uint64]), ("SSL_get_stream_type", I, [P]),
                              ("SSL_set_incoming_stream_policy", I, [P, I, ctypes.c_uint64]),
                              ("SSL_CTX_use_certificate_chain_file", I, [P, ctypes.c_char_p]),
                              ("SSL_CTX_use_PrivateKey_file", I, [P, ctypes.c_char_p, I]),
                              ("SSL_CTX_set_alpn_select_cb", None, [P, ALPN_CB, P])):
            f = getattr(lib, fn)
            f.restype, f.argtypes = res, args
        self.lib, self.ip, self.stop = lib, ip, False
        self.ctx = lib.SSL_CTX_new(lib.OSSL_QUIC_server_method())
        assert lib.SSL_CTX_use_certificate_chain_file(self.ctx, CRT.encode()) == 1
        assert lib.SSL_CTX_use_PrivateKey_file(self.ctx, KEY.encode(), 1) == 1
        self.h3 = ctypes.create_string_buffer(b"h3", 2)

        def select_(ssl_, out, outlen, inp, inlen, arg):
            out[0] = ctypes.cast(self.h3, ctypes.c_void_p)
            outlen[0] = 2
            return 0
        self.cb = ALPN_CB(select_)
        lib.SSL_CTX_set_alpn_select_cb(self.ctx, self.cb, None)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))
        self.sock.setblocking(False)
        self.listener = lib.SSL_new_listener(self.ctx, 0)
        bio = lib.BIO_new_dgram(self.sock.fileno(), 0)
        lib.SSL_set_bio(self.listener, bio, bio)
        lib.SSL_set_blocking_mode(self.listener, 0)
        assert lib.SSL_listen(self.listener) == 1
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        lib, h = self.lib, _h3tools
        conns, streams, later = [], {}, []
        buf, got = ctypes.create_string_buffer(65536), ctypes.c_size_t(0)
        while not self.stop:
            select.select([self.sock], [], [], 0.005)
            lib.SSL_handle_events(self.listener)
            while True:
                conn = lib.SSL_accept_connection(self.listener, 1)
                if not conn:
                    break
                SEEN.setdefault(self.ip, {"ns": 0, "names": 0, "conns": 0})["conns"] += 1
                lib.SSL_set_blocking_mode(conn, 0)
                lib.SSL_set_incoming_stream_policy(conn, 1, 0)
                conns.append(conn)
            for conn in conns:
                lib.SSL_handle_events(conn)
                while True:
                    st = lib.SSL_accept_stream(conn, 1)
                    if not st:
                        break
                    if lib.SSL_get_stream_type(st) == 3:
                        streams[st] = b""
            for st in list(streams):
                while lib.SSL_read_ex(st, buf, len(buf), ctypes.byref(got)) == 1:
                    streams[st] += buf.raw[:got.value]
                if lib.SSL_get_error(st, 0) != 6:
                    continue
                frames = dict(h.h3_frames(streams.pop(st)))
                if self.ip in B["frozen"]:
                    continue
                msg = frames[0]
                name, qt, _ = qname(msg)
                d = delay(name, self.ip, qt, "?", "h3")
                if d is None:
                    continue
                body = answer(msg, last(self.ip))
                out = h.varint(1) + h.varint(3) + b"\x00\x00\xd9" + h.varint(0) + h.varint(len(body)) + body
                later.append((time.monotonic() + d, st, out))
            for item in [x for x in later if x[0] <= time.monotonic()]:
                later.remove(item)
                _, st, out = item
                lib.SSL_write_ex(st, out, len(out), ctypes.byref(got))
                lib.SSL_stream_conclude(st, 0)
            if len(conns) > 300:                      # старые соединения не копим
                for c in conns[:100]:
                    lib.SSL_free(c)
                del conns[:100]


def quic_ok() -> bool:
    try:
        if os.path.exists(LIBSSL):                   # песочница: OpenSSL 3.6 из nix; в образе панели — свой (3.5)
            _h3tools.LIBSSL = (LIBSSL,)
            _h3tools._lib, _h3tools._lib_tried = None, False
        lib = _h3tools.libssl()
        return lib is not None and hasattr(lib, "OSSL_QUIC_server_method")
    except Exception:  # noqa: BLE001
        return False


async def start_servers(h3: bool = True):
    if SRV_NS:                                   # сокеты серверов — в их сети, потом обратно
        here = os.open("/proc/self/ns/net", os.O_RDONLY)
        there = os.open(SRV_NS, os.O_RDONLY)
        os.setns(there, os.CLONE_NEWNET)
        try:
            return await _start_servers(h3)
        finally:
            os.setns(here, os.CLONE_NEWNET)
            os.close(here)
            os.close(there)
    return await _start_servers(h3)


async def _start_servers(h3: bool = True):
    loop = asyncio.get_running_loop()
    srv = []
    for ip in SHARED_DOH + SHARED_DOT + SHARED_UDP + [FB_UDP, FB_UDP2]:
        await loop.create_datagram_endpoint(lambda ip=ip: Udp(ip), local_addr=(ip, UP_PORT))
    for ip in SHARED_DOH + [FB_DOH]:
        srv.append(await asyncio.start_server(tls_handler(ip, "doh"), ip, UP_PORT, ssl=tls_ctx(["http/1.1"]),
                                              reuse_address=True, backlog=1024))
    for ip in SHARED_DOT + [FB_DOT]:
        srv.append(await asyncio.start_server(tls_handler(ip, "dot"), ip, UP_PORT, ssl=tls_ctx(None),
                                              reuse_address=True, backlog=1024))
    if h3 and quic_ok():
        H3Server(FB_H3, UP_PORT)
    return srv


# ------------------------------------------------------------------ клиенты
class Clients(asyncio.DatagramProtocol):
    """Клиенты с адресов src (127.0.2.x): запрос → (задержка, итог). Итог: shared / fallback / servfail / refused /
    timeout / other."""

    def __init__(self):
        self.wait: dict[tuple, asyncio.Future] = {}
        self.eps = {}

    async def ep(self, src: str):
        if src not in self.eps:
            loop = asyncio.get_running_loop()
            tr, _ = await loop.create_datagram_endpoint(lambda: _Cl(self), local_addr=(src, 0))
            self.eps[src] = tr
        return self.eps[src]

    async def ask(self, dst: str, name: str, src: str = "127.0.2.1", timeout: float = 30.0, qtype: int = 1):
        tr = await self.ep(src)
        fut = asyncio.get_running_loop().create_future()
        key = (dst, src, name.lower().rstrip(".") + ".")
        self.wait[key] = fut
        t0 = time.monotonic()
        tr.sendto(qmsg(name, qtype), (dst, 53))
        try:
            reply = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            return time.monotonic() - t0, "timeout"
        finally:
            self.wait.pop(key, None)
        dt = time.monotonic() - t0
        rc, a, _tc = parse(reply)
        if rc == 2:
            return dt, "servfail"
        if rc == 5:
            return dt, "refused"
        if rc == 0 and a:
            return dt, ("fallback" if int(a.rsplit(".", 1)[1]) >= 10 else "shared")
        return dt, f"rc{rc}"


class _Cl(asyncio.DatagramProtocol):
    def __init__(self, owner):
        self.owner = owner

    def connection_made(self, tr):
        self.tr = tr

    def datagram_received(self, data, addr):
        try:
            name = qname(data)[0]
        except Exception:  # noqa: BLE001
            return
        src = self.tr.get_extra_info("sockname")[0]
        fut = self.owner.wait.get((addr[0], src, name))
        if fut and not fut.done():
            fut.set_result(data)


# ------------------------------------------------------------------ dnsproxy.py
class Proxy:
    def __init__(self, ver: str, cfg: dict, code: str | None = None):
        self.ver, self.dir = ver, tempfile.mkdtemp(prefix=f"p31-{ver}-")
        self.listen = cfg.get("listen") or LISTEN[ver]
        self.stats_path = os.path.join(self.dir, "stats.json")
        base = {"listen": self.listen, "port": 53, "clients": "127.0.0.0/8", "stats": self.stats_path,
                "upstreams": SHARED_DOH, "encrypt": "doh", "default": {"mark": 0, "tcp": False}, "routes": {},
                "dom": {}, "direct_fallback": [FB_UDP], "addr_marks": [0x2101, 0x2110], "ca_file": CRT,
                "upstream_port": UP_PORT}
        if os.path.exists(LIBSSL):
            base["libssl"] = LIBSSL
        base.update(cfg)
        self.cfg = base
        self.conf = os.path.join(self.dir, "dns.json")
        self.write()
        self.log = open(os.path.join(self.dir, "log.txt"), "w")
        self.proc = subprocess.Popen([sys.executable, "-I", code or CODE[ver], self.conf], stdout=self.log,
                                     stderr=subprocess.STDOUT)

    def write(self):
        with open(self.conf + ".tmp", "w") as f:
            json.dump(self.cfg, f)
        os.replace(self.conf + ".tmp", self.conf)

    def hup(self, **changes):
        self.cfg.update(changes)
        self.write()
        self.proc.send_signal(signal.SIGHUP)

    def stats(self) -> dict:
        try:
            with open(self.stats_path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    async def fresh_stats(self, timeout: float = 17.0) -> dict:
        t0 = time.time()
        while time.time() - t0 < timeout:
            s = self.stats()
            if s.get("at", 0) > t0:
                return s
            await asyncio.sleep(0.25)
        return self.stats()

    def stop(self) -> float:
        t0 = time.monotonic()
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        return time.monotonic() - t0

    def rss_threads_fds(self) -> tuple[int, int, int]:
        pid = self.proc.pid
        with open(f"/proc/{pid}/status") as f:
            st = f.read()
        rss = int(re.search(r"VmRSS:\s+(\d+)", st).group(1))
        thr = int(re.search(r"Threads:\s+(\d+)", st).group(1))
        fds = len(os.listdir(f"/proc/{pid}/fd"))
        return rss, thr, fds


async def ready(cl: Clients, proxies, t: float = 10.0):
    for p in proxies:
        t0 = time.monotonic()
        while time.monotonic() - t0 < t:
            _, r = await cl.ask(p.listen, f"warm{random.randrange(10**9)}.example", timeout=1.0)
            if r in ("shared", "fallback", "servfail", "refused"):
                break
            await asyncio.sleep(0.2)


def uid() -> str:
    return f"{random.randrange(16**8):08x}"


def summary(rows) -> dict:
    """rows — [(t, задержка, итог)] → счётчики и задержки."""
    out = {}
    for _t, dt, r in rows:
        out.setdefault(r, []).append(dt)
    res = {}
    for r, v in out.items():
        v.sort()
        res[r] = {"n": len(v), "med": round(v[len(v) // 2], 3), "max": round(v[-1], 3),
                  "over1": sum(1 for x in v if x > 1.0), "over3": sum(1 for x in v if x > 3.0)}
    return res
