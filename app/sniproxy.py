"""Правила по доменам для выходов SOCKS5. Только стандартная библиотека, без импорта панели.

Запускается панелью в сети сервера AWG (как туннели выходов):
    nsenter -t PID -n -- python3 sniproxy.py /run/awgr/sni.json
Клиенты, у которых в правилах есть список доменов, отправляют сюда свои TCP-соединения на
порты 443 и 80 (nftables, redirect). Посредник читает начало соединения — имя сайта из TLS
ClientHello (SNI) или заголовок Host у HTTP — и решает:
  * имя есть в списке из правила → соединение открывается через прокси SOCKS5 выхода командой
    CONNECT с именем сайта (адрес находит сам прокси, поэтому подменённый местным DNS адрес
    ничему не мешает);
  * иначе → соединение к исходному адресу с меткой «политика клиента N»: цепочка nftables
    type route (hook output) проверяет обычные правила по адресам и ставит метку нужного выхода
    (AWG, SOCKS5 через hev-socks5-tunnel, напрямую или блок).
Если выход правила не работает, панель передаёт его резервный путь (метку, напрямую или блок).
SIGHUP — перечитать настройки и списки. Счётчики и байты по «клиент|выход» — в файл stats
раз в 15 секунд и при остановке (по ним панель считает трафик выходов).
"""
from __future__ import annotations

import asyncio
import bisect
import ipaddress
import json
import os
import signal
import socket
import struct
import sys
import time

SO_MARK = 36
SO_ORIGINAL_DST = 80
PEEK_TIMEOUT = 3.0          # сколько ждём первых данных клиента (ClientHello / запрос HTTP)
PEEK_MAX = 64 * 1024
CONNECT_TIMEOUT = 10.0
BUF = 256 * 1024
IDLE_TIMEOUT = 900          # соединение без данных в обе стороны дольше — закрываем
KEEPALIVE = (120, 30, 4)    # TCP keepalive: пропавший без FIN собеседник виден через ~4 мин
STATS_EVERY = 15


# --------------------------------------------------------------- разбор имени
def tls_sni(data: bytes) -> str | None | bool:
    """Имя из TLS ClientHello. None — это не TLS или имени нет; False — данных пока мало."""
    hs = b""
    off = 0
    while True:
        if len(data) < off + 5:
            return False
        if data[off] != 0x16 or data[off + 1] != 0x03:
            return None
        rlen = struct.unpack("!H", data[off + 3:off + 5])[0]
        if len(data) < off + 5 + rlen:
            return False
        hs += data[off + 5:off + 5 + rlen]
        off += 5 + rlen
        if len(hs) >= 4:
            if hs[0] != 0x01:
                return None
            need = 4 + int.from_bytes(hs[1:4], "big")
            if len(hs) >= need:
                return _client_hello_sni(hs[4:need])
            if need > PEEK_MAX:
                return None


def _client_hello_sni(b: bytes) -> str | None:
    try:
        p = 2 + 32                                   # версия, random
        p += 1 + b[p]                                # session id
        p += 2 + struct.unpack("!H", b[p:p + 2])[0]  # cipher suites
        p += 1 + b[p]                                # compression
        if p + 2 > len(b):
            return None
        end = p + 2 + struct.unpack("!H", b[p:p + 2])[0]
        p += 2
        while p + 4 <= min(end, len(b)):
            etype, elen = struct.unpack("!HH", b[p:p + 4])
            p += 4
            if etype == 0:
                q = p + 2
                while q + 3 <= p + elen:
                    ntype, nlen = b[q], struct.unpack("!H", b[q + 1:q + 3])[0]
                    q += 3
                    if ntype == 0:
                        return b[q:q + nlen].decode("ascii", "replace").lower().rstrip(".")
                    q += nlen
                return None
            p += elen
    except (IndexError, struct.error):
        return None
    return None


def http_host(data: bytes) -> str | None | bool:
    end = data.find(b"\r\n\r\n")
    if end < 0:
        return False if len(data) < 16 * 1024 else None
    head = data[:end].decode("latin-1")
    lines = head.split("\r\n")
    if len(lines[0].split(" ")) != 3:
        return None
    for line in lines[1:]:
        k, _, v = line.partition(":")
        if k.strip().lower() == "host":
            v = v.strip().lower()
            if v.startswith("["):
                return None
            return v.rsplit(":", 1)[0] if ":" in v else v
    return None


def name_of(data: bytes, port: int) -> str | None | bool:
    if data[:1] == b"\x16":
        return tls_sni(data)
    if port == 80 or data[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"DELE", b"PATC", b"CONN"):
        return http_host(data)
    return None


def match(name: str, doms: set[str]) -> bool:
    labels = name.split(".")
    return any(".".join(labels[i:]) in doms for i in range(len(labels)))


# --------------------------------------------------------------- SOCKS5
async def socks_connect(s: dict, host: str | None, ip: str, port: int):
    """Соединение через прокси: CONNECT по имени (или по адресу, если имени нет)."""
    r, w = await asyncio.wait_for(asyncio.open_connection(s["ip"], int(s["port"])), CONNECT_TIMEOUT)
    try:
        user, pw = (s.get("user") or "").encode(), (s.get("password") or "").encode()
        w.write(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
        ver, method = await asyncio.wait_for(r.readexactly(2), CONNECT_TIMEOUT)
        if ver != 5 or method == 0xFF:
            raise OSError("socks: no acceptable auth method")
        if method == 2:
            w.write(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
            if (await asyncio.wait_for(r.readexactly(2), CONNECT_TIMEOUT))[1] != 0:
                raise OSError("socks: login rejected")
        if host:
            hb = host.encode("idna") if any(ord(c) > 127 for c in host) else host.encode()
            addr = b"\x03" + bytes([len(hb)]) + hb
        else:
            addr = b"\x01" + socket.inet_aton(ip)
        w.write(b"\x05\x01\x00" + addr + struct.pack("!H", port))
        head = await asyncio.wait_for(r.readexactly(4), CONNECT_TIMEOUT)
        if head[1] != 0:
            raise OSError(f"socks: connect failed ({head[1]})")
        n = {1: 4, 4: 16}.get(head[3])
        if n is None:
            n = (await r.readexactly(1))[0]
        await r.readexactly(n + 2)
        return r, w
    except BaseException:
        w.close()
        raise


async def direct_connect(ip: str, port: int, mark: int):
    loop = asyncio.get_running_loop()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if mark:
            s.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
        s.setblocking(False)
        await asyncio.wait_for(loop.sock_connect(s, (ip, port)), CONNECT_TIMEOUT)
    except BaseException:
        s.close()
        raise
    return await asyncio.open_connection(sock=s)


def keepalive(sock) -> None:
    """Пропавший клиент (телефон ушёл из сети без FIN) не держит соединение вечно."""
    if sock is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for opt, v in zip(("TCP_KEEPIDLE", "TCP_KEEPINTVL", "TCP_KEEPCNT"), KEEPALIVE):
            if hasattr(socket, opt):
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), v)
    except OSError:
        pass


async def pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter, cnt: list | None = None,
               i: int = 0, act: list | None = None) -> None:
    """Копирует поток. cnt[i] — счётчик байт (учёт трафика выходов), act[0] — время последних данных."""
    try:
        while True:
            data = await r.read(BUF)
            if not data:
                break
            if cnt is not None:
                cnt[i] += len(data)
            if act is not None:
                act[0] = time.monotonic()
            w.write(data)
            await w.drain()
    except (OSError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            if w.can_write_eof():
                w.write_eof()
        except OSError:
            pass


class Nets:
    """Адреса списка (файл CIDR панели) для поиска «в какой выход уйдёт соединение» —
    так же, как цепочка q_* в nftables, только для учёта трафика."""

    def __init__(self, path: str):
        ranges = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    n = ipaddress.ip_network(line, strict=False)
                except ValueError:
                    continue
                if n.version == 4:
                    ranges.append((int(n.network_address), int(n.broadcast_address)))
        ranges.sort()
        self.starts, self.ends = [], []
        for a, b in ranges:
            if self.ends and a <= self.ends[-1] + 1:
                self.ends[-1] = max(self.ends[-1], b)
            else:
                self.starts.append(a)
                self.ends.append(b)

    def __contains__(self, ip: str) -> bool:
        x = int(ipaddress.IPv4Address(ip))
        i = bisect.bisect_right(self.starts, x) - 1
        return i >= 0 and self.ends[i] >= x


# --------------------------------------------------------------- посредник
class Sniffer:
    def __init__(self, path: str):
        self.path = path
        self.cfg: dict = {}
        self.lists: dict[str, set[str]] = {}
        self.nets: dict[str, Nets] = {}
        self.stats = {"conns": 0, "active": 0, "matched": 0, "errors": 0, "no_name": 0,
                      "started": time.time(), "by_list": {}}
        # байты по «клиент|выход» с запуска процесса: панель добавляет их к трафику выходов
        # (соединения через посредника — не транзитные, таблица учёта nftables их не видит)
        self.bytes: dict[str, list[int]] = {}
        self.reload()

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
        nets = {}
        for lid, p in (cfg.get("cidrs") or {}).items():
            try:
                nets[lid] = Nets(p)
            except OSError as e:
                log(f"cidrs {lid}: {e}")
        self.cfg, self.lists, self.nets = cfg, lists, nets
        self.net = ipaddress.ip_network(cfg.get("clients") or "0.0.0.0/0", strict=False)

    def policy(self, client: str) -> dict:
        pname = (self.cfg.get("client_policy") or {}).get(client, "p_global")
        return (self.cfg.get("policies") or {}).get(pname) or {}

    def decide(self, client: str, name: str | None) -> tuple[dict, str | None]:
        """→ (куда: {"socks"} | {"mark"} | {"block"}, список). Без совпадения — метка политики."""
        pol = self.policy(client)
        if name:
            for rule in pol.get("rules") or []:
                for lid in rule.get("lists") or []:
                    if match(name, self.lists.get(lid, set())):
                        return rule.get("to") or {"mark": 0}, lid
        return {"mark": int(pol.get("mark") or 0)}, None

    def miss_out(self, client: str, ip: str) -> str | None:
        """Выход соединения без совпадения по домену (для учёта): правила политики по адресам,
        затем выход по умолчанию — как цепочка q_* в nftables. None — блок или неизвестно."""
        acct = self.policy(client).get("acct") or {}
        try:
            for lids, out in acct.get("rules") or []:
                if any(ip in self.nets[lid] for lid in lids if lid in self.nets):
                    return out
        except ValueError:
            return None
        return acct.get("default")

    def counter(self, client: str, out: str | None) -> list | None:
        if not out:
            return None
        return self.bytes.setdefault(f"{client}|{out}", [0, 0])

    async def client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        peer = (writer.get_extra_info("peername") or ("0.0.0.0", 0))[0]
        out_w = None
        counted = False
        try:
            if ipaddress.ip_address(peer) not in self.net:
                return
            raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            dport = struct.unpack("!H", raw[2:4])[0]
            dip = socket.inet_ntoa(raw[4:8])
            self.stats["conns"] += 1
            self.stats["active"] += 1
            counted = True
            data = b""
            name = False
            deadline = time.monotonic() + PEEK_TIMEOUT
            while name is False and len(data) < PEEK_MAX:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                try:
                    chunk = await asyncio.wait_for(reader.read(PEEK_MAX - len(data)), left)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                data += chunk
                name = name_of(data, dport)
            name = name or None
            if name is None:
                self.stats["no_name"] += 1
            to, lid = self.decide(peer, name)
            if lid:
                self.stats["matched"] += 1
                self.stats["by_list"][lid] = self.stats["by_list"].get(lid, 0) + 1
            if to.get("block"):
                return
            if to.get("socks"):
                out_r, out_w = await socks_connect(to["socks"], name, dip, dport)
            else:
                out_r, out_w = await direct_connect(dip, dport, int(to.get("mark") or 0))
            keepalive(sock)
            keepalive(out_w.get_extra_info("socket"))
            cnt = self.counter(peer, to.get("acct") if lid else self.miss_out(peer, dip))
            if data:
                out_w.write(data)
                await out_w.drain()
                if cnt is not None:
                    cnt[0] += len(data)
            act = [time.monotonic()]
            both = asyncio.gather(pipe(reader, out_w, cnt, 0, act), pipe(out_r, writer, cnt, 1, act))
            while not both.done():
                await asyncio.wait([both], timeout=min(60, IDLE_TIMEOUT))
                if not both.done() and time.monotonic() - act[0] > IDLE_TIMEOUT:
                    both.cancel()           # молчит в обе стороны дольше IDLE_TIMEOUT — закрываем
                    try:
                        await both
                    except (asyncio.CancelledError, OSError):
                        pass
                    break
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError) as e:
            self.stats["errors"] += 1
            if self.cfg.get("debug"):
                log(f"{peer}: {e!r}")
        finally:
            if counted:
                self.stats["active"] -= 1
            for w in (writer, out_w):
                if w is not None:
                    try:
                        w.close()
                    except OSError:
                        pass

    def write_stats(self) -> None:
        p = self.cfg.get("stats")
        if not p:
            return
        try:
            with open(p + ".tmp", "w") as f:
                json.dump({**self.stats, "bytes": self.bytes, "pid": os.getpid(), "at": time.time()}, f)
            os.replace(p + ".tmp", p)
        except OSError:
            pass

    async def serve(self) -> None:
        loop = asyncio.get_running_loop()
        host, port = self.cfg["listen"], int(self.cfg.get("port") or 10443)
        await asyncio.start_server(self.client, host, port, reuse_address=True, backlog=1024)
        loop.add_signal_handler(signal.SIGHUP, self.on_hup)
        loop.add_signal_handler(signal.SIGTERM, loop.stop)
        log(f"listening on {host}:{port}, {len(self.lists)} domain lists")
        while True:
            self.write_stats()
            await asyncio.sleep(STATS_EVERY)

    def on_hup(self) -> None:
        try:
            self.reload()
        except Exception as e:  # noqa: BLE001
            log(f"reload: {e}")


def log(text: str) -> None:
    print(time.strftime("%Y-%m-%d %H:%M:%S"), text, file=sys.stderr, flush=True)


def main() -> None:
    s = Sniffer(sys.argv[1])
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    task = loop.create_task(s.serve())
    try:
        loop.run_forever()
    finally:
        task.cancel()
        s.write_stats()


if __name__ == "__main__":
    main()
