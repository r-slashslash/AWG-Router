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
Данные соединений пересылаются внутри ядра (splice), без копирования в Python: через посредника
идёт весь TCP 80/443 таких клиентов, а не только сайты из списков.
Ограничение скорости выхода SOCKS5 (rates в настройках): соединения через CONNECT идут к прокси
мимо туннеля выхода, и очередь tc на нём их не видит — их ограничивает общий для выхода «бак
токенов» в каждую сторону; splice берёт из бака каждую порцию до отправки дальше.
Предел выхода у двух дорог общий (shared): раз в секунду посредник смотрит, сколько идёт через
туннель (/proc/net/dev — счётчики своей сети) и через него самого, и делит предел (share):
каждой дороге — то, что не занято другой, но не меньше половины. Свою долю он ставит баку, долю
туннеля — классу tc на нём (tc class change, очередь не пересоздаётся). При остановке и когда
выход пропадает из настроек туннель получает весь предел обратно.
SIGHUP — перечитать настройки и списки (разбор идёт в потоке, соединения его не ждут).
Счётчики и байты по «клиент|выход» — в файл stats раз в 15 секунд и при остановке (по ним панель
считает трафик выходов).
"""
from __future__ import annotations

import asyncio
import bisect
import fcntl
import ipaddress
import json
import os
import resource
import signal
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass

SO_MARK = 36
SO_ORIGINAL_DST = 80
PEEK_TIMEOUT = 3.0          # сколько ждём первых данных клиента (ClientHello / запрос HTTP)
PEEK_MAX = 64 * 1024
CONNECT_TIMEOUT = 10.0
BUF = 256 * 1024
# splice без блокировки (ожидание готовности сокета остаётся за циклом событий); MOVE просит ядро
# переносить страницы, а не копировать. Запасные числа: модуль импортируется и там, где splice нет
# (тесты на macOS), сами вызовы splice там не выполняются.
SPLICE_FLAGS = getattr(os, "SPLICE_F_MOVE", 1) | getattr(os, "SPLICE_F_NONBLOCK", 2)
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
async def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Ровно n байт ответа прокси. Лишнее не читается: данные сайта, пришедшие сразу за ответом,
    остаются в сокете, и их пересылает splice."""
    loop = asyncio.get_running_loop()
    buf = b""
    while len(buf) < n:
        chunk = await asyncio.wait_for(loop.sock_recv(sock, n - len(buf)), CONNECT_TIMEOUT)
        if not chunk:
            raise OSError("socks: connection closed")
        buf += chunk
    return buf


async def _connect_any(host: str, port: int) -> socket.socket:
    """Подключение к прокси. Панель передаёт адрес, а если не смогла его разрешить, то имя; у имени
    может быть несколько адресов (IPv4 и IPv6), поэтому они пробуются по очереди. Адрес, который
    не подходит сети сервера (IPv6 без IPv6), тоже просто пропускается."""
    loop = asyncio.get_running_loop()
    err = None
    for family, kind, proto, _, addr in await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        s = None
        try:
            s = socket.socket(family, kind, proto)
            s.setblocking(False)
            await loop.sock_connect(s, addr)
            return s
        except BaseException as e:
            if s is not None:
                s.close()
            if not isinstance(e, OSError):
                raise
            err = e
    raise err or OSError(f"socks: no address for {host}")


async def socks_connect(s: dict, host: str | None, ip: str, port: int) -> socket.socket:
    """Соединение через прокси: CONNECT по имени (или по адресу, если имени нет).
    Возвращает сырой сокет: дальше поток идёт через splice, как и на прямом пути."""
    loop = asyncio.get_running_loop()
    sock = await asyncio.wait_for(_connect_any(s["ip"], int(s["port"])), CONNECT_TIMEOUT)
    try:
        user, pw = (s.get("user") or "").encode(), (s.get("password") or "").encode()
        await loop.sock_sendall(sock, b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
        ver, method = await _recv_exact(sock, 2)
        if ver != 5 or method == 0xFF:
            raise OSError("socks: no acceptable auth method")
        if method == 2:
            await loop.sock_sendall(sock, b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
            if (await _recv_exact(sock, 2))[1] != 0:
                raise OSError("socks: login rejected")
        if host:
            hb = host.encode("idna") if any(ord(c) > 127 for c in host) else host.encode()
            addr = b"\x03" + bytes([len(hb)]) + hb
        else:
            addr = b"\x01" + socket.inet_aton(ip)
        await loop.sock_sendall(sock, b"\x05\x01\x00" + addr + struct.pack("!H", port))
        head = await _recv_exact(sock, 4)
        if head[1] != 0:
            raise OSError(f"socks: connect failed ({head[1]})")
        n = {1: 4, 4: 16}.get(head[3])
        if n is None:
            n = (await _recv_exact(sock, 1))[0]          # адрес-имя: длина в первом байте
        await _recv_exact(sock, n + 2)
        return sock
    except BaseException:
        sock.close()
        raise


async def direct_socket(ip: str, port: int, mark: int) -> socket.socket:
    """Соединение к исходному адресу; метка политики выбирает выход в цепочке type route."""
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
    return s


def keepalive(sock: socket.socket) -> None:
    """Пропавший клиент (телефон ушёл из сети без FIN) не держит соединение вечно."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for opt, v in zip(("TCP_KEEPIDLE", "TCP_KEEPINTVL", "TCP_KEEPCNT"), KEEPALIVE):
            if hasattr(socket, opt):
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), v)
    except OSError:
        pass


SHARE_EVERY = 1.0          # как часто делить предел выхода между туннелем и посредником, с
TC_REFRESH = 10.0          # долю туннеля повторяем не реже (панель могла пересоздать очередь)
SHARE_SMOOTH = 0.5         # сглаживание скоростей при делении


def share(cap: float, other: float) -> float:
    """Доля одной дороги в общем пределе cap: то, что не занято другой, но не меньше половины —
    когда качают обе, предел делится примерно поровну, когда одна — она получает весь."""
    return max(cap - other, cap / 2)


def net_dev(text: str) -> dict[str, tuple[int, int]]:
    """/proc/net/dev → {интерфейс: (принято, отправлено)} в байтах."""
    out = {}
    for line in text.splitlines()[2:]:
        name, _, rest = line.partition(":")
        f = rest.split()
        if len(f) >= 9:
            out[name.strip()] = (int(f[0]), int(f[8]))
    return out


class Bucket:
    """Ограничение скорости, общее для всех соединений одного выхода в одну сторону: каждое
    соединение берёт байты из бака и, уйдя в минус, ждёт, пока бак не наполнится."""

    def __init__(self, rate: float):
        self.rate = float(rate)                       # байт/с
        self.cap = self.rate                          # предел из настроек (rate — текущая доля)
        self.burst = max(self.rate * 0.05, 65536.0)
        self.tokens = self.burst
        self.t = time.monotonic()
        self.total = 0                                # байт через бак — скорость посредника по выходу

    async def take(self, n: int) -> None:
        self.total += n
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.t) * self.rate)
        self.t = now
        self.tokens -= n
        if self.tokens < 0:
            await asyncio.sleep(-self.tokens / self.rate)


async def _ready(fd: int, writable: bool) -> None:
    """Ждёт готовности сокета через цикл событий, не читая данные в Python."""
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    add, remove = (loop.add_writer, loop.remove_writer) if writable else (loop.add_reader, loop.remove_reader)
    add(fd, lambda: fut.done() or fut.set_result(None))
    try:
        await fut
    finally:
        remove(fd)


async def splice_pipe(src: socket.socket, dst: socket.socket, cnt: list | None = None,
                      i: int = 0, act: list | None = None, bucket: Bucket | None = None) -> None:
    """Копирует поток src -> dst внутри ядра: сокет -> канал -> сокет через splice.

    Данные не попадают в Python: копирование в пространство пользователя и обратно стоило
    большей части CPU посредника. cnt[i]: счётчик байт (учёт трафика выходов), act[0]: время
    последних данных, bucket: ограничение скорости выхода SOCKS5. Пока бак ждёт, прочитанное
    лежит в канале, а сокет src не читается: TCP притормаживает отправителя.
    """
    rp, wp = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        try:
            fcntl.fcntl(wp, fcntl.F_SETPIPE_SZ, BUF)    # меньше переключений на каждый мегабайт
        except OSError:
            pass                                        # лимит pipe-user-pages: остаётся размер по умолчанию
        while True:
            try:
                n = os.splice(src.fileno(), wp, BUF, flags=SPLICE_FLAGS)
            except BlockingIOError:
                await _ready(src.fileno(), False)
                continue
            if n == 0:
                break                                   # собеседник закрыл запись
            if cnt is not None:
                cnt[i] += n
            if act is not None:
                act[0] = time.monotonic()
            if bucket is not None:
                await bucket.take(n)
            # Канал опустошается до следующего чтения: так EAGAIN при чтении означает только пустой сокет.
            while n:
                try:
                    n -= os.splice(rp, dst.fileno(), n, flags=SPLICE_FLAGS)
                except BlockingIOError:
                    await _ready(dst.fileno(), True)
    except OSError:
        pass
    finally:
        os.close(rp)
        os.close(wp)
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


async def relay_both(up, down, act: list) -> None:
    """Обе стороны соединения: до конца или пока соединение молчит дольше IDLE_TIMEOUT (act[0] -
    время последних данных). Сокеты потом закрывает вызывающий, поэтому возврат только когда обе
    стороны остановлены: иначе уцелевшая ждала бы на закрытом дескрипторе, который ядро уже выдало
    другому соединению. Ошибка одной стороны останавливает другую и поднимается дальше."""
    tasks = [asyncio.ensure_future(up), asyncio.ensure_future(down)]
    try:
        while True:
            done, pending = await asyncio.wait(tasks, timeout=min(60, IDLE_TIMEOUT),
                                               return_when=asyncio.FIRST_EXCEPTION)
            if not pending or any(t.exception() for t in done):
                break
            if time.monotonic() - act[0] > IDLE_TIMEOUT:
                break
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.wait(tasks)
    for t in tasks:
        if not t.cancelled() and t.exception():
            raise t.exception()


def _ipv4_range(text: str) -> int | None:
    """'a.b.c.d/nn' или адрес -> первый адрес << 32 | последний; None: IPv6, мусор, пустая строка.
    Без модуля ipaddress: он разбирает 100 000 строк за 0,7 с, а inet_pton в разы быстрее. Длина
    префикса строгая, как у ipaddress и nftables: учёт не должен расходиться с маршрутами."""
    addr, slash, bits = text.partition("/")
    if slash and not (bits.isascii() and bits.isdigit()):
        return None
    try:
        a = int.from_bytes(socket.inet_pton(socket.AF_INET, addr), "big")
    except OSError:
        return None
    n = int(bits) if slash else 32
    if n > 32:
        return None
    host = (1 << (32 - n)) - 1                      # биты узла: подсеть без strict, как у панели
    return (a & ~host) << 32 | a | host


class Nets:
    """Адреса списка (файл CIDR панели) для поиска «в какой выход уйдёт соединение» —
    так же, как цепочка q_* в nftables, только для учёта трафика."""

    def __init__(self, path: str):
        # Полоса хранится одним числом "начало << 32 | конец": сортировка держит GIL и на это время
        # останавливает цикл событий, а числа сортируются втрое быстрее пар.
        ranges = []
        with open(path) as f:
            for line in f:
                r = _ipv4_range(line.strip())
                if r is not None:
                    ranges.append(r)
        ranges.sort()
        self.starts, self.ends = [], []
        for r in ranges:
            a, b = r >> 32, r & 0xFFFFFFFF
            if self.ends and a <= self.ends[-1] + 1:
                self.ends[-1] = max(self.ends[-1], b)
            else:
                self.starts.append(a)
                self.ends.append(b)

    def __contains__(self, ip: str) -> bool:
        x = int(ipaddress.IPv4Address(ip))
        i = bisect.bisect_right(self.starts, x) - 1
        return i >= 0 and self.ends[i] >= x


# --------------------------------------------------------------- настройки
@dataclass(frozen=True)
class Conf:
    """Разобранный sni.json со списками. Строится целиком до подмены: посредник видит либо старые
    настройки, либо новые, но не смесь."""
    cfg: dict
    lists: dict[str, set[str]]                      # домены списков из правил
    nets: dict[str, Nets]                           # адреса списков: учёт трафика без совпадения
    rates: dict[tuple[str, int], float]             # (выход, сторона) -> байт/с для бака
    shared: dict[tuple[str, int], dict]             # общий предел туннеля и посредника: {"iface", "cap", "tc"}
    net: ipaddress.IPv4Network | ipaddress.IPv6Network   # адреса клиентов, которых посредник обслуживает


def load(path: str) -> Conf:
    """Читает и разбирает настройки, ничего не меняя в посреднике: так это можно делать в потоке,
    пока цикл событий обслуживает соединения (100 000 адресов разбираются около секунды)."""
    with open(path) as f:
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
    rates = {}
    for out, pair in (cfg.get("rates") or {}).items():
        for i in (0, 1):
            v = pair[i] if isinstance(pair, list) and len(pair) == 2 else 0
            if isinstance(v, (int, float)) and v > 0:
                rates[(out, i)] = float(v)
    shared = {}
    for out, dirs in (cfg.get("shared") or {}).items():
        for i in (0, 1):
            d = (dirs or {}).get(str(i)) if isinstance(dirs, dict) else None
            # cap нужен числом: по нему туннелю возвращают весь предел, когда деление кончается
            if isinstance(d, dict) and (out, i) in rates and isinstance(d.get("tc"), list) \
                    and isinstance(d.get("cap"), (int, float)) and d["cap"] > 0:
                shared[(out, i)] = d
    net = ipaddress.ip_network(cfg.get("clients") or "0.0.0.0/0", strict=False)
    return Conf(cfg, lists, nets, rates, shared, net)


# --------------------------------------------------------------- посредник
class Sniffer:
    def __init__(self, path: str):
        self.path = path
        self.stats = {"conns": 0, "active": 0, "matched": 0, "errors": 0, "no_name": 0,
                      "started": time.time(), "by_list": {}}
        # байты по «клиент|выход» с запуска процесса: панель добавляет их к трафику выходов
        # (соединения через посредника — не транзитные, таблица учёта nftables их не видит)
        self.bytes: dict[str, list[int]] = {}
        self.buckets: dict[tuple[str, int], Bucket] = {}   # (выход, 0 — отдача | 1 — загрузка)
        self.shared: dict[tuple[str, int], dict] = {}
        self.share_state: dict[tuple[str, int], dict] = {}  # скорости и последняя доля tc для деления
        self.hup = False                    # пришёл SIGHUP, который ещё не перечитан
        self.reloading: asyncio.Task | None = None
        self.reload()

    def reload(self) -> None:
        """Перечитать настройки сразу, в вызывающем потоке (запуск посредника)."""
        for d in self.apply(load(self.path)):
            self.tc_set(d, d["cap"], wait=False)

    def apply(self, c: Conf) -> list[dict]:
        """Подменяет настройки. Бак с прежней скоростью остаётся тем же: открытые соединения держат
        ссылку на него, и с новым баком предел выхода делился бы надвое.
        -> настройки tc выходов, которые больше не делятся: их туннелям нужно вернуть весь предел."""
        self.cfg, self.lists, self.nets, self.net = c.cfg, c.lists, c.nets, c.net
        self.buckets = {k: b if (b := self.buckets.get(k)) and b.cap == r else Bucket(r)
                        for k, r in c.rates.items()}
        old, self.shared = self.shared, c.shared
        self.share_state = {k: v for k, v in self.share_state.items() if k in c.shared}
        return [d for k, d in old.items() if k not in c.shared or c.shared[k].get("tc") != d.get("tc")]

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

    async def client(self, sock: socket.socket) -> None:
        """Одно перенаправленное соединение: имя сайта, выбор пути, пересылка через splice."""
        loop = asyncio.get_running_loop()
        sock.setblocking(False)
        out = None
        counted = False
        peer = "?"                  # для журнала, если клиент пропал раньше, чем узнали его адрес
        try:
            peer = sock.getpeername()[0]
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
                    chunk = await asyncio.wait_for(loop.sock_recv(sock, PEEK_MAX - len(data)), left)
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
            keepalive(sock)
            cnt = self.counter(peer, to.get("acct") if lid else self.miss_out(peer, dip))
            act = [time.monotonic()]
            if to.get("socks"):
                out = await socks_connect(to["socks"], name, dip, dport)
                # через прокси — мимо туннеля выхода: его ограничение скорости — здесь
                bk = [self.buckets.get((to.get("acct"), i)) for i in (0, 1)]
            else:
                out = await direct_socket(dip, dport, int(to.get("mark") or 0))
                bk = [None, None]           # с меткой идёт через туннель выхода: его ограничивает tc там
            keepalive(out)
            if data:
                await loop.sock_sendall(out, data)
                if cnt is not None:
                    cnt[0] += len(data)
            await relay_both(splice_pipe(sock, out, cnt, 0, act, bk[0]),
                             splice_pipe(out, sock, cnt, 1, act, bk[1]), act)
        except (OSError, asyncio.TimeoutError, ValueError) as e:
            self.stats["errors"] += 1
            if self.cfg.get("debug"):
                log(f"{peer}: {e!r}")
        finally:
            if counted:
                self.stats["active"] -= 1
            for c in (sock, out):
                if c is not None:
                    try:
                        c.close()
                    except OSError:
                        pass

    # ------------------------------------------------ общий предел выхода SOCKS5
    def tc_set(self, d: dict, bps: float, wait: bool = True):
        """Скорость класса tc туннеля → bps (байт/с). wait=False — без ожидания (остановка, reload)."""
        argv = [str(x).replace("{kbit}", str(max(1, int(bps * 8 / 1000)))) for x in d["tc"]]
        try:
            p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except OSError as e:
            log(f"tc: {e}")
            return None
        if not wait:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
            return None
        return p

    def share_tick(self, dev: dict[str, tuple[int, int]], now: float) -> list:
        """Одно деление: новые доли бакам и туннелям. → [(настройка, байт/с)] — что поставить tc."""
        todo = []
        for k, d in self.shared.items():
            out, i = k
            b = self.buckets[k]
            st = self.share_state.setdefault(k, {"t": now, "own": b.total, "tun": None,
                                                  "r_own": 0.0, "r_tun": 0.0, "tc": None, "tc_at": 0.0})
            dt = now - st["t"]
            c = dev.get(d.get("iface") or "")
            # отправлено в туннель — отдача клиентов (0), принято из туннеля — загрузка (1)
            tun = c[1] if c and i == 0 else c[0] if c else None
            if dt > 0:
                inst_own = (b.total - st["own"]) / dt
                inst_tun = (tun - st["tun"]) / dt if tun is not None and st["tun"] is not None and tun >= st["tun"] else 0.0
                st["r_own"] += SHARE_SMOOTH * (inst_own - st["r_own"])
                st["r_tun"] += SHARE_SMOOTH * (inst_tun - st["r_tun"])
            st.update(t=now, own=b.total, tun=tun)
            cap = float(d["cap"])
            b.rate = share(cap, st["r_tun"])
            want = share(cap, st["r_own"])
            if st["tc"] is None or abs(want - st["tc"]) > cap * 0.03 or now - st["tc_at"] >= TC_REFRESH:
                st["tc"], st["tc_at"] = want, now
                todo.append((d, want))
        return todo

    async def share_loop(self) -> None:
        while True:
            await asyncio.sleep(SHARE_EVERY)
            if not self.shared:
                continue
            try:
                with open("/proc/net/dev") as f:
                    dev = net_dev(f.read())
            except OSError:
                dev = {}
            for d, bps in self.share_tick(dev, time.monotonic()):
                p = self.tc_set(d, bps)
                if p is not None:
                    await asyncio.get_running_loop().run_in_executor(None, self._reap, p)

    @staticmethod
    def _reap(p) -> None:
        try:
            _, err = p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
            return
        if p.returncode and err:
            log(f"tc: {err.decode(errors='replace').strip()[-200:]}")

    def restore(self) -> None:
        """Остановка: туннелям — весь предел."""
        for d in self.shared.values():
            self.tc_set(d, d["cap"], wait=False)

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
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1024)
        listener.setblocking(False)
        asyncio.ensure_future(self.accept_loop(listener))
        loop.add_signal_handler(signal.SIGHUP, self.on_hup)
        loop.add_signal_handler(signal.SIGTERM, loop.stop)
        log(f"listening on {host}:{port}, {len(self.lists)} domain lists")
        asyncio.ensure_future(self.share_loop())
        while True:
            self.write_stats()
            await asyncio.sleep(STATS_EVERY)

    async def accept_loop(self, listener: socket.socket) -> None:
        """Свой приём вместо start_server: клиенту нужен сырой сокет, а не потоки asyncio."""
        loop = asyncio.get_running_loop()
        tasks: set[asyncio.Task] = set()      # цикл событий держит только слабые ссылки на задачи
        while True:
            try:
                conn, _ = await loop.sock_accept(listener)
            except OSError as e:
                log(f"accept: {e}")         # например, исчерпаны дескрипторы: не крутим цикл впустую
                await asyncio.sleep(0.1)
                continue
            task = asyncio.ensure_future(self.client(conn))
            tasks.add(task)
            task.add_done_callback(tasks.discard)

    def on_hup(self) -> None:
        """SIGHUP: перечитать настройки. Панель шлёт его при каждом изменении, и сигнал во время
        перечитывания не теряется: после текущего идёт ещё одно, уже с последним файлом."""
        self.hup = True
        if self.reloading is None or self.reloading.done():
            self.reloading = asyncio.ensure_future(self.reload_async())

    async def reload_async(self) -> None:
        """Чтение и разбор идут в потоке, подмена в цикле событий: соединения не ждут разбора."""
        loop = asyncio.get_running_loop()
        while self.hup:
            self.hup = False
            try:
                conf = await loop.run_in_executor(None, load, self.path)
            except Exception as e:  # noqa: BLE001
                log(f"reload: {e}")             # прежние настройки остаются
                continue
            for d in self.apply(conf):
                p = self.tc_set(d, d["cap"])    # выход ушёл из деления — весь предел туннелю
                if p is not None:
                    await loop.run_in_executor(None, self._reap, p)


def log(text: str) -> None:
    print(time.strftime("%Y-%m-%d %H:%M:%S"), text, file=sys.stderr, flush=True)


def raise_open_files_limit() -> None:
    """Соединение держит 6 дескрипторов (2 сокета и 2 канала splice), а мягкий предел, унаследованный
    от панели, бывает 1024: это около 170 соединений. Жёсткий предел процесс может взять себе сам."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < hard:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        except (OSError, ValueError) as e:
            log(f"open files limit stays {soft}: {e}")


def main() -> None:
    raise_open_files_limit()
    s = Sniffer(sys.argv[1])
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    task = loop.create_task(s.serve())
    try:
        loop.run_forever()
    finally:
        task.cancel()
        s.write_stats()
        s.restore()


if __name__ == "__main__":
    main()
