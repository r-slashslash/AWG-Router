"""DNS панели для клиентов. Только стандартная библиотека, без импорта панели.

Запускается панелью в сети сервера AWG (как туннели выходов и sniproxy.py):
    nsenter -t PID -n -- python3 dnsproxy.py /run/awgr/dns.json
Слушает UDP и TCP 53 на адресе сервера в туннеле. Клиенты получают этот адрес в строке DNS
своего конфига. Запрос клиента пересылается серверам DNS из настроек (рекурсией занимаются
они) — тем же путём, что и трафик этого клиента: сокет получает метку (fwmark) его основного
выхода, поэтому запрос уходит через туннель выхода, а ответ получен в стране выхода. Клиент,
который ходит напрямую, получает ответ, полученный напрямую с этого сервера; клиент с блоком —
отказ (REFUSED). На запрос адреса IPv6 (AAAA) — ответ «записей нет»: в туннеле только IPv4.

Ответы кэшируются отдельно для каждого пути (ответы CDN зависят от страны) на срок их TTL,
отдаются с уменьшенным TTL.

Шифрование (настройка encrypt): «doh» — DNS поверх HTTPS (порт 443, RFC 8484), «dot» — поверх TLS
(порт 853, RFC 7858), «plain» — без шифрования. С шифрованием сертификат сервера проверяется (по имени
сервиса для известных адресов — KNOWN_NAMES — или по IP-адресу), открытый DNS вместо него не
используется: сервер не ответил — клиент получает SERVFAIL и спрашивает второй DNS из конфига.
TLS-соединения держатся открытыми (пул на пару «путь, сервер»), чтобы не делать рукопожатие на
каждый запрос. Без шифрования через выходы SOCKS5 запросы идут по TCP (UDP через прокси часто не
работает), иначе — UDP, а при обрезанном ответе — TCP.

Правила по доменам (с 1.21.0, настройка dom). Имя из правила по доменам политики клиента
разбирается через выход этого правила, а не через основной: соединение с сайтом уйдёт в этот
выход (sniproxy.py), и адрес нужен оттуда — не подменённый по дороге и рядом с выходом (CDN).
Правило «блок» и выход, который сейчас не работает, — обычным путём клиента. Если задан набор
nftables (dom.set), адреса A из ответа на такое имя добавляются в него на срок TTL, но не меньше
SET_MIN: с ним панель перехватывает только соединения к этим адресам (режим «фильтр по DNS»).
Набор пересоздаётся вместе с таблицей панели — по SIGUSR1 все живые адреса добавляются заново.

SIGHUP — перечитать настройки. Счётчики — в файл stats раз в 15 секунд (по свежести файла
панель видит, что процесс не завис).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time

SO_MARK = 36
PORT = 53
UDP_TIMEOUT = 2.0           # ждём ответа сервера по UDP, потом следующий сервер
TCP_TIMEOUT = 5.0
CLIENT_TCP_IDLE = 10.0      # соединение клиента по TCP без новых запросов дольше — закрываем
CACHE_MAX = 20000           # записей в кэше; старые вытесняются
CACHE_BYTES = 16 * 1024 * 1024   # и не больше 16 МБ ответов: по TCP ответ до 64 КБ, 20 000 таких — больше гигабайта
TTL_MAX = 3600              # дольше часа не храним, даже если TTL больше
NEG_TTL_MAX = 300           # «нет такого имени» / «нет записей» — не дольше 5 минут
NEG_TTL_DEFAULT = 30        # если в ответе нет SOA
STATS_EVERY = 15
MAX_INFLIGHT = 512          # одновременных запросов к серверам; больше — отказ (SERVFAIL)
# Путь «напрямую» и шифрованный DNS: из России, Китая и Ирана общие серверы по DoH/DoT часто не отвечают. Тогда
# имена спрашиваются у местного DNS страны сервера (cfg direct_fallback, обычный DNS), а шифрованный пробуется снова
# не раньше чем через DIRECT_RETRY и одним запросом в фоне: DoH из России «зависает» до ENC_TIMEOUT на каждом
# сервере, и проба с запросом клиента раз в две минуты на 10 с останавливала бы имена всем, кто идёт напрямую.
# Только «напрямую»: имена клиентов, которые идут через выход, и имена из правил по доменам, у которых сейчас нет
# пути (выход подключается, лежит или «блок»), мимо выхода не уходят никогда.
DIRECT_RETRY = 120.0

DOT_PORT, DOH_PORT = 853, 443
ENC_TIMEOUT = 5.0           # соединение и ответ по DoT/DoH
POOL_SIZE = 4               # открытых TLS-соединений на пару «путь, сервер»
POOL_IDLE = 50.0            # дольше без запросов — соединение закрываем (серверы сами закрывают через ~60 с)
# Имя сервиса для известных адресов: с ним проверяется сертификат и его ждёт заголовок Host у DoH
# (Google по голому IP DoH может не отвечать). Остальные адреса проверяются по IP в сертификате.
KNOWN_NAMES = {"1.1.1.1": "cloudflare-dns.com", "1.0.0.1": "cloudflare-dns.com",
               "8.8.8.8": "dns.google", "8.8.4.4": "dns.google",
               "9.9.9.9": "dns.quad9.net", "149.112.112.112": "dns.quad9.net"}

SET_MIN = 1800              # с: адрес сайта из правила держится в наборе не меньше (устройства кэшируют дольше TTL)
SET_MAX = 86400
SET_FLUSH = 0.3             # с: адреса копятся и уходят в nftables одной командой
SET_LIVE_MAX = 200000       # живых адресов в памяти для повторного добавления; больше — старые забываются

T_OPT, T_SOA, T_A, T_AAAA = 41, 6, 1, 28
T_SVCB, T_HTTPS = 64, 65   # записи SVCB и HTTPS: в HTTPS браузер берёт ключи ECH
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
    start = off
    while True:
        n = msg[off]
        if n == 0:
            return ".".join(labels).lower() + "."
        if n & 0xC0:
            raise ValueError("label")
        label = msg[off + 1:off + 1 + n]
        if b"." in label:
            # метка «victim.site» + «test» дала бы то же имя «victim.site.test.», что у обычного вопроса, и
            # ответ «нет такого имени» на неё из кэша получили бы другие клиенты
            raise ValueError("label")
        labels.append(label.decode("ascii", "replace"))
        off += 1 + n
        if off - start > 255:           # имя в DNS — не длиннее 255 байт (RFC 1035 §3.1)
            raise ValueError("name")


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


def answer_v4(msg: bytes) -> list[tuple[str, int]]:
    """Адреса IPv4 из раздела ответов (вместе с теми, что после CNAME): [(адрес, TTL)]."""
    _id, _flags, qd, an, _ns, _ar = struct.unpack("!6H", msg[:12])
    off = 12
    for _ in range(qd):
        off = skip_name(msg, off) + 4
    out = []
    for _ in range(an):
        off = skip_name(msg, off)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        if rtype == T_A and rclass == 1 and rdlen == 4 and off + 4 <= len(msg):
            out.append((socket.inet_ntoa(msg[off:off + 4]), ttl))
        off += rdlen
    return out


def match(name: str, doms: set[str]) -> bool:
    """Имя (с точкой в конце или без) есть в списке — само или как поддомен (как в sniproxy.py)."""
    if len(name) > 254:                 # не имя DNS; на нём перебор суффиксов занял бы секунды
        return False
    labels = name.rstrip(".").split(".")
    return any(".".join(labels[i:]) in doms for i in range(len(labels)))


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
        self.nets: tuple = ()
        self.self_addrs: set[str] = set()
        self.cache: dict[tuple, tuple[float, int, bytes, list[int]]] = {}
        self.cache_bytes = 0
        self.stats = {"queries": 0, "cached": 0, "errors": 0, "refused": 0}
        self.last_ok = 0.0                  # когда серверы DNS последний раз ответили
        # шифрованный DNS на пути «напрямую»: когда последний раз ответил и когда не ответил ни один сервер;
        # direct_down — не отвечает, имена у местного DNS; direct_retry_at — когда пробовать снова (в фоне)
        self.direct_ok_at = self.direct_fail_at = 0.0
        self.direct_down, self.direct_retry_at = False, 0.0
        self._direct_probe = None            # идущая проба шифрованного (asyncio.Task)
        self.last_error, self.last_error_at = "", 0.0
        self.inflight = 0
        self.pools: dict[tuple, Pool] = {}
        self.dom_lists: dict[str, set[str]] = {}
        self._dom_files: dict[str, tuple] = {}       # путь → (признаки файла, разобранное): SIGHUP не разбирает заново
        self.live: dict[str, float] = {}             # адрес → до какого времени (time.time) он в наборе
        self.pending: dict[str, int] = {}            # адрес → секунд, ещё не отправленные в nftables
        self._flush_at = 0.0
        self.load()

    def load(self) -> None:
        with open(self.conf_path) as f:
            cfg = json.load(f)
        raw_nets = cfg.get("clients_nets") or ([cfg["clients"]] if cfg.get("clients") else [])
        self.nets = tuple(ipaddress.ip_network(n) for n in raw_nets)
        self.net = self.nets[0] if self.nets else None
        self.up_port = int(cfg.get("upstream_port") or PORT)     # не 53 — только в тестах
        # адрес этого DNS: свой DNS правила с ним спрашивал бы сам себя (domain_route его пропускает)
        same_port = self.up_port == int(cfg.get("port") or PORT)
        addrs = cfg.get("listen_addrs") or ([cfg["listen"]] if cfg.get("listen") else [])
        self.self_addrs = set(addrs) if same_port else set()
        self.self_addr = cfg.get("listen") if same_port else None
        old = self.cfg
        self.cfg = cfg
        if old and (old.get("upstreams") != cfg.get("upstreams") or old.get("encrypt") != cfg.get("encrypt")):
            self.cache.clear()                       # другие серверы — старые ответы не нужны
            self.cache_bytes = 0
            # и «шифрованный не отвечает напрямую» был о прежних серверах или прежнем шифровании
            self.direct_ok_at = self.direct_fail_at = 0.0
            self.direct_down, self.direct_retry_at = False, 0.0
        for p in self.pools.values():                # пути, серверы или сертификаты могли смениться
            p.close()
        self.pools.clear()
        self.ctx = ssl.create_default_context(cafile=cfg.get("ca_file") or None)   # ca_file — только в тестах
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.dom = cfg.get("dom") or {}
        lists, files = {}, {}
        for lid, path in (self.dom.get("lists") or {}).items():
            try:
                with open(path) as f:
                    st = os.fstat(f.fileno())
                    sig = (st.st_ino, st.st_size, st.st_mtime_ns)
                    hit = self._dom_files.get(path)
                    lists[lid] = hit[1] if hit and hit[0] == sig else {x.strip() for x in f if x.strip()}
                files[path] = (sig, lists[lid])
            except OSError as e:
                print(f"dnsproxy: list {lid}: {e}", flush=True)
        self.dom_lists, self._dom_files = lists, files
        if old and old.get("dom", {}).get("set") != self.dom.get("set"):
            self.live.clear()

    def domain_route(self, ip: str, name: str):
        """Правило по доменам политики клиента, в чей список входит имя: (путь, серверы, в набор?) — разбирать
        через выход правила (путь None — обычным путём клиента: «блок» или выход сейчас не работает) у своих
        серверов DNS правила (пусто — у общих); None — имя ни в одном правиле. Правило — [списки, путь] или
        [списки, путь, серверы, в набор?] (у политики со своим DNS).
        Без пути (выход правила подключается, лежит или «блок») свой DNS не спрашивается: путь клиента часто
        «напрямую», и имена сайтов правила ушли бы мимо выхода обычным DNS без шифрования — общие серверы, как
        до 1.22.0. Свой DNS с адресом, на котором слушает этот DNS, пропускается: он спрашивал бы сам себя."""
        pol = (self.dom.get("clients") or {}).get(ip, "p_global")
        for rule in (self.dom.get("policies") or {}).get(pol) or ():
            if any(match(name, self.dom_lists.get(lid) or ()) for lid in rule[0]):
                if len(rule) >= 4:
                    own = () if rule[1] is None else tuple(s for s in rule[2] or () if s not in self.self_addrs)
                    return rule[1], own, bool(rule[3])
                return rule[1], (), True
        return None

    def remember(self, reply: bytes) -> None:
        """Адреса из ответа на имя из правила — в набор nftables (режим «фильтр по DNS»)."""
        if not self.dom.get("set"):
            return
        try:
            ips = answer_v4(reply)
        except (ValueError, struct.error, IndexError):
            return
        now = time.time()
        for addr, ttl in ips:
            secs = max(SET_MIN, min(int(ttl), SET_MAX))
            if self.live.get(addr, 0) - now > secs - 60:
                continue                             # уже в наборе почти на тот же срок
            self.pending[addr] = secs
            if len(self.live) >= SET_LIVE_MAX:
                self.live.pop(next(iter(self.live)))
            self.live[addr] = now + secs
        if self.pending and not self._flush_at:
            self._flush_at = now
            asyncio.get_running_loop().call_later(SET_FLUSH, self.flush)

    def resync(self) -> None:
        """SIGUSR1: панель пересоздала свою таблицу (а с ней пустой набор) — добавить все живые адреса."""
        now = time.time()
        self.live = {a: t for a, t in self.live.items() if t > now + 5}
        for a, t in self.live.items():
            self.pending[a] = int(t - now)
        # сразу, без SET_FLUSH: пока набор пуст, соединения к сайтам из правил идут мимо обработчика
        if self.pending:
            self.flush()

    def flush(self):
        """Накопленные адреса — в набор nftables. Команда идёт в отдельном потоке: nft ждёт блокировку
        таблицы, пока панель её пересобирает (с большими списками — секунды), а цикл событий в это
        время должен отвечать на запросы DNS. → future команды (тестам) или None."""
        self._flush_at = 0.0
        batch, self.pending = self.pending, {}
        target = self.dom.get("set")
        if not batch or not target:
            return None
        self.stats["set_added"] = self.stats.get("set_added", 0) + len(batch)
        return asyncio.get_running_loop().run_in_executor(None, self._nft_add, *target, list(batch.items()))

    @staticmethod
    def _nft_add(table: str, name: str, items: list) -> None:
        for i in range(0, len(items), 2000):             # одна команда — не больше 2000 адресов
            elems = ", ".join(f"{a} timeout {t}s" for a, t in items[i:i + 2000])
            try:
                r = subprocess.run(["nft", "add", "element", "ip", table, name, "{ " + elems + " }"],
                                   capture_output=True, text=True, timeout=10)
                if r.returncode:
                    print(f"dnsproxy: nft: {r.stderr.strip()[:200]}", flush=True)
            except (OSError, subprocess.SubprocessError) as e:
                print(f"dnsproxy: nft: {e}", flush=True)

    def route(self, ip: str) -> dict | None:
        """Путь запросов клиента: {"mark", "tcp"}; None — блок."""
        r = (self.cfg.get("routes") or {}).get(ip, "default")
        return self.cfg.get("default") if r == "default" else r

    def allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            if self.nets:
                return any(addr in n for n in self.nets)
            return self.net is None or addr in self.net
        except ValueError:
            return False

    async def resolve(self, query: bytes, q: dict, ip: str) -> bytes:
        self.stats["queries"] += 1
        dom = self.domain_route(ip, q["name"]) if self.dom else None
        route = dom[0] if dom and dom[0] is not None else self.route(ip)
        servers = dom[1] if dom else ()
        if dom:
            self.stats["by_rule"] = self.stats.get("by_rule", 0) + 1
        if route is None:
            self.stats["refused"] += 1
            return error_reply(query, q, RC_REFUSED)
        if q["qtype"] == T_AAAA and q["qclass"] == 1:
            # В туннеле только IPv4 (у клиентов нет адреса IPv6, правила панели — для IPv4): с адресом IPv6
            # приложение сначала ждало бы соединения, которое не пройдёт, и только потом брало IPv4.
            # Ответ «записей нет» (NOERROR без записей) — и оно сразу идёт по IPv4.
            self.stats["aaaa"] = self.stats.get("aaaa", 0) + 1
            return error_reply(query, q, 0)
        if dom and q["qtype"] in (T_HTTPS, T_SVCB) and q["qclass"] == 1:
            # ECH: ключи ECH браузер берёт из записи HTTPS (Cloudflare включил ECH по умолчанию), и тогда имя сайта в
            # ClientHello зашифровано — правило по доменам его не узнаёт, и сайт идёт по правилам адресов. Для имён из
            # правил по доменам — «записей нет»: браузер открывает сайт без ECH (решение владельца 2026-11-21)
            self.stats["https_rr"] = self.stats.get("https_rr", 0) + 1
            return error_reply(query, q, 0)
        if servers:
            self.stats["own_dns"] = self.stats.get("own_dns", 0) + 1
        # имя из правила, у которого сейчас нет пути (выход подключается, лежит или «блок»): местного DNS ему нельзя —
        # сайт должен идти через выход, и имя ушло бы мимо него открытым текстом
        reply = await self._resolve(query, q, route, servers, fallback=not (dom and dom[0] is None))
        if dom and dom[2] and q["qtype"] == T_A:
            self.remember(reply)
        return reply

    async def _resolve(self, query: bytes, q: dict, route: dict, servers: tuple = (), fallback: bool = True) -> bytes:
        mark, tcp = int(route.get("mark") or 0), bool(route.get("tcp"))
        key = (mark, servers, q["name"], q["qtype"], q["qclass"])
        hit = self.cache.get(key)
        now = time.monotonic()
        if hit and hit[0] > now:
            self.stats["cached"] += 1
            reply = with_ttl(hit[2], hit[3], int(now - hit[1]))
            if reply[4:6] == b"\x00\x01":
                # вопрос — как задал этот клиент (регистр букв), а не первый, чей ответ лёг в кэш
                reply = reply[:12] + query[12:q["qend"]] + reply[q["qend"]:]
            return struct.pack("!H", q["id"]) + reply[2:]
        if self.inflight >= MAX_INFLIGHT:
            self.stats["errors"] += 1
            return error_reply(query, q, RC_SERVFAIL)
        self.inflight += 1
        try:
            cfg = getattr(self, "cfg", None) or {}       # тесты собирают Proxy без load()
            enc_direct = not servers and mark == 0 and (cfg.get("encrypt") or "plain") != "plain"
            fb = tuple(cfg.get("direct_fallback") or ()) if enc_direct and fallback else ()
            reply = None
            if fb and getattr(self, "direct_down", False):
                self._probe_direct(query, q, tcp)          # клиент не ждёт: шифрованный пробуется в фоне
            else:
                reply = await self.forward(query, q, mark, tcp, servers)
                if enc_direct:
                    self._direct_seen(reply is not None, bool(fb))
            if reply is None and fb:
                reply = await self.forward(query, q, mark, tcp, fb)          # местный DNS, обычный
                if reply is not None:
                    self.stats["direct_fallback"] = self.stats.get("direct_fallback", 0) + 1
        finally:
            self.inflight -= 1
        if reply is None or reply[3] & 0xF == RC_SERVFAIL:
            self.stats["errors"] += 1           # SERVFAIL самих серверов не кэшируется (cache_ttl) и уходит клиенту
            if reply is None:
                return error_reply(query, q, RC_SERVFAIL)
        try:
            ttl, offs = cache_ttl(reply)
        except (ValueError, struct.error):
            ttl, offs = 0, []
        if ttl > 0:
            old = self.cache.pop(key, None)
            if old:
                self.cache_bytes -= len(old[2])
            while self.cache and (len(self.cache) >= CACHE_MAX or self.cache_bytes + len(reply) > CACHE_BYTES):
                self.cache_bytes -= len(self.cache.pop(next(iter(self.cache)))[2])
            self.cache[key] = (now + ttl, int(now), reply, offs)
            self.cache_bytes += len(reply)
        return struct.pack("!H", q["id"]) + reply[2:]

    def _direct_seen(self, ok: bool, fallback: bool) -> None:
        """Ответил ли шифрованный DNS на пути «напрямую» (ответ SERVFAIL — тоже ответ: сервер на связи, сломан сайт).
        Не ответил и есть местный DNS — имена «напрямую» идут к нему, шифрованный пробуется снова через DIRECT_RETRY."""
        if ok:
            self.direct_ok_at, self.direct_down = time.time(), False
            return
        self.direct_fail_at = time.time()
        if fallback:
            self.direct_down, self.direct_retry_at = True, time.monotonic() + DIRECT_RETRY

    def _probe_direct(self, query: bytes, q: dict, tcp: bool) -> None:
        """Шифрованный DNS не отвечает напрямую: раз в DIRECT_RETRY один запрос клиента спрашивается у него ещё раз — в
        фоне, а клиент сразу получает ответ местного DNS. Ответил — имена «напрямую» снова идут к шифрованному."""
        probe = getattr(self, "_direct_probe", None)
        if time.monotonic() < getattr(self, "direct_retry_at", 0.0) or (probe and not probe.done()):
            return
        self.direct_retry_at = time.monotonic() + DIRECT_RETRY

        async def run():
            try:
                reply = await self.forward(query, q, 0, tcp)
            except Exception:  # noqa: BLE001  — проба не должна ронять цикл; считаем, что не ответил
                reply = None
            self._direct_seen(reply is not None, True)
        self._direct_probe = asyncio.get_running_loop().create_task(run())

    async def forward(self, query: bytes, q: dict, mark: int, tcp: bool, servers: tuple = ()) -> bytes | None:
        """Запрос к серверам по очереди: первый, кто ответил по делу, — ответ. servers — свой DNS правила по
        сайтам: всегда обычный DNS (UDP, при обрезанном ответе — TCP), без шифрования: местные DNS вроде
        Яндекса, Alibaba или иранских по адресу DoH/DoT часто не отвечают. Все, кто ответил, ответили SERVFAIL, —
        этот ответ (серверы на связи, не разрешилось само имя); None — не ответил никто."""
        mode = "plain" if servers else (self.cfg.get("encrypt") or "plain")
        servfail = None
        for server in servers or self.cfg.get("upstreams") or []:
            if not servers and mode == "plain" and server in self.self_addrs:
                continue        # общий сервер = адрес этого DNS: спрашивал бы сам себя по кругу (Г20 проверки 1.23.0)
            qid = secrets.randbelow(65536)       # ID запроса — непредсказуемый (не вихрь Мерсенна)
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
                servfail = reply
                continue                                              # спросим следующий сервер
            self.last_ok = time.time()
            return reply
        return servfail

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
                               "direct_ok_at": self.direct_ok_at, "direct_fail_at": self.direct_fail_at,
                               "fallback": list(self.cfg.get("direct_fallback") or ()),
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
    addrs = proxy.cfg.get("listen_addrs") or [proxy.cfg["listen"]]
    port = int(proxy.cfg.get("port") or PORT)
    servers = []
    for listen in addrs:
        await loop.create_datagram_endpoint(lambda: UDPServer(proxy), local_addr=(listen, port))
        servers.append(await asyncio.start_server(proxy.handle_tcp, listen, port, reuse_address=True))
    stop = asyncio.Event()
    loop.add_signal_handler(signal.SIGHUP, proxy.load)
    loop.add_signal_handler(signal.SIGUSR1, proxy.resync)
    loop.add_signal_handler(signal.SIGTERM, stop.set)
    loop.add_signal_handler(signal.SIGINT, stop.set)
    print(f"dnsproxy: {','.join(addrs)}:{port}", flush=True)
    proxy.stats_loop()
    try:
        await stop.wait()
    finally:
        for s in servers:
            s.close()
        for s in servers:
            await s.wait_closed()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
