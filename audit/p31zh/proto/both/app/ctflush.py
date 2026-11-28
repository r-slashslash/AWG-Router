"""Обрыв соединений, у которых сменился путь (1.25.0): записи conntrack клиентов, чей выход или адрес поменяли вручную.

Запускается в сети сервера AWG: `nsenter -t PID -n -- python3 ctflush.py`, задание — JSON на stdin:
    {"clients": {IP клиента: {"old": путь, "new": путь}}, "lists": {id списка: [сети]}, "skip": [сети],
     "quic": [IP клиентов, у которых поменялись правила по доменам]}
путь — {"rules": [[[id списков], выход], …] (правила по адресам по порядку), "default": выход}; выход — строка
настроек («up:id», «direct@адрес», «block», балансировка). Запись conntrack клиента (адрес отправителя — клиент) к
адресу, для которого первое совпавшее правило (или «По умолчанию») ведёт теперь в другое место, удаляется: следующий
пакет соединения идёт новым путём уже без прежней подмены адреса, сайт отвечает сбросом, и приложение подключается
заново. Остальные соединения клиента не трогаются. Решения QUIC по имени сайта (ct mark с QUIC_CT_BIT) у клиентов из
"quic" удаляются все: по адресу не видно, к какому правилу по доменам они относились.

Без iproute2 и conntrack-tools: netlink (NETLINK_NETFILTER, ctnetlink) из стандартной библиотеки.
Печатает JSON: {"seen": записей клиентов, "deleted": удалено}."""
from __future__ import annotations

import bisect
import ipaddress
import json
import socket
import struct
import sys

NETLINK_NETFILTER = 12
NFNL_SUBSYS_CTNETLINK = 1
IPCTNL_MSG_CT_GET, IPCTNL_MSG_CT_DELETE = 1, 2
NLM_F_REQUEST, NLM_F_ACK, NLM_F_DUMP = 0x1, 0x4, 0x300
NLMSG_ERROR, NLMSG_DONE = 2, 3
NLA_F_NESTED, NLA_TYPE_MASK = 0x8000, 0x3FFF
CTA_TUPLE_ORIG, CTA_MARK, CTA_ID, CTA_ZONE = 1, 8, 12, 18
CTA_TUPLE_IP, CTA_TUPLE_PROTO = 1, 2
CTA_IP_V4_SRC, CTA_IP_V4_DST = 1, 2
CTA_PROTO_NUM, CTA_PROTO_DST_PORT = 1, 3
QUIC_CT_BIT = 0x40000000


def attrs(data: bytes) -> dict[int, bytes]:
    """Атрибуты netlink: {тип: байты}; вложенные остаются байтами (разбор — снова attrs)."""
    out, i = {}, 0
    while i + 4 <= len(data):
        ln, typ = struct.unpack_from("=HH", data, i)
        if ln < 4:
            break
        out[typ & NLA_TYPE_MASK] = data[i + 4:i + ln]
        i += (ln + 3) & ~3
    return out


def raw_attr(data: bytes, want: int) -> bytes | None:
    """Атрибут целиком (с заголовком) — для запроса на удаление (кортеж записи как есть)."""
    i = 0
    while i + 4 <= len(data):
        ln, typ = struct.unpack_from("=HH", data, i)
        if ln < 4:
            break
        if typ & NLA_TYPE_MASK == want:
            return data[i:i + ((ln + 3) & ~3)]
        i += (ln + 3) & ~3
    return None


def entry(payload: bytes, want: set | frozenset | None = None) -> dict | None:
    """Сообщение ctnetlink (после nfgenmsg) → {"src", "dst", "proto", "dport", "mark", "tuple", "extra"}. want — адреса
    клиентов, чьи записи нужны: запись другого отправителя — None сразу после адреса, без разбора остального (в таблице
    сервера сотни тысяч чужих соединений: Docker, сайты, другие программы — их в памяти не держим)."""
    a = attrs(payload)
    orig = a.get(CTA_TUPLE_ORIG)
    if orig is None:
        return None
    t = attrs(orig)
    ip = attrs(t.get(CTA_TUPLE_IP, b""))
    if CTA_IP_V4_SRC not in ip or CTA_IP_V4_DST not in ip:
        return None
    src = socket.inet_ntoa(ip[CTA_IP_V4_SRC])
    if want is not None and src not in want:
        return None
    pr = attrs(t.get(CTA_TUPLE_PROTO, b""))
    proto = pr.get(CTA_PROTO_NUM, b"\0")[0]
    dport = struct.unpack("!H", pr[CTA_PROTO_DST_PORT])[0] if CTA_PROTO_DST_PORT in pr else 0
    mark = struct.unpack("!I", a[CTA_MARK])[0] if len(a.get(CTA_MARK, b"")) == 4 else 0
    extra = b"".join(x for x in (raw_attr(payload, CTA_ZONE), raw_attr(payload, CTA_ID)) if x)
    return {"src": src, "dst": socket.inet_ntoa(ip[CTA_IP_V4_DST]), "proto": proto,
            "dport": dport, "mark": mark, "tuple": raw_attr(payload, CTA_TUPLE_ORIG), "extra": extra}


def _msg(typ: int, flags: int, seq: int, body: bytes) -> bytes:
    nfgen = struct.pack("=BBH", socket.AF_INET, 0, 0)
    return struct.pack("=IHHII", 16 + len(nfgen) + len(body), (NFNL_SUBSYS_CTNETLINK << 8) | typ, flags, seq, 0) \
        + nfgen + body


def messages(data: bytes):
    """Сообщения netlink в ответе: (тип, флаги, полезная нагрузка после nfgenmsg)."""
    i = 0
    while i + 16 <= len(data):
        ln, typ, flags, _, _ = struct.unpack_from("=IHHII", data, i)
        if ln < 16:
            break
        yield typ, flags, data[i + 16:i + ln]
        i += (ln + 3) & ~3


def dump(sock: socket.socket, want: set | frozenset | None = None) -> list[dict]:
    """Все записи conntrack (want — только записи этих отправителей, см. entry)."""
    sock.send(_msg(IPCTNL_MSG_CT_GET, NLM_F_REQUEST | NLM_F_DUMP, 1, b""))
    out = []
    while True:
        data = sock.recv(1 << 20)
        if not data:
            break
        for typ, _, body in messages(data):
            if typ == NLMSG_DONE:
                return out
            if typ == NLMSG_ERROR:
                err = struct.unpack_from("=i", body, 0)[0] if len(body) >= 4 else 0
                if err:
                    raise OSError(-err, "ctnetlink dump")
                continue
            e = entry(body[4:], want)
            if e:
                out.append(e)
    return out


class Nets:
    """Списки сетей → поиск адреса за O(log n): отсортированные и слитые промежутки."""

    def __init__(self, cidrs):
        spans = []
        for c in cidrs:
            try:
                n = ipaddress.IPv4Network(str(c), strict=False)
            except ValueError:
                continue
            spans.append((int(n.network_address), int(n.broadcast_address)))
        spans.sort()
        self.lo, self.hi = [], []
        for a, b in spans:
            if self.hi and a <= self.hi[-1] + 1:
                self.hi[-1] = max(self.hi[-1], b)
            else:
                self.lo.append(a)
                self.hi.append(b)

    def __contains__(self, ip: int) -> bool:
        i = bisect.bisect_right(self.lo, ip) - 1
        return i >= 0 and ip <= self.hi[i]


def path_of(pol: dict, nets: dict[str, Nets], ip: int) -> str:
    """Куда ведёт адрес по правилам пути (первое совпавшее, иначе «По умолчанию»)."""
    for lids, out in pol.get("rules") or []:
        if any(lid in nets and ip in nets[lid] for lid in lids):
            return str(out)
    return str(pol.get("default"))


def changed(job: dict, entries: list[dict]) -> list[dict]:
    """Записи, которые нужно удалить."""
    nets = {lid: Nets(c) for lid, c in (job.get("lists") or {}).items()}
    skip = Nets(job.get("skip") or [])
    clients = job.get("clients") or {}
    quic = set(job.get("quic") or ())
    out = []
    for e in entries:
        c = clients.get(e["src"])
        if c is None and e["src"] not in quic:
            continue
        ip = int(ipaddress.IPv4Address(e["dst"]))
        if ip in skip:
            continue                    # сам сервер и местные сети: правила их не касаются
        if e["src"] in quic and e["proto"] == socket.IPPROTO_UDP and e["dport"] == 443 and e["mark"] & QUIC_CT_BIT:
            out.append(e)
            continue
        if c is not None and path_of(c["old"], nets, ip) != path_of(c["new"], nets, ip):
            out.append(e)
    return out


def delete(sock: socket.socket, entries: list[dict]) -> int:
    """Удаление записей по их кортежу (и номеру записи). Без подтверждений: ошибка придёт сообщением, её читаем в конце
    (запись могла исчезнуть сама — это не ошибка)."""
    n = 0
    for seq, e in enumerate(entries, 2):
        if not e.get("tuple"):
            continue
        sock.send(_msg(IPCTNL_MSG_CT_DELETE, NLM_F_REQUEST, seq, e["tuple"] + e.get("extra", b"")))
        n += 1
    sock.setblocking(False)
    try:
        while sock.recv(1 << 16):
            pass
    except OSError:
        pass
    return n


def main() -> None:
    job = json.loads(sys.stdin.read() or "{}")
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER) as s:
        s.bind((0, 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
        mine = dump(s, frozenset(job.get("clients") or {}) | frozenset(job.get("quic") or ()))
        todo = changed(job, mine)
        print(json.dumps({"seen": len(mine), "deleted": delete(s, todo)}))


if __name__ == "__main__":
    main()
