"""Запрос к Telegram через выход. Запускается внутри сети сервера AWG:
    nsenter -t PID -n -- python3 tgreq.py <fwmark>
Сокеты помечены fwmark'ом выхода, поэтому идут через его туннель, как трафик клиентов.

stdin: первая строка — JSON {"url", "ctype", "timeout"}, дальше — тело запроса.
stdout: JSON {"status": код, "body": ответ} или {"err": причина}.

Имя хоста тоже узнаём через туннель (DNS-запрос к 1.1.1.1 / 8.8.8.8 с той же меткой):
там, где Telegram заблокирован, местный DNS часто отвечает подменённым адресом."""
import http.client
import json
import random
import socket
import ssl
import struct
import sys
import urllib.parse

SO_MARK = 36
DNS_SERVERS = ("1.1.1.1", "8.8.8.8")


def _sock(mark, typ):
    s = socket.socket(socket.AF_INET, typ)
    if mark:
        s.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
    return s


def dns_query(host, qid):
    """Запрос записи A (RFC 1035)."""
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in host.rstrip(".").split(".")) + b"\0"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)


def _skip_name(data, i):
    while True:
        n = data[i]
        if n & 0xC0 == 0xC0:          # ссылка на имя выше — конец имени
            return i + 2
        if n == 0:
            return i + 1
        i += n + 1


def dns_answer(data, qid):
    """Ответ DNS → список IPv4. Чужой ответ или ошибка — пустой список."""
    if len(data) < 12:
        return []
    rid, flags, qd, an = struct.unpack(">HHHH", data[:8])
    if rid != qid or not flags & 0x8000 or flags & 0x000F:
        return []
    i = 12
    try:
        for _ in range(qd):
            i = _skip_name(data, i) + 4
        out = []
        for _ in range(an):
            i = _skip_name(data, i)
            typ, cls, _, rdlen = struct.unpack(">HHIH", data[i:i + 10])
            i += 10
            if i + rdlen > len(data):       # обрезанный ответ: берём то, что успели
                break
            if typ == 1 and cls == 1 and rdlen == 4:
                out.append(socket.inet_ntoa(data[i:i + 4]))
            i += rdlen
        return out
    except (IndexError, struct.error):
        return []


def resolve(host, mark, timeout=4):
    if not mark:
        return [a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)]
    last = None
    for server in DNS_SERVERS:
        qid = random.randrange(1, 65536)
        s = _sock(mark, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(dns_query(host, qid), (server, 53))
            ips = dns_answer(s.recv(4096), qid)
            if ips:
                return ips
        except OSError as e:
            last = e
        finally:
            s.close()
    raise last or OSError(f"no DNS answer for {host}")


class MarkedHTTPS(http.client.HTTPSConnection):
    """HTTPS через помеченный сокет; сертификат проверяется по имени хоста."""

    def __init__(self, host, mark, timeout, ctx):
        super().__init__(host, timeout=timeout, context=ctx)
        self.mark, self.ctx = mark, ctx

    def connect(self):
        last = None
        for ip in resolve(self.host, self.mark):
            s = _sock(self.mark, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            try:
                s.connect((ip, self.port))
                self.sock = self.ctx.wrap_socket(s, server_hostname=self.host)
                return
            except OSError as e:
                last = e
                s.close()
        raise last or OSError("connect failed")


def request(mark, url, body, ctype, timeout):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not u.hostname:
        raise OSError("https only")
    c = MarkedHTTPS(u.hostname, mark, timeout, ssl.create_default_context())
    try:
        c.request("POST", u.path + ("?" + u.query if u.query else ""), body=body,
                  headers={"Content-Type": ctype, "User-Agent": "awg-router"})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def main():
    mark = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    raw = sys.stdin.buffer.read()
    head, _, body = raw.partition(b"\n")
    try:
        h = json.loads(head)
        status, data = request(mark, h["url"], body, h.get("ctype", "application/json"),
                               float(h.get("timeout", 15)))
        print(json.dumps({"status": status, "body": data.decode(errors="replace")}))
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"err": str(e) or type(e).__name__}))


if __name__ == "__main__":
    main()
