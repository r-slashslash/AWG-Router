"""Маленькие серверы для сквозных проверок (tests/domains_socks_e2e.py): запускаются в своих
сетевых пространствах как отдельные процессы.

    python3 e2e_servers.py http  <ответ> <ip> [<ip>…]      TCP :80 и :443 → «<ответ> from <адрес клиента>»
    python3 e2e_servers.py echo  <ответ> <ip> [<ip>…]      UDP :7  → «<ответ>»
    python3 e2e_servers.py dns   <ip> <имя>=<A|CNAME:имя> …  DNS :53 (UDP и TCP), зона из аргументов
    python3 e2e_servers.py socks <ip> <порт> [<логин> <пароль>]   SOCKS5: CONNECT и UDP ASSOCIATE
"""
import select
import socket
import struct
import sys
import threading


def http(answer, ips):
    def serve(ip, port):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ip, port))
        s.listen(32)
        while True:
            c, a = s.accept()
            c.sendall(f"{answer} from {a[0]}".encode())
            c.close()
    for ip in ips:
        threading.Thread(target=serve, args=(ip, 80), daemon=True).start()
        threading.Thread(target=serve, args=(ip, 443), daemon=True).start()   # цель проверки socks.check
    threading.Event().wait()


def echo(answer, ips):
    def serve(ip):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((ip, 7))
        while True:
            _, a = s.recvfrom(2048)
            s.sendto(answer.encode(), a)
    for ip in ips:
        threading.Thread(target=serve, args=(ip,), daemon=True).start()
    threading.Event().wait()


# ------------------------------------------------------------------ DNS
def _name(msg, off):
    labels = []
    while True:
        n = msg[off]
        if n & 0xC0 == 0xC0:
            name, _ = _name(msg, ((n & 0x3F) << 8) | msg[off + 1])
            return ".".join(labels + ([name] if name else [])), off + 2
        off += 1
        if n == 0:
            return ".".join(labels), off
        labels.append(msg[off:off + n].decode().lower())
        off += n


def _enc(name):
    return b"".join(bytes([len(x)]) + x.encode() for x in name.split(".") if x) + b"\0"


def dns_answer(q, zone):
    qid, flags = struct.unpack("!HH", q[:4])
    name, off = _name(q, 12)
    qtype = struct.unpack("!H", q[off:off + 2])[0]
    question = q[12:off + 4]
    rrs, cur = [], name
    for _ in range(8):
        v = zone.get(cur)
        if v is None:
            break
        if v.startswith("CNAME:"):
            target = v[6:]
            rrs.append(_enc(cur) + struct.pack("!HHIH", 5, 1, 60, len(_enc(target))) + _enc(target))
            cur = target
            continue
        if qtype == 1:
            rrs.append(_enc(cur) + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(v))
        elif qtype == 28:
            rrs.append(_enc(cur) + struct.pack("!HHIH", 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, "2001:db8::1"))
        break
    rcode = 0 if cur in zone or rrs else 3
    return struct.pack("!HHHHHH", qid, 0x8180 | (flags & 0x0100) | rcode, 1, len(rrs), 0, 0) + question + b"".join(rrs)


def dns(ip, entries):
    zone = dict(e.split("=", 1) for e in entries)

    def udp():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((ip, 53))
        while True:
            q, a = s.recvfrom(4096)
            s.sendto(dns_answer(q, zone), a)

    def tcp():
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ip, 53))
        s.listen(16)
        while True:
            c, _ = s.accept()
            try:
                n = struct.unpack("!H", c.recv(2))[0]
                q = b""
                while len(q) < n:
                    q += c.recv(n - len(q))
                r = dns_answer(q, zone)
                c.sendall(struct.pack("!H", len(r)) + r)
            finally:
                c.close()
    threading.Thread(target=udp, daemon=True).start()
    threading.Thread(target=tcp, daemon=True).start()
    threading.Event().wait()


# ---------------------------------------------------------------- SOCKS5
def _recv(c, n):
    b = b""
    while len(b) < n:
        x = c.recv(n - len(b))
        if not x:
            raise OSError("closed")
        b += x
    return b


def _pipe(a, b):
    socks_ = [a, b]
    try:
        while True:
            r, _, _ = select.select(socks_, [], [], 60)
            if not r:
                return
            for s in r:
                d = s.recv(65536)
                if not d:
                    return
                (b if s is a else a).sendall(d)
    except OSError:
        pass
    finally:
        a.close()
        b.close()


def _addr(c):
    atyp = _recv(c, 1)[0]
    if atyp == 1:
        host = socket.inet_ntoa(_recv(c, 4))
    elif atyp == 3:
        host = _recv(c, _recv(c, 1)[0]).decode()
    else:
        host = socket.inet_ntop(socket.AF_INET6, _recv(c, 16))
    return host, struct.unpack("!H", _recv(c, 2))[0]


def socks_client(c, user, pw):
    try:
        ver, n = _recv(c, 2)
        methods = _recv(c, n)
        want = 2 if user else 0
        if want not in methods:
            c.sendall(b"\x05\xff")
            return
        c.sendall(bytes([5, want]))
        if user:
            _recv(c, 1)
            u = _recv(c, _recv(c, 1)[0]).decode()
            p = _recv(c, _recv(c, 1)[0]).decode()
            if (u, p) != (user, pw):
                c.sendall(b"\x01\x01")
                return
            c.sendall(b"\x01\x00")
        _, cmd, _ = _recv(c, 3)
        host, port = _addr(c)
        if cmd == 1:
            try:
                r = socket.create_connection((host, port), timeout=5)
            except OSError:
                c.sendall(b"\x05\x05\x00\x01\0\0\0\0\0\0")
                return
            c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(r.getsockname()[0]) + struct.pack("!H", r.getsockname()[1]))
            _pipe(c, r)
        elif cmd == 3:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.bind((c.getsockname()[0], 0))
            c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(u.getsockname()[0]) + struct.pack("!H", u.getsockname()[1]))
            client = None
            while True:
                r, _, _ = select.select([u, c], [], [], 60)
                if not r or c in r and not c.recv(1):
                    return
                if u not in r:
                    continue
                d, a = u.recvfrom(65536)
                if client is None or a == client:
                    client = a
                    off = 3
                    atyp = d[off]
                    off += 1
                    if atyp == 1:
                        dst = socket.inet_ntoa(d[off:off + 4]); off += 4
                    elif atyp == 3:
                        ln = d[off]; dst = d[off + 1:off + 1 + ln].decode(); off += 1 + ln
                    else:
                        continue
                    dport = struct.unpack("!H", d[off:off + 2])[0]
                    u.sendto(d[off + 2:], (dst, dport))
                else:
                    u.sendto(b"\0\0\0\x01" + socket.inet_aton(a[0]) + struct.pack("!H", a[1]) + d, client)
        else:
            c.sendall(b"\x05\x07\x00\x01\0\0\0\0\0\0")
    except OSError:
        pass
    finally:
        c.close()


def socks5(ip, port, user="", pw=""):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, int(port)))
    s.listen(64)
    while True:
        c, _ = s.accept()
        threading.Thread(target=socks_client, args=(c, user, pw), daemon=True).start()


if __name__ == "__main__":
    kind, args = sys.argv[1], sys.argv[2:]
    if kind == "http":
        http(args[0], args[1:])
    elif kind == "echo":
        echo(args[0], args[1:])
    elif kind == "dns":
        dns(args[0], args[1:])
    elif kind == "socks":
        socks5(*args)
