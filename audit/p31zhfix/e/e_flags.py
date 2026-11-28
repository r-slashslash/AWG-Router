"""Е: какие флаги и параметры EDNS шлют настоящие клиенты DNS (риск R15: ключ кэша и объединения — RD, CD, EDNS, DO; не в
ключе — COOKIE, ECS и прочие параметры). Сервер-«ловушка» отвечает A 192.0.2.1 (с OPT, если он был в запросе) и пишет
каждый запрос строкой JSON. Запуск: python3 -I e_flags.py serve <адрес> <порт> <файл журнала> [метка]
Сводка: python3 -I e_flags.py sum <файл журнала>"""
from __future__ import annotations

import json
import socket
import socketserver
import struct
import sys
import threading

OPTS = {3: "NSID", 8: "ECS", 9: "EXPIRE", 10: "COOKIE", 11: "KEEPALIVE", 12: "PADDING", 15: "EDE"}


def parse(msg: bytes) -> dict:
    qid, flags, qd, an, ns, ar = struct.unpack("!6H", msg[:12])
    off, labels = 12, []
    while msg[off]:
        labels.append(msg[off + 1:off + 1 + msg[off]].decode("ascii", "replace"))
        off += 1 + msg[off]
    qtype, qclass = struct.unpack("!HH", msg[off + 1:off + 5])
    qend = off + 5
    info = {"name": ".".join(labels), "qtype": qtype, "rd": bool(flags & 0x0100), "cd": bool(flags & 0x0010),
            "ad": bool(flags & 0x0020), "edns": False, "do": False, "udp": None, "opts": [], "qend": qend}
    off = qend
    try:
        for _ in range(an + ns + ar):
            while msg[off] and msg[off] & 0xC0 != 0xC0:
                off += 1 + msg[off]
            off += 2 if msg[off] & 0xC0 == 0xC0 else 1
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
            if rtype == 41:
                info.update(edns=True, do=bool(ttl & 0x8000), udp=rclass)
                o, end = off + 10, off + 10 + rdlen
                while o + 4 <= end:
                    code, ln = struct.unpack("!HH", msg[o:o + 4])
                    info["opts"].append(OPTS.get(code, str(code)) + ("" if code != 10 else f"/{ln}"))
                    o += 4 + ln
            off += 10 + rdlen
    except (IndexError, struct.error):
        info["bad"] = True
    return info


def reply(msg: bytes, info: dict) -> bytes:
    qid, flags = struct.unpack("!HH", msg[:4])
    q = msg[12:info["qend"]]
    ans = b""
    an = 0
    if info["qtype"] == 1:
        ans, an = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("192.0.2.1"), 1
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0) if info["edns"] else b""
    return struct.pack("!6H", qid, 0x8180 | (flags & 0x0110), 1, an, 0, 1 if opt else 0) + q + ans + opt


def serve(addr: str, port: int, path: str, tag: str) -> None:
    lock = threading.Lock()
    log = open(path, "a")

    def note(info, proto, peer):
        with lock:
            log.write(json.dumps({"tag": tag, "proto": proto, "peer": peer, **{k: v for k, v in info.items()
                                                                                 if k != "qend"}}) + "\n")
            log.flush()

    class U(socketserver.BaseRequestHandler):
        def handle(self):
            data, s = self.request
            try:
                info = parse(data)
            except Exception:  # noqa: BLE001
                return
            note(info, "udp", self.client_address[0])
            s.sendto(reply(data, info), self.client_address)

    class T(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                while True:
                    h = self.request.recv(2)
                    if len(h) < 2:
                        return
                    n = struct.unpack("!H", h)[0]
                    data = b""
                    while len(data) < n:
                        c = self.request.recv(n - len(data))
                        if not c:
                            return
                        data += c
                    info = parse(data)
                    note(info, "tcp", self.client_address[0])
                    r = reply(data, info)
                    self.request.sendall(struct.pack("!H", len(r)) + r)
            except OSError:
                pass

    class TS(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True
        daemon_threads = True
    u = socketserver.ThreadingUDPServer((addr, port), U)
    t = TS((addr, port), T)
    threading.Thread(target=t.serve_forever, daemon=True).start()
    print(f"serving {addr}:{port}", flush=True)
    u.serve_forever()


def summarize(path: str) -> None:
    rows = [json.loads(x) for x in open(path) if x.strip()]
    prof = {}
    for r in rows:
        k = (r["tag"], r["proto"], r["qtype"], "RD" if r["rd"] else "-", "CD" if r["cd"] else "-",
             "AD" if r["ad"] else "-", f"EDNS{r['udp']}" if r["edns"] else "noEDNS", "DO" if r["do"] else "-",
             ",".join(r["opts"]) or "-")
        prof[k] = prof.get(k, 0) + 1
    for k, n in sorted(prof.items()):
        print(n, *k)


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5] if len(sys.argv) > 5 else "")
    else:
        summarize(sys.argv[2])
