"""Проверка выхода. Запускается внутри сети контейнера Amnezia:
    nsenter -t PID -n -- python3 probe.py <fwmark>
Помечает свои сокеты fwmark'ом, поэтому идёт тем же путём, что и трафик клиентов.
Печатает JSON: внешний IP, страна, задержка TCP-соединения."""
import json
import socket
import sys
import time

SO_MARK = 36
MARK = int(sys.argv[1]) if len(sys.argv) > 1 else 0


def sock(host, port, timeout=6):
    last = None
    for fam, typ, proto, _, addr in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
        s = socket.socket(fam, typ, proto)
        if MARK:
            s.setsockopt(socket.SOL_SOCKET, SO_MARK, MARK)
        s.settimeout(timeout)
        try:
            t0 = time.monotonic()
            s.connect(addr)
            return s, (time.monotonic() - t0) * 1000
        except OSError as e:
            last = e
            s.close()
    raise last or OSError("connect failed")


def http_get(host, path):
    s, _ = sock(host, 80)
    try:
        s.sendall(f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: awg-router\r\n\r\n".encode())
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    if b" 200 " not in head.split(b"\r\n", 1)[0]:
        raise OSError(head.split(b"\r\n", 1)[0].decode(errors="replace"))
    return body.decode(errors="replace")


def main():
    res = {"ok": False}
    try:
        lat = []
        for _ in range(3):
            s, ms = sock("1.1.1.1", 443, timeout=4)
            s.close()
            lat.append(ms)
        res["latency_ms"] = round(min(lat))
    except OSError as e:
        res.update(err="no_connection", detail=str(e))
        print(json.dumps(res, ensure_ascii=False))
        return
    try:
        d = json.loads(http_get("ip-api.com", "/json/?fields=status,query,countryCode,isp"))
        res.update(ok=True, ip=d.get("query"), cc=d.get("countryCode"), isp=d.get("isp"))
    except Exception:  # noqa: BLE001
        try:
            ip = http_get("ifconfig.me", "/ip").strip()
            res.update(ok=True, ip=ip)
        except Exception as e:  # noqa: BLE001
            res.update(ok=True, ip=None, warn="no_ip", detail=str(e))
    print(json.dumps(res, ensure_ascii=False))


if __name__ == "__main__":
    main()
