"""Проверка выхода. Запускается внутри сети контейнера Amnezia:
    nsenter -t PID -n -- python3 probe.py <fwmark> [--udp] [имя=IP ...]
Помечает свои сокеты fwmark'ом, поэтому идёт тем же путём, что и трафик клиентов.
Печатает JSON: внешний IP, страна, задержка, для --udp — проходит ли UDP (QUIC)."""
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import time

SO_MARK = 36
MARK = 0          # аргументы — в main(): модуль импортируют и тесты
UDP = False
HOSTS: dict = {}  # адреса, которые панель разобрала сама: резолвера контейнера Amnezia может не быть
TARGETS = ("1.1.1.1", "8.8.8.8")


def sock(host, port, timeout=6, kind=socket.SOCK_STREAM):
    last = None
    for fam, typ, proto, _, addr in socket.getaddrinfo(HOSTS.get(host, host), port, socket.AF_INET, kind):
        s = socket.socket(fam, typ, proto)
        if MARK:
            s.setsockopt(socket.SOL_SOCKET, SO_MARK, MARK)
        s.settimeout(timeout)
        try:
            if kind == socket.SOCK_STREAM:
                s.connect(addr)
            return s, addr
        except OSError as e:
            last = e
            s.close()
    raise last or OSError("connect failed")


def client_hello() -> bytes:
    """Начало TLS 1.2 без имени сервера: сервер на 443 отвечает рукопожатием или ошибкой TLS."""
    ciphers = bytes.fromhex("c02bc02fc02cc030cca9cca8009c009d002f0035")
    exts = (struct.pack("!HH", 0x000A, 8) + struct.pack("!H", 6) + bytes.fromhex("001d00170018")
            + struct.pack("!HH", 0x000D, 8) + struct.pack("!H", 6) + bytes.fromhex("040308040401"))
    body = (b"\x03\x03" + os.urandom(32) + b"\x00" + struct.pack("!H", len(ciphers)) + ciphers
            + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def answer_ms(host, port=443, timeout=6):
    """Время от отправки начала TLS до первого байта ответа. Время connect() не годится: у выхода
    SOCKS5 соединение принимает сам hev-socks5-tunnel на этом сервере (0 мс), а до прокси и цели
    он идёт уже потом. Первый байт ответа приходит только через весь путь."""
    s, _ = sock(host, port, timeout)
    try:
        t0 = time.monotonic()
        s.sendall(client_hello())
        if not s.recv(1):
            raise OSError("closed without an answer")
        return (time.monotonic() - t0) * 1000
    finally:
        s.close()


def http_get(host, path, tls=False):
    s, _ = sock(host, 443 if tls else 80)
    try:
        if tls:
            # без имени (адрес 1.1.1.1): у сертификата Cloudflare адрес есть среди имён
            s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        s.sendall(f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: awg-router\r\n\r\n".encode())
        data = b""
        while len(data) < 65536:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    if b" 200 " not in head.split(b"\r\n", 1)[0]:
        raise OSError(head.split(b"\r\n", 1)[0].decode(errors="replace") or "empty answer")
    return body.decode(errors="replace")


def ip_of(text) -> str:
    """Адрес из ответа сервиса — только сам IP. Ответ по HTTP можно подменить по дороге, а панель кладёт
    этот адрес во «Внешний адрес сервера» и в конфиги клиентов: строка с переводом строки дописала бы
    в каждый конфиг свои строки (например, PostUp, который awg-quick выполняет от root)."""
    s = str(text if text is not None else "").strip()
    return str(ipaddress.ip_address(s))         # ValueError — не адрес


def whoami():
    """Внешний IP и страна. Сначала HTTPS к 1.1.1.1 (без DNS и по 443: многие прокси пускают
    только 80/443), затем ip-api.com по HTTP (страна и провайдер) и ifconfig.me по HTTPS. Ответ,
    в котором не IP-адрес, не принимается."""
    errors = []
    try:
        kv = dict(ln.split("=", 1) for ln in http_get("1.1.1.1", "/cdn-cgi/trace", tls=True).splitlines() if "=" in ln)
        if kv.get("ip"):
            return {"ip": ip_of(kv["ip"]), "cc": kv.get("loc") if kv.get("loc") not in (None, "XX", "T1") else None}
    except Exception as e:  # noqa: BLE001
        errors.append(f"1.1.1.1: {e}")
    try:
        d = json.loads(http_get("ip-api.com", "/json/?fields=status,query,countryCode,isp"))
        if d.get("query"):
            cc = d.get("countryCode")
            return {"ip": ip_of(d["query"]), "cc": cc if isinstance(cc, str) and len(cc) == 2 else None,
                    "isp": str(d.get("isp") or "")[:80] or None}
    except Exception as e:  # noqa: BLE001
        errors.append(f"ip-api.com: {e}")
    try:
        return {"ip": ip_of(http_get("ifconfig.me", "/ip", tls=True))}
    except Exception as e:  # noqa: BLE001
        errors.append(f"ifconfig.me: {e}")
    raise OSError("; ".join(errors))


def quic_probe() -> bytes:
    """Пакет QUIC с версией для согласования (RFC 9000, 6: вид 0x?a?a?a?a): сервер QUIC обязан
    ответить пакетом Version Negotiation. Не меньше 1200 байт — иначе сервер промолчит."""
    dcid, scid = os.urandom(8), os.urandom(8)
    p = bytes([0xC0 | (os.urandom(1)[0] & 0x0F)]) + bytes.fromhex("1a2a3a4a") \
        + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    return p + b"\x00" * (1200 - len(p))


def udp_ok(timeout=3):
    """Проходит ли UDP через выход: ответ на пакет QUIC от 1.1.1.1 или 8.8.8.8 (порт 443)."""
    for host in TARGETS:
        try:
            s, addr = sock(host, 443, timeout, socket.SOCK_DGRAM)
        except OSError:
            continue
        try:
            for _ in range(2):
                s.sendto(quic_probe(), addr)
                try:
                    data, _ = s.recvfrom(2048)
                except socket.timeout:
                    continue
                if data and data[0] & 0x80 and data[1:5] == b"\x00\x00\x00\x00":
                    return True
        except OSError:
            pass
        finally:
            s.close()
    return False


def main():
    global MARK, UDP, HOSTS
    MARK = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    UDP = "--udp" in sys.argv[2:]
    HOSTS = dict(a.split("=", 1) for a in sys.argv[2:] if "=" in a)
    res = {"ok": False}
    lat, err = [], None
    for host in TARGETS:
        for _ in range(3):
            try:
                lat.append(answer_ms(host, timeout=4))
            except OSError as e:
                err = e
                break
        if lat:
            break
    if not lat:
        res.update(err="no_connection", detail=str(err or "?"))
        print(json.dumps(res, ensure_ascii=False))
        return
    res["latency_ms"] = round(min(lat))
    try:
        res.update(ok=True, **whoami())
    except Exception as e:  # noqa: BLE001
        res.update(ok=True, ip=None, warn="no_ip", detail=str(e)[:300])
    if UDP:
        res["udp"] = udp_ok()
    print(json.dumps(res, ensure_ascii=False))


if __name__ == "__main__":
    main()
