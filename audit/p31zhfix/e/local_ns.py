"""Соседство (П31, к): общий сервер DNS на той же машине — systemd-resolved 127.0.0.53, свой unbound, dnsmasq,
AdGuard Home. Отвечает ли он на контрольный запрос «. NS» (проверка пути кода d7a90cc, Proxy._check) и чем (код
ответа), и на обычное имя. Запуск: python3 -I local_ns.py <путь к app> имя=адрес …"""
import asyncio
import json
import os
import socket
import struct
import sys
import tempfile
import time

sys.path.insert(0, sys.argv[1])
import dnsproxy  # noqa: E402


def raw(addr, q):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(q, (addr, 53))
        r = s.recv(65535)
        fl, an, ns, ar = struct.unpack("!H", r[2:4])[0], *struct.unpack("!HHH", r[6:12])
        return {"rcode": fl & 0xF, "tc": bool(fl & 0x200), "an": an, "ns": ns, "ar": ar, "size": len(r)}
    except OSError as e:
        return {"error": str(e)[:60]}
    finally:
        s.close()


async def main():
    out = {}
    for item in sys.argv[2:]:
        name, addr = item.split("=", 1)
        d = tempfile.mkdtemp()
        conf = os.path.join(d, "dns.json")
        with open(conf, "w") as f:
            json.dump({"listen": "127.0.9.9", "port": 53, "clients": "127.0.0.0/8", "upstreams": [addr],
                       "encrypt": "plain", "default": {"mark": 0, "tcp": False}, "routes": {}, "dom": {},
                       "direct_fallback": []}, f)
        p = dnsproxy.Proxy(conf)
        oks, times = 0, []
        for _ in range(20):
            t0 = time.monotonic()
            oks += await p._check(0, False)
            times.append(round(time.monotonic() - t0, 3))
        out[name] = {"addr": addr, "checks_ok": f"{oks}/20", "max_s": max(times),
                     "ns_answer": raw(addr, dnsproxy.check_query()), "name_answer": raw(addr, dnsproxy.a_query("github.com"))}
    print(json.dumps(out, indent=1), flush=True)


asyncio.run(main())
os._exit(0)
