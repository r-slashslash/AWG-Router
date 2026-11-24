"""Проверка для test_v124_rules.RuleSpeedTest.test_foreign_marks_in_kernel (запускается в своей сети: unshare -n).

Ставит набор панели с метками соединений и без них, шлёт UDP через lo с меткой Tailscale 0x80000, сокетом посредника
со служебной меткой и с меткой выхода (оба — с номером ограничения 7, его биты совпадают с 0x80000) и смотрит, с какой
меткой пакеты прошли postrouting. Печатает JSON: {"labels": {...}, "plain": {...}}."""
import fcntl
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.getcwd())
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
from app import nftgen, sniproxy  # noqa: E402

s = socket.socket()
fcntl.ioctl(s, 0x8914, struct.pack("16sH14s", b"lo", 0x49, b""))      # lo up без ip
s.close()
LIM7 = 8 << 16
WATCH = ("table ip watch {\n chain post {\n  type filter hook postrouting priority 300; policy accept;\n"
         "  meta mark 0x80000 counter\n  meta mark 0x0 counter\n  meta mark 0x2001 counter\n"
         "  meta mark & 0x00ff0000 != 0x0 meta mark != 0x80000 counter\n }\n chain inp {\n"
         "  type filter hook input priority 300; policy accept;\n  ct label 71 counter\n }\n}\n")


def send(port: int, mark: int) -> str:
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", port))
    rx.settimeout(0.5)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.setsockopt(socket.SOL_SOCKET, sniproxy.SO_MARK, mark)
    try:
        tx.sendto(b"x", ("127.0.0.1", port))
        rx.recv(4)
        return "ok"
    except OSError as e:
        return type(e).__name__
    finally:
        rx.close()
        tx.close()


out = {}
for name, labels in (("labels", True), ("plain", False)):
    gp = {"rules": [(["ru"], "direct")], "default": 1, "domain": []}
    if labels:
        gp.update(slots=[0], dslots=[], lims=[7], dlims=[])
    text = nftgen.generate("awg0", {"ru": ["5.0.0.0/8"]}, [{"num": 1, "mtu": 1280}], gp, {}, labels=labels,
                           limits={7: (10 ** 6, 10 ** 6)} if labels else None)
    subprocess.run(["nft", "-f", "-"], input=text.encode(), check=True)
    subprocess.run(["nft", "-f", "-"], input=b"table ip watch\ndelete table ip watch\n" + WATCH.encode(), check=True)
    base = 41000 if labels else 42000
    res = {"foreign": send(base + 1, 0x80000), "tag": send(base + 2, sniproxy.with_lim(0, LIM7)),
           "exit": send(base + 3, sniproxy.with_lim(0x2001, LIM7))}
    w = subprocess.run(["nft", "list", "table", "ip", "watch"], capture_output=True, text=True, check=True).stdout
    nums = [int(ln.split("packets")[1].split()[0]) for ln in w.splitlines() if "counter packets" in ln]
    res["after"], res["lab"] = nums[:4], nums[4]
    out[name] = res
    subprocess.run(["nft", "delete", "table", "ip", nftgen.config.NFT_TABLE], check=True)
print(json.dumps(out))
