"""Е: окно «фильтра по DNS» после пересборки таблицы панелью (риск R8): таблица пересоздаётся (delete table — набор dom4
пуст), панель шлёт SIGUSR1, dnsproxy.py (resync) возвращает живые адреса. Сколько длится окно, пока адресов в наборе
нет (соединения к сайтам из правил идут по правилам адресов), — при N живых адресов. Настоящий nftables (unshare -rn).
Запуск: unshare -rn python3 -I e_resync.py <папка app> N [N…]"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import random
import subprocess
import sys
import tempfile
import time

APP = sys.argv[1]
sys.path.insert(0, os.path.dirname(APP))
from app import dnsproxy  # noqa: E402

TABLE = """table ip awgr
delete table ip awgr
table ip awgr {
\tset dom4 {
\t\ttype ipv4_addr
\t\tflags timeout
\t}
\tset l_big {
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = { %s }
\t}
\tchain c_pre {
\t\ttype filter hook prerouting priority mangle; policy accept;
\t\tip daddr @dom4 tcp dport { 80, 443 } ct state new meta mark set 0xd000 accept
\t\tip daddr @l_big meta mark set 0x2001
\t}
}
"""


def big_list(n: int) -> str:
    # как список страны: n сетей /24 (у панели с большими списками — сотни тысяч строк)
    return ", ".join(f"{10 + i // 65536}.{(i // 256) % 256}.{i % 256}.0/24" for i in range(n))


def count() -> int:
    out = subprocess.run(["nft", "-j", "list", "set", "ip", "awgr", "dom4"], capture_output=True, text=True).stdout
    try:
        d = json.loads(out)
        for x in d["nftables"]:
            if "set" in x:
                return len(x["set"].get("elem") or [])
    except (ValueError, KeyError):
        pass
    return -1


async def one(n: int, lists: int) -> dict:
    path = tempfile.mktemp(suffix=".nft")
    with open(path, "w") as f:
        f.write(TABLE % big_list(lists))
    t = time.monotonic()
    subprocess.run(["nft", "-f", path], check=True)
    build = time.monotonic() - t
    p = dnsproxy.Proxy.__new__(dnsproxy.Proxy)
    p.dom, p.live, p.pending, p._flush_at, p.stats = {"set": ["awgr", "dom4"]}, {}, {}, 0.0, {}
    now = time.time()
    addrs = {str(ipaddress.IPv4Address(random.randrange(0x01000000, 0xDF000000))) for _ in range(n)}
    p.live = {a: now + 1800 for a in addrs}
    fut = p.flush() if False else None
    # набор как до пересборки: все живые адреса
    p.resync()
    fut = p.__dict__.get("_flushing")
    if fut:
        await fut
    before = count()
    # пересборка таблицы панелью → окно → SIGUSR1 → resync
    t0 = time.monotonic()
    subprocess.run(["nft", "-f", path], check=True)
    t1 = time.monotonic()
    p.resync()
    fut = p.__dict__.get("_flushing")
    if fut:
        await fut
    t2 = time.monotonic()
    after = count()
    os.unlink(path)
    return {"live": len(addrs), "list_nets": lists, "in_set_before": before, "in_set_after": after,
            "rebuild_s": round(t1 - t0, 3), "window_after_commit_s": round(t2 - t1, 3), "first_build_s": round(build, 3)}


async def main():
    out = []
    for n in [int(x) for x in sys.argv[2:]]:
        for lists in (1000, 100000):
            out.append(await one(n, lists))
            print(json.dumps(out[-1]), flush=True)


asyncio.run(main())
