#!/usr/bin/env python3
"""Ж: цена одной записи в dom4 — старая команда (c934013: `nft add element … timeout`) против транзакции b87eaa5
(add 1s → delete → add) при разном числе элементов в самом dom4 и с таблицей размера ru (12 302 сети).
Риск 1 карты: не заставляет ли `delete` nft читать элементы набора (тогда цена растёт с dom4).
Запуск от root в своей сети: unshare -n python3 zh_delcost.py [--foreign N]"""
import ipaddress
import json
import random
import subprocess
import sys
import time

R = random.Random(7)


def nft(text: str) -> float:
    t = time.perf_counter()
    r = subprocess.run(["nft", "-f", "-"], input=text, capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(r.stderr[:300])
    return time.perf_counter() - t


def nets(n: int) -> list[str]:
    """n сетей /24, которые не пересекаются и не соседствуют (nft 1.0.2 на 22.04 отказывал на пересечениях)."""
    return [f"{20 + (2 * i) // 65536}.{((2 * i) // 256) % 256}.{(2 * i) % 256}.0/24" for i in range(n)]


def addrs(n: int, base: int = 0) -> list[str]:
    return [str(ipaddress.IPv4Address(0x0A000000 + base + i)) for i in range(n)]


def setup(dom_n: int, ru: int, foreign: int) -> None:
    subprocess.run(["nft", "flush", "ruleset"], check=True)
    lines = ["table ip awgr {", "\tset dom4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}",
             "\tset l_ru {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t}",
             "\tchain c_prerouting {\n\t\ttype filter hook prerouting priority mangle + 10; policy accept;",
             "\t\tip daddr @dom4 tcp dport { 80, 443 } ct state new meta mark set 0xd000 accept",
             "\t\tip daddr @l_ru meta mark set 0x2001\n\t}", "}"]
    nft("\n".join(lines) + "\n")
    for i in range(0, ru, 2000):
        nft("add element ip awgr l_ru { " + ", ".join(nets(min(2000, ru - i))) + " }\n")
    a = addrs(dom_n)
    for i in range(0, dom_n, 2000):
        nft("add element ip awgr dom4 { " + ", ".join(f"{x} timeout 1800s" for x in a[i:i + 2000]) + " }\n")
    if foreign:
        nft("table ip crowdsec {\n\tset blk {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n}\n")
        b = [str(ipaddress.IPv4Address(0xC0000000 + i)) for i in range(foreign)]
        for i in range(0, foreign, 2000):
            nft("add element ip crowdsec blk { " + ", ".join(f"{x} timeout 86400s" for x in b[i:i + 2000]) + " }\n")


def old(a: list[str]) -> str:
    return "add element ip awgr dom4 { " + ", ".join(f"{x} timeout 1800s" for x in a) + " }\n"


def new(a: list[str]) -> str:
    return ("add element ip awgr dom4 { " + ", ".join(f"{x} timeout 1s" for x in a) + " }\n"
            "delete element ip awgr dom4 { " + ", ".join(a) + " }\n"
            "add element ip awgr dom4 { " + ", ".join(f"{x} timeout 1800s" for x in a) + " }\n")


def main():
    foreign = int(sys.argv[sys.argv.index("--foreign") + 1]) if "--foreign" in sys.argv else 0
    res = []
    for ru in (0, 12302):
        for dom_n in (0, 10000, 50000, 200000):
            setup(dom_n, ru, foreign)
            row = {"ru": ru, "dom4": dom_n, "foreign": foreign}
            for kind, fn in (("old", old), ("new", new)):
                for what in ("fresh", "known"):
                    ts = []
                    for k in range(9):
                        a = addrs(3, 0x500000 + k * 10) if what == "fresh" else addrs(3, k * 3)
                        ts.append(nft(fn(a)))
                    ts.sort()
                    row[f"{kind}_{what}_ms"] = round(ts[len(ts) // 2] * 1000, 1)
            res.append(row)
            print(json.dumps(row), flush=True)


if __name__ == "__main__":
    main()
