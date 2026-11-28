"""Ж: пропадает ли адрес из dom4 для пакетов, пока его перезаписывают настоящим Proxy._nft_tx (b87eaa5). Своя сеть:
таблица ip awgr с dom4 и цепочкой output, которая считает пакеты к адресу X — в наборе и не в наборе. Поток UDP к X
(через lo, адрес на lo) — в своём процессе; ROUNDS перезаписей X вместе с 500 другими адресами (как пачка).
Запуск: unshare -n python3 -I zh_gap.py <папка app> [ROUNDS]"""
import fcntl
import json
import multiprocessing
import socket
import struct
import subprocess
import sys
import time

APP = sys.argv[1]
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 300
sys.path.insert(0, APP)
import dnsproxy  # noqa: E402

X = "127.0.5.5"


def lo_up():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fcntl.ioctl(s.fileno(), 0x8914, struct.pack("16sH14s", b"lo", 0x49, b""))
    s.close()


def sender(stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while not stop.is_set():
        for _ in range(1000):
            try:
                s.sendto(b"x", (X, 9))
            except OSError:
                pass


def counters():
    out = json.loads(subprocess.run(["nft", "-j", "list", "chain", "ip", "awgr", "c_out"], capture_output=True,
                                    text=True).stdout)
    got = []
    for x in out["nftables"]:
        r = x.get("rule")
        if r:
            for e in r["expr"]:
                if "counter" in e:
                    got.append(e["counter"]["packets"])
    return got


def main():
    lo_up()
    subprocess.run(["nft", "-f", "-"], text=True, check=True, input=f"""table ip awgr {{
\tset dom4 {{
\t\ttype ipv4_addr
\t\tflags timeout
\t}}
\tchain c_out {{
\t\ttype filter hook output priority 0; policy accept;
\t\tip daddr {X} ip daddr @dom4 counter
\t\tip daddr {X} ip daddr != @dom4 counter
\t}}
}}
""")
    dnsproxy.Proxy._nft_tx("awgr", "dom4", [(X, 1800)])
    stop = multiprocessing.Event()
    ps = [multiprocessing.Process(target=sender, args=(stop,)) for _ in range(2)]
    for p in ps:
        p.start()
    time.sleep(0.5)
    others = [(f"10.1.{i // 256}.{i % 256}", 1800) for i in range(500)]
    t = time.perf_counter()
    errs = 0
    for k in range(ROUNDS):
        items = others[:k % 500] + [(X, 1800)] + others[k % 500:]
        if dnsproxy.Proxy._nft_tx("awgr", "dom4", items):
            errs += 1
    dt = time.perf_counter() - t
    time.sleep(0.3)
    stop.set()
    for p in ps:
        p.join()
    inset, miss = counters()
    print("RESULT " + json.dumps({"rounds": ROUNDS, "secs": round(dt, 2), "tx_errors": errs, "packets_in_set": inset,
                                  "packets_missed": miss}), flush=True)


if __name__ == "__main__":
    main()
