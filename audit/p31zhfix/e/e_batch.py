"""Е: окно после пересборки таблицы (resync) — сейчас по процессу nft на каждые 2000 адресов (каждый заново читает всю
таблицу), прототип — один `nft -f -` со всеми строками (и «add → delete → add», чтобы срок обновлялся и на ядре 6.8).
Таблица как у панели со списком ru (12 302 сети). Запуск: unshare -rn python3 -I e_batch.py N"""
import json, random, subprocess, sys, tempfile, time
N = int(sys.argv[1])
el = ", ".join(f"{10 + i // 65536}.{(i // 256) % 256}.{i % 256}.0/24" for i in range(12302))
T = ("table ip awgr\ndelete table ip awgr\ntable ip awgr {\n\tset dom4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n"
     "\tset l_ru {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { %s }\n\t}\n}\n" % el)
p = tempfile.mktemp(); open(p, "w").write(T)
addrs = list({f"{random.randrange(1, 223)}.{random.randrange(256)}.{random.randrange(256)}.{random.randrange(1, 255)}" for _ in range(N)})
items = [(a, 1800) for a in addrs]
def now_way():
    for i in range(0, len(items), 2000):
        elems = ", ".join(f"{a} timeout {t}s" for a, t in items[i:i + 2000])
        subprocess.run(["nft", "add", "element", "ip", "awgr", "dom4", "{ " + elems + " }"], check=True, capture_output=True)
def proto():
    lines = []
    for i in range(0, len(items), 2000):
        part = items[i:i + 2000]
        lines.append("add element ip awgr dom4 { " + ", ".join(f"{a} timeout 1s" for a, _ in part) + " }")
        lines.append("delete element ip awgr dom4 { " + ", ".join(a for a, _ in part) + " }")
        lines.append("add element ip awgr dom4 { " + ", ".join(f"{a} timeout {t}s" for a, t in part) + " }")
    subprocess.run(["nft", "-f", "-"], input="\n".join(lines) + "\n", text=True, check=True, capture_output=True)
for name, fn in (("now", now_way), ("proto", proto)):
    subprocess.run(["nft", "-f", p], check=True)
    t = time.monotonic(); fn(); dt = time.monotonic() - t
    out = subprocess.run(["nft", "-j", "list", "set", "ip", "awgr", "dom4"], capture_output=True, text=True).stdout
    n = sum(len((x.get("set") or {}).get("elem") or []) for x in json.loads(out)["nftables"])
    print(json.dumps({"live": len(items), "way": name, "window_s": round(dt, 3), "in_set": n}), flush=True)
