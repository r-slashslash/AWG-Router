"""Е: сколько идёт одна команда `nft add element … dom4` (Д2: ответ клиенту ждёт её) при спискrequired сетей в таблице
панели разного размера. Настоящий nftables (unshare -rn). Запуск: unshare -rn python3 -I e_nftcost.py"""
import json, subprocess, sys, tempfile, time
sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else ".")
T = """table ip awgr
delete table ip awgr
table ip awgr {
\tset dom4 {
\t\ttype ipv4_addr
\t\tflags timeout
\t}
%s
\tchain c_pre {
\t\ttype filter hook prerouting priority mangle; policy accept;
\t\tip daddr @dom4 tcp dport { 80, 443 } ct state new meta mark set 0xd000 accept
\t}
}
"""
def lst(n, k):
    if not n:
        return ""
    el = ", ".join(f"{10 + k + i // 65536}.{(i // 256) % 256}.{i % 256}.0/24" for i in range(n))
    return "\tset l_%d {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { %s }\n\t}" % (k, el)
for n in (0, 1000, 10000, 30000, 100000):
    p = tempfile.mktemp(suffix=".nft"); open(p, "w").write(T % lst(n, 0)); subprocess.run(["nft", "-f", p], check=True)
    ts = []
    for i in range(5):
        t = time.monotonic()
        subprocess.run(["nft", "add", "element", "ip", "awgr", "dom4", "{ 1.2.3.%d timeout 1800s }" % i], check=True)
        ts.append(time.monotonic() - t)
    t = time.monotonic(); subprocess.run(["nft", "-f", p], check=True); rb = time.monotonic() - t
    print(json.dumps({"list_nets": n, "add_one_ms": [round(x * 1000, 1) for x in ts], "rebuild_ms": round(rb * 1000)}), flush=True)
