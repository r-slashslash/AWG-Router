"""Е: держит ли один долгоживущий `nft -i` таблицу в памяти между командами (тогда «add element» не перечитывает всю
таблицу каждый раз). 20 команд отдельными процессами против 20 строк в одном `nft -i`, таблица со 100 000 сетей.
Запуск: unshare -rn python3 -I e_nfti.py"""
import subprocess, time, tempfile
el = ", ".join(f"{10 + i // 65536}.{(i // 256) % 256}.{i % 256}.0/24" for i in range(100000))
p = tempfile.mktemp(); open(p, "w").write("table ip awgr {\n\tset dom4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n"
    "\tset l {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { %s }\n\t}\n}\n" % el)
subprocess.run(["nft", "-f", p], check=True)
t = time.monotonic()
for i in range(20):
    subprocess.run(["nft", "add", "element", "ip", "awgr", "dom4", "{ 198.51.100.%d timeout 1800s }" % i], check=True)
a = time.monotonic() - t
proc = subprocess.Popen(["nft", "-i"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
t = time.monotonic()
for i in range(20):
    proc.stdin.write("add element ip awgr dom4 { 198.51.101.%d timeout 1800s }\n" % i)
proc.stdin.write("quit\n"); proc.stdin.flush(); proc.wait()
b = time.monotonic() - t
out = subprocess.run(["nft", "list", "set", "ip", "awgr", "dom4"], capture_output=True, text=True).stdout
print({"20_processes_s": round(a, 2), "one_nft_i_20_lines_s": round(b, 2), "added_via_i": out.count("198.51.101.")})
