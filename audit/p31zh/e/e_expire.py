"""Е: адрес фильтра по DNS, который продолжают спрашивать, выпадает ли из набора по первому сроку (ядро без обновления
срока у `add element`). Копия dnsproxy.py с коротким сроком (SET_MIN 20 с, порог обновления 5 с вместо 60). Ответ на
имя — каждые 8 с; через 21–24 с после первого ответа — есть ли адрес в наборе. Запуск в своей сети:
python3 -I e_expire.py <папка app> (папки app: до, после, прототип)"""
import asyncio, json, os, shutil, socket, struct, subprocess, sys, tempfile, time
APP = sys.argv[1]
d = tempfile.mkdtemp()
shutil.copytree(APP, d + "/app", ignore=shutil.ignore_patterns("__pycache__"))
src = open(d + "/app/dnsproxy.py").read()
src = src.replace("SET_MIN = 1800", "SET_MIN = 20").replace("if until - now > secs - 60:", "if until - now > secs - 5:") \
         .replace("if self.live.get(addr, 0) - now > secs - 60:", "if self.live.get(addr, 0) - now > secs - 5:")
assert "SET_MIN = 20" in src and "secs - 5" in src
open(d + "/app/dnsproxy.py", "w").write(src)
subprocess.run(["nft", "-f", "-"], text=True, check=True, input="table ip awgr {\n\tset dom4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n}\n")
UP = ("127.0.0.2", 8053)


class Up(asyncio.DatagramProtocol):
    def connection_made(self, tr):
        self.tr = tr

    def datagram_received(self, data, addr):
        qid = struct.unpack("!H", data[:2])[0]
        off = 12
        while data[off]:
            off += 1 + data[off]
        qend = off + 5
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 5, 4) + socket.inet_aton("198.51.100.7")
        self.tr.sendto(struct.pack("!6H", qid, 0x8180, 1, 1, 0, 0) + data[12:qend] + rr, addr)


def elems():
    out = subprocess.run(["nft", "list", "set", "ip", "awgr", "dom4"], capture_output=True, text=True).stdout
    return out.split("elements = ", 1)[1].split("\n")[0] if "elements = " in out else "(empty)"


async def main():
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fcntl.ioctl(s.fileno(), 0x8914, struct.pack("16sH14s", b"lo", 0x49, b""))
    s.close()
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(Up, local_addr=UP)
    open(d + "/rule.txt", "w").write("rule.example\n")
    cfg = {"listen": "127.0.1.1", "port": 53, "clients": "127.0.0.0/8", "stats": d + "/st.json", "upstreams": [UP[0]],
           "encrypt": "plain", "upstream_port": UP[1], "default": {"mark": 0, "tcp": False}, "routes": {},
           "dom": {"lists": {"l": d + "/rule.txt"}, "clients": {}, "set": ["awgr", "dom4"],
                   "policies": {"p_global": [[["l"], {"mark": 0, "tcp": False}]]}}}
    json.dump(cfg, open(d + "/dns.json", "w"))
    proc = subprocess.Popen([sys.executable, "-I", d + "/app/dnsproxy.py", d + "/dns.json"],
                            stdout=open(d + "/log.txt", "w"), stderr=subprocess.STDOUT)
    await asyncio.sleep(1.0)
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.settimeout(3)
    q = struct.pack("!6H", 7, 0x0100, 1, 0, 0, 0) + b"\x01w\x04rule\x07example\x00\x00\x01\x00\x01"
    t0, out = time.monotonic(), []
    for k in range(6):                       # ответы в 0, 8, 16, 24, 32, 40 с; набор — сразу после каждого и в 21 с
        c.sendto(q, ("127.0.1.1", 53))
        r = await loop.run_in_executor(None, c.recv, 512)
        if k == 0:
            out.append(("rcode", r[3] & 15, len(r), open(d + "/log.txt").read()[-300:]))
        out.append((round(time.monotonic() - t0, 1), "after answer", elems()))
        await asyncio.sleep(4)
        out.append((round(time.monotonic() - t0, 1), "between answers", elems()))
        await asyncio.sleep(4)
    proc.terminate()
    print(json.dumps({"app": APP, "kernel": os.uname().release, "timeline": out}), flush=True)
    os._exit(0)


asyncio.run(main())
