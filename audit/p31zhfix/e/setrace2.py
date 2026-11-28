"""Режим «фильтр по DNS» на настоящем ядре: клиент получает адрес сайта из правила и через DELAY (как удалённый клиент
— время пути ответа и SYN) открывает соединение. Попал ли первый SYN в набор dom4 (счётчик правила nftables с
`ip daddr @dom4`)? Правила панели ведут в обработчик только такие соединения, остальные — по правилам адресов.
Запуск: unshare -rn python3 -I setrace2.py [DELAY_MS …]"""
import asyncio, json, os, socket, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab  # noqa: E402

def counters():
    out = subprocess.run(["nft", "-j", "list", "chain", "ip", "awgr", "o"], capture_output=True, text=True).stdout
    c = [e["rule"]["expr"][-1]["counter"]["packets"] for e in json.loads(out)["nftables"] if "rule" in e]
    return c  # [в наборе, все]

async def main(delays):
    lab.lo_up()
    lab.nft("table ip awgr {\nset dom4 {\ntype ipv4_addr\nflags timeout\n}\nchain o {\ntype filter hook output priority 0; policy accept;\n"
            "tcp dport 8443 tcp flags syn ip daddr @dom4 counter\ntcp dport 8443 tcp flags syn counter\n}\n}")
    await lab.start_servers(h3=False)
    d = tempfile.mkdtemp(); lst = os.path.join(d, "l.txt")
    open(lst, "w").write("rule.example\n")
    res = {}
    for ver in ("old", "new"):
        p = lab.Proxy(ver, {"dom": {"lists": {"l": lst}, "clients": {}, "set": ["awgr", "dom4"],
                                    "policies": {"p_global": [[["l"], {"mark": 0, "tcp": False}]]}}})
        subprocess.run(["nft", "flush", "set", "ip", "awgr", "dom4"])
        cl = lab.Clients()
        await asyncio.sleep(0.8); await lab.ready(cl, [p])
        for dl in delays:
            hit0, all0 = counters()
            for i in range(20):
                n = delays.index(dl) * 20 + i + 1
                await cl.ask(p.listen, f"a{n}.rule.example")
                await asyncio.sleep(dl / 1000)
                s = socket.socket(); s.setblocking(False)
                try: s.connect((f"127.0.0.{50 + n}", 8443))
                except OSError: pass
                await asyncio.sleep(0.01); s.close()
                await asyncio.sleep(0.4)
            hit1, all1 = counters()
            res[f"{ver}/{dl}ms"] = f"{hit1 - hit0} из {all1 - all0} первых соединений — в наборе"
        p.stop()
    print(json.dumps(res, ensure_ascii=False), flush=True); os._exit(0)

asyncio.run(main([int(x) for x in sys.argv[1:]] or [20, 50, 100, 250, 400]))
