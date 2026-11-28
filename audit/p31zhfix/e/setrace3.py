"""Д2 на настоящем ядре (песочница, unshare -rn): клиент получает адрес сайта из правила и через DELAY мс открывает
соединение. Сколько первых SYN попали в набор dom4 (счётчик правила с `ip daddr @dom4`) и сколько ждал ответ DNS — код
до исправлений (old) и новый (new). Как setrace2.py проверки, плюс время ответа. Запуск: unshare -rn python3 -I setrace3.py"""
import asyncio, json, os, socket, subprocess, sys, tempfile, time
sys.path.insert(0, os.environ.get("LAB_DIR", "/home/claude/scripts-p31d/audit-scripts-p31d"))
import lab  # noqa: E402


def counters():
    out = subprocess.run(["nft", "-j", "list", "chain", "ip", "awgr", "o"], capture_output=True, text=True).stdout
    return [e["rule"]["expr"][-1]["counter"]["packets"] for e in json.loads(out)["nftables"] if "rule" in e]


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
        for k, dl in enumerate(delays):
            hit0, all0 = counters()
            dts = []
            for i in range(30):
                n = k * 30 + i + 1
                dt, _r = await cl.ask(p.listen, f"a{n}.rule.example")
                dts.append(dt)
                await asyncio.sleep(dl / 1000)
                s = socket.socket(); s.setblocking(False)
                try: s.connect((f"127.0.0.{50 + n}", 8443))
                except OSError: pass
                await asyncio.sleep(0.01); s.close()
                await asyncio.sleep(0.2)
            hit1, all1 = counters()
            dts.sort()
            res[f"{ver}/{dl}ms"] = {"first_syn_in_set": f"{hit1 - hit0} of {all1 - all0}",
                                   "dns_ms_median": round(dts[len(dts) // 2] * 1000, 1), "dns_ms_max": round(dts[-1] * 1000, 1)}
        cached = []
        for i in range(10):                       # тот же адрес снова: в наборе уже есть — ответ без ожидания
            dt, _r = await cl.ask(p.listen, f"a1.rule.example")
            cached.append(dt)
        res[f"{ver}/known"] = {"dns_ms_median": round(sorted(cached)[5] * 1000, 1)}
        st = await p.fresh_stats()
        res[f"{ver}/stats"] = {k: st.get(k) for k in ("set_added", "set_late")}
        p.stop()
    print(json.dumps(res, ensure_ascii=False), flush=True); os._exit(0)

asyncio.run(main([int(x) for x in sys.argv[1:]] or [0, 20]))
