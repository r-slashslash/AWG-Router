"""Е: прототип исправления Е3 (поверх Е1): «последователей» одного запроса не больше JOIN_MAX (1024) — дальше мгновенный SERVFAIL,
как у MAX_INFLIGHT (поток одного «мёртвого» имени не копит задачи без предела). Запуск: python3 -I e_mkfix3.py <app> <новая app>"""
import subprocess, sys
src, dst = sys.argv[1], sys.argv[2]
subprocess.run([sys.executable, "-I", __file__.replace("e_mkfix3.py", "e_mkfix.py"), src, dst], check=True)
p = dst + "/dnsproxy.py"
s = open(p).read()
old = '''        else:
            self.stats["joined"] = self.stats.get("joined", 0) + 1
        reply = await asyncio.shield(task)
'''
new = '''        else:
            joins = self.__dict__.setdefault("joins", {})          # прототип Е3: предел ждущих одного запроса
            if joins.get(task, 0) >= JOIN_MAX:
                self.stats["errors"] += 1
                return error_reply(query, q, RC_SERVFAIL)
            joins[task] = joins.get(task, 0) + 1
            self.stats["joined"] = self.stats.get("joined", 0) + 1
        reply = await asyncio.shield(task)
'''
assert s.count(old) == 1
s = s.replace(old, new)
c_old = "MAX_INFLIGHT = 512          # одновременных запросов к серверам; больше — отказ (SERVFAIL)\n"
assert s.count(c_old) == 1
s = s.replace(c_old, c_old + "JOIN_MAX = 1024             # прототип Е3: ждущих одного запроса в пути; больше — отказ (SERVFAIL)\n")
old2 = """        self.inflight -= 1
        if self.asking.get(wkey) is task:"""
new2 = """        self.inflight -= 1
        self.__dict__.setdefault("joins", {}).pop(task, None)
        if self.asking.get(wkey) is task:"""
assert s.count(old2) == 1
open(p, "w").write(s.replace(old2, new2))
print("fix3 ready:", p)
