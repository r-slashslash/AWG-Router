"""Е: прототип исправления Е1 — копия app с объединением запросов, которое не держит повтор у ведущего, пока путь
«напрямую» не отвечает или проверяется. Запуск: python3 -I e_mkfix.py <исходная app> <новая app>"""
import shutil, sys
src, dst = sys.argv[1], sys.argv[2]
shutil.rmtree(dst, ignore_errors=True)
shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
p = dst + "/dnsproxy.py"
s = open(p).read()
old = "        wkey = key + (tcp, bool(fallback))\n"
new = '''        stage = False
        if fallback and not servers and self.is_direct(mark) and (getattr(self, "cfg", None) or {}).get("direct_fallback"):
            dp = self._dp(mark)
            stage = bool(dp.down or _busy(dp.probe))
        wkey = key + (tcp, bool(fallback), stage)
'''
assert s.count(old) == 1, "place not found"
open(p, "w").write(s.replace(old, new))
print("fix ready:", p)
