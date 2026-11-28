"""Е: прототип исправления Е2 — запись адресов фильтра по DNS одной транзакцией `nft -f -`: «add с коротким сроком →
delete → add с нужным сроком», чтобы срок обновлялся и на ядрах без обновления срока у `add element` (6.8), и всё —
одним процессом nft (он один раз читает таблицу). Запуск: python3 -I e_mkfix2.py <исходная app> <новая app>"""
import shutil, sys
src, dst = sys.argv[1], sys.argv[2]
shutil.rmtree(dst, ignore_errors=True)
shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
p = dst + "/dnsproxy.py"
s = open(p).read()
old = '''        for i in range(0, len(items), 2000):             # одна команда — не больше 2000 адресов
            elems = ", ".join(f"{a} timeout {t}s" for a, t in items[i:i + 2000])
            try:
                r = subprocess.run(["nft", "add", "element", "ip", table, name, "{ " + elems + " }"],
                                   capture_output=True, text=True, timeout=10)
                if r.returncode:
                    print(f"dnsproxy: nft: {r.stderr.strip()[:200]}", flush=True)
            except (OSError, subprocess.SubprocessError) as e:
                print(f"dnsproxy: nft: {e}", flush=True)'''
new = '''        lines = []
        for i in range(0, len(items), 2000):             # строка — не больше 2000 адресов
            part = items[i:i + 2000]
            lines.append(f"add element ip {table} {name} {{ " + ", ".join(f"{a} timeout 1s" for a, _t in part) + " }")
            lines.append(f"delete element ip {table} {name} {{ " + ", ".join(a for a, _t in part) + " }")
            lines.append(f"add element ip {table} {name} {{ " + ", ".join(f"{a} timeout {t}s" for a, t in part) + " }")
        try:
            r = subprocess.run(["nft", "-f", "-"], input="\\n".join(lines) + "\\n", capture_output=True, text=True,
                               timeout=10)
            if r.returncode:
                print(f"dnsproxy: nft: {r.stderr.strip()[:200]}", flush=True)
        except (OSError, subprocess.SubprocessError) as e:
            print(f"dnsproxy: nft: {e}", flush=True)'''
assert s.count(old) == 1, "place not found"
open(p, "w").write(s.replace(old, new))
print("fix2 ready:", p)
