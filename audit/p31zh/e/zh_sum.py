"""Ж: вывод результата в журнал — по строке на версию (e_net.sh резал одну строку на 6000 знаков, и четыре версии
обрезались). Без rows_* (сырые строки) — они остаются в файле. Запуск: python3 -I zh_sum.py ИМЯ файл.json"""
import json
import sys

name, path = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        d = json.load(f)
except (OSError, ValueError) as e:
    print(f"SUM {name} unreadable: {e}")
    sys.exit(0)


def strip(x):
    if isinstance(x, dict):
        return {k: strip(v) for k, v in x.items() if not str(k).startswith("rows")}
    return x


res = (d.get("result") or d.get("res")) if isinstance(d, dict) else None
if isinstance(res, dict) and res and all(isinstance(v, dict) for v in res.values()):
    head = {k: v for k, v in d.items() if k not in ("result", "res")}
    print(f"SUMHEAD {name} " + json.dumps(head)[:1500])
    for ver, v in res.items():
        print(f"SUM {name} {ver} " + json.dumps(strip(v))[:5500])
else:
    print(f"SUM {name} " + json.dumps(strip(d))[:5500])
