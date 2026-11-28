"""Е: насколько флаги в ключе кэша (c934013) уменьшают долю ответов из кэша. Расчёт (не процесс): имена по закону Ципфа
(10 000 имён, s=1,0), TTL у всех 300 с, 50 запросов в секунду 30 минут, устройства по профилям флагов (замер на машине
GitHub: iOS/macOS, Windows, glibc — без EDNS; systemd-resolved по умолчанию — EDNS без DO; resolved с DNSSEC, BIND —
EDNS+DO+CD; unbound — EDNS+DO). Печатает долю попаданий: ключ без флагов и с флагами."""
import json, random
random.seed(7)
N, S, TTL, RATE, DUR = 10000, 1.0, 300, 50, 1800
w = [1 / (i + 1) ** S for i in range(N)]
tot = sum(w)
cum, acc = [], 0
for x in w:
    acc += x / tot
    cum.append(acc)
import bisect
def name():
    return bisect.bisect_left(cum, random.random())
mixes = {"phones_only (iOS 50 %, Android? EDNS 50 %)": [("A", .5), ("B", .5)],
         "typical (no EDNS 70 %, EDNS 25 %, DNSSEC 5 %)": [("A", .7), ("B", .25), ("C", .05)],
         "all without EDNS": [("A", 1.0)]}
for label, mix in mixes.items():
    res = {}
    for keyed in (False, True):
        cache, hits, q = {}, 0, 0
        t = 0.0
        while t < DUR:
            r, acc2 = random.random(), 0
            for prof, share in mix:
                acc2 += share
                if r <= acc2:
                    break
            n = name()
            k = (n, prof) if keyed else n
            if cache.get(k, -1) > t:
                hits += 1
            else:
                cache[k] = t + TTL
            q += 1
            t += 1 / RATE
        res["with_flags" if keyed else "without_flags"] = round(100 * hits / q, 1)
    print(json.dumps({"mix": label, "hit_pct": res}, ensure_ascii=False))
