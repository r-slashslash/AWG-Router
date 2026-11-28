"""Е: сколько сетей в настоящих списках, которые панель кладёт в nftables (страны — первым источником COUNTRY_SOURCES, как
lists.fetch_list; списки «по ссылке» — antifilter), и сколько стоит одна команда `nft add element … dom4` (Д2: ответ клиенту
ждёт её) в таблице с этими списками. Нужен интернет. Запуск: unshare -n python3 -I e_sizes.py <папка репозитория>"""
import json, subprocess, sys, tempfile, time, urllib.request
sys.path.insert(0, sys.argv[1])
from app import lists  # noqa: E402

def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "audit"}), timeout=60) as r:
        return r.read().decode("utf-8", "replace")

sets = {}
for cc in ("ru", "cn", "ir", "by", "kz", "tr"):
    for tpl in lists.COUNTRY_SOURCES:
        try:
            nets = lists.parse_cidrs(get(tpl.format(cc=cc)), lists.WIDE_MIN)
            if nets:
                sets[cc] = list(nets.cidrs())
                print(json.dumps({"list": cc, "source": tpl.split("/")[2], "cidrs": len(sets[cc])}), flush=True)
                break
        except Exception as e:  # noqa: BLE001
            print(json.dumps({"list": cc, "error": str(e)[:80]}), flush=True)
for name, url in (("antifilter_allyouneed", "https://antifilter.download/list/allyouneed.lst"),
                  ("antifilter_ipsum", "https://antifilter.download/list/ipsum.lst")):
    try:
        nets = lists.parse_cidrs(get(url), lists.WIDE_MIN)
        sets[name] = list(nets.cidrs())
        print(json.dumps({"list": name, "cidrs": len(sets[name])}), flush=True)
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"list": name, "error": str(e)[:80]}), flush=True)

def table(names):
    body = ""
    for n in names:
        el = ", ".join(sets[n])
        body += "\tset l_%s {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { %s }\n\t}\n" % (n, el)
    return ("table ip awgr\ndelete table ip awgr\ntable ip awgr {\n\tset dom4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n"
            + body + "}\n")

for combo in (["ru"], ["ru", "antifilter_allyouneed"], ["cn"], ["ir"], ["ru", "cn", "ir"]):
    if not all(c in sets for c in combo):
        continue
    p = tempfile.mktemp(suffix=".nft")
    open(p, "w").write(table(combo))
    t = time.monotonic(); subprocess.run(["nft", "-f", p], check=True); rb = time.monotonic() - t
    ts = []
    for i in range(5):
        t = time.monotonic()
        subprocess.run(["nft", "add", "element", "ip", "awgr", "dom4", "{ 198.51.100.%d timeout 1800s }" % i], check=True)
        ts.append(round((time.monotonic() - t) * 1000, 1))
    print(json.dumps({"table": combo, "nets": sum(len(sets[c]) for c in combo), "rebuild_ms": round(rb * 1000),
                      "add_one_ms": ts}), flush=True)
