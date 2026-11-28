"""Сводка результатов scen.py (песочница или журнал GitHub): по сценарию — d7a90cc («old») и новый код («new»).
python3 scen_sum.py <папка с *.json | файл журнала GitHub>"""
import json
import os
import re
import sys


def load(src):
    out = {}
    if os.path.isdir(src):
        for f in sorted(os.listdir(src)):
            if f.endswith(".json"):
                try:
                    out[f[:-5]] = json.load(open(os.path.join(src, f)))
                except ValueError:
                    pass
    else:
        name = None
        for line in open(src, errors="replace"):
            line = re.sub(r"^\S+Z ", "", line.rstrip("\n"))
            m = re.match(r"^== (\S+)$", line)
            if m:
                name = m.group(1)
            elif name and line.startswith("{"):
                try:
                    out[name] = json.loads(line)
                except ValueError:
                    pass
    return out


def brief(s):
    return " ".join(f"{k}={v['n']}" + (f"(med {v['med']}, >1с {v['over1']}, >3с {v['over3']})" if v["n"] else "")
                    for k, v in sorted((s or {}).items()))


def main():
    for name, d in load(sys.argv[1]).items():
        r = d.get("result") or {}
        print(f"## {name}: {d.get('scenario')} {d.get('args')}")
        for v in ("old", "new"):
            x = r.get(v)
            if not x:
                continue
            st = x.get("stats") or {}
            extra = []
            for k in ("slow_name", "first"):
                if x.get(k):
                    extra.append(f"{k}={x[k]}")
            if "dead_queries" in x:
                extra.append("dead: " + brief(x["dead_queries"]))
            if "after_first" in x:
                extra.append("after_first: " + brief(x["after_first"]))
            print(f"  {v}: names: {brief(x.get('names'))}")
            if extra:
                print(f"       {' | '.join(extra)}")
            print(f"       checks {st.get('checks')}/{st.get('checks_ok')} fb_checks {st.get('fb_checks')}/"
                  f"{st.get('fb_checks_ok')} warn_direct_down {st.get('warn_direct_down')} warn_fb_down "
                  f"{st.get('warn_fb_down')} errors {st.get('errors')}")


main()
