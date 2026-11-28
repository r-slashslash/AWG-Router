"""Е: Д8 при нескольких путях — «Запасной DNS тоже не отвечает» по чужому пути. dns_view на файле stats, собранном руками:
путь адреса системы (метка 0) «не отвечает», его запасной отвечает; путь «Напрямую — адрес» (0x2101) отвечает, а его
запасной недавно не ответил (проверка во время короткого сбоя). Запуск: python3 -I e_d8.py <папка репозитория>"""
import json, os, sys, tempfile, time, types
sys.path.insert(0, sys.argv[1])
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp()); os.environ.setdefault("DRY_RUN", "0"); os.environ.setdefault("PANEL_PASSWORD", "x")
from app.engine import dns as edns  # noqa: E402
now = time.time()
st = {"pid": os.getpid(), "at": now, "last_ok": now, "direct_ok_at": now - 300, "direct_fail_at": now - 10,
      "addr_direct": {str(0x2101): [now - 5, now - 200]}, "fallback": ["77.88.8.8"],
      "fb_paths": {"0": [now - 3, now - 400], str(0x2101): [now - 600, now - 190]}}
p = tempfile.mktemp(); json.dump(st, open(p, "w"))
edns.DNS_STATS = p
m = edns.DnsMixin.__new__(edns.DnsMixin)
m.dns_state = {"state": "on"}
m.dns = types.SimpleNamespace(proc=types.SimpleNamespace(pid=os.getpid()))
v = m.dns_view()
print(json.dumps({"direct_down": v.get("direct_down"), "fallback": v.get("fallback"),
                  "expected": "fallback used on path 0 (its fallback answers), not 'down'"}))
