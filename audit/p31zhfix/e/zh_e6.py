"""Ж: Е6 при трёх путях и больше — что видит вкладка «Сервер» (dns_view: direct_down, fallback used/down)."""
import json, os, sys, tempfile, time, unittest
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp()); os.environ.setdefault("DRY_RUN", "1"); os.environ.setdefault("PANEL_PASSWORD", "x")
sys.path.insert(0, ".")
from tests.test_v125_p31d import FallbackLineTest
t = FallbackLineTest("test_line_goes_with_the_warning")
now = time.time()
ok, down = [now - 10, now - 400], [now - 300, now - 100]          # общие: ответили / не отвечают
fb_used, fb_down, fb_none = [now - 5, 0], [now - 300, now - 50], [0, 0]
cases = {
 "1: система не отвечает, её запасной работает; А и Б в порядке": ({"0": down, "8449": ok, "8450": ok}, {"0": fb_used, "8449": fb_none, "8450": fb_none}),
 "2: система — запасной работает; А не отвечает и запасной тоже; Б в порядке": ({"0": down, "8449": down, "8450": ok}, {"0": fb_used, "8449": fb_down, "8450": fb_none}),
 "3: А не отвечает, запасной работает; Б в порядке, но его запасной недавно не ответил": ({"0": ok, "8449": down, "8450": ok}, {"0": fb_none, "8449": fb_used, "8450": fb_down}),
 "4: все три не отвечают; запасные: работает, работает, не отвечает": ({"0": down, "8449": down, "8450": down}, {"0": fb_used, "8449": fb_used, "8450": fb_down}),
 "5: все три в порядке, у Б запасной недавно не ответил": ({"0": ok, "8449": ok, "8450": ok}, {"0": fb_none, "8449": fb_none, "8450": fb_down}),
}
for name, (paths, fbs) in cases.items():
    s = {"fallback": ["77.88.8.8"], "direct_ok_at": paths["0"][0], "direct_fail_at": paths["0"][1],
         "addr_direct": {k: v for k, v in paths.items() if k != "0"}, "fb_paths": fbs}
    v = t.view(s)
    print(name, "→", {k: v.get(k) for k in ("direct_down", "fallback")})
