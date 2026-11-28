"""Ж3, проверка «как в LXC»: настоящий проход движка (подделка цели из test_v121f), набор правил панели со списком размера
России (12 302 сети, вразброс, как у настоящего списка) применяется настоящим nft в своём пространстве пользователей
(unshare -rn — без CAP_NET_ADMIN в начальном, как Docker в LXC) при net.core.wmem_max 212 992. Ждём: ошибка прохода —
понятный текст err.nft_wmem на 4 языках. Код: argv[1] — папка репозитория."""
import os, random, subprocess, sys
sys.path.insert(0, sys.argv[1])
os.environ.setdefault("DATA_DIR", "/tmp/zh3data"); os.environ.setdefault("DRY_RUN", "1"); os.environ.setdefault("PANEL_PASSWORD", "x")
from app import system, uitext
from app.i18n import msg_of
from tests.test_v121f import ReconcileOrderTest
random.seed(1)
nets = sorted({f"{random.randrange(1, 223)}.{random.randrange(256)}.{random.randrange(256)}.0/24" for _ in range(12302 * 2)})[:12302]
h = ReconcileOrderTest("test_pass_sets_ip_rules"); h.setUp()
from app import lists
lists.save_cidrs("big", nets)
h.e.store.mutate(lambda st: (st["lists"].append({"id": "big", "name": "big", "kind": "manual", "source": "\n".join(nets)}),
                             st["routing"]["rules"].append({"lists": ["big"], "outbound": "direct", "enabled": True})))
real = h.ns
def ns(cmd, **kw):
    if cmd[:2] == ["nft", "-f"] and cmd[2].endswith("ruleset.nft"):
        return system.run(["unshare", "-rn", "nft", "-f", cmd[2]], timeout=60)
    return real(cmd, **kw)
tg = h.target("container:amnezia-awg2:9999:z"); tg.ns.side_effect = ns
try:
    old = open("/proc/sys/net/core/wmem_max").read().strip()
except OSError:
    old = None                       # в контейнере: значение хоста (его ставит сам workflow)
for wmem in ("212992", os.environ.get("WMEM_OK", "4194304")) if old else ("host",):
    if old and subprocess.run(["sysctl", "-qw", f"net.core.wmem_max={wmem}"]).returncode:
        print("sysctl refused: the host value stays"); wmem = "host"
    try:
        h.reconcile(tg); print(f"wmem_max {wmem}: rules applied, size {len(h.e.ruleset)} bytes")
    except Exception as e:
        m = msg_of(e)
        print(f"wmem_max {wmem}: {type(e).__name__} key={getattr(m, 'key', None)}")
        for lang in ("ru", "en", "zh", "fa"):
            print(f"  {lang}: {uitext.text(lang, m)}")
        print("  nft:", str(e.__cause__)[:300].replace("\n", " | "))
if old:
    subprocess.run(["sysctl", "-qw", f"net.core.wmem_max={old}"])
