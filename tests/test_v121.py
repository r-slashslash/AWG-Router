"""1.21.0: правила по доменам на любой выход, строка правила, точная версия AWG, статус в шапке,
порты и ssh-команда установщика.

python3 -m unittest discover tests
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.store import Store  # noqa: E402
from app import lists, nftgen  # noqa: E402
from app import main  # noqa: E402

UP = ("[Interface]\nAddress = 10.9.0.{n}/32\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\n"
      "[Peer]\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\nAllowedIPs = 0.0.0.0/0\n"
      "Endpoint = 198.51.100.{n}:51820\n")
ROOT = os.path.join(os.path.dirname(__file__), "..")


class Req:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


def read(*path):
    with open(os.path.join(ROOT, *path), encoding="utf-8") as f:
        return f.read()


# ------------------------------------------------------------------ домены на любой выход
class DomainsAnyExitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.engine.reconcile()

    def setUp(self):
        st = main.store.snapshot()
        self._routing = {"default": st["routing"]["default"], "rules": list(st["routing"]["rules"])}
        self._lists = {l["id"] for l in st["lists"]}
        self.ids = []
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            self.lid = main.add_list(Req({"kind": "domains", "source": "youtube.com"}))["id"]

    def tearDown(self):
        r = self._routing
        main.store.mutate(lambda st: st.update(routing={"default": r["default"], "rules": r["rules"]}))
        for uid in self.ids:
            if Store.upstream(main.store.snapshot(), uid):
                main.del_upstream(Req({"replace": "direct"}), uid)
        for l in main.store.snapshot()["lists"]:
            if l["id"] not in self._lists:
                main.del_list(None, l["id"])
        main.engine.reconcile()

    def awg(self, n=61, routing=None, name="Mobile"):
        body = {"name": name, "config": UP.format(n=n)}
        if routing is not None:
            body["routing"] = routing
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            uid = main.add_upstream(Req(body))["id"]
        self.ids.append(uid)
        return uid

    def rules(self, default, *rules):
        main.put_routing(Req({"default": default, "rules": [
            {"lists": l, "outbound": o, "enabled": True, "comment": ""} for l, o in rules]}))

    def test_awg_target_is_exit_mark(self):
        uid = self.awg()
        st = main.store.snapshot()
        num = Store.upstream(st, uid)["num"]
        with mock.patch.object(main.engine, "resolve", side_effect=lambda o, s: num if o == "up:" + uid else o):
            to = main.engine._sni_target(st, "up:" + uid)
        self.assertEqual(to, {"mark": nftgen.mark_for(num), "acct": uid})

    def test_rule_reaches_sniproxy(self):
        uid = self.awg()
        self.rules("direct", ([self.lid], "up:" + uid))
        st = main.store.snapshot()
        num = Store.upstream(st, uid)["num"]
        with mock.patch.object(main.engine, "resolve", side_effect=lambda o, s: num if o == "up:" + uid else o):
            gp, _ = main.engine._policies(st)
        self.assertEqual(gp["domain"], [([self.lid], "up:" + uid)])
        # выход лёг и резерв — «напрямую», как и всё остальное: перехват не нужен до его возвращения
        with mock.patch.object(main.engine, "resolve", side_effect=lambda o, s: "direct" if o == "up:" + uid else o):
            gp, _ = main.engine._policies(st)
        self.assertEqual(gp["domain"], [])

    def test_useless_domain_rule_skips_sniffing(self):
        # домены туда же, куда всё остальное, и правил по адресам нет — перехват не нужен
        self.rules("direct", ([self.lid], "direct"))
        gp, _ = main.engine._policies(main.store.snapshot())
        self.assertEqual(gp["domain"], [])
        # с правилом по адресам — нужен: домен проверяется раньше и уводит сайт мимо него
        self.rules("direct", ([self.lid], "direct"), (["ru"], "block"))
        gp, _ = main.engine._policies(main.store.snapshot())
        self.assertEqual(gp["domain"], [([self.lid], "direct")])
        self.rules("direct", ([self.lid], "block"))
        gp, _ = main.engine._policies(main.store.snapshot())
        self.assertEqual(gp["domain"], [([self.lid], "block")])

    def test_exit_window_routing_for_awg(self):
        uid = self.awg(routing={"domains": "youtube.com\ngooglevideo.com", "default": False})
        st = main.store.snapshot()
        own = Store.upstream(st, uid)["own_list"]
        self.assertEqual(Store.lst(st, own)["kind"], "domains")
        self.assertIn({"lists": [own], "outbound": "up:" + uid},
                      [{"lists": r["lists"], "outbound": r["outbound"]} for r in st["routing"]["rules"]])

    def test_delete_takes_own_sites_but_replaces_shared(self):
        uid = self.awg(routing={"domains": "a.example", "domain_lists": [self.lid], "default": False})
        own = Store.upstream(main.store.snapshot(), uid)["own_list"]
        main.del_upstream(Req({"replace": "block"}), uid)
        self.ids.remove(uid)
        st = main.store.snapshot()
        self.assertIsNone(Store.lst(st, own))                      # свой список ушёл с выходом
        self.assertFalse(any(own in r["lists"] for r in st["routing"]["rules"]))
        shared = [r for r in st["routing"]["rules"] if self.lid in r["lists"]]
        self.assertEqual([r["outbound"] for r in shared], ["block"])  # общий список — на замену

    def test_ui_has_no_socks_only(self):
        js = read("app", "static", "app.js")
        self.assertNotIn("socksOnly", js)
        i18n = read("app", "static", "i18n.js")
        for key in ("re.need_socks", "re.domain_no_socks", "err.domains_need_socks"):
            self.assertNotIn(f'"{key}"', i18n)


# ------------------------------------------------------------------ установщик: порты и ssh
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import textwrap  # noqa: E402

from app import system  # noqa: E402
from tests.test_v118 import func, install_sh, unsafe_block  # noqa: E402


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class InstallerPortsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        self.stub("ss", "echo 'udp UNCONN 0 0 0.0.0.0:4000 0.0.0.0:*'\n"
                        "echo 'tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))'")
        self.env = {k: v for k, v in os.environ.items() if k not in ("SUDO_USER", "AWGR_AWG_PORT")}
        self.env["PATH"] = f"{self.bin}:{os.environ['PATH']}"

    def stub(self, name, body):
        path = os.path.join(self.bin, name)
        with open(path, "w") as f:
            f.write("#!/bin/sh\n" + body + "\n")
        os.chmod(path, 0o755)

    def bash(self, body, **env):
        r = subprocess.run(["bash", "-uo", "pipefail", "-c", body], env={**self.env, **env},
                           capture_output=True, text=True, timeout=60)
        return r

    def ports(self) -> str:
        return (func("port_busy") + unsafe_block() + re.search(r"^AWG_AVOID=.*\n", install_sh(), re.M).group(0)
                + func("panel_port_problem") + func("awg_port_problem") + func("awg_random_problem")
                + func("random_port"))

    def test_awg_port_any_but_dns(self):
        for p, want in (("1", ""), ("443", ""), ("1023", ""), ("65535", ""), ("53", "DNS on the server"),
                        ("4000", "in use"), ("0", "from 1 to 65535"), ("x", "from 1 to 65535")):
            with self.subTest(p=p):
                out = self.bash(self.ports() + f'awg_port_problem "{p}"').stdout.strip()
                self.assertIn(want, out) if want else self.assertEqual(out, "")

    def test_random_ports_are_four_digit_and_avoid_lists(self):
        body = self.ports() + 'for i in $(seq 1 300); do random_port 1000 9999 awg_random_problem; ' \
                              'random_port 1000 9999 panel_port_problem; done'
        got = [int(x) for x in self.bash(body).stdout.split()]
        self.assertEqual(len(got), 600)
        unsafe = {int(x) for x in re.search(r'UNSAFE_PORTS=" ([^"]*) "', install_sh()).group(1).split()}
        for i, p in enumerate(got):
            self.assertTrue(1000 <= p <= 9999, p)
            self.assertNotEqual(p, 4000)                                   # занят
            if i % 2 == 0:
                self.assertNotIn(p, system.AWG_AVOID)
            else:
                self.assertNotIn(p, unsafe)

    def test_random_port_when_almost_all_taken(self):
        # свободен только один порт диапазона — найдётся перебором; ни одного — пусто
        body = self.ports() + 'only() { [ "$1" = 1003 ] || echo busy; }; random_port 1000 1009 only; echo "|"; ' \
                              'none() { echo busy; }; random_port 1000 1009 none; echo "|"'
        self.assertEqual(self.bash(body).stdout.replace("\n", ""), "1003||")

    def test_avoid_list_same_in_panel(self):
        sh = re.search(r'^AWG_AVOID=" ([^"]*) "', install_sh(), re.M).group(1)
        self.assertEqual({int(x) for x in sh.split()}, set(system.AWG_AVOID))
        for _ in range(500):
            p = system.random_udp_port()
            self.assertTrue(1000 <= p <= 9999 and p not in system.AWG_AVOID)

    def test_sni_port_from_env(self):
        body = self.ports() + 'SNI_PORT=4443; panel_port_problem 4443; panel_port_problem 10443'
        out = self.bash(body).stdout.strip().splitlines()
        self.assertEqual(len(out), 1)
        self.assertIn("domain rules", out[0])

    # ------------------------------------------------------------ ssh-команда
    def info(self, **env):
        envf = os.path.join(self.tmp, ".env")
        with open(envf, "w") as f:
            f.write("PANEL_ACCESS=ssh\nPANEL_PORT=2053\nPUBLIC_HOST=203.0.113.5\n" + env.pop("saved", ""))
        body = textwrap.dedent(f"""\
            ENV_FILE="{envf}"; DIR="{self.tmp}"; G=; N=; B=; C=
            envget() {{ [ -f "$ENV_FILE" ] && grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true; }}
            """) + func("ssh_user") + func("ssh_port") + func("print_info") + "print_info"
        r = self.bash(body, **env)
        m = re.search(r"ssh -N .*", r.stdout)
        return m.group(0).strip() if m else r.stdout + r.stderr

    def test_sudo_user_and_port(self):
        self.stub("logname", "echo root")
        self.stub("sshd", "echo 'port 2222'")
        self.assertEqual(self.info(SUDO_USER="ubuntu"), "ssh -N -L 2053:127.0.0.1:2053 -p 2222 ubuntu@203.0.113.5")

    def test_su_dash_takes_logname(self):
        self.stub("logname", "echo admin")
        self.stub("sshd", "exit 1")                         # нет sshd -T — порт из ss
        self.assertEqual(self.info(SUDO_USER="root"), "ssh -N -L 2053:127.0.0.1:2053 -p 2222 admin@203.0.113.5")

    def test_saved_user_then_root(self):
        self.stub("logname", "echo 'logname: no login name' >&2; exit 1")
        self.stub("sshd", "echo 'port 22'")
        self.assertEqual(self.info(saved="SSH_USER=debian\n"), "ssh -N -L 2053:127.0.0.1:2053 debian@203.0.113.5")
        self.assertEqual(self.info(), "ssh -N -L 2053:127.0.0.1:2053 root@203.0.113.5")

    def test_ssh_user_saved_in_env(self):
        text = install_sh()
        self.assertIn("SSH_USER=$SSH_USER\n", text)
        self.assertIn('SSH_USER="$(ssh_user 2>/dev/null)"', text)


# ------------------------------------------------------------------ строка правила, карточка выхода
class RuleLineTest(unittest.TestCase):
    def test_auto_comment_dropped_own_kept(self):
        st = {"upstreams": [{"id": "u1", "name": "mobile"}],
              "routing": {"rules": [{"lists": ["l1"], "outbound": "up:u1", "comment": "mobile"},
                                    {"lists": ["l2"], "outbound": "up:u1", "comment": "Work sites"},
                                    {"lists": ["l3"], "outbound": "direct", "comment": "mobile"}]},
              "clients": {"pk": {"rules": [{"lists": ["l1"], "outbound": "up:u1", "comment": "mobile"}]}}}
        self.assertTrue(Store.drop_auto_comments(st))
        self.assertEqual([r["comment"] for r in st["routing"]["rules"]], ["", "Work sites", "mobile"])
        self.assertEqual(st["clients"]["pk"]["rules"][0]["comment"], "")
        self.assertFalse(Store.drop_auto_comments(st))                      # второй раз — нечего менять

    def test_domain_list_knows_its_first_domain(self):
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")), \
                mock.patch.object(lists.domains, "save"):
            res = lists.refresh({"id": "lx", "kind": "domains", "source": "youtube.com\ngooglevideo.com"})
        self.assertEqual((res["first"], res["count"]), ("youtube.com", 2))

    def test_ui(self):
        js = read("app", "static", "app.js")
        self.assertIn("function listLabel(", js)
        self.assertIn("data-rule-more", js)
        self.assertNotIn("${esc(u.iface)}</span>", js)                   # имя awgrN в карточке выхода не показываем
        css = read("app", "static", "app.css")
        self.assertRegex(css, r"\.dot \{[^}]*vertical-align: middle")
        self.assertNotRegex(css, r"\.state \{[^}]*inline-flex")         # базовая линия — от текста, не от точки


if __name__ == "__main__":
    unittest.main()
