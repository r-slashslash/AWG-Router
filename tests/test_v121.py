"""1.21.0: правила по доменам на любой выход, строка правила, точная версия AWG, статус в шапке,
порты и ssh-команда установщика.

python3 -m unittest discover tests
"""
import asyncio
import os
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tests.seed import legacy, legacy_lists  # noqa: E402,F401

from app.store import Store  # noqa: E402
from app import lists, nftgen  # noqa: E402

UP = ("[Interface]\nAddress = 10.9.0.{n}/32\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\n"
      "[Peer]\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\nAllowedIPs = 0.0.0.0/0\n"
      "Endpoint = 198.51.100.{n}:51820\n")
ROOT = os.path.join(os.path.dirname(__file__), "..")


class Req:
    def __init__(self, body):
        self.body = body

    def json(self, limit=None):
        return self.body


def read(*path):
    with open(os.path.join(ROOT, *path), encoding="utf-8") as f:
        return f.read()


# ------------------------------------------------------------------ домены на любой выход
class DomainsAnyExitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        panel.engine.reconcile()

    def setUp(self):
        legacy_lists(panel.store)                 # страны, как в новой установке до 1.22.0
        st = panel.store.snapshot()
        self._routing = {"default": st["routing"]["default"], "rules": list(st["routing"]["rules"])}
        self._lists = {l["id"] for l in st["lists"]}
        self.ids = []
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            self.lid = routing.add_list(Req({"kind": "domains", "source": "youtube.com"}))["id"]

    def tearDown(self):
        r = self._routing
        panel.store.mutate(lambda st: st.update(routing={"default": r["default"], "rules": r["rules"]}))
        for uid in self.ids:
            if Store.upstream(panel.store.snapshot(), uid):
                exits.del_upstream(Req({"replace": "direct"}), uid)
        for l in panel.store.snapshot()["lists"]:
            if l["id"] not in self._lists:
                routing.del_list(None, l["id"])
        panel.engine.reconcile()

    def awg(self, n=61, routing=None, name="Mobile"):
        body = {"name": name, "config": UP.format(n=n)}
        if routing is not None:
            body["routing"] = routing
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            uid = exits.add_upstream(Req(body))["id"]
        self.ids.append(uid)
        return uid

    def rules(self, default, *rules):
        routing.put_routing(Req({"default": default, "rules": [
            {"lists": l, "outbound": o, "enabled": True, "comment": ""} for l, o in rules]}))

    def test_awg_target_is_exit_mark(self):
        uid = self.awg()
        st = panel.store.snapshot()
        num = Store.upstream(st, uid)["num"]
        with mock.patch.object(panel.engine, "resolve", side_effect=lambda o, s: num if o == "up:" + uid else o):
            to = panel.engine._sni_target(st, "up:" + uid)
        self.assertEqual(to, {"mark": nftgen.mark_for(num), "acct": uid})

    def test_rule_reaches_sniproxy(self):
        uid = self.awg()
        self.rules("direct", ([self.lid], "up:" + uid))
        st = panel.store.snapshot()
        num = Store.upstream(st, uid)["num"]
        with mock.patch.object(panel.engine, "resolve", side_effect=lambda o, s: num if o == "up:" + uid else o):
            gp, _ = panel.engine._policies(st)
        self.assertEqual(gp["domain"], [([self.lid], "up:" + uid)])
        # выход лёг и резерв — «напрямую», как и всё остальное: перехват не нужен до его возвращения
        with mock.patch.object(panel.engine, "resolve", side_effect=lambda o, s: "direct" if o == "up:" + uid else o):
            gp, _ = panel.engine._policies(st)
        self.assertEqual(gp["domain"], [])

    def test_useless_domain_rule_skips_sniffing(self):
        # домены туда же, куда всё остальное, и правил по адресам нет — перехват не нужен
        self.rules("direct", ([self.lid], "direct"))
        gp, _ = panel.engine._policies(panel.store.snapshot())
        self.assertEqual(gp["domain"], [])
        # с правилом по адресам — нужен: домен проверяется раньше и уводит сайт мимо него
        self.rules("direct", ([self.lid], "direct"), (["ru"], "block"))
        gp, _ = panel.engine._policies(panel.store.snapshot())
        self.assertEqual(gp["domain"], [([self.lid], "direct")])
        # второй круг проверки 1.22.0: и правила по адресам туда же («Применить для России» на новой установке,
        # всё напрямую) — уводить нечего, перехват всего HTTPS клиентов не нужен
        self.rules("direct", ([self.lid], "direct"), (["ru"], "direct"))
        gp, _ = panel.engine._policies(panel.store.snapshot())
        self.assertEqual(gp["domain"], [])
        self.rules("direct", ([self.lid], "block"))
        gp, _ = panel.engine._policies(panel.store.snapshot())
        self.assertEqual(gp["domain"], [([self.lid], "block")])

    def test_exit_window_routing_for_awg(self):
        uid = self.awg(routing={"domains": "youtube.com\ngooglevideo.com", "default": False})
        st = panel.store.snapshot()
        own = Store.upstream(st, uid)["own_list"]
        self.assertEqual(Store.lst(st, own)["kind"], "domains")
        self.assertIn({"lists": [own], "outbound": "up:" + uid},
                      [{"lists": r["lists"], "outbound": r["outbound"]} for r in st["routing"]["rules"]])

    def test_delete_takes_own_sites_but_replaces_shared(self):
        uid = self.awg(routing={"domains": "a.example", "domain_lists": [self.lid], "default": False})
        own = Store.upstream(panel.store.snapshot(), uid)["own_list"]
        exits.del_upstream(Req({"replace": "block"}), uid)
        self.ids.remove(uid)
        st = panel.store.snapshot()
        self.assertIsNone(Store.lst(st, own))                      # свой список ушёл с выходом
        self.assertFalse(any(own in r["lists"] for r in st["routing"]["rules"]))
        shared = [r for r in st["routing"]["rules"] if self.lid in r["lists"]]
        self.assertEqual([r["outbound"] for r in shared], ["block"])  # общий список — на замену

    def test_ui_has_no_socks_only(self):
        js = panel_js.source()
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
from app import nftgen as _nftgen  # noqa: E402,F401
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
        # 1.22.0: и порт — для команды в боте Telegram
        self.assertIn("SSH_PORT=$SSH_PORT\n", text)
        self.assertIn('SSH_PORT="$(ssh_port 2>/dev/null)"', text)

    def test_saved_port_when_unknown(self):
        """1.22.0: порт не узнать (обновление без sshd -T и ss) — сохранённый при установке; узнали 22 — без -p."""
        self.stub("logname", "exit 1")
        self.stub("sshd", "exit 1")
        self.stub("ss", "exit 1")
        self.assertEqual(self.info(saved="SSH_PORT=2200\n"), "ssh -N -L 2053:127.0.0.1:2053 -p 2200 root@203.0.113.5")
        self.stub("sshd", "echo 'port 22'")
        self.assertEqual(self.info(saved="SSH_PORT=2200\n"), "ssh -N -L 2053:127.0.0.1:2053 root@203.0.113.5")


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
        js = panel_js.source()
        self.assertIn("function listLabel(", js)
        self.assertIn("data-rule-more", js)
        self.assertNotIn("${esc(u.iface)}</span>", js)                   # имя awgrN в карточке выхода не показываем
        css = read("app", "static", "app.css")
        self.assertRegex(css, r"\.dot \{[^}]*vertical-align: middle")
        self.assertNotRegex(css, r"\.state \{[^}]*inline-flex")         # базовая линия — от текста, не от точки


# ------------------------------------------------------------------ статус в шапке
import time  # noqa: E402

from app import engine as engine_mod, selfupdate  # noqa: E402


class HeaderPhaseTest(unittest.TestCase):
    def setUp(self):
        self.e = engine_mod.Engine.__new__(engine_mod.Engine)
        self.e._srv_down, self.e.server_restart_at, self.e.switching = None, None, False
        self.e.last_reconcile, self.e.last_error = time.time(), None

    def test_phases(self):
        e = self.e
        self.assertIsNone(e.phase())
        e.last_reconcile = None
        self.assertEqual(e.phase(), "starting")
        e.last_error = "boom"                               # первый проход упал — это ошибка, не «Запуск…»
        self.assertIsNone(e.phase())
        e.last_error, e.last_reconcile = None, time.time()
        e.server_restart_at = time.time()
        self.assertEqual(e.phase(), "server_restart")
        e.server_restart_at = None
        e._srv_down = time.time() - 5                       # интерфейс пропал, панель ждёт и поднимет
        self.assertEqual(e.phase(), "server_restart")
        e._srv_down = time.time() - engine_mod.SERVER_DOWN_AFTER - 1
        self.assertEqual(e.phase(), "server_down")
        e.switching = True
        self.assertEqual(e.phase(), "engine")

    def test_switch_flag_is_cleared(self):
        e = self.e
        with mock.patch.object(engine_mod.Engine, "_switch_engine", side_effect=RuntimeError("x")):
            with self.assertRaises(RuntimeError):
                e.switch_engine("go")
        self.assertFalse(e.switching)

    def test_state_has_phase(self):
        self.assertIn("phase", state.get_state(None))


class CliUpdateTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        p = mock.patch.multiple(selfupdate, INSTALLING=os.path.join(self.d, "installing"),
                                STATE=os.path.join(self.d, "update.json"), LOG=os.path.join(self.d, "update.log"))
        p.start()
        self.addCleanup(p.stop)

    def test_console_install_shows_as_running(self):
        self.assertEqual(selfupdate.status(), {"state": "idle"})
        with open(selfupdate.INSTALLING, "w") as f:
            f.write("1")
        self.assertEqual(selfupdate.status(), {"state": "running", "cli": True})
        old = time.time() - selfupdate.STALE - 10            # оборванный установщик не держит «Обновление…»
        os.utime(selfupdate.INSTALLING, (old, old))
        self.assertEqual(selfupdate.status(), {"state": "idle"})

    def test_installer_writes_and_removes_marker(self):
        sh = install_sh()
        self.assertIn('date +%s > "$DIR/data/installing"; trap \'rm -f "$DIR/data/installing"\' EXIT', sh)
        self.assertLess(sh.index("data/installing"), sh.index('step "Starting"'))

    def test_ui(self):
        js = panel_js.source()
        for key in ("status.offline", "status.updating_s", "status.starting", "status.server_restart",
                    "status.engine", "status.server_down", "sy.updating_cli"):
            self.assertIn(f'"{key}"', js)
        self.assertIn("OFFLINE_AFTER = 2", js)


# ------------------------------------------------------------------ QUIC по имени
import json as _json  # noqa: E402
import socket as _socket  # noqa: E402
import struct as _struct  # noqa: E402

from app import config as _config, dnsproxy, nfqueue, quic, sniproxy  # noqa: E402
from app import panel  # noqa: E402
from app.api import backup, exits, routing, server, state  # noqa: E402
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # tests/panel_js.py
import panel_js  # noqa: E402

DATA = os.path.join(os.path.dirname(__file__), "fixtures")


def chromium(v="v1"):
    """Настоящие первые датаграммы Chromium 153 к quic.test (ClientHello с ML-KEM — в двух пакетах)."""
    with open(os.path.join(DATA, f"quic-chromium153-{v}.hex")) as f:
        return [bytes.fromhex(x) for x in f.read().split()]


def ipv4_udp(src, sport, dst, dport, payload):
    """Пакет IPv4 + UDP, как его отдаёт очередь ядра."""
    udp = _struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    hdr = _struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                       _socket.inet_aton(src), _socket.inet_aton(dst))
    return hdr + udp


class QuicParseTest(unittest.TestCase):
    def sni(self, datagrams):
        a = quic.Assembler()
        for d in datagrams:
            a.add(quic.initial_frames(d)[1])
        h = a.hello()
        return sniproxy._client_hello_sni(h) if h is not None else None

    def test_chromium_v1_and_v2(self):
        for v in ("v1", "v2"):
            with self.subTest(v=v):
                ds = chromium(v)
                self.assertEqual([quic.kind(d) for d in ds], ["initial", "initial"])
                self.assertEqual(self.sni(ds), "quic.test")
                self.assertEqual(self.sni(ds[::-1]), "quic.test")         # пришли в другом порядке
                self.assertIsNone(self.sni(ds[:1]))                       # половины ClientHello мало

    def test_keys_verified_by_gcm_tag(self):
        """Ключи Initial выведены верно: тег GCM первого пакета сходится (libcrypto)."""
        lib = quic._LIB
        if lib is None or not hasattr(lib, "EVP_aes_128_gcm"):
            self.skipTest("нет libcrypto")
        import ctypes
        d = chromium()[0]
        dl = d[5]
        dcid = d[6:6 + dl]
        q = 6 + dl
        q += 1 + d[q]
        tl, q = quic.varint(d, q)
        q += tl
        ln, q = quic.varint(d, q)
        pkt = d[:q + ln]
        key, iv, hp = quic.client_keys(quic.V1, dcid)
        mask = quic.aes_ecb(hp, pkt[q + 4:q + 20])
        first = pkt[0] ^ (mask[0] & 0x0F)
        pnl = (first & 3) + 1
        pnb = bytes(x ^ y for x, y in zip(pkt[q:q + pnl], mask[1:1 + pnl]))
        aad = bytes([first]) + pkt[1:q] + pnb
        nonce = (int.from_bytes(iv, "big") ^ int.from_bytes(pnb, "big")).to_bytes(12, "big")
        ct, tag = pkt[q + pnl:-16], pkt[-16:]
        lib.EVP_aes_128_gcm.restype = ctypes.c_void_p
        lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p] * 3 + [ctypes.c_char_p] * 2
        lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
                                          ctypes.c_char_p, ctypes.c_int]
        lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
        lib.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
        ctx = lib.EVP_CIPHER_CTX_new()
        self.addCleanup(lib.EVP_CIPHER_CTX_free, ctx)
        n, out = ctypes.c_int(0), ctypes.create_string_buffer(len(ct) + 16)
        lib.EVP_DecryptInit_ex(ctx, lib.EVP_aes_128_gcm(), None, key, nonce)
        lib.EVP_DecryptUpdate(ctx, None, ctypes.byref(n), aad, len(aad))
        lib.EVP_DecryptUpdate(ctx, out, ctypes.byref(n), ct, len(ct))
        lib.EVP_CIPHER_CTX_ctrl(ctx, 0x11, 16, tag)                      # EVP_CTRL_GCM_SET_TAG
        self.assertEqual(lib.EVP_DecryptFinal_ex(ctx, out, ctypes.byref(n)), 1)

    def test_pure_python_aes_matches(self):
        k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        with mock.patch.object(quic, "_LIB", None):
            # FIPS-197, приложение C.1
            self.assertEqual(quic.aes_ecb(k, bytes.fromhex("00112233445566778899aabbccddeeff")).hex(),
                             "69c4e0d86a7b0430d8cdb78070b4c55a")
            quic._keys.clear()
            self.assertEqual(self.sni(chromium("v2")), "quic.test")
            py = quic.aes_ctr(k, bytes(12) + b"\0\0\0\2", bytes(range(100)))
        quic._keys.clear()
        if quic._LIB is not None:
            self.assertEqual(py, quic.aes_ctr(k, bytes(12) + b"\0\0\0\2", bytes(range(100))))

    def test_kinds(self):
        self.assertEqual(quic.kind(b"\x16\xfe\xfd" + bytes(40)), "other")      # DTLS
        self.assertEqual(quic.kind(b"\x01\x00\x00\x00" + bytes(40)), "other")  # WireGuard
        self.assertEqual(quic.kind(bytes([0x41]) + bytes(40)), "quic")         # короткий заголовок
        self.assertEqual(quic.kind(bytes([0xC0, 0xFF, 0, 0, 0x1D]) + bytes(40)), "quic")   # черновик 29
        with self.assertRaises(quic.NotInitial):
            quic.initial_frames(chromium()[0][:60])                              # обрезан
        bad = bytearray(chromium()[0])
        bad[60:200] = bytes(140)                                                 # испорчено содержимое
        try:
            a = quic.Assembler()
            a.add(quic.initial_frames(bytes(bad))[1])
            self.assertIsNone(a.hello())                                         # имени нет — ждать, потом отказ
        except quic.NotInitial:
            pass


class FakeQueue:
    def __init__(self):
        self.verdicts = []

    def verdict(self, pid, accept=True, mark=None):
        self.verdicts.append((pid, accept, mark))


class SnifferQuicTest(unittest.TestCase):
    def sniffer(self, qmark):
        s = sniproxy.Sniffer.__new__(sniproxy.Sniffer)
        s.stats, s.qflows, s.qdone, s.queue = {}, {}, {}, FakeQueue()
        s.lists = {"dq": {"quic.test"}}
        s.cfg = {"client_policy": {"10.8.1.9": "p_1"},
                 "quic": {"queue": 1, "pass": _config.QUIC_PASS_MARK, "block": _config.MARK_BLOCK},
                 "policies": {"p_global": {"rules": [{"lists": ["dq"], "to": {"mark": 0}, "qmark": qmark}]},
                              "p_1": {"rules": []}}}
        return s

    def run_packets(self, s, packets, client="10.8.1.2"):
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)

        async def go():
            for i, d in enumerate(packets):
                s.on_packet(i + 1, ipv4_udp(client, 50000, "8.8.8.8", 443, d),
                            _config.MARK_BLOCK, _config.QUIC_PASS_MARK)
            await asyncio.sleep(sniproxy.QUIC_HOLD + 0.05)
        loop.run_until_complete(go())
        return s.queue.verdicts

    def test_match_gets_rule_mark_for_all_held_packets(self):
        s = self.sniffer(0x2005)
        self.assertEqual(self.run_packets(s, chromium()), [(1, True, 0x2005), (2, True, 0x2005)])
        self.assertEqual(s.qflows, {})

    def test_repeat_of_first_packets_gets_same_decision(self):
        """Пока сервер не ответил, повтор Initial (бывает половиной ClientHello) снова идёт в очередь: решение
        по тем же адресам и портам уже есть — без ожидания и без отказа по таймауту."""
        s = self.sniffer(0x2005)
        ds = chromium()
        self.assertEqual(self.run_packets(s, ds + ds[1:]), [(1, True, 0x2005), (2, True, 0x2005), (3, True, 0x2005)])
        s2 = self.sniffer(0x2005)
        self.assertEqual(self.run_packets(s2, ds + ds[:1], client="10.8.1.9")[-1], (3, True, _config.QUIC_PASS_MARK))

    def test_other_policy_passes(self):
        s = self.sniffer(0x2005)
        self.assertEqual(self.run_packets(s, chromium(), client="10.8.1.9"),
                         [(1, True, _config.QUIC_PASS_MARK), (2, True, _config.QUIC_PASS_MARK)])

    def test_incomplete_hello_blocked_after_hold(self):
        s = self.sniffer(0x2005)
        self.assertEqual(self.run_packets(s, chromium()[:1]), [(1, True, _config.MARK_BLOCK)])
        self.assertEqual(s.stats.get("quic_timeout"), 1)

    def test_not_quic_passes_short_header_blocked(self):
        v = self.run_packets(self.sniffer(0x2005), [b"\x16\xfe\xfd" + bytes(60)])
        self.assertEqual(v, [(1, True, _config.QUIC_PASS_MARK)])
        v = self.run_packets(self.sniffer(0x2005), [bytes([0x41]) + bytes(60)])
        self.assertEqual(v, [(1, True, _config.MARK_BLOCK)])

    def test_udp_of(self):
        self.assertEqual(nfqueue.udp_of(ipv4_udp("10.8.1.2", 1, "8.8.8.8", 443, b"ab")),
                         ("10.8.1.2", 1, "8.8.8.8", 443, b"ab"))
        tcp = bytearray(ipv4_udp("10.8.1.2", 1, "8.8.8.8", 443, b"ab"))
        tcp[9] = 6
        self.assertIsNone(nfqueue.udp_of(bytes(tcp)))


@unittest.skipUnless(os.geteuid() == 0 and shutil.which("unshare") and shutil.which("iptables"),
                     "нужны root, unshare и iptables")
class NfqueueKernelTest(unittest.TestCase):
    def test_verdict_with_mark_in_own_netns(self):
        """Настоящая очередь ядра в своей сети: iptables NFQUEUE в OUTPUT, вердикт с меткой доходит."""
        script = textwrap.dedent(f"""\
            import fcntl, socket, struct, subprocess, sys, time
            sys.path.insert(0, {ROOT!r})
            from app import nfqueue
            s = socket.socket(); fcntl.ioctl(s, 0x8914, struct.pack("16sH14s", b"lo", 0x9, b""))
            run = lambda c: subprocess.run(c, shell=True, capture_output=True, text=True)
            if run("iptables -t mangle -A OUTPUT -p udp --dport 443 -j NFQUEUE --queue-num 77").returncode:
                print("skip"); sys.exit()
            run("iptables -t mangle -A POSTROUTING -p udp --dport 443 -m mark --mark 0xe101 -j ACCEPT")
            q = nfqueue.Queue(77)
            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); srv.bind(("127.0.0.1", 443)); srv.settimeout(1)
            c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.sendto(b"hello", ("127.0.0.1", 443))
            time.sleep(0.2)
            pk = q.read()
            for pid, p in pk:
                q.verdict(pid, True, 0xe101)
            got = srv.recvfrom(100)[0]
            marked = run("iptables -t mangle -L POSTROUTING -v -x -n").stdout.split()
            print(len(pk), nfqueue.udp_of(pk[0][1])[4].decode(), got.decode(), "0xe101" in marked)
            """)
        r = subprocess.run(["unshare", "-n", sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
        if r.stdout.strip() == "skip":
            self.skipTest("iptables NFQUEUE недоступен")
        self.assertEqual(r.stdout.strip(), "1 hello hello True", r.stderr)


class NftQuicTest(unittest.TestCase):
    GP = {"rules": [(["ru"], "direct")], "default": 1, "domain": [(["yt"], "up:x")]}
    CPS = {"10.8.1.5": {"rules": [], "default": 1, "domain": []}}
    UPS = [{"num": 1, "mtu": 1280}]

    def gen(self, **kw):
        return nftgen.generate("awg0", {"ru": ["5.0.0.0/8"]}, self.UPS, self.GP, self.CPS, 10443, **kw)

    def test_without_flags_as_before(self):
        t = self.gen()
        self.assertIn("\t\tudp dport 443 goto o_block", t)
        self.assertNotIn("queue", t)
        self.assertNotIn("dom4", t)

    def test_quic_and_filter(self):
        t = self.gen(quic=True, dom_filter=True)
        self.assertIn(f"queue num {_config.QUIC_QUEUE} bypass", t)
        self.assertIn("ip saddr != @q_skip ip daddr @dom4 queue", t)
        self.assertIn("elements = { 10.8.1.5 }", t)                    # у клиента своя политика без доменов
        self.assertIn(f"ip daddr @dom4 udp dport 443 meta mark != {_config.QUIC_PASS_MARK:#x} goto o_block", t)
        self.assertIn("ip daddr @dom4 tcp dport { 80, 443 } ct state new meta mark set", t)
        self.assertIn(f"ct mark set meta mark | {_config.QUIC_CT_BIT:#x} accept", t)
        self.assertLess(t.index("ip daddr @local4 return\n\t\tudp dport 443 meta mark"), t.index("ip saddr vmap @clients"))

    @unittest.skipUnless(os.geteuid() == 0 and shutil.which("nft") and shutil.which("unshare"), "нужны root и nft")
    def test_nft_accepts(self):
        for kw in ({}, {"dom_filter": True}, {"quic": True, "dom_filter": True}, {"quic": True}):
            text = self.gen(**kw).replace(f"queue num {_config.QUIC_QUEUE} bypass", "accept")  # nft_queue есть не везде
            r = subprocess.run(["unshare", "-n", "nft", "-c", "-f", "-"], input=text, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, (kw, r.stderr))


# ------------------------------------------------------------------ DNS через выход правила, фильтр по DNS
def dns_answer(name, ips, ttl=60, cname=None):
    q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"
    msg = _struct.pack("!6H", 7, 0x8180, 1, len(ips) + (1 if cname else 0), 0, 0) + q + _struct.pack("!HH", 1, 1)
    if cname:
        c = b"".join(bytes([len(x)]) + x.encode() for x in cname.split(".")) + b"\0"
        msg += b"\xc0\x0c" + _struct.pack("!HHIH", 5, 1, ttl, len(c)) + c
    for ip in ips:
        msg += b"\xc0\x0c" + _struct.pack("!HHIH", 1, 1, ttl, 4) + _socket.inet_aton(ip)
    return msg


class DnsDomainTest(unittest.TestCase):
    def proxy(self, with_set=False):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        lp = os.path.join(d, "yt.domains")
        with open(lp, "w") as f:
            f.write("youtube.com\ngooglevideo.com\n")
        conf = os.path.join(d, "dns.json")
        with open(conf, "w") as f:
            _json.dump({"listen": "127.0.0.1", "default": {"mark": 0, "tcp": False}, "routes": {},
                        "dom": {"lists": {"yt": lp}, "clients": {"10.8.1.9": "p_1"},
                                "policies": {"p_global": [[["yt"], {"mark": 0x2003, "tcp": False}]],
                                             "p_1": [[["yt"], None]]},
                                "set": ["awgr", "dom4"] if with_set else None}}, f)
        return dnsproxy.Proxy(conf)

    def test_rule_route(self):
        p = self.proxy()
        self.assertEqual(p.domain_route("10.8.1.2", "rr3---sn-x.googlevideo.com."), ({"mark": 0x2003, "tcp": False}, (), True))
        self.assertIsNone(p.domain_route("10.8.1.2", "example.com."))
        self.assertEqual(p.domain_route("10.8.1.9", "youtube.com."), (None, (), True))   # блок / выход не работает

    def test_resolve_goes_through_rule_exit(self):
        p = self.proxy()
        seen = []

        async def fake(query, q, route, servers=(), fallback=True):
            seen.append(route)
            return b"\0\0" + query[2:]
        p._resolve = fake
        from tests.test_v115 import q_msg
        for name in ("www.youtube.com", "example.com"):
            m = q_msg(name)
            asyncio.run(p.resolve(m, dnsproxy.parse_query(m), "10.8.1.2"))
        self.assertEqual(seen, [{"mark": 0x2003, "tcp": False}, {"mark": 0, "tcp": False}])

    def test_answer_v4_through_cname(self):
        a = dns_answer("youtube.com", ["142.250.1.1", "142.250.1.2"], ttl=20, cname="y.googlevideo.com")
        self.assertEqual(dnsproxy.answer_v4(a), [("142.250.1.1", 20), ("142.250.1.2", 20)])

    def test_remember_and_resync(self):
        p = self.proxy(with_set=True)
        calls = []
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)

        async def go():
            with mock.patch.object(dnsproxy.subprocess, "run", side_effect=lambda c, **k: calls.append(c) or
                                   subprocess.CompletedProcess(c, 0, "", "")):
                p.remember(dns_answer("youtube.com", ["142.250.1.1"], ttl=20))
                p.remember(dns_answer("youtube.com", ["142.250.1.1"], ttl=20))   # уже в наборе — не повторяем
                await asyncio.sleep(dnsproxy.SET_FLUSH + 0.1)
                p.resync()                                                        # таблица пересоздана
                await asyncio.sleep(dnsproxy.SET_FLUSH + 0.1)
        loop.run_until_complete(go())
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][:6], ["nft", "add", "element", "ip", "awgr", "dom4"])
        self.assertIn(f"142.250.1.1 timeout {dnsproxy.SET_MIN}s", calls[0][6])
        self.assertIn("142.250.1.1 timeout", calls[1][6])


class EngineDomainDnsTest(DomainsAnyExitTest):
    def test_dns_domains_and_quic_marks(self):
        uid = self.awg()
        self.rules("direct", ([self.lid], "up:" + uid), ([self.lid], "block"))
        st = panel.store.snapshot()
        num = Store.upstream(st, uid)["num"]
        with mock.patch.object(panel.engine, "resolve", side_effect=lambda o, s: num if o == "up:" + uid else o):
            d = panel.engine.dns_domains(st, with_set=False)
            # «блок» (путь None) — и без набора: по нему dnsproxy.py не спрашивает такие имена у местного DNS
            # «напрямую» (второй круг проверки 1.22.0)
            self.assertEqual(d["policies"]["p_global"], [[[self.lid], {"mark": nftgen.mark_for(num), "tcp": False}],
                                                        [[self.lid], None]])
            self.assertIsNone(d["set"])
            d = panel.engine.dns_domains(st, with_set=True)
            self.assertEqual(d["policies"]["p_global"][1], [[self.lid], None])     # блок — и в набор
            self.assertEqual(d["set"], [_config.NFT_TABLE, nftgen.DOM_SET])
            self.assertEqual(panel.engine._quic_mark(st, "up:" + uid), nftgen.mark_for(num))
        self.assertEqual(panel.engine._quic_mark(st, "direct"), _config.QUIC_DIRECT_MARK)
        self.assertEqual(panel.engine._quic_mark(st, "block"), _config.MARK_BLOCK)

    def test_dom_filter_setting(self):
        server.put_server(Req({"dom_filter": True}))
        self.addCleanup(panel.store.mutate, lambda st: st["settings"].pop("dom_filter", None))
        st = panel.store.snapshot()
        self.assertTrue(st["settings"]["dom_filter"])
        self.assertTrue(server.get_server(None)["dom_filter"])
        self.assertFalse(panel.engine.dom_filter(st))                  # без DNS на сервере фильтра нет
        self.assertTrue(backup.clean_backup_state(panel.store.snapshot(texts=True))["settings"]["dom_filter"])

    def test_apply_falls_back_without_queue(self):
        """Ядро без nft_queue: набор правил с очередью не применился — применяется без неё, и QUIC у этих
        клиентов блокируется, как раньше."""
        e = panel.engine
        tried = []

        def ns(cmd, **kw):
            if cmd[:2] == ["nft", "-f"]:
                with open(cmd[2]) as f:
                    text = f.read()
                tried.append("queue" in text)
                if "queue" in text:
                    raise system.SysError("nft -f: Error: Could not process rule: No such file or directory queue num")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        uid = self.awg()
        self.rules("direct", ([self.lid], "up:" + uid))
        st = panel.store.snapshot()
        num = Store.upstream(st, uid)["num"]
        with mock.patch.object(e._fake, "ns", side_effect=ns), \
                mock.patch.object(e, "resolve", side_effect=lambda o, s: num if o == "up:" + uid else o), \
                mock.patch.object(e, "_sync_sni", return_value=_config.SNI_PROXY_PORT), \
                mock.patch.object(e, "_watch_server", return_value=False):
            e._quic_nft, e.applied_hash = None, None
            e.reconcile()
        self.assertEqual(tried[-2:], [True, False])      # сначала с очередью, затем без неё
        self.assertIs(e._quic_nft, False)
        self.assertNotIn("queue", e.ruleset)


if __name__ == "__main__":
    unittest.main()
