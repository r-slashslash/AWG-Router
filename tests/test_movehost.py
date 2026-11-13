"""Перенос сервера AWG из контейнера на хост (app.movehost и шаги install.sh), удаление панели с вопросом о
сервере AWG и пустой контейнер Amnezia (issue #25).

python3 -m unittest discover tests
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import awgserver, config, movehost, system  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
K = lambda c: c * 43 + "="       # noqa: E731 — ключ нужной формы

CONTAINER_CONF = f"""[Interface]
PrivateKey = {K("A")}
Address = 10.8.1.0/24
ListenPort = 41234
Jc = 4
H1 = 123456
PostUp = iptables -A INPUT -j ACCEPT
# I1 = <b 0x01>

[Peer]
PublicKey = {K("B")}
PresharedKey = {K("C")}
AllowedIPs = 10.8.1.2/32

#awgr:disabled
#[Peer]
#PublicKey = {K("D")}
#AllowedIPs = 10.8.1.3/32
"""


class MoveHostTest(unittest.TestCase):
    """Файлы контейнера → сервер на хосте: те же ключи, порт, параметры и клиенты; NAT — панели."""

    def setUp(self):
        self.root = tempfile.mkdtemp()                 # «корень хоста»
        self.src = tempfile.mkdtemp()                  # копия /opt/amnezia/awg (docker cp)
        self.addCleanup(shutil.rmtree, self.root)
        self.addCleanup(shutil.rmtree, self.src)
        with open(os.path.join(self.src, "awg0.conf"), "w") as f:
            f.write(CONTAINER_CONF)
        with open(os.path.join(self.src, "clientsTable"), "w") as f:
            json.dump([{"clientId": K("B"), "userData": {"clientName": "Phone"}}], f)
        self.cmds, self.up = [], [True]
        root = self.root

        class FakeHost(system.HostTarget):
            def host_path(s, p):
                return root + p

            def native(s, cmd, **kw):
                self.cmds.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, "", "")

            def is_up(s):
                return self.up[0]
        self.patches = [mock.patch.object(movehost, "host_target", lambda: FakeHost(movehost.IFACE)),
                        mock.patch.object(system, "install_host_runtime"),
                        mock.patch.object(system, "open_firewall_udp"),
                        mock.patch.object(movehost.time, "sleep")]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def host_file(self, name):
        with open(f"{self.root}{config.HOST_AWG_DIR}/{name}") as f:
            return f.read()

    def test_check(self):
        self.assertEqual(movehost.check(self.src), "port=41234 clients=2")

    def test_install_keeps_server_and_clients(self):
        self.assertEqual(movehost.install(self.src), "port=41234 clients=2")
        sc = awgserver.parse(self.host_file("awg0.conf"))
        self.assertEqual(sc.get("PrivateKey"), K("A"))
        self.assertEqual((sc.get("ListenPort"), sc.get("Jc"), sc.get("H1")), ("41234", "4", "123456"))
        self.assertEqual([p.public_key for p in sc.peers], [K("B"), K("D")])
        self.assertFalse(sc.peers[1].enabled)                       # отключённый клиент так и остался
        self.assertEqual(sc.peers[0].psk, K("C"))
        self.assertIn("MASQUERADE", sc.get("PostUp"))              # NAT панели вместо хуков контейнера
        self.assertNotIn("-A INPUT", sc.get("PostUp"))
        self.assertIn("# I1 = <b 0x01>", self.host_file("awg0.conf"))
        self.assertIn("Phone", self.host_file("clientsTable"))
        self.assertIn(["systemctl", "enable", "--now", "awg-quick@awg0"], self.cmds)
        system.open_firewall_udp.assert_called_once()
        with self.assertRaises(movehost.MoveError):                # второй раз — уже есть на хосте
            movehost.check(self.src)

    def test_interface_not_up_and_undo(self):
        self.up[0] = False
        with self.assertRaises(movehost.MoveError):
            movehost.install(self.src)
        movehost.undo()
        self.assertIn(["systemctl", "disable", "--now", "awg-quick@awg0"], self.cmds)
        left = os.listdir(f"{self.root}{config.HOST_AWG_DIR}")
        self.assertNotIn("awg0.conf", left)                         # сервер на хосте снова «не найден»
        self.assertTrue(any(n.startswith("awg0.conf.failed-") for n in left))

    def test_bad_source(self):
        os.remove(os.path.join(self.src, "awg0.conf"))
        with self.assertRaises(movehost.MoveError):
            movehost.check(self.src)
        with open(os.path.join(self.src, "wg0.conf"), "w") as f:   # старый контейнер amnezia-awg
            f.write(CONTAINER_CONF.replace("ListenPort = 41234\n", ""))
        with self.assertRaises(movehost.MoveError) as cm:
            movehost.check(self.src)
        self.assertIn("listen port", str(cm.exception))
        self.assertEqual(movehost.main(["check", self.src]), 1)
        self.assertEqual(movehost.main(["nope"]), 2)


DOCKER = r"""#!/usr/bin/env bash
# поддельный docker: журнал вызовов, состояние контейнеров — файлы в $STATE
echo "docker $*" >> "$DOCKER_LOG"
case "$1" in
  ps)      [ "${2:-}" = -a ] && ls "$STATE/all" 2>/dev/null || ls "$STATE/run" 2>/dev/null ;;
  exec)    [ -f "$STATE/conf-$2" ]; exit $? ;;
  update|stop) exit 0 ;;
  start)   [ -f "$STATE/all/$2" ] && touch "$STATE/run/$2" ;;
  rename)  [ -f "$STATE/all/$2" ] || exit 1; mv "$STATE/all/$2" "$STATE/all/$3"; rm -f "$STATE/run/$2"
           [ -f "$STATE/conf-$2" ] && mv "$STATE/conf-$2" "$STATE/conf-$3"; exit 0 ;;
  inspect) case "$3" in
             *Mounts*) cat "$STATE/mounts-$4" 2>/dev/null ;;
             *RestartPolicy*) echo always ;;
             *Image*) echo sha256:img ;;
           esac ;;
  cp)      exit "${CP_RC:-0}" ;;
  rm)      rm -f "$STATE/all/$3" "$STATE/run/$3" ;;
  image)   exit 0 ;;
  compose) shift; case "$1" in
             run) for a in "$@"; do last="$a"; done
                  case "$*" in
                    *"movehost check"*) echo "port=41234 clients=2"; exit "${CHECK_RC:-0}" ;;
                    *"movehost install"*) [ "${INSTALL_RC:-0}" = 0 ] && echo "port=41234 clients=2" \
                                             || echo "the awg0 interface did not come up"; exit "${INSTALL_RC:-0}" ;;
                  esac ;;
           esac ;;
esac
exit 0
"""


class InstallerMoveTest(unittest.TestCase):
    """install.sh: выбор «перенести на хост», пустой контейнер, шаг переноса с откатом, удаление."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.state = os.path.join(self.tmp, "state")
        for d in ("all", "run"):
            os.makedirs(os.path.join(self.state, d))
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir)
        for name, text in (("docker", DOCKER), ("systemctl", "#!/bin/sh\necho \"systemctl $*\" >> \"$DOCKER_LOG\"\n")):
            with open(os.path.join(bindir, name), "w") as f:
                f.write(text)
            os.chmod(os.path.join(bindir, name), 0o755)
        self.log = os.path.join(self.tmp, "docker.log")
        self.env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "DOCKER_LOG": self.log,
                    "STATE": self.state}
        for k in ("AWGR_MODE", "AWGR_MOVE", "AWGR_INSTALL", "AWGR_AWG_PORT"):
            self.env.pop(k, None)
        with open(os.path.join(ROOT, "install.sh")) as f:
            self.sh = f.read()

    def container(self, name, conf=True, ours=False):
        open(os.path.join(self.state, "all", name), "w").close()
        open(os.path.join(self.state, "run", name), "w").close()
        if conf:
            open(os.path.join(self.state, f"conf-{name}"), "w").close()
        if ours:
            with open(os.path.join(self.state, f"mounts-{name}"), "w") as f:
                f.write(f"{self.tmp}/awg-server/data\n")

    def part(self, start, end):
        a = self.sh.index(start)
        return self.sh[a:self.sh.index(end, a)]

    def stubs(self):
        c = self.sh.index("choose() {")
        return (self.sh[self.sh.index("ask() {"):self.sh.index("\n}\n", self.sh.index("ask() {")) + 3] +
                self.sh[c:self.sh.index("\n}\n", c) + 3] +
                textwrap.dedent(f"""\
                    DIR="{self.tmp}"; ENV_FILE="$DIR/.env"; SRV_DATA="$DIR/awg-server/data"; IMAGE=awg-router:latest
                    HOSTCONF="$DIR/etc/amnezia/amneziawg/awg0.conf"; HAVE_DOCKER=1; RECONF=${{RECONF:-0}}
                    B=; N=; step() {{ echo "STEP $1"; }}; ok() {{ echo "OK $1"; }}; warn() {{ echo "WARN $1"; }}
                    die() {{ echo "DIE $1"; exit 1; }}
                    envget() {{ [ -f "$ENV_FILE" ] && grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true; }}
                    random_port() {{ echo 41000; }}; port_busy() {{ return 1; }}
                    """))

    def run_sh(self, body, answers="", **env):
        open(self.log, "w").close()
        # ask читает /dev/tty: в тестах ответы идут из ANSWERS по одному (без терминала — по умолчанию)
        script = self.stubs() + textwrap.dedent("""\
            ask() { printf '%s' "$1"; REPLY="${ANSWERS%%,*}"; [ "$ANSWERS" = "${ANSWERS#*,}" ] && ANSWERS="" \
                    || ANSWERS="${ANSWERS#*,}"; REPLY="${REPLY:-$2}"; }
            """) + body
        r = subprocess.run(["bash", "-uo", "pipefail", "-c", script], env={**self.env, "ANSWERS": answers, **env},
                           capture_output=True, text=True, timeout=30)
        with open(self.log) as f:
            return r.stdout + r.stderr, f.read()

    def mode_block(self):
        return self.part("# ------------------------------------------------------------------ AmneziaWG server",
                         'case "$INSTALL_AWG" in') + '\necho "MODE=$AWG_MODE MOVE=$MOVE_FROM INSTALL=$INSTALL_AWG"\n'

    def test_choose_move(self):
        self.container("amnezia-awg2")
        out, _ = self.run_sh(self.mode_block(), answers="2", RECONF="1")
        self.assertIn("Move this server to the host", out)
        self.assertIn("MODE=host MOVE=amnezia-awg2 INSTALL=", out)

    def test_move_from_env(self):
        self.container("amnezia-awg2")
        out, _ = self.run_sh(self.mode_block(), AWGR_MODE="host", AWGR_MOVE="yes")
        self.assertIn("MODE=host MOVE=amnezia-awg2", out)

    def test_new_host_server_still_possible(self):
        self.container("amnezia-awg2")
        out, _ = self.run_sh(self.mode_block(), answers="3", RECONF="1")
        self.assertIn("MODE=host MOVE= INSTALL=host", out)

    def test_empty_container_is_set_aside(self):
        # #25: папку /opt/awg-router удалили, а контейнер работает без конфига и держит порт
        self.container("amnezia-awg2", conf=False)
        out, log = self.run_sh(self.mode_block(), answers="2", RECONF="1")
        self.assertIn("has no AmneziaWG config", out)
        self.assertNotIn("Found an AmneziaVPN server", out)
        self.assertIn("MODE=host MOVE= INSTALL=host", out)          # «на хосте» — уже без занятого порта
        self.assertIn("docker update --restart no amnezia-awg2", log)
        self.assertRegex(log, r"docker rename amnezia-awg2 amnezia-awg2-empty-\d{8}-\d{6}")

    def move_block(self):
        return (self.part("move_server() {", "\n}\n") + "\n}\n" +
                self.part('if [ -n "$MOVE_FROM" ]; then\n  step "Moving', "\nfi\n") + "\nfi\n" +
                'echo "MODE=$AWG_MODE"; cat "$ENV_FILE"\n')

    def test_move_step(self):
        self.container("amnezia-awg2")
        with open(os.path.join(self.tmp, ".env"), "w") as f:
            f.write("AWG_MODE=host\n")
        out, log = self.run_sh('MOVE_FROM=amnezia-awg2; AWG_MODE=host\n' + self.move_block())
        self.assertIn("AmneziaWG runs on the host: port=41234 clients=2", out)
        self.assertIn("MODE=host", out)
        order = [l.split()[1] + (" " + l.split()[2] if l.split()[1] == "compose" else "") for l in log.splitlines()]
        self.assertLess(order.index("stop"), [i for i, x in enumerate(order) if x == "compose run"][-1])
        self.assertRegex(log, r"docker rename amnezia-awg2 amnezia-awg2-moved-")
        self.assertIn("docker compose stop awg-router", log)

    def test_move_failure_puts_container_back(self):
        self.container("amnezia-awg2")
        with open(os.path.join(self.tmp, ".env"), "w") as f:
            f.write("AWG_MODE=host\n")
        out, log = self.run_sh('MOVE_FROM=amnezia-awg2; AWG_MODE=host\n' + self.move_block(), INSTALL_RC="1")
        self.assertIn("did not come up", out)
        self.assertIn("The server stays in container amnezia-awg2", out)
        self.assertIn("AWG_MODE=container", out)                    # .env и переменная — снова контейнер
        self.assertIn("movehost undo", log)
        self.assertRegex(log, r"docker rename amnezia-awg2-moved-\S+ amnezia-awg2")
        self.assertIn("docker update --restart always amnezia-awg2", log)
        self.assertIn("docker start amnezia-awg2", log)

    def test_move_check_failure_changes_nothing(self):
        self.container("amnezia-awg2")
        out, log = self.run_sh('MOVE_FROM=amnezia-awg2; AWG_MODE=host; touch "$ENV_FILE"\n' + self.move_block(),
                               CHECK_RC="1")
        self.assertNotIn("docker stop", log)
        self.assertNotIn("docker rename", log)

    def uninstall_block(self):
        return self.part("our_container() {", "if [ \"$UNINSTALL\" = 1 ]") + "uninstall\n"

    def test_uninstall_keeps_own_server_and_warns_about_folder(self):
        self.container("amnezia-awg2", ours=True)
        out, log = self.run_sh(self.uninstall_block(), answers="yes,1")
        self.assertIn("The AmneziaWG server in container amnezia-awg2", out)
        self.assertNotIn("docker rm -f", log)
        self.assertIn("do not delete", out)
        self.assertIn("python3 -m app.uninstall", log)

    def test_uninstall_removes_own_server(self):
        self.container("amnezia-awg2", ours=True)
        out, log = self.run_sh(self.uninstall_block(), answers="yes,2")
        self.assertIn("docker rm -f amnezia-awg2", log)
        self.assertLess(log.index("app.uninstall"), log.index("docker rm -f"))   # правила убраны до сервера
        self.assertIn("delete the folder to remove them too", out)

    def test_uninstall_leaves_amnezia_app_container(self):
        self.container("amnezia-awg2")                              # создан приложением AmneziaVPN
        out, log = self.run_sh(self.uninstall_block(), answers="yes")
        self.assertIn("belongs to the AmneziaVPN app", out)
        self.assertNotIn("what should happen to it", out)
        self.assertNotIn("docker rm", log)

    def test_uninstall_host_server(self):
        os.makedirs(os.path.join(self.tmp, "etc/amnezia/amneziawg"))
        open(os.path.join(self.tmp, "etc/amnezia/amneziawg/awg0.conf"), "w").close()
        with open(os.path.join(self.tmp, ".env"), "w") as f:
            f.write("AWG_MODE=host\n")
        out, log = self.run_sh(self.uninstall_block(), answers="yes,2")
        self.assertIn("systemctl disable --now awg-quick@awg0", log)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "etc/amnezia/amneziawg")))
        self.assertTrue(any(n.startswith("amneziawg.removed-") for n in os.listdir(os.path.join(self.tmp, "etc/amnezia"))))

    def test_uninstall_needs_yes(self):
        self.container("amnezia-awg2", ours=True)
        out, log = self.run_sh(self.uninstall_block(), answers="no")
        self.assertIn("Cancelled", out)
        self.assertNotIn("compose", log)

    def test_helper_calls_installer(self):
        self.assertIn('uninstall)   bash "\\$DIR/install.sh" --uninstall ;;', self.sh)
        subprocess.run(["bash", "-n", os.path.join(ROOT, "install.sh")], check=True)


if __name__ == "__main__":
    unittest.main()
