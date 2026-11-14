"""1.20.0: модуль ядра — рекомендуемый движок. Вопрос установщика (модуль первым, «рекомендуется»), сбой сборки при
установке — предупреждение и amneziawg-go; кнопка «Установить модуль» в панели; оповещение сверху; модуль пропал
после обновления ядра — событие; сервер не поднимается на модуле — панель сама отключает модуль и переводит сервер
на amneziawg-go; kernel.panic, чтобы сбой в модуле не оставлял сервер зависшим.

python3 -m unittest discover tests
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from app import config, engine, kernelmod, main, notify, web  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
with open(os.path.join(ROOT, "install.sh")) as _f:
    SH = _f.read()


def ok(cmd=(), out="", rc=0):
    return subprocess.CompletedProcess(list(cmd), rc, out, "")


class InstallerBase(unittest.TestCase):
    """Настоящие куски install.sh с поддельными apt-get, modprobe, sysctl и systemd-detect-virt."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        self.sys = os.path.join(self.tmp, "sys")
        self.log = os.path.join(self.tmp, "calls")
        stubs = {
            "systemd-detect-virt": 'echo "${VIRT:-none}"',
            "uname": 'case "$1" in -m) echo "${ARCH:-x86_64}";; -r) echo 7.0.0-1017-azure;; *) echo Linux;; esac',
            "apt-get": 'echo "apt-get $*" >> "$LOG"; if [[ "$*" == *"install -y -qq amneziawg-dkms"* ]]; then '
                       '[ -n "${FAIL_BUILD:-}" ] && exit 100; mkdir -p "$AWGR_SYS"; touch "$AWGR_SYS/dkms"; fi; exit 0',
            "apt-cache": "exit 0",
            "add-apt-repository": 'echo "add-apt-repository $*" >> "$LOG"',
            "modprobe": 'echo "modprobe $*" >> "$LOG"; mkdir -p "$AWGR_SYS/module/amneziawg"; '
                        'echo 3.1.20261113 > "$AWGR_SYS/module/amneziawg/version"',
            "rmmod": 'echo "rmmod $*" >> "$LOG"; rm -rf "$AWGR_SYS/module/amneziawg"',
            "modinfo": '[ -f "$AWGR_SYS/dkms" ] && echo 3.1.20261113 || exit 1',
            "sysctl": 'case "$1" in -n) echo "${PANIC:-0}";; *) echo "sysctl $*" >> "$LOG";; esac',
        }
        for name, body in stubs.items():
            path = os.path.join(self.bin, name)
            with open(path, "w") as f:
                f.write("#!/bin/bash\n" + body + "\n")
            os.chmod(path, 0o755)
        self.part = SH[SH.index('AWG_SYS="${AWGR_SYS:-/sys}"'):SH.index('if [ "$INFO_ONLY" = 1 ]')]
        self.osr = os.path.join(self.tmp, "os-release")
        self.block = os.path.join(self.tmp, "modprobe.d", "block.conf")
        self.panic = os.path.join(self.tmp, "sysctl.d", "panic.conf")
        self.modload = os.path.join(self.tmp, "modules-load.d", "amneziawg.conf")

    def run_sh(self, body: str, os_id="ubuntu", ver="24.04", loaded=None, **env):
        shutil.rmtree(self.sys, ignore_errors=True)                     # модуль прошлого запуска не переносится
        with open(self.osr, "w") as f:
            f.write(f'ID={os_id}\nVERSION_ID="{ver}"\n')
        if loaded:
            os.makedirs(os.path.join(self.sys, "module", "amneziawg"), exist_ok=True)
            with open(os.path.join(self.sys, "module", "amneziawg", "version"), "w") as f:
                f.write(loaded + "\n")
        script = ("set -uo pipefail\nstep() { echo \"STEP $1\"; }; ok() { echo \"OK $1\"; }; warn() { echo \"WARN $1\"; }\n"
                  "die() { echo \"DIE $1\"; exit 1; }\nask() { REPLY=\"$2\"; }\n"
                  "choose() { echo \"ASK $1 | $2 | $3\"; CHOICE=\"${ANSWER:-1}\"; }\n" + self.part + "\n" + body)
        e = {"PATH": self.bin + ":/usr/bin:/bin", "AWGR_SYS": self.sys, "AWGR_OS_RELEASE": self.osr, "LOG": self.log,
             "AWGR_MODLOAD": self.modload, "AWGR_MODBLOCK": self.block, "AWGR_PANIC_CONF": self.panic, **env}
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e, timeout=30)
        calls = open(self.log).read() if os.path.exists(self.log) else ""
        return p.returncode, p.stdout + p.stderr, calls


class EngineQuestionTest(InstallerBase):
    """Новая установка или reconfigure на подходящем сервере: вопрос, модуль первым и «рекомендуется»."""

    def question(self, env_file="", reconf="0", **kw):
        a = SH.index("# ------------------------------------------------------------------ AmneziaWG engine")
        block = SH[a:SH.index("# ------------------------------------------------------------------ settings", a)]
        env = os.path.join(self.tmp, ".env")
        with open(env, "w") as f:
            f.write(env_file)
        body = (f'ENV_FILE="{env}"\nRECONF={reconf}\n'
                'envget() { [ -f "$ENV_FILE" ] && grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true; }\n'
                + block + '\necho "WANT=$WANT_KERNEL"\n')
        return self.run_sh(body, **kw)

    def test_new_install_asks_and_recommends(self):
        rc, out, calls = self.question()
        self.assertEqual(rc, 0, out)
        self.assertIn("ASK Which AmneziaWG engine should the server use? | The Linux kernel module (recommended) | "
                      "amneziawg-go, a regular program", out)
        self.assertNotIn("CPU", out)                                   # просто «рекомендуется»
        self.assertIn("WANT=1", out)                                   # Enter — модуль
        self.assertEqual(calls, "")                                    # вопрос ничего не ставит
        rc, out, _ = self.question(ANSWER="2")
        self.assertIn("WANT=0", out)

    def test_no_question(self):
        for kw, why in (({"VIRT": "openvz"}, "контейнер"), ({"os_id": "debian", "ver": "11"}, "старая система"),
                        ({"ARCH": "armv7l"}, "процессор"), ({"env_file": "PANEL_ACCESS=public\n"}, "обновление"),
                        ({"AWGR_ENGINE": "go"}, "выбрано заранее"), ({"loaded": "3.1.20261113"}, "уже на модуле")):
            rc, out, _ = self.question(**kw)
            self.assertEqual(rc, 0, out)
            self.assertNotIn("ASK", out, why)
            self.assertIn("WANT=0", out, why)
        rc, out, _ = self.question(AWGR_ENGINE="kernel")
        self.assertNotIn("ASK", out)
        self.assertIn("WANT=1", out)
        rc, out, _ = self.question(env_file="PANEL_ACCESS=public\n", reconf="1")
        self.assertIn("ASK", out)                                      # reconfigure спрашивает

    def test_module_goes_before_the_server(self):
        k = SH.index('KERNEL_SOFT=1 install_kernel')
        self.assertLess(SH.index("# ------------------------------------------------------------------ AmneziaWG engine"), k)
        self.assertLess(k, SH.index('step "Installing AmneziaWG into container $SRV_NAME"'))
        self.assertLess(k, SH.index('step "Starting"'))                # сервер на хосте создаёт панель при запуске


class SoftFailTest(InstallerBase):
    """При установке сбой модуля — предупреждение, установка идёт дальше на amneziawg-go."""

    def test_build_failure_is_a_warning(self):
        rc, out, calls = self.run_sh('KERNEL_SOFT=1 install_kernel || echo "GO ON"\necho AFTER\n', FAIL_BUILD="1")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("DIE", out)
        self.assertIn("WARN The module did not build for kernel 7.0.0-1017-azure", out)
        self.assertIn("GO ON", out)
        self.assertIn("AFTER", out)
        self.assertIn("apt-get remove -y -qq amneziawg-dkms", calls)
        self.assertFalse(os.path.exists(self.modload))

    def test_not_fit_is_a_warning_too(self):
        rc, out, calls = self.run_sh('KERNEL_SOFT=1 install_kernel || echo "GO ON"\n', VIRT="lxc")
        self.assertEqual(rc, 0, out)
        self.assertIn("WARN This server is a container (lxc)", out)
        self.assertEqual(calls, "")

    def test_command_still_stops(self):
        rc, out, _ = self.run_sh("install_kernel\necho AFTER\n", FAIL_BUILD="1", AWGR_YES="y")
        self.assertEqual(rc, 1)
        self.assertIn("DIE The module did not build", out)            # awg-router install-kernel — код ошибки
        self.assertNotIn("AFTER", out)

    def test_no_confirmation_during_install(self):
        rc, out, calls = self.run_sh("KERNEL_SOFT=1 KERNEL_NEW_SERVER=1 install_kernel\n", AWGR_YES="n")
        self.assertEqual(rc, 0, out)                                   # ответ уже дан на вопрос о движке
        self.assertIn("OK Kernel module loaded: version 3.1.20261113", out)
        self.assertNotIn("Restart the AWG server", out)                # новый сервер сразу поднимется на модуле


class ModuleExtrasTest(InstallerBase):
    def test_unblocks_and_sets_panic(self):
        os.makedirs(os.path.dirname(self.block))
        with open(self.block, "w") as f:
            f.write("blacklist amneziawg\n")
        rc, out, calls = self.run_sh("install_kernel\n", AWGR_YES="y")
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(self.block))                   # «Попробовать снова» снимает запрет
        with open(self.panic) as f:
            self.assertEqual(f.read(), "kernel.panic = 10\n")
        self.assertIn("sysctl -q -w kernel.panic=10", calls)

    def test_own_panic_setting_stays(self):
        rc, out, calls = self.run_sh("install_kernel\n", AWGR_YES="y", PANIC="30")
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(self.panic))
        self.assertNotIn("kernel.panic", calls)


class KernelModTest(unittest.TestCase):
    """app.kernelmod: подходит ли сервер, установка кнопкой, своё состояние, запрет модуля."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        for name, val in (("STATE", os.path.join(self.d, "engine.json")), ("LOG", os.path.join(self.d, "kernel.log"))):
            p = mock.patch.object(kernelmod, name, val)
            p.start()
            self.addCleanup(p.stop)
        kernelmod._fit = None
        self.addCleanup(setattr, kernelmod, "_fit", None)

    def host(self, os_release, virt="none\n", arch="x86_64"):
        root = os.path.join(self.d, "host")
        os.makedirs(os.path.join(root, "etc"), exist_ok=True)
        with open(os.path.join(root, "etc", "os-release"), "w") as f:
            f.write(os_release)
        kernelmod._fit = None
        return (mock.patch.object(config, "DRY_RUN", False), mock.patch.object(config, "HOST_ROOT", root),
                mock.patch.object(kernelmod.selfupdate, "_host", return_value=ok(out=virt)),
                mock.patch.object(kernelmod.os, "uname", return_value=mock.Mock(machine=arch)))

    def fit(self, *a, **kw):
        ps = self.host(*a, **kw)
        for p in ps:
            p.start()
        try:
            return kernelmod.fit()
        finally:
            for p in ps:
                p.stop()

    def test_fit(self):
        self.assertTrue(self.fit('ID=ubuntu\nVERSION_ID="24.04"\n')["ok"])
        self.assertTrue(self.fit('ID=debian\nVERSION_ID="12"\n')["ok"])
        f = self.fit('ID=ubuntu\nVERSION_ID="20.04"\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\n')
        self.assertEqual((f["ok"], f["why"].key, f["why"].p["os"]), (False, "eng.fit_os", "Ubuntu 20.04.6 LTS"))
        f = self.fit('ID=ubuntu\nVERSION_ID="24.04"\n', virt="openvz\n")
        self.assertEqual((f["why"].key, f["why"].p["virt"]), ("eng.fit_container", "openvz"))
        self.assertEqual(self.fit('ID=debian\nVERSION_ID="12"\n', arch="armv7l")["why"].key, "eng.fit_arch")

    def test_state_file(self):
        self.assertEqual(kernelmod.load(), {})
        kernelmod.update(hidden="offer", seen="3.1")
        self.assertEqual(kernelmod.update(seen=None), {"hidden": "offer"})
        with open(kernelmod.STATE, "w") as f:
            f.write("{oops")
        self.assertEqual(kernelmod.load(), {})                         # повреждённый файл — как пустой

    def test_demo_install(self):
        with mock.patch.object(kernelmod.time, "sleep"):
            st = kernelmod.start()
            self.assertIn(st["state"], ("running", "done"))
            for _ in range(100):
                if kernelmod.status()["state"] == "done":
                    break
                time.sleep(0.02)
        self.assertEqual(kernelmod.status()["state"], "done")
        self.assertIn("  ✓ Kernel module loaded: version 3.1.20261113", kernelmod.log_lines())

    def test_running_and_unfit_refused(self):
        kernelmod.update(job={"started": time.time()})
        with self.assertRaises(kernelmod.KernelError) as cm:
            kernelmod.start()
        self.assertEqual(cm.exception.msg.key, "eng.inst_running")
        kernelmod.update(job=None)
        kernelmod._fit = {"ok": False, "why": main.Msg("eng.fit_arch", arch="armv7l")}
        with self.assertRaises(kernelmod.KernelError) as cm:
            kernelmod.start()
        self.assertEqual(cm.exception.msg.key, "eng.fit_arch")

    def test_host_install_runs_install_sh(self):
        calls = []

        def host(cmd, timeout=30):
            calls.append(cmd)
            return ok(cmd, rc=1 if cmd[:2] == ["systemctl", "is-active"] else 0)
        kernelmod._fit = {"ok": True, "why": None}
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(kernelmod.selfupdate, "_host", side_effect=host), \
                mock.patch.object(kernelmod.selfupdate, "host_dir", return_value="/opt/awg-router"):
            self.assertEqual(kernelmod.start()["state"], "running")
        run = calls[-1]
        self.assertEqual(run[:3], ["systemd-run", "--unit", kernelmod.UNIT])
        self.assertIn('AWGR_YES=y bash "/opt/awg-router/install.sh" --install-kernel', run[-1])
        self.assertIn('echo "exit=$?" >>"/opt/awg-router/data/kernel.log"', run[-1])
        with open(kernelmod.LOG, "a") as f:
            f.write("  ✗ The module did not build\nexit=1\n")
        self.assertEqual(kernelmod.status()["state"], "failed")

    def test_block(self):
        root = os.path.join(self.d, "host")
        os.makedirs(os.path.join(root, "etc", "modules-load.d"))
        with open(os.path.join(root, "etc", "modules-load.d", "amneziawg.conf"), "w") as f:
            f.write("amneziawg\n")
        with mock.patch.object(config, "HOST_ROOT", root), \
                mock.patch.object(kernelmod.selfupdate, "_host", return_value=ok()) as h:
            self.assertIsNone(kernelmod.block())
        h.assert_called_once_with(["rmmod", "amneziawg"], timeout=30)
        with open(os.path.join(root, "etc", "modprobe.d", "awg-router-amneziawg.conf")) as f:
            text = f.read()
        self.assertIn("blacklist amneziawg\n", text)                   # и автозагрузка по ip link add …
        self.assertIn("install amneziawg /bin/false\n", text)          # и явный modprobe
        self.assertFalse(os.path.exists(os.path.join(root, "etc", "modules-load.d", "amneziawg.conf")))
        with mock.patch.object(config, "HOST_ROOT", root), \
                mock.patch.object(kernelmod.selfupdate, "_host",
                                  return_value=subprocess.CompletedProcess([], 1, "", "Module amneziawg is in use")):
            self.assertEqual(kernelmod.block(), "Module amneziawg is in use")


class EngineWatchTest(unittest.TestCase):
    """Движок: модуль пропал — событие; сервер не поднимается на модуле — модуль отключается."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        p = mock.patch.object(kernelmod, "STATE", os.path.join(self.d, "engine.json"))
        p.start()
        self.addCleanup(p.stop)
        self.e = engine.Engine.__new__(engine.Engine)
        self.e.events = []
        self.e.event = lambda lvl, m: self.e.events.append((lvl, m.key, m.p))
        self.e.server_engine, self.e.kernel_fallback, self.e.rt = "kernel", None, {}
        self.mod = {"loaded": True, "version": "3.1.20261113", "ok": True}
        self.e.module_info = lambda: dict(self.mod)

    def watch(self):
        with mock.patch.object(config, "DRY_RUN", False):
            self.e._watch_module()

    def test_module_gone_after_kernel_update(self):
        self.watch()
        self.assertEqual(kernelmod.load().get("seen"), "3.1.20261113")
        self.assertEqual([x[1] for x in self.e.events], ["ev.kernel_on"])   # сервер на модуле — сообщаем раз
        self.watch()
        self.assertEqual(len(self.e.events), 1)
        self.e.events.clear()
        self.mod = {"loaded": False, "version": None, "ok": False}
        self.e.server_engine = None                    # сервер ещё не поднялся — молчим (модуль мог не успеть)
        self.watch()
        self.assertEqual(self.e.events, [])
        self.e.server_engine = "go"                    # поднялся на amneziawg-go — модуль пропал
        self.watch()
        self.watch()
        self.assertEqual([x[1] for x in self.e.events], ["ev.kernel_gone"])     # один раз
        self.assertEqual(self.e.events[0][2]["version"], "3.1.20261113")
        self.assertTrue(kernelmod.load().get("lost"))
        self.mod = {"loaded": True, "version": "3.1.20261113", "ok": True}
        self.watch()
        self.assertNotIn("lost", kernelmod.load())

    def test_never_on_module_no_event(self):
        self.mod = {"loaded": False, "version": None, "ok": False}
        self.e.server_engine = "go"
        self.watch()
        self.assertEqual(self.e.events, [])

    def test_server_down_on_module_switches_to_go(self):
        """Сервер не поднимается: после KERNEL_GIVE_UP перезапусков с загруженным модулем — запрет модуля, событие,
        перезапуск; дальше — без повторов."""
        e = self.e
        e._srv_down, e._srv_tries, e._srv_next = None, 0, 0.0
        e.wake = mock.Mock()
        e._stop_all = mock.Mock()
        t = mock.Mock(kind="host", iface="awg0")                       # на хосте — без SERVER_GRACE
        t.is_up = lambda: False
        now = [1000.0]
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(engine.time, "time", lambda: now[0]), \
                mock.patch.object(kernelmod, "block", return_value=None) as blk:
            for _ in range(5):
                now[0] += 4000                         # дольше любой паузы SERVER_PAUSES
                self.assertTrue(e._watch_server(t))
                if e._srv_tries == engine.KERNEL_GIVE_UP:
                    blk.assert_not_called()            # первые перезапуски — как раньше
        blk.assert_called_once()
        e._stop_all.assert_called()
        self.assertEqual(t.restart.call_count, 5)
        kinds = [x[1] for x in e.events if x[1].startswith("ev.kernel")]
        self.assertEqual(kinds, ["ev.kernel_disabled"])
        self.assertEqual([x[2]["n"] for x in e.events if x[1] == "ev.kernel_disabled"], [engine.KERNEL_GIVE_UP])
        self.assertTrue(kernelmod.load()["disabled"]["at"])

    def test_unload_failed_says_reboot(self):
        e = self.e
        e._srv_tries = engine.KERNEL_GIVE_UP + 1
        e._stop_all = mock.Mock()
        with mock.patch.object(kernelmod, "block", return_value="in use"):
            e._drop_module()
        self.assertEqual(e.events[-1][1], "ev.kernel_disabled_reboot")
        self.assertEqual(kernelmod.load()["disabled"]["error"], "in use")

    def test_no_module_no_switch(self):
        e = self.e
        e._srv_down, e._srv_tries, e._srv_next = None, 0, 0.0
        e.wake = mock.Mock()
        self.mod = {"loaded": False, "version": None, "ok": False}
        t = mock.Mock(kind="host", iface="awg0")
        t.is_up = lambda: False
        now = [1000.0]
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(engine.time, "time", lambda: now[0]), \
                mock.patch.object(kernelmod, "block") as blk:
            for _ in range(4):
                now[0] += 4000
                e._watch_server(t)
        blk.assert_not_called()

    def test_reinstalled_module_clears_disabled(self):
        kernelmod.update(disabled={"at": 1.0, "error": None})
        self.e.server_engine = "go"
        self.watch()
        self.assertNotIn("disabled", kernelmod.load())


class OfferTest(unittest.TestCase):
    """Оповещение сверху (engine_offer): какой вид и когда; «Скрыть» — по виду."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        for name, val in (("STATE", os.path.join(self.d, "engine.json")), ("LOG", os.path.join(self.d, "kernel.log"))):
            p = mock.patch.object(kernelmod, name, val)
            p.start()
            self.addCleanup(p.stop)
        self.t = mock.Mock(exists=True)
        self.saved = main.engine.server_engine
        self.addCleanup(setattr, main.engine, "server_engine", self.saved)

    def notice(self, mod, server="go", fit=True):
        main.engine.server_engine = server
        with mock.patch.object(main.engine, "module_info", return_value=mod), \
                mock.patch.object(kernelmod, "fit", return_value={"ok": fit, "why": None}):
            return main.engine_offer(self.t)["notice"]

    NONE = {"loaded": False, "version": None, "ok": False}
    OLD = {"loaded": True, "version": "1.0.2025", "ok": False}
    NEW = {"loaded": True, "version": "3.1.20261113", "ok": True}

    def test_kinds(self):
        self.assertEqual(self.notice(self.NONE), "offer")
        self.assertIsNone(self.notice(self.NONE, fit=False))            # не подходит — не предлагаем
        self.assertEqual(self.notice(self.OLD), "old")
        self.assertEqual(self.notice(self.NEW, server="go"), "restart")  # модуль есть, сервер ещё на amneziawg-go
        self.assertIsNone(self.notice(self.NEW, server="kernel"))
        kernelmod.update(lost=1700000000.5)
        self.assertEqual(self.notice(self.NONE), "lost:1700000000")
        kernelmod.update(disabled={"at": 1700000100, "error": None})
        self.assertEqual(self.notice(self.NONE), "disabled:1700000100")
        kernelmod.update(job={"started": time.time()})
        self.assertEqual(self.notice(self.NONE), "installing")
        self.assertIsNone(main.engine_offer(mock.Mock(exists=False))["notice"])

    def test_hide_by_kind(self):
        R = type("R", (), {"__init__": lambda s, b: setattr(s, "b", b), "json": lambda s: s.b})
        main.put_engine(R({"hidden": "offer"}))
        self.assertIsNone(self.notice(self.NONE))
        kernelmod.update(lost=5.0)
        self.assertEqual(self.notice(self.NONE), "lost:5")              # новый случай — снова видно
        for bad in ("<b>", 5, "offer:abc", "x" * 40):
            with self.assertRaises(web.HTTPError):
                main.put_engine(R({"hidden": bad}))
        main.put_engine(R({"hidden": None}))
        self.assertNotIn("hidden", kernelmod.load())

    def test_api(self):
        with mock.patch.object(kernelmod, "start", side_effect=kernelmod.KernelError(main.Msg("eng.inst_running"))):
            with self.assertRaises(web.HTTPError) as cm:
                main.engine_install(None)
        self.assertEqual((cm.exception.code, cm.exception.detail.key), (409, "eng.inst_running"))
        st = main.engine_install_status(None)
        self.assertEqual(st["state"], "idle")
        self.assertIn("log", st)


class TelegramTextsTest(unittest.TestCase):
    def test_new_events(self):
        for key, kind in (("ev.kernel_gone", "kernel_gone"), ("ev.kernel_disabled", "kernel_disabled"),
                          ("ev.kernel_disabled_reboot", "kernel_disabled_reboot")):
            self.assertEqual(notify.ENGINE_EVENTS[key], ("server", kind))
            for lang in notify.LANGS:
                text = notify.render(lang, kind, "", version="3.1", n=2)
                self.assertNotIn("{", text, (lang, kind))
        sent = []
        n = notify.Notifier.__new__(notify.Notifier)
        n._target_lost = False
        n.event = lambda kind, key, refs=None, **p: sent.append((kind, key, p))
        n.engine_event(main.Msg("ev.kernel_disabled", n=2))
        self.assertEqual(sent, [("server", "kernel_disabled", {"n": 2})])


if __name__ == "__main__":
    unittest.main()


class FastPathTest(InstallerBase):
    """Модуль установлен, но не загружен (выбран amneziawg-go или отключён после сбоя): «Попробовать снова» и
    переключатель только загружают его — без PPA и сборки (PPA из РФ бывает недоступен)."""

    def test_installed_module_just_loads(self):
        os.makedirs(self.sys, exist_ok=True)
        rc, out, calls = self.run_sh('mkdir -p "$AWGR_SYS"; touch "$AWGR_SYS/dkms"\nKERNEL_SOFT=1 install_kernel\n')
        self.assertEqual(rc, 0, out)
        self.assertIn("OK Kernel module loaded: version 3.1.20261113", out)
        self.assertIn("modprobe amneziawg", calls)
        self.assertNotIn("apt-get", calls)
        self.assertTrue(os.path.exists(self.modload))


class SwitchEngineTest(unittest.TestCase):
    """Ручной выбор движка: amneziawg-go — стоп сервера, запрет и выгрузка модуля, запуск; модуль — перезапуск
    или установка."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        for name, val in (("STATE", os.path.join(self.d, "engine.json")), ("LOG", os.path.join(self.d, "kernel.log"))):
            p = mock.patch.object(kernelmod, name, val)
            p.start()
            self.addCleanup(p.stop)
        self.e = engine.Engine.__new__(engine.Engine)
        self.e.lock = __import__("threading").RLock()
        self.e.events, self.e.rt, self.e.kernel_fallback, self.e.server_engine = [], {}, None, "kernel"
        self.e.event = lambda lvl, m: self.e.events.append(m.key)
        self.e.wake = mock.Mock()
        self.e._stop_all = mock.Mock()
        self.calls = []
        self.t = mock.Mock(exists=True)
        self.t.stop.side_effect = lambda: self.calls.append("stop")
        self.t.start.side_effect = lambda: self.calls.append("start")
        self.e.target = self.t
        self.mod = {"loaded": True, "version": "3.1.20261113", "ok": True}
        self.e.module_info = lambda: dict(self.mod)

    def test_to_go(self):
        with mock.patch.object(config, "DRY_RUN", False), \
                mock.patch.object(kernelmod, "block", side_effect=lambda: self.calls.append("block")) as blk:
            r = self.e.switch_engine("go")
        self.assertEqual(r, {"action": "restarted", "reboot": False})
        self.assertEqual(self.calls, ["stop", "block", "start"])       # модуль выгружается, пока сервер стоит
        self.e._stop_all.assert_called_once()
        blk.assert_called_once()
        self.assertEqual(kernelmod.load()["choice"], "go")
        self.assertEqual(self.e.events, ["ev.engine_go"])

    def test_to_go_server_starts_even_if_block_fails(self):
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(kernelmod, "block", side_effect=OSError("ro fs")):
            r = self.e.switch_engine("go")
        self.assertTrue(r["reboot"])
        self.assertEqual(self.calls, ["stop", "start"])
        self.assertEqual(self.e.events, ["ev.engine_go_reboot"])

    def test_to_go_without_module(self):
        self.mod = {"loaded": False, "version": None, "ok": False}
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(kernelmod, "block") as blk:
            self.e.switch_engine("go")
        blk.assert_not_called()
        self.assertEqual(self.calls, [])                               # и так на amneziawg-go — без перезапуска
        self.assertEqual(kernelmod.load()["choice"], "go")

    def test_to_kernel(self):
        kernelmod.update(choice="go")
        self.e.restart_server = mock.Mock()
        self.assertEqual(self.e.switch_engine("kernel"), {"action": "restarted"})
        self.e.restart_server.assert_called_once()
        self.assertNotIn("choice", kernelmod.load())
        self.mod = {"loaded": False, "version": None, "ok": False}
        with mock.patch.object(kernelmod, "start") as st:
            self.assertEqual(self.e.switch_engine("kernel"), {"action": "install"})
        st.assert_called_once()

    def test_api_and_offer(self):
        R = type("R", (), {"__init__": lambda s, b: setattr(s, "b", b), "json": lambda s: s.b})
        for bad in ("auto", None, 1):
            with self.assertRaises(web.HTTPError):
                main.engine_choose(R({"engine": bad}))
        with mock.patch.object(main.engine, "switch_engine", return_value={"action": "restarted"}) as sw:
            self.assertEqual(main.engine_choose(R({"engine": "go"})), {"action": "restarted"})
        sw.assert_called_once_with("go")
        kernelmod.update(choice="go")
        with mock.patch.object(main.engine, "module_info", return_value={"loaded": False, "version": None, "ok": False}), \
                mock.patch.object(kernelmod, "fit", return_value={"ok": True, "why": None}):
            o = main.engine_offer(mock.Mock(exists=True))
        self.assertIsNone(o["notice"])                                 # выбрали amneziawg-go — модуль не навязываем
        self.assertEqual(o["choice"], "go")


class BotEngineLineTest(unittest.TestCase):
    def test_line(self):
        from app import tgbot
        self.assertEqual(tgbot.Bot._engine_line("ru", {"server": "kernel", "version": "3.1.20261113"}),
                         ["⚙️ Движок: модуль ядра 3.1.20261113"])
        self.assertEqual(tgbot.Bot._engine_line("en", {"server": "go"}), ["⚙️ Engine: amneziawg-go"])
        self.assertEqual(tgbot.Bot._engine_line("zh", {"server": None}), [])
        for lang in notify.LANGS:
            self.assertNotIn("{", tgbot.tr(lang, "st_engine_kernel", version="3.1"))
            self.assertNotIn("{", notify.render(lang, "kernel_on", "", version="3.1"))
        self.assertEqual(notify.ENGINE_EVENTS["ev.kernel_on"], ("server", "kernel_on"))
        info = main._bot_host_info()
        self.assertIn("engine", info)
