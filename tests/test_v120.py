"""1.20.0: проверка Let's Encrypt через веб-сервер кладёт файл в папку токенов (issue #21); выход по IPv6
без пути до него, панель по IPv6 и сертификат на адрес IPv6 (issue #20).

python3 -m unittest discover tests
"""
import http.client
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import config, engine, main, system, tlsconf, tlsmgr, web, webfront  # noqa: E402


class SelfTestPathTest(unittest.TestCase):
    """С настоящим HOST_ROOT (/proc/1/root) файл проверки должен лечь в .well-known/acme-challenge/,
    а не рядом с ней: без этого проверка через nginx, Apache, Caddy всегда получала 404."""

    def test_token_inside_challenge_dir(self):
        root = tempfile.mkdtemp()
        webroot = "/var/lib/awg-router/acme"
        seen = []

        class Conn:
            """Веб-сервер: отдаёт файлы из webroot на хосте по пути запроса."""

            def __init__(self, *a, **k):
                pass

            def request(self, method, path, headers=None):
                fp = root + webroot + path
                seen.append(fp)
                if os.path.isfile(fp):
                    with open(fp) as f:
                        self.status, self.body = 200, f.read()
                else:
                    self.status, self.body = 404, ""

            def getresponse(self):
                me = self

                class R:
                    status = me.status

                    def read(self, n):
                        return me.body.encode()
                return R()

            def close(self):
                pass

        with mock.patch.object(config, "HOST_ROOT", root), mock.patch.object(config, "DRY_RUN", False), \
                mock.patch.object(webfront.http.client, "HTTPConnection", Conn), \
                mock.patch.object(webfront.time, "sleep"):
            ok, detail = webfront.self_test(webroot, "203.0.113.5", tries=1)
        self.assertEqual((ok, detail), (True, ""))
        self.assertTrue(seen[0].startswith(f"{root}{webroot}/.well-known/acme-challenge/awgr-check-"))
        self.assertEqual(os.listdir(f"{root}{webroot}/.well-known/acme-challenge"), [])   # файл убран
        self.assertEqual(sorted(os.listdir(f"{root}{webroot}/.well-known")), ["acme-challenge"])


class V6RouteTest(unittest.TestCase):
    """Выход по IPv6 проверяет путь в сети сервера AWG, а не режим: у кого IPv6 в Docker включён, работает."""

    def target(self, kind: str, rc: int):
        calls = []
        t = mock.Mock(kind=kind)
        t.ns = lambda cmd, **kw: calls.append(cmd) or subprocess.CompletedProcess(cmd, rc, "", "")
        return t, calls

    def test_ipv4_not_checked(self):
        t, calls = self.target("container", 2)
        engine.Engine._v6_route(t, "203.0.113.7")
        self.assertEqual(calls, [])

    def test_no_route(self):
        for kind, key in (("container", "sys.no_v6_container"), ("host", "sys.no_v6_route")):
            t, calls = self.target(kind, 2)
            with self.assertRaises(system.SysError) as cm:
                engine.Engine._v6_route(t, "2001:db8::7")
            self.assertEqual(cm.exception.msg.key, key)
            self.assertEqual(cm.exception.msg.p, {"ip": "2001:db8::7"})
            self.assertEqual(calls, [["ip", "-6", "route", "get", "2001:db8::7"]])

    def test_route_ok(self):
        t, _ = self.target("container", 0)
        engine.Engine._v6_route(t, "2001:db8::7")


class PanelV6Test(unittest.TestCase):
    """Панель слушает и IPv6: «Внешний адрес сервера» может быть IPv6 — по нему открывается панель, на него
    выписан сертификат и к нему подключаются клиенты, как и задумано у одного поля (issue #20)."""

    def test_v6_public_host_accepted(self):
        main.engine.reconcile()            # демо-сервер AWG как цель
        try:
            main.engine.srv.update_server({"public_host": "[2001:db8::5]"})
            self.assertEqual(main.store.snapshot()["settings"]["public_host"], "2001:db8::5")
            self.assertEqual(main.panel_url().split("//", 1)[1].split("/", 1)[0][:14], "[2001:db8::5]:")
        finally:
            main.engine.srv.update_server({"public_host": "203.0.113.5"})

    def test_client_key(self):
        self.assertEqual(web.client_key("203.0.113.5"), "203.0.113.5")
        self.assertEqual(web.client_key("::ffff:203.0.113.5"), "203.0.113.5")      # IPv4 через сокет IPv6
        # один абонент — одна /64: смена адреса внутри неё не обходит блокировку подбора пароля
        self.assertEqual(web.client_key("2001:db8:1:2::1"), web.client_key("2001:db8:1:2:abcd::9"))
        self.assertEqual(web.client_key("2001:db8:1:2::1"), "2001:db8:1:2::/64")
        self.assertNotEqual(web.client_key("2001:db8:1:2::1"), web.client_key("2001:db8:1:3::1"))
        self.assertEqual(web.client_key("fe80::1%eth0"), "fe80::/64")

    def test_listens_v4_and_v6(self):
        """Один сокет на «все адреса» принимает IPv4 и IPv6; без IPv6 в ядре — только IPv4."""
        app = web.App()

        @app.get("/ping")
        def ping(req):
            return {"ip": req.client_ip}

        srv = app.serve("0.0.0.0", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]

            def get(host):
                c = http.client.HTTPConnection(host, port, timeout=5)
                c.request("GET", "/ping")
                r = c.getresponse()
                return json.loads(r.read())["ip"]
            self.assertEqual(get("127.0.0.1"), "127.0.0.1")
            if srv.address_family == socket.AF_INET6:
                self.assertEqual(get("::1"), "::/64")
            else:
                with self.assertRaises(OSError):
                    socket.socket(socket.AF_INET6)         # уходит на IPv4 только без IPv6 в ядре
        finally:
            srv.shutdown()
            srv.server_close()


class LePathsTest(unittest.TestCase):
    """lego меняет «:» в имени файла на «-»: сертификат на IPv6 ищется по имени внутри него."""

    def test_sanitized_file_found(self):
        d = os.path.join(tlsmgr.ACME_DIR, "certificates")
        os.makedirs(d, exist_ok=True)
        cert, key = os.path.join(d, "2001-db8--5.crt"), os.path.join(d, "2001-db8--5.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "30", "-subj", "/CN=test", "-addext", "subjectAltName=IP:2001:db8::5",
                        "-keyout", key, "-out", cert], capture_output=True, check=True)
        tlsconf.update(domain="")
        try:
            self.assertEqual(tlsmgr.TLSManager(lambda: "2001:db8::5")._le_paths(), (cert, key))
            # обычное имя (IPv4, домен) — как раньше, без перебора папки
            self.assertEqual(tlsmgr.TLSManager(lambda: "203.0.113.5")._le_paths(),
                             (os.path.join(d, "203.0.113.5.crt"), os.path.join(d, "203.0.113.5.key")))
        finally:
            for p in (cert, key):
                os.remove(p)


class TwoAddressCertTest(unittest.TestCase):
    """Сертификат панели на оба адреса сервера (IPv4 и IPv6), чтобы она открывалась без предупреждения по
    любому; Let's Encrypt не проверил второй — сертификат на основной, повтор не раньше ALT_RETRY."""

    def setUp(self):
        self.d = os.path.join(tlsmgr.ACME_DIR, "certificates")
        os.makedirs(self.d, exist_ok=True)
        tlsconf.update(domain="", web=None)
        self.runs, self.fail = [], set()
        real = subprocess.run

        def fake(cmd, **kw):
            if cmd[:2] != ["lego", "run"]:
                return real(cmd, **kw)
            names = [cmd[i + 1] for i, x in enumerate(cmd) if x == "-d"]
            self.runs.append((names, "--renew-force" in cmd))
            if tuple(names) in self.fail:
                return subprocess.CompletedProcess(cmd, 1, "", "acme: error: 403 :: urn:ietf:params:acme:error:connection")
            base = os.path.join(self.d, names[0].replace(":", "-"))
            san = ",".join(f"IP:{n}" for n in names)
            real(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                  "-days", "6", "-subj", "/CN=x", "-addext", f"subjectAltName={san}", "-keyout", base + ".key",
                  "-out", base + ".crt"], capture_output=True, check=True)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        self.patches = [mock.patch.object(tlsmgr.subprocess, "run", side_effect=fake),
                        mock.patch.object(config, "DRY_RUN", False),
                        mock.patch.object(webfront, "listeners", return_value=[])]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        for n in os.listdir(self.d):
            os.remove(os.path.join(self.d, n))

    def mgr(self, host, alt):
        m = tlsmgr.TLSManager(lambda: host, lambda: alt)
        m.mode = "letsencrypt"
        return m

    def test_names(self):
        self.assertEqual(self.mgr("203.0.113.5", ["2001:db8::5"]).names(), ["203.0.113.5", "2001:db8::5"])
        self.assertEqual(self.mgr("2001:db8::5", ["203.0.113.5"]).names(), ["2001:db8::5", "203.0.113.5"])
        self.assertEqual(self.mgr("203.0.113.5", ["198.51.100.1"]).names(), ["203.0.113.5"])   # то же семейство
        self.assertEqual(self.mgr("203.0.113.5", []).names(), ["203.0.113.5"])
        self.assertEqual(self.mgr("vpn.example.com", ["2001:db8::5"]).names(), ["vpn.example.com"])
        tlsconf.update(domain="panel.example.com")
        self.assertEqual(self.mgr("203.0.113.5", ["2001:db8::5"]).names(), ["panel.example.com"])

    def test_both_addresses(self):
        m = self.mgr("2001:db8::5", ["203.0.113.5"])
        self.assertTrue(m._lego())
        self.assertEqual(self.runs, [(["2001:db8::5", "203.0.113.5"], False)])
        cert = m._le_paths()[0]
        self.assertTrue(tlsmgr._san_matches(cert, "203.0.113.5") and tlsmgr._san_matches(cert, "2001:db8::5"))

    def test_second_address_refused_falls_back(self):
        self.fail = {("203.0.113.5", "2001:db8::5")}
        m = self.mgr("203.0.113.5", ["2001:db8::5"])
        self.assertTrue(m._lego())
        self.assertEqual([r[0] for r in self.runs], [["203.0.113.5", "2001:db8::5"], ["203.0.113.5"]])
        self.assertEqual(m._want(), ["203.0.113.5"])           # до ALT_RETRY второй адрес не просим
        with mock.patch.object(tlsmgr.time, "time", return_value=time.time() + tlsmgr.ALT_RETRY + 1):
            self.assertEqual(m._want(), ["203.0.113.5", "2001:db8::5"])

    def test_add_second_to_valid_cert(self):
        """Действующий сертификат на один адрес: дополняется вторым (--renew-force), а при отказе остаётся."""
        m = self.mgr("203.0.113.5", [])
        m._apply()
        self.assertEqual(self.runs, [(["203.0.113.5"], False)])
        m._get_alt = lambda: ["2001:db8::5"]
        self.fail = {("203.0.113.5", "2001:db8::5")}
        m._apply()
        self.assertEqual(self.runs[1:], [(["203.0.113.5", "2001:db8::5"], True)])   # лишнего на один нет
        self.assertEqual((m.active, m.error), ("letsencrypt", None))
        self.fail, m._alt_failed = set(), {}
        m._apply()
        self.assertEqual(self.runs[-1], (["203.0.113.5", "2001:db8::5"], True))
        self.assertTrue(tlsmgr._san_matches(m._le_paths()[0], "2001:db8::5"))

    def test_web_server_only_main_address(self):
        tlsconf.update(web={"kind": "manual", "host": "203.0.113.5", "webroot": "/var/lib/awg-router/acme"})
        with mock.patch.object(config, "HOST_ROOT", ""):
            self.assertTrue(self.mgr("203.0.113.5", ["2001:db8::5"])._lego())
        self.assertEqual([r[0] for r in self.runs], [["203.0.113.5"]])

    def test_selfsigned_both(self):
        m = self.mgr("2001:db8::7", ["203.0.113.7"])
        m._selfsigned()
        cert = os.path.join(tlsmgr.TLS_DIR, "self.crt")
        self.assertTrue(tlsmgr._san_matches(cert, "2001:db8::7") and tlsmgr._san_matches(cert, "203.0.113.7"))

    def test_main_alt(self):
        """Второй адрес — только если IPv6 в ходу: в «Внешнем адресе» или в «Адрес в конфигах»."""
        st = main.store.snapshot()["settings"]
        def with_settings(**kw):
            main.store.mutate(lambda s: s["settings"].update(kw))
            return main._tls_alt()
        try:
            with mock.patch.object(config, "PUBLIC_HOST", "203.0.113.5"):
                self.assertEqual(with_settings(public_host="2001:db8::5", client_host=""), ["203.0.113.5"])
                self.assertEqual(with_settings(public_host="203.0.113.5", client_host="2001:db8::9"), ["2001:db8::9"])
                self.assertEqual(with_settings(public_host="203.0.113.5", client_host=""), [])
                self.assertEqual(with_settings(public_host="vpn.example.com", client_host="2001:db8::9"), [])
        finally:
            main.store.mutate(lambda s: s["settings"].update({k: st.get(k, "") for k in ("public_host", "client_host")}))


class SysMonTest(unittest.TestCase):
    """Процессор и память сервера в шапке: загрузка между двумя чтениями /proc/stat."""

    def stat(self, user, idle):
        with open(self.path, "w") as f:
            f.write(f"cpu  {user} 0 0 {idle} 0 0 0 0 0 0\ncpu0 1 2 3 4 5 6 7 8\n")

    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "stat")

    def test_percent_between_reads(self):
        from app import hostnet
        self.stat(100, 900)
        m = hostnet.CpuMeter(self.path)
        m.MIN_GAP = 0
        self.stat(130, 970)                  # +30 работы, +70 простоя → 30 %
        self.assertEqual(m.percent(), 30.0)
        m.MIN_GAP = 3600
        self.stat(200, 970)
        self.assertEqual(m.percent(), 30.0)  # чаще MIN_GAP не пересчитывает
        m.MIN_GAP = 0
        self.assertEqual(m.percent(), 100.0)
        self.assertEqual(m.percent(), 100.0)  # тиков не прибавилось — прежнее значение

    def test_unreadable(self):
        from app import hostnet
        m = hostnet.CpuMeter(self.path + "-none")
        self.assertIsNone(m.percent())

    def test_in_state(self):
        main.engine.reconcile()            # демо-сервер AWG как цель
        st = main.get_state(None)
        self.assertEqual(sorted(st["system"]), ["cores", "cpu", "load", "mem"])
        self.assertLess(len(json.dumps(st["system"])), 120)      # /api/state опрашивается часто


class ServerWatchTest(unittest.TestCase):
    """Интерфейс сервера пропал (OOM завершил amneziawg-go), а контейнер работает: панель перезапускает сервер
    сама — контейнер после SERVER_GRACE, дальше с паузами SERVER_PAUSES; кнопка — сразу."""

    def setUp(self):
        self.e = main.engine
        self.ev = []
        self.now = [1_000_000.0]
        self.patches = [mock.patch.object(self.e, "event", side_effect=lambda lvl, m: self.ev.append(m.key)),
                        mock.patch.object(config, "DRY_RUN", False),
                        mock.patch.object(engine.time, "time", side_effect=lambda: self.now[0])]
        for p in self.patches:
            p.start()
        self.e._srv_down, self.e._srv_tries, self.e._srv_next = None, 0, 0.0

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.e._srv_down, self.e._srv_tries, self.e._srv_next = None, 0, 0.0

    def target(self, kind, up):
        t = mock.Mock(kind=kind, iface="awg0", exists=True)
        t.is_up = lambda: up[0]
        return t

    def test_container_restarts_after_grace_with_pauses(self):
        up = [False]
        t = self.target("container", up)
        self.e._watch_server(t)
        self.now[0] += engine.SERVER_GRACE - 1
        self.e._watch_server(t)
        t.restart.assert_not_called()                     # интерфейс мог пропасть ненадолго (смена порта)
        self.now[0] += 2
        self.e._watch_server(t)
        self.assertEqual(t.restart.call_count, 1)
        self.assertEqual(self.ev, ["ev.server_iface_gone"])
        self.now[0] += engine.SERVER_PAUSES[0] - 1
        self.e._watch_server(t)
        self.assertEqual(t.restart.call_count, 1)         # не чаще паузы
        self.now[0] += 2
        self.e._watch_server(t)
        self.assertEqual(t.restart.call_count, 2)
        up[0] = True
        self.e._watch_server(t)                          # поднялся — счёт сначала
        self.assertEqual((self.e._srv_down, self.e._srv_tries), (None, 0))

    def test_host_restarts_at_once(self):
        t = self.target("host", [False])
        self.e._watch_server(t)
        self.assertEqual(t.restart.call_count, 1)
        self.assertEqual(t.native.call_args[0][0][:2], ["systemctl", "enable"])

    def test_restart_failure_is_reported(self):
        t = self.target("container", [False])
        t.restart.side_effect = system.SysError("docker: no such container")
        self.e._watch_server(t)
        self.now[0] += engine.SERVER_GRACE + 1
        self.e._watch_server(t)
        self.assertEqual(self.ev, ["ev.server_iface_gone", "ev.server_start_failed"])

    def test_button(self):
        t = self.target("container", [True])
        with mock.patch.object(self.e, "target", t):
            self.assertEqual(main.restart_server(None), {"ok": True})
        t.restart.assert_called_once()
        with mock.patch.object(self.e, "target", None):
            with self.assertRaises(web.HTTPError):
                main.restart_server(None)


class ResourceAlertTest(unittest.TestCase):
    """Память или процессор выше порога RES_ALERT_SECS — одно событие, ниже MEM_OK / CPU_OK — второе."""

    def setUp(self):
        self.e = main.engine
        self.ev, self.now, self.mem, self.cpu = [], [2_000_000.0], [50], [10.0]
        self.patches = [
            mock.patch.object(self.e, "event", side_effect=lambda lvl, m: self.ev.append((m.key, m.p))),
            mock.patch.object(config, "DRY_RUN", False),
            mock.patch.object(engine.time, "time", side_effect=lambda: self.now[0]),
            mock.patch.object(engine.hostnet, "memory", side_effect=lambda: (self.mem[0] * 2**20, 100 * 2**20)),
            mock.patch.object(engine.hostnet.cpu, "percent", side_effect=lambda: self.cpu[0])]
        for p in self.patches:
            p.start()
        self.e._res = {}

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.e._res = {}

    def step(self, secs, mem=None, cpu=None):
        self.now[0] += secs
        if mem is not None:
            self.mem[0] = mem
        if cpu is not None:
            self.cpu[0] = cpu
        self.e._watch_resources()

    def test_memory(self):
        self.step(0, mem=93)
        self.step(engine.RES_ALERT_SECS - 10)
        self.assertEqual(self.ev, [])                     # короткий всплеск — не тревога
        self.step(20)
        self.assertEqual(self.ev, [("ev.mem_high", {"pct": 93, "min": engine.RES_ALERT_SECS // 60})])
        self.step(600)
        self.assertEqual(len(self.ev), 1)                 # одно сообщение, а не каждую минуту
        self.step(10, mem=88)                             # между порогами — ещё не норма
        self.assertEqual(len(self.ev), 1)
        self.step(10, mem=60)
        self.assertEqual(self.ev[-1], ("ev.mem_ok", {"pct": 60}))

    def test_cpu(self):
        self.step(0, cpu=99.0)
        self.step(engine.RES_ALERT_SECS + 1)
        self.step(5, cpu=20.0)
        self.assertEqual([k for k, _ in self.ev], ["ev.cpu_high", "ev.cpu_ok"])

    def test_telegram_kind(self):
        from app import notify
        self.assertIn("system", notify.KINDS)
        self.assertEqual(notify.ENGINE_EVENTS["ev.mem_high"], ("system", "mem_high"))
        self.assertEqual(notify.ENGINE_EVENTS["ev.server_iface_gone"], ("server", "server_iface_gone"))
        n = notify.Notifier.__new__(notify.Notifier)
        n._target_lost = False
        got = []
        n.event = lambda kind, key, refs=None, **p: got.append((kind, key, p))
        n.engine_event(engine.Msg("ev.mem_high", pct=93, min=5))
        self.assertEqual(got, [("system", "mem_high", {"pct": 93, "min": 5})])
        self.assertIn("93%", notify.render("ru", "mem_high", **got[0][2]))


class KernelInstallTest(unittest.TestCase):
    """awg-router install-kernel: настоящий кусок install.sh с поддельными apt-get, modprobe и прочими."""

    def setUp(self):
        root = os.path.join(os.path.dirname(__file__), "..")
        with open(os.path.join(root, "install.sh")) as f:
            sh = f.read()
        self.part = sh[sh.index('AWG_SYS="${AWGR_SYS:-/sys}"'):sh.index('if [ "$INFO_ONLY" = 1 ]')]
        self.tmp = tempfile.mkdtemp()
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        self.sys = os.path.join(self.tmp, "sys")
        self.log = os.path.join(self.tmp, "calls")
        stubs = {
            "systemd-detect-virt": 'echo "${VIRT:-none}"',
            "uname": 'case "$1" in -m) echo "${ARCH:-x86_64}";; -r) echo 6.8.0-45-generic;; *) echo Linux;; esac',
            "apt-get": 'echo "apt-get $*" >> "$LOG"',
            "apt-cache": 'exit 0',
            "add-apt-repository": 'echo "add-apt-repository $*" >> "$LOG"',
            "modprobe": 'echo "modprobe $*" >> "$LOG"; mkdir -p "$AWGR_SYS/module/amneziawg"; '
                        'echo "$NEWVER" > "$AWGR_SYS/module/amneziawg/version"',
            "rmmod": 'echo "rmmod $*" >> "$LOG"; rm -rf "$AWGR_SYS/module/amneziawg"',
            "modinfo": 'echo "${FILEVER:-$NEWVER}"',
        }
        for name, body in stubs.items():
            path = os.path.join(self.bin, name)
            with open(path, "w") as f:
                f.write("#!/bin/bash\n" + body + "\n")
            os.chmod(path, 0o755)

    def run_sh(self, os_id="ubuntu", ver="24.04", loaded=None, newver="3.1.20260812", virt="none", yes="y", **env):
        osr = os.path.join(self.tmp, "os-release")
        with open(osr, "w") as f:
            f.write(f'ID={os_id}\nVERSION_ID="{ver}"\n')
        if loaded:
            os.makedirs(os.path.join(self.sys, "module", "amneziawg"), exist_ok=True)
            with open(os.path.join(self.sys, "module", "amneziawg", "version"), "w") as f:
                f.write(loaded + "\n")
        script = ("set -uo pipefail\nstep() { echo \"STEP $1\"; }; ok() { echo \"OK $1\"; }; warn() { echo \"WARN $1\"; }\n"
                  "die() { echo \"DIE $1\"; exit 1; }\nask() { REPLY=\"$2\"; }\n" + self.part + "\ninstall_kernel\n")
        e = {"PATH": self.bin + ":/usr/bin:/bin", "AWGR_SYS": self.sys, "AWGR_OS_RELEASE": osr, "LOG": self.log,
             "NEWVER": newver, "VIRT": virt, "AWGR_YES": yes, **env}
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e, timeout=30)
        calls = open(self.log).read() if os.path.exists(self.log) else ""
        return p.returncode, p.stdout, calls

    def test_already_new_enough(self):
        rc, out, calls = self.run_sh(loaded="3.1.20260812")
        self.assertEqual(rc, 0)
        self.assertIn("OK Already loaded: version 3.1.20260812", out)
        self.assertEqual(calls, "")

    def test_ubuntu_installs_module_only(self):
        rc, out, calls = self.run_sh()
        self.assertEqual(rc, 0, out)
        self.assertIn("add-apt-repository -y ppa:amnezia/ppa", calls)
        self.assertIn("apt-get install -y -qq amneziawg-dkms", calls)      # без amneziawg-tools
        self.assertIn("OK Kernel module loaded: version 3.1.20260812", out)

    def test_old_module_from_ppa_is_removed(self):
        rc, out, calls = self.run_sh(newver="1.0.20251009")
        self.assertEqual(rc, 1)
        self.assertIn("apt-get remove -y -qq amneziawg-dkms", calls)
        self.assertIn("doesn't speak AWG 3.1", out)

    def test_old_loaded_new_installed_asks_reboot(self):
        # старый модуль занят сервером и не выгружается: установлен новый — нужна перезагрузка
        with open(os.path.join(self.bin, "rmmod"), "w") as f:
            f.write("#!/bin/bash\necho \"rmmod $*\" >> \"$LOG\"; exit 1\n")
        with open(os.path.join(self.bin, "modprobe"), "w") as f:
            f.write("#!/bin/bash\necho \"modprobe $*\" >> \"$LOG\"\n")
        rc, out, calls = self.run_sh(loaded="1.0.20251009", FILEVER="3.1.20260812")
        self.assertEqual(rc, 0, out)
        self.assertIn("reboot the server", out)
        self.assertNotIn("apt-get remove", calls)

    def test_build_failure_changes_nothing(self):
        """Модуль не собрался под ядро (так было с PPA на ядре 7.0): пакет убран, панель на amneziawg-go."""
        with open(os.path.join(self.bin, "apt-get"), "w") as f:
            f.write('#!/bin/bash\necho "apt-get $*" >> "$LOG"\n[[ "$*" == *"install -y -qq amneziawg-dkms"* ]] && exit 100\nexit 0\n')
        rc, out, calls = self.run_sh()
        self.assertEqual(rc, 1)
        self.assertIn("did not build for kernel 6.8.0-45-generic", out)
        self.assertIn("apt-get remove -y -qq amneziawg-dkms", calls)
        self.assertNotIn("modprobe", calls)

    def test_refusals(self):
        for kw, text in (({"virt": "lxc"}, "is a container (lxc)"),
                         ({"os_id": "debian", "ver": "11"}, "Debian 12 or newer"),
                         ({"os_id": "fedora", "ver": "40"}, "Only Ubuntu and Debian"),
                         ({"ARCH": "armv7l"}, "Only x86_64 and aarch64"),
                         ({"yes": "n"}, "Cancelled")):
            if os.path.exists(self.log):
                os.remove(self.log)
            rc, out, calls = self.run_sh(**kw)
            self.assertEqual(rc, 1, kw)
            self.assertIn(text, out, kw)
            self.assertEqual(calls, "", kw)                  # ничего не поставлено

    def test_helper_command(self):
        root = os.path.join(os.path.dirname(__file__), "..")
        with open(os.path.join(root, "install.sh")) as f:
            sh = f.read()
        self.assertIn('install-kernel) bash "\\$DIR/install.sh" --install-kernel ;;', sh)
        self.assertIn("--install-kernel) KERNEL_ONLY=1 ;;", sh)


class ExitEngineTest(unittest.TestCase):
    """Туннели к выходам: модуль ядра — только по выбору и с модулем 3.x; отказ ядра — сразу amneziawg-go."""

    def setUp(self):
        self.e = main.engine
        self.e.kernel_fallback = None

    def tearDown(self):
        self.e.kernel_fallback = None
        main.store.mutate(lambda st: st["settings"].pop("exit_engine", None))

    def test_choice_needs_module(self):
        self.assertEqual(self.e.exit_engine(), "go")                    # по умолчанию
        with mock.patch.object(self.e, "module_info", return_value={"loaded": True, "version": "1.0.2025", "ok": False}):
            with self.assertRaises(system.SysError) as cm:
                self.e.set_exit_engine("kernel")
            self.assertEqual(cm.exception.msg.key, "eng.no_module")
        self.e.set_exit_engine("kernel")                                 # демо: модуль 3.1 «загружен»
        self.assertEqual(self.e.exit_engine(), "kernel")
        with mock.patch.object(self.e, "module_info", return_value={"loaded": False, "version": None, "ok": False}):
            self.assertEqual(self.e.exit_engine(), "go")                # модуль пропал — amneziawg-go
        self.e.kernel_fallback = {"error": "x", "at": 0}
        self.assertEqual(self.e.exit_engine(), "go")                    # отказ ядра — до нового выбора
        self.e.set_exit_engine("kernel")
        self.assertIsNone(self.e.kernel_fallback)

    def test_kernel_failure_falls_back_to_go(self):
        from app import awgconf
        e = engine.Engine.__new__(engine.Engine)
        e.rt, e.kernel_fallback, events = {}, None, []
        e.event = lambda lvl, m: events.append(m.key)
        e.exit_engine = lambda st=None: "kernel" if not e.kernel_fallback else "go"
        calls = []

        def ns(cmd, **kw):
            calls.append(cmd)
            if cmd[:3] == ["ip", "link", "add"]:
                raise system.SysError("RTNETLINK answers: Operation not supported")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        t = mock.Mock(pid=1, key="k")
        t.ns = ns
        from test_v115 import conf
        pc = awgconf.parse_upstream(conf("203.0.113.7:51820"))
        # без настоящих /var/run/amneziawg и журналов: тесты в CI идут не от root
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(engine.subprocess, "Popen") as po, \
                mock.patch.object(engine.os.path, "exists", return_value=True), \
                mock.patch.object(engine.os, "makedirs"), mock.patch.object(engine.os, "remove"), \
                mock.patch("builtins.open", mock.mock_open()), \
                mock.patch.object(engine.Engine, "_setconf"):
            po.return_value.poll.return_value = None
            e._start_up(t, "u1", {"num": 3, "name": "X"}, pc, "h")
        self.assertEqual(e.rt["u1"].engine, "go")
        self.assertIn("ev.kernel_fallback", events)
        self.assertIn(["ip", "link", "del", "awgr3"], calls)            # недосозданный интерфейс убран
        self.assertIn("amneziawg-go", po.call_args[0][0])

    def test_server_engine_and_old_module(self):
        e = engine.Engine.__new__(engine.Engine)
        e.server_engine, e._srv_engine_at, e.module_warn, e._module_warned = None, ("", 0.0), None, None
        events = []
        e.event = lambda lvl, m: events.append((m.key, m.p))
        out = {"kernel": "5: awg0: <POINTOPOINT,NOARP,UP> mtu 1376\n    link/none promiscuity 0\n    amneziawg \n",
               "go": "5: awg0: <POINTOPOINT> mtu 1376\n    link/none\n    tun type tun pi off vnet_hdr off\n"}
        for want, text in out.items():
            t = mock.Mock(key=want, iface="awg0", conf_path="/c")
            t.ns = lambda cmd, text=text, **kw: subprocess.CompletedProcess(cmd, 0, text, "")
            t.read_file = lambda p: "[Interface]\nHeaderProtectionKey = x\n"
            info = {"loaded": True, "version": "1.0.20251009", "ok": False}
            with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(e, "module_info", return_value=info, create=True):
                e._watch_engine(t)
            self.assertEqual(e.server_engine, want)
        self.assertEqual(e.module_warn, "1.0.20251009")
        self.assertEqual(len(events), 2)                                 # по одному на каждый Target.key
        self.assertEqual(events[0], ("ev.kernel_old", {"version": "1.0.20251009", "min": engine.KERNEL_MIN}))

    def test_state_and_api(self):
        main.engine.reconcile()
        st = main.get_state(None)
        self.assertEqual(sorted(st["awg_engine"]), ["exits", "exits_now", "fallback", "min", "module", "old", "server"])
        self.assertEqual(main.set_engine(type("R", (), {"json": lambda self: {"exits": "kernel"}})()), {"ok": True})
        self.assertEqual(main.store.snapshot()["settings"]["exit_engine"], "kernel")
        with self.assertRaises(web.HTTPError):
            main.set_engine(type("R", (), {"json": lambda self: {"exits": "nope"}})())
        from test_api import good_state
        g = good_state()
        g.setdefault("settings", {})["exit_engine"] = "kernel"
        self.assertEqual(main.clean_backup_state(g)["settings"]["exit_engine"], "kernel")


class ReviewFixesTest(unittest.TestCase):
    """Замечания проверки 1.20.0: отказ модуля и отказ конфига различаются; после перезапуска сервера проход
    не трогает старую цель; восстановление не берёт адрес старого сервера; Infinity и глубокий JSON — 400."""

    def start_up(self, setconf_fails):
        """_start_up на модуле ядра: setconf_fails — сколько первых вызовов awg setconf падает."""
        from app import awgconf
        from test_v115 import conf
        e = engine.Engine.__new__(engine.Engine)
        e.rt, e.kernel_fallback, events = {}, None, []
        e.event = lambda lvl, m: events.append(m.key)
        e.exit_engine = lambda st=None: "kernel" if not e.kernel_fallback else "go"
        n = [0]

        def setconf(*a):
            n[0] += 1
            if n[0] <= setconf_fails:
                raise system.SysError("Invalid argument")
        t = mock.Mock(pid=1, key="k")
        t.ns.return_value = subprocess.CompletedProcess([], 0, "", "")
        pc = awgconf.parse_upstream(conf("203.0.113.7:51820"))
        err = None
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(engine.subprocess, "Popen") as po, \
                mock.patch.object(engine.os.path, "exists", return_value=True), \
                mock.patch.object(engine.os, "makedirs"), mock.patch.object(engine.os, "remove"), \
                mock.patch("builtins.open", mock.mock_open()), \
                mock.patch.object(engine.Engine, "_setconf", side_effect=setconf):
            po.return_value.poll.return_value = None
            try:
                e._start_up(t, "u1", {"num": 3, "name": "X"}, pc, "h")
            except system.SysError as ex:
                err = ex
        return e, events, err

    def test_bad_config_does_not_blame_module(self):
        e, events, err = self.start_up(setconf_fails=2)        # не принял ни модуль, ни amneziawg-go
        self.assertIsNotNone(err)
        self.assertNotIn("ev.kernel_fallback", events)
        self.assertIsNone(e.kernel_fallback)                    # остальные выходы остаются на модуле

    def test_module_rejects_what_go_accepts(self):
        e, events, err = self.start_up(setconf_fails=1)
        self.assertIsNone(err)
        self.assertEqual(e.rt["u1"].engine, "go")
        self.assertIn("ev.kernel_fallback", events)

    def test_pass_stops_after_server_restart(self):
        e = main.engine
        t = mock.Mock(kind="host", iface="awg0", exists=True)
        t.is_up = lambda: False
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(e, "event"), \
                mock.patch.object(engine.system, "discover", return_value=t), \
                mock.patch.object(e, "_watch_resources"), mock.patch.object(e, "_watch_engine") as we:
            e._srv_down, e._srv_tries, e._srv_next = None, 0, 0.0
            try:
                self.assertTrue(e._watch_server(t))              # перезапуск — True
                self.assertFalse(e._watch_server(t))             # пауза — False
                e._srv_down, e._srv_tries, e._srv_next = None, 0, 0.0
                e.applied_hash = "old"
                e.reconcile()
            finally:
                e._srv_down, e._srv_tries, e._srv_next = None, 0, 0.0
        we.assert_not_called()                                   # дальше проход не пошёл
        self.assertIsNone(e.applied_hash)
        self.assertEqual(t.restart.call_count, 2)

    def restore(self, local):
        from test_api import good_state
        g = good_state()
        g["settings"].update(public_host="198.51.100.1", client_host="198.51.100.2")
        main.store.mutate(lambda st: st["settings"].update(local) or
                          [st["settings"].pop(k, None) for k in ("public_host", "client_host") if k not in local])
        b = {"format": main.BACKUP_FORMAT, "state": g}
        main.restore_backup(type("R", (), {"json": lambda self: {"backup": b}})())
        return main.store.snapshot()["settings"]

    def test_restore_ignores_old_server_address(self):
        st0 = main.store.snapshot()
        try:
            s = self.restore({})                                 # свой адрес — PUBLIC_HOST из .env
            self.assertNotIn("public_host", s)
            self.assertNotIn("client_host", s)
            s = self.restore({"public_host": "203.0.113.9"})
            self.assertEqual(s.get("public_host"), "203.0.113.9")
            self.assertNotIn("client_host", s)
        finally:
            main.store.mutate(lambda st: (st.clear(), st.update(st0)))

    def test_non_finite_and_deep_json_are_400(self):
        def req(raw):
            h = mock.Mock(rfile=io.BytesIO(raw))
            r = web.Request.__new__(web.Request)
            r.h, r.headers, r._body = h, {"Content-Length": str(len(raw))}, None
            return r
        for raw in (b'{"list_update_hours": Infinity}', b'{"x": NaN}', b'{"a":' * 100000 + b'1' + b'}' * 100000):
            with self.assertRaises(web.HTTPError) as cm:
                req(raw).json()
            self.assertEqual(cm.exception.code, 400)
        self.assertFalse(main._num(float("inf")))
        self.assertTrue(main._num(2.5))

    def test_tls_loop_survives_error(self):
        from app import tlsmgr
        m = tlsmgr.TLSManager.__new__(tlsmgr.TLSManager)
        m.stop_ev, m._wake, m.error, m.busy = threading.Event(), mock.Mock(), None, True
        m._wake.wait.side_effect = [True, True]
        calls = []

        def step(woke):
            calls.append(woke)
            if len(calls) == 1:
                raise OSError("disk full")
            m.stop_ev.set()
        m._step = step
        m._wait = lambda: 1
        m._loop()
        self.assertEqual(len(calls), 2)                          # поток жив после ошибки
        self.assertIn("disk full", m.error)

    def test_selfsigned_reissued_when_second_address_changes(self):
        """Режим без Let's Encrypt: поменялся только второй адрес — самоподписанный выпускается заново."""
        alt = ["203.0.113.7"]
        m = tlsmgr.TLSManager(lambda: "2001:db8::7", lambda: alt)
        m.mode = "selfsigned"
        cert = os.path.join(tlsmgr.TLS_DIR, "self.crt")
        with mock.patch.object(config, "DRY_RUN", False):
            m._apply()
            self.assertTrue(tlsmgr._san_matches(cert, "203.0.113.7"))
            alt[0] = "203.0.113.8"
            m._apply()
        self.assertTrue(tlsmgr._san_matches(cert, "203.0.113.8"))
    def test_fallback_loop_rejected(self):
        R = lambda b: type("R", (), {"json": lambda self: b})()
        st0 = main.store.snapshot()
        try:
            a = main.add_upstream(R({"name": "A", "config": "socks5://198.51.100.21:1080"}))["id"]
            b = main.add_upstream(R({"name": "B", "config": "socks5://198.51.100.22:1080", "fallback": "up:" + a}))["id"]
            c = main.add_upstream(R({"name": "C", "config": "socks5://198.51.100.23:1080", "fallback": "up:" + b}))["id"]
            with self.assertRaises(web.HTTPError) as cm:
                main.edit_upstream(R({"fallback": "up:" + c}), a)          # A → C → B → A
            self.assertEqual(cm.exception.detail.key, "err.fallback_loop")
            main.edit_upstream(R({"fallback": "direct"}), b)
            main.edit_upstream(R({"fallback": "up:" + c}), a)              # цепочка без круга — можно
        finally:
            main.store.mutate(lambda st: (st.clear(), st.update(st0)))

if __name__ == "__main__":
    unittest.main()
