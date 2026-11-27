"""1.25.0, исправления полной проверки (П1–П71): каждый тест падает без своего исправления.
python3 -m unittest tests.test_v125_fix"""
import asyncio
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from app import sniproxy  # noqa: E402

A = "198.51.100.7"


def _sni_conf(d: str, cfg: dict, lists: dict[str, str] | None = None, cidrs: dict[str, str] | None = None) -> str:
    """sni.json для настоящего Sniffer(путь): списки — файлами рядом."""
    out = dict(cfg)
    for key, src in (("lists", lists or {}), ("cidrs", cidrs or {})):
        files = {}
        for lid, text in src.items():
            fp = os.path.join(d, f"{key}-{lid}.txt")
            with open(fp, "w") as f:
                f.write(text)
            files[lid] = fp
        out[key] = files
    p = os.path.join(d, "sni.json")
    with open(p, "w") as f:
        json.dump(out, f)
    return p


class Sock:
    def __init__(self):
        self.shut = False

    def shutdown(self, how):
        self.shut = True


class SniDropRealTest(unittest.TestCase):
    """П1: ручная смена пути закрывает соединения посредника в настоящем Sniffer(путь), а не только в обходе __init__
    (атрибут self.path — путь к sni.json — закрывал метод с тем же именем: TypeError, соединения жили на старом пути)."""

    def test_drop_on_a_real_sniffer(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        base = {"listen": "127.0.0.1", "clients": "10.8.1.0/24",
                "policies": {"p_global": {"mark": 1, "rules": []}}}
        p = _sni_conf(d, base, cidrs={"ru": "77.88.0.0/18\n"})
        s = sniproxy.Sniffer(p)
        socks = {k: (Sock(), Sock()) for k in ("ru", "other")}
        s.live = {1: ("10.8.1.2", None, "77.88.55.242", *socks["ru"]),
                  2: ("10.8.1.2", None, "8.8.8.8", *socks["other"])}
        drop = {"gen": 7, "clients": {"10.8.1.2": {
            "old": {"rules": [[["ru"], "direct@system"]], "drules": [], "default": "up:u1"},
            "new": {"rules": [[["ru"], "up:u2"]], "drules": [], "default": "up:u1"}}}}
        _sni_conf(d, {**base, "drop": drop}, cidrs={"ru": "77.88.0.0/18\n"})
        s.apply(sniproxy.load(p, s.files))
        self.assertTrue(socks["ru"][0].shut and socks["ru"][1].shut)
        self.assertFalse(socks["other"][0].shut)

    def test_reload_survives_a_failed_apply(self):
        """Сбой применения настроек не обрывает перечитывание: следующий SIGHUP снова читает файл."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = _sni_conf(d, {"listen": "127.0.0.1"})
        s = sniproxy.Sniffer(p)
        calls = []

        def apply(conf):
            calls.append(1)
            raise TypeError("boom")

        async def run():
            s.apply = apply
            s.hup_pending = True
            with mock.patch.object(sniproxy, "log"):
                await s.reload_async()
            s.on_hup()
            await s.reload_task
        asyncio.run(run())
        self.assertEqual(len(calls), 2)


class SniNamesTest(unittest.TestCase):
    """П21, П70: имя есть, но не прочитано — не «имени нет» (иначе сайт из списка шёл по правилам адресов)."""

    def test_long_headers_with_host_first(self):
        req = b"GET / HTTP/1.1\r\nHost: Example.com\r\nCookie: " + b"a" * (17 * 1024)
        self.assertEqual(sniproxy.http_host(req), "example.com")

    def test_long_headers_without_host_close(self):
        req = b"GET / HTTP/1.1\r\nCookie: " + b"a" * (17 * 1024) + b"\r\nX: y"
        self.assertIs(sniproxy.http_host(req), False)

    def test_long_line_that_is_not_http(self):
        self.assertIsNone(sniproxy.http_host(b"\x00\x01 x\r\n" + b"z" * (17 * 1024)))

    def test_short_first_chunk_on_443(self):
        self.assertIs(sniproxy.name_of(b"GE", 443), False)
        self.assertIsNone(sniproxy.name_of(b"\x05\x01", 443))
        self.assertEqual(sniproxy.name_of(b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n", 443), "a.com")

    def test_zero_length_tls_record(self):
        self.assertIsNone(sniproxy.tls_sni(b"\x16\x03\x01\x00\x00" * 100))


class SniQuicUnknownClientTest(unittest.TestCase):
    """П70 (дубль decide_rule и quic_mark разошёлся): QUIC клиента, которого нет в настройках, — блок, как TCP."""

    def test_unknown_client_is_blocked(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = _sni_conf(d, {"listen": "127.0.0.1", "quic": {"block": 0xB10C, "pass": 0xE100},
                          "client_policy": {"10.8.1.2": "p_1"},
                          "policies": {"p_1": {"mark": 2, "rules": [{"lists": ["yt"], "qmark": 0x2001,
                                                                       "to": {"mark": 0x2001}}]}}},
                      lists={"yt": "youtube.com\n"})
        s = sniproxy.Sniffer(p)
        self.assertEqual(s.quic_mark("10.8.1.9", "youtube.com"), 0xB10C)
        self.assertEqual(s.decide_rule("10.8.1.9", "youtube.com")[0], {"block": True})
        self.assertEqual(s.quic_mark("10.8.1.2", "www.youtube.com"), 0x2001)
        self.assertEqual(s.quic_mark("10.8.1.2", "example.com"), 0xE100)


class SniSocksFromBindTest(unittest.TestCase):
    """П32: посредник подключается к прокси SOCKS5 выхода с адреса «Подключаться с адреса», а не с адреса системы."""

    def test_socks_socket_gets_the_address_mark(self):
        seen = {}

        async def fake(s, host, ip, port, mark=0):
            seen["mark"] = mark
            raise OSError("stop")
        s = sniproxy.Sniffer.__new__(sniproxy.Sniffer)
        with mock.patch.object(sniproxy, "socks_connect", fake):
            with self.assertRaises(OSError):
                asyncio.run(s.open_upstream({"socks": {"ip": "1.2.3.4", "port": 1080, "mark": 0x2101}},
                                            "a.com", "5.6.7.8", 443, b""))
        self.assertEqual(seen["mark"], 0x2101)

    def test_engine_target_has_the_mark(self):
        from app.engine import Engine
        e = Engine.__new__(Engine)
        u = {"id": "u1", "num": 1, "config": "socks5://198.51.100.9:1080", "enabled": True}
        st = {"upstreams": [u]}
        e.rt = {}
        e.resolve = lambda out, st: 1
        e.parsed = lambda u: type("P", (), {"kind": "socks5", "socks": {"host": "198.51.100.9", "port": 1080,
                                                                       "user": "", "password": ""}})()
        e.exit_mark = lambda st, u: 0x2103
        self.assertEqual(Engine._sni_target(e, st, "up:u1")["socks"]["mark"], 0x2103)


class SniEarlyHupTest(unittest.TestCase):
    """П18: SIGHUP, пока посредник разбирает списки (до serve), не убивает процесс; настройки потом перечитываются."""

    def test_hup_during_start(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        p = _sni_conf(d, {"listen": "127.0.0.1", "port": port})
        # сигнал приходит посреди Sniffer(...) — так же, как SIGHUP панели во время разбора больших списков
        code = ("import os, signal, sys; sys.path.insert(0, sys.argv[2]); sys.argv = ['sniproxy.py', sys.argv[1]];"
                "from app import sniproxy as s; r = s.Sniffer.reload\n"
                "def hup(self):\n    os.kill(os.getpid(), signal.SIGHUP); r(self)\n"
                "s.Sniffer.reload = hup; s.main()")
        pr = subprocess.Popen([sys.executable, "-c", code, p, ROOT], stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            up = False
            while time.monotonic() < deadline and pr.poll() is None:
                try:
                    socket.create_connection(("127.0.0.1", port), 0.2).close()
                    up = True
                    break
                except OSError:
                    time.sleep(0.05)
            self.assertIsNone(pr.poll(), "посредник завершился от SIGHUP во время запуска")
            self.assertTrue(up)
        finally:
            pr.send_signal(signal.SIGTERM)
            try:
                pr.wait(10)
            except subprocess.TimeoutExpired:
                pr.kill()
                pr.wait()
            pr.stderr.close()


if __name__ == "__main__":
    unittest.main()


def _ruleset(**kw) -> str:
    from app import nftgen
    gp = kw.pop("gp", None) or {"rules": [(["ru"], "direct")], "default": 1,
                                "domain": [(["yt"], 1)]}
    return nftgen.generate("awg0", {"ru": ["5.3.0.0/16"]}, [{"num": 1, "snat": "10.9.0.2", "mtu": 1280}],
                           gp, {}, kw.pop("sniff", 10443), **kw)


def _chain(txt: str, name: str) -> str:
    start = txt.index(f"\tchain {name} {{")
    return txt[start:txt.index("\n\t}", start)]


class RulesetFixTest(unittest.TestCase):
    """Набор правил nftables после исправлений полной проверки 1.25.0."""

    def test_sniff_mark_only_for_new_connections(self):
        """П2: соединение, открытое до перенаправления, не получает метку посредника (с ней оно шло по основной
        таблице мимо выхода); пакеты перенаправленных — к посреднику; страховка в c_forward."""
        for dom in (False, True):
            txt = _ruleset(dom_filter=dom)
            pol = _chain(txt, "p_global")
            pre = "ip daddr @dom4 " if dom else ""
            self.assertIn(f"{pre}tcp dport {{ 80, 443 }} ct state new meta mark set 0xd000 accept", pol)
            self.assertIn(f"{pre}tcp dport {{ 80, 443 }} ct status dnat accept", pol)
            self.assertNotIn("} meta mark set 0xd000", pol)
            self.assertIn('iifname "awg0" meta mark 0xd000 reject', _chain(txt, "c_forward"))

    def test_marks_after_foreign_mangle(self):
        """П10: метки ставятся после чужих цепочек mangle (premangle wg-quick, priority -150, стирает метку UDP);
        c_quic — раньше c_prerouting, обе позже -150."""
        txt = _ruleset(quic=True)
        self.assertIn("type filter hook prerouting priority mangle + 10;", _chain(txt, "c_prerouting"))
        self.assertIn("type filter hook prerouting priority mangle + 5;", _chain(txt, "c_quic"))
        self.assertNotIn("priority mangle;", _chain(txt, "c_prerouting"))
        self.assertNotIn("priority mangle - 5", txt)

    def test_alibaba_metadata_closed(self):
        """П33: служебный адрес Alibaba Cloud закрыт клиентам, как 169.254.169.254."""
        fwd = _chain(_ruleset(), "c_forward")
        self.assertIn('iifname "awg0" ip daddr 100.100.100.200 reject', fwd)
        self.assertIn('iifname "awg0" ip daddr 169.254.0.0/16 reject', fwd)

    def test_exit_nat_before_host_nat(self):
        """П49: NAT туннеля выхода раньше NAT хоста (iptables, srcnat)."""
        self.assertIn("type nat hook postrouting priority srcnat - 1;", _chain(_ruleset(), "c_postrouting"))

    def test_address_guard_lets_lo_through(self):
        """П48: соединение посредника с меткой адреса к адресу самого сервера (через lo) не отбрасывается."""
        from app import nftgen
        a = nftgen.Addr(A, 1)
        txt = _ruleset(gp={"rules": [(["ru"], a)], "default": a, "domain": [(["yt"], 1)]},
                       addrs={1: {"ip": A, "dev": "eth0", "gw": "203.0.113.1", "nat": "snat"}})
        post = _chain(txt, "c_addr_post")
        self.assertIn('meta mark 0x2101 oifname != "lo" oifname != "eth0" drop', post)
        self.assertIn(f'meta mark 0x2101 oifname != "lo" ip saddr != {A} drop', post)
        self.assertIn('meta mark 0x2101 oifname != "eth0" reject', _chain(txt, "c_forward"))   # пересылка — без lo

    @unittest.skipUnless(shutil.which("nft") and os.geteuid() == 0, "nft -c — только от root")
    def test_kernel_accepts(self):
        from app import nftgen
        a = nftgen.Addr(A, 1)
        for kw in ({"dom_filter": True},            # без quic: в песочнице нет nft_queue
                   {"gp": {"rules": [(["ru"], a)], "default": a, "domain": [(["yt"], 1)]},
                    "addrs": {1: {"ip": A, "dev": "eth0", "gw": "203.0.113.1", "nat": "snat"}}}):
            txt = _ruleset(**kw)
            p = subprocess.run(["unshare", "-n", "nft", "-c", "-f", "-"], input=txt, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)


class RecoverCreatedTest(unittest.TestCase):
    """П9: обрыв SSH между созданием и запуском нового контейнера сервера (обновление, смена порта) — панель запускает
    созданный, а не пишет «нет контейнера» (VPN лежал у всех до повторного awg-router update)."""

    def run_recover(self, status, created_ago=300):
        from app import config, selfupdate, system
        calls = []
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S.123456789Z", time.gmtime(time.time() - created_ago))
        names = ["awg-router", "amnezia-awg2", "amnezia-awg2-prev-20261127-050000"]
        system._port_mark({"old": "amnezia-awg2-prev-20261127-050000"})
        self.addCleanup(system._port_mark, None)

        def get(path):
            if path.startswith("/containers/json"):
                return [{"Names": ["/" + n]} for n in names]
            if "/amnezia-awg2/" in path:
                return {"State": {"Status": status, "Running": False, "FinishedAt": "0001-01-01T00:00:00Z"},
                        "Created": stamp}
            return {"State": {"Status": "exited", "Running": False, "FinishedAt": stamp},
                    "HostConfig": {"RestartPolicy": {"Name": "no"}}}

        def api(method, path, timeout=10, body=None):
            calls.append((method, path))
            return {}
        system.recovered.clear()
        self.addCleanup(system.recovered.clear)
        with mock.patch.object(system, "docker_get", get), mock.patch.object(system, "docker_api", api), \
                mock.patch.object(config, "AWG_MODE", "container"), mock.patch.object(config, "AWG_CONTAINER", ""), \
                mock.patch.object(selfupdate, "installer_running", lambda: False):
            return system.recover_renamed(), calls

    def test_created_container_is_started(self):
        name, calls = self.run_recover("created")
        self.assertEqual(name, "amnezia-awg2")
        self.assertEqual(calls, [("POST", "/containers/amnezia-awg2/update"), ("POST", "/containers/amnezia-awg2/start")])

    def test_stopped_or_fresh_left_alone(self):
        self.assertEqual(self.run_recover("exited"), (None, []))          # выключен руками — не трогаем
        self.assertEqual(self.run_recover("created", created_ago=5), (None, []))      # его запускают прямо сейчас


class ServerNatTest(unittest.TestCase):
    """П34: свой контейнер сервера подменяет адрес клиентов и на основной сети, когда после перезапуска с сетями
    исходящих адресов она уже не eth0 и не eth1 (машина GitHub: основная — eth2)."""

    def _run(self, default):
        with open(os.path.join(ROOT, "awg-server", "start.sh")) as f:
            text = f.read()
        part = text[text.index("\nWAN="):text.index("\ntail -f /dev/null")]
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "ip"), "w") as f:
            f.write(f"#!/bin/sh\necho '{default}'\n")
        with open(os.path.join(d, "iptables"), "w") as f:
            f.write(f'#!/bin/sh\necho "$*" >>"{d}/calls"\n')
        for n in ("ip", "iptables"):
            os.chmod(os.path.join(d, n), 0o755)
        subprocess.run(["bash", "-c", 'SUBNET=10.8.1.0/24\n' + part],
                       env={**os.environ, "PATH": d + ":" + os.environ["PATH"]}, check=True)
        with open(os.path.join(d, "calls")) as f:
            nat = [ln.split("-o ")[1].split()[0] for ln in f if "MASQUERADE" in ln]
        shutil.rmtree(d)
        return nat

    def test_default_route_interface(self):
        self.assertEqual(self._run("default via 172.17.0.1 dev eth2"), ["eth0", "eth1", "eth2"])
        self.assertEqual(self._run("default via 172.17.0.1 dev eth1 metric 5"), ["eth0", "eth1"])
        self.assertEqual(self._run(""), ["eth0", "eth1"])


class InstallerHupTest(unittest.TestCase):
    """П9: SIGHUP (обрыв SSH) после вопросов установщика не останавливает его посреди замены контейнера сервера."""

    def test_hup_ignored_before_the_dangerous_part(self):
        with open(os.path.join(ROOT, "install.sh")) as f:
            text = f.read()
        trap = text.index("\ntrap '' HUP\n")
        for later in ("refresh_own_server\n", "run_server_container >", "move_server() {", "compose up -d"):
            self.assertLess(trap, text.index(later), later)
        last_question = max(text.rindex('choose "$q"'), text.rindex('ask "Panel port'))
        self.assertLess(last_question, trap)

    def test_real_bash_survives_a_hangup(self):
        """Кусок установщика от trap до «замены контейнера»: SIGHUP группе процессов посреди — доходит до конца."""
        with open(os.path.join(ROOT, "install.sh")) as f:
            text = f.read()
        line = "trap '' HUP\n"
        self.assertIn(line, text)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        done = os.path.join(d, "done")
        script = line + f"sleep 1\necho ok > {done}\n"
        p = subprocess.Popen(["bash", "-c", script], start_new_session=True)
        time.sleep(0.3)
        os.killpg(p.pid, signal.SIGHUP)
        p.wait(10)
        self.assertTrue(os.path.exists(done))


class InstallerImagesTest(unittest.TestCase):
    """П4, П6: образ сервера не для этого процессора — сборка на месте; перед сборкой — место на диске, после —
    уборка кэша сборки. Функции install.sh вырезаны, docker и df поддельные (как RefreshOwnServerTest)."""

    def setUp(self):
        from tests import test_v122
        self.t = test_v122.RefreshOwnServerTest("test_new_image_recreates_container")
        self.t.setUp()
        self.addCleanup(self.t.doCleanups)

    def test_foreign_cpu_image_is_built_here(self):
        out, log = self.t.run_sh(HOST_ARCH="aarch64", IMG_ARCH="amd64")
        self.assertIn("docker pull ghcr.io/r-slashslash/awg-router@sha256:", log)
        self.assertIn("docker build -t amnezia-awg2", log)
        self.assertNotIn("docker tag", log)
        with open(os.path.join(self.t.tmp, "data", "awg-pull.log")) as f:
            self.assertIn("the ready image is for amd64, this server is arm64", f.read())

    def test_same_cpu_image_is_used(self):
        out, log = self.t.run_sh(HOST_ARCH="aarch64", IMG_ARCH="arm64")
        self.assertIn("docker tag ghcr.io/r-slashslash/awg-router@sha256:", log)
        self.assertNotIn("docker build", log)

    def test_little_disk_space_no_build(self):
        out, log = self.t.run_sh(PULL_RC="1", FREE_MB="1700")
        self.assertNotIn("docker build", log)
        self.assertIn("keeps the old one", out)
        with open(os.path.join(self.t.tmp, "data", "awg-build.log")) as f:
            self.assertIn("Not enough disk space to build here: 1700 MB free", f.read())

    def test_build_cache_removed(self):
        out, log = self.t.run_sh(PULL_RC="1")
        self.assertIn("docker build -t amnezia-awg2", log)
        self.assertIn("docker builder prune -f", log)


class InstallerPluginsTest(unittest.TestCase):
    """П22: Docker Compose и buildx — закреплённые версии и sha256 для каждого процессора; файл с другой суммой не
    ставится (раньше сумму брали из checksums.txt того же выпуска — от подмены выпуска это не защищает)."""

    def setUp(self):
        with open(os.path.join(ROOT, "install.sh")) as f:
            self.sh = f.read()

    def fn(self, name):
        a = self.sh.index(name + "() {")
        return self.sh[a:self.sh.index("\n}\n", a) + 3]

    def test_pinned_for_every_cpu(self):
        import re
        self.assertNotIn("gh_latest", self.sh)
        self.assertNotIn("checksums.txt", self.sh)
        comp = re.search(r"^COMPOSE_VERSION=(v[\d.]+)$", self.sh, re.M).group(1)
        bx = re.search(r"^BUILDX_VERSION=(v[\d.]+)$", self.sh, re.M).group(1)
        arches = re.search(r"case \"\$\(uname -m\)\" in\n(.*?)\nesac", self.sh, re.S).group(1)
        for b, dc in re.findall(r"BX_ARCH=(\S+);\s+DC_ARCH=(\S+) ;;", arches):
            for asset in (f"docker-compose-linux-{dc}", f"buildx-{bx}.linux-{b}"):
                self.assertRegex(self.sh, rf"\n    {re.escape(asset)}\)\s+echo [0-9a-f]{{64}} ;;", asset)
        self.assertTrue(comp and bx)

    def test_wrong_sum_is_refused(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        fake = os.path.join(d, "curl")
        with open(fake, "w") as f:
            f.write('#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && { echo replaced > "$2"; }; shift; done\n')
        os.chmod(fake, 0o755)
        script = (f'PLUGINS="{d}/plugins"; ' + self.fn("gh_plugin")
                  + 'gh_plugin docker/compose v1 docker-compose-linux-x86_64 docker-compose ' + "0" * 64
                  + '; echo "rc=$?"; [ -e "$PLUGINS/docker-compose" ] && echo installed\n')
        r = subprocess.run(["bash", "-c", script], env={**os.environ, "PATH": f"{d}:{os.environ['PATH']}"},
                           capture_output=True, text=True, timeout=30)
        self.assertIn("rc=1", r.stdout)
        self.assertNotIn("installed", r.stdout)
        import hashlib
        good = hashlib.sha256(b"replaced\n").hexdigest()
        r = subprocess.run(["bash", "-c", script.replace("0" * 64, good)],
                           env={**os.environ, "PATH": f"{d}:{os.environ['PATH']}"}, capture_output=True, text=True)
        self.assertIn("installed", r.stdout)

    def test_upstream_watches_them(self):
        from tools import upstream
        names = [p[0] for p in upstream.INSTALL_PROGRAMS]
        self.assertEqual(names, ["docker-compose", "docker-buildx"])
        args = upstream.pinned_sh(self.sh)
        for _, _, var in upstream.INSTALL_PROGRAMS:
            self.assertIn(var, args)


class InstallerEnvTest(unittest.TestCase):
    """П66: .env с паролем панели — 0600 и тогда, когда до обновления был 0644; AWGR_DOMAIN проверяется."""

    def setUp(self):
        with open(os.path.join(ROOT, "install.sh")) as f:
            self.sh = f.read()

    def test_env_mode_fixed(self):
        a = self.sh.index("HAD_ENV=0\n")
        b = self.sh.index("# Everything else the previous .env had")
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        env = os.path.join(d, ".env")
        with open(env, "w") as f:
            f.write("PANEL_PASSWORD=x\n")
        os.chmod(env, 0o644)
        script = f'ENV_FILE="{env}"; ssh_user() {{ :; }}; ssh_port() {{ :; }}\n' + self.sh[a:b]
        subprocess.run(["bash", "-c", script], check=True, capture_output=True, timeout=30)
        self.assertEqual(os.stat(env).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(env + ".bak").st_mode & 0o777, 0o600)

    def test_bad_domain_from_environment(self):
        self.assertIn('valid_domain "$PANEL_DOMAIN" || die "AWGR_DOMAIN=', self.sh)
        a = self.sh.index("valid_domain() {")
        fn = self.sh[a:self.sh.index("\n", a) + 1]
        for bad in ("https://panel.example.com", "panel example.com"):
            r = subprocess.run(["bash", "-c", fn + 'valid_domain "$1"', "x", bad], capture_output=True)
            self.assertNotEqual(r.returncode, 0, bad)


class ReleaseArmTest(unittest.TestCase):
    """П4: образ сервера AWG в выпуске — и для arm64 (на ARM контейнер сервера падал по кругу)."""

    def test_server_image_for_arm64(self):
        with open(os.path.join(ROOT, ".github", "workflows", "release.yml")) as f:
            text = f.read()
        a = text.index("id: server\n")
        self.assertIn("platforms: linux/amd64,linux/arm64", text[a:text.index("tags:", a)])


def _bind_state():
    from tests.test_v125 import state
    st = state(out_hosts=[A, "198.51.100.8"])
    u = st["upstreams"][0]
    u.update(bind=A, fallback="direct")
    return st


class BindPendingTest(unittest.TestCase):
    """П12: выход «Подключаться с адреса» с резервом «Напрямую», пока адрес не проверен или его путь не встал, — блок,
    а не резерв (клиенты шли напрямую при каждом перезапуске сервера и перезагрузке). Не работает — резерв."""

    def eng(self, state, live=True):
        from app.engine import Engine
        e = Engine.__new__(Engine)
        e.health, e.rt = {"u1": {"healthy": True}}, {}
        e._addr_rt = {A: {"state": state}} if state else {}
        e._addr_live = {1: {"ip": A, "dev": "eth0"}} if live else {}
        e.over_quota = lambda u: False
        return e

    def test_unchecked_address_blocks(self):
        st = _bind_state()
        for state, live in ((None, True), ("checking", True), ("ok", False), (None, False)):
            with self.subTest(state=state, live=live):
                self.assertEqual(self.eng(state, live).resolve("up:u1", st), "block")
        self.assertEqual(self.eng("failed").resolve("up:u1", st), "direct")       # не работает — резерв
        self.assertEqual(self.eng("bad", False).resolve("up:u1", st), "direct")
        self.assertEqual(self.eng("ok").resolve("up:u1", st), 1)

    def test_rule_balancing_waits_too(self):
        st = _bind_state()
        self.assertTrue(self.eng("checking").rule_pending(st, {"u1"}))
        self.assertFalse(self.eng("failed").rule_pending(st, {"u1"}))


class HoldPassTest(unittest.TestCase):
    """Новая сеть сервера (перезапуск контейнера): П17 — правила до туннелей блокируют выход с резервом «Напрямую», даже
    если его проверка в прошлой сети — ошибка; П11 — IPv6 клиентов закрыт сразу, до запуска туннелей; П14 — набор не
    встал, а таблицы панели нет — запасная таблица закрывает пересылку клиентов."""

    def setUp(self):
        from tests import test_v121f
        self.t = test_v121f.ReconcileOrderTest("test_pass_sets_ip_rules")
        self.t.setUp()
        self.addCleanup(self.t.doCleanups)
        self.t.e.store.mutate(lambda st: st["upstreams"][0].update(fallback="direct"))

    def test_hold_blocks_exit_with_old_error(self):
        t = self.t
        t.reconcile(t.t)
        t.e.health["u1"] = {"state": "error", "error": "nsenter failed"}       # контейнер умер посреди прохода
        seen = []
        orig = t.e.build_ruleset

        def build(tg, st, sniff, *a, **kw):
            text = orig(tg, st, sniff, *a, **kw)
            seen.append(text)
            return text
        t.e.build_ruleset = build
        t.reconcile(t.target("container:amnezia-awg2:5151:b"))
        p_global = seen[0][seen[0].index("\tchain p_global {"):]
        self.assertIn("goto o_block", p_global[:p_global.index("\n\t}")])
        self.assertNotIn("goto o_direct", p_global[:p_global.index("\n\t}")])

    def test_ipv6_closed_before_tunnels(self):
        t = self.t
        t.reconcile(t.t)
        t.log.clear()
        t.reconcile(t.target("container:amnezia-awg2:5151:b"))
        self.assertLess(t.log.index(("nft6",)), t.log.index(("tunnel", 1)), t.log)

    def test_failed_rules_close_forwarding(self):
        t = self.t
        applied = []
        ns = t.ns

        def failing(cmd, **kw):
            if cmd[:2] == ["nft", "-f"] and cmd[2].endswith("ruleset.nft"):
                from app import system
                raise system.SysError("syntax error, unexpected newline")
            if cmd[:2] == ["nft", "-f"] and cmd[2].endswith("ruleset-closed.nft"):
                with open(cmd[2]) as f:
                    applied.append(f.read())
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return ns(cmd, **kw)
        t.table["present"] = False
        tg = t.target("container:amnezia-awg2:7171:d")
        tg.ns.side_effect = failing
        from app import system
        with self.assertRaises(system.SysError):
            t.reconcile(tg)
        self.assertTrue(applied, "запасная таблица не поставлена")
        self.assertIn('iifname "awg0" reject', applied[0])
        self.assertIn("hook forward", applied[0])

    def test_present_table_is_left(self):
        """Прежний набор панели стоит (не новая сеть): запасная таблица не ставится — действуют прежние правила."""
        from app.engine import Engine
        e = Engine.__new__(Engine)
        calls = []

        class T:
            iface = "awg0"

            def ns(self, cmd, **kw):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, "", "")
        from app import config
        with mock.patch.object(config, "DRY_RUN", False):
            e._close_forward(T())
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:3], ["nft", "list", "chain"])


class HoldFilesTest(unittest.TestCase):
    """П11: правила «до панели» закрывают и IPv6 клиентов — отдельным файлом и отдельной командой (служба на хосте и
    свой контейнер), чтобы без IPv6 в ядре не падали и правила IPv4."""

    def test_unit_has_separate_ipv6_command(self):
        from app import system
        pre = [ln for ln in system.UNIT_TEXT.splitlines() if ln.startswith("ExecStartPre=-")]
        self.assertEqual(len(pre), 2)
        self.assertIn("awgr-hold-%i.nft", pre[0])
        self.assertIn("awgr-hold6-%i.nft", pre[1])
        self.assertNotIn("awgr-hold6", pre[0])

    def test_start_sh_applies_both(self):
        with open(os.path.join(ROOT, "awg-server", "start.sh")) as f:
            sh = f.read()
        up = sh.index('awg-quick up "$CONF"')
        self.assertLess(sh.index("awgr-hold6-awg0.nft"), up)
        self.assertLess(sh.index('nft -f "$HOLD"'), sh.index('nft -f "$HOLD6"'))

    def test_hold6_rejects_clients(self):
        from app.engine import server
        txt = server.v6_ruleset("awg0")
        self.assertIn("table ip6 awgr6", txt)
        self.assertIn('iifname "awg0" reject', txt)


class KernelOrDeadTargetTest(unittest.TestCase):
    """П17: контейнер сервера умер посреди прохода — отказ `ip link add` не объявляется отказом модуля ядра (ложное
    сообщение в Telegram и все выходы на amneziawg-go до перезапуска сервера)."""

    def test_dead_target_is_not_a_kernel_failure(self):
        from app import config, system
        from app.engine import Engine, tunnels
        e = Engine.__new__(Engine)
        e.events, e.kernel_fallback, e.rt = [], None, {}
        e.event = lambda kind, msg: e.events.append(msg.key)
        e._pre = {"198.51.100.1": "198.51.100.1"}
        e._v6_route = lambda t, ip: None
        e.exit_engine = lambda: "kernel"

        def ns(cmd, **kw):
            if cmd[:3] == ["ip", "link", "add"]:
                raise system.SysError("nsenter: reassociate to namespace 'ns/net' failed: No such process")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        t = mock.Mock(iface="awg0", key="k")
        t.ns.side_effect = ns
        pc = mock.Mock(kind="awg", endpoint="198.51.100.1:51820", setconf="[Interface]\n")
        u = {"num": 1, "name": "NL"}
        with mock.patch.object(config, "DRY_RUN", False), \
                mock.patch.object(tunnels.awgconf, "setconf_for", lambda pc, ip: "[Interface]\n"):
            t.is_up.return_value = False                      # сеть сервера пропала
            with self.assertRaises(system.SysError):
                e._start_up(t, "u1", u, pc, "h")
            self.assertIsNone(e.kernel_fallback)
            self.assertNotIn("ev.kernel_fallback", e.events)
            t.is_up.return_value = True                       # сервер жив — это и правда отказ модуля
            try:
                e._start_up(t, "u1", u, pc, "h")
            except Exception:  # noqa: BLE001 — дальше amneziawg-go, которого здесь нет
                pass
            self.assertIn("ev.kernel_fallback", e.events)


def _panel():
    from app import panel
    return panel


class AuthFixTest(unittest.TestCase):
    """Вход в панель (П15, П16, П26)."""

    def setUp(self):
        _panel()
        from app.api import auth
        self.auth = auth
        auth._fails.clear()
        auth._inflight.clear()
        self.addCleanup(auth._fails.clear)

    def test_empty_secret_files_made_again(self):
        """П15: пустой ключ сессий или пароль после сбоя первого запуска — создаются заново, через временный файл."""
        from app import config
        auth = self.auth
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with mock.patch.object(config, "DATA_DIR", d):
            for name in ("session.key", "panel_password"):
                open(os.path.join(d, name), "w").close()             # пустой файл
                with mock.patch.object(auth, "log"):
                    v = auth._secret_file(name, lambda: "fresh-secret")
                self.assertEqual(v, "fresh-secret")
                with open(os.path.join(d, name)) as f:
                    self.assertEqual(f.read(), "fresh-secret")
                self.assertEqual(os.stat(os.path.join(d, name)).st_mode & 0o777, 0o600)
                self.assertFalse(os.path.exists(os.path.join(d, name + ".tmp")))
                self.assertEqual(auth._secret_file(name, lambda: "other"), "fresh-secret")

    def test_empty_password_never_lets_in(self):
        auth = self.auth
        with mock.patch.object(auth, "PASSWORD", ""), mock.patch.object(auth, "custom_password", lambda: None):
            self.assertFalse(auth.check_password(""))
            self.assertFalse(auth.check_password("anything"))
        self.assertFalse(auth.check_password(""))

    def test_one_48_is_limited(self):
        """П16: 20 разных /64 одной /48 по 8 неверных паролей — дальше 429; другая /48 и IPv4 — как раньше."""
        from app import web
        auth = self.auth
        codes = []
        with mock.patch.object(auth.time, "sleep"), mock.patch.object(auth, "notifier") as nt:
            for i in range(20):
                ip = web.client_key(f"2001:db8:1:{i:x}::1")
                for _ in range(8):
                    try:
                        auth._check_blocked(ip)
                        try:
                            auth._failed(ip, "err.wrong_password")
                        finally:
                            auth._done(ip)
                    except web.HTTPError as e:
                        codes.append(e.code)
            self.assertIn(429, codes)
            self.assertLessEqual(codes.count(403), auth.FAIL_NET_MAX)
            # одно сообщение «вход заблокирован» на /48, а не на каждую /64
            ips = {c.kwargs.get("ip") for c in nt.event.call_args_list if c.args[1] == "login_blocked"}
            self.assertEqual(ips, {"2001:db8:1::/48"})
            other = web.client_key("2001:db8:2::1")
            auth._check_blocked(other)                       # соседняя /48 не задета
            auth._done(other)
            auth._check_blocked("203.0.113.7")
            auth._done("203.0.113.7")

    def test_big_backup_passes_the_middleware(self):
        """П26: копия 5 МБ доходит до обработчика (раньше проверка входа отвечала 413 на всё больше 4 МБ)."""
        from app import web
        auth = self.auth

        class Req:
            path = auth.BASE + "/api/restore"
            headers = {"Content-Length": str(5 * 1024 * 1024), "Content-Type": "application/json",
                       "Origin": "", "Host": ""}
            cookies = {auth.COOKIE: auth.make_session()}
            authed = False
        r = Req()
        with mock.patch.object(auth, "same_origin", lambda req: True):
            auth.auth_mw(r)
            self.assertTrue(r.authed)
            r.path = auth.BASE + "/api/routing"
            with self.assertRaises(web.HTTPError) as c:
                auth.auth_mw(r)
            self.assertEqual(c.exception.code, 413)


class NotifySentPrunedTest(unittest.TestCase):
    """П16: отметки «уже отправлено» не растут без конца (3000 разных /64 — 3000 записей навсегда)."""

    def test_pruned(self):
        from app import notify
        n = notify.Notifier.__new__(notify.Notifier)
        old = time.time() - notify.SENT_KEEP - 10
        n._sent = {f"k{i}": old for i in range(notify.SENT_MAX + 5)}
        st = {"settings": {}}
        n.store = mock.Mock(snapshot=lambda: st)
        with mock.patch.object(notify, "cfg_of", lambda st: {"enabled": True, "token": "t", "chat_id": "1",
                                                              "events": {"login": True}, "control": False,
                                                              "lang": "en"}):
            n.host_fn = lambda st: ""
            n.buttons_fn = None
            n.queue_fn = None
            with mock.patch.object(n, "_send", create=True):
                try:
                    n.event("login", "login_blocked", cooldown=600, ip="x")
                except Exception:  # noqa: BLE001 — сама отправка здесь не нужна
                    pass
        self.assertLess(len(n._sent), 10)


class HoldFileBlocksTest(unittest.TestCase):
    """П13, П17: файл правил «до панели» — выход с резервом «Напрямую», который сейчас лежит, тоже блок: после
    перезагрузки, до панели, никто не знает, работает ли он (раньше файл вёл его клиентов напрямую)."""

    def test_hold_file(self):
        from tests import test_v121f
        t = test_v121f.ReconcileOrderTest("test_pass_sets_ip_rules")
        t.setUp()
        self.addCleanup(t.doCleanups)
        t.e.store.mutate(lambda st: st["upstreams"][0].update(fallback="direct"))
        t.reconcile(t.t)
        t.e.health["u1"] = {"state": "down", "healthy": False}
        st = t.e.store.snapshot()
        normal = t.e.build_ruleset(t.t, st, None, hold=True)
        self.assertIn("goto o_direct", _chain(normal, "p_global"))      # без защиты — напрямую
        t.e._hold_key = None
        from app import config
        with mock.patch.object(config, "DRY_RUN", False):
            t.e._save_hold(t.t, st)
        texts = [c.args[1] for c in t.t.write_file.call_args_list if c.args[0].endswith("awgr-hold-awg0.nft")]
        self.assertTrue(texts)
        self.assertIn("goto o_block", _chain(texts[-1], "p_global"))
        self.assertNotIn("goto o_direct", _chain(texts[-1], "p_global"))


class DnsRedirectTest(unittest.TestCase):
    """П5: при включённом «DNS на сервере» все запросы DNS клиентов (UDP и TCP 53, к любому адресу) идут к DNS на
    сервере — и в правилах «до панели»; выключен — как раньше."""

    def test_ruleset(self):
        txt = _ruleset(dns_to="10.8.1.1")
        c = _chain(txt, "c_dns")
        self.assertIn("type nat hook prerouting priority dstnat;", c)
        for p in ("udp", "tcp"):
            self.assertIn(f'iifname "awg0" ip daddr != 10.8.1.1 {p} dport 53 dnat to 10.8.1.1:53', c)
        self.assertNotIn("c_dns", _ruleset())

    def engine(self, panel_dns):
        from app.engine import Engine
        from tests.test_v125 import state
        e = Engine.__new__(Engine)
        e.tunnel_addr = lambda t: ("10.8.1.1", "10.8.1.0/24")
        return e, state(panel_dns=panel_dns)

    def test_engine_follows_the_setting(self):
        e, st = self.engine(True)
        self.assertEqual(e.dns_redirect(None, st), "10.8.1.1")
        e, st = self.engine(False)
        self.assertIsNone(e.dns_redirect(None, st))
        e, st = self.engine(True)
        e.tunnel_addr = lambda t: None                      # интерфейса ещё нет
        self.assertIsNone(e.dns_redirect(None, st))

    def test_before_the_panel_too(self):
        """Правила «до панели» (и при остановке панели) — с перенаправлением: dnsproxy.py тогда не работает, имена не
        разрешаются, но и мимо выхода не уходят (решение владельца 2026-11-27)."""
        from tests import test_v121f
        t = test_v121f.ReconcileOrderTest("test_pass_sets_ip_rules")
        t.setUp()
        self.addCleanup(t.doCleanups)
        t.e.store.mutate(lambda st: st["settings"].update(panel_dns=True))
        t.e.tunnel_addr = lambda tg: ("10.8.1.1", "10.8.1.0/24")
        st = t.e.store.snapshot()
        self.assertIn("dnat to 10.8.1.1:53", t.e.build_ruleset(t.t, st, None, hold=True))

    @unittest.skipUnless(shutil.which("nft") and os.geteuid() == 0, "nft -c — только от root")
    def test_kernel_accepts(self):
        p = subprocess.run(["unshare", "-n", "nft", "-c", "-f", "-"], input=_ruleset(dns_to="10.8.1.1"),
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)


class HungExitTest(unittest.TestCase):
    """П27: завис amneziawg-go выхода (`awg show` не отвечает) — проход идёт, выход «stale», клиенты на резерве; раньше
    каждый проход падал на TimeoutExpired и резерв не включался никогда."""

    def test_hung_awg_show(self):
        from app import config
        from app.engine import Engine
        from app.engine.common import UpRT
        e = Engine.__new__(Engine)
        e.health, e.events = {}, []
        e.rt = {"u1": UpRT(1, "h", "k")}
        e.rt["u1"].started = time.time() - 600
        e.event = lambda kind, msg: e.events.append(msg.key)
        e.parsed = lambda u: mock.Mock(kind="awg", rekey_after=120)
        e._fake = None
        calls = []

        def ns(cmd, **kw):
            calls.append(cmd)
            if cmd[:2] == ["awg", "show"]:
                raise subprocess.TimeoutExpired(cmd, 10)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        t = mock.Mock(key="k")
        t.ns.side_effect = ns
        st = {"upstreams": [{"id": "u1", "num": 1, "name": "NL", "enabled": True, "fallback": "direct"}]}
        with mock.patch.object(config, "DRY_RUN", False):
            e._update_health(t, st)
        self.assertEqual(e.health["u1"]["state"], "stale")
        self.assertEqual(sum(1 for c in calls if c[:2] == ["awg", "show"]), 1)   # не 10 с на каждый выход


class AddressFixTest(unittest.TestCase):
    """Адреса сервера: П29, П42, повтор раз в 15 минут, П51, П52."""

    def setUp(self):
        from tests import test_v125
        self.t = test_v125.AddressesInSystemTest("test_added_checked_and_removed")
        self.t.setUp()
        self.addCleanup(self.t.tearDown)

    def test_network_restart_keeps_a_working_address(self):
        """П29: сеть системы перезапускается в момент круга (маршрута по умолчанию нет) — рабочий адрес не «не заработал»
        на 15 минут, а добавляется снова на следующем круге."""
        t = self.t
        t.tick(out_hosts=[A])
        self.assertTrue(t.eng.addr_ok(A))
        t.host.addrs.pop(A)                                       # адрес пропал вместе с сетью
        wan = t.eng._wan
        t.eng._wan = lambda: {}                                  # и маршрута по умолчанию ещё нет
        t.eng._addr_tick(t.store.snapshot())
        self.assertNotEqual(t.eng.addr_state(A), "bad")
        t.eng._wan = wan                                          # сеть вернулась
        t.tick()
        self.assertIn(A, t.host.addrs)
        self.assertTrue(t.eng.addr_ok(A))

    def test_docker_gw_not_retried_by_itself(self):
        """Сеть адреса, которую Docker сделал маршрутом по умолчанию, сама через 15 минут больше не подключается."""
        from app.engine import addrs as addrs_mod
        from app.i18n import Msg
        t = self.t
        t.store.mutate(lambda s: s["settings"].update(out_hosts=[A]))
        t.eng.addr_rt()[A] = {"state": "bad", "error": Msg("addr.docker_gw"),
                              "at": time.time() - addrs_mod.ADDR_BAD_RETRY - 5}
        t.eng._addr_tick(t.store.snapshot())
        self.assertEqual(t.eng.addr_state(A), "bad")
        t.eng.addrs_wake(retry=[A])                              # «Сервер» сохранили снова — пробуется
        t.eng._addr_tick(t.store.snapshot())
        self.assertNotEqual(t.eng.addr_state(A), "bad")


class GwPriorityTest(unittest.TestCase):
    """П42: смена порта сохраняет низкий приоритет сети адреса; проход замечает маршрут по умолчанию в сети адреса."""

    def test_endpoint_keeps_gw_priority(self):
        from app import system
        info = {"Id": "abcdef1234567890", "HostConfig": {"NetworkMode": "bridge"},
                "NetworkSettings": {"Networks": {"bridge": {}, "zz-awgr-out-1": {"GwPriority": -1000,
                                                                                  "Aliases": ["abcdef123456"]}}}}
        self.assertEqual(system.extra_networks(info), {"zz-awgr-out-1": {"GwPriority": -1000}})

    def test_pass_drops_network_that_became_default(self):
        from app import system
        from app.engine import Engine
        e = Engine.__new__(Engine)
        e._addr_rt = {}
        e.addr_slots = lambda st: {A: 1}
        e._addr_rec = lambda: {"ever": [A], "slots": {A: 1}}
        t = mock.Mock(key="k", kind="container")
        t.name = "amnezia-awg2"
        t.ns.side_effect = lambda cmd, **kw: subprocess.CompletedProcess(
            cmd, 0, json.dumps([{"dev": "eth1", "gateway": "172.30.0.1"}]) if "route" in cmd else "[]", "")
        dropped = []
        e._net_drop = lambda tg, name, connected: dropped.append(name)
        net = {"Name": "zz-awgr-out-1", "Options": {"com.docker.network.host_ipv4": A}}
        ct = {"NetworkSettings": {"Networks": {"zz-awgr-out-1": {"Gateway": "172.30.0.1", "IPAddress": "172.30.0.2"}}}}
        from app import config
        with mock.patch.object(system, "docker_get", lambda p: [net] if p.startswith("/networks") else ct), \
                mock.patch.object(system, "docker_api", lambda *a, **k: {}), \
                mock.patch.object(config, "DRY_RUN", False), mock.patch("os.path.exists", lambda p: True):
            out = e._sync_addr_nets(t, {})
        self.assertEqual(out, {})
        self.assertEqual(dropped, ["zz-awgr-out-1"])
        self.assertEqual(e.addr_state(A), "bad")


class DetectHostTest(unittest.TestCase):
    """П51: внешний адрес системы ищется с адреса системы, а не с основного исходящего; П52: поток не умирает молча."""

    def test_probe_from_the_system_address_and_survives(self):
        from app.engine import Engine
        e = Engine.__new__(Engine)
        e.stop_ev = mock.Mock()
        e.stop_ev.is_set.side_effect = [False, True]
        e.target = mock.Mock(exists=True)
        seen = []
        e.probe = lambda out: seen.append(out) or {"ok": True, "ip": "203.0.113.5", "cc": "RU"}
        e.trigger = lambda: None
        e.public_v4 = None
        e.srv = mock.Mock()
        e.srv.public_host.side_effect = OSError(28, "No space left on device")
        e.store = mock.Mock()
        with mock.patch("app.engine.log"):
            e._detect_host()
        self.assertEqual(seen, ["direct@system"])
        self.assertEqual(e.public_v4, "203.0.113.5")


class BotFixTest(unittest.TestCase):
    """Бот: П28 (смена токена), П54 (экранирование, отказ в file_id, смена чата, права файла), тесты вслепую."""

    def setUp(self):
        from app import notify, tgbot
        from app.api import telegram
        from tests import test_v19
        self.tgbot, self.notify, self.v19 = tgbot, notify, test_v19
        self.tg = test_v19.FakeTG()
        p = mock.patch.object(notify, "_post", self.tg)
        p.start()
        self.addCleanup(p.stop)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        sp = mock.patch.object(tgbot, "STATE", os.path.join(d, "tgbot.json"))
        sp.start()
        self.addCleanup(sp.stop)
        self.bot = tgbot.Bot(_panel().store, telegram.bot_ops)
        self.c = test_v19.cfg()

    def test_new_bot_starts_without_old_offset(self):
        """П28: другой бот после смены токена опрашивается без старой отметки — его команды не пропадают."""
        self.bot._st.update(offset=20008, offset_bot=self.c["token"].split(":")[0])
        self.bot.poll_once(self.c, timeout=0)
        self.assertEqual(self.tg.last("getUpdates")["offset"], 20008)          # тот же бот — та же отметка
        other = {**self.c, "token": "987654321:" + "B" * 35}
        self.bot.poll_once(other, timeout=0)
        self.assertEqual(self.tg.last("getUpdates")["offset"], 0)

    def test_state_file_private(self):
        self.bot._st["x"] = 1
        self.bot._save()
        self.assertEqual(os.stat(self.tgbot.STATE).st_mode & 0o777, 0o600)

    def test_exit_name_escaped_once(self):
        """П54: имя выхода «NL & <1>» в тексте бота — «&amp;» один раз, а не «&amp;amp;»."""
        st = {"upstreams": [{"id": "u1", "num": 1, "name": "NL & <1>"}]}
        label = self.bot.out_label(self.c, "up:u1", st)
        text = self.tgbot.tr("en", "st_default", out=label)
        self.assertIn("NL &amp; &lt;1&gt;", text)
        self.assertNotIn("&amp;amp;", text)

    def test_file_id_refused_is_not_a_button_error(self):
        e = self.notify.NotifyError("Bad Request: wrong file identifier/HTTP URL specified")
        self.assertFalse(self.tgbot._button_refused(e))
        self.assertTrue(self.tgbot._button_refused(self.notify.NotifyError("Bad Request: BUTTON_URL_INVALID")))

    def test_new_chat_does_not_delete_by_old_numbers(self):
        """П54: после смены Chat ID первое меню не удаляет сообщение нового чата с номером меню из прежнего."""
        self.bot._set_panel(self.c, {"message_id": 1015}, photo=False)
        self.tg.calls.clear()
        self.bot._set_panel({**self.c, "chat_id": "-4002"}, {"message_id": 7}, photo=False)
        self.assertNotIn("deleteMessage", self.tg.methods())
        self.bot._set_panel({**self.c, "chat_id": "-4002"}, {"message_id": 8}, photo=False)
        self.assertEqual(self.tg.last("deleteMessage")["message_id"], 7)

    def test_migration_only_from_own_chat(self):
        """Тест вслепую (было): «группа стала супергруппой» из чужого чата не меняет Chat ID панели."""
        seen = []
        with mock.patch.object(self.notify, "on_migrate", lambda old, new: seen.append((old, new))):
            want = self.c["chat_id"]
            self.assertFalse(self.bot._migration({"chat": {"id": -777}, "migrate_to_chat_id": -1001}, self.c))
            self.assertFalse(self.bot._migration({"chat": {"id": -1001}, "migrate_from_chat_id": -777}, self.c))
            self.assertEqual(seen, [])
            self.assertTrue(self.bot._migration({"chat": {"id": int(want)}, "migrate_to_chat_id": -1002}, self.c))
            self.assertTrue(self.bot._migration({"chat": {"id": -1003}, "migrate_from_chat_id": int(want)}, self.c))
            self.assertEqual(seen, [(want, "-1002"), (want, "-1003")])


class BackupToTelegramTest(unittest.TestCase):
    """Тест вслепую (было): копия в Telegram с паролем уходит зашифрованной — без подмены send_backup целиком."""

    def test_encrypted_with_password(self):
        _panel()
        from app import notify
        from app.api import backup
        sent = []
        with mock.patch.object(notify, "send_document", lambda tok, chat, name, data, cap, via: sent.append((name, data))):
            backup.send_backup({"token": "t", "chat_id": "1", "lang": "en", "backup_pw": "pw-123456", "via": "direct"})
            backup.send_backup({"token": "t", "chat_id": "1", "lang": "en", "via": "direct"})
        self.assertTrue(sent[0][0].endswith(".json.enc"))
        self.assertTrue(sent[0][1].startswith(b"Salted__"))
        self.assertTrue(sent[1][0].endswith(".json"))
        self.assertTrue(sent[1][1].lstrip().startswith(b"{"))


class BotDirectFromMainTest(unittest.TestCase):
    """П53: бот на «Напрямую», когда основной исходящий адрес — дополнительный, идёт с него (как подписано в выборе)."""

    def test_router_asked_for_direct(self):
        from app import notify
        asked = []
        old = notify.router
        notify.router = lambda via: asked.append(via) or (4242, 0x2101)
        self.addCleanup(setattr, notify, "router", old)
        with mock.patch.object(notify, "_post_via", lambda route, *a: (200, b'{"ok":true,"result":1}')):
            notify._post_once("t", "getMe", b"{}", "application/json", 5, "direct")
        self.assertEqual(asked, ["direct"])


class StatusCardDnsTest(unittest.TestCase):
    """П54: картинка «Состояние» — при DNS без шифрования счётчики запросов не налезают на значение строки."""

    def test_counts_do_not_overlap(self):
        from app import tgbot, tgcard
        from tests.test_v124 import STATUS
        rows = []
        orig = tgcard.Painter.row

        def row(self, y, icon, label, value, sub=None, **kw):
            if icon == "compass":
                rows.append((self.lang, self.width(sub or []), self.width(value)))
            return orig(self, y, icon, label, value, sub, **kw)
        dns = {"state": "on", "listen": "10.8.0.1", "encrypt": "plain", "queries": 1234567, "cached": 7654321}
        with mock.patch.object(tgcard.Painter, "row", row):
            for lang in ("ru", "en", "zh", "fa"):
                tgcard.status(tgbot.TEXTS[lang], lang, {**STATUS, "dns": dns})
        room = tgcard.W - 2 * tgcard.PAD_X - 44 - tgcard.GAP
        for lang, sub, value in rows:
            self.assertLessEqual(sub + value + tgcard.GAP, room, lang)


class StateFixTest(unittest.TestCase):
    """Состояние и копии: П55, П56, П57; П58 — медленное тело запроса."""

    def test_deleted_client_takes_its_lists(self):
        """П55: удаление клиента со своими правилами убирает их списки, которые больше нигде не стоят."""
        panel = _panel()
        from app.api import clients, routing
        from tests.test_v125 import Req
        panel.engine.reconcile()
        pk = panel.engine.clients[0]["public_key"]
        lid = routing.add_list(Req({"kind": "manual", "name": "own", "source": "203.0.113.0/24"}))["id"]
        shared = routing.add_list(Req({"kind": "manual", "name": "shared", "source": "198.51.100.0/24"}))["id"]
        st0 = panel.store.snapshot()
        self.addCleanup(lambda: panel.store.mutate(lambda s: (s.clear(), s.update(st0))))

        def own(st):
            st["clients"].setdefault(pk, {}).update(rules_mode="custom", rules=[
                {"lists": [lid, shared], "outbound": "direct", "enabled": True, "comment": ""}])
            st["routing"]["rules"].append({"lists": [shared], "outbound": "direct", "enabled": True, "comment": ""})
        panel.store.mutate(own)
        with mock.patch.object(panel.engine.srv, "delete_client",          # как настоящий: клиента в состоянии нет
                               lambda key: panel.store.mutate(lambda st: st["clients"].pop(key, None))):
            clients.delete_user(pk)
        ids = {x["id"] for x in panel.store.snapshot()["lists"]}
        self.assertNotIn(lid, ids)
        self.assertIn(shared, ids)                  # стоит и в общих правилах — остаётся

    def test_disk_full_is_explained(self):
        """П56: нет места на диске — ответ «кончилось место», а не «внутренняя ошибка: [Errno 28]»."""
        import errno
        from app import web
        app_ = web.App("")

        @app_.post("/api/x")
        def x(req):
            raise OSError(errno.ENOSPC, "No space left on device")
        code, body = _call(app_, "POST", "/api/x", b"{}")
        self.assertEqual(code, 507)
        self.assertEqual(body["detail"]["$t"], "err.disk_full")

    def test_wrong_types_in_backup(self):
        """П57: копия с полями неверного вида — отказ с именем поля, а не «внутренняя ошибка»."""
        _panel()
        from app.api import backup
        from app.web import HTTPError
        from tests.test_v125 import state
        for path, value in ((("routing", "rules"), 5), (("clients",), 5), (("routing", "balance"), {"skip": [[1]]})):
            st = state()
            o = st
            for k in path[:-1]:
                o = o[k]
            o[path[-1]] = value
            try:
                backup.clean_backup_state(st)
            except HTTPError:
                pass                                 # отказ с именем поля — так и надо

    def test_restored_state_file_private(self):
        """П57: после возврата state.json.bak файлы — 0600 (закрытые ключи клиентов)."""
        from app.store import Store
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = os.path.join(d, "state.json")
        s = Store(p)
        s.mutate(lambda st: st["settings"].update(a=1))
        s.mutate(lambda st: st["settings"].update(a=2))
        with open(p, "w") as f:
            f.write("{broken")
        old = os.umask(0o022)
        try:
            with mock.patch("app.store.log"):
                Store(p)
        finally:
            os.umask(old)
        for f in (p, p + ".broken"):
            self.assertEqual(os.stat(f).st_mode & 0o777, 0o600, f)

    def test_slow_body_is_408(self):
        """П58: тело запроса не дошло за срок — 408 и закрытие соединения, без трассировки в журнале."""
        from app import web
        app_ = web.App("")

        @app_.post("/api/y")
        def y(req):
            return req.json()
        with mock.patch.object(web, "IDLE_TIMEOUT", 0.5), mock.patch.object(web.log, "error") as err:
            code, body = _call(app_, "POST", "/api/y", b'{"a"', length=100)
        self.assertEqual(code, 408)
        err.assert_not_called()


def _call(app_, method, path, body, length=None):
    """Настоящий запрос к App на своём порту."""
    import http.client
    srv = app_.serve("127.0.0.1", 0)
    import threading as th
    t = th.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        port = srv.server_address[1]
        s = socket.create_connection(("127.0.0.1", port), 5)
        head = (f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {length if length is not None else len(body)}\r\n\r\n").encode()
        s.sendall(head + body)
        r = http.client.HTTPResponse(s)
        r.begin()
        data = json.loads(r.read() or b"{}")
        s.close()
        return r.status, data
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------- интерфейс (П38–П40, П50, П59–П65)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # tests/panel_js.py
import panel_js  # noqa: E402


def _read(*path) -> str:
    with open(os.path.join(ROOT, *path), encoding="utf-8") as f:
        return f.read()


def _fn(src: str, head: str) -> str:
    """Тело функции/обработчика от строки head до парной закрывающей скобки."""
    i = src.index(head)
    j = src.index("{", i)
    depth = 0
    for k in range(j, len(src)):
        depth += {"{": 1, "}": -1}.get(src[k], 0)
        if depth == 0:
            return src[i:k + 1]
    raise AssertionError(head)


def _node(code: str) -> str:
    node = shutil.which("node")
    if not node:
        raise unittest.SkipTest("нет node")
    return subprocess.run([node, "-e", code], capture_output=True, text=True, check=True, timeout=30).stdout


class FaBidiTest(unittest.TestCase):
    """П38: в персидском латинские «vpn://», «.conf», «socks5://» в фразе — в изоляции U+2066…U+2069, иначе
    человек видит «//:vpn» и «conf.»."""

    def test_isolated(self):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from test_rules import i18n
        fa = i18n()["fa"]
        bad = []
        for k, v in fa.items():
            if not v or k in ("ex.config_ph", "ls.domains_ph"):      # заполнители полей dir="ltr"
                continue
            v = json.loads('"' + v + '"')
            for piece in ("vpn://", ".conf", "socks5://"):
                for i in [n for n in range(len(v)) if v.startswith(piece, n)]:
                    before = v[:i]
                    if before.count("\u2066") <= before.count("\u2069"):
                        bad.append((k, piece))
        self.assertEqual(bad, [])


class UiCssTest(unittest.TestCase):
    """П39, П40, П63: сообщения не закрывают кнопки окна; окно правила не шире телефона; контраст текста ≥ 4,5."""

    css = _read("app", "static", "app.css")

    def test_toasts_on_top_in_dialog_and_close_on_click(self):
        self.assertRegex(self.css, r"dialog #toasts \{[^}]*top: 12px;[^}]*bottom: auto")
        self.assertIn("el.onclick = () => el.remove();", _fn(panel_js.source(), "function toast("))

    def test_rule_window_lists_can_shrink(self):
        self.assertRegex(self.css, r"#rw-lists \{ min-width: 0; \}")

    @staticmethod
    def _ratio(a: str, b: str) -> float:
        def lum(h):
            c = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
            c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
            return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
        la, lb = sorted((lum(a), lum(b)), reverse=True)
        return (la + 0.05) / (lb + 0.05)

    def _vars(self, block: str) -> dict:
        import re
        return dict(re.findall(r"--([\w-]+): (#[0-9a-fA-F]{6});", block))

    def test_contrast(self):
        light = self._vars(self.css[self.css.index(":root {"):self.css.index("color-scheme: light")])
        dark = {**light, **self._vars(self.css[self.css.index(':root[data-theme="dark"]'):])}
        pairs = [("light warn on surface", light["warn"], light["surface"]),
                 ("light muted on bg", light["muted"], light["bg"]),
                 ("light primary-ink on primary", light["primary-ink"], light["primary"]),
                 ("dark primary-ink on primary", dark["primary-ink"], dark["primary"])]
        low = [(n, round(self._ratio(a, b), 2)) for n, a, b in pairs if self._ratio(a, b) < 4.5]
        self.assertEqual(low, [])


class UiHandlersTest(unittest.TestCase):
    """П59–П62, П64, П65: обработчики кнопок интерфейса."""

    js = panel_js.source()

    def test_buttons_report_errors(self):
        for head in ('$("#reapply").onclick', '$("#logout").onclick', '$("#s-gen").onclick'):
            self.assertRegex(_fn(self.js, head), r"catch \(e\) \{ if \(!\(e instanceof AuthError\)\) toast\(e\.message, true\)",
                             head)

    def test_login_closes_the_window_over_the_window(self):
        body = _fn(self.js, "function showLogin()")
        self.assertLess(body.index('$("#modal2").close()'), body.index("closeModal()"))

    def test_window_close_keeps_typed_fields(self):
        for head in ('$("#modal2").addEventListener("close"', '$("#modal").addEventListener("close"'):
            body = _fn(self.js, head)
            self.assertIn("renderKeep()", body, head)
            self.assertNotRegex(body, r"(?<!Keep)\brender\(\)", head)
        keep = _fn(self.js, "function renderKeep()")
        self.assertLess(keep.index("typedFields()"), keep.index("render()"))

    def test_empty_client_name_says_so(self):
        body = _fn(self.js, "  const go = async () => {\n    const name = $(\"#n-name\")")
        self.assertIn('toast(t("cl.name_required"), true)', body)
        self.assertIn('classList.add("invalid")', body)

    def test_client_save_not_twice(self):
        body = _fn(self.js, '$("#c-save").onclick')
        self.assertIn("if (btn.disabled) return;", body)
        self.assertIn("finally { btn.disabled = false; }", body)

    def test_overview_goes_through_gotab_and_opens_add(self):
        body = _fn(self.js, "bind.overview = () =>")
        self.assertIn("goTab(b.dataset.goto)", body)
        self.assertIn("editUpstream(null)", body)
        self.assertNotIn("tab = b.dataset.goto", body)
        self.assertIn('data-goto="exits" data-add', self.js)

    def test_non_json_answer_is_a_phrase(self):
        self.assertNotIn("`HTTP ${r.status}`", self.js)
        self.assertIn('t("err.http", { code: r.status })', self.js)

    def test_quota_field_marked(self):
        self.assertIn('data-field="quota_gb" id="c-quota"', self.js)
        from app.api import clients as api_clients
        from app.web import HTTPError

        class R:
            def json(self):
                return {"quota_gb": -5, "period": "month"}
        with self.assertRaises(HTTPError) as ctx:
            api_clients.put_limits(R(), "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
        self.assertEqual(ctx.exception.field, "quota_gb")

    def test_socks_errors_are_about_socks_fields(self):
        from app import checks
        from app.web import HTTPError
        with self.assertRaises(HTTPError) as ctx:
            checks.exit_config("socks5://proxy.example.com:99999")
        self.assertEqual((ctx.exception.detail.key, ctx.exception.field), ("cfg.socks_port", "socks"))
        with self.assertRaises(HTTPError) as ctx:
            checks.exit_config("[Interface]\nmusor")
        self.assertEqual(ctx.exception.field, "config")
        for i in ("u-sh", "u-sp", "u-su", "u-sw"):
            self.assertIn(f'data-field="socks" id="{i}"', self.js)

    def test_one_letter_does_not_switch_to_socks(self):
        src = _read("app", "static", "js", "exits.js")
        code = _fn(src, "function socksParse(text)") + "\n" + _fn(src, "const looksSocks = (s) =>") + ";\n"
        out = _node(code + 'for (const s of ["P", "PrivateKey", "AmneziaWG", "proxy.example.com", "1.2.3.4:1080",'
                    ' "socks5://h", "u:p@h:1080", "h:1080:u:p", "vpn://abc"]) console.log(s + "=" + looksSocks(s));')
        got = dict(x.split("=", 1) for x in out.split())
        self.assertEqual(got, {"P": "false", "PrivateKey": "false", "AmneziaWG": "false", "proxy.example.com": "false",
                               "1.2.3.4:1080": "true", "socks5://h": "true", "u:p@h:1080": "true",
                               "h:1080:u:p": "true", "vpn://abc": "false"})
        self.assertIn('if (kind === "socks5" && c && !/^socks(5h?)?:', src)


class TraceFixTest(unittest.TestCase):
    """П50: проверка маршрута — служебный адрес облака закрыт (а не «напрямую»); шаг балансировки с запасным
    «Напрямую — адрес» — фраза, а не сырой ключ «out.direct@…»."""

    def setUp(self):
        self.e = _panel().engine

    def test_cloud_addresses_block(self):
        for ip in ("169.254.169.254", "100.100.100.200"):
            r = self.e.trace(None, ip)
            self.assertEqual((r["result"], r["steps"][0].key), ("block", "tr.cloud_meta"), ip)
        self.assertEqual(self.e.trace(None, "192.168.1.1")["result"], "direct")

    def test_balance_step_direct_at(self):
        from app.engine import diag
        rule = {"id": "r_x", "lists": ["ru"], "outbound": "direct", "enabled": True, "balance": ["a", "b"],
                "balance_fb": "direct@198.51.100.7"}
        pol = {"rules": [rule], "own": False}
        with mock.patch.object(type(self.e), "policy_for", return_value=pol), \
                mock.patch.object(type(self.e), "rule_out", return_value=("direct@198.51.100.7", False)), \
                mock.patch.object(type(self.e), "domain_lists", return_value=set()), \
                mock.patch.object(self.e.matcher, "contains", return_value="5.0.0.0/8"):
            r = self.e.trace(None, "5.6.7.8")
        step = next(s for s in r["steps"] if s.key == "tr.rule_balance_new")
        self.assertEqual((step.p["exit"].key, step.p["exit"].p), ("out.direct_at", {"addr": "198.51.100.7"}))
        self.assertTrue(diag)

    def test_bot_says_closed(self):
        from app import uitext
        from app.i18n import Msg
        self.assertNotEqual(uitext.text("ru", Msg("tr.cloud_meta", ip="169.254.169.254")), "tr.cloud_meta")
        src = _read("app", "tgbot.py")
        self.assertIn('s.key == "tr.cloud_meta"', src)


class UninstallDisabledTest(unittest.TestCase):
    """П67: удаление панели «оставить сервер» называет клиентов, которых выключила панель: без неё они так и
    останутся выключенными, а включить их можно только правкой конфига."""

    def test_note(self):
        import contextlib
        import io
        from app import awgserver, uninstall
        sc = awgserver.parse("[Interface]\nPrivateKey = x\nListenPort = 1\nAddress = 10.8.1.1/24\n")
        sc.peers += [awgserver.Peer("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", allowed_ips="10.8.1.2/32", enabled=False),
                     awgserver.Peer("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", allowed_ips="10.8.1.3/32")]
        text = sc.render()

        class T:
            conf_path, name = "/opt/amnezia/awg/awg0.conf", "amnezia-awg2"

            def read_file(self, p):
                return text
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            uninstall.disabled_note(T())
        self.assertIn("1 client(s) turned off by the panel", out.getvalue())
        self.assertIn(awgserver.DISABLED_MARK, out.getvalue())
        self.assertIn("disabled_note(eng.target)", _read("app", "uninstall.py"))


class WorkflowInputsTest(unittest.TestCase):
    """П68: ввод ручного запуска workflow — только через окружение, не текстом в команду (под sudo)."""

    def test_no_inputs_in_commands(self):
        import re
        d = os.path.join(ROOT, ".github", "workflows")
        bad = []
        for name in sorted(os.listdir(d)):
            in_run = False
            for n, line in enumerate(_read(".github", "workflows", name).splitlines(), 1):
                s = line.strip()
                if re.match(r"(- )?run:", s):
                    in_run = True
                elif re.match(r"(- )?[\w-]+:", s) and not s.startswith(("run:", "- run:")) and in_run \
                        and len(line) - len(line.lstrip()) <= 8:
                    in_run = False
                if in_run and re.search(r"\$\{\{\s*(github\.event\.)?inputs\.", line):
                    bad.append(f"{name}:{n}")
        self.assertEqual(bad, [])


class UpgradeImagesCheckTest(unittest.TestCase):
    """П69: проверка «работает образ из IMAGES» в tests/e2e/upgrade.sh — только когда IMAGES есть (пустой ref совпадал
    с любым образом, и проверка проходила всегда)."""

    def test_guarded(self):
        text = _read("tests", "e2e", "upgrade.sh")
        i = text.index('grep -qF "${ref#*@}"')
        guard = text.rindex('if [ -f "$DIR/IMAGES" ]; then', 0, i)
        self.assertNotIn("\nfi\n", text[guard:i])
        self.assertIn('[ -n "$ref" ] || fail', text[guard:i])


# ---------------------------------------------------------------- оптимизация (Е) и дубли (Ж)
class PerfFixTest(unittest.TestCase):
    """Е: адреса разбираются один раз, ответы кодируются без копии на Python (те же байты), за проход — одна полная
    копия состояния, политики клиентов — один раз; скорость клиентов — только для вкладки «Клиенты»."""

    def setUp(self):
        self.p = _panel()
        self.e = self.p.engine

    def test_addresses_parsed_once(self):
        import ipaddress
        from app import srcaddr
        from app.api import state as api_state
        hosts = [f"198.51.100.{i}" for i in range(1, 17)]
        st0 = self.p.store.snapshot()["settings"].get("out_hosts")
        self.p.store.mutate(lambda s: s["settings"].update(out_hosts=hosts))
        self.addCleanup(lambda: self.p.store.mutate(lambda s: s["settings"].update(out_hosts=st0 or [])))
        srcaddr._ipv4.cache_clear()
        real = ipaddress.IPv4Address
        with mock.patch.object(srcaddr.ipaddress, "IPv4Address", side_effect=real) as spy:
            api_state._state_view()
            api_state._state_view()
        self.assertLessEqual(spy.call_count, 40)

    def test_json_same_bytes(self):
        from app import web
        from app.api import state as api_state
        from app.i18n import Msg, to_json
        obj = {"a": Msg("x.y", n=1, inner=Msg("z", s=[Msg("w"), (1, "т")])), "l": [Msg("q"), {"k": (Msg("r"),)}],
               1: "int key", "s": api_state._state_view()}
        self.assertEqual(json.dumps(obj, ensure_ascii=False, default=web._msg_json),
                         json.dumps(to_json(obj), ensure_ascii=False))
        with self.assertRaises(TypeError):
            json.dumps({"x": {1, 2}}, default=web._msg_json)
        self.assertNotIn("to_json(obj)", _read("app", "web.py"))

    def test_one_snapshot_per_pass(self):
        from app import store as store_mod
        self.e.reconcile()
        with mock.patch.object(store_mod.Store, "snapshot", autospec=True,
                               side_effect=store_mod.Store.snapshot) as spy:
            self.e.reconcile()
        self.assertEqual(spy.call_count, 1)

    def test_policies_once_per_pass(self):
        from app.engine import Engine
        got = []
        real = Engine._policies

        def spy(self_, st, labels=None):
            r = real(self_, st, labels)
            got.append((id(st), id(r[0])))
            return r
        self.p.store.mutate(lambda s: s["settings"].update(panel_dns=True))
        self.addCleanup(lambda: self.p.store.mutate(lambda s: s["settings"].pop("panel_dns", None)))
        with mock.patch.object(Engine, "_policies", spy):
            self.e.reconcile()
        pass_st = {s for s, _ in got}
        self.assertGreaterEqual(len(got), 2)
        self.assertEqual(len({r for s, r in got if s in pass_st}), 1)       # один и тот же результат: посчитан раз

    def test_hold_rules_not_from_the_pass(self):
        """Правила «до панели» (выход → блок) не берутся из запомненных политик прохода."""
        import threading
        st = self.p.store.snapshot()
        self.e._pol_memo = {"st": st, "tid": threading.get_ident(), "v": {}}
        self.addCleanup(setattr, self.e, "_pol_memo", None)
        normal = self.e._policies(st)
        self.e._holding = threading.get_ident()
        try:
            held = self.e._policies(st)
        finally:
            self.e._holding = None
        self.assertIsNot(held, normal)

    def test_speeds_only_for_clients_tab(self):
        from app.api import state as api_state

        class R:
            def __init__(self, h):
                self.headers = h
        with mock.patch.object(self.e, "client_speeds", return_value={"k": [1, 2]}) as cs:
            self.assertEqual(api_state.get_state(R({}))["speeds"], {})
            cs.assert_not_called()
            self.assertEqual(api_state.get_state(R({"X-Speeds": "1"}))["speeds"], {"k": [1, 2]})
        body = _fn(panel_js.source(), "async function refresh(")
        self.assertIn('if (tab === "clients") hdr["X-Speeds"] = "1";', body)


class DedupeTest(unittest.TestCase):
    """Ж: одна проверка галочки, один «пройти скорее», MSS clamp — одной функцией."""

    def test_one_flag_check(self):
        from app import checks
        from app.web import HTTPError
        self.assertIn("users.check_flag(v)", _fn(_read("app", "checks.py"), "def flag("))
        with self.assertRaises(HTTPError):
            checks.flag("false")
        self.assertIs(checks.flag(None, True), True)

    def test_one_trigger(self):
        from app.engine import Engine
        self.assertFalse(hasattr(Engine, "reconcile_soon"))

    def test_mss_once(self):
        from app import nftgen
        src = _read("app", "nftgen.py")
        self.assertEqual(src.count("tcp option maxseg size set"), 1)
        r = nftgen.generate("awg0", {}, [{"num": 1, "snat": "10.9.0.2", "mtu": 1280}],
                            {"rules": [], "default": 1, "domain": []}, {}, 1234, frozenset(), quic=True)
        self.assertEqual(r.count("tcp option maxseg size > 1240 tcp option maxseg size set 1240"), 2)


# ---------------------------------------------------------------- тесты, которые проходили со сломанной защитой (Ж)
from test_v121g import Isolated as _Isolated, Req as _GReq  # noqa: E402


class SignInGuardsTest(_Isolated):
    """Вход (web.md M13, M28, N3, N15): вторая смена пароля гасит сессии; текущая вкладка после смены входит;
    2FA с неверным кодом не включается; cookie с не-ASCII — просто отказ."""

    def test_second_password_change_logs_out(self):
        from app.api import auth
        auth.set_password("first-password-1")
        s = auth.make_session()
        auth.set_password("second-password-2")
        self.assertFalse(auth.check_session(s))

    def test_this_tab_stays_signed_in(self):
        from app.api import auth
        r = _GReq({"current": os.environ["PANEL_PASSWORD"], "new": "a-brand-new-pass"})
        auth.change_password(r)
        cookie = [v for n, v, _ in r.set_cookies if n == auth.COOKIE]
        self.assertTrue(cookie and auth.check_session(cookie[-1]))

    def test_2fa_wrong_code_not_enabled(self):
        from app import totp
        from app.api import auth
        from app.web import HTTPError
        sec = auth.totp_setup(_GReq())["secret"]
        good = totp.match(sec, "000000")
        code = "000000" if good is None else "111111"
        with self.assertRaises(HTTPError) as cm:
            auth.totp_enable(_GReq({"password": os.environ["PANEL_PASSWORD"], "code": code}))
        self.assertEqual(cm.exception.code, 403)
        self.assertIsNone(totp.load())

    def test_non_ascii_cookie(self):
        from app.api import auth
        self.assertFalse(auth.check_session("1.ab.\xe9"))


class DnsGuardsTest(unittest.TestCase):
    """DNS на сервере (dns.md M15/M16, M18): чужой адрес — без ответа; HTTPS/SVCB имени правила — «записей нет»."""

    def _proxy(self):
        from app import dnsproxy
        d = tempfile.mkdtemp()
        lst = os.path.join(d, "l1.txt")
        with open(lst, "w") as f:
            f.write("youtube.com\n")
        conf = os.path.join(d, "dns.json")
        with open(conf, "w") as f:
            json.dump({"listen": "10.8.1.1", "port": 53, "clients": "10.8.1.0/24", "upstreams": ["1.1.1.1"],
                       "default": {"mark": 0, "tcp": False}, "routes": {},
                       "dom": {"lists": {"l1": lst}, "policies": {"p_global": [[["l1"], {"mark": 0x2001, "tcp": False}]]},
                               "clients": {}, "set": None}}, f)
        p = dnsproxy.Proxy(conf)
        p.asked = []

        async def fwd(query, q, mark, tcp, servers=()):
            p.asked.append((q["name"].rstrip("."), q["qtype"]))
            from tests.test_v115 import a_reply
            return a_reply(query, ["203.0.113.9"])
        p.forward = fwd
        return p

    def test_https_records_of_rule_names(self):
        from app import dnsproxy
        from tests.test_v115 import q_msg
        p = self._proxy()

        async def go():
            out = []
            for name, qt in (("www.youtube.com", 65), ("youtube.com", 64), ("example.org", 65)):
                m = q_msg(name, qtype=qt)
                out.append(await p.resolve(m, dnsproxy.parse_query(m), "10.8.1.5"))
            return out
        r = asyncio.run(go())
        for reply in r[:2]:
            self.assertEqual((reply[3] & 0xF, struct_unpack_ancount(reply)), (0, 0))
        self.assertEqual(p.asked, [("example.org", 65)])

    def test_foreign_client_address(self):
        from app import dnsproxy
        from tests.test_v115 import q_msg
        p = self._proxy()
        srv = dnsproxy.UDPServer(p)
        sent = []

        class T:
            def sendto(self, data, addr):
                sent.append(addr)
        srv.connection_made(T())

        async def go():
            srv.datagram_received(q_msg("example.org"), ("192.0.2.9", 5353))
            srv.datagram_received(q_msg("example.org"), ("10.8.1.5", 5353))
            await asyncio.sleep(0.05)

            class W:
                def get_extra_info(self, k):
                    return ("192.0.2.9", 4000)

                def write(self, data):
                    sent.append("tcp")

                async def drain(self):
                    pass

                def close(self):
                    pass
            import struct
            reader = asyncio.StreamReader()
            m = q_msg("example.org")
            reader.feed_data(struct.pack("!H", len(m)) + m)
            reader.feed_eof()
            await p.handle_tcp(reader, W())
        asyncio.run(go())
        self.assertEqual(sent, [("10.8.1.5", 5353)])
        self.assertEqual(p.asked, [("example.org", 1)])          # TCP с чужого адреса — не спрошен


def struct_unpack_ancount(reply: bytes) -> int:
    import struct
    return struct.unpack("!H", reply[6:8])[0]


class StrictInEngineTest(unittest.TestCase):
    """invariants.md Q_strict: «Правила по доменам не работают — блокировать»: посредник лежит, галочка стоит —
    политика с правилами по доменам в движке уходит в блок (раньше это проверял только nftgen)."""

    def test_strict(self):
        p = _panel()
        e = p.engine
        st0 = p.store.snapshot()
        self.addCleanup(lambda: p.store.mutate(lambda s: s.update(routing=st0["routing"], lists=st0["lists"])))
        p.store.mutate(lambda s: s["lists"].append({"id": "dstrict", "kind": "domains", "name": "d", "source": ""}))
        p.store.mutate(lambda s: s["routing"].update(rules=[
            {"id": "rs", "lists": ["dstrict"], "outbound": "block", "enabled": True, "comment": ""}], default="direct",
            strict=True))
        st = p.store.snapshot()
        e.reconcile()
        block = "\tchain p_global {\n\t\tgoto o_block\n\t}"
        self.assertIn(block, e.build_ruleset(e.target, st, None))
        self.assertNotIn(block, e.build_ruleset(e.target, st, 1234))
        st["routing"]["strict"] = False
        self.assertNotIn(block, e.build_ruleset(e.target, st, None))


class StateBakFirstWriteTest(unittest.TestCase):
    """invariants.md F4: state.json повреждён, а первая запись после запуска не удалась (нет места) — следующий
    запуск всё равно берёт прежнюю версию, а не пустые настройки (все клиенты мимо выходов)."""

    def test_first_write_fails(self):
        from app import store
        d = tempfile.mkdtemp()
        path = os.path.join(d, "state.json")
        s = store.Store(path)
        s.mutate(lambda st: st["settings"].update(mark=1))
        s.mutate(lambda st: st["settings"].update(mark=2))
        with open(path, "w") as f:
            f.write('{"version": 1, "routing": {"default": "dir')
        with mock.patch.object(store.Store, "_write", side_effect=OSError(28, "No space left on device")), \
                self.assertLogs("awgr.store", "WARNING"):
            try:
                store.Store(path)
            except OSError:
                pass
        self.assertEqual(store.Store(path).state["settings"].get("mark"), 1)


class UiEscapeTest(unittest.TestCase):
    """ui.md: имена (выходов, клиентов, списков) в разметке интерфейса — через esc(): имя «<b>» или «<a href>» не
    становится разметкой. Подстановка свойства .name без esc() — только в известных местах (названия языков; подписи
    выбора клиента, которые экранирует ruleWindow)."""

    def test_names_escaped(self):
        import re
        ok = {"v.name", "c.name || c.ip"}
        bad = [m.group(1) for m in re.finditer(r"\$\{([^{}]*\.name\b[^{}]*)\}", panel_js.source())
               if "esc(" not in m.group(1) and m.group(1) not in ok]
        self.assertEqual(bad, [])
