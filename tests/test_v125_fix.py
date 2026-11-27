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
