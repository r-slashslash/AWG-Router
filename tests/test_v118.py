"""1.18.0: установщик спрашивает порт панели (Enter — случайный свободный), как порт AmneziaWG.

python3 -m unittest discover tests
"""
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def install_sh() -> str:
    with open(os.path.join(ROOT, "install.sh"), encoding="utf-8") as f:
        return f.read()


def func(name: str) -> str:
    """Функция из install.sh: однострочная (`f() { …; }`) или многострочная до `}` в начале строки."""
    text = install_sh()
    one = re.search(rf"^{name}\(\) \{{[^\n]*\}}\n", text, re.M)
    if one:
        return one.group(0)
    m = re.search(rf"^{name}\(\) \{{.*?^\}}\n", text, re.S | re.M)
    assert m, name
    return m.group(0)


def unsafe_block() -> str:
    m = re.search(r"^UNSAFE_PORTS=.*?\n^unsafe_port\(\).*?\n", install_sh(), re.S | re.M)
    assert m
    return m.group(0)


def port_section() -> str:
    """Выбор порта панели: от чтения .env до конца вопроса (поиск по строкам, без регулярных выражений)."""
    text = install_sh()
    start = text.index('PANEL_PORT="$(envget PANEL_PORT)"\n')
    end = text.index("\nfi\n", text.index('if [ -z "$CUR_PORT" ]', start)) + len("\nfi\n")
    return text[start:end]


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class PanelPortTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir)
        # ss: «слушают» 4821 (tcp) и 5353 (udp)
        with open(os.path.join(bindir, "ss"), "w") as f:
            f.write("#!/bin/sh\necho 'tcp LISTEN 0 4096 0.0.0.0:4821 0.0.0.0:*'\n"
                    "echo 'udp UNCONN 0 0 [::]:5353 [::]:*'\n")
        os.chmod(os.path.join(bindir, "ss"), 0o755)
        self.env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
        self.env.pop("AWGR_PORT", None)
        self.envfile = os.path.join(self.tmp, ".env")

    def bash(self, body, **env):
        return subprocess.run(["bash", "-uo", "pipefail", "-c", body], env={**self.env, **env},
                              capture_output=True, text=True, timeout=30)

    # ---------------------------------------------------------------- проверка порта
    def problem(self, port, current=""):
        body = func("port_busy") + unsafe_block() + func("panel_port_problem") + \
            f'panel_port_problem "{port}" "{current}"'
        r = self.bash(body)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_good_ports(self):
        for p in ("1024", "5000", "9999", "65535"):
            with self.subTest(p=p):
                self.assertEqual(self.problem(p), "")

    def test_not_a_port(self):
        for p in ("", "abc", "80", "443", "1023", "65536", "50 00", "5000;id"):
            with self.subTest(p=p):
                self.assertIn("from 1024 to 65535", self.problem(p))

    def test_browsers_refuse(self):
        self.assertIn("Browsers refuse", self.problem("6697"))
        self.assertIn("Browsers refuse", self.problem("10080"))

    def test_domain_rules_port(self):
        self.assertIn("10443", self.problem("10443"))

    def test_busy(self):
        self.assertIn("in use", self.problem("4821"))
        self.assertIn("in use", self.problem("5353"))                  # и UDP тоже

    def test_busy_with_long_socket_list(self):
        """Занятый порт в начале длинного списка должен отклоняться при включённом pipefail."""
        with open(os.path.join(self.tmp, "bin", "ss"), "w") as f:
            f.write("#!/bin/sh\nawk 'BEGIN {\n"
                    ' print "tcp LISTEN 0 4096 0.0.0.0:4821 0.0.0.0:*"\n'
                    ' for (i = 0; i < 10000; i++) print "udp UNCONN 0 0 [::]:5353 [::]:*"\n'
                    "}'\n")
        self.assertIn("Port 4821 is in use", self.problem("4821"))

    def test_own_port_is_allowed(self):
        """При --reconfigure текущий порт занят самой панелью — его можно оставить."""
        self.assertEqual(self.problem("4821", current="4821"), "")

    # ---------------------------------------------------------------- выбор порта целиком
    def choose(self, answers=(), env_port="", version="1.17.1", reconf=0, **env):
        with open(self.envfile, "w") as f:
            if env_port:
                f.write(f"PANEL_PORT={env_port}\nAWGR_VERSION={version}\n")
        answers_file = os.path.join(self.tmp, "answers")
        with open(answers_file, "w") as f:
            f.write("".join(a + "\n" for a in answers))
        stubs = textwrap.dedent(f"""\
            ENV_FILE="{self.envfile}"; RECONF={reconf}
            envget() {{ [ -f "$ENV_FILE" ] && grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true; }}
            random_port() {{ echo 7777; }}
            die() {{ echo "DIE $1"; exit 1; }}
            # ask: ответы по одному из файла; кончились — Enter (значение по умолчанию)
            ask() {{ printf '%s' "$1"; REPLY="$(head -n 1 "{answers_file}")"; sed -i 1d "{answers_file}"
                    REPLY="${{REPLY:-$2}}"; echo "$REPLY"; }}
            """)
        body = stubs + func("port_busy") + unsafe_block() + func("panel_port_problem") + port_section() + \
            'echo "PORT=$PANEL_PORT"'
        r = self.bash(body, **env)
        m = re.search(r"PORT=(\S*)", r.stdout)
        return r, (m.group(1) if m else None)

    def test_new_install_enter_takes_the_random_one(self):
        r, port = self.choose([""])
        self.assertEqual(port, "7777")
        self.assertIn("Panel port [7777]: ", r.stdout)

    def test_new_install_own_port_after_mistakes(self):
        r, port = self.choose(["abc", "4821", "6697", "5000"])
        self.assertEqual(port, "5000")
        for why in ("from 1024 to 65535", "Port 4821 is in use", "Browsers refuse"):
            self.assertIn(why, r.stdout)

    def test_new_install_without_a_terminal(self):
        r, port = self.choose([])                                     # ответов нет — как без терминала
        self.assertEqual(port, "7777")

    def test_awgr_port(self):
        r, port = self.choose(["9000"], AWGR_PORT="5001")
        self.assertEqual(port, "5001")
        self.assertNotIn("Panel port [", r.stdout)                    # не спрашивает
        r, port = self.choose([], AWGR_PORT="4821")
        self.assertIn("DIE AWGR_PORT=4821: Port 4821 is in use", r.stdout)
        self.assertNotEqual(r.returncode, 0)

    def test_update_keeps_the_port_and_does_not_ask(self):
        r, port = self.choose(["5000"], env_port="4821")
        self.assertEqual(port, "4821")
        self.assertNotIn("Panel port [", r.stdout)

    def test_reconfigure_offers_the_current_port(self):
        r, port = self.choose([""], env_port="4821", reconf=1)
        self.assertEqual(port, "4821")                                # свой порт «занят» самой панелью
        self.assertIn("Panel port [4821]: ", r.stdout)
        r, port = self.choose(["5000"], env_port="4821", reconf=1)
        self.assertEqual(port, "5000")

    def test_old_8080_still_moves_without_asking_on_update(self):
        r, port = self.choose([], env_port="8080")
        self.assertEqual(port, "7777")
        self.assertNotIn("Panel port [", r.stdout)


if __name__ == "__main__":
    unittest.main()
