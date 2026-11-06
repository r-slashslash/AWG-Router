"""1.17.0: готовые образы из GHCR вместо сборки на сервере (issue #8).

Сборка ходит в dl-cdn.alpinelinux.org и в GitHub по git, которые фильтруются в России, Китае, Иране.
release.yml публикует образы и пишет их digest в файл IMAGES архива; install.sh скачивает образ по
digest и собирает его сам, только если скачать не вышло.

python3 -m unittest discover tests
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

from tests import test_v1106

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DIGEST = "sha256:" + "ab" * 32
PANEL = "ghcr.io/r-slashslash/awg-router@" + DIGEST
SERVER = "ghcr.io/r-slashslash/awg-router@sha256:" + "cd" * 32


def install_sh() -> str:
    with open(os.path.join(ROOT, "install.sh"), encoding="utf-8") as f:
        return f.read()


def func(name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{.*?^\}}\n", install_sh(), re.S | re.M)
    assert m, name
    return m.group(0)


def image_section() -> str:
    """Часть install.sh, которая решает: скачать образ панели или собрать."""
    m = re.search(r"^OLD_IMAGE_ID=.*?(?=^# -+ AmneziaWG in a container)", install_sh(), re.S | re.M)
    assert m
    return m.group(0)


@unittest.skipUnless(shutil.which("bash") and shutil.which("timeout"), "needs bash and timeout")
class InstallerImagesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        os.makedirs(os.path.join(self.tmp, "data"))
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir)
        # docker: пишет вызов в лог; PULL=ok|fail|hang|nomatch; inspect печатает OLD_ID
        with open(os.path.join(bindir, "docker"), "w") as f:
            f.write(textwrap.dedent("""\
                #!/usr/bin/env bash
                echo "docker $*" >> "$DOCKER_LOG"
                case "$1 $2" in
                  "image inspect") [ -n "${OLD_ID:-}" ] && echo "$OLD_ID"; exit 0 ;;
                esac
                case "$1" in
                  pull) case "$PULL" in
                          ok) echo "Status: Downloaded newer image"; exit 0 ;;
                          hang) sleep 5; exit 0 ;;
                          nomatch) echo "no matching manifest for linux/arm/v7 in the manifest list entries" >&2; exit 1 ;;
                          *) echo "Error response from daemon: Get \\"https://ghcr.io/v2/\\": net/http: request canceled" >&2; exit 1 ;;
                        esac ;;
                  tag) exit 0 ;;
                  build) echo "built"; exit 0 ;;
                esac
                """))
        os.chmod(os.path.join(bindir, "docker"), 0o755)
        self.log = os.path.join(self.tmp, "docker.log")
        self.env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "DOCKER_LOG": self.log,
                    "PULL": "ok"}
        for k in ("AWGR_BUILD", "AWGR_PULL_TIMEOUT"):
            self.env.pop(k, None)

    def images(self, text):
        with open(os.path.join(self.tmp, "IMAGES"), "w") as f:
            f.write(text)

    def bash(self, body, **env):
        open(self.log, "w").close()
        r = subprocess.run(["bash", "-uo", "pipefail", "-c", f'DIR="{self.tmp}"\n{body}'],
                           env={**self.env, **env}, capture_output=True, text=True, timeout=30)
        with open(self.log) as f:
            calls = [ln.strip() for ln in f if ln.strip()]
        return r, calls

    # ---------------------------------------------------------- image_ref
    def ref(self, key="PANEL_IMAGE", **env):
        r, _ = self.bash(func("image_ref") + f"image_ref {key}", **env)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_ref_from_images(self):
        self.images(f"PANEL_IMAGE={PANEL}\nSERVER_IMAGE={SERVER}\n")
        self.assertEqual(self.ref(), PANEL)
        self.assertEqual(self.ref("SERVER_IMAGE"), SERVER)

    def test_no_ref_without_images_or_when_asked_to_build(self):
        self.assertEqual(self.ref(), "")                               # архив ветки: файла нет
        self.images(f"PANEL_IMAGE={PANEL}\n")
        self.assertEqual(self.ref(AWGR_BUILD="1"), "")

    def test_only_pinned_references(self):
        """Тег (его можно перевесить) или что-то похожее на команду — не ссылка."""
        for bad in ("ghcr.io/x/awg-router:1.17.0", "ghcr.io/x/awg-router@sha256:abc",
                    f"{PANEL}; rm -rf /", f"$(id){PANEL}", "Ghcr.io/X@" + DIGEST):
            with self.subTest(bad=bad):
                self.images(f"PANEL_IMAGE={bad}\n")
                self.assertEqual(self.ref(), "")

    # ---------------------------------------------------------- pull_image
    def pull(self, ref=PANEL, **env):
        logf = os.path.join(self.tmp, "pull.log")
        r, calls = self.bash(func("pull_image") + f'pull_image "{ref}" awg-router:latest "{logf}"', **env)
        with open(logf) if os.path.exists(logf) else open(os.devnull) as f:
            return r.returncode, calls, f.read()

    def test_pull_and_tag(self):
        rc, calls, _ = self.pull()
        self.assertEqual(rc, 0)
        self.assertEqual(calls, [f"docker pull {PANEL}", f"docker tag {PANEL} awg-router:latest"])

    def test_failed_pull_is_not_tagged(self):
        for mode in ("fail", "nomatch"):
            with self.subTest(mode=mode):
                rc, calls, log = self.pull(PULL=mode)
                self.assertNotEqual(rc, 0)
                self.assertEqual(calls, [f"docker pull {PANEL}"])
                self.assertTrue(log.strip())

    def test_registry_that_hangs(self):
        rc, calls, log = self.pull(PULL="hang", AWGR_PULL_TIMEOUT="1")
        self.assertNotEqual(rc, 0)
        self.assertNotIn(f"docker tag {PANEL} awg-router:latest", calls)
        self.assertIn("no answer in 1 s", log)

    def test_empty_reference(self):
        rc, calls, _ = self.pull(ref="")
        self.assertNotEqual(rc, 0)
        self.assertEqual(calls, [])

    # ---------------------------------------------------------- скачать или собрать
    def run_section(self, **env):
        stubs = textwrap.dedent("""\
            IMAGE=awg-router:latest
            step() { echo "STEP $1"; }; ok() { echo "OK $1"; }; warn() { echo "WARN $1"; }
            die() { echo "DIE $1"; exit 1; }; buildx_ver() { echo 0.38.1; }
            """)
        body = stubs + "".join(func(n) for n in ("build_image", "image_ref", "no_ready_image", "pull_image",
                                                 "last_line", "with_spinner")) + image_section()
        r, calls = self.bash(body, **env)
        return r, [c.split()[1] for c in calls if c.split()[1] != "image"]

    def test_ready_image_is_used(self):
        self.images(f"PANEL_IMAGE={PANEL}\n")
        r, calls = self.run_section()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(calls, ["pull", "tag"])
        self.assertIn("STEP Downloading the panel", r.stdout)

    def test_falls_back_to_build(self):
        self.images(f"PANEL_IMAGE={PANEL}\n")
        r, calls = self.run_section(PULL="fail")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(calls, ["pull", "build"])
        self.assertIn("WARN Could not download the ready image (Error response from daemon", r.stdout)
        self.assertIn("STEP Building the panel", r.stdout)

    def test_builds_without_images(self):
        """1.17.1: сборка без IMAGES не молчит — иначе обновление «висит» на apk без объяснений (#8)."""
        r, calls = self.run_section()
        self.assertEqual(calls, ["build"])
        self.assertIn("WARN This download has no ready image of the panel (no IMAGES file", r.stdout)
        self.assertIn("dl-cdn.alpinelinux.org", r.stdout)

    def test_asked_to_build_is_quiet(self):
        self.images(f"PANEL_IMAGE={PANEL}\n")
        r, calls = self.run_section(AWGR_BUILD="1")
        self.assertEqual(calls, ["build"])
        self.assertNotIn("WARN", r.stdout)
        os.remove(os.path.join(self.tmp, "IMAGES"))
        r, calls = self.run_section(AWGR_BUILD="1")
        self.assertNotIn("WARN", r.stdout)

    def test_ready_image_is_quiet(self):
        self.images(f"PANEL_IMAGE={PANEL}\n")
        r, _ = self.run_section()
        self.assertNotIn("WARN", r.stdout)


@unittest.skipUnless(shutil.which("bash") and shutil.which("tar"), "needs bash and tar")
class StaleImagesTest(unittest.TestCase):
    """IMAGES прежнего релиза не должен пережить его: у архива ветки файла нет, образ собирается."""

    def test_branch_update_removes_old_images(self):
        h = test_v1106.FetchCodeTest("test_release_first")
        h.setUp()
        self.addCleanup(h.doCleanups)
        dest = os.path.join(h.tmp, "dest")
        os.makedirs(dest)
        with open(os.path.join(dest, "IMAGES"), "w") as f:
            f.write(f"PANEL_IMAGE={PANEL}\n")
        script = f'REPO=o/r; BRANCH=dev; AWGR_SRC_URL=""\n{h.func}\nfetch_code "{dest}"'
        open(h.env["CURL_LOG"], "w").close()
        r = subprocess.run(["bash", "-uo", "pipefail", "-c", script],
                           env={**h.env, "CODES": "", "SUM": h.sum}, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(dest, "marker")))
        self.assertFalse(os.path.exists(os.path.join(dest, "IMAGES")))


class WorkflowImagesTest(unittest.TestCase):
    """release.yml читается как текст: PyYAML нет в стандартной библиотеке."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, ".github", "workflows", "release.yml"), encoding="utf-8") as f:
            cls.text = f.read()
        draft = cls.text[cls.text.index("  draft:"):cls.text.index("  published:")]
        cls.steps = {}
        for block in re.split(r"^      - ", draft, flags=re.M)[1:]:
            m = re.match(r"(?:name|uses): (.+)", block)
            cls.steps[m.group(1).strip()] = block

    def test_may_push_packages(self):
        perms = self.text[self.text.index("permissions:"):self.text.index("concurrency:")]
        self.assertRegex(perms, r"\n  packages: write")

    def test_images_and_platforms(self):
        panel = self.steps["Panel image (amd64, arm64)"]
        self.assertIn("context: .\n", panel)
        plat = re.search(r"platforms: (\S+)", panel).group(1)
        self.assertEqual(set(plat.split(",")), {"linux/amd64", "linux/arm64"})
        server = self.steps["AmneziaWG server image (amd64)"]
        self.assertIn("context: awg-server\n", server)
        self.assertIn("platforms: linux/amd64\n", server)
        for b in (panel, server):
            self.assertIn("push: ${{ steps.v.outputs.state != 'published' }}", b)

    def test_check_run_publishes_nothing(self):
        """Ручной запуск check собирает образы, но не пушит их и не трогает архив и черновик."""
        self.assertIn("      check:\n", self.text)
        for name in ("Panel image (amd64, arm64)", "AmneziaWG server image (amd64)"):
            self.assertIn("|| inputs.check", self.steps[name])
        for name in ("Anyone can pull the images", "Build the archive", "Create or refresh the draft",
                     "Release notes (4 languages)"):
            self.assertIn("if: steps.v.outputs.state != 'published'\n", self.steps[name])
            self.assertNotIn("inputs.check", self.steps[name])

    def test_archive_after_images_and_carries_them(self):
        names = list(self.steps)
        self.assertLess(names.index("AmneziaWG server image (amd64)"), names.index("Build the archive"))
        self.assertLess(names.index("Build the archive"), names.index("Create or refresh the draft"))
        run = self.steps["Build the archive"]
        self.assertIn("--add-file=", run)
        self.assertIn("awg-router/IMAGES", run)
        for key in ("PANEL_IMAGE=", "SERVER_IMAGE="):
            self.assertIn(key, run)

    def test_same_reference_format_as_installer(self):
        """Workflow не должен записать ссылку, которую install.sh отбросит."""
        wf_re = re.search(r"=~ \^(\S+)\$ \]\]", self.steps["Build the archive"]).group(1)
        sh_re = re.search(r"grep -E '\^(\S+)\$'", func("image_ref")).group(1)
        self.assertEqual(wf_re, sh_re)

    def published_job(self) -> str:
        return self.text[self.text.index("  published:"):]

    @unittest.skipUnless(shutil.which("jq"), "needs jq")
    def test_published_job_keeps_the_draft_archive(self):
        """1.17.1: при публикации архив черновика (с IMAGES) не перезаливается (#8). До этого case
        требовал два пробела между именами, никогда не срабатывал, и архив заменялся архивом без IMAGES."""
        flt = re.search(r"ASSETS_PRESENT: '(.+)'", self.published_job()).group(1)

        def present(*names):
            doc = json.dumps({"assets": [{"name": n} for n in names]})
            return subprocess.run(["jq", "-r", flt], input=doc, capture_output=True, text=True,
                                  check=True).stdout.strip()
        self.assertEqual(present("awg-router.tar.gz", "awg-router.tar.gz.sha256"), "true")
        self.assertEqual(present("awg-router.tar.gz.sha256", "awg-router.tar.gz"), "true")
        self.assertEqual(present("awg-router.tar.gz"), "false")
        self.assertEqual(present("awg-router.tar.gz.sha256"), "false")       # не путать с префиксом
        self.assertEqual(present(), "false")
        self.assertNotIn('case " $have "', self.published_job())

    def test_published_job_checks_images(self):
        job = self.published_job()
        self.assertIn("gh release download", job)
        self.assertIn("awg-router/IMAGES", job)

    def test_dockerfiles_name_the_repository(self):
        for p in ("Dockerfile", os.path.join("awg-server", "Dockerfile")):
            with open(os.path.join(ROOT, p), encoding="utf-8") as f:
                self.assertIn("org.opencontainers.image.source", f.read(), p)


if __name__ == "__main__":
    unittest.main()
