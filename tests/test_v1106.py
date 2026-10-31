"""1.10.6: код ставится из архива последнего релиза (у него есть счётчик скачиваний),
и версия для «доступно обновление» берётся оттуда же.

python3 -m unittest discover tests
"""
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import updates  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


class FakeResp:
    def __init__(self, url="", body=b""):
        self.url, self.body = url, body

    def geturl(self):
        return self.url

    def read(self, n=-1):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def opener(release=None, branch=None):
    """urlopen-заглушка: release — куда переадресует /releases/latest, branch — версия в version.py."""
    calls = []

    def urlopen(req, timeout=None):
        calls.append((req.get_method(), req.full_url))
        if req.full_url == updates.RELEASE_URL:
            if release is None:
                raise OSError("unreachable")
            return FakeResp(url=release)
        if req.full_url == updates.URL:
            if branch is None:
                raise OSError("unreachable")
            return FakeResp(body=f'VERSION = "{branch}"\n'.encode())
        raise AssertionError(req.full_url)
    return urlopen, calls


class UpdateCheckTest(unittest.TestCase):
    def test_latest_release_wins(self):
        urlopen, calls = opener(release="https://github.com/r-slashslash/AWG-Router/releases/tag/v9.1.2",
                                branch="9.9.9")
        with mock.patch("urllib.request.urlopen", urlopen):
            self.assertEqual(updates.latest_version(), "9.1.2")
        self.assertEqual(calls, [("HEAD", updates.RELEASE_URL)])   # version.py не нужен

    def test_no_release_falls_back_to_branch(self):
        # /releases/latest без релизов переадресует на список релизов — версии в адресе нет
        for release in ("https://github.com/r-slashslash/AWG-Router/releases", None):
            urlopen, _ = opener(release=release, branch="1.2.3")
            with mock.patch("urllib.request.urlopen", urlopen):
                self.assertEqual(updates.latest_version(), "1.2.3")

    def test_other_branch_reads_only_version_py(self):
        urlopen, calls = opener(release="https://github.com/x/y/releases/tag/v9.0.0", branch="2.0.0")
        with mock.patch("urllib.request.urlopen", urlopen), mock.patch.object(updates, "BRANCH", "dev"):
            self.assertEqual(updates.latest_version(), "2.0.0")
        self.assertEqual([c[0] for c in calls], ["GET"])

    def test_checker_status(self):
        urlopen, _ = opener(release="https://github.com/a/b/releases/tag/v999.0.0")
        uc = updates.UpdateChecker()
        with mock.patch("urllib.request.urlopen", urlopen):
            uc.check()
        self.assertEqual(uc.latest, "999.0.0")
        self.assertTrue(uc.available)
        self.assertIsNone(uc.error)
        urlopen, _ = opener()                                   # GitHub не отвечает вовсе
        with mock.patch("urllib.request.urlopen", urlopen):
            uc.check()
        self.assertTrue(uc.error)
        self.assertEqual(uc.latest, "999.0.0")                  # прежнее значение остаётся


@unittest.skipUnless(shutil.which("bash") and shutil.which("tar"), "needs bash and tar")
class FetchCodeTest(unittest.TestCase):
    """fetch_code из install.sh с подменённым curl: какие адреса и в каком порядке."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        src = os.path.join(self.tmp, "src", "awg-router")
        os.makedirs(src)
        with open(os.path.join(src, "marker"), "w") as f:
            f.write("ok")
        self.tgz = os.path.join(self.tmp, "good.tgz")
        with tarfile.open(self.tgz, "w:gz") as t:
            t.add(src, arcname="awg-router")
        with open(os.path.join(ROOT, "install.sh")) as f:
            m = re.search(r"^fetch_code\(\) \{.*?^\}\n", f.read(), re.S | re.M)
        self.func = m.group(0)
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir)
        # curl: пишет адрес в лог; адреса из FAIL — ошибка, остальные отдают архив
        with open(os.path.join(bindir, "curl"), "w") as f:
            f.write(textwrap.dedent("""\
                #!/usr/bin/env bash
                out=""; url=""
                while [ $# -gt 0 ]; do
                  case "$1" in -o) out="$2"; shift 2 ;; --retry|--max-time) shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac
                done
                echo "$url" >> "$CURL_LOG"
                for u in $FAIL; do [ "$u" = "$url" ] && exit 22; done
                cp "$GOOD_TGZ" "$out"
                """))
        os.chmod(os.path.join(bindir, "curl"), 0o755)
        self.env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "GOOD_TGZ": self.tgz,
                    "CURL_LOG": os.path.join(self.tmp, "curl.log")}

    def run_fetch(self, branch="main", src_url="", fail=""):
        dest = os.path.join(self.tmp, "dest")
        shutil.rmtree(dest, ignore_errors=True)
        open(self.env["CURL_LOG"], "w").close()
        script = (f'REPO=o/r; BRANCH={branch}; AWGR_SRC_URL="{src_url}"\n{self.func}\n'
                  f'fetch_code "{dest}"')
        r = subprocess.run(["bash", "-uo", "pipefail", "-c", script], env={**self.env, "FAIL": fail},
                           capture_output=True, text=True)
        with open(self.env["CURL_LOG"]) as f:
            urls = f.read().split()
        ok = os.path.exists(os.path.join(dest, "marker"))
        return r.returncode, urls, ok

    REL = "https://github.com/o/r/releases/latest/download/awg-router.tar.gz"
    MAIN = "https://codeload.github.com/o/r/tar.gz/refs/heads/main"

    def test_release_first(self):
        rc, urls, ok = self.run_fetch()
        self.assertEqual((rc, urls, ok), (0, [self.REL], True))

    def test_branch_when_release_missing(self):
        rc, urls, ok = self.run_fetch(fail=self.REL)
        self.assertEqual((rc, urls, ok), (0, [self.REL, self.MAIN], True))

    def test_both_fail(self):
        rc, urls, ok = self.run_fetch(fail=f"{self.REL} {self.MAIN}")
        self.assertNotEqual(rc, 0)
        self.assertFalse(ok)

    def test_other_branch_and_override(self):
        rc, urls, _ = self.run_fetch(branch="dev")
        self.assertEqual(urls, ["https://codeload.github.com/o/r/tar.gz/refs/heads/dev"])
        rc, urls, _ = self.run_fetch(src_url="https://example.org/x.tgz")
        self.assertEqual(urls, ["https://example.org/x.tgz"])

    def test_broken_archive_is_skipped(self):
        with open(self.tgz, "wb") as f:                         # не архив — например, страница ошибки
            f.write(b"<html>")
        rc, urls, ok = self.run_fetch()
        self.assertEqual(urls, [self.REL, self.MAIN])
        self.assertNotEqual(rc, 0)


class WorkflowTest(unittest.TestCase):
    def test_archive_layout_matches_installer(self):
        """Архив релиза распаковывается так же, как архив ветки: один каталог верхнего уровня."""
        with open(os.path.join(ROOT, ".github", "workflows", "release.yml")) as f:
            wf = f.read()
        self.assertIn("--prefix=awg-router/", wf)
        self.assertIn("awg-router.tar.gz", wf)
        with open(os.path.join(ROOT, "install.sh")) as f:
            self.assertIn("releases/latest/download/awg-router.tar.gz", f.read())


if __name__ == "__main__":
    unittest.main()
