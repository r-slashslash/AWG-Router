"""Состояние и резервные копии прежних выпусков загружаются как раньше: python3 -m unittest tests.test_old_files

tests/fixtures/old/<выпуск>/ — файлы, сделанные демо-панелью настоящего кода выпуска (tools/fixtures/make_old.py):
state.json, резервная копия backup.json, копия с паролем backup.enc (пароль make_old.PASSWORD) и log.txt —
что выпуск принял, а что отклонил. expected.json — что из них получалось при загрузке. Если загрузка меняется
сознательно, expected.json пересоздаётся (python3 tests/test_old_files.py --write), а разница смотрится глазами:
всё, что в ней есть, увидят люди со старыми копиями."""
import base64
import copy
import glob
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from app import lists, notify  # noqa: E402
from app.store import Store  # noqa: E402
from app.traffic import Traffic  # noqa: E402
from app import panel  # noqa: E402
from app.api import backup  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures", "old")
PASSWORD = "fixture-backup-pw"


def versions() -> list[str]:
    return sorted(os.listdir(FIX), key=lambda v: [int(x) for x in v.split(".")])


def read_json(*path):
    with open(os.path.join(FIX, *path), encoding="utf-8") as f:
        return json.load(f)


def loaded_state(v: str) -> dict:
    """state.json выпуска v, как его читает панель при запуске (Store), — с текстами ручных списков (с 1.21.0
    они лежат в своих файлах, а не в state.json: Store переносит их при первом запуске)."""
    d = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join(FIX, v, "state.json"), os.path.join(d, "state.json"))
        if os.path.isdir(os.path.join(FIX, v, "texts")):         # 1.21.0 и новее: тексты уже в своих файлах
            shutil.copytree(os.path.join(FIX, v, "texts"), os.path.join(d, "texts"))
        return json.loads(json.dumps(Store(os.path.join(d, "state.json")).snapshot(texts=True)))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def from_backup(b: dict) -> dict:
    """Что делает «Восстановить из файла» с копией b, по шагам: проверенное состояние, состояние после замены
    (на чистом сервере без своих адресов), файлы сервера AWG и итоги трафика."""
    new = backup.clean_backup_state(b["state"])
    cur = {"settings": {}}
    backup.restore_state(cur, copy.deepcopy(new))
    out = {"clean": new, "restored": cur}
    if b.get("server"):
        sc, files = backup.clean_server_files(b["server"], b["server"]["kind"])
        out["server"] = {"conf": sc.render(), "files": files}
    d = tempfile.mkdtemp()
    try:
        t = Traffic(os.path.join(d, "traffic.json"))
        t.replace(b.get("traffic") or {})
        out["traffic"] = t.export()
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return json.loads(json.dumps(out))


def expected_now(v: str) -> dict:
    out = {"state": loaded_state(v)}
    if os.path.exists(os.path.join(FIX, v, "backup.json")):
        out["backup"] = from_backup(read_json(v, "backup.json"))
    return out


class OldFilesTest(unittest.TestCase):
    def test_fixtures_cover_releases(self):
        """Файлы есть от первого выпуска до последнего опубликованного; копии — с 1.3.0, где они появились."""
        vs = versions()
        self.assertEqual(vs[0], "1.0.0")
        self.assertIn("1.21.0", vs)            # выпуск, с которого обновляются на 1.22.0
        self.assertIn("1.22.0", vs)            # выпуск, с которого обновляются на 1.23.0
        self.assertIn("1.23.1", vs)            # выпуск, с которого обновляются на 1.24.0
        self.assertIn("1.24.0", vs)            # выпуск, с которого обновляются на 1.25.0
        for v in vs:
            self.assertTrue(os.path.exists(os.path.join(FIX, v, "expected.json")), v)
            if v != "1.0.0":
                self.assertTrue(os.path.exists(os.path.join(FIX, v, "backup.json")), v)

    def test_load_as_before(self):
        for v in versions():
            with self.subTest(v=v):
                self.assertEqual(expected_now(v), read_json(v, "expected.json"))

    def test_texts_move_out_of_state(self):
        """Первый запуск 1.21.0 на state.json прежнего выпуска: тексты ручных списков — в своих файлах, в
        state.json их нет, а состояние с текстами (резервная копия) — прежнее."""
        for v in versions():
            if os.path.isdir(os.path.join(FIX, v, "texts")):
                continue                                    # 1.21.0 и новее: переносить уже нечего
            with self.subTest(v=v):
                d = tempfile.mkdtemp()
                try:
                    path = os.path.join(d, "state.json")
                    shutil.copy(os.path.join(FIX, v, "state.json"), path)
                    old = read_json(v, "state.json")
                    texts = {l["id"]: l["source"] for l in old["lists"] if l["kind"] in ("manual", "domains")}
                    self.assertTrue(texts)
                    st = Store(path)
                    with open(path, encoding="utf-8") as f:
                        disk = json.load(f)
                    for l in disk["lists"]:
                        if l["id"] in texts:
                            self.assertEqual(l["source"], "")
                            self.assertRegex(l["text"], r"^[0-9a-f]{16}$")
                            self.assertEqual(st.list_text(l["id"]), texts[l["id"]])
                    self.assertEqual(len(os.listdir(os.path.join(d, "texts"))), len(texts))
                    again = Store(path)                     # второй запуск ничего не переносит заново
                    self.assertEqual(again.snapshot(), st.snapshot())
                finally:
                    shutil.rmtree(d, ignore_errors=True)

    def test_encrypted_backups(self):
        """Копия с паролем (Telegram с 1.5.0, «Скачать копию» с паролем с 1.12.0) открывается и даёт то же."""
        found = glob.glob(os.path.join(FIX, "*", "backup.enc"))
        self.assertGreaterEqual(len(found), 3)
        for path in found:
            v = os.path.basename(os.path.dirname(path))
            with self.subTest(v=v), open(path) as f:
                plain = notify.decrypt(base64.b64decode(f.read().strip()), PASSWORD)
                self.assertIsNotNone(plain)
                b = json.loads(plain)
                self.assertEqual(backup.clean_backup_state(b["state"]),
                                 backup.clean_backup_state(read_json(v, "backup.json")["state"]))

    def test_restore_end_to_end(self):
        """Настоящий «Восстановить из файла» (с сервером AWG) на самой старой и самой новой копии."""
        R = lambda body: type("R", (), {"json": lambda self, *a: body})()
        if panel.engine.target is None:
            with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
                panel.engine.reconcile()
        st0 = panel.store.snapshot()
        tr0 = panel.engine.traffic.export()
        t = panel.engine.target
        conf0 = {n: t.read_file(f"{t.dir}/{n}") for n in (os.path.basename(t.conf_path),) + backup.SERVER_FILES}
        try:
            for v in (versions()[1], versions()[-1]):
                with self.subTest(v=v), mock.patch.object(panel.engine, "refresh_lists"):
                    b = read_json(v, "backup.json")
                    self.assertEqual(backup.restore_backup(R({"backup": b, "server": True})),
                                     {"ok": True, "restarted": True})
                    exp = read_json(v, "expected.json")["backup"]
                    self.assertEqual(panel.store.snapshot()["upstreams"], exp["restored"]["upstreams"])
                    self.assertEqual(panel.store.snapshot(texts=True)["lists"], exp["restored"]["lists"])
        finally:
            panel.store.mutate(lambda st: (st.clear(), st.update(st0)))
            panel.engine.traffic.replace(tr0)
            for n, text in conf0.items():
                if text is not None:
                    t.write_file(f"{t.dir}/{n}", text)


if __name__ == "__main__":
    if "--write" in sys.argv:
        for v in versions():
            with open(os.path.join(FIX, v, "expected.json"), "w", encoding="utf-8") as f:
                json.dump(expected_now(v), f, ensure_ascii=False, indent=1, sort_keys=True)
                f.write("\n")
        print("expected.json written for", ", ".join(versions()))
    else:
        unittest.main()
