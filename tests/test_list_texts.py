"""Тексты ручных списков — в своих файлах, а не в state.json (1.21.0): python3 -m unittest tests.test_list_texts"""
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
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from app import lists, panel  # noqa: E402
from app.api import backup, routing, state  # noqa: E402
from app.store import Store  # noqa: E402
from tests.seed import legacy, legacy_lists  # noqa: E402,F401

R = lambda body: type("R", (), {"json": lambda self, *a: body})()
NETS = "203.0.113.0/24\n198.51.100.0/25 # склад\n" + "\n".join(f"10.{i // 256}.{i % 256}.0/24" for i in range(3000))


class StoreTextsTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.path = os.path.join(self.d, "state.json")
        self.addCleanup(shutil.rmtree, self.d, True)

    def disk(self) -> dict:
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def texts(self) -> list[str]:
        return sorted(os.listdir(os.path.join(self.d, "texts")))

    def add(self, s: Store, lid: str, text: str, kind: str = "manual") -> None:
        s.mutate(lambda st: st["lists"].append({"id": lid, "kind": kind, "source": text, "name": lid}))

    def test_text_in_its_file(self):
        s = Store(self.path)
        legacy_lists(s)                                          # страны, как в новой установке до 1.22.0
        self.add(s, "l1", NETS)
        self.add(s, "l2", "example.com\n*.example.org", "domains")
        disk = {l["id"]: l for l in self.disk()["lists"]}
        for lid in ("l1", "l2"):
            self.assertEqual(disk[lid]["source"], "")
            self.assertRegex(disk[lid]["text"], r"^[0-9a-f]{16}$")
        self.assertEqual(disk["ru"]["source"], "ru")                 # страна — как была
        self.assertNotIn("text", disk["ru"])
        self.assertEqual(s.list_text("l1"), NETS)
        self.assertEqual(s.list_text("l2"), "example.com\n*.example.org")
        self.assertLess(os.path.getsize(self.path), 3000)             # state.json маленький
        self.assertLess(len(json.dumps(s.snapshot())), 3000)          # и копия состояния на каждый запрос
        full = {l["id"]: l for l in s.snapshot(texts=True)["lists"]}
        self.assertEqual(full["l1"]["source"], NETS)
        self.assertNotIn("text", full["l1"])
        self.assertEqual(Store(self.path).list_text("l1"), NETS)      # после перезапуска

    def test_old_text_lives_while_bak_needs_it(self):
        s = Store(self.path)
        self.add(s, "l1", "203.0.113.0/24")
        first = self.texts()
        s.mutate(lambda st: Store.lst(st, "l1").update(source="198.51.100.0/24"))
        self.assertEqual(len(self.texts()), 2)                       # прежний текст нужен state.json.bak
        self.assertEqual(s.list_text("l1"), "198.51.100.0/24")
        s.mutate(lambda st: st["settings"].update(list_update_hours=12))
        self.assertEqual(len(self.texts()), 1)
        self.assertNotEqual(self.texts(), first)
        # удалённый список: его файл уходит на второй записи
        s.mutate(lambda st: st.update(lists=[l for l in st["lists"] if l["id"] != "l1"]))
        s.mutate(lambda st: st["settings"].update(list_update_hours=6))
        self.assertEqual(self.texts(), [])

    def test_damaged_state_starts_from_bak_with_texts(self):
        s = Store(self.path)
        self.add(s, "l1", "203.0.113.0/24")
        s.mutate(lambda st: Store.lst(st, "l1").update(source="198.51.100.0/24"))
        with open(self.path, "w") as f:
            f.write("{oops")
        self.assertEqual(Store(self.path).list_text("l1"), "203.0.113.0/24")    # из state.json.bak

    def test_failed_write_changes_nothing(self):
        s = Store(self.path)
        self.add(s, "l1", "203.0.113.0/24")
        real = os.replace

        def fail_state(a, b):
            if b == self.path:
                raise OSError("disk full")
            return real(a, b)
        with mock.patch("os.replace", side_effect=fail_state), self.assertRaises(OSError):
            s.mutate(lambda st: Store.lst(st, "l1").update(source="198.51.100.0/24"))
        self.assertEqual(s.list_text("l1"), "203.0.113.0/24")        # состояние и его текст — прежние
        self.assertEqual(Store(self.path).list_text("l1"), "203.0.113.0/24")

    def test_lost_file_is_empty_text(self):
        s = Store(self.path)
        self.add(s, "l1", "203.0.113.0/24")
        for n in self.texts():
            os.remove(os.path.join(self.d, "texts", n))
        with self.assertLogs("awgr.store", "WARNING"):
            self.assertEqual(s.list_text("l1"), "")


class PanelTextsTest(unittest.TestCase):
    """Через API панели: список с текстом, правка названия, копия и восстановление."""

    @classmethod
    def setUpClass(cls):
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            panel.engine.reconcile()

    def setUp(self):
        self.st0 = panel.store.snapshot(texts=True)
        self.addCleanup(lambda: panel.store.mutate(lambda st: (st.clear(), st.update(self.st0))))

    def test_add_edit_view(self):
        lid = routing.add_list(R({"kind": "manual", "name": "Office", "source": NETS}))["id"]
        self.assertEqual(Store.lst(panel.store.snapshot(), lid)["source"], "")
        self.assertEqual(routing.get_list(None, lid)["source"], NETS)
        self.assertNotIn("text", routing.get_list(None, lid))
        view = next(l for l in state.get_state(None)["lists"] if l["id"] == lid)
        self.assertIsNone(view["source"])
        self.assertNotIn("text", view)
        self.assertEqual(lists.load_cidrs(lid), [str(n) for n in lists.parse_cidrs(NETS)])   # сети — из текста файла
        routing.edit_list(R({"name": "HQ"}), lid)                      # только название: текст тот же
        self.assertEqual(panel.store.list_text(lid), NETS)
        self.assertEqual(Store.lst(panel.store.snapshot(), lid)["name"], "HQ")
        routing.edit_list(R({"name": "HQ", "source": "192.0.2.0/24"}), lid)
        self.assertEqual(panel.store.list_text(lid), "192.0.2.0/24")
        self.assertEqual(lists.load_cidrs(lid), ["192.0.2.0/24"])
        # фоновое обновление берёт текст из файла
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            panel.engine.refresh_lists(False, [lid])
        self.assertEqual(lists.load_cidrs(lid), ["192.0.2.0/24"])
        routing.del_list(None, lid)

    def test_backup_carries_texts_and_restore_puts_them_back(self):
        lid = routing.add_list(R({"kind": "domains", "name": "Sites", "source": "example.com\nexample.org"}))["id"]
        b = backup.make_backup()
        l = next(x for x in b["state"]["lists"] if x["id"] == lid)
        self.assertEqual(l["source"], "example.com\nexample.org")       # копию поймёт и прежний выпуск
        self.assertNotIn("text", l)
        routing.del_list(None, lid)
        self.assertEqual(panel.store.list_text(lid), "")
        with mock.patch.object(panel.engine, "refresh_lists"):
            backup.restore_backup(R({"backup": b}))
        self.assertEqual(panel.store.list_text(lid), "example.com\nexample.org")
        self.assertEqual(Store.lst(panel.store.snapshot(), lid)["source"], "")


if __name__ == "__main__":
    unittest.main()
