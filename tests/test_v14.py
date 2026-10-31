"""1.4.0: обновление из панели, копии в Telegram, предупреждения клиентам, иконка на главный экран.

python3 -m unittest discover tests
"""
import base64
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import selfupdate  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


class Req:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class Proc:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class SelfUpdateTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.p = [mock.patch.object(selfupdate, "LOG", os.path.join(self.dir, "update.log")),
                  mock.patch.object(selfupdate, "STATE", os.path.join(self.dir, "update.json"))]
        for p in self.p:
            p.start()

    def tearDown(self):
        for p in self.p:
            p.stop()
        shutil.rmtree(self.dir)

    def log(self, text):
        with open(selfupdate.LOG, "w") as f:
            f.write(text)

    def test_status(self):
        self.assertEqual(selfupdate.status(), {"state": "idle"})
        selfupdate._write_state({"started": time.time(), "from": "1.3.1", "to": "1.4.0"})
        self.log("\x1b[1m▸ Building\x1b[0m\n")
        self.assertEqual(selfupdate.status()["state"], "running")
        self.log("▸ Building\n✗ Build failed\nexit=1\n")
        self.assertEqual((selfupdate.status()["state"], selfupdate.status()["exit"]), ("failed", 1))
        self.log("▸ Starting\nexit=0\n")
        self.assertEqual(selfupdate.status()["state"], "done")
        selfupdate._write_state({"started": time.time() - selfupdate.STALE - 1, "to": "1.4.0"})
        self.log("▸ Building\n")
        self.assertEqual(selfupdate.status()["state"], "failed")      # оборвалось

    def test_log_lines_clean(self):
        self.log("\x1b[32m✓\x1b[0m Done\r  | \r  / \n  Password: secret123\n\nexit=0\n")
        self.assertEqual(selfupdate.log_lines(), ["✓ Done", "exit=0"])

    def test_host_dir(self):
        with mock.patch.object(selfupdate.system, "docker_get", return_value={
                "Config": {"Labels": {"com.docker.compose.project.working_dir": "/opt/awg-router"}}}):
            self.assertEqual(selfupdate.host_dir(), "/opt/awg-router")
        with mock.patch.object(selfupdate.system, "docker_get", return_value={
                "Config": {"Labels": {}}, "Mounts": [{"Destination": "/data", "Source": "/srv/panel/data"}]}):
            self.assertEqual(selfupdate.host_dir(), "/srv/panel")
        for bad in ("/opt/a b", "/opt/$(id)", "relative", "/opt/../etc"):
            with mock.patch.object(selfupdate.system, "docker_get", return_value={
                    "Config": {"Labels": {"com.docker.compose.project.working_dir": bad}}}):
                with self.assertRaises(selfupdate.UpdateError):
                    selfupdate.host_dir()

    def test_start_on_host(self):
        calls = []

        def host(cmd, timeout=30):
            calls.append(cmd)
            if cmd[:2] == ["systemctl", "is-active"]:
                return Proc(3)          # не идёт
            return Proc(0)
        with mock.patch.object(selfupdate.config, "DRY_RUN", False), \
                mock.patch.object(selfupdate, "host_dir", return_value="/opt/awg-router"), \
                mock.patch.object(selfupdate, "_host", side_effect=host):
            st = selfupdate.start("1.3.1", "1.4.0")
        self.assertEqual((st["state"], st["to"]), ("running", "1.4.0"))
        run = calls[-1]
        self.assertEqual(run[:4], ["systemd-run", "--unit", "awg-router-update", "--collect"])
        self.assertIn('bash "/opt/awg-router/install.sh" --update', run[-1])
        self.assertIn('echo "exit=$?" >>"/opt/awg-router/data/update.log"', run[-1])
        with self.assertRaises(selfupdate.UpdateError):          # второй раз — уже идёт
            selfupdate.start("1.3.1", "1.4.0")

    def test_start_without_systemd(self):
        with mock.patch.object(selfupdate.config, "DRY_RUN", False), \
                mock.patch.object(selfupdate, "host_dir", return_value="/opt/awg-router"), \
                mock.patch.object(selfupdate, "_host", return_value=Proc(1)):
            with self.assertRaises(selfupdate.UpdateError) as cm:
                selfupdate.start("1.3.1", "1.4.0")
        self.assertEqual(cm.exception.msg.key, "err.update_no_systemd")
        self.assertEqual(selfupdate.status(), {"state": "idle"})


@unittest.skipUnless(shutil.which("openssl"), "openssl")
class BackupCryptoTest(unittest.TestCase):
    def test_roundtrip(self):
        from app import notify
        data = json.dumps({"format": "awg-router-backup", "x": "ключ"}).encode()
        enc = notify.encrypt(data, "correct horse")
        self.assertTrue(enc.startswith(notify.ENC_MAGIC))
        self.assertNotIn(b"awg-router-backup", enc)
        self.assertEqual(notify.decrypt(enc, "correct horse"), data)
        self.assertIsNone(notify.decrypt(enc, "wrong password"))

    def test_decrypt_endpoint(self):
        from app import main, notify, web
        b = {"format": "awg-router-backup", "state": {}}
        enc = base64.b64encode(notify.encrypt(json.dumps(b).encode(), "password1")).decode()
        self.assertEqual(main.decrypt_backup(Req({"data": enc, "password": "password1"}))["backup"], b)
        for body in ({"data": enc, "password": "nope"}, {"data": "not base64!", "password": "x"},
                     {"data": base64.b64encode(b"plain").decode(), "password": "x"}):
            with self.assertRaises(web.HTTPError):
                main.decrypt_backup(Req(body))


class TelegramBackupTest(unittest.TestCase):
    TOKEN = "123456789:" + "A" * 35

    def setUp(self):
        from app import main
        self.main = main
        main.store.mutate(lambda st: st["settings"].__setitem__("telegram", {
            **main.notify.defaults(), "enabled": True, "token": self.TOKEN, "chat_id": "42"}))
        main._backup_try = 0.0

    def test_settings(self):
        from app import notify, web
        c = self.main._tg_draft({"backup": "weekly", "backup_pw": "longenough"})
        self.assertEqual((c["backup"], c["backup_pw"]), ("weekly", "longenough"))
        self.assertEqual(self.main._tg_draft({"backup_pw_clear": True})["backup_pw"], "")
        for bad in ({"backup": "hourly"}, {"backup_pw": "short"}):
            with self.assertRaises(web.HTTPError):
                self.main._tg_draft(bad)
        v = notify.public_view(c)
        self.assertNotIn("backup_pw", v)
        self.assertTrue(v["backup_pw_set"])

    def test_schedule(self):
        sent = []
        set_cfg = lambda **kw: self.main.store.mutate(  # noqa: E731
            lambda st: st["settings"]["telegram"].update(kw))
        with mock.patch.object(self.main, "send_backup", side_effect=lambda c: sent.append(c["backup"])):
            self.assertFalse(self.main.backup_tick(now=1000.0))               # выключено
            set_cfg(backup="daily")
            self.assertTrue(self.main.backup_tick(now=10_000.0))               # первая — сразу
            self.assertFalse(self.main.backup_tick(now=10_000.0 + 3600 * 5))  # ещё рано
            self.main._backup_try = 0.0
            self.assertTrue(self.main.backup_tick(now=10_000.0 + 86400 - 300))  # через сутки (с запасом)
        self.assertEqual(sent, ["daily", "daily"])
        c = self.main.notify.cfg_of(self.main.store.snapshot())
        self.assertEqual((c["backup_last"], c["backup_error"]), (10_000.0 + 86400 - 300, None))

    def test_failure_retries_after_an_hour(self):
        self.main.store.mutate(lambda st: st["settings"]["telegram"].update(backup="weekly"))
        with mock.patch.object(self.main, "send_backup", side_effect=self.main.notify.NotifyError("down")):
            self.assertFalse(self.main.backup_tick(now=50_000.0))
        self.assertEqual(self.main.notify.cfg_of(self.main.store.snapshot())["backup_error"], "down")
        with mock.patch.object(self.main, "send_backup") as s:
            self.assertFalse(self.main.backup_tick(now=50_000.0 + 1800))       # раньше часа — нет
            self.assertTrue(self.main.backup_tick(now=50_000.0 + 3700))
            self.assertEqual(s.call_count, 1)

    def test_send_document_multipart(self):
        from app import notify
        seen = {}

        class R:
            def __init__(s, req):
                seen["req"] = req

            def __enter__(s):
                return s

            def __exit__(s, *a):
                return False

            def read(s):
                return b'{"ok": true, "result": {}}'
        with mock.patch.object(notify.urllib.request, "urlopen", side_effect=lambda req, timeout: R(req)):
            notify.send_document(self.TOKEN, "42", "b.json", b"\x00DATA\xff", "caption")
        req = seen["req"]
        self.assertTrue(req.full_url.endswith("/sendDocument"))
        self.assertIn(b'name="document"; filename="b.json"', req.data)
        self.assertIn(b"\x00DATA\xff", req.data)
        self.assertIn(b'name="chat_id"\r\n\r\n42\r\n', req.data)

    def test_restore_keeps_backup_settings(self):
        import test_api
        s = test_api.good_state()
        s["settings"]["telegram"] = {"enabled": True, "token": self.TOKEN, "chat_id": "42",
                                     "backup": "daily", "backup_pw": "secret-pass", "backup_last": 5}
        t = self.main.clean_backup_state(s)["settings"]["telegram"]
        self.assertEqual((t["backup"], t["backup_pw"], t["backup_last"]), ("daily", "secret-pass", None))


class EarlyWarningTest(unittest.TestCase):
    def engine(self, L, used, enabled=True):
        from app import limits as lim

        class Store:
            def __init__(s):
                s.st = {"limits": {"K": L}}

            def snapshot(s):
                return json.loads(json.dumps(s.st))

            def mutate(s, fn):
                fn(s.st)

        class Tr:
            def used(s, pk, period):
                return used

        class E:
            pass
        e = E()
        e.store, e.traffic, e.events = Store(), Tr(), []
        e.clients = [{"public_key": "K", "name": "Dad", "enabled": enabled}]
        e.event = lambda lvl, m: e.events.append(m)
        return e, lim

    def test_expiring_once(self):
        now = 1_800_000_000
        e, lim = self.engine({"expires": now + 2 * 86400 + 60}, used=0)
        lim.enforce(e, now=now)
        lim.enforce(e, now=now + 3600)
        self.assertEqual([(m.key, m.p["days"]) for m in e.events], [("ev.client_expiring", 3)])
        self.assertEqual(e.events[0].p["date"], time.strftime("%Y-%m-%d", time.gmtime(now + 2 * 86400 + 60)))
        e, lim = self.engine({"expires": now + 5 * 86400}, used=0)            # ещё рано
        lim.enforce(e, now=now)
        self.assertEqual(e.events, [])
        e, lim = self.engine({"expires": now + 86400}, used=0, enabled=False)  # выключен — молчим
        lim.enforce(e, now=now)
        self.assertEqual(e.events, [])

    def test_quota_90_once_per_month(self):
        now = 1_800_000_000
        e, lim = self.engine({"quota": 100, "period": "month"}, used=92)
        lim.enforce(e, now=now)
        lim.enforce(e, now=now + 60)
        self.assertEqual([m.key for m in e.events], ["ev.client_quota_warn"])
        e.traffic.used = lambda pk, period: 95
        lim.enforce(e, now=now + 40 * 86400)                                  # новый месяц
        self.assertEqual([m.key for m in e.events], ["ev.client_quota_warn"] * 2)
        e, lim = self.engine({"quota": 100, "period": "month"}, used=50)
        lim.enforce(e, now=now)
        self.assertEqual(e.events, [])

    def test_telegram_mapping(self):
        from app import notify
        for key in ("client_expiring", "client_quota_warn", "backup", "backup_enc"):
            for lang in notify.LANGS:
                self.assertIn(key, notify.TEXTS[lang])
        self.assertEqual(notify.ENGINE_EVENTS["ev.client_expiring"], ("clients", "client_expiring"))


class ManifestTest(unittest.TestCase):
    def test_manifest(self):
        st = os.path.join(ROOT, "app", "static")
        with open(os.path.join(st, "manifest.webmanifest")) as f:
            m = json.load(f)
        self.assertEqual((m["start_url"], m["scope"], m["display"]), ("../", "../", "standalone"))
        for icon in m["icons"]:
            self.assertTrue(os.path.isfile(os.path.join(st, icon["src"])), icon["src"])
        with open(os.path.join(st, "index.html")) as f:
            html = f.read()
        self.assertIn('rel="manifest" href="static/manifest.webmanifest"', html)
        self.assertIn("static/icons/apple-touch-icon.png", html)
        import mimetypes
        from app import web  # noqa: F401  — регистрирует тип
        self.assertEqual(mimetypes.guess_type("x.webmanifest")[0], "application/manifest+json")


if __name__ == "__main__":
    unittest.main()
