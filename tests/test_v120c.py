"""1.20.0, третья проверка: открытые адреса не тратят процессор панели (сжатая статика — один раз, токен ссылки — без
копии состояния); запросы со страниц того же сайта не меняют настройки; типы и границы ввода (настройки Telegram,
имя клиента, срок); круг резервов из старой копии; старый `.env.bak` не возвращается; чтение трафика под
блокировкой; кэш разобранных конфигов не растёт.

python3 -m unittest discover tests
"""
import copy
import gzip
import http.client
import os
import shutil
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
sys.path.insert(0, os.path.dirname(__file__))

from app import config, engine, limits, main, traffic, web  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


class R:
    """Запрос для обработчика: тело, метод и заголовки."""

    def __init__(self, body=None, method="POST", headers=None, path="/api/x"):
        self._b, self.method, self.headers, self.path = body or {}, method, headers or {}, path
        self.cookies, self.client_ip = {}, "203.0.113.9"

    def json(self):
        return self._b


class StaticGzipTest(unittest.TestCase):
    """Файл статики сжимается один раз на версию: `/s/assets/*` открыт без входа, и сжатие `i18n.js` на каждый
    запрос (миллисекунды процессора) было бы бесплатной нагрузкой на панель для любого."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        with open(os.path.join(self.d, "big.js"), "w") as f:
            f.write("const a = 1;\n" * 1000)
        app = web.App()
        app.public_static = ("/s/assets", self.d)
        app.public_files = {"big.js"}
        self.srv = app.serve("127.0.0.1", 0)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        web._gz_cache.clear()

    def get(self):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=5)
        self.addCleanup(c.close)
        c.request("GET", "/s/assets/big.js", headers={"Accept-Encoding": "gzip"})
        r = c.getresponse()
        return r.getheader("Content-Encoding"), gzip.decompress(r.read())

    def test_compressed_once_per_version(self):
        real = gzip.compress
        with mock.patch.object(web.gzip, "compress", side_effect=real) as gz:
            for _ in range(5):
                self.assertEqual(self.get(), ("gzip", b"const a = 1;\n" * 1000))
            self.assertEqual(gz.call_count, 1)
            p = os.path.join(self.d, "big.js")
            with open(p, "w") as f:
                f.write("const b = 2;\n" * 1000)
            os.utime(p, (time.time() + 5, time.time() + 5))     # новая версия файла — новый ETag
            self.assertEqual(self.get()[1], b"const b = 2;\n" * 1000)
            self.assertEqual(gz.call_count, 2)


class ShareNoCopyTest(unittest.TestCase):
    """Адреса /s/… открыты без входа: чужой токен не должен стоить панели копии всего состояния."""

    def setUp(self):
        main.engine.reconcile()
        self.pk = main.engine.clients[0]["public_key"]
        self.saved = main.store.snapshot()
        exp = int(time.time()) + 86400
        main.store.mutate(lambda st: (st.setdefault("shares", {}).__setitem__("T" * 24, {"pk": self.pk}),
                                      st.setdefault("limits", {}).__setitem__(self.pk, {"expires": exp})))
        self.exp = exp

    def tearDown(self):
        main.store.mutate(lambda st: (st.clear(), st.update(self.saved)))

    def test_unknown_token_without_snapshot(self):
        with mock.patch.object(main.store, "snapshot", side_effect=AssertionError("копия состояния")):
            for fn in (main.share_page, main.share_data):
                with self.assertRaises(web.HTTPError) as cm:
                    fn(None, "x" * 24)
                self.assertEqual(cm.exception.code, 404)
            self.assertIsNotNone(main.share_page(None, "T" * 24))

    def test_known_token_still_answers(self):
        d = main.share_data(None, "T" * 24)
        self.assertEqual(d["limits"]["expires"], self.exp)
        self.assertIn("handshake", d)


class SameOriginTest(unittest.TestCase):
    """Cookie с SameSite=Strict уходит и со страниц того же сайта (другой порт этого IP, соседний поддомен): форма
    оттуда отправит POST без тела — перезапуск сервера, обновление. Такой запрос отклоняется."""

    def test_rules(self):
        cases = [
            ("POST", {"Sec-Fetch-Site": "same-origin"}, True),
            ("POST", {"Sec-Fetch-Site": "none"}, True),
            ("POST", {"Sec-Fetch-Site": "same-site"}, False),
            ("POST", {"Sec-Fetch-Site": "cross-site"}, False),
            ("GET", {"Sec-Fetch-Site": "cross-site"}, True),          # чтение ничего не меняет
            ("POST", {}, True),                                       # curl, старый браузер — как раньше
            ("POST", {"Origin": "https://203.0.113.5:4821", "Host": "203.0.113.5:4821"}, True),
            ("POST", {"Origin": "https://[2001:db8::5]:4821", "Host": "[2001:db8::5]:4821"}, True),
            ("POST", {"Origin": "https://203.0.113.5:8080", "Host": "203.0.113.5:4821"}, False),
            ("DELETE", {"Origin": "null", "Host": "203.0.113.5:4821"}, False),
        ]
        for method, h, ok in cases:
            self.assertEqual(main.same_origin(R(method=method, headers=h)), ok, (method, h))

    def test_middleware_refuses_before_anything(self):
        req = R(headers={"Sec-Fetch-Site": "same-site"}, path=main.BASE + "/api/server/restart")
        with self.assertRaises(web.HTTPError) as cm:
            main.auth_mw(req)
        self.assertEqual((cm.exception.code, cm.exception.detail.key), (403, "err.cross_site"))
        req = R(headers={"Sec-Fetch-Site": "cross-site"}, path=main.BASE + "/api/login")
        with self.assertRaises(web.HTTPError):
            main.auth_mw(req)                                         # и вход с чужой страницы


class InputTypesTest(unittest.TestCase):
    """Неверный тип в запросе — 400, а не 500 (нашёл перебор всех маршрутов API)."""

    def setUp(self):
        main.engine.reconcile()
        self.pk = main.engine.clients[0]["public_key"]
        self.saved = main.store.snapshot()

    def tearDown(self):
        main.store.mutate(lambda st: (st.clear(), st.update(self.saved)))

    def code(self, fn, *a):
        with self.assertRaises(web.HTTPError) as cm:
            fn(*a)
        return cm.exception.code

    def test_telegram_fields(self):
        for body in ({"backup": []}, {"backup": {"a": 1}}, {"lang": ["ru"]}, {"lang": {}}):
            for fn in (main.put_telegram, main.telegram_test, main.telegram_backup, main.telegram_detect):
                self.assertEqual(self.code(fn, R(body)), 400, (fn.__name__, body))

    def test_client_name(self):
        for v in (False, True, 1.5, -1, [], {}):
            self.assertEqual(self.code(main.edit_user, R({"name": v}), self.pk), 400, v)
            self.assertEqual(self.code(main.add_user, R({"name": v})), 400, v)
        n = len(main.engine.clients)
        main.add_user(R({"name": "Ok"}))
        self.assertEqual(len(main.engine.clients), n + 1)

    def test_expiry_limit(self):
        """Срок позже 9999 года не перевести в дату: бот падал на карточке клиента, браузер писал Invalid Date."""
        self.assertEqual(self.code(main.put_limits, R({"expires": 10 ** 17}), self.pk), 400)
        main.put_limits(R({"expires": limits.EXPIRES_MAX}), self.pk)
        time.strftime("%Y-%m-%d", time.gmtime(limits.EXPIRES_MAX))
        self.assertEqual(main.store.snapshot()["limits"][self.pk]["expires"], limits.EXPIRES_MAX)

    def test_restore_drops_impossible_dates(self):
        from test_api import PUB, good_state
        g = good_state()
        g["limits"][PUB].update(expires=10 ** 17, exp_done=10 ** 17, exp_warned=10 ** 16)
        st = main.clean_backup_state(g)
        L = st["limits"][PUB]
        self.assertEqual((L["expires"], L["exp_done"], L["exp_warned"]), (None, None, None))


class RestoreLoopTest(unittest.TestCase):
    """Круг резервов (A → B → A) в копии до 1.20.0: панель такой больше не сохраняет, а при восстановлении круг
    разрывается резервом «напрямую» — копия не становится невосстановимой."""

    def test_loop_is_broken(self):
        from test_api import good_state
        g = good_state()
        a = g["upstreams"][0]
        b = copy.deepcopy(a)
        b.update(id="u000002", name="DE", num=2)
        a["fallback"], b["fallback"] = "up:u000002", "up:u000001"
        g["upstreams"].append(b)
        st = main.clean_backup_state(g)
        fbs = {u["id"]: u["fallback"] for u in st["upstreams"]}
        self.assertEqual(sorted(fbs.values()), ["direct", "up:u000001"])
        for u in st["upstreams"]:
            self.assertFalse(main._fallback_loops(st, u["id"], u["fallback"]))

    def test_chain_without_loop_is_kept(self):
        from test_api import good_state
        g = good_state()
        b = copy.deepcopy(g["upstreams"][0])
        b.update(id="u000002", name="DE", num=2, fallback="block")
        g["upstreams"][0]["fallback"] = "up:u000002"
        g["upstreams"].append(b)
        st = main.clean_backup_state(g)
        self.assertEqual([u["fallback"] for u in st["upstreams"]], ["up:u000002", "block"])


class StaleEnvBakTest(unittest.TestCase):
    """`.env` удалили нарочно, а `.env.bak` от прошлой установки остался: из него ничего не возвращается."""

    def test_old_bak_is_ignored(self):
        from test_v120b import EnvKeepTest
        t = EnvKeepTest("test_fresh_install")
        t.setUp()
        self.addCleanup(t.doCleanups)
        with open(t.env + ".bak", "w") as f:
            f.write("AWG_CONTAINER=gone-long-ago\nEXIT_ENGINE=kernel\n")
        os.path.exists(t.env) and os.remove(t.env)
        script = (f'set -uo pipefail\nENV_FILE="{t.env}"\n{t.envget}'
                  'ACCESS=public; PANEL_PASSWORD=pw; PANEL_PORT=4821; PANEL_BASE_PATH=/abc; PUBLIC_HOST=198.51.100.5; '
                  'TLS_DOMAIN=; ACME_EMAIL=; AWG_MODE=container; AWG_INIT_PORT=\n' + t.modes + t.write)
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(t.env) as f:
            text = f.read()
        self.assertNotIn("AWG_CONTAINER", text)
        self.assertNotIn("EXIT_ENGINE", text)


class TrafficReadLockTest(unittest.TestCase):
    """Чтение итогов идёт из потоков HTTP, учёт — из потока движка: обход словаря месяцев, в который как раз
    добавляется новый месяц, падал бы с RuntimeError. Чтение ждёт учёт."""

    def test_view_waits_for_update(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        tr = traffic.Traffic(os.path.join(d, "t.json"))
        tr.update([{"public_key": "k", "enabled": True, "live": {"rx": 1, "tx": 1}}], now=1.0)
        tr.update([{"public_key": "k", "enabled": True, "live": {"rx": 5, "tx": 9}}], now=2.0)
        held, done = threading.Event(), threading.Event()

        def hold():
            with tr.lock:
                held.set()
                time.sleep(0.3)

        threading.Thread(target=hold).start()
        held.wait(2)
        t0 = time.monotonic()
        threading.Thread(target=lambda: (tr.view("k"), tr.out_view("direct"), tr.server_view(), done.set())).start()
        self.assertTrue(done.wait(3))
        self.assertGreaterEqual(time.monotonic() - t0, 0.2)
        self.assertEqual((tr.view("k")["total_rx"], tr.view("k")["total_tx"]), (4, 8))


class EngineSmallTest(unittest.TestCase):
    def test_parsed_cache_is_bounded(self):
        from test_v115 import conf
        e = engine.Engine.__new__(engine.Engine)
        e._parsed = {}
        for i in range(engine.Engine.PARSED_MAX + 50):
            e.parsed({"config": conf(f"203.0.113.{i % 250}:{1000 + i}")})
        self.assertLessEqual(len(e._parsed), engine.Engine.PARSED_MAX)

    def test_no_lookups_while_exits_wait(self):
        from test_v115 import conf
        e = main.engine
        saved = (dict(e.rt), dict(e._up_fail), dict(e.health))
        self.addCleanup(lambda: setattr(e, "rt", saved[0]) or setattr(e, "_up_fail", saved[1])
                        or setattr(e, "health", saved[2]))
        st = {"upstreams": [{"id": f"u{i}", "name": f"E{i}", "num": i + 1, "config": conf(f"n{i}.example.net:51820")}
                            for i in range(3)]}
        e.rt, e._up_fail = {}, {}
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(e, "_links", return_value=set()), \
                mock.patch.object(e, "exit_engine", return_value="go"), \
                mock.patch.object(e, "engine_pending", return_value=True), \
                mock.patch.object(engine.awgconf, "resolve_many") as rm, mock.patch.object(e, "_start_up") as su:
            e._sync_upstreams(mock.Mock(key="k", pid=1), st)
        rm.assert_not_called()
        su.assert_not_called()


if __name__ == "__main__":
    unittest.main()
