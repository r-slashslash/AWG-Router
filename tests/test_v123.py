"""1.23.0: смена движка без «Ошибки» в шапке, настройки Telegram, вкладка «Сервер», окно правила, скорость клиентов,
запасные пути бота."""
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DRY_RUN", "1")

from app import engine as engine_mod  # noqa: E402


# ------------------------------------------------------------------ смена движка: шапка ждёт сервер
class EngineSettleTest(unittest.TestCase):
    def setUp(self):
        self.e = engine_mod.Engine.__new__(engine_mod.Engine)
        self.e._srv_down, self.e.server_restart_at, self.e.switching = None, None, False
        self.e.last_reconcile, self.e.last_error = time.time(), None

    def test_phase_waits_for_a_good_pass(self):
        e = self.e
        e._settle = ("engine", time.time())
        e.last_error = "boom"                    # проход упал, пока сервер поднимается на новом движке
        self.assertEqual(e.phase(), "engine")
        e._settle = ("server_restart", time.time())
        self.assertEqual(e.phase(), "server_restart")
        e._settle = ("engine", time.time() - engine_mod.SETTLE_SECS - 1)
        self.assertIsNone(e.phase())             # так и не заработал — дальше видна ошибка

    def test_good_pass_ends_the_wait_only_with_the_interface_up(self):
        e = self.e
        e._settle, e._srv_up = ("engine", time.time()), False
        e._pass_done()
        self.assertEqual(e.phase(), "engine")    # интерфейса ещё нет — ждём дальше
        e._srv_up = True
        e._pass_done()
        self.assertIsNone(e._settle)
        self.assertIsNone(e.phase())

    def test_switch_to_go_waits(self):
        e = self.e
        t = mock.Mock(exists=True)
        e.target, e.lock = t, mock.MagicMock()
        e.kernel_fallback, e._srv_tries, e._srv_next = None, 0, 0.0
        with mock.patch.object(e, "module_info", create=True, return_value={"loaded": True}), \
                mock.patch.object(e, "_stop_all", create=True), mock.patch.object(e, "event", create=True), \
                mock.patch.object(e, "reconcile_soon", create=True), \
                mock.patch.object(engine_mod.server.kernelmod, "update"):
            self.assertEqual(e.switch_engine("go")["action"], "restarted")
        t.stop.assert_called_once()
        t.start.assert_called_once()
        e.last_error = "boom"
        self.assertEqual(e.phase(), "engine")

    def test_restart_button_waits(self):
        e = self.e
        t = mock.Mock(exists=True, kind="container")
        e.target, e.lock = t, mock.MagicMock()
        with mock.patch.object(e, "reconcile_soon", create=True):
            e.restart_server()
        e.server_restart_at = None               # интерфейс уже на месте, а проход ещё не удался
        e.last_error = "boom"
        self.assertEqual(e.phase(), "server_restart")


if __name__ == "__main__":
    unittest.main()


# ------------------------------------------------------------------ Telegram: «Включить бот» — главный выключатель
from app import notify, tgbot  # noqa: E402
from app.store import BOT_SWITCH, Store  # noqa: E402


class BotSwitchTest(unittest.TestCase):
    def tg(self, **kw):
        c = notify.defaults()
        c.update(token="123456:" + "A" * 35, chat_id="424242", **kw)
        return c

    def test_master_switch(self):
        self.assertTrue(tgbot.admin_on(self.tg(enabled=True, control=True)))
        self.assertFalse(tgbot.admin_on(self.tg(enabled=False, control=True)))
        self.assertTrue(tgbot.clients_on(self.tg(enabled=True, clients=True, client_notify=False)))
        self.assertFalse(tgbot.clients_on(self.tg(enabled=False, clients=True)))

    def test_upgrade_turns_on_a_working_bot(self):
        for kw, on in (({"control": True, "clients": False}, True), ({"control": False, "clients": True}, True),
                       ({"control": False, "clients": False}, False)):
            st = {"settings": {"telegram": self.tg(enabled=False, **kw)}, "upgraded": ["rule_names", "client_bot"]}
            self.assertTrue(Store.bot_switch_once(st))
            self.assertEqual(st["settings"]["telegram"]["enabled"], on, kw)
            self.assertEqual(st["upgraded"], ["rule_names", "client_bot", BOT_SWITCH])
            st["settings"]["telegram"]["enabled"] = False          # потом человек выключил бот сам
            self.assertFalse(Store.bot_switch_once(st))
            self.assertFalse(st["settings"]["telegram"]["enabled"])

    def test_upgrade_from_a_backup(self):
        old = {"upgraded": ["rule_names", "client_bot"]}            # копия 1.22.0
        st = {"settings": {"telegram": self.tg(enabled=False, control=True)}, "upgraded": []}
        Store.bot_switch_once(st, old)
        self.assertTrue(st["settings"]["telegram"]["enabled"])
        new = {"upgraded": ["rule_names", "client_bot", BOT_SWITCH]}  # копия 1.23.0 — как в ней
        st = {"settings": {"telegram": self.tg(enabled=False, control=True)}, "upgraded": []}
        Store.bot_switch_once(st, new)
        self.assertFalse(st["settings"]["telegram"]["enabled"])

    def test_restore_runs_it(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "api", "backup.py"), encoding="utf-8") as f:
            self.assertIn("Store.bot_switch_once(st, new)", f.read())

    def test_form(self):
        from tests import panel_js
        js = panel_js.source()
        self.assertNotIn("tg-cnotify", js)
        self.assertNotIn("tg.control_title", js)
        i = js.index('id="tg-on"')
        self.assertLess(i, js.index('id="tg-control"'))
        self.assertLess(js.index('id="tg-control"'), js.index('id="tg-token"'))   # сразу под «Включить бот»
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "static", "i18n.js"), encoding="utf-8") as f:
            src = f.read()
        self.assertEqual(src.count('"tg.enable": "Включить бот"'), 1)
        self.assertNotIn("галочка ниже", src)
        self.assertNotIn("не подключайте этот же бот", src)


class BotSwitchApiTest(unittest.TestCase):
    def setUp(self):
        from app import panel
        self.panel = panel
        panel.store.mutate(lambda st: st["settings"].__setitem__("telegram", notify.defaults()))

    def put(self, body):
        from app.api import telegram
        return telegram.put_telegram(mock.Mock(json=lambda: body))

    def test_clients_only_bot_needs_no_chat(self):
        from app import web
        tok = "123456:" + "A" * 35
        off = {k: False for k in notify.KINDS}
        self.put({"enabled": True, "token": tok, "chat_id": "", "clients": True, "control": False, "events": off})
        with self.assertRaises(web.HTTPError) as cm:                 # уведомления без чата — некуда слать
            self.put({"enabled": True, "token": tok, "chat_id": "", "clients": True, "control": False,
                      "events": {k: True for k in notify.KINDS}})
        self.assertEqual(cm.exception.field, "chat_id")
        self.setUp()                                                  # токена нет и в сохранённом
        with self.assertRaises(web.HTTPError) as cm:
            self.put({"enabled": True, "token": "", "chat_id": "424242"})
        self.assertEqual(cm.exception.field, "token")


# ------------------------------------------------------------------ скорость клиентов в списке
from app.engine import tunnels as tunnels_mod  # noqa: E402


class ClientSpeedTest(unittest.TestCase):
    def test_rates_between_two_samples(self):
        e = engine_mod.Engine.__new__(engine_mod.Engine)
        dumps = [{"A": {"rx": 1000, "tx": 5000}, "B": {"rx": 10, "tx": 10}},
                 {"A": {"rx": 3000, "tx": 25000}, "B": {"rx": 10, "tx": 10}}]
        e.target = mock.Mock(exists=True, key="k1", dump=lambda: dumps.pop(0))
        clock = [1000.0]
        with mock.patch.object(tunnels_mod.time, "time", lambda: clock[0]):
            self.assertEqual(e.client_speeds(), {})                    # первый замер — сравнивать не с чем
            clock[0] += 1
            self.assertEqual(e.client_speeds(), {})                    # чаще CLIENT_SPEED_EVERY — прежний ответ
            clock[0] += 1.5
            r = e.client_speeds()
        dt = 2.5
        self.assertEqual(r, {"A": [round(20000 / dt), round(2000 / dt)]})   # [к клиенту, от клиента]; B стоит

    def test_restarted_server_starts_over(self):
        e = engine_mod.Engine.__new__(engine_mod.Engine)
        e.target = mock.Mock(exists=True, key="k1", dump=lambda: {"A": {"rx": 9000, "tx": 9000}})
        clock = [1000.0]
        with mock.patch.object(tunnels_mod.time, "time", lambda: clock[0]):
            e.client_speeds()
            e.target = mock.Mock(exists=True, key="k2", dump=lambda: {"A": {"rx": 10, "tx": 10}})
            clock[0] += 3
            self.assertEqual(e.client_speeds(), {})

    def test_hung_server_does_not_hold_the_poll(self):
        """`awg show` завис (проверка 1.23.0): опрос ждёт замер не дольше CLIENT_SPEED_WAIT, другие опросы — совсем не
        ждут, а после неудачи следующий замер — через CLIENT_SPEED_PAUSE."""
        import threading
        import time as _time
        e = engine_mod.Engine.__new__(engine_mod.Engine)
        go, calls = threading.Event(), []

        def hung():
            calls.append(1)
            go.wait(5)
            raise OSError("awg show: timed out")
        e.target = mock.Mock(exists=True, key="k1", dump=hung)
        with mock.patch.object(tunnels_mod, "CLIENT_SPEED_WAIT", 0.05):
            t0 = _time.monotonic()
            self.assertEqual(e.client_speeds(), {})
            self.assertEqual(e.client_speeds(), {})              # замер ещё идёт — сразу прежний ответ
            self.assertLess(_time.monotonic() - t0, 1)
            go.set()
            for _ in range(100):
                if not e._cspeed["busy"]:
                    break
                _time.sleep(0.01)
            self.assertEqual(e.client_speeds(), {})              # не удался — пауза, сервер не спрашивается
        self.assertEqual(len(calls), 1)
        self.assertGreater(e._cspeed["at"], _time.time() + tunnels_mod.CLIENT_SPEED_PAUSE - 5)

    def test_speeds_outside_the_tag(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "api", "state.py"), encoding="utf-8") as f:
            src = f.read()
        i = src.index("vol = {")
        self.assertIn('"speeds": engine.client_speeds()', src[i:i + 600])
        from tests import panel_js
        js = panel_js.source()
        self.assertIn("S.speeds = data.speeds", js)
        self.assertIn('data-speed="${esc(c.public_key)}"></span>', js)  # место в строке пустое — строка та же


# ------------------------------------------------------------------ бот: запасные пути
class BotPathsTest(unittest.TestCase):
    def test_exit_with_direct_fallback_is_down_for_telegram(self):
        from app import config, panel, system
        from tests.test_v18 import good_state
        st = good_state()
        st["upstreams"][0]["fallback"] = "direct"
        with mock.patch.object(config, "DRY_RUN", False), \
                mock.patch.object(panel.engine.store, "snapshot", return_value=st), \
                mock.patch.object(panel.engine, "target", mock.Mock(pid=777)), \
                mock.patch.object(panel.engine, "rt", {"u000001": mock.Mock(num=1)}), \
                mock.patch.object(panel.engine, "health", {"u000001": {"healthy": False}}):
            self.assertIsNone(panel.engine.own_route("up:u000001"))           # списки: резерв «Напрямую», как раньше
            with self.assertRaises(system.SysError) as cm:
                panel.engine.own_route("up:u000001", direct=False)
            self.assertEqual(cm.exception.msg.key, "tg.via_down")
            with self.assertRaises(notify.NotifyError):
                panel._tg_route("up:u000001")                                 # Telegram — никогда напрямую

    def test_checkbox_on_by_default_and_saved(self):
        from app import checks, panel
        self.assertTrue(notify.defaults()["fallback"])
        panel.store.mutate(lambda st: st["settings"].__setitem__("telegram", notify.defaults()))
        self.assertTrue(notify.fallback_on())
        st = panel.store.snapshot()
        self.assertFalse(checks.telegram(st, notify.cfg_of(st), {"fallback": False})["fallback"])
        from tests import panel_js
        js = panel_js.source()
        self.assertIn('fallback: $("#tg-fb").checked', js)
        self.assertIn('th("tg.path_now"', js)

    def test_state_says_which_path(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "api", "state.py"), encoding="utf-8") as f:
            self.assertIn('"tg_path": notify.paths.view(notify.cfg_of(st)["via"])', f.read())
        p = notify.Paths()
        p.ok("direct", "up:x", now=100.0)
        self.assertEqual(p.view("direct"), {"via": "up:x", "since": 100.0})
        self.assertIsNone(p.view("up:y"))                                     # выбрали другой путь — не про него


# ------------------------------------------------------------------ окно правила: списки внутри правил
class RuleListsTest(unittest.TestCase):
    """Список, который убрали из правил и который больше нигде не стоит, удаляется вместе с правилом (1.23.0)."""

    def setUp(self):
        from app import panel
        self.panel = panel

        def fn(st):
            st["lists"] = [{"id": "la", "kind": "manual", "source": "", "name": "a"},
                           {"id": "lb", "kind": "manual", "source": "", "name": "b"},
                           {"id": "lc", "kind": "domains", "source": "", "name": "c"}]
            st["routing"]["rules"] = [{"lists": ["la"], "outbound": "direct", "enabled": True},
                                      {"lists": ["lb"], "outbound": "direct", "enabled": True}]
            st["clients"] = {}
        panel.store.mutate(fn)

    def ids(self):
        return [l["id"] for l in self.panel.store.snapshot()["lists"]]

    def test_rule_deleted_with_its_list(self):
        from app.api import routing
        st = self.panel.store.snapshot()
        routing.put_routing(mock.Mock(json=lambda: {"default": "direct", "rules": [st["routing"]["rules"][1]]}))
        self.assertEqual(self.ids(), ["lb", "lc"])           # «la» ушёл с правилом; «lc» и не стоял — не трогаем

    def test_list_kept_while_a_client_uses_it(self):
        from app.api import clients, routing
        pk = "DEMO" + "A" * 40
        with mock.patch.object(clients, "awgconf") as ac:
            ac.KEY_RE.match.return_value = True
            clients.put_client(mock.Mock(json=lambda: {"outbound": "inherit", "rules_mode": "custom",
                                                       "rules": [{"lists": ["la"], "outbound": "block", "enabled": True}]}), pk)
        routing.put_routing(mock.Mock(json=lambda: {"default": "direct", "rules": []}))
        self.assertEqual(self.ids(), ["la", "lc"])           # «la» нужен клиенту, «lb» ушёл
        with mock.patch.object(clients, "awgconf") as ac:
            ac.KEY_RE.match.return_value = True
            clients.put_client(mock.Mock(json=lambda: {"outbound": "inherit", "rules_mode": "inherit", "rules": []}), pk)
        self.assertEqual(self.ids(), ["lc"])                 # своих правил больше нет — и списка

    def test_exit_forgets_its_own_sites(self):
        from app.api import routing
        self.panel.store.mutate(lambda st: st["upstreams"].append({"id": "u9", "name": "X", "own_list": "la"}))
        try:
            routing.put_routing(mock.Mock(json=lambda: {"default": "direct", "rules": []}))
            u = next(u for u in self.panel.store.snapshot()["upstreams"] if u["id"] == "u9")
            self.assertNotIn("own_list", u)
        finally:
            self.panel.store.mutate(lambda st: st.update(upstreams=[u for u in st["upstreams"] if u["id"] != "u9"]))

    def test_panel_code(self):
        from tests import panel_js
        js = panel_js.source()
        self.assertNotIn('id="lists-sec"', js)                 # раздела «Списки» нет
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "static", "index.html"), encoding="utf-8") as f:
            self.assertIn('<dialog id="modal2">', f.read())
        self.assertIn("ruleWindow(i === null ?", js)            # свои правила клиента — то же окно
        self.assertIn('okLabel: t("rw.done")', js)
        self.assertIn("dropNewLists(newLists.splice(0))", js)  # окно клиента закрыли без сохранения
        self.assertIn('if (!dom) { delete r.dns; box.innerHTML = ""; return; }', js)   # свой DNS — только у доменов
        self.assertNotIn('t("out.via"', js)                     # «Германия», а не «Через «Германия»»

    def test_rule_window_audit(self):
        """Проверка 1.23.0 (этап 1): окно правила."""
        from tests import panel_js
        js = panel_js.source()
        # список страны в окне — просто список (владелец, 2026-11-20): ни правила её доменов, ни «DNS на сервере»
        self.assertNotIn("countryPick", js)
        self.assertIn("function withRule(rules, i, r) {", js)
        self.assertIn("const keepIds = new Set(r.lists);", js)
        # пока список в правиле скачивается, перерисовка раз в 2,5 с не стирает открытую форму списка
        self.assertIn("drawLists(true); } }, 2500)", js)
        self.assertIn("else if (fb.dataset.key !== `${form.kind}:${form.id || \"\"}`) drawForm();", js)
        # созданные в окне и не попавшие в правило списки удаляются при закрытии окна
        self.assertIn("made.splice(0, made.length, ...made.filter((id) => !keepIds.has(id)));", js)

    def test_owner_requests_20(self):
        """Просьбы владельца 2026-11-20."""
        from tests import panel_js
        js = panel_js.source()
        # «Сервер»: опрос перерисовывает блок «Движок AmneziaWG», когда он изменился (после смены движка)
        self.assertIn('if (auto && tab === "server" && !anyModal()) drawEngine();', js)
        self.assertIn("if (!fresh || fresh.outerHTML === el.outerHTML) return;", js)
        # окно клиента → «Управление»: «За месяц по выходам» — колонкой рядом с суммами
        self.assertIn('<div class="c-traffic"><div class="kv">${sums}</div>', js)
        # в «+ Добавить список» окна правила нет группы «Страны — готовые правила»
        self.assertNotIn("re.countries", js)
        self.assertNotIn('value="cc:', js)
        # окно клиента: «Удалить» — внизу слева, рядом с «Сохранить»; в «Управлении» строки удаления больше нет
        self.assertIn('<button class="btn danger left" id="c-delete">${esc(t("cl.delete"))}</button>', js)
        self.assertNotIn("cl.delete_hint", js)
        # «Маршрутизация»: «+ Добавить правило» и «Применить для …» — строкой под заголовком, не в шапке справа
        self.assertIn('<div class="add-row rules-add"><button class="btn primary" id="g-add">', js)

    def test_routing_rows_audit(self):
        """Проверка 1.23.0 (этап 2): строки правил «Маршрутизации»."""
        from tests import panel_js
        js = panel_js.source()
        # пока переключение или место правила сохраняется, следующее нажатие не проходит (иначе отменяло бы это)
        self.assertIn("box.inert = true;\n    try { await saveRules(next); }", js)
        self.assertIn("finally { box.inert = false; }", js)
        # правила поменяли в другой вкладке — опрос перерисовывает строки (старая строка сохранила бы прежний набор)
        self.assertIn("JSON.stringify(S.routing.rules) !== rulesDrawn)) drawRoutingRules();", js)
        self.assertIn("rulesDrawn = JSON.stringify(S.routing.rules);", js)


class SmallUiTest(unittest.TestCase):
    def test_default_and_date_field(self):
        root = os.path.join(os.path.dirname(__file__), "..", "app", "static")
        with open(os.path.join(root, "i18n.js"), encoding="utf-8") as f:
            src = f.read()
        self.assertIn('"rt.else": "По умолчанию"', src)               # вместо «Всё остальное» (владелец 2026-11-19)
        self.assertNotIn("Всё остальное", src)
        # пример в поле списка доменов: сначала зоны, потом сайты, ссылка — последней (владелец 2026-11-19)
        self.assertIn(r'"ls.domains_ph": ".net\n.ru\nyoutube.com\ngooglevideo.com\nhttps://example.com/domains.txt"', src)
        with open(os.path.join(root, "app.css"), encoding="utf-8") as f:
            css = f.read()
        self.assertIn("input[type=search], input[type=date], select, textarea {", css)   # как остальные поля
        self.assertRegex(css, r"\.field \{[^}]*align-content: start")  # поле рядом с высоким не растягивается


# ------------------------------------------------------------------ шифрование DNS после «Применить для …»
class DnsEncKeptTest(unittest.TestCase):
    """«Применить для …» включает DNS на сервере без шифрования в запросе (1.22.0): шифрование записывается (DoH),
    а не становится «Без шифрования» при следующем запуске; DNS на сервере 1.15.0 (до шифрования) — как было."""

    def test_button_writes_doh(self):
        from app import panel
        panel.engine.reconcile()                                          # демо-сервер (DRY_RUN)
        panel.store.mutate(lambda st: [st["settings"].pop(k, None) for k in ("panel_dns", "panel_dns_enc")])
        try:
            panel.engine.srv.update_server({"panel_dns": True})          # так шлёт panelDnsOn в routing.js
            self.assertEqual(panel.store.snapshot()["settings"].get("panel_dns_enc"), "doh")
            panel.engine.srv.update_server({"panel_dns": True, "panel_dns_enc": "dot"})
            panel.engine.srv.update_server({"panel_dns": True})
            self.assertEqual(panel.store.snapshot()["settings"].get("panel_dns_enc"), "dot")   # выбранное — не трогаем
        finally:
            panel.store.mutate(lambda st: [st["settings"].pop(k, None) for k in ("panel_dns", "panel_dns_enc")])

    def test_start_and_backup_by_release(self):
        import json
        import tempfile
        from app.api import backup
        d = tempfile.mkdtemp()
        for upgraded, want in ((None, "plain"), (["rule_names"], "doh"), (["rule_names", "client_bot"], "doh")):
            st = {"settings": {"panel_dns": True}}
            if upgraded:
                st["upgraded"] = upgraded
            path = os.path.join(d, "state.json")
            with open(path, "w") as f:
                json.dump(st, f)
            self.assertEqual(Store(path).snapshot()["settings"].get("panel_dns_enc"), want, upgraded)
            self.assertEqual(backup.clean_backup_state(st)["settings"].get("panel_dns_enc"), want, upgraded)
        st = backup.clean_backup_state({"settings": {"panel_dns": False}, "upgraded": ["rule_names"]})
        self.assertNotIn("panel_dns_enc", st["settings"])               # DNS на сервере выключен — DoH по умолчанию


# ------------------------------------------------------------------ Г1 (глубокая проверка 1.23.0): первый проход
class FirstPassExitTest(unittest.TestCase):
    """Г1: правила до запуска туннелей (_hold_rules) ставились раньше первой проверки выходов. Выход без записи
    в health уходил на резерв, и с резервом «Напрямую» после запуска, обновления панели и перезагрузки сервера его
    клиенты 1–2 с шли мимо выхода (так было и в 1.22.0; подтверждено на тестовом VPS). Так же — выход AWG, который
    ждёт подъёма сервера на модуле ядра (engine_pending): он не упал, а ещё не запущен."""

    def eng(self):
        e = engine_mod.Engine.__new__(engine_mod.Engine)
        e.rt, e.health = {}, {}
        e.over_quota = lambda u: False
        st = {"upstreams": [{"id": "u1", "num": 1, "name": "x", "enabled": True, "fallback": "direct"}]}
        return e, st

    def test_no_record_is_block(self):
        e, st = self.eng()
        self.assertEqual(e.resolve("up:u1", st), "block")              # проверки ещё не было
        st["upstreams"][0]["enabled"] = False
        self.assertEqual(e.resolve("up:u1", st), "direct")             # выключенный выход — резерв, как раньше
        st["upstreams"][0]["enabled"] = True
        e._update_health(mock.Mock(), st)                               # проверка была: туннеля нет — упал
        self.assertEqual(e.health["u1"]["state"], "down")
        self.assertEqual(e.resolve("up:u1", st), "direct")

    def test_waiting_for_server_is_block(self):
        e, st = self.eng()
        e._waiting = {"u1"}                                             # _sync_upstreams не запустил: ждёт сервер
        e._update_health(mock.Mock(), st)
        self.assertEqual(e.health["u1"]["state"], "connecting")
        self.assertEqual(e.resolve("up:u1", st), "block")
        e._waiting = set()                                              # сервер поднялся, а выход не запустился
        e._update_health(mock.Mock(), st)
        self.assertEqual(e.resolve("up:u1", st), "direct")


# ------------------------------------------------------------------ глубокая проверка 1.23.0: почти даром
class AuditSmallFixesTest(unittest.TestCase):
    def test_one_line_refuses_every_line_break(self):
        """Г7: I1 из резервной копии с U+2028 проходил проверку «одна строка» (искала только \\n и \\r)."""
        from app import awgserver
        prof = awgserver.ClientProfile(host="203.0.113.5", port=51820, server_pub="pub", dns=["1.1.1.1"])
        peer = awgserver.Peer(public_key="pk", allowed_ips="10.8.1.2/32")
        awgserver._one_line(prof, peer, "priv", {"I1": "<b 0xf6ab3267fa>"})               # обычное — можно
        for c in ("\n", "\r", " ", " ", "\x85", "\x0b", "\x0c", "\x1c"):
            with self.assertRaises(awgserver.ServerConfError, msg=repr(c)):
                awgserver._one_line(prof, peer, "priv", {"I1": "<b 0x01>" + c + "[Peer]"})
            with self.assertRaises(awgserver.ServerConfError, msg=repr(c)):
                awgserver._one_line(awgserver.ClientProfile(host="h" + c + "x", port=1, server_pub="p", dns=[]),
                                    peer, "priv", {})

    def test_totp_any_digits(self):
        """Г9: код 2FA персидскими (۱۲۳) или полноширинными цифрами — тот же код; «²» — не цифра, а не ошибка 500."""
        from app import totp
        sec = "JBSWY3DPEHPK3PXP"
        now = 1_700_000_000
        code = totp.code_at(sec, int(now // totp.STEP))
        fa = "".join(chr(0x6F0 + int(d)) for d in code)
        wide = "".join(chr(0xFF10 + int(d)) for d in code)
        for c in (code, fa, wide, code[:3] + " " + code[3:]):
            self.assertIsNotNone(totp.match(sec, c, now=now), c)
        self.assertIsNone(totp.match(sec, "²" * 6, now=now))

    def test_backup_body_limit(self):
        """Г2: копия больше 4 МБ (тысяча клиентов с историей, большие списки) не загружалась обратно: 413."""
        from app.api import backup
        from app import web
        seen = []

        class Req:
            def json(self, limit=web.MAX_BODY):
                seen.append(limit)
                return {}
        for fn in (backup.restore_backup, backup.decrypt_backup):
            with self.assertRaises((ValueError, KeyError, TypeError, RuntimeError, OSError, LookupError, AttributeError, web.HTTPError)):
                fn(Req())
        self.assertEqual(seen, [backup.BACKUP_BODY] * 2)
        self.assertGreater(backup.BACKUP_BODY, 4 * web.MAX_BODY)
