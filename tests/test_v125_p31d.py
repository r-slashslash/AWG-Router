"""1.25.0, исправления по независимой проверке П31 (коды находок — Д): застрявший номер дескриптора (Д10), одинаковые
запросы в пути (Д1), «фильтр по DNS» ждёт записи нового адреса в набор (Д2), запасной после ожидания — из нынешних
настроек (Д7), «Запасной DNS тоже не отвечает» без «не отвечают напрямую» (Д8), запасной по имени на «Напрямую — адрес»
(Д6) и пробелы тестов П31, которые нашла проверка (её поломки M8, M41, M38, M34, M39). Каждый класс падает на d7a90cc (до
этих исправлений), кроме охраны того, что было и раньше (сказано в самом тесте).
Подделки сети — Net из test_v125_p31; Д10 — настоящий TLS и настоящий пул соединений.
python3 -m unittest tests.test_v125_p31d"""
import asyncio
import json
import os
import socket
import ssl
import struct
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
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from app import dnsproxy  # noqa: E402
from tests.test_v115 import a_reply, q_msg  # noqa: E402
from tests.test_v125_p31 import (AM, EXIT, FB, FB2, LONG, SHARED, Net, ask, busy, proxy, run,  # noqa: E402
                                 settle, who)


def conf_proxy(**cfg) -> dnsproxy.Proxy:
    """Proxy с настоящими _enc, _udp и пулами (без подделок сети)."""
    d = tempfile.mkdtemp()
    conf = os.path.join(d, "dns.json")
    base = {"listen": "10.8.1.1", "port": 53, "clients": "10.8.1.0/24", "upstreams": ["1.1.1.1"], "encrypt": "dot",
            "direct_fallback": ["77.88.8.8"], "default": {"mark": 0, "tcp": False}, "routes": {}}
    base.update(cfg)
    with open(conf, "w") as f:
        json.dump(base, f)
    return dnsproxy.Proxy(conf)


def reload(p, **cfg):
    """SIGHUP с новыми настройками."""
    with open(p.conf_path, "w") as f:
        json.dump(dict(p.cfg, **cfg), f)
    p.load()


class DelayNet(Net):
    """Net, где у имени свой срок ответа (delay, с) и свой адрес в ответе (ips) — у всех серверов."""

    def __init__(self):
        super().__init__()
        self.delay, self.ips = {}, {}

    async def enc(self, msg, server, mark, mode):
        name = dnsproxy.read_name(msg, 12)
        if name in self.delay:
            self.seen.append((mode, server, mark, name))
            await asyncio.sleep(self.delay[name])
            return a_reply(msg, [self.ips.get(name, self.answer.get(server, SHARED))])
        if name in self.ips and self.mode.get(server, "ok") == "ok":
            self.seen.append((mode, server, mark, name))
            return a_reply(msg, [self.ips[name]])
        return await super().enc(msg, server, mark, mode)


# ------------------------------------------------------------------ Д10
class StuckDescriptorTest(unittest.TestCase):
    """Д10: отмена соединения DoT/DoH сразу после рукопожатия TLS (срок запроса или отмена лишних запросов проверки
    пришлись на тот же оборот цикла). Сокет, отданный asyncio, закрывает только транспорт: раньше open_conn закрывал его
    сам, номер дескриптора освобождался, а транспорт ещё до 30 с вежливо закрывал TLS — и новый сокет с тем же номером
    не открывался («File descriptor N is used by transport»), проверка пути ложно не проходила. Способ отмены — как
    fdrace.py проверки: в _on_handshake_complete. Linux даёт новому сокету наименьший свободный номер: свободные номера
    ниже заняты на время теста, чтобы новый сокет получил именно его (как бывает под нагрузкой)."""

    @classmethod
    def setUpClass(cls):
        from tests.test_doh_http import cert
        cls.d = tempfile.mkdtemp()
        cls.crt, cls.key = cert(cls.d, "dns.test", ips=("127.0.0.1",))

    def test_new_connection_and_check_after_a_cancel(self):
        from asyncio import sslproto
        if not hasattr(sslproto.SSLProtocol, "_on_handshake_complete"):
            self.skipTest("другой asyncio")

        async def go():
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(self.crt, self.key)

            async def handler(r, w):
                try:
                    while True:
                        q = await r.readexactly(struct.unpack("!H", await r.readexactly(2))[0])
                        body = a_reply(q, ["203.0.113.9"])
                        w.write(struct.pack("!H", len(body)) + body)
                        await w.drain()
                except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
                    pass
                w.close()
            srv = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=sctx)
            port = srv.sockets[0].getsockname()[1]
            p = conf_proxy(upstreams=["127.0.0.1"], upstream_port=port, ca_file=self.crt)
            fds = []
            make = p._sock

            def sock(kind, mark):
                s = make(kind, mark)
                fds.append(s.fileno())
                return s
            p._sock = sock
            target = {}
            orig = sslproto.SSLProtocol._on_handshake_complete

            def hooked(proto, exc):
                orig(proto, exc)
                t = target.pop("task", None)
                if t is not None:
                    t.cancel()
            with mock.patch.object(sslproto.SSLProtocol, "_on_handshake_complete", hooked):
                task = asyncio.ensure_future(p._enc(q_msg("a.example"), "127.0.0.1", 0, "dot"))
                target["task"] = task
                with self.assertRaises(asyncio.CancelledError):
                    await task
            self.assertEqual(target, {})                          # отмена правда пришлась на конец рукопожатия
            holders = []
            try:
                while True:                                       # номера ниже отменённого — заняты
                    t = socket.socket()
                    if t.fileno() >= fds[0]:
                        t.close()
                        break
                    holders.append(t)
                t0 = time.monotonic()
                ok = await p._check(0, False)
                reply = await p._enc(q_msg("b.example"), "127.0.0.1", 0, "dot")
                dt = time.monotonic() - t0
            finally:
                for h in holders:
                    h.close()
                for pl in p.pools.values():
                    pl.close()
                srv.close()
            await asyncio.sleep(0.2)                              # вежливое закрытие TLS доходит до конца
            return ok, reply, dt
        ok, reply, dt = asyncio.run(go())
        self.assertTrue(ok)                                       # проверка пути на новом соединении прошла
        self.assertIn(socket.inet_aton("203.0.113.9"), reply)
        self.assertLess(dt, 3.0)                                  # а не 30 с ожидания чужого транспорта

    def test_source_closes_only_an_unconnected_socket(self):
        """В open_conn сокет закрывается вручную только до open_connection (не подключился); после — через транспорт
        (Conn.close). Тест по тексту: настоящая гонка выше ловит то же поведение, этот — место в коде."""
        import inspect
        src = inspect.getsource(dnsproxy.Proxy._enc)
        before, after = src.split("asyncio.open_connection(", 1)
        self.assertIn("s.close()", before)
        self.assertNotIn("s.close()", after)


# ------------------------------------------------------------------ Д1
def do_query(name: str, qid: int = 0x1234) -> bytes:
    """Запрос с EDNS и флагом DO (подписи DNSSEC)."""
    m = q_msg(name, qid=qid, edns=1232)
    return m[:-6] + struct.pack("!I", 0x8000) + m[-2:]


async def resolve(p, m, ip="10.8.1.5"):
    return await p.resolve(m, dnsproxy.parse_query(m), ip)


class SameQueryTest(unittest.TestCase):
    """Д1: одинаковый запрос, который уже в пути, не уходит к серверу снова — ждёт ответа первого. Каждому клиенту — его
    ID и регистр букв вопроса; разные пути, правило без пути и запросы с другими флагами не смешиваются."""

    def test_five_same_queries_one_to_the_server(self):
        net = DelayNet()
        net.delay["same.example."] = 0.1
        p = proxy(net)
        qs = [q_msg("SaMe.Example" if i % 2 else "same.example", qid=100 + i) for i in range(5)]

        async def go():
            return await asyncio.gather(*[resolve(p, m) for m in qs])
        outs = run(go)
        self.assertEqual(len([x for x in net.seen if x[3] == "same.example."]), 1)
        self.assertEqual(p.stats.get("joined"), 4)
        for m, r in zip(qs, outs):
            q = dnsproxy.parse_query(m)
            self.assertEqual(r[:2], m[:2])                                    # свой ID
            self.assertEqual(r[12:q["qend"]], m[12:q["qend"]])                # свой регистр букв
            self.assertEqual(who(r), "shared")

    def test_followers_take_no_client_place(self):
        net = DelayNet()
        net.delay["same.example."] = 0.1
        p = proxy(net)

        async def go():
            with mock.patch.object(dnsproxy, "MAX_INFLIGHT", 1):
                return await asyncio.gather(*[resolve(p, q_msg("same.example", qid=i)) for i in range(5)])
        self.assertEqual([who(r) for r in run(go)], ["shared"] * 5)

    def test_paths_rules_and_flags_apart(self):
        """Через выход и напрямую; имя правила без пути и то же имя у клиента без этого правила; с флагом DO и CD и без
        — каждый к серверу сам."""
        net = DelayNet()
        for n in ("e.example.", "www.youtube.com.", "f.example."):
            net.delay[n] = 0.1
        p = proxy(net)
        p.dom["clients"] = {"10.8.1.8": "p_other"}                # у этого клиента правила youtube.com нет
        cd = q_msg("f.example", qid=3)
        cd = cd[:2] + struct.pack("!H", 0x0110) + cd[4:]

        async def go():
            return await asyncio.gather(resolve(p, q_msg("e.example", qid=1)), resolve(p, q_msg("e.example", qid=2),
                                                                                      "10.8.1.7"),
                                        resolve(p, q_msg("www.youtube.com", qid=3)),
                                        resolve(p, q_msg("www.youtube.com", qid=4), "10.8.1.8"),
                                        resolve(p, q_msg("f.example", qid=1)), resolve(p, do_query("f.example", 2)),
                                        resolve(p, cd))
        run(go)
        seen = [(x[2], x[3]) for x in net.seen]
        self.assertEqual(sorted(seen.count((m, "e.example.")) for m in (0, EXIT)), [1, 1])
        self.assertEqual(seen.count((0, "www.youtube.com.")), 2)
        self.assertEqual(seen.count((0, "f.example.")), 3)
        self.assertFalse(p.stats.get("joined"))

    def test_rule_name_never_gets_the_fallback_answer(self):
        """Общие серверы замёрзли. Обычный клиент спросил имя первым — ему ответ запасного; клиент, у которого это имя
        — в правиле без пути (выход подключается, лежит, «блок»), ждёт своего: SERVFAIL, а не ответ запасного."""
        net = Net()
        net.mode["1.1.1.1"] = "freeze"
        p = proxy(net)
        p.dom["clients"] = {"10.8.1.8": "p_other"}

        async def go():
            first = asyncio.ensure_future(resolve(p, q_msg("www.youtube.com", qid=1), "10.8.1.8"))
            await asyncio.sleep(0.01)
            rule = await resolve(p, q_msg("www.youtube.com", qid=2))
            return await first, rule
        normal, rule = run(go)
        self.assertEqual(who(normal), "fb")
        self.assertEqual(who(rule), "SF")

    def test_a_follower_gets_its_own_servfail(self):
        net = Net()
        net.mode["1.1.1.1"] = "rst"
        p = proxy(net, direct_fallback=[])

        async def go():
            return await asyncio.gather(*[resolve(p, q_msg("x.example", qid=50 + i)) for i in range(3)])
        outs = run(go)
        self.assertEqual([who(r) for r in outs], ["SF"] * 3)
        self.assertEqual([r[:2] for r in outs], [struct.pack("!H", 50 + i) for i in range(3)])
        self.assertEqual(p.stats["errors"], 3)

    def test_first_client_gone_others_answered(self):
        net = DelayNet()
        net.delay["same.example."] = 0.15
        p = proxy(net)

        async def go():
            t1 = asyncio.ensure_future(resolve(p, q_msg("same.example", qid=1)))
            await asyncio.sleep(0.02)
            t2 = asyncio.ensure_future(resolve(p, q_msg("same.example", qid=2)))
            await asyncio.sleep(0.02)
            t1.cancel()                                           # первый клиент ушёл (соединение TCP закрылось)
            return await t2
        self.assertEqual(who(run(go)), "shared")

    def test_repeated_dead_name_one_query_one_check(self):
        """«Мёртвое» имя повторяют 10 раз, пока первый запрос ждёт: к серверу — один запрос, проверка пути — одна."""
        net = Net()
        net.slow["1.1.1.1"] = {"dead.example."}
        p = proxy(net, direct_fallback=[])

        async def go():
            tasks = []
            for i in range(10):
                tasks.append(asyncio.ensure_future(resolve(p, q_msg("dead.example", qid=i), f"10.8.1.{10 + i % 3}")))
                await asyncio.sleep(0.02)
            outs = await asyncio.gather(*tasks)
            await settle(p)
            return outs
        outs = run(go)
        self.assertEqual([who(r) for r in outs], ["SF"] * 10)
        self.assertEqual(len([x for x in net.seen if x[3] == "dead.example."]), 1)
        self.assertEqual(p.stats.get("checks"), 1)

    def test_no_joining_across_a_sighup(self):
        """Запрос, начатый до SIGHUP с новыми серверами, отвечает своим клиентам, а такой же запрос после SIGHUP идёт к
        новым серверам, а не ждёт ответа прежних."""
        net = DelayNet()
        net.delay["same.example."] = 0.2
        net.answer["9.9.9.9"] = FB2
        p = proxy(net)

        async def go():
            first = asyncio.ensure_future(resolve(p, q_msg("same.example", qid=1)))
            await asyncio.sleep(0.05)
            reload(p, upstreams=["9.9.9.9"])
            second = await resolve(p, q_msg("same.example", qid=2))
            return await first, second
        first, second = run(go)
        self.assertEqual(who(first), "shared")                   # прежний сервер
        self.assertEqual(who(second), "fb2")                     # новый: 9.9.9.9 отвечает адресом FB2
        self.assertEqual([x[1] for x in net.seen if x[3] == "same.example."], ["1.1.1.1", "9.9.9.9"])

    def test_dead_name_does_not_hold_the_pool(self):
        """Настоящий пул соединений (POOL_SIZE = 4): «мёртвое» имя повторяют 6 раз — оно занимает одно соединение, и
        новое имя отвечается сразу. Раньше 4 повтора занимали все соединения, и новое имя ждало очереди до их срока."""
        p = conf_proxy()

        class C:
            reusable, used = True, 0.0

            def __init__(self):
                self.reader = type("R", (), {"at_eof": lambda s: False})()

            def close(self):
                pass

        async def open_conn():
            return C()
        pool = dnsproxy.Pool(open_conn)
        pool.host, pool.path = "cloudflare-dns.com", "/dns-query"
        p.pools[("dot", 0, "1.1.1.1")] = pool

        async def dot(conn, msg):
            if dnsproxy.read_name(msg, 12) == "dead.example.":
                await asyncio.sleep(LONG)
            return a_reply(msg, [SHARED])

        async def go():
            tasks = []
            for i in range(6):
                tasks.append(asyncio.ensure_future(resolve(p, q_msg("dead.example", qid=i))))
                await asyncio.sleep(0.01)
            t0 = time.monotonic()
            r = await resolve(p, q_msg("new.example"))
            dt = time.monotonic() - t0
            await asyncio.gather(*tasks)
            return r, dt
        with mock.patch.object(dnsproxy, "dot_query", dot), mock.patch.object(dnsproxy, "UDP_TIMEOUT", 0.05):
            r, dt = run(go)
        self.assertEqual(who(r), "shared")
        self.assertLess(dt, 0.1)


# ------------------------------------------------------------------ Д2
class SetWriteTest(unittest.TestCase):
    """Д2: «фильтр по DNS» — адрес из ответа на имя правила, которого ещё нет в наборе nftables, сначала записывается в
    набор, потом ответ уходит клиенту: клиент соединяется сразу, и соединение к адресу не из набора шло по правилам
    адресов — мимо выхода. Уже известный адрес — без ожидания; nft, который ждёт пересборку таблицы, держит ответ не
    дольше SET_WAIT. nft подменён (subprocess.run в потоке, как настоящий)."""

    def setUp(self):
        self.calls = []                       # (начало, конец, адреса)
        self.delay = 0.05
        self.lock = threading.Lock()

    def fake_run(self, cmd, **kw):
        t0 = time.monotonic()
        time.sleep(self.delay)
        with self.lock:
            self.calls.append((t0, time.monotonic(), cmd[6]))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def _proxy(self):
        net = DelayNet()
        p = proxy(net)
        p.dom = {"lists": p.dom["lists"], "clients": {}, "set": ["awgr", "dom4"],
                 "policies": {"p_global": [[["l1"], {"mark": EXIT, "tcp": False}]]}}
        return net, p

    def _run(self, go):
        with mock.patch.object(dnsproxy.subprocess, "run", side_effect=self.fake_run):
            return run(go)

    def written(self, ip) -> float | None:
        """Когда кончилась команда nft, которая добавила адрес."""
        for _t0, t1, elems in self.calls:
            if f"{ip} timeout" in elems:
                return t1
        return None

    def test_new_address_written_before_the_answer(self):
        net, p = self._proxy()
        net.ips["www.youtube.com."] = "192.0.2.10"

        async def go():
            r = await resolve(p, q_msg("www.youtube.com"))
            return r, time.monotonic()
        r, t = self._run(go)
        self.assertIn(socket.inet_aton("192.0.2.10"), r)
        self.assertIsNotNone(self.written("192.0.2.10"))
        self.assertGreaterEqual(t, self.written("192.0.2.10"))
        self.assertFalse(p.stats.get("set_late"))

    def test_known_address_answered_at_once(self):
        """Охрана (так было и раньше): адрес уже в наборе — ответ не ждёт nft, новой команды нет."""
        net, p = self._proxy()
        net.ips.update({"a.youtube.com.": "192.0.2.11", "b.youtube.com.": "192.0.2.11"})

        async def go():
            await resolve(p, q_msg("a.youtube.com"))
            await asyncio.sleep(dnsproxy.SET_FLUSH)
            self.delay = 0.5
            t0 = time.monotonic()
            await resolve(p, q_msg("b.youtube.com"))
            return time.monotonic() - t0
        self.assertLess(self._run(go), 0.05)
        self.assertEqual(len(self.calls), 1)

    def test_second_client_waits_for_the_write_in_progress(self):
        net, p = self._proxy()
        net.ips.update({"a.youtube.com.": "192.0.2.12", "b.youtube.com.": "192.0.2.12"})
        self.delay = 0.2

        async def go():
            first = asyncio.ensure_future(resolve(p, q_msg("a.youtube.com")))
            await asyncio.sleep(0.05)                     # команда nft уже идёт
            await resolve(p, q_msg("b.youtube.com"))
            t = time.monotonic()
            await first
            return t
        t = self._run(go)
        self.assertGreaterEqual(t, self.written("192.0.2.12"))
        self.assertEqual(len(self.calls), 1)

    def test_table_rebuild_holds_the_answer_at_most_set_wait(self):
        net, p = self._proxy()
        net.ips["www.youtube.com."] = "192.0.2.13"
        self.delay = 2.0                                  # панель пересобирает таблицу: nft ждёт

        async def go():
            t0 = time.monotonic()
            r = await resolve(p, q_msg("www.youtube.com"))
            return r, time.monotonic() - t0
        with mock.patch.object(dnsproxy, "SET_WAIT", 0.3):
            r, dt = self._run(go)
        self.assertIn(socket.inet_aton("192.0.2.13"), r)
        self.assertGreaterEqual(dt, 0.3)
        self.assertLess(dt, 0.6)
        self.assertEqual(p.stats.get("set_late"), 1)

    def test_batch_one_command_and_the_loop_keeps_answering(self):
        """30 имён с новыми адресами разом — не больше двух команд nft (одна идёт, следующие копятся), каждый ответ — после
        записи своего адреса; пока nft работает, имена не из правил отвечаются сразу."""
        net, p = self._proxy()
        for i in range(30):
            net.ips[f"n{i}.youtube.com."] = f"192.0.2.{100 + i}"
        self.delay = 0.3

        async def one(i):
            await resolve(p, q_msg(f"n{i}.youtube.com", qid=i))
            return i, time.monotonic()

        async def go():
            rule = [asyncio.ensure_future(one(i)) for i in range(30)]
            await asyncio.sleep(0.05)
            t0 = time.monotonic()
            other = await resolve(p, q_msg("other.example"))
            lag = time.monotonic() - t0
            return await asyncio.gather(*rule), other, lag
        done, other, lag = self._run(go)
        self.assertLessEqual(len(self.calls), 2)
        for i, t in done:
            self.assertIsNotNone(self.written(f"192.0.2.{100 + i}"), i)
            self.assertGreaterEqual(t, self.written(f"192.0.2.{100 + i}"), i)
        self.assertEqual(who(other), "shared")
        self.assertLess(lag, 0.05)

    def test_without_the_filter_nothing_waits(self):
        """Охрана: без набора (галочка выключена) и для имён не из правил — как раньше, nft не вызывается."""
        net, p = self._proxy()
        p.dom["set"] = None
        net.ips["www.youtube.com."] = "192.0.2.14"

        async def go():
            await resolve(p, q_msg("www.youtube.com"))
            await resolve(p, q_msg("other.example"))
        self._run(go)
        self.assertEqual(self.calls, [])


# ------------------------------------------------------------------ Д7
class FallbackAfterWaitTest(unittest.TestCase):
    """Д7: имя ждало общие серверы (до ENC_TIMEOUT × 2), за это время запасной сменили или выключили (SIGHUP) — имя идёт
    к нынешнему запасному, а прежний не спрашивается."""

    def _go(self, **cfg):
        net = Net()
        net.mode["1.1.1.1"] = "freeze"
        net.answer["77.88.8.9"] = FB2
        p = proxy(net)

        async def go():
            first = asyncio.ensure_future(ask(p, "a.example"))
            await asyncio.sleep(0.1)
            reload(p, **cfg)
            r = await first
            await settle(p)
            return r
        return net, p, run(go)

    def test_changed_fallback(self):
        net, p, r = self._go(direct_fallback=["77.88.8.9"])
        self.assertEqual(r[0], "fb2")
        self.assertEqual([x for x in net.seen if x[1] == "77.88.8.8"], [])

    def test_fallback_turned_off(self):
        net, p, r = self._go(direct_fallback=[])
        self.assertEqual(r[0], "SF")
        self.assertEqual([x for x in net.seen if x[1] == "77.88.8.8"], [])


# ------------------------------------------------------------------ Д8
class FallbackLineTest(unittest.TestCase):
    """Д8: «Запасной DNS тоже не отвечает» — только вместе с «Серверы DNS не отвечают напрямую». После того как общие
    снова отвечают, запасной никто не спрашивает, и строка держалась до 15 минут."""

    def view(self, stats: dict) -> dict:
        import types
        from app import config
        from app.engine import Engine
        from app.engine import dns as edns
        e = Engine.__new__(Engine)
        e.dns_state = {"state": "on", "listen": "10.8.1.1", "encrypt": "doh"}
        e.dns = types.SimpleNamespace(proc=types.SimpleNamespace(pid=4242))
        path = os.path.join(tempfile.mkdtemp(), "dns-stats.json")
        with open(path, "w") as f:
            json.dump({"pid": 4242, "at": time.time(), **stats}, f)
        with mock.patch.object(edns, "DNS_STATS", path), mock.patch.object(config, "DRY_RUN", False):
            return e.dns_view()

    def test_line_goes_with_the_warning(self):
        now = time.time()
        fb_failed = {"fallback": ["77.88.8.8"], "fb_paths": {"0": [now - 300, now - 200]}}
        back = self.view({"direct_ok_at": now - 10, "direct_fail_at": now - 200, **fb_failed})
        self.assertNotIn("direct_down", back)
        self.assertNotIn("fallback", back)                       # общие снова отвечают — строки нет
        down = self.view({"direct_ok_at": now - 300, "direct_fail_at": now - 200, **fb_failed})
        self.assertTrue(down.get("direct_down"))
        self.assertEqual(down.get("fallback"), "down")           # охрана: вместе с предупреждением — есть


# ------------------------------------------------------------------ Д6
class NamedFallbackOnAddressTest(unittest.TestCase):
    """Д6: «Напрямую — адрес», общие серверы без шифрования не отвечают, запасной вписан именем (tls://…): искать его
    адрес этим путём нечем — берётся адрес, который нашла панель (запись «#адрес»), соединение — с этого адреса, имя
    в сертификате — то же. Раньше запасной на 2 минуты становился «не отвечает», хотя исправен."""

    def test_names_get_the_fallback_answer(self):
        entry = "tls://dns.test#77.88.8.8"
        net = Net()
        net.mode["1.1.1.1"] = "drop"
        p = proxy(net, encrypt="plain", direct_fallback=[entry])
        net.answer[entry] = FB

        async def go():
            first = await ask(p, "a.example", "10.8.1.6")
            await settle(p, AM)
            return first, [await ask(p, f"n{i}.example", "10.8.1.6") for i in range(2)]
        first, nxt = run(go)
        self.assertEqual(first[0], "fb")
        self.assertEqual([w for w, _ in nxt], ["fb", "fb"])
        self.assertTrue(p._dp(AM).down)
        self.assertFalse(p._dp(AM).fb_down)
        asked = [x for x in net.seen if x[1] == entry]
        self.assertTrue(asked)
        self.assertEqual({x[2] for x in asked}, {AM})            # с адреса пути, а не с адреса системы
        self.assertEqual({x[0] for x in asked}, {"dot"})         # шифрованным, как вписан
        self.assertGreaterEqual(p.stats.get("name_hint", 0), 1)

    def test_path_lookup_first(self):
        """Охрана А11: общие этим путём отвечают — адрес имени ищется ими (с этого адреса), подсказка панели не нужна."""
        entry = "tls://dns.test#77.88.8.8"
        net = Net()
        p = proxy(net, encrypt="plain", direct_fallback=[entry])
        net.ips = {}

        async def udp(msg, server, mark):
            net.seen.append(("udp", server, mark, dnsproxy.read_name(msg, 12)))
            if dnsproxy.read_name(msg, 12) == "dns.test.":
                return a_reply(msg, ["198.51.100.53"])
            return None
        p._udp = udp

        async def go():
            return await p._name_addr("dns.test", AM, False, "77.88.8.8")
        self.assertEqual(run(go), "198.51.100.53")
        self.assertFalse(p.stats.get("name_hint"))


# ------------------------------------------------------------------ пробелы тестов П31 (раздел 7 отчёта)
class FallbackCheckFromTheAddressTest(unittest.TestCase):
    """M8: проверка запасного на «Напрямую — адрес» — с адреса этого пути (его метка), как и сам запасной."""

    def test_fallback_check_mark(self):
        net = Net()
        net.mode["1.1.1.1"] = "rst"
        p = proxy(net)
        net.slow["77.88.8.8"] = {"slow.example."}

        async def go():
            await ask(p, "a.example", "10.8.1.6")
            await settle(p, AM)
            await ask(p, "slow.example", "10.8.1.6")
            self.assertTrue(busy(p._dp(AM).fb_probe))
            await settle(p, AM)
        run(go)
        marks = {x[2] for x in net.checks("77.88.8.8")}
        self.assertEqual(marks, {AM})
        self.assertFalse(p._dp(AM).fb_down)


class CheckOnAFreshConnectionTest(unittest.TestCase):
    """M41: проверка пути не берёт простаивающее соединение пула: его сервер или NAT могли тихо закрыть («замёрзло»), и
    проверка на нём сочла бы живой сервер молчащим."""

    def test_frozen_idle_connection_skipped(self):
        p = conf_proxy()

        class C:
            reusable = True

            def __init__(self, frozen=False):
                self.frozen, self.used = frozen, time.monotonic()
                self.reader = type("R", (), {"at_eof": lambda s: False})()

            def close(self):
                pass

        async def open_conn():
            return C()
        pool = dnsproxy.Pool(open_conn)
        pool.host, pool.path = "cloudflare-dns.com", "/dns-query"
        pool.idle.append(C(frozen=True))
        p.pools[("dot", 0, "1.1.1.1")] = pool

        async def dot(conn, msg):
            if conn.frozen:
                await asyncio.sleep(LONG)
            return a_reply(msg, [SHARED])
        with mock.patch.object(dnsproxy, "dot_query", dot), mock.patch.object(dnsproxy, "POOL_IDLE", 3600):
            self.assertTrue(run(lambda: p._check(0, False)))
        self.assertEqual(len(pool.idle), 1)                       # простаивающее осталось нетронутым


class FallbackAnsweredMeanwhileTest(unittest.TestCase):
    """M38 (зеркало теста общих серверов): проверка запасного не успела, а он тем временем ответил на другое имя — он на
    связи, «запасной не отвечает» не ставится."""

    def test_answer_during_the_check_wins(self):
        net = Net()
        net.mode["1.1.1.1"] = "rst"
        p = proxy(net)

        async def udp(msg, server, mark):
            name = dnsproxy.read_name(msg, 12)
            if name == "slow.example.":
                await asyncio.sleep(0.05)
                return None
            if name == "late.example.":
                await asyncio.sleep(0.15)
            elif name == ".":
                await asyncio.sleep(LONG)                         # проверка запасного не успевает
            return a_reply(msg, [FB])
        p._udp = udp

        async def go():
            await ask(p, "a.example")
            await settle(p)
            self.assertTrue(p.direct_down)
            late = asyncio.ensure_future(ask(p, "late.example"))
            await ask(p, "slow.example")
            self.assertTrue(busy(p._dp(0).fb_probe))
            r = await late
            await settle(p)
            return r
        self.assertEqual(run(go)[0], "fb")
        self.assertFalse(p._dp(0).fb_down)
        self.assertEqual(p._dp(0).fb_fail_at, 0.0)


class NoFallbackOneCheckTest(unittest.TestCase):
    """M34: без запасного серверы молчат — после неудачной проверки следующие имена без ответа не начинают новых проверок
    до DIRECT_RETRY (только продлевают «не отвечают» для «Сервера»)."""

    def test_twenty_names_one_check(self):
        net = Net()
        net.mode["1.1.1.1"] = "rst"
        p = proxy(net, direct_fallback=[])

        async def go():
            for i in range(20):
                await ask(p, f"n{i}.example")
                await settle(p)
        run(go)
        self.assertEqual(len(net.checks("1.1.1.1")), 1)
        self.assertEqual(p.stats.get("checks"), 1)
        self.assertGreater(p.direct_fail_at, p.direct_ok_at)


class RuleNameStartsTheCheckTest(unittest.TestCase):
    """M39: имя правила без пути (к запасному ему нельзя) осталось без ответа — проверка пути всё равно ставит «не
    отвечают», и обычные имена этого пути сразу идут к запасному, а не ждут замёрзшие общие серверы."""

    def test_normal_names_at_once(self):
        net = Net()
        net.mode["1.1.1.1"] = "freeze"
        p = proxy(net)

        async def go():
            rule = await ask(p, "www.youtube.com")
            await settle(p)
            return rule, await ask(p, "a.example")
        rule, normal = run(go)
        self.assertEqual(rule[0], "SF")
        self.assertTrue(p.direct_down)
        self.assertEqual(normal[0], "fb")
        self.assertLess(normal[1], 0.05)


if __name__ == "__main__":
    unittest.main()
