"""1.25.0, исправления по проверке исправлений П31 (коды находок — Е): повтор запроса в начале блокировки идёт к запасному,
а не ждёт первого (Е1), предел ждущих одного запроса (Е3), «Запасной DNS тоже не отвечает» — только по своему пути (Е6),
набор «фильтра по DNS» на настоящем nftables (Е2; подделка набора — SetWriteTest в test_v125_p31d) и тесты на пробелы,
которые нашла проверка (раздел 7 её отчёта: поломки E6/E7, E24, E27, E32, E3, E33, E14). Каждый класс падает на c934013
(до этих исправлений) или на поломке, которую он охраняет (сказано в самом тесте).
python3 -m unittest tests.test_v125_p31e"""
import asyncio
import gc
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import warnings
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from app import dnsproxy  # noqa: E402
from tests.test_v115 import a_reply, q_msg  # noqa: E402
from tests.test_v125_p31 import FB, FB2, SHARED, Net, ask, proxy, run, settle, who  # noqa: E402
from tests.test_v125_p31d import DelayNet, FakeSet, conf_proxy, do_query, reload, resolve  # noqa: E402


# ------------------------------------------------------------------ Е1
class RetryDuringCheckTest(unittest.TestCase):
    """Е1: устройство повторяет запрос через 1–2 с (Windows, Linux). Пока путь «напрямую» проверяется или «не отвечает»,
    повтор идёт к запасному сам, а не ждёт первый запрос, который ещё ждёт общие серверы (ENC_TIMEOUT × 2 на каждый). С
    Д1 повтор присоединялся к первому — ответ до 20 с вместо 10–15 (настоящие Cloudflare и Google из России)."""

    def _go(self, at: float):
        """Общие (два DoH) замёрзли; срок — 0,4 с (запрос ждёт общий 0,8 с), запас 0,2 с с каждой стороны, чтобы тест не
        зависел от нагрузки машины. y — в 0 с, x — в 0,8 с; повтор x другим клиентом — в at с. → x, повтор, состояние пути."""
        net = Net()
        net.mode.update({"1.1.1.1": "freeze", "1.0.0.1": "freeze"})
        p = proxy(net, upstreams=["1.1.1.1", "1.0.0.1"])

        async def go():
            y = asyncio.ensure_future(ask(p, "y.example"))
            await asyncio.sleep(0.8)
            x = asyncio.ensure_future(ask(p, "x.example"))
            await asyncio.sleep(at - 0.8)
            state = (p.direct_down, _busy(p._dp(0).probe))
            again = await ask(p, "x.example", "10.8.1.9")
            out = await x, again, state
            await y
            await settle(p)
            return out
        with mock.patch.object(dnsproxy, "ENC_TIMEOUT", 0.4), mock.patch.object(dnsproxy, "CHECK_TIMEOUT", 0.4):
            return asyncio.run(go())

    def test_retry_while_the_path_is_checked(self):
        # y без ответа в 1,6 с → проверка 1,6–2,0 с; x ждёт общие до 2,4 с
        x, again, state = self._go(1.8)
        self.assertEqual(state, (False, True))
        self.assertEqual(again[0], "fb")
        self.assertLess(again[1], 0.1)
        self.assertEqual(x[0], "fb")                              # сам x — у запасного, когда дождался общих

    def test_retry_after_the_path_is_down(self):
        x, again, state = self._go(2.2)
        self.assertEqual(state, (True, False))
        self.assertEqual(again[0], "fb")
        self.assertLess(again[1], 0.1)

    def test_repeat_of_an_old_query_starts_the_check(self):
        """Е1, дальше: «популярное» имя в начале блокировки. Первый запрос ждёт общие (замёрзли), а путь ничего не ответил
        дольше JOIN_CHECK, — повтор, присоединившийся к нему позже JOIN_CHECK, начинает проверку пути сразу (одну на
        запрос); следующие клиенты получают ответ запасного, не дожидаясь срока первого. Без этого проверку начинал только
        конец первого запроса: в песочнице «популярное» имя ждало до 15 с против 11 до Д1."""
        net = Net()
        net.mode.update({"1.1.1.1": "freeze", "1.0.0.1": "freeze"})
        p = proxy(net, upstreams=["1.1.1.1", "1.0.0.1"])

        async def go():
            first = asyncio.ensure_future(ask(p, "x.example"))          # ждёт общие до 0,8 с
            await asyncio.sleep(0.35)
            rep = [asyncio.ensure_future(ask(p, "x.example", f"10.8.1.{20 + i}")) for i in range(3)]
            await asyncio.sleep(0.05)
            checking = _busy(p._dp(0).probe)
            other = await ask(p, "x.example", "10.8.1.30")
            out = checking, other, await first, await asyncio.gather(*rep)
            await settle(p)
            return out
        with mock.patch.object(dnsproxy, "JOIN_CHECK", 0.3, create=True):
            checking, other, first, rep = run(go)
        self.assertTrue(checking)
        self.assertEqual(p.stats.get("join_checks"), 1)
        self.assertEqual(other[0], "fb")
        self.assertLess(other[1], 0.1)
        self.assertEqual([w for w, _ in rep], ["fb"] * 3)           # присоединились до проверки — ждут первый, как Д1
        self.assertTrue(p.direct_down)

    def test_slow_name_on_a_live_path_starts_no_check(self):
        """Охрана: путь отвечает (другое имя получило ответ недавно), одно имя медленное и его повторяют — проверки от
        повтора нет, имена идут к общим, как с Д1."""
        net = Net()
        net.slow["1.1.1.1"] = {"slow.example."}
        p = proxy(net)

        async def go():
            first = asyncio.ensure_future(ask(p, "slow.example"))
            await asyncio.sleep(0.25)
            await ask(p, "a.example")                                    # путь отвечает
            await asyncio.sleep(0.1)
            await asyncio.gather(*[ask(p, "slow.example", f"10.8.1.{20 + i}") for i in range(3)])
            await first
            await settle(p)
        with mock.patch.object(dnsproxy, "JOIN_CHECK", 0.3, create=True):
            run(go)
        self.assertFalse(p.stats.get("join_checks"))
        self.assertEqual(p.stats.get("checks"), 1)                      # как и раньше: конец медленного имени
        self.assertFalse(p.direct_down)

    def test_repeat_of_a_young_query_starts_no_check(self):
        """Охрана: путь ещё ни разу не отвечал (только запустились), повтор пришёл раньше JOIN_CHECK — проверки нет, повтор
        ждёт первый, как Д1."""
        net = Net()
        net.slow["1.1.1.1"] = {"slow.example."}
        p = proxy(net)

        async def go():
            first = asyncio.ensure_future(ask(p, "slow.example"))
            await asyncio.sleep(0.1)
            again = await ask(p, "slow.example", "10.8.1.20")
            out = await first, again
            await settle(p)
            return out
        with mock.patch.object(dnsproxy, "JOIN_CHECK", 0.3, create=True):
            run(go)
        self.assertFalse(p.stats.get("join_checks"))

    def test_one_check_per_query(self):
        """Путь исправен, но молчит (больше никто не спрашивает), а «мёртвое» имя (у обоих общих серверов — первый запрос
        ждёт 0,8 с) повторяют после JOIN_CHECK и ещё раз позже двух JOIN_CHECK: проверка от повторов — одна (прошла: путь
        в порядке), и одна — в конце, как с Д1."""
        net = Net()
        net.slow["*"] = {"dead.example."}
        p = proxy(net, upstreams=["1.1.1.1", "1.0.0.1"])

        async def go():
            first = asyncio.ensure_future(ask(p, "dead.example"))
            reps, t0 = [], time.monotonic()
            for i, at in enumerate((0.32, 0.36, 0.66)):
                await asyncio.sleep(at - (time.monotonic() - t0))
                reps.append(asyncio.ensure_future(ask(p, "dead.example", f"10.8.1.{20 + i}")))
                await asyncio.sleep(0.01)
                await settle(p)
            await asyncio.gather(first, *reps)
            await settle(p)
        with mock.patch.object(dnsproxy, "JOIN_CHECK", 0.3, create=True):
            run(go)
        self.assertEqual(p.stats.get("join_checks"), 1)
        self.assertEqual(p.stats.get("checks"), 2)
        self.assertEqual(p.stats.get("checks_ok"), 2)
        self.assertFalse(p.direct_down)

    def test_repeats_still_join_at_the_fallback(self):
        """Польза Д1 остаётся: путь «не отвечает», «мёртвое» имя (молчит и запасной) повторяют 6 раз, пока первый ждёт
        запасной, — к запасному один запрос."""
        net = Net()
        net.mode["1.1.1.1"] = "rst"
        net.slow["77.88.8.8"] = {"dead.example."}
        p = proxy(net)

        async def go():
            await ask(p, "a.example")
            await settle(p)
            self.assertTrue(p.direct_down)
            tasks = []
            for i in range(6):
                tasks.append(asyncio.ensure_future(ask(p, "dead.example", f"10.8.1.{20 + i}")))
                await asyncio.sleep(0.01)
            return await asyncio.gather(*tasks)
        outs = run(go)
        self.assertEqual([w for w, _ in outs], ["SF"] * 6)
        self.assertEqual(len([x for x in net.seen if x[1] == "77.88.8.8" and x[3] == "dead.example."]), 1)
        self.assertEqual(p.stats.get("joined"), 5)

    def test_no_fallback_repeats_join(self):
        """Охрана: без запасного признак не нужен — повторы, как в Д1, ждут первый запрос (к серверу один)."""
        net = Net()
        net.mode["1.1.1.1"] = "freeze"
        p = proxy(net, direct_fallback=[])

        async def go():
            tasks = []
            for i in range(4):
                tasks.append(asyncio.ensure_future(ask(p, "x.example", f"10.8.1.{20 + i}")))
                await asyncio.sleep(0.05)
            return await asyncio.gather(*tasks)
        self.assertEqual([w for w, _ in run(go)], ["SF"] * 4)
        self.assertEqual(len([x for x in net.seen if x[3] == "x.example."]), 1)


def _busy(t) -> bool:
    return t is not None and not t.done()


# ------------------------------------------------------------------ Е3, E32
class WaitersLimitTest(unittest.TestCase):
    """Е3: ждущих одного запроса в пути — не больше JOIN_MAX, всех таких вместе — не больше JOIN_ALL; лишний сразу
    получает SERVFAIL (поток тысяч одинаковых запросов копил память без предела: 35 → 191–218 МБ за 30 с). E32: разных
    запросов к серверам одновременно — не больше MAX_INFLIGHT."""

    def test_join_max_plus_one(self):
        net = DelayNet()
        net.delay["same.example."] = 0.2
        p = proxy(net)

        async def go():
            tasks = [asyncio.ensure_future(resolve(p, q_msg("same.example", qid=i % 65536)))
                     for i in range(dnsproxy.JOIN_MAX + 1)]
            await asyncio.sleep(0.05)
            t0 = time.monotonic()
            extra = await resolve(p, q_msg("same.example", qid=7))
            dt = time.monotonic() - t0
            return await asyncio.gather(*tasks), extra, dt
        outs, extra, dt = run(go)
        self.assertEqual(dnsproxy.JOIN_MAX, 1024)
        self.assertEqual({who(r) for r in outs}, {"shared"})        # первый и 1024 ждущих — ответ сервера
        self.assertEqual(who(extra), "SF")
        self.assertLess(dt, 0.05)                                  # сразу, а не через 0,2 с
        self.assertEqual(p.stats.get("join_full"), 1)
        self.assertEqual(len([x for x in net.seen if x[3] == "same.example."]), 1)
        self.assertEqual((p.followers, p.joins), (0, {}))         # счёт ждущих вернулся к нулю

    def test_join_all(self):
        net = DelayNet()
        for i in range(3):
            net.delay[f"n{i}.example."] = 0.2
        p = proxy(net)

        async def go():
            tasks = [asyncio.ensure_future(resolve(p, q_msg(f"n{i % 3}.example", qid=i))) for i in range(9)]
            await asyncio.sleep(0.05)                              # 3 первых и 6 ждущих
            extra = await resolve(p, q_msg("n0.example", qid=99))
            outs = await asyncio.gather(*tasks)
            after = await resolve(p, q_msg("n0.example", qid=98))  # ждущих больше нет — снова как обычно
            return outs, extra, after
        with mock.patch.object(dnsproxy, "JOIN_ALL", 6, create=True):
            outs, extra, after = run(go)
        self.assertEqual({who(r) for r in outs}, {"shared"})
        self.assertEqual(who(extra), "SF")
        self.assertEqual(who(after), "shared")
        self.assertEqual((p.followers, p.joins), (0, {}))

    def test_max_inflight_513th(self):
        """E32: 512 разных имён в пути — 513-е сразу SERVFAIL, остальные отвечены (теста на этот предел не было совсем)."""
        net = DelayNet()
        n = dnsproxy.MAX_INFLIGHT
        for i in range(n + 1):
            net.delay[f"n{i}.example."] = 0.25
        p = proxy(net)

        async def go():
            tasks = [asyncio.ensure_future(resolve(p, q_msg(f"n{i}.example", qid=i))) for i in range(n)]
            await asyncio.sleep(0.05)
            t0 = time.monotonic()
            extra = await resolve(p, q_msg(f"n{n}.example"))
            dt = time.monotonic() - t0
            return await asyncio.gather(*tasks), extra, dt
        outs, extra, dt = run(go)
        self.assertEqual(n, 512)
        self.assertEqual({who(r) for r in outs}, {"shared"})
        self.assertEqual(who(extra), "SF")
        self.assertLess(dt, 0.05)
        self.assertEqual(p.inflight, 0)


# ------------------------------------------------------------------ Е6
class FallbackLinePerPathTest(unittest.TestCase):
    """Е6: «Запасной DNS тоже не отвечает» — только если запасной не ответил у того пути, где общие не отвечают. Два
    «Напрямую — адрес»: у первого общие не отвечают, а его запасной работает (имена идут через него); у второго общие
    отвечают, а запасной недавно не ответил — строки нет («Сейчас используется …»)."""

    def view(self, stats):
        from tests.test_v125_p31d import FallbackLineTest
        return FallbackLineTest.view(self, stats)

    def test_two_addresses(self):
        now = time.time()
        base = {"fallback": ["77.88.8.8"], "direct_ok_at": now - 10, "direct_fail_at": 0,
                "addr_direct": {"8449": [now - 300, now - 200], "8450": [now - 10, now - 400]}}
        v = self.view({**base, "fb_paths": {"0": [0, 0], "8449": [now - 5, 0], "8450": [now - 600, now - 100]}})
        self.assertTrue(v.get("direct_down"))
        self.assertEqual(v.get("fallback"), "used")
        v = self.view({**base, "fb_paths": {"0": [0, 0], "8449": [now - 300, now - 50], "8450": [now - 600, now - 100]}})
        self.assertEqual(v.get("fallback"), "down")              # у первого не отвечает и запасной — строка есть

    def test_one_path_as_before(self):
        """Охрана: один путь — как было (Д8): общие не отвечают и запасной тоже — «down»; общие отвечают — ничего."""
        now = time.time()
        fb = {"fallback": ["77.88.8.8"], "fb_paths": {"0": [now - 300, now - 200]}}
        self.assertEqual(self.view({"direct_ok_at": now - 300, "direct_fail_at": now - 200, **fb}).get("fallback"), "down")
        self.assertNotIn("fallback", self.view({"direct_ok_at": now - 10, "direct_fail_at": now - 200, **fb}))


# ------------------------------------------------------------------ Е2 на настоящем nftables
class RealSetTest(unittest.TestCase):
    """Е2 на настоящем ядре: tests/dns_set_check.py в своей сети — срок адреса после повторной записи растёт (с тем же и
    с другим сроком), пакеты к адресу ни разу не прошли мимо набора за 100 перезаписей, resync 20 000 адресов — одной
    транзакцией. Только от root и с nft; на машинах GitHub (ядра 6.8 и 7.x) — задание dns-set в net-tests."""

    @unittest.skipUnless(os.geteuid() == 0 and shutil.which("nft") and shutil.which("unshare"), "нужны root и nft")
    def test_real_set(self):
        here = os.path.dirname(os.path.abspath(__file__))
        r = subprocess.run(["unshare", "-n", sys.executable, os.path.join(here, "dns_set_check.py")],
                           capture_output=True, text=True, timeout=180, cwd=os.path.dirname(here))
        res = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual(res["bad"], [], res)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(res["resync_nft_runs"], 1)


# ------------------------------------------------------------------ пробелы тестов (раздел 7 отчёта проверки Е)
class CacheProfilesTest(unittest.TestCase):
    """E6 / E7: три профиля запроса — без EDNS (Windows, macOS, glibc), EDNS без DO (systemd-resolved), EDNS + DO
    (проверка DNSSEC) — три запроса к серверу и в кэше, и в объединении: CacheFlagsTest сравнивал только «без EDNS» с
    «EDNS + DO», и второй флаг закрывал поломку первого."""

    def _enc(self, seen):
        async def enc(msg, server, mark, mode):
            q = dnsproxy.parse_query(msg)
            seen.append((q["name"], q["edns"], q["do"]))
            await asyncio.sleep(0.05)
            return a_reply(msg, [FB if q["do"] else FB2 if q["edns"] else SHARED])
        return enc

    def profiles(self, name):
        return [q_msg(name, qid=1), q_msg(name, qid=2, edns=1232), do_query(name, 3)]

    def test_cache(self):
        p, seen = proxy(Net()), []
        p._enc = self._enc(seen)

        async def go():
            return [who(await resolve(p, m)) for m in self.profiles("sig.example") + self.profiles("sig.example")]
        self.assertEqual(run(go), ["shared", "fb2", "fb"] * 2)
        self.assertEqual(len(seen), 3)
        self.assertEqual(p.stats["cached"], 3)

    def test_joined(self):
        p, seen = proxy(Net()), []
        p._enc = self._enc(seen)

        async def go():
            return [who(r) for r in await asyncio.gather(*[resolve(p, m) for m in self.profiles("j.example")])]
        self.assertEqual(run(go), ["shared", "fb2", "fb"])
        self.assertEqual(len(seen), 3)
        self.assertFalse(p.stats.get("joined"))


class OwnDnsApartTest(unittest.TestCase):
    """E3: свой DNS правила — в ключе объединения. Одно имя сразу от клиента, у которого в правиле свой DNS, и от
    клиента без него (тот же путь) — два запроса к разным серверам, у каждого свой ответ."""

    def test_two_servers(self):
        net = DelayNet()
        net.delay["www.youtube.com."] = 0.1
        net.answer["9.9.9.9"] = FB2
        p = proxy(net)
        direct = {"mark": 0, "tcp": False}
        p.dom["policies"] = {"p_global": [[["l1"], direct]], "p_own": [[["l1"], direct, ["9.9.9.9"], False]]}
        p.dom["clients"] = {"10.8.1.8": "p_own"}

        async def go():
            return await asyncio.gather(resolve(p, q_msg("www.youtube.com", qid=1)),
                                        resolve(p, q_msg("www.youtube.com", qid=2), "10.8.1.8"))
        plain, own = run(go)
        self.assertEqual((who(plain), who(own)), ("shared", "fb2"))
        self.assertEqual(sorted(x[1] for x in net.seen if x[3] == "www.youtube.com."), ["1.1.1.1", "9.9.9.9"])


class SighupTaskKeptTest(unittest.TestCase):
    """E14: запрос, начатый до SIGHUP, кончился — он не снимает из объединения такой же запрос, начатый после: следующий
    повтор присоединяется к нему (к серверу — два запроса, а не три)."""

    def test_old_end_keeps_the_new(self):
        net = Net()
        p = proxy(net)

        async def enc(msg, server, mark, mode):
            net.seen.append((mode, server, mark, dnsproxy.read_name(msg, 12)))
            await asyncio.sleep(0.2)
            return a_reply(msg, [SHARED], ttl=0)                  # TTL 0 — не в кэш: третий спрашивает не из кэша
        p._enc = enc

        async def go():
            r1 = asyncio.ensure_future(resolve(p, q_msg("same.example", qid=1)))
            await asyncio.sleep(0.05)
            reload(p)                                             # SIGHUP: те же настройки
            await asyncio.sleep(0.05)
            r2 = asyncio.ensure_future(resolve(p, q_msg("same.example", qid=2)))   # своя задача, до 0,3 с
            await r1                                              # первая кончилась в 0,2 с
            await asyncio.sleep(0.03)
            r3 = await resolve(p, q_msg("same.example", qid=3))
            return await r2, r3
        outs = run(go)
        self.assertEqual([who(r) for r in outs], ["shared", "shared"])
        self.assertEqual(len([x for x in net.seen if x[3] == "same.example."]), 2)
        self.assertEqual(p.stats.get("joined"), 1)


class SetQueueTest(unittest.TestCase):
    """E24 и E27 («фильтр по DNS», Д2). Набор — FakeSet (как ядро), nft — в потоке с задержкой 0,3 с.
    E24: адрес, пришедший, пока идёт команда nft, уходит следующей командой сразу после неё — его ответ после записи и не
    по сроку SET_WAIT (set_late нет). E27: тот же адрес во второй пачке (ответ с бо́льшим TTL продлевает срок), пока кончается
    первая, — отметку «пишется» второй пачки конец первой не снимает: третий ответ с этим адресом ждёт вторую."""

    def setUp(self):
        self.kernel, self.calls, self.lock = FakeSet(), [], threading.Lock()

    def fake_run(self, cmd, **kw):
        t0 = time.monotonic()
        time.sleep(0.3)
        with self.lock:
            r = self.kernel.run(cmd, **kw)
            self.calls.append((t0, time.monotonic(), kw.get("input") or cmd[6]))
        return r

    def _proxy(self, ttls):
        net = DelayNet()
        p = proxy(net)
        p.dom = {"lists": p.dom["lists"], "clients": {}, "set": ["awgr", "dom4"],
                 "policies": {"p_global": [[["l1"], {"mark": 0x2001, "tcp": False}]]}}

        async def enc(msg, server, mark, mode):
            name = dnsproxy.read_name(msg, 12)
            ip, ttl = ttls[name]
            return a_reply(msg, [ip], ttl=ttl)
        p._enc = enc
        return p

    def written(self, ip, nth=0):
        ends = [t1 for _t0, t1, text in self.calls if f"{ip} timeout" in text]
        return ends[nth] if len(ends) > nth else None

    def test_address_during_a_command(self):
        p = self._proxy({"a.youtube.com.": ("192.0.2.30", 300), "b.youtube.com.": ("192.0.2.31", 300)})

        async def go():
            first = asyncio.ensure_future(resolve(p, q_msg("a.youtube.com")))
            await asyncio.sleep(0.1)                             # первая команда идёт
            t0 = time.monotonic()
            await resolve(p, q_msg("b.youtube.com"))
            t = time.monotonic()
            await first
            return t0, t
        with mock.patch.object(dnsproxy.subprocess, "run", side_effect=self.fake_run):
            t0, t = run(go)
        self.assertEqual(len(self.calls), 2)
        self.assertGreaterEqual(t, self.written("192.0.2.31"))
        self.assertLess(t - t0, 0.75)                            # 0,2 + 0,3 с, а не срок SET_WAIT (1 с)
        self.assertFalse(p.stats.get("set_late"))
        self.assertIsNotNone(self.kernel.left("192.0.2.31"))

    def test_same_address_in_the_second_batch(self):
        ip = "192.0.2.32"
        p = self._proxy({"a.youtube.com.": (ip, 300), "b.youtube.com.": (ip, 7200), "c.youtube.com.": (ip, 300)})

        async def go():
            first = asyncio.ensure_future(resolve(p, q_msg("a.youtube.com")))
            await asyncio.sleep(0.1)
            second = asyncio.ensure_future(resolve(p, q_msg("b.youtube.com")))   # продление: вторая пачка
            await first                                           # первая команда кончилась (0,3 с), вторая идёт
            await asyncio.sleep(0.05)
            await resolve(p, q_msg("c.youtube.com"))
            t = time.monotonic()
            await second
            return t
        with mock.patch.object(dnsproxy.subprocess, "run", side_effect=self.fake_run):
            t = run(go)
        self.assertEqual(len(self.calls), 2)
        self.assertGreaterEqual(t, self.written(ip, 1))          # третий ответ — после второй команды
        self.assertGreater(self.kernel.left(ip), 7000)


class PrefaceCancelTest(unittest.TestCase):
    """E33: отмена во время начала HTTP/2 (drain() после H2_PREFACE) закрывает соединение через транспорт — номер
    дескриптора возвращается, а не остаётся занятым брошенным транспортом. Настоящий TLS с ALPN h2."""

    @classmethod
    def setUpClass(cls):
        from tests.test_doh_http import cert
        cls.d = tempfile.mkdtemp()
        cls.crt, cls.key = cert(cls.d, "dns.test", ips=("127.0.0.1",))

    def test_fd_returns(self):
        def nfds():
            return len(os.listdir("/proc/self/fd"))

        async def go():
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(self.crt, self.key)
            sctx.set_alpn_protocols(["h2"])

            async def handler(r, w):
                try:
                    while await r.read(65536):
                        pass
                except (ConnectionError, ssl.SSLError):
                    pass
                w.close()
            srv = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=sctx)
            port = srv.sockets[0].getsockname()[1]
            p = conf_proxy(upstreams=["127.0.0.1"], upstream_port=port, ca_file=self.crt, encrypt="doh")
            base = nfds()
            target = {}
            orig = asyncio.StreamWriter.drain

            async def hooked(w):
                t = target.pop("task", None)
                if t is not None:
                    t.cancel()
                    await asyncio.sleep(0)                        # отмена приходит внутри drain(), как под нагрузкой
                return await orig(w)
            with mock.patch.object(asyncio.StreamWriter, "drain", hooked):
                task = asyncio.ensure_future(p._enc(q_msg("a.example"), "127.0.0.1", 0, "doh"))
                target["task"] = task
                with self.assertRaises(asyncio.CancelledError):
                    await task
            self.assertEqual(target, {})                          # отмена правда пришлась на drain() начала HTTP/2
            for _ in range(40):
                await asyncio.sleep(0.05)
                if nfds() <= base:
                    break
            left = nfds() - base
            for pl in p.pools.values():
                pl.close()
            srv.close()
            await srv.wait_closed()
            return left
        # брошенное соединение Python закрывает сам, когда удаляет StreamWriter, — с предупреждением «unclosed»: так
        # поломка видна сразу, а не через счёт дескрипторов
        with warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter("always", ResourceWarning)
            left = asyncio.run(go())
            gc.collect()
        self.assertLessEqual(left, 0)
        self.assertEqual([str(w.message) for w in seen if "StreamWriter" in str(w.message)], [])


if __name__ == "__main__":
    unittest.main()
