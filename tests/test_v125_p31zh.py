"""1.25.0, исправления по проверке Ж (независимая проверка исправлений по проверке Е): вторая попытка запроса, который
ждут повторы (Ж1), свои места для запросов к запасному (Ж2), понятный текст, когда таблица панели не помещается в предел
ядра в LXC (Ж3), и тесты на пробелы раздела 7 её отчёта (Ж5: поломки Z7, Z30, Z28, Z31, Z15, Z27). Классы Ж1 и Ж2 падают на
b87eaa5 (до этих исправлений), классы Ж5 — на поломке, которую охраняют (сказано в самом тесте).
python3 -m unittest tests.test_v125_p31zh"""
import asyncio
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from app import dnsproxy  # noqa: E402
from tests.test_v115 import a_reply, q_msg  # noqa: E402
from tests.test_v125_p31 import EXIT, LONG, Net, ask, proxy, run, settle, who  # noqa: E402
from tests.test_v125_p31d import reload, resolve  # noqa: E402


class LossyNet(Net):
    """Net, где у имени из lose теряются ответы на первые lose[имя] попытки к каждому серверу (сервер с потерями,
    «мигающая» блокировка): попытка ждёт срока, следующая отвечает (через later[имя] с, если задано). fresh — каждая
    попытка: (имя, сервер, на своём новом соединении — вторая попытка, _FRESH)."""

    def __init__(self):
        super().__init__()
        self.lose, self.later, self.tries, self.fresh, self.cancelled = {}, {}, {}, [], []

    async def enc(self, msg, server, mark, mode):
        name = dnsproxy.read_name(msg, 12)
        n = self.tries[(server, name)] = self.tries.get((server, name), 0) + 1
        self.fresh.append((name, server, dnsproxy._FRESH.get()))
        if n <= self.lose.get(name, 0):
            self.seen.append((mode, server, mark, name))
            try:
                await asyncio.sleep(LONG)                        # срок попытки (wait_for в _ask) прервёт
            except asyncio.CancelledError:
                self.cancelled.append((name, time.monotonic()))  # отменили (срок попытки или ответила вторая)
                raise
        if name in self.later:
            await asyncio.sleep(self.later[name])
        return await super().enc(msg, server, mark, mode)

    def attempts(self, name):
        return [f for n, _s, f in self.fresh if n == name]


def hedge(after=0.1, most=None):
    """Срок второй попытки в тестах (вместо 1,5 с) и её предел на путь."""
    patches = [mock.patch.object(dnsproxy, "HEDGE_AFTER", after, create=True)]
    if most is not None:
        patches.append(mock.patch.object(dnsproxy, "HEDGE_MAX", most, create=True))
    return patches


def with_patches(patches, fn, *a):
    for x in patches:
        x.start()
    try:
        return run(fn, *a)
    finally:
        for x in patches:
            x.stop()


# ------------------------------------------------------------------ Ж1
class SecondAttemptTest(unittest.TestCase):
    """Ж1: устройство повторяет запрос, а тот ждёт шифрованный DNS дольше HEDGE_AFTER, — одна вторая попытка того же
    запроса на новом соединении. На пути, где ответ теряется («через раз»), её ответ получают все ждущие: с Д1 повтор
    присоединялся к первому запросу и ждал его срока (до 10 с), и имя уходило к запасному. На b87eaa5 тесты класса
    падают: второй попытки нет. Сроки уменьшены: попытка — 0,4 с, вторая — после 0,1 с."""

    def test_repeat_gets_the_second_attempt(self):
        net = LossyNet()
        net.lose["x.example."] = 1
        p = proxy(net)
        t0 = []

        async def go():
            t0.append(time.monotonic())
            first = asyncio.ensure_future(ask(p, "x.example"))
            await asyncio.sleep(0.15)
            again = await ask(p, "x.example", "10.8.1.9")
            out = await first, again
            third = await ask(p, "x.example", "10.8.1.10")       # из кэша
            await settle(p)
            await asyncio.sleep(0.35)          # дольше срока попытки: не отменённую первую отменил бы он, а не ответ второй
            return out, third
        (first, again), third = with_patches(hedge(), go)
        self.assertEqual(first[0], "shared")
        self.assertLess(first[1], 0.3)                           # а не срок попытки (0,4 с) и запасной
        self.assertEqual(again[0], "shared")
        self.assertLess(again[1], 0.1)
        self.assertEqual(third[0], "shared")
        self.assertEqual(p.stats.get("cached"), 1)               # ответ второй попытки — в кэше
        self.assertEqual(net.attempts("x.example."), [False, True])     # вторая — на своём новом соединении
        self.assertEqual((p.stats.get("hedges"), p.stats.get("hedge_won")), (1, 1))
        self.assertGreater(p.direct_ok_at, 0)                    # путь отвечает
        self.assertFalse(p.stats.get("checks"))                  # и не проверялся
        self.assertEqual((p.hedging, p.inflight, p.followers, p.joins), ({}, 0, 0, {}))
        self.assertEqual(len(net.cancelled), 1)                 # первая попытка отменена сразу, а не ждала срока
        self.assertLess(net.cancelled[0][1] - t0[0], 0.3)

    def test_young_repeat_starts_none(self):
        """Охрана: повтор раньше HEDGE_AFTER — второй попытки нет, повтор ждёт первый, как с Д1."""
        net = LossyNet()
        net.lose["x.example."] = 1
        p = proxy(net)

        async def go():
            first = asyncio.ensure_future(ask(p, "x.example"))
            await asyncio.sleep(0.05)
            again = await ask(p, "x.example", "10.8.1.9")
            out = await first, again
            await settle(p)
            return out
        first, again = with_patches(hedge(), go)
        self.assertEqual(net.attempts("x.example."), [False])
        self.assertFalse(p.stats.get("hedges"))
        self.assertEqual((first[0], again[0]), ("fb", "fb"))     # как с Д1: срок первого, потом запасной

    def test_one_per_query_and_not_slower_when_both_lost(self):
        """Ответ теряется и на второй попытке: вторая одна, сколько бы повторов ни пришло; первая кончилась без ответа —
        вторая отменяется, и имя у запасного в тот же срок, что без второй попытки."""
        net = LossyNet()
        net.lose["x.example."] = 2
        p = proxy(net)

        async def go():
            first = asyncio.ensure_future(ask(p, "x.example"))
            for i in range(3):
                await asyncio.sleep(0.07)
                asyncio.ensure_future(ask(p, "x.example", f"10.8.1.{20 + i}"))
            out = await first
            await asyncio.sleep(0.05)
            await settle(p)
            return out
        first = with_patches(hedge(), go)
        self.assertEqual(p.stats.get("hedges"), 1)
        self.assertEqual(net.attempts("x.example."), [False, True])
        self.assertEqual(first[0], "fb")
        self.assertLess(first[1], 0.55)                          # 0,4 с попытка и запасной, а не дольше
        self.assertEqual((p.hedging, p.inflight, p.followers), ({}, 0, 0))

    def test_full_block_same_times(self):
        """При полной блокировке (общие замёрзли) времена те же, что без второй попытки: она ждёт так же и отменяется,
        как только первая кончилась; проверка пути и переход к запасному — как раньше."""
        def once(after):
            net = LossyNet()
            net.mode.update({"1.1.1.1": "freeze", "1.0.0.1": "freeze"})
            p = proxy(net, upstreams=["1.1.1.1", "1.0.0.1"])

            async def go():
                first = asyncio.ensure_future(ask(p, "x.example"))
                reps = []
                for i in range(6):
                    await asyncio.sleep(0.15)
                    reps.append(asyncio.ensure_future(ask(p, "x.example", f"10.8.1.{20 + i}")))
                out = [await first] + list(await asyncio.gather(*reps))
                await settle(p)
                return out
            out = with_patches(hedge(after), go)
            self.assertEqual((p.hedging, p.inflight, p.inflight_fb, p.followers), ({}, 0, 0, 0))
            return out, p
        with_hedge, p = once(0.1)
        without, _ = once(100.0)
        self.assertEqual(p.stats.get("hedges"), 1)
        self.assertEqual([w for w, _ in with_hedge], [w for w, _ in without])
        for (_, a), (_, b) in zip(with_hedge, without):
            self.assertLess(abs(a - b), 0.1)

    def test_live_quiet_path_starts_no_check(self):
        """Тихий путь (никто больше не спрашивает, ok_at старый), ответ на первую попытку потерялся: вторая отвечает
        раньше JOIN_CHECK — путь отвечает, и следующий повтор проверку не начинает (на b87eaa5 — проверка от повтора, и
        на её время имена уходят к запасному без шифрования)."""
        net = LossyNet()
        net.lose["x.example."] = 1
        net.check_delay = 0.1
        p = proxy(net)

        async def go():
            first = asyncio.ensure_future(ask(p, "x.example"))
            await asyncio.sleep(0.15)
            asyncio.ensure_future(ask(p, "x.example", "10.8.1.9"))
            await asyncio.sleep(0.2)
            again = await ask(p, "x.example", "10.8.1.10")       # 0,35 с: старше JOIN_CHECK
            other = await ask(p, "y.example", "10.8.1.11")
            out = await first, again, other
            await settle(p)
            return out
        first, again, other = with_patches(hedge() + [mock.patch.object(dnsproxy, "JOIN_CHECK", 0.3)], go)
        self.assertFalse(p.stats.get("join_checks"))
        self.assertFalse(p.stats.get("checks"))
        self.assertEqual([first[0], again[0], other[0]], ["shared"] * 3)

    def test_second_attempt_servfail_is_kept(self):
        """Вторая попытка получила SERVFAIL (сервер на связи, имя не разбирается), первая — ничего: клиенты получают
        SERVFAIL сервера, путь отвечает сразу (повтор старше JOIN_CHECK проверку не начинает), к запасному имя не идёт
        (так же, как когда SERVFAIL ответила первая)."""
        net = LossyNet()
        net.lose["x.example."] = 1
        p = proxy(net)
        enc = p._enc

        async def servfail_second(msg, server, mark, mode):
            if dnsproxy._FRESH.get():
                net.fresh.append((dnsproxy.read_name(msg, 12), server, True))
                r = bytearray(a_reply(msg, []))
                r[3] = (r[3] & 0xF0) | dnsproxy.RC_SERVFAIL
                return bytes(r)
            return await enc(msg, server, mark, mode)
        p._enc = servfail_second

        async def go():
            first = asyncio.ensure_future(ask(p, "x.example"))
            await asyncio.sleep(0.15)
            again = asyncio.ensure_future(ask(p, "x.example", "10.8.1.9"))
            await asyncio.sleep(0.17)
            await ask(p, "x.example", "10.8.1.10")                  # 0,32 с: старше JOIN_CHECK
            out = await first, await again
            await settle(p)
            return out
        first, again = with_patches(hedge() + [mock.patch.object(dnsproxy, "JOIN_CHECK", 0.3)], go)
        self.assertFalse(p.stats.get("join_checks"))
        self.assertEqual((first[0], again[0]), ("SF", "SF"))
        self.assertGreater(first[1], 0.35)                       # SERVFAIL второй — не раньше конца первой
        self.assertFalse(p.stats.get("direct_fallback"))
        self.assertFalse(p.direct_down)

    def test_path_state_stays_with_first_attempts(self):
        """Ответ второй попытки идёт ждущим, но «не отвечает» и итог идущей проверки он не меняет: их решают первые
        попытки и проверки, как до второй попытки. Иначе при «мигающей» блокировке (проходит каждый третий запрос) ответы
        вторых попыток то и дело возвращали путь из «не отвечает» и засчитывали проверку, и имена снова ждали
        заблокированные серверы."""
        def once(how):
            net = LossyNet()
            net.lose["x.example."] = 1
            net.later["x.example."] = 0.2                        # вторая попытка отвечает в 0,35 с
            net.check_delay = LONG                               # проверка не проходит
            p = proxy(net)

            async def go():
                first = asyncio.ensure_future(ask(p, "x.example"))
                await asyncio.sleep(0.15)
                again = asyncio.ensure_future(ask(p, "x.example", "10.8.1.9"))
                await asyncio.sleep(0.05)
                if how == "down":
                    down(p)
                else:
                    p._doubt(p._dp(0), 0, False, True)           # проверка 0,2–0,4 с
                out = await first, await again
                state = p.direct_down
                await settle(p)
                return out, state, p.direct_down
            return with_patches(hedge(), go)
        (first, again), state, after = once("down")
        self.assertEqual((first[0], again[0]), ("shared", "shared"))
        self.assertLess(first[1], 0.45)
        self.assertTrue(state)                                   # путь так и «не отвечает»
        (first, again), state, after = once("check")
        self.assertEqual((first[0], again[0]), ("shared", "shared"))
        self.assertTrue(after)                                   # проверка не засчитана ответом второй попытки

    def test_takes_no_client_place(self):
        net = LossyNet()
        net.lose["x.example."] = 1
        net.later["x.example."] = 0.1
        p = proxy(net)

        async def go():
            first = asyncio.ensure_future(ask(p, "x.example"))
            await asyncio.sleep(0.15)
            again = asyncio.ensure_future(ask(p, "x.example", "10.8.1.9"))
            await asyncio.sleep(0.02)
            mid = (p.inflight, dict(p.hedging))
            await first, await again
            await settle(p)
            return mid
        self.assertEqual(with_patches(hedge(), go), (1, {0: 1}))

    def test_limit_per_path(self):
        """Не больше HEDGE_MAX вторых попыток на путь сразу (в начале настоящей блокировки каждая ждёт до конца первой);
        у другого пути — свой счёт."""
        net = LossyNet()
        for n in ("a", "b", "c", "d"):
            net.lose[f"{n}.example."] = 2
        p = proxy(net)

        async def go():
            firsts = [asyncio.ensure_future(ask(p, f"{n}.example")) for n in "abc"]
            via_exit = asyncio.ensure_future(ask(p, "d.example", "10.8.1.7"))
            await asyncio.sleep(0.15)
            reps = [asyncio.ensure_future(ask(p, f"{n}.example", "10.8.1.30")) for n in "abc"]
            reps.append(asyncio.ensure_future(ask(p, "d.example", "10.8.1.7")))
            await asyncio.sleep(0.02)
            mid = dict(p.hedging)
            await asyncio.gather(*firsts, via_exit, *reps)
            await settle(p)
            return mid
        mid = with_patches(hedge(most=2), go)
        self.assertEqual(mid, {0: 2, EXIT: 1})
        self.assertEqual((p.stats.get("hedges"), p.stats.get("hedge_full")), (3, 1))
        self.assertEqual(p.hedging, {})

    def test_plain_dns_has_none(self):
        """Без шифрования второй попытки нет: потерянный пакет UDP стоит UDP_TIMEOUT."""
        net = LossyNet()
        net.lost["1.1.1.1"] = {"x.example."}
        p = proxy(net, encrypt="plain")

        async def go():
            first = asyncio.ensure_future(ask(p, "x.example"))
            await asyncio.sleep(0.05)                            # первый пакет ещё ждёт (срок UDP подделки — 0,1 с)
            await ask(p, "x.example", "10.8.1.9")
            await first
            await settle(p)
        with_patches(hedge(after=0.01), go)
        self.assertEqual(p.stats.get("joined"), 1)
        self.assertFalse(p.stats.get("hedges"))

    def _own(self, servers):
        net = LossyNet()
        p = proxy(net)
        p.dom = dict(p.dom, policies={"p_global": [[["l1"], {"mark": 0, "tcp": False}, servers, False]]})
        net.lose["www.youtube.com."] = 1
        return net, p

    def _own_go(self, p):
        async def go():
            first = asyncio.ensure_future(ask(p, "www.youtube.com"))
            await asyncio.sleep(0.15)
            again = await ask(p, "www.youtube.com", "10.8.1.9")
            return await first, again
        return with_patches(hedge(), go)

    def test_own_dns_of_a_rule(self):
        """Свой DNS правила с DoH — вторая попытка тоже; только обычный DNS — без неё."""
        own = "https://dns.example/dns-query#192.0.2.53"
        net, p = self._own([own])
        first, again = self._own_go(p)
        self.assertEqual((first[0], again[0]), ("shared", "shared"))
        self.assertLess(first[1], 0.3)
        self.assertEqual(net.attempts("www.youtube.com."), [False, True])
        net, p = self._own(["192.0.2.54"])
        self._own_go(p)
        self.assertFalse(p.stats.get("hedges"))

    def test_own_dns_skips_http3(self):
        """Запись h3:// вторая попытка пропускает (поток HTTP/3 отмена не прерывает) и спрашивает следующую — DoH."""
        h3, doh = "h3://dns.example/dns-query#192.0.2.53", "https://dns.example/dns-query#192.0.2.53"
        net, p = self._own([h3, doh])
        net.lose["www.youtube.com."] = 1
        first, again = self._own_go(p)
        fresh = [(s, f) for n, s, f in net.fresh if n == "www.youtube.com." and f]
        self.assertEqual(fresh, [(doh, True)])
        self.assertEqual(again[0], "shared")

    def test_sighup_during_the_second_attempt(self):
        """SIGHUP, пока идёт вторая попытка: её ответ получают те, кто ждал (запрос начат до SIGHUP), решение «путь
        отвечает» — в прежнее состояние пути, а не в новое; новые запросы к старой задаче не присоединяются."""
        net = LossyNet()
        net.lose["x.example."] = 1
        net.later["x.example."] = 0.2
        p = proxy(net)

        async def go():
            first = asyncio.ensure_future(ask(p, "x.example"))
            await asyncio.sleep(0.15)
            again = asyncio.ensure_future(ask(p, "x.example", "10.8.1.9"))
            await asyncio.sleep(0.05)
            old = p._dp(0)
            reload(p, upstreams=["1.0.0.1"])
            new = asyncio.ensure_future(ask(p, "x.example", "10.8.1.10"))
            out = await first, await again, await new
            await settle(p)
            return out, old
        (first, again, new), old = with_patches(hedge(), go)
        self.assertEqual((first[0], again[0]), ("shared", "shared"))
        self.assertGreater(old.ok_at, 0)
        self.assertEqual(p.stats.get("joined"), 1)               # новый — своим запросом
        self.assertIn(("x.example.", "1.0.0.1", False), net.fresh)
        self.assertEqual((p.hedging, p.inflight, p.followers, p.joins), ({}, 0, 0, {}))

    def test_cancelled_query_cancels_it(self):
        """Общую задачу отменили (выход процесса): вторая попытка отменяется с ней, счёт мест и попыток — к нулю."""
        net = LossyNet()
        net.lose["x.example."] = 2
        p = proxy(net)

        async def go():
            first = asyncio.ensure_future(ask(p, "x.example"))
            await asyncio.sleep(0.15)
            again = asyncio.ensure_future(ask(p, "x.example", "10.8.1.9"))
            await asyncio.sleep(0.02)
            for t in list(p.asking.values()):
                t.cancel()
            await asyncio.gather(first, again, return_exceptions=True)
            await asyncio.sleep(0.02)
        with_patches(hedge(), go)
        self.assertEqual((p.hedging, p.inflight, p.followers, p.joins), ({}, 0, 0, {}))

    def test_fresh_connection_in_enc(self):
        """Вторая попытка в настоящем _enc — на своём соединении (Pool.once), а не в очереди пула."""
        p = proxy(Net())
        del p._enc                                              # настоящий _enc
        calls = []

        class FakePool:
            host, path = "dns.google", "/dns-query"

            async def run(self, fn):
                calls.append("run")
                return b"pool"

            async def once(self, fn):
                calls.append("once")
                return b"once"
        p.pools[("doh", 0, "8.8.8.8")] = FakePool()

        async def go():
            tok = dnsproxy._FRESH.set(True)
            try:
                a = await p._enc(b"q", "8.8.8.8", 0, "doh")
            finally:
                dnsproxy._FRESH.reset(tok)
            b = await p._enc(b"q", "8.8.8.8", 0, "doh")
            return a, b
        self.assertEqual(asyncio.run(go()), (b"once", b"pool"))
        self.assertEqual(calls, ["once", "run"])


# ------------------------------------------------------------------ Ж2
class SlowFallbackNet(Net):
    """Net, где запасной (обычный DNS) отвечает через fb_delay с."""

    def __init__(self, delay=0.25):
        super().__init__()
        self.fb_delay = delay

    async def udp(self, msg, server, mark):
        if server == "77.88.8.8":
            await asyncio.sleep(self.fb_delay)
        return await super().udp(msg, server, mark)


def down(p, mark=0):
    """Путь «не отвечает» (проверка не прошла); проба — не скоро."""
    d = p._dp(mark)
    d.down, d.fail_at, d.retry_at = True, time.time(), time.monotonic() + 100


class FallbackPlacesTest(unittest.TestCase):
    """Ж2: запросы, которые сразу идут к запасному (путь «напрямую» проверяется или «не отвечает»), — свои MAX_INFLIGHT
    мест (inflight_fb). В начале блокировки места занимают запросы, которые ждут заблокированные общие серверы, и на
    большом сервере все клиенты «напрямую» 15 с получали SERVFAIL, хотя запасной отвечал сразу (на b87eaa5 первый тест
    класса падает)."""

    def test_fallback_answers_while_the_places_wait_for_shared(self):
        net = Net()
        net.mode["1.1.1.1"] = "freeze"
        p = proxy(net)
        n = dnsproxy.MAX_INFLIGHT

        async def go():
            waiting = [asyncio.ensure_future(resolve(p, q_msg(f"n{i}.example", qid=i))) for i in range(n)]
            await asyncio.sleep(0.05)
            full = p.inflight
            down(p)
            t0 = time.monotonic()
            r = await resolve(p, q_msg("new.example"))
            dt = time.monotonic() - t0
            outs = await asyncio.gather(*waiting)
            await settle(p)
            return full, r, dt, outs
        full, r, dt, outs = run(go)
        self.assertEqual((n, full), (512, 512))
        self.assertEqual(who(r), "fb")
        self.assertLess(dt, 0.05)
        self.assertEqual({who(x) for x in outs}, {"fb"})         # дождались общих — и к запасному
        self.assertEqual((p.inflight, p.inflight_fb), (0, 0))

    def test_513th_at_the_fallback(self):
        """MAX_INFLIGHT разных имён у запасного — следующее сразу SERVFAIL; места ждущих общие серверы не тронуты."""
        net = SlowFallbackNet()
        p = proxy(net)
        n = dnsproxy.MAX_INFLIGHT

        async def go():
            down(p)
            tasks = [asyncio.ensure_future(resolve(p, q_msg(f"n{i}.example", qid=i))) for i in range(n)]
            await asyncio.sleep(0.05)
            mid = (p.inflight, p.inflight_fb)
            t0 = time.monotonic()
            extra = await resolve(p, q_msg(f"n{n}.example"))
            dt = time.monotonic() - t0
            return mid, await asyncio.gather(*tasks), extra, dt
        mid, outs, extra, dt = run(go)
        self.assertEqual(mid, (0, 512))
        self.assertEqual({who(r) for r in outs}, {"fb"})
        self.assertEqual(who(extra), "SF")
        self.assertLess(dt, 0.05)
        self.assertEqual(p.stats.get("inflight_fb_full"), 1)
        self.assertEqual((p.inflight, p.inflight_fb), (0, 0))

    def test_started_at_the_fallback_stays_there(self):
        """Запрос, начатый, когда путь проверялся, идёт к запасному, даже если проверка кончилась «в порядке» до начала
        его задачи: его ждут повторы того же времени, и место у него — среди запросов к запасному."""
        net = Net()
        p = proxy(net)
        q = q_msg("x.example")
        cq = dnsproxy.parse_query(q)
        rec = dnsproxy.Asking(True)
        p.inflight_fb = 1

        async def go():
            return await p._lookup(q, cq, 0, False, (), True, (0, (), "x.example.", 1, 1, (0x100, False, False)), rec)
        self.assertEqual(who(run(go)), "fb")
        self.assertEqual([x for x in net.seen if x[3] == "x.example." and x[1] == "1.1.1.1"], [])
        self.assertTrue(rec.fb)

    def test_place_moves_when_the_fallback_is_gone(self):
        """Начат к запасному, а запасного уже нет (SIGHUP выключил его до начала задачи): место — среди ждущих серверы."""
        net = Net()
        p = proxy(net, direct_fallback=[])
        q = q_msg("x.example")
        rec = dnsproxy.Asking(True)
        p.inflight_fb = 1

        async def go():
            return await p._lookup(q, dnsproxy.parse_query(q), 0, False, (), True, ("k",), rec)
        self.assertEqual(who(run(go)), "shared")
        self.assertEqual((rec.fb, p.inflight_fb, p.inflight), (False, 0, 1))

    def test_counts_return_after_error_and_sighup(self):
        net = SlowFallbackNet(0.15)
        p = proxy(net)

        async def boom(*a, **kw):
            raise RuntimeError("test")

        async def go():
            down(p)
            ok = [asyncio.ensure_future(resolve(p, q_msg(f"s{i}.example", qid=i))) for i in range(5)]
            await asyncio.sleep(0.02)
            reload(p)                                            # SIGHUP: задачи до него отвечают своим клиентам
            down(p)
            more = [asyncio.ensure_future(resolve(p, q_msg(f"s{i}.example", qid=10 + i))) for i in range(5)]
            await asyncio.gather(*ok, *more)
            mid = (p.inflight, p.inflight_fb)
            p._fallback = boom
            bad = await asyncio.gather(resolve(p, q_msg("e.example")), return_exceptions=True)
            await asyncio.sleep(0.01)
            return mid, bad
        mid, bad = run(go)
        self.assertEqual(mid, (0, 0))
        self.assertIsInstance(bad[0], RuntimeError)
        self.assertEqual((p.inflight, p.inflight_fb, p.followers, p.joins), (0, 0, 0, {}))


# ------------------------------------------------------------------ Ж3
NFT_GLIBC = ("netlink: Error: Could not process rule: Message too long\n"
             "Please, rise /proc/sys/net/core/wmem_max on the host namespace. Hint: 2097152 bytes")
NFT_MUSL = ("netlink: Error: Could not process rule: Message too large\n"
            "Please, rise /proc/sys/net/core/wmem_max on the host namespace. Hint: 33554433 bytes")
NFT_OLD = "netlink: Error: Could not process rule: Message too long"          # nft 1.0.2 (Ubuntu 22.04): без подсказки


class TableTooBigTest(unittest.TestCase):
    """Ж3: Docker в непривилегированном LXC — netlink берёт за раз не больше net.core.wmem_max хоста, и таблица панели со
    списком России не загружается («Message too long»: клиентам не работает ничего). Панель пишет, что сделать на хосте:
    команду с нужным значением и как её сохранить."""

    def test_texts(self):
        from app.engine import wmem_msg
        m = wmem_msg(NFT_GLIBC)
        self.assertEqual(m.key, "err.nft_wmem")
        self.assertEqual(m.p["cmd"], "sysctl -w net.core.wmem_max=16777216")       # не меньше 16 МБ
        self.assertIn("net.core.wmem_max=16777216 > /etc/sysctl.d/", m.p["keep"])
        self.assertEqual(wmem_msg(NFT_MUSL).p["cmd"], f"sysctl -w net.core.wmem_max={33 << 20}")   # вверх до МБ
        self.assertEqual(wmem_msg(NFT_OLD).p["cmd"], "sysctl -w net.core.wmem_max=16777216")
        self.assertIsNone(wmem_msg("Error: syntax error, unexpected newline"))
        from app import uitext
        for lang in ("ru", "en", "zh", "fa"):
            text = uitext.text(lang, m)
            self.assertIn("sysctl -w net.core.wmem_max=16777216", text)
            self.assertIn("/etc/sysctl.d/", text)
            self.assertNotIn("{", text)

    def test_apply_error_says_what_to_do(self):
        """Основное применение набора: отказ nft по размеру → ошибка с понятным текстом (её показывают шапка и полоса
        «Ошибка применения правил»), а в новой сети — запасная таблица, как при любой ошибке (П14)."""
        from app import system
        from app.i18n import msg_of
        from tests.test_v125_fix import HoldPassTest
        h = HoldPassTest("test_failed_rules_close_forwarding")
        h.setUp()
        self.addCleanup(h.doCleanups)
        tg, applied = h._fail_nth({1, 2}, system.SysError(NFT_MUSL), "container:amnezia-awg2:7400:z")
        with self.assertRaises(system.SysError) as cm:
            h.t.reconcile(tg)
        m = msg_of(cm.exception)
        self.assertEqual(getattr(m, "key", None), "err.nft_wmem")
        self.assertTrue(applied)                                 # пересылка клиентов закрыта

    @unittest.skipUnless(os.geteuid() == 0 and shutil.which("nft") and shutil.which("unshare"), "нужны root, nft, unshare")
    def test_real_nft_in_a_user_namespace(self):
        """Настоящий nft в своём пространстве пользователей (как Docker в LXC без полных прав): таблица со списком больше
        net.core.wmem_max — текст отказа nft панель узнаёт, значение в команде — не меньше подсказки nft."""
        try:
            with open("/proc/sys/net/core/wmem_max") as f:
                wmem = int(f.read())
        except OSError:
            self.skipTest("нет net.core.wmem_max")
        if wmem > 8 << 20:
            self.skipTest("wmem_max больше 8 МБ: таблицу такого размера тест не строит")
        n = wmem // 10 + 1000                     # ~20 байт на сеть /24 в сообщении netlink (замер), с запасом вдвое
        els = ", ".join(f"{10 + (i >> 16)}.{(i >> 8) & 255}.{i & 255}.0/24" for i in range(n))
        text = "table ip awgr_t {\n set s {\n  type ipv4_addr\n  flags interval\n  elements = { " + els + " }\n }\n}\n"
        r = subprocess.run(["unshare", "-rn", "nft", "-f", "-"], input=text, capture_output=True, text=True, timeout=120)
        if r.returncode == 0 or "Operation not permitted" in r.stderr:
            self.skipTest(f"nft в своём пространстве: {r.returncode} {r.stderr[:100]}")
        from app.engine import wmem_msg
        m = wmem_msg(r.stderr)
        self.assertIsNotNone(m, r.stderr)
        want = int(m.p["cmd"].rsplit("=", 1)[1])
        if "Hint:" in r.stderr:
            self.assertGreaterEqual(want, int(r.stderr.rsplit("Hint:", 1)[1].split()[0]))


# ------------------------------------------------------------------ Ж5
class SetSplitTest(unittest.TestCase):
    """Z7: отказ по размеру у nft образа панели (musl) — «Message too large»: запись тоже делится (только по тексту
    glibc в образе она не делилась бы вовсе). Z30: nft отвергает по размеру любую часть — запись кончается, запусков не
    больше log₂(n/SET_TX_MIN) + 1 (поломка «делить и части ≤ SET_TX_MIN» — бесконечный цикл в потоке записи)."""

    def setUp(self):
        dnsproxy._set_tx[0] = 0
        self.addCleanup(dnsproxy._set_tx.__setitem__, 0, 0)
        self.calls = []

    def _run(self, fake, n):
        items = [(f"10.{i >> 16}.{(i >> 8) & 255}.{i & 255}", 1800) for i in range(n)]
        with mock.patch.object(dnsproxy.Proxy, "_nft_tx", staticmethod(fake)):
            dnsproxy.Proxy._nft_add("awgr", "dom4", items)
        return items

    def test_musl_text_splits(self):
        written = []

        def fake(table, name, part):
            self.calls.append(len(part))
            if len(part) > 3000:
                return "netlink: Error: Could not process rule: Message too large"
            written.extend(part)
            return ""
        items = self._run(fake, 8000)
        self.assertEqual(self.calls, [8000, 4000, 2000, 2000, 2000, 2000])
        self.assertEqual(written, items)
        self.assertEqual(dnsproxy._set_tx[0], 2000)

    def test_every_part_refused_ends(self):
        def fake(table, name, part):
            self.calls.append(len(part))
            if len(self.calls) > 50:
                raise AssertionError("запись не кончается")
            return ("netlink: Error: Could not process rule: Message too long\n"
                    "Please, rise /proc/sys/net/core/wmem_max on the host namespace. Hint: 300000 bytes")
        n = 16000
        self._run(fake, n)
        self.assertLessEqual(len(self.calls), math.log2(n / dnsproxy.SET_TX_MIN) + 1)
        self.assertEqual(self.calls[-1], dnsproxy.SET_TX_MIN)


class JoinsAfterSighupTest(unittest.TestCase):
    """Z28: ждущие запроса, SIGHUP, запрос кончился — счёт ждущих (followers) к нулю, законченных задач в joins нет.
    Иначе после JOIN_ALL таких ждущих — SERVFAIL всем повторам до перезапуска."""

    def test_followers_return(self):
        net = Net()
        net.slow["1.1.1.1"] = {"x.example."}
        p = proxy(net)

        async def go():
            first = asyncio.ensure_future(ask(p, "x.example"))
            await asyncio.sleep(0.05)
            reps = [asyncio.ensure_future(ask(p, "x.example", f"10.8.1.{20 + i}")) for i in range(3)]
            await asyncio.sleep(0.02)
            mid = p.followers
            reload(p)
            await asyncio.gather(first, *reps)
            await settle(p)
            return mid
        self.assertEqual(run(go), 3)
        self.assertEqual((p.followers, p.joins), (0, {}))


class RepeatCheckDownTest(unittest.TestCase):
    """Z31: проверка пути, начатая повтором (Е1), не прошла — путь «не отвечает» (у него есть запасной), и следующее имя
    сразу получает ответ запасного, не дожидаясь конца первого запроса (поломка «проверка от повтора без запасного»)."""

    def test_next_name_at_the_fallback(self):
        net = Net()
        net.mode.update({"1.1.1.1": "freeze", "1.0.0.1": "freeze"})
        p = proxy(net, upstreams=["1.1.1.1", "1.0.0.1"])

        async def go():
            first = asyncio.ensure_future(ask(p, "x.example"))         # ждёт общий до 0,8 с
            await asyncio.sleep(0.35)
            asyncio.ensure_future(ask(p, "x.example", "10.8.1.20"))     # старше JOIN_CHECK — проверка 0,35–0,55 с
            await asyncio.sleep(0.25)
            state = p.direct_down
            nxt = await ask(p, "z.example", "10.8.1.21")
            await first
            await settle(p)
            return state, nxt
        with mock.patch.object(dnsproxy, "JOIN_CHECK", 0.3), mock.patch.object(dnsproxy, "HEDGE_AFTER", 100.0):
            state, nxt = run(go)
        self.assertEqual(p.stats.get("join_checks"), 1)
        self.assertTrue(state)
        self.assertEqual(nxt[0], "fb")
        self.assertLess(nxt[1], 0.1)


class ExitHasNoDirectStateTest(unittest.TestCase):
    """Z15: имя через выход, общие серверы замёрзли — у пути выхода нет состояния «напрямую» (stage, DirectPath): иначе
    на «Сервере» — «Серверы DNS не отвечают напрямую» по пути выхода (а запасной ему всё равно не достаётся)."""

    def test_exit(self):
        net = Net()
        net.mode["1.1.1.1"] = "freeze"
        p = proxy(net)

        async def go():
            first = asyncio.ensure_future(ask(p, "x.example", "10.8.1.7"))
            await asyncio.sleep(0.05)
            again = await ask(p, "x.example", "10.8.1.7")
            out = await first, again
            await settle(p)
            p.stats_loop()
            return out
        first, again = run(go)
        self.assertEqual((first[0], again[0]), ("SF", "SF"))
        self.assertNotIn(EXIT, p.dpaths)
        with open(p.cfg["stats"]) as f:
            self.assertNotIn(str(EXIT), json.load(f).get("addr_direct") or {})


class FallbackDownAnyPathTest(unittest.TestCase):
    """Z27 (Е6): два «не отвечающих» пути, у одного запасной работает, у другого — нет: «Запасной DNS тоже не отвечает»
    (поломка «только когда у всех путей» прятала строку)."""

    def test_one_of_two(self):
        from tests.test_v125_p31d import FallbackLineTest
        now = time.time()
        v = FallbackLineTest.view(self, {
            "fallback": ["77.88.8.8"], "direct_ok_at": now - 10, "direct_fail_at": 0,
            "addr_direct": {"8449": [now - 300, now - 200], "8450": [now - 300, now - 100]},
            "fb_paths": {"0": [0, 0], "8449": [now - 5, 0], "8450": [now - 600, now - 50]}})
        self.assertTrue(v.get("direct_down"))
        self.assertEqual(v.get("fallback"), "down")


if __name__ == "__main__":
    unittest.main()
