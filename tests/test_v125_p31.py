"""1.25.0, П31 полной проверки: запасной DNS «Напрямую» не включается от одного медленного имени или одного потерянного
пакета, и зеркальный случай — у самого запасного одно имя без ответа не даёт всем SERVFAIL на 2 минуты. Подделки _enc,
_udp и _h3 (как DirectFallbackTest в test_v122 и DnsProxyEntriesTest в test_v125), сроки уменьшены; настоящие сокеты
(HTTP/2, DoT, HTTP/3) — SlowNameRealTest в tests/test_doh_http.py, сеть с правилами nftables — tests/netns_e2e.py.
Тесты ложной тревоги падают на 6a8c54f (до исправления); тесты настоящей блокировки на нём проходят (там переключение
было верным) и падают, если сломать проверку пути.
python3 -m unittest tests.test_v125_p31"""
import asyncio
import json
import os
import socket
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

SHARED, FB, FB2 = "198.51.100.1", "203.0.113.7", "203.0.113.8"     # кто ответил — по адресу в ответе
AM = 0x2101                     # метка адреса 1 («Напрямую — адрес»)
EXIT = 0x2001                   # метка выхода
ENC, UDP = 0.2, 0.1             # с: ENC_TIMEOUT и «срок UDP» подделки (вместо 5 и 2)
LONG = 3.0                      # с: медленное имя — дольше любого срока


class Net:
    """Поддельная сеть: что делает каждый сервер (общий 1.1.1.1 и др. или запись запасного DNS). Режимы: ok; rst — сброс
    соединения; syn — соединение не устанавливается (ждём срок); hello — TLS (QUIC) не проходит (ждём срок); freeze —
    рукопожатие прошло, ответа нет; drop — UDP не доходит. slow[сервер] — имена, которые сервер разбирает дольше срока
    («*» — любой сервер: у имени молчат его серверы имён, так у любого резолвера); lost[сервер] — имена, у которых
    теряется первый пакет UDP. check_delay — с, через сколько отвечает «. NS» (контрольный запрос проверки пути)."""

    def __init__(self):
        self.mode = {}
        self.slow, self.lost, self.lost_done = {}, {}, set()
        self.check_delay = 0.0
        self.seen = []                       # (вид, сервер, метка, имя)
        self.answer = {}                     # сервер → адрес в ответе

    def is_slow(self, server, name):
        return name in self.slow.get(server, ()) or name in self.slow.get("*", ())

    async def enc(self, msg, server, mark, mode):
        name = dnsproxy.read_name(msg, 12)
        self.seen.append((mode, server, mark, name))
        how = self.mode.get(server, "ok")
        if how == "rst":
            raise ConnectionResetError("reset")
        if how in ("syn", "hello", "freeze"):
            await asyncio.sleep(LONG)                    # срок ответа (wait_for в forward) прервёт
        if name == ".":
            await asyncio.sleep(self.check_delay)
        elif self.is_slow(server, name):
            await asyncio.sleep(LONG)
        return a_reply(msg, [self.answer.get(server, SHARED)])

    async def h3(self, msg, server, mark):
        return await self.enc(msg, server, mark, "doh3")

    async def udp(self, msg, server, mark):
        name = dnsproxy.read_name(msg, 12)
        self.seen.append(("udp", server, mark, name))
        if self.mode.get(server) == "drop" or self.is_slow(server, name):
            await asyncio.sleep(UDP)
            return None
        if name in self.lost.get(server, ()) and (server, name) not in self.lost_done:
            self.lost_done.add((server, name))
            await asyncio.sleep(UDP)
            return None
        if name == ".":
            await asyncio.sleep(self.check_delay)
        return a_reply(msg, [self.answer.get(server, SHARED)])

    def checks(self, server=None):
        return [x for x in self.seen if x[3] == "." and (server is None or x[1] == server)]


def proxy(net: Net, **cfg) -> dnsproxy.Proxy:
    d = tempfile.mkdtemp()
    conf = os.path.join(d, "dns.json")
    lst = os.path.join(d, "l1.txt")
    with open(lst, "w") as f:
        f.write("youtube.com\n")
    base = {"listen": "10.8.1.1", "port": 53, "clients": "10.8.1.0/24", "upstreams": ["1.1.1.1"], "encrypt": "doh",
            "direct_fallback": ["77.88.8.8"], "default": {"mark": 0, "tcp": False}, "addr_marks": [0x2101, 0x2110],
            "routes": {"10.8.1.6": {"mark": AM, "tcp": False}, "10.8.1.7": {"mark": EXIT, "tcp": False}},
            "stats": os.path.join(d, "stats.json"),
            # правило по доменам youtube.com без пути (выход подключается, лежит или «блок»)
            "dom": {"lists": {"l1": lst}, "policies": {"p_global": [[["l1"], None]]}, "clients": {}, "set": None}}
    base.update(cfg)
    with open(conf, "w") as f:
        json.dump(base, f)
    p = dnsproxy.Proxy(conf)

    async def enc(msg, server, mark, mode):
        if mode == "doh3":                               # как настоящий _enc: HTTP/3 — через _h3
            return await p._h3(msg, server, mark)
        return await net.enc(msg, server, mark, mode)
    p._enc, p._udp, p._h3 = enc, net.udp, net.h3
    net.answer.setdefault("77.88.8.8", FB)
    return p


def who(reply: bytes) -> str:
    if reply[3] & 0xF == dnsproxy.RC_SERVFAIL:
        return "SF"
    for name, ip in (("shared", SHARED), ("fb", FB), ("fb2", FB2)):
        if socket.inet_aton(ip) in reply:
            return name
    return f"rc{reply[3] & 0xF}"


async def ask(p, name, ip="10.8.1.5"):
    """→ (кто ответил, секунды)."""
    q = q_msg(name)
    t0 = time.monotonic()
    r = await p.resolve(q, dnsproxy.parse_query(q), ip)
    return who(r), time.monotonic() - t0


async def settle(p, *marks):
    """Дождаться идущих проверок и проб путей."""
    for m in marks or (0,):
        for t in (p._dp(m).probe, p._dp(m).fb_probe):
            if t is not None and not t.done():
                await t


def run(coro_fn, *a):
    # create=True: тот же тест на коде до исправления (6a8c54f) падает на поведении, а не на имени
    with mock.patch.object(dnsproxy, "ENC_TIMEOUT", ENC), mock.patch.object(dnsproxy, "CHECK_TIMEOUT", ENC, create=True):
        return asyncio.run(coro_fn(*a))


def busy(task) -> bool:
    return task is not None and not task.done()


class SlowNameTest(unittest.TestCase):
    """а) и б): одно медленное имя или один потерянный пакет — проверка пути проходит, путь не «не отвечает», следующее
    имя — у общего сервера, «Серверы DNS не отвечают напрямую» не появляется."""

    def _one(self, encrypt, event, where="1.1.1.1"):
        net = Net()
        p = proxy(net, encrypt=encrypt)
        name = "slow.example." if event == "slow" else "lost.example."
        (net.slow if event == "slow" else net.lost)[where] = {name}

        async def go():
            self.assertEqual((await ask(p, "a.example"))[0], "shared")
            first = await ask(p, name)
            await settle(p)
            nxt = [await ask(p, f"n{i}.example") for i in range(3)]
            return first, nxt
        first, nxt = run(go)
        # само это имя — у запасного, как раньше (или SERVFAIL, если медленное и у него)
        self.assertEqual(first[0], "fb" if where != "*" else "SF", (encrypt, event))
        self.assertEqual([w for w, _ in nxt], ["shared"] * 3, (encrypt, event))
        dp = p._dp(0)
        self.assertFalse(dp.down)
        self.assertEqual(dp.fail_at, 0.0)                                  # «не отвечают» не было вовсе
        self.assertFalse(dp.fb_down)                                       # и «запасной не отвечает» — тоже
        self.assertEqual(dp.fb_fail_at, 0.0)
        self.assertEqual(len(net.checks("1.1.1.1")), 1)                    # одна проверка тем же серверам
        self.assertEqual(p.stats.get("checks_ok"), 1)
        return p

    def test_one_slow_name_doh_dot(self):
        for encrypt in ("doh", "dot"):
            self._one(encrypt, "slow")

    def test_one_slow_name_plain(self):
        self._one("plain", "slow")

    def test_one_lost_packet_plain(self):
        self._one("plain", "lost")

    def test_slow_everywhere(self):
        """Как бывает на деле: у имени молчат его серверы имён — оно медленное у всех, и у запасного. До исправления все
        имена «напрямую» после этого 2 минуты получали SERVFAIL (путь «не отвечает», запасной «не отвечает»)."""
        for encrypt in ("doh", "dot", "plain"):
            self._one(encrypt, "slow", "*")

    def test_slow_name_with_no_fallback_does_not_warn(self):
        """Без запасного: одно медленное имя не включает «Серверы DNS не отвечают напрямую» (fail_at не пишется), а
        настоящая блокировка — включает (проверка не прошла)."""
        net = Net()
        p = proxy(net, direct_fallback=[])
        net.slow["1.1.1.1"] = {"slow.example."}

        async def go():
            await ask(p, "slow.example")
            await settle(p)
        run(go)
        self.assertEqual(p.direct_fail_at, 0.0)
        net.mode["1.1.1.1"] = "rst"
        run(go)
        self.assertGreater(p.direct_fail_at, p.direct_ok_at)
        self.assertFalse(p.direct_down)                                     # без запасного имена всё равно к серверам

    def test_dns_view_shows_no_alarm(self):
        """Состояние для «Сервера» (dns_view) после медленного имени — без «не отвечают»; после настоящей блокировки —
        с ним. Файл stats пишет сам dnsproxy (stats_loop)."""
        import types
        from app import config
        from app.engine import Engine
        from app.engine import dns as edns
        net = Net()
        p = proxy(net)
        net.slow["1.1.1.1"] = {"slow.example."}
        e = Engine.__new__(Engine)
        e.dns_state = {"state": "on", "listen": "10.8.1.1", "encrypt": "doh"}
        e.dns = types.SimpleNamespace(proc=types.SimpleNamespace(pid=os.getpid()))

        async def go(name):
            await ask(p, name)
            await settle(p)
            p.stats_loop()

        def view():
            with mock.patch.object(edns, "DNS_STATS", p.cfg["stats"]), mock.patch.object(config, "DRY_RUN", False):
                return e.dns_view()
        run(go, "slow.example")
        self.assertNotIn("direct_down", view())
        net.mode["1.1.1.1"] = "freeze"
        run(go, "b.example")
        self.assertTrue(view().get("direct_down"))
        self.assertEqual(view().get("fallback"), "used")


class MirrorTest(unittest.TestCase):
    """в) Общие серверы режут, запасной не ответил на одно имя: следующие имена — его ответ, а не SERVFAIL; запасной,
    который правда не отвечает, пропускается сразу."""

    def test_one_slow_name_at_the_fallback(self):
        for kind, entry in (("plain", "77.88.8.8"), ("doh", "https://dns.example/dns-query#77.88.8.8"),
                            ("dot", "tls://dns.example#77.88.8.8"), ("h3", "h3://dns.example/dns-query#77.88.8.8")):
            net = Net()
            net.mode["1.1.1.1"] = "rst"
            net.answer[entry] = FB
            p = proxy(net, direct_fallback=[entry])
            net.slow[entry] = {"slow.example."}

            async def go():
                self.assertEqual((await ask(p, "a.example"))[0], "fb", kind)       # общие режут — у запасного
                await settle(p)
                self.assertTrue(p.direct_down, kind)
                slow = await ask(p, "slow.example")
                await settle(p)
                return slow, [await ask(p, f"n{i}.example") for i in range(3)]
            slow, nxt = run(go)
            self.assertEqual(slow[0], "SF", kind)                                  # само это имя — SERVFAIL
            self.assertEqual([w for w, _ in nxt], ["fb"] * 3, kind)
            self.assertFalse(p._dp(0).fb_down, kind)
            self.assertEqual(p._dp(0).fb_fail_at, 0.0, kind)                       # «запасной не отвечает» не было
            self.assertEqual(len(net.checks(entry)), 1, kind)

    def test_lost_packet_at_the_fallback(self):
        net = Net()
        net.mode["1.1.1.1"] = "rst"
        p = proxy(net)
        net.lost["77.88.8.8"] = {"lost.example."}

        async def go():
            await ask(p, "a.example")
            await settle(p)
            await ask(p, "lost.example")
            await settle(p)
            return await ask(p, "b.example")
        self.assertEqual(run(go)[0], "fb")
        self.assertFalse(p._dp(0).fb_down)

    def test_dead_fallback_skipped_at_once(self):
        """Запасной правда не отвечает (UDP 53 режут; HTTP/3 — UDP 443; DoH замерзает): первое имя ждёт его, как раньше,
        дальше — сразу SERVFAIL, а сам он пробуется в фоне раз в DIRECT_RETRY."""
        for kind, entry, how in (("plain", "77.88.8.8", "drop"), ("h3", "h3://dns.example/dns-query#77.88.8.8", "hello"),
                                 ("doh", "https://dns.example/dns-query#77.88.8.8", "freeze")):
            net = Net()
            net.mode.update({"1.1.1.1": "rst", entry: how})
            p = proxy(net, direct_fallback=[entry])

            async def go():
                first = await ask(p, "a.example")
                during = await ask(p, "b.example")                  # проверка запасного ещё идёт — не ждём его
                await settle(p)
                return first, during, [await ask(p, f"n{i}.example") for i in range(2)]
            first, during, nxt = run(go)
            self.assertEqual(first[0], "SF", kind)
            self.assertEqual(during[0], "SF", kind)
            self.assertLess(during[1], 0.05, kind)
            self.assertTrue(p._dp(0).fb_down, kind)
            self.assertEqual([w for w, _ in nxt], ["SF", "SF"], kind)
            self.assertLess(max(t for _, t in nxt), 0.05, kind)
            asked = len([x for x in net.seen if x[1] == entry])
            run(lambda: ask(p, "c.example"))
            self.assertEqual(len([x for x in net.seen if x[1] == entry]), asked, kind)    # до DIRECT_RETRY не спрашивается
            checks = len(net.checks(entry))
            p._dp(0).fb_retry_at = 0                                 # прошло DIRECT_RETRY — проба в фоне, клиент не ждёт

            async def probe():
                r = await ask(p, "d.example")
                await settle(p)
                return r
            r = run(probe)
            self.assertEqual(r[0], "SF", kind)
            self.assertLess(r[1], 0.05, kind)
            self.assertGreater(len(net.checks(entry)), checks, kind)             # проба — контрольным запросом


class RealBlockTest(unittest.TestCase):
    """г) Настоящая блокировка в любом виде — первое имя получает ответ запасного не позже прежнего (сроки те же),
    следующие — сразу у него, а серверы DNS потом пробуются в фоне."""

    CASES = (("doh", "syn"), ("doh", "rst"), ("doh", "hello"), ("doh", "freeze"), ("dot", "syn"), ("dot", "freeze"),
             ("plain", "drop"))

    def test_each_kind_switches_at_once(self):
        for encrypt, how in self.CASES:
            net = Net()
            net.mode["1.1.1.1"] = how
            p = proxy(net, encrypt=encrypt)

            async def go():
                first = await ask(p, "a.example")
                nxt = [await ask(p, f"n{i}.example") for i in range(3)]     # проверка ещё идёт — уже у запасного
                await settle(p)
                later = await ask(p, "later.example")
                return first, nxt, later
            first, nxt, later = run(go)
            limit = {"syn": ENC * 2, "hello": ENC * 2, "freeze": ENC * 2, "rst": 0.05, "drop": UDP}[how]
            self.assertEqual(first[0], "fb", (encrypt, how))
            self.assertLess(first[1], limit + 0.1, (encrypt, how))               # как раньше: один срок ответа
            self.assertEqual([w for w, _ in nxt], ["fb"] * 3, (encrypt, how))
            self.assertLess(max(t for _, t in nxt), 0.05, (encrypt, how))
            self.assertTrue(p.direct_down, (encrypt, how))                       # проверка не прошла — «не отвечают»
            self.assertGreater(p.direct_fail_at, p.direct_ok_at)
            self.assertEqual(later[0], "fb", (encrypt, how))
            self.assertLess(later[1], 0.05, (encrypt, how))
            self.assertEqual([x[3] for x in net.seen if x[1] == "1.1.1.1"].count("a.example."), 1)

    def test_probe_in_background_then_back(self):
        """Через DIRECT_RETRY — контрольный запрос в фоне, клиент сразу получает ответ запасного; блокировку сняли —
        имена снова у общих серверов."""
        net = Net()
        net.mode["1.1.1.1"] = "freeze"
        p = proxy(net)

        async def go():
            await ask(p, "a.example")
            await settle(p)
            p.direct_retry_at = 0
            net.mode["1.1.1.1"] = "ok"
            r = await ask(p, "b.example")
            self.assertTrue(busy(p._direct_probe))                    # проба идёт, клиент её не ждал
            await settle(p)
            return r, await ask(p, "c.example")
        r, after = run(go)
        self.assertEqual(r[0], "fb")
        self.assertLess(r[1], 0.05)
        self.assertEqual(after[0], "shared")
        self.assertEqual(net.checks("1.1.1.1")[-1][3], ".")                     # проба — контрольным запросом

    def test_probe_is_not_fooled_by_a_slow_name(self):
        """Проба раз в DIRECT_RETRY спрашивает «. NS», а не имя клиента: медленное имя клиента не продлевает «не
        отвечают» ещё на 2 минуты (раньше пробой был запрос клиента)."""
        net = Net()
        net.mode["1.1.1.1"] = "rst"
        p = proxy(net)
        net.slow["1.1.1.1"] = {"slow.example."}

        async def go():
            await ask(p, "a.example")
            await settle(p)
            net.mode["1.1.1.1"] = "ok"                                          # блокировку сняли
            p.direct_retry_at = 0
            await ask(p, "slow.example")                                        # проба пришлась на медленное имя
            await settle(p)
        run(go)
        self.assertFalse(p.direct_down)

    def test_name_answered_meanwhile_wins(self):
        """Пока шла проверка, общий сервер ответил на другое имя (правило без пути спрашивает его и во время проверки) —
        путь работает, даже если сама проверка не успела."""
        net = Net()
        p = proxy(net)
        net.slow["1.1.1.1"] = {"slow.example."}
        net.check_delay = LONG                                                  # контрольный запрос не успевает

        async def go():
            await ask(p, "slow.example")
            self.assertEqual((await ask(p, "www.youtube.com"))[0], "shared")     # ответ во время проверки
            await settle(p)
        run(go)
        self.assertFalse(p.direct_down)
        self.assertEqual(p.direct_fail_at, 0.0)


class PathsTest(unittest.TestCase):
    """д) У каждого пути своя проверка: медленное имя на «Напрямую — адрес» не трогает адрес системы, и наоборот; проверка
    и запасной — с того же адреса (та же метка)."""

    def test_slow_name_on_one_path_only(self):
        net = Net()
        p = proxy(net)
        net.slow["1.1.1.1"] = {"slow.example."}
        net.check_delay = 0.1

        async def go():
            await ask(p, "slow.example", "10.8.1.6")             # «Напрямую — адрес»
            self.assertTrue(busy(p._dp(AM).probe))
            sys_path = await ask(p, "a.example")                 # адрес системы: проверки нет — к общему серверу
            await settle(p, AM, 0)
            return sys_path, await ask(p, "b.example", "10.8.1.6")
        sys_path, addr_path = run(go)
        self.assertEqual(sys_path[0], "shared")
        self.assertEqual(addr_path[0], "shared")
        self.assertEqual([c[2] for c in net.checks()], [AM])     # проверка — только этого пути и с его меткой
        self.assertFalse(p._dp(AM).down)
        self.assertFalse(p.direct_down)

    def test_real_block_on_one_path_only(self):
        net = Net()
        p = proxy(net)

        async def go():
            net.mode["1.1.1.1"] = "freeze"
            await ask(p, "a.example", "10.8.1.6")
            await settle(p, AM)
            net.mode["1.1.1.1"] = "ok"                           # с адреса системы общие отвечают
            return await ask(p, "b.example"), await ask(p, "c.example", "10.8.1.6")
        sys_path, addr_path = run(go)
        self.assertTrue(p._dp(AM).down)
        self.assertFalse(p.direct_down)
        self.assertEqual(sys_path[0], "shared")
        self.assertEqual(addr_path[0], "fb")
        self.assertEqual({s[2] for s in net.seen if s[1] == "77.88.8.8"}, {AM})   # запасной — с того же адреса


class NeverPastExitTest(unittest.TestCase):
    """е) Имена клиентов через выход и имена правил без пути не уходят к запасному никогда — и во время проверки тоже."""

    def test_during_the_check(self):
        net = Net()
        p = proxy(net)
        net.slow["1.1.1.1"] = {"slow.example."}
        net.check_delay = 0.3                                    # проверка идёт, пока спрашиваются имена ниже

        async def go():
            await ask(p, "slow.example")
            self.assertTrue(busy(p._direct_probe))
            out = {"exit": await ask(p, "e.example", "10.8.1.7"), "rule": await ask(p, "www.youtube.com"),
                   "direct": await ask(p, "d.example")}
            self.assertTrue(busy(p._direct_probe))
            await settle(p)
            return out
        out = run(go)
        self.assertEqual(out["exit"][0], "shared")               # через выход — общие серверы, с меткой выхода
        self.assertEqual(out["rule"][0], "shared")               # правило без пути — общие серверы, не запасной
        self.assertEqual(out["direct"][0], "fb")                 # обычное имя «напрямую» во время проверки — запасной
        to_fb = [x[3] for x in net.seen if x[1] == "77.88.8.8"]
        self.assertNotIn("e.example.", to_fb)
        self.assertNotIn("www.youtube.com.", to_fb)
        self.assertIn(("doh", "1.1.1.1", EXIT, "e.example."), net.seen)

    def test_during_a_real_block(self):
        net = Net()
        net.mode["1.1.1.1"] = "rst"
        p = proxy(net)

        async def go():
            await ask(p, "a.example")
            await settle(p)
            return await ask(p, "e.example", "10.8.1.7"), await ask(p, "www.youtube.com")
        via_exit, rule = run(go)
        self.assertEqual((via_exit[0], rule[0]), ("SF", "SF"))
        self.assertEqual([x[3] for x in net.seen if x[1] == "77.88.8.8"], ["a.example."])


class ManyNamesTest(unittest.TestCase):
    """ж) 50 имён сразу в момент медленного имени — одна проверка; проверка не занимает мест клиентов (MAX_INFLIGHT)."""

    def test_one_check_for_fifty(self):
        net = Net()
        p = proxy(net)
        net.slow["1.1.1.1"] = {f"slow{i}.example." for i in range(50)}
        net.check_delay = 0.2                                     # проверка ещё идёт, когда не ответили остальные

        async def go():
            return await asyncio.gather(*[ask(p, f"slow{i}.example") for i in range(50)])
        with mock.patch.object(dnsproxy, "MAX_INFLIGHT", 60):
            run(go)
        self.assertEqual(len(net.checks()), 1)
        self.assertEqual(p.stats.get("checks"), 1)

    def test_check_takes_no_client_place(self):
        net = Net()
        p = proxy(net)
        net.slow["1.1.1.1"] = {"slow.example."}
        net.check_delay = 0.5
        net.mode["77.88.8.8"] = "ok"

        async def go():
            await ask(p, "slow.example")                              # проверка пошла (0,5 с)
            self.assertEqual(p.inflight, 0)
            with mock.patch.object(dnsproxy, "MAX_INFLIGHT", 1):
                r = await ask(p, "a.example")                         # единственное место — клиенту
            await settle(p)
            return r
        self.assertEqual(run(go)[0], "fb")


class SighupTest(unittest.TestCase):
    """Проверка или проба, начатая до SIGHUP с новыми серверами, пишет своё решение в прежнее состояние пути, а не в
    новое (новые серверы начинают с чистого листа, как и раньше)."""

    def test_probe_result_stays_with_old_servers(self):
        net = Net()
        net.mode["1.1.1.1"] = "freeze"
        p = proxy(net)

        async def go():
            await ask(p, "a.example")
            await settle(p)
            p.direct_retry_at = 0
            await ask(p, "b.example")                                 # проба старых серверов пошла
            old = p._direct_probe
            net.mode["9.9.9.9"] = "freeze"
            cfg = dict(p.cfg, upstreams=["9.9.9.9"])
            with open(p.conf_path, "w") as f:
                json.dump(cfg, f)
            p.load()                                                  # SIGHUP: новые серверы
            await old                                                 # старая проба: не ответили
        run(go)
        self.assertFalse(p.direct_down)
        self.assertEqual(p.direct_fail_at, 0.0)


if __name__ == "__main__":
    unittest.main()
