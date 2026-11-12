"""Исправления 1.12.2: python3 -m unittest discover tests"""
import asyncio
import json
import os
import shutil
import socket
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

from app import awgserver, config, lists, nftgen, sniproxy, system, users, web  # noqa: E402
from app import main  # noqa: E402
from app.i18n import Msg  # noqa: E402
from app.store import Store  # noqa: E402
from app.traffic import Traffic  # noqa: E402

PRIV = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
PUB = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
AWG_EXIT = f"""[Interface]
Address = 10.9.0.2/32
PrivateKey = {PRIV}

[Peer]
PublicKey = {PUB}
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.1:51820
"""


class Req:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class Fixture(unittest.TestCase):
    """Своё состояние на время теста: выходы, списки и правила потом убираются."""

    def setUp(self):
        st = main.store.snapshot()
        self._routing = {"default": st["routing"]["default"], "rules": list(st["routing"]["rules"])}
        self._lists = {l["id"] for l in st["lists"]}
        self._ups = {u["id"] for u in st["upstreams"]}
        self._fetch = mock.patch.object(lists, "_fetch", side_effect=OSError("offline"))
        self._fetch.start()

    def tearDown(self):
        r = self._routing
        main.store.mutate(lambda st: st.update(routing={"default": r["default"], "rules": r["rules"]}))
        for u in main.store.snapshot()["upstreams"]:
            if u["id"] not in self._ups:
                main.del_upstream(Req({"replace": "direct"}), u["id"])
        for l in main.store.snapshot()["lists"]:
            if l["id"] not in self._lists:
                main.del_list(None, l["id"])
        self._fetch.stop()

    def exit(self, name="NL", config_text="socks5://198.51.100.9:1080", routing=None):
        b = {"name": name, "config": config_text}
        if routing:
            b["routing"] = routing
        return main.add_upstream(Req(b))["id"]

    def lst(self, name, src="203.0.113.0/24", kind="manual"):
        return main.add_list(Req({"kind": kind, "source": src, "name": name}))["id"]

    def rules(self):
        return [(r["comment"], r["lists"], r["outbound"], r["enabled"])
                for r in main.store.snapshot()["routing"]["rules"]]


# ------------------------------------------------------------- №2 окно выхода
class ExitWindowRulesTest(Fixture):
    def test_disabled_rules_comments_and_order_kept(self):
        uid = self.exit()
        a, b, c = self.lst("A"), self.lst("B", "198.51.100.0/24"), self.lst("C", "192.0.2.0/24")
        out = "up:" + uid
        main.put_routing(Req({"default": "direct", "rules": [
            {"lists": [a], "outbound": out, "enabled": True, "comment": "Netflix"},
            {"lists": ["ru"], "outbound": "direct", "enabled": True, "comment": "RU"},
            {"lists": [b], "outbound": out, "enabled": True, "comment": "Office"},
            {"lists": [c], "outbound": out, "enabled": False, "comment": "Paused"}]}))
        before = self.rules()
        # окно показывает списки включённых правил и отправляет их же — ничего не меняется
        main.edit_upstream(Req({"routing": {"domains": "", "domain_lists": [], "net_lists": [a, b]}}), uid)
        self.assertEqual(self.rules(), before)
        # сняли «B»: его правило уходит, выключенное «Paused» и порядок остаются
        main.edit_upstream(Req({"routing": {"domains": "", "domain_lists": [], "net_lists": [a]}}), uid)
        self.assertEqual(self.rules(), [("Netflix", [a], out, True), ("RU", ["ru"], "direct", True),
                                        ("Paused", [c], out, False)])

    def test_new_lists_join_existing_rule_or_go_after_last(self):
        uid = self.exit()
        a, b = self.lst("A"), self.lst("B", "198.51.100.0/24")
        out = "up:" + uid
        main.put_routing(Req({"default": "direct", "rules": [
            {"lists": ["ru"], "outbound": "direct", "enabled": True, "comment": "RU"},
            {"lists": [a], "outbound": out, "enabled": True, "comment": "Mine"}]}))
        main.edit_upstream(Req({"routing": {"domains": "", "domain_lists": [], "net_lists": [a, b]}}), uid)
        self.assertEqual(self.rules(), [("RU", ["ru"], "direct", True), ("Mine", [a, b], out, True)])
        # сайты выхода — новое правило со списком доменов сразу после правил на выход
        main.edit_upstream(Req({"routing": {"domains": "example.com", "domain_lists": [],
                                            "net_lists": [a, b]}}), uid)
        own = Store.upstream(main.store.snapshot(), uid)["own_list"]
        self.assertEqual(self.rules(), [("RU", ["ru"], "direct", True), ("Mine", [a, b], out, True),
                                        ("NL", [own], out, True)])


# --------------------------------------------- №4 восстановление, №11–12 API
class RestoreAndApiTest(Fixture):
    def test_restore_keeps_own_list(self):
        uid = self.exit(routing={"domains": "youtube.com\ngooglevideo.com"})
        own = Store.upstream(main.store.snapshot(), uid)["own_list"]
        b = main.make_backup()
        self.assertEqual(Store.upstream(main.clean_backup_state(b["state"]), uid)["own_list"], own)
        # чужой id или не список доменов — не берётся
        b["state"]["upstreams"][-1]["own_list"] = "ru"
        self.assertNotIn("own_list", Store.upstream(main.clean_backup_state(b["state"]), uid))

    def test_exit_type_cannot_change(self):
        uid = self.exit()
        with self.assertRaises(web.HTTPError) as cm:
            main.edit_upstream(Req({"config": AWG_EXIT}), uid)
        self.assertIn("err.exit_kind_change", str(cm.exception))
        main.edit_upstream(Req({"config": "socks5://u:p@198.51.100.10:1080"}), uid)    # тот же тип — можно
        self.assertIn("198.51.100.10", Store.upstream(main.store.snapshot(), uid)["config"])

    def test_list_kind_cannot_change(self):
        lid = self.lst("Office")
        with self.assertRaises(web.HTTPError) as cm:
            main.edit_list(Req({"kind": "country", "source": "de"}), lid)
        self.assertIn("err.list_kind_change", str(cm.exception))
        main.edit_list(Req({"kind": "manual", "source": "203.0.113.0/25", "name": "Office"}), lid)
        self.assertEqual(Store.lst(main.store.snapshot(), lid)["source"], "203.0.113.0/25")


# ----------------------------------------------------- №3 подсеть и NAT на хосте
class _HostDemo(system.DemoTarget):
    kind = "host"

    def __init__(self):
        super().__init__()
        self.conf_path = "/etc/amnezia/amneziawg/awg0.conf"


class SubnetNatTest(unittest.TestCase):
    def test_host_subnet_change_moves_nat(self):
        t = _HostDemo()
        sc = awgserver.new_server(PRIV, 51820, "10.8.1.0/24", {})
        t.write_file(t.conf_path, sc.render())
        old = main.engine.target
        main.engine.target = t
        try:
            main.engine.srv.update_server({"address": "10.66.0.1/24"})
        finally:
            main.engine.target = old
        new = awgserver.parse(t.read_file(t.conf_path))
        self.assertIn("-s 10.66.0.0/24 ", new.get("PostUp"))
        self.assertIn("-s 10.66.0.0/24 ", new.get("PostDown"))
        self.assertNotIn("10.8.1.0", new.get("PostUp"))
        self.assertTrue(any("-D POSTROUTING -s 10.8.1.0/24" in c for c in t.log))   # старое правило убрано

    def test_amnezia_container_subnet_locked(self):
        class T:
            kind = "container"

            def __init__(self, script):
                self.script = script

            def read_file(self, p):
                return self.script if p == "/opt/amnezia/start.sh" else None
        with mock.patch.object(config, "DRY_RUN", False):
            # контейнер AmneziaVPN: подсеть вписана в start.sh
            self.assertFalse(users.ServerManager.subnet_follows_conf(
                T("iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE")))
            with open(os.path.join(os.path.dirname(__file__), "..", "awg-server", "start.sh")) as f:
                self.assertTrue(users.ServerManager.subnet_follows_conf(T(f.read())))    # наш контейнер


# --------------------------------------------- №1 учёт трафика через sniproxy
class SniTrafficTest(unittest.TestCase):
    def test_update_sni_deltas_and_new_process(self):
        tr = Traffic(os.path.join(tempfile.mkdtemp(), "t.json"))
        tr.data["PK"] = {"total": [0, 0], "months": {}, "last": None}
        valid, pk_of = {"direct", "u1"}, {"10.8.1.2": "PK"}
        tr.update_sni(100, {"10.8.1.2|u1": [10, 100], "10.8.1.2|direct": [1, 2], "10.8.1.2|gone": [5, 5]},
                      valid, pk_of)
        tr.update_sni(100, {"10.8.1.2|u1": [15, 300], "10.8.1.2|direct": [1, 2]}, valid, pk_of)
        self.assertEqual(tr.out_month("u1"), [15, 300])
        self.assertEqual(tr.out_month("direct"), [1, 2])
        self.assertIsNone(tr.outs.get("gone"))                      # удалённый выход не считается
        tr.update_sni(100, {"10.8.1.2|u1": [15, 300]}, valid, pk_of)   # тот же файл ещё раз — без прироста
        tr.update_sni(200, {"10.8.1.2|u1": [5, 5]}, valid, pk_of)      # новый процесс считает с нуля
        self.assertEqual(tr.out_month("u1"), [20, 305])
        self.assertEqual(tr.view("PK")["by_out"]["u1"], [20, 305])
        tr._dirty = True
        tr.save()
        again = Traffic(tr.path)
        self.assertEqual(again.sni["pid"], 200)
        again.update_sni(200, {"10.8.1.2|u1": [5, 5]}, valid, pk_of)   # после перезапуска панели — не вдвое
        self.assertEqual(again.out_month("u1"), [20, 305])

    def test_engine_reads_sniproxy_stats(self):
        e = main.engine
        uid = main.add_upstream(Req({"name": "S", "config": "socks5://198.51.100.9:1080"}))["id"]
        try:
            ip = next(c["ip"] for c in e.clients if c.get("ip"))
            with open(_sni_stats(), "w") as f:
                json.dump({"pid": 4242424, "at": time.time(), "bytes": {f"{ip}|{uid}": [1000, 9000]}}, f)
            before = e.traffic.out_month(uid)
            e._sni_account()
            self.assertEqual([a - b for a, b in zip(e.traffic.out_month(uid), before)], [1000, 9000])
        finally:
            main.del_upstream(Req({"replace": "direct"}), uid)

    def test_sniproxy_counts_and_misses(self):
        d = tempfile.mkdtemp()
        for name, text in (("dom.txt", "example.com\n"), ("nets.txt", "203.0.113.0/24\n10.0.0.0/8\n")):
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        cfg = {"listen": "127.0.0.1", "clients": "10.8.1.0/24",
               "lists": {"ld": os.path.join(d, "dom.txt")}, "cidrs": {"ln": os.path.join(d, "nets.txt")},
               "client_policy": {"10.8.1.9": "p_1"},
               "policies": {"p_global": {"mark": 1, "rules": [], "acct": {"rules": [[["ln"], "u1"]],
                                                                           "default": "direct"}},
                            "p_1": {"mark": 2, "rules": [{"lists": ["ld"], "to": {"socks": {}, "acct": "u2"}}],
                                    "acct": {"rules": [[["ln"], None]], "default": "u3"}}}}
        p = os.path.join(d, "sni.json")
        with open(p, "w") as f:
            json.dump(cfg, f)
        s = sniproxy.Sniffer(p)
        self.assertEqual(s.miss_out("10.8.1.2", "203.0.113.7"), "u1")
        self.assertEqual(s.miss_out("10.8.1.2", "198.51.100.1"), "direct")
        self.assertIsNone(s.miss_out("10.8.1.9", "203.0.113.7"))     # блок — не считаем
        self.assertEqual(s.miss_out("10.8.1.9", "8.8.8.8"), "u3")
        to, lid = s.decide("10.8.1.9", "www.example.com")
        self.assertEqual((to["acct"], lid), ("u2", "ld"))
        self.assertIsNone(s.counter("10.8.1.9", None))
        s.counter("10.8.1.9", "u2")[0] += 5
        self.assertEqual(s.bytes, {"10.8.1.9|u2": [5, 0]})

    def test_client_gone_before_peername(self):
        """Клиент пропал до разбора соединения: посредник закрывает сокет и не падает при записи в журнал.

        Вход: неподключённый сокет (getpeername даёт ENOTCONN), в настройках debug.
        Ожидание: client() завершается без исключения, сокет закрыт.
        """
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = os.path.join(d, "sni.json")
        with open(p, "w") as f:
            json.dump({"listen": "127.0.0.1", "debug": True}, f)
        s = sniproxy.Sniffer(p)
        sock = socket.socket()
        with mock.patch.object(sniproxy, "log") as log:     # журнал проверяется: в нём и была ошибка
            asyncio.run(s.client(sock))
        self.assertEqual(sock.fileno(), -1)
        self.assertTrue(log.call_args.args[0].startswith("?: "), log.call_args)
        self.assertEqual((s.stats["active"], s.stats["errors"]), (0, 1))

    @unittest.skipUnless(hasattr(os, "splice"), "нужен os.splice (Linux)")
    def test_splice_pipe_relays_counts_and_half_closes(self):
        """Пересылка внутри ядра доставляет поток целиком, считает байты и передаёт конец потока.

        Вход: 3 МБ по TCP через пару сокетов посредника, затем SHUT_WR у отправителя.
        Ожидание: получатель видит те же байты и EOF, счётчик равен объёму, время активности обновлено.
        """
        payload = os.urandom(3 * 1024 * 1024)
        received, eof, cnt, act, _ = self._splice_relay(payload)
        self.assertEqual(received, payload)
        self.assertTrue(eof)
        self.assertEqual(cnt, [len(payload), 0])
        self.assertGreater(act[0], 0)

    @unittest.skipUnless(hasattr(os, "splice"), "нужен os.splice (Linux)")
    def test_splice_pipe_bucket_limits_rate(self):
        """Ограничение скорости выхода SOCKS5 действует на пересылку внутри ядра.

        Вход: 1,2 МБ через бак 4 МБ/с (запас 200 КБ), сторона загрузки (счётчик cnt[1]).
        Ожидание: передача не быстрее (1,2 МБ - запас) / 4 МБ/с = 0,25 с, но и без лишних пауз;
        бак, счётчик своей стороны и получатель видят весь объём.
        """
        payload = os.urandom(1_200_000)
        bucket = sniproxy.Bucket(4_000_000)
        received, eof, cnt, _, dt = self._splice_relay(payload, bucket, side=1)
        self.assertGreater(dt, 0.2)
        self.assertLess(dt, 1.0)
        self.assertEqual(received, payload)
        self.assertTrue(eof)
        self.assertEqual(cnt, [0, len(payload)])
        self.assertEqual(bucket.total, len(payload))

    @unittest.skipUnless(hasattr(os, "splice"), "нужен os.splice (Linux)")
    def test_splice_pipe_cancel_closes_pipe_and_sends_eof(self):
        """Отмена (соединение молчит дольше IDLE_TIMEOUT) не оставляет открытых каналов.

        Вход: splice_pipe отменяется через 0,1 с, пока ждёт данных от молчащего отправителя или
        ждёт бак (1 КБ/с, отправлено 100 КБ).
        Ожидание: оба дескриптора канала закрыты, получатель дочитывает до EOF (а не ждёт до
        таймаута сокета).
        """
        for case, rate, data in (("ждёт данных", None, b""), ("ждёт бак", 1000, b"x" * 100_000)):
            with self.subTest(case):
                sender, proxy_in = _tcp_pair()
                proxy_out, receiver = _tcp_pair()
                try:
                    sender.sendall(data)

                    async def run():
                        """Запускает пересылку, отменяет её и отдаёт дескрипторы созданного канала."""
                        proxy_in.setblocking(False)
                        proxy_out.setblocking(False)
                        bucket = sniproxy.Bucket(rate) if rate else None
                        fds = []
                        real_pipe2 = os.pipe2
                        with mock.patch.object(sniproxy.os, "pipe2",
                                               side_effect=lambda flags: fds.extend(real_pipe2(flags)) or fds):
                            task = asyncio.ensure_future(
                                sniproxy.splice_pipe(proxy_in, proxy_out, [0, 0], 0, [0.0], bucket))
                            await asyncio.sleep(0.1)
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                        return fds
                    for fd in asyncio.run(run()):
                        with self.assertRaises(OSError):
                            os.fstat(fd)
                    receiver.settimeout(5)
                    got = b""
                    while chunk := receiver.recv(65536):    # запас бака мог пройти до отмены
                        got += chunk
                    self.assertLessEqual(len(got), len(data))
                finally:
                    for s in (sender, proxy_in, proxy_out, receiver):
                        s.close()

    def test_relay_both_stops_other_side_on_error(self):
        """Одна сторона соединения упала (например, не хватило дескрипторов на канал splice).

        Вход: первая сторона сразу бросает OSError, вторая ждёт данных.
        Ожидание: вторая остановлена до возврата (вызывающий сразу закрывает сокеты: живая сторона
        ждала бы на закрытом и снова выданном ядром дескрипторе), ошибка идёт дальше.
        """
        stopped = []

        async def fails():
            """Сторона, упавшая сразу."""
            raise OSError(24, "Too many open files")

        async def run():
            """-> какие стороны успели остановиться к возврату relay_both."""
            with self.assertRaises(OSError):
                await sniproxy.relay_both(fails(), _side(3600, stopped), [time.monotonic()])
            return list(stopped)            # до того, как asyncio.run отменит оставшиеся задачи
        self.assertEqual(asyncio.run(run()), ["cancelled"])

    def test_relay_both_half_close_keeps_other_side(self):
        """Клиент закрыл запись (запрос отправлен), а ответ сайта ещё идёт.

        Вход: одна сторона заканчивается нормально сразу, другая через 0,2 с.
        Ожидание: вторая сторона доработала до конца, а не отменена вместе с первой.
        """
        stopped = []

        async def run():
            """Обе стороны заканчиваются сами, в разное время."""
            await sniproxy.relay_both(_side(0, stopped), _side(0.2, stopped), [time.monotonic()])
            return list(stopped)
        self.assertEqual(asyncio.run(run()), ["done", "done"])

    def test_relay_both_stops_idle_connection(self):
        """Соединение молчит дольше IDLE_TIMEOUT: обе стороны останавливаются.

        Вход: IDLE_TIMEOUT 0,05 с, время последних данных давно в прошлом, обе стороны ждут.
        Ожидание: relay_both возвращается быстро и без ошибки, обе стороны отменены.
        """
        stopped = []

        async def run():
            """Обе стороны ждут бесконечно; выйти можно только по простою."""
            await asyncio.wait_for(sniproxy.relay_both(_side(3600, stopped), _side(3600, stopped), [0.0]), 5)
            return list(stopped)
        with mock.patch.object(sniproxy, "IDLE_TIMEOUT", 0.05):
            self.assertEqual(asyncio.run(run()), ["cancelled", "cancelled"])

    def test_relay_both_waits_sides_even_if_cancelled_again(self):
        """Соединение отменяют дважды (остановка посредника), пока стороны ещё снимают регистрацию.

        Вход: стороны после отмены освобождаются 0,1 с; задача relay_both отменяется второй раз
        во время этого ожидания.
        Ожидание: к выходу из relay_both обе стороны остановлены (иначе вызывающий закрыл бы сокеты
        под ними), а отмена доходит до вызывающего.
        """
        stopped = []

        async def run():
            """Отменяет relay_both дважды и смотрит, кто остановился к её выходу."""
            task = asyncio.ensure_future(sniproxy.relay_both(_side(3600, stopped, linger=0.1),
                                                             _side(3600, stopped, linger=0.1), [time.monotonic()]))
            await asyncio.sleep(0.05)
            task.cancel()
            await asyncio.sleep(0.02)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            return list(stopped)
        self.assertEqual(asyncio.run(run()), ["cancelled", "cancelled"])

    def test_send_to_peer_that_does_not_read_times_out(self):
        """Собеседник принял соединение, но не читает: отправка (первые байты клиента сайту,
        запросы SOCKS5) не висит вечно, а кончается по CONNECT_TIMEOUT.

        Вход: буферы сокетов меньше данных (4 МБ), получатель не читает, CONNECT_TIMEOUT 0,5 с.
        Ожидание: send_all заканчивается TimeoutError не позже чем через 3 с.
        """
        sender, peer = _tcp_pair()
        self.addCleanup(sender.close)
        self.addCleanup(peer.close)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        sender.setblocking(False)

        async def run():
            """Отправка в сокет, который никто не читает. -> сколько она длилась."""
            t0 = time.monotonic()
            # внешний предел: без тайм-аута в send_all тест упал бы, а не завис
            send = asyncio.ensure_future(sniproxy.send_all(sender, b"x" * (4 * 1024 * 1024)))
            done, _ = await asyncio.wait([send], timeout=3)
            if not done:
                send.cancel()
                self.fail("send_all ждёт дольше 3 с")
            self.assertIsInstance(send.exception(), asyncio.TimeoutError)
            return time.monotonic() - t0
        with mock.patch.object(sniproxy, "CONNECT_TIMEOUT", 0.5):
            self.assertLess(asyncio.run(run()), 3)

    @staticmethod
    def _splice_relay(payload: bytes, bucket=None, side=0) -> tuple[bytes, bool, list, list, float]:
        """Пропускает payload через splice_pipe между двумя парами loopback-сокетов.
        -> (что получил получатель, увидел ли он EOF до закрытия сокетов, счётчик, время активности,
        длительность пересылки)."""
        sender, proxy_in = _tcp_pair()
        proxy_out, receiver = _tcp_pair()
        received = bytearray()

        def send():
            """Отправитель закрывает свою сторону записи, как браузер после запроса."""
            sender.sendall(payload)
            sender.shutdown(socket.SHUT_WR)

        def receive():
            """Чтение до EOF доказывает, что посредник передал конец потока."""
            while chunk := receiver.recv(65536):
                received.extend(chunk)

        async def run():
            """Пересылка одной стороны; время меряется только по ней, без запуска потоков и цикла."""
            proxy_in.setblocking(False)
            proxy_out.setblocking(False)
            cnt, act = [0, 0], [0.0]
            t0 = time.monotonic()
            await asyncio.wait_for(sniproxy.splice_pipe(proxy_in, proxy_out, cnt, side, act, bucket), 20)
            return cnt, act, time.monotonic() - t0

        sending = threading.Thread(target=send, daemon=True)
        receiving = threading.Thread(target=receive, daemon=True)
        sending.start()
        receiving.start()
        try:
            cnt, act, dt = asyncio.run(run())
            receiving.join(5)               # сокеты ещё открыты: EOF мог прийти только от shutdown
            eof = not receiving.is_alive()
        finally:
            for s in (sender, proxy_in, proxy_out, receiver):
                s.close()
            sending.join(20)
            receiving.join(20)
        return bytes(received), eof, cnt, act, dt


class SniproxyServeTest(unittest.TestCase):
    """Приём соединений посредником: нехватка дескрипторов и падение цикла приёма."""

    def sniffer(self, **cfg) -> sniproxy.Sniffer:
        """Посредник с минимальным sni.json во временном каталоге."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = os.path.join(d, "sni.json")
        with open(p, "w") as f:
            json.dump({"listen": "127.0.0.1", **cfg}, f)
        return sniproxy.Sniffer(p)

    def test_accept_errors_do_not_flood_log(self):
        """Приём падает раз за разом (как при исчерпании дескрипторов): журнал не заливается.

        Вход: слушающий сокет, на котором accept всегда даёт ошибку; цикл приёма работает 0,5 с.
        Ожидание: одна запись в журнале, а не по записи на каждую попытку.
        """
        s = self.sniffer()
        broken = socket.socket()                        # не слушает: accept даёт EINVAL
        broken.setblocking(False)
        self.addCleanup(broken.close)

        async def run():
            """Даёт циклу приёма поработать 0,5 с."""
            task = asyncio.ensure_future(s.accept_loop(broken))
            await asyncio.sleep(0.5)
            task.cancel()
        with mock.patch.object(sniproxy, "log") as log:
            asyncio.run(run())
        self.assertEqual(log.call_count, 1, log.call_args_list)

    def test_accept_loop_death_stops_process(self):
        """Цикл приёма упал неожиданной ошибкой: процесс останавливается, а не живёт без приёма.

        Вход: serve() с циклом приёма, который сразу бросает RuntimeError.
        Ожидание: цикл событий остановлен меньше чем за 3 с, причина в журнале
        (панель увидит остановку и перезапустит посредника).
        """
        with socket.socket() as probe:                  # свободный порт
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        s = self.sniffer(port=port)
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)
        with mock.patch.object(s, "accept_loop", side_effect=RuntimeError("boom")), \
                mock.patch.object(sniproxy, "log") as log:
            loop.create_task(s.serve())
            guard = loop.call_later(3, loop.stop)       # не дать тесту зависнуть, если остановки нет
            t0 = time.monotonic()
            loop.run_forever()
            elapsed = time.monotonic() - t0
            guard.cancel()
            rest = asyncio.all_tasks(loop)              # serve и деление предела работают бесконечно
            for t in rest:
                t.cancel()
            loop.run_until_complete(asyncio.gather(*rest, return_exceptions=True))
        self.assertLess(elapsed, 2.5)
        self.assertTrue(any("accept" in c.args[0] and "boom" in c.args[0] for c in log.call_args_list),
                        log.call_args_list)


async def _side(seconds: float, stopped: list, linger: float = 0.0) -> None:
    """Сторона соединения для relay_both: работает seconds и пишет в stopped, как закончила.
    linger — сколько она освобождается после отмены (снимает регистрацию дескрипторов)."""
    try:
        await asyncio.sleep(seconds)
    except asyncio.CancelledError:
        await asyncio.sleep(linger)
        stopped.append("cancelled")
        raise
    stopped.append("done")


def _tcp_pair() -> tuple[socket.socket, socket.socket]:
    """Пара соединённых TCP-сокетов на loopback, как у посредника с клиентом или целью."""
    with socket.create_server(("127.0.0.1", 0)) as listener:
        outer = socket.create_connection(listener.getsockname())
        inner, _ = listener.accept()
    return outer, inner


def _sni_stats():
    from app import engine as eng
    return eng.SNI_STATS


# -------------------------------------------------------------- №10 MSS clamp
class MssOutputTest(unittest.TestCase):
    def test_output_clamp_with_sniffing(self):
        ups = [{"num": 1, "snat": "10.9.0.2", "mtu": 1280}]
        gp = {"rules": [], "default": 1, "domain": [(["ld"], "up:x")]}
        text = nftgen.generate("awg0", {}, ups, gp, {}, 10443)
        self.assertIn("type filter hook postrouting priority mangle", text)
        self.assertIn('oifname "awgr1" tcp flags & (syn | rst) == syn tcp option maxseg size > 1240', text)
        self.assertNotIn("c_mss_out", nftgen.generate("awg0", {}, ups, gp, {}, None))   # без sniproxy не нужно


# ---------------------------------------------------- №5 пауза для неработающих выходов
class ExitBackoffTest(unittest.TestCase):
    def test_failed_start_backs_off_and_resets(self):
        e = main.engine
        uid = main.add_upstream(Req({"name": "Dead", "config": "socks5://proxy.invalid:1080"}))["id"]
        calls = []

        def boom(*a, **k):
            calls.append(1)
            raise system.SysError(Msg("socks.resolve", host="proxy.invalid"))
        try:
            with mock.patch.object(e, "_start_up", side_effect=boom):
                n0 = sum(1 for x in e.events if x["msg"].key == "ev.upstream_error")
                for _ in range(5):
                    e.reconcile()
                self.assertEqual(len(calls), 1)                     # 10 с паузы ещё не прошли
                self.assertEqual(sum(1 for x in e.events if x["msg"].key == "ev.upstream_error") - n0, 1)
                self.assertEqual(e.health[uid]["state"], "error")
                e._up_fail[uid]["next"] = 0                          # пауза прошла
                e.reconcile()
                self.assertEqual(len(calls), 2)
                self.assertGreaterEqual(e._up_fail[uid]["next"] - time.time(), 25)   # дальше — дольше
                main.reapply(None)                                   # «Применить заново» — сразу
                e.reconcile()
                self.assertEqual(len(calls), 3)
        finally:
            main.del_upstream(Req({"replace": "direct"}), uid)
        e.reconcile()
        self.assertNotIn(uid, e._up_fail)                            # выхода нет — нет и паузы


# ---------------------------------------------------------------- №13–15 подсказки
class HintsTest(unittest.TestCase):
    def test_texts(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "app", "static", "i18n.js")) as f:
            js = f.read()
        for key in ("err.exit_kind_change", "err.list_kind_change", "srv.subnet_container",
                    "srv.subnet_container_hint"):
            self.assertEqual(js.count(f'"{key}":'), 4, key)
        for key in ("cl.quota_hint", "ex.quota_hint"):               # когда начнётся месяц по часам браузера
            lines = [l for l in js.splitlines() if f'"{key}":' in l]
            self.assertEqual(len(lines), 4, key)
            self.assertTrue(all("{time}" in l and "UTC" in l for l in lines), key)
        self.assertEqual(js.count("ECH"), 4)


if __name__ == "__main__":
    unittest.main()
