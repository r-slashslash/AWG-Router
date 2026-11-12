"""Исправления 1.12.2: python3 -m unittest discover tests"""
import asyncio
import json
import os
import sys
import tempfile
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

    def test_pipe_counts_bytes(self):
        async def run():
            r = asyncio.StreamReader()
            r.feed_data(b"x" * 1000)
            r.feed_eof()

            class W:
                data = b""

                def write(self, b):
                    W.data += b

                async def drain(self):
                    pass

                def can_write_eof(self):
                    return False
            cnt, act = [0, 0], [0.0]
            await sniproxy.pipe(r, W(), cnt, 1, act)
            return cnt, act, W.data
        cnt, act, data = asyncio.run(run())
        self.assertEqual((cnt, len(data)), ([0, 1000], 1000))
        self.assertGreater(act[0], 0)

    def test_client_gone_before_peername(self):
        """Клиент пропал до разбора соединения: посредник закрывает сокет и не падает при записи в журнал.

        Вход: неподключённый сокет (getpeername даёт ENOTCONN), в настройках debug.
        Ожидание: client() завершается без исключения, сокет закрыт.
        """
        import socket
        p = os.path.join(tempfile.mkdtemp(), "sni.json")
        with open(p, "w") as f:
            json.dump({"listen": "127.0.0.1", "debug": True}, f)
        s = sniproxy.Sniffer(p)
        sock = socket.socket()
        with mock.patch.object(sniproxy, "log"):
            asyncio.run(s.client(sock))
        self.assertEqual(sock.fileno(), -1)

    @unittest.skipUnless(hasattr(os, "splice"), "нужен os.splice (Linux)")
    def test_splice_pipe_relays_counts_and_half_closes(self):
        """Пересылка внутри ядра доставляет поток целиком, считает байты и передаёт конец потока.

        Вход: 3 МБ по TCP через пару сокетов посредника, затем SHUT_WR у отправителя.
        Ожидание: получатель видит те же байты и EOF, счётчик равен объёму, время активности обновлено.
        """
        import socket
        import threading

        def pair():
            """Пара соединённых TCP-сокетов на loopback, как у посредника с клиентом или целью."""
            with socket.create_server(("127.0.0.1", 0)) as listener:
                outer = socket.create_connection(listener.getsockname())
                inner, _ = listener.accept()
            return outer, inner

        sender, proxy_in = pair()
        proxy_out, receiver = pair()
        payload = os.urandom(3 * 1024 * 1024)
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
            proxy_in.setblocking(False)
            proxy_out.setblocking(False)
            cnt, act = [0, 0], [0.0]
            await asyncio.wait_for(sniproxy.splice_pipe(proxy_in, proxy_out, cnt, 0, act), 20)
            return cnt, act

        threads = [threading.Thread(target=send), threading.Thread(target=receive)]
        for thread in threads:
            thread.start()
        try:
            cnt, act = asyncio.run(run())
        finally:
            for thread in threads:
                thread.join(20)
            for s in (sender, proxy_in, proxy_out, receiver):
                s.close()
        self.assertEqual(bytes(received), payload)
        self.assertEqual(cnt, [len(payload), 0])
        self.assertGreater(act[0], 0)


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
