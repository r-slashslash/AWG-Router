"""1.21.0, проверка ветки: QUIC «пропустить» живёт и после ответа сервера, DNS клиента со своей политикой без
правил по доменам, команда nft набора адресов не держит цикл событий DNS, пульс прошлого sniproxy.py не
убивает новый, предел кусков CRYPTO, неверные типы фильтра по DNS и периода копий.

python3 -m unittest discover tests
"""
import asyncio
import json
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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import config, dnsproxy, engine, lists, main, nftgen, quic  # noqa: E402
from app.store import Store  # noqa: E402
from app.web import HTTPError  # noqa: E402

UP = ("[Interface]\nAddress = 10.9.0.{n}/32\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\n"
      "[Peer]\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\nAllowedIPs = 0.0.0.0/0\n"
      "Endpoint = 198.51.100.{n}:51820\n")
PASS, BIT = config.QUIC_PASS_MARK, config.QUIC_CT_BIT


class Req:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


def chain(text, name):
    return text.split(f"\tchain {name} {{\n")[1].split("\n\t}")[0]


# ------------------------------------------------------------------ QUIC «пропустить» в conntrack
class QuicPassConntrackTest(unittest.TestCase):
    """Сайт не из правил: вердикт «пропустить» запоминается в conntrack. Раньше он не записывался, и после
    ответа сервера (UDP уже не «новый», в очередь не идёт) пакет без метки попадал в строку блока QUIC
    политики — HTTP/3 обрывался у всех сайтов, кроме сайтов из правил."""
    UPS = [{"num": 1, "mtu": 1280}, {"num": 2, "mtu": 1280, "no_quic": True}]

    def gen(self, default=1, balance=frozenset(), quic_on=True):
        gp = {"rules": [], "default": default, "domain": [(["d1"], "direct")]}
        return nftgen.generate("awg0", {}, self.UPS, gp, {}, config.SNI_PROXY_PORT, balance, quic=quic_on)

    def test_pass_written_and_goes_on(self):
        pre = chain(self.gen(), "c_prerouting")
        line = f"udp dport 443 meta mark {PASS:#x} ct mark set {PASS | BIT:#x}"
        self.assertIn(line + "\n", pre)
        self.assertNotIn(line + " accept", pre)                   # дальше — обычные правила политики
        self.assertLess(pre.index(line), pre.index("ip saddr vmap @clients"))

    def test_restore_gives_pass_back(self):
        """c_quic возвращает метку из conntrack без бита: «пропустить» снова проходит мимо блока политики."""
        t = self.gen()
        self.assertEqual((PASS | BIT) & (0xFFFFFFFF ^ BIT), PASS)
        self.assertIn(f"meta mark set ct mark & {0xFFFFFFFF ^ BIT:#x} accept", chain(t, "c_quic"))
        self.assertIn(f"udp dport 443 meta mark != {PASS:#x} goto o_block", chain(t, "p_global"))

    def test_sticky_keeps_pass_decision(self):
        """Выход с балансировкой (Sticky) переписывает ct mark: решение «пропустить» на этом выходе — с битом,
        и дальше пакеты соединения идут тем же выходом, а не в блок."""
        t = self.gen(nftgen.Sticky(1), {1, 2})
        ob1 = chain(t, "ob_u1")
        line = f"udp dport 443 meta mark {PASS:#x} meta mark set {nftgen.mark_for(1):#x} " \
               f"ct mark set {nftgen.mark_for(1) | BIT:#x} accept"
        self.assertIn(line, ob1)
        self.assertLess(ob1.index(line), ob1.index(f"meta mark set {nftgen.mark_for(1):#x} ct mark set "
                                                   f"{nftgen.mark_for(1):#x} accept"))
        ob2 = chain(t, "ob_u2")                                  # выход без QUIC: отказ раньше
        self.assertLess(ob2.index(f"udp dport 443 meta mark set {config.MARK_BLOCK:#x}"), ob2.index(f"{PASS:#x}"))

    def test_without_queue_nothing_new(self):
        t = self.gen(nftgen.Sticky(1), {1, 2}, quic_on=False)
        self.assertNotIn(f"{PASS:#x}", t)
        self.assertNotIn(f"{BIT:#x}", t)

    @unittest.skipUnless(os.geteuid() == 0 and shutil.which("nft") and shutil.which("unshare"), "нужны root и nft")
    def test_nft_accepts(self):
        for kw in ({}, {"default": nftgen.Sticky(1), "balance": {1, 2}}):
            text = self.gen(**kw).replace(f"queue num {config.QUIC_QUEUE} bypass", "accept")
            r = subprocess.run(["unshare", "-n", "nft", "-c", "-f", "-"], input=text, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, (kw, r.stderr))


# ------------------------------------------------------------------ DNS: клиент со своей политикой
class DnsOwnPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.engine.reconcile()

    def setUp(self):
        st = main.store.snapshot()
        self._routing = {"default": st["routing"]["default"], "rules": list(st["routing"]["rules"])}
        self._lists = {l["id"] for l in st["lists"]}
        with mock.patch.object(lists, "_fetch", side_effect=OSError("offline")):
            self.lid = main.add_list(Req({"kind": "domains", "source": "youtube.com"}))["id"]
            self.uid = main.add_upstream(Req({"name": "Exit", "config": UP.format(n=71)}))["id"]
        self.pk = None

    def tearDown(self):
        r = self._routing
        main.store.mutate(lambda st: st.update(routing={"default": r["default"], "rules": r["rules"]}))
        if self.pk:
            main.store.mutate(lambda st: st["clients"].pop(self.pk, None))
        if Store.upstream(main.store.snapshot(), self.uid):
            main.del_upstream(Req({"replace": "direct"}), self.uid)
        for l in main.store.snapshot()["lists"]:
            if l["id"] not in self._lists:
                main.del_list(None, l["id"])
        main.engine.reconcile()

    def test_client_without_domain_rules_not_global(self):
        """Общая политика — домены через выход, у клиента своя политика без правил по доменам. Раньше
        клиента не было в "clients", и dnsproxy.py разбирал его имена через выход общего правила."""
        e = main.engine
        main.put_routing(Req({"default": "direct", "rules": [
            {"lists": [self.lid], "outbound": "up:" + self.uid, "enabled": True, "comment": ""}]}))
        st = main.store.snapshot()
        num = Store.upstream(st, self.uid)["num"]
        ip = "10.8.1.77"
        with mock.patch.object(e, "_policies", return_value=(
                {"rules": [], "default": "direct", "domain": [([self.lid], "up:" + self.uid)]},
                {ip: {"rules": [], "default": num, "domain": []}})), \
                mock.patch.object(e, "resolve", side_effect=lambda o, s: num if o == "up:" + self.uid else o):
            d = e.dns_domains(st, with_set=False)
        self.assertIn(ip, d["clients"])
        self.assertNotIn(d["clients"][ip], d["policies"])
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        lp = os.path.join(tmp, "l.domains")
        with open(lp, "w") as f:
            f.write("youtube.com\n")
        conf = os.path.join(tmp, "dns.json")
        with open(conf, "w") as f:
            json.dump({"listen": "127.0.0.1", "default": {"mark": 0, "tcp": False}, "routes": {},
                       "dom": {**d, "lists": {self.lid: lp}}}, f)
        p = dnsproxy.Proxy(conf)
        self.assertIsNone(p.domain_route(ip, "www.youtube.com."))                 # обычным путём клиента
        self.assertEqual(p.domain_route("10.8.1.2", "www.youtube.com.")[0]["mark"], nftgen.mark_for(num))


# ------------------------------------------------------------------ DNS: nft add element в потоке
class DnsFlushThreadTest(unittest.TestCase):
    def test_flush_does_not_block_loop(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        conf = os.path.join(tmp, "dns.json")
        with open(conf, "w") as f:
            json.dump({"listen": "127.0.0.1", "default": {"mark": 0, "tcp": False}, "routes": {},
                       "dom": {"lists": {}, "policies": {}, "clients": {}, "set": ["awgr", "dom4"]}}, f)
        p = dnsproxy.Proxy(conf)
        calls = []

        def slow(cmd, **kw):          # nft ждёт блокировку таблицы, пока панель её пересобирает
            time.sleep(0.5)
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        async def go():
            p.pending = {"142.250.1.1": 1800}
            with mock.patch.object(dnsproxy.subprocess, "run", side_effect=slow):
                t0 = time.monotonic()
                fut = p.flush()
                await asyncio.sleep(0.01)
                lag = time.monotonic() - t0
                await fut
            return lag
        lag = asyncio.run(go())
        self.assertLess(lag, 0.3)
        self.assertEqual(calls[0][:6], ["nft", "add", "element", "ip", "awgr", "dom4"])
        self.assertIn("142.250.1.1 timeout 1800s", calls[0][6])


# ------------------------------------------------------------------ пульс прошлого sniproxy.py
class SniStaleBeatTest(unittest.TestCase):
    def test_start_removes_old_beat(self):
        """Файл пульса остался от прошлого процесса (старый mtime): новый посредник, который разбирает большие
        списки дольше SNI_HANG, присмотр убил бы, не дождавшись первого пульса."""
        e = main.engine
        os.makedirs(os.path.dirname(engine.SNI_BEAT), exist_ok=True)
        open(engine.SNI_BEAT, "a").close()
        os.utime(engine.SNI_BEAT, (time.time() - 3600, time.time() - 3600))
        st = main.store.snapshot()
        t = mock.Mock(key="k-beat", pid=1, iface="awg0")
        proc = mock.Mock()
        proc.poll.return_value = None
        proc.pid = 4242
        pol = {"rules": [], "default": "direct", "domain": [(["l1"], "direct")]}
        old_sni, old_retry = e.sni, e._sni_retry
        self.addCleanup(setattr, e, "sni", old_sni)
        self.addCleanup(setattr, e, "_sni_retry", old_retry)
        e.sni, e._sni_retry = None, 0.0
        with mock.patch.object(config, "DRY_RUN", False), \
                mock.patch.object(e, "_policies", return_value=(pol, {})), \
                mock.patch.object(e, "tunnel_addr", return_value=("10.8.1.1", "10.8.1.0/24")), \
                mock.patch.object(e, "_input_rule"), mock.patch.object(engine.time, "sleep"), \
                mock.patch.object(engine.subprocess, "Popen", return_value=proc):
            self.assertEqual(e._sync_sni(t, st), config.SNI_PROXY_PORT)
            self.assertFalse(os.path.exists(engine.SNI_BEAT))
            e.sni.started = time.time() - engine.SNI_HANG - 5
            self.assertFalse(e._sni_hung())                  # первого пульса ещё нет — ждём SNI_HANG × 4
            e.sni.started = time.time() - engine.SNI_HANG * 4 - 5
            self.assertTrue(e._sni_hung())
        e.sni = None


# ------------------------------------------------------------------ предел кусков CRYPTO
class AssemblerPartsTest(unittest.TestCase):
    def test_many_offsets_capped(self):
        a = quic.Assembler()
        a.add([(i * 3, b"xy") for i in range(500)])
        self.assertLessEqual(len(a.parts), quic.PARTS_MAX)
        a.add([(0, b"\x01\x00\x00\x02ab")])                  # уже известное смещение — заменяется длинным
        self.assertEqual(a.parts[0], b"\x01\x00\x00\x02ab")


# ------------------------------------------------------------------ неверные типы
class BadTypesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.engine.reconcile()                              # демо-сервер AWG: без него put_server — srv.no_server

    def test_dom_filter_not_bool(self):
        for v in ("false", 0, 1, None, [], {}):
            with self.assertRaises(HTTPError) as cm:
                main.put_server(Req({"dom_filter": v}))
            self.assertEqual((cm.exception.code, getattr(cm.exception.detail, "key", None)), (400, "err.bad_value"), v)
        self.assertFalse(main.store.snapshot()["settings"].get("dom_filter"))

    def test_backup_period_list_in_backup(self):
        st = main.store.snapshot()
        st["settings"]["telegram"] = {"token": "", "chat_id": "", "backup": ["daily"]}
        out = main.clean_backup_state(st)                    # раньше — TypeError (список ключом dict) → 500
        self.assertNotEqual(out["settings"]["telegram"].get("backup"), ["daily"])


if __name__ == "__main__":
    unittest.main()
