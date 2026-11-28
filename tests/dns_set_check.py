"""Набор «фильтра по DNS» на настоящем nftables (Е2 проверки исправлений П31). Запускается в своей сети (unshare -n) — из
test_v125_p31e.RealSetTest (root) и из net-tests (задание dns-set: ядра машин GitHub 6.8 и 7.x).

Проверяет запись dnsproxy.py (Proxy._nft_add): повторная запись адреса, который уже в наборе, обновляет его срок — с тем
же сроком и с другим (ядро 6.8 повторный `add element` не продлевает никогда, 6.18 и 7.0 — только с другим сроком); адрес
ни на миг не пропадает из набора, пока его записывают снова (транзакция целиком); новый и уже стоящий адрес — в одной
пачке; запись через Proxy.remember — как у dnsproxy.py, когда адрес «записан 29 минут назад»; resync 20 000 адресов —
одной транзакцией. Печатает JSON и выходит с кодом 1, если что-то не так."""
import asyncio
import fcntl
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.getcwd())
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
from app import dnsproxy  # noqa: E402
from tests.test_v115 import a_reply, q_msg  # noqa: E402

TABLE = "table ip awgr {\n\tset dom4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n}\n"


def nft(*args, inp=None) -> subprocess.CompletedProcess:
    return subprocess.run(["nft", *args], input=inp, capture_output=True, text=True, timeout=60)


def left(addr: str) -> float | None:
    """Секунд до выпадения адреса из набора (None — его нет)."""
    out = nft("list", "set", "ip", "awgr", "dom4").stdout
    m = re.search(re.escape(addr) + r" timeout \S+ expires ((?:\d+h)?(?:\d+m)?(?:\d+s)?(?:\d+ms)?)", out)
    if not m:
        return None
    secs = 0.0
    for n, unit in re.findall(r"(\d+)(h|ms|m|s)", m.group(1)):
        secs += int(n) * {"h": 3600, "m": 60, "s": 1, "ms": 0.001}[unit]
    return secs


def main() -> dict:
    r = nft("-f", "-", inp=TABLE)
    assert r.returncode == 0, r.stderr
    res, bad = {"kernel": os.uname().release, "nft": nft("--version").stdout.strip()}, []
    add = dnsproxy.Proxy._nft_add

    # как ведёт себя само ядро: прежняя запись — повторный add с тем же сроком
    nft("add", "element", "ip", "awgr", "dom4", "{ 192.0.2.99 timeout 8s }")
    time.sleep(2.2)
    nft("add", "element", "ip", "awgr", "dom4", "{ 192.0.2.99 timeout 8s }")
    res["kernel_extends_plain_add"] = (left("192.0.2.99") or 0) > 7

    # 1. та же запись снова — срок свежий (с тем же и с другим сроком); новый адрес в той же пачке
    add("awgr", "dom4", [("192.0.2.1", 8)])
    time.sleep(2.2)
    add("awgr", "dom4", [("192.0.2.1", 8), ("192.0.2.2", 8)])
    res["same_timeout"] = left("192.0.2.1")
    time.sleep(1.1)
    add("awgr", "dom4", [("192.0.2.1", 30)])
    res["other_timeout"] = left("192.0.2.1")
    res["new_in_batch"] = left("192.0.2.2")
    if not (res["same_timeout"] or 0) > 7:
        bad.append("same_timeout")
    if not (res["other_timeout"] or 0) > 28:
        bad.append("other_timeout")
    if not (res["new_in_batch"] or 0) > 5:
        bad.append("new_in_batch")

    # 2. адрес ни на миг не пропадает для пакетов: 100 повторных записей пачки в 2000 адресов, и всё это время к нему идут
    # пакеты (127.0.0.3 через lo; счётчики в хуке output — «в наборе» и «не в наборе»). Не `nft get element`: чтение
    # набора во время чужой транзакции изредка не видит адрес (1 из ~120 в песочнице), а пакеты — видят всегда
    s = socket.socket()
    fcntl.ioctl(s, 0x8914, struct.pack("16sH14s", b"lo", 0x49, b""))      # lo up без ip
    s.close()
    r = nft("-f", "-", inp="table ip awgr {\n\tcounter hit {\n\t}\n\tcounter miss {\n\t}\n\tchain out {\n"
            "\t\ttype filter hook output priority 0; policy accept;\n"
            "\t\tip daddr 127.0.0.3 ip daddr @dom4 counter name hit\n"
            "\t\tip daddr 127.0.0.3 ip daddr != @dom4 counter name miss\n\t}\n}\n")
    assert r.returncode == 0, r.stderr
    batch = [("127.0.0.3", 1800)] + [(f"10.1.{i // 256}.{i % 256}", 1800) for i in range(1999)]
    add("awgr", "dom4", batch)
    stop, sent = threading.Event(), [0]

    def blast():
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not stop.is_set():
            try:
                u.sendto(b"x", ("127.0.0.3", 9))
                sent[0] += 1
            except OSError:
                pass
        u.close()
    th = threading.Thread(target=blast)
    th.start()
    for _ in range(100):
        add("awgr", "dom4", batch)
    stop.set()
    th.join()

    def counter(name: str) -> int:
        out = json.loads(nft("-j", "list", "counter", "ip", "awgr", name).stdout)
        return [x["counter"]["packets"] for x in out["nftables"] if "counter" in x][0]
    res["rewrite_packets"], res["rewrite_misses"] = counter("hit"), counter("miss")
    if res["rewrite_misses"] or res["rewrite_packets"] < 1000:
        bad.append("rewrite_misses")

    # 3. как в dnsproxy.py: ответ на имя правила → набор; «29 минут спустя» ответ снова — срок снова ~SET_MIN
    p = dnsproxy.Proxy.__new__(dnsproxy.Proxy)
    p.dom, p.live, p.pending, p._flush_at, p.stats = {"set": ["awgr", "dom4"]}, {}, {}, 0.0, {}

    async def flow():
        q = q_msg("www.example.com")
        await p.remember(a_reply(q, ["192.0.2.4"], ttl=60))
        first = left("192.0.2.4")
        nft("delete", "element", "ip", "awgr", "dom4", "{ 192.0.2.4 }")
        nft("add", "element", "ip", "awgr", "dom4", "{ 192.0.2.4 timeout 50s }")    # «осталось 50 с»
        p.live["192.0.2.4"] = time.time() + 50
        p.remember(a_reply(q, ["192.0.2.4"], ttl=60))       # продление: ответ не ждёт, запись — следующей командой
        for _ in range(100):
            await asyncio.sleep(0.05)
            if not p.pending and p._flushing.done():
                break
        return first, left("192.0.2.4")
    res["remember_first"], res["remember_again"] = asyncio.run(flow())
    if not (res["remember_first"] or 0) > dnsproxy.SET_MIN - 60 or not (res["remember_again"] or 0) > dnsproxy.SET_MIN - 60:
        bad.append("remember")

    # 4. resync после пересборки таблицы: 20 000 живых адресов — в набор (одна транзакция)
    nft("-f", "-", inp="table ip awgr\ndelete table ip awgr\n" + TABLE)
    now = time.time()
    p.live = {f"10.2.{i // 256}.{i % 256}": now + 1800 for i in range(20000)}

    async def resync():
        p.resync()
        await p._flushing
    t = time.monotonic()
    with_calls = []
    real = subprocess.run

    def counted(cmd, **kw):
        with_calls.append(cmd[:3])
        return real(cmd, **kw)
    dnsproxy.subprocess.run = counted
    try:
        asyncio.run(resync())
    finally:
        dnsproxy.subprocess.run = real
    res["resync_s"] = round(time.monotonic() - t, 3)
    res["resync_nft_runs"] = len(with_calls)
    out = nft("-j", "list", "set", "ip", "awgr", "dom4").stdout
    res["resync_in_set"] = sum(len(x["set"].get("elem") or []) for x in json.loads(out)["nftables"] if "set" in x)
    if res["resync_in_set"] != 20000:
        bad.append("resync")
    res["bad"] = bad
    return res


if __name__ == "__main__":
    out = main()
    print(json.dumps(out), flush=True)
    sys.exit(1 if out["bad"] else 0)
