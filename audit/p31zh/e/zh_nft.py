"""Ж: запись в набор dom4 настоящим кодом (Proxy._nft_tx / _nft_add из папки app) на настоящем nftables.
Части (аргумент part):
  sem      — транзакция: таблицы нет; адреса нет; адрес есть; адрес истёк, но ещё не убран; срок после перезаписи растёт;
             тот же адрес дважды (ключи словаря не повторяются — проверка самого nft); 1.24/c934013 для сравнения;
  wmem     — без CAP_NET_ADMIN в начальном пространстве (запускать в unshare -rn, wmem_max задан снаружи): делится ли
             запись, все ли адреса в наборе, сколько запусков nft, текст ошибки nft;
  resync   — время _nft_add на N адресов (новые и уже в наборе) с таблицей размера ru (12 302 сети) против срока
             10 + N/1000 с; заодно прежний _nft_add (по команде на 2000) для сравнения;
  rebuild  — панель пересобирает таблицу (delete table + table {…}, как nftgen) во время долгой транзакции: что в
             наборе после обоих; две транзакции сразу (resync и обычная запись);
  neigh    — соседи: inet awgr dom4, ip filter dom4, свой набор CrowdSec — запись трогает только ip awgr dom4.
Запуск: unshare -n python3 -I zh_nft.py <папка app> <часть> [N…]   (wmem — unshare -rn)"""
from __future__ import annotations

import ipaddress
import json
import os
import random
import subprocess
import sys
import tempfile
import threading
import time

APP = sys.argv[1]
PART = sys.argv[2]
ARGS = [int(x) for x in sys.argv[3:]]
sys.path.insert(0, APP)
import dnsproxy  # noqa: E402

R = random.Random(11)
NFT_LOG = tempfile.mktemp()


def shim():
    """nft через обёртку, которая считает запуски (PATH)."""
    d = tempfile.mkdtemp()
    real = subprocess.run(["sh", "-c", "command -v nft"], capture_output=True, text=True).stdout.strip()
    with open(d + "/nft", "w") as f:
        f.write(f"#!/bin/sh\necho run >> {NFT_LOG}\nexec {real} \"$@\"\n")
    os.chmod(d + "/nft", 0o755)
    os.environ["PATH"] = d + ":" + os.environ.get("PATH", "")


def runs() -> int:
    try:
        with open(NFT_LOG) as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def nft(text: str, check=True) -> subprocess.CompletedProcess:
    r = subprocess.run(["nft", "-f", "-"], input=text, capture_output=True, text=True)
    if check and r.returncode:
        raise SystemExit(r.stderr[:400])
    return r


def table(ru: int = 0, name: str = "awgr") -> None:
    nft(f"table ip {name}\ndelete table ip {name}\n" + panel_table(ru, name))


def panel_table(ru: int, name: str = "awgr") -> str:
    lines = [f"table ip {name} {{", "\tset dom4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}",
             "\tset l_ru {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge"]
    if ru:
        lines.append("\t\telements = { " + ", ".join(nets(ru)) + " }")
    lines += ["\t}", "\tchain c_prerouting {\n\t\ttype filter hook prerouting priority mangle + 10; policy accept;",
              "\t\tip daddr @dom4 tcp dport { 80, 443 } ct state new meta mark set 0xd000 accept",
              "\t\tip daddr @l_ru meta mark set 0x2001\n\t}", "}"]
    return "\n".join(lines) + "\n"


_NETS = {}


def nets(n: int) -> list[str]:
    if n in _NETS:
        return _NETS[n]
    out, seen = [], set()
    rr = random.Random(3)
    while len(out) < n:
        a = ipaddress.ip_network(f"{rr.randrange(1, 223)}.{rr.randrange(256)}.{rr.randrange(256)}.0/"
                                 f"{rr.choice([16, 20, 22, 24])}", strict=False)
        if not any(a.overlaps(b) for b in ()) and a not in seen:
            seen.add(a)
            out.append(str(a))
    _NETS[n] = out
    return out


def addrs(n: int, base: int = 0) -> list[str]:
    return [str(ipaddress.IPv4Address(0x0A000000 + base + i)) for i in range(n)]


def elements(tbl="awgr", st="dom4", fam="ip") -> dict[str, float]:
    """Адрес → сколько секунд осталось (expires)."""
    out = subprocess.run(["nft", "-j", "list", "set", fam, tbl, st], capture_output=True, text=True).stdout
    try:
        js = json.loads(out)
    except ValueError:
        return {}
    res = {}
    for x in js.get("nftables", []):
        s = x.get("set")
        if not s:
            continue
        for e in s.get("elem", []) or []:
            if isinstance(e, dict) and "elem" in e:
                res[e["elem"]["val"]] = e["elem"].get("expires", -1)
            else:
                res[str(e)] = -1
    return res


def part_sem():
    out = {}
    tx = dnsproxy.Proxy._nft_tx
    subprocess.run(["nft", "delete", "table", "ip", "awgr"], capture_output=True)
    out["no_table"] = tx("awgr", "dom4", [("10.0.0.1", 1800)])[:160]
    table()
    out["new"] = tx("awgr", "dom4", [("10.0.0.1", 1800)])
    out["new_present"] = "10.0.0.1" in elements()
    # уже есть, тот же срок: через 3 с перезаписать — срок вырос обратно
    time.sleep(3)
    before = elements().get("10.0.0.1")
    out["same_ttl"] = tx("awgr", "dom4", [("10.0.0.1", 1800)])
    after = elements().get("10.0.0.1")
    out["renew_same_ttl"] = {"before": before, "after": after}
    # прежняя команда (c934013 и 1.24.0): add того же адреса тем же сроком
    time.sleep(3)
    b2 = elements().get("10.0.0.1")
    r = subprocess.run(["nft", "add", "element", "ip", "awgr", "dom4", "{ 10.0.0.1 timeout 1800s }"], capture_output=True,
                       text=True)
    out["old_cmd_same_ttl"] = {"rc": r.returncode, "before": b2, "after": elements().get("10.0.0.1")}
    r = subprocess.run(["nft", "add", "element", "ip", "awgr", "dom4", "{ 10.0.0.1 timeout 1900s }"], capture_output=True,
                       text=True)
    out["old_cmd_other_ttl"] = {"rc": r.returncode, "after": elements().get("10.0.0.1")}
    # истёк, но ещё в ядре (сборщик не прошёл): срок 1 с, подождать 1,5 с
    nft("add element ip awgr dom4 { 10.0.0.2 timeout 1s }\n")
    time.sleep(1.5)
    out["expired"] = tx("awgr", "dom4", [("10.0.0.2", 1800)])
    out["expired_present"] = elements().get("10.0.0.2")
    # тот же адрес дважды в одной транзакции (в коде не бывает — ключи словаря; что сделал бы nft)
    out["dup"] = tx("awgr", "dom4", [("10.0.0.3", 1800), ("10.0.0.3", 1800)])[:160]
    out["dup_present"] = "10.0.0.3" in elements()
    # пачка, в которой один адрес уже есть, другой нет
    out["mixed"] = tx("awgr", "dom4", [("10.0.0.1", 1800), ("10.0.0.9", 1800)])
    el = elements()
    out["mixed_present"] = ["10.0.0.1" in el, "10.0.0.9" in el]
    # 0.0.0.0 и 255.255.255.255 (AdGuard и др. отвечают 0.0.0.0 на заблокированное)
    out["zero"] = tx("awgr", "dom4", [("0.0.0.0", 1800), ("255.255.255.255", 1800)])
    out["zero_present"] = ["0.0.0.0" in elements(), "255.255.255.255" in elements()]
    return out


def part_wmem():
    shim()
    wm = open("/proc/sys/net/core/wmem_max").read().strip()
    out = {"wmem_max": int(wm), "nft": subprocess.run(["nft", "--version"], capture_output=True, text=True).stdout.strip()}
    for n in ARGS or [1000, 3000, 5000, 8000, 20000, 50000]:
        table()
        dnsproxy._set_tx[0] = 0
        # одна транзакция без деления — какой текст ошибки
        err = dnsproxy.Proxy._nft_tx("awgr", "dom4", [(a, 1800) for a in addrs(n)])
        table()
        dnsproxy._set_tx[0] = 0
        r0 = runs()
        t = time.perf_counter()
        dnsproxy.Proxy._nft_add("awgr", "dom4", [(a, 1800) for a in addrs(n)])
        dt = time.perf_counter() - t
        got = len(elements())
        # вторая пачка с уже известным пределом (продление тех же адресов)
        r1 = runs()
        dnsproxy.Proxy._nft_add("awgr", "dom4", [(a, 1800) for a in addrs(n)])
        out[str(n)] = {"one_tx_error": err[:200], "in_set": got, "runs_first": r1 - r0, "runs_second": runs() - r1,
                       "set_tx": dnsproxy._set_tx[0], "secs": round(dt, 2), "in_set_after_second": len(elements())}
        print(json.dumps({str(n): out[str(n)]}), flush=True)
    return out


def part_resync():
    out = {}
    ru = 12302
    for n in ARGS or [50000, 200000]:
        table(ru)
        items = [(a, 1800) for a in addrs(n)]
        t = time.perf_counter()
        dnsproxy.Proxy._nft_add("awgr", "dom4", items)
        new_s = time.perf_counter() - t
        n1 = len(elements())
        t = time.perf_counter()
        dnsproxy.Proxy._nft_add("awgr", "dom4", items)            # продление всех (как resync, когда они уже есть)
        renew_s = time.perf_counter() - t
        out[str(n)] = {"ru": ru, "first_s": round(new_s, 2), "renew_s": round(renew_s, 2), "in_set": n1,
                       "deadline_s": 10 + n // 1000}
        # прежняя запись (c934013): по команде на 2000 адресов
        table(ru)
        t = time.perf_counter()
        for i in range(0, n, 2000):
            el = ", ".join(f"{a} timeout {s}s" for a, s in items[i:i + 2000])
            subprocess.run(["nft", "add", "element", "ip", "awgr", "dom4", "{ " + el + " }"], capture_output=True)
        out[str(n)]["old_cmds_s"] = round(time.perf_counter() - t, 2)
        print(json.dumps({str(n): out[str(n)]}), flush=True)
    return out


def part_rebuild():
    out = {}
    n = ARGS[0] if ARGS else 100000
    ru = 12302
    table(ru)
    items = [(a, 1800) for a in addrs(n)]
    res = {}

    def writer():
        t = time.perf_counter()
        res["err"] = dnsproxy.Proxy._nft_tx("awgr", "dom4", items)[:200]
        res["t"] = round(time.perf_counter() - t, 2)
    th = threading.Thread(target=writer)
    th.start()
    time.sleep(0.15)
    t = time.perf_counter()
    r = nft("table ip awgr\ndelete table ip awgr\n" + panel_table(ru), check=False)
    out["rebuild_rc"], out["rebuild_s"], out["rebuild_err"] = r.returncode, round(time.perf_counter() - t, 2), r.stderr[:200]
    th.join()
    out["writer"] = res
    out["in_set_after"] = len(elements())
    # обратный порядок: пересборка идёт, запись начинается во время неё
    table(ru)

    def rebuild():
        t = time.perf_counter()
        rr = nft("table ip awgr\ndelete table ip awgr\n" + panel_table(ru), check=False)
        res["rb"] = (rr.returncode, round(time.perf_counter() - t, 2))
    th = threading.Thread(target=rebuild)
    th.start()
    time.sleep(0.05)
    t = time.perf_counter()
    e2 = dnsproxy.Proxy._nft_tx("awgr", "dom4", [("10.9.9.9", 1800)])
    out["write_during_rebuild"] = {"err": e2[:200], "secs": round(time.perf_counter() - t, 2)}
    th.join()
    out["rebuild2"] = res["rb"]
    out["small_present"] = "10.9.9.9" in elements()
    # две транзакции сразу: resync (большая) и обычная запись (тот же адрес и новый)
    table(ru)
    res2 = {}

    def big():
        res2["big"] = dnsproxy.Proxy._nft_tx("awgr", "dom4", items)[:200]
    th = threading.Thread(target=big)
    th.start()
    time.sleep(0.1)
    res2["small"] = dnsproxy.Proxy._nft_tx("awgr", "dom4", [(items[5][0], 1800), ("10.8.8.8", 1800)])[:200]
    th.join()
    el = elements()
    out["two_at_once"] = {**res2, "in_set": len(el), "small_present": "10.8.8.8" in el}
    return out


def part_neigh():
    out = {}
    table()
    nft("table inet awgr {\n\tset dom4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n}\n"
        "table ip filter {\n\tset dom4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n}\n"
        "table ip crowdsec {\n\tset crowdsec-blacklists {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n}\n")
    nft("add element inet awgr dom4 { 10.0.0.1 timeout 600s }\nadd element ip filter dom4 { 10.0.0.1 timeout 600s }\n"
        "add element ip crowdsec crowdsec-blacklists { 10.0.0.1 timeout 600s }\n")
    time.sleep(2)
    before = {k: elements(*k[1:], fam=k[0]) for k in (("inet", "awgr", "dom4"), ("ip", "filter", "dom4"),
                                                       ("ip", "crowdsec", "crowdsec-blacklists"))}
    err = dnsproxy.Proxy._nft_tx("awgr", "dom4", [("10.0.0.1", 1800), ("10.0.0.2", 1800)])
    after = {k: elements(*k[1:], fam=k[0]) for k in before}
    out["err"] = err
    out["own"] = elements()
    out["neighbours_unchanged"] = {"/".join(k): [before[k], after[k]] for k in before}
    return out


if __name__ == "__main__":
    lo = subprocess.run(["sh", "-c", "nft --version; uname -r"], capture_output=True, text=True).stdout.split("\n")
    res = {"app": APP, "part": PART, "nft": lo[0], "kernel": lo[1]}
    res.update(globals()["part_" + PART]())
    print("RESULT " + json.dumps(res), flush=True)
