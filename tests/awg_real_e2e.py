"""Настоящий туннель AmneziaWG: сервер и клиент в разных сетевых пространствах.

Проверяет, что панель генерирует рабочие серверный и клиентский конфиги:
  * новый сервер (параметры AWG 3.1 с защитой заголовков и «старые» AWG 1.5/2);
  * добавление клиента на лету через `awg syncconf` (как делает панель);
  * клиентский .conf и ссылка vpn:// после разбора дают рабочее подключение;
  * отключённый клиент перестаёт подключаться, включённый — снова работает.

Нужны root, /dev/net/tun, amneziawg-go и awg в PATH.
Запуск: PATH=<bin>:$PATH python3 tests/awg_real_e2e.py
"""
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import awgconf, awgserver  # noqa: E402

NS = ["awgt_srv", "awgt_cli"]


def sh(*cmd, ns=None, check=True, **kw):
    if ns:
        cmd = ("ip", "netns", "exec", ns) + cmd if _has_ip() else ("nsenter", f"--net=/var/run/netns/{ns}") + cmd
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {p.stderr or p.stdout}")
    return p


def _has_ip():
    return subprocess.run(["sh", "-c", "command -v ip"], capture_output=True).returncode == 0


def awg(*args, inp=None):
    return subprocess.run(["awg", *args], input=inp, capture_output=True, text=True, check=True).stdout.strip()


def keypair():
    priv = awg("genkey")
    return priv, awg("pubkey", inp=priv + "\n")


class Net:
    """Сетевые пространства через pyroute2 (в песочнице нет iproute2)."""

    def __init__(self):
        from pyroute2 import IPRoute, NetNS, netns
        self.IPRoute, self.NetNS, self.netns = IPRoute, NetNS, netns
        for n in NS:
            if n in netns.listnetns():
                netns.remove(n)
            netns.create(n)
        with IPRoute() as ip:
            ip.link("add", ifname="t_s0", kind="veth", peer="t_c0")
            ip.link("set", index=ip.link_lookup(ifname="t_s0")[0], net_ns_fd=NS[0])
            ip.link("set", index=ip.link_lookup(ifname="t_c0")[0], net_ns_fd=NS[1])
        for ns, ifn, addr in ((NS[0], "t_s0", "192.0.2.1"), (NS[1], "t_c0", "192.0.2.2")):
            with NetNS(ns) as ip:
                for name in ("lo", ifn):
                    ip.link("set", index=ip.link_lookup(ifname=name)[0], state="up")
                ip.addr("add", index=ip.link_lookup(ifname=ifn)[0], address=addr, prefixlen=24)
        self.procs = []

    def nsrun(self, ns, *cmd, check=True, timeout=20, inp=None):
        p = subprocess.run(["nsenter", f"--net=/var/run/netns/{ns}", "--", *cmd], input=inp,
                           capture_output=True, text=True, timeout=timeout)
        if check and p.returncode != 0:
            raise RuntimeError(f"{ns} {' '.join(cmd)}: {p.stderr or p.stdout}")
        return p

    def up_awg(self, ns, ifn, setconf_text, addr, prefix, mtu=1376):
        log = open(f"/tmp/{ifn}.log", "w")
        self.procs.append(subprocess.Popen(["nsenter", f"--net=/var/run/netns/{ns}", "--",
                                            "amneziawg-go", "-f", ifn], stdout=log, stderr=log))
        for _ in range(50):
            if os.path.exists(f"/var/run/amneziawg/{ifn}.sock"):
                break
            time.sleep(0.1)
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write(setconf_text)
        self.nsrun(ns, "awg", "setconf", ifn, f.name)
        with self.NetNS(ns) as ip:
            idx = ip.link_lookup(ifname=ifn)[0]
            ip.addr("add", index=idx, address=addr, prefixlen=prefix)
            ip.link("set", index=idx, mtu=mtu, state="up")
            if prefix == 32:
                ip.route("add", dst="10.8.1.0/24", oif=idx)

    def down_awg(self, ns, ifn):
        with self.NetNS(ns) as ip:
            idx = ip.link_lookup(ifname=ifn)
            if idx:
                ip.link("del", index=idx[0])
        time.sleep(0.3)

    def ping(self, ns, dst):
        """TCP-«пинг» через туннель: ICMP в песочнице может быть недоступен."""
        code = ("import socket,sys\ns=socket.socket();s.settimeout(3)\n"
                "try:\n s.connect((sys.argv[1],7));print('OK')\n"
                "except ConnectionRefusedError: print('OK')\n"
                "except OSError as e: print('FAIL',e)")
        return self.nsrun(ns, sys.executable, "-c", code, dst, check=False).stdout.strip()

    def close(self):
        for p in self.procs:
            p.kill()
        for n in NS:
            try:
                self.netns.remove(n)
            except Exception:  # noqa: BLE001
                pass


def handshake_ok(net, ifn, ns):
    out = net.nsrun(ns, "awg", "show", ifn, "latest-handshakes").stdout.split()
    return len(out) >= 2 and out[1] != "0"


def scenario(net, label, params, use_link, amnezia_style=False):
    results = []
    srv_priv, _ = keypair()
    sc = awgserver.new_server(srv_priv, 51000, "10.8.1.0/24", params, wan_masq=False,
                              amnezia_style=amnezia_style)
    srv_ip = str(sc.network.ip)            # 10.8.1.1, а в стиле Amnezia — 10.8.1.0
    net.up_awg(NS[0], "awg0", sc.stripped(), srv_ip, 24)

    # клиент добавляется в конфиг и применяется «на лету», как в панели
    cpriv, cpub = keypair()
    psk = awg("genpsk")
    ip = sc.next_ip()
    sc.peers.append(awgserver.Peer(cpub, psk, f"{ip}/32"))
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write(awgserver.parse(sc.render()).stripped())   # через запись/чтение файла
    net.nsrun(NS[0], "awg", "syncconf", "awg0", f.name)

    prof = awgserver.ClientProfile(host="192.0.2.1", port=51000, server_pub=awg("pubkey", inp=srv_priv + "\n"),
                                   dns=["1.1.1.1"], mtu=1376, keepalive=awgserver.default_keepalive(sc.params()))
    peer = sc.peer(cpub)
    conf = awgserver.client_conf(sc, prof, peer, cpriv)
    source = awgserver.vpn_link(sc, prof, peer, cpriv, conf, "test") if use_link else conf
    up = awgconf.parse_upstream(source)       # тот же разбор, что и для выходов панели
    net.up_awg(NS[1], "awgc", up.setconf, up.address, 32, up.mtu)

    r = net.ping(NS[1], srv_ip)
    ok = r == "OK" and handshake_ok(net, "awgc", NS[1])
    results.append((f"{label}: клиент {ip} подключается ({'vpn://' if use_link else '.conf'})", ok, r))

    # отключение: пир закомментирован, syncconf убирает его с интерфейса
    peer.enabled = False
    reparsed = awgserver.parse(sc.render())
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write(reparsed.stripped())
    net.nsrun(NS[0], "awg", "syncconf", "awg0", f.name)
    peers_now = net.nsrun(NS[0], "awg", "show", "awg0", "peers").stdout.split()
    results.append((f"{label}: отключённый клиент убран с сервера", cpub not in peers_now
                    and reparsed.peer(cpub) and not reparsed.peer(cpub).enabled, peers_now))
    r2 = net.ping(NS[1], srv_ip)
    results.append((f"{label}: отключённый клиент не проходит", r2.startswith("FAIL"), r2))

    reparsed.peer(cpub).enabled = True
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write(awgserver.parse(reparsed.render()).stripped())
    net.nsrun(NS[0], "awg", "syncconf", "awg0", f.name)
    # клиент держит старую сессию; новое рукопожатие — по его собственным таймаутам
    t0 = time.time()
    r3 = ""
    while time.time() - t0 < 45:
        r3 = net.ping(NS[1], srv_ip)
        if r3 == "OK":
            break
    results.append((f"{label}: снова включённый клиент работает (через {time.time() - t0:.0f} с)",
                    r3 == "OK", r3))

    net.down_awg(NS[1], "awgc")
    net.down_awg(NS[0], "awg0")
    return results


def main():
    net = Net()
    results = []
    try:
        results += scenario(net, "AWG 3.1", awgserver.generate_params(True), use_link=False)
        results += scenario(net, "AWG 3.1", awgserver.generate_params(True), use_link=True)
        results += scenario(net, "AWG 1.5/2", awgserver.generate_params(False), use_link=False)
        results += scenario(net, "Формат AmneziaVPN (10.8.1.0/24)", awgserver.generate_params(True),
                            use_link=True, amnezia_style=True)
    finally:
        net.close()
    for name, ok, detail in results:
        print(f"{'OK ' if ok else 'BAD'} {name}" + ("" if ok else f"  → {detail}"))
    print(f"\n{sum(1 for _, ok, _ in results if ok)}/{len(results)} проверок пройдено")
    sys.exit(0 if all(ok for _, ok, _ in results) else 1)


if __name__ == "__main__":
    main()
