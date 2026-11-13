"""Перенос сервера на хост по-настоящему (issue #25): файлы «контейнера» в формате AmneziaVPN →
`python3 -m app.movehost install` → служба awg-quick@awg0 на этой машине, и клиент со СТАРЫМ конфигом
подключается к серверу на хосте. Затем `undo` выключает службу и убирает файлы.

Только на одноразовой машине (машина GitHub Actions): пишет в /etc/amnezia/amneziawg, /usr/local/bin и
/etc/systemd/system, поднимает awg0 на хосте. Нужны root, systemd, awg, awg-quick, amneziawg-go в PATH.
Запуск: sudo env PATH=<bin>:$PATH python3 tests/movehost_e2e.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import awgconf, awgserver, config  # noqa: E402

NS = "awgm_cli"
PORT = 47123
HOST_IP, CLI_IP = "192.0.2.1", "192.0.2.2"


def sh(*cmd, check=True, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {p.stderr or p.stdout}")
    return p


def awg(*args, inp=None):
    return sh("awg", *args, input=inp).stdout.strip()


def movehost(*args):
    return sh(sys.executable, "-m", "app.movehost", *args, check=False, cwd=os.path.join(os.path.dirname(__file__), ".."))


def main():
    if os.path.exists(f"{config.HOST_AWG_DIR}/awg0.conf"):
        print(f"{config.HOST_AWG_DIR}/awg0.conf already exists: this test needs a clean machine")
        return 2
    results = []
    src = tempfile.mkdtemp()
    # сервер в формате AmneziaVPN (как в контейнере): адрес 10.8.1.0/24, свои хуки, один клиент
    srv_priv = awg("genkey")
    sc = awgserver.new_server(srv_priv, PORT, "10.8.1.0/24", awgserver.generate_params(True),
                              amnezia_style=True)
    sc.set("PostUp", "iptables -A INPUT -i awg0 -j ACCEPT")             # хук контейнера — не переносится
    cpriv = awg("genkey")
    cpub = awg("pubkey", inp=cpriv + "\n")
    sc.peers.append(awgserver.Peer(cpub, awg("genpsk"), f"{sc.next_ip()}/32"))
    with open(os.path.join(src, "awg0.conf"), "w") as f:
        f.write(sc.render())
    with open(os.path.join(src, "clientsTable"), "w") as f:
        json.dump([{"clientId": cpub, "userData": {"clientName": "Phone"}}], f)
    # конфиг клиента сделан ДО переноса: он и должен заработать с сервером на хосте
    prof = awgserver.ClientProfile(host=HOST_IP, port=PORT, server_pub=awg("pubkey", inp=srv_priv + "\n"),
                                   dns=["1.1.1.1"], mtu=1376, keepalive=awgserver.default_keepalive(sc.params()))
    up = awgconf.parse_upstream(awgserver.client_conf(sc, prof, sc.peer(cpub), cpriv))

    try:
        r = movehost("check", src)
        results.append(("check видит сервер", r.returncode == 0 and f"port={PORT}" in r.stdout, r.stdout + r.stderr))
        r = movehost("install", src)
        results.append(("install поднимает сервер на хосте", r.returncode == 0, r.stdout + r.stderr))
        active = sh("systemctl", "is-active", "awg-quick@awg0", check=False).stdout.strip()
        results.append(("служба awg-quick@awg0 работает", active == "active", active))
        port = sh("awg", "show", "awg0", "listen-port", check=False).stdout.strip()
        results.append(("тот же порт", port == str(PORT), port))
        peers = sh("awg", "show", "awg0", "peers", check=False).stdout.split()
        results.append(("тот же клиент", cpub in peers, peers))
        hooks = sh("iptables", "-S", "INPUT", check=False).stdout
        results.append(("хук контейнера не перенесён", "-i awg0 -j ACCEPT" not in hooks, ""))
        nat = sh("iptables", "-t", "nat", "-S", "POSTROUTING", check=False).stdout
        results.append(("NAT панели на хосте", "10.8.1.0/24" in nat, nat[-300:]))

        # клиент в своём пространстве имён, связь с хостом — через veth
        sh("ip", "netns", "add", NS)
        sh("ip", "link", "add", "m_h0", "type", "veth", "peer", "name", "m_c0")
        sh("ip", "link", "set", "m_c0", "netns", NS)
        sh("ip", "addr", "add", f"{HOST_IP}/24", "dev", "m_h0")
        sh("ip", "link", "set", "m_h0", "up")
        sh("ip", "netns", "exec", NS, "ip", "addr", "add", f"{CLI_IP}/24", "dev", "m_c0")
        sh("ip", "netns", "exec", NS, "ip", "link", "set", "m_c0", "up")
        sh("ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up")
        sh("ip", "netns", "exec", NS, "amneziawg-go", "awgc")
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write(up.setconf)
        sh("ip", "netns", "exec", NS, "awg", "setconf", "awgc", f.name)
        sh("ip", "netns", "exec", NS, "ip", "addr", "add", f"{up.address}/32", "dev", "awgc")
        sh("ip", "netns", "exec", NS, "ip", "link", "set", "awgc", "mtu", str(up.mtu or 1376), "up")
        sh("ip", "netns", "exec", NS, "ip", "route", "add", "10.8.1.0/24", "dev", "awgc")
        ok, out = False, ""
        for _ in range(10):
            p = sh("ip", "netns", "exec", NS, "ping", "-c1", "-W2", "10.8.1.0", check=False)
            out = p.stdout[-200:]
            if p.returncode == 0:
                ok = True
                break
            time.sleep(1)
        results.append(("старый конфиг клиента подключается к серверу на хосте", ok, out))

        r = movehost("undo")
        active = sh("systemctl", "is-active", "awg-quick@awg0", check=False).stdout.strip()
        left = os.listdir(config.HOST_AWG_DIR)
        results.append(("undo выключает службу и убирает конфиг",
                        r.returncode == 0 and active != "active" and "awg0.conf" not in left, (active, left)))
    finally:
        sh("ip", "netns", "del", NS, check=False)
        sh("ip", "link", "del", "m_h0", check=False)
        sh("systemctl", "disable", "--now", "awg-quick@awg0", check=False)
        shutil.rmtree(src, ignore_errors=True)

    bad = 0
    for name, good, detail in results:
        print(("OK   " if good else "FAIL ") + name + ("" if good else f"  {detail}"))
        bad += not good
    print(f"{len(results) - bad}/{len(results)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
