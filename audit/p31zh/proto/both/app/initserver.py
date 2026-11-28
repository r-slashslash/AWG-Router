"""Создание нового сервера AmneziaWG в формате AmneziaVPN (для контейнера amnezia-awg2).

    python3 -m app.initserver --out DIR --port 47823 [--subnet 10.8.1.0/24]

Пишет в DIR те же файлы, что создаёт приложение AmneziaVPN:
awg0.conf, wireguard_server_private_key.key, wireguard_server_public_key.key,
wireguard_psk.key, clientsTable. Существующий конфиг не перезаписывается.
"""
from __future__ import annotations

import argparse
import os
import sys

from . import awgserver, system


def write(path: str, text: str, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--subnet", default="10.8.1.0/24")
    a = ap.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    conf = os.path.join(a.out, "awg0.conf")
    if os.path.exists(conf):
        print(f"exists: {conf}", file=sys.stderr)
        return 0
    if not 1 <= a.port <= 65535:
        print("bad port", file=sys.stderr)
        return 2
    priv, pub = system.genkey()
    psk = system.local_awg(["genpsk"])
    sc = awgserver.new_server(priv, a.port, a.subnet, awgserver.generate_params(True), amnezia_style=True)
    write(os.path.join(a.out, "wireguard_server_private_key.key"), priv + "\n")
    write(os.path.join(a.out, "wireguard_server_public_key.key"), pub + "\n", 0o644)
    write(os.path.join(a.out, "wireguard_psk.key"), psk + "\n")
    write(os.path.join(a.out, "clientsTable"), "[]", 0o644)
    write(conf, sc.render())
    print(f"created {conf} port={a.port} subnet={a.subnet}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
