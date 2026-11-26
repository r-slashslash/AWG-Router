"""Removes the panel's routing (nftables table, ip rules, tunnels) from the AWG server, and the server addresses
the panel added itself (and its Docker networks for them).

Run while the panel is stopped:  docker compose run --rm awg-router python3 -m app.uninstall
The AmneziaWG server itself and its clients are left untouched. The panel's Let's Encrypt validation
file in nginx or Apache (webfront.py) is removed too.
"""
from __future__ import annotations

import sys

from . import system, webfront
from .engine import Engine
from .store import Store


def main() -> int:
    try:
        webfront.remove()        # свой файл проверки Let's Encrypt в nginx / Apache, если добавляли
    except Exception as e:  # noqa: BLE001
        print(f"Could not remove the Let's Encrypt validation file from the web server: {e}")
    eng = Engine(Store())
    try:
        gone = eng.remove_own_addrs()     # адреса, которые добавила панель (1.25.0), и её сети Docker
        if gone:
            print("Removed the panel's server addresses: " + ", ".join(gone))
    except Exception as e:  # noqa: BLE001
        print(f"Could not remove the panel's server addresses: {e}")
    try:
        eng.target = system.discover()
    except Exception as e:  # noqa: BLE001
        print(f"AWG server not found, nothing to clean ({e})")
        return 0
    if not eng.target.exists:
        print("AWG server not found, nothing to clean")
        return 0
    eng.teardown()
    print(f"Routing rules removed from {eng.target.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
