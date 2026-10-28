"""Removes the panel's routing (nftables table, ip rules, tunnels) from the AWG server.

Run while the panel is stopped:  docker compose run --rm awg-router python3 -m app.uninstall
The AmneziaWG server itself and its clients are left untouched.
"""
from __future__ import annotations

import sys

from . import system
from .engine import Engine
from .store import Store


def main() -> int:
    eng = Engine(Store())
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
