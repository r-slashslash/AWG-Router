"""Removes the panel's routing (nftables table, ip rules, tunnels) from the AWG server, and the server addresses
the panel added itself (and its Docker networks for them).

Run while the panel is stopped:  docker compose run --rm awg-router python3 -m app.uninstall
The AmneziaWG server itself and its clients are left untouched. The panel's Let's Encrypt validation
file in nginx or Apache (webfront.py) is removed too.
"""
from __future__ import annotations

import sys

from . import awgserver, system, webfront
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
    disabled_note(eng.target)
    return 0


def disabled_note(t) -> None:
    """Клиенты, которых выключила панель (срок, лимит, кнопка), выключены и после удаления панели: без неё их
    включают только правкой конфига сервера — приложение AmneziaVPN этот вид записи не знает (П67)."""
    try:
        off = [p for p in awgserver.parse(t.read_file(t.conf_path) or "").peers if not p.enabled]
    except Exception:  # noqa: BLE001
        return
    if off:
        print(f"{len(off)} client(s) turned off by the panel (expired, over the traffic limit or turned off by hand) "
              f"stay off. To turn one on without the panel: in {t.conf_path} on {t.name} remove the line "
              f"{awgserver.DISABLED_MARK} and the \"# \" at the start of that client's lines, then restart the AWG server")


if __name__ == "__main__":
    sys.exit(main())
