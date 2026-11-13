"""Перенос сервера AmneziaWG из контейнера (раскладка AmneziaVPN) на хост — с теми же ключами, портом,
параметрами маскировки и клиентами, поэтому конфиги клиентов продолжают работать.

Запускает install.sh в контейнере панели (`docker compose run`: pid host, privileged, сеть хоста), а сам
контейнер останавливает и переименовывает установщик — между `check` и `install`:

    python3 -m app.movehost check DIR      # DIR — копия /opt/amnezia/awg контейнера (docker cp)
    python3 -m app.movehost install DIR    # файлы на хост, awg-quick@awg0 включён и поднят
    python3 -m app.movehost undo           # сервер на хосте не поднялся: выключить и убрать файлы

Хуки PostUp/PostDown из контейнера не переносятся (там NAT делает start.sh): на хосте — NAT панели
(`awgserver.safe_hooks`), как у сервера, созданного панелью.
"""
from __future__ import annotations

import glob
import os
import sys
import time

from . import awgconf, awgserver, config, system

IFACE = "awg0"
UP_WAIT = 15            # секунд ждать интерфейс после `systemctl enable --now`


class MoveError(Exception):
    pass


def read_source(src: str) -> tuple[awgserver.ServerConf, str]:
    """Конфиг сервера и clientsTable из копии папки контейнера (awg0.conf, иначе первый *.conf)."""
    confs = sorted(glob.glob(os.path.join(src, "*.conf")), key=lambda p: (not p.endswith("/awg0.conf"), p))
    if not confs:
        raise MoveError(f"no AmneziaWG config (*.conf) in the container's {config.AWG_DIR}")
    with open(confs[0]) as f:
        sc = awgserver.parse(f.read())
    if not awgconf.KEY_RE.match(sc.get("PrivateKey") or "") or not sc.network:
        raise MoveError(f"{os.path.basename(confs[0])} has no private key or address")
    port = sc.get("ListenPort") or ""
    if not (port.isdigit() and 1 <= int(port) <= 65535):
        raise MoveError(f"{os.path.basename(confs[0])} has no listen port")
    table = os.path.join(src, "clientsTable")
    raw = None
    if os.path.exists(table):
        with open(table) as f:
            raw = f.read()
    rows = awgserver.parse_clients_table(raw)
    return sc, awgserver.render_clients_table(rows)


def host_target() -> system.HostTarget:
    return system.HostTarget(IFACE)


def check(src: str) -> str:
    sc, _ = read_source(src)
    if host_target().exists:
        raise MoveError(f"{config.HOST_AWG_DIR}/{IFACE}.conf already exists on the host")
    return f"port={sc.get('ListenPort')} clients={len(sc.peers)}"


def install(src: str) -> str:
    """Файлы на хост и запуск. Контейнер к этому моменту уже остановлен (порт свободен)."""
    sc, table = read_source(src)
    t = host_target()
    if t.exists:
        raise MoveError(f"{config.HOST_AWG_DIR}/{IFACE}.conf already exists on the host")
    awgserver.safe_hooks(sc, True)           # NAT панели вместо iptables из start.sh контейнера
    system.install_host_runtime(t)
    t.write_file(t.conf_path, sc.render())
    t.write_file(t.clients_table_path, table, 0o644)
    t.exists = True
    t.native(["systemctl", "enable", "--now", f"awg-quick@{IFACE}"], timeout=60)
    for _ in range(UP_WAIT):
        if t.is_up():
            break
        time.sleep(1)
    else:
        raise MoveError(f"awg-quick@{IFACE} started, but the {IFACE} interface did not come up "
                        f"(journalctl -u awg-quick@{IFACE})")
    port = int(sc.get("ListenPort"))
    system.open_firewall_udp(t, port)
    return f"port={port} clients={len(sc.peers)}"


def undo() -> None:
    """Откат неудачного install: служба выключена, файлы отложены с суффиксом — сервер на хосте «не найден»,
    и контейнер снова главный."""
    t = host_target()
    t.native(["systemctl", "disable", "--now", f"awg-quick@{IFACE}"], check=False, timeout=60)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for p in (t.conf_path, t.clients_table_path):
        hp = t.host_path(p)
        if os.path.exists(hp):
            os.replace(hp, f"{hp}.failed-{stamp}")


def main(argv=None) -> int:
    a = list(sys.argv[1:] if argv is None else argv)
    try:
        if a[:1] == ["check"] and len(a) == 2:
            print(check(a[1]))
        elif a[:1] == ["install"] and len(a) == 2:
            print(install(a[1]))
        elif a == ["undo"]:
            undo()
        else:
            print("usage: python3 -m app.movehost check DIR | install DIR | undo", file=sys.stderr)
            return 2
    except (MoveError, system.SysError, OSError) as e:
        print(str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
