"""Адреса хоста без внешних запросов. Панель работает в сети хоста (network_mode: host),
поэтому /proc/net здесь показывает сетевые интерфейсы и сокеты самого сервера."""
import ipaddress

# флаги адреса в /proc/net/if_inet6: временный, ошибка DAD, устаревший, ещё проверяется
_SKIP_FLAGS = 0x01 | 0x08 | 0x20 | 0x40
# туннели, мосты Docker и виртуальные пары — не внешние адреса сервера
_SKIP_IFACES = ("lo", "docker", "br-", "veth", "awg", "wg", "tun", "tap")


def global_ipv6(path: str = "/proc/net/if_inet6", limit: int = 4) -> list[str]:
    """Публичные IPv6-адреса сервера (глобальные, постоянные; без ULA и служебных)."""
    out = []
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError:
        return out
    for line in lines:
        p = line.split()
        if len(p) < 6 or p[3] != "00":          # 00 — глобальная область
            continue
        try:
            flags = int(p[4], 16)
            ip = ipaddress.IPv6Address(int(p[0], 16))
        except ValueError:
            continue
        if flags & _SKIP_FLAGS or p[5].startswith(_SKIP_IFACES) or not ip.is_global:
            continue
        s = str(ip)
        if s not in out:
            out.append(s)
    return out[:limit]


def udp6_listening(port: int, path: str = "/proc/net/udp6") -> bool:
    """Есть ли на хосте UDP-сокет IPv6 на этом порту (AWG в режиме хоста или docker-proxy)."""
    try:
        with open(path) as f:
            lines = f.read().splitlines()[1:]
    except OSError:
        return False
    for line in lines:
        p = line.split()
        if len(p) < 2 or ":" not in p[1]:
            continue
        try:
            if int(p[1].rsplit(":", 1)[1], 16) == port:
                return True
        except ValueError:
            continue
    return False
