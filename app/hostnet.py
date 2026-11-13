"""Адреса хоста без внешних запросов. Панель работает в сети хоста (network_mode: host),
поэтому /proc/net здесь показывает сетевые интерфейсы и сокеты самого сервера."""
import ipaddress

# флаги адреса в /proc/net/if_inet6: временный, ошибка DAD, устаревший, ещё проверяется
_SKIP_FLAGS = 0x01 | 0x08 | 0x20 | 0x40
# туннели, мосты Docker и виртуальные пары — не внешние адреса сервера
_SKIP_IFACES = ("lo", "docker", "br-", "veth", "awg", "wg", "tun", "tap")


def is_v6(host) -> bool:
    """Строка — адрес IPv6 (в скобках или без)."""
    try:
        return ipaddress.ip_address(str(host).strip("[]")).version == 6
    except ValueError:
        return False


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


def uptime(path: str = "/proc/uptime") -> int | None:
    """Сколько секунд работает сервер (pid: host — /proc общий с хостом)."""
    try:
        with open(path) as f:
            return int(float(f.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


def memory(path: str = "/proc/meminfo") -> tuple[int, int] | None:
    """Память сервера в байтах: (занято, всего). Занято — всего минус MemAvailable."""
    vals = {}
    try:
        with open(path) as f:
            for line in f:
                k, _, v = line.partition(":")
                if k in ("MemTotal", "MemAvailable"):
                    vals[k] = int(v.split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    if "MemTotal" not in vals or "MemAvailable" not in vals:
        return None
    return vals["MemTotal"] - vals["MemAvailable"], vals["MemTotal"]
