"""Адреса хоста без внешних запросов. Панель работает в сети хоста (network_mode: host),
поэтому /proc/net здесь показывает сетевые интерфейсы и сокеты самого сервера."""
import ipaddress
import os
import threading
import time

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


class CpuMeter:
    """Загрузка процессоров сервера в процентах между двумя чтениями /proc/stat (не делится по
    контейнерам — это весь хост). Чаще MIN_GAP не пересчитывает: опрос /api/state идёт с каждой вкладки."""
    MIN_GAP = 1.0

    def __init__(self, path: str = "/proc/stat"):
        self.path = path
        self._lock = threading.Lock()
        self._prev = self._read()
        self._at = time.monotonic()
        self._pct: float | None = None

    def _read(self) -> tuple[int, int] | None:
        """(всего, простой) в тиках по строке «cpu»: простой — idle + iowait."""
        try:
            with open(self.path) as f:
                v = [int(x) for x in f.readline().split()[1:]]
        except (OSError, ValueError):
            return None
        if len(v) < 5:
            return None
        return sum(v[:8]), v[3] + v[4]          # guest уже входит в user — дальше 8 полей не считаем

    def percent(self) -> float | None:
        with self._lock:
            now = time.monotonic()
            if now - self._at < self.MIN_GAP and self._pct is not None:
                return self._pct
            cur = self._read()
            if cur and self._prev and cur[0] > self._prev[0]:
                total, idle = cur[0] - self._prev[0], cur[1] - self._prev[1]
                self._pct = round(max(0.0, min(100.0, 100.0 * (total - idle) / total)), 1)
            if cur:
                self._prev, self._at = cur, now
            return self._pct


def loadavg(path: str = "/proc/loadavg") -> list[float] | None:
    try:
        with open(path) as f:
            return [float(x) for x in f.read().split()[:3]]
    except (OSError, ValueError):
        return None


cpu = CpuMeter()


def system_view() -> dict:
    """Шапка панели: процессор и память сервера. Маленький словарь — уходит в каждый /api/state."""
    mem = memory()
    return {"cpu": cpu.percent(), "cores": os.cpu_count(), "load": loadavg(),
            "mem": list(mem) if mem else None}
