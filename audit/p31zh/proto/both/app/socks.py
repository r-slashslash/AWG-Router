"""Выходы через прокси SOCKS5.

Трафик клиентов в SOCKS5 переводит hev-socks5-tunnel (MIT, github.com/heiher/hev-socks5-tunnel):
он создаёт в сети сервера AWG интерфейс awgrN (TUN) и всё, что в него попадает, отправляет
через прокси — TCP командой CONNECT, UDP через UDP ASSOCIATE. Дальше всё как у выходов AWG:
метка fwmark → своя таблица маршрутизации → default dev awgrN. Собственные соединения
hev-socks5-tunnel к прокси без метки и идут напрямую, поэтому в петлю не попадают.

Здоровье выхода: раз в минуту панель подключается к прокси сама, проходит вход по логину,
просит соединение с 1.1.1.1:443 (или 8.8.8.8:443) и посылает туда начало TLS-рукопожатия.
Выход работает, только если из-за прокси пришёл ответ. Ответа «соединение открыто» мало: прокси на
этом же сервере (Xray и подобные) отвечает так до того, как дозвонился дальше, и всегда успешно,
даже когда за ним ничего нет.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import sys
import time

from .awgconf import ConfigError, resolve_host
from .i18n import Msg

HEV = "hev-socks5-tunnel"
CHECK_TARGETS = (("1.1.1.1", 443), ("8.8.8.8", 443))
CHECK_EVERY = 60
CHECK_FRESH = 200           # результат проверки старше — выход считается неработающим

REPLY = {1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable",
         4: "host unreachable", 5: "connection refused", 6: "TTL expired",
         7: "command not supported", 8: "address type not supported"}


def resolve(host: str, timeout: float | None = None) -> str:
    """Адрес прокси для hev-socks5-tunnel (имя он не разрешает): IPv4, если есть, иначе IPv6. С пределом
    времени (awgconf.resolve_host): разбор идёт в проходе движка под его блокировкой, и молчащий DNS
    держал бы десятки секунд и проход, и выдачу конфигов, и личные страницы клиентов."""
    try:
        return resolve_host(host, timeout)
    except ConfigError:
        raise SocksError(Msg("socks.resolve", host=host)) from None


def _yq(s: str) -> str:
    """Строка для YAML в одинарных кавычках."""
    return "'" + str(s).replace("'", "''") + "'"


def hev_config(iface: str, num: int, server_ip: str, s: dict, mark: int = 0) -> str:
    """Настройки hev-socks5-tunnel. mark (1.25.0) — метка его сокетов к прокси: с какого исходящего адреса сервера."""
    lines = [
        "tunnel:",
        f"  name: {_yq(iface)}",
        "  mtu: 8500",
        f"  ipv4: {_yq(f'169.254.200.{num}')}",
        "socks5:",
        f"  address: {_yq(server_ip)}",
        f"  port: {int(s['port'])}",
        "  udp: 'udp'",
    ]
    if s.get("user"):
        lines += [f"  username: {_yq(s['user'])}", f"  password: {_yq(s.get('password', ''))}"]
    if mark:
        lines.append(f"  mark: {int(mark)}")
    # log-file — явно: новые версии hev (2.10+) по умолчанию не пишут никуда, а причину отказа панель читает из его вывода
    lines += ["misc:", "  log-file: stderr", "  log-level: warn", "  connect-timeout: 10000", "  limit-nofile: 65535"]
    return "\n".join(lines) + "\n"


class SocksError(Exception):
    def __init__(self, msg: Msg):
        super().__init__(str(msg))
        self.msg = msg


def _recv(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise SocksError(Msg("socks.closed"))
        buf += chunk
    return buf


def _connect(host: str, port: int, timeout: float, mark: int = 0) -> socket.socket:
    """Соединение с прокси; mark — метка сокета (SO_MARK): тот же путь, что у hev с этого исходящего адреса."""
    if not mark:
        return socket.create_connection((host, port), timeout=timeout)
    last = None
    for fam, typ, proto, _, addr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        s = socket.socket(fam, typ, proto)
        try:
            s.setsockopt(socket.SOL_SOCKET, 36, int(mark))        # SO_MARK
            s.settimeout(timeout)
            s.connect(addr)
            return s
        except OSError as e:
            last = e
            s.close()
    raise last or OSError("connect failed")


def client_hello() -> bytes:
    """Начало TLS 1.2 (ClientHello без имени сервера): любой сервер на 443 отвечает на него
    рукопожатием или TLS-ошибкой, то есть байтами, которых от закрытого пути не бывает."""
    ciphers = bytes.fromhex("c02bc02fc02cc030cca9cca8009c009d002f0035")
    exts = (struct.pack("!HH", 0x000A, 8) + struct.pack("!H", 6) + bytes.fromhex("001d00170018")
            + struct.pack("!HH", 0x000D, 8) + struct.pack("!H", 6) + bytes.fromhex("040308040401"))
    body = (b"\x03\x03" + os.urandom(32) + b"\x00" + struct.pack("!H", len(ciphers)) + ciphers
            + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def connect_check(host: str, port: int, user: str = "", password: str = "",
                  target: tuple[str, int] = CHECK_TARGETS[0], timeout: float = 8,
                  data: bool = False, mark: int = 0) -> float:
    """Вход на прокси и CONNECT к target. Возвращает время в мс или бросает SocksError.
    data — после CONNECT послать начало TLS и дождаться ответа цели (`socks.no_data`, если из-за
    прокси ничего не пришло): так видно, что за прокси что-то есть. Время тогда — до первого ответа."""
    t0 = time.monotonic()
    try:
        s = _connect(host, port, timeout, mark)
    except OSError as e:
        raise SocksError(Msg("socks.unreachable", error=str(e)[:120])) from None
    try:
        s.settimeout(timeout)
        methods = b"\x00\x02" if user else b"\x00"
        s.sendall(b"\x05" + bytes([len(methods)]) + methods)
        ver, method = _recv(s, 2)
        if ver != 5:
            raise SocksError(Msg("socks.not_socks5"))
        if method == 0xFF:
            raise SocksError(Msg("socks.auth_required" if not user else "socks.auth_failed"))
        if method == 0x02:
            u, p = user.encode(), password.encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            if _recv(s, 2)[1] != 0:
                raise SocksError(Msg("socks.auth_failed"))
        elif method != 0x00:
            raise SocksError(Msg("socks.not_socks5"))
        ip, tport = target
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack("!H", tport))
        head = _recv(s, 4)
        if head[1] != 0:
            raise SocksError(Msg("socks.connect_failed", code=head[1], reason=REPLY.get(head[1], "?")))
        atyp = head[3]
        _recv(s, {1: 4, 4: 16}.get(atyp) or _recv(s, 1)[0])
        _recv(s, 2)
        if data:
            try:
                s.sendall(client_hello())
                if not s.recv(1):
                    raise SocksError(Msg("socks.no_data"))      # закрыли, ничего не ответив
            except (socket.timeout, OSError):
                raise SocksError(Msg("socks.no_data")) from None
        return round((time.monotonic() - t0) * 1000)
    except socket.timeout:
        raise SocksError(Msg("socks.timeout")) from None
    except SocksError:
        raise
    except OSError as e:
        raise SocksError(Msg("socks.unreachable", error=str(e)[:120])) from None
    finally:
        s.close()


def check(conf: dict) -> dict:
    """Проверка выхода: {"ok", "ms", "error", "at"}. Успех — если хоть одна цель ответила из-за
    прокси (не просто открыла соединение, см. `connect_check(data=True)`)."""
    err = None
    for target in CHECK_TARGETS:
        try:
            ms = connect_check(conf["host"], conf["port"], conf.get("user", ""),
                               conf.get("password", ""), target, data=True, mark=int(conf.get("mark") or 0))
            return {"ok": True, "ms": ms, "error": None, "at": time.time()}
        except SocksError as e:
            err = e.msg
            if e.msg.key in ("socks.unreachable", "socks.not_socks5", "socks.auth_failed",
                             "socks.auth_required", "socks.timeout"):
                break                       # до второй цели дело не дойдёт: прокси сам не пускает
    return {"ok": False, "ms": None, "error": err, "at": time.time()}


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check_in(t, conf: dict, ip: str, timeout: int = 30) -> dict:
    """check() из сети сервера AWG — оттуда, откуда к прокси ходит hev-socks5-tunnel (1.22.0). Из сети панели
    проверка ошибалась: прокси на 127.0.0.1 самого VPS «работал», хотя из контейнера сервера его не видно, и
    наоборот. Имя прокси разобрано заранее (ip): в чужой сети может не быть DNS. Пароль — через stdin, не в
    командной строке (её видят все процессы)."""
    code = f"import sys;sys.path.insert(0,{ROOT!r});from app import socks;socks.main()"
    try:
        p = t.ns([sys.executable, "-c", code], input=json.dumps({**conf, "host": ip}), timeout=timeout,
                 check=False)
        d = json.loads(p.stdout or "{}")
    except Exception as e:  # noqa: BLE001  — нет сети сервера, процесс не ответил: выход не работает
        return {"ok": False, "ms": None, "error": Msg("socks.unreachable", error=str(e)[:120]), "at": time.time()}
    err = d.get("error")
    if isinstance(err, dict) and err.get("$t"):
        err = Msg(err["$t"], **(err.get("p") or {}))
    elif not d.get("ok"):
        err = err or Msg("socks.unreachable", error=(p.stderr or "no answer").strip()[:120])
    return {"ok": bool(d.get("ok")), "ms": d.get("ms"), "error": None if d.get("ok") else err, "at": time.time()}


def main() -> None:
    """Запуск в сети сервера (check_in): настройки прокси — JSON на stdin, ответ — JSON на stdout."""
    r = check(json.loads(sys.stdin.read() or "{}"))
    e = r.get("error")
    print(json.dumps({**r, "error": e.to_json() if isinstance(e, Msg) else e}))
