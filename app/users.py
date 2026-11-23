"""Управление сервером AWG: клиенты (пользователи) и параметры туннеля.

Все изменения делаются под общей блокировкой движка: читаем конфиг цели,
меняем, записываем атомарно и применяем — `awg syncconf` для пиров, перезапуск
интерфейса для серверных параметров (порт, S1–S4, H1–H4, ключ защиты заголовков).
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import secrets
import shlex
import time

from . import awgserver, config, cps, hostnet, system
from .awgserver import ServerConf
from .i18n import Msg, MsgError

log = logging.getLogger("awgr.users")

DEFAULT_DNS = ["1.1.1.1", "1.0.0.1"]


def client_dns(s: dict) -> list[str]:
    """DNS для клиентов. В туннеле только IPv4, поэтому IPv6-адреса (сохранённые до 1.6.0)
    в конфиги не попадают: такой DNS у клиента не ответит."""
    dns = [d for d in s.get("client_dns") or [] if ":" not in d]
    return dns or DEFAULT_DNS


DNS_ENC = ("doh", "dot", "plain")


def dns_encrypt(s: dict) -> str:
    """Шифрование запросов DNS на сервере: doh (по умолчанию), dot или plain."""
    v = s.get("panel_dns_enc")
    return v if v in DNS_ENC else "doh"


def panel_dns_addr(sc: ServerConf) -> str | None:
    """Адрес сервера в туннеле (на нём слушает DNS панели): IPv4 из Address сервера."""
    for a in re.split(r"[,\s]+", sc.get("Address") or ""):
        try:
            ip = ipaddress.ip_interface(a)
        except ValueError:
            continue
        if ip.version == 4:
            return str(ip.ip)
    return None


def profile_dns(s: dict, sc: ServerConf, live: str | None = None) -> list[str]:
    """DNS в конфиге клиента. С DNS панели — сначала адрес сервера в туннеле, вторым — первый сервер
    из настроек: пока панель перезапускается или обновляется, клиент спросит его (тоже через туннель).
    live — адрес, на котором DNS панели уже слушает (с интерфейса); пока его нет — из Address сервера."""
    dns = client_dns(s)
    addr = (live or panel_dns_addr(sc)) if s.get("panel_dns") else None
    return [addr] + [d for d in dns if d != addr][:1] if addr else dns


DEFAULT_MTU = 1376
NAME_MAX = 60
PROTOS = ("awg", "wg")


def client_proto(st: dict, pk: str) -> str:
    """Протокол клиента: 'wg' (классический WireGuard) или 'awg' (AmneziaWG, по умолчанию)."""
    return "wg" if (st.get("clients") or {}).get(pk, {}).get("proto") == "wg" else "awg"


def iface_for(t: system.Target, proto: str) -> str:
    """Интерфейс сервера для протокола клиента."""
    return "wg0" if proto == "wg" else getattr(t, "iface", "awg0")


class UserError(MsgError):
    pass


TUNNEL_NAME = re.compile(r"[A-Za-z0-9_=+.-]{1,15}")


def conf_label(pk: str) -> str:
    """Название подключения у клиента — 8 цифр из его ключа (1.22.0, решение владельца): одно и то же при
    каждом скачивании, у разных клиентов разное, и без имени, которое клиенту дал владелец панели. Подходит
    приложениям AmneziaWG и WireGuard: имя туннеля у них — [A-Za-z0-9_=+.-]{1,15}."""
    num = int.from_bytes(hashlib.sha256(pk.encode()).digest()[:8], "big") % 10 ** 8
    return f"{num:08d}"


def conf_filename(pk: str) -> str:
    """Имя файла конфига = имя туннеля в приложениях AmneziaWG и WireGuard."""
    return conf_label(pk) + ".conf"


EXTRA_HOSTS_MAX = 16
_HOSTNAME = re.compile(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")


# ---- клиентские настройки сервера: одна проверка для формы «Сервер» (update_server) и для резервной копии
def check_flag(v) -> bool:
    """Галочка: только true/false ("no" строкой включила бы настройку)."""
    if not isinstance(v, bool):
        raise UserError(Msg("err.bad_value"))
    return v


def check_public_host(v) -> str:
    """Внешний адрес сервера (адрес панели, сертификата и клиентов): IPv4, IPv6 (можно в []) или домен; "" — нет."""
    h = str(v or "").strip()
    if h and not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]{1,253}", h):
        raise UserError(Msg("srv.bad_host"))
    return h.strip("[]")


def check_client_dns(value, old_v6: bool = False) -> list[str]:
    """DNS для клиентов: не больше четырёх IPv4 — строкой (через запятую или пробел) или списком. В туннеле только
    IPv4: IPv6 — ошибка, а в копиях до 1.6.0 (old_v6) такие адреса молча пропускаются."""
    if isinstance(value, list):
        items = [str(d).strip() for d in value]
    elif old_v6:                   # в копии DNS всегда списком
        raise UserError(Msg("err.bad_value"))
    else:
        items = re.split(r"[,\s]+", str(value or ""))
    out = []
    for d in filter(None, items):
        try:
            a = ipaddress.ip_address(d)
        except ValueError:
            raise UserError(Msg("srv.bad_dns", value=d)) from None
        if a.version != 4:
            if old_v6:
                continue
            raise UserError(Msg("srv.dns_v6", value=d))
        out.append(d)
    return out[:4]


def check_dns_enc(v) -> str:
    """Как DNS на сервере спрашивает дальше: doh | dot | plain."""
    if v not in DNS_ENC:
        raise UserError(Msg("srv.bad_dns_enc"))
    return v


def check_mtu(v) -> int:
    """MTU в конфигах клиентов: 1100 … 1500."""
    try:
        mtu = int(v)
    except (TypeError, ValueError, OverflowError):
        raise UserError(Msg("srv.bad_mtu")) from None
    if not 1100 <= mtu <= 1500:
        raise UserError(Msg("srv.bad_mtu"))
    return mtu


def check_keepalive(v) -> str:
    """PersistentKeepalive клиентов: секунды или диапазон «15-25» (панель выбирает число в нём); "" — сама."""
    ka = str(v if v is not None else "").strip()
    m = re.fullmatch(r"([0-9]{1,5})(?:-([0-9]{1,5}))?", ka) if ka else None
    # предел WireGuard — 65535 с; «35-25» (от большего к меньшему) — тоже ошибка, а не конфиг, который телефон не примет
    if ka and (not m or int(m.group(1)) > 65535 or (m.group(2) and not int(m.group(1)) <= int(m.group(2)) <= 65535)):
        raise UserError(Msg("srv.bad_keepalive"))
    return ka


def parse_extra_hosts(value) -> list[str]:
    """Дополнительные внешние адреса сервера (#37): IPv4, IPv6 или домен; строкой (через запятую, пробел,
    перевод строки) или списком строк. Не больше EXTRA_HOSTS_MAX, повторы убираются."""
    if isinstance(value, str):
        items = re.split(r"[,\s]+", value)
    elif isinstance(value, list) and all(isinstance(x, str) for x in value):
        items = value
    else:
        raise UserError(Msg("err.bad_value"))
    out = []
    for raw in items:
        h = raw.strip().strip("[]")
        if not h:
            continue
        try:
            h = str(ipaddress.ip_address(h.replace("%", " ")))     # без зоны IPv6: в ней ipaddress пропускает любой текст
        except ValueError:
            if not _HOSTNAME.fullmatch(h):
                raise UserError(Msg("srv.bad_extra_host", value=raw.strip()[:60])) from None
            h = h.lower()
        if h not in out:
            out.append(h)
    if len(out) > EXTRA_HOSTS_MAX:
        raise UserError(Msg("srv.extra_hosts_max", n=EXTRA_HOSTS_MAX))
    return out


class ServerManager:
    def __init__(self, engine):
        self.e = engine
        self._pub_cache: dict[str, str] = {}

    # --------------------------------------------------------------- чтение
    def _target(self) -> system.Target:
        t = self.e.target
        if not t or not t.exists:
            raise UserError(Msg("srv.no_server"))
        return t

    def load(self, t: system.Target, iface: str | None = None) -> tuple[ServerConf, list[dict]]:
        iface = iface or t.iface
        text = t.read_file(t.conf_path_for(iface))
        if text is None:
            raise UserError(Msg("srv.no_server"))
        return awgserver.parse(text), awgserver.parse_clients_table(t.read_file(t.clients_table_for(iface)))

    def server_pub(self, sc: ServerConf) -> str:
        priv = sc.get("PrivateKey")
        if priv not in self._pub_cache:
            self._pub_cache[priv] = system.pubkey(priv) if not config.DRY_RUN else \
                "DEMOserverPUBLICkey0000000000000000000000000="
        return self._pub_cache[priv]

    def public_host(self, st: dict) -> str:
        return st["settings"].get("public_host") or config.PUBLIC_HOST or ""

    def client_host(self, st: dict, pk: str | None = None) -> str:
        """Адрес сервера в конфигах клиентов: свой у клиента (pk), иначе выбранный IPv4/IPv6 или внешний адрес.
        Отдельно от public_host — тот же адрес у панели и её сертификата."""
        own = (st.get("chost") or {}).get(pk) if pk else None
        return own or st["settings"].get("client_host") or self.public_host(st)

    def host_choices(self, st: dict) -> list[str]:
        """Адреса, из которых клиенту выбирают свой (#37): основной, выбранный для всех и дополнительные с
        вкладки «Сервер». Меняется только адрес, к которому подключается клиент, — не адрес выхода в интернет."""
        s = st["settings"]
        out = []
        for h in (self.public_host(st), s.get("client_host"), *(s.get("extra_hosts") or [])):
            if h and h not in out:
                out.append(h)
        return out

    def host_addrs(self, port: int) -> dict:
        """Найденные адреса сервера для выбора на вкладке «Сервер»."""
        if config.DRY_RUN:
            return {"v4": self.e.public_v4 or "203.0.113.10", "v6": ["2001:db8:42::10"], "v6_listen": True}
        return {"v4": self.e.public_v4, "v6": hostnet.global_ipv6(),
                "v6_listen": hostnet.udp6_listening(port)}

    def _dns_live(self) -> str | None:
        """Адрес, на котором сейчас слушает DNS панели (None — не запущен)."""
        d = getattr(self.e, "dns_state", None) or {}
        return d.get("listen") if d.get("state") == "on" else None

    def _dns_live_for(self, sc: ServerConf, iface: str | None = None) -> str | None:
        """Адрес, на котором сейчас слушает DNS панели для указанного серверного конфига."""
        live = self._dns_live()
        if not live:
            return None
        target_iface = getattr(getattr(self.e, "target", None), "iface", None)
        if iface is not None and target_iface is not None and iface != target_iface:
            return panel_dns_addr(sc)
        if sc.network:
            try:
                if ipaddress.ip_address(live) not in sc.network.network:
                    return panel_dns_addr(sc)
            except ValueError:
                pass
        return live

    def profile(self, st: dict, sc: ServerConf, pk: str | None = None,
                iface: str | None = None) -> awgserver.ClientProfile:
        s = st["settings"]
        params = sc.params()
        return awgserver.ClientProfile(
            host=self.client_host(st, pk) or "SERVER_IP",
            port=sc.port,
            server_pub=self.server_pub(sc),
            dns=profile_dns(s, sc, self._dns_live_for(sc, iface)),
            mtu=int(s.get("client_mtu") or DEFAULT_MTU),
            keepalive=s.get("client_keepalive") or awgserver.default_keepalive(params),
        )

    def list_clients(self, t: system.Target) -> list[dict]:
        """Клиенты для движка и интерфейса: конфиги (awg0 + wg0) + clientsTable + живые данные."""
        ifaces = t.server_ifaces()
        keys = self.e.store.snapshot().get("keys", {})
        out = []
        primary = getattr(t, "iface", "awg0")
        for iface in ifaces:
            sc, rows = self.load(t) if iface == primary else self.load(t, iface)
            proto = "wg" if iface == "wg0" and t.iface != "wg0" else "awg"
            names = {r["clientId"]: r.get("userData") or {} for r in rows}
            try:
                live = t.dump_iface(iface)
            except Exception as e:  # noqa: BLE001
                log.warning("%s", e)
                live = {}
            for p in sc.peers:
                ud = names.get(p.public_key, {})
                out.append({
                    "public_key": p.public_key, "ip": p.ip, "enabled": p.enabled,
                    "proto": proto,
                    "name": ud.get("clientName") or "", "created": ud.get("creationDate") or "",
                    "live": live.get(p.public_key) if p.enabled else None,
                    "has_config": p.public_key in keys,
                })
        return out

    # ------------------------------------------------------------ применение
    def _write(self, t: system.Target, sc: ServerConf, rows: list[dict] | None = None,
               restart: bool = False, port: tuple[int, int] | None = None,
               iface: str | None = None) -> None:
        """port — (прежний, новый) при смене порта: контейнер для него пересоздаётся (Target.change_port)."""
        iface = iface or t.iface
        conf_path = t.conf_path_for(iface)
        table_path = t.clients_table_for(iface)
        old_conf = t.read_file(conf_path)
        old_rows = t.read_file(table_path) if rows is not None else None
        t.write_file(conf_path, sc.render())
        if rows is not None:
            t.write_file(table_path, awgserver.render_clients_table(rows), 0o644)
        if port:
            try:
                t.change_port(port[0], port[1], old_conf)
            except system.SysError:
                if t.kind != "container":           # контейнер сам вернул прежний конфиг вместе с собой
                    self._put_back(t, old_conf, None, iface)
                    t.restart()
                raise UserError(Msg("srv.port_failed", port=port[1])) from None
            self.e.trigger()
            return
        if restart:
            t.restart()
        else:
            try:
                if iface == t.iface:
                    t.sync(sc)
                else:
                    t.sync_iface(iface, sc)
            except Exception:
                # Интерфейс остался прежним — прежними возвращаем и файлы: иначе панель показывала бы клиента
                # отключённым (или удалённым), а его пир работал бы дальше до перезапуска сервера.
                self._put_back(t, old_conf, old_rows, iface)
                raise
            try:
                self.e.clients = self.list_clients(t)
            except Exception:  # noqa: BLE001
                pass
        self.e.trigger()

    @staticmethod
    def _put_back(t: system.Target, conf: str | None, rows: str | None, iface: str | None = None) -> None:
        iface = iface or t.iface
        try:
            if conf is not None:
                t.write_file(t.conf_path_for(iface), conf)
            if rows is not None:
                t.write_file(t.clients_table_for(iface), rows, 0o644)
        except OSError as e:
            log.warning("could not put the server config back: %s", e)

    # ---------------------------------------------------------------- клиенты
    def add_client(self, name: str, proto: str = "awg") -> str:
        name = (name or "").strip()[:NAME_MAX]
        if not name:
            raise UserError(Msg("err.name_required"))
        if proto not in PROTOS:
            raise UserError(Msg("err.bad_value"))
        with self.e.lock:
            t = self._target()
            if proto == "wg" and not t.wg_exists():
                raise UserError(Msg("srv.wg_disabled"))
            iface = iface_for(t, proto)
            sc, rows = self.load(t, iface)
            priv, pub = system.genkey() if not config.DRY_RUN else _demo_keypair()
            ip = sc.next_ip()
            sc.peers.append(awgserver.Peer(pub, t.psk_for_new_client(), f"{ip}/32"))
            rows.append({"clientId": pub, "userData": {
                "clientName": name, "creationDate": awgserver.amnezia_date()}})

            def keep(st):
                st.setdefault("keys", {})[pub] = priv
                # сообщить, когда клиент подключится впервые (limits.first_seen)
                st.setdefault("await_first", {})[pub] = time.time()
                # личная ссылка (и приглашение в бота по тому же ключу) — сразу у каждого нового клиента (1.22.0)
                st.setdefault("shares", {})[secrets.token_urlsafe(18)] = {"pk": pub, "created": time.time()}
                if proto == "wg":
                    st.setdefault("clients", {}).setdefault(pub, {})["proto"] = "wg"

            def undo(st):
                st.get("keys", {}).pop(pub, None)
                st.get("await_first", {}).pop(pub, None)
                st["shares"] = {k: v for k, v in st.get("shares", {}).items() if v.get("pk") != pub}
                if proto == "wg":
                    st.get("clients", {}).pop(pub, None)
            self.e.store.mutate(keep)
            try:
                self._write(t, sc, rows, iface=iface)
            except Exception:
                self.e.store.mutate(undo)
                raise
            self.e.event("info", Msg("ev.user_added", name=name, ip=ip))
            return pub

    def _find_peer(self, t: system.Target, pk: str, preferred_iface: str) -> tuple[str, ServerConf, list[dict], awgserver.Peer]:
        ifaces = [preferred_iface] + [i for i in (t.server_ifaces() if hasattr(t, "server_ifaces") else []) if i != preferred_iface]
        primary = getattr(t, "iface", "awg0")
        for iface in ifaces:
            sc, rows = self.load(t) if iface == primary else self.load(t, iface)
            p = sc.peer(pk)
            if p:
                return iface, sc, rows, p
        raise UserError(Msg("err.not_found"))

    def update_client(self, pk: str, name: str | None = None, enabled: bool | None = None,
                      proto: str | None = None) -> None:
        if proto is not None and proto not in PROTOS:
            raise UserError(Msg("err.bad_value"))
        with self.e.lock:
            t = self._target()
            st = self.e.store.snapshot()
            cur_proto = client_proto(st, pk)
            old_iface, sc, rows, p = self._find_peer(t, pk, iface_for(t, cur_proto))
            actual_proto = "wg" if old_iface == "wg0" and t.iface != "wg0" else "awg"
            if name is not None:
                name = name.strip()[:NAME_MAX]
                if not name:
                    raise UserError(Msg("err.name_required"))
                row = next((r for r in rows if r["clientId"] == pk), None)
                if row:
                    row.setdefault("userData", {})["clientName"] = name
                else:
                    rows.append({"clientId": pk, "userData": {
                        "clientName": name, "creationDate": awgserver.amnezia_date()}})
            switched = enabled is not None and p.enabled != bool(enabled)
            if switched:
                p.enabled = bool(enabled)

            def set_proto(s):
                c = dict((s.get("clients") or {}).get(pk) or {})
                if proto == "wg":
                    c["proto"] = "wg"
                    s.setdefault("clients", {})[pk] = c
                else:
                    c.pop("proto", None)
                    if c.get("outbound", "inherit") == "inherit" and c.get("rules_mode", "inherit") == "inherit" and not c.get("note"):
                        s.get("clients", {}).pop(pk, None)
                    else:
                        s.setdefault("clients", {})[pk] = c

            new_iface = iface_for(t, proto) if proto is not None else old_iface
            if proto is not None and new_iface != old_iface:
                if proto == "wg" and not t.wg_exists():
                    raise UserError(Msg("srv.wg_disabled"))
                old_new_conf = t.read_file(t.conf_path_for(new_iface))
                old_new_rows = t.read_file(t.clients_table_for(new_iface))
                old_old_conf = t.read_file(t.conf_path_for(old_iface))
                old_old_rows = t.read_file(t.clients_table_for(old_iface))
                old_new_sc = awgserver.parse(old_new_conf) if old_new_conf else None
                old_old_sc = awgserver.parse(old_old_conf) if old_old_conf else None
                new_sc, new_rows = self.load(t, new_iface)
                new_ip = new_sc.next_ip()
                new_sc.peers.append(awgserver.Peer(p.public_key, p.psk, f"{new_ip}/32", enabled=p.enabled))
                row = next((r for r in rows if r["clientId"] == pk), None)
                if row:
                    new_rows.append(row)
                sc.peers = [x for x in sc.peers if x.public_key != pk]
                rows = [r for r in rows if r["clientId"] != pk]

                self._write(t, new_sc, new_rows, iface=new_iface)
                try:
                    self._write(t, sc, rows, iface=old_iface)
                except Exception:
                    self._put_back(t, old_new_conf, old_new_rows, new_iface)
                    if old_new_sc is not None:
                        try:
                            t.sync_iface(new_iface, old_new_sc)
                        except Exception:  # noqa: BLE001
                            pass
                    raise
                try:
                    self.e.store.mutate(set_proto)
                except Exception:
                    self._put_back(t, old_new_conf, old_new_rows, new_iface)
                    self._put_back(t, old_old_conf, old_old_rows, old_iface)
                    for ifc, osc in ((new_iface, old_new_sc), (old_iface, old_old_sc)):
                        if osc is not None:
                            try:
                                t.sync_iface(ifc, osc)
                            except Exception:  # noqa: BLE001
                                pass
                    raise
                cname = self._name(new_rows, pk)
            else:
                if proto is not None and (proto != cur_proto or proto != actual_proto):
                    self.e.store.mutate(set_proto)
                self._write(t, sc, rows, iface=old_iface)
                cname = self._name(rows, pk)
            if switched:        # после записи: о несостоявшемся отключении журнал и Telegram не сообщают
                self.e.event("info", Msg("ev.user_enabled" if p.enabled else "ev.user_disabled", name=cname))

    def set_enabled_many(self, wanted: dict[str, bool]) -> set[str]:
        """Включить или выключить многих клиентов одной записью файлов сервера и одним awg syncconf (сроки и
        лимиты, enforce): по одному тысяча клиентов с общим сроком отключалась около 25 с, и всё это время
        добавить клиента было нельзя. → ключи, которые теперь в нужном состоянии (уже были — тоже)."""
        if not wanted:
            return set()
        with self.e.lock:
            t = self._target()
            ifaces = t.server_ifaces()
            done, switched = set(), []
            for iface in ifaces:
                sc, rows = self.load(t, iface)
                iface_switched = []
                for pk, on in wanted.items():
                    p = sc.peer(pk)
                    if not p:
                        continue
                    if p.enabled != bool(on):
                        p.enabled = bool(on)
                        iface_switched.append((p, rows))
                    done.add(pk)
                if iface_switched:
                    self._write(t, sc, rows, iface=iface)
                    switched.extend(iface_switched)
            for p, rows in switched:     # после записи: о несостоявшемся отключении журнал и Telegram не сообщают
                self.e.event("info", Msg("ev.user_enabled" if p.enabled else "ev.user_disabled",
                                         name=self._name(rows, p.public_key)))
            return done

    def delete_client(self, pk: str) -> None:
        with self.e.lock:
            t = self._target()
            st = self.e.store.snapshot()
            iface, sc, rows, _ = self._find_peer(t, pk, iface_for(t, client_proto(st, pk)))
            name = self._name(rows, pk)
            sc.peers = [p for p in sc.peers if p.public_key != pk]
            rows = [r for r in rows if r["clientId"] != pk]
            self._write(t, sc, rows, iface=iface)

            def forget(st):
                st.get("keys", {}).pop(pk, None)
                st["clients"].pop(pk, None)
                st.get("limits", {}).pop(pk, None)
                st.get("cps", {}).pop(pk, None)
                st.get("chost", {}).pop(pk, None)
                st.get("await_first", {}).pop(pk, None)
                st["shares"] = {k: v for k, v in st.get("shares", {}).items() if v.get("pk") != pk}
            self.e.store.mutate(forget)
            self.e.event("info", Msg("ev.user_deleted", name=name))

    def client_config(self, pk: str) -> dict:
        # Без блокировки движка: файлы сервера только читаются, а пишутся целиком (os.replace), поэтому
        # прочитать «половину» нельзя. С блокировкой выдача конфига — и личная страница клиента /s/ —
        # ждала бы конца прохода движка, а он с запуском туннелей длится секунды.
        t = self._target()
        st = self.e.store.snapshot()
        proto = client_proto(st, pk)
        iface, sc, rows, p = self._find_peer(t, pk, iface_for(t, proto))
        priv = st.get("keys", {}).get(pk)
        if not priv:
            raise UserError(Msg("usr.no_key"))
        prof = self.profile(st, sc, pk) if iface == getattr(t, "iface", "awg0") else self.profile(st, sc, pk, iface=iface)
        wg_only = proto == "wg"
        override = None if wg_only else cps.for_client(st.get("cps", {}).get(pk))      # свои I1–I5 клиента
        conf = awgserver.client_conf(sc, prof, p, priv, override, wg_only=wg_only)
        name = self._name(rows, pk) or p.ip
        # Название подключения — 8 цифр клиента (conf_label), и в имени файла, и в vpn:// для AmneziaVPN: ни
        # имени клиента, ни адреса сервера (его приложение и так показывает; issue #7). В .conf и QR названия
        # нет вовсе: приложения AmneziaWG берут его из имени файла или спрашивают. name — только для панели.
        return {"name": name, "conf": conf, "filename": conf_filename(pk),
                "proto": proto,
                "link": None if wg_only else awgserver.vpn_link(sc, prof, p, priv, conf, conf_label(pk), override),
                "warn_host": not self.client_host(st, pk)}

    @staticmethod
    def _name(rows: list[dict], pk: str) -> str:
        r = next((r for r in rows if r["clientId"] == pk), None)
        return ((r or {}).get("userData") or {}).get("clientName") or pk[:8]

    # -------------------------------------------------------------- сервер
    def server_view(self) -> dict:
        st = self.e.store.snapshot()
        t = self.e.target
        if not t:
            return {"exists": False}
        if not t.exists:
            return {"exists": False, "kind": t.kind, "can_init": t.kind == "host"}
        sc, _ = self.load(t)
        s = st["settings"]
        params = sc.params()
        net = sc.network
        wg_on = t.wg_exists()
        wg_port = config.WG_INIT_PORT or 51820
        wg_subnet = config.WG_INIT_SUBNET or "10.8.2.0/24"
        wg_locked = False
        if wg_on:
            try:
                wg_sc, _ = self.load(t, "wg0")
                wg_port = wg_sc.port
                if wg_sc.network:
                    wg_subnet = str(wg_sc.network.network)
                wg_locked = bool(wg_sc.peers)
            except Exception:  # noqa: BLE001
                pass
        return {
            "exists": True, "kind": t.kind, "iface": t.iface, "conf": t.conf_path,
            "wg": {"enabled": wg_on, "port": wg_port, "subnet": wg_subnet, "subnet_locked": wg_locked},
            # подсеть, а не адрес сервера с маской: на хосте в Address стоит 10.8.1.1/24 (сервер — первый адрес),
            # у AmneziaVPN — 10.8.1.0/24, и «10.8.1.1/24» в поле «Подсеть» выглядело ошибкой (#26)
            "port": sc.port, "address": str(net.network) if net else "",
            "subnet_locked": bool(sc.peers) or not self.subnet_follows_conf(t),
            "subnet_lock": "clients" if sc.peers else (None if self.subnet_follows_conf(t) else "container"),
            "params": {k: sc.get(k) for k in awgserver.PARAM_ORDER},
            "param_meta": {k: {"type": v[0], "side": v[1]} for k, v in awgserver.AWG_PARAMS.items()},
            "cps_presets": cps.catalog(),
            "cps_server": cps.match(params),
            "version": awgserver.protocol_version(params),
            "public_host": self.public_host(st),
            "client_host": s.get("client_host") or "",
            "extra_hosts": s.get("extra_hosts") or [],
            "addrs": self.host_addrs(sc.port),
            "client_dns": client_dns(s),
            "panel_dns": bool(s.get("panel_dns")),
            "dom_filter": bool(s.get("dom_filter")),
            "panel_dns_addr": self._dns_live() or panel_dns_addr(sc),
            "panel_dns_state": self.e.dns_view(),
            "panel_dns_enc": dns_encrypt(s),
            "client_mtu": int(s.get("client_mtu") or DEFAULT_MTU),
            "client_keepalive": s.get("client_keepalive") or "",
            "keepalive_auto": awgserver.default_keepalive(params),
            "server_pub": self.server_pub(sc),
        }

    @staticmethod
    def _same_subnet(value, sc: awgserver.ServerConf) -> bool:
        """В поле — подсеть (10.8.1.0/24); старое значение с адресом сервера (10.8.1.1/24) — та же подсеть."""
        try:
            return sc.network is not None and ipaddress.ip_interface(str(value)).network == sc.network.network
        except ValueError:
            return False

    @staticmethod
    def _server_address(i: ipaddress.IPv4Interface, sc: awgserver.ServerConf) -> str:
        """В поле — только подсеть: 10.66.0.5/24 значит подсеть 10.66.0.0/24. Адрес сервера в ней панель ставит
        сама в том же виде, что был: адрес сети (как у AmneziaVPN) или первый адрес (как создаёт панель)."""
        net = i.network
        old = sc.network
        if old is not None and old.ip == old.network.network_address:
            return str(net)                              # стиль AmneziaVPN: 10.66.0.0/24
        return f"{next(net.hosts())}/{net.prefixlen}"    # 10.66.0.1/24

    @staticmethod
    def subnet_follows_conf(t: system.Target) -> bool:
        """Можно ли менять подсеть: NAT контейнера должен брать её из Address конфига при
        запуске (наш start.sh). У контейнера AmneziaVPN подсеть вписана в start.sh при
        установке — после смены клиенты остались бы без интернета."""
        if t.kind != "container" or config.DRY_RUN:
            return True
        return "/^Address/" in (t.read_file("/opt/amnezia/start.sh") or "")

    def update_server(self, body: dict) -> dict:
        """Сохраняет настройки. Возвращает {restarted, server_side_changed, host_changed}."""
        with self.e.lock:
            t = self._target()
            sc, rows = self.load(t)
            old = sc.params()
            restart = False
            # клиентские настройки панели
            settings_patch = {}
            if "public_host" in body:
                h = check_public_host(body["public_host"])
                # пусто или то же, что PUBLIC_HOST в .env, — своей настройки нет: адрес берётся из .env
                settings_patch["public_host"] = None if not h or h.lower() == config.PUBLIC_HOST.lower() else h
            if "extra_hosts" in body:
                settings_patch["extra_hosts"] = parse_extra_hosts(body["extra_hosts"])
            if "client_host" in body:
                ch = str(body["client_host"] or "").strip().strip("[]")
                extra = settings_patch.get("extra_hosts", self.e.store.snapshot()["settings"].get("extra_hosts") or [])
                if ch and ch not in extra:               # домен — только из дополнительных адресов
                    try:
                        ch = str(ipaddress.ip_address(ch.replace("%", " ")))     # зона IPv6 — отказ, см. выше
                    except ValueError:
                        raise UserError(Msg("srv.bad_client_host")) from None
                settings_patch["client_host"] = ch
            if "client_dns" in body:
                settings_patch["client_dns"] = check_client_dns(body["client_dns"])
            for k in ("panel_dns", "dom_filter"):
                if k in body:
                    settings_patch[k] = check_flag(body[k])
            if "panel_dns_enc" in body:
                settings_patch["panel_dns_enc"] = check_dns_enc(body["panel_dns_enc"])
            if "client_mtu" in body:
                settings_patch["client_mtu"] = check_mtu(body["client_mtu"])
            if "client_keepalive" in body:
                settings_patch["client_keepalive"] = check_keepalive(body["client_keepalive"])
            # серверный конфиг
            if "params" in body:
                if body["params"] is not None and not isinstance(body["params"], dict):
                    raise UserError(Msg("err.bad_value"))      # строка или список — 400, а не 500
                new = awgserver.validate_params(body["params"] or {})
                merged = {**{k: sc.get(k) for k in awgserver.PARAM_ORDER}, **new}
                awgserver.validate_params({k: v for k, v in merged.items()})
                for k, v in new.items():
                    sc.set(k, v)
                if awgserver.server_side_changed(old, sc.params()):
                    restart = True
            raw = body.get("port") or sc.port
            # 1.5 и true int() молча делал портом 1: только целое число или строка из цифр
            if isinstance(raw, bool) or not (isinstance(raw, int) or (isinstance(raw, str) and raw.strip().isdigit())):
                raise UserError(Msg("srv.bad_port"))
            port = int(raw)
            new_port = None
            if port != sc.port:
                if not 1 <= port <= 65535:
                    raise UserError(Msg("srv.bad_port")) from None
                if port in system.AWG_RESERVED:
                    raise UserError(Msg("srv.port_dns", port=port))
                new_port = (sc.port, port)
                sc.set("ListenPort", str(port))
                restart = True
            drop_nat = None
            if body.get("address") and not self._same_subnet(body["address"], sc):
                if sc.peers:
                    raise UserError(Msg("srv.subnet_locked"))
                if not self.subnet_follows_conf(t):
                    raise UserError(Msg("srv.subnet_container"))
                try:
                    i = ipaddress.ip_interface(body["address"])
                except ValueError:
                    raise UserError(Msg("srv.bad_subnet")) from None
                if i.version != 4 or i.network.prefixlen > 29:
                    raise UserError(Msg("srv.bad_subnet")) from None
                old_net = str(sc.network.network) if sc.network else None
                sc.set("Address", self._server_address(i, sc))
                # NAT на хосте задан в PostUp для подсети: без замены клиенты новой подсети
                # остались бы без интернета
                if t.kind == "host" and old_net and old_net != str(i.network) and \
                        awgserver.retarget_nat(sc, old_net, str(i.network)):
                    drop_nat = old_net
                restart = True
            wg_plan = None
            if "wg" in body:
                wg_plan = self._plan_wg(t, sc, body.get("wg"))
            elif t.wg_exists() and t.iface != "wg0":
                wg_sc, _ = self.load(t, "wg0")
                if wg_sc.port == sc.port:
                    raise UserError(Msg("srv.wg_port_conflict"))
                if wg_sc.network is not None and sc.network is not None and wg_sc.network.network.overlaps(sc.network.network):
                    raise UserError(Msg("srv.wg_subnet_overlap"))
            if new_port and isinstance(t, system.HostTarget):
                system.open_firewall_udp(t, port)
            host_before = self.client_host(self.e.store.snapshot())
            dns_before = profile_dns(self.e.store.snapshot()["settings"], sc, self._dns_live())
            if settings_patch:
                def apply(st):
                    st["settings"].update(settings_patch)
                    # DNS на сервере включили без выбора шифрования («Применить для …» шлёт только panel_dns):
                    # записать то, с которым он работает (DoH по умолчанию), — без записи Store._upgrade при
                    # следующем запуске принял бы его за включённый до 1.16.0 и поставил «Без шифрования»
                    if st["settings"].get("panel_dns") and "panel_dns_enc" not in st["settings"]:
                        st["settings"]["panel_dns_enc"] = dns_encrypt(st["settings"])
                    if st["settings"].get("public_host") is None:
                        st["settings"].pop("public_host", None)
                    if not st["settings"].get("extra_hosts"):
                        st["settings"].pop("extra_hosts", None)
                    # адрес, которого больше нет среди выбора, у клиента снимается: он снова «как у всех»
                    keep = set(self.host_choices(st))
                    st["chost"] = {k: v for k, v in (st.get("chost") or {}).items() if v in keep}
                self.e.store.mutate(apply)
            host_changed = self.client_host(self.e.store.snapshot()) != host_before
            dns_changed = profile_dns(self.e.store.snapshot()["settings"], sc, self._dns_live()) != dns_before
            changed_conf = sc.render() != (t.read_file(t.conf_path) or "")
            if changed_conf:
                self._write(t, sc, None, restart=restart, port=new_port)
                if drop_nat:
                    t.native(["sh", "-c", awgserver.drop_nat_cmd(drop_nat)], check=False, timeout=30)
                self.e.event("info" if not restart else "warn",
                             Msg("ev.server_restarted" if restart else "ev.server_updated"))
                if restart and t.kind == "container" and not config.DRY_RUN and not isinstance(t, system.FakeTarget) and wg_plan is not None:
                    t = system.discover()
            wg_changed = self._apply_wg(t, wg_plan) if wg_plan is not None else False
            if wg_changed and not changed_conf:
                self.e.trigger()
            return {"restarted": restart and changed_conf,
                    "server_side_changed": awgserver.server_side_changed(old, sc.params()),
                    "host_changed": host_changed, "dns_changed": dns_changed,
                    "wg_changed": wg_changed}

    def _plan_wg(self, t: system.Target, awg_sc: ServerConf, wg: dict) -> dict:
        if not isinstance(wg, dict):
            raise UserError(Msg("err.bad_value"))
        was_on = t.wg_exists()
        want_on = check_flag(wg["enabled"]) if "enabled" in wg else was_on
        if not want_on:
            if not was_on:
                return {"action": "noop"}
            wg_sc, _ = self.load(t, "wg0")
            if wg_sc.peers:
                raise UserError(Msg("srv.wg_has_clients"))
            return {"action": "disable"}
        cur_port = config.WG_INIT_PORT or 51820
        cur_subnet = config.WG_INIT_SUBNET or "10.8.2.0/24"
        wg_sc = None
        if was_on:
            wg_sc, _ = self.load(t, "wg0")
            cur_port = wg_sc.port
            if wg_sc.network:
                cur_subnet = str(wg_sc.network.network)
        raw_p = wg.get("port")
        if raw_p is None or raw_p == "":
            wg_port = cur_port
        else:
            if isinstance(raw_p, bool) or not (isinstance(raw_p, int) or (isinstance(raw_p, str) and raw_p.strip().isdigit())):
                raise UserError(Msg("srv.bad_port"))
            wg_port = int(raw_p)
        if not 1 <= wg_port <= 65535:
            raise UserError(Msg("srv.bad_port"))
        if wg_port in system.AWG_RESERVED:
            raise UserError(Msg("srv.port_dns", port=wg_port))
        if wg_port == awg_sc.port:
            raise UserError(Msg("srv.wg_port_conflict"))
        raw_sub = wg.get("subnet") or cur_subnet
        try:
            wg_iface = ipaddress.ip_interface(str(raw_sub))
        except ValueError:
            raise UserError(Msg("srv.bad_subnet")) from None
        if wg_iface.version != 4 or wg_iface.network.prefixlen > 29:
            raise UserError(Msg("srv.bad_subnet"))
        wg_net = wg_iface.network
        if awg_sc.network is not None and wg_net.overlaps(awg_sc.network.network):
            raise UserError(Msg("srv.wg_subnet_overlap"))
        if not was_on:
            return {"action": "enable", "port": wg_port, "subnet": str(wg_net)}
        changed = False
        if str(wg_net) != cur_subnet:
            if wg_sc.peers:
                raise UserError(Msg("srv.subnet_locked"))
            wg_sc.set("Address", f"{next(wg_net.hosts())}/{wg_net.prefixlen}")
            changed = True
        if wg_port != cur_port:
            wg_sc.set("ListenPort", str(wg_port))
            changed = True
        if not changed:
            return {"action": "noop"}
        return {"action": "update", "sc": wg_sc, "port": wg_port if wg_port != cur_port else None}

    def _apply_wg(self, t: system.Target, plan: dict) -> bool:
        act = plan["action"]
        if act == "noop":
            return False
        if act == "disable":
            t.disable_wg()
            return True
        if act == "enable":
            t.enable_wg(plan["port"], plan["subnet"])
            return True
        wg_sc = plan["sc"]
        if plan["port"] and isinstance(t, system.HostTarget):
            system.open_firewall_udp(t, plan["port"])
        t.write_file(t.conf_path_for("wg0"), wg_sc.render())
        if not config.DRY_RUN and not isinstance(t, system.FakeTarget):
            if t.kind == "container":
                p = shlex.quote(t.conf_path_for("wg0"))
                t.native(["sh", "-c", f"awg-quick down {p} 2>/dev/null || true; awg-quick up {p}"], timeout=60)
            else:
                t.native(["sh", "-c", "systemctl restart awg-quick@wg0 2>/dev/null || (awg-quick down wg0 2>/dev/null || true; awg-quick up wg0)"], timeout=60)
        return True

    def _update_wg(self, t: system.Target, awg_sc: ServerConf, wg: dict) -> bool:
        return self._apply_wg(t, self._plan_wg(t, awg_sc, wg))

    def upgrade_masking(self, t: system.Target) -> None:
        """Один раз на сервер: старый I1 AmneziaVPN → новый DNS-ответ icloud.com."""
        with self.e.lock:
            sc, _ = self.load(t)
            if awgserver.upgrade_i1(sc):
                self._write(t, sc)
                self.e.event("info", Msg("ev.cps_upgraded"))

    def regenerate_params(self) -> dict[str, str]:
        """Новые параметры обфускации (не применяет — возвращает для формы)."""
        return awgserver.generate_params(True)

    def init_host(self, port: int, subnet: str) -> None:
        with self.e.lock:
            t = self.e.target
            if not isinstance(t, system.HostTarget):
                raise UserError(Msg("srv.init_only_host"))
            if not 1 <= port <= 65535:
                raise UserError(Msg("srv.bad_port")) from None
            if port in system.AWG_RESERVED:
                raise UserError(Msg("srv.port_dns", port=port))
            try:
                ipaddress.ip_network(str(subnet), strict=False)
            except ValueError:
                raise UserError(Msg("err.bad_value")) from None       # раньше — ошибка 500
            system.init_host_server(t, port, subnet, awgserver.generate_params(True))
            self.e.event("info", Msg("ev.server_created", port=port))
            self.e.trigger()


def _demo_keypair() -> tuple[str, str]:
    import base64
    import secrets
    return (base64.b64encode(secrets.token_bytes(32)).decode(),
            base64.b64encode(secrets.token_bytes(32)).decode())

