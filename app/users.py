"""Управление сервером AWG: клиенты (пользователи) и параметры туннеля.

Все изменения делаются под общей блокировкой движка: читаем конфиг цели,
меняем, записываем атомарно и применяем — `awg syncconf` для пиров, перезапуск
интерфейса для серверных параметров (порт, S1–S4, H1–H4, ключ защиты заголовков).
"""
from __future__ import annotations

import ipaddress
import logging
import re

from . import awgserver, config, cps, system
from .awgserver import ServerConf
from .i18n import Msg, MsgError

log = logging.getLogger("awgr.users")

DEFAULT_DNS = ["1.1.1.1", "1.0.0.1"]
DEFAULT_MTU = 1376
NAME_MAX = 60


class UserError(MsgError):
    pass


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

    def load(self, t: system.Target) -> tuple[ServerConf, list[dict]]:
        text = t.read_file(t.conf_path)
        if text is None:
            raise UserError(Msg("srv.no_server"))
        return awgserver.parse(text), awgserver.parse_clients_table(t.read_file(t.clients_table_path))

    def server_pub(self, sc: ServerConf) -> str:
        priv = sc.get("PrivateKey")
        if priv not in self._pub_cache:
            self._pub_cache[priv] = system.pubkey(priv) if not config.DRY_RUN else \
                "DEMOserverPUBLICkey0000000000000000000000000="
        return self._pub_cache[priv]

    def public_host(self, st: dict) -> str:
        return st["settings"].get("public_host") or config.PUBLIC_HOST or ""

    def profile(self, st: dict, sc: ServerConf) -> awgserver.ClientProfile:
        s = st["settings"]
        params = sc.params()
        return awgserver.ClientProfile(
            host=self.public_host(st) or "SERVER_IP",
            port=sc.port,
            server_pub=self.server_pub(sc),
            dns=s.get("client_dns") or DEFAULT_DNS,
            mtu=int(s.get("client_mtu") or DEFAULT_MTU),
            keepalive=s.get("client_keepalive") or awgserver.default_keepalive(params),
        )

    def list_clients(self, t: system.Target) -> list[dict]:
        """Клиенты для движка и интерфейса: конфиг + clientsTable + живые данные."""
        sc, rows = self.load(t)
        names = {r["clientId"]: r.get("userData") or {} for r in rows}
        try:
            live = t.dump()
        except Exception as e:  # noqa: BLE001
            log.warning("%s", e)
            live = {}
        keys = self.e.store.snapshot().get("keys", {})
        out = []
        for p in sc.peers:
            ud = names.get(p.public_key, {})
            out.append({
                "public_key": p.public_key, "ip": p.ip, "enabled": p.enabled,
                "name": ud.get("clientName") or "", "created": ud.get("creationDate") or "",
                "live": live.get(p.public_key) if p.enabled else None,
                "has_config": p.public_key in keys,
            })
        return out

    # ------------------------------------------------------------ применение
    def _write(self, t: system.Target, sc: ServerConf, rows: list[dict] | None = None,
               restart: bool = False) -> None:
        t.write_file(t.conf_path, sc.render())
        if rows is not None:
            t.write_file(t.clients_table_path, awgserver.render_clients_table(rows), 0o644)
        if restart:
            t.restart()
        else:
            t.sync(sc)
            try:
                self.e.clients = self.list_clients(t)
            except Exception:  # noqa: BLE001
                pass
        self.e.trigger()

    # ---------------------------------------------------------------- клиенты
    def add_client(self, name: str) -> str:
        name = (name or "").strip()[:NAME_MAX]
        if not name:
            raise UserError(Msg("err.name_required"))
        with self.e.lock:
            t = self._target()
            sc, rows = self.load(t)
            priv, pub = system.genkey() if not config.DRY_RUN else _demo_keypair()
            ip = sc.next_ip()
            sc.peers.append(awgserver.Peer(pub, t.psk_for_new_client(), f"{ip}/32"))
            rows.append({"clientId": pub, "userData": {
                "clientName": name, "creationDate": awgserver.amnezia_date()}})

            def keep(st):
                st.setdefault("keys", {})[pub] = priv
            self.e.store.mutate(keep)
            try:
                self._write(t, sc, rows)
            except Exception:
                self.e.store.mutate(lambda st: st.get("keys", {}).pop(pub, None))
                raise
            self.e.event("info", Msg("ev.user_added", name=name, ip=ip))
            return pub

    def update_client(self, pk: str, name: str | None = None, enabled: bool | None = None) -> None:
        with self.e.lock:
            t = self._target()
            sc, rows = self.load(t)
            p = sc.peer(pk)
            if not p:
                raise UserError(Msg("err.not_found"))
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
            if enabled is not None and p.enabled != bool(enabled):
                p.enabled = bool(enabled)
                self.e.event("info", Msg("ev.user_enabled" if p.enabled else "ev.user_disabled",
                                         name=self._name(rows, pk)))
            self._write(t, sc, rows)

    def delete_client(self, pk: str) -> None:
        with self.e.lock:
            t = self._target()
            sc, rows = self.load(t)
            if not sc.peer(pk):
                raise UserError(Msg("err.not_found"))
            name = self._name(rows, pk)
            sc.peers = [p for p in sc.peers if p.public_key != pk]
            rows = [r for r in rows if r["clientId"] != pk]
            self._write(t, sc, rows)

            def forget(st):
                st.get("keys", {}).pop(pk, None)
                st["clients"].pop(pk, None)
                st.get("limits", {}).pop(pk, None)
                st.get("cps", {}).pop(pk, None)
                st["shares"] = {k: v for k, v in st.get("shares", {}).items() if v.get("pk") != pk}
            self.e.store.mutate(forget)
            self.e.event("info", Msg("ev.user_deleted", name=name))

    def client_config(self, pk: str) -> dict:
        with self.e.lock:
            t = self._target()
            sc, rows = self.load(t)
        st = self.e.store.snapshot()
        p = sc.peer(pk)
        priv = st.get("keys", {}).get(pk)
        if not p:
            raise UserError(Msg("err.not_found"))
        if not priv:
            raise UserError(Msg("usr.no_key"))
        prof = self.profile(st, sc)
        override = cps.for_client(st.get("cps", {}).get(pk))      # свои I1–I5 клиента
        conf = awgserver.client_conf(sc, prof, p, priv, override)
        name = self._name(rows, pk) or p.ip
        safe = re.sub(r"[^\w.-]+", "_", name, flags=re.UNICODE).strip("_")[:40] or "awg"
        return {"name": name, "conf": conf, "filename": f"{safe}.conf",
                "link": awgserver.vpn_link(sc, prof, p, priv, conf, f"{name} · {prof.host}", override),
                "warn_host": not self.public_host(st)}

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
        return {
            "exists": True, "kind": t.kind, "iface": t.iface, "conf": t.conf_path,
            "port": sc.port, "address": str(net) if net else "",
            "subnet_locked": bool(sc.peers),
            "port_locked": t.kind != "host",
            "params": {k: sc.get(k) for k in awgserver.PARAM_ORDER},
            "param_meta": {k: {"type": v[0], "side": v[1]} for k, v in awgserver.AWG_PARAMS.items()},
            "cps_presets": cps.catalog(),
            "cps_server": cps.match(params),
            "version": awgserver.protocol_version(params),
            "public_host": self.public_host(st),
            "client_dns": s.get("client_dns") or DEFAULT_DNS,
            "client_mtu": int(s.get("client_mtu") or DEFAULT_MTU),
            "client_keepalive": s.get("client_keepalive") or "",
            "keepalive_auto": awgserver.default_keepalive(params),
            "server_pub": self.server_pub(sc),
        }

    def update_server(self, body: dict) -> dict:
        """Сохраняет настройки. Возвращает {restarted, server_side_changed}."""
        with self.e.lock:
            t = self._target()
            sc, rows = self.load(t)
            old = sc.params()
            restart = False
            # клиентские настройки панели
            settings_patch = {}
            if "public_host" in body:
                h = str(body["public_host"] or "").strip()
                if h and not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]{1,253}", h):
                    raise UserError(Msg("srv.bad_host"))
                settings_patch["public_host"] = h.strip("[]")
            if "client_dns" in body:
                dns = [d.strip() for d in re.split(r"[,\s]+", str(body["client_dns"] or "")) if d.strip()]
                for d in dns:
                    try:
                        ipaddress.ip_address(d)
                    except ValueError:
                        raise UserError(Msg("srv.bad_dns", value=d))
                settings_patch["client_dns"] = dns[:4]
            if "client_mtu" in body:
                try:
                    mtu = int(body["client_mtu"])
                except (TypeError, ValueError):
                    raise UserError(Msg("srv.bad_mtu"))
                if not 1100 <= mtu <= 1500:
                    raise UserError(Msg("srv.bad_mtu"))
                settings_patch["client_mtu"] = mtu
            if "client_keepalive" in body:
                ka = str(body["client_keepalive"] or "").strip()
                if ka and not re.fullmatch(r"\d{1,5}(-\d{1,5})?", ka):
                    raise UserError(Msg("srv.bad_keepalive"))
                settings_patch["client_keepalive"] = ka
            # серверный конфиг
            if "params" in body:
                new = awgserver.validate_params(body["params"] or {})
                merged = {**{k: sc.get(k) for k in awgserver.PARAM_ORDER}, **new}
                awgserver.validate_params({k: v for k, v in merged.items()})
                for k, v in new.items():
                    sc.set(k, v)
                if awgserver.server_side_changed(old, sc.params()):
                    restart = True
            try:
                port = int(body.get("port") or sc.port)
            except (TypeError, ValueError):
                raise UserError(Msg("srv.bad_port"))
            if port != sc.port:
                if t.kind != "host":
                    raise UserError(Msg("srv.port_container"))
                if not 1 <= port <= 65535:
                    raise UserError(Msg("srv.bad_port"))
                sc.set("ListenPort", str(port))
                restart = True
                if isinstance(t, system.HostTarget):
                    system.open_firewall_udp(t, port)
            if body.get("address") and body["address"] != str(sc.network or ""):
                if sc.peers:
                    raise UserError(Msg("srv.subnet_locked"))
                try:
                    i = ipaddress.ip_interface(body["address"])
                except ValueError:
                    raise UserError(Msg("srv.bad_subnet"))
                if i.version != 4 or i.network.prefixlen > 29:
                    raise UserError(Msg("srv.bad_subnet"))
                sc.set("Address", str(i))
                restart = True
            if settings_patch:
                self.e.store.mutate(lambda st: st["settings"].update(settings_patch))
            changed_conf = sc.render() != (t.read_file(t.conf_path) or "")
            if changed_conf:
                self._write(t, sc, None, restart=restart)
                self.e.event("info" if not restart else "warn",
                             Msg("ev.server_restarted" if restart else "ev.server_updated"))
            return {"restarted": restart and changed_conf,
                    "server_side_changed": awgserver.server_side_changed(old, sc.params())}

    def regenerate_params(self) -> dict[str, str]:
        """Новые параметры обфускации (не применяет — возвращает для формы)."""
        return awgserver.generate_params(True)

    def init_host(self, port: int, subnet: str) -> None:
        with self.e.lock:
            t = self.e.target
            if not isinstance(t, system.HostTarget):
                raise UserError(Msg("srv.init_only_host"))
            system.init_host_server(t, port, subnet, awgserver.generate_params(True))
            self.e.event("info", Msg("ev.server_created", port=port))
            self.e.trigger()


def _demo_keypair() -> tuple[str, str]:
    import base64
    import secrets
    return (base64.b64encode(secrets.token_bytes(32)).decode(),
            base64.b64encode(secrets.token_bytes(32)).decode())

