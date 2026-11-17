"""Управление HTTP и HTTPS приёмниками прокси-клиентов."""
from __future__ import annotations

import threading
import copy
import ipaddress
import json
import subprocess
import time

from . import config, nftgen, proxy_bridge, proxy_listener


class Manager:
    def __init__(self, store, engine, tls):
        self.store, self.engine, self.tls = store, engine, tls
        self.listeners = {}
        self.errors = {}
        self.lock = threading.RLock()
        self._address_cache = (0.0, ())

    def _server_addresses(self):
        """IPv4 хоста и определённый публичный адрес; при ошибке проверки соединение запрещено."""
        with self.lock:
            now = time.monotonic()
            until, addresses = self._address_cache
            if now >= until:
                try:
                    raw = subprocess.run(["ip", "-j", "-4", "address", "show"], capture_output=True,
                                         text=True, timeout=3, check=True)
                    links = json.loads(raw.stdout)
                    addresses = tuple(str(ipaddress.IPv4Address(a["local"])) for link in links
                                      for a in link.get("addr_info", []) if a.get("family") == "inet")
                    if not addresses:
                        raise ValueError("empty host addresses")
                except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
                    raise OSError("cannot verify server addresses") from exc
                self._address_cache = (now + 30, addresses)
            public = getattr(self.engine, "public_v4", None)
            if public:
                try:
                    addresses = (*addresses, str(ipaddress.IPv4Address(public)))
                except ipaddress.AddressValueError:
                    raise OSError("invalid public address") from None
            if not any(ipaddress.IPv4Address(ip).is_global for ip in addresses):
                raise OSError("public server address is unavailable")
            return tuple(set(addresses))

    def _credentials(self, uid):
        client = self.store.peek(lambda st: next((copy.deepcopy(c) for c in st.get("proxy_clients", [])
                                                  if c["id"] == uid and c["enabled"]), None))
        return {"username": client["username"], "password": client["password"],
                "upstream": client["upstream"]} if client else None

    def _account(self, uid, direction, count):
        up = self.store.peek(lambda st: next((dict(u) for u in st["upstreams"]
                                              if u["id"] == uid and u.get("enabled", True)), None))
        if not up:
            return False
        # Проверка и резервирование байтов под одной блокировкой: встречное направление
        # или другое соединение не обойдёт квоту до обновления счётчика.
        with self.engine.traffic.lock:
            if self.engine.over_quota(up):
                return False
            if count:
                self.engine.traffic.add_proxy(uid, direction, count)
            return True

    def _connect(self, uid, host, port):
        client, state = self.store.peek(lambda st: (
            next((dict(c) for c in st.get("proxy_clients", []) if c["id"] == uid and c["enabled"]), None),
            {"upstreams": [dict(u) for u in st["upstreams"]]}))
        if not client:
            raise OSError("client disabled")
        up = next((u for u in state["upstreams"] if u["id"] == client["upstream"] and u.get("enabled", True)), None)
        if not up:
            raise OSError("exit missing")
        if self.engine.over_quota(up):
            raise OSError("exit quota exceeded")
        with self.engine.lock:
            rt = self.engine.rt.get(up["id"])
            target = self.engine.target
            resolved = self.engine.resolve("up:" + up["id"], state)
            if not target or not target.exists or not rt or rt.target_key != target.key or resolved != up["num"]:
                raise OSError("exit unavailable")
            pid, iface, mark = target.pid, rt.iface, nftgen.mark_for(rt.num)
        return proxy_bridge.connect(pid, iface, mark, host, port, self._server_addresses())

    def sync(self):
        """Применить настройки; ошибка порта одного клиента не останавливает остальные."""
        with self.lock:
            state = self.store.snapshot()
            if config.DRY_RUN:
                return
            wanted = {c["id"]: c for c in state.get("proxy_clients", []) if c["enabled"]}
            for uid in list(self.listeners):
                server, port = self.listeners[uid]
                if (uid not in wanted or wanted[uid]["port"] != port
                        or wanted[uid].get("protocol", "https") != getattr(server, "proxy_protocol", "https")):
                    server.close_active()
                    server.shutdown()
                    server.server_close()
                    del self.listeners[uid]
            self.errors = {uid: err for uid, err in self.errors.items() if uid in wanted}
            for uid, client in wanted.items():
                if uid in self.listeners:
                    server, _ = self.listeners[uid]
                    signature = (client["username"], client["password"]["hash"], client["upstream"])
                    if server.proxy_signature != signature:
                        server.close_active()
                        server.proxy_signature = signature
                    continue
                try:
                    protocol = client.get("protocol", "https")
                    context = self.tls.context if protocol == "https" else None
                    server = proxy_listener.create(("0.0.0.0", client["port"]), context,
                                                   lambda u=uid: self._credentials(u),
                                                   lambda host, port, u=uid: self._connect(u, host, port),
                                                   self._account)
                except OSError as exc:
                    self.errors[uid] = str(exc)
                    continue
                self.listeners[uid] = (server, client["port"])
                server.proxy_protocol = protocol
                server.proxy_signature = (client["username"], client["password"]["hash"], client["upstream"])
                self.errors.pop(uid, None)
                threading.Thread(target=server.serve_forever, name="proxy-" + uid, daemon=True).start()

    def stop(self):
        with self.lock:
            for server, _ in self.listeners.values():
                server.close_active()
                server.shutdown()
                server.server_close()
            self.listeners.clear()
