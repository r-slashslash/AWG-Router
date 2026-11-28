"""Е: Д10 на настоящем коде dnsproxy.py (Proxy._enc → open_conn, Pool.run): отмена в каждой точке открытия соединения
DoT/DoH — во время connect, во время рукопожатия TLS, сразу после рукопожатия, во время начала HTTP/2 (preface) и во
время запроса. После каждой — 20 новых сокетов (как открывает их dnsproxy) и число дескрипторов процесса через 35 с
(транспорт «вежливо» закрывается до 30 с). Запуск: python3 -I e_fd.py <папка app> <c.crt> <c.key>"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import ssl
import sys
import time
from asyncio import sslproto

APP, CRT, KEY = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, os.path.dirname(APP))
from app import dnsproxy  # noqa: E402


def nfds() -> int:
    return len(os.listdir("/proc/self/fd"))


def proxy(port: int) -> dnsproxy.Proxy:
    p = dnsproxy.Proxy.__new__(dnsproxy.Proxy)
    p.cfg = {"upstream_port": port, "encrypt": "doh"}
    p.up_port, p.pools, p.stats = port, {}, {}
    for name in ("ctx", "ctx_doh"):
        c = ssl.create_default_context()
        c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
        if name == "ctx_doh":
            c.set_alpn_protocols(["h2", "http/1.1"])
        setattr(p, name, c)
    return p


async def probe_new_sockets(port: int) -> dict:
    loop = asyncio.get_running_loop()
    fails, errs = 0, set()
    for _ in range(20):
        u = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        u.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(u, ("127.0.0.1", port)), 2)
        except RuntimeError as e:
            fails += 1
            errs.add(str(e)[:60])
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            u.close()
    return {"new_sockets_failed": fails, "errors": sorted(errs)}


async def main():
    loop = asyncio.get_running_loop()
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(CRT, KEY)
    sctx.set_alpn_protocols(["h2"])

    async def silent(r, w):              # принимает, читает и молчит
        try:
            while await r.read(65536):
                pass
        except Exception:  # noqa: BLE001
            pass
        w.close()
    tls = await asyncio.start_server(silent, "127.0.0.1", 0, ssl=sctx)
    tls_port = tls.sockets[0].getsockname()[1]
    # TCP без TLS: рукопожатие TLS не кончится никогда
    raw = await asyncio.start_server(silent, "127.0.0.1", 0)
    raw_port = raw.sockets[0].getsockname()[1]
    out = {"python": sys.version.split()[0], "app": APP}
    base = nfds()
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01"

    async def case(name: str, port: int, mode: str, hook=None, delay=None):
        p = proxy(port)
        undo = hook(lambda: target.get("t")) if hook else None
        target = {}
        t = asyncio.ensure_future(p._enc(q, "127.0.0.1", 0, mode))
        target["t"] = t
        if delay is not None:
            await asyncio.sleep(delay)
            t.cancel()
        try:
            await t
            res = "finished"
        except asyncio.CancelledError:
            res = "cancelled"
        except Exception as e:  # noqa: BLE001
            res = type(e).__name__
        if undo:
            undo()
        for pl in p.pools.values():
            pl.close()
        r = {"result": res, **(await probe_new_sockets(tls_port))}
        await asyncio.sleep(35)
        r["fds_after_35s_minus_base"] = nfds() - base
        out[name] = r
        print(name, r, flush=True)

    def after_handshake(get):
        orig = sslproto.SSLProtocol._on_handshake_complete

        def hooked(self, exc):
            orig(self, exc)
            t = get()
            if t is not None and not t.done():
                t.cancel()
        sslproto.SSLProtocol._on_handshake_complete = hooked
        return lambda: setattr(sslproto.SSLProtocol, "_on_handshake_complete", orig)

    def in_preface(get):
        orig = asyncio.StreamWriter.drain

        async def hooked(self):
            t = get()
            if t is not None and not t.done():
                t.cancel()
            return await orig(self)
        asyncio.StreamWriter.drain = hooked
        return lambda: setattr(asyncio.StreamWriter, "drain", orig)

    await case("cancel_in_tls_handshake", raw_port, "dot", delay=0.2)
    await case("cancel_right_after_handshake_dot", tls_port, "dot", hook=after_handshake)
    await case("cancel_right_after_handshake_doh", tls_port, "doh", hook=after_handshake)
    await case("cancel_in_h2_preface_drain", tls_port, "doh", hook=in_preface)
    await case("cancel_in_query", tls_port, "dot", delay=0.5)
    # connect к адресу, который не отвечает (SYN теряется): отмена во время connect
    await case("cancel_in_connect", 9, "dot", delay=0.2)
    print("RESULT " + json.dumps(out), flush=True)


asyncio.run(main())
