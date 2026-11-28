"""Гонка в open_conn (dnsproxy.py): отмена задачи в тот миг, когда рукопожатие TLS уже закончилось, но задача ещё не
проснулась. Тогда asyncio закрывает соединение «вежливо» (close_notify и ждать ответа до ssl_shutdown_timeout, 30 с), а
open_conn в `except BaseException` закрывает сам сокет. Номер дескриптора свободен, но в цикле остаётся транспорт,
который ещё не закрывается: следующий сокет с тем же номером не открывается («File descriptor N is used by transport»).
Код открытия — как в dnsproxy.py (open_conn). Печатает, сколько секунд новые сокеты не открываются.
Запуск: python3 -I fdrace.py <c.crt> <c.key>"""
import asyncio
import json
import socket
import ssl
import sys
import time
from asyncio import sslproto

CRT, KEY = sys.argv[1], sys.argv[2]


async def main():
    loop = asyncio.get_running_loop()
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(CRT, KEY)

    async def handler(r, w):
        try:
            while await r.read(65536):
                pass
        except Exception:  # noqa: BLE001
            pass
        w.close()
    srv = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=sctx)
    port = srv.sockets[0].getsockname()[1]
    cctx = ssl.create_default_context()
    cctx.check_hostname, cctx.verify_mode = False, ssl.CERT_NONE

    async def open_conn():                              # как open_conn в dnsproxy.py
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(s, ("127.0.0.1", port)), 5)
            r, w = await asyncio.wait_for(asyncio.open_connection(sock=s, ssl=cctx, server_hostname="x"), 5)
        except BaseException:
            s.close()
            raise
        return r, w

    # отмена ровно после конца рукопожатия: так её ставит as_completed/t.cancel() проверки или срок wait_for, если
    # ответ другого сервера (или срок) пришёлся на тот же оборот цикла
    target = {}
    orig = sslproto.SSLProtocol._on_handshake_complete

    def hooked(self, exc):
        orig(self, exc)
        t = target.pop("task", None)
        if t is not None:
            t.cancel()
    sslproto.SSLProtocol._on_handshake_complete = hooked
    task = asyncio.ensure_future(open_conn())
    target["task"] = task
    try:
        await task
        cancelled = False
    except asyncio.CancelledError:
        cancelled = True
    sslproto.SSLProtocol._on_handshake_complete = orig

    # теперь — новое соединение, как открывает его dnsproxy (TCP к DoH/DoT; UDP падает так же в sock_recv)
    t0 = time.monotonic()
    fails, first_ok, errors = 0, None, set()
    while time.monotonic() - t0 < 45:
        u = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        # как новое соединение DoH/DoT
        u.setblocking(False)
        try:
            await loop.sock_connect(u, ("127.0.0.1", port))
            first_ok = round(time.monotonic() - t0, 2)
            break
        except RuntimeError as e:
            fails += 1
            errors.add(str(e).split(" is used")[0])
        finally:
            u.close()
        await asyncio.sleep(0.5)
    print(json.dumps({"python": sys.version.split()[0], "cancelled_after_handshake": cancelled,
                      "new_sockets_failed": fails, "first_new_socket_ok_after_s": first_ok,
                      "errors": sorted(errors)}), flush=True)
    srv.close()


asyncio.run(main())
