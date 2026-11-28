"""Отметки в копии dnsproxy.py для разбора (не для выпуска): почему не прошла проверка пути (CHECKFAIL) и какие ошибки
RuntimeError при открытии соединения к DoH/DoT (OPENFAIL — «File descriptor N is used by transport»), и когда open_conn закрыл
сокет живого транспорта (STUCK; check=True — отменила проверка пути). Работает и на
коде до П31 (там нет _check — только OPENFAIL). Запуск: python3 -I dbgpatch.py <путь к dnsproxy.py>"""
import sys

p = sys.argv[1]
s = open(p).read()
n = 0
old = """                except BaseException:
                    s.close()
                    raise
                c = Conn(r, w)"""
new = """                except BaseException as e:
                    if isinstance(e, RuntimeError):
                        print(f"OPENFAIL {time.time():.2f} mark={mark:#x} {str(e)[:60]}", flush=True)
                    _fd = s.fileno()
                    s.close()
                    _t = loop._transports.get(_fd)
                    if _t is not None and not _t.is_closing() and not isinstance(e, RuntimeError):
                        _cv = globals().get("_CHECKING")
                        print(f"STUCK {time.time():.2f} fd={_fd} mark={mark:#x} {type(e).__name__} "
                              f"check={bool(_cv and _cv.get())}", flush=True)
                    raise
                c = Conn(r, w)"""
if s.count(old) == 1:
    s, n = s.replace(old, new), n + 1
old = """        try:
            for fut in asyncio.as_completed(tasks, timeout=CHECK_TIMEOUT):
                try:
                    if await fut is not None:
                        return True
                except Exception:  # noqa: BLE001
                    pass
            return False
        except asyncio.TimeoutError:
            return False"""
new = """        _t0, _why = time.monotonic(), []
        try:
            for fut in asyncio.as_completed(tasks, timeout=CHECK_TIMEOUT):
                try:
                    if await fut is not None:
                        return True
                    _why.append(("none", round(time.monotonic() - _t0, 2)))
                except Exception as e:  # noqa: BLE001
                    _why.append((str(e)[:60], round(time.monotonic() - _t0, 2)))
            print(f"CHECKFAIL {time.time():.2f} mark={mark:#x} fb={bool(servers)} why={_why}", flush=True)
            return False
        except asyncio.TimeoutError:
            print(f"CHECKFAIL {time.time():.2f} mark={mark:#x} fb={bool(servers)} timeout why={_why}", flush=True)
            return False"""
if s.count(old) == 1:
    s, n = s.replace(old, new), n + 1
assert n >= 1, "nothing patched"
open(p, "w").write(s)
print(f"patched {n} place(s) in {p}")
