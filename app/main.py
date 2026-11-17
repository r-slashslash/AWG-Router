"""Веб-панель AWG Router: запуск (python3 -m app.main). Общие части — app/panel.py, адреса API по темам — app/api."""
from __future__ import annotations

import logging
import os
import signal
import threading
import time

from . import api, config
from .api.backup import backup_loop
from .api.telegram import bot
from .panel import app, engine, panel_url, proxies, tls, updates, write_status

log = logging.getLogger("awgr")
assert api.ROUTES                      # импорт пакета api регистрирует все адреса в panel.app


def run():
    try:
        os.remove(os.path.join(config.DATA_DIR, "status.json"))
    except OSError:
        pass
    engine.start()
    if not config.DRY_RUN:
        updates.start(engine.stop_ev)
        threading.Thread(target=backup_loop, name="backup", daemon=True).start()
    bot.start()
    if tls.enabled:
        # адрес для сертификата: из настроек или определённый автоматически
        for _ in range(30):
            if tls.host():
                break
            time.sleep(1)
        tls.start()
    proxies.sync()
    srv = app.serve(config.PANEL_HOST, config.PANEL_PORT, tls=tls.context if tls.enabled else None)
    write_status()
    log.info("Panel: %s", panel_url())

    def stop(*_):
        log.info("Stopping")
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        srv.serve_forever(poll_interval=0.5)
    finally:
        tls.stop_ev.set()
        proxies.stop()
        engine.shutdown()
        log.info("Stopped")


if __name__ == "__main__":
    run()
