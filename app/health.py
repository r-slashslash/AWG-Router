"""Проверка живости для Docker HEALTHCHECK."""
import socket
import sys

from . import config

host = "127.0.0.1"
try:
    with socket.create_connection((host, config.PANEL_PORT), timeout=4):
        pass
except OSError as e:
    print(e)
    sys.exit(1)
