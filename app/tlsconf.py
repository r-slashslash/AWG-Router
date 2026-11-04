"""Настройки HTTPS панели: data/tls.json.

Они свои у каждого сервера (домен смотрит на этот сервер, пути к сертификату — на его диске),
поэтому в резервную копию не входят и восстановлением не переносятся.

    {"domain": "panel.example.com",     # пусто — адрес сервера (PUBLIC_HOST)
     "source": "letsencrypt",           # или "custom" — готовый сертификат с диска хоста
     "cert": "/etc/letsencrypt/live/panel.example.com/fullchain.pem",
     "key":  "/etc/letsencrypt/live/panel.example.com/privkey.pem",
     "web":  {...}}                      # проверка Let's Encrypt через веб-сервер (webfront.py)

Ключа "domain" нет — действует TLS_DOMAIN из .env: так домен задавали до 1.14.0.
"""
from __future__ import annotations

import json
import os
import threading

from . import config

SOURCES = ("letsencrypt", "custom")
_lock = threading.Lock()


def path() -> str:
    return os.path.join(config.DATA_DIR, "tls.json")


def load() -> dict:
    try:
        with open(path()) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def update(**kw) -> dict:
    """Меняет поля (None — удалить поле) и сохраняет атомарно. Возвращает новые настройки."""
    with _lock:
        d = load()
        for k, v in kw.items():
            if v is None:
                d.pop(k, None)
            else:
                d[k] = v
        p = path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p + ".tmp", "w") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
        os.replace(p + ".tmp", p)
        return d


def domain(d: dict | None = None) -> str:
    d = load() if d is None else d
    return str(d["domain"]) if "domain" in d else config.TLS_DOMAIN


def source(d: dict | None = None) -> str:
    d = load() if d is None else d
    return d.get("source") if d.get("source") in SOURCES else "letsencrypt"
