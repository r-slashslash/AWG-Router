"""Сообщения для интерфейса.

Бэкенд не хранит переводов: любое сообщение для человека — это ключ и параметры,
сериализуемые в JSON как {"$t": "ключ", "p": {...}}. Перевод на выбранный язык
делает браузер (каталог в static/i18n.js), там же — названия стран и склонения.
"""
from __future__ import annotations


class Msg:
    __slots__ = ("key", "p")

    def __init__(self, msg_key: str, /, **params):
        self.key = msg_key
        self.p = params

    def to_json(self) -> dict:
        return {"$t": self.key, "p": {k: to_json(v) for k, v in self.p.items()}}

    def __str__(self) -> str:  # для логов
        if not self.p:
            return self.key
        return self.key + " " + " ".join(f"{k}={v}" for k, v in self.p.items())

    __repr__ = __str__


def to_json(v):
    if isinstance(v, Msg):
        return v.to_json()
    if isinstance(v, (list, tuple)):
        return [to_json(x) for x in v]
    if isinstance(v, dict):
        return {k: to_json(x) for k, x in v.items()}
    return v


def msg_of(e: BaseException):
    """Сообщение из исключения: Msg, если оно было, иначе техническая строка."""
    m = getattr(e, "msg", None)
    if isinstance(m, Msg):
        return m
    return str(e)[:300]


class MsgError(Exception):
    def __init__(self, msg, *args):
        self.msg = msg if isinstance(msg, Msg) else Msg(msg, **(args[0] if args else {}))
        super().__init__(str(self.msg))
