"""Тексты интерфейса на сервере: перевод сообщений панели (Msg) для бота Telegram.

Переводы живут в одном месте — app/static/i18n.js (их читает браузер). Бот брал оттуда только ключ и писал
человеку «srv.subnet_full» вместо фразы. Здесь словари читаются из того же файла (строки и формы
множественного числа), один раз и заново, когда файл поменялся.
"""
from __future__ import annotations

import json
import os
import re
import threading

from .i18n import Msg

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "i18n.js")
LANGS = ("ru", "en", "zh", "fa")
_STR = r'"((?:[^"\\]|\\.)*)"'
_STR_ANY = r'"(?:[^"\\]|\\.)*"'          # то же без группы — внутри объекта форм числа
_lock = threading.Lock()
_cache: tuple[float, dict] = (-1.0, {})


def _unq(s: str) -> str:
    try:
        return json.loads('"' + s + '"')
    except ValueError:
        return s


def _parse(js: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {lang: {} for lang in LANGS}
    blocks = []
    if "const I18N = {" in js:
        main = js[js.index("const I18N = {"):]
        main = main[:main.index("\n};")] if "\n};" in main else main
        parts = re.split(r"\n  (ru|en|zh|fa): \{", main)
        blocks += list(zip(parts[1::2], parts[2::2]))
    for m in re.finditer(r"Object\.assign\(I18N\.(\w+), \{(.*?)\n\}\);", js, re.S):
        blocks.append((m.group(1), m.group(2)))
    for lang, body in blocks:
        if lang not in out:
            continue
        d = out[lang]
        # строка: "ключ": "текст"; формы числа: "ключ": { one: "…", …, other: "…" } — берём other
        for k, v in re.findall(rf'"([a-z][\w.]*)":\s*{_STR}', body):
            d[k] = _unq(v)
        for k, obj in re.findall(rf'"([a-z][\w.]*)":\s*\{{((?:[^{{}}"]|{_STR_ANY})*)\}}', body):
            forms = dict(re.findall(rf'(\w+):\s*{_STR}', obj))
            v = forms.get("other") or forms.get("many") or forms.get("one")
            if v is not None:
                d[k] = _unq(v)
    return out


def dicts() -> dict[str, dict[str, str]]:
    global _cache
    try:
        mtime = os.stat(PATH).st_mtime
    except OSError:
        return _cache[1] or {lang: {} for lang in LANGS}
    with _lock:
        if mtime != _cache[0]:
            try:
                with open(PATH, encoding="utf-8") as f:
                    _cache = (mtime, _parse(f.read()))
            except OSError:
                pass
        return _cache[1]


def text(lang: str, msg) -> str:
    """Msg (или строка, или их список) → текст на языке lang; ключ без перевода — английский, потом сам ключ."""
    if isinstance(msg, (list, tuple)):
        return ", ".join(text(lang, x) for x in msg)
    if not isinstance(msg, Msg):
        return str(msg)
    d = dicts()
    s = d.get(lang, {}).get(msg.key) or d.get("en", {}).get(msg.key) or msg.key
    params = {k: text(lang, v) for k, v in msg.p.items()}
    return re.sub(r"\{(\w+)\}", lambda m: params.get(m.group(1), m.group(0)), s)
