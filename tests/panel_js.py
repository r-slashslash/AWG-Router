"""Код интерфейса панели для тестов, которые его читают: части app/static/js в порядке загрузки из index.html.

Читайте его отсюда, а не по имени одного файла: функция, переехавшая в другую часть, иначе выпала бы из
проверки молча (тест искал бы её там, где её больше нет)."""
import os
import re

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
STATIC = os.path.join(ROOT, "app", "static")


def files() -> list[str]:
    """Пути частей панели в порядке тегов <script> в index.html."""
    with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as f:
        html = f.read()
    return [os.path.join(STATIC, *p.split("/")) for p in re.findall(r'<script src="static/(js/[\w-]+\.js)"', html)]


def source() -> str:
    """Весь код панели одной строкой (части — через перевод строки)."""
    out = []
    for p in files():
        with open(p, encoding="utf-8") as f:
            out.append(f.read())
    return "\n".join(out)
