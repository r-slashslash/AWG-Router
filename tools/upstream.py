"""Есть ли новые версии чужих программ в образах, за которыми не следит Dependabot.

Запуск: python3 tools/upstream.py [--out <папка>]

Dependabot обновляет действия workflow и образы в FROM, но не исходники, которые Dockerfile скачивает по хешу
коммита (amneziawg-go, amneziawg-tools, hev-socks5-tunnel), и не образ lego из ARG. Скрипт берёт закреплённые
версии из Dockerfile, спрашивает у их репозиториев список тегов (`git ls-remote --tags`) и печатает, что вышло
новее. Сам ничего не обновляет. С --out пишет в папку `title` и `body.md` для issue (только если есть что
сказать); это делает еженедельный `.github/workflows/upstream.yml`.

Заодно проверяет, что тег закреплённой версии всё ещё указывает на закреплённый коммит: тег можно незаметно
переставить на другой код — сборка тогда не сломается (она идёт по хешу), но об этом стоит знать.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TITLE = "New upstream versions"

# имя, репозиторий, ARG с версией, ARG с хешем коммита (у lego — образ, его отпечаток не коммит)
PROGRAMS = (
    ("amneziawg-go", "https://github.com/amnezia-vpn/amneziawg-go", "AWG_GO_REF", "AWG_GO_SHA"),
    ("amneziawg-tools", "https://github.com/amnezia-vpn/amneziawg-tools", "AWG_TOOLS_REF", "AWG_TOOLS_SHA"),
    ("hev-socks5-tunnel", "https://github.com/heiher/hev-socks5-tunnel", "HEV_REF", "HEV_SHA"),
    ("lego", "https://github.com/go-acme/lego", "LEGO_IMAGE", None),
)

# Версии, которые проверены и сознательно не взяты: о них issue не напоминает (о более новых — напоминает)
SKIP = {
    "hev-socks5-tunnel": {"2.20.0"},
}

# Что сказать в issue о новой версии программы
NOTES = {
    "amneziawg-go": "AmneziaWG versions are the same in `Dockerfile` and `awg-server/Dockerfile`.",
    "amneziawg-tools": "AmneziaWG versions are the same in `Dockerfile` and `awg-server/Dockerfile`.",
    "hev-socks5-tunnel": "2.20.0 was slower under a speed limit (hev-socks5-core `8e3b4cd`): before updating, "
                         "look at the speed lines of `domains_socks_e2e` in net-tests.",
    "lego": "The image is pinned by digest: take the new tag's digest from Docker Hub (`goacme/lego`).",
}

VERSION = re.compile(r"v?(\d+(?:\.\d+)+)")


def pinned(text: str) -> dict:
    """ARG из Dockerfile: имя → значение."""
    return dict(re.findall(r"^ARG (\w+)=(\S+)", text, re.M))


def version_of(ref: str) -> str:
    """Название версии из ARG: «v3.1.20260828», «2.19.3» или образ «goacme/lego:v5.6.0@sha256:…» → «v5.6.0»."""
    if ":" in ref:
        ref = ref.split("@")[0].rsplit(":", 1)[1]
    return ref


def key(tag: str):
    """Числа версии для сравнения; None — не выпуск (snapshot, -rc, v1.0.20260618-2 и т. п.)."""
    m = VERSION.fullmatch(tag)
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def tags(out: str) -> dict:
    """Вывод `git ls-remote --tags` → тег: коммит (у тега с подписью — коммит из строки `^{}`)."""
    found = {}
    for line in out.splitlines():
        sha, _, ref = line.partition("\t")
        if not ref.startswith("refs/tags/"):
            continue
        name = ref[len("refs/tags/"):]
        if name.endswith("^{}"):
            found[name[:-3]] = sha
        else:
            found.setdefault(name, sha)
    return found


def compare(name: str, current: str, sha: str | None, remote: dict) -> dict:
    """Что сказать о программе: {"newer": (тег, коммит)} и/или {"moved": коммит, на который теперь указывает тег}."""
    have = key(current)
    skip = SKIP.get(name, set())
    best = None
    for tag, commit in remote.items():
        k = key(tag)
        if k is None or tag in skip or (have is not None and k <= have):
            continue
        if best is None or k > best[0]:
            best = (k, tag, commit)
    res = {}
    if best:
        res["newer"] = (best[1], best[2])
    if sha and current in remote and remote[current] != sha:
        res["moved"] = remote[current]
    return res


def ls_remote(url: str) -> str:
    return subprocess.run(["git", "ls-remote", "--tags", url], capture_output=True, text=True,
                          timeout=120, check=True).stdout


def report(found: list) -> tuple[str, str]:
    """(заголовок, текст issue) по списку (имя, закреплённая версия, итог compare); пустые — нечего сказать."""
    found = [f for f in found if f[2]]
    if not found:
        return "", ""
    newer = [f for f in found if "newer" in f[2]]
    moved = [f for f in found if "moved" in f[2]]
    parts = [f"{n} {r['newer'][0]}" for n, _, r in newer] + [f"{n} tag moved" for n, _, r in moved]
    title = f"{TITLE}: " + ", ".join(parts)
    body = ["Programs built into the images have something new upstream. Nothing was updated: this is only a "
            "reminder.", ""]
    if newer:
        body += ["| Program | Pinned | Newest | Commit |", "|---|---|---|---|"]
        body += [f"| {n} | {cur} | {r['newer'][0]} | `{r['newer'][1]}` |" for n, cur, r in newer]
        body += ["", "To update, change the version (`*_REF`) and the commit (`*_SHA`) together in `Dockerfile`, "
                 "then run net-tests on the branch.", ""]
        body += [f"- **{n}**: {NOTES[n]}" for n, _, _ in newer if n in NOTES] + [""]
    if moved:
        body += ["**A tag now points to other code** than the commit we pinned. The build is not affected (it "
                 "fetches by commit), but find out why before updating:", ""]
        body += [f"- {n} {cur}: now `{r['moved']}`" for n, cur, r in moved] + [""]
    body += ["This issue is updated by the weekly `upstream.yml` run and closed when everything is up to date."]
    return title, "\n".join(body) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", help="папка для title и body.md")
    a = ap.parse_args(argv)
    with open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8") as f:
        args = pinned(f.read())
    found, failed = [], 0
    for name, url, ref_arg, sha_arg in PROGRAMS:
        current = version_of(args[ref_arg])
        try:
            remote = tags(ls_remote(url))
        except (OSError, subprocess.SubprocessError) as e:
            print(f"::warning::{name}: no tag list ({e})")
            failed += 1
            continue
        res = compare(name, current, args.get(sha_arg) if sha_arg else None, remote)
        print(f"{name}: {current} → " + (", ".join(f"{k}: {v}" for k, v in res.items()) or "up to date"))
        found.append((name, current, res))
    title, body = report(found)
    if a.out:
        # incomplete — не все репозитории ответили: тогда открытое issue не закрывается
        files = {"title": title, "body.md": body, "incomplete": "yes" if failed else ""}
        os.makedirs(a.out, exist_ok=True)
        for n, text in files.items():
            if text:
                with open(os.path.join(a.out, n), "w", encoding="utf-8") as f:
                    f.write(text)
    return 1 if failed == len(PROGRAMS) else 0


if __name__ == "__main__":
    sys.exit(main())
