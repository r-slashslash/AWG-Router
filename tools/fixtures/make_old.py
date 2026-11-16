"""Состояние и резервные копии прежних выпусков для тестов загрузки (tests/fixtures/old).

Запуск: python3 tools/fixtures/make_old.py <папка с кодом выпуска> <куда положить>

Код выпуска — например, `git archive v1.20.0 | tar -x -C /tmp/v1.20.0`. Скрипт запускает его демо-панель
(DRY_RUN) в пустой папке данных, через API заводит всё, что этот выпуск умеет (клиенты, списки всех видов,
выходы AWG и SOCKS5, правила, сроки и лимиты, ссылки, маскировку, Telegram, настройки сервера), и сохраняет
state.json, резервную копию (backup.json) и, если выпуск умеет, копию с паролем (backup.enc, пароль
PASSWORD). Чего выпуск не умеет, он отклоняет — это записывается в log.txt и не мешает остальному.
Адреса, ключи и пароли — выдуманные (документационные сети RFC 5737)."""
from __future__ import annotations

import http.cookiejar
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PASSWORD = "fixture-backup-pw"
PRIV = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
PUB = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
AWG_EXIT = f"""[Interface]
Address = 10.9.0.2/32
PrivateKey = {PRIV}
Jc = 4
Jmin = 40
Jmax = 70

[Peer]
PublicKey = {PUB}
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.1:51820
"""


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Panel:
    def __init__(self, code: str, data: str):
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        env = {**os.environ, "DRY_RUN": "1", "PANEL_PASSWORD": "demo", "DATA_DIR": data,
               "PANEL_PORT": str(self.port), "PUBLIC_HOST": "203.0.113.5", "PYTHONDONTWRITEBYTECODE": "1"}
        self.proc = subprocess.Popen([sys.executable, "-m", "app.main"], cwd=code, env=env,
                                     stdout=open(os.path.join(data, "..", "panel.out"), "w"), stderr=subprocess.STDOUT)
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.log: list[str] = []
        for _ in range(100):
            try:
                self.call("POST", "/api/login", {"password": "demo"}, quiet=True)
                return
            except OSError:
                time.sleep(0.2)
        raise SystemExit("панель не запустилась")

    def call(self, method: str, path: str, body=None, quiet: bool = False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", "Origin": self.base,
                                              "Sec-Fetch-Site": "same-origin"})
        try:
            with self.op.open(req, timeout=120) as r:
                out = json.loads(r.read() or b"null")
            if not quiet:
                self.log.append(f"ok   {method} {path}")
            return out
        except urllib.error.HTTPError as e:
            if quiet:
                raise
            self.log.append(f"FAIL {method} {path} {e.code} {e.read()[:200]!r}")
            return None

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def populate(p: Panel) -> None:
    pks = []
    for name in ("alice", "bob", "carol"):
        r = p.call("POST", "/api/users", {"name": name})
        if r and r.get("public_key"):
            pks.append(r["public_key"])
    time.sleep(1.5)                          # проход движка: клиенты появляются в engine.clients
    a, b, c = (pks + [None, None, None])[:3]

    ids = {}
    for key, body in (
        ("office", {"kind": "manual", "name": "Office",
                    "source": "203.0.113.0/24\n198.51.100.0/25 # склад\n192.0.2.7\n2001:db8::/32"}),
        ("v6only", {"kind": "manual", "name": "Only v6", "source": "2001:db8:1::/48"}),
        ("sites", {"kind": "domains", "name": "Sites",
                   "source": "example.com\n*.example.org\n# comment\nhttps://lists.example/d.txt"}),
        ("asn", {"kind": "asn", "name": "", "source": "AS64496 64511"}),
        ("feed", {"kind": "url", "name": "Feed", "source": "https://lists.example/nets.txt"}),
        ("de", {"kind": "country", "name": "Germany", "source": "de"}),
    ):
        r = p.call("POST", "/api/lists", body)
        if not r and key == "office":            # до 1.8.0 разбор списка не пропускал IPv6 и пометки
            r = p.call("POST", "/api/lists", {**body, "source": "203.0.113.0/24\n198.51.100.0/25\n192.0.2.7"})
        if r and r.get("id"):
            ids[key] = r["id"]

    nl = (p.call("POST", "/api/upstreams", {"name": "NL", "config": AWG_EXIT, "quota_gb": 50,
                                            "quota_action": "direct", "rate_down": 50, "rate_up": 10}) or {}).get("id")
    routing = {"domains": "a.example\nb.example", "default": False}
    if "sites" in ids:
        routing["domain_lists"] = [ids["sites"]]
    if "office" in ids:
        routing["net_lists"] = [ids["office"]]
    px = (p.call("POST", "/api/upstreams", {"name": "Proxy", "config": "socks5://user:pass@198.51.100.9:1080",
                                            "fallback": f"up:{nl}" if nl else "direct", "quic": True,
                                            "quota_gb": 2.5, "quota_action": "block",
                                            "routing": routing}) or {}).get("id")
    if not px:                               # до 1.11.0 выходов SOCKS5 нет: второй выход — AWG
        px = (p.call("POST", "/api/upstreams", {"name": "DE", "config": AWG_EXIT.replace("198.51.100.1", "198.51.100.2"),
                                                "fallback": f"up:{nl}" if nl else "direct", "quota_gb": 2.5,
                                                "quota_action": "block"}) or {}).get("id")
    if nl and px:
        p.call("PUT", f"/api/upstreams/{nl}", {"fallback": f"up:{px}"})   # круг резервов: до 1.20.0 сохранялся
        p.call("PUT", f"/api/upstreams/{nl}", {"quota_gb": 50, "quota_action": f"up:{px}"})
    off = (p.call("POST", "/api/upstreams", {"name": "Spare", "config": "socks5://198.51.100.10:1080"}) or {}).get("id")
    if off:
        p.call("PUT", f"/api/upstreams/{off}", {"enabled": False})

    st = p.call("GET", "/api/state") or {}
    rules = (st.get("routing") or {}).get("rules") or []
    rules = [{k: r.get(k) for k in ("id", "lists", "outbound", "enabled", "comment") if k in r} for r in rules]
    rules.append({"lists": ["ru", "cn"], "outbound": "direct", "comment": "geo"})
    if "office" in ids and px:
        rules.append({"lists": [ids["office"]], "outbound": f"up:{px}", "comment": "Proxy"})   # подпись = имя выхода
    if "sites" in ids:
        rules.append({"lists": [ids["sites"]], "outbound": "block", "enabled": False, "comment": "off"})
    if "asn" in ids and "feed" in ids:
        rules.append({"lists": [ids["asn"], ids["feed"], ids.get("de", "ir")], "outbound": "direct"})
    body = {"default": f"up:{nl}" if nl else "direct", "rules": rules,
            "balance": {"on": True, "skip": [off] if off else []}, "strict": True}
    if not p.call("PUT", "/api/routing", body) and "sites" in ids:
        # до 1.21.0 правило по доменам вело только на SOCKS5, до домен-правил — его нет вовсе
        for r in rules:
            if r["lists"] == [ids["sites"]]:
                r["outbound"] = f"up:{px}" if px else "direct"
        if not p.call("PUT", "/api/routing", body):
            body["rules"] = [r for r in rules if r["lists"] != [ids["sites"]]]
            p.call("PUT", "/api/routing", body)

    if a:
        p.call("PUT", f"/api/clients/{a}", {"outbound": f"up:{px}" if px else "direct", "rules_mode": "custom",
                                            "rules": [{"lists": [ids.get("office", "ru")], "outbound": "direct",
                                                       "comment": "home"}], "note": "phone"})
        p.call("PUT", f"/api/limits/{a}", {"expires": 1900000000, "quota_gb": 20, "period": "month",
                                           "rate_down": 5, "rate_up": 1})
        p.call("POST", f"/api/shares/{a}")
        if not p.call("PUT", f"/api/cps/{a}", {"preset": "amnezia"}):
            p.call("PUT", f"/api/cps/{a}", {"preset": "icloud"})
    if b:
        p.call("PUT", f"/api/clients/{b}", {"outbound": "block", "rules_mode": "inherit", "note": ""})
        p.call("PUT", f"/api/limits/{b}", {"expires": 1800000000, "quota_gb": 1.5, "period": "total"})
        p.call("PUT", f"/api/cps/{b}", {"preset": "custom", "values": {"I1": "<b 0x0102030405060708>"}})
        p.call("POST", f"/api/shares/{b}")
    if c:
        p.call("PUT", f"/api/users/{c}", {"enabled": False})

    p.call("PUT", "/api/settings", {"list_update_hours": 12, "on_stop": "restore",
                                    "shaping": {"down": 200, "up": 100}})
    p.call("PUT", "/api/telegram", {"token": "123456:" + "A" * 35, "chat_id": "-1001234567", "lang": "ru",
                                    "events": {"login": False, "exit_down": True}, "enabled": True,
                                    "control": True, "backup": "weekly", "backup_pw": "tg-backup-pass",
                                    "via": f"up:{nl}" if nl else "direct"})
    for body in ({"client_dns": "1.1.1.1, 9.9.9.9"}, {"client_mtu": 1380}, {"client_keepalive": "25"},
                 {"panel_dns": True}, {"panel_dns_enc": "doh"}, {"dom_filter": True},
                 {"public_host": "vpn.example.com"}, {"extra_hosts": "198.51.100.20"},
                 {"client_host": "198.51.100.21"}):
        p.call("PUT", "/api/server", body)
    if a:
        p.call("PUT", f"/api/hosts/{a}", {"host": "198.51.100.20"})


def main() -> None:
    code, out = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    work = tempfile.mkdtemp()
    data = os.path.join(work, "data")
    os.makedirs(data)
    p = Panel(code, data)
    try:
        populate(p)
        time.sleep(2)
        backup = p.call("GET", "/api/backup")
        enc = p.call("POST", "/api/backup/encrypted", {"password": PASSWORD})
    finally:
        p.stop()
    os.makedirs(out, exist_ok=True)
    shutil.copy(os.path.join(data, "state.json"), os.path.join(out, "state.json"))
    if backup:
        with open(os.path.join(out, "backup.json"), "w") as f:
            json.dump(backup, f, ensure_ascii=False, indent=1)
    if enc and enc.get("data"):
        with open(os.path.join(out, "backup.enc"), "w") as f:
            f.write(enc["data"] + "\n")
    with open(os.path.join(out, "log.txt"), "w") as f:
        f.write("\n".join(p.log) + "\n")
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
