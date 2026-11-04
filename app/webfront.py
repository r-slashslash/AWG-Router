"""Проверка Let's Encrypt через веб-сервер, который уже занял порт 80 (nginx, Apache и др.).

Let's Encrypt проверяет адрес панели запросом http://<адрес>/.well-known/acme-challenge/<токен>
на порт 80. Если порт свободен, lego сам слушает его несколько секунд. Если там уже работает
веб-сервер, панель кладёт токены в папку на хосте (WEBROOT), а веб-сервер отдаёт её только для
адреса панели и только по этому пути — сайты на нём не затрагиваются.

Наш файл настроек веб-сервера — отдельный (FILE): чужие файлы не правятся. Перед перезагрузкой
конфиг проверяется (nginx -t, apachectl configtest), после — запрос к самому себе через веб-сервер;
если что-то не так, файл удаляется и веб-сервер возвращается к прежним настройкам.
Сам добавляет: nginx (и Angie, OpenResty) на хосте и в Docker, если папка конфигов подключена
с хоста; Apache на хосте. Для остальных — текст, который пользователь вставит сам (kind=manual).

Командная строка (для install.sh, через docker compose run):
    python3 -m app.webfront check HOST   — что на порту 80; 0 — можно добавить, 2 — только вручную,
                                           1 — порт свободен, 3 — уже настроено для HOST
    python3 -m app.webfront add HOST     — добавить свой файл
    python3 -m app.webfront remove       — убрать свой файл
    python3 -m app.webfront domain [D]   — показать или задать домен панели (пусто — по IP)
"""
from __future__ import annotations

import http.client
import ipaddress
import logging
import os
import re
import secrets
import shutil
import socket
import sys
import time
import urllib.parse

from . import config, system, tlsconf
from .i18n import Msg, MsgError

log = logging.getLogger("awgr.web")

FILE = "awg-router-acme.conf"
WEBROOT = "/var/lib/awg-router/acme"        # на хосте, для веб-сервера на хосте
SUBDIR = "awg-router-acme"                  # для nginx в Docker: рядом с нашим файлом в папке конфигов
CHALLENGE = "/.well-known/acme-challenge/"
NGINX = ("nginx", "angie", "openresty")
APACHE = ("apache2", "httpd")
# предпочтительные папки из include: только в них server {} окажется внутри http {}
NGINX_DIRS = ("conf.d", "http.d", "sites-enabled")


class WebError(MsgError):
    pass


# ------------------------------------------------------------------ хост
def host_path(p: str) -> str:
    """Путь на хосте → путь, по которому его видит панель (config.HOST_ROOT).

    Ссылки разбираются вручную: абсолютная ссылка внутри /proc/1/root указала бы на файлы самой
    панели, а не хоста (certbot кладёт в live/ относительные, но бывают и абсолютные)."""
    root = config.HOST_ROOT
    if not root:
        return p
    parts, out, hops = [x for x in p.split("/") if x], [], 0
    while parts:
        x = parts.pop(0)
        if x == ".":
            continue
        if x == "..":
            if out:
                out.pop()
            continue
        cand = root + "/" + "/".join(out + [x])
        if os.path.islink(cand):
            hops += 1
            if hops > 40:
                raise OSError(40, "too many symbolic links", p)
            target = os.readlink(cand)
            if target.startswith("/"):
                out = []
            parts = [y for y in target.split("/") if y] + parts
            continue
        out.append(x)
    return root + "/" + "/".join(out)


def host_run(cmd: list[str], timeout: int = 30):
    """Команда на хосте (его файлы, его PATH, его docker)."""
    if config.HOST_ROOT:
        cmd = ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--"] + cmd
    try:
        return system.run(cmd, timeout=timeout, check=False)
    except (OSError, ValueError) as e:
        return _Done(127, "", str(e))
    except Exception as e:  # noqa: BLE001 — TimeoutExpired и пр.
        return _Done(124, "", str(e))


class _Done:
    def __init__(self, rc, out, err):
        self.returncode, self.stdout, self.stderr = rc, out, err


def _tail(p, n: int = 3) -> str:
    lines = [x for x in ((p.stderr or "") + "\n" + (p.stdout or "")).strip().splitlines() if x.strip()]
    return " ".join(lines[-n:])[-400:] or f"exit {p.returncode}"


def _mkdirs(webroot: str) -> None:
    """Папка токенов и путь к ней: веб-сервер (www-data, nginx) должен пройти по каждой папке."""
    top = os.path.dirname(WEBROOT) if webroot == WEBROOT else webroot.rstrip("/")
    p = webroot.rstrip("/") + CHALLENGE.rstrip("/")
    os.makedirs(host_path(p), exist_ok=True)
    while len(p) >= len(top):
        try:
            os.chmod(host_path(p), 0o755)
        except OSError:
            pass
        p = os.path.dirname(p)


# ------------------------------------------------------------- кто на порту 80
def listeners(port: int = 80) -> list[dict]:
    """Процессы, слушающие TCP-порт на хосте: [{"name", "pid", "addr"}]. Панель в сети хоста."""
    try:
        p = system.run(["ss", "-Hltnp", f"sport = :{port}"], check=False, timeout=10)
    except (OSError, ValueError):
        return []
    out = []
    for line in (p.stdout or "").splitlines():
        f = line.split()
        addr = f[3] if len(f) > 3 else ""
        for name, pid in re.findall(r'\("([^"]+)",pid=(\d+)', line):
            out.append({"name": name, "pid": int(pid), "addr": addr})
    return [x for x in out if x["name"] != "lego"]   # это сама панель получает сертификат


def _same_mnt(pid: int) -> bool:
    try:
        return os.readlink(f"/proc/{pid}/ns/mnt") == os.readlink("/proc/1/ns/mnt")
    except OSError:
        return True


def _ancestors(pid: int) -> set[int]:
    seen = set()
    while pid > 1 and pid not in seen:
        seen.add(pid)
        try:
            with open(f"/proc/{pid}/status") as f:
                pid = int(next(x.split()[1] for x in f if x.startswith("PPid:")))
        except (OSError, StopIteration, ValueError):
            break
    return seen


def _containers() -> list[dict]:
    try:
        return system.docker_get("/containers/json") or []
    except Exception:  # noqa: BLE001 — нет Docker
        return []


def _inspect(cid: str) -> dict:
    try:
        return system.docker_get(f"/containers/{urllib.parse.quote(cid)}/json") or {}
    except Exception:  # noqa: BLE001
        return {}


def _container_of_pid(pid: int) -> dict | None:
    up = _ancestors(pid)
    for c in _containers():
        info = _inspect(c.get("Id", ""))
        if (info.get("State") or {}).get("Pid") in up:
            return info
    return None


def _container_on_port(port: int) -> dict | None:
    for c in _containers():
        if any(p.get("PublicPort") == port and p.get("Type", "tcp") == "tcp" for p in c.get("Ports") or []):
            return _inspect(c.get("Id", ""))
    return None


def _cname(info: dict) -> str:
    return (info.get("Name") or "").lstrip("/") or (info.get("Id") or "")[:12]


def _cmd(det: dict, args: list[str], timeout: int = 30):
    if det.get("where") == "docker":
        return host_run(["docker", "exec", det["container"]] + args, timeout=timeout)
    return host_run(args, timeout=timeout)


def detect() -> dict:
    """Что слушает порт 80 и можно ли добавить наш файл самим.

    kind: none (порт свободен) | nginx | apache | other; where: host | docker; auto — можно самим,
    иначе reason (Msg) — почему только вручную."""
    if config.DRY_RUN:
        return _demo()
    ls = listeners()
    if not ls:
        return {"kind": "none"}
    first = ls[0]
    det = {"kind": "other", "process": first["name"], "where": "host", "container": "", "auto": False,
           "reason": None}
    info = None
    if first["name"] == "docker-proxy":
        info = _container_on_port(80)
    elif not _same_mnt(first["pid"]):
        info = _container_of_pid(first["pid"])
    if info is not None:
        det.update(where="docker", container=_cname(info))
        return _detect_docker(det, info)
    name = first["name"]
    if name in NGINX:
        return _detect_nginx(det, name)
    if name in APACHE:
        return _detect_apache(det)
    if name == "caddy":
        det.update(kind="caddy", reason=Msg("web.manual_only", server="Caddy"))
        return det
    det["reason"] = Msg("web.manual_only", server=name)
    return det


def _nginx_dump(det: dict, binary: str) -> str | None:
    p = _cmd(det, [binary, "-T"], timeout=20)
    return p.stdout if p.returncode == 0 and p.stdout else None


def _include_dir(dump: str) -> str | None:
    """Папка из include с маской (*.conf или *), куда положить наш server {}."""
    dirs = []
    for m in re.finditer(r"^\s*include\s+([^;#\s]+)\s*;", dump, re.M):
        inc = m.group(1).strip("'\"")
        if inc.endswith(("/*.conf", "/*")):
            dirs.append(inc.rsplit("/", 1)[0])
    for name in NGINX_DIRS:
        for d in dirs:
            if os.path.basename(d) == name:
                return d
    return None


def _detect_nginx(det: dict, binary: str) -> dict:
    det.update(kind="nginx", binary=binary, process=binary)
    dump = _nginx_dump(det, binary)
    if dump is None:
        det["reason"] = Msg("web.no_dump", server=binary)
        return det
    d = _include_dir(dump)
    if not d:
        det["reason"] = Msg("web.no_conf_dir", server=binary)
        return det
    det.update(auto=True, file=f"{d}/{FILE}", webroot=WEBROOT, root_in=WEBROOT,
               ipv6=bool(re.search(r"^\s*listen\s+\[::\]:80\b", dump, re.M)),
               test=[binary, "-t"], reload=[binary, "-s", "reload"])
    return det


def _detect_docker(det: dict, info: dict) -> dict:
    name = det["container"]
    for binary in NGINX:
        dump = _nginx_dump(det, binary)
        if dump is None:
            continue
        det.update(kind="nginx", binary=binary, process=binary)
        d = _include_dir(dump)
        if not d:
            det["reason"] = Msg("web.no_conf_dir", server=binary)
            return det
        mount = None
        for m in info.get("Mounts") or []:
            dst = (m.get("Destination") or "").rstrip("/")
            if dst and (d == dst or d.startswith(dst + "/")) and (not mount or len(dst) > len(mount[0])):
                mount = (dst, m)
        if not mount:
            det["reason"] = Msg("web.in_image", container=name, dir=d)
            return det
        dst, m = mount
        if not m.get("RW", True):
            det["reason"] = Msg("web.read_only", container=name, dir=d)
            return det
        src = (m.get("Source") or "").rstrip("/") + d[len(dst):]
        det.update(auto=True, file=f"{src}/{FILE}", file_in=f"{d}/{FILE}",
                   webroot=f"{src}/{SUBDIR}", root_in=f"{d}/{SUBDIR}",
                   ipv6=bool(re.search(r"^\s*listen\s+\[::\]:80\b", dump, re.M)),
                   test=[binary, "-t"], reload=[binary, "-s", "reload"])
        return det
    for binary in ("httpd", "apache2"):
        if _cmd(det, [binary, "-v"], timeout=10).returncode == 0:
            det.update(kind="apache", process=binary, reason=Msg("web.docker_manual", container=name))
            return det
    det["reason"] = Msg("web.docker_manual", container=name)
    return det


def _detect_apache(det: dict) -> dict:
    det.update(kind="apache")
    if os.path.isdir(host_path("/etc/apache2/sites-enabled")):        # Debian, Ubuntu
        det.update(auto=True, file=f"/etc/apache2/sites-available/{FILE}",
                   link=f"/etc/apache2/sites-enabled/{FILE}", webroot=WEBROOT, root_in=WEBROOT,
                   test=["apache2ctl", "configtest"], reload=["apache2ctl", "graceful"])
    elif os.path.isdir(host_path("/etc/httpd/conf.d")):               # RHEL, Fedora
        det.update(auto=True, file=f"/etc/httpd/conf.d/{FILE}", webroot=WEBROOT, root_in=WEBROOT,
                   test=["apachectl", "configtest"], reload=["apachectl", "graceful"])
    else:
        det["reason"] = Msg("web.no_conf_dir", server="Apache")
    return det


def _demo() -> dict:
    return {"kind": "nginx", "process": "nginx", "where": "host", "container": "", "auto": True,
            "reason": None, "binary": "nginx", "file": f"/etc/nginx/conf.d/{FILE}", "webroot": WEBROOT,
            "root_in": WEBROOT, "ipv6": True, "test": ["nginx", "-t"], "reload": ["nginx", "-s", "reload"]}


# ---------------------------------------------------------------- текст конфига
def _is_ip(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def snippet(det: dict, host: str) -> str:
    root = det.get("root_in") or WEBROOT
    name = f"[{host}]" if ":" in host else host
    head = (f"# AWG Router: Let's Encrypt validation for the panel address {host}.\n"
            f"# Only this address and {CHALLENGE}; your sites are not affected.\n")
    if det.get("kind") == "apache":
        return head + (f"<VirtualHost *:80>\n"
                       f"    ServerName {name}\n"
                       f"    DocumentRoot {root}\n"
                       f"    <Directory {root}>\n"
                       f"        Options None\n"
                       f"        AllowOverride None\n"
                       f"        Require all granted\n"
                       f"    </Directory>\n"
                       f"</VirtualHost>\n")
    if det.get("kind") == "caddy":
        return head + f"http://{name} {{\n    root * {root}\n    file_server\n}}\n"
    v6 = "    listen [::]:80;\n" if det.get("ipv6") else ""
    # root на весь server: кроме папки токенов там ничего нет — остальное 404 (без модуля rewrite)
    return head + (f"server {{\n"
                   f"    listen 80;\n{v6}"
                   f"    server_name {name};\n"
                   f"    root {root};\n"
                   f"    location {CHALLENGE} {{\n"
                   f"        default_type text/plain;\n"
                   f"    }}\n"
                   f"}}\n")


def public(det: dict) -> dict:
    """Что показать в панели (без команд)."""
    return {k: det.get(k) for k in ("kind", "process", "where", "container", "auto", "reason", "file",
                                    "webroot")}


def info(host: str) -> dict:
    """Порт 80 сейчас: кто, можно ли самим, текст для вставки и текущая настройка."""
    det = detect()
    cur = tlsconf.load().get("web")
    out = {**public(det), "host": host, "web": cur}
    if det.get("kind") != "none":
        manual = dict(det, root_in=det.get("root_in") if det.get("auto") else WEBROOT)
        out["snippet"] = snippet(det if det.get("auto") else manual, host)
    return out


# ---------------------------------------------------------------- проверка
def _addrs(host: str) -> list[str]:
    if _is_ip(host):
        return [host]
    try:
        return list(dict.fromkeys(a[4][0] for a in socket.getaddrinfo(host, 80, type=socket.SOCK_STREAM)))
    except OSError:
        return []


def self_test(webroot: str, host: str, tries: int = 6) -> tuple[bool, str]:
    """Кладёт файл в папку токенов и просит его через порт 80 с адресом панели в Host.
    Сначала по адресам панели, потом через 127.0.0.1 (в облаке внешний IP бывает не на интерфейсе)."""
    if config.DRY_RUN:
        return True, ""
    name = "awgr-check-" + secrets.token_hex(8)
    body = secrets.token_hex(16)
    _mkdirs(webroot)
    fp = host_path(webroot.rstrip("/") + CHALLENGE) + name
    with open(fp, "w") as f:
        f.write(body)
    os.chmod(fp, 0o644)
    hdr = f"[{host}]" if ":" in host else host
    addrs, detail = _addrs(host) + ["127.0.0.1"], ""
    try:
        for i in range(tries):
            for addr in list(addrs):
                try:
                    c = http.client.HTTPConnection(f"[{addr}]" if ":" in addr else addr, 80, timeout=4)
                    c.request("GET", CHALLENGE + name, headers={"Host": hdr, "User-Agent": "awg-router"})
                    r = c.getresponse()
                    got = r.read(256).decode("utf-8", "replace").strip()
                    c.close()
                except OSError as e:
                    detail = f"{addr}: {e}"[:200]
                    if len(addrs) > 1:
                        addrs.remove(addr)      # адрес не отвечает изнутри — дальше пробуем следующий
                    continue
                if r.status == 200 and got == body:
                    return True, ""
                detail = f"HTTP {r.status}"
                break                           # ответил не тот файл — ждём перезагрузки и спрашиваем снова
            time.sleep(0.5 * (i + 1))
        return False, detail
    finally:
        try:
            os.remove(fp)
        except OSError:
            pass


# ---------------------------------------------------------------- добавить / убрать
def _write(p: str, text: str) -> None:
    hp = host_path(p)
    with open(hp + ".tmp", "w") as f:
        f.write(text)
    os.chmod(hp + ".tmp", 0o644)
    os.replace(hp + ".tmp", hp)


def _rm(p: str | None) -> None:
    if not p:
        return
    try:
        os.remove(host_path(p))
    except FileNotFoundError:
        pass
    except OSError as e:
        log.warning("remove %s: %s", p, e)


def _drop_files(web: dict, keep_root: bool = False) -> None:
    _rm(web.get("link"))
    _rm(web.get("file"))
    wr = (web.get("webroot") or "").rstrip("/")
    if not keep_root and wr.endswith(("/" + SUBDIR, WEBROOT)):        # только своя папка токенов
        shutil.rmtree(host_path(wr), ignore_errors=True)
        if wr == WEBROOT:
            try:
                os.rmdir(host_path(os.path.dirname(WEBROOT)))
            except OSError:
                pass


def install(host: str, det: dict | None = None) -> dict:
    """Добавляет наш файл в веб-сервер на порту 80 для адреса host; при любой ошибке — откат."""
    det = det or detect()
    if not det.get("auto"):
        raise WebError(det.get("reason") or Msg("web.not_busy"))
    old = tlsconf.load().get("web")
    if old and old.get("kind") != "manual":
        remove(old, reload=old.get("file") != det["file"])
    # папку токенов, которую отдаёт вставленный вручную блок, при откате не трогаем
    keep = bool(old and old.get("kind") == "manual" and old.get("webroot") == det.get("webroot"))
    web = {k: det.get(k) for k in ("kind", "process", "where", "container", "binary", "file", "link",
                                    "webroot", "root_in", "test", "reload")}
    web["host"] = host
    if config.DRY_RUN:
        tlsconf.update(web=web)
        return web
    _mkdirs(det["webroot"])
    _write(det["file"], snippet(det, host))
    if det.get("link"):
        try:
            os.symlink(f"../sites-available/{FILE}", host_path(det["link"]))
        except FileExistsError:
            pass
    t = _cmd(det, det["test"])
    if t.returncode != 0:
        _drop_files(web, keep)
        raise WebError(Msg("web.test_failed", server=det["process"], detail=_tail(t)))
    r = _cmd(det, det["reload"])
    if r.returncode != 0:
        _drop_files(web, keep)
        _cmd(det, det["reload"])
        raise WebError(Msg("web.reload_failed", server=det["process"], detail=_tail(r)))
    ok, detail = self_test(det["webroot"], host)
    if not ok:
        _drop_files(web, keep)
        _cmd(det, det["reload"])
        raise WebError(Msg("web.check_failed", server=det["process"], host=host, detail=detail))
    tlsconf.update(web=web)
    log.info("Let's Encrypt validation through %s: %s", det["process"], det["file"])
    return web


def manual(host: str) -> dict:
    """Пользователь вставил текст сам: проверяем, что папка токенов отдаётся, и запоминаем."""
    det = detect()
    ok, detail = self_test(WEBROOT, host)
    if not ok:
        raise WebError(Msg("web.check_failed", server=det.get("process") or "web", host=host, detail=detail))
    web = {"kind": "manual", "process": det.get("process") or "", "where": det.get("where") or "host",
           "container": det.get("container") or "", "webroot": WEBROOT, "root_in": WEBROOT, "host": host}
    tlsconf.update(web=web)
    return web


def remove(web: dict | None = None, reload: bool = True) -> None:
    """Убирает наш файл (для manual — только запоминание: свой конфиг пользователь правит сам)."""
    web = web or tlsconf.load().get("web")
    if not web:
        return
    if web.get("kind") != "manual" and not config.DRY_RUN:
        _drop_files(web)
        if reload and web.get("test"):
            if _cmd(web, web["test"]).returncode == 0:
                _cmd(web, web["reload"])
    tlsconf.update(web=None)


def reinstall_for(host: str) -> None:
    """Адрес панели сменился: наш файл переписываем на новый адрес, ручную настройку забываем."""
    web = tlsconf.load().get("web")
    if not web or web.get("host") == host:
        return
    if web.get("kind") == "manual":
        tlsconf.update(web=None)
        return
    try:
        install(host)
    except WebError as e:
        log.warning("Let's Encrypt validation through %s for %s: %s", web.get("process"), host, e.msg)
        remove(web)
        raise


# ---------------------------------------------------------------- командная строка
_EN = {
    "web.manual_only": "{server} is not supported for automatic setup",
    "web.no_dump": "could not read the {server} configuration ({server} -T)",
    "web.no_conf_dir": "no conf.d or sites-enabled folder found in the {server} configuration",
    "web.in_image": "the configuration of container {container} is inside its image ({dir} is not a mounted folder)",
    "web.read_only": "the configuration folder {dir} of container {container} is read-only",
    "web.docker_manual": "the web server runs in container {container}",
    "web.not_busy": "nothing listens on port 80",
    "web.test_failed": "{server} rejected the configuration: {detail}",
    "web.reload_failed": "{server} could not reload: {detail}",
    "web.check_failed": "{server} does not serve the validation folder for {host}: {detail}",
}


def _en(m) -> str:
    if isinstance(m, Msg):
        return _EN.get(m.key, m.key).format(**{k: str(v) for k, v in m.p.items()})
    return str(m)


def _label(det: dict) -> str:
    name = det.get("process") or "a web server"
    return f"{name} in container {det['container']}" if det.get("where") == "docker" else f"{name} on this server"


def cli(argv: list[str]) -> int:
    cmd = argv[0] if argv else ""
    host = argv[1] if len(argv) > 1 else ""
    if cmd == "domain":
        if len(argv) > 1:
            tlsconf.update(domain=host.strip().lower())
        print(tlsconf.domain())
        return 0
    if cmd == "remove":
        remove()
        return 0
    if cmd not in ("check", "add") or not host:
        print("usage: python3 -m app.webfront check HOST | add HOST | remove | domain [NAME]")
        return 64
    if cmd == "add":
        try:
            web = install(host)
        except WebError as e:
            print(f"Could not set it up: {_en(e.msg)}")
            return 1
        print(f"Added {web['file']}; {web['process']} reloaded")
        return 0
    cur = tlsconf.load().get("web")
    det = detect()
    if det.get("kind") == "none":
        return 1
    if cur and cur.get("host") == host and (cur.get("kind") == "manual" or os.path.exists(host_path(cur["file"]))):
        print(f"Port 80 is used by {_label(det)}; Let's Encrypt validation through it is already set up")
        return 3
    print(f"Port 80 is used by {_label(det)}.")
    if det.get("auto"):
        print(f"AWG Router can add its own file {det['file']} so that {det['process']} passes the")
        print(f"Let's Encrypt validation for {host} to the panel. Nothing else changes:\n")
        text = snippet(det, host)
    else:
        print(f"It can't be set up automatically: {_en(det.get('reason'))}.")
        print(f"Add this to the web server's configuration (the folder {WEBROOT} must be visible to it),")
        print("then press Check in the panel: System → Set up validation through the web server.\n")
        text = snippet(dict(det, root_in=WEBROOT), host)
    print("\n".join("    " + x for x in text.rstrip().splitlines()))
    return 0 if det.get("auto") else 2


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    sys.exit(cli(sys.argv[1:]))
