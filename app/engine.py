"""Движок: приводит сетевое пространство контейнера Amnezia к желаемому состоянию.

Каждые RECONCILE_INTERVAL секунд (и сразу после изменений в панели):
  * находит контейнер Amnezia (если он перезапустился — всё создаётся заново);
  * поднимает/гасит туннели awgrN к выходным серверам;
  * проверяет «живость» туннелей по рукопожатиям и переключает на резерв;
  * генерирует и атомарно применяет nftables, синхронизирует ip rule / маршруты.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import subprocess
import threading
import time

from . import awgconf, config, limits, lists, nftgen, system
from .i18n import Msg, msg_of
from .store import Store
from .traffic import Traffic, month_key
from .users import ServerManager

log = logging.getLogger("awgr.engine")

RUN_DIR = "/run/awgr" if not config.DRY_RUN else os.path.join(config.DATA_DIR, "run")
SOCK_DIR = "/var/run/amneziawg"
LOG_DIR = os.path.join(config.DATA_DIR, "logs")
PROBE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probe.py")


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


class UpRT:
    """Состояние запущенного туннеля."""

    def __init__(self, num: int, conf_hash: str, target_key: str):
        self.num = num
        self.iface = f"{config.IFACE_PREFIX}{num}"
        self.conf_hash = conf_hash
        self.target_key = target_key
        self.proc: subprocess.Popen | None = None
        self.started = time.time()


class Engine:
    def __init__(self, store: Store):
        self.store = store
        self.lock = threading.RLock()
        self.wake = threading.Event()
        self.stop_ev = threading.Event()
        self.target: system.Target | None = None
        self.target_error = Msg("sys.not_checked")
        self.rt: dict[str, UpRT] = {}
        self.health: dict[str, dict] = {}
        self.clients: list[dict] = []
        self.applied_hash: str | None = None
        self.ruleset: str = ""
        self.last_apply: float | None = None
        self.last_error: str | None = None
        self.last_reconcile: float | None = None
        self.events: list[dict] = []
        self.notifier = None          # notify.Notifier, задаёт main.py
        self.traffic = Traffic()
        # учёт трафика по выходам (таблица nftables awgr_acct): ok | off | None (ещё не было)
        self.acct_state: str | None = None
        self.acct_error: str | None = None
        self._acct_key: str | None = None      # для какой цели таблица проверена
        self._acct_retry = 0.0
        self.matcher = lists.Matcher()
        self._list_cache: dict[str, tuple[float, list[str]]] = {}
        self._parsed: dict[str, awgconf.UpstreamConf] = {}
        self._fake = system.DemoTarget() if config.DRY_RUN else None
        self.public_v4: str | None = None      # внешний IPv4, найденный проверкой «напрямую»
        self.srv = ServerManager(self)
        self._runtime_checked = False
        self._last_start_try = 0.0
        os.makedirs(RUN_DIR, exist_ok=True)
        os.makedirs(LOG_DIR, exist_ok=True)

    # ------------------------------------------------------------------ util
    def event(self, level: str, msg: Msg) -> None:
        log.log(logging.WARNING if level != "info" else logging.INFO, "%s", msg)
        self.events.append({"t": time.time(), "level": level, "msg": msg})
        self.events[:] = self.events[-100:]
        if self.notifier:
            self.notifier.engine_event(msg)

    def trigger(self) -> None:
        self.wake.set()

    def reconcile_soon(self) -> None:
        self.wake.set()

    def start(self) -> None:
        threading.Thread(target=self._loop, name="reconcile", daemon=True).start()
        threading.Thread(target=self._lists_loop, name="lists", daemon=True).start()
        threading.Thread(target=self._detect_host, name="public-ip", daemon=True).start()

    def _detect_host(self) -> None:
        """Внешний IPv4 сервера: показывается на вкладке «Сервер» и становится внешним
        адресом, если его не задали."""
        for _ in range(30):
            if self.stop_ev.is_set():
                return
            if self.target and self.target.exists:
                try:
                    r = self.probe("direct")
                    if r.get("ok") and r.get("ip"):
                        self.public_v4 = r["ip"]
                        if not self.srv.public_host(self.store.snapshot()):
                            self.store.mutate(lambda st: st["settings"].setdefault("public_host", r["ip"]))
                        return
                except Exception:  # noqa: BLE001
                    pass
            self.stop_ev.wait(20)

    def _loop(self) -> None:
        while not self.stop_ev.is_set():
            try:
                self.reconcile()
            except Exception as e:  # noqa: BLE001
                self.last_error = msg_of(e)
                log.exception("reconcile")
            self.wake.wait(config.RECONCILE_INTERVAL)
            self.wake.clear()

    def _lists_loop(self) -> None:
        time.sleep(2)
        while not self.stop_ev.is_set():
            try:
                self.refresh_lists(only_due=True)
            except Exception:  # noqa: BLE001
                log.exception("lists")
            self.stop_ev.wait(300)

    # ---------------------------------------------------------------- lists
    def refresh_lists(self, only_due: bool = True, ids: list[str] | None = None) -> None:
        st = self.store.snapshot()
        period = float(st["settings"].get("list_update_hours", 24)) * 3600
        changed = False
        for l in st["lists"]:
            if ids is not None and l["id"] not in ids:
                continue
            if only_due:
                if l["kind"] == "manual" and l.get("updated"):
                    continue
                age = time.time() - (l.get("updated") or 0)
                since_check = time.time() - (l.get("checked") or 0)
                if age < period and os.path.exists(lists.path_for(l["id"])):
                    continue
                if l.get("error") and since_check < 900:
                    continue
            res = lists.refresh(l)
            if res.get("error"):
                self.event("warn", Msg("ev.list_failed", list=l["id"],
                                       error=Msg(res["error"]["$t"], **res["error"]["p"])))
            else:
                changed = True

            def upd(s, lid=l["id"], res=res):
                x = Store.lst(s, lid)
                if x:
                    x.update(res)
            self.store.mutate(upd)
        if changed:
            self.trigger()

    def _cidrs(self, lid: str) -> list[str]:
        p = lists.path_for(lid)
        try:
            m = os.path.getmtime(p)
        except OSError:
            return []
        c = self._list_cache.get(lid)
        if c and c[0] == m:
            return c[1]
        v = lists.load_cidrs(lid)
        self._list_cache[lid] = (m, v)
        return v

    # ----------------------------------------------------------- upstreams
    def parsed(self, u: dict) -> awgconf.UpstreamConf:
        h = _sha(u["config"])
        if h not in self._parsed:
            self._parsed[h] = awgconf.parse_upstream(u["config"])
        return self._parsed[h]

    def _stop_up(self, uid: str) -> None:
        r = self.rt.pop(uid, None)
        if not r:
            return
        if r.proc and r.proc.poll() is None:
            r.proc.terminate()
            try:
                r.proc.wait(5)
            except subprocess.TimeoutExpired:
                r.proc.kill()
        t = self.target
        if t and t.key == r.target_key:
            t.ns(["ip", "link", "del", r.iface], check=False)
        try:
            os.remove(f"{SOCK_DIR}/{r.iface}.sock")
        except OSError:
            pass

    def _stop_all(self) -> None:
        for uid in list(self.rt):
            self._stop_up(uid)

    def _start_up(self, t: system.Target, uid: str, u: dict, pc: awgconf.UpstreamConf,
                  conf_hash: str) -> None:
        r = UpRT(u["num"], conf_hash, t.key)
        ifn = r.iface
        t.ns(["ip", "link", "del", ifn], check=False)
        if not config.DRY_RUN:
            if config.UPSTREAM_BACKEND == "kernel":
                t.ns(["ip", "link", "add", ifn, "type", "amneziawg"])
            else:
                sock = f"{SOCK_DIR}/{ifn}.sock"
                try:
                    os.remove(sock)
                except OSError:
                    pass
                os.makedirs(SOCK_DIR, exist_ok=True)
                env = dict(os.environ, LOG_LEVEL="error")
                # у процесса своя копия дескриптора журнала — наш закрываем сразу,
                # иначе каждый перезапуск туннеля оставлял бы открытый файл
                with open(os.path.join(LOG_DIR, f"{ifn}.log"), "w") as logf:
                    r.proc = subprocess.Popen(
                        ["nsenter", "-t", str(t.pid), "-n", "--", "amneziawg-go", "-f", ifn],
                        stdout=logf, stderr=subprocess.STDOUT, env=env, start_new_session=True)
                for _ in range(50):
                    if os.path.exists(sock) or r.proc.poll() is not None:
                        break
                    time.sleep(0.1)
                if not os.path.exists(sock):
                    r.proc.kill()
                    try:
                        r.proc.wait(5)          # не оставлять процесс-зомби
                    except subprocess.TimeoutExpired:
                        pass
                    raise system.SysError(Msg("sys.awg_start_failed", iface=ifn))
        self.rt[uid] = r
        path = os.path.join(RUN_DIR, f"{ifn}.conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pc.setconf)
        try:
            t.ns(["awg", "setconf", ifn, path])
        finally:
            if not config.DRY_RUN:
                os.remove(path)
        # Служебный link-local адрес: без IPv4-адреса ядро при включённом rp_filter
        # отбрасывает входящие пакеты на интерфейсе. Настоящий адрес туннеля (часто
        # из той же подсети 10.8.1.0/24, что и наши клиенты) подставляется через SNAT.
        t.ns(["ip", "addr", "replace", f"169.254.200.{u['num']}/32", "dev", ifn])
        t.ns(["ip", "link", "set", ifn, "mtu", str(pc.mtu), "up"])
        t.ns(["sysctl", "-qw", f"net.ipv4.conf.{ifn}.rp_filter=2"], check=False)
        self.event("info", Msg("ev.tunnel_up", iface=ifn, name=u["name"], endpoint=pc.endpoint))

    def _links(self, t: system.Target) -> set[str] | None:
        if config.DRY_RUN:
            return None
        p = t.ns(["ip", "-j", "link", "show"], check=False)
        try:
            return {x["ifname"] for x in json.loads(p.stdout or "[]")}
        except ValueError:
            return set()

    def _sync_upstreams(self, t: system.Target, st: dict) -> None:
        wanted = {u["id"]: u for u in st["upstreams"] if u.get("enabled", True)}
        for uid in list(self.rt):
            r = self.rt[uid]
            if uid not in wanted or wanted[uid]["num"] != r.num or r.target_key != t.key:
                self._stop_up(uid)
        links = self._links(t)
        for uid, u in wanted.items():
            try:
                pc = self.parsed(u)
            except awgconf.ConfigError as e:
                self.health[uid] = {"state": "error", "error": e.msg}
                continue
            h = _sha(pc.setconf + str(pc.mtu))
            r = self.rt.get(uid)
            alive = bool(r) and (links is None or r.iface in links) and \
                (r.proc is None or r.proc.poll() is None)
            if r and (r.conf_hash != h or not alive):
                if not alive:
                    self.event("warn", Msg("ev.tunnel_down", iface=r.iface, name=u["name"]))
                self._stop_up(uid)
                r = None
            if not r:
                try:
                    self._start_up(t, uid, u, pc, h)
                except Exception as e:  # noqa: BLE001
                    self._stop_up(uid)
                    self.health[uid] = {"state": "error", "error": msg_of(e)}
                    self.event("error", Msg("ev.upstream_error", name=u["name"], error=msg_of(e)))

    def _update_health(self, t: system.Target, st: dict) -> None:
        now = time.time()
        for u in st["upstreams"]:
            uid = u["id"]
            if not u.get("enabled", True):
                self.health[uid] = {"state": "disabled"}
                continue
            r = self.rt.get(uid)
            if not r:
                self.health.setdefault(uid, {"state": "down"})
                if self.health[uid].get("state") not in ("error",):
                    self.health[uid] = {"state": "down"}
                continue
            if config.DRY_RUN and self._fake and r.iface not in self._fake.handshakes:
                # в демо второй туннель «мёртвый», чтобы было видно резервирование
                self._fake.handshakes[r.iface] = now - (900 if r.num == 2 else 20)
            p = t.ns(["awg", "show", r.iface, "dump"], check=False, timeout=10)
            peers = system._parse_dump(p.stdout) if p.returncode == 0 else {}
            peer = next(iter(peers.values()), None)
            try:
                limit = self.parsed(u).rekey_after + 70
            except Exception:  # noqa: BLE001
                limit = 190
            hs = peer["handshake"] if peer else 0
            age = now - hs if hs else None
            healthy = age is not None and age < limit
            prev = self.health.get(uid, {}).get("healthy")
            if prev is not None and prev != healthy:
                self.event("info" if healthy else "warn",
                           Msg("ev.upstream_ok" if healthy else "ev.upstream_failed", name=u["name"]))
            self.health[uid] = {
                "state": "up" if healthy else ("connecting" if now - r.started < 30 and not hs else "stale"),
                "healthy": healthy, "handshake_age": age, "iface": r.iface,
                "rx": peer["rx"] if peer else 0, "tx": peer["tx"] if peer else 0,
                "endpoint": peer["endpoint"] if peer else None,
                "since": r.started,
            }

    # ------------------------------------------------- трафик по выходам
    def _account(self, t: system.Target, st: dict) -> None:
        """Счётчики таблицы учёта → traffic. Ошибка здесь не мешает маршрутизации:
        учёт выключается, и через час (или при смене цели) пробуем снова."""
        now = time.time()
        if self.acct_state == "off" and self._acct_key == t.key and now < self._acct_retry:
            return
        fresh = False
        p = t.ns(["nft", "-j", "list", "table", "ip", nftgen.ACCT_TABLE], check=False, timeout=20)
        counters = None
        if p.returncode == 0:
            try:
                counters = nftgen.parse_acct(json.loads(p.stdout or "{}"), t.iface)
            except ValueError:
                counters = None
        if counters is None:
            path = os.path.join(RUN_DIR, "acct.nft")
            with open(path, "w") as f:
                f.write(nftgen.acct_ruleset(t.iface))
            r = t.ns(["nft", "-f", path], check=False, timeout=60)
            if r.returncode != 0:
                err = (r.stderr or r.stdout or "").strip()[-300:]
                if self.acct_state != "off":
                    log.warning("exit traffic accounting is off: %s", err)
                    self.event("warn", Msg("ev.acct_off", error=err))
                self.acct_state, self.acct_error = "off", err
                self._acct_key, self._acct_retry = t.key, now + 3600
                return
            counters, fresh = {}, True
        self.acct_state, self.acct_error, self._acct_key = "ok", None, t.key
        by_num = {u["num"]: u["id"] for u in st["upstreams"]}
        pfx = config.IFACE_PREFIX

        def out_of(ifn: str):
            if ifn.startswith(pfx) and ifn[len(pfx):].isdigit():
                return by_num.get(int(ifn[len(pfx):]))   # выход удалён — не считаем
            return "direct"
        pk_of = {c["ip"]: c["public_key"] for c in self.clients if c.get("ip")}
        self.traffic.update_outs(counters, out_of, pk_of, fresh=fresh, now=now)

    @staticmethod
    def quota_target(u: dict) -> str | None:
        """Куда идёт трафик выхода, когда его квота исчерпана: 'direct' | 'block' | 'up:<id>';
        None — только уведомить. 'fallback' — значение из первых сборок 1.3.0: как резерв."""
        qa = u.get("quota_action") or "notify"
        if qa == "notify":
            return None
        if qa == "fallback":
            return u.get("fallback") or "direct"
        return qa

    def over_quota(self, u: dict) -> bool:
        """Месячная квота выхода исчерпана и трафик должен уйти на выход из quota_target."""
        q = u.get("quota")
        return bool(q) and self.quota_target(u) is not None and \
            self.traffic.out_used(u["id"]) >= q

    def _exit_quotas(self, st: dict) -> None:
        """События квот выходов: 90 %, исчерпана, новый месяц. Отметки — в state, чтобы
        не повторять событие после перезапуска панели."""
        if self.acct_state != "ok":
            return
        mk = month_key()
        patches: dict[str, dict] = {}
        for u in st["upstreams"]:
            q = u.get("quota")
            if not q:
                continue
            used = self.traffic.out_used(u["id"])
            gb = float(f"{q / limits.GB:.3g}")
            to = self.quota_target(u)
            fb = to is not None
            p = {}
            if used >= q and u.get("quota_hit") != mk:
                p["quota_hit"] = p["quota_warned"] = mk
                if to is None:
                    self.event("warn", Msg("ev.upstream_quota_notify", name=u["name"], gb=gb))
                elif to in ("direct", "block"):
                    self.event("warn", Msg(f"ev.upstream_quota_{to}", name=u["name"], gb=gb))
                else:
                    t = Store.upstream(st, to[3:])
                    self.event("warn", Msg("ev.upstream_quota", name=u["name"], gb=gb,
                                           to=t["name"] if t else "?"))
            elif q * 0.9 <= used < q and u.get("quota_warned") != mk:
                p["quota_warned"] = mk
                self.event("warn", Msg("ev.upstream_quota_warn", name=u["name"], gb=gb))
            if u.get("quota_hit") and u["quota_hit"] != mk and used < q and "quota_hit" not in p:
                p["quota_hit"] = None
                if fb:
                    self.event("info", Msg("ev.upstream_quota_reset", name=u["name"]))
            if p:
                patches[u["id"]] = p
        if patches:
            def fn(s):
                for x in s["upstreams"]:
                    if x["id"] in patches:
                        x.update(patches[x["id"]])
            self.store.mutate(fn)

    # --------------------------------------------------------------- policy
    def resolve(self, out: str, st: dict, depth: int = 0):
        """Выход из настроек → фактический: 'direct' | 'block' | номер туннеля."""
        if out in ("direct", "block"):
            return out
        if depth > 6:
            return "block"
        if out.startswith("up:"):
            u = Store.upstream(st, out[3:])
            if not u:
                return "block"
            h = self.health.get(u["id"], {})
            if u.get("enabled", True) and h.get("healthy"):
                if not self.over_quota(u):
                    return u["num"]
                return self.resolve(self.quota_target(u), st, depth + 1)
            return self.resolve(u.get("fallback") or "direct", st, depth + 1)
        return "block"

    def policy_for(self, st: dict, pk: str | None) -> dict:
        """Политика в терминах настроек (до резолва), с учётом настроек клиента."""
        g = st["routing"]
        cp = st["clients"].get(pk or "", {})
        rules = g["rules"]
        if cp.get("rules_mode") == "custom":
            rules = cp.get("rules") or []
        default = g["default"]
        if cp.get("outbound") and cp["outbound"] != "inherit":
            default = cp["outbound"]
        return {"rules": [r for r in rules if r.get("enabled", True) and r.get("lists")],
                "default": default, "custom": bool(cp) and (
                    cp.get("rules_mode") == "custom" or cp.get("outbound", "inherit") != "inherit")}

    def _resolved(self, st: dict, pol: dict) -> dict:
        return {"rules": [(r["lists"], self.resolve(r["outbound"], st)) for r in pol["rules"]],
                "default": self.resolve(pol["default"], st)}

    def build_ruleset(self, t: system.Target, st: dict) -> str:
        gp = self._resolved(st, self.policy_for(st, None))
        cps = {}
        for c in self.clients:
            if not c.get("ip"):
                continue
            pol = self.policy_for(st, c["public_key"])
            if pol["custom"]:
                cps[c["ip"]] = self._resolved(st, pol)
        used = {lid for p in [gp, *cps.values()] for l, _ in p["rules"] for lid in l}
        lst = {lid: self._cidrs(lid) for lid in used}
        ups = []
        for u in st["upstreams"]:
            if u["id"] in self.rt:
                try:
                    pc = self.parsed(u)
                except Exception:  # noqa: BLE001
                    continue
                ups.append({"num": u["num"], "snat": pc.address, "mtu": pc.mtu})
        return nftgen.generate(t.iface, lst, ups, gp, cps)

    # -------------------------------------------------------- ip rule/route
    def _sync_rules(self, t: system.Target) -> None:
        want = {r.num for r in self.rt.values()}
        lo, hi = config.RULE_PRIO_BASE + 1, config.RULE_PRIO_BASE + config.MAX_UPSTREAMS
        p = t.ns(["ip", "-j", "rule", "show"], check=False)
        try:
            have = json.loads(p.stdout or "[]")
        except ValueError:
            have = []
        present = set()
        for rule in have:
            prio = rule.get("priority", 0)
            if not lo <= prio <= hi:
                continue
            num = prio - config.RULE_PRIO_BASE
            ok = num in want and str(rule.get("table")) == str(config.TABLE_BASE + num) and \
                int(str(rule.get("fwmark", "0")), 0) == nftgen.mark_for(num)
            if ok and num not in present:
                present.add(num)
            else:
                t.ns(["ip", "rule", "del", "priority", str(prio)], check=False)
                if num not in want:
                    t.ns(["ip", "route", "flush", "table", str(config.TABLE_BASE + num)], check=False)
        for num in want:
            table = str(config.TABLE_BASE + num)
            if num not in present:
                t.ns(["ip", "rule", "add", "fwmark", hex(nftgen.mark_for(num)), "lookup", table,
                      "priority", str(config.RULE_PRIO_BASE + num)])
            # Если туннель исчезнет, останется unreachable — трафик не утечёт мимо
            t.ns(["ip", "route", "replace", "unreachable", "default", "metric", "4096",
                  "table", table], check=False)
            t.ns(["ip", "route", "replace", "default", "dev", f"{config.IFACE_PREFIX}{num}",
                  "table", table], check=False)

    def _sysctl(self, t: system.Target) -> None:
        for kv in ("net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=2",
                   "net.ipv4.conf.default.rp_filter=2", "net.ipv4.conf.all.src_valid_mark=1"):
            t.ns(["sysctl", "-qw", kv], check=False)

    # ------------------------------------------------------------ reconcile
    def reconcile(self) -> None:
        with self.lock:
            st = self.store.snapshot()
            try:
                t = self._fake if config.DRY_RUN else system.discover()
            except Exception as e:  # noqa: BLE001
                if self.target is not None:
                    self.event("error", Msg("ev.target_lost", error=msg_of(e)))
                self.target_error = msg_of(e)
                self._stop_all()
                self.target = None
                self.applied_hash = None
                return
            if isinstance(t, system.HostTarget) and not config.DRY_RUN:
                if not self._runtime_checked and t.exists:
                    try:
                        system.install_host_runtime(t)
                    except Exception as e:  # noqa: BLE001
                        self.event("warn", Msg("ev.runtime_failed", error=msg_of(e)))
                    self._runtime_checked = True
                if not t.exists and config.AWG_INIT_PORT:
                    self.target = t
                    self.srv.init_host(config.AWG_INIT_PORT, config.AWG_INIT_SUBNET)
                    self._runtime_checked = True
                if t.exists and not t.is_up() and time.time() - self._last_start_try > 60:
                    # сервер на хосте не запущен (например, после неудачного старта) — поднимаем
                    self._last_start_try = time.time()
                    p = t.native(["systemctl", "enable", "--now", f"awg-quick@{t.iface}"],
                                 check=False, timeout=60)
                    if p.returncode != 0:
                        self.event("error", Msg("ev.server_start_failed",
                                                error=(p.stderr or p.stdout).strip()[-300:]))
            if not t.exists:
                self.target = t
                self.target_error = Msg("sys.host_no_server")
                self.clients = []
                return
            self.target_error = None
            if self.notifier:
                self.notifier.target_ok()
            if self.target is None or self.target.key != t.key or not self.target.exists:
                if self.target is not None and self.target.exists:
                    self.event("warn", Msg("ev.target_restarted"))
                self._stop_all()
                self.target = t
                self.applied_hash = None
                self._sysctl(t)

            try:
                self.clients = self.srv.list_clients(t)
            except Exception as e:  # noqa: BLE001
                self.event("warn", Msg("ev.clients_failed", error=msg_of(e)))
            else:
                try:
                    self.traffic.update(self.clients)
                    limits.enforce(self)
                except Exception:  # noqa: BLE001
                    log.exception("traffic/limits")
            try:
                self._account(t, st)
                self._exit_quotas(st)
            except Exception:  # noqa: BLE001
                log.exception("exit traffic")

            self._sync_upstreams(t, st)
            self._update_health(t, st)

            text = self.build_ruleset(t, st)
            h = _sha(text)
            present = t.ns(["nft", "list", "chain", "ip", config.NFT_TABLE, "c_prerouting"],
                           check=False).returncode == 0
            if h != self.applied_hash or not present:
                path = os.path.join(RUN_DIR, "ruleset.nft")
                with open(path, "w") as f:
                    f.write(text)
                t.ns(["nft", "-f", path], timeout=60)
                if self.applied_hash and present:
                    self.event("info", Msg("ev.rules_applied"))
                self.applied_hash = h
                self.ruleset = text
                self.last_apply = time.time()
            self._sync_rules(t)
            self.last_error = None
            self.last_reconcile = time.time()

    def teardown(self) -> None:
        """Полностью убирает следы панели (как будто её не было)."""
        with self.lock:
            t = self.target
            self._stop_all()
            if t:
                t.ns(["nft", "delete", "table", "ip", config.NFT_TABLE], check=False)
                t.ns(["nft", "delete", "table", "ip", nftgen.ACCT_TABLE], check=False)
                self._acct_key = None
                p = t.ns(["ip", "-j", "rule", "show"], check=False)
                try:
                    for rule in json.loads(p.stdout or "[]"):
                        prio = rule.get("priority", 0)
                        if config.RULE_PRIO_BASE < prio <= config.RULE_PRIO_BASE + config.MAX_UPSTREAMS:
                            t.ns(["ip", "rule", "del", "priority", str(prio)], check=False)
                            t.ns(["ip", "route", "flush", "table",
                                  str(config.TABLE_BASE + prio - config.RULE_PRIO_BASE)], check=False)
                except ValueError:
                    pass
            self.applied_hash = None

    def shutdown(self) -> None:
        self.stop_ev.set()
        self.wake.set()
        self.traffic.save()
        st = self.store.snapshot()
        if st["settings"].get("on_stop") == "restore":
            self.teardown()
        else:
            with self.lock:
                self._stop_all()

    # ---------------------------------------------------------------- tools
    def probe(self, out: str) -> dict:
        """Проверка выхода: внешний IP, страна, задержка."""
        t = self.target
        if not t:
            raise system.SysError(self.target_error if isinstance(self.target_error, Msg)
                                  else Msg("sys.no_container"))
        st = self.store.snapshot()
        eff = self.resolve(out, st)
        if eff == "block":
            return {"ok": False, "error": Msg("probe.blocked")}
        mark = 0 if eff == "direct" else nftgen.mark_for(eff)
        if config.DRY_RUN:
            return {"ok": True, "ip": "203.0.113.%d" % (10 + (eff if eff != "direct" else 0)),
                    "cc": "NL" if eff != "direct" else "RU", "latency_ms": 42, "via": eff}
        p = t.ns(["python3", PROBE, str(mark)], check=False, timeout=25)
        try:
            res = json.loads(p.stdout)
        except ValueError:
            res = {"ok": False, "err": "no_answer", "detail": (p.stderr or p.stdout).strip()[:300]}
        if res.get("err"):
            res["error"] = Msg("probe." + res.pop("err"), detail=res.pop("detail", ""))
        if res.get("warn"):
            res["warn"] = Msg("probe." + res["warn"], detail=res.pop("detail", ""))
        res["via"] = eff
        return res

    def trace(self, pk: str | None, ip: str) -> dict:
        st = self.store.snapshot()
        steps = []
        for net in nftgen.LOCAL_NETS:
            if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(net):
                return {"result": "direct", "effective": "direct",
                        "steps": [Msg("tr.local", ip=ip, net=net)]}
        pol = self.policy_for(st, pk)
        steps.append(Msg("tr.client_rules" if pk and st["clients"].get(pk, {}).get("rules_mode")
                         == "custom" else "tr.global_rules"))
        for r in pol["rules"]:
            for lid in r["lists"]:
                hit = self.matcher.contains(lid, ip)
                if hit:
                    steps.append(Msg("tr.match", list=lid, net=hit))
                    eff = self.resolve(r["outbound"], st)
                    return {"result": r["outbound"], "effective": eff, "steps": steps,
                            "rule": r.get("comment") or r["id"]}
        steps.append(Msg("tr.default_client" if pk and st["clients"].get(pk, {}).get(
            "outbound", "inherit") != "inherit" else "tr.default"))
        return {"result": pol["default"], "effective": self.resolve(pol["default"], st),
                "steps": steps}
