"""Сервер AWG: присмотр за интерфейсом и перезапуск, модуль ядра (переход на amneziawg-go, ручной выбор
движка), правила «до панели» рядом с конфигом сервера."""
from __future__ import annotations

from collections.abc import Sequence
import os
import time

from .. import config, hostnet, kernelmod, system
from ..i18n import Msg, msg_of
from .common import KERNEL_MIN, RUN_DIR, log, server_ifaces

V6_TABLE = "awgr6"


def v6_ruleset(iface: str | Sequence[str]) -> str:
    """Таблица ip6 панели: IPv6 из интерфейса клиентов дальше не пересылается (см. Engine._sync_v6)."""
    ifaces = [iface] if isinstance(iface, str) else list(iface)
    expr = f'"{ifaces[0]}"' if len(ifaces) == 1 else "{ " + ", ".join(f'"{w}"' for w in ifaces) + " }"
    return (f"table ip6 {V6_TABLE}\nflush table ip6 {V6_TABLE}\ntable ip6 {V6_TABLE} {{\n"
            "\tchain forward {\n\t\ttype filter hook forward priority filter - 1; policy accept;\n"
            f'\t\tiifname {expr} reject with icmpv6 type admin-prohibited\n\t}}\n}}\n')

SERVER_GRACE = 30        # с: столько интерфейса сервера в контейнере может не быть, прежде чем панель его поднимет
SERVER_PAUSES = (60, 120, 300, 600, 1800)   # паузы между попытками поднять сервер, если не помогает, с
KERNEL_GIVE_UP = 2       # столько перезапусков сервер не поднялся на модуле ядра — панель переводит его на amneziawg-go


class ServerMixin:
    """Сервер AWG и модуль ядра (часть Engine)."""

    # ------------------------------------------------------------- движок AWG
    def module_info(self) -> dict:
        """Модуль ядра на хосте: {"loaded", "version", "ok"} (ok — версия не меньше KERNEL_MIN)."""
        if config.DRY_RUN:
            # демо: выбор amneziawg-go вручную (switch_engine) «выгружает» модуль, как на настоящем сервере
            m = {"loaded": False, "version": None} if kernelmod.load().get("choice") == "go" else \
                {"loaded": True, "version": "3.1.20260812"}
        else:
            m = hostnet.awg_module()
            if m["loaded"] and not m["version"]:
                # у сборки без /sys/module/amneziawg/version версию знает modinfo хоста (не чаще раза в минуту)
                at, v = self._modinfo
                if time.time() - at > 60:
                    from . import webfront
                    p = webfront.host_run(["modinfo", "-F", "version", "amneziawg"], timeout=10)
                    v = (p.stdout or "").strip() if p.returncode == 0 else ""
                    self._modinfo = (time.time(), v)
                m["version"] = v or None
        return {**m, "ok": m["loaded"] and hostnet.module_major(m["version"]) >= KERNEL_MIN}

    # ------------------------------------------------------------ reconcile
    def _watch_server(self, t: system.Target) -> bool:
        """Интерфейса сервера нет, а цель на месте — например, ядро завершило amneziawg-go при нехватке памяти:
        контейнер работает дальше без awg0, служба на хосте числится запущенной, клиенты отваливаются.
        Поднимаем перезапуском (контейнер — docker restart, хост — служба awg-quick). Контейнер — не сразу
        (SERVER_GRACE: при смене порта и S1–S4 интерфейс пропадает ненадолго), дальше с растущими паузами."""
        if config.DRY_RUN:
            self.server_restart_at = None
            self._srv_up = True
            return False
        now = time.time()
        self._srv_up = t.is_up()
        if self._srv_up:
            self._srv_down, self._srv_tries, self._srv_next = None, 0, 0.0
            self.server_restart_at = None
            return False
        if self._srv_down is None:
            self._srv_down = now
        grace = SERVER_GRACE if t.kind == "container" else 0
        if now - self._srv_down < grace or now < self._srv_next:
            return False
        self._srv_tries += 1
        self._srv_next = now + SERVER_PAUSES[min(self._srv_tries, len(SERVER_PAUSES)) - 1]
        self.event("warn", Msg("ev.server_iface_gone", iface=t.iface))
        if self._srv_tries > KERNEL_GIVE_UP and self.module_info()["loaded"] and not kernelmod.load().get("disabled"):
            self._drop_module()
        self.server_restart_at = now
        try:
            if t.kind == "host":
                t.native(["systemctl", "enable", f"awg-quick@{t.iface}"], check=False, timeout=30)
            t.restart()
        except Exception as e:  # noqa: BLE001
            self.event("error", Msg("ev.server_start_failed", error=msg_of(e)))
        # True: цель перезапущена — у контейнера новый PID, и этот проход работал бы со старым. Следующий —
        # сразу, а не через RECONCILE_INTERVAL: в новой сети контейнера ещё нет наших правил (_hold_rules)
        self.wake.set()
        return True

    def _drop_module(self) -> None:
        """Сервер не поднимается на модуле ядра уже KERNEL_GIVE_UP перезапусков: модуль загружен — awg-quick
        берёт его и не переходит на amneziawg-go сам, клиенты так и остались бы без связи. Панель запрещает и
        выгружает модуль (kernelmod.block), и следующий перезапуск поднимает сервер на amneziawg-go; выходы
        идут следом. Снова — кнопкой «Попробовать снова» (install.sh --install-kernel снимает запрет)."""
        self._stop_all()                       # туннели выходов на модуле держат его
        try:
            err = kernelmod.block()
        except OSError as e:
            err = str(e)[:200]
        kernelmod.update(disabled={"at": time.time(), "error": err}, seen=None, lost=None)
        self.kernel_fallback = None
        if err:
            log.warning("kernel module is blocked but still loaded: %s", err)
            self.event("error", Msg("ev.kernel_disabled_reboot", n=self._srv_tries - 1))
        else:
            self.event("error", Msg("ev.kernel_disabled", n=self._srv_tries - 1))

    def switch_engine(self, choice: str) -> dict:
        """Ручной выбор движка в панели — один на весь сервер (выходы идут следом). → {"action": …}.

        go: модуль загружен — сервер останавливается, модуль запрещается и выгружается (kernelmod.block: иначе
        awg-quick снова взял бы его), сервер запускается на amneziawg-go. Модуль остаётся установленным.
        kernel: модуль уже загружен — перезапуск сервера (он сам возьмёт модуль); нет — установка
        (`install.sh --install-kernel`: снимает запрет и, если пакет уже стоит, просто загружает модуль)."""
        self.switching = True
        try:
            return self._switch_engine(choice)
        finally:
            self.switching = False

    def _switch_engine(self, choice: str) -> dict:
        if choice == "go":
            with self.lock:
                t = self.target
                if not t or not t.exists:
                    raise system.SysError(Msg("srv.no_server"))
                err = None
                if self.module_info()["loaded"]:
                    self._stop_all()                       # туннели выходов на модуле держат его
                    t.stop()
                    try:
                        err = None if config.DRY_RUN else kernelmod.block()
                    except OSError as e:
                        err = str(e)[:200]
                    finally:
                        t.start()
                    self._settle = ("engine", time.time())   # до первого удачного прохода — «Смена движка…»
                kernelmod.update(choice="go", seen=None, lost=None, disabled=None)
                self.kernel_fallback = None
                self._srv_down, self._srv_tries, self._srv_next = None, 0, 0.0
                self.server_engine = None                  # перечитать после запуска
                self.event("info", Msg("ev.engine_go_reboot" if err else "ev.engine_go"))
            self.reconcile_soon()
            return {"action": "restarted", "reboot": bool(err)}
        if choice != "kernel":
            raise ValueError(choice)
        kernelmod.update(choice=None)
        m = self.module_info()
        if m["loaded"] and m["ok"]:
            self.restart_server("engine")
            return {"action": "restarted"}
        kernelmod.start()
        return {"action": "install"}

    def _watch_module(self) -> None:
        """Модуль, на котором работал сервер, пропал (после обновления ядра не собрался или не загрузился):
        awg-quick сам поднял сервер на amneziawg-go, но об этом надо сказать — событие и Telegram, а в панели
        оповещение с кнопкой «Установить модуль». Версия модуля, на котором работал сервер, — в engine.json
        (`seen`): после перезагрузки сервера память панели пуста. Модуль снова загружен — отметки сняты."""
        if config.DRY_RUN:
            return
        m = self.module_info()
        ks = kernelmod.load()
        if m["loaded"]:
            patch = {}
            if m["ok"] and ks.get("disabled"):
                patch["disabled"] = None       # модуль поставили снова («Попробовать снова»)
            if ks.get("lost"):
                patch["lost"] = None
            seen = m["version"] or "?"
            if m["ok"] and self.server_engine == "kernel" and ks.get("seen") != seen:
                patch["seen"] = seen
                self.event("info", Msg("ev.kernel_on", version=seen))     # сервер перешёл на модуль (или новую версию)
            if patch:
                kernelmod.update(**patch)
            return
        if ks.get("seen") and self.server_engine == "go":
            kernelmod.update(seen=None, lost=time.time())
            self.event("warn", Msg("ev.kernel_gone", version=ks["seen"]))

    def _hold_rules(self, t: system.Target, st: dict) -> None:
        """Новая цель (контейнер перезапустился, панель запустилась): в её сети ещё нет наших правил, и до
        конца прохода — а в нём запуск всех туннелей — клиенты шли бы напрямую, даже с резервом «Блокировать».
        Поэтому правила ставятся до запуска туннелей: выход, туннеля которого ещё нет, `nftgen.layout` ведёт в
        блок. `applied_hash` не меняется: обычное применение в конце прохода заменит эти правила настоящими."""
        if config.DRY_RUN:
            return
        try:
            path = os.path.join(RUN_DIR, "ruleset.nft")
            with open(path, "w") as f:
                f.write(self.build_ruleset(t, st, None))
            t.ns(["nft", "-f", path], timeout=60)
        except Exception as e:  # noqa: BLE001  — обычное применение в конце прохода скажет об ошибке само
            log.warning("rules before tunnels: %s", e)

    def _sync_v6(self, t: system.Target) -> None:
        """IPv6 клиентов закрыт (пересмотр Б8 глубокой проверки 1.23.0, Г3; владелец 2026-11-21). Правила панели — только
        для IPv4, а сервер «на хосте», поставленный сторонним скриптом, раздаёт клиентам IPv6 и выпускает его в интернет
        мимо выходов и блоков. Пересылка IPv6 из интерфейса клиентов — отказ (reject: приложение сразу берёт IPv4).
        Отдельная таблица и без ошибки прохода: в сети без IPv6 её может не быть, а правила IPv4 важнее."""
        if config.DRY_RUN:
            return
        ifaces = tuple(server_ifaces(t))
        key = (t.key, ifaces)
        if getattr(self, "_v6_key", None) == key and t.ns(
                ["nft", "list", "table", "ip6", V6_TABLE], check=False).returncode == 0:
            return
        path = os.path.join(RUN_DIR, "ruleset6.nft")
        with open(path, "w") as f:
            f.write(v6_ruleset(ifaces))
        p = t.ns(["nft", "-f", path], check=False)
        if p.returncode == 0:
            self._v6_key = key
        elif getattr(self, "_v6_key", None) != ("failed",) + key:
            self._v6_key = ("failed",) + key            # в журнал — один раз на цель
            log.info("IPv6 of clients: no ip6 table here: %s", (p.stderr or "").strip()[:200])

    def _hold_path(self, t: system.Target, iface: str | None = None) -> str | None:
        """Где лежит файл правил «до панели» (HOLD_FILE) — там, где его применит сам сервер при запуске:
        на хосте — служба awg-quick (system.UNIT_TEXT), в контейнере — только в нашем (awg-server/start.sh);
        в контейнере приложения AmneziaVPN его никто не применит, и писать туда незачем."""
        ifn = iface or t.iface
        conf_p = getattr(t, "wg_conf_path", None) if ifn == "wg0" and t.iface != "wg0" else None
        conf_dir = os.path.dirname(conf_p or t.conf_path)
        path = os.path.join(conf_dir, system.HOLD_NAME.format(iface=ifn))
        if t.kind == "host":
            return path
        if t.kind != "container":
            return None
        ok = self._hold_ok.get(t.key)
        if ok is None:
            ok = "awgr-hold" in (t.read_file("/opt/amnezia/start.sh") or "")
            self._hold_ok = {t.key: ok}
        return path if ok else None

    def _save_hold(self, t: system.Target, st: dict) -> None:
        """Файл правил «до панели»: сервер ставит их сам при запуске, до подъёма интерфейса — после
        перезапуска контейнера или перезагрузки хоста клиенты не идут мимо выходов, пока панель не
        применила свои. Это те же правила, что остаются при остановке панели. С «Когда панель останавливают:
        Вернуть всё напрямую» (on_stop = restore) файла нет: тогда без панели всё должно идти напрямую."""
        if config.DRY_RUN:
            return
        restore = st["settings"].get("on_stop") == "restore"
        ifaces = tuple(server_ifaces(t))
        # strict меняет эти правила, даже когда посредник работает и применённые правила те же
        key = (self.applied_hash, restore, t.key, self.strict(st), ifaces)
        if key == self._hold_key:
            return
        try:
            rules = None if restore else self.build_ruleset(t, st, None, hold=True)
            for ifn in ifaces:
                path = self._hold_path(t, ifn)
                if not path:
                    continue
                if restore:
                    try:
                        os.unlink(t.host_path(path))
                    except FileNotFoundError:
                        pass
                else:
                    t.write_file(path, rules, 0o600)
            self._hold_key = key
        except Exception as e:  # noqa: BLE001  — не мешает работе: сработает при следующем применении
            log.warning("rules before the panel starts: %s", e)

    def _drop_hold(self, t: system.Target) -> None:
        """Убрать файл правил «до панели» (удаление панели): иначе сервер ставил бы их и без неё."""
        for ifn in dict.fromkeys([*server_ifaces(t), "wg0"]):
            conf_p = getattr(t, "wg_conf_path", None) if ifn == "wg0" and t.iface != "wg0" else None
            conf_dir = os.path.dirname(conf_p or t.conf_path)
            try:
                os.unlink(t.host_path(os.path.join(conf_dir, system.HOLD_NAME.format(iface=ifn))))
            except OSError:
                pass
        self._hold_key = None

    def restart_server(self, why: str = "server_restart") -> None:
        """Кнопка «Перезапустить сервер AWG» (why = engine — смена движка). Дальше всё применит reconcile: у
        контейнера сменится Target.key. До первого удачного прохода шапка говорит «Перезапуск…» (_settle)."""
        with self.lock:
            t = self.target
            if not t or not t.exists:
                raise system.SysError(Msg("srv.no_server"))
            if t.kind == "host" and not config.DRY_RUN:
                t.native(["systemctl", "enable", f"awg-quick@{t.iface}"], check=False, timeout=30)
            self.server_restart_at = time.time()
            t.restart()
            self._settle = (why, time.time())
            self._srv_down, self._srv_tries, self._srv_next = None, 0, 0.0
            self.kernel_fallback = None     # на хосте Target.key не меняется: модуль пробуем снова здесь
        self.reconcile_soon()
