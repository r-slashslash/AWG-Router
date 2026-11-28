"""Настройки из переменных окружения."""
import os
import re


def _bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


DATA_DIR = os.environ.get("DATA_DIR", "/data")
DRY_RUN = _bool("DRY_RUN")

# Где сервер AWG: auto (контейнер Amnezia, если есть, иначе хост) | container | host
AWG_MODE = os.environ.get("AWG_MODE", "auto").strip().lower() or "auto"
# Каталог конфигов AWG на хосте (режим host)
HOST_AWG_DIR = os.environ.get("HOST_AWG_DIR", "/etc/amnezia/amneziawg")
# Создать сервер на хосте при первом запуске (ставит установщик): UDP-порт
AWG_INIT_PORT = int(os.environ.get("AWG_INIT_PORT", "0") or 0)
AWG_INIT_SUBNET = os.environ.get("AWG_INIT_SUBNET", "10.8.1.0/24")

# Адрес сервера для клиентских конфигов и сертификата (IP или домен)
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "").strip()

# HTTPS панели: letsencrypt | selfsigned | off
TLS_MODE = os.environ.get("TLS_MODE", "off").strip().lower() or "off"
TLS_DOMAIN = os.environ.get("TLS_DOMAIN", "").strip()       # пусто = PUBLIC_HOST
ACME_EMAIL = os.environ.get("ACME_EMAIL", "").strip()
ACME_SERVER = os.environ.get("ACME_SERVER", "https://acme-v02.api.letsencrypt.org/directory")
ACME_HTTP_PORT = int(os.environ.get("ACME_HTTP_PORT", "80"))
# Корень файловой системы хоста, как его видит панель (pid: host). Пусто — свой корень (демо, тесты)
HOST_ROOT = os.environ.get("HOST_ROOT", "" if DRY_RUN else "/proc/1/root").rstrip("/")

# Контейнер Amnezia: пусто = автопоиск (amnezia-awg2, затем amnezia-awg)
AWG_CONTAINER = os.environ.get("AWG_CONTAINER", "").strip()
# Каталог конфигов внутри контейнера Amnezia
AWG_DIR = os.environ.get("AWG_DIR", "/opt/amnezia/awg")
# Имя интерфейса сервера: пусто = по имени .conf (awg0 / wg0)
AWG_IFACE = os.environ.get("AWG_IFACE", "").strip()

DOCKER_SOCK = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")

# userspace (amneziawg-go, по умолчанию) или kernel (модуль amneziawg на хосте)
# туннели к выходам: auto — тем же, чем сервер (модуль ядра или amneziawg-go); go / kernel — принудительно
EXIT_ENGINE = os.environ.get("EXIT_ENGINE", "auto").strip().lower()
if EXIT_ENGINE not in ("auto", "go", "kernel"):
    EXIT_ENGINE = "auto"

PANEL_HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "8080"))
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "")
# Секретный префикс URL, например /my-secret-path
PANEL_BASE_PATH = "/" + os.environ.get("PANEL_BASE_PATH", "").strip("/")
if PANEL_BASE_PATH == "/":
    PANEL_BASE_PATH = ""

# Команда SSH-туннеля в боте (панель только через SSH): кто входит и порт сервера SSH, если не 22. Их пишет
# install.sh (ssh_user, ssh_port) в .env; непохожее на имя пользователя или порт — как без них (root, 22)
SSH_USER = os.environ.get("SSH_USER", "").strip()
if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9._-]{0,31}", SSH_USER):
    SSH_USER = "root"
SSH_PORT = os.environ.get("SSH_PORT", "").strip()
SSH_PORT = int(SSH_PORT) if SSH_PORT.isdigit() and 0 < int(SSH_PORT) < 65536 and int(SSH_PORT) != 22 else 0

RECONCILE_INTERVAL = int(os.environ.get("RECONCILE_INTERVAL", "10"))

# Нумерация служебных объектов
IFACE_PREFIX = "awgr"          # awgr1, awgr2 ...
TABLE_BASE = 2000              # таблица маршрутизации = 2000 + N
MARK_BASE = 0x2000             # fwmark = 0x2000 + N
RULE_PRIO_BASE = 20000         # приоритет ip rule = 20000 + N
MARK_BLOCK = 0xB10C
NFT_TABLE = "awgr"
MAX_UPSTREAMS = 200
# «Напрямую» с дополнительного исходящего адреса номер K (1.25.0): метка ADDR_MARK_BASE + K → ip rule
# ADDR_PRIO_BASE + K → таблица ADDR_TABLE_BASE + K (маршрут по умолчанию с этим адресом отправителя; на хосте —
# и подмена адреса в цепочке c_addr_nat, в контейнере — через сеть Docker адреса). K = 1 … srcaddr.OUT_HOSTS_MAX (16).
# Метки — младшие 16 бит, рядом с метками выходов 0x20xx; на пакете целиком, без лишних битов (ip rule сравнивает всё)
ADDR_MARK_BASE = 0x2100
ADDR_TABLE_BASE = 2300
ADDR_PRIO_BASE = 20300
ADDR_MAX = 16
# Правила по доменам (sniproxy.py): порт на адресе сервера в туннеле, куда
# nftables перенаправляет TCP 80/443 клиентов с такими правилами
SNI_PROXY_PORT = int(os.environ.get("SNI_PROXY_PORT", "10443"))
SNIFF_MARK = 0xD000            # пакет клиента → в sniproxy.py
SNIFF_OUT_BASE = 0xD100        # соединения sniproxy.py: метка = база + номер политики клиента
# QUIC по имени (sniproxy.py, очередь ядра): номер очереди и метки вердикта
QUIC_QUEUE = 2310
QUIC_PASS_MARK = 0xE100        # сайт не из правил: дальше обычные правила политики
QUIC_DIRECT_MARK = 0xE101      # сайт из правила «напрямую»: метка без ip rule — основная таблица
QUIC_CT_BIT = 0x40000000       # в ct mark: решение по имени уже принято, остальные пакеты берут его
# Учёт трафика по правилам (1.24.0): номер правила в политике клиента — метка соединения в conntrack (ct label N:
# бит N), «По умолчанию» — RULE_DEFAULT_SLOT. QUIC, разобранный по имени, несёт номер правила+1 в битах
# QUIC_SLOT_MASK метки вердикта: цепочка q_lab ставит по нему метку соединения и снимает эти биты до маршрутизации
RULE_DEFAULT_SLOT = 63
# Правил в одном списке (общие, свои правила клиента) не больше: номер правила + 1 должен влезать в 6 бит QUIC_SLOT_MASK
# вердикта QUIC и не доходить до RULE_DEFAULT_SLOT — иначе бит переполнится в QUIC_CT_BIT, и QUIC уйдёт мимо выхода
MAX_RULES = 50
QUIC_SLOT_MASK = 0x3F000000
QUIC_SLOT_SHIFT = 24
# Ограничение скорости правила (1.24.0): у соединения правила с ограничением j ещё метки conntrack RULE_LIM_BASE + j
# и RULE_LIM_ANY («есть ограничение»: остальной трафик проверяется одной строкой). Ограничивает общий для обеих
# сторон «limit» nftables там, куда пакеты приходят: от клиента и из сети — и у транзитных, и у соединений
# sniproxy.py. Посредник передаёт номер ограничения в метке своих сокетов, вердикт QUIC — в метке вердикта:
# (j + 1) << RULE_LIM_SHIFT в битах RULE_LIM_MASK; цепочки rl_lab и q_lab ставят по ним метку соединения и снимают
# эти биты до маршрутизации
RULE_LIM_BASE = 64
RULE_LIM_MAX = 63                # j = 0…62
RULE_LIM_ANY = 127
RULE_LIM_MASK = 0x00FF0000
RULE_LIM_SHIFT = 16
# Сокет посредника без своей метки (к клиенту, к прокси SOCKS5, «напрямую») с номером ограничения: младшие 16 бит —
# эта служебная метка, а не 0. Цепочки вывода (rl_lab) и защита c_guard_post смотрят только на метки панели (выход,
# политика, эта): на сервере «на хосте» те же биты 0x00FF0000 занимают чужие программы — Tailscale (0x40000, 0x80000)
RULE_LIM_TAG = 0xE1F0
# Младшие 16 бит меток панели, у которых могут быть биты номера ограничения (метки сокетов посредника): выходы
# MARK_BASE + N, исходящие адреса ADDR_MARK_BASE + K (1.25.0), политики sniproxy.py, RULE_LIM_TAG. Другие метки с
# этими битами — чужие, их не трогаем
RULE_LIM_OWN = (f"{MARK_BASE:#x}-{MARK_BASE + 0xFF:#x}, {ADDR_MARK_BASE + 1:#x}-{ADDR_MARK_BASE + ADDR_MAX:#x}, "
                f"{SNIFF_OUT_BASE:#x}-{QUIC_PASS_MARK - 1:#x}, {RULE_LIM_TAG:#x}")
