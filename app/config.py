"""Настройки из переменных окружения."""
import os


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

RECONCILE_INTERVAL = int(os.environ.get("RECONCILE_INTERVAL", "10"))

# Нумерация служебных объектов
IFACE_PREFIX = "awgr"          # awgr1, awgr2 ...
TABLE_BASE = 2000              # таблица маршрутизации = 2000 + N
MARK_BASE = 0x2000             # fwmark = 0x2000 + N
RULE_PRIO_BASE = 20000         # приоритет ip rule = 20000 + N
MARK_BLOCK = 0xB10C
NFT_TABLE = "awgr"
MAX_UPSTREAMS = 200
# Правила по доменам для выходов SOCKS5 (sniproxy.py): порт на адресе сервера в туннеле, куда
# nftables перенаправляет TCP 80/443 клиентов с такими правилами
SNI_PROXY_PORT = int(os.environ.get("SNI_PROXY_PORT", "10443"))
SNIFF_MARK = 0xD000            # пакет клиента → в sniproxy.py
SNIFF_OUT_BASE = 0xD100        # соединения sniproxy.py: метка = база + номер политики клиента
