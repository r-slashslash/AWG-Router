#!/usr/bin/env bash
# AWG Router installer — a control panel for AmneziaWG.
#   curl -fsSL https://raw.githubusercontent.com/r-slashslash/AWG-Router/main/install.sh | bash
#   bash install.sh                — install or update (settings are kept)
#   bash install.sh --update       — download the latest version from GitHub and update
#   bash install.sh --reconfigure  — choose the server mode and access method again
#   bash install.sh --info         — show the panel link and password
# Non-interactive:
#   AWGR_MODE=container|host  AWGR_ACCESS=public|ssh  bash install.sh
#   if AmneziaWG is missing:   AWGR_INSTALL=container|host  AWGR_AWG_PORT=47823
set -uo pipefail

REPO="${AWGR_REPO:-r-slashslash/AWG-Router}"
BRANCH="${AWGR_BRANCH:-main}"
INSTALL_DIR="${AWGR_DIR:-/opt/awg-router}"

# Downloads the code from GitHub into $1 (settings in .env and data/ are kept).
fetch_code() {
  local tmp
  tmp="$(mktemp -d)" || return 1
  local url="${AWGR_SRC_URL:-https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH}"
  if ! curl -fsSL --retry 3 "$url" -o "$tmp/src.tgz"; then
    rm -rf "$tmp"; echo "Could not download https://github.com/$REPO" >&2; return 1
  fi
  mkdir -p "$1" && tar -xzf "$tmp/src.tgz" --strip-components=1 -C "$1"
  local rc=$?; rm -rf "$tmp"; return $rc
}

# Started from a pipe (curl | bash) or without the rest of the files — fetch them first.
{
  _src="${BASH_SOURCE[0]:-}"
  _here=""
  [ -n "$_src" ] && [ -f "$_src" ] && _here="$(cd "$(dirname "$_src")" && pwd)"
  _update=0
  for a in "$@"; do [ "$a" = "--update" ] && _update=1; done
  if [ -z "$_here" ] || [ ! -f "$_here/docker-compose.yml" ] || [ "$_update" = 1 ]; then
    [ "$(id -u)" = 0 ] || { echo "Run as root: sudo bash install.sh" >&2; exit 1; }
    for b in curl tar; do
      command -v "$b" >/dev/null || { apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq "$b" >/dev/null 2>&1; }
    done
    _target="${_here:-$INSTALL_DIR}"
    [ -f "$_target/docker-compose.yml" ] || _target="$INSTALL_DIR"
    echo "Downloading AWG Router from github.com/$REPO into $_target …"
    fetch_code "$_target" || exit 1
    _args=()
    for a in "$@"; do [ "$a" = "--update" ] || _args+=("$a"); done
    exec bash "$_target/install.sh" ${_args[@]+"${_args[@]}"} </dev/null
  fi
}

DIR="$_here"
cd "$DIR" || exit 1
ENV_FILE="$DIR/.env"
NAME=awg-router                       # panel container and helper command
IMAGE=awg-router:latest
SRV_NAME=amnezia-awg2                 # same name as AmneziaVPN uses — the app recognises it
SRV_DATA="$DIR/awg-server/data"
HOSTCONF="/etc/amnezia/amneziawg/awg0.conf"
RECONF=0; INFO_ONLY=0
for a in "$@"; do
  case "$a" in
    --reconfigure) RECONF=1 ;;
    --info) INFO_ONLY=1 ;;
  esac
done

B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; N=$'\e[0m'
step() { printf '\n%s▸ %s%s\n' "$B" "$1" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$1"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$1"; }
die()  { printf '\n%s✗ %s%s\n' "$R" "$1" "$N"; exit 1; }

envget() { [ -f "$ENV_FILE" ] && grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true; }

# Reads an answer from the terminal; without a terminal returns the default.
ask() { # $1 prompt, $2 default → REPLY
  printf '%s' "$1"
  if ! read -r REPLY 2>/dev/null </dev/tty; then REPLY=""; echo "$2"; fi
  REPLY="${REPLY:-$2}"
}

choose() { # $1 question, then options; answer number in CHOICE
  local q="$1"; shift
  local n=$# i=1
  printf '\n%s%s%s\n' "$B" "$q" "$N"
  for opt in "$@"; do printf '  %d) %s\n' "$i" "$opt"; i=$((i+1)); done
  while true; do
    ask "Enter a number [1]: " 1
    CHOICE="$REPLY"
    [[ "$CHOICE" =~ ^[0-9]+$ ]] && [ "$CHOICE" -ge 1 ] && [ "$CHOICE" -le "$n" ] && return
  done
}

port_busy() { ss -Hltnu 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]$1\$"; }

# Ports that Chrome, Firefox and Safari refuse to open (ERR_UNSAFE_PORT)
UNSAFE_PORTS=" 1 7 9 11 13 15 17 19 20 21 22 23 25 37 42 43 53 69 77 79 87 95 101 102 103 104 109 110 111 113 115 117 119 123 135 137 139 143 161 179 389 427 465 512 513 514 515 526 530 531 532 540 548 554 556 563 587 601 636 989 990 993 995 1719 1720 1723 2049 3659 4045 4190 5060 5061 6000 6566 6665 6666 6667 6668 6669 6679 6697 10080 "
unsafe_port() { [[ "$UNSAFE_PORTS" == *" $1 "* ]]; }

random_port() { # $1 min, $2 max
  local p
  for _ in $(seq 1 200); do
    p=$(( $1 + RANDOM % ($2 - $1 + 1) ))
    unsafe_port "$p" && continue
    port_busy "$p" || { echo "$p"; return; }
  done
  echo "$1"
}

public_ip() {
  local ip=""
  for u in https://api.ipify.org https://ifconfig.me/ip https://ipv4.icanhazip.com; do
    ip=$(curl -4fsS --max-time 6 "$u" 2>/dev/null | tr -d '[:space:]') && [[ "$ip" =~ ^[0-9]+(\.[0-9]+){3}$ ]] && { echo "$ip"; return; }
  done
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

print_info() {
  local url pass access port tls_line
  pass="$(envget PANEL_PASSWORD)"
  access="$(envget PANEL_ACCESS)"
  port="$(envget PANEL_PORT)"
  url=""
  [ -f "$DIR/data/status.json" ] && url=$(python3 -c "import json;print(json.load(open('$DIR/data/status.json'))['url'])" 2>/dev/null || true)
  [ -n "$url" ] || url="?"
  printf '\n%s════════════════════════════════════════════════════════%s\n' "$G" "$N"
  printf '%s  AWG Router is ready%s\n' "$B" "$N"
  printf '%s════════════════════════════════════════════════════════%s\n' "$G" "$N"
  if [ "$access" = "ssh" ]; then
    echo "  The panel is reachable only through an SSH tunnel."
    echo "  1) On your phone (Termux) or computer run:"
    printf '     %sssh -N -L %s:127.0.0.1:%s root@%s%s\n' "$C" "$port" "$port" "$(envget PUBLIC_HOST)" "$N"
    echo "  2) Keep it running and open in the browser:"
    printf '     %s%s%s\n' "$C$B" "$url" "$N"
  else
    printf '  Link:     %s%s%s\n' "$C$B" "$url" "$N"
  fi
  if [ -f "$DIR/data/panel_password.json" ]; then
    echo "  Password: changed in the panel (forgot it? run: awg-router password)"
  else
    printf '  Password: %s%s%s\n' "$B" "$pass" "$N"
  fi
  if [ -f "$DIR/data/status.json" ] && [ "$access" != "ssh" ]; then
    tls_line=$(python3 - "$DIR/data/status.json" <<'PY' 2>/dev/null
import json, sys, time
s = json.load(open(sys.argv[1])).get("tls", {})
exp = s.get("expires")
d = time.strftime("%Y-%m-%d %H:%M", time.localtime(exp)) if exp else "?"
if s.get("active") == "letsencrypt":
    print(f"Let's Encrypt certificate valid until {d}, renews automatically")
elif s.get("active") == "selfsigned":
    print("Temporary self-signed certificate (the browser will warn). Let's Encrypt: "
          + (s.get("error") or "")[:160])
PY
)
    [ -n "$tls_line" ] && printf '  %s\n' "$tls_line"
  fi
  echo "  Show this again: awg-router info"
  printf '\n'
}

if [ "$INFO_ONLY" = 1 ]; then print_info; exit 0; fi
[ "$(id -u)" = 0 ] || die "Run as root: sudo bash install.sh"

# ------------------------------------------------------------------ system
step "Checking the system"
mkdir -p "$DIR/data"; chmod 700 "$DIR/data"
APT_LOG="$DIR/data/apt.log"
APT_UPDATED=0
apt_install() {
  command -v apt-get >/dev/null || return 1
  # a fresh VM often runs unattended-upgrades for a few minutes: wait for the lock instead of failing
  [ "$APT_UPDATED" = 1 ] || {
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 update -qq >>"$APT_LOG" 2>&1; APT_UPDATED=1; }
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq "$@" >>"$APT_LOG" 2>&1
}
apt_has() { LC_ALL=C apt-cache policy "$1" 2>/dev/null | grep -q 'Candidate: [0-9]'; }
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }   # $1 >= $2
osr() { ( . /etc/os-release 2>/dev/null; eval "echo \"\${$1:-}\"" ); }       # a field of /etc/os-release

OS_ID="$(osr ID)"; OS_VER="$(osr VERSION_ID)"; OS_LIKE="$(osr ID_LIKE)"; OS_NAME="$(osr PRETTY_NAME)"
OS_NAME="${OS_NAME:-$(uname -s)}"
case "$OS_ID" in
  debian) { [ -z "$OS_VER" ] || ver_ge "$OS_VER" 11; } && ok "$OS_NAME" \
            || warn "$OS_NAME: Debian 11 or newer is supported, trying anyway" ;;
  ubuntu) ver_ge "${OS_VER:-0}" 20.04 && ok "$OS_NAME" \
            || warn "$OS_NAME: Ubuntu 20.04 or newer is supported, trying anyway" ;;
  *) if command -v apt-get >/dev/null; then warn "$OS_NAME is not tested (Debian or Ubuntu is), trying anyway"
     elif command -v docker >/dev/null; then warn "$OS_NAME: no apt, using the installed Docker as is"
     else die "Debian/Ubuntu (apt) or a preinstalled Docker is required"; fi ;;
esac

for b in curl openssl ss python3; do
  command -v "$b" >/dev/null || case "$b" in
    ss) apt_install iproute2 ;; *) apt_install "$b" ;;
  esac
done

# Binaries from GitHub releases: the names differ between buildx and compose
case "$(uname -m)" in
  x86_64|amd64)  BX_ARCH=amd64;   DC_ARCH=x86_64 ;;
  aarch64|arm64) BX_ARCH=arm64;   DC_ARCH=aarch64 ;;
  armv7l|armhf)  BX_ARCH=arm-v7;  DC_ARCH=armv7 ;;
  armv6l)        BX_ARCH=arm-v6;  DC_ARCH=armv6 ;;
  ppc64le)       BX_ARCH=ppc64le; DC_ARCH=ppc64le ;;
  riscv64)       BX_ARCH=riscv64; DC_ARCH=riscv64 ;;
  s390x)         BX_ARCH=s390x;   DC_ARCH=s390x ;;
  *)             BX_ARCH="";      DC_ARCH="" ;;
esac
PLUGINS=/usr/local/lib/docker/cli-plugins     # searched before the distro's /usr/lib and /usr/libexec

gh_latest() { # $1 owner/repo, $2 tag to use if GitHub does not answer → the latest release tag
  local u t
  u=$(curl -fsSLI -o /dev/null -w '%{url_effective}' --max-time 20 "https://github.com/$1/releases/latest" 2>/dev/null) || u=""
  t="${u##*/}"
  [[ "$t" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || t="$2"
  echo "$t"
}

gh_plugin() { # $1 owner/repo, $2 tag, $3 asset, $4 plugin file — download, check sha256, install
  local tmp sum base="https://github.com/$1/releases/download/$2"
  tmp=$(mktemp -d) || return 1
  if curl -fsSL --retry 3 --max-time 600 -o "$tmp/bin" "$base/$3" 2>/dev/null \
     && curl -fsSL --retry 3 --max-time 60 -o "$tmp/sums" "$base/checksums.txt" 2>/dev/null; then
    sum=$(awk -v f="$3" '{n=$2; sub(/^\*/, "", n)} n == f {print $1}' "$tmp/sums")
    if [ -n "$sum" ] && echo "$sum  $tmp/bin" | sha256sum -c --status 2>/dev/null; then
      install -D -m 0755 "$tmp/bin" "$PLUGINS/$4"; rm -rf "$tmp"; return 0
    fi
  fi
  rm -rf "$tmp"; return 1
}

docker_up() { docker info >/dev/null 2>&1; }
ensure_daemon() {
  docker_up && return 0
  echo "  Starting the Docker service…"
  systemctl reset-failed docker >/dev/null 2>&1 || true
  systemctl enable --now docker >/dev/null 2>&1 || service docker start >/dev/null 2>&1 || true
  for _ in $(seq 1 15); do docker_up && return 0; sleep 1; done
  systemctl restart docker >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do docker_up && return 0; sleep 1; done
  journalctl -u docker -n 20 --no-pager 2>/dev/null | sed 's/^/    /'
  die "The Docker service does not start (see the lines above; full log: journalctl -u docker)"
}

buildx_ver() { docker buildx version 2>/dev/null | awk '{v=$2; sub(/^v/, "", v); sub(/[+-].*/, "", v); print v; exit}'; }

# The panel itself always runs in a container, so Docker is needed in both modes.
# It is installed after the questions; if it is already here, it must be running to find an Amnezia container.
HAVE_DOCKER=0
if command -v docker >/dev/null; then
  HAVE_DOCKER=1; ensure_daemon
else
  ok "Docker will be installed after a few questions (the panel runs in a container in every mode)"
fi

# ------------------------------------------------------------------ AmneziaWG server
AWG_MODE="$(envget AWG_MODE)"; ACCESS="$(envget PANEL_ACCESS)"
AWG_INIT_PORT=""; INSTALL_AWG=""; AWG_PORT=""

find_amnezia() { [ "$HAVE_DOCKER" = 1 ] && docker ps --format '{{.Names}}' 2>/dev/null | grep -E '^amnezia-awg2?$' | sort -r | head -1; }
AMN="$(find_amnezia)"
if [ -z "$AMN" ] && [ "$HAVE_DOCKER" = 1 ]; then   # the container exists but is stopped — start it
  STOPPED="$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^amnezia-awg2?$' | sort -r | head -1)"
  if [ -n "$STOPPED" ]; then
    docker start "$STOPPED" >/dev/null 2>&1 && sleep 3
    AMN="$(find_amnezia)"
    [ -n "$AMN" ] && ok "Container $AMN was stopped — started it"
  fi
fi

ask_port() { # UDP port for the AmneziaWG server → AWG_PORT
  local def p
  def="$(random_port 20000 59999)"
  p="${AWGR_AWG_PORT:-}"
  while [ -z "$p" ]; do
    ask "UDP port for AmneziaWG [$def]: " "$def"
    p="$REPLY"
    if ! [[ "$p" =~ ^[0-9]+$ ]] || [ "$p" -lt 1024 ] || [ "$p" -gt 65535 ]; then
      echo "  A number from 1024 to 65535 is required"; p=""
    elif port_busy "$p"; then
      echo "  Port $p is in use, pick another"; p=""
    fi
  done
  AWG_PORT="$p"
}

ask_install() { # AmneziaWG not found: offer to install it
  local how="${AWGR_INSTALL:-}"
  if [ -z "$how" ]; then
    choose "AmneziaWG was not found on this server. Install it?" \
           "Yes, in a Docker container — like AmneziaVPN, the app will see it too (recommended)" \
           "Yes, directly on the host — a systemd service" \
           "No, exit"
    case "$CHOICE" in 1) how=container ;; 2) how=host ;; *) exit 0 ;; esac
  fi
  ask_port
  INSTALL_AWG="$how"; AWG_MODE="$how"
  [ "$how" = host ] && AWG_INIT_PORT="$AWG_PORT"
}

[ -n "${AWGR_MODE:-}" ] && AWG_MODE="$AWGR_MODE"
[ -n "${AWGR_ACCESS:-}" ] && ACCESS="$AWGR_ACCESS"
if { [ "$RECONF" = 1 ] && [ -z "${AWGR_MODE:-}" ]; } || [ -z "$AWG_MODE" ]; then
  if [ -n "$AMN" ]; then
    choose "Found an AmneziaVPN server ($AMN). What should the panel manage?" \
           "This Amnezia container (recommended)" \
           "A separate AmneziaWG server on the host"
    [ "$CHOICE" = 1 ] && AWG_MODE=container || AWG_MODE=host
    if [ "$AWG_MODE" = host ] && [ ! -f "$HOSTCONF" ]; then AWGR_INSTALL=host ask_install; fi
  elif [ -f "$HOSTCONF" ]; then
    AWG_MODE=host
  else
    ask_install
  fi
elif [ "$AWG_MODE" = container ] && [ -z "$AMN" ]; then
  warn "The AmneziaWG container was not found"
  ask_install
elif [ "$AWG_MODE" = host ] && [ ! -f "$HOSTCONF" ]; then
  warn "The AmneziaWG server on the host was not found"
  ask_install
fi

case "$INSTALL_AWG" in
  container) ok "AmneziaWG will be installed into container $SRV_NAME, UDP port $AWG_PORT" ;;
  host)      ok "AmneziaWG will be installed on the host, UDP port $AWG_PORT" ;;
  *) if [ "$AWG_MODE" = host ]; then ok "AmneziaWG server on the host: $HOSTCONF"
     else ok "Amnezia container: $AMN"; fi ;;
esac

# ------------------------------------------------------------------ panel access
if { [ "$RECONF" = 1 ] && [ -z "${AWGR_ACCESS:-}" ]; } || [ -z "$ACCESS" ]; then
  choose "How will you open the panel?" \
         "In a browser over HTTPS with a Let's Encrypt certificate (recommended)" \
         "Only through an SSH tunnel — the panel is hidden from the internet"
  [ "$CHOICE" = 1 ] && ACCESS=public || ACCESS=ssh
fi

# ------------------------------------------------------------------ settings
step "Preparing settings"
PUBLIC_HOST="$(envget PUBLIC_HOST)"
{ [ -n "$PUBLIC_HOST" ] && [ "$RECONF" = 0 ]; } || PUBLIC_HOST="$(public_ip)"
[ -n "$PUBLIC_HOST" ] || die "Could not detect the server's public IP"
ok "Public address: $PUBLIC_HOST"

PANEL_PORT="$(envget PANEL_PORT)"
# the first version listened on 8080 — move to a random 4-digit port
# browsers block some ports (6697 etc.) — pick another one
if [ -z "$PANEL_PORT" ] || [ -z "$(envget AWGR_VERSION)" ] || [ "$PANEL_PORT" = 8080 ] || unsafe_port "$PANEL_PORT"; then
  PANEL_PORT="$(random_port 2000 9999)"
fi
TLS_DOMAIN="$(envget TLS_DOMAIN)"; ACME_EMAIL="$(envget ACME_EMAIL)"
PANEL_PASSWORD="$(envget PANEL_PASSWORD)"
[ -n "$PANEL_PASSWORD" ] || PANEL_PASSWORD="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 16)"
PANEL_BASE_PATH="$(envget PANEL_BASE_PATH)"
[ -n "$PANEL_BASE_PATH" ] || PANEL_BASE_PATH="/$(openssl rand -hex 6)"

if [ "$ACCESS" = ssh ]; then PANEL_HOST=127.0.0.1; TLS_MODE=off; else PANEL_HOST=0.0.0.0; TLS_MODE=letsencrypt; fi
ok "Panel port: $PANEL_PORT"

if [ "$TLS_MODE" = letsencrypt ] && port_busy 80 && ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$NAME"; then
  warn "Port 80 is used by another program — Let's Encrypt cannot validate, a temporary certificate will be used"
fi

# ------------------------------------------------------------------ firewall
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  [ "$ACCESS" = public ] && { ufw allow "$PANEL_PORT/tcp" >/dev/null; ufw allow 80/tcp >/dev/null; }
  [ -n "$AWG_PORT" ] && ufw allow "$AWG_PORT/udp" >/dev/null
  ok "ufw rules added"
fi

# ------------------------------------------------------------------ .env
[ -f "$ENV_FILE" ] && cp "$ENV_FILE" "$ENV_FILE.bak"
umask 077
cat > "$ENV_FILE" <<EOF
# Generated by install.sh $(date '+%Y-%m-%d %H:%M')
AWGR_VERSION=2
PANEL_PASSWORD=$PANEL_PASSWORD
PANEL_PORT=$PANEL_PORT
PANEL_HOST=$PANEL_HOST
PANEL_BASE_PATH=$PANEL_BASE_PATH
PANEL_ACCESS=$ACCESS
PUBLIC_HOST=$PUBLIC_HOST
TLS_MODE=$TLS_MODE
TLS_DOMAIN=$TLS_DOMAIN
ACME_EMAIL=$ACME_EMAIL
AWG_MODE=$AWG_MODE
AWG_INIT_PORT=$AWG_INIT_PORT
UPSTREAM_BACKEND=userspace
RECONCILE_INTERVAL=10
EOF
umask 022

# ------------------------------------------------------------------ Docker
step "Docker"
if ! command -v docker >/dev/null; then
  echo "  Installing Docker…"
  apt_install docker.io || { tail -n 15 "$APT_LOG" 2>/dev/null; die "Failed to install Docker, see $APT_LOG"; }
  HAVE_DOCKER=1
fi
ensure_daemon

# Compose and buildx are kept at the latest GitHub release on every install and update
# (sha256-checked, into $PLUGINS). Distro packages are only a fallback when GitHub is unreachable:
# Debian 11/12 have only Compose v1, Debian 13 ships buildx 0.13 while Compose 2.40.2+ needs 0.17+.
plugin_latest() { # $1 label, $2 owner/repo, $3 tag if GitHub is silent, $4 asset (@TAG@ = tag), $5 plugin file, $6 installed version, $7 minimum
  local cur="$6" tag
  tag="$(gh_latest "$2" "")"
  if [ -z "$tag" ]; then
    { [ -n "$cur" ] && ver_ge "$cur" "$7"; } && return 0    # cannot check, the installed one is enough
    tag="$3"
  fi
  { [ -n "$cur" ] && ver_ge "$cur" "${tag#v}"; } && return 0
  echo "  Installing $1 ${tag#v}${cur:+ (installed: $cur)}…"
  gh_plugin "$2" "$tag" "${4//@TAG@/$tag}" "$5" && return 0
  warn "Could not download $1 ${tag#v} from GitHub"
  return 1
}
dc_ver() { docker compose version --short 2>/dev/null | sed 's/^v//; s/[+-].*//'; }

[ -n "$DC_ARCH" ] && plugin_latest "Docker Compose" docker/compose v5.6.1 \
  "docker-compose-linux-$DC_ARCH" docker-compose "$(dc_ver)" 2.0.0
if ! docker compose version >/dev/null 2>&1; then
  # Ubuntu: docker-compose-v2; Docker's own repo: docker-compose-plugin; Debian 13: docker-compose 2.x
  for p in docker-compose-v2 docker-compose-plugin; do
    apt_has "$p" && apt_install "$p" && docker compose version >/dev/null 2>&1 && break
  done
  if ! docker compose version >/dev/null 2>&1 \
     && LC_ALL=C apt-cache policy docker-compose 2>/dev/null | grep -q 'Candidate: 2\.'; then
    apt_install docker-compose || true
  fi
  docker compose version >/dev/null 2>&1 || die "Failed to install Docker Compose"
fi

BX_MIN=0.17.0
[ -n "$BX_ARCH" ] && plugin_latest "Docker buildx" docker/buildx v0.38.1 \
  "buildx-@TAG@.linux-$BX_ARCH" docker-buildx "$(buildx_ver)" "$BX_MIN"
[ -n "$(buildx_ver)" ] || apt_install docker-buildx || apt_install docker-buildx-plugin || true
bx="$(buildx_ver)"
if [ -z "$bx" ]; then warn "Docker buildx is not available — the panel is built with the classic builder"
elif ! ver_ge "$bx" "$BX_MIN"; then
  warn "Docker buildx $bx is old (an older copy in ~/.docker/cli-plugins?)"
fi
ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null), Compose $(dc_ver)${bx:+, buildx $bx}"

# ------------------------------------------------------------------ build
# Images are built by "docker build" rather than "docker compose build": it does not depend on
# the Compose/buildx version pairing. If BuildKit fails (very old engine), the classic builder is tried.
build_image() { # $1 tag, $2 context dir, $3 log (the classic attempt goes to $3.classic)
  docker build -t "$1" "$2" >"$3" 2>&1 && return 0
  [ -n "$(buildx_ver)" ] || return 1          # it already was the classic builder
  DOCKER_BUILDKIT=0 docker build -t "$1" "$2" >"$3.classic" 2>&1
}

step "Building the panel (first time takes 3–10 minutes)"
LOG="$DIR/data/build.log"
build_image "$IMAGE" "$DIR" "$LOG" &
BPID=$!
spin='|/-\'; i=0
if [ -t 1 ]; then   # spinner only on a terminal: an update from the panel writes to a log
  while kill -0 "$BPID" 2>/dev/null; do printf '\r  %s ' "${spin:i++%4:1}"; sleep 0.5; done
  printf '\r    \r'
fi
wait "$BPID" || { tail -n 25 "$LOG"; die "Build failed, see $LOG"; }
ok "Done"

# ------------------------------------------------------------------ AmneziaWG in a container
if [ "$INSTALL_AWG" = container ]; then
  step "Installing AmneziaWG into container $SRV_NAME"
  mkdir -p "$SRV_DATA"; chmod 700 "$DIR/awg-server" "$SRV_DATA"
  docker run --rm --network none -v "$SRV_DATA:/out" "$IMAGE" \
      python3 -m app.initserver --out /out --port "$AWG_PORT" >"$DIR/data/awg-init.log" 2>&1 \
    || { cat "$DIR/data/awg-init.log"; die "Failed to create the server config"; }
  build_image "$SRV_NAME" "$DIR/awg-server" "$DIR/data/awg-build.log" \
    || { tail -n 20 "$DIR/data/awg-build.log"; die "Failed to build the AmneziaWG container"; }
  if docker ps -a --format '{{.Names}}' | grep -qx "$SRV_NAME"; then
    # an old container that would not start may still hold client configs — keep it, just rename
    OLD="$SRV_NAME-old-$(date +%Y%m%d-%H%M%S)"
    docker stop "$SRV_NAME" >/dev/null 2>&1 || true
    docker update --restart no "$SRV_NAME" >/dev/null 2>&1 || true
    docker rename "$SRV_NAME" "$OLD" >/dev/null 2>&1 || die "Could not rename the old container $SRV_NAME"
    warn "The old container was kept as $OLD (stopped)"
  fi
  docker run -d --name "$SRV_NAME" --restart always --log-driver none \
      --privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE \
      -p "$AWG_PORT:$AWG_PORT/udp" -v /lib/modules:/lib/modules \
      -v "$SRV_DATA:/opt/amnezia/awg" \
      --sysctl net.ipv4.conf.all.src_valid_mark=1 \
      "$SRV_NAME" >"$DIR/data/awg-run.log" 2>&1 \
    || { cat "$DIR/data/awg-run.log"; die "Failed to start the AmneziaWG container"; }
  sleep 3
  docker ps --format '{{.Names}}' | grep -qx "$SRV_NAME" \
    || { docker logs --tail 20 "$SRV_NAME" 2>&1; die "The AmneziaWG container did not start"; }
  ok "AmneziaWG is running: container $SRV_NAME, UDP port $AWG_PORT"
fi

# ------------------------------------------------------------------ start
step "Starting"
rm -f "$DIR/data/status.json"
docker compose up -d --no-build --force-recreate >"$DIR/data/up.log" 2>&1 || { cat "$DIR/data/up.log"; die "Failed to start"; }
echo "  Waiting for start-up and the certificate (up to 5 minutes)…"
for _ in $(seq 1 300); do
  [ -f "$DIR/data/status.json" ] && break
  sleep 1
done
[ -f "$DIR/data/status.json" ] || { docker logs --tail 30 "$NAME"; die "The panel did not start"; }

# ------------------------------------------------------------------ helper command
cat > /usr/local/bin/awg-router <<EOF
#!/usr/bin/env bash
# AWG Router helper
DIR="$DIR"
case "\${1:-info}" in
  info)        bash "\$DIR/install.sh" --info ;;
  restart)     cd "\$DIR" && docker compose restart && bash "\$DIR/install.sh" --info ;;
  logs)        docker logs --tail 100 -f awg-router ;;
  update)      bash "\$DIR/install.sh" --update ;;
  reconfigure) bash "\$DIR/install.sh" --reconfigure ;;
  password)    P=\$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 16)
               sed -i "s/^PANEL_PASSWORD=.*/PANEL_PASSWORD=\$P/" "\$DIR/.env"
               rm -f "\$DIR/data/panel_password.json"
               cd "\$DIR" && docker compose up -d >/dev/null 2>&1; sleep 3; bash "\$DIR/install.sh" --info ;;
  2fa-off)     rm -f "\$DIR/data/totp.json"
               echo "Two-factor sign-in is off: the panel password alone is enough now." ;;
  uninstall)   printf 'Remove AWG Router? The AmneziaWG server and its clients stay. Type yes: '
               read -r A </dev/tty; [ "\$A" = yes ] || exit 1
               cd "\$DIR" && docker compose down
               docker compose run --rm --no-deps awg-router python3 -m app.uninstall
               docker image rm awg-router:latest >/dev/null 2>&1
               rm -f /usr/local/bin/awg-router
               echo "Done. Settings are kept in \$DIR — delete the folder to remove them too." ;;
  *) echo "awg-router info | restart | logs | password | 2fa-off | update | reconfigure | uninstall" ;;
esac
EOF
chmod 755 /usr/local/bin/awg-router

print_info
