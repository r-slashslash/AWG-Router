#!/usr/bin/env bash
# AWG Router installer — a control panel for AmneziaWG.
#   curl -fsSL https://raw.githubusercontent.com/r-slashslash/AWG-Router/main/install.sh | bash
#   bash install.sh                — install or update (settings are kept)
#   bash install.sh --update       — download the latest version from GitHub and update
#   bash install.sh --reconfigure  — choose the server mode and access method again
#   bash install.sh --info         — show the panel link and password
#   bash install.sh --install-kernel — build and load the AmneziaWG kernel module (awg-router install-kernel)
#   bash install.sh --uninstall    — remove the panel; asks whether to remove the AWG server too (awg-router uninstall)
# Non-interactive:
#   AWGR_MODE=container|host  AWGR_ACCESS=public|ssh  bash install.sh
#   if AmneziaWG is missing:   AWGR_INSTALL=container|host  AWGR_AWG_PORT=47823
#   move the Amnezia container's server to the host (same keys, port, clients): AWGR_MODE=host AWGR_MOVE=yes
#   replace the AmneziaWG server found on the host with a new one (new keys): AWGR_REPLACE=yes
#   panel port:                AWGR_PORT=4821 (empty — a random free 4-digit one)
#   panel domain:              AWGR_DOMAIN=panel.example.com (empty — by IP)
#   panel domain in client configs instead of the IP: AWGR_CLIENT_DOMAIN=yes|no
#   port 80 taken by nginx or Apache: AWGR_WEB=yes adds the Let's Encrypt validation file to it
#   build the images here instead of downloading the ready ones: AWGR_BUILD=1
#   how long to wait for a ready image before building it here: AWGR_PULL_TIMEOUT=600 (seconds)
set -uo pipefail

REPO="${AWGR_REPO:-r-slashslash/AWG-Router}"
BRANCH="${AWGR_BRANCH:-main}"
INSTALL_DIR="${AWGR_DIR:-/opt/awg-router}"

# Downloads the code from GitHub into $1 (settings in .env and data/ are kept).
# Branch main: the archive attached to the latest release (GitHub counts its downloads), checked
# against its .sha256. If github.com fails to serve it (in Russia /releases/download/ sometimes
# answers HTTP 504), the same files come through api.github.com, which redirects straight to the
# file storage. The branch archive is used only when the repository has no release yet (HTTP 404
# from github.com): a network error or a bad checksum stops here, so an update never installs
# unreleased code instead of the version it announced. Another branch or AWGR_SRC_URL: just that.
fetch_code() {
  local tmp url sum_url ok=0 code sum assets api_url api_sum_url urls=()
  local accept="Accept: application/octet-stream"
  tmp="$(mktemp -d)" || return 1
  if [ -z "${AWGR_SRC_URL:-}" ] && [ "$BRANCH" = main ]; then
    url="https://github.com/$REPO/releases/latest/download/awg-router.tar.gz"
    sum_url="$url.sha256"
    code=$(curl -sSL --retry 3 --max-time 300 -w '%{http_code}' -o "$tmp/src.tgz" "$url" 2>/dev/null) || true
    if [ "$code" != 200 ] && [ "$code" != 404 ]; then
      echo "github.com did not serve the release (HTTP ${code:-000}), trying api.github.com …" >&2
      # "name file-url" for each file of the release; grep -o makes it work whatever the JSON layout
      assets=$(curl -fsSL --retry 2 --max-time 30 "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
        | grep -oE '"(url|name)": *"[^"]*"' \
        | awk -F'"' '$2 == "url" && $4 ~ /\/releases\/assets\/[0-9]+$/ { u = $4; next }
                     $2 == "name" && u != "" { print $4, u; u = "" }') || true
      api_url=$(printf '%s\n' "$assets" | awk '$1 == "awg-router.tar.gz" { print $2; exit }')
      api_sum_url=$(printf '%s\n' "$assets" | awk '$1 == "awg-router.tar.gz.sha256" { print $2; exit }')
      # only 200 counts: a 404 here must not be taken for "no release yet" and install the branch
      if [ -n "$api_url" ] && [ -n "$api_sum_url" ] && [ "$(curl -sSL --retry 3 --max-time 300 -H "$accept" \
           -w '%{http_code}' -o "$tmp/src.tgz" "$api_url" 2>/dev/null)" = 200 ]; then
        code=200; sum_url="$api_sum_url"
      fi
    fi
    if [ "$code" = 200 ]; then
      sum=$(curl -fsSL --retry 3 --max-time 60 -H "$accept" "$sum_url" 2>/dev/null | awk '{print $1; exit}')
      if [ -z "$sum" ] || ! echo "$sum  $tmp/src.tgz" | sha256sum -c --status 2>/dev/null \
         || ! tar -tzf "$tmp/src.tgz" >/dev/null 2>&1; then
        rm -rf "$tmp"; echo "The release archive failed its checksum check. Try again later." >&2; return 1
      fi
      ok=1
    elif [ "$code" != 404 ]; then
      rm -rf "$tmp"; echo "Could not download the latest release (HTTP ${code:-000}). Try again later." >&2; return 1
    fi
  fi
  if [ "$ok" != 1 ]; then
    if [ -n "${AWGR_SRC_URL:-}" ]; then urls=("$AWGR_SRC_URL")
    else urls=("https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH"); fi
    for url in "${urls[@]}"; do
      if curl -fsSL --retry 3 --max-time 300 "$url" -o "$tmp/src.tgz" 2>/dev/null \
         && tar -tzf "$tmp/src.tgz" >/dev/null 2>&1; then
        ok=1; break
      fi
    done
  fi
  if [ "$ok" != 1 ]; then
    rm -rf "$tmp"; echo "Could not download https://github.com/$REPO" >&2; return 1
  fi
  # IMAGES of an earlier release must not outlive it: a branch archive has none, so it is built here
  mkdir -p "$1" && rm -f "$1/IMAGES" && tar -xzf "$tmp/src.tgz" --strip-components=1 -C "$1"
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
HOST_UNIT="/etc/systemd/system/awg-quick@.service"   # written by the panel (system.UNIT_TEXT)
HOST_BIN="/usr/local/bin"                            # the panel's awg, awg-quick, amneziawg-go
RECONF=0; INFO_ONLY=0; KERNEL_ONLY=0; UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --reconfigure) RECONF=1 ;;
    --info) INFO_ONLY=1 ;;
    --install-kernel) KERNEL_ONLY=1 ;;
    --uninstall) UNINSTALL=1 ;;
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

# grep reads the whole stream: with pipefail an early exit (grep -q) would make awk die of SIGPIPE
# and hide a busy port behind a failed pipeline.
port_busy() { ss -Hltnu 2>/dev/null | awk '{print $5}' | grep -E "[:.]$1\$" >/dev/null; }

# Ports that Chrome, Firefox and Safari refuse to open (ERR_UNSAFE_PORT)
UNSAFE_PORTS=" 1 7 9 11 13 15 17 19 20 21 22 23 25 37 42 43 53 69 77 79 87 95 101 102 103 104 109 110 111 113 115 117 119 123 135 137 139 143 161 179 389 427 465 512 513 514 515 526 530 531 532 540 548 554 556 563 587 601 636 989 990 993 995 1719 1720 1723 2049 3659 4045 4190 5060 5061 6000 6566 6665 6666 6667 6668 6669 6679 6697 10080 "
unsafe_port() { [[ "$UNSAFE_PORTS" == *" $1 "* ]]; }

# Why a port can't be the panel's (nothing — it can): $1 port, $2 the panel's current port, which is
# "in use" by the panel itself and stays allowed on --reconfigure
panel_port_problem() {
  local p="$1"
  if ! [[ "$p" =~ ^[0-9]+$ ]] || [ "$p" -lt 1024 ] || [ "$p" -gt 65535 ]; then
    echo "A number from 1024 to 65535 is required"
  elif unsafe_port "$p"; then
    echo "Browsers refuse to open port $p, pick another"
  elif [ "$p" = 10443 ]; then
    echo "Port 10443 is used by the panel for domain rules, pick another"
  elif [ "$p" != "${2:-}" ] && port_busy "$p"; then
    echo "Port $p is in use, pick another"
  fi
}

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
err = s.get("error") or ""
if isinstance(err, dict):   # a message for the panel: {"$t": key, "p": params}
    p = err.get("p") or {}
    err = (f"port 80 is used by {p.get('server')} — System → Set up validation through the web server"
           if err.get("$t") == "tls.port80" else "see System in the panel")
if s.get("active") == "letsencrypt":
    print(f"Let's Encrypt certificate valid until {d}, renews automatically")
elif s.get("active") == "custom":
    print(f"Own certificate valid until {d}")
elif s.get("active") == "selfsigned":
    print("Temporary self-signed certificate (the browser will warn). Let's Encrypt: " + str(err)[:160])
PY
)
    [ -n "$tls_line" ] && printf '  %s\n' "$tls_line"
  fi
  echo "  Show this again: awg-router info"
  printf '\n'
}

# ------------------------------------------------------------------ kernel module
# The AmneziaWG kernel module (recommended) encrypts inside the kernel and uses far fewer system resources
# than amneziawg-go. A new install asks for it when the server fits (kernel_fit); `awg-router install-kernel`
# and the panel's "Install the module" button run install_kernel too. With the module the AWG server moves
# to it by itself after a restart (awg-quick prefers the kernel), and tunnels to exits follow the server.
# Only a 3.x module speaks AWG 3.1 — an older one leaves the server without awg0, so it is removed again.
# Any failure leaves the server on amneziawg-go: during an install (KERNEL_SOFT=1) it is a warning, not a stop.
AWG_SYS="${AWGR_SYS:-/sys}"; OS_RELEASE="${AWGR_OS_RELEASE:-/etc/os-release}"
MODLOAD="${AWGR_MODLOAD:-/etc/modules-load.d/amneziawg.conf}"
# Written by the panel when the AWG server didn't come up on the module (it switched the server to
# amneziawg-go): without it the next `ip link add … type amneziawg` would load the module again.
MODBLOCK="${AWGR_MODBLOCK:-/etc/modprobe.d/awg-router-amneziawg.conf}"
PANIC_CONF="${AWGR_PANIC_CONF:-/etc/sysctl.d/90-awg-router-panic.conf}"
kfail() { [ "${KERNEL_SOFT:-0}" = 1 ] || die "$1"; warn "$1"; }
# Loaded at boot, before Docker starts the AWG container: otherwise the module comes only when awg-quick asks
# for it, and a server whose container starts first could quietly come up on amneziawg-go.
module_autoload() { mkdir -p "$(dirname "$MODLOAD")" && echo amneziawg > "$MODLOAD"; }
KERNEL_MIN=3
module_version() { # loaded module: /sys, or modinfo for builds without a version file
  [ -d "$AWG_SYS/module/amneziawg" ] || return 0
  cat "$AWG_SYS/module/amneziawg/version" 2>/dev/null || modinfo -F version amneziawg 2>/dev/null || true
}
module_new_enough() { local m="${1%%.*}"; [[ "$m" =~ ^[0-9]+$ ]] && [ "$m" -ge "$KERNEL_MIN" ]; }

# Can this server build and load the module? 0 — yes; otherwise KERNEL_WHY says why not.
kernel_fit() {
  local virt id ver
  KERNEL_WHY=""
  virt=$(systemd-detect-virt -c 2>/dev/null || true)
  if [ -n "$virt" ] && [ "$virt" != none ]; then
    KERNEL_WHY="This server is a container ($virt): it can't load kernel modules."; return 1
  fi
  case "$(uname -m)" in
    x86_64|aarch64) ;;
    *) KERNEL_WHY="Only x86_64 and aarch64 are supported (this is $(uname -m))."; return 1 ;;
  esac
  id=$(. "$OS_RELEASE" 2>/dev/null && echo "${ID:-}"); ver=$(. "$OS_RELEASE" 2>/dev/null && echo "${VERSION_ID:-0}")
  case "$id" in
    ubuntu) [ "${ver%%.*}" -ge 22 ] 2>/dev/null || { KERNEL_WHY="Ubuntu 22.04 or newer is needed (this is $ver)."; return 1; } ;;
    debian) [ "${ver%%.*}" -ge 12 ] 2>/dev/null || { KERNEL_WHY="Debian 12 or newer is needed (this is $ver)."; return 1; } ;;
    *) KERNEL_WHY="Only Ubuntu and Debian are supported (this is ${id:-unknown}). To build the module by hand: https://github.com/amnezia-vpn/amneziawg-linux-kernel-module"; return 1 ;;
  esac
}

# A crash in a kernel module takes the whole kernel down: with kernel.panic the server reboots by itself
# instead of hanging until someone resets it at the hosting provider. An own setting is left alone.
kernel_panic_reboot() {
  [ "$(sysctl -n kernel.panic 2>/dev/null || echo 1)" = 0 ] || return 0
  mkdir -p "$(dirname "$PANIC_CONF")" && echo "kernel.panic = 10" > "$PANIC_CONF"
  sysctl -q -w kernel.panic=10 2>/dev/null || true
}

# The Amnezia PPA on Debian: the key is the one Launchpad says signs the PPA (full fingerprint, not a
# short id), fetched from the Ubuntu keyserver and checked before apt trusts it.
amnezia_ppa_debian() {
  local fp tmp key=/usr/share/keyrings/amnezia-ppa.gpg src=https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu
  fp=$(curl -fsS --max-time 30 https://api.launchpad.net/1.0/~amnezia/+archive/ubuntu/ppa 2>/dev/null \
       | grep -o '"signing_key_fingerprint": *"[0-9A-F]*"' | grep -o '[0-9A-F]\{40\}' | head -1)
  [ -n "$fp" ] || return 1
  tmp=$(mktemp -d)
  if ! curl -fsS --max-time 30 "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x$fp" -o "$tmp/key.asc" \
     || ! gpg --batch --quiet --dearmor -o "$tmp/key.gpg" "$tmp/key.asc" \
     || ! gpg --batch --show-keys --with-colons "$tmp/key.gpg" 2>/dev/null | grep -q "^fpr:::::::::$fp:"; then
    rm -rf "$tmp"; return 1
  fi
  install -m 0644 "$tmp/key.gpg" "$key"; rm -rf "$tmp"
  # the source package is the same for every release; deb-src lets DKMS fetch what it needs
  printf 'deb [signed-by=%s] %s focal main\ndeb-src [signed-by=%s] %s focal main\n' "$key" "$src" "$key" "$src" \
    > /etc/apt/sources.list.d/amnezia-ppa.list
}

install_kernel() {
  step "AmneziaWG kernel module"
  local v id pkg
  rm -f "$MODBLOCK"          # the panel switched the module off after a failure: trying again means allowing it
  v=$(module_version)
  if [ -n "$v" ] && module_new_enough "$v"; then
    ok "Already loaded: version $v"
    module_autoload; kernel_panic_reboot
    kernel_next; return 0
  fi
  kernel_fit || { kfail "$KERNEL_WHY The AWG server keeps using amneziawg-go."; return 1; }
  id=$(. "$OS_RELEASE" 2>/dev/null && echo "${ID:-}")
  [ -n "$v" ] && warn "Module $v is loaded: it is older than $KERNEL_MIN.x and doesn't speak AWG 3.1 — it will be replaced."
  if command -v mokutil >/dev/null && mokutil --sb-state 2>/dev/null | grep -qi enabled; then
    warn "Secure Boot is on: a module built here won't load unless you enroll a signing key (mokutil)."
  fi
  echo "  The module is built for kernel $(uname -r) from the Amnezia PPA; this takes a few minutes."
  if [ "${KERNEL_SOFT:-0}" != 1 ]; then    # during an install the answer was the engine question
    ask "Continue? [y/N]: " "${AWGR_YES:-n}"
    [[ "$REPLY" =~ ^[Yy] ]] || die "Cancelled: nothing was changed."
  fi
  export DEBIAN_FRONTEND=noninteractive    # a fresh VM may run unattended-upgrades: wait for the apt lock
  apt-get update -qq -o DPkg::Lock::Timeout=300 >/dev/null || { kfail "apt-get update failed. The AWG server keeps using amneziawg-go."; return 1; }
  apt-get install -y -qq "linux-headers-$(uname -r)" dkms gnupg curl -o DPkg::Lock::Timeout=300 >/dev/null \
    || { kfail "Could not install the kernel headers for $(uname -r) (a custom kernel?). The AWG server keeps using amneziawg-go."; return 1; }
  if [ "$id" = ubuntu ]; then
    apt-get install -y -qq software-properties-common python3-launchpadlib -o DPkg::Lock::Timeout=300 >/dev/null \
      && add-apt-repository -y ppa:amnezia/ppa >/dev/null \
      || { kfail "Could not add ppa:amnezia/ppa (Launchpad unreachable?). The AWG server keeps using amneziawg-go."; return 1; }
  else
    amnezia_ppa_debian \
      || { kfail "Could not add the Amnezia repository (Launchpad or the key server is unreachable). The AWG server keeps using amneziawg-go."; return 1; }
  fi
  apt-get update -qq -o DPkg::Lock::Timeout=300 >/dev/null || { kfail "apt-get update failed. The AWG server keeps using amneziawg-go."; return 1; }
  # only the module: the panel brings its own awg and awg-quick, and the AWG server has its own
  pkg=amneziawg-dkms; apt-cache show "$pkg" >/dev/null 2>&1 || pkg=amneziawg
  echo "  Building the module ($pkg) …"
  if ! apt-get install -y -qq "$pkg" -o DPkg::Lock::Timeout=300 >/dev/null 2>&1; then
    apt-get remove -y -qq "$pkg" -o DPkg::Lock::Timeout=300 >/dev/null 2>&1   # a failed DKMS build would retry on every kernel update
    kfail "The module did not build for kernel $(uname -r): the Amnezia PPA may not support this kernel yet (details: /var/lib/dkms/amneziawg/*/build/make.log). Nothing changed — the AWG server keeps using amneziawg-go."
    return 1
  fi
  [ -n "$v" ] && rmmod amneziawg 2>/dev/null       # the old one goes if nothing uses it
  if ! modprobe amneziawg 2>/dev/null; then
    apt-get remove -y -qq "$pkg" -o DPkg::Lock::Timeout=300 >/dev/null 2>&1
    kfail "The module was built but doesn't load (Secure Boot?) — removed again. The AWG server keeps using amneziawg-go."
    return 1
  fi
  v=$(module_version)
  if [ -z "$v" ]; then
    warn "The module is loaded, but its version can't be read."
  elif ! module_new_enough "$v"; then
    local file; file=$(modinfo -F version amneziawg 2>/dev/null || true)
    if [ -n "$file" ] && module_new_enough "$file"; then
      warn "Version $file is installed, but the old $v is still in use: reboot the server to switch to it."
    else
      rmmod amneziawg 2>/dev/null; apt-get remove -y -qq "$pkg" -o DPkg::Lock::Timeout=300 >/dev/null 2>&1
      kfail "The PPA gave module $v, which doesn't speak AWG 3.1 ($KERNEL_MIN.x is needed) — removed again so the server keeps working."
      return 1
    fi
  fi
  ok "Kernel module loaded: version ${v:-?}"
  module_autoload && ok "Loaded at boot too ($MODLOAD)"
  kernel_panic_reboot
  kernel_next
}

kernel_next() {
  [ "${KERNEL_NEW_SERVER:-0}" = 1 ] && return 0     # the server is created after this, right on the module
  echo "  Next: the AWG server moves to the module after a restart — in the panel, Server → Restart the AWG server"
  echo "  (clients drop for a few seconds); tunnels to exits follow it."
  echo "  To go back to amneziawg-go: apt remove amneziawg-dkms && rm -f $MODLOAD, then reboot the server."
}

if [ "$INFO_ONLY" = 1 ]; then print_info; exit 0; fi
[ "$(id -u)" = 0 ] || die "Run as root: sudo bash install.sh"
if [ "$KERNEL_ONLY" = 1 ]; then install_kernel; exit $?; fi

# ------------------------------------------------------------------ the AWG server on the host
# Set aside, not deleted: the service is stopped and the config folder renamed, so the server can be put
# back by hand, while the installer and the panel see no server on the host any more.
retire_host_server() {
  local d bak; d="$(dirname "$HOSTCONF")"; bak="$d.removed-$(date +%Y%m%d-%H%M%S)"
  systemctl disable --now awg-quick@awg0 >/dev/null 2>&1
  mv "$d" "$bak" || die "Could not move $d aside"
  ok "The old AmneziaWG server is stopped; its config is kept in $bak"
}
# The service file and programs the panel put on the host — only if the service file is the panel's own,
# so an AmneziaWG installed some other way is left alone.
remove_host_runtime() {
  grep -q "(AWG Router)" "$HOST_UNIT" 2>/dev/null || return 0
  rm -f "$HOST_UNIT" "$HOST_BIN/awg" "$HOST_BIN/awg-quick" "$HOST_BIN/amneziawg-go"
  systemctl daemon-reload >/dev/null 2>&1
  ok "Removed the AmneziaWG programs and service file the panel had installed"
}

# ------------------------------------------------------------------ uninstall
# The AWG server is asked about separately: the one this script put into a container keeps its keys and
# clients in $SRV_DATA, inside $DIR, so "delete the folder" would silently delete the server as well.
our_container() { # $1 container: was it made by this script (its config folder is $SRV_DATA)?
  docker inspect -f '{{range .Mounts}}{{println .Source}}{{end}}' "$1" 2>/dev/null | grep -qx "$SRV_DATA"
}
uninstall() {
  local amn srv="" A
  amn="$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^amnezia-awg2?$' | sort -r | head -1)"
  if [ -n "$amn" ] && our_container "$amn"; then srv=container
  elif [ "$(envget AWG_MODE)" = host ] && [ -f "$HOSTCONF" ]; then srv=host
  fi
  ask "Remove AWG Router? Type yes: " ""
  [ "$REPLY" = yes ] || die "Cancelled: nothing was changed."
  local drop=0
  if [ -n "$srv" ]; then
    if [ "$srv" = container ]; then where="container $amn"; else where="the host ($HOSTCONF)"; fi
    choose "The AmneziaWG server in $where — what should happen to it?" \
           "Keep it: clients stay connected (recommended)" \
           "Remove it too: all its clients lose the connection"
    [ "$CHOICE" = 2 ] && drop=1
  elif [ -n "$amn" ]; then
    ok "Container $amn belongs to the AmneziaVPN app and stays (remove it there if needed)"
  fi
  cd "$DIR" || exit 1
  docker compose down >/dev/null 2>&1
  docker compose run --rm --no-deps awg-router python3 -m app.uninstall
  if [ "$drop" = 1 ] && [ "$srv" = container ]; then
    local img; img="$(docker inspect -f '{{.Image}}' "$amn" 2>/dev/null)"
    docker rm -f "$amn" >/dev/null 2>&1 && ok "Container $amn removed"
    [ -n "$img" ] && docker image rm "$img" >/dev/null 2>&1
  elif [ "$drop" = 1 ]; then
    retire_host_server
    remove_host_runtime
  fi
  local i; i="$(docker image inspect -f '{{.Id}}' "$IMAGE" 2>/dev/null)"
  [ -n "$i" ] && docker image rm -f "$i" >/dev/null 2>&1
  rm -f /usr/local/bin/awg-router
  if [ "$srv" = container ] && [ "$drop" = 0 ]; then
    echo "Done. The AmneziaWG server keeps running, and its keys and clients live in $SRV_DATA:"
    echo "do not delete $DIR while the server is in use. Panel settings are in $DIR/data."
  elif [ "$srv" = host ] && [ "$drop" = 0 ]; then
    echo "Done. The AmneziaWG server keeps running on the host ($(dirname "$HOSTCONF")): a new install picks it"
    echo "up again and asks whether to keep it. Panel settings are kept in $DIR — delete the folder to remove them too."
  else
    echo "Done. Settings are kept in $DIR — delete the folder to remove them too."
  fi
}
if [ "$UNINSTALL" = 1 ]; then uninstall; exit $?; fi

# ------------------------------------------------------------------ system
step "Checking the system"
mkdir -p "$DIR/data"; chmod 700 "$DIR/data"
APT_LOG="$DIR/data/apt.log"
APT_UPDATED=0
apt_update() {
  command -v apt-get >/dev/null || return 1
  # a fresh VM often runs unattended-upgrades for a few minutes: wait for the lock instead of failing
  [ "$APT_UPDATED" = 1 ] || {
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 update -qq >>"$APT_LOG" 2>&1; APT_UPDATED=1; }
}
apt_install() {
  apt_update || return 1
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

# Speed limits shape incoming traffic (client upload, download from an exit) through an ifb device.
# Cloud kernels (aws, azure, gcp, oracle…) often ship ifb only in linux-modules-extra: install it for
# the running kernel and, through the flavour's meta package, for the kernels that come later.
# Without ifb the panel says so and still limits download to clients and upload to exits.
ifb_ok() { modprobe -nq ifb 2>/dev/null || modinfo ifb >/dev/null 2>&1 || [ -d /sys/module/ifb ]; }
ensure_ifb() {
  ifb_ok && return 0
  local kr flavour pkgs=()
  kr="$(uname -r)"; flavour="${kr##*-}"
  apt_update || return 1
  apt_has "linux-modules-extra-$kr" && pkgs+=("linux-modules-extra-$kr")
  [ "$flavour" != "$kr" ] && apt_has "linux-modules-extra-$flavour" && pkgs+=("linux-modules-extra-$flavour")
  [ "${#pkgs[@]}" -gt 0 ] && apt_install "${pkgs[@]}" && ifb_ok
}
if ensure_ifb; then ok "Kernel module ifb (speed limits)"
else warn "Kernel module ifb is not available: client upload and exit download speed limits will not work"; fi

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
# A container without a config is no server: its folder was deleted (the server installed by this script
# keeps its config in $SRV_DATA, so removing $DIR removes it). It still holds the UDP port and the name, so
# it is stopped and kept under another name, and a new server is offered below.
BROKEN=""
if [ -n "$AMN" ] && ! docker exec "$AMN" sh -c 'ls /opt/amnezia/awg/*.conf' >/dev/null 2>&1; then
  BROKEN="$AMN"; AMN=""
  warn "Container $BROKEN has no AmneziaWG config in /opt/amnezia/awg (its folder was deleted?): there is no server to manage"
fi
retire_broken() { # stop the empty container and keep it under another name: frees the port and the name
  [ -n "$BROKEN" ] || return 0
  local old; old="$BROKEN-empty-$(date +%Y%m%d-%H%M%S)"
  docker update --restart no "$BROKEN" >/dev/null 2>&1
  docker stop "$BROKEN" >/dev/null 2>&1
  docker rename "$BROKEN" "$old" >/dev/null 2>&1 || die "Could not rename the empty container $BROKEN"
  ok "The empty container is stopped and kept as $old (docker rm $old removes it)"
  BROKEN=""
}
MOVE_FROM=""

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
    if [ "${REPLACE_HOST:-0}" = 1 ]; then    # nothing is changed until the answer
      choose "Where should the new AmneziaWG server go?" \
             "In a Docker container — like AmneziaVPN, the app will see it too (recommended)" \
             "Directly on the host — a systemd service" \
             "Cancel: keep the old server and exit"
    else
      choose "AmneziaWG was not found on this server. Install it?" \
             "Yes, in a Docker container — like AmneziaVPN, the app will see it too (recommended)" \
             "Yes, directly on the host — a systemd service" \
             "No, exit"
    fi
    case "$CHOICE" in 1) how=container ;; 2) how=host ;; *) exit 0 ;; esac
  fi
  retire_broken
  if [ "${REPLACE_HOST:-0}" = 1 ]; then retire_host_server; REPLACE_HOST=0; fi   # frees its UDP port
  ask_port
  INSTALL_AWG="$how"; AWG_MODE="$how"
  [ "$how" = host ] && AWG_INIT_PORT="$AWG_PORT"
}

[ -n "${AWGR_MODE:-}" ] && AWG_MODE="$AWGR_MODE"
[ -n "${AWGR_ACCESS:-}" ] && ACCESS="$AWGR_ACCESS"
if { [ "$RECONF" = 1 ] && [ -z "${AWGR_MODE:-}" ]; } || [ -z "$AWG_MODE" ]; then
  if [ -n "$AMN" ] && [ -f "$HOSTCONF" ]; then
    choose "Found an AmneziaVPN server ($AMN). What should the panel manage?" \
           "This Amnezia container (recommended)" \
           "The AmneziaWG server on the host ($HOSTCONF)"
    [ "$CHOICE" = 1 ] && AWG_MODE=container || AWG_MODE=host
  elif [ -n "$AMN" ]; then
    choose "Found an AmneziaVPN server ($AMN). What should the panel manage?" \
           "This Amnezia container (recommended)" \
           "Move this server to the host: same keys, port and clients, client configs keep working; the container is stopped and kept" \
           "A new AmneziaWG server on the host: new keys, clients need new configs"
    case "$CHOICE" in
      1) AWG_MODE=container ;;
      2) AWG_MODE=host; MOVE_FROM="$AMN" ;;
      *) AWG_MODE=host; AWGR_INSTALL=host ask_install ;;
    esac
  elif [ -f "$HOSTCONF" ]; then
    if [[ "${AWGR_REPLACE:-}" =~ ^[Yy] ]]; then
      CHOICE=2
    else
      choose "Found an AmneziaWG server on the host ($HOSTCONF). What should the panel manage?" \
             "This server (recommended)" \
             "A new AmneziaWG server instead: new keys, so clients need new configs; the old one is stopped and its config kept"
    fi
    if [ "$CHOICE" = 1 ]; then AWG_MODE=host; else REPLACE_HOST=1; ask_install; fi
  else
    ask_install
  fi
elif [ "$AWG_MODE" = container ] && [ -z "$AMN" ]; then
  [ -n "$BROKEN" ] || warn "The AmneziaWG container was not found"
  ask_install
elif [ "$AWG_MODE" = host ] && [ ! -f "$HOSTCONF" ] && [ -n "$AMN" ] && [[ "${AWGR_MOVE:-}" =~ ^[Yy] ]]; then
  MOVE_FROM="$AMN"
elif [ "$AWG_MODE" = host ] && [ ! -f "$HOSTCONF" ]; then
  warn "The AmneziaWG server on the host was not found"
  ask_install
fi
retire_broken     # an empty container is no use in any mode, but would keep its port and the name

case "$INSTALL_AWG" in
  container) ok "AmneziaWG will be installed into container $SRV_NAME, UDP port $AWG_PORT" ;;
  host)      ok "AmneziaWG will be installed on the host, UDP port $AWG_PORT" ;;
  *) if [ -n "$MOVE_FROM" ]; then ok "The AmneziaWG server will move from container $MOVE_FROM to the host"
     elif [ "$AWG_MODE" = host ]; then ok "AmneziaWG server on the host: $HOSTCONF"
     else ok "Amnezia container: $AMN"; fi ;;
esac

# ------------------------------------------------------------------ panel access
ASK_DOMAIN=0
if { [ "$RECONF" = 1 ] && [ -z "${AWGR_ACCESS:-}" ]; } || [ -z "$ACCESS" ]; then
  choose "How will you open the panel?" \
         "In a browser over HTTPS with a Let's Encrypt certificate (recommended)" \
         "Only through an SSH tunnel — the panel is hidden from the internet"
  [ "$CHOICE" = 1 ] && ACCESS=public || ACCESS=ssh
  ASK_DOMAIN=1
fi
[ -z "$(envget PANEL_ACCESS)" ] && ASK_DOMAIN=1    # a new install

# ------------------------------------------------------------------ AmneziaWG engine
# A new install or reconfigure (never an update) on a server that can take the module: the kernel module is
# recommended. AWGR_ENGINE=kernel|go answers without the question; without a terminal — the module.
WANT_KERNEL=0
if [ "$RECONF" = 1 ] || [ -z "$(envget PANEL_ACCESS)" ]; then
  KV=$(module_version)
  if [ -n "$KV" ] && module_new_enough "$KV"; then
    :                                               # already on the module
  elif [ "${AWGR_ENGINE:-}" = go ]; then
    :
  elif [ "${AWGR_ENGINE:-}" = kernel ]; then
    WANT_KERNEL=1
  elif kernel_fit; then
    choose "Which AmneziaWG engine should the server use?" \
           "The Linux kernel module (recommended)" \
           "amneziawg-go, a regular program"
    [ "$CHOICE" = 1 ] && WANT_KERNEL=1
  fi
fi

# ------------------------------------------------------------------ settings
step "Preparing settings"
# PUBLIC_HOST is the address in client configs: the server's IP or a domain.
# SERVER_IP is always the IP: the domain check compares DNS answers with it.
is_ipv4() { [[ "$1" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; }
PUBLIC_HOST="$(envget PUBLIC_HOST)"
if [ -n "$PUBLIC_HOST" ] && is_ipv4 "$PUBLIC_HOST" && [ "$RECONF" = 0 ]; then
  SERVER_IP="$PUBLIC_HOST"
else
  SERVER_IP="$(public_ip)"
  [ -n "$SERVER_IP" ] || die "Could not detect the server's public IP"
fi
{ [ -z "$PUBLIC_HOST" ] || is_ipv4 "$PUBLIC_HOST"; } && PUBLIC_HOST="$SERVER_IP"
ok "Public address: $SERVER_IP"

PANEL_PORT="$(envget PANEL_PORT)"
CUR_PORT="$PANEL_PORT"
# the first version listened on 8080 — move to a random 4-digit port
# browsers block some ports (6697 etc.) — pick another one
if [ -z "$PANEL_PORT" ] || [ -z "$(envget AWGR_VERSION)" ] || [ "$PANEL_PORT" = 8080 ] || unsafe_port "$PANEL_PORT"; then
  PANEL_PORT="$(random_port 2000 9999)"
fi
# Asked on a new install and with --reconfigure (Enter — the random one above, or the current one);
# an update keeps the port. Without a terminal: AWGR_PORT, or the default.
if [ -z "$CUR_PORT" ] || [ "$RECONF" = 1 ]; then
  if [ -n "${AWGR_PORT:-}" ]; then
    why="$(panel_port_problem "$AWGR_PORT" "$CUR_PORT")"
    [ -z "$why" ] || die "AWGR_PORT=$AWGR_PORT: $why"
    PANEL_PORT="$AWGR_PORT"
  else
    def="$PANEL_PORT"
    while true; do
      ask "Panel port [$def]: " "$def"
      why="$(panel_port_problem "$REPLY" "$CUR_PORT")"
      [ -z "$why" ] && break
      echo "  $why"
    done
    PANEL_PORT="$REPLY"
  fi
fi
TLS_DOMAIN="$(envget TLS_DOMAIN)"; ACME_EMAIL="$(envget ACME_EMAIL)"
PANEL_PASSWORD="$(envget PANEL_PASSWORD)"
[ -n "$PANEL_PASSWORD" ] || PANEL_PASSWORD="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 16)"
PANEL_BASE_PATH="$(envget PANEL_BASE_PATH)"
[ -n "$PANEL_BASE_PATH" ] || PANEL_BASE_PATH="/$(openssl rand -hex 6)"

if [ "$ACCESS" = ssh ]; then PANEL_HOST=127.0.0.1; TLS_MODE=off; else PANEL_HOST=0.0.0.0; TLS_MODE=letsencrypt; fi
# Values set by hand in .env stay while the access method does: another listen address, selfsigned, or
# TLS off behind a reverse proxy. An .env of the first version (no AWGR_VERSION) is migrated as before.
if [ "$ACCESS" = public ] && [ "$(envget PANEL_ACCESS)" = public ] && [ -n "$(envget AWGR_VERSION)" ]; then
  old="$(envget TLS_MODE)"; [[ "$old" =~ ^(selfsigned|off)$ ]] && TLS_MODE="$old"
  old="$(envget PANEL_HOST)"; [ -n "$old" ] && [[ "$old" != 127.* ]] && PANEL_HOST="$old"
fi
RECONCILE_INTERVAL="$(envget RECONCILE_INTERVAL)"
[[ "$RECONCILE_INTERVAL" =~ ^[0-9]+$ ]] && [ "$RECONCILE_INTERVAL" -ge 1 ] || RECONCILE_INTERVAL=10
ok "Panel port: $PANEL_PORT"

# Panel domain: asked on a new install and with --reconfigure; Enter — the panel opens by IP.
# Kept by the panel in data/tls.json (System → Domain and certificate changes it too).
cur_domain() {
  local d=""
  [ -f "$DIR/data/tls.json" ] && d=$(sed -n 's/.*"domain": *"\([^"]*\)".*/\1/p' "$DIR/data/tls.json" | head -1)
  [ -f "$DIR/data/tls.json" ] && grep -q '"domain"' "$DIR/data/tls.json" || d="$TLS_DOMAIN"
  echo "$d"
}
valid_domain() { [[ "$1" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$ ]]; }
PANEL_DOMAIN="$(cur_domain)"; SET_DOMAIN=0
if [ "$ACCESS" = public ] && [ -n "${AWGR_DOMAIN+x}" ]; then
  PANEL_DOMAIN="$(echo "$AWGR_DOMAIN" | tr 'A-Z' 'a-z')"; SET_DOMAIN=1
elif [ "$ACCESS" = public ] && [ "$ASK_DOMAIN" = 1 ]; then
  printf '\n%sPanel domain%s — only if you have one and it points to this server (an A record).\n' "$B" "$N"
  while true; do
    if [ -n "$PANEL_DOMAIN" ]; then
      ask "Domain (Enter — keep $PANEL_DOMAIN, type ip — open by IP $SERVER_IP): " "$PANEL_DOMAIN"
    else
      ask "Domain (Enter — open the panel by IP $SERVER_IP): " ""
    fi
    d="$(echo "$REPLY" | tr 'A-Z' 'a-z' | tr -d '[:space:]')"; d="${d%.}"
    [ "$d" = ip ] && d=""
    if [ -z "$d" ] || valid_domain "$d"; then PANEL_DOMAIN="$d"; break; fi
    echo "  Not a domain name, try again (for example panel.example.com)"
  done
  SET_DOMAIN=1
fi
DNS_OK=0
if [ "$ACCESS" = public ] && [ -n "$PANEL_DOMAIN" ]; then
  dns=$(getent ahostsv4 "$PANEL_DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')
  if [ -z "$dns" ]; then
    warn "$PANEL_DOMAIN is not found in DNS yet — the panel uses a temporary certificate until it is"
  elif [[ " $dns" != *" $SERVER_IP "* ]]; then
    warn "$PANEL_DOMAIN points to ${dns% }, this server is $SERVER_IP — Let's Encrypt fails until DNS is fixed"
  else
    DNS_OK=1
  fi
  ok "Panel domain: $PANEL_DOMAIN"
fi

# Client configs: the panel domain instead of the IP keeps them working when the IP changes.
OLD_DOMAIN="$(cur_domain)"
if [ -n "$OLD_DOMAIN" ] && [ "$PUBLIC_HOST" = "$OLD_DOMAIN" ] && [ "$PANEL_DOMAIN" != "$OLD_DOMAIN" ]; then
  PUBLIC_HOST="$SERVER_IP"    # configs used the old panel domain — ask again below
fi
# Asked whenever the domain is (re)entered, also when configs already use it: AWGR_CLIENT_DOMAIN=no
# and the second answer must be able to return them to the IP.
if [ "$ACCESS" = public ] && [ -n "$PANEL_DOMAIN" ] \
   && { [ "$SET_DOMAIN" = 1 ] || [ -n "${AWGR_CLIENT_DOMAIN:-}" ]; }; then
  ip_host="$PUBLIC_HOST"; [ "$PUBLIC_HOST" = "$PANEL_DOMAIN" ] && ip_host="$SERVER_IP"
  ans="${AWGR_CLIENT_DOMAIN:-}"
  if [ -z "$ans" ]; then
    q="Which address should client configs use?"
    use_domain="$PANEL_DOMAIN — configs keep working if the IP changes"
    if [ "$PUBLIC_HOST" = "$PANEL_DOMAIN" ]; then
      choose "$q" "$use_domain (current)" "$ip_host"
      [ "$CHOICE" = 1 ] && ans=yes || ans=no
    elif [ "$DNS_OK" = 1 ]; then
      choose "$q" "$use_domain (recommended)" "$ip_host"
      [ "$CHOICE" = 1 ] && ans=yes || ans=no
    else
      choose "$q" "$ip_host (recommended)" \
             "$use_domain; it must lead straight to this server, without a proxy such as Cloudflare"
      [ "$CHOICE" = 2 ] && ans=yes || ans=no
    fi
  fi
  if [[ "$ans" =~ ^[Yy] ]]; then PUBLIC_HOST="$PANEL_DOMAIN"; else PUBLIC_HOST="$ip_host"; fi
fi
ok "Address in client configs: $PUBLIC_HOST"
# Server → Server public address in the panel is kept in data/state.json and overrides PUBLIC_HOST
PANEL_HOST_SET=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["settings"].get("public_host") or "")' \
  "$DIR/data/state.json" 2>/dev/null || true)
if [ -n "$PANEL_HOST_SET" ] && [ "$PANEL_HOST_SET" != "$PUBLIC_HOST" ]; then
  warn "The panel has its own server address $PANEL_HOST_SET, so client configs use it, not $PUBLIC_HOST."
  warn "To use $PUBLIC_HOST, change it in the panel: Server → Server public address"
fi
TLS_HOST="${PANEL_DOMAIN:-$PUBLIC_HOST}"

# ------------------------------------------------------------------ firewall
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  [ "$ACCESS" = public ] && { ufw allow "$PANEL_PORT/tcp" >/dev/null; ufw allow 80/tcp >/dev/null; }
  [ -n "$AWG_PORT" ] && ufw allow "$AWG_PORT/udp" >/dev/null
  ok "ufw rules added"
fi

# ------------------------------------------------------------------ .env
HAD_ENV=0
[ -f "$ENV_FILE" ] && cp "$ENV_FILE" "$ENV_FILE.bak" && HAD_ENV=1
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
RECONCILE_INTERVAL=$RECONCILE_INTERVAL
EOF
umask 022
# Everything else the previous .env had (EXIT_ENGINE, AWG_CONTAINER, SNI_PROXY_PORT, ACME_HTTP_PORT …) is
# carried over: this file is rewritten on every update, and settings added by hand must not vanish with it.
# tac: for a name written twice the last line wins, as it does for Docker. Only from this run's copy: a .env.bak
# left from an earlier run (the .env was deleted on purpose) must not bring old settings back.
keep_env() { # $1 previous .env, $2 new .env
  local line k known
  [ -f "$1" ] || return 0
  known=" $(grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' "$2" | tr -d '=' | tr '\n' ' ')"
  while IFS= read -r line; do
    [[ "$line" == *=* ]] || continue
    k="${line%%=*}"
    [[ "$k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    [[ "$known" == *" $k "* ]] && continue
    [ "$k" = UPSTREAM_BACKEND ] && continue     # written by installers before 1.20.0, never did anything
    printf '%s\n' "$line" >> "$2"; known="$known$k "
  done < <(tac "$1")
}
if [ "$HAD_ENV" = 1 ]; then keep_env "$ENV_FILE.bak" "$ENV_FILE"; fi

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

# A release archive carries IMAGES: the ready images the release workflow built from the same commit,
# pinned by digest (the archive itself passed its .sha256 check, and a digest names exactly one image).
# Downloading one needs only the registry, so an update works where the build cannot reach its
# sources (Alpine packages and git over HTTPS are filtered in Russia, China, Iran). The image is built
# here when there is no IMAGES (a branch or AWGR_SRC_URL), AWGR_BUILD=1, no image for this CPU, or
# the registry does not answer within AWGR_PULL_TIMEOUT seconds.
image_ref() { # $1 key in IMAGES → the reference, or nothing
  [ "${AWGR_BUILD:-}" = 1 ] && return 0
  [ -f "$DIR/IMAGES" ] || return 0
  grep -E "^$1=" "$DIR/IMAGES" | tail -1 | cut -d= -f2- \
    | grep -E '^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$' || true
}

# Why the image is built here although nobody asked (AWGR_BUILD=1 is asking): the build needs
# dl-cdn.alpinelinux.org and git over HTTPS to github.com, so it is said aloud, not left to a silent wait
no_ready_image() { # $1 what (the panel / AmneziaWG)
  [ "${AWGR_BUILD:-}" = 1 ] && return 0
  warn "This download has no ready image of $1 (no IMAGES file: a branch, AWGR_SRC_URL or an old release) — building it here; this needs dl-cdn.alpinelinux.org and github.com"
}

pull_image() { # $1 reference, $2 local tag, $3 log
  [ -n "$1" ] || return 1
  local rc
  timeout "${AWGR_PULL_TIMEOUT:-600}" docker pull "$1" >"$3" 2>&1; rc=$?
  [ "$rc" = 124 ] && echo "no answer in ${AWGR_PULL_TIMEOUT:-600} s" >>"$3"
  [ "$rc" = 0 ] && docker tag "$1" "$2" >>"$3" 2>&1
}

# Last line of a log, for a one-line reason
last_line() { tail -n 1 "$1" 2>/dev/null | cut -c1-200; }

# Runs "$@" in the background; a spinner only on a terminal (an update from the panel writes to a log)
with_spinner() {
  "$@" &
  local pid=$! spin='|/-\' i=0
  if [ -t 1 ]; then
    while kill -0 "$pid" 2>/dev/null; do printf '\r  %s ' "${spin:i++%4:1}"; sleep 0.5; done
    printf '\r    \r'
  fi
  wait "$pid"
}

OLD_IMAGE_ID="$(docker image inspect -f '{{.Id}}' "$IMAGE" 2>/dev/null || true)"
LOG="$DIR/data/build.log"
PANEL_REF="$(image_ref PANEL_IMAGE)"
if [ -n "$PANEL_REF" ]; then
  step "Downloading the panel"
  if with_spinner pull_image "$PANEL_REF" "$IMAGE" "$DIR/data/pull.log"; then
    ok "Done"
  else
    warn "Could not download the ready image ($(last_line "$DIR/data/pull.log")) — building it here"
    PANEL_REF=""
  fi
fi
if [ -z "$PANEL_REF" ]; then
  step "Building the panel (first time takes 3–10 minutes)"
  [ -f "$DIR/IMAGES" ] || no_ready_image "the panel"
  with_spinner build_image "$IMAGE" "$DIR" "$LOG" || { tail -n 25 "$LOG"; die "Build failed, see $LOG"; }
  ok "Done"
fi

# ------------------------------------------------------------------ kernel module
# Before the AWG server is created, so a new server comes up right on the module. A failure is only a warning:
# the server runs on amneziawg-go, and the panel offers the module again.
if [ "${WANT_KERNEL:-0}" = 1 ]; then
  [ -n "$INSTALL_AWG" ] && KERNEL_NEW_SERVER=1
  KERNEL_SOFT=1 install_kernel || warn "Going on with amneziawg-go; the panel offers the module again (Server → AmneziaWG engine)."
fi

# ------------------------------------------------------------------ AmneziaWG in a container
if [ "$INSTALL_AWG" = container ]; then
  step "Installing AmneziaWG into container $SRV_NAME"
  mkdir -p "$SRV_DATA"; chmod 700 "$DIR/awg-server" "$SRV_DATA"
  docker run --rm --network none -v "$SRV_DATA:/out" "$IMAGE" \
      python3 -m app.initserver --out /out --port "$AWG_PORT" >"$DIR/data/awg-init.log" 2>&1 \
    || { cat "$DIR/data/awg-init.log"; die "Failed to create the server config"; }
  SRV_REF="$(image_ref SERVER_IMAGE)"
  [ -f "$DIR/IMAGES" ] || no_ready_image "AmneziaWG"
  if ! pull_image "$SRV_REF" "$SRV_NAME" "$DIR/data/awg-pull.log"; then
    [ -n "$SRV_REF" ] && warn "Could not download the ready AmneziaWG image ($(last_line "$DIR/data/awg-pull.log")) — building it here"
    build_image "$SRV_NAME" "$DIR/awg-server" "$DIR/data/awg-build.log" \
      || { tail -n 20 "$DIR/data/awg-build.log"; die "Failed to build the AmneziaWG container"; }
  fi
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

# Moves the container's server to the host with the same files: keys, port, obfuscation and clients stay,
# so client configs keep working. The container is only stopped and renamed; any failure puts it back.
move_server() { # $1 container → 0 moved, 1 nothing changed
  local c="$1" tmp pol old out
  tmp="$(mktemp -d)"; chmod 700 "$tmp"
  mover() { docker compose run --rm --no-deps -T -v "$tmp:/move:ro" awg-router python3 -m app.movehost "$@" 2>&1; }
  if ! docker cp "$c:/opt/amnezia/awg/." "$tmp/" >/dev/null 2>&1; then
    rm -rf "$tmp"; warn "Could not copy the server files out of $c"; return 1
  fi
  if ! out="$(mover check /move)"; then rm -rf "$tmp"; warn "$out"; return 1; fi
  ok "Server in $c: $out"
  docker compose stop awg-router >/dev/null 2>&1    # the running panel manages the container
  pol="$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$c" 2>/dev/null)"; pol="${pol:-always}"
  old="$c-moved-$(date +%Y%m%d-%H%M%S)"
  docker update --restart no "$c" >/dev/null 2>&1
  docker stop "$c" >/dev/null 2>&1                  # frees the UDP port
  if ! docker rename "$c" "$old" >/dev/null 2>&1; then
    docker update --restart "$pol" "$c" >/dev/null 2>&1; docker start "$c" >/dev/null 2>&1
    rm -rf "$tmp"; warn "Could not rename container $c"; return 1
  fi
  if out="$(mover install /move)"; then
    rm -rf "$tmp"
    ok "AmneziaWG runs on the host: $out; client configs stay the same"
    ok "The old container is kept stopped as $old — when everything works: docker rm $old"
    warn "If this server has its own firewall, allow the AmneziaWG UDP port there (Docker opened it before)"
    return 0
  fi
  warn "$out"
  mover undo >/dev/null 2>&1
  docker rename "$old" "$c" >/dev/null 2>&1
  docker update --restart "$pol" "$c" >/dev/null 2>&1
  docker start "$c" >/dev/null 2>&1
  rm -rf "$tmp"; return 1
}
if [ -n "$MOVE_FROM" ]; then
  step "Moving AmneziaWG from container $MOVE_FROM to the host"
  if ! move_server "$MOVE_FROM"; then
    warn "The server stays in container $MOVE_FROM, and the panel keeps managing it"
    AWG_MODE=container
    sed -i 's/^AWG_MODE=.*/AWG_MODE=container/' "$ENV_FILE"
  fi
fi

# ------------------------------------------------------------------ port 80
# Let's Encrypt validates the panel address on port 80. If a web server already holds it, the
# panel can add its own small file there that serves only the validation for the panel address.
panel_cli() { docker compose run --rm --no-deps -T awg-router python3 -m app.webfront "$@" 2>>"$DIR/data/up.log"; }
have_tty() { { : </dev/tty; } 2>/dev/null; }
if [ "$SET_DOMAIN" = 1 ]; then
  panel_cli domain "$PANEL_DOMAIN" >/dev/null || warn "Could not save the panel domain"
fi
if [ "$ACCESS" = public ] && port_busy 80; then
  step "Port 80"
  out="$(panel_cli check "$TLS_HOST")"; rc=$?
  case "$rc" in
    3) ok "$(echo "$out" | head -1)" ;;
    0) echo "$out" | sed 's/^/  /'
       ans="${AWGR_WEB:-}"
       if [ -z "$ans" ]; then
         if have_tty; then ask "Add it automatically? [Y/n]: " Y; ans="$REPLY"; else ans=n; fi
       fi
       if [[ "$ans" =~ ^[Yy] ]]; then
         res="$(panel_cli add "$TLS_HOST")" && ok "$res" \
           || warn "$res — the panel uses a temporary certificate; add the text above by hand"
       else
         warn "Not added. You can do it later in the panel: System → Set up validation through the web server"
       fi ;;
    2) echo "$out" | sed 's/^/  /'
       warn "Until then the panel uses a temporary certificate (the browser will warn)" ;;
    *) [ -n "$out" ] && echo "$out" | sed 's/^/  /' ;;
  esac
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
# The previous panel image is not used any more: each update would otherwise leave ~100 MB behind
if [ -n "$OLD_IMAGE_ID" ] && [ "$OLD_IMAGE_ID" != "$(docker image inspect -f '{{.Id}}' "$IMAGE" 2>/dev/null)" ]; then
  docker image rm "$OLD_IMAGE_ID" >/dev/null 2>&1 || true
fi

# ------------------------------------------------------------------ helper command
cat > /usr/local/bin/awg-router <<EOF
#!/usr/bin/env bash
# AWG Router helper
DIR="$DIR"
case "\${1:-info}" in
  info)        bash "\$DIR/install.sh" --info ;;
  restart)     cd "\$DIR" && docker compose restart && bash "\$DIR/install.sh" --info ;;
  logs)        if [ -t 1 ]; then docker logs --tail 100 -f awg-router; else docker logs --tail 2000 awg-router 2>&1; fi ;;
  update)      bash "\$DIR/install.sh" --update ;;
  install-kernel) bash "\$DIR/install.sh" --install-kernel ;;
  reconfigure) bash "\$DIR/install.sh" --reconfigure ;;
  password)    P=\$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 16)
               sed -i "s/^PANEL_PASSWORD=.*/PANEL_PASSWORD=\$P/" "\$DIR/.env"
               rm -f "\$DIR/data/panel_password.json"
               cd "\$DIR" && docker compose up -d >/dev/null 2>&1; sleep 3; bash "\$DIR/install.sh" --info ;;
  2fa-off)     rm -f "\$DIR/data/totp.json"
               echo "Two-factor sign-in is off: the panel password alone is enough now." ;;
  uninstall)   bash "\$DIR/install.sh" --uninstall ;;
  *) echo "awg-router info | restart | logs | password | 2fa-off | update | reconfigure | install-kernel | uninstall" ;;
esac
EOF
chmod 755 /usr/local/bin/awg-router

print_info
