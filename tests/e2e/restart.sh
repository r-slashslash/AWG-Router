#!/usr/bin/env bash
# Перезапуск и «перезагрузка» сервера AWG с настоящей установкой панели (1.21.0): клиенты не идут мимо выходов,
# пока панель не поставила свои правила.
#
#   1. ставит панель из этой копии кода (install.sh, образы собираются здесь), сервер AWG — E2E_MODE;
#   2. добавляет выход AWG без связи с резервом «Блокировать» и второй, по умолчанию, с резервом «Напрямую»
#      (полная проверка 1.25.0, П13): пока туннелей нет, клиенты в блоке, а не напрямую — «Напрямую» только у
#      выхода, который лежит дольше CONNECTING_SECS при работающей панели;
#   3. панель работает, сервер AWG перезапускается: правила есть сразу (контейнер ставит их сам), правила
#      панели — через секунды (события Docker), а не через проход;
#   4. «перезагрузка»: панель остановлена, правил нет, сервер AWG запускается — правила «до панели» ставит
#      сам сервер (свой контейнер: start.sh; хост: служба awg-quick); панель запускается — её правила;
#   5. на хосте панель не меняет общий rp_filter; удаление панели убирает файл правил.
#
# Только на одноразовой машине (машина GitHub Actions): ставит панель и сервер AWG в систему.
#   sudo E2E_MODE=container|host bash tests/e2e/restart.sh
set -uo pipefail

MODE="${E2E_MODE:-container}"
DIR=/opt/awg-router
LOGS="${E2E_LOGS:-/tmp/e2e-logs}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$LOGS"
# shellcheck source=tests/e2e/secrets.sh
. "$(dirname "${BASH_SOURCE[0]}")/secrets.sh"
trap 'scrub_logs "$LOGS"' EXIT
FAILS=0

step() { printf '\n\033[1m=== %s\033[0m\n' "$1"; }
ok() { printf '  \033[32mok\033[0m %s\n' "$1"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILS=$((FAILS + 1)); }
die() {
  printf '\n\033[31mFAIL: %s\033[0m\n' "$1"
  cp -f "$DIR"/data/*.log "$LOGS/" 2>/dev/null
  docker logs --tail 200 awg-router >"$LOGS/panel-container.log" 2>&1
  exit 1
}
[ "$(id -u)" = 0 ] || { echo "Run as root"; exit 2; }
[ -e "$DIR" ] && die "$DIR already exists: this test needs a clean machine"

if [ "$MODE" = host ] && command -v nft >/dev/null; then
  # без nft на хосте служба не может поставить правила «до панели»: установщик должен поставить его сам
  DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq nftables >/dev/null 2>&1 || true
fi
rp_all_before=$(sysctl -n net.ipv4.conf.all.rp_filter)
rp_def_before=$(sysctl -n net.ipv4.conf.default.rp_filter)

# ---------------------------------------------------------------- установка из этой копии
step "Install from this code (AmneziaWG: $MODE)"
mkdir -p "$DIR"
tar -C "$SRC" --exclude=.git -cf - . | tar -C "$DIR" -xf -
AWGR_INSTALL="$MODE" AWGR_ACCESS=ssh AWGR_ENGINE=go bash "$DIR/install.sh" </dev/null >"$LOGS/install.log" 2>&1
rc=$?
hide_secrets "$DIR"
tail -n 15 "$LOGS/install.log"
[ "$rc" = 0 ] || die "install.sh exit $rc"
ok "installed"
if [ "$MODE" = host ]; then
  command -v nft >/dev/null && ok "the installer put nft on the host" || bad "no nft on the host after install"
  systemctl is-enabled --quiet nftables 2>/dev/null && bad "nftables.service is enabled (it would flush rules at boot)" \
    || ok "nftables.service stays off"
  docker ps >/dev/null && ok "Docker works" || bad "Docker broke"
fi

envget() { grep -E "^$1=" "$DIR/.env" | tail -1 | cut -d= -f2-; }
api() { # $1 метод, $2 путь, $3 тело JSON → ответ JSON
  python3 - "$1" "$2" "${3:-}" <<PY
import http.cookiejar, json, sys, urllib.request
base = "http://127.0.0.1:$(envget PANEL_PORT)$(envget PANEL_BASE_PATH)/api/"
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                 urllib.request.ProxyHandler({}))
def call(m, p, body=None):
    r = urllib.request.Request(base + p, method=m, headers={"Content-Type": "application/json"},
                               data=json.dumps(body).encode() if body is not None else None)
    return json.loads(op.open(r, timeout=30).read() or b"{}")
call("POST", "login", {"password": "$(envget PANEL_PASSWORD)"})
m, p, b = sys.argv[1:4]
print(json.dumps(call(m, p, json.loads(b) if b else None)))
PY
}
jq_py() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
wait_panel() {
  for _ in $(seq 1 60); do
    s=$(api GET state 2>/dev/null) && [ "$(jq_py 'bool(d["target"] and d["target"]["exists"])' <<<"$s")" = True ] && return 0
    sleep 2
  done
  return 1
}

# правила в сети сервера AWG: контейнер — его сеть, хост — сеть хоста
srv_pid() { docker inspect -f '{{.State.Pid}}' amnezia-awg2 2>/dev/null; }
rules() {
  if [ "$MODE" = container ]; then
    local pid; pid=$(srv_pid)
    [ -n "$pid" ] && [ "$pid" != 0 ] && nsenter -t "$pid" -n nft list table ip awgr 2>/dev/null
  else
    nft list table ip awgr 2>/dev/null
  fi
}
has_rules() { rules >/dev/null; }
full_rules() { rules | grep -q "chain o_u1 "; }          # правила панели: туннель выхода 1 есть
hold_rules() { local r; r=$(rules) && ! grep -q "chain o_u1 " <<<"$r" && grep -q "chain o_block" <<<"$r"; }
# политика «По умолчанию» в правилах сети сервера; direct_now — клиенты идут напрямую (резерв выхода 2)
p_global() { rules | awk '/chain p_global \{/ {f = 1} f {print} f && /^[[:space:]]*\}[[:space:]]*$/ {exit}'; }
direct_now() { p_global | grep -q "goto o_direct"; }
no_direct_for() { # $1 с: ни разу не «напрямую» (правил нет совсем — тоже не годится)
  local end=$(( $(date +%s) + $1 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    { has_rules && ! direct_now; } || { p_global >"$LOGS/p_global-direct.txt" 2>&1; return 1; }
    sleep 0.2
  done
}
wait_for() { # $1 — сколько секунд ждать, дальше команда; печатает, через сколько секунд вышло
  local limit=$1; shift
  local t0; t0=$(date +%s.%N)
  while :; do
    if "$@"; then python3 -c "print(round($(date +%s.%N) - $t0, 1))"; return 0; fi
    python3 -c "import sys; sys.exit(0 if $(date +%s.%N) - $t0 < $limit else 1)" || return 1
    sleep 0.2
  done
}
panel() { (cd "$DIR" && docker compose "$@") >/dev/null 2>&1; }

step "Panel and an exit without a connection (fallback: block)"
wait_panel || die "the panel does not see the AmneziaWG server"
k1=$(docker exec awg-router awg genkey); k2=$(docker exec awg-router awg genkey | docker exec -i awg-router awg pubkey)
conf=$(printf '[Interface]\nPrivateKey = %s\nAddress = 10.99.0.2/32\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.10:51820\n' "$k1" "$k2")
body=$(python3 -c 'import json,sys; print(json.dumps({"name": "e2e-exit", "config": sys.argv[1], "fallback": "block", "make_default": True}))' "$conf")
api POST upstreams "$body" >/dev/null || die "could not add the exit"
api POST users '{"name":"e2e-client"}' >/dev/null || die "could not add a client"
t=$(wait_for 90 full_rules) && ok "the panel's rules with the exit tunnel are up (${t}s)" || die "no panel rules with the exit"
step "A second exit without a connection, by default, fallback: direct"
conf2=$(printf '[Interface]\nPrivateKey = %s\nAddress = 10.99.0.3/32\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.11:51820\n' "$k1" "$k2")
body=$(python3 -c 'import json,sys; print(json.dumps({"name": "e2e-direct", "config": sys.argv[1], "fallback": "direct", "make_default": True}))' "$conf2")
api POST upstreams "$body" >/dev/null || die "could not add the second exit"
# лежит дольше CONNECTING_SECS — его клиенты на резерве «Напрямую», так задумано (при работающей панели)
t=$(wait_for 120 direct_now) && ok "the second exit is down: its clients are on the fallback Direct (${t}s)" \
  || bad "the fallback Direct of the second exit did not come"
if [ "$MODE" = container ]; then hold="$DIR/awg-server/data/awgr-hold-awg0.nft"; else hold=/etc/amnezia/amneziawg/awgr-hold-awg0.nft; fi
t=$(wait_for 30 test -f "$hold") && ok "rules «before the panel» are saved next to the server's config" || bad "no $hold"
if [ -f "$hold" ] && ! grep -q "chain o_u1 " "$hold" && grep -q "goto o_block" "$hold"; then
  ok "in them the exit without a tunnel is a block"
else
  bad "the saved rules don't block the exit without a tunnel"; cp -f "$hold" "$LOGS/" 2>/dev/null
fi
if [ -f "$hold" ] && ! awk '/chain p_global \{/ {f = 1} f {print} f && /^[[:space:]]*\}/ {exit}' "$hold" | grep -q "goto o_direct"; then
  ok "and the exit with the fallback Direct is a block too: before the panel nobody knows if it works"
else
  bad "the saved rules send the clients of the second exit direct"; cp -f "$hold" "$LOGS/" 2>/dev/null
fi

# ---------------------------------------------------------------- перезапуск при работающей панели
if [ "$MODE" = container ]; then
  step "The AWG container restarts while the panel runs"
  docker restart -t 3 amnezia-awg2 >/dev/null
  t=$(wait_for 10 has_rules) && ok "rules are there right after the start (${t}s): the container put them in itself" \
    || bad "no rules in the new container network"
  no_direct_for 8 && ok "8 s after the restart — nothing direct, though the exit's fallback is Direct" \
    || bad "clients of the exit with the fallback Direct went direct after the restart"
  t=$(wait_for 30 full_rules) && ok "the panel's own rules followed in ${t}s (Docker events, not the next pass)" \
    || bad "the panel did not put its rules in within 30 s"
else
  step "The awg-quick service restarts while the panel runs"
  systemctl restart awg-quick@awg0
  full_rules && ok "the panel's rules stay: the service doesn't replace a table that is there" || bad "the panel's rules are gone"
fi

# ---------------------------------------------------------------- «перезагрузка»
step "Reboot: the server starts before the panel"
panel stop
if [ "$MODE" = container ]; then
  docker restart -t 3 amnezia-awg2 >/dev/null              # новая сеть контейнера — правил панели в ней нет
else
  nft delete table ip awgr 2>/dev/null                       # после перезагрузки таблицы нет
  systemctl restart awg-quick@awg0
fi
t=$(wait_for 15 hold_rules) && ok "without the panel the server put the «before the panel» rules in (${t}s)" \
  || { bad "no rules while the panel is down"; rules >"$LOGS/rules-down.txt"; }
sleep 10
hold_rules && ok "10 s later — still the same: exit traffic is blocked, nothing goes past the exit" || bad "the rules changed without the panel"
! direct_now && ok "and nothing direct for the exit with the fallback Direct" || bad "without the panel the clients of the second exit go direct"
panel start
no_direct_for 8 && ok "the panel starts: 8 s — still nothing direct" \
  || bad "the panel's first pass sent the clients of the exit with the fallback Direct direct"
t=$(wait_for 90 full_rules) && ok "the panel started and put its rules in (${t}s)" || bad "the panel did not put its rules in"

# ---------------------------------------------------------------- хост: rp_filter
if [ "$MODE" = host ]; then
  step "rp_filter on the host"
  [ "$(sysctl -n net.ipv4.conf.all.rp_filter)" = "$rp_all_before" ] && [ "$(sysctl -n net.ipv4.conf.default.rp_filter)" = "$rp_def_before" ] \
    && ok "all/default unchanged ($rp_all_before/$rp_def_before)" || bad "the panel changed all/default rp_filter"
  [ "$(sysctl -n net.ipv4.conf.awg0.rp_filter)" = 2 ] && ok "awg0 has its own rp_filter=2" || bad "awg0 rp_filter is not 2"
fi

# ---------------------------------------------------------------- удаление панели
step "Uninstall removes the rules file"
panel down
(cd "$DIR" && timeout 120 docker compose run --rm --no-deps -T awg-router python3 -m app.uninstall) >"$LOGS/uninstall.log" 2>&1
[ ! -f "$hold" ] && ok "no rules file after uninstall: without the panel the server won't block anything" || bad "$hold is still there"

[ "$FAILS" = 0 ] || { cp -f "$DIR"/data/*.log "$LOGS/" 2>/dev/null; docker logs --tail 200 awg-router >"$LOGS/panel-container.log" 2>&1
                      printf '\n\033[31mFAIL: %s checks\033[0m\n' "$FAILS"; exit 1; }
printf '\n\033[32mPASS\033[0m restart and reboot (%s)\n' "$MODE"
