#!/usr/bin/env bash
# Сквозная проверка обновления — так, как его получает пользователь (issue #8: юнит-тесты были
# зелёными, а опубликованный архив терял IMAGES, и обновление молча уходило в сборку).
#
#   1. ставит опубликованную версию E2E_FROM из архива релиза, как install.sh (сервер AWG — E2E_MODE);
#   2. проверяет панель через API и заводит клиента;
#   3. запускает `awg-router update` — оно ставит последний опубликованный релиз;
#   4. проверяет: образ панели скачан, а не собран; версия — последняя; клиент и сервер AWG на месте.
#
# Запуск от root на одноразовой машине (машина GitHub Actions) или на тестовом сервере:
#   E2E_MODE=container|host  E2E_FROM=previous|latest|vX.Y.Z  E2E_CLEANUP=1  bash tests/e2e/upgrade.sh
# E2E_FROM=latest — установка последней версии и обновление «на неё же»: путь обновления без сборки,
# когда у прошлой версии ещё нет готовых образов. E2E_CLEANUP=1 — убрать всё за собой (cleanup.sh).
# Обновление до кода, который ещё не выпущен: E2E_TO_SRC — адрес архива кода (AWGR_SRC_URL, можно file://;
# с IMAGES внутри — образы скачиваются, без — собираются здесь), E2E_TO_VERSION — версия этого кода.
# Свой контейнер сервера AWG (E2E_MODE=container) с 1.22.0 обновляется вместе с панелью: проверяется, что
# его образ сменился (при E2E_FROM=latest — что остался тем же), а порт, интерфейс и клиенты сервера — те же.
# Журналы — в $E2E_LOGS (по умолчанию /tmp/e2e-logs).
set -uo pipefail

REPO="${E2E_REPO:-r-slashslash/AWG-Router}"
MODE="${E2E_MODE:-container}"
FROM="${E2E_FROM:-previous}"
DIR=/opt/awg-router
LOGS="${E2E_LOGS:-/tmp/e2e-logs}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$LOGS"
# shellcheck source=tests/e2e/secrets.sh
. "$HERE/secrets.sh"
trap 'scrub_logs "$LOGS"' EXIT

step() { printf '\n\033[1m=== %s\033[0m\n' "$1"; }
fail() {
  printf '\n\033[31mFAIL: %s\033[0m\n' "$1"
  cp -f "$DIR"/data/*.log "$LOGS/" 2>/dev/null
  docker logs --tail 200 awg-router >"$LOGS/panel-container.log" 2>&1
  exit 1
}
ok() { printf '  \033[32mok\033[0m %s\n' "$1"; }

[ "$(id -u)" = 0 ] || { echo "Run as root"; exit 2; }
if [ "${E2E_CLEANUP:-0}" = 1 ]; then
  bash "$HERE/cleanup.sh" >"$LOGS/cleanup-before.log" 2>&1
  trap 'bash "$HERE/cleanup.sh" >"$LOGS/cleanup-after.log" 2>&1; scrub_logs "$LOGS"' EXIT
fi

# ---------------------------------------------------------------- какие версии
step "Releases"
# без ключа API GitHub отвечает 403, когда с адреса машины CI спросили слишком много (адреса общие)
auth=(); [ -n "${E2E_GH_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $E2E_GH_TOKEN")
rels=$(curl -fsSL --retry 3 "${auth[@]}" "https://api.github.com/repos/$REPO/releases?per_page=20") || fail "GitHub API is not reachable"
mapfile -t TAGS < <(python3 -c 'import json,sys; [print(r["tag_name"]) for r in json.load(sys.stdin) if not r["draft"] and not r["prerelease"]]' <<<"$rels")
LATEST="${TAGS[0]:-}"
[ -n "$LATEST" ] || fail "no published release"
TO_SRC="${E2E_TO_SRC:-}"
[ -n "$TO_SRC" ] && LATEST="v${E2E_TO_VERSION:?E2E_TO_VERSION is needed with E2E_TO_SRC}"
case "$FROM" in
  latest) FROM="$LATEST" ;;
  previous) FROM="${TAGS[1]:-}"; [ -n "$FROM" ] || fail "no previous release" ;;
esac
ok "from $FROM to $LATEST, AmneziaWG: $MODE"

# ---------------------------------------------------------------- установка прошлой версии
step "Install $FROM"
[ -e "$DIR" ] && fail "$DIR already exists: this test needs a clean machine (or E2E_CLEANUP=1)"
tmp=$(mktemp -d)
url="https://github.com/$REPO/releases/download/$FROM/awg-router.tar.gz"
curl -fsSL --retry 3 -o "$tmp/a.tgz" "$url" || fail "download $url"
sum=$(curl -fsSL --retry 3 "$url.sha256" | awk '{print $1}')
echo "$sum  $tmp/a.tgz" | sha256sum -c --status || fail "checksum of $url"
mkdir -p "$DIR" && tar -xzf "$tmp/a.tgz" --strip-components=1 -C "$DIR"
if [ -f "$DIR/IMAGES" ]; then ok "the archive has IMAGES"; else echo "  (the archive has no IMAGES: $FROM is built here)"; fi
AWGR_INSTALL="$MODE" AWGR_ACCESS=ssh AWGR_ENGINE=go bash "$DIR/install.sh" </dev/null >"$LOGS/install.log" 2>&1
rc=$?
hide_secrets "$DIR"
tail -n 25 "$LOGS/install.log"
[ "$rc" = 0 ] || fail "install.sh exit $rc"
ok "installed"

# ---------------------------------------------------------------- API панели
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
state() { api GET state; }
jq_py() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

wait_server() { # сервер AWG найден и существует (у host — после его установки панелью)
  local s
  for _ in $(seq 1 60); do
    s=$(state 2>/dev/null) && [ "$(jq_py 'bool(d["target"] and d["target"]["exists"])' <<<"$s")" = True ] && return 0
    sleep 3
  done
  echo "$s" | head -c 2000 >"$LOGS/state.json"
  return 1
}

step "Panel $FROM"
wait_server || fail "the panel does not see the AmneziaWG server (see state.json)"
s=$(state)
cur=$(jq_py 'd["version"]["current"]' <<<"$s")
[ "v$cur" = "$FROM" ] || fail "the panel says $cur, expected $FROM"
ok "version $cur, server: $(jq_py 'd["target"]["kind"]' <<<"$s")"
pk=$(api POST users '{"name":"e2e-client"}' | jq_py 'd["public_key"]') || fail "could not add a client"
ok "client added: $pk"
srv_box() { # свой контейнер сервера AWG: образ, порт и число клиентов в awg0
  local c=amnezia-awg2
  docker inspect -f '{{range .Mounts}}{{println .Source}}{{end}}' "$c" 2>/dev/null | grep -qx "$DIR/awg-server/data" || return 1
  printf '%s %s %s\n' "$(docker inspect -f '{{.Image}}' "$c")" \
    "$(docker inspect -f '{{range $p, $_ := .NetworkSettings.Ports}}{{$p}} {{end}}' "$c" | tr -d ' ')" \
    "$(docker exec "$c" awg show awg0 peers 2>/dev/null | wc -l)"
}
box_before=$(srv_box || true)
[ -n "$box_before" ] && ok "own AWG container: port $(cut -d' ' -f2 <<<"$box_before"), $(cut -d' ' -f3 <<<"$box_before") clients"

# ---------------------------------------------------------------- обновление
step "awg-router update"
build_mtime=$(stat -c %Y "$DIR/data/build.log" 2>/dev/null || echo none)
AWGR_SRC_URL="$TO_SRC" awg-router update </dev/null >"$LOGS/update.log" 2>&1
rc=$?
hide_secrets "$DIR"
tail -n 25 "$LOGS/update.log"
[ "$rc" = 0 ] || fail "awg-router update exit $rc"
if [ -z "$TO_SRC" ] || [ -f "$DIR/IMAGES" ]; then
  grep -q "Downloading the panel" "$LOGS/update.log" || fail "the update did not download the ready image"
  grep -q "Building the panel" "$LOGS/update.log" && fail "the update built the panel instead of downloading it"
  grep -q "no ready image" "$LOGS/update.log" && fail "the release archive has no IMAGES"
  [ "$(stat -c %Y "$DIR/data/build.log" 2>/dev/null || echo none)" = "$build_mtime" ] || fail "data/build.log changed: something was built"
  ok "the ready image was downloaded, nothing was built"
else
  ok "code without IMAGES: the images were built here"
fi

step "Panel $LATEST"
wait_server || fail "after the update the panel does not see the AmneziaWG server"
s=$(state)
cur=$(jq_py 'd["version"]["current"]' <<<"$s")
[ "v$cur" = "$LATEST" ] || fail "after the update the panel says $cur, expected $LATEST"
ok "version $cur"
[ "$(jq_py "any(c['public_key'] == '$pk' for c in d['clients'])" <<<"$s")" = True ] || fail "the client disappeared"
ok "the client is still there"
img=$(docker inspect -f '{{.Image}}' awg-router)
ref=$(grep -E '^PANEL_IMAGE=' "$DIR/IMAGES" | cut -d= -f2-)
docker image inspect -f '{{join .RepoDigests " "}}' "$img" | grep -qF "${ref#*@}" || fail "the running panel is not the image from IMAGES ($ref)"
ok "the running panel is $ref"
if [ -n "$box_before" ] && grep -q "refresh_own_server()" "$DIR/install.sh"; then
  for _ in $(seq 1 20); do docker exec amnezia-awg2 ip link show awg0 >/dev/null 2>&1 && break; sleep 1; done
  box_after=$(srv_box) || fail "the own AWG container is gone after the update"
  [ "$(cut -d' ' -f2 <<<"$box_after")" = "$(cut -d' ' -f2 <<<"$box_before")" ] || fail "the own AWG container has another port"
  [ "$(cut -d' ' -f3 <<<"$box_after")" = "$(cut -d' ' -f3 <<<"$box_before")" ] || fail "the own AWG container lost clients"
  if [ "$FROM" = "$LATEST" ]; then
    # обновление «на ту же версию»: образ сервера тот же, и refresh_own_server его справедливо не трогает
    [ "$(cut -d' ' -f1 <<<"$box_after")" = "$(cut -d' ' -f1 <<<"$box_before")" ] || fail "the same version replaced the own AWG container"
    ok "own AWG container: the same version keeps its image, port and clients"
  else
    [ "$(cut -d' ' -f1 <<<"$box_after")" != "$(cut -d' ' -f1 <<<"$box_before")" ] || fail "the own AWG container kept its old image"
    grep -q "AmneziaWG runs on the new image" "$LOGS/update.log" || fail "the installer did not report the new AWG image"
    ok "own AWG container: new image ($(docker exec amnezia-awg2 cat /etc/alpine-release 2>/dev/null | sed 's/^/Alpine /')), same port and clients"
  fi
fi
err=$(jq_py 'd["engine"]["last_error"]' <<<"$s")
[ "$err" = None ] || fail "the panel reports: $err"
ok "no errors"

printf '\n\033[32mPASS\033[0m %s → %s (%s)\n' "$FROM" "$LATEST" "$MODE"
