#!/usr/bin/env bash
# Убирает за tests/e2e/upgrade.sh всё, что ставит install.sh: панель, её образы, правила
# маршрутизации, сервер AmneziaWG (контейнер amnezia-awg2 или awg-quick@awg0 на хосте).
# ТОЛЬКО для тестовой машины: удаляет сервер AmneziaWG вместе с клиентами. Docker остаётся.
set -u
DIR=/opt/awg-router

if [ -f "$DIR/docker-compose.yml" ] && command -v docker >/dev/null; then
  (cd "$DIR" && docker compose down --remove-orphans) || true
  # правила маршрутизации панели на сервере AWG — так же, как `awg-router uninstall`
  (cd "$DIR" && timeout 120 docker compose run --rm --no-deps -T awg-router python3 -m app.uninstall) || true
fi
if command -v docker >/dev/null; then
  for c in $(docker ps -aq --filter name='^awg-router$' --filter name='^amnezia-awg2' 2>/dev/null); do
    docker rm -f "$c" || true
  done
  for i in $(docker images -q awg-router; docker images -q amnezia-awg2; docker images -q 'ghcr.io/r-slashslash/awg-router'); do
    docker image rm -f "$i" || true
  done
fi

# сервер AmneziaWG на хосте
systemctl disable --now awg-quick@awg0 2>/dev/null || true
rm -f /etc/systemd/system/awg-quick@.service && systemctl daemon-reload 2>/dev/null || true
ip link del awg0 2>/dev/null || true
for l in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^awgr[0-9]+' | cut -d@ -f1); do
  ip link del "$l" || true
done
nft delete table ip awgr 2>/dev/null || true
nft delete table ip awgr_acct 2>/dev/null || true
ip rule show 2>/dev/null | awk -F: '$1 >= 20000 && $1 < 21000 {print $1}' | while read -r p; do
  ip rule del priority "$p" || true
done
rm -rf "$DIR" /etc/amnezia /usr/local/bin/awg /usr/local/bin/awg-quick /usr/local/bin/amneziawg-go \
       /usr/local/bin/awg-router
echo "cleaned"
