#!/bin/sh
# Е: настоящая блокировка к настоящим серверам с клиентами, которые повторяют запрос (e_realretry.py), — каждый случай в
# своём контейнере образа панели (своя сеть). IMG — образ, DK — docker (на VPS — sudo docker), OLD — код до исправлений.
D=$(cd "$(dirname "$0")" && pwd)
export W=$(cd "$D/../.." && pwd)
echo "$CASES" | tr ';' '\n' | xargs -P "${PAR:-2}" -L 1 sh -c '$DK run --rm --privileged -e PYTHONDONTWRITEBYTECODE=1 \
    -e LAB_OLD=/old/app -e LAB_NEW=/w/app -e LAB_FIX=/tmp/fix/app -e LAB_VERS=old,new,fix -e RETRY=${RETRY:-1} \
    -v "$W:/w:ro" -v "$OLD:/old:ro" -w /w "$IMG" sh -c "apk add -q --no-cache nftables >/dev/null &&
    sysctl -qw net.netfilter.nf_conntrack_acct=1; python3 -I /w/audit/p31e/e_mkfix.py /w/app /tmp/fix/app >/dev/null &&
    python3 -I /w/audit/p31e/e_realretry.py $0 $1 $2 $3" 2>&1 | grep -E "^RESULT|^WARMLOG|Error|rror:" | cut -c1-6000'
