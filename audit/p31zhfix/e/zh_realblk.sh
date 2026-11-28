#!/bin/sh
# Ж: настоящая блокировка к настоящим серверам, клиенты повторяют запрос (e_realretry.py) — каждый случай в своём
# контейнере образа панели (своя сеть). old — d7a90cc (/old), new — c934013 (/new), fix — ветка (/w). IMG — образ,
# DK — docker (на VPS — sudo docker), OLD, NEW — папки кода; CASES — «вид шифрование поставщик pre» через «;».
D=$(cd "$(dirname "$0")" && pwd)
export W=$(cd "$D/../../.." && pwd)
echo "$CASES" | tr ';' '\n' | xargs -P "${PAR:-2}" -L 1 sh -c '$DK run --rm --privileged -e PYTHONDONTWRITEBYTECODE=1 \
    -e LAB_OLD=/old/app -e LAB_NEW=/new/app -e LAB_FIX=/w/app -e LAB_VERS=old,new,fix -e RETRY=${RETRY:-1} \
    -v "$W:/w:ro" -v "$OLD:/old:ro" -v "$NEW:/new:ro" -w /w "$IMG" sh -c "apk add -q --no-cache nftables >/dev/null &&
    sysctl -qw net.netfilter.nf_conntrack_acct=1; python3 -I /w/audit/p31zhfix/e/e_realretry.py $0 $1 $2 $3 > /tmp/r.txt 2>&1;
    grep -E \"^WARMLOG|rror:\" /tmp/r.txt | cut -c1-600;
    grep ^RESULT /tmp/r.txt | cut -c8- > /tmp/r.json; python3 -I /w/audit/p31zhfix/e/zh_sum.py real_$0_$1_$2_$3_r${RETRY:-1} /tmp/r.json"'
