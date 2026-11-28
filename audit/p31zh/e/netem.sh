#!/bin/sh
# Части проверки П31 на машине GitHub с netem (вызывается из workflow в контейнере образа панели): block, loss, rate, slow.
D=$(cd "$(dirname "$0")" && pwd)
sh "$D/net.sh" cert       # сертификат — один раз, до параллельных запусков
if [ "$1" = rate ]; then                                 # своя часть: вывод — JSON, не сценарии
  for d in 40 150 300 750; do for l in 0 5 10 20; do for e in doh dot plain; do echo "$d $l $e"; done; done; done |
    xargs -P 4 -L 1 sh "$D/net.sh" rate
  exit 0
fi
case "$1" in
  block) {
    for d in 40 150; do for k in syn rst hello freeze; do for pre in false true; do
      echo "blk_${k}_${pre}_$d $d 0 block kind=$k pre_open=$pre"; done; done; done
    for k in syn freeze; do echo "blk_dot_${k}_true_40 40 0 block kind=$k enc=dot pre_open=true"; done
    echo "blk_udp53_40 40 0 block kind=udp enc=plain"
  } ;;
  loss) {
    for l in 1 5 10 20; do echo "loss_plain_$l 40 $l loss pct=$l enc=plain nft_loss=false dur=180"; done
    for l in 5 10 20; do echo "loss_doh_$l 40 $l loss pct=$l enc=doh nft_loss=false dur=180"; done
  } ;;
  slow) {
    echo "slow_doh_150 150 0 slow_one enc=doh fb=udp"
    echo "slow_dot_150 150 0 slow_one enc=dot fb=udp"
    echo "rep2_40 40 0 slow_repeat rate=2"
    echo "site8_40 40 0 dead_site n=8 repeat=15"
    echo "mir_udp_40 40 0 mirror fb=udp"
    echo "fl30s_40 40 0 flaky pass_pct=30 mode=syn"
    echo "fl30f_40 40 0 flaky pass_pct=30 mode=freeze"
  } ;;
esac | xargs -P 4 -L 1 sh "$D/net.sh" scen
