#!/bin/sh
# Ж (копия стенда проверки Е; версии: old — d7a90cc /old, new — c934013 /new, fix — ветка /w): сети для проверки (как net.sh проверки П31): srvN — dnsproxy.py и клиенты (10.99.0.2 — адрес системы, .3 — «Напрямую —
# адрес» по метке 0x2101, .4 — «выход» по метке 0x2001), inetN — серверы DNS (10.99.1.x) за veth, netem — задержка (мс) и
# потери (%) на обоих концах. Запуск в контейнере образа панели с --privileged:
#   e_net.sh cert
#   e_net.sh run ИМЯ ЗАДЕРЖКА ПОТЕРИ скрипт.py параметры…   — скрипт в сети srv, вывод — в /tmp/lab/ИМЯ.json и .err
set -e
D=$(cd "$(dirname "$0")" && pwd)
LAB=/tmp/lab
mkdir -p $LAB
if [ ! -s $LAB/c.crt ]; then
  SAN="DNS:dns.test"
  for i in $(seq 2 40); do SAN="$SAN,IP:127.0.0.$i,IP:10.99.1.$i"; done
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=dns-test \
    -addext "subjectAltName=$SAN" -keyout $LAB/c.key -out $LAB/c.crt 2>/dev/null
fi
pair() {
  n=$1
  ip netns add srv$n; ip netns add inet$n
  ip link add a$n netns srv$n type veth peer name b$n netns inet$n
  for a in 2 3 4; do ip -n srv$n addr add 10.99.0.$a/24 dev a$n; done
  ip -n srv$n link set a$n up; ip -n srv$n link set lo up
  ip -n srv$n route add default via 10.99.0.1 src 10.99.0.2
  ip -n srv$n rule add fwmark 0x2101 lookup 201 prio 100
  ip -n srv$n route add default via 10.99.0.1 dev a$n src 10.99.0.3 table 201
  ip -n srv$n rule add fwmark 0x2001 lookup 101 prio 101
  ip -n srv$n route add default via 10.99.0.1 dev a$n src 10.99.0.4 table 101
  ip -n inet$n addr add 10.99.0.1/24 dev b$n; ip -n inet$n link set b$n up; ip -n inet$n link set lo up
  for i in $(seq 2 14); do ip -n inet$n addr add 10.99.1.$i/32 dev lo; done
  if [ "${2:-0}" != 0 ] || [ "${3:-0}" != 0 ]; then
    ip netns exec srv$n tc qdisc add dev a$n root netem delay "${2:-0}ms" loss "${3:-0}%"
    ip netns exec inet$n tc qdisc add dev b$n root netem delay "${2:-0}ms" loss "${3:-0}%"
  fi
}
unpair() { ip netns del srv$1 2>/dev/null || true; ip netns del inet$1 2>/dev/null || true; }
case "$1" in
  cert) ;;
  run)
    out=$2; dl=$3; ls=$4; script=$5; shift 5
    n=$(echo "$out" | cksum | cut -c1-5)
    unpair "$n"; pair "$n" "$dl" "$ls"
    ip netns exec srv$n env LAB_NET=10.99.1. LAB_SRV_NS=/run/netns/inet$n LAB_NFT_NS=inet$n LAB_OLD=${LAB_OLD:-/old/app} \
      LAB_NEW=${LAB_NEW:-/new/app} LAB_FIX=${LAB_FIX:-/w/app} LAB_VERS=${LAB_VERS:-old,new,fix} MARKS_VER=${MARKS_VER:-fix} LAB_CERT_DIR=$LAB PYTHONDONTWRITEBYTECODE=1 \
      python3 -I "$D/$script" "$@" > $LAB/$out.json 2> $LAB/$out.err || echo "$out failed"
    unpair "$n"
    echo "== $out"; python3 -I "$D/zh_sum.py" "$out" $LAB/$out.json; tail -3 $LAB/$out.err | cut -c1-300 ;;
esac
