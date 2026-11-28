#!/bin/sh
# Сети для проверки П31 (машина GitHub, контейнер образа панели с --privileged): srvN — dnsproxy.py и клиенты
# (10.99.0.2 — адрес системы, .3 — «Напрямую — адрес» по метке 0x2101, .4 — «выход» по метке 0x2001), inetN — серверы
# DNS (10.99.1.x) за veth. netem — задержка в одну сторону (мс) и потери (%) на обоих концах veth.
#   net.sh marks                 — метки и адрес отправителя (новый код, потом старый)
#   net.sh scen OUT DELAY LOSS сценарий параметры…  — сценарий scen.py «до/после» в своей паре сетей
#   net.sh rate DELAY LOSS ENC   — частота ложного непрохождения проверки (checkrate.py)
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

pair() {  # pair N DELAY LOSS
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

labenv() {  # labenv N — окружение стенда для пары N
  echo "LAB_NET=10.99.1. LAB_SRV_NS=/run/netns/inet$1 LAB_NFT_NS=inet$1 LAB_OLD=${LAB_OLD:-/old/app} LAB_NEW=${LAB_NEW:-/w/app} LAB_CERT_DIR=$LAB PYTHONDONTWRITEBYTECODE=1"
}

case "$1" in
  cert) ;;
  marks)
    for v in new old; do
      unpair 0; pair 0 0 0
      echo "== marks $v"
      ip netns exec srv0 env $(labenv 0) MARKS_VER=$v python3 -I "$D/marks.py" || echo "marks $v failed"
      unpair 0
    done ;;
  d6)
    for v in new old; do
      unpair 0; pair 0 0 0
      echo "== d6 $v"
      ip netns exec srv0 env $(labenv 0) MARKS_VER=$v LAB_DIR="$D" python3 -I "$D/d6marks.py" || echo "d6 $v failed"
      unpair 0
    done ;;
  scen)
    out=$2; dl=$3; ls=$4; shift 4
    n=$(echo "$out" | cksum | cut -c1-6)
    unpair "$n"; pair "$n" "$dl" "$ls"
    ip netns exec srv$n env $(labenv "$n") LAB_NETEM="$dl/$ls" python3 -I "$D/scen.py" "$@" > $LAB/$out.json 2> $LAB/$out.err || true
    unpair "$n"
    echo "== $out (netem ${dl}ms ${ls}%)"; cat $LAB/$out.json; tail -3 $LAB/$out.err ;;
  rate)
    n=$(echo "rate$2$3$4" | cksum | cut -c1-6)
    unpair "$n"; pair "$n" "$2" "$3"
    ip netns exec srv$n env $(labenv "$n") LAB_NETEM="$2/$3" python3 -I "$D/checkrate.py" "$4" "${5:-200}" "${6:-20}" || true
    unpair "$n" ;;
esac
