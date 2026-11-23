#!/bin/bash
# Запуск сервера AmneziaWG (по образцу start.sh приложения AmneziaVPN)
CONF=/opt/amnezia/awg/awg0.conf
WG_CONF=/opt/amnezia/awg/wg0.conf
echo "Container startup"

start_iface() {
  local iface=$1 conf=$2 def_sub=$3
  awg-quick down "$conf" 2>/dev/null

  # Правила AWG Router до подъёма сервера: панель узнаёт о перезапуске контейнера не сразу, а в новой сети
  # контейнера её правил нет — клиенты эти секунды шли бы мимо выходов напрямую. Файл пишет панель (те же
  # правила, что остаются при её остановке); через секунды она заменит их своими.
  local hold=/opt/amnezia/awg/awgr-hold-${iface}.nft
  if [ -f "$hold" ] && command -v nft >/dev/null 2>&1; then
    nft -f "$hold" || echo "AWG Router rules were not applied ($iface)"
  fi

  [ -f "$conf" ] && awg-quick up "$conf"

  # подсеть клиентов — из Address в конфиге (например 10.8.1.0/24)
  local subnet
  subnet=$(awk -F' *= *' '/^Address/ {print $2; exit}' "$conf" | cut -d, -f1)
  subnet=${subnet:-$def_sub}

  iptables -A INPUT -i "$iface" -j ACCEPT
  iptables -A FORWARD -i "$iface" -j ACCEPT
  iptables -A OUTPUT -o "$iface" -j ACCEPT
  iptables -A FORWARD -i "$iface" -o eth0 -s "$subnet" -j ACCEPT
  iptables -A FORWARD -i "$iface" -o eth1 -s "$subnet" -j ACCEPT
  iptables -t nat -A POSTROUTING -s "$subnet" -o eth0 -j MASQUERADE
  iptables -t nat -A POSTROUTING -s "$subnet" -o eth1 -j MASQUERADE
}

start_iface awg0 "$CONF" 10.8.1.0/24
if [ -f "$WG_CONF" ]; then
  start_iface wg0 "$WG_CONF" 10.8.2.0/24
fi
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

tail -f /dev/null
