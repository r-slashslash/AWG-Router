#!/bin/bash
# Запуск сервера AmneziaWG (по образцу start.sh приложения AmneziaVPN)
CONF=/opt/amnezia/awg/awg0.conf
WG_CONF=/opt/amnezia/awg/wg0.conf
echo "Container startup"

awg-quick down "$CONF" 2>/dev/null

# Правила AWG Router до подъёма сервера: панель узнаёт о перезапуске контейнера не сразу, а в новой сети
# контейнера её правил нет — клиенты эти секунды шли бы мимо выходов напрямую. Файл пишет панель (те же
# правила, что остаются при её остановке); через секунды она заменит их своими.
HOLD=/opt/amnezia/awg/awgr-hold-awg0.nft
if [ -f "$HOLD" ] && command -v nft >/dev/null 2>&1; then
  nft -f "$HOLD" || echo "AWG Router rules were not applied"
fi

[ -f "$CONF" ] && awg-quick up "$CONF"

# подсеть клиентов — из Address в конфиге (например 10.8.1.0/24)
SUBNET=$(awk -F' *= *' '/^Address/ {print $2; exit}' "$CONF" | cut -d, -f1)
SUBNET=${SUBNET:-10.8.1.0/24}

iptables -A INPUT -i awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -j ACCEPT
iptables -A OUTPUT -o awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -o eth0 -s "$SUBNET" -j ACCEPT
iptables -A FORWARD -i awg0 -o eth1 -s "$SUBNET" -j ACCEPT
iptables -t nat -A POSTROUTING -s "$SUBNET" -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s "$SUBNET" -o eth1 -j MASQUERADE

if [ -f "$WG_CONF" ]; then
  awg-quick down "$WG_CONF" 2>/dev/null
  WG_HOLD=/opt/amnezia/awg/awgr-hold-wg0.nft
  if [ -f "$WG_HOLD" ] && command -v nft >/dev/null 2>&1; then
    nft -f "$WG_HOLD" || echo "AWG Router rules were not applied (wg0)"
  fi
  awg-quick up "$WG_CONF"
  WG_SUBNET=$(awk -F' *= *' '/^Address/ {print $2; exit}' "$WG_CONF" | cut -d, -f1)
  WG_SUBNET=${WG_SUBNET:-10.8.2.0/24}
  iptables -A INPUT -i wg0 -j ACCEPT
  iptables -A FORWARD -i wg0 -j ACCEPT
  iptables -A OUTPUT -o wg0 -j ACCEPT
  iptables -A FORWARD -i wg0 -o eth0 -s "$WG_SUBNET" -j ACCEPT
  iptables -A FORWARD -i wg0 -o eth1 -s "$WG_SUBNET" -j ACCEPT
  iptables -t nat -A POSTROUTING -s "$WG_SUBNET" -o eth0 -j MASQUERADE
  iptables -t nat -A POSTROUTING -s "$WG_SUBNET" -o eth1 -j MASQUERADE
fi

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

tail -f /dev/null
