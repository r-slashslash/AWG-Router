#!/bin/bash
# Запуск сервера AmneziaWG (по образцу start.sh приложения AmneziaVPN)
CONF=/opt/amnezia/awg/awg0.conf
echo "Container startup"

awg-quick down "$CONF" 2>/dev/null
[ -f "$CONF" ] && awg-quick up "$CONF"

# подсеть клиентов — из Address в конфиге (например 10.8.1.0/24)
SUBNET=$(awk -F' *= *' '/^Address/ {print $2; exit}' "$CONF" | cut -d, -f1)
SUBNET=${SUBNET:-10.8.1.0/24}

iptables -A INPUT -i awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -j ACCEPT
iptables -A OUTPUT -o awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -o eth0 -s "$SUBNET" -j ACCEPT
iptables -A FORWARD -i awg0 -o eth1 -s "$SUBNET" -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s "$SUBNET" -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s "$SUBNET" -o eth1 -j MASQUERADE

tail -f /dev/null
