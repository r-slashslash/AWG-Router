#!/bin/bash
# Запуск сервера AmneziaWG (по образцу start.sh приложения AmneziaVPN)
CONF=/opt/amnezia/awg/awg0.conf
echo "Container startup"

awg-quick down "$CONF" 2>/dev/null

# Правила AWG Router до подъёма сервера: панель узнаёт о перезапуске контейнера не сразу, а в новой сети
# контейнера её правил нет — клиенты эти секунды шли бы мимо выходов напрямую. Файл пишет панель (те же
# правила, что остаются при её остановке); через секунды она заменит их своими.
HOLD=/opt/amnezia/awg/awgr-hold-awg0.nft
if [ -f "$HOLD" ] && command -v nft >/dev/null 2>&1; then
  nft -f "$HOLD" || echo "AWG Router rules were not applied"
fi
# IPv6 клиентов — отдельной командой: без IPv6 в ядре эта таблица не встанет, а правила выше — должны
HOLD6=/opt/amnezia/awg/awgr-hold6-awg0.nft
if [ -f "$HOLD6" ] && command -v nft >/dev/null 2>&1; then
  nft -f "$HOLD6" 2>/dev/null || echo "AWG Router IPv6 rules were not applied"
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
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s "$SUBNET" -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s "$SUBNET" -o eth1 -j MASQUERADE

tail -f /dev/null
