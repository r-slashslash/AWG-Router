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
# основная сеть контейнера — та, где маршрут по умолчанию. С сетями исходящих адресов (zz-awgr-out-K) Docker после
# перезапуска может дать ей другое имя (eth2…), а не eth0 или eth1 — тогда «Напрямую» шло бы без подмены адреса
WAN=$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
OUTS="eth0 eth1"
if [ -n "$WAN" ]; then case " $OUTS " in *" $WAN "*) ;; *) OUTS="$OUTS $WAN" ;; esac; fi
for o in $OUTS; do
  iptables -A FORWARD -i awg0 -o "$o" -s "$SUBNET" -j ACCEPT
done
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
for o in $OUTS; do
  iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$o" -j MASQUERADE
done

tail -f /dev/null
