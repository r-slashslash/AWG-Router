#!/bin/sh
# Е: проверка c934013 («кэш различает флаги») на настоящем резолвере: dnsproxy.py до (OLD) и после (NEW) на машине
# GitHub, общий сервер — 1.1.1.1 без шифрования. Сначала имя спрашивает клиент без EDNS (как телефон), потом — с DO
# (dig +dnssec) и systemd-resolved с DNSSEC=yes. Печатает, есть ли подписи (RRSIG) и открылось ли имя.
OLD=$1; NEW=$2
for v in old:20:$OLD new:21:$NEW; do
  name=${v%%:*}; rest=${v#*:}; ip=127.0.0.${rest%%:*}; app=${rest#*:}
  printf '{"listen": "%s", "port": 53, "clients": "127.0.0.0/8", "stats": "/tmp/st_%s.json", "upstreams": ["1.1.1.1"], "encrypt": "plain", "default": {"mark": 0, "tcp": false}, "routes": {}, "dom": {}}' $ip $name > /tmp/dns_$name.json
  sudo python3 -I $app/dnsproxy.py /tmp/dns_$name.json > /tmp/dnsproxy_$name.log 2>&1 &
done
sleep 2
for d in cloudflare.com ietf.org; do
  for v in old:20 new:21; do
    ip=127.0.0.${v#*:}
    dig +noedns +short @$ip $d A >/dev/null
    sig=$(dig +dnssec @$ip $d A | grep -c "RRSIG")
    echo "$d ${v%%:*}: dig +dnssec after a plain query — RRSIG lines: $sig"
  done
done
sudo mkdir -p /etc/systemd/resolved.conf.d
for v in old:20 new:21; do
  ip=127.0.0.${v#*:}
  for d in www.cloudflare.com www.ietf.org; do dig +noedns +short @$ip $d A >/dev/null; done
  printf '[Resolve]\nDNS=%s\nDNSSEC=yes\nDomains=~.\nFallbackDNS=\n' $ip | sudo tee /etc/systemd/resolved.conf.d/e.conf >/dev/null
  sudo systemctl restart systemd-resolved; sleep 1; sudo resolvectl flush-caches
  for d in www.cloudflare.com www.ietf.org; do echo "resolved DNSSEC=yes via ${v%%:*} $d: $(resolvectl query $d 2>&1 | tail -1)"; done
done
sudo rm -f /etc/systemd/resolved.conf.d/e.conf; sudo systemctl restart systemd-resolved
