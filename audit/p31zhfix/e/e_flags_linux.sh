#!/bin/sh
# Е: флаги и EDNS настоящих клиентов DNS на машине GitHub (Ubuntu): dig, kdig, glibc (getent, Python), systemd-resolved с
# DNSSEC=no / allow-downgrade / yes, dnsmasq, unbound (без проверки и с проверкой DNSSEC), BIND (named) как пересылающие.
# Каждый клиент спрашивает свою «ловушку» (e_flags.py) на своём адресе 127.0.0.X:53. Плюс: отвечают ли публичные
# резолверы своим COOKIE (если да, чужой COOKIE из общего ответа клиенту не подходит).
D=$(cd "$(dirname "$0")" && pwd)
sudo mkdir -p /var/tmp/eflags; L=/var/tmp/eflags/flags.log; sudo rm -f $L
sudo apt-get install -y -qq dnsmasq-base unbound bind9 knot-dnsutils >/dev/null 2>&1 || true
sudo systemctl stop unbound named bind9 2>/dev/null || true
for x in 2:glibc 3:resolved-no 4:resolved-allow-downgrade 5:resolved-yes 6:dnsmasq 7:unbound 8:unbound-validator 9:dig 10:bind 11:glibc-edns0; do
  ip=127.0.0.${x%%:*}; tag=${x#*:}
  sudo python3 -I "$D/e_flags.py" serve $ip 53 $L $tag >/tmp/flagsrv_$tag.log 2>&1 &
done
sleep 3
sudo ss -lunp | grep ":53 " | head -20
for f in /tmp/flagsrv_*.log; do echo "$f: $(tail -c 400 $f)"; done
echo "== dig, kdig"
dig +short @127.0.0.9 dig-default.example; dig +short +dnssec @127.0.0.9 dig-dnssec.example; dig +short +noedns @127.0.0.9 dig-noedns.example
kdig +short @127.0.0.9 kdig-default.example || true
echo "== glibc"
sudo cp -P /etc/resolv.conf /tmp/resolv.bak
sudo rm -f /etc/resolv.conf; echo "nameserver 127.0.0.2" | sudo tee /etc/resolv.conf >/dev/null
getent ahosts glibc-getent.example; python3 -c "import socket; print(socket.getaddrinfo('glibc-python.example', 80)[:1])"
printf 'nameserver 127.0.0.11\noptions edns0 trust-ad\n' | sudo tee /etc/resolv.conf >/dev/null
getent ahosts glibc-edns0.example
sudo rm -f /etc/resolv.conf; sudo cp -P /tmp/resolv.bak /etc/resolv.conf
echo "== systemd-resolved"
systemctl --version | head -1
sudo mkdir -p /etc/systemd/resolved.conf.d
for m in 3:no 4:allow-downgrade 5:yes; do
  printf '[Resolve]\nDNS=127.0.0.%s\nDNSSEC=%s\nDomains=~.\nFallbackDNS=\n' "${m%%:*}" "${m#*:}" | sudo tee /etc/systemd/resolved.conf.d/e.conf >/dev/null
  sudo systemctl restart systemd-resolved; sleep 1; sudo resolvectl flush-caches
  resolvectl query "resolved-${m#*:}.example" 2>&1 | head -2
  resolvectl query "resolved2-${m#*:}.example" 2>&1 | head -1
done
sudo rm -f /etc/systemd/resolved.conf.d/e.conf; sudo systemctl restart systemd-resolved
echo "== dnsmasq"
dnsmasq --version | head -1
sudo dnsmasq --no-daemon --port=5300 --listen-address=127.0.0.1 --bind-interfaces --no-resolv --server=127.0.0.6 --user=root >/dev/null 2>&1 &
sleep 1; dig +short @127.0.0.1 -p 5300 dnsmasq-default.example; dig +short +dnssec @127.0.0.1 -p 5300 dnsmasq-dnssec.example
dig +short +noedns @127.0.0.1 -p 5300 dnsmasq-noedns.example
echo "== unbound"
unbound -V | head -1
for v in 7:iterator 8:validator; do
  port=$((5300 + ${v%%:*}))
  mods="iterator"; [ "${v#*:}" = validator ] && mods="validator iterator"
  printf 'server:\n  interface: 127.0.0.1@%s\n  do-not-query-localhost: no\n  access-control: 127.0.0.0/8 allow\n  module-config: "%s"\n  chroot: ""\n  username: ""\n  pidfile: ""\n  use-syslog: no\n  verbosity: 0\n  harden-dnssec-stripped: no\n  val-permissive-mode: yes\n  trust-anchor: ". DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"\nforward-zone:\n  name: "."\n  forward-addr: 127.0.0.%s\n' \
    $port "$mods" ${v%%:*} | sudo tee /etc/unbound/e${v%%:*}.conf >/dev/null
  sudo unbound -d -c /etc/unbound/e${v%%:*}.conf >/tmp/unbound${v%%:*}.log 2>&1 &
  sleep 2; dig +short @127.0.0.1 -p $port "unbound-${v#*:}.example"; tail -2 /tmp/unbound${v%%:*}.log
done
echo "== bind"
named -v
printf 'options {\n  directory "/var/cache/bind";\n  listen-on port 5310 { 127.0.0.1; };\n  listen-on-v6 { none; };\n  forwarders { 127.0.0.10; };\n  forward only;\n  recursion yes;\n  allow-query { any; };\n  dnssec-validation no;\n  pid-file none;\n};\n' | sudo tee /etc/bind/e.conf >/dev/null
sudo named -g -c /etc/bind/e.conf -u bind >/tmp/named.log 2>&1 &
sleep 3; dig +short @127.0.0.1 -p 5310 bind-default.example; tail -3 /tmp/named.log
sleep 2
echo "== summary (count tag proto qtype RD CD AD EDNS DO options)"
sudo python3 -I "$D/e_flags.py" sum $L
echo "== public resolvers: COOKIE in reply"
for ip in 1.1.1.1 8.8.8.8 9.9.9.9 77.88.8.8 94.140.14.14 223.5.5.5 119.29.29.29; do
  echo "$ip: $(dig +cookie +time=3 +tries=1 @$ip example.com | grep -E 'COOKIE|status' | tr '\n' ' ')"
done
