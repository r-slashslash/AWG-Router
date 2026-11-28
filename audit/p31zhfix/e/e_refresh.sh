#!/bin/sh
# Е: продлевает ли `nft add element` срок адреса, который уже есть в наборе с timeout (так dnsproxy.py «обновляет» адрес
# фильтра по DNS). Своя сеть (unshare -n). Печатает ядро, nft и срок адреса после повторного добавления: ~1m40s —
# продлил, ~7s — нет (адрес выпадет из набора по первому сроку, хотя dnsproxy.py считает его живым).
# Вторая часть — прототип: одна транзакция «add (если нет) → delete → add с новым сроком» — для адреса, который есть, и
# для адреса, которого нет.
printf 'table ip t {\n\tset s {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n}\n' > /tmp/e_t1.nft
echo "kernel $(uname -r) $(nft --version)"
unshare -n sh -c 'nft -f /tmp/e_t1.nft && nft add element ip t s "{ 1.2.3.4 timeout 10s }" && sleep 3 &&
  nft add element ip t s "{ 1.2.3.4 timeout 100s }" && echo "plain add: $(nft list set ip t s | grep -o "elements = .*")" &&
  printf "add element ip t s { 1.2.3.4 timeout 1s, 5.6.7.8 timeout 1s }\ndelete element ip t s { 1.2.3.4, 5.6.7.8 }\nadd element ip t s { 1.2.3.4 timeout 100s, 5.6.7.8 timeout 100s }\n" > /tmp/e_t2.nft &&
  nft -f /tmp/e_t2.nft && echo "add-delete-add: $(nft list set ip t s | grep -o "elements = .*")"'
