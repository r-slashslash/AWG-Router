# Пароль панели, её секретный путь и адрес сервера — не в журналы E2E: репозиторий открытый, вывод прогона и его
# файлы (upload-artifact) видит любой, а тестовый сервер в России — настоящая машина владельца.
# Подключается из upgrade.sh и restart.sh:
#   hide_secrets <папка панели>  — после установки: GitHub заменяет эти строки звёздочками в выводе прогона;
#   scrub_logs <папка журналов>  — при выходе (trap): те же строки в файлах журналов заменяются на ***.
SECRETS=()

hide_secrets() {
  local k v
  for k in PANEL_PASSWORD PANEL_BASE_PATH PUBLIC_HOST; do
    v=$(grep -E "^$k=" "$1/.env" 2>/dev/null | tail -1 | cut -d= -f2-)
    v="${v#/}"
    [ "${#v}" -ge 4 ] || continue          # короткое («/», пусто) не прячем: звёздочки съели бы полжурнала
    SECRETS+=("$v")
    echo "::add-mask::$v"
  done
}

scrub_logs() {
  [ "${#SECRETS[@]}" -gt 0 ] || return 0
  printf '%s\n' "${SECRETS[@]}" | python3 -c '
import os, sys
secrets = [s for s in sys.stdin.read().split("\n") if s]
for name in os.listdir(sys.argv[1]):
    p = os.path.join(sys.argv[1], name)
    if not os.path.isfile(p):
        continue
    with open(p, "rb") as f:
        data = f.read()
    new = data
    for s in secrets:
        new = new.replace(s.encode(), b"***")
    if new != data:
        with open(p, "wb") as f:
            f.write(new)
' "$1"
}
