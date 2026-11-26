"""Сеть Docker исходящего адреса (1.25.0) на Docker этой машины — любой версии, и старше 28, где нет GwPriority.

Режим контейнера: на каждый исходящий адрес панель создаёт сеть Docker с com.docker.network.host_ipv4 и подключает её к
работающему контейнеру сервера AWG. Docker 28 не делает её маршрутом по умолчанию (GwPriority −1000); старый Docker
выбирает шлюз по-своему (по имени сети — поэтому имя начинается с «zz-»), а если всё же сменил его — панель сеть
отключает. Здесь — то же, что в container_e2e.addr_net (сайт за вторым адресом, «Напрямую — адрес» видит второй адрес,
сеть пропала — блок, проход подключил снова), но с контейнером-заглушкой из любого образа со sleep и в двух видах:
контейнер в сети Docker по умолчанию (bridge) и в своей сети, как у приложения AmneziaVPN.

Только на одноразовой машине или тестовом VPS: root, Docker, ip, nft. Адресов машины не печатает — только свои
тестовые (172.31.250.x на своём veth).
Запуск: sudo python3 tests/addrs_docker_e2e.py [образ]     (по умолчанию alpine:3.22)
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
import container_e2e as ce  # noqa: E402
from container_e2e import sh  # noqa: E402

NAME = "awgr-addrcheck"
NETS = (None, "amnezia-dns-net-e2e")          # bridge по умолчанию и своя сеть «как у AmneziaVPN»


def main() -> int:
    image = sys.argv[1] if len(sys.argv) > 1 else "alpine:3.22"
    v = json.loads(sh("docker", "version", "--format", "{{json .Server}}").stdout or "{}")
    print(f"Docker {v.get('Version')} (API {v.get('ApiVersion')})")
    results = []
    d = tempfile.mkdtemp()
    os.chmod(d, 0o755)
    with open(os.path.join(d, "awg0.conf"), "w") as f:      # Engine ищет конфиг сервера в контейнере
        f.write("[Interface]\nListenPort = 47999\n")
    ce.NAME = NAME
    try:
        for net in NETS:
            sh("docker", "rm", "-f", NAME, check=False)
            if net:
                sh("docker", "network", "rm", net, check=False)
                sh("docker", "network", "create", net)
            sh("docker", "run", "-d", "--name", NAME, *(["--network", net] if net else []),
               "-v", f"{d}:/opt/amnezia/awg", "--entrypoint", "sleep", image, "3600")
            got = []
            ce.addr_net(got)
            where = f"[{net or 'bridge'}] "
            results += [(where + n, ok, det) for n, ok, det in got]
            left = sh("docker", "network", "ls", "-q", "--filter", "name=zz-awgr-out-").stdout.split()
            results.append((where + "сети панели убраны (uninstall)", not left, left))
    finally:
        sh("docker", "rm", "-f", NAME, check=False)
        for net in NETS:
            if net:
                sh("docker", "network", "rm", net, check=False)
        for n in sh("docker", "network", "ls", "-q", "--filter", "name=zz-awgr-out-", check=False).stdout.split():
            sh("docker", "network", "rm", n, check=False)
        shutil.rmtree(d, ignore_errors=True)
    bad = 0
    for name, good, detail in results:
        print(("OK   " if good else "FAIL ") + name + ("" if good else f"  {detail}"))
        bad += not good
    print(f"{len(results) - bad}/{len(results)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
