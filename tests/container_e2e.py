"""Перезапуск сервера AWG по-настоящему (1.21.0): правила панели «до панели» и события Docker.

Собирает образ сервера AWG из awg-server/ (как у пользователей), кладёт в его папку конфиг и файл правил
`awgr-hold-awg0.nft` (как Engine._save_hold) и запускает контейнер:
  * start.sh ставит правила до подъёма awg0 — таблица панели есть сразу, без панели;
  * без файла правил таблицы нет (значит, она именно из файла);
  * панель узнаёт о запуске контейнера из потока событий Docker (system.docker_events);
  * панель видит, что этот контейнер сам ставит правила (метка в /opt/amnezia/start.sh);
  * смена порта (1.22.0, system.recreate_with_port): свой контейнер (папка на диске хоста), контейнер «как у
    AmneziaVPN» (файлы внутри, вторая сеть) и возврат прежнего, когда новый порт занят;
  * исходящий адрес (1.25.0): сеть Docker с com.docker.network.host_ipv4 подключается к контейнеру без перезапуска,
    маршрут по умолчанию контейнера не меняется, «Напрямую — адрес» уходит с этого адреса, сеть убрали — блок.

Только на одноразовой машине (машина GitHub Actions): нужны root, Docker, awg в PATH (для ключей).
Запуск: sudo env PATH=<bin>:$PATH python3 tests/container_e2e.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import awgserver, nftgen, system  # noqa: E402
from app.engine import Engine  # noqa: E402
from app.store import Store  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
IMAGE, NAME = "awgr-server-e2e", "amnezia-awg-e2e"


def sh(*cmd, check=True, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {p.stderr or p.stdout}")
    return p


def hold_rules() -> str:
    """Правила «до панели», как их собирает панель (build_ruleset(hold=True)): выход 1 ещё без туннеля → блок."""
    return nftgen.generate("awg0", {}, [], {"rules": [], "default": 1, "domain": []}, {}, None)


def run_container(data: str) -> None:
    sh("docker", "rm", "-f", NAME, check=False)
    sh("docker", "run", "-d", "--name", NAME, "--privileged", "--cap-add=NET_ADMIN",
       "-v", f"{data}:/opt/amnezia/awg", IMAGE)


def wait_awg0(timeout=30) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if sh("docker", "exec", NAME, "ip", "link", "show", "awg0", check=False).returncode == 0:
            return True
        time.sleep(0.5)
    return False


NET = "awgr-e2e-net"
ROWS = '[{"clientId": "e2e", "userData": {"clientName": "phone"}}]'


def listen_port() -> str:
    return sh("docker", "exec", NAME, "awg", "show", "awg0", "listen-port", check=False).stdout.strip()


def bound(port: int) -> bool:
    """Порт опубликован Docker'ом (docker port) для UDP."""
    return f"{port}/udp" in sh("docker", "port", NAME, check=False).stdout


def leftovers() -> list[str]:
    return sh("docker", "ps", "-a", "--format", "{{.Names}}", "--filter", f"name={NAME}-old-",
              check=False).stdout.split()


def port_change(results, data, sc) -> None:
    """Смена порта контейнера: как её делает панель (новый ListenPort в конфиге, потом recreate_with_port)."""
    conf_dir = "/opt/amnezia/awg"
    # 1) свой контейнер панели: папка сервера на диске хоста, без снимка образа
    sh("docker", "rm", "-f", NAME, check=False)
    with open(os.path.join(data, "clientsTable"), "w") as f:
        f.write(ROWS)
    sh("docker", "run", "-d", "--name", NAME, "--privileged", "--cap-add=NET_ADMIN", "--restart", "always",
       "-p", "47321:47321/udp", "-v", f"{data}:{conf_dir}", IMAGE)
    wait_awg0()
    old_conf = open(os.path.join(data, "awg0.conf")).read()
    sc.set("ListenPort", "47999")
    with open(os.path.join(data, "awg0.conf"), "w") as f:
        f.write(sc.render())
    err = ""
    try:
        system.recreate_with_port(NAME, conf_dir, "awg0", 47321, 47999, old_conf)
    except Exception as e:  # noqa: BLE001
        err = str(e)
    pol = sh("docker", "inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", NAME, check=False).stdout.strip()
    results.append(("свой контейнер: новый порт опубликован и слушается, папка та же, старого нет",
                    not err and bound(47999) and not bound(47321) and listen_port() == "47999"
                    and not leftovers() and pol == "always",
                    [err, listen_port(), leftovers(), pol, sh("docker", "port", NAME, check=False).stdout]))

    # 2) контейнер «как у AmneziaVPN»: файлы внутри контейнера, вторая сеть с постоянным адресом
    sh("docker", "rm", "-f", NAME, check=False)
    sh("docker", "network", "rm", NET, check=False)
    sh("docker", "network", "create", "--subnet", "172.29.99.0/24", NET)
    sc.set("ListenPort", "47321")
    inside = tempfile.mkdtemp()
    with open(os.path.join(inside, "awg0.conf"), "w") as f:
        f.write(sc.render())
    with open(os.path.join(inside, "clientsTable"), "w") as f:
        f.write(ROWS)
    sh("docker", "create", "--name", NAME, "--privileged", "--cap-add=NET_ADMIN", "--restart", "always",
       "-p", "47321:47321/udp", IMAGE)
    sh("docker", "network", "connect", "--ip", "172.29.99.7", NET, NAME)
    sh("docker", "cp", f"{inside}/.", f"{NAME}:{conf_dir}/")
    sh("docker", "start", NAME)
    wait_awg0()
    old_conf = sc.render()
    sc.set("ListenPort", "48111")
    with open(os.path.join(inside, "awg0.conf"), "w") as f:
        f.write(sc.render())
    sh("docker", "cp", os.path.join(inside, "awg0.conf"), f"{NAME}:{conf_dir}/awg0.conf")   # как write_file панели
    shutil.rmtree(inside, ignore_errors=True)
    err = ""
    try:
        system.recreate_with_port(NAME, conf_dir, "awg0", 47321, 48111, old_conf)
    except Exception as e:  # noqa: BLE001
        err = str(e)
    rows = sh("docker", "exec", NAME, "cat", f"{conf_dir}/clientsTable", check=False).stdout
    ip = sh("docker", "inspect", "-f", "{{(index .NetworkSettings.Networks \"" + NET + "\").IPAddress}}", NAME,
            check=False).stdout.strip()
    image = sh("docker", "inspect", "-f", "{{.Config.Image}}", NAME, check=False).stdout.strip()
    results.append(("контейнер AmneziaVPN: новый порт, файлы внутри и вторая сеть с адресом на месте",
                    not err and bound(48111) and listen_port() == "48111" and rows == ROWS
                    and ip == "172.29.99.7" and image.startswith(system.PORT_IMAGE + ":") and not leftovers(),
                    [err, listen_port(), rows, ip, image, leftovers()]))

    # 3) новый порт занят на хосте: Docker не запускает контейнер — прежний возвращается с прежним конфигом
    import socket
    busy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    busy.bind(("0.0.0.0", 48222))
    try:
        old_conf = sc.render()
        sc.set("ListenPort", "48222")
        sh("docker", "exec", NAME, "sh", "-c", f"cat > {conf_dir}/awg0.conf", input=sc.render())
        err = ""
        try:
            system.recreate_with_port(NAME, conf_dir, "awg0", 48111, 48222, old_conf)
        except system.SysError as e:
            err = str(e)
        wait_awg0()
        conf = sh("docker", "exec", NAME, "cat", f"{conf_dir}/awg0.conf", check=False).stdout
        results.append(("новый порт занят: ошибка, работает прежний контейнер с прежним портом и конфигом",
                        bool(err) and bound(48111) and listen_port() == "48111" and "ListenPort = 48111" in conf
                        and not leftovers(), [err, listen_port(), leftovers()]))
    finally:
        busy.close()


SITE_NS, SITE_IP, HOST_IP, SECOND = "awgrsite", "172.31.250.254", "172.31.250.1", "172.31.250.7"
MARKED = r"""
import socket,sys
s=socket.socket(); s.settimeout(4)
if int(sys.argv[2]): s.setsockopt(socket.SOL_SOCKET, 36, int(sys.argv[2]))
try:
    s.connect((sys.argv[1], 80)); print(s.recv(100).decode())
except OSError as e: print("FAIL", e)
"""


def addr_net(results) -> None:
    """Исходящий адрес в режиме контейнера (1.25.0): «сайт» в своей сети за вторым адресом хоста."""
    sh("ip", "netns", "add", SITE_NS, check=False)
    sh("ip", "link", "add", "awgrsite0", "type", "veth", "peer", "name", "awgrsite1")
    sh("ip", "link", "set", "awgrsite1", "netns", SITE_NS)
    sh("ip", "addr", "add", f"{HOST_IP}/24", "dev", "awgrsite0")
    sh("ip", "addr", "add", f"{SECOND}/32", "dev", "awgrsite0", "label", "awgrsite0:aw")   # «добавлен панелью»
    sh("ip", "link", "set", "awgrsite0", "up")
    for c in (["ip", "addr", "add", f"{SITE_IP}/24", "dev", "awgrsite1"], ["ip", "link", "set", "awgrsite1", "up"],
              ["ip", "link", "set", "lo", "up"], ["ip", "route", "add", "default", "via", HOST_IP]):
        sh("ip", "netns", "exec", SITE_NS, *c)
    site = subprocess.Popen(["ip", "netns", "exec", SITE_NS, sys.executable,
                             os.path.join(ROOT, "tests", "e2e_servers.py"), "http", "SITE", SITE_IP])
    time.sleep(0.5)
    d = tempfile.mkdtemp()
    try:
        st = Store(os.path.join(d, "state.json"))
        st.mutate(lambda s: s["settings"].update(out_hosts=[SECOND]))
        eng = Engine(st)
        eng.addr_rt()[SECOND] = {"state": "ok", "seen": SECOND}      # проверка адреса — отдельно (юнит-тесты)
        t = system._container_target(NAME)
        before = eng._ct_default(t)
        eng._addr_pass(t, st.snapshot())
        k = eng._addr_rec()["slots"].get(SECOND)
        net = system.docker_get(f"/networks/zz-awgr-out-{k}") or {}
        results.append(("сеть Docker адреса создана с host_ipv4",
                         (net.get("Options") or {}).get("com.docker.network.host_ipv4") == SECOND, net.get("Options")))
        attached = (system.docker_get(f"/containers/{NAME}/json") or {})["NetworkSettings"]["Networks"]
        results.append(("сеть подключена к контейнеру сервера без перезапуска", f"zz-awgr-out-{k}" in attached,
                        list(attached)))
        results.append(("маршрут по умолчанию контейнера не поменялся", eng._ct_default(t) == before,
                        (before, eng._ct_default(t))))
        live = getattr(eng, "_addr_live", {})
        results.append(("путь адреса встал (интерфейс сети внутри контейнера)", bool(live.get(k)), live))
        path = os.path.join(d, "r.nft")
        with open(path, "w") as f:
            f.write(nftgen.generate("awg0", {}, [], {"rules": [], "default": "direct", "domain": []}, {}, None,
                                    addrs=live))
        r = t.ns(["nft", "-f", path], check=False)
        results.append(("правила с путём адреса встали в контейнере", r.returncode == 0, r.stderr))

        def get(mark):
            return t.ns([sys.executable, "-c", MARKED, SITE_IP, str(mark)], check=False, timeout=15).stdout.strip()
        got = get(nftgen.addr_mark(k))
        results.append(("«Напрямую — адрес» из контейнера: сайт видит второй адрес", got == f"SITE from {SECOND}", got))
        got = get(0)
        results.append(("«Напрямую» из контейнера: адрес хоста, как раньше", got == f"SITE from {HOST_IP}", got))
        eng._net_drop(t, f"zz-awgr-out-{k}", True)
        eng._addr_routes = eng._addr_nets = None
        eng._addr_pass(t, st.snapshot())
        got = get(nftgen.addr_mark(k))
        results.append(("сеть адреса убрали: метка адреса — никуда, не с адреса хоста", got.startswith("FAIL"), got))
        eng.remove_own_addrs()
    finally:
        site.kill()
        sh("ip", "netns", "del", SITE_NS, check=False)
        sh("ip", "link", "del", "awgrsite0", check=False)
        shutil.rmtree(d, ignore_errors=True)


def main():
    results = []
    data = tempfile.mkdtemp()
    os.chmod(data, 0o700)
    priv = sh("awg", "genkey").stdout.strip()
    sc = awgserver.new_server(priv, 47321, "10.8.1.0/24", awgserver.generate_params(True), amnezia_style=True)
    with open(os.path.join(data, "awg0.conf"), "w") as f:
        f.write(sc.render())
    hold = os.path.join(data, system.HOLD_NAME.format(iface="awg0"))
    with open(hold, "w") as f:
        f.write(hold_rules())
    try:
        print(sh("docker", "build", "-q", "-t", IMAGE, os.path.join(ROOT, "awg-server")).stdout.strip())

        seen = []
        threading.Thread(target=lambda: system.docker_events(seen.append), daemon=True).start()
        time.sleep(1)                                   # поток событий открыт до запуска

        run_container(data)
        up = wait_awg0()
        results.append(("сервер AWG в контейнере поднялся (awg0)", up, sh("docker", "logs", NAME, check=False).stdout[-300:]))
        table = sh("docker", "exec", NAME, "nft", "list", "table", "ip", "awgr", check=False)
        results.append(("правила панели есть без панели (start.sh поставил их до awg-quick up)",
                        table.returncode == 0 and "chain c_prerouting" in table.stdout and "o_block" in table.stdout,
                        (table.stderr or table.stdout)[-300:]))
        results.append(("в правилах выход без туннеля — блок", "meta mark set" in table.stdout and "reject" in table.stdout,
                        table.stdout[-300:]))
        t0 = time.time()
        while NAME not in seen and time.time() - t0 < 10:
            time.sleep(0.2)
        results.append(("панель узнала о запуске из событий Docker", NAME in seen, seen))
        script = sh("docker", "exec", NAME, "cat", "/opt/amnezia/start.sh").stdout
        results.append(("контейнер сам ставит правила (метка для Engine._hold_path)", "awgr-hold" in script, ""))

        os.unlink(hold)
        run_container(data)
        up = wait_awg0()
        table = sh("docker", "exec", NAME, "nft", "list", "table", "ip", "awgr", check=False)
        results.append(("без файла правил таблицы нет (она именно из файла), сервер работает",
                        up and table.returncode != 0, table.stdout[-200:]))

        port_change(results, data, sc)
        run_container(data)
        wait_awg0()
        addr_net(results)
    finally:
        sh("docker", "rm", "-f", NAME, check=False)
        for n in sh("docker", "ps", "-aq", "--filter", f"name={NAME}-old-", check=False).stdout.split():
            sh("docker", "rm", "-f", n, check=False)
        sh("docker", "network", "rm", NET, check=False)
        shutil.rmtree(data, ignore_errors=True)

    bad = 0
    for name, good, detail in results:
        print(("OK   " if good else "FAIL ") + name + ("" if good else f"  {detail}"))
        bad += not good
    print(f"{len(results) - bad}/{len(results)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
