"""Перезапуск сервера AWG по-настоящему (1.21.0): правила панели «до панели» и события Docker.

Собирает образ сервера AWG из awg-server/ (как у пользователей), кладёт в его папку конфиг и файл правил
`awgr-hold-awg0.nft` (как Engine._save_hold) и запускает контейнер:
  * start.sh ставит правила до подъёма awg0 — таблица панели есть сразу, без панели;
  * без файла правил таблицы нет (значит, она именно из файла);
  * панель узнаёт о запуске контейнера из потока событий Docker (system.docker_events);
  * панель видит, что этот контейнер сам ставит правила (метка в /opt/amnezia/start.sh).

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
    finally:
        sh("docker", "rm", "-f", NAME, check=False)
        shutil.rmtree(data, ignore_errors=True)

    bad = 0
    for name, good, detail in results:
        print(("OK   " if good else "FAIL ") + name + ("" if good else f"  {detail}"))
        bad += not good
    print(f"{len(results) - bad}/{len(results)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
