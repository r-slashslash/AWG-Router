"""Полный маршрут AWG -> Engine -> IKEv2 с проверкой отсутствия прямой утечки.

Запускать в отдельном привилегированном Linux-контейнере с отключённой внешней
сетью: python3 -B tests/ikev2_routing_e2e.py. Нужны бинарники из Dockerfile,
/dev/net/tun и поддержка XFRM в ядре. Внешние серверы и реквизиты не нужны.
Тест проверяет HTTP Host; проверка DNS и полноценного HTTPS сюда не входит.
"""
from __future__ import annotations

import base64
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from unittest import mock

# Разные внешние адреса позволяют отключить транспорт VPN, сохранив прямой путь.
ROUTER_WAN = "172.20.0.1"
DIRECT_WAN = "172.20.0.2"
TRANSIT_WAN = "198.18.100.1"
IKE_WAN = "198.18.100.2"
# Один и тот же ресурс существует с обеих сторон, поэтому ответ различает пути.
RESOURCE = "10.55.0.10"
CONTROL = "8.8.4.4"
SITE = "portal.example.test"
UPSTREAM = "u_ike"
HTTP_TIMEOUT = 1.5
WAIT_TIMEOUT = 25
HERE = Path(__file__).resolve()


def run(*args, check=True, **kwargs):
    """Ограничение каждого шага сохраняет диагностику при ошибке внешней программы."""
    return subprocess.run(args, capture_output=True, text=True, timeout=20, check=check, **kwargs)


def require(condition, message):
    """Проверки сохраняются и при запуске Python с отключёнными assert."""
    if not condition:
        raise AssertionError(message)


def wait_for(label, probe):
    """Готовность определяется состоянием компонента, а не фиксированной задержкой."""
    deadline = time.monotonic() + WAIT_TIMEOUT
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(0.2)
    raise AssertionError(f"Timed out waiting for {label}")


class ResourceHandler(http.server.BaseHTTPRequestHandler):
    """Маркер пути и адрес клиента подтверждают доставку запроса и применение SNAT."""

    def do_GET(self):
        """Законченный HTTP-ответ позволяет отличать ошибку протокола от обрыва VPN."""
        body = json.dumps({"via": self.server.marker, "source": self.client_address[0]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Штатные запросы не засоряют общий результат сквозной проверки."""
        pass


def serve_resource(marker):
    """Один сервер обслуживает одинаковые адреса ресурсов в своём пространстве сети."""
    with http.server.ThreadingHTTPServer(("0.0.0.0", 80), ResourceHandler) as server:
        server.marker = marker
        server.serve_forever()


def request_resource(address, hostname):
    """Новый TCP-сеанс с явным Host исключает кэш браузера и переиспользование соединений."""
    connection = http.client.HTTPConnection(address, 80, timeout=HTTP_TIMEOUT)
    try:
        connection.request("GET", "/probe", headers={"Host": hostname, "Connection": "close"})
        response = connection.getresponse()
        require(response.status == 200, f"Unexpected HTTP status: {response.status}")
        result = json.loads(response.read())
        print(json.dumps({"ok": True, **result}), flush=True)
    except (OSError, http.client.HTTPException) as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__}), flush=True)
    finally:
        connection.close()


class Network:
    """Только объекты текущего запуска попадают в список последующей очистки."""

    def __init__(self, root):
        """Уникальные имена не позволяют занять пространства другого теста."""
        self.root = root
        self.prefix = "ike-route-" + secrets.token_hex(4)
        self.namespaces = {}
        self.processes = []
        self.temporary_files = []
        self.temporary_dirs = []
        self.engine = None

    def create(self, role):
        """Пространство регистрируется сразу после создания, до следующих сетевых шагов."""
        name = f"{self.prefix}-{role}"
        run("ip", "netns", "add", name)
        self.namespaces[role] = name
        self.command(role, "ip", "link", "set", "lo", "up")

    def command(self, role, *args, **kwargs):
        """Сеть хоста не используется даже для команд управления стендом."""
        return run("ip", "netns", "exec", self.namespaces[role], *args, **kwargs)

    def spawn(self, role, name, *args, env=None):
        """Родитель закрывает журнал, а группа процесса остаётся доступна для уборки."""
        with (self.root / f"{name}.log").open("w") as logfile:
            process = subprocess.Popen(
                ["ip", "netns", "exec", self.namespaces[role], *args],
                stdout=logfile, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        self.processes.append(process)
        return process

    def link(self, left, left_name, left_address, right, right_name, right_address):
        """Временные концы veth переименовываются только после переноса из общей сети."""
        token = secrets.token_hex(3)
        a, b = "ia" + token, "ib" + token
        run("ip", "link", "add", a, "type", "veth", "peer", "name", b)
        try:
            for role, old, name, address in (
                (left, a, left_name, left_address), (right, b, right_name, right_address),
            ):
                run("ip", "link", "set", old, "netns", self.namespaces[role])
                self.command(role, "ip", "link", "set", old, "name", name)
                self.command(role, "ip", "addr", "add", address, "dev", name)
                self.command(role, "ip", "link", "set", name, "up")
        finally:
            # При частичной ошибке первый конец ещё может находиться в общей сети контейнера.
            run("ip", "link", "del", a, check=False)
            run("ip", "link", "del", b, check=False)

    def nft(self, role, text):
        """Правила передаются через stdin без временного файла с неоднозначным владельцем."""
        self.command(role, "nft", "-f", "-", input=text)

    def setup(self):
        """Прямая и VPN-копия ресурса доступны независимо друг от друга."""
        for role in ("client", "router", "direct", "ike"):
            self.create(role)
        self.link("client", "underlay", "192.0.2.2/30", "router", "underlay", "192.0.2.1/30")
        self.link("router", "wan", f"{ROUTER_WAN}/30", "direct", "router", f"{DIRECT_WAN}/30")
        self.link("direct", "vpn", f"{TRANSIT_WAN}/30", "ike", "wan", f"{IKE_WAN}/30")
        self.command("router", "ip", "route", "add", "default", "via", DIRECT_WAN)
        self.command("ike", "ip", "route", "add", "default", "via", TRANSIT_WAN)
        for role in ("router", "direct", "ike"):
            self.command(role, "sysctl", "-qw", "net.ipv4.ip_forward=1")
            self.command(role, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
            self.command(role, "sysctl", "-qw", "net.ipv4.conf.default.rp_filter=0")
        for role in ("direct", "ike"):
            self.command(role, "ip", "addr", "add", RESOURCE + "/32", "dev", "lo")
        self.command("direct", "ip", "addr", "add", CONTROL + "/32", "dev", "lo")
        # Обычный прямой выход сервера AWG сохраняется независимо от правил панели.
        self.nft("router", """table ip awgr_test_nat {
 chain post {
  type nat hook postrouting priority 100; policy accept;
  oifname "wan" ip saddr 10.8.1.0/24 masquerade
 }
}
""")
        # Считаются SYN, поэтому поздние ACK прежнего прямого запроса не дают ложной утечки.
        self.nft("direct", f"""table inet awgr_test_observe {{
 counter selected_direct {{ }}
 chain input {{
  type filter hook input priority -10; policy accept;
  ip daddr {RESOURCE} tcp dport 80 tcp flags & (syn | ack) == syn counter name selected_direct
 }}
}}
""")
        for role, marker in (("direct", "DIRECT"), ("ike", "IKE")):
            self.spawn(role, role + "-http", sys.executable, "-B", str(HERE), "--serve", marker)

    def start_awg(self, role, interface, config_text, address):
        """Реальный userspace AWG обрабатывает рукопожатие и клиентские пакеты."""
        socket_dir = Path("/var/run/amneziawg")
        try:
            socket_dir.mkdir(mode=0o700)
        except FileExistsError:
            pass
        else:
            self.temporary_dirs.append(socket_dir)
        process = self.spawn(role, role + "-awg", "amneziawg-go", "-f", interface)
        socket_path = socket_dir / f"{interface}.sock"
        wait_for(interface + " socket", lambda: socket_path.exists() or process.poll() is not None)
        require(process.poll() is None, f"AWG process exited: {interface}")
        path = self.root / f"{interface}-setconf.conf"
        path.write_text(config_text)
        path.chmod(0o600)
        self.command(role, "awg", "setconf", interface, str(path))
        self.command(role, "ip", "addr", "add", address, "dev", interface)
        self.command(role, "ip", "link", "set", interface, "mtu", "1376", "up")

    def request(self, address=RESOURCE, hostname=SITE):
        """Отдельный процесс клиента гарантирует прохождение запроса через настоящий AWG."""
        output = self.command(
            "client", sys.executable, "-B", str(HERE), "--request", address, hostname).stdout
        return json.loads(output)

    def direct_syns(self):
        """Независимый счётчик обнаруживает обход VPN даже при потерянном HTTP-ответе."""
        data = json.loads(self.command(
            "direct", "nft", "-j", "list", "counter", "inet", "awgr_test_observe", "selected_direct").stdout)
        return next(row["counter"]["packets"] for row in data["nftables"] if "counter" in row)

    def outage(self, enabled):
        """Отказ транспорта не закрывает SA и не изменяет здоровье выхода вручную."""
        if enabled:
            self.nft("direct", f"""table inet awgr_test_outage {{
 chain forward {{
  type filter hook forward priority -300; policy accept;
  ip saddr {IKE_WAN} drop
  ip daddr {IKE_WAN} drop
 }}
}}
""")
        else:
            self.command("direct", "nft", "delete", "table", "inet", "awgr_test_outage")

    def drain_namespace(self, namespace):
        """Удаление имени netns само по себе не завершает процесс, удерживающий его сеть."""
        for sig in (signal.SIGTERM, signal.SIGKILL):
            pids = run("ip", "netns", "pids", namespace).stdout.split()
            for pid in pids:
                try:
                    os.kill(int(pid), sig)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if not run("ip", "netns", "pids", namespace).stdout.strip():
                    return
                time.sleep(0.1)
        raise AssertionError(f"Processes remain in namespace {namespace}")

    def close(self):
        """Очистка продолжается после отдельной ошибки и сообщает о любых оставшихся объектах."""
        errors = []
        processes = list(self.processes)
        if self.engine is not None:
            # teardown может потерять ссылки на процессы до исключения; сохраняем их заранее.
            processes.extend(rt.ike.proc for rt in self.engine.rt.values() if rt.ike and rt.ike.proc)
            processes.extend(helper.proc for helper in (self.engine.sni, self.engine.dns) if helper)
            try:
                self.engine.teardown()
            except Exception as exc:
                errors.append(f"Engine cleanup: {exc}")
        for process in reversed(list(dict.fromkeys(processes))):
            try:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(f"Process cleanup: {exc}")
        for namespace in reversed(list(self.namespaces.values())):
            try:
                self.drain_namespace(namespace)
            except (OSError, subprocess.SubprocessError, AssertionError) as exc:
                errors.append(f"Namespace process cleanup: {exc}")
            try:
                run("ip", "netns", "del", namespace)
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(f"Namespace cleanup: {exc}")
        for path in reversed(self.temporary_files + self.temporary_dirs):
            try:
                if path.is_dir():
                    path.rmdir()
                else:
                    path.unlink(missing_ok=True)
            except OSError as exc:
                errors.append(f"File cleanup: {exc}")
        remaining = run("ip", "netns", "list").stdout
        require(not any(name in remaining for name in self.namespaces.values()), "Test namespaces remain")
        require(not errors, "; ".join(errors))


def start_ike_server(network, ikev2, certificate):
    """Собственный CA и сервер EAP исключают зависимость от корпоративного VPN."""
    root = network.root / "ike-server"
    root.mkdir(mode=0o700)
    certificate(root)
    for directory in ("x509", "rsa"):
        (root / directory).mkdir(mode=0o700)
    (root / "x509/server.pem").write_bytes((root / "server.pem").read_bytes())
    (root / "rsa/server.key").write_bytes((root / "server.key").read_bytes())
    secret = "0s" + base64.b64encode(b"routing-test-password").decode()
    connection = root / "swanctl.conf"
    connection.write_text(f"""connections {{
 server {{
  version = 2
  local_addrs = {IKE_WAN}
  pools = clients
  local {{
   auth = pubkey
   id = vpn.example.com
   certs = server.pem
  }}
  remote {{
   auth = eap-mschapv2
   eap_id = %any
  }}
  children {{
   net {{
    local_ts = 0.0.0.0/0
    remote_ts = dynamic
   }}
  }}
 }}
}}
pools {{
 clients {{
  addrs = 10.99.0.0/24
 }}
}}
secrets {{
 eap-user {{
  id = employee
  secret = {secret}
 }}
 rsa-server {{
  file = server.key
 }}
}}
""")
    connection.chmod(0o600)
    socket_path = root / "vici.sock"
    daemon = root / "strongswan.conf"
    daemon.write_text(ikev2.daemon_config(str(socket_path)).replace(
        "port = 0", "port = 500").replace("port_nat_t = 0", "port_nat_t = 4500"))
    private_pid = root / "charon.pid"
    private_pid.touch(mode=0o600)
    # Это тот же отдельный mount namespace, который использует рабочий Runtime.
    shared_pid = Path("/run/charon.pid")
    try:
        shared_pid.touch(mode=0o600, exist_ok=False)
    except FileExistsError:
        pass
    else:
        network.temporary_files.append(shared_pid)
    process = network.spawn(
        "ike", "ike-server", "unshare", "--mount", "--propagation", "private", "--", "sh", "-c",
        'mount --bind "$1" /run/charon.pid && exec /usr/lib/strongswan/charon', "sh", str(private_pid),
        env=dict(os.environ, STRONGSWAN_CONF=str(daemon)))
    wait_for("IKE server socket", lambda: socket_path.exists() or process.poll() is not None)
    require(process.poll() is None, "IKE server exited")
    run("swanctl", "--load-all", "--file", str(connection), "--uri", "unix://" + str(socket_path))
    return (root / "ca.pem").read_text()


def expect_route(network, marker, source=None, address=RESOURCE, hostname=SITE):
    """Маркер и исходный адрес проверяются раздельно, чтобы не пропустить ошибку SNAT."""
    result = network.request(address, hostname)
    require(result.get("ok") and result.get("via") == marker, f"Expected {marker}: {result}")
    if source is not None:
        require(result.get("source") == source, f"Unexpected source address: {result}")


def check_outage(network, engine, label):
    """Тайм-аут дополняется контролем прямой копии и работающим несвязанным ресурсом."""
    before = network.direct_syns()
    network.outage(True)
    try:
        engine.reconcile()
        for _ in range(2):
            result = network.request()
            require(not result.get("ok"), f"Request escaped during {label} outage: {result}")
        expect_route(network, "DIRECT", ROUTER_WAN, address=CONTROL, hostname="control.example.test")
        require(network.direct_syns() == before, f"Direct SYN leak during {label} outage")
        print(f"{label}: transport outage blocks selected traffic without direct SYN leaks", flush=True)
    finally:
        network.outage(False)
    wait_for(label + " recovery", lambda: network.request().get("via") == "IKE")
    expect_route(network, "IKE", engine.health[UPSTREAM]["address"])
    print(f"{label}: new connections recover through IKEv2", flush=True)


def scenarios(root):
    """Настоящий reconcile собирает маршруты, SNAT и доменного посредника как на сервере."""
    from app import awgconf, awgserver, engine as engine_module, ikev2, system
    from app.store import Store
    from tests.ikev2_e2e import certificate

    class NamespaceTarget(system.Target):
        """Файлы общие с тестом, а все сетевые команды ограничены пространством маршрутизатора."""
        kind = "ikev2-test"

        def native(self, command, **kwargs):
            """awg и входящие правила используют те же бинарники в изолированной сети."""
            return self.ns(command, **kwargs)

    network = Network(root)
    # Каталоги Runtime и посредников удаляются вместе с остальными временными файлами.
    runtime = root / "runtime"
    paths = {"RUN_DIR": str(runtime), "SNI_CONF": str(runtime / "sni.json"),
             "SNI_STATS": str(runtime / "sni-stats.json"), "DNS_CONF": str(runtime / "dns.json"),
             "DNS_STATS": str(runtime / "dns-stats.json")}
    with mock.patch.multiple(engine_module, **paths):
        try:
            network.setup()
            anchor = network.spawn("router", "router-anchor", "sleep", "300")
            target = NamespaceTarget("routing-test", anchor.pid, "awg0", str(root / "awg0.conf"), network.prefix)
            server_key = run("awg", "genkey").stdout.strip()
            server = awgserver.new_server(
                server_key, 51000, "10.8.1.0/24", awgserver.generate_params(True), wan_masq=False)
            target.write_file(target.conf_path, server.render())
            network.start_awg("router", "awg0", server.stripped(), "10.8.1.1/24")
            store = Store(str(root / "state.json"))

            def initial_state(state):
                """Только локальные списки исключают обновление данных из интернета."""
                state["lists"] = []
                state["routing"] = {"default": "direct", "rules": []}
                state["settings"]["client_host"] = "192.0.2.1"

            store.mutate(initial_state)
            engine = engine_module.Engine(store)
            network.engine = engine
            with mock.patch.object(system, "discover", return_value=target):
                engine.reconcile()
                public_key = engine.srv.add_client("IKEv2 routing test")
                profile = awgconf.parse_upstream(engine.srv.client_config(public_key)["conf"])
                network.start_awg("client", "awgc", profile.setconf, profile.address + "/32")
                network.command("client", "ip", "route", "add", "default", "dev", "awgc")
                wait_for("direct resource over AWG", lambda: network.request().get("via") == "DIRECT")
                expect_route(network, "DIRECT", ROUTER_WAN)
                handshakes = network.command("client", "awg", "show", "awgc", "latest-handshakes").stdout.split()
                require(len(handshakes) == 2 and int(handshakes[1]) > 0, "No real AWG handshake")
                print("AWG: real client handshake and direct resource access passed", flush=True)
                ca = start_ike_server(network, ikev2, certificate)

                def subnet_policy(state):
                    """Частная сеть намеренно совпадает у прямого и VPN-ресурса."""
                    state["upstreams"] = [{"id": UPSTREAM, "name": "Test IKEv2", "num": 1,
                        "enabled": True, "fallback": "block", "config": json.dumps({
                            "kind": "ikev2", "host": IKE_WAN, "remote_id": "vpn.example.com",
                            "user": "employee", "password": "routing-test-password", "ca": ca})}]
                    state["lists"] = [
                        {"id": "company", "name": "Company subnet", "kind": "manual", "source": "10.55.0.0/16"},
                        {"id": "sites", "name": "Company sites", "kind": "domains", "source": SITE}]
                    state["routing"]["rules"] = [{"lists": ["company"], "outbound": "up:" + UPSTREAM}]

                store.mutate(subnet_policy)
                engine.refresh_lists(only_due=False)

                def ike_ready():
                    """Ожидается установленный CHILD_SA, а не только работающий charon."""
                    engine.reconcile()
                    return engine.health.get(UPSTREAM, {}).get("healthy", False)

                wait_for("IKEv2 CHILD_SA", ike_ready)
                expect_route(network, "IKE", engine.health[UPSTREAM]["address"])
                expect_route(network, "DIRECT", ROUTER_WAN, address=CONTROL, hostname="control.example.test")
                print("Subnet policy: selected private network uses IKEv2 with virtual-IP SNAT", flush=True)
                check_outage(network, engine, "Subnet policy")

                def domain_policy(state):
                    """После смены политики один и тот же IP различается только по HTTP Host."""
                    state["routing"]["rules"] = [{"lists": ["sites"], "outbound": "up:" + UPSTREAM}]

                store.mutate(domain_policy)
                engine.reconcile()
                require(engine.sni_state and engine.sni_state.get("state") == "on", "Domain helper is not ready")
                expect_route(network, "IKE", engine.health[UPSTREAM]["address"])
                expect_route(network, "IKE", engine.health[UPSTREAM]["address"], hostname="sub." + SITE)
                expect_route(network, "DIRECT", ROUTER_WAN, hostname="other.example.test")
                print("Domain policy: selected host and subdomain use IKEv2; unmatched host uses DIRECT", flush=True)
                check_outage(network, engine, "Domain policy")
        except Exception:
            for logfile in sorted(root.glob("*.log")) + sorted((root / "data/logs").glob("*.log")):
                print(f"--- {logfile.name} ---\n{logfile.read_text()}", file=sys.stderr)
            raise
        finally:
            network.close()
    print("Cleanup: test processes and namespaces removed", flush=True)


def main():
    """Окружение задаётся до импорта панели, чтобы все её файлы оставались временными."""
    require(os.geteuid() == 0, "root is required")
    with tempfile.TemporaryDirectory(prefix="awgr-ike-routing-") as directory:
        root = Path(directory)
        with mock.patch.dict(os.environ, {"DATA_DIR": str(root / "data"), "DRY_RUN": "0"}):
            sys.path.insert(0, str(HERE.parent.parent))
            scenarios(root)
    print("All AWG to IKEv2 routing checks passed", flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--serve":
        serve_resource(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == "--request":
        request_resource(sys.argv[2], sys.argv[3])
    else:
        main()
