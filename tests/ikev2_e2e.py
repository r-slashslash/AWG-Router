"""Настоящие IKEv2/EAP-сессии в Linux: python3 -B tests/ikev2_e2e.py.

Нужны root, strongSwan, openssl, iproute2 и util-linux. Все адреса и сертификаты тестовые.
"""
import base64
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import ikev2  # noqa: E402


def run(*args, **kwargs):
    """Каждый внешний шаг ограничен по времени, чтобы ошибка сети не подвесила проверку."""
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20, **kwargs)


def certificate(root):
    """Собственный тестовый CA позволяет проверить подлинную проверку сертификата сервера."""
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=IKEv2 test CA",
        "-keyout", str(root / "ca.key"), "-out", str(root / "ca.pem"))
    run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=vpn.example.com",
        "-keyout", str(root / "server.key"), "-out", str(root / "server.csr"))
    (root / "extensions").write_text("subjectAltName=DNS:vpn.example.com\nextendedKeyUsage=serverAuth\n")
    run("openssl", "x509", "-req", "-days", "1", "-in", str(root / "server.csr"), "-CA", str(root / "ca.pem"),
        "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-extfile", str(root / "extensions"), "-out", str(root / "server.pem"))


def cross_signed_chain(root):
    """Иерархия как у нового поколения Let's Encrypt: сервер присылает только промежуточный
    сертификат, его корень Y доверен лишь через кросс-подпись уже доверенного корня X (ca.pem)."""
    (root / "ca-extensions").write_text("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                                        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    (root / "chain-extensions").write_text("subjectAltName=DNS:chain.example.com\nextendedKeyUsage=serverAuth\n")
    ca_ext = str(root / "ca-extensions")
    for name, subject in (("root-y", "IKEv2 test root Y"), ("int", "IKEv2 test intermediate"), ("chain", "chain.example.com")):
        run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + subject,
            "-keyout", str(root / f"{name}.key"), "-out", str(root / f"{name}.csr"))
    run("openssl", "x509", "-req", "-days", "1", "-in", str(root / "root-y.csr"), "-key", str(root / "root-y.key"),
        "-extfile", ca_ext, "-out", str(root / "root-y.pem"))
    run("openssl", "x509", "-req", "-days", "1", "-in", str(root / "root-y.csr"), "-CA", str(root / "ca.pem"),
        "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-extfile", ca_ext, "-out", str(root / "root-y-by-x.pem"))
    run("openssl", "x509", "-req", "-days", "1", "-in", str(root / "int.csr"), "-CA", str(root / "root-y.pem"),
        "-CAkey", str(root / "root-y.key"), "-CAcreateserial", "-extfile", ca_ext, "-out", str(root / "int.pem"))
    run("openssl", "x509", "-req", "-days", "1", "-in", str(root / "chain.csr"), "-CA", str(root / "int.pem"),
        "-CAkey", str(root / "int.key"), "-CAcreateserial", "-extfile", str(root / "chain-extensions"),
        "-out", str(root / "chain.pem"))
    cross = root / "cross"
    cross.mkdir()
    (cross / "root-y-by-x.pem").write_text((root / "root-y-by-x.pem").read_text())
    (root / "no-cross").mkdir()


def wait_status(runtime, healthy, seconds=20):
    """Проверяется состояние CHILD_SA, а не только завершение команды загрузки."""
    deadline = time.monotonic() + seconds
    last = {}
    while time.monotonic() < deadline:
        last = runtime.status()
        if last["healthy"] == healthy:
            return last
        time.sleep(0.2)
    raw = runtime.command("--list-sas", "--raw").stdout
    raise AssertionError(f"Unexpected IPsec state: {last}; {raw}")


def main(password):
    """Два клиента проверяют независимость PID-файлов, сокетов, паролей и остановки."""
    if os.geteuid() != 0:
        raise RuntimeError("root is required")
    namespace = f"awgr-ike-test-{os.getpid()}"
    link = f"ik{os.getpid()}"
    server_proc = None
    clients = []
    with tempfile.TemporaryDirectory(prefix="awgr-ike-") as tmp:
        root = Path(tmp)
        try:
            certificate(root)
            cross_signed_chain(root)
            run("ip", "netns", "add", namespace)
            run("ip", "link", "add", link, "type", "veth", "peer", "name", "ikepeer")
            run("ip", "link", "set", "ikepeer", "netns", namespace)
            run("ip", "addr", "add", "198.18.100.1/30", "dev", link)
            run("ip", "link", "set", link, "up")
            run("ip", "netns", "exec", namespace, "ip", "addr", "add", "198.18.100.2/30", "dev", "ikepeer")
            run("ip", "netns", "exec", namespace, "ip", "link", "set", "ikepeer", "up")
            run("ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up")
            server = root / "server"
            for directory in ("x509", "x509ca", "rsa"):
                (server / directory).mkdir(parents=True)
            (server / "x509/server.pem").write_text((root / "server.pem").read_text())
            (server / "rsa/server.key").write_text((root / "server.key").read_text())
            # Сервер доверяет своему корню Y и потому отправляет клиенту промежуточный сертификат,
            # но не кросс-подпись, как реальные серверы с сертификатами Let's Encrypt.
            (server / "x509/chain.pem").write_text((root / "chain.pem").read_text())
            (server / "rsa/chain.key").write_text((root / "chain.key").read_text())
            (server / "x509ca/int.pem").write_text((root / "int.pem").read_text())
            (server / "x509ca/root-y.pem").write_text((root / "root-y.pem").read_text())
            (server / "swanctl.conf").write_text('''connections {
    server {
        version = 2
        local_addrs = 198.18.100.2
        pools = clients
        local {
            auth = pubkey
            id = vpn.example.com
            certs = server.pem
        }
        remote {
            auth = eap-mschapv2
            eap_id = %any
        }
        children {
            net {
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
            }
        }
    }
    chain {
        version = 2
        local_addrs = 198.18.100.2
        pools = clients
        local {
            auth = pubkey
            id = chain.example.com
            certs = chain.pem
        }
        remote {
            auth = eap-mschapv2
            eap_id = %any
        }
        children {
            net {
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
            }
        }
    }
}
pools {
    clients {
        addrs = 10.99.0.0/24
    }
}
secrets {
    eap-user {
        id = employee
        secret = "test-only"
    }
    rsa-server {
        file = server.key
    }
    rsa-chain {
        file = chain.key
    }
}
'''.replace('secret = "test-only"', "secret = 0s" + base64.b64encode(password.encode()).decode()))
            socket = str(server / "vici.sock")
            (server / "strongswan.conf").write_text(ikev2.daemon_config(socket).replace("port = 0", "port = 500").replace("port_nat_t = 0", "port_nat_t = 4500"))
            (server / "charon.pid").touch(mode=0o600)
            Path("/run/charon.pid").touch(mode=0o600, exist_ok=True)
            with (server / "log").open("w") as log:
                server_proc = subprocess.Popen(
                    ["ip", "netns", "exec", namespace, "unshare", "--mount", "--propagation", "private", "--", "sh", "-c",
                     'mount --bind "$1" /run/charon.pid && exec /usr/lib/strongswan/charon', "sh", str(server / "charon.pid")],
                    env=dict(os.environ, STRONGSWAN_CONF=str(server / "strongswan.conf")), stdout=log, stderr=subprocess.STDOUT)
            for _ in range(50):
                if Path(socket).exists():
                    break
                time.sleep(0.1)
            run("swanctl", "--load-all", "--file", str(server / "swanctl.conf"), "--uri", "unix://" + socket)
            fields = ikev2.normalize({"host": "vpn.example.com", "user": "employee", "password": password, "ca": (root / "ca.pem").read_text()})
            for num in (71, 72):
                runtime = ikev2.Runtime(str(root / f"client{num}"), f"awgr{num}", str(root / f"client{num}.log"))
                clients.append(runtime)
                runtime.start(SimpleNamespace(pid=os.getpid()), fields, "198.18.100.2")
                status = wait_status(runtime, True)
                print(f"{runtime.name}: established, virtual IP {status['address']}")
            clients[0].close()
            assert clients[1].status()["healthy"], "stopping one exit disrupted another exit"
            print("independent daemon shutdown: passed")
            bad = ikev2.Runtime(str(root / "badpassword"), "awgr73", str(root / "badpassword.log"))
            clients.append(bad)
            bad.start(SimpleNamespace(pid=os.getpid()), {**fields, "password": "wrong"}, "198.18.100.2")
            time.sleep(3)
            assert not bad.status()["healthy"], "wrong password was accepted"
            assert bad.failure() is None, "rejected password was reported as an untrusted server"
            bad.close()
            wrong_id = ikev2.Runtime(str(root / "wrongid"), "awgr74", str(root / "wrongid.log"))
            clients.append(wrong_id)
            wrong_id.start(SimpleNamespace(pid=os.getpid()), {**fields, "remote_id": "wrong.example.com"}, "198.18.100.2")
            time.sleep(3)
            assert not wrong_id.status()["healthy"], "wrong server identity was accepted"
            # strongSwan-сервер сам отклоняет незнакомый IDr и не присылает сертификат: причина не угадывается.
            assert wrong_id.failure() is None, "server-side rejection was reported as an untrusted server"
            assert clients[1].status()["healthy"]
            untrusted = ikev2.Runtime(str(root / "untrusted"), "awgr75", str(root / "untrusted.log"))
            clients.append(untrusted)
            untrusted.start(SimpleNamespace(pid=os.getpid()), {**fields, "ca": ""}, "198.18.100.2")
            time.sleep(3)
            assert not untrusted.status()["healthy"], "untrusted server certificate was accepted"
            assert untrusted.failure().key == "ike.untrusted_server", "untrusted certificate reason was not reported"
            assert clients[1].status()["healthy"]
            print("wrong password, server identity and untrusted certificate rejected with reasons: passed")
            chain_fields = {**fields, "remote_id": "chain.example.com"}
            incomplete = ikev2.Runtime(str(root / "incomplete"), "awgr77", str(root / "incomplete.log"),
                                       intermediates=str(root / "no-cross"))
            clients.append(incomplete)
            incomplete.start(SimpleNamespace(pid=os.getpid()), chain_fields, "198.18.100.2")
            time.sleep(3)
            assert not incomplete.status()["healthy"], "chain without the cross-signed root was accepted"
            assert incomplete.failure().key == "ike.untrusted_server", "incomplete chain reason was not reported"
            incomplete.close()
            completed = ikev2.Runtime(str(root / "completed"), "awgr78", str(root / "completed.log"),
                                      intermediates=str(root / "cross"))
            clients.append(completed)
            completed.start(SimpleNamespace(pid=os.getpid()), chain_fields, "198.18.100.2")
            wait_status(completed, True)
            completed.close()
            print("cross-signed root completes a chain the server sends without it: passed")
            bundled = ikev2.Runtime(str(root / "bundled"), "awgr79", str(root / "bundled.log"))
            clients.append(bundled)
            bundled.start(SimpleNamespace(pid=os.getpid()), fields, "198.18.100.2")
            wait_status(bundled, True)
            bundled.close()
            print("bundled public intermediates load into charon: passed")
            crashed = ikev2.Runtime(str(root / "crashed"), "awgr76", str(root / "crashed.log"))
            clients.append(crashed)
            crashed.start(SimpleNamespace(pid=os.getpid()), fields, "198.18.100.2")
            wait_status(crashed, True)
            crashed.proc.kill()
            crashed.proc.wait(5)
            crashed.close()
            policies = run("ip", "xfrm", "policy", "list").stdout
            assert "if_id 0x4157004c" not in policies, "crashed exit left IPsec policies behind"
            assert clients[1].status()["healthy"], "crash cleanup disrupted another exit"
            print("crashed daemon cleanup preserves another exit: passed")
        except Exception:
            for logfile in root.glob("**/*log"):
                print(f"--- {logfile.name} ---\n{logfile.read_text()}", file=sys.stderr)
            raise
        finally:
            for runtime in clients:
                runtime.close()
            if server_proc:
                server_proc.terminate()
                server_proc.wait(10)
            subprocess.run(["ip", "link", "del", link], capture_output=True, timeout=5)
            subprocess.run(["ip", "netns", "del", namespace], capture_output=True, timeout=5)


if __name__ == "__main__":
    # Подробный журнал допустим только с тестовыми реквизитами и нужен для диагностики протокола.
    settings = ikev2.daemon_config
    with mock.patch.object(ikev2, "daemon_config", side_effect=lambda socket: settings(socket).replace("default = 0", "default = 1")):
        for password in (' p\\a"ss #{} ', '0x4142', '0sYWJj'):
            main(password)
