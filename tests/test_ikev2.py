"""Проверки IKEv2: параметры выхода, доменные правила и сохранение настроек."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import awgconf, main  # noqa: E402


def vpn_config(**changes):
    """Тестовые реквизиты не требуют доступа к корпоративному серверу."""
    fields = {"kind": "ikev2", "host": "vpn.example.com", "remote_id": "vpn.example.com",
              "local_id": "", "user": "employee", "password": "s e c r e t", "ca": "", "mtu": 1280}
    fields.update(changes)
    return json.dumps(fields)


class Ikev2ConfigTest(unittest.TestCase):
    """Разбор сохраняет секреты точно и отклоняет опасные или неполные параметры."""

    def test_roundtrip(self):
        """Вход JSON превращается в IKEv2 и повторно разбирается без потери пароля."""
        pc = awgconf.parse_upstream(vpn_config(host="VPN.example.com", password='p\\a"ss #{}'))
        self.assertEqual(pc.kind, "ikev2")
        self.assertEqual(pc.endpoint, "vpn.example.com:500")
        self.assertEqual(pc.ikev2["password"], 'p\\a"ss #{}')
        self.assertEqual(awgconf.parse_upstream(pc.raw), pc)
        self.assertEqual(pc.address, "")

    def test_remote_id_defaults_to_host(self):
        """Пустой удалённый ID означает проверку сертификата по имени сервера."""
        pc = awgconf.parse_upstream(vpn_config(remote_id=""))
        self.assertEqual(pc.ikev2["remote_id"], "vpn.example.com")

    def test_invalid_settings(self):
        """Пустые реквизиты, неверный CA и управляющие символы запрещены до запуска VPN."""
        for changes in ({"host": ""}, {"host": "host; command"}, {"user": ""}, {"password": ""},
                        {"remote_id": "%any"}, {"local_id": "bad\nID"}, {"password": "bad\x00pw"},
                        {"ca": "not a certificate"}, {"ca": "не сертификат"}, {"remote_id": "*.example.com"},
                        {"mtu": 900}, {"mtu": "bad"}, {"mtu": 1280.5}, {"mtu": float("inf")}):
            with self.subTest(changes=changes), self.assertRaises(awgconf.ConfigError):
                awgconf.parse_upstream(vpn_config(**changes))


class Ikev2RuntimeTest(unittest.TestCase):
    """Конфиги strongSwan изолируют выходы и сохраняют проверку личности сервера."""

    def test_generated_configuration(self):
        """Пароль со спецсимволами экранируется, а интерфейс получает собственный ID."""
        from app import ikev2
        fields = ikev2.normalize(json.loads(vpn_config(password='p\\\\a"ss')))
        conf = ikev2.connection_config(fields, "awgr7", "198.51.100.7", "/run/test/ca.pem")
        self.assertIn('auth = eap-mschapv2', conf)
        self.assertIn('auth = pubkey', conf)
        self.assertIn('id = "vpn.example.com"', conf)
        self.assertIn('if_id_in = 1096220679', conf)
        self.assertIn('if_id_out = 1096220679', conf)
        self.assertIn('vips = 0.0.0.0', conf)
        self.assertIn('set_mark_out = 0x40000000/0xffffffff', conf)
        import base64
        self.assertIn('secret = 0s' + base64.b64encode(fields["password"].encode()).decode(), conf)
        self.assertNotIn("%any", conf)

    def test_password_encoding_prefixes_are_literal(self):
        """Префиксы 0x и 0s в пароле не должны интерпретироваться как формат его хранения."""
        import base64
        import re
        from app import ikev2
        for password in ("0x4142", "0X4142", "0sYWJj", "0SYWJj"):
            with self.subTest(password=password):
                fields = ikev2.normalize(json.loads(vpn_config(password=password)))
                conf = ikev2.connection_config(fields, "awgr7", "198.51.100.7")
                encoded = re.search(r"secret = 0s([A-Za-z0-9+/=]+)", conf)
                self.assertIsNotNone(encoded)
                self.assertEqual(base64.b64decode(encoded.group(1)).decode(), password)

    def test_daemon_configuration(self):
        """Демон использует случайные порты, собственный сокет и не меняет адреса и DNS цели."""
        from app import ikev2
        conf = ikev2.daemon_config("/tmp/ike7/vici.sock")
        for setting in ("port = 0", "port_nat_t = 0", "install_routes = no", "install_virtual_ip = no",
                        "unix:///tmp/ike7/vici.sock", "fwmark = 0x40000000"):
            self.assertIn(setting, conf)
        self.assertNotIn("resolve", conf)

    def test_stale_runtime_does_not_write_through_old_ca_symlink(self):
        """После перезапуска старый каталог заменяется до записи нового сертификата."""
        from pathlib import Path
        from app import ikev2
        with tempfile.TemporaryDirectory() as root:
            outside = Path(root) / "system-ca"
            outside.mkdir()
            work = Path(root) / "ike"
            work.mkdir()
            (work / "x509ca").symlink_to(outside, target_is_directory=True)
            runtime = ikev2.Runtime(str(work), "awgr7", root + "/awgr7.log")
            fields = json.loads(vpn_config(ca="new company certificate"))
            runtime._prepare(fields, "198.51.100.7")
            self.assertEqual(list(outside.iterdir()), [])
            self.assertFalse((work / "x509ca").is_symlink())
            self.assertEqual((work / "x509ca/company.pem").read_text(), "new company certificate")
            self.assertEqual((work / "swanctl.conf").stat().st_mode & 0o777, 0o600)

    def test_intermediates_complete_chain_without_becoming_trusted(self):
        """Кросс-подписи достраивают цепочку сервера, но доверие остаётся только у корней из x509ca.

        Вход: каталог с одним промежуточным сертификатом, выход с CA компании и без него.
        Ожидание: файл доступен в x509, в x509ca его нет; закрытие выхода не удаляет общий каталог.
        """
        from pathlib import Path
        from app import ikev2
        with tempfile.TemporaryDirectory() as root:
            bundle = Path(root) / "bundle"
            bundle.mkdir()
            (bundle / "cross.pem").write_text("cross-signed root")
            for ca in ("", "company certificate"):
                with self.subTest(company_ca=bool(ca)):
                    work = Path(root) / "ike"
                    runtime = ikev2.Runtime(str(work), "awgr7", root + "/awgr7.log", intermediates=str(bundle))
                    runtime._prepare(json.loads(vpn_config(ca=ca)), "198.51.100.7")
                    self.assertEqual((work / "x509/cross.pem").read_text(), "cross-signed root")
                    self.assertNotIn("cross.pem", os.listdir(work / "x509ca"))
                    runtime.close()
                    self.assertEqual((bundle / "cross.pem").read_text(), "cross-signed root")

    def test_server_verification_failure_from_log(self):
        """Отказ в доверии серверу распознаётся по журналу charon, иначе причина не угадывается.

        Вход: журнала нет; строки отказа для RSA- и ECDSA-ключа; обычный ход подключения.
        Ожидание: ike.untrusted_server только для строк отказа.
        """
        from pathlib import Path
        from app import ikev2
        with tempfile.TemporaryDirectory() as root:
            log = Path(root) / "awgr7.log"
            runtime = ikev2.Runtime(root + "/ike", "awgr7", str(log))
            self.assertIsNone(runtime.failure())
            for key in ("RSA", "ECDSA"):
                with self.subTest(key=key):
                    log.write_text("02[IKE] received end entity cert \"CN=vpn.example.com\"\n"
                                   f"02[IKE] no trusted {key} public key found for 'vpn.example.com'\n")
                    self.assertEqual(runtime.failure().key, "ike.untrusted_server")
            log.write_text("10[IKE] initiating IKE_SA awgr7[1] to 198.51.100.7\n13[IKE] establishing CHILD_SA net{1}\n")
            self.assertIsNone(runtime.failure())

    def test_unknown_runtime_owner_preserves_existing_files(self):
        """Ошибка чтения владельца не разрешает удалять его сертификаты или IPsec-состояние."""
        from pathlib import Path
        from types import SimpleNamespace
        from app import ikev2
        with tempfile.TemporaryDirectory() as root:
            work = Path(root) / "ike"
            work.mkdir()
            existing = work / "company.pem"
            existing.write_text("existing certificate")
            runtime = ikev2.Runtime(str(work), "awgr7", root + "/log")
            with mock.patch("app.ikev2.open", side_effect=PermissionError, create=True), mock.patch("app.ikev2.subprocess.run") as command:
                with self.assertRaises(ikev2.Ikev2Error):
                    runtime.start(SimpleNamespace(pid=42), json.loads(vpn_config()), "198.51.100.7")
                runtime.close()
            self.assertEqual(existing.read_text(), "existing certificate")
            command.assert_not_called()

    def test_cleanup_after_crash_only_removes_owned_ipsec(self):
        """После аварии демона удаляются только политики и SA его зарезервированного ID."""
        import subprocess
        from app import ikev2
        with tempfile.TemporaryDirectory() as root:
            runtime = ikev2.Runtime(root + "/ike", "awgr7", root + "/awgr7.log")
            runtime._prepare(json.loads(vpn_config()), "198.51.100.7")
            runtime.target_pid = 42
            runtime.proc = mock.Mock()
            runtime.proc.poll.return_value = 1
            policies = ("src 10.9.0.7/32 dst 0.0.0.0/0\n dir out priority 1\n"
                        " tmpl src 192.0.2.1 dst 192.0.2.2 proto esp reqid 1096220679 mode tunnel\n if_id 0x41570007\n"
                        "src 10.9.0.8/32 dst 0.0.0.0/0\n dir out priority 1\n"
                        " tmpl src 192.0.2.1 dst 192.0.2.2 proto esp reqid 1096220680 mode tunnel\n if_id 0x41570008\n")
            with mock.patch.object(ikev2.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, policies, "")) as execute:
                runtime.close()
            commands = [call.args[0] for call in execute.call_args_list]
            self.assertTrue(any(command[-2:] == ["reqid", "1096220679"] for command in commands))
            deletes = [command for command in commands if "policy" in command and "delete" in command]
            self.assertEqual(len(deletes), 1)
            self.assertIn("10.9.0.7/32", deletes[0])
            self.assertNotIn("10.9.0.8/32", deletes[0])

    def test_status_requires_installed_child_and_virtual_ipv4(self):
        """Одна IKE-сессия без рабочего IPsec-туннеля не считается готовым выходом."""
        from app import ikev2
        output = "list-sa event {awgr7 {state=ESTABLISHED local-vips=[10.9.0.7] child-sas {net-1 {name=net state=INSTALLED if-id-in=41570007 if-id-out=41570007 bytes-in=123 bytes-out=456 local-ts=[10.9.0.7/32] remote-ts=[0.0.0.0/0]}}}}"
        self.assertEqual(ikev2.parse_status(output, 1096220679), {"healthy": True, "address": "10.9.0.7", "rx": 123, "tx": 456})
        for text in ("", output.replace("INSTALLED", "INSTALLING"), output.replace("10.9.0.7", "fd00::7"),
                     output.replace("41570007", "41570008"), output.replace("local-ts=[10.9.0.7/32]", "local-ts=[10.9.0.8/32]")):
            with self.subTest(text=text):
                self.assertFalse(ikev2.parse_status(text, 1096220679)["healthy"])


class Ikev2RoutingTest(unittest.TestCase):
    """Существующие правила и резервные копии должны принимать новый тип выхода."""

    def setUp(self):
        """Изолированное состояние оставляет глобальное хранилище панели неизменным."""
        from test_api import good_state
        self.st = good_state()
        self.st["upstreams"][0]["config"] = vpn_config()
        self.st["lists"].append({"id": "l_sites", "kind": "domains", "source": "portal.example.com", "name": "Sites"})

    def test_domain_rule_and_backup(self):
        """Домен назначается IKEv2, а резервная копия сохраняет правило и реквизиты."""
        rules = [{"lists": ["l_sites"], "outbound": "up:u000001", "enabled": True}]
        self.st["routing"]["rules"] = main.v_rules(self.st, rules)
        restored = main.clean_backup_state(self.st)
        self.assertEqual(restored["routing"]["rules"][0]["outbound"], "up:u000001")
        self.assertEqual(awgconf.parse_upstream(restored["upstreams"][0]["config"]).kind, "ikev2")

    def test_health_and_dynamic_snat(self):
        """SNAT использует выданный VPN адрес, а после потери SA выход перестаёт быть рабочим."""
        from app.engine import Engine, UpRT
        engine = Engine(main.store)
        runtime = UpRT(1, "hash", "target")
        runtime.ike = mock.Mock()
        runtime.ike.status.return_value = {"healthy": True, "address": "10.9.0.17", "rx": 42, "tx": 24}
        engine.rt["u000001"] = runtime
        target = mock.Mock()
        engine._update_health(target, self.st)
        self.assertTrue(engine.health["u000001"]["healthy"])
        self.assertEqual(engine._up_list(self.st)[0]["snat"], "10.9.0.17")
        runtime.ike.status.return_value = {"healthy": False, "address": "", "rx": 0, "tx": 0}
        engine._update_health(target, self.st)
        self.assertFalse(engine.health["u000001"]["healthy"])
        self.assertEqual(engine._up_list(self.st)[0]["snat"], "")
        target.ns.assert_not_called()

    def test_server_verification_failure_is_shown(self):
        """Причина из журнала видна и пока выход ждёт сессию, и после остановки попыток.

        Вход: SA не установлена, журнал сообщает об отказе в доверии; затем прошло 120 с.
        Ожидание: ошибка ike.untrusted_server в здоровье выхода в обоих состояниях.
        """
        from app.engine import Engine, UpRT
        from app.i18n import Msg
        engine = Engine(main.store)
        runtime = UpRT(1, "hash", "target")
        runtime.ike = mock.Mock()
        runtime.ike.status.return_value = {"healthy": False, "address": "", "rx": 0, "tx": 0}
        runtime.ike.failure.return_value = Msg("ike.untrusted_server")
        engine.rt["u000001"] = runtime
        engine._update_health(mock.Mock(), self.st)
        self.assertEqual(engine.health["u000001"]["error"].key, "ike.untrusted_server")
        runtime.ike_down_since -= 120
        with mock.patch.object(engine, "_stop_up"):
            engine._update_health(mock.Mock(), self.st)
        self.assertEqual(engine.health["u000001"]["state"], "error")
        self.assertEqual(engine.health["u000001"]["error"].key, "ike.untrusted_server")

    def test_routes_installed_before_daemon_start(self):
        """Пока IKEv2 подключается, метка выхода уже имеет проверенный запрещающий маршрут."""
        import subprocess
        from app import config, ikev2, system
        from app.engine import Engine
        engine = Engine(main.store)
        target = mock.Mock(spec=system.Target)
        target.key = "test-target"
        target.pid = 42
        target.ns.return_value = subprocess.CompletedProcess([], 0, "[]", "")
        runtime = mock.Mock()
        runtime.proc = None

        def check_routes(*args):
            """Проверка на границе запуска доказывает порядок сетевых действий."""
            calls = target.ns.call_args_list
            guarded = [call for call in calls if call.args[0][:5] == ["ip", "route", "replace", "unreachable", "default"]]
            self.assertTrue(guarded)
            self.assertTrue(guarded[0].kwargs.get("check", True))

        runtime.start.side_effect = check_routes
        u = self.st["upstreams"][0]
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(ikev2, "Runtime", return_value=runtime), \
                mock.patch.object(awgconf, "resolve_host", return_value="198.51.100.7"):
            engine._start_up(target, u["id"], u, awgconf.parse_upstream(u["config"]), "hash")

    def test_private_corporate_website_is_intercepted(self):
        """Частный адрес корпоративного сайта не обходит доменное правило IKEv2."""
        from app.engine import Engine
        engine = Engine(main.store)
        self.st["routing"]["rules"] = [{"lists": ["l_sites"], "outbound": "up:u000001", "enabled": True}]
        target = mock.Mock()
        target.iface = "awg0"
        rules = engine.build_ruleset(target, self.st, sniff_port=10443)
        policy = rules.split("\tchain p_global {", 1)[1].split("\n\t}", 1)[0]
        self.assertLess(policy.index("tcp dport { 80, 443 }"), policy.index("ip daddr @local4"))

    def test_private_network_rule_precedes_local_bypass(self):
        """Явно выбранная сеть компании идёт в IKEv2, прочие частные сети остаются напрямую."""
        from app.engine import Engine, UpRT
        engine = Engine(main.store)
        engine.rt["u000001"] = UpRT(1, "hash", "target")
        engine.health["u000001"] = {"healthy": True}
        self.st["lists"].append({"id": "l_company", "kind": "manual", "source": "10.55.0.0/16"})
        self.st["routing"]["default"] = "direct"
        self.st["routing"]["rules"] = [{"lists": ["l_company"], "outbound": "up:u000001", "enabled": True}]
        target = mock.Mock()
        target.iface = "awg0"
        with mock.patch.object(engine, "_cidrs", return_value=["10.55.0.0/16"]):
            rules = engine.build_ruleset(target, self.st)
        policy = rules.split("\tchain p_global {", 1)[1].split("\n\t}", 1)[0]
        self.assertIn("ip daddr @local4 ip daddr @l_l_company goto o_u1", policy)
        self.assertIn("ip daddr @local4 goto o_direct", policy)

    def test_missing_domain_helper_keeps_ikev2_sites_intercepted(self):
        """При отказе посредника клиент не отправляет корпоративный сайт обычным маршрутом."""
        from app import config
        from app.engine import Engine
        engine = Engine(main.store)
        target = mock.Mock()
        target.iface = "awg0"
        policy = {"rules": [], "default": "direct", "domain": [(["l_sites"], "up:u000001")]}
        with mock.patch.object(engine, "_policies", return_value=(policy, {})):
            rules = engine.build_ruleset(target, self.st, sniff_port=None)
        self.assertIn(f"redirect to :{config.SNI_PROXY_PORT}", rules)
        self.assertIn("udp dport 443", rules)

    def test_live_runtime_owner_is_checked_before_network_changes(self):
        """Отказ занять активный выход сохраняет его интерфейс и маршруты."""
        from pathlib import Path
        from app import ikev2
        from app.engine import Engine
        from app.store import Store
        with tempfile.TemporaryDirectory() as root:
            work = Path(root) / "ike-1"
            work.mkdir()
            owner = b"STRONGSWAN_CONF=" + os.fsencode(str(work / "strongswan.conf"))
            engine = Engine(Store(root + "/state.json"))
            target = mock.Mock(key="target", pid=42)
            target.ns.return_value = mock.Mock(stdout="", stderr="", returncode=0)
            engine.target = target
            upstream = self.st["upstreams"][0]
            files = [mock.mock_open(read_data="123").return_value, mock.mock_open(read_data=owner).return_value]
            with mock.patch("app.engine.RUN_DIR", root), mock.patch("app.engine.config.DRY_RUN", False), \
                    mock.patch("app.engine.awgconf.resolve_host", return_value="198.51.100.7"), \
                    mock.patch.object(engine, "_sync_rules"), mock.patch("app.ikev2.open", side_effect=files, create=True):
                with self.assertRaises(ikev2.Ikev2Error):
                    engine._start_up(target, upstream["id"], upstream, engine.parsed(upstream), "hash")
                engine._stop_up(upstream["id"])
            target.ns.assert_not_called()
            self.assertTrue(work.is_dir())

    def test_private_route_diagnostics_follow_ikev2_rules(self):
        """Диагностика частного адреса совпадает с сетевым правилом или основным IKEv2."""
        from app.engine import Engine, UpRT
        from app.store import Store
        with tempfile.TemporaryDirectory() as root:
            store = Store(root + "/state.json")
            engine = Engine(store)
            engine.rt["u000001"] = UpRT(1, "hash", "target")
            engine.health["u000001"] = {"healthy": True}
            store.mutate(lambda st: st.update(self.st))
            self.assertEqual(engine.trace(None, "10.55.0.1")["effective"], 1)
            self.st["routing"]["default"] = "direct"
            self.st["routing"]["rules"] = [{"id": "r_company", "lists": ["l0a0b0c"], "outbound": "up:u000001", "enabled": True}]
            store.mutate(lambda st: st.update(self.st))
            with mock.patch.object(engine.matcher, "contains", return_value="10.55.0.0/16"):
                self.assertEqual(engine.trace(None, "10.55.0.1")["effective"], 1)
            with mock.patch.object(engine.matcher, "contains", return_value=None):
                self.assertEqual(engine.trace(None, "10.56.0.1")["effective"], "direct")

    def test_domain_target_uses_vpn_mark(self):
        """Соединение к сайту получает метку туннеля, а при блокировке не уходит напрямую."""
        from app import nftgen
        with mock.patch.object(main.engine, "resolve", return_value=1):
            self.assertEqual(main.engine._sni_target(self.st, "up:u000001"),
                             {"mark": nftgen.mark_for(1), "acct": "u000001"})
        with mock.patch.object(main.engine, "resolve", return_value="block"):
            self.assertEqual(main.engine._sni_target(self.st, "up:u000001"), {"block": True})


if __name__ == "__main__":
    unittest.main()
