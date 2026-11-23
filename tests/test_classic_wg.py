"""Tests for classic WireGuard server and client config generation."""
import os
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import threading

import app.awgserver as awgserver  # noqa: E402
import app.config as config  # noqa: E402
import app.nftgen as nftgen  # noqa: E402
import app.shaping as shaping  # noqa: E402
import app.store as store_mod  # noqa: E402
import app.system as system  # noqa: E402
import app.tgbot as tgbot  # noqa: E402
import app.users as users  # noqa: E402
import app.engine.common as engine_common  # noqa: E402
import app.engine.server as engine_server  # noqa: E402
import app.engine as engine_mod  # noqa: E402


class TestClassicWG(unittest.TestCase):
    def test_new_wg_server_has_no_awg_params(self):
        sc = awgserver.new_wg_server("PRIVKEY==", 51820, "10.8.2.0/24")
        self.assertEqual(sc.params(), {})
        text = sc.render()
        for k in awgserver.AWG_PARAMS:
            self.assertNotIn(f"{k} =", text)
        self.assertIn("ListenPort = 51820", text)
        self.assertIn("Address = 10.8.2.1/24", text)

    def test_client_conf_wg_only_strips_all_awg_params(self):
        sc = awgserver.new_server("PRIVKEY==", 47823, "10.8.1.0/24", awgserver.generate_params(True))
        peer = awgserver.Peer(public_key="PUB==", psk="PSK==", allowed_ips="10.8.2.2/32")
        prof = awgserver.ClientProfile(
            host="1.2.3.4",
            port=51820,
            server_pub="SPUB==",
            dns=["10.8.2.1"],
            mtu=1420,
            keepalive="25-35",
        )
        conf = awgserver.client_conf(sc, prof, peer, "CPRIV==", override={"I1": "<r 2>"}, wg_only=True)
        for k in awgserver.AWG_PARAMS:
            self.assertNotIn(f"{k} =", conf)
        self.assertIn("PersistentKeepalive = 25\n", conf)
        self.assertIn("PrivateKey = CPRIV==", conf)
        self.assertIn("Endpoint = 1.2.3.4:51820", conf)

    def test_client_conf_wg_only_preserves_scalar_keepalive(self):
        sc = awgserver.new_wg_server("PRIVKEY==", 51820, "10.8.2.0/24")
        peer = awgserver.Peer(public_key="PUB==", psk="PSK==", allowed_ips="10.8.2.2/32")
        prof = awgserver.ClientProfile(
            host="1.2.3.4",
            port=51820,
            server_pub="SPUB==",
            dns=["10.8.2.1"],
            mtu=1420,
            keepalive="30",
        )
        conf = awgserver.client_conf(sc, prof, peer, "CPRIV==", wg_only=True)
        self.assertIn("PersistentKeepalive = 30\n", conf)

    def test_nftgen_supports_multiple_wg_interfaces(self):
        rules = nftgen.generate(["awg0", "wg0"], {}, [], {"rules": [], "default": "direct"}, {}, 10443)
        self.assertIn('iifname != { "awg0", "wg0" } return', rules)
        self.assertIn('iifname { "awg0", "wg0" } ip daddr', rules)

        acct = nftgen.acct_ruleset(["awg0", "wg0"])
        self.assertIn('iifname { "awg0", "wg0" }', acct)
        self.assertIn('oifname { "awg0", "wg0" }', acct)

        marker = nftgen.acct_marker(["awg0", "wg0"])
        parsed = nftgen.parse_acct({
            "nftables": [
                {"rule": {"comment": marker}},
                {"set": {"table": nftgen.ACCT_TABLE, "name": "up", "elem": [
                    {"elem": {"val": {"concat": ["10.8.2.2", "eth0"]}, "counter": {"bytes": 1234}}}
                ]}},
            ]
        }, ["awg0", "wg0"])
        self.assertEqual(parsed, {("10.8.2.2", "eth0"): [1234, 0]})

    def test_server_ifaces_helper(self):
        t_no_wg = mock.Mock(iface="awg0", spec=["iface"])
        self.assertEqual(engine_common.server_ifaces(t_no_wg), ["awg0"])

        t_wg_off = mock.Mock(iface="awg0")
        t_wg_off.wg_exists.return_value = False
        self.assertEqual(engine_common.server_ifaces(t_wg_off), ["awg0"])

        t_wg_on = mock.Mock(iface="awg0")
        t_wg_on.wg_exists.return_value = True
        self.assertEqual(engine_common.server_ifaces(t_wg_on), ["awg0", "wg0"])

    def test_v6_ruleset_supports_multiple_ifaces(self):
        single = engine_server.v6_ruleset("awg0")
        self.assertIn('iifname "awg0" reject', single)
        multi = engine_server.v6_ruleset(["awg0", "wg0"])
        self.assertIn('iifname { "awg0", "wg0" } reject', multi)

    def test_shaping_plan_supports_multiple_ifaces(self):
        plan = shaping.plan(["awg0", "wg0"], {"down": 100, "up": 50}, {}, [])
        self.assertIn("awg0", plan["roots"])
        self.assertIn("wg0", plan["roots"])
        self.assertEqual(plan["ingress"].get("awg0"), "awgq0")
        self.assertEqual(plan["ingress"].get("wg0"), "awgq0")

    def test_engine_routes_multi_iface_ruleset_and_sysctl(self):
        eng = engine_mod.Engine.__new__(engine_mod.Engine)
        eng.bal_nums = frozenset()
        eng._sniff_slots = {}
        eng.rt = {}
        eng._policies = lambda st: ({"rules": [], "default": "direct"}, {})
        eng._cidrs = lambda lid: []
        eng._up_list = lambda st: []
        eng.dom_filter_on = lambda st: False
        eng.strict = lambda st: False

        t = mock.Mock(iface="awg0", kind="host")
        t.wg_exists.return_value = True
        rules = eng.build_ruleset(t, {"settings": {}, "routing": {}}, 10443)
        self.assertIn('iifname != { "awg0", "wg0" } return', rules)

        eng._sysctl(t)
        sysctl_cmds = [c.args[0] for c in t.ns.call_args_list]
        self.assertIn(["sysctl", "-qw", "net.ipv4.conf.awg0.rp_filter=2"], sysctl_cmds)
        self.assertIn(["sysctl", "-qw", "net.ipv4.conf.wg0.rp_filter=2"], sysctl_cmds)

    def test_config_wg_init_defaults(self):
        self.assertIsInstance(config.WG_INIT_PORT, int)
        self.assertEqual(config.WG_INIT_SUBNET, "10.8.2.0/24")

    def test_fake_target_enable_and_disable_wg(self):
        t = system.FakeTarget()
        t.disable_wg()
        self.assertFalse(t.wg_exists())
        t.enable_wg(51820, "10.8.2.0/24")
        self.assertTrue(t.wg_exists())
        conf = t.read_file(t.conf_path_for("wg0"))
        self.assertIsNotNone(conf)
        self.assertIn("ListenPort = 51820", conf)
        self.assertIn("Address = 10.8.2.1/24", conf)
        self.assertEqual(t.read_file(t.clients_table_for("wg0")), "[]")
        t.disable_wg()
        self.assertFalse(t.wg_exists())

    def test_fake_target_multi_iface_paths_sync_and_dump(self):
        t = system.FakeTarget()
        t.disable_wg()
        self.assertEqual(t.conf_path_for("awg0"), t.conf_path)
        self.assertEqual(t.conf_path_for("wg0"), f"{t.dir}/wg0.conf")
        self.assertEqual(t.clients_table_for("awg0"), t.clients_table_path)
        self.assertEqual(t.clients_table_for("wg0"), f"{t.dir}/wg0.clientsTable")

        t.enable_wg(51820, "10.8.2.0/24")
        try:
            sc = awgserver.parse(t.read_file(t.conf_path_for("wg0")))
            sc.peers.append(awgserver.Peer(public_key="WG_PEER_PUB==", psk="WG_PSK==", allowed_ips="10.8.2.2/32"))
            t.write_file(t.conf_path_for("wg0"), sc.render())
            t.sync_iface("wg0", sc)
            self.assertTrue(any("awg syncconf wg0 " in line for line in t.log))
            dumped = t.dump_iface("wg0")
            self.assertIn("WG_PEER_PUB==", dumped)
            self.assertEqual(dumped["WG_PEER_PUB=="]["allowed_ips"], "10.8.2.2/32")
        finally:
            t.disable_wg()

    def test_host_target_dir_and_paths(self):
        with mock.patch("os.path.exists", return_value=False):
            h = system.HostTarget("awg0")
        self.assertEqual(h.dir, config.HOST_AWG_DIR)
        self.assertEqual(h.conf_path_for("awg0"), f"{config.HOST_AWG_DIR}/awg0.conf")
        self.assertEqual(h.conf_path_for("wg0"), f"{config.HOST_AWG_DIR}/wg0.conf")
        self.assertEqual(h.clients_table_for("wg0"), f"{config.HOST_AWG_DIR}/wg0.clientsTable")

    def test_container_target_enable_disable_wg_and_sync_iface(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = system.ContainerTarget("amnezia-awg2", 999, "awg0", "/opt/amnezia/awg/awg0.conf", "s")
            c.host_path = lambda p: tmp + p
            cmds = []
            c.native = lambda cmd, **kw: (cmds.append(cmd), mock.Mock(returncode=0, stdout="", stderr=""))[1]
            with mock.patch("app.system.local_awg", return_value="CPRIVKEY=="):
                c.enable_wg(51820, "10.8.2.0/24")
            self.assertTrue(c.wg_exists())
            self.assertIn("ListenPort = 51820", c.read_file("/opt/amnezia/awg/wg0.conf"))
            self.assertEqual(c.read_file("/opt/amnezia/awg/wg0.clientsTable"), "[]")
            self.assertIn(["awg-quick", "up", "/opt/amnezia/awg/wg0.conf"], cmds)

            sc = awgserver.parse(c.read_file(c.conf_path_for("wg0")))
            c.sync_iface("wg0", sc)
            self.assertIn(["awg", "syncconf", "wg0", c.sync_tmp], cmds)

            c.disable_wg()
            self.assertIn(["awg-quick", "down", "/opt/amnezia/awg/wg0.conf"], cmds)
            self.assertFalse(c.wg_exists())

    def test_host_target_enable_and_disable_wg_systemctl_and_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("os.path.exists", return_value=False):
                h = system.HostTarget("awg0")
            h.host_path = lambda p: tmp + p

            # Branch 1: systemctl unit exists
            cmds = []

            def fake_native_unit(cmd, **kw):
                cmds.append(cmd)
                return mock.Mock(returncode=0, stdout="", stderr="")

            h.native = fake_native_unit
            with mock.patch("app.system.local_awg", return_value="HPRIVKEY=="), \
                 mock.patch("app.system.open_firewall_udp") as fw_mock:
                h.enable_wg(51820, "10.8.2.0/24")
            self.assertTrue(h.wg_exists())
            self.assertIn(["systemctl", "enable", "--now", "awg-quick@wg0"], cmds)
            fw_mock.assert_called_once_with(h, 51820)

            cmds.clear()
            h.disable_wg()
            self.assertIn(["systemctl", "disable", "--now", "awg-quick@wg0"], cmds)
            self.assertFalse(h.wg_exists())

            # Branch 2: systemctl unit missing -> awg-quick fallback
            cmds.clear()

            def fake_native_fallback(cmd, **kw):
                cmds.append(cmd)
                rc = 1 if cmd[:2] == ["systemctl", "cat"] else 0
                return mock.Mock(returncode=rc, stdout="", stderr="")

            h.native = fake_native_fallback
            with mock.patch("app.system.local_awg", return_value="HPRIVKEY=="), \
                 mock.patch("app.system.open_firewall_udp") as fw_mock:
                h.enable_wg(51820, "10.8.2.0/24")
            self.assertIn(["awg-quick", "up", "wg0"], cmds)
            fw_mock.assert_called_once_with(h, 51820)

            cmds.clear()
            h.disable_wg()
            self.assertIn(["awg-quick", "down", "wg0"], cmds)
            self.assertFalse(h.wg_exists())

    def _make_fake_env(self, tmp):
        st = store_mod.Store(path=os.path.join(tmp, "state.json"))
        t = system.FakeTarget()
        t.write_file(
            t.conf_path,
            awgserver.new_server(
                "PRIVKEY==", 47823, "10.8.1.0/24", awgserver.generate_params(True)
            ).render(),
        )
        t.write_file(t.clients_table_path, "[]", 0o644)

        class FakeEngine:
            def __init__(self, target, store):
                self.target = target
                self.store = store
                self.lock = threading.RLock()
                self.clients = []
                self.dns_state = {}
                self.public_v4 = "203.0.113.10"
                self.events = []

            def trigger(self):
                pass

            def event(self, level, msg):
                self.events.append((level, msg))

            def dns_view(self):
                return {"state": "off"}

        eng = FakeEngine(t, st)
        return st, t, eng, users.ServerManager(eng)

    def test_add_and_switch_client_proto_preserves_policy(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DRY_RUN", True), \
             mock.patch.object(config, "DATA_DIR", tmp):
            st, t, eng, u = self._make_fake_env(tmp)
            t.enable_wg(51820, "10.8.2.0/24")

            pk = u.add_client("phone", proto="wg")
            cfg = u.client_config(pk)
            self.assertEqual(cfg["proto"], "wg")
            self.assertIsNone(cfg["link"])
            self.assertNotIn("Jc =", cfg["conf"])
            self.assertIn(":51820", cfg["conf"])

            # Attach routing policy to client and verify switching proto preserves it
            def set_pol(s):
                s["clients"].setdefault(pk, {}).update({
                    "outbound": "direct",
                    "rules_mode": "custom",
                    "rules": [],
                    "note": "keep-me",
                    "name": "phone",
                })
            st.mutate(set_pol)

            u.update_client(pk, proto="awg")
            cfg2 = u.client_config(pk)
            self.assertEqual(cfg2["proto"], "awg")
            self.assertTrue(cfg2["link"].startswith("vpn://"))
            self.assertIn("Jc =", cfg2["conf"])
            pol = st.snapshot()["clients"][pk]
            self.assertEqual(pol["outbound"], "direct")
            self.assertEqual(pol["rules_mode"], "custom")
            self.assertEqual(pol["note"], "keep-me")

            # Also verify list_clients shows proto
            listed = {c["public_key"]: c for c in u.list_clients(t)}
            self.assertEqual(listed[pk]["proto"], "awg")

    def test_server_view_and_update_wg_settings(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DRY_RUN", True), \
             mock.patch.object(config, "DATA_DIR", tmp):
            st, t, eng, u = self._make_fake_env(tmp)
            sv = u.server_view()
            self.assertIn("wg", sv)
            self.assertFalse(sv["wg"]["enabled"])

            # Enable wg0
            u.update_server({"wg": {"enabled": True, "port": 51821, "subnet": "10.8.3.0/24"}})
            self.assertTrue(t.wg_exists())
            sv2 = u.server_view()
            self.assertTrue(sv2["wg"]["enabled"])
            self.assertEqual(sv2["wg"]["port"], 51821)
            self.assertEqual(sv2["wg"]["subnet"], "10.8.3.0/24")

            # Overlapping subnet with awg0 must fail
            with self.assertRaises(users.UserError):
                u.update_server({"wg": {"enabled": True, "port": 51821, "subnet": "10.8.1.0/24"}})

            # Cannot disable wg0 while wg clients exist
            pk = u.add_client("wg-user", proto="wg")
            with self.assertRaises(users.UserError):
                u.update_server({"wg": {"enabled": False}})

            # After deleting wg client, disabling wg0 succeeds
            u.delete_client(pk)
            u.update_server({"wg": {"enabled": False}})
            self.assertFalse(t.wg_exists())

    def test_api_clients_and_server_wg(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DRY_RUN", True), \
             mock.patch.object(config, "DATA_DIR", tmp):
            import app.api.clients as api_clients
            import app.api.server as api_server
            st, t, eng, u = self._make_fake_env(tmp)
            t.write_file(
                t.conf_path,
                awgserver.new_server(
                    t._wg_genkey(), 47823, "10.8.1.0/24", awgserver.generate_params(True)
                ).render(),
            )
            eng.srv = u
            eng.reconcile_soon = lambda: None
            eng.dns_listen = lambda: None
            t.enable_wg(51820, "10.8.2.0/24")

            with mock.patch.object(api_clients, "engine", eng), \
                 mock.patch.object(api_clients, "store", st), \
                 mock.patch.object(api_server, "engine", eng), \
                 mock.patch.object(api_server, "store", st):
                req_add = mock.Mock(json=lambda: {"name": "wg-api", "proto": "wg"})
                res = api_clients.add_user(req_add)
                pk = res["public_key"]
                self.assertEqual(u.client_config(pk)["proto"], "wg")

                # put_client (policy edit) must preserve proto == "wg"
                eng.clients = u.list_clients(t)
                req_pol = mock.Mock(json=lambda: {"outbound": "inherit", "rules_mode": "inherit", "rules": [], "note": ""})
                api_clients.put_client(req_pol, pk)
                self.assertEqual(u.client_config(pk)["proto"], "wg")

                # edit_user switches proto -> awg
                req_edit = mock.Mock(json=lambda: {"proto": "awg"})
                api_clients.edit_user(req_edit, pk)
                self.assertEqual(u.client_config(pk)["proto"], "awg")

                # get_server & put_server expose/update wg
                sv = api_server.get_server(mock.Mock())
                self.assertTrue(sv["wg"]["enabled"])

    def test_tgbot_omits_vpn_link_for_wg_client(self):
        ops = mock.Mock()
        wg_cfg = {
            "name": "phone",
            "conf": "[Interface]\nPrivateKey = A\n\n[Peer]\nPublicKey = B\n",
            "filename": "12345678.conf",
            "link": None,
            "proto": "wg",
        }
        ops.share_info.return_value = {"config": wg_cfg}
        ops.client_config.return_value = wg_cfg
        bot = tgbot.Bot(mock.Mock(), ops)
        c = {"token": "TOK", "via": None, "lang": "en", "chat_id": "100"}
        with mock.patch("app.tgbot.notify.send_photo") as send_photo, \
             mock.patch("app.tgbot.notify.send_document") as send_doc, \
             mock.patch("app.tgbot.notify.send") as send_msg:
            bot.client_config(c, "100", "en", "tok123")
            send_photo.assert_called_once()
            send_doc.assert_called_once()
            send_msg.assert_not_called()

            send_photo.reset_mock()
            send_doc.reset_mock()
            send_msg.reset_mock()
            bot.send_config(c, "PUBKEY==")
            send_photo.assert_called_once()
            send_doc.assert_called_once()
            send_msg.assert_not_called()

    def test_dnsproxy_and_sniproxy_multi_subnet_and_profile_dns(self):
        import json
        import app.dnsproxy as dnsproxy
        import app.sniproxy as sniproxy

        with tempfile.TemporaryDirectory() as tmp:
            dns_cfg = os.path.join(tmp, "dns.json")
            with open(dns_cfg, "w") as f:
                json.dump({
                    "listen": "10.8.1.1",
                    "listen_addrs": ["10.8.1.1", "10.8.2.1"],
                    "port": 53,
                    "clients": "10.8.1.0/24",
                    "clients_nets": ["10.8.1.0/24", "10.8.2.0/24"],
                    "upstreams": ["1.1.1.1"],
                }, f)
            p = dnsproxy.Proxy(dns_cfg)
            self.assertTrue(p.allowed("10.8.1.2"))
            self.assertTrue(p.allowed("10.8.2.2"))
            self.assertFalse(p.allowed("10.8.3.2"))

            sni_cfg = os.path.join(tmp, "sni.json")
            with open(sni_cfg, "w") as f:
                json.dump({
                    "listen": "10.8.1.1",
                    "listen_addrs": ["10.8.1.1", "10.8.2.1"],
                    "port": 10443,
                    "clients": "10.8.1.0/24",
                    "clients_nets": ["10.8.1.0/24", "10.8.2.0/24"],
                }, f)
            conf = sniproxy.load(sni_cfg)
            sn = sniproxy.Sniffer(sni_cfg)
            sn.apply(conf)
            self.assertTrue(sn._allowed("10.8.1.2"))
            self.assertTrue(sn._allowed("10.8.2.2"))
            self.assertFalse(sn._allowed("10.8.3.2"))

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DRY_RUN", True), \
             mock.patch.object(config, "DATA_DIR", tmp):
            st, t, eng, u = self._make_fake_env(tmp)
            t.enable_wg(51820, "10.8.2.0/24")
            st.mutate(lambda s: s["settings"].update({"panel_dns": True}))
            eng.dns_state = {"state": "on", "listen": "10.8.1.1"}
            pk_awg = u.add_client("awg-cli", proto="awg")
            pk_wg = u.add_client("wg-cli", proto="wg")
            self.assertIn("DNS = 10.8.1.1", u.client_config(pk_awg)["conf"])
            self.assertIn("DNS = 10.8.2.1", u.client_config(pk_wg)["conf"])

    def test_wg_lifecycle_fixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            # 1. ContainerTarget._write_wg_files omits PostUp/PostDown, HostTarget includes them
            c = system.ContainerTarget("amnezia-awg", 1, "awg0", "/opt/amnezia/awg/awg0.conf", "now")
            c.host_path = lambda p: os.path.join(tmp, "c", p.lstrip("/"))
            with mock.patch("app.system.local_awg", return_value="CPRIVKEY=="):
                c._write_wg_files(51820, "10.8.2.0/24")
            c_conf = c.read_file(c.conf_path_for("wg0")) or ""
            self.assertNotIn("PostUp", c_conf)

            h = system.HostTarget("awg0")
            h.host_path = lambda p: os.path.join(tmp, "h", p.lstrip("/"))
            with mock.patch("app.system.local_awg", return_value="HPRIVKEY=="):
                h._write_wg_files(51820, "10.8.2.0/24")
            h_conf = h.read_file(h.conf_path_for("wg0")) or ""
            self.assertIn("PostUp", h_conf)

            # 2. ContainerTarget.enable_wg / HostTarget.enable_wg clean up files on failure
            c2 = system.ContainerTarget("amnezia-awg", 1, "awg0", "/opt/amnezia/awg/awg0.conf", "now")
            c2.host_path = lambda p: os.path.join(tmp, "c2", p.lstrip("/"))
            c2.native = mock.Mock(side_effect=system.SysError("up failed"))
            with mock.patch("app.system.local_awg", return_value="CPRIVKEY=="):
                with self.assertRaises(system.SysError):
                    c2.enable_wg(51820, "10.8.2.0/24")
            self.assertFalse(c2.wg_exists())

            h2 = system.HostTarget("awg0")
            h2.host_path = lambda p: os.path.join(tmp, "h2", p.lstrip("/"))
            def fail_up(cmd, **kw):
                if cmd[:2] == ["systemctl", "cat"]:
                    return mock.Mock(returncode=1)
                raise system.SysError("up failed")
            h2.native = fail_up
            with mock.patch("app.system.local_awg", return_value="HPRIVKEY=="):
                with self.assertRaises(system.SysError):
                    h2.enable_wg(51820, "10.8.2.0/24")
            self.assertFalse(h2.wg_exists())

            # 3. Target.sync_iface("wg0", sc) falls back to wg when awg_bin fails
            calls = []
            def sync_native(cmd, **kw):
                calls.append(cmd)
                if cmd[0] == "awg":
                    raise system.SysError("no awg")
                return mock.Mock(returncode=0)
            c2.native = sync_native
            sc = awgserver.new_wg_server("CPRIVKEY==", 51820, "10.8.2.0/24", wan_masq=False)
            c2.sync_iface("wg0", sc)
            self.assertEqual([x[0] for x in calls], ["awg", "wg"])

        # 4. _update_wg on ContainerTarget uses t.native (not t.exec)
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DRY_RUN", False), \
             mock.patch.object(config, "DATA_DIR", tmp):
            st, _, eng, u = self._make_fake_env(tmp)
            ct = system.ContainerTarget("amnezia-awg", 1, "awg0", "/opt/amnezia/awg/awg0.conf", "now")
            ct.host_path = lambda p: os.path.join(tmp, "ct", p.lstrip("/"))
            ct.write_file(ct.conf_path, awgserver.new_server("PRIVKEY==", 47823, "10.8.1.0/24", awgserver.generate_params(True)).render())
            ct.write_file(ct.clients_table_path, "[]", 0o644)
            with mock.patch("app.system.local_awg", return_value="CPRIVKEY=="):
                ct._write_wg_files(51820, "10.8.2.0/24")
            native_calls = []
            ct.native = lambda cmd, **kw: native_calls.append(cmd) or mock.Mock(returncode=0)
            eng.target = ct
            awg_sc, _ = u.load(ct)
            self.assertTrue(u._update_wg(ct, awg_sc, {"enabled": True, "port": 51821}))
            self.assertTrue(any("awg-quick up /opt/amnezia/awg/wg0.conf" in " ".join(c) for c in native_calls))

    def test_update_client_proto_atomic_rollback(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DRY_RUN", True), \
             mock.patch.object(config, "DATA_DIR", tmp):
            st, t, eng, u = self._make_fake_env(tmp)
            t.enable_wg(51820, "10.8.2.0/24")
            pk = u.add_client("phone", proto="awg")
            awg_before = t.read_file(t.conf_path)
            wg_before = t.read_file(t.conf_path_for("wg0"))

            # Case 1: second _write (old_iface) fails -> new_iface & store rolled back
            orig_write = u._write
            calls = []
            def fail_second_write(tgt, sc, rows=None, **kw):
                calls.append(kw.get("iface"))
                if len(calls) == 2:
                    raise system.SysError("sync failed")
                return orig_write(tgt, sc, rows, **kw)

            with mock.patch.object(u, "_write", side_effect=fail_second_write):
                with self.assertRaises(system.SysError):
                    u.update_client(pk, proto="wg")
            self.assertEqual(users.client_proto(st.snapshot(), pk), "awg")
            self.assertEqual(t.read_file(t.conf_path), awg_before)
            self.assertEqual(t.read_file(t.conf_path_for("wg0")), wg_before)

            # Case 2: store.mutate fails -> both interfaces rolled back
            with mock.patch.object(st, "mutate", side_effect=RuntimeError("disk full")):
                with self.assertRaises(RuntimeError):
                    u.update_client(pk, proto="wg")
            self.assertEqual(users.client_proto(st.snapshot(), pk), "awg")
            self.assertEqual(t.read_file(t.conf_path), awg_before)
            self.assertEqual(t.read_file(t.conf_path_for("wg0")), wg_before)

    def test_update_client_same_iface_when_state_out_of_sync(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DRY_RUN", True), \
             mock.patch.object(config, "DATA_DIR", tmp):
            st, t, eng, u = self._make_fake_env(tmp)
            t.enable_wg(51820, "10.8.2.0/24")
            pk = u.add_client("phone", proto="wg")
            wg_before = t.read_file(t.conf_path_for("wg0"))

            # Simulate state.json missing proto="wg" while peer is already in wg0.conf
            st.mutate(lambda s: s.get("clients", {}).pop(pk, None))
            self.assertEqual(users.client_proto(st.snapshot(), pk), "awg")

            u.update_client(pk, proto="wg")
            self.assertEqual(users.client_proto(st.snapshot(), pk), "wg")
            wg_sc, _ = u.load(t, "wg0")
            self.assertEqual([p.public_key for p in wg_sc.peers].count(pk), 1)
            self.assertEqual(t.read_file(t.conf_path_for("wg0")), wg_before)

    def test_update_server_validates_wg_conflicts_before_restart(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DRY_RUN", True), \
             mock.patch.object(config, "DATA_DIR", tmp):
            import app.api.server as api_server
            st, t, eng, u = self._make_fake_env(tmp)
            t.write_file(
                t.conf_path,
                awgserver.new_server(
                    t._wg_genkey(), 47823, "10.8.1.0/24", awgserver.generate_params(True)
                ).render(),
            )
            eng.srv = u
            eng.reconcile_soon = lambda: None
            eng.dns_listen = lambda: None
            awg_before = t.read_file(t.conf_path)

            # 1. Port conflict with wg in same request: awg0 must NOT be written/restarted
            with mock.patch.object(u, "_write") as write_mock:
                with self.assertRaises(users.UserError):
                    u.update_server({"port": 51820, "wg": {"enabled": True, "port": 51820, "subnet": "10.8.2.0/24"}})
                write_mock.assert_not_called()
            self.assertEqual(t.read_file(t.conf_path), awg_before)

            # 2. Enable wg0 via api_server.put_server, then change awg0 port to collide with active wg0 (without "wg" in body)
            with mock.patch.object(api_server, "engine", eng), \
                 mock.patch.object(api_server, "store", st):
                res = api_server.put_server(mock.Mock(json=lambda: {
                    "wg": {"enabled": True, "port": 51820, "subnet": "10.8.2.0/24"}
                }))
                self.assertTrue(res["wg_changed"])
                with mock.patch.object(u, "_write") as write_mock:
                    with self.assertRaises(users.UserError):
                        u.update_server({"port": 51820})
                    write_mock.assert_not_called()
                with mock.patch.object(u, "_write") as write_mock:
                    with self.assertRaises(users.UserError):
                        u.update_server({"address": "10.8.2.1/24"})
                    write_mock.assert_not_called()

    def test_backup_and_restore_preserves_wg_proto_and_files(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DRY_RUN", True), \
             mock.patch.object(config, "DATA_DIR", tmp):
            import app.api.backup as backup
            st, t, eng, u = self._make_fake_env(tmp)
            t.write_file(
                t.conf_path,
                awgserver.new_server(
                    t._wg_genkey(), 47823, "10.8.1.0/24", awgserver.generate_params(True)
                ).render(),
            )
            eng.srv = u
            eng.traffic = mock.Mock(export=lambda: {}, replace=lambda x: None)
            eng.refresh_lists = lambda *a: None
            eng.applied_hash = "x"
            t.enable_wg(51820, "10.8.2.0/24")
            pk_wg = u.add_client("wg-cli", proto="wg")

            with mock.patch.object(backup, "engine", eng), \
                 mock.patch.object(backup, "store", st):
                b = backup.make_backup()
                self.assertEqual(b["state"]["clients"][pk_wg].get("proto"), "wg")
                self.assertIn("wg0.conf", b["server"]["files"])
                self.assertIn("wg0.clientsTable", b["server"]["files"])

                # clean_backup_state preserves proto: "wg"
                cleaned = backup.clean_backup_state(b["state"])
                self.assertEqual(cleaned["clients"][pk_wg].get("proto"), "wg")

                # Remove wg0 files and restore from backup -> wg0 files & proto restored
                t.disable_wg()
                self.assertFalse(t.wg_exists())
                req = mock.Mock(json=lambda *a, **kw: {"backup": b, "server": True})
                backup.restore_backup(req)
                self.assertTrue(t.wg_exists())
                self.assertEqual(users.client_proto(st.snapshot(), pk_wg), "wg")

                # Restore a backup without wg0.conf -> strips proto: "wg"
                b_no_wg = json.loads(json.dumps(b)) if "json" in globals() else __import__("json").loads(__import__("json").dumps(b))
                b_no_wg["server"]["files"].pop("wg0.conf", None)
                b_no_wg["server"]["files"].pop("wg0.clientsTable", None)
                req2 = mock.Mock(json=lambda *a, **kw: {"backup": b_no_wg, "server": True})
                backup.restore_backup(req2)
                self.assertEqual(users.client_proto(st.snapshot(), pk_wg), "awg")

    def test_speed_mixin_clears_wg0_ingress_qdisc(self):
        import json
        from app.engine.speed import SpeedMixin

        class DummySpeed(SpeedMixin):
            def __init__(self):
                self._shape = {"ing:awg0": "awgq0", "ing:wg0": "awgq0"}
                self._shape_key = "fake"
                self.shape_state = {"state": "on"}

            def _links(self, t):
                return {"awg0", "wg0", "awgq0"}

        t = mock.Mock(iface="awg0")
        t.wg_exists.return_value = True
        tc_json = json.dumps([
            {"dev": "awg0", "kind": "htb", "parent": "root"},
            {"dev": "awg0", "kind": "ingress", "parent": "ffff:fff1"},
            {"dev": "wg0", "kind": "htb", "parent": "root"},
            {"dev": "wg0", "kind": "ingress", "parent": "ffff:fff1"},
            {"dev": "awgq0", "kind": "htb", "parent": "root"},
        ])
        cmds = []
        def fake_ns(cmd, **kw):
            cmds.append(cmd)
            if cmd[:3] == ["tc", "-j", "qdisc"]:
                return mock.Mock(returncode=0, stdout=tc_json, stderr="")
            return mock.Mock(returncode=0, stdout="", stderr="")
        t.ns = fake_ns

        ds = DummySpeed()
        with mock.patch.object(config, "DRY_RUN", False):
            ds._clear_shaping(t)
        self.assertIn(["tc", "qdisc", "del", "dev", "awg0", "ingress"], cmds)
        self.assertIn(["tc", "qdisc", "del", "dev", "wg0", "ingress"], cmds)
        self.assertIn(["ip", "link", "del", "awgq0"], cmds)

    def test_restore_backup_container_refreshes_target_and_disables_before_restart(self):
        import tempfile
        import threading
        import app.api.backup as backup
        import app.store as store

        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(config, "DATA_DIR", td), \
                 mock.patch.object(config, "DRY_RUN", False):
                st = store.Store(os.path.join(td, "state.json"))
                old_t = mock.Mock(kind="container", iface="awg0", dir="/opt/amnezia/awg",
                                  conf_path="/opt/amnezia/awg/awg0.conf")
                new_t = mock.Mock(kind="container", iface="awg0", dir="/opt/amnezia/awg",
                                  conf_path="/opt/amnezia/awg/awg0.conf")
                order = []
                old_t.read_file.return_value = awgserver.new_server("PRIV==", 47823, "10.8.1.0/24", {}).render()
                old_t.wg_exists.return_value = True
                old_t.disable_wg.side_effect = lambda: order.append("disable")
                old_t.restart.side_effect = lambda: order.append("restart")
                new_t.conf_path_for.return_value = "/opt/amnezia/awg/wg0.conf"
                new_t.iface_exists.return_value = False
                new_t.native.side_effect = lambda cmd, **kw: order.append(("native", cmd))

                srv_mock = mock.Mock()
                srv_mock.host_choices.return_value = []
                srv_mock.load.return_value = (awgserver.new_server("PRIV==", 47823, "10.8.1.0/24", {}), [])
                eng = mock.Mock(store=st, lock=threading.Lock(), srv=srv_mock,
                                traffic=mock.Mock(), target=old_t)

                with mock.patch.object(backup, "store", st), \
                     mock.patch.object(backup, "engine", eng), \
                     mock.patch.object(backup.system, "discover", return_value=new_t):
                    priv, _ = users._demo_keypair()
                    wpriv, _ = users._demo_keypair()
                    awg_conf = awgserver.new_server(priv, 47823, "10.8.1.0/24", {}).render()
                    wg_conf = awgserver.new_wg_server(wpriv, 51820, "10.8.2.0/24").render()
                    old_t.read_file.return_value = awg_conf
                    srv_mock.load.return_value = (awgserver.parse(awg_conf), [])

                    # Case 1: backup without wg0.conf -> disable_wg happens BEFORE restart
                    b_no_wg = {"format": backup.BACKUP_FORMAT, "state": st.snapshot(), "server": {
                        "kind": "container", "conf": "awg0.conf", "files": {"awg0.conf": awg_conf}}}
                    backup.restore_backup(mock.Mock(json=lambda *a, **kw: {"backup": b_no_wg, "server": True}))
                    self.assertEqual(order, ["disable", "restart"])

                    # Case 2: backup with wg0.conf -> discover() refreshes target AFTER restart
                    order.clear()
                    b_with_wg = {"format": backup.BACKUP_FORMAT, "state": st.snapshot(), "server": {
                        "kind": "container", "conf": "awg0.conf",
                        "files": {"awg0.conf": awg_conf, "wg0.conf": wg_conf}}}
                    backup.restore_backup(mock.Mock(json=lambda *a, **kw: {"backup": b_with_wg, "server": True}))
                    self.assertEqual(order[0], "restart")
                    self.assertEqual(order[1][0], "native")

    def test_update_server_container_refreshes_target_before_apply_wg(self):
        import tempfile
        import threading
        import app.store as store

        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(config, "DATA_DIR", td), \
                 mock.patch.object(config, "DRY_RUN", False):
                st = store.Store(os.path.join(td, "state.json"))
                old_t = mock.Mock(kind="container", iface="awg0", dir="/opt/amnezia/awg",
                                  conf_path="/opt/amnezia/awg/awg0.conf")
                new_t = mock.Mock(kind="container", iface="awg0", dir="/opt/amnezia/awg",
                                  conf_path="/opt/amnezia/awg/awg0.conf")
                sc = awgserver.new_server("PRIV==", 47823, "10.8.1.0/24", awgserver.generate_params(True))
                old_t.read_file.return_value = sc.render()
                old_t.wg_exists.return_value = False
                eng = mock.Mock(store=st, lock=threading.Lock(), target=old_t)
                u = users.ServerManager(eng)
                u.load = mock.Mock(return_value=(sc, []))
                u._write = mock.Mock()
                seen = []
                u._apply_wg = mock.Mock(side_effect=lambda tgt, plan: seen.append(tgt) or True)

                with mock.patch.object(users.system, "discover", return_value=new_t):
                    res = u.update_server({
                        "params": {"S1": "15"},  # triggers server-side restart
                        "wg": {"enabled": True, "port": 51820, "subnet": "10.8.2.0/24"},
                    })
                self.assertTrue(res["restarted"])
                self.assertTrue(res["wg_changed"])
                self.assertIs(seen[0], new_t)


if __name__ == "__main__":
    unittest.main()
