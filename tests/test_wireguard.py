"""WireGuard service and export-format tests.

Everything here runs without a WireGuard installation and without touching the
real ``wg0.conf``: the config path, peer registry and settings are all patched to
temporary values.  That is deliberate — these tests cover the logic that is easy
to get quietly wrong (address allocation, tunnel-mode routing, key redaction,
foreign-peer detection) rather than the subprocess plumbing.
"""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from hub import wireguard_export as wgx
from hub import wireguard_net_svc, wireguard_svc

SERVER_PRIV = "aFakeServerPrivateKeyValueForTests0000000000="
CLIENT_PRIV = "aFakeClientPrivateKeyValueForTests0000000000="
SERVER_PUB = "sPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0="
PEER_PUB_A = "pPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0="
PEER_PUB_B = "pPubKeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB0="
PSK = "pskValueAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0="

BASE_SETTINGS = {
    "interface": "wg0",
    "subnet": "10.10.0.0/24",
    "listen_port": 51820,
    "dns": "1.1.1.1, 8.8.8.8",
    "mtu": 1280,
    "keepalive": 25,
    "endpoint": "vpn.example.com",
    "lan_cidr": "192.168.1.0/24",
    "wan_interface": "en0",
}


def settings_with(**overrides) -> dict:
    merged = dict(BASE_SETTINGS)
    merged.update(overrides)
    return merged


CLIENT_CONF = f"""[Interface]
PrivateKey = {CLIENT_PRIV}
Address = 10.10.0.5/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280

[Peer]
PublicKey = {SERVER_PUB}
PresharedKey = {PSK}
AllowedIPs = 10.10.0.0/24, 192.168.1.0/24
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
"""


class ParseConfTests(unittest.TestCase):
    def test_separates_interface_from_peer_sections(self):
        """PublicKey means different things per section, so parsing is scoped."""
        parsed = wgx.parse_conf(CLIENT_CONF)
        self.assertEqual(parsed["interface"]["PrivateKey"], CLIENT_PRIV)
        self.assertEqual(parsed["interface"]["Address"], "10.10.0.5/32")
        self.assertEqual(len(parsed["peers"]), 1)
        self.assertEqual(parsed["peers"][0]["PublicKey"], SERVER_PUB)
        self.assertNotIn("PublicKey", parsed["interface"])

    def test_ignores_comments_and_blank_lines(self):
        parsed = wgx.parse_conf(
            "# lead\n\n[Interface]\n; note\nPrivateKey = k\n\n[Peer]\nPublicKey = p\n"
        )
        self.assertEqual(parsed["interface"], {"PrivateKey": "k"})
        self.assertEqual(parsed["peers"], [{"PublicKey": "p"}])

    def test_multiple_peers_are_kept_separate(self):
        text = "[Interface]\nPrivateKey = k\n[Peer]\nPublicKey = a\n[Peer]\nPublicKey = b\n"
        self.assertEqual(
            [p["PublicKey"] for p in wgx.parse_conf(text)["peers"]], ["a", "b"]
        )

    def test_empty_input_is_not_an_error(self):
        self.assertEqual(wgx.parse_conf(""), {"interface": {}, "peers": []})


class ClashExportTests(unittest.TestCase):
    def test_proxy_entry_carries_key_material_and_endpoint(self):
        out = wgx.to_clash_proxy(CLIENT_CONF, "home")
        self.assertIn('- name: "home"', out)
        self.assertIn("type: wireguard", out)
        self.assertIn("server: vpn.example.com", out)
        self.assertIn("port: 51820", out)
        self.assertIn("ip: 10.10.0.5", out)
        self.assertIn(f"private-key: {CLIENT_PRIV}", out)
        self.assertIn(f"public-key: {SERVER_PUB}", out)
        self.assertIn(f"pre-shared-key: {PSK}", out)
        self.assertIn("mtu: 1280", out)

    def test_allowed_ips_become_a_yaml_list(self):
        out = wgx.to_clash_proxy(CLIENT_CONF, "home")
        self.assertIn("allowed-ips:", out)
        self.assertIn("      - 10.10.0.0/24", out)
        self.assertIn("      - 192.168.1.0/24", out)

    def test_preshared_key_omitted_when_absent(self):
        conf = CLIENT_CONF.replace(f"PresharedKey = {PSK}\n", "")
        self.assertNotIn("pre-shared-key", wgx.to_clash_proxy(conf, "home"))


class ClashFullConfigTests(unittest.TestCase):
    def test_split_tunnel_routes_only_the_given_subnets(self):
        out = wgx.to_clash_full(
            CLIENT_CONF, "home", lan_cidr="192.168.1.0/24", wg_cidr="10.10.0.0/24"
        )
        self.assertIn("IP-CIDR,192.168.1.0/24,Home,no-resolve", out)
        self.assertIn("IP-CIDR,10.10.0.0/24,Home,no-resolve", out)
        self.assertIn("- MATCH,DIRECT", out)
        self.assertNotIn("- MATCH,Home", out)

    def test_full_tunnel_matches_everything(self):
        conf = CLIENT_CONF.replace(
            "AllowedIPs = 10.10.0.0/24, 192.168.1.0/24", "AllowedIPs = 0.0.0.0/0, ::/0"
        )
        out = wgx.to_clash_full(conf, "home")
        self.assertIn("- MATCH,Home", out)
        self.assertNotIn("MATCH,DIRECT", out)

    def test_split_tunnel_without_subnets_states_that_nothing_routes(self):
        """An empty rule set would look functional but steer no traffic."""
        out = wgx.to_clash_full(CLIENT_CONF, "home")
        self.assertIn("no home subnet configured", out)
        self.assertIn("- MATCH,DIRECT", out)

    def test_subnets_are_parameters_not_hardcoded(self):
        """The reference panel baked one household's LAN into the rules section.

        Asserted against the rules block only: the proxy entry legitimately
        echoes the peer's own AllowedIPs, which is a different concern.
        """
        out = wgx.to_clash_full(CLIENT_CONF, "home", lan_cidr="10.77.0.0/16")
        rules = out.split("rules:", 1)[1]
        self.assertIn("IP-CIDR,10.77.0.0/16,Home,no-resolve", rules)
        self.assertNotIn("192.168.1.0/24", rules)


class ShadowrocketExportTests(unittest.TestCase):
    def test_url_shape_and_percent_encoding(self):
        out = wgx.to_shadowrocket(CLIENT_CONF, "my phone")
        self.assertTrue(out.startswith("wireguard://vpn.example.com:51820?"))
        self.assertIn("publicKey=sPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0%3D", out)
        self.assertIn("ip=10.10.0.5", out)
        self.assertIn("mtu=1280", out)
        self.assertIn("udp=1", out)
        # The label is a fragment and must survive a space.
        self.assertTrue(out.endswith("#my%20phone"))

    def test_optional_fields_only_appear_when_present(self):
        conf = CLIENT_CONF.replace(f"PresharedKey = {PSK}\n", "")
        self.assertNotIn("presharedKey", wgx.to_shadowrocket(conf, "p"))
        self.assertIn("presharedKey", wgx.to_shadowrocket(CLIENT_CONF, "p"))


class RenderDispatchTests(unittest.TestCase):
    def test_unknown_format_falls_back_to_raw_config(self):
        self.assertEqual(wgx.render("nope", CLIENT_CONF, "n"), CLIENT_CONF)
        self.assertEqual(wgx.render("wg", CLIENT_CONF, "n"), CLIENT_CONF)

    def test_filenames_are_sanitised_per_format(self):
        # Four path characters (/ . . /) each collapse to one dash, so a name
        # cannot escape the download directory or smuggle an extension.
        self.assertEqual(wgx.filename_for("wg", "my phone/../x"), "my-phone----x.conf")
        self.assertEqual(wgx.filename_for("clash", "p"), "p-clash.yaml")
        self.assertEqual(wgx.filename_for("clashfull", "p"), "p-clash-full.yaml")
        self.assertEqual(wgx.filename_for("sr", "p"), "p-shadowrocket.txt")


SERVER_CONF = f"""[Interface]
PrivateKey = {SERVER_PRIV}
Address = 10.10.0.1/24
ListenPort = 51820
DNS = 1.1.1.1
MTU = 1280

[Peer]
# alpha
PublicKey = {PEER_PUB_A}
AllowedIPs = 10.10.0.2/32
PersistentKeepalive = 25

[Peer]
PublicKey = {PEER_PUB_B}
AllowedIPs = 10.10.0.3/32
PersistentKeepalive = 25
"""


class TempConfCase(unittest.TestCase):
    """Points the service at a throwaway config dir and registry."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.conf = self.root / "wg0.conf"
        self.conf.write_text(SERVER_CONF)
        self.registry = self.root / "peers.json"
        self._patches = [
            patch("hub.wireguard_svc.conf_path", return_value=self.conf),
            patch("hub.wireguard_svc.REGISTRY_PATH", self.registry),
            patch("hub.wireguard_svc.settings", side_effect=lambda: settings_with()),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._tmp.cleanup)
        for p in self._patches:
            self.addCleanup(p.stop)


class StripConfTests(unittest.TestCase):
    def test_drops_only_the_wg_quick_directives(self):
        """`wg setconf` rejects Address/DNS/MTU; wg-quick strip needs root."""
        out = wireguard_svc.strip_conf(SERVER_CONF)
        for gone in ("Address", "DNS", "MTU"):
            self.assertNotIn(gone, out)
        self.assertIn("PrivateKey", out)
        self.assertIn("ListenPort", out)
        self.assertIn("PersistentKeepalive", out)
        self.assertEqual(out.count("[Peer]"), 2)

    def test_comments_are_removed(self):
        self.assertNotIn("# alpha", wireguard_svc.strip_conf(SERVER_CONF))


class AddressAllocationTests(TempConfCase):
    def test_used_addresses_includes_the_server_itself(self):
        used = wireguard_svc.used_addresses()
        self.assertIn("10.10.0.1", used)
        self.assertIn("10.10.0.2", used)
        self.assertIn("10.10.0.3", used)

    def test_next_ip_skips_taken_addresses(self):
        result = wireguard_svc.next_ip()
        self.assertEqual(result["next_ip"], "10.10.0.4/32")
        self.assertEqual(result["used"], 3)

    def test_next_ip_reuses_a_freed_address(self):
        """A gap left by a revoked peer is filled before extending the range."""
        self.conf.write_text(SERVER_CONF.replace("AllowedIPs = 10.10.0.2/32", "AllowedIPs = 10.10.0.9/32"))
        self.assertEqual(wireguard_svc.next_ip()["next_ip"], "10.10.0.2/32")

    def test_subnet_full_raises(self):
        peers = "".join(
            f"\n[Peer]\nPublicKey = k{i}\nAllowedIPs = 10.10.0.{i}/32\n" for i in range(2, 255)
        )
        self.conf.write_text(f"[Interface]\nPrivateKey = {SERVER_PRIV}\nAddress = 10.10.0.1/24\n{peers}")
        with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
            wireguard_svc.next_ip()
        self.assertEqual(ctx.exception.code, "wg.subnet_full")

    def test_address_outside_subnet_is_refused(self):
        with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
            wireguard_svc._validate_ip("192.168.5.5")
        self.assertEqual(ctx.exception.code, "wg.ip_outside_subnet")

    def test_garbage_address_is_refused(self):
        for bad in ("", "not-an-ip", "10.10.0.999", "10.10.0.5; rm -rf /"):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc._validate_ip(bad)
            self.assertEqual(ctx.exception.code, "wg.bad_ip")

    def test_valid_address_is_normalised_to_a_host_route(self):
        self.assertEqual(wireguard_svc._validate_ip("10.10.0.77"), "10.10.0.77/32")
        self.assertEqual(wireguard_svc._validate_ip("10.10.0.77/24"), "10.10.0.77/32")


class TunnelModeTests(unittest.TestCase):
    def test_full_tunnel_routes_everything(self):
        with patch("hub.wireguard_svc.settings", side_effect=lambda: settings_with()):
            self.assertEqual(wireguard_svc.client_allowed_ips("full"), "0.0.0.0/0, ::/0")

    def test_split_tunnel_routes_tunnel_and_lan(self):
        with patch("hub.wireguard_svc.settings", side_effect=lambda: settings_with()):
            self.assertEqual(
                wireguard_svc.client_allowed_ips("split"), "10.10.0.0/24, 192.168.1.0/24"
            )

    def test_split_tunnel_without_a_lan_still_routes_the_tunnel(self):
        with patch("hub.wireguard_svc.settings", side_effect=lambda: settings_with(lan_cidr="")):
            self.assertEqual(wireguard_svc.client_allowed_ips("split"), "10.10.0.0/24")


class ClientConfBuildTests(TempConfCase):
    def _identity(self):
        return {
            "private_key": SERVER_PRIV,
            "public_key": SERVER_PUB,
            "address": "10.10.0.1/24",
            "listen_port": 51820,
        }

    def test_includes_endpoint_when_configured(self):
        with patch("hub.wireguard_svc.server_identity", return_value=self._identity()):
            conf = wireguard_svc.build_client_conf(
                private_key=CLIENT_PRIV, ip="10.10.0.5/32", mode="split", preshared_key=PSK
            )
        self.assertIn("Endpoint = vpn.example.com:51820", conf)
        self.assertIn(f"PresharedKey = {PSK}", conf)
        self.assertIn("AllowedIPs = 10.10.0.0/24, 192.168.1.0/24", conf)
        self.assertIn("PersistentKeepalive = 25", conf)

    def test_missing_endpoint_leaves_a_commented_placeholder(self):
        """A silently absent Endpoint would produce a config that cannot connect."""
        with (
            patch("hub.wireguard_svc.settings", side_effect=lambda: settings_with(endpoint="")),
            patch("hub.wireguard_svc.server_identity", return_value=self._identity()),
        ):
            conf = wireguard_svc.build_client_conf(
                private_key=CLIENT_PRIV, ip="10.10.0.5/32", mode="full"
            )
        self.assertNotIn("\nEndpoint =", conf)
        self.assertIn("# Endpoint =", conf)

    def test_explicit_port_in_endpoint_is_preserved(self):
        with (
            patch("hub.wireguard_svc.settings",
                  side_effect=lambda: settings_with(endpoint="vpn.example.com:7777")),
            patch("hub.wireguard_svc.server_identity", return_value=self._identity()),
        ):
            conf = wireguard_svc.build_client_conf(
                private_key=CLIENT_PRIV, ip="10.10.0.5/32", mode="split"
            )
        self.assertIn("Endpoint = vpn.example.com:7777", conf)


class RenderServerConfTests(TempConfCase):
    def test_peer_blocks_are_regenerated_with_names_as_comments(self):
        server = {
            "private_key": SERVER_PRIV, "public_key": SERVER_PUB,
            "address": "10.10.0.1/24", "listen_port": 51820,
        }
        body = wireguard_svc.render_conf(server, [
            {"public_key": PEER_PUB_A, "ip": "10.10.0.2/32", "name": "alpha", "preshared_key": ""},
            {"public_key": PEER_PUB_B, "ip": "10.10.0.3/32", "name": "", "preshared_key": PSK},
        ])
        self.assertIn("# alpha", body)
        self.assertIn(f"PresharedKey = {PSK}", body)
        self.assertEqual(body.count("[Peer]"), 2)
        # Round-trips through the parser it will be read back with.
        parsed = wgx.parse_conf(body)
        self.assertEqual(len(parsed["peers"]), 2)
        self.assertEqual(parsed["interface"]["ListenPort"], "51820")


class PeerRegistryTests(TempConfCase):
    def test_config_is_the_source_of_membership(self):
        """A hand-added peer must still appear, with no registry entry."""
        records = wireguard_svc.peer_records()
        self.assertEqual({r["public_key"] for r in records}, {PEER_PUB_A, PEER_PUB_B})
        for record in records:
            self.assertFalse(record["known"])
            self.assertFalse(record["reissuable"])

    def test_registry_adds_name_mode_and_reissuability(self):
        self.registry.write_text(
            '{"peers": {"%s": {"name": "alpha", "mode": "full", "private_key": "%s"}}}'
            % (PEER_PUB_A, CLIENT_PRIV)
        )
        by_key = {r["public_key"]: r for r in wireguard_svc.peer_records()}
        self.assertEqual(by_key[PEER_PUB_A]["name"], "alpha")
        self.assertEqual(by_key[PEER_PUB_A]["mode"], "full")
        self.assertTrue(by_key[PEER_PUB_A]["reissuable"])
        # The other peer is untouched by a partial registry.
        self.assertFalse(by_key[PEER_PUB_B]["reissuable"])

    def test_peer_without_stored_key_is_not_reissuable(self):
        self.registry.write_text('{"peers": {"%s": {"name": "alpha"}}}' % PEER_PUB_A)
        by_key = {r["public_key"]: r for r in wireguard_svc.peer_records()}
        self.assertTrue(by_key[PEER_PUB_A]["known"])
        self.assertFalse(by_key[PEER_PUB_A]["reissuable"])

    def test_corrupt_registry_degrades_instead_of_raising(self):
        self.registry.write_text("{not json")
        self.assertEqual(len(wireguard_svc.peer_records()), 2)


class ForeignPeerDetectionTests(TempConfCase):
    def test_all_foreign_peers_are_flagged_as_a_conflict(self):
        """The state this machine was found in: peers copied from another server.

        Each client pins the *other* server's public key, so none can handshake
        here no matter how healthy the interface looks.
        """
        with patch("hub.wireguard_net_svc.wireguard_svc", wireguard_svc):
            result = wireguard_net_svc.peer_origin_conflict()
        self.assertTrue(result["conflict"])
        self.assertEqual(result["reason"], "all_peers_foreign")
        self.assertEqual((result["foreign"], result["total"]), (2, 2))

    def test_panel_created_peers_are_not_a_conflict(self):
        self.registry.write_text(
            '{"peers": {"%s": {"name": "a", "private_key": "%s"}, "%s": {"name": "b", "private_key": "%s"}}}'
            % (PEER_PUB_A, CLIENT_PRIV, PEER_PUB_B, CLIENT_PRIV)
        )
        with patch("hub.wireguard_net_svc.wireguard_svc", wireguard_svc):
            self.assertFalse(wireguard_net_svc.peer_origin_conflict()["conflict"])

    def test_a_mix_is_not_reported_as_a_wholesale_copy(self):
        self.registry.write_text(
            '{"peers": {"%s": {"name": "a", "private_key": "%s"}}}' % (PEER_PUB_A, CLIENT_PRIV)
        )
        with patch("hub.wireguard_net_svc.wireguard_svc", wireguard_svc):
            result = wireguard_net_svc.peer_origin_conflict()
        self.assertFalse(result["conflict"])
        self.assertEqual(result["foreign"], 1)

    def test_no_peers_is_not_a_conflict(self):
        self.conf.write_text(f"[Interface]\nPrivateKey = {SERVER_PRIV}\nAddress = 10.10.0.1/24\n")
        with patch("hub.wireguard_net_svc.wireguard_svc", wireguard_svc):
            self.assertFalse(wireguard_net_svc.peer_origin_conflict()["conflict"])


class PfAnchorTests(unittest.TestCase):
    def test_nat_rule_targets_the_egress_interface(self):
        body = wireguard_net_svc.render_anchor("10.10.0.0/24", "en0")
        self.assertIn("nat on en0 inet from 10.10.0.0/24 to any -> (en0)", body)
        self.assertIn(wireguard_net_svc.PF_MARKER, body)

    def test_no_hardcoded_utun_device(self):
        """wireguard-go picks its utun number at runtime; utun0 may be someone else."""
        body = wireguard_net_svc.render_anchor("10.10.0.0/24", "en7")
        self.assertNotIn("utun0", body)
        self.assertNotIn("pass in", body)

    def test_egress_is_parenthesised_so_a_new_lease_still_matches(self):
        body = wireguard_net_svc.render_anchor("10.10.0.0/24", "en0")
        self.assertIn("-> (en0)", body)


class SettingsValidationTests(unittest.TestCase):
    def _save(self, patch_dict):
        with (
            patch("hub.wireguard_svc.cfg", return_value={"settings": {"wireguard": {}}}),
            patch("hub.wireguard_svc.update_settings") as saved,
        ):
            wireguard_svc.save_settings(patch_dict)
            return saved

    def test_rejects_a_bad_subnet(self):
        with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
            self._save({"subnet": "not-a-subnet"})
        self.assertEqual(ctx.exception.code, "wg.bad_subnet")

    def test_rejects_an_out_of_range_port(self):
        for port in (0, 70000):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                self._save({"listen_port": port})
            self.assertEqual(ctx.exception.code, "wg.bad_number")

    def test_rejects_an_absurd_mtu(self):
        with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
            self._save({"mtu": 9000})
        self.assertEqual(ctx.exception.code, "wg.bad_number")

    def test_rejects_an_endpoint_with_shell_metacharacters(self):
        with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
            self._save({"endpoint": "host.example.com; rm -rf /"})
        self.assertEqual(ctx.exception.code, "wg.bad_endpoint")

    def test_rejects_a_bad_interface_name(self):
        for name in ("WG0", "wg 0", "../wg0", "9wg"):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                self._save({"interface": name})
            self.assertEqual(ctx.exception.code, "wg.bad_interface")

    def test_accepts_a_valid_patch(self):
        saved = self._save({"endpoint": "vpn.example.com:51820", "subnet": "10.20.0.0/24"})
        saved.assert_called_once()
        stored = saved.call_args[0][0]["wireguard"]
        self.assertEqual(stored["endpoint"], "vpn.example.com:51820")
        self.assertEqual(stored["subnet"], "10.20.0.0/24")


class PeerKeyRouteShapeTests(unittest.TestCase):
    """The peer key must ride in the query string, never the URL path.

    Starlette percent-decodes the path BEFORE routing, so a base64 WireGuard
    key containing "/" (client-encoded as %2F) splits into extra path segments
    and the request 404s.  That is exactly what broke the config dialog's
    format tabs and download link for every peer whose key contains a slash.
    """

    @classmethod
    def setUpClass(cls):
        from hub.app_factory import create_app

        cls.paths = set(create_app().openapi()["paths"])

    def test_config_and_download_take_the_key_as_a_query_parameter(self):
        for path in ("/api/wireguard/peers/config", "/api/wireguard/peers/download"):
            self.assertIn(path, self.paths, f"{path} is not registered")

    def test_no_route_embeds_the_peer_key_in_the_path(self):
        offenders = sorted(
            p for p in self.paths
            if p.startswith("/api/wireguard/peers/") and "{pubkey}" in p
        )
        self.assertEqual(
            offenders, [],
            "a %2F-encoded key in these paths 404s before it reaches the handler:\n"
            + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
