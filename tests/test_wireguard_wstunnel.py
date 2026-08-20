"""wstunnel obfuscation: argv parse, settings, and the localhost client config."""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from hub import wireguard_svc, wireguard_wstunnel as wst
from tests.test_wireguard import CLIENT_PRIV, PSK, SERVER_PUB, settings_with

PS_ROW = (
    "80722 /opt/homebrew/bin/wstunnel server "
    "--restrict-to 192.168.1.206:51821 ws://0.0.0.0:8444\n"
)

PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.elvin.wstunnel-wg-server</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/wstunnel</string>
    <string>server</string>
    <string>--restrict-to</string><string>192.168.1.206:51821</string>
    <string>ws://0.0.0.0:8444</string>
  </array>
</dict>
</plist>
"""


class ParseArgvTests(unittest.TestCase):
    def test_reads_listen_and_the_first_restrict_to(self):
        parsed = wst.parse_argv([
            "/opt/homebrew/bin/wstunnel", "server",
            "--restrict-to", "192.168.1.206:51821",
            "ws://0.0.0.0:8444",
        ])
        self.assertEqual(parsed["listen"], "ws://0.0.0.0:8444")
        self.assertEqual(parsed["restrict_to"], "192.168.1.206:51821")

    def test_ignores_a_client_process(self):
        found = wst.parse_process_table(
            "99 /opt/homebrew/bin/wstunnel client -L udp://127.0.0.1:51821:10.0.0.1:51821 "
            "ws://elvin.top:8444\n"
        )
        self.assertFalse(found["running"])

    def test_reads_the_server_row_from_ps(self):
        found = wst.parse_process_table(PS_ROW)
        self.assertTrue(found["running"])
        self.assertEqual(found["pid"], 80722)
        self.assertEqual(found["listen"], "ws://0.0.0.0:8444")
        self.assertEqual(found["restrict_to"], "192.168.1.206:51821")

    def test_reads_the_launch_daemon_plist(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "wstunnel.plist"
            path.write_text(PLIST)
            parsed = wst.read_plist(path)
        self.assertEqual(parsed["listen"], "ws://0.0.0.0:8444")
        self.assertEqual(parsed["restrict_to"], "192.168.1.206:51821")

    def test_array_plist_does_not_500(self):
        import plistlib
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "wstunnel.plist"
            path.write_bytes(plistlib.dumps(["not", "a", "dict"]))
            parsed = wst.read_plist(path)
        self.assertEqual(parsed["listen"], "")
        self.assertEqual(parsed["restrict_to"], "")

    def test_huge_plist_does_not_oom_read(self):
        """``Path.read_bytes()`` of leftover multi-MB LaunchDaemon used to OOM GET /api/wireguard."""
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "wstunnel.plist"
            path.write_bytes(b"x" * (2 * 1024 * 1024))
            parsed = wst.read_plist(path)
        self.assertEqual(parsed["listen"], "")
        self.assertEqual(parsed["restrict_to"], "")

    def test_nested_plist_does_not_500(self):
        """plistlib RecursionError is not ValueError; GET /api/wireguard used to 500."""
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "wstunnel.plist"
            path.write_bytes(b"plist")
            with patch.object(wst.plistlib, "loads", side_effect=RecursionError):
                parsed = wst.read_plist(path)
        self.assertEqual(parsed["listen"], "")
        self.assertEqual(parsed["restrict_to"], "")


class UrlAndCommandTests(unittest.TestCase):
    def test_public_url_keeps_the_listen_port_and_takes_the_endpoint_host(self):
        self.assertEqual(
            wst.public_url("ws://0.0.0.0:8444", "elvin.top"),
            "ws://elvin.top:8444",
        )
        self.assertEqual(
            wst.public_url("ws://0.0.0.0:8444", "elvin.top:51821"),
            "ws://elvin.top:8444",
        )

    def test_rejects_a_url_that_would_break_a_pasted_shell_command(self):
        for bad in (
            "ws://elvin.top:8444; rm -rf /",
            "ws://elvin.top",
            "ftp://elvin.top:8444",
            "ws://elvin.top:8444/../etc",
        ):
            self.assertFalse(wst.valid_listen_url(bad), bad)

    def test_accepts_the_live_bind_and_a_public_hostname(self):
        self.assertTrue(wst.valid_listen_url("ws://0.0.0.0:8444"))
        self.assertTrue(wst.valid_listen_url("ws://elvin.top:8444"))

    def test_client_command_points_at_restrict_to(self):
        self.assertEqual(
            wst.client_command(
                public="ws://elvin.top:8444",
                restrict_to="192.168.1.206:51821",
                local_port=51821,
            ),
            "wstunnel client -L udp://127.0.0.1:51821:192.168.1.206:51821 ws://elvin.top:8444",
        )

    def test_client_command_refuses_metacharacters(self):
        self.assertEqual(
            wst.client_command(
                public="ws://elvin.top:8444;id",
                restrict_to="192.168.1.206:51821",
                local_port=51821,
            ),
            "",
        )


class StatusMergeTests(unittest.TestCase):
    def _live(self, **overrides):
        found = {
            "listen": "ws://0.0.0.0:8444",
            "restrict_to": "192.168.1.206:51821",
            "pid": 80722,
            "running": True,
            "binary": "/opt/homebrew/bin/wstunnel",
            "plist": "/Library/LaunchDaemons/com.elvin.wstunnel-wg-server.plist",
        }
        found.update(overrides)
        return found

    def test_fills_blanks_from_the_running_process(self):
        with (
            patch.object(wst, "live", return_value=self._live()),
            patch.object(wst, "local_ipv4s", return_value=frozenset({"192.168.1.206"})),
        ):
            snap = wst.status({
                "endpoint": "elvin.top",
                "listen_port": 51821,
            })
        self.assertTrue(snap["running"])
        self.assertFalse(snap["enabled"], "a leftover process is not an opt-in")
        self.assertTrue(snap["configured"])
        self.assertEqual(snap["public"], "ws://elvin.top:8444")
        self.assertEqual(snap["port"], 8444)
        self.assertEqual(snap["local_endpoint"], "127.0.0.1:51821")
        self.assertIn("192.168.1.206:51821", snap["client_command"])
        self.assertFalse(snap["stable_restrict"])
        self.assertFalse(snap["needs_apply"])
        self.assertFalse(snap["needs_stabilize"])

    def test_export_uses_the_live_restrict_to_while_the_process_is_up(self):
        """A generated -L dest the running server will refuse is worse than a LAN IP."""
        with (
            patch.object(wst, "live", return_value=self._live()),
            patch.object(wst, "local_ipv4s", return_value=frozenset({"192.168.1.206"})),
        ):
            snap = wst.status({
                "wstunnel_enabled": True,
                "wstunnel_listen": "ws://0.0.0.0:8444",
                "wstunnel_restrict_to": "127.0.0.1:51821",
                "endpoint": "elvin.top",
                "listen_port": 51821,
            })
        self.assertEqual(snap["restrict_to"], "192.168.1.206:51821")
        self.assertEqual(snap["desired_restrict_to"], "127.0.0.1:51821")
        self.assertFalse(snap["aligned"])
        self.assertTrue(snap["needs_apply"])
        self.assertTrue(snap["needs_stabilize"])
        self.assertIn("192.168.1.206:51821", snap["client_command"])

    def test_lan_restrict_is_unstable_even_when_the_address_is_still_here(self):
        with (
            patch.object(wst, "live", return_value=self._live()),
            patch.object(wst, "local_ipv4s", return_value=frozenset({"192.168.1.206"})),
        ):
            snap = wst.status({
                "wstunnel_enabled": True,
                "wstunnel_listen": "ws://0.0.0.0:8444",
                "wstunnel_restrict_to": "192.168.1.206:51821",
                "listen_port": 51821,
            })
        self.assertTrue(snap["aligned"])
        self.assertFalse(snap["stable_restrict"])
        self.assertFalse(snap["stale_restrict"])
        self.assertTrue(snap["needs_stabilize"])
        self.assertFalse(snap["needs_apply"])

    def test_status_tolerates_a_list_settings_blob(self):
        with (
            patch.object(wst, "live", return_value={
                "listen": "", "restrict_to": "", "pid": 0, "running": False,
                "binary": "", "plist": "",
            }),
            patch.object(wst, "local_ipv4s", return_value=frozenset()),
        ):
            snap = wst.status(["not", "a", "map"])
        self.assertFalse(snap["enabled"])
        self.assertFalse(snap["running"])
        self.assertFalse(snap["configured"])

    def test_a_default_listen_alone_does_not_count_as_configured(self):
        with (
            patch.object(wst, "live", return_value={
                "listen": "", "restrict_to": "", "pid": 0, "running": False,
                "binary": "", "plist": "",
            }),
            patch.object(wst, "local_ipv4s", return_value=frozenset()),
        ):
            snap = wst.status({
                "wstunnel_enabled": False,
                "wstunnel_listen": wst.DEFAULT_LISTEN,
                "listen_port": 51821,
            })
        self.assertFalse(snap["configured"])
        self.assertFalse(snap["enabled"])

    def test_ports_tab_gains_the_root_listener_lsof_cannot_see(self):
        from hub.network_svc import _with_wstunnel_listener

        rows = _with_wstunnel_listener(
            [{"process": "nginx", "pid": "1", "user": "a0000", "address": "*:80", "port": "80"}],
            {"listen": "ws://0.0.0.0:8444", "port": 8444, "pid": 80722},
        )
        self.assertEqual(rows[-1]["process"], "wstunnel")
        self.assertEqual(rows[-1]["port"], "8444")

    def test_listener_row_is_what_the_ports_tab_was_missing(self):
        row = wst.listener_row({
            "listen": "ws://0.0.0.0:8444",
            "port": 8444,
            "pid": 80722,
        })
        self.assertEqual(row["process"], "wstunnel")
        self.assertEqual(row["port"], "8444")
        self.assertEqual(row["user"], "root")

    def test_listener_row_out_of_range_port_does_not_500(self):
        """urlparse().port raises on 99999; listen_parts already rejected the path."""
        self.assertIsNone(wst.listener_row({
            "listen": "ws://0.0.0.0:99999/secret",
            "port": 0,
        }))
        self.assertIsNone(wst.listener_row(["not", "a", "map"]))
        from hub.network_svc import _with_wstunnel_listener
        rows = _with_wstunnel_listener(
            [{"process": "nginx", "pid": "1", "user": "a", "address": "*:80", "port": "80"}],
            {"listen": "ws://0.0.0.0:99999/x", "port": 0},
        )
        self.assertEqual(len(rows), 1)

    def test_unicode_pid_and_nul_argv_are_skipped(self):
        self.assertFalse(wst.parse_process_table(
            "\u00b2 /opt/homebrew/bin/wstunnel server "
            "--restrict-to 127.0.0.1:51821 ws://0.0.0.0:8444\n"
        )["running"])
        self.assertFalse(wst.parse_process_table(
            "99 /opt/homebrew/bin/wstunnel\x00evil server "
            "--restrict-to 127.0.0.1:51821 ws://0.0.0.0:8444\n"
        )["running"])


class SettingsAndExportTests(unittest.TestCase):
    def _identity(self):
        return {
            "private_key": "aFakeServerPrivateKeyValueForTests0000000000=",
            "public_key": SERVER_PUB,
            "address": "10.10.0.1/24",
            "listen_port": 51821,
        }

    def test_rejects_a_wstunnel_url_with_a_path(self):
        with (
            patch("hub.wireguard_svc.cfg", return_value={"settings": {"wireguard": {}}}),
            patch("hub.wireguard_svc.update_settings"),
            self.assertRaises(wireguard_svc.WireGuardError) as ctx,
        ):
            wireguard_svc.save_settings({"wstunnel_listen": "ws://elvin.top:8444/secret"})
        self.assertEqual(ctx.exception.code, "wg.bad_wstunnel_url")

    def test_rejects_a_restrict_to_without_a_port(self):
        with (
            patch("hub.wireguard_svc.cfg", return_value={"settings": {"wireguard": {}}}),
            patch("hub.wireguard_svc.update_settings"),
            self.assertRaises(wireguard_svc.WireGuardError) as ctx,
        ):
            wireguard_svc.save_settings({"wstunnel_restrict_to": "192.168.1.206"})
        self.assertEqual(ctx.exception.code, "wg.bad_wstunnel_target")

    def test_persists_a_valid_wstunnel_patch(self):
        with (
            patch("hub.wireguard_svc.cfg", return_value={"settings": {"wireguard": {}}}),
            patch("hub.wireguard_svc.update_settings") as saved,
        ):
            wireguard_svc.save_settings({
                "wstunnel_enabled": True,
                "wstunnel_listen": "ws://0.0.0.0:8444",
                "wstunnel_public": "ws://elvin.top:8444",
                "wstunnel_restrict_to": "192.168.1.206:51821",
            })
        stored = saved.call_args[0][0]["wireguard"]
        self.assertTrue(stored["wstunnel_enabled"])
        self.assertEqual(stored["wstunnel_public"], "ws://elvin.top:8444")

    def test_obfuscated_client_conf_dials_localhost(self):
        snap = {
            "local_endpoint": "127.0.0.1:51821",
            "client_command": (
                "wstunnel client -L udp://127.0.0.1:51821:192.168.1.206:51821 "
                "ws://elvin.top:8444"
            ),
        }
        with (
            patch("hub.wireguard_svc.settings", side_effect=lambda: settings_with(
                listen_port=51821, endpoint="elvin.top",
            )),
            patch("hub.wireguard_svc.server_identity", return_value=self._identity()),
            patch("hub.wireguard_svc.wstunnel_status", return_value=snap),
        ):
            conf = wireguard_svc.build_client_conf(
                private_key=CLIENT_PRIV, ip="10.10.0.5/32", mode="split",
                preshared_key=PSK, obfuscated=True,
            )
        self.assertIn("Endpoint = 127.0.0.1:51821", conf)
        self.assertIn("wstunnel client -L udp://127.0.0.1:51821:192.168.1.206:51821", conf)
        self.assertNotIn("Endpoint = elvin.top", conf)


class RestrictAndPlistTests(unittest.TestCase):
    def test_loopback_is_the_stable_restrict_to(self):
        self.assertTrue(wst.restrict_is_stable("127.0.0.1:51821"))
        self.assertFalse(wst.restrict_is_stable("192.168.1.206:51821"))
        self.assertTrue(wst.valid_restrict_to("127.0.0.1:51821"))
        self.assertFalse(wst.valid_restrict_to("192.168.1.206"))
        self.assertFalse(wst.valid_restrict_to("127.0.0.1:51821;id"))

    def test_stale_is_not_guessed_when_ifconfig_is_empty(self):
        self.assertFalse(wst.restrict_is_stale("10.0.0.1:51821", frozenset()))
        self.assertTrue(wst.restrict_is_stale("10.0.0.1:51821", frozenset({"192.168.1.206"})))
        self.assertFalse(wst.restrict_is_stale("127.0.0.1:51821", frozenset({"192.168.1.206"})))

    def test_render_plist_pins_the_homebrew_binary(self):
        body = wst.render_plist(
            binary="/opt/homebrew/bin/wstunnel",
            listen="ws://0.0.0.0:8444",
            restrict_to="127.0.0.1:51821",
        )
        self.assertIn("com.elvin.wstunnel-wg-server", body)
        self.assertIn("127.0.0.1:51821", body)
        self.assertIn("/opt/homebrew/bin/wstunnel", body)
        with self.assertRaises(ValueError):
            wst.render_plist(
                binary="/tmp/wstunnel",
                listen="ws://0.0.0.0:8444",
                restrict_to="127.0.0.1:51821",
            )


class ReadinessAndApplyTests(unittest.TestCase):
    def test_readiness_stays_quiet_unless_the_operator_enabled_it(self):
        from hub import wireguard_net_svc as net

        with patch.object(wst, "status") as status:
            checks = net._wstunnel_readiness_checks({
                "interface": "wg0", "listen_port": 51821,
            })
        self.assertEqual(checks, [])
        status.assert_not_called()

    def test_readiness_warns_when_enabled_but_the_process_is_down(self):
        from hub import wireguard_net_svc as net

        with patch.object(wst, "status", return_value={
            "running": False, "aligned": True, "stable_restrict": True,
            "stale_restrict": False, "listen": "ws://0.0.0.0:8444",
            "restrict_to": "127.0.0.1:51821", "label": wst.LABEL,
            "desired_listen": "ws://0.0.0.0:8444",
            "desired_restrict_to": "127.0.0.1:51821",
        }):
            checks = net._wstunnel_readiness_checks({"wstunnel_enabled": True})
        by_id = {c["id"]: c for c in checks}
        self.assertFalse(by_id["wstunnel"]["ok"])
        self.assertEqual(by_id["wstunnel"]["level"], "warn")
        self.assertEqual(by_id["wstunnel_align"]["superseded_by"], "wstunnel")
        self.assertEqual(by_id["wstunnel_restrict"]["superseded_by"], "wstunnel")

    def test_readiness_keeps_the_restrict_row_while_the_process_is_up(self):
        from hub import wireguard_net_svc as net

        with patch.object(wst, "status", return_value={
            "running": True, "aligned": True, "stable_restrict": False,
            "stale_restrict": False, "listen": "ws://0.0.0.0:8444",
            "restrict_to": "192.168.1.206:51821", "label": wst.LABEL,
            "desired_listen": "ws://0.0.0.0:8444",
            "desired_restrict_to": "192.168.1.206:51821",
            "suggest_restrict_to": "127.0.0.1:51821",
        }):
            checks = net._wstunnel_readiness_checks({"wstunnel_enabled": True})
        by_id = {c["id"]: c for c in checks}
        self.assertTrue(by_id["wstunnel"]["ok"])
        self.assertFalse(by_id["wstunnel_restrict"]["ok"])
        self.assertNotIn("superseded_by", by_id["wstunnel_restrict"])

    def test_uninstall_is_a_no_op_when_the_plist_and_process_are_already_gone(self):
        from hub import wireguard_net_svc as net

        with (
            patch.object(wst, "PLIST_PATH") as plist,
            patch.object(wst, "live", return_value={"running": False}),
            patch.object(wireguard_svc, "save_settings") as saved,
            patch.object(net, "run_admin_sequence") as admin,
        ):
            plist.exists.return_value = False
            result = net.uninstall_wstunnel()
        self.assertTrue(result["ok"])
        self.assertFalse(result["removed"])
        saved.assert_called_once_with({"wstunnel_enabled": False})
        admin.assert_not_called()

    def test_install_refuses_a_missing_binary_without_asking_for_a_password(self):
        from hub import wireguard_net_svc as net

        with (
            patch.object(wst, "find_binary", return_value=""),
            patch.object(net, "run_admin_sequence") as admin,
        ):
            result = net.install_wstunnel()
        self.assertEqual(result["error"], "wstunnel_missing")
        admin.assert_not_called()

    def test_install_writes_the_desired_layout_into_a_root_plist(self):
        from hub import wireguard_net_svc as net

        with (
            patch.object(wst, "find_binary", return_value="/opt/homebrew/bin/wstunnel"),
            patch.object(wireguard_svc, "settings", return_value={
                "wstunnel_enabled": True,
                "wstunnel_listen": "ws://0.0.0.0:8444",
                "wstunnel_restrict_to": "127.0.0.1:51821",
                "listen_port": 51821,
            }),
            patch.object(wst, "status", return_value={
                "desired_listen": "ws://0.0.0.0:8444",
                "desired_restrict_to": "127.0.0.1:51821",
            }),
            patch.object(net, "replace_secret_text") as staged,
            patch.object(net, "run_admin_sequence", return_value={"ok": True}) as admin,
            patch.object(wst, "read_plist", return_value={
                "listen": "ws://0.0.0.0:8444",
                "restrict_to": "127.0.0.1:51821",
            }),
            patch.object(wst.live, "invalidate") as bust,
        ):
            result = net.install_wstunnel()
        self.assertTrue(result["ok"])
        body = staged.call_args[0][1]
        self.assertIn("127.0.0.1:51821", body)
        self.assertIn("/opt/homebrew/bin/wstunnel", body)
        argv = [cmd[0] for cmd in admin.call_args[0][0]]
        self.assertEqual(argv[0], "/bin/launchctl")
        self.assertEqual(argv[-1], "/bin/launchctl")
        bust.assert_called_once()

    def test_install_refuses_to_report_success_it_cannot_see_on_disk(self):
        """A ";"-joined sequence reports only its last step's exit status.

        The steps run as one `/bin/sh -c "a; b; c"`, so a failed cp/chown leaves
        `launchctl bootstrap` to succeed on whatever plist a previous install
        left behind -- and the caller would be told the *new* listen and
        restrict-to are live when root is still running the old ones.
        """
        from hub import wireguard_net_svc as net

        with (
            patch.object(wst, "find_binary", return_value="/opt/homebrew/bin/wstunnel"),
            patch.object(wireguard_svc, "settings", return_value={"listen_port": 51821}),
            patch.object(wst, "status", return_value={
                "desired_listen": "ws://0.0.0.0:8444",
                "desired_restrict_to": "127.0.0.1:51821",
            }),
            patch.object(net, "replace_secret_text"),
            patch.object(net, "run_admin_sequence", return_value={"ok": True}),
            # The stale plist a previous install left in place.
            patch.object(wst, "read_plist", return_value={
                "listen": "ws://0.0.0.0:9999",
                "restrict_to": "127.0.0.1:51820",
            }),
            patch.object(wst.live, "invalidate"),
        ):
            result = net.install_wstunnel()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "wstunnel_install_unverified")
        # What root is actually running, so the message is not a bare failure.
        self.assertEqual(result["listen"], "ws://0.0.0.0:9999")
        self.assertEqual(result["restrict_to"], "127.0.0.1:51820")

    def test_stabilize_does_not_persist_a_restrict_to_that_never_landed(self):
        """The docstring promises settings follow the privileged install."""
        from hub import wireguard_net_svc as net

        with (
            patch.object(wst, "find_binary", return_value="/opt/homebrew/bin/wstunnel"),
            patch.object(wireguard_svc, "settings", return_value={"listen_port": 51821}),
            patch.object(wst, "status", return_value={
                "desired_listen": "ws://0.0.0.0:8444",
                "desired_restrict_to": "0.0.0.0:51821",
            }),
            patch.object(net, "replace_secret_text"),
            patch.object(net, "run_admin_sequence", return_value={"ok": True}),
            patch.object(wst, "read_plist", return_value={
                "listen": "ws://0.0.0.0:8444",
                "restrict_to": "0.0.0.0:51821",
            }),
            patch.object(wst.live, "invalidate"),
            patch.object(wireguard_svc, "save_settings") as saved,
        ):
            result = net.stabilize_wstunnel()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "wstunnel_install_unverified")
        saved.assert_not_called()

    def test_stabilize_saves_loopback_only_after_the_daemon_applies(self):
        from hub import wireguard_net_svc as net

        with (
            patch.object(wireguard_svc, "settings", return_value={"listen_port": 51821}),
            patch.object(net, "install_wstunnel", return_value={"ok": True}) as install,
            patch.object(wireguard_svc, "save_settings") as saved,
        ):
            result = net.stabilize_wstunnel()
        self.assertTrue(result["ok"])
        install.assert_called_once_with(restrict_to="127.0.0.1:51821")
        saved.assert_called_once()
        self.assertEqual(saved.call_args[0][0]["wstunnel_restrict_to"], "127.0.0.1:51821")

    def test_stabilize_does_not_rewrite_settings_when_the_password_sheet_is_cancelled(self):
        from hub import wireguard_net_svc as net

        with (
            patch.object(wireguard_svc, "settings", return_value={"listen_port": 51821}),
            patch.object(net, "install_wstunnel", return_value={"ok": False, "error": "password_required"}),
            patch.object(wireguard_svc, "save_settings") as saved,
        ):
            result = net.stabilize_wstunnel()
        self.assertFalse(result["ok"])
        saved.assert_not_called()
