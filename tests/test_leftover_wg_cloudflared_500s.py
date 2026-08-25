"""Leftover 500s on WireGuard settings/status and cloudflared status.

YAML ``.inf`` listen_port OverflowError'd GET /api/wireguard; a last-address
subnet parsed then crashed next-ip; Infinity in cloudflared state JSON 500'd
the status encoder; a huge login.pid OverflowError'd every poll.

Follow-up: ``is_file()`` EACCES on the brew log 500'd GET /api/cloudflared/logs;
a directory occupying login.url 500'd login poll/start; a file occupying
``~/.cloudflared`` 500'd POST /login (cwd); TOKEN_FILE EACCES 500'd status.

Follow-up 2: ``wg --version`` / ``wg show dump`` bytes 500'd GET /api/wireguard;
bytes ifconfig 500'd wstunnel status; leftover Infinity pid 500'd the ports
row; bytes ``ps`` lines 500'd GET /api/cloudflared/status; a file occupying
STATE_DIR 500'd POST /start-token; login.pid unlink EACCES 500'd every poll.

Follow-up 3: YAML leftover ``endpoint: 2026-08-19`` / ``!!binary`` / ``!!set``
leaked into GET /api/wireguard and GET /api/wireguard/settings (settings()
never went through ``_jsonable``).

Follow-up 4: ``_jsonable_state`` walked dict/list/float only, so leftover
``datetime.date`` / ``!!binary`` / ``!!set`` still leaked into
GET /api/cloudflared/status (``active_tunnel`` / ``mode``).
"""
from __future__ import annotations

import datetime
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import cloudflared_svc, wireguard_net_svc, wireguard_svc
from hub import wireguard_wstunnel as wst


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")

_REAL_EXISTS = Path.exists


def _wg_binaries_present(self: Path) -> bool:
    if str(self) in {
        wireguard_svc.WG,
        wireguard_svc.WG_QUICK,
        wireguard_svc.WIREGUARD_GO,
    }:
        return True
    return _REAL_EXISTS(self)


class WireGuardNonfiniteSettingsTests(unittest.TestCase):
    def test_inf_listen_port_mtu_fall_back_not_500(self):
        with mock.patch(
            "hub.wireguard_svc.settings_section",
            return_value={
                "listen_port": float("inf"),
                "mtu": float("-inf"),
                "keepalive": float("nan"),
            },
        ):
            cfg = wireguard_svc.settings()
        self.assertEqual(cfg["listen_port"], 51820)
        self.assertEqual(cfg["mtu"], 1280)
        self.assertEqual(cfg["keepalive"], 25)
        json.dumps(cfg, allow_nan=False)

    def test_inf_endpoint_and_dns_do_not_500_json(self):
        """Starlette allow_nan=False: leftover Infinity used to 500 GET /api/wireguard."""
        with mock.patch(
            "hub.wireguard_svc.settings_section",
            return_value={"endpoint": float("inf"), "dns": float("nan")},
        ):
            cfg = wireguard_svc.settings()
        json.dumps(cfg, allow_nan=False)
        self.assertEqual(cfg["endpoint"], "")
        self.assertEqual(cfg["dns"], "1.1.1.1, 8.8.8.8")

    def test_yaml_date_endpoint_and_wstunnel_do_not_500(self):
        """YAML ``endpoint: 2026-08-19`` used to 500 GET /api/wireguard/settings."""
        leftover = datetime.date(2026, 8, 19)
        with mock.patch(
            "hub.wireguard_svc.settings_section",
            return_value={
                "endpoint": leftover,
                "dns": leftover,
                "lan_cidr": leftover,
                "wan_interface": leftover,
                "wstunnel_enabled": leftover,
                "wstunnel_listen": leftover,
                "wstunnel_public": leftover,
                "wstunnel_restrict_to": leftover,
                "interface": leftover,
                "subnet": leftover,
            },
        ):
            cfg = wireguard_svc.settings()
        json.dumps(cfg, allow_nan=False)
        self.assertEqual(cfg["endpoint"], "")
        self.assertEqual(cfg["dns"], "1.1.1.1, 8.8.8.8")
        self.assertEqual(cfg["lan_cidr"], "")
        self.assertEqual(cfg["wan_interface"], "")
        self.assertIs(cfg["wstunnel_enabled"], False)
        self.assertEqual(cfg["wstunnel_listen"], wireguard_svc.DEFAULTS["wstunnel_listen"])
        self.assertEqual(cfg["wstunnel_public"], "")
        self.assertEqual(cfg["wstunnel_restrict_to"], "")
        self.assertEqual(cfg["interface"], "wg0")
        self.assertEqual(cfg["subnet"], "10.10.0.0/24")

    def test_yaml_binary_and_set_dns_do_not_500(self):
        """YAML ``!!binary`` / ``!!set`` used to leak into GET /api/wireguard."""
        with mock.patch(
            "hub.wireguard_svc.settings_section",
            return_value={
                "dns": b"1.1.1.1",
                "endpoint": {"vpn.example"},
                "wstunnel_enabled": b"yes",
            },
        ):
            cfg = wireguard_svc.settings()
        json.dumps(cfg, allow_nan=False)
        self.assertEqual(cfg["dns"], "1.1.1.1")
        self.assertEqual(cfg["endpoint"], "")
        self.assertIs(cfg["wstunnel_enabled"], False)

    def test_conf_int_inf_fallback_is_zero_not_500(self):
        self.assertEqual(wireguard_svc._conf_int("auto", float("inf")), 0)
        self.assertEqual(wireguard_svc._conf_int(float("inf"), 51820), 51820)

    def test_huge_rx_tx_does_not_500_human_bytes(self):
        """A leftover 400-digit ``rx`` OverflowError'd GET /api/wireguard."""
        self.assertEqual(wireguard_svc._human_bytes(10 ** 400), "0.0B")
        self.assertEqual(wireguard_svc._human_bytes(float("inf")), "0.0B")
        self.assertEqual(wireguard_svc._human_bytes(-1), "0.0B")
        self.assertEqual(wireguard_svc._human_bytes(1024), "1.0K")

    def test_save_settings_inf_port_is_coded_not_500(self):
        with (
            mock.patch(
                "hub.wireguard_svc.cfg",
                return_value={"settings": {"wireguard": {}}},
            ),
            mock.patch("hub.wireguard_svc.update_settings"),
            self.assertRaises(wireguard_svc.WireGuardError) as ctx,
        ):
            wireguard_svc.save_settings({"listen_port": float("inf")})
        self.assertEqual(ctx.exception.code, "wg.bad_number")


class WireGuardLastAddressSubnetTests(unittest.TestCase):
    def test_save_settings_rejects_a_subnet_with_no_host(self):
        with (
            mock.patch(
                "hub.wireguard_svc.cfg",
                return_value={"settings": {"wireguard": {}}},
            ),
            mock.patch("hub.wireguard_svc.update_settings"),
        ):
            for subnet in (
                "255.255.255.255/32",
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
            ):
                with self.subTest(subnet=subnet):
                    with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                        wireguard_svc.save_settings({"subnet": subnet})
                    self.assertEqual(ctx.exception.code, "wg.bad_subnet")

    def test_settings_falls_back_instead_of_500(self):
        with mock.patch(
            "hub.wireguard_svc.settings_section",
            return_value={"subnet": "255.255.255.255/32"},
        ):
            cfg = wireguard_svc.settings()
        self.assertEqual(cfg["subnet"], "10.10.0.0/24")
        json.dumps(cfg, allow_nan=False)

    def test_allocate_ip_is_coded_not_500(self):
        with mock.patch(
            "hub.wireguard_svc.settings",
            return_value={**wireguard_svc.DEFAULTS, "subnet": "255.255.255.255/32"},
        ):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.allocate_ip(set())
        self.assertEqual(ctx.exception.code, "wg.bad_subnet")


class WstunnelNonfiniteTests(unittest.TestCase):
    def test_inf_listen_port_does_not_500_status(self):
        with (
            mock.patch.object(
                wst,
                "live",
                return_value={
                    "listen": "",
                    "restrict_to": "",
                    "pid": float("inf"),
                    "running": False,
                    "binary": "",
                    "plist": "",
                },
            ),
            mock.patch.object(wst, "local_ipv4s", return_value=frozenset()),
        ):
            snap = wst.status({"listen_port": float("inf")})
        json.dumps(snap, allow_nan=False)
        self.assertEqual(snap["pid"], 0)
        self.assertIsInstance(snap["local_port"], int)

    def test_inf_local_port_is_empty_not_500(self):
        self.assertEqual(wst.local_endpoint(float("inf")), "")
        self.assertEqual(
            wst.client_command(
                public="ws://example:8444",
                restrict_to="127.0.0.1:51820",
                local_port=float("inf"),
            ),
            "",
        )


class CloudflaredNonfiniteStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_save_state_drops_leftover_inf(self):
        path = Path(self.tmp.name) / "state.json"
        with (
            mock.patch.object(cloudflared_svc, "STATE_FILE", path),
            mock.patch.object(cloudflared_svc, "_ensure_dirs"),
        ):
            cloudflared_svc._save_state({
                "tunnel_name": "home",
                "updated": float("inf"),
            })
        raw = json.loads(path.read_text())
        json.dumps(raw, allow_nan=False)
        self.assertEqual(raw["tunnel_name"], "home")
        self.assertIsNone(raw["updated"])

    def test_infinity_in_state_does_not_500_status(self):
        path = Path(self.tmp.name) / "state.json"
        path.write_text(
            '{"tunnel_name": Infinity, "mode": NaN, "updated": Infinity, "tunnel_id": -Infinity}'
        )
        with (
            mock.patch.object(cloudflared_svc, "STATE_FILE", path),
            mock.patch.object(cloudflared_svc, "_ensure_dirs"),
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=False),
            mock.patch.object(cloudflared_svc, "_is_running", return_value=False),
            mock.patch.object(cloudflared_svc, "_bin", side_effect=Exception("no")),
            mock.patch.object(cloudflared_svc, "_login_process_pending", return_value=False),
            mock.patch.object(cloudflared_svc, "LOGIN_URL_FILE") as urlfile,
        ):
            urlfile.is_file.return_value = False
            loaded = cloudflared_svc._load_state()
            snap = cloudflared_svc.status()
        self.assertIsNone(loaded.get("tunnel_name"))
        self.assertIsNone(loaded.get("mode"))
        json.dumps(snap, allow_nan=False)
        self.assertNotEqual(snap.get("active_tunnel"), float("inf"))

    def test_isoformat_inf_does_not_500_jsonable_state(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/cloudflared/status."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(cloudflared_svc._jsonable_state(_Stamp()))
        out = cloudflared_svc._jsonable_state({"tunnel_name": _Stamp(), "mode": "token"})
        json.dumps(out, allow_nan=False)
        _starlette(out)
        self.assertIsNone(out["tunnel_name"])
        self.assertEqual(out["mode"], "token")

    def test_yaml_date_bytes_and_set_do_not_500_jsonable_state(self):
        """Leftover YAML dates/!!binary/!!set used to leak into GET /api/cloudflared/status."""
        payload = {
            "tunnel_name": datetime.date(2026, 8, 19),
            "mode": b"token",
            "tags": {"ac", "usb"},
            "nested": {"when": datetime.datetime(2026, 8, 19, 12, 0, 0)},
        }
        out = cloudflared_svc._jsonable_state(payload)
        json.dumps(out, allow_nan=False)
        self.assertEqual(out["tunnel_name"], "2026-08-19")
        self.assertEqual(out["mode"], "token")
        self.assertCountEqual(out["tags"], ["ac", "usb"])
        self.assertTrue(out["nested"]["when"].startswith("2026-08-19"))

    def test_leftover_date_bytes_set_in_state_do_not_500_status(self):
        """GET /api/cloudflared/status used to 500 when state held YAML leftovers."""
        leftover = {
            "tunnel_name": datetime.date(2026, 8, 19),
            "mode": b"token",
            "tunnel_id": {"edge"},
        }
        with (
            mock.patch.object(cloudflared_svc, "_ensure_dirs"),
            mock.patch.object(cloudflared_svc, "_load_state", return_value=leftover),
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=False),
            mock.patch.object(cloudflared_svc, "_is_running", return_value=False),
            mock.patch.object(cloudflared_svc, "_bin", side_effect=Exception("no")),
            mock.patch.object(cloudflared_svc, "_login_process_pending", return_value=False),
            mock.patch.object(cloudflared_svc, "LOGIN_URL_FILE") as urlfile,
            mock.patch.object(cloudflared_svc, "_path_is_file", return_value=False),
        ):
            urlfile.is_file.return_value = False
            snap = cloudflared_svc.status()
        json.dumps(snap, allow_nan=False)
        self.assertEqual(snap["active_tunnel"], "2026-08-19")
        self.assertEqual(snap["mode"], "token")

    def test_save_state_coerces_date_bytes_and_set(self):
        """``_save_state`` used to TypeError-skip the write when leftovers were present."""
        path = Path(self.tmp.name) / "state.json"
        with (
            mock.patch.object(cloudflared_svc, "STATE_FILE", path),
            mock.patch.object(cloudflared_svc, "_ensure_dirs"),
        ):
            cloudflared_svc._save_state({
                "tunnel_name": datetime.date(2026, 8, 19),
                "mode": b"token",
                "tags": {"ac", "usb"},
            })
        raw = json.loads(path.read_text())
        json.dumps(raw, allow_nan=False)
        self.assertEqual(raw["tunnel_name"], "2026-08-19")
        self.assertEqual(raw["mode"], "token")
        self.assertCountEqual(raw["tags"], ["ac", "usb"])

    def test_leftover_date_tunnel_does_not_500_restart(self):
        """POST /api/cloudflared/restart used to leak leftover ``active_tunnel``."""
        leftover = {"tunnel_name": datetime.date(2026, 8, 19), "mode": b"token"}
        with (
            mock.patch.object(cloudflared_svc, "_load_state", return_value=leftover),
            mock.patch.object(cloudflared_svc, "_path_is_file", return_value=True),
            mock.patch.object(cloudflared_svc, "_write_launchagent_token"),
            mock.patch.object(
                cloudflared_svc, "_launchctl_bootstrap", return_value={"ok": True},
            ),
            mock.patch.object(cloudflared_svc, "_is_running", return_value=True),
            mock.patch.object(cloudflared_svc, "token_looks_valid", return_value=True),
            mock.patch.object(cloudflared_svc, "_read_saved_token", return_value="ok"),
        ):
            out = cloudflared_svc.restart()
        json.dumps(out, allow_nan=False)
        self.assertEqual(out["active_tunnel"], "2026-08-19")
        self.assertTrue(out["ok"])

    def test_junk_log_lines_is_clamped_not_500(self):
        for junk in ("nope", float("inf"), [120], float("nan")):
            with self.subTest(junk=junk):
                out = cloudflared_svc.logs(junk)
            self.assertTrue(out["ok"])
            self.assertIn("log", out)

    def test_surrogate_state_key_does_not_500(self):
        """Leftover ``\\ud800`` keys used to UTF-8 500 GET /api/cloudflared/status."""
        leftover = {"ok\ud800": "token\ud800", "tunnel_name": "home\ud800"}
        out = cloudflared_svc._jsonable_state(leftover)
        _starlette(out)
        blob = json.dumps(out, ensure_ascii=False)
        self.assertNotIn("\ud800", blob)
        self.assertEqual(out["tunnel_name"], "home?")

    def test_as_text_drops_surrogate(self):
        self.assertNotIn("\ud800", cloudflared_svc._as_text("err\ud800"))
        _starlette({"message": cloudflared_svc._as_text("err\ud800")})

    def test_home_dir_falls_back_when_unresolvable(self):
        """``Path.home()`` leftover used to 500 import of cloudflared_svc."""
        with mock.patch.object(cloudflared_svc, "user_home", return_value=None):
            self.assertEqual(
                cloudflared_svc._home_dir(),
                Path("/var/empty/serverhub-cloudflared"),
            )

    def test_probe_cf_bin_is_file_eio_falls_back(self):
        with mock.patch.object(Path, "is_file", side_effect=OSError(5, "I/O error")):
            self.assertEqual(
                cloudflared_svc._probe_cf_bin(), "/usr/local/bin/cloudflared"
            )

    def test_modern_bash_exists_eio_falls_back(self):
        with mock.patch.object(Path, "exists", side_effect=OSError(5, "I/O error")):
            self.assertEqual(wireguard_svc._modern_bash(), "/bin/bash")

    def test_registry_surrogate_key_save_does_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        path = tmp / "wireguard-peers.json"
        with mock.patch.object(wireguard_svc, "REGISTRY_PATH", path):
            wireguard_svc._save_registry({"peers": {"ok\ud800": {"name": "n\ud800"}}})
        raw = json.loads(path.read_text())
        _starlette(raw)
        self.assertNotIn("\ud800", path.read_text())


class CloudflaredHugeLoginPidTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pidfile = Path(self.tmp.name) / "login.pid"
        self._patch = mock.patch.object(cloudflared_svc, "LOGIN_PID", self.pidfile)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def test_overflow_pid_is_discarded_not_500(self):
        self.pidfile.write_text(str(2**31))
        self.assertIsNone(cloudflared_svc._read_login_pid())
        self.assertFalse(self.pidfile.exists())

        self.pidfile.write_text(str(10**18))
        self.assertFalse(cloudflared_svc._login_process_pending())
        self.assertTrue(cloudflared_svc._terminate_login_process())
        self.assertFalse(self.pidfile.exists())


class CloudflaredBytesAndDirsTests(unittest.TestCase):
    def test_bytes_launchctl_print_does_not_500(self):
        with mock.patch.object(
            cloudflared_svc, "sh", return_value=(0, b"state = running\n", "")
        ):
            self.assertTrue(cloudflared_svc._launchd_running())

    def test_bytes_tunnel_list_does_not_500(self):
        listing = (
            b"ID NAME CREATED CONNECTIONS\n"
            b"11111111-2222-3333-4444-555555555555 home 2026-01-01T00:00:00Z 1xSJC\n"
        )
        cloudflared_svc.invalidate_tunnels()
        self.addCleanup(cloudflared_svc.invalidate_tunnels)
        with (
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=True),
            mock.patch.object(cloudflared_svc, "_bin", return_value="/usr/bin/cloudflared"),
            mock.patch.object(cloudflared_svc, "sh", return_value=(0, listing, None)),
        ):
            tunnels = cloudflared_svc.list_tunnels(force=True)
        self.assertEqual(len(tunnels), 1)
        self.assertEqual(tunnels[0]["name"], "home")

    def test_ensure_dirs_file_collision_does_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        cf_home = tmp / "cf"
        cf_home.write_text("not-a-dir")
        with (
            mock.patch.object(cloudflared_svc, "CF_HOME", cf_home),
            mock.patch.object(cloudflared_svc, "STATE_DIR", tmp / "state"),
        ):
            cloudflared_svc._ensure_dirs()
        self.assertTrue((tmp / "state").is_dir())


class _FakeLoginProc:
    def __init__(self, text="Please visit https://dash.cloudflare.com/argotunnel\n"):
        self.pid = 4242
        self.stdout = io.StringIO(text)
        self.stderr = None

    def poll(self):
        return None


class CloudflaredLogsAndStatusIsFileTests(unittest.TestCase):
    def test_unreadable_brew_log_does_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        log = tmp / "tunnel.log"
        log.write_text("hello\n")
        orig = Path.is_file

        def maybe(self, *args, **kwargs):
            if "homebrew" in str(self):
                raise PermissionError("nope")
            return orig(self, *args, **kwargs)

        with (
            mock.patch.object(cloudflared_svc, "LOG_FILE", log),
            mock.patch.object(cloudflared_svc, "LOGIN_LOG", tmp / "login.log"),
            mock.patch.object(Path, "is_file", maybe),
        ):
            out = cloudflared_svc.logs(20)
        self.assertTrue(out["ok"])
        self.assertIn("hello", out["log"])
        json.dumps(out, allow_nan=False)

    def test_token_is_file_permissionerror_does_not_500_status(self):
        with (
            mock.patch.object(cloudflared_svc, "_ensure_dirs"),
            mock.patch.object(cloudflared_svc, "_load_state", return_value={}),
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=False),
            mock.patch.object(cloudflared_svc, "_is_running", return_value=False),
            mock.patch.object(cloudflared_svc, "_bin", side_effect=Exception("no")),
            mock.patch.object(cloudflared_svc, "_login_process_pending", return_value=False),
            mock.patch.object(cloudflared_svc, "LOGIN_URL_FILE") as urlfile,
            mock.patch.object(cloudflared_svc, "TOKEN_FILE") as token,
            mock.patch.object(cloudflared_svc, "CERT") as cert,
            mock.patch.object(cloudflared_svc, "PLIST") as plist,
            mock.patch.object(cloudflared_svc, "CONFIG_YML") as cfg,
        ):
            urlfile.is_file.side_effect = PermissionError("nope")
            token.is_file.side_effect = PermissionError("nope")
            cert.is_file.side_effect = PermissionError("nope")
            plist.is_file.side_effect = PermissionError("nope")
            cfg.is_file.side_effect = PermissionError("nope")
            snap = cloudflared_svc.status()
        self.assertTrue(snap["ok"])
        self.assertFalse(snap["has_token"])
        json.dumps(snap, allow_nan=False)

    def test_launch_env_home_runtimeerror_does_not_500(self):
        """``Path.home()`` RuntimeError used to 500 POST /api/cloudflared/start."""
        with mock.patch.object(Path, "home", side_effect=RuntimeError("HOME")):
            env = cloudflared_svc._launch_env()
        self.assertIn("PATH", env)
        self.assertNotIn("HOME", env)
        json.dumps(env, allow_nan=False)


class CloudflaredLoginFsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda: setattr(cloudflared_svc, "_login_proc", None))
        root = Path(self.tmp.name)
        self.state = root / "state"
        self.state.mkdir()
        self.cf_home = root / "cf"
        self.cf_home.mkdir()

    def _login_patches(self, **extra):
        patches = {
            "CF_HOME": self.cf_home,
            "STATE_DIR": self.state,
            "LOGIN_PID": self.state / "login.pid",
            "LOGIN_LOG": self.state / "login.log",
            "LOGIN_URL_FILE": self.state / "login.url",
            "_logged_in": mock.Mock(return_value=False),
            "_ensure_dirs": mock.Mock(),
            "_bin": mock.Mock(return_value="/usr/bin/true"),
            "_terminate_login_process": mock.Mock(return_value=True),
        }
        patches.update(extra)
        stack = [mock.patch.object(cloudflared_svc, name, value) for name, value in patches.items()]
        for p in stack:
            p.start()
            self.addCleanup(p.stop)

    def test_login_poll_url_directory_does_not_500(self):
        url = self.state / "login.url"
        url.mkdir()
        with (
            mock.patch.object(cloudflared_svc, "LOGIN_URL_FILE", url),
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=True),
            mock.patch.object(cloudflared_svc, "_terminate_login_process", return_value=True),
        ):
            out = cloudflared_svc.login_poll()
        self.assertTrue(out["logged_in"])
        self.assertTrue(url.is_dir())
        json.dumps(out, allow_nan=False)

    def test_login_start_url_directory_does_not_500(self):
        url = self.state / "login.url"
        url.mkdir()
        self._login_patches(LOGIN_URL_FILE=url)
        fake = _FakeLoginProc()
        with mock.patch("hub.cloudflared_svc.subprocess.Popen", return_value=fake):
            out = cloudflared_svc.login_start()
        self.assertTrue(out["ok"])
        self.assertIn("https://", out["login_url"])
        json.dumps(out, allow_nan=False)

    def test_login_start_cf_home_file_does_not_500(self):
        cf_home = Path(self.tmp.name) / "cf-file"
        cf_home.write_text("not-a-dir")
        self._login_patches(CF_HOME=cf_home)
        fake = _FakeLoginProc()
        with mock.patch("hub.cloudflared_svc.subprocess.Popen", return_value=fake) as popen:
            out = cloudflared_svc.login_start()
        self.assertTrue(out["ok"])
        self.assertIsNone(popen.call_args.kwargs.get("cwd"))
        json.dumps(out, allow_nan=False)

    def test_login_start_does_not_follow_pid_or_log_symlinks(self):
        """``Path.write_text`` followed a planted LOGIN_PID / LOGIN_LOG symlink
        and O_TRUNCed the target.  LOGIN_URL already used replace_secret_text."""
        pid_victim = Path(self.tmp.name) / "pid-victim"
        log_victim = Path(self.tmp.name) / "log-victim"
        pid_victim.write_text("keep-pid")
        log_victim.write_text("keep-log")
        pid = self.state / "login.pid"
        log = self.state / "login.log"
        pid.symlink_to(pid_victim)
        log.symlink_to(log_victim)
        self._login_patches(LOGIN_PID=pid, LOGIN_LOG=log)
        fake = _FakeLoginProc()
        with mock.patch("hub.cloudflared_svc.subprocess.Popen", return_value=fake):
            out = cloudflared_svc.login_start()
        self.assertTrue(out["ok"])
        self.assertEqual(pid_victim.read_text(), "keep-pid")
        self.assertEqual(log_victim.read_text(), "keep-log")
        json.dumps(out, allow_nan=False)

    def test_login_start_missing_binary_is_false_not_500(self):
        self._login_patches(_bin=mock.Mock(return_value="/no/such/cloudflared-bin"))
        out = cloudflared_svc.login_start()
        self.assertFalse(out["ok"])
        self.assertIn("Could not start", out["message"])
        json.dumps(out, allow_nan=False)

    def test_login_start_surrogate_env_is_not_500(self):
        """Leftover ``\\ud800`` in os.environ UnicodeEncodeError'd POST /login."""
        self._login_patches()
        fake = _FakeLoginProc()
        leftover_env = {"PATH": "/usr/bin:/bin", "LEFTOVER": "x\ud800"}
        with (
            mock.patch.object(cloudflared_svc.os, "environ", leftover_env),
            mock.patch("hub.cloudflared_svc.subprocess.Popen", return_value=fake) as popen,
        ):
            out = cloudflared_svc.login_start()
        self.assertTrue(out["ok"])
        env = popen.call_args.kwargs.get("env") or {}
        self.assertNotIn("LEFTOVER", env)
        json.dumps(out, allow_nan=False)

    def test_login_start_popen_unicodeencode_is_false_not_500(self):
        self._login_patches()
        with mock.patch(
            "hub.cloudflared_svc.subprocess.Popen",
            side_effect=UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed"),
        ):
            out = cloudflared_svc.login_start()
        self.assertFalse(out["ok"])
        json.dumps(out, allow_nan=False)

    def test_login_start_undecodable_stdout_does_not_500(self):
        class Boom:
            def readline(self, _size=-1):
                raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")

            def close(self):
                pass

        class Proc:
            pid = 7
            stdout = Boom()
            stderr = None

            def poll(self):
                return None

        self._login_patches()
        with mock.patch("hub.cloudflared_svc.subprocess.Popen", return_value=Proc()):
            out = cloudflared_svc.login_start()
        self.assertFalse(out["ok"])
        self.assertTrue(out.get("login_pending"))
        json.dumps(out, allow_nan=False)

    def test_login_start_huge_stdout_line_does_not_oom(self):
        """Unbounded ``readline()`` of leftover junk used to RSS-bomb POST /login."""
        calls = {"n": 0}

        class Huge:
            def readline(self, size=-1):
                calls["n"] += 1
                cap = size if size and size > 0 else 4096
                if calls["n"] == 1:
                    return "x" * cap
                if calls["n"] == 2:
                    return "rest-of-huge-line\n"
                if calls["n"] == 3:
                    return "Please open https://dash.cloudflare.com/login\n"
                return ""

            def close(self):
                pass

        class Proc:
            pid = 7
            stdout = Huge()
            stderr = None

            def poll(self):
                return None

        self._login_patches()
        with mock.patch("hub.cloudflared_svc.subprocess.Popen", return_value=Proc()):
            out = cloudflared_svc.login_start()
        json.dumps(out, allow_nan=False)
        url = out.get("login_url") or ""
        self.assertIn("https://dash.cloudflare.com/login", url)
        self.assertLess(calls["n"], 20)


class WireGuardPingTimeoutTests(unittest.TestCase):
    def test_junk_timeout_does_not_500(self):
        with mock.patch.object(wireguard_svc, "peer_records", return_value=[]):
            for junk in ("nope", float("inf"), [800]):
                out = wireguard_svc.ping_peers(junk)
                self.assertTrue(out["ok"])
                self.assertEqual(out["results"], [])


class WireGuardBytesDumpAndVersionTests(unittest.TestCase):
    def test_exists_eio_does_not_500_installation(self):
        with mock.patch.object(Path, "exists", side_effect=OSError(5, "I/O error")):
            info = wireguard_svc.installation()
        self.assertFalse(info["installed"])
        json.dumps(info, allow_nan=False)

    def test_bytes_wg_version_does_not_500_installation(self):
        with (
            mock.patch.object(wireguard_svc.Path, "exists", _wg_binaries_present),
            mock.patch.object(
                wireguard_svc, "sh", return_value=(0, b"wireguard-tools v1.0\n", b"")
            ),
            mock.patch.object(
                wireguard_svc, "conf_path",
                return_value=Path("/tmp/wg0-leftover-nope.conf"),
            ),
        ):
            info = wireguard_svc.installation()
        self.assertEqual(info["tools_version"], "wireguard-tools v1.0")
        self.assertIsInstance(info["tools_version"], str)
        json.dumps(info, allow_nan=False)

    def test_bytes_and_none_dump_do_not_500_status(self):
        dump = b"priv\tpPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0=\t51820\toff\n"
        with (
            mock.patch.object(
                wireguard_svc, "settings", return_value={**wireguard_svc.DEFAULTS}
            ),
            mock.patch.object(
                wireguard_svc, "installation", return_value={"installed": True}
            ),
            mock.patch.object(wireguard_svc, "peer_records", return_value=[]),
            mock.patch.object(
                wireguard_svc, "read_conf",
                return_value={"interface": {}, "peers": []},
            ),
            mock.patch.object(wireguard_svc, "wstunnel_status", return_value={}),
            mock.patch.object(wireguard_svc, "real_interface", return_value="utun8"),
            mock.patch.object(wireguard_svc, "sh", return_value=(0, dump, "")),
            mock.patch.object(wireguard_svc, "sudo_capture", return_value=(0, dump, "")),
        ):
            snap = wireguard_svc.status()
        json.dumps(snap, allow_nan=False)
        self.assertEqual(snap["listen_port"], 51820)

        with (
            mock.patch.object(wireguard_svc, "sh", return_value=(0, None, "")),
            mock.patch.object(wireguard_svc, "sudo_capture", return_value=(0, None, "")),
        ):
            grouped, _err = wireguard_svc._dump_all()
        self.assertEqual(grouped, {})

    def test_bytes_ping_and_interface_action_do_not_500(self):
        with (
            mock.patch.object(
                wireguard_svc, "peer_records",
                return_value=[{"public_key": "p", "name": "n", "ip": "10.10.0.2/32"}],
            ),
            mock.patch.object(
                wireguard_svc, "sh", return_value=(0, b"64 bytes time=1.2 ms\n", "")
            ),
        ):
            out = wireguard_svc.ping_peers(200)
        json.dumps(out, allow_nan=False)
        self.assertTrue(out["results"][0]["reachable"])
        self.assertEqual(out["results"][0]["latency_ms"], 1.2)

        tmp = Path(tempfile.mkdtemp()) / "wg0.conf"
        tmp.write_text("[Interface]\nPrivateKey = k\n")
        with (
            mock.patch.object(wireguard_svc, "conf_path", return_value=tmp),
            mock.patch.object(
                wireguard_svc, "settings", return_value={**wireguard_svc.DEFAULTS}
            ),
            mock.patch.object(
                wireguard_svc, "runtime_state",
                return_value={"stale": False, "live": False, "name_file": "x"},
            ),
            mock.patch.object(wireguard_svc, "sh", return_value=(1, b"out", b"err")),
            mock.patch.object(wireguard_svc, "sudo_refused", return_value=False),
        ):
            action = wireguard_svc.interface_action("up")
        json.dumps(action, allow_nan=False)
        self.assertFalse(action["ok"])

    def test_apply_live_none_err_and_batch_inf_do_not_500(self):
        tmp = Path(tempfile.mkdtemp()) / "wg0.conf"
        tmp.write_text("[Interface]\nPrivateKey = k\n")
        with (
            mock.patch.object(
                wireguard_svc, "settings", return_value={**wireguard_svc.DEFAULTS}
            ),
            mock.patch.object(
                wireguard_svc, "live_interface", return_value=("utun8", [], "")
            ),
            mock.patch.object(wireguard_svc, "conf_path", return_value=tmp),
            mock.patch("hub.wireguard_svc.replace_secret_text"),
            mock.patch.object(wireguard_svc, "sh", return_value=(1, "", None)),
            mock.patch.object(wireguard_svc, "run_admin", return_value={"ok": False}),
        ):
            out = wireguard_svc.apply_live()
        json.dumps(out, allow_nan=False)
        self.assertFalse(out["ok"])
        self.assertEqual(out["detail"], "")

        with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
            wireguard_svc.batch_add(count=float("inf"))
        self.assertEqual(ctx.exception.code, "wg.bad_count")


class WstunnelBytesAndInfPidTests(unittest.TestCase):
    def test_bytes_ifconfig_does_not_500_status(self):
        wst.local_ipv4s.invalidate()
        with (
            mock.patch.object(
                wst, "live",
                return_value={
                    "listen": "", "restrict_to": "", "pid": 0,
                    "running": False, "binary": "", "plist": "",
                },
            ),
            mock.patch.object(
                wst, "sh",
                return_value=(0, b"\tinet 192.0.2.10 netmask 0xffffff00\n", ""),
            ),
        ):
            snap = wst.status({"listen_port": 51820})
        json.dumps(snap, allow_nan=False)

    def test_bytes_ps_table_does_not_500_live(self):
        wst.live.invalidate()
        found = wst.parse_process_table(
            b"80722 /opt/homebrew/bin/wstunnel server "
            b"--restrict-to 127.0.0.1:51820 ws://0.0.0.0:8444\n"
        )
        self.assertTrue(found["running"])
        self.assertEqual(found["pid"], 80722)
        json.dumps(found, allow_nan=False)

    def test_inf_pid_listener_row_does_not_500(self):
        row = wst.listener_row({
            "listen": "ws://0.0.0.0:8444",
            "port": 8444,
            "pid": float("inf"),
        })
        json.dumps(row, allow_nan=False)
        self.assertEqual(row["pid"], "")

    def test_leftover_inf_pid_ps_row_does_not_500(self):
        found = wst.parse_process_table(
            "Infinity /opt/homebrew/bin/wstunnel server "
            "--restrict-to 127.0.0.1:51820 ws://0.0.0.0:8444\n"
        )
        self.assertFalse(found.get("running"))
        json.dumps(found, allow_nan=False)

    def test_recursing_ps_table_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        found = wst.parse_process_table(Recursing())
        json.dumps(found, allow_nan=False)
        self.assertFalse(found.get("running"))


class CloudflaredBytesPsAndFsTests(unittest.TestCase):
    def test_bytes_ps_lines_do_not_500_status(self):
        with (
            mock.patch.object(cloudflared_svc, "_ensure_dirs"),
            mock.patch.object(cloudflared_svc, "_load_state", return_value={}),
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=False),
            mock.patch.object(cloudflared_svc, "_bin", side_effect=Exception("no")),
            mock.patch.object(
                cloudflared_svc, "_login_process_pending", return_value=False
            ),
            mock.patch.object(cloudflared_svc, "_launchd_running", return_value=False),
            mock.patch.object(cloudflared_svc, "_path_is_file", return_value=False),
            mock.patch(
                "hub.cloudflared_svc.ps_lines",
                return_value=(
                    b"USER PID COMMAND",
                    b"me 1 cloudflared tunnel run --token-file /x",
                ),
            ),
        ):
            snap = cloudflared_svc.status()
        self.assertTrue(snap["running"])
        json.dumps(snap, allow_nan=False)

    def test_start_token_state_dir_file_is_coded_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        state_dir = tmp / "state"
        state_dir.write_text("not-a-dir")
        with (
            mock.patch.object(cloudflared_svc, "STATE_DIR", state_dir),
            mock.patch.object(cloudflared_svc, "STATE_FILE", state_dir / "s.json"),
            mock.patch.object(cloudflared_svc, "TOKEN_FILE", state_dir / "tunnel.token"),
            mock.patch.object(cloudflared_svc, "CF_HOME", tmp / "cf"),
        ):
            (tmp / "cf").mkdir()
            with self.assertRaises(HTTPException) as ctx:
                cloudflared_svc.start_with_token(
                    "eyJhIjoiYWNjdGFjY3RhY2N0YWNjdGFjY3RhY2N0YWNjdGFjY3QiLCJzIjoic2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0IiwidCI6IjAxMjM0NTY3LTg5YWItY2RlZi0wMTIzLTQ1Njc4OWFiY2RlZiJ9"
                )
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.no_token")

    def test_save_state_file_collision_does_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        state = tmp / "state"
        state.mkdir()
        sf = state / "serverhub-state.json"
        sf.mkdir()
        with (
            mock.patch.object(cloudflared_svc, "STATE_DIR", state),
            mock.patch.object(cloudflared_svc, "STATE_FILE", sf),
            mock.patch.object(cloudflared_svc, "CF_HOME", tmp / "cf"),
        ):
            (tmp / "cf").mkdir()
            cloudflared_svc._save_state({"mode": "token"})
        self.assertTrue(sf.is_dir())

    def test_login_pid_unlink_permissionerror_does_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        pidfile = tmp / "login.pid"
        pidfile.write_text("nope")
        orig = Path.unlink

        def boom(self, *args, **kwargs):
            if Path(self) == pidfile:
                raise PermissionError("nope")
            return orig(self, *args, **kwargs)

        with (
            mock.patch.object(cloudflared_svc, "LOGIN_PID", pidfile),
            mock.patch.object(Path, "unlink", boom),
        ):
            self.assertIsNone(cloudflared_svc._read_login_pid())
            self.assertFalse(cloudflared_svc._login_process_pending())

    def test_login_poll_is_file_valueerror_does_not_500(self):
        url = mock.Mock()
        url.is_file.side_effect = ValueError("nul")
        url.read_text.side_effect = ValueError("nul")
        with (
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=False),
            mock.patch.object(
                cloudflared_svc, "_login_process_pending", return_value=False
            ),
            mock.patch.object(cloudflared_svc, "LOGIN_URL_FILE", url),
        ):
            out = cloudflared_svc.login_poll()
        self.assertFalse(out["logged_in"])
        json.dumps(out, allow_nan=False)


class WireGuardHugeFileTests(unittest.TestCase):
    """``read_text()`` of leftover multi-MB key/conf used to OOM GET /api/wireguard."""

    def test_huge_conf_does_not_oom_read_or_view(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        path = tmp / "wg0.conf"
        path.write_bytes(b"x" * (2 * 1024 * 1024))
        with mock.patch.object(wireguard_svc, "conf_path", return_value=path):
            parsed = wireguard_svc.read_conf()
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.view_conf()
        self.assertEqual(parsed, {"interface": {}, "peers": []})
        self.assertEqual(ctx.exception.code, "wg.no_conf")

    def test_huge_privatekey_does_not_oom_identity(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        (tmp / "privatekey").write_bytes(b"k" * (2 * 1024 * 1024))
        priv = "aFakeServerPrivateKeyValueForTests0000000000="
        pub = "sPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0="
        with (
            mock.patch.object(
                wireguard_svc, "read_conf", return_value={"interface": {}, "peers": []}
            ),
            mock.patch.object(wireguard_svc, "conf_dir", return_value=tmp),
            mock.patch.object(
                wireguard_svc, "settings", return_value={**wireguard_svc.DEFAULTS}
            ),
            mock.patch.object(
                wireguard_svc, "generate_keypair", return_value=(priv, pub)
            ),
            mock.patch.object(wireguard_svc, "public_from_private", return_value=pub),
        ):
            ident = wireguard_svc.server_identity()
        json.dumps(ident, allow_nan=False)
        self.assertEqual(ident["private_key"], priv)

    def test_huge_conf_apply_live_is_unreadable_not_500(self):
        tmp = Path(tempfile.mkdtemp()) / "wg0.conf"
        tmp.write_bytes(b"x" * (2 * 1024 * 1024))
        with (
            mock.patch.object(
                wireguard_svc, "settings", return_value={**wireguard_svc.DEFAULTS}
            ),
            mock.patch.object(
                wireguard_svc, "live_interface", return_value=("utun8", [], "")
            ),
            mock.patch.object(wireguard_svc, "conf_path", return_value=tmp),
        ):
            out = wireguard_svc.apply_live()
        json.dumps(out, allow_nan=False)
        self.assertEqual(out, {"ok": False, "error": "conf_unreadable"})


class PfConfCapTests(unittest.TestCase):
    def test_huge_pf_conf_does_not_oom_nat_installed(self):
        """``read_text()`` of leftover multi-MB /etc/pf.conf used to OOM GET /api/wireguard."""
        tmp = Path(tempfile.mkdtemp())
        conf = tmp / "pf.conf"
        conf.write_bytes(b"x" * (2 * 1024 * 1024))
        with (
            mock.patch.object(wireguard_net_svc, "PF_CONF", conf),
            mock.patch.object(wireguard_net_svc, "PF_ANCHOR_PATH", tmp / "missing"),
            mock.patch.object(wireguard_net_svc, "nat_active", return_value=False),
            mock.patch.object(
                wireguard_net_svc, "pf_conf_valid",
                return_value={"ok": True, "message": ""},
            ),
        ):
            out = wireguard_net_svc.nat_installed()
        json.dumps(out, allow_nan=False)
        self.assertFalse(out["referenced"])
        self.assertFalse(out["anchor_exists"])

    def test_huge_daemon_plist_does_not_oom_daemon_state(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "com.wireguard.wg0.plist").write_bytes(b"x" * (2 * 1024 * 1024))
        with (
            mock.patch.object(wireguard_net_svc, "LAUNCH_DAEMON_DIR", tmp),
            mock.patch.object(
                wireguard_svc, "settings",
                return_value={**wireguard_svc.DEFAULTS, "interface": "wg0"},
            ),
            mock.patch.object(wireguard_net_svc, "sh", return_value=(1, "", "")),
            mock.patch.object(
                wireguard_net_svc, "sudo_capture", return_value=(1, "", ""),
            ),
            mock.patch.object(wireguard_net_svc, "loaded_labels", return_value=frozenset()),
        ):
            out = wireguard_net_svc.daemon_state()
        json.dumps(out, allow_nan=False)
        self.assertTrue(out["installed"])
        self.assertEqual(out["defects"], ["unreadable"])


class WireGuardPubkeyLeftoverTests(unittest.TestCase):
    def test_ud800_argv_does_not_500_pubkey(self):
        """subprocess.run leftover ``\\ud800`` argv UnicodeEncodeError used to 500 peer create."""
        with mock.patch.object(
            wireguard_svc.subprocess, "run", side_effect=ValueError("surrogate"),
        ):
            self.assertEqual(wireguard_svc._run_with_input(["wg", "pubkey"], "x"), "")


class WireGuardClockLeftoverTests(unittest.TestCase):
    def test_infinite_clock_does_not_raise(self):
        """int(time.time()) OverflowError on leftover inf used to 500 GET /api/wireguard."""
        with mock.patch.object(wireguard_svc.time, "time", return_value=float("inf")):
            self.assertEqual(wireguard_svc._now(), 0)

    def test_overflow_strftime_does_not_500_status_ts(self):
        """Leftover inf clock OverflowError'd GET /api/wireguard ``ts``."""
        from hub.util import strftime_now

        with mock.patch("hub.util.time.strftime", side_effect=OverflowError):
            self.assertEqual(strftime_now("%Y-%m-%d %H:%M:%S"), "")


class CloudflaredTunnelListExcDetailTests(unittest.TestCase):
    def test_recursing_list_tunnels_does_not_500_status(self):
        """str(e) RecursionError used to 500 GET /api/cloudflared/status."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with mock.patch.object(cloudflared_svc, "_as_text", wraps=cloudflared_svc._as_text):
            self.assertEqual(cloudflared_svc._as_text(Recursing()), "Recursing")
        json.dumps({"error": cloudflared_svc._as_text(Recursing())}, ensure_ascii=False).encode("utf-8")

    def test_recursing_login_popen_does_not_500(self):
        """leftover ``{e}`` RecursionError used to 500 POST /api/cloudflared/login."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        # login_start clears LOGIN_URL_FILE / LOGIN_LOG before spawning; left
        # unpatched it created a real ~/Services/cloudflared/login.log on the
        # host running the suite.
        root = Path(tempfile.mkdtemp(prefix="cf-login-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with (
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=False),
            mock.patch.object(cloudflared_svc, "_ensure_dirs"),
            mock.patch.object(cloudflared_svc, "LOGIN_PID", root / "login.pid"),
            mock.patch.object(cloudflared_svc, "LOGIN_LOG", root / "login.log"),
            mock.patch.object(cloudflared_svc, "LOGIN_URL_FILE", root / "login.url"),
            mock.patch.object(cloudflared_svc, "_bin", return_value="/opt/homebrew/bin/cloudflared"),
            mock.patch.object(cloudflared_svc, "_terminate_login_process", return_value=True),
            mock.patch.object(cloudflared_svc.subprocess, "Popen", side_effect=Recursing()),
        ):
            out = cloudflared_svc.login_start()
        _starlette(out)
        self.assertFalse(out["ok"])
        self.assertIn("Recursing", out["message"])

    def test_recursing_log_tail_does_not_500(self):
        """leftover ``{e}`` RecursionError used to 500 GET /api/cloudflared/logs."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with (
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(
                cloudflared_svc, "tail_file_lines", side_effect=Recursing(),
            ),
        ):
            out = cloudflared_svc.logs(40)
        _starlette(out)
        self.assertTrue(out["ok"])
        self.assertIn("read error", out["log"])
        self.assertIn("Recursing", out["log"])


class WireGuardAsTextRecursionLeftoverTests(unittest.TestCase):
    def test_wireguard_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(wireguard_svc._as_text(Recursing()), "Recursing")
        _starlette({"message": wireguard_svc._as_text(Recursing())})

    def test_wireguard_net_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(wireguard_net_svc._as_text(Recursing()), "Recursing")
        _starlette({"message": wireguard_net_svc._as_text(Recursing())})


if __name__ == "__main__":
    unittest.main()
