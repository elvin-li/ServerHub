"""Callers that used to slurp a whole log just to show a tail."""
from __future__ import annotations

import errno
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import (
    actions,
    adaptive,
    alerts,
    api_keys,
    apps_manage_svc,
    assistant_svc,
    audit,
    auth,
    autostart_svc,
    backups,
    brew_cache,
    catalog,
    catalog_remote,
    cloudflared_svc,
    compose_svc,
    config,
    containers_svc,
    files_svc,
    health_svc,
    immich_svc,
    logs_svc,
    metrics_rollup,
    nfs_svc,
    notify_channels,
    ollama_svc,
    photoshub_svc,
    scheduler_svc,
    service_credentials,
    services_manage_svc,
    services_uninstall_svc,
    smart_test_svc,
    stale_runtime,
    terminal_svc,
    tools_svc,
    twofa_svc,
    ups_policy,
    wireguard_net_svc,
    wireguard_svc,
    wireguard_wstunnel,
)
from hub.discovery import launchd
from hub.util import read_bytes_capped, read_text_capped, tail_file_lines


class TailFileLinesTests(unittest.TestCase):
    def test_returns_the_last_n_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log.txt"
            path.write_text("a\nb\nc\nd\n")
            self.assertEqual(tail_file_lines(path, 2), ["c", "d"])

    def test_drops_a_torn_first_row_after_a_mid_file_seek(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log.txt"
            path.write_bytes(b"OLD\n" + b"x" * 4000 + b"\nTAIL\n")
            lines = tail_file_lines(path, 2, max_bytes=16)
            self.assertEqual(lines[-1], "TAIL")
            self.assertNotIn("OLD", lines)

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.txt"
            path.write_bytes(b"")
            self.assertEqual(tail_file_lines(path, 10), [])


class ReadTextCappedTests(unittest.TestCase):
    def test_returns_a_small_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ok.txt"
            path.write_text("hello\n")
            self.assertEqual(read_text_capped(path, 64), "hello\n")

    def test_exact_cap_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exact.txt"
            path.write_text("abcd")
            self.assertEqual(read_text_capped(path, 4), "abcd")

    def test_leftover_multi_mb_file_raises_efbig(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "huge.txt"
            path.write_bytes(b"x" * (2 * 1024 * 1024))
            with self.assertRaises(OSError) as ctx:
                read_text_capped(path, 256)
        self.assertEqual(ctx.exception.errno, errno.EFBIG)

    def test_leftover_surrogate_name_is_oserror_not_500(self):
        """``Path.open`` UnicodeEncodeError used to 500 OSError-only callers."""
        with mock.patch.object(Path, "open", side_effect=UnicodeEncodeError(
            "utf-8", "\ud800", 0, 1, "surrogates not allowed",
        )):
            with self.assertRaises(OSError) as ctx:
                read_text_capped(Path("/tmp/leftover"), 64)
        self.assertEqual(ctx.exception.errno, errno.EINVAL)

    def test_leftover_nul_name_is_oserror_not_500(self):
        with self.assertRaises(OSError) as ctx:
            read_text_capped("/tmp/foo\x00.log", 64)
        self.assertEqual(ctx.exception.errno, errno.EINVAL)


class ReadBytesCappedTests(unittest.TestCase):
    def test_returns_a_small_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ok.bin"
            path.write_bytes(b"hello\n")
            self.assertEqual(read_bytes_capped(path, 64), b"hello\n")

    def test_exact_cap_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exact.bin"
            path.write_bytes(b"abcd")
            self.assertEqual(read_bytes_capped(path, 4), b"abcd")

    def test_leftover_multi_mb_file_raises_efbig(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "huge.bin"
            path.write_bytes(b"x" * (2 * 1024 * 1024))
            with self.assertRaises(OSError) as ctx:
                read_bytes_capped(path, 256)
        self.assertEqual(ctx.exception.errno, errno.EFBIG)


class CallSiteContractTests(unittest.TestCase):
    """A helper nobody calls is not a fix."""

    def test_log_tails_go_through_the_capped_reader(self):
        sites = {
            cloudflared_svc: "def logs",
            apps_manage_svc: "def _native_logs",
            tools_svc: "def _syslog_tail_uncached",
            terminal_svc: "def recent_audit",
            services_manage_svc: "def _tail_file",
            logs_svc: "def tail_log",
            audit: "def recent",
            scheduler_svc: "def _journal_lines",
            alerts: "def list_alerts",
        }
        for module, marker in sites.items():
            source = Path(module.__file__).read_text()
            self.assertIn(
                "tail_file_lines",
                source,
                f"{module.__name__} stopped using tail_file_lines",
            )
            self.assertIn(marker, source)

    def test_wireguard_registry_writes_atomically(self):
        from hub import wireguard_svc
        source = Path(wireguard_svc.__file__).read_text()
        body = source[source.index("def _save_registry"): source.index("\ndef ", source.index("def _save_registry") + 10)]
        self.assertIn("replace_secret_text", body)
        self.assertNotIn("write_secret_text", body)

    def test_wireguard_live_conf_writes_atomically(self):
        from hub import wireguard_svc
        source = Path(wireguard_svc.__file__).read_text()
        start = source.index("def _write_conf")
        body = source[start: source.index("\ndef ", start + 10)]
        self.assertIn("replace_secret_text(path, body)", body)
        self.assertNotIn("write_secret_text(path,", body)

    def test_wireguard_sync_stage_is_atomic(self):
        from hub import wireguard_svc
        source = Path(wireguard_svc.__file__).read_text()
        self.assertIn("replace_secret_text(staged, stripped)", source)
        self.assertNotIn("write_secret_text(staged, stripped)", source)

    def test_nfs_stage_is_atomic(self):
        from hub import nfs_svc
        source = Path(nfs_svc.__file__).read_text()
        self.assertIn("replace_secret_text(_STAGE_PATH, body)", source)
        self.assertNotIn("write_secret_text(_STAGE_PATH", source)

    def test_metrics_history_tails(self):
        from hub import metrics
        source = Path(metrics.__file__).read_text()
        start = source.index("def history")
        body = source[start: source.index("\ndef ", start + 10)]
        self.assertIn("tail_file_lines", body)
        self.assertNotIn("read_text(errors=\"replace\").splitlines()", body)

    def test_rsync_preview_caps_lines(self):
        from hub import rsync_svc
        source = Path(rsync_svc.__file__).read_text()
        self.assertIn("iter_capped_lines", source)

    def test_request_path_state_reads_go_through_the_capped_reader(self):
        """A helper nobody calls is not a fix."""
        sites = {
            wireguard_svc: (
                "def read_conf",
                "def server_identity",
                "def _load_registry",
                "def view_conf",
            ),
            nfs_svc: ("def read_exports",),
            compose_svc: ("def get_compose", "def save_compose"),
            ups_policy: ("def _load_state",),
            api_keys: ("def _load",),
            twofa_svc: ("def _load",),
            brew_cache: ("def _read_disk_file",),
            catalog_remote: ("def _load_state",),
            backups: ("def _pg_password", "def _json_object", "def _immich_conn"),
            wireguard_net_svc: ("def nat_installed", "def daemon_state"),
            alerts: ("def _load_state",),
            notify_channels: ("def _load_secrets",),
            smart_test_svc: ("def _load_history",),
            containers_svc: ("def _load_update_status",),
            service_credentials: ("def _load",),
            photoshub_svc: ("def _load_json",),
            cloudflared_svc: ("def _load_state",),
            assistant_svc: ("def _load_json",),
            immich_svc: ("def run_checks",),
            metrics_rollup: ("def _load_state_locked",),
            config: ("def _read_disk", "def cfg"),
            catalog: ("def _parse_template",),
            adaptive: ("def nginx_sites",),
            auth: ("def _persistent_token",),
        }
        for module, markers in sites.items():
            source = Path(module.__file__).read_text()
            self.assertIn(
                "read_text_capped",
                source,
                f"{module.__name__} stopped using read_text_capped",
            )
            for marker in markers:
                self.assertIn(marker, source, f"{module.__name__} lost {marker}")

    def test_request_path_plist_reads_go_through_the_capped_reader(self):
        """A helper nobody calls is not a fix."""
        sites = {
            files_svc: ("def _plist_keepalive", "def set_filebrowser_ondemand"),
            services_manage_svc: ("def _plist_dict", "def _load_plist"),
            autostart_svc: ("def _read_plist",),
            actions: ("def _plist_dict", "def registry"),
            launchd: ("def discover_launchd",),
            health_svc: ("def _collect_checks",),
            tools_svc: ("def launchd_timers", "def launchd_agents_summary"),
            ollama_svc: ("def _plist_label_if_ollama",),
            stale_runtime: ("def scan",),
            services_uninstall_svc: ("def _agent_paths", "def preview"),
            wireguard_wstunnel: ("def read_plist",),
        }
        for module, markers in sites.items():
            source = Path(module.__file__).read_text()
            self.assertIn(
                "read_bytes_capped",
                source,
                f"{module.__name__} stopped using read_bytes_capped",
            )
            for marker in markers:
                self.assertIn(marker, source, f"{module.__name__} lost {marker}")

    def test_terminal_audit_rotation_is_capped_and_atomic(self):
        source = Path(terminal_svc.__file__).read_text()
        body = source[source.index("def _audit"): source.index("\ndef _reap_group")]
        self.assertIn("tail_file_lines", body)
        self.assertIn("replace_secret_text", body)
        self.assertNotIn("write_secret_text(", body)

    def test_auth_audit_trim_is_capped_and_atomic(self):
        source = Path(audit.__file__).read_text()
        body = source[source.index("def _trim"): source.index("\ndef record")]
        self.assertIn("tail_file_lines", body)
        self.assertIn("replace_secret_text", body)
        self.assertNotIn("write_secret_text(", body)
