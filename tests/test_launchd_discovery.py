from __future__ import annotations

import plistlib
import socket
import sys
import tempfile
import threading
import time
import unittest
from contextlib import nullcontext
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

from hub.discovery import launchd

# Ubuntu CI has no /bin/zsh; a present path keeps a running pid in state ok.
_PRESENT_EXE = "/bin/sh" if Path("/bin/sh").exists() else sys.executable


class LaunchdDiscoveryTests(unittest.TestCase):
    def setUp(self):
        launchd._http_misses.clear()
        self.addCleanup(launchd._http_misses.clear)

    def _discover(
        self,
        arguments: list[str],
        table_value: tuple[str, str] | None,
        hide: bool = False,
        group: str = "Native",
        override: dict | None = None,
        pid_exe: str | None = _PRESENT_EXE,
        http_alive: bool = True,
        port_reachable: bool = True,
        orphan_pids: list[int] | None = None,
        probe_orphans: bool = False,
        **extra,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            label = "com.example.service"
            payload = {
                "Label": label,
                "ProgramArguments": arguments,
                "RunAtLoad": True,
                **extra,
            }
            path = Path(tmp) / f"{label}.plist"
            path.write_bytes(plistlib.dumps(payload))
            table = {} if table_value is None else {label: table_value}
            ov = {"hide": True} if hide else dict(override or {})
            orphan_ctx = (
                nullcontext()
                if probe_orphans
                else patch.object(
                    launchd,
                    "pids_for_argv",
                    return_value=list(orphan_pids or []),
                )
            )
            with (
                patch.object(launchd, "AGENTS_DIR", tmp),
                patch.object(launchd, "launchctl_table", return_value=table),
                patch.object(launchd, "override", return_value=ov),
                patch.object(launchd, "friendly_name", return_value="Example"),
                patch.object(launchd, "guess_group", return_value=group),
                patch.object(launchd, "ports_from_plist", return_value=[]),
                patch.object(launchd, "ports_for_pid", return_value=[]),
                patch.object(launchd, "configured_signatures", return_value=[]),
                patch.object(launchd, "url_from_plist", return_value=None),
                patch.object(launchd, "resolve_template", side_effect=lambda value: value),
                patch.object(launchd, "enrich_service", side_effect=lambda item, **_: item),
                patch.object(launchd, "port_open", lambda port, **kw: port_reachable),
                patch.object(launchd, "pid_exe_path", lambda pid: pid_exe),
                patch.object(launchd, "_http_alive", lambda port: http_alive),
                orphan_ctx,
            ):
                items = launchd.discover_launchd()
                return items[0] if items else None

    def test_launchservices_login_item_success_is_healthy_without_pid(self):
        item = self._discover(
            ["/usr/bin/open", "-gj", "/Applications/ServerHub.app"],
            ("-", "0"),
        )
        self.assertEqual(item["state"], "ok")
        self.assertEqual(item["detail"], "loaded · opens app at login")
        self.assertIn("run", item["actions"])

    def test_launchservices_login_item_failure_is_warning(self):
        item = self._discover(
            ["/usr/bin/open", "-gj", "/Applications/ServerHub.app"],
            ("-", "7"),
        )
        self.assertEqual(item["state"], "warn")
        self.assertIn("exit 7", item["detail"])

    def test_non_launchservices_job_without_pid_remains_down(self):
        item = self._discover(
            ["/usr/bin/python3", "/tmp/service.py"],
            ("-", "0"),
            KeepAlive=True,
        )
        self.assertEqual(item["state"], "down")
        self.assertEqual(item["detail"], "Loaded but not running")

    def test_keepalive_nonzero_exit_is_crash_looping(self):
        item = self._discover(
            ["/opt/homebrew/bin/cloudflared", "tunnel", "run"],
            ("-", "255"),
            KeepAlive=True,
        )
        self.assertEqual(item["state"], "down")
        self.assertEqual(item["detail"], "Crash-looping · last exit 255")
        self.assertIn("start", item["actions"])

    def test_oneshot_nonzero_exit_is_exited(self):
        item = self._discover(
            ["/usr/bin/true"],
            ("-", "1"),
            KeepAlive=False,
        )
        self.assertEqual(item["state"], "down")
        self.assertEqual(item["detail"], "Exited · last exit 1")

    def test_interval_job_last_exit_nonzero_is_ok(self):
        item = self._discover(
            ["/bin/zsh", "/tmp/nightly.sh"],
            ("-", "1"),
            StartCalendarInterval={"Hour": 3, "Minute": 30},
        )
        self.assertEqual(item["state"], "ok")
        self.assertIn("last exit code 1", item["detail"])

    def test_disabled_interval_job_not_loaded_is_stopped(self):
        item = self._discover(
            ["/bin/zsh", "/tmp/refresh.sh"],
            None,
            Disabled=True,
            StartInterval=7200,
        )
        self.assertEqual(item["state"], "stopped")
        self.assertEqual(item["detail"], "Disabled")
        self.assertIn("start", item["actions"])

    def test_disabled_keepalive_job_not_running_is_stopped(self):
        item = self._discover(
            ["/opt/homebrew/opt/redis/bin/redis-server"],
            ("-", "1"),
            Disabled=True,
            KeepAlive=True,
        )
        self.assertEqual(item["state"], "stopped")
        self.assertEqual(item["detail"], "Disabled")

    def test_keepalive_exact_path_orphan_is_ok(self):
        """App-managed helper is healthy even though launchd shows pid '-'."""
        helper = "/Applications/BaiduNetdisk.app/Contents/MacOS/BaiduNetdisk_mac"
        item = self._discover(
            [helper],
            ("-", "1"),
            KeepAlive=True,
            orphan_pids=[4242],
        )
        self.assertEqual(item["state"], "ok")
        self.assertIn("Running", item["detail"])
        self.assertIn("pid 4242", item["detail"])

    def test_orphan_not_promoted_for_disabled_interval_or_open(self):
        disabled = self._discover(
            ["/opt/homebrew/opt/redis/bin/redis-server"],
            ("-", "1"),
            Disabled=True,
            KeepAlive=True,
            orphan_pids=[9],
        )
        self.assertEqual(disabled["state"], "stopped")
        self.assertEqual(disabled["detail"], "Disabled")

        never_loaded = self._discover(
            ["/Applications/BaiduNetdisk.app/Contents/MacOS/BaiduNetdisk_mac"],
            None,
            KeepAlive=True,
            orphan_pids=[9],
        )
        self.assertEqual(never_loaded["state"], "down")
        self.assertEqual(never_loaded["detail"], "Not loaded")

        interval = self._discover(
            ["/usr/local/bin/helper"],
            ("-", "1"),
            StartCalendarInterval={"Hour": 3, "Minute": 30},
            orphan_pids=[9],
        )
        self.assertEqual(interval["state"], "ok")
        self.assertIn("scheduled task", interval["detail"])
        self.assertNotIn("pid 9", interval["detail"])

        opened = self._discover(
            ["/usr/bin/open", "-gj", "/Applications/ServerHub.app"],
            ("-", "0"),
            orphan_pids=[9],
        )
        self.assertEqual(opened["state"], "ok")
        self.assertEqual(opened["detail"], "loaded · opens app at login")
        self.assertNotIn("pid 9", opened["detail"])

    def test_orphan_basename_collision_does_not_promote(self):
        """Host cloudflared / zsh / true must not match a different argv."""
        rows = (
            (111, "cloudflared"),
            (112, "/opt/homebrew/bin/cloudflared --version"),
            (113, "/bin/zsh"),
            (114, "/usr/bin/true"),
        )
        with patch("hub.proc_utils.ps_pid_commands", return_value=rows):
            collided = self._discover(
                ["/opt/homebrew/bin/cloudflared", "tunnel", "run"],
                ("-", "255"),
                KeepAlive=True,
                probe_orphans=True,
            )
        self.assertEqual(collided["state"], "down")
        self.assertEqual(collided["detail"], "Crash-looping · last exit 255")

    def test_orphan_full_argv_match_promotes(self):
        rows = ((4242, "/opt/homebrew/bin/cloudflared tunnel run --token x"),)
        with patch("hub.proc_utils.ps_pid_commands", return_value=rows):
            item = self._discover(
                ["/opt/homebrew/bin/cloudflared", "tunnel", "run"],
                ("-", "255"),
                KeepAlive=True,
                probe_orphans=True,
            )
        self.assertEqual(item["state"], "ok")
        self.assertIn("Running", item["detail"])
        self.assertIn("pid 4242", item["detail"])

    def test_hidden_override_is_omitted(self):
        item = self._discover(
            ["/opt/homebrew/opt/redis/bin/redis-server"],
            ("-", "1"),
            KeepAlive=True,
            hide=True,
        )
        self.assertIsNone(item)

    def test_recognised_binary_uses_signature_name_and_category(self):
        item = self._discover(
            ["/opt/homebrew/opt/redis/bin/redis-server"],
            ("1234", "0"),
            group="Native Services",
            KeepAlive=True,
        )
        self.assertEqual(item["name"], "Redis")
        self.assertEqual(item["group"], "Databases")
        self.assertEqual(item["signature"]["slug"], "redis")
        self.assertEqual(item["signature"]["confidence"], "high")

    def test_name_override_wins_over_signature(self):
        item = self._discover(
            ["/opt/homebrew/opt/redis/bin/redis-server"],
            ("1234", "0"),
            group="Native Services",
            override={"name": "Cache", "group": "Infra"},
            KeepAlive=True,
        )
        self.assertEqual(item["name"], "Cache")
        self.assertEqual(item["group"], "Infra")
        self.assertEqual(item["signature"]["slug"], "redis")

    def test_unknown_binary_keeps_friendly_name(self):
        item = self._discover(
            ["/usr/local/bin/mysteryd"],
            ("1234", "0"),
            KeepAlive=True,
        )
        self.assertEqual(item["name"], "Example")
        self.assertNotIn("signature", item)

    def test_missing_interpreter_is_warn_even_when_tcp_is_open(self):
        item = self._discover(
            ["/usr/bin/python3", "/tmp/dashboard.py"],
            ("4242", "0"),
            KeepAlive=True,
            pid_exe="/opt/homebrew/Cellar/python@3.12/3.12.13_4/Python",
            override={"url": "http://127.0.0.1:6052/", "port": 6052},
        )
        self.assertEqual(item["state"], "warn")
        self.assertIn("missing interpreter", item["detail"])

    def test_http_401_still_counts_as_alive(self):
        item = self._discover(
            ["/usr/bin/python3", "/tmp/dashboard.py"],
            ("4242", "0"),
            KeepAlive=True,
            override={"url": "http://127.0.0.1:6052/", "port": 6052},
            http_alive=True,
        )
        self.assertEqual(item["state"], "ok")
        self.assertIn("pid 4242", item["detail"])

    def test_huge_plist_does_not_oom_discover(self):
        """``open(rb)`` of leftover multi-MB LaunchAgent used to OOM GET /api/status."""
        import json

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "huge.plist").write_bytes(b"x" * (2 * 1024 * 1024))
            (Path(tmp) / "com.example.service.plist").write_bytes(plistlib.dumps({
                "Label": "com.example.service",
                "ProgramArguments": ["/usr/bin/true"],
                "RunAtLoad": True,
            }))
            with (
                patch.object(launchd, "AGENTS_DIR", tmp),
                patch.object(launchd, "launchctl_table", return_value={}),
                patch.object(launchd, "override", return_value={}),
                patch.object(launchd, "friendly_name", return_value="Example"),
                patch.object(launchd, "guess_group", return_value="Native"),
                patch.object(launchd, "ports_from_plist", return_value=[]),
                patch.object(launchd, "ports_for_pid", return_value=[]),
                patch.object(launchd, "configured_signatures", return_value=[]),
                patch.object(launchd, "url_from_plist", return_value=None),
                patch.object(launchd, "resolve_template", side_effect=lambda value: value),
                patch.object(launchd, "enrich_service", side_effect=lambda item, **_: item),
                patch.object(launchd, "port_open", lambda port, **kw: True),
                patch.object(launchd, "pid_exe_path", lambda pid: _PRESENT_EXE),
                patch.object(launchd, "_http_alive", lambda port: True),
                patch.object(launchd, "pids_for_argv", return_value=[]),
            ):
                items = launchd.discover_launchd()
        json.dumps(items, allow_nan=False)
        ids = {item["id"] for item in items}
        self.assertIn("com.example.service", ids)
        self.assertIn("huge", ids)

    def test_plist_label_wins_over_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "Label": "com.real.job",
                "ProgramArguments": ["/usr/bin/python3", "/tmp/x.py"],
                "RunAtLoad": True,
                "KeepAlive": True,
            }
            (Path(tmp) / "com.file.name.plist").write_bytes(plistlib.dumps(payload))
            with (
                patch.object(launchd, "AGENTS_DIR", tmp),
                patch.object(launchd, "launchctl_table", return_value={"com.real.job": ("9", "0")}),
                patch.object(launchd, "override", return_value={}),
                patch.object(launchd, "friendly_name", return_value="Example"),
                patch.object(launchd, "guess_group", return_value="Native"),
                patch.object(launchd, "ports_from_plist", return_value=[]),
                patch.object(launchd, "ports_for_pid", return_value=[]),
                patch.object(launchd, "configured_signatures", return_value=[]),
                patch.object(launchd, "url_from_plist", return_value=None),
                patch.object(launchd, "resolve_template", side_effect=lambda value: value),
                patch.object(launchd, "enrich_service", side_effect=lambda item, **_: item),
                patch.object(launchd, "port_open", lambda port, **kw: True),
                patch.object(launchd, "pid_exe_path", lambda pid: _PRESENT_EXE),
                patch.object(launchd, "_http_alive", lambda port: True),
                patch.object(launchd, "pids_for_argv", return_value=[]),
            ):
                items = launchd.discover_launchd()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "com.real.job")
        self.assertIn("pid 9", items[0]["detail"])

    def test_recursing_label_does_not_500_discover(self):
        """leftover ``str(Label)`` RecursionError used to 500 GET /api/status."""
        import json

        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "x.plist").write_bytes(plistlib.dumps({
                "Label": "x",
                "ProgramArguments": ["/usr/bin/true"],
                "RunAtLoad": True,
            }))
            with (
                patch.object(launchd, "AGENTS_DIR", tmp),
                patch.object(launchd, "launchctl_table", return_value={}),
                patch.object(launchd, "override", return_value={}),
                patch.object(launchd, "friendly_name", return_value="Example"),
                patch.object(launchd, "guess_group", return_value="Native"),
                patch.object(launchd, "ports_from_plist", return_value=[]),
                patch.object(launchd, "ports_for_pid", return_value=[]),
                patch.object(launchd, "configured_signatures", return_value=[]),
                patch.object(launchd, "url_from_plist", return_value=None),
                patch.object(launchd, "resolve_template", side_effect=lambda value: value),
                patch.object(launchd, "enrich_service", side_effect=lambda item, **_: item),
                patch.object(launchd, "port_open", lambda port, **kw: True),
                patch.object(launchd, "pid_exe_path", lambda pid: _PRESENT_EXE),
                patch.object(launchd, "_http_alive", lambda port: True),
                patch.object(launchd, "pids_for_argv", return_value=[]),
                patch.object(
                    launchd.plistlib, "loads",
                    return_value={
                        "Label": Recursing(),
                        "ProgramArguments": ["/usr/bin/true"],
                        "RunAtLoad": True,
                    },
                ),
            ):
                items = launchd.discover_launchd()
        json.dumps(items, allow_nan=False).encode("utf-8")
        self.assertEqual(len(items), 1)
        self.assertIsInstance(items[0]["id"], str)

    def test_single_http_miss_does_not_warn(self):
        item = self._discover(
            ["/usr/bin/python3", "/tmp/dashboard.py"],
            ("4242", "0"),
            KeepAlive=True,
            override={"url": "http://127.0.0.1:6052/", "port": 6052},
            http_alive=False,
        )
        self.assertEqual(item["state"], "ok")
        self.assertIn("pid 4242", item["detail"])

    def test_two_http_misses_are_still_held(self):
        kwargs = dict(
            arguments=["/usr/bin/python3", "/tmp/dashboard.py"],
            table_value=("4242", "0"),
            KeepAlive=True,
            override={"url": "http://127.0.0.1:6052/", "port": 6052},
            http_alive=False,
        )
        self._discover(**kwargs)
        item = self._discover(**kwargs)
        self.assertEqual(item["state"], "ok")
        self.assertIn("pid 4242", item["detail"])

    def test_tcp_open_but_http_dead_is_warn(self):
        kwargs = dict(
            arguments=["/usr/bin/python3", "/tmp/dashboard.py"],
            table_value=("4242", "0"),
            KeepAlive=True,
            override={"url": "http://127.0.0.1:6052/", "port": 6052},
            http_alive=False,
        )
        self._discover(**kwargs)
        self._discover(**kwargs)
        item = self._discover(**kwargs)
        self.assertEqual(item["state"], "warn")
        self.assertIn("HTTP :6052 not answering", item["detail"])

    def test_http_success_clears_the_miss_counter(self):
        kwargs = dict(
            arguments=["/usr/bin/python3", "/tmp/dashboard.py"],
            table_value=("4242", "0"),
            KeepAlive=True,
            override={"url": "http://127.0.0.1:6052/", "port": 6052},
        )
        self._discover(**kwargs, http_alive=False)
        self._discover(**kwargs, http_alive=True)
        item = self._discover(**kwargs, http_alive=False)
        self.assertEqual(item["state"], "ok")

    def test_redis_is_not_http_probed(self):
        """A TCP-only daemon must not go warn just because GET / fails."""
        item = self._discover(
            ["/opt/homebrew/opt/redis/bin/redis-server"],
            ("1234", "0"),
            KeepAlive=True,
            override={"port": 6379},
            http_alive=False,
        )
        self.assertEqual(item["state"], "ok")

    def test_redis_url_override_is_still_not_http_probed(self):
        """A docs URL on a TCP-only daemon must not flip the row to warn."""
        item = self._discover(
            ["/opt/homebrew/opt/redis/bin/redis-server"],
            ("1234", "0"),
            KeepAlive=True,
            override={"port": 6379, "url": "http://127.0.0.1:6379/"},
            http_alive=False,
        )
        self.assertEqual(item["state"], "ok")


class ProcUtilsTests(unittest.TestCase):
    """Command-prefix matching must never fall back to a basename pgrep."""

    def test_pids_for_exe_is_absolute_argv0_not_basename(self):
        from hub.proc_utils import pids_for_argv, pids_for_exe

        rows = (
            (1, "/usr/bin/true"),
            (2, "true"),
            (3, "/usr/bin/true extra"),
            (4, "/bin/zsh"),
            (5, "/bin/zsh /tmp/refresh.sh"),
            (6, "/opt/homebrew/bin/cloudflared tunnel run"),
            (7, "cloudflared"),
            (8, "/Applications/BaiduNetdisk.app/Contents/MacOS/BaiduNetdisk_mac"),
        )
        with patch("hub.proc_utils.ps_pid_commands", return_value=rows):
            self.assertEqual(pids_for_exe("/usr/bin/true"), [1, 3])
            self.assertEqual(pids_for_exe("true"), [])
            self.assertEqual(pids_for_exe("/bin/zsh"), [4, 5])
            self.assertEqual(pids_for_argv(["/bin/zsh", "/tmp/refresh.sh"]), [5])
            self.assertEqual(
                pids_for_argv(["/opt/homebrew/bin/cloudflared", "tunnel", "run"]),
                [6],
            )
            self.assertEqual(pids_for_exe("cloudflared"), [])
            self.assertEqual(
                pids_for_argv([
                    "/Applications/BaiduNetdisk.app/Contents/MacOS/BaiduNetdisk_mac",
                ]),
                [8],
            )
            self.assertEqual(pids_for_exe(""), [])
            self.assertEqual(pids_for_argv(["zsh"]), [])
            self.assertEqual(pids_for_argv("not-a-list"), [])


class _SilentTCP:
    """Accept and never reply, so the plaintext probe times out."""

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._hold, args=(conn,), daemon=True).start()

    def _hold(self, conn):
        try:
            time.sleep(2.0)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self):
        self._stop.set()
        try:
            self._sock.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class _CloseTCP:
    """Accept, then close without writing — Sunshine's plaintext behaviour."""

    def __init__(self, payload=b""):
        self._payload = payload
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            try:
                conn.recv(64)
                if self._payload:
                    conn.sendall(self._payload)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def close(self):
        self._stop.set()
        try:
            self._sock.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class HttpAliveTests(unittest.TestCase):
    """401 is a speaking daemon; a hang is not; a TLS-only close still is."""

    def test_http_401_is_alive(self):
        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            with patch.object(launchd, "_tls_alive") as tls:
                self.assertTrue(launchd._http_alive(port))
            tls.assert_not_called()
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_http_421_is_alive(self):
        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(421)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            with patch.object(launchd, "_tls_alive") as tls:
                self.assertTrue(launchd._http_alive(port))
            tls.assert_not_called()
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_plaintext_hang_is_dead_without_tls_retry(self):
        with _SilentTCP() as srv:
            with patch.object(launchd, "_tls_alive") as tls:
                tls.return_value = True
                self.assertFalse(launchd._http_alive(srv.port))
            tls.assert_not_called()

    def test_tls_only_close_falls_through_to_handshake(self):
        with _CloseTCP() as srv:
            with patch.object(launchd, "_tls_alive", lambda port: True):
                self.assertTrue(launchd._http_alive(srv.port))

    def test_non_http_bytes_are_dead_without_tls_retry(self):
        with _CloseTCP(b"-ERR wrong number of arguments for 'get' command\r\n") as srv:
            with patch.object(launchd, "_tls_alive") as tls:
                tls.return_value = True
                self.assertFalse(launchd._http_alive(srv.port))
            tls.assert_not_called()

    def test_tls_record_is_alive_without_a_second_handshake(self):
        with _CloseTCP(b"\x15\x03\x01\x00\x02\x02\x28") as srv:
            with patch.object(launchd, "_tls_alive") as tls:
                self.assertTrue(launchd._http_alive(srv.port))
            tls.assert_not_called()

    def test_plaintext_and_tls_dead_is_dead(self):
        with _CloseTCP() as srv:
            with patch.object(launchd, "_tls_alive", lambda port: False):
                self.assertFalse(launchd._http_alive(srv.port))

    def test_infinite_port_is_dead_not_raised(self):
        """YAML leftover ``port: .inf`` used to OverflowError this fan_out probe."""
        self.assertFalse(launchd._http_alive(float("inf")))
        self.assertFalse(launchd._http_alive(float("nan")))
        self.assertFalse(launchd._http_alive({}))


if __name__ == "__main__":
    unittest.main()
