"""SSRF / rebinding / symlink / notify / login-rate / jobs argv hardening."""
from __future__ import annotations

import ipaddress
import json
import socket
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import alerts, auth, bookmarks_svc, files_svc, jobs, url_safety  # noqa: E402


def _addrinfo(ip: str):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, 0, "", (ip, 0))]


class UrlSafetyTests(unittest.TestCase):
    def test_literal_loopback_and_imds_are_blocked(self):
        for host in ("127.0.0.1", "::1", "localhost", "169.254.169.254", "metadata"):
            with self.subTest(host=host):
                self.assertTrue(url_safety.is_blocked_literal_host(host))
                self.assertTrue(url_safety.resolved_probe_blocked(host))

    def test_ipv4_mapped_loopback_and_imds_are_blocked(self):
        for host in ("::ffff:127.0.0.1", "::ffff:169.254.169.254"):
            with self.subTest(host=host):
                self.assertTrue(url_safety.is_blocked_literal_host(host))
                self.assertTrue(url_safety.resolved_probe_blocked(host))
        # Notify may talk to localhost HA, but never to mapped IMDS.
        self.assertTrue(url_safety.outbound_url_allowed("http://[::ffff:127.0.0.1]/")[0])
        self.assertFalse(url_safety.outbound_url_allowed("http://[::ffff:169.254.169.254]/")[0])
        self.assertFalse(
            url_safety.outbound_url_allowed("http://[::ffff:127.0.0.1]/", allow_loopback=False)[0]
        )

    def test_public_name_rebinding_to_loopback_is_blocked(self):
        with mock.patch.object(socket, "getaddrinfo", return_value=_addrinfo("127.0.0.1")):
            self.assertTrue(url_safety.resolved_probe_blocked("evil.example"))

    def test_public_name_rebinding_to_mapped_imds_is_blocked_for_notify(self):
        with mock.patch.object(
            socket, "getaddrinfo", return_value=_addrinfo("::ffff:169.254.169.254")
        ):
            ok, _ = url_safety.outbound_url_allowed("http://evil.example/hook")
            self.assertFalse(ok)

    def test_public_name_rebinding_to_rfc1918_is_blocked(self):
        with mock.patch.object(socket, "getaddrinfo", return_value=_addrinfo("10.0.0.5")):
            self.assertTrue(url_safety.resolved_probe_blocked("evil.example"))

    def test_lan_name_may_resolve_to_rfc1918(self):
        with mock.patch.object(socket, "getaddrinfo", return_value=_addrinfo("192.168.1.10")):
            self.assertFalse(url_safety.resolved_probe_blocked("nas.local"))

    def test_lan_name_cannot_resolve_to_loopback(self):
        with mock.patch.object(socket, "getaddrinfo", return_value=_addrinfo("127.0.0.1")):
            self.assertTrue(url_safety.resolved_probe_blocked("nas.local"))

    def test_unresolved_public_name_is_fail_closed(self):
        with mock.patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("nxdomain")):
            self.assertTrue(url_safety.resolved_probe_blocked("missing.example"))

    def test_unresolved_lan_name_is_still_allowed(self):
        with mock.patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("nxdomain")):
            self.assertFalse(url_safety.resolved_probe_blocked("nas.local"))

    def test_lan_tls_decision_still_never_resolves(self):
        with mock.patch.object(socket, "getaddrinfo", side_effect=AssertionError("no dns")):
            self.assertTrue(url_safety.is_lan_host("nas.local"))
            self.assertFalse(url_safety.is_lan_host("example.com"))


class BookmarkRebindTests(unittest.TestCase):
    def test_a_rebinding_public_bookmark_is_not_opened(self):
        with (
            mock.patch.object(socket, "getaddrinfo", return_value=_addrinfo("169.254.169.254")),
            mock.patch.object(
                urllib.request, "build_opener", side_effect=AssertionError("opened")
            ),
        ):
            result = bookmarks_svc._probe("http://rebind.example/meta")
        self.assertFalse(result["ok"])
        self.assertIn("blocked host", result["error"])

    def test_a_redirect_to_a_rebinding_name_is_not_followed(self):
        handler = bookmarks_svc._SchemeSafeRedirects()
        req = urllib.request.Request("http://nas.local/app")
        with mock.patch.object(socket, "getaddrinfo", return_value=_addrinfo("127.0.0.1")):
            self.assertIsNone(
                handler.redirect_request(
                    req, None, 302, "Found", {}, "http://evil.example/admin"
                )
            )


class NotifyUrlTests(unittest.TestCase):
    def test_file_scheme_webhook_is_refused(self):
        with mock.patch.object(
            alerts,
            "notify_settings",
            return_value={"enabled": True, "ha_webhook_url": "file:///etc/passwd"},
        ):
            with mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("opened")):
                result = alerts.send_ha_notify("t", "m")
        self.assertFalse(result["ok"])
        self.assertIn("blocked", result["message"])

    def test_imds_webhook_is_refused(self):
        with mock.patch.object(
            alerts,
            "notify_settings",
            return_value={
                "enabled": True,
                "ha_webhook_url": "http://169.254.169.254/latest/meta-data",
            },
        ):
            with mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("opened")):
                result = alerts.send_ha_notify("t", "m")
        self.assertFalse(result["ok"])
        self.assertIn("blocked", result["message"])

    def test_localhost_ha_url_is_still_allowed(self):
        self.assertTrue(url_safety.outbound_url_allowed("http://localhost:8123/")[0])
        self.assertTrue(url_safety.outbound_url_allowed("http://127.0.0.1:8123/")[0])


class SymlinkMutationTests(unittest.TestCase):
    def test_delete_removes_the_link_not_the_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            media = root / "media"
            media.mkdir()
            target = media / "real.txt"
            target.write_text("keep-me", encoding="utf-8")
            link = media / "alias.txt"
            link.symlink_to(target)
            with mock.patch.object(
                files_svc,
                "default_roots",
                return_value=[{"id": "media", "name": "Media", "path": str(media)}],
            ):
                result = files_svc.delete_path(str(link), "media")
            self.assertTrue(result["ok"])
            self.assertFalse(link.exists() or link.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), "keep-me")

    def test_rename_moves_the_link_not_the_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            media = root / "media"
            media.mkdir()
            target = media / "real.txt"
            target.write_text("keep-me", encoding="utf-8")
            link = media / "alias.txt"
            link.symlink_to(target)
            with mock.patch.object(
                files_svc,
                "default_roots",
                return_value=[{"id": "media", "name": "Media", "path": str(media)}],
            ):
                result = files_svc.rename_path(str(link), "moved.txt", "media")
            moved = media / "moved.txt"
            self.assertTrue(result["ok"])
            self.assertTrue(moved.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), "keep-me")
            self.assertFalse(link.exists() or link.is_symlink())

    def test_upload_refuses_a_leaf_symlink(self):
        import asyncio

        class FakeUpload:
            filename = "alias.txt"

            async def read(self, _size: int = -1):
                return b""

            async def close(self):
                return None

        with tempfile.TemporaryDirectory() as temporary:
            media = Path(temporary) / "media"
            media.mkdir()
            target = media / "real.txt"
            target.write_text("keep-me", encoding="utf-8")
            link = media / "alias.txt"
            link.symlink_to(target)
            with mock.patch.object(
                files_svc,
                "default_roots",
                return_value=[{"id": "media", "name": "Media", "path": str(media)}],
            ):
                with self.assertRaises(Exception) as raised:
                    asyncio.run(files_svc.upload(str(media), FakeUpload(), "media"))
            self.assertEqual(target.read_text(encoding="utf-8"), "keep-me")
            detail = getattr(raised.exception, "detail", {})
            code = detail.get("code") if isinstance(detail, dict) else None
            self.assertEqual(code, "files.upload_would_overwrite")


class LoginRatePersistTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / ".login-failures.json"
        self.patchers = [
            mock.patch.object(auth, "LOGIN_FAILURES_FILE", self.path),
            mock.patch.object(auth, "_login_attempts", {}),
            mock.patch.object(auth, "_login_hydrated", False),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_failures_survive_an_in_memory_clear(self):
        client = "203.0.113.9"
        for _ in range(5):
            auth.record_login_failure(client)
        allowed, _ = auth.login_allowed(client)
        self.assertFalse(allowed)
        auth._login_attempts.clear()
        auth._login_hydrated = False
        allowed, retry = auth.login_allowed(client)
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)
        self.assertTrue(self.path.is_file())
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(len(data[client]), 5)

    def test_clear_login_failures_wipes_the_disk_entry(self):
        client = "198.51.100.10"
        auth.record_login_failure(client)
        auth.clear_login_failures(client)
        auth._login_attempts.clear()
        auth._login_hydrated = False
        allowed, _ = auth.login_allowed(client)
        self.assertTrue(allowed)
        data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.is_file() else {}
        self.assertNotIn(client, data)


class JobsArgvTests(unittest.TestCase):
    def test_a_list_command_runs_without_bash_c(self):
        captured = {}

        class FakePopen:
            def __init__(self, argv, **kwargs):
                captured["argv"] = list(argv)
                self.stdout = iter([])
                self.returncode = 0
                self.pid = 1

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return 0

        with (
            mock.patch.object(jobs.subprocess, "Popen", FakePopen),
            mock.patch.object(jobs, "invalidate_status"),
            mock.patch.object(jobs.threading.Thread, "start", lambda self: self.run()),
        ):
            jobs.start_job({"id": "echo", "command": ["/bin/echo", "hello"], "timeout": 5})
        self.assertEqual(captured["argv"], ["/bin/echo", "hello"])

    def test_a_string_command_still_uses_bash_c(self):
        captured = {}

        class FakePopen:
            def __init__(self, argv, **kwargs):
                captured["argv"] = list(argv)
                self.stdout = iter([])
                self.returncode = 0
                self.pid = 1

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return 0

        with (
            mock.patch.object(jobs.subprocess, "Popen", FakePopen),
            mock.patch.object(jobs, "invalidate_status"),
            mock.patch.object(jobs.threading.Thread, "start", lambda self: self.run()),
        ):
            jobs.start_job({"id": "shell", "command": "echo hello", "timeout": 5})
        self.assertEqual(captured["argv"][:2], ["/bin/bash", "-c"])


class ShellFootgunTests(unittest.TestCase):
    def test_util_sh_has_no_shell_kwarg(self):
        source = (BASE / "hub" / "util.py").read_text(encoding="utf-8")
        self.assertNotIn("shell=", source)
        catalog = (BASE / "hub" / "native_catalog.py").read_text(encoding="utf-8")
        self.assertNotRegex(catalog, r"def _run\([^)]*shell")


if __name__ == "__main__":
    unittest.main()
