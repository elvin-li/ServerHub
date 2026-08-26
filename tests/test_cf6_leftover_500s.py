"""Sixth leftover-500s sweep of the Cloudflare / tunnel surfaces, over HTTP.

Two live leftovers survived cf/cf2/cf3/cf4/cf5:

* **Surrogates in the LaunchAgent payload.**  A leftover surrogateescape HOME
  (a non-UTF-8 home directory decoded by ``os.environ``) reaches the plist
  payload through ``_launch_env()`` and the HOME-derived paths, and
  ``plistlib.dumps`` raises ``UnicodeEncodeError`` — a ValueError, not the
  OSError the writer caught — so

      POST /api/cloudflared/start          POST /api/cloudflared/start-token
      POST /api/cloudflared/restart        POST /api/apps/managed/action
                                                (native-cloudflared autostart_on)

  all answered a raw 500 with a traceback.  launchd could never load such a
  plist anyway, so the fix folds it into the existing coded 503
  ``cloudflared.plist_write_failed`` (no new error code, no locale changes).

* **Vanished CLI during POST /api/cloudflared/login.**  ``_bin()`` probes the
  disk before the spawn; a cloudflared uninstalled between that probe and
  ``subprocess.Popen`` raised FileNotFoundError, which the handler flattened
  into an *uncoded* ``{ok: false, message: "Could not start cloudflared
  login: [Errno 2]…"}`` the SPA cannot map — while every other endpoint
  answers the same race with the coded 503 ``cloudflared.not_installed``
  (see ``_cli_vanished``).  The re-check confirms the binary is actually gone
  from disk before classifying, so a spawn failure with the binary still
  present — including a FileNotFoundError for a vanished cwd — keeps its raw
  result rather than inventing a lie.

The rest of the battery pins classes from the leftover zoo that this surface
already survives, so a regression cannot reintroduce them silently:
over-digit-cap ints and surrogate keys/values in serverhub-state.json, FIFOs
occupying every state path at once, 4300-digit ints in the request body
itself, and undecodable token junk.  Everything runs through the real
``create_app()`` stack with ``raise_server_exceptions=False``.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import cloudflared_svc
from hub.app_factory import create_app
from hub.auth import require_auth

#: A shape-valid Zero Trust connector JWT (three base64url segments).
_GOOD_TOKEN = "eyJ" + "a" * 100 + "." + "b" * 40 + "." + "c" * 40

#: What os.environ hands a panel whose home directory name is not UTF-8:
#: surrogateescape'd bytes.  plistlib cannot encode this into XML.
_SURROGATE_HOME = Path("/private/tmp/serverhub-home\udcff")

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    # raise_server_exceptions=False: a leftover 500 must surface as the
    # response the SPA would see, not as a test-side exception.
    return TestClient(_app, raise_server_exceptions=False)


class _CloudflaredSandbox(unittest.TestCase):
    """Every module-level path constant redirected into a private temp tree."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="cf6-http-")
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.root = root
        self.state_dir = root / "state"
        self.state_dir.mkdir()
        self.cf_home = root / "cf"
        self.cf_home.mkdir()
        self.state_file = self.state_dir / "serverhub-state.json"
        self.token_file = self.state_dir / "tunnel.token"
        self.log_file = self.state_dir / "tunnel.log"
        self.cert = self.cf_home / "cert.pem"
        self.plist = root / "local.cloudflared-tunnel.plist"
        for name, value in {
            "STATE_DIR": self.state_dir,
            "STATE_FILE": self.state_file,
            "TOKEN_FILE": self.token_file,
            "LOG_FILE": self.log_file,
            "LOGIN_PID": self.state_dir / "login.pid",
            "LOGIN_LOG": self.state_dir / "login.log",
            "LOGIN_URL_FILE": self.state_dir / "login.url",
            "CF_HOME": self.cf_home,
            "CERT": self.cert,
            "CONFIG_YML": self.cf_home / "config.yml",
            "PLIST": self.plist,
        }.items():
            patcher = mock.patch.object(cloudflared_svc, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        cloudflared_svc.invalidate_tunnels()
        self.addCleanup(cloudflared_svc.invalidate_tunnels)
        self.client = _client()

    def assert_coded(self, resp, status: int, code: str) -> None:
        self.assertEqual(resp.status_code, status)
        body = resp.content.decode("utf-8")  # strict on purpose
        self.assertEqual(json.loads(body)["detail"]["code"], code)


class SurrogateHomePlistWriterTests(_CloudflaredSandbox):
    """Live leftover #1: surrogateescape HOME 500'd the plist writer."""

    def _surrogate_home(self):
        return mock.patch.object(
            cloudflared_svc, "user_home", return_value=_SURROGATE_HOME,
        )

    def test_start_token_with_surrogate_home_is_coded_503(self):
        """Was a raw 500: UnicodeEncodeError out of plistlib.dumps."""
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/true"),
            self._surrogate_home(),
        ):
            resp = self.client.post(
                "/api/cloudflared/start-token", json={"token": _GOOD_TOKEN},
            )
        self.assert_coded(resp, 503, "cloudflared.plist_write_failed")
        # The failed write must not leave a torn or partial plist behind.
        self.assertFalse(self.plist.exists())

    def test_restart_with_surrogate_home_is_coded_503(self):
        self.token_file.write_text(_GOOD_TOKEN)
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/true"),
            self._surrogate_home(),
        ):
            resp = self.client.post("/api/cloudflared/restart")
        self.assert_coded(resp, 503, "cloudflared.plist_write_failed")
        # The saved token survives the refused restart.
        self.assertEqual(self.token_file.read_text(), _GOOD_TOKEN)

    def test_start_with_surrogate_home_is_coded_503(self):
        self.cert.write_text("x" * 64)
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/true"),
            mock.patch.object(
                cloudflared_svc, "fetch_token", return_value=_GOOD_TOKEN,
            ),
            self._surrogate_home(),
        ):
            resp = self.client.post(
                "/api/cloudflared/start", json={"tunnel": "home"},
            )
        self.assert_coded(resp, 503, "cloudflared.plist_write_failed")

    def test_apps_autostart_with_surrogate_home_is_coded_503(self):
        """The Apps-page autostart toggle reaches the same writer."""
        self.token_file.write_text(_GOOD_TOKEN)
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/true"),
            self._surrogate_home(),
        ):
            resp = self.client.post(
                "/api/apps/managed/action",
                json={"id": "native:native-cloudflared", "action": "autostart_on"},
            )
        self.assert_coded(resp, 503, "cloudflared.plist_write_failed")

    def test_clean_home_still_starts(self):
        """The broadened except must not swallow the healthy path."""
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/true"),
            mock.patch.object(
                cloudflared_svc, "_launchctl_bootstrap",
                return_value={"ok": True, "message": "up"},
            ),
        ):
            resp = self.client.post(
                "/api/cloudflared/start-token", json={"token": _GOOD_TOKEN},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["ok"])
        self.assertTrue(self.plist.is_file())

    def test_status_with_surrogate_home_is_still_200(self):
        """The read-only poll never touches the plist writer."""
        with self._surrogate_home():
            resp = self.client.get("/api/cloudflared/status")
        self.assertEqual(resp.status_code, 200)
        resp.content.decode("utf-8")  # strict on purpose


class VanishedCliLoginTests(_CloudflaredSandbox):
    """Live leftover #2: cloudflared uninstalled between _bin() and Popen."""

    def tearDown(self):
        # Reap any login child so the suite leaks no zombies.
        proc = cloudflared_svc._login_proc
        cloudflared_svc._terminate_login_process()
        if proc is not None:
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
        super().tearDown()

    def test_login_vanished_binary_is_coded_503(self):
        """Was an uncoded 200 {ok:false, message:"[Errno 2]…"}."""
        gone = self.root / "vanished-cloudflared"
        with mock.patch.object(cloudflared_svc, "_bin", return_value=str(gone)):
            resp = self.client.post("/api/cloudflared/login")
        self.assert_coded(resp, 503, "cloudflared.not_installed")

    def test_login_spawn_failure_with_binary_present_keeps_raw_result(self):
        """Do not invent the 503: FileNotFoundError while the binary is still
        on disk (a vanished cwd, a torn mount) is not a missing CLI."""
        present = self.root / "present-cloudflared"
        present.write_text("#!/bin/sh\nexit 0\n")
        present.chmod(0o755)
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value=str(present)),
            mock.patch.object(
                cloudflared_svc.subprocess, "Popen",
                side_effect=FileNotFoundError(2, "No such file or directory"),
            ),
        ):
            resp = self.client.post("/api/cloudflared/login")
        self.assertEqual(resp.status_code, 200)
        out = resp.json()
        self.assertFalse(out["ok"])
        self.assertIn("Could not start cloudflared login", out["message"])

    def test_login_permission_error_stays_uncoded_ok_false(self):
        """A refused spawn is a raw result, not a missing binary."""
        present = self.root / "present-cloudflared"
        present.write_text("#!/bin/sh\nexit 0\n")
        present.chmod(0o755)
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value=str(present)),
            mock.patch.object(
                cloudflared_svc.subprocess, "Popen",
                side_effect=PermissionError(13, "Permission denied"),
            ),
        ):
            resp = self.client.post("/api/cloudflared/login")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["ok"])


class StaysImmuneZooTests(_CloudflaredSandbox):
    """Classes from the leftover zoo this surface already survives — pinned."""

    def test_over_digit_cap_int_in_state_keeps_status_and_restart_coded(self):
        """json.loads of a 4300+-digit number is bare ValueError; the parse_int
        guard nulls the one value instead of wiping the document or 500ing."""
        self.state_file.write_text(
            '{"tunnel_name": ' + "9" * 4400 + ', "mode": "token"}'
        )
        resp = self.client.get("/api/cloudflared/status")
        self.assertEqual(resp.status_code, 200)
        snap = resp.json()
        # The over-cap number is dropped, not the whole state document.
        self.assertEqual(snap["mode"], "token")
        self.assertIsNone(snap["active_tunnel"])
        resp = self.client.post("/api/cloudflared/restart")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["ok"])

    def test_huge_int_in_request_body_is_400_not_500(self):
        """json.loads huge numbers is ValueError not JSONDecodeError; the
        framework must still answer 4xx, never a traceback."""
        huge = ("9" * 4400).encode()
        for path, body in (
            ("/api/cloudflared/create", b'{"name": ' + huge + b"}"),
            (
                "/api/cloudflared/route-dns",
                b'{"tunnel": "t", "hostname": "h.example.com", "x": '
                + huge + b"}",
            ),
        ):
            with self.subTest(path=path):
                resp = self.client.post(
                    path, content=body,
                    headers={"content-type": "application/json"},
                )
                self.assertEqual(resp.status_code, 400)
                resp.content.decode("utf-8")  # strict on purpose

    def test_surrogate_keys_and_values_in_state_render_strictly(self):
        self.state_file.write_text(
            json.dumps({"tunnel_name": "t\ud800x", "\ud800key": "v"}),
        )
        resp = self.client.get("/api/cloudflared/status")
        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode("utf-8")  # strict on purpose
        rendered = json.loads(body)["active_tunnel"]
        self.assertTrue(rendered.startswith("t") and rendered.endswith("x"))

    def test_numeric_state_tunnel_name_restarts_instead_of_refusing(self):
        """A ``tunnel_name: 123`` written unquoted stays a working restart."""
        self.token_file.write_text(_GOOD_TOKEN)
        self.state_file.write_text('{"tunnel_name": 123, "mode": "token"}')
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/true"),
            mock.patch.object(
                cloudflared_svc, "_launchctl_bootstrap",
                return_value={"ok": True, "message": "up"},
            ),
        ):
            resp = self.client.post("/api/cloudflared/restart")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["ok"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo required")
    def test_fifos_at_every_state_path_do_not_park_or_500(self):
        for p in (self.state_file, self.token_file, self.cert, self.log_file):
            os.mkfifo(p)
        resp = self.client.get("/api/cloudflared/status")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["ok"])
        resp = self.client.get("/api/cloudflared/logs")
        self.assertEqual(resp.status_code, 200)
        resp.content.decode("utf-8")  # strict on purpose

    def test_undecodable_token_body_is_coded_400(self):
        resp = self.client.post(
            "/api/cloudflared/start-token",
            content=b'{"token": "eyJ' + b"\xef\xbf\xbd" * 40 + b'"}',
            headers={"content-type": "application/json"},
        )
        self.assert_coded(resp, 400, "cloudflared.invalid_token")


if __name__ == "__main__":
    unittest.main()
