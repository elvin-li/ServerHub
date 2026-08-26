"""Fifth leftover-500s sweep of the Cloudflare / tunnel surfaces, over HTTP.

One live leftover survived cf/cf2/cf3/cf4: a leftover **directory occupying
the LaunchAgent plist path** (``~/Library/LaunchAgents/
local.cloudflared-tunnel.plist``).  ``_write_launchagent_token`` handed the
rendered plist to ``secure_io.replace_bytes``, whose final ``os.replace``
raises ``IsADirectoryError`` when the destination is a directory — an OSError
no frame on the path caught, so

    POST /api/cloudflared/start          POST /api/cloudflared/start-token
    POST /api/cloudflared/restart        POST /api/apps/managed/action
                                              (native-cloudflared autostart_on)

all answered a raw 500 with a traceback.  Every sibling writer in the module
(``_write_token``, ``_save_state``, the login.url/login.pid/login.log writers)
already caught OSError; the plist writer was the one leftover.  The fix uses
the purpose-built ``secure_io.drop_leftover_nonfile`` (an *empty* leftover
directory or FIFO is removed and the start self-heals) and turns anything the
drop cannot remove — a non-empty directory — into the new coded 503
``cloudflared.plist_write_failed``, registered in hub/errors.py and all three
SPA locales.

The rest of this battery pins the two panel routes cf4's HTTP sweep did not
mount — POST /api/cloudflared/login and GET /api/cloudflared/login/poll —
against the classes hunted by the prior sweeps (FIFO / directory / undecodable
junk planted at login.url and login.pid, a real login child that prints
non-UTF-8 bytes around the URL, undecodable log tails), asserting every body
stays a strictly-UTF-8-renderable coded answer through the real
``create_app()`` stack.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import cloudflared_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.errors import CODES

#: A shape-valid Zero Trust connector JWT (three base64url segments).
_GOOD_TOKEN = "eyJ" + "a" * 100 + "." + "b" * 40 + "." + "c" * 40

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
        self._tmp = tempfile.TemporaryDirectory(prefix="cf5-http-")
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.root = root
        self.state_dir = root / "state"
        self.state_dir.mkdir()
        self.cf_home = root / "cf"
        self.cf_home.mkdir()
        self.state_file = self.state_dir / "serverhub-state.json"
        self.token_file = self.state_dir / "tunnel.token"
        self.login_pid = self.state_dir / "login.pid"
        self.login_url = self.state_dir / "login.url"
        self.cert = self.cf_home / "cert.pem"
        self.plist = root / "local.cloudflared-tunnel.plist"
        for name, value in {
            "STATE_DIR": self.state_dir,
            "STATE_FILE": self.state_file,
            "TOKEN_FILE": self.token_file,
            "LOG_FILE": self.state_dir / "tunnel.log",
            "LOGIN_PID": self.login_pid,
            "LOGIN_LOG": self.state_dir / "login.log",
            "LOGIN_URL_FILE": self.login_url,
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

    def _fake_bin(self, script: str) -> str:
        p = self.root / "fake-cloudflared"
        p.write_text("#!/bin/sh\n" + script + "\n")
        p.chmod(0o755)
        return str(p)

    def assert_coded(self, resp, status: int, code: str) -> None:
        self.assertEqual(resp.status_code, status)
        body = resp.content.decode("utf-8")  # strict on purpose
        self.assertEqual(json.loads(body)["detail"]["code"], code)


class PlistDirLeftoverTests(_CloudflaredSandbox):
    """The live leak: a directory occupying the LaunchAgent plist path."""

    def _occupy_plist_with_nonempty_dir(self):
        self.plist.mkdir()
        (self.plist / "occupied").write_text("x")

    def test_start_token_with_nonempty_plist_dir_is_coded_503(self):
        """Was a raw 500: IsADirectoryError out of secure_io.replace_bytes."""
        self._occupy_plist_with_nonempty_dir()
        with mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/true"):
            resp = self.client.post(
                "/api/cloudflared/start-token", json={"token": _GOOD_TOKEN},
            )
        self.assert_coded(resp, 503, "cloudflared.plist_write_failed")

    def test_restart_with_nonempty_plist_dir_is_coded_503(self):
        self._occupy_plist_with_nonempty_dir()
        self.token_file.write_text(_GOOD_TOKEN)
        with mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/true"):
            resp = self.client.post("/api/cloudflared/restart")
        self.assert_coded(resp, 503, "cloudflared.plist_write_failed")

    def test_start_with_nonempty_plist_dir_is_coded_503(self):
        self._occupy_plist_with_nonempty_dir()
        self.cert.write_text("x" * 64)
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/true"),
            mock.patch.object(
                cloudflared_svc, "fetch_token", return_value=_GOOD_TOKEN,
            ),
        ):
            resp = self.client.post(
                "/api/cloudflared/start", json={"tunnel": "home"},
            )
        self.assert_coded(resp, 503, "cloudflared.plist_write_failed")

    def test_apps_autostart_with_nonempty_plist_dir_is_coded_503(self):
        """The Apps-page autostart toggle reaches the same writer."""
        self._occupy_plist_with_nonempty_dir()
        self.token_file.write_text(_GOOD_TOKEN)
        with mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/true"):
            resp = self.client.post(
                "/api/apps/managed/action",
                json={"id": "native:native-cloudflared", "action": "autostart_on"},
            )
        self.assert_coded(resp, 503, "cloudflared.plist_write_failed")

    def test_empty_plist_dir_self_heals(self):
        """drop_leftover_nonfile removes an empty leftover; the start goes on."""
        self.plist.mkdir()
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

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo required")
    def test_fifo_at_plist_self_heals(self):
        os.mkfifo(self.plist)
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
        self.assertTrue(self.plist.is_file())

    def test_error_code_is_registered_everywhere(self):
        """503 in hub/errors.py and the key present in all three locales."""
        self.assertEqual(CODES["cloudflared.plist_write_failed"][0], 503)
        i18n = Path(__file__).resolve().parents[1] / "web" / "src" / "i18n"
        for locale in ("en.js", "zh-CN.js", "ja.js"):
            text = (i18n / locale).read_text(errors="replace")
            self.assertIn("plist_write_failed:", text, locale)


class LoginRouteHttpTests(_CloudflaredSandbox):
    """POST /login and GET /login/poll had no HTTP-level pins before cf5."""

    def tearDown(self):
        # Reap any fake login child so the suite leaks no sleeps/zombies.
        proc = cloudflared_svc._login_proc
        cloudflared_svc._terminate_login_process()
        if proc is not None:
            # The reap above went through os.waitpid, so the Popen never saw
            # its exit; settle returncode so its __del__ cannot warn.
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
        super().tearDown()

    def test_login_without_binary_is_coded_503(self):
        resp = self.client.post("/api/cloudflared/login")
        self.assert_coded(resp, 503, "cloudflared.not_installed")

    def test_login_already_logged_in_is_200(self):
        self.cert.write_text("x" * 64)
        resp = self.client.post("/api/cloudflared/login")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["already"])

    def test_login_child_url_flow_over_http(self):
        b = self._fake_bin(
            "printf 'visit https://dash.cloudflare.com/argotunnel?x=1\\n'; sleep 30"
        )
        with mock.patch.object(cloudflared_svc, "_bin", return_value=b):
            resp = self.client.post("/api/cloudflared/login")
            self.assertEqual(resp.status_code, 200)
            out = resp.json()
            self.assertTrue(out["ok"])
            self.assertEqual(
                out["login_url"], "https://dash.cloudflare.com/argotunnel?x=1",
            )
            poll = self.client.get("/api/cloudflared/login/poll")
        self.assertEqual(poll.status_code, 200)
        snap = poll.json()
        self.assertTrue(snap["login_pending"])
        self.assertEqual(
            snap["login_url"], "https://dash.cloudflare.com/argotunnel?x=1",
        )

    def test_login_child_undecodable_bytes_render_strictly(self):
        """Non-UTF-8 noise around the URL must never break the body encode."""
        b = self._fake_bin(
            "printf '\\xff\\xfe\\xed\\xa0\\x80 https://example.com/cb\\n'; sleep 30"
        )
        with mock.patch.object(cloudflared_svc, "_bin", return_value=b):
            resp = self.client.post("/api/cloudflared/login")
            self.assertEqual(resp.status_code, 200)
            resp.content.decode("utf-8")  # strict on purpose
            self.assertIn("https://example.com/cb", resp.json()["login_url"])
            poll = self.client.get("/api/cloudflared/login/poll")
        self.assertEqual(poll.status_code, 200)
        poll.content.decode("utf-8")

    def test_login_child_dying_instantly_is_ok_false_not_500(self):
        b = self._fake_bin("exit 7")
        with mock.patch.object(cloudflared_svc, "_bin", return_value=b):
            resp = self.client.post("/api/cloudflared/login")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["ok"])


class LoginArtifactPoisonHttpTests(_CloudflaredSandbox):
    """Planted junk at login.url / login.pid must not 500, hang, or tear UTF-8."""

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo required")
    def test_fifo_at_login_url_does_not_park_poll_or_status(self):
        os.mkfifo(self.login_url)
        for path in ("/api/cloudflared/login/poll", "/api/cloudflared/status"):
            with self.subTest(path=path):
                resp = self.client.get(path)
                self.assertEqual(resp.status_code, 200)
                self.assertTrue(resp.json()["ok"])

    def test_undecodable_login_url_renders_strictly(self):
        self.login_url.write_bytes(b"\xff\xfe garbage \xed\xa0\x80")
        for path in ("/api/cloudflared/login/poll", "/api/cloudflared/status"):
            with self.subTest(path=path):
                resp = self.client.get(path)
                self.assertEqual(resp.status_code, 200)
                resp.content.decode("utf-8")  # strict on purpose

    def test_directory_at_login_url_does_not_500_login_or_poll(self):
        self.login_url.mkdir()
        resp = self.client.get("/api/cloudflared/login/poll")
        self.assertEqual(resp.status_code, 200)
        # POST /login unlinks login.url on its way in; a directory there is
        # OSError, swallowed — the request then fails on the missing binary,
        # never on the leftover.
        resp = self.client.post("/api/cloudflared/login")
        self.assert_coded(resp, 503, "cloudflared.not_installed")

    def test_poisoned_login_pid_variants_stay_coded(self):
        """dir / FIFO / huge / undecodable pid records are all discarded."""
        def plant(kind: str) -> None:
            shutil.rmtree(self.login_pid, ignore_errors=True)
            self.login_pid.unlink(missing_ok=True)
            if kind == "dir":
                self.login_pid.mkdir()
            elif kind == "fifo":
                os.mkfifo(self.login_pid)
            elif kind == "huge":
                self.login_pid.write_text("9" * 32)
            elif kind == "binary":
                self.login_pid.write_bytes(b"\xff\x80 not a pid")

        kinds = ["dir", "huge", "binary"]
        if hasattr(os, "mkfifo"):
            kinds.append("fifo")
        for kind in kinds:
            with self.subTest(kind=kind):
                plant(kind)
                poll = self.client.get("/api/cloudflared/login/poll")
                self.assertEqual(poll.status_code, 200)
                self.assertFalse(poll.json()["login_pending"])
                status = self.client.get("/api/cloudflared/status")
                self.assertEqual(status.status_code, 200)
                login = self.client.post("/api/cloudflared/login")
                self.assert_coded(login, 503, "cloudflared.not_installed")

    def test_logged_in_poll_cleans_up_despite_directory_login_url(self):
        self.cert.write_text("x" * 64)
        self.login_url.mkdir()
        resp = self.client.get("/api/cloudflared/login/poll")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["logged_in"])


class LogsUndecodableTailHttpTests(_CloudflaredSandbox):
    def test_undecodable_and_surrogate_byte_logs_render_strictly(self):
        (self.state_dir / "tunnel.log").write_bytes(
            b"\xff\x80 bad utf8 \xed\xa0\x80 surrogate bytes\n" * 5
        )
        (self.state_dir / "login.log").write_bytes(b"\xed\xa0\x80" * 50)
        resp = self.client.get("/api/cloudflared/logs")
        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode("utf-8")  # strict on purpose
        self.assertIn("tunnel.log", json.loads(body)["log"])


if __name__ == "__main__":
    unittest.main()
