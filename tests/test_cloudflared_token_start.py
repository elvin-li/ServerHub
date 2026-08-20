"""Refuse dummy Cloudflare tokens and report KeepAlive crash loops.

A 40-character placeholder used to pass ``len < 40``, KeepAlive then respawned
cloudflared forever on "Provided Tunnel token is not valid.", and both the
Cloudflare page and Services start treated ``launchctl kickstart`` rc=0 as
success while the job sat at ``state = spawn scheduled``.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import cloudflared_svc

#: Compact ``{"a","s","t"}`` connector token (not a live secret).
FAKE_COMPACT = (
    "eyJhIjoiYWNjdGFjY3RhY2N0YWNjdGFjY3RhY2N0YWNjdGFjY3QiLCJzIjoic2VjcmV0c2"
    "VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0IiwidCI6IjAxMjM"
    "0NTY3LTg5YWItY2RlZi0wMTIzLTQ1Njc4OWFiY2RlZiJ9"
)
FAKE_JWT = (
    "eyJhbGciOiJub25lIn0."
    "eyJhIjoidGVzdC10dW5uZWwiLCJ0IjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIn0."
    + ("d" * 48)
)


class TokenShapeTests(unittest.TestCase):
    def test_dummy_all_t_is_rejected(self):
        self.assertFalse(cloudflared_svc.token_looks_valid("t" * 40))
        self.assertFalse(cloudflared_svc.token_looks_valid("t" * 64))
        self.assertFalse(cloudflared_svc.token_looks_valid("t" * 200))

    def test_compact_connector_token_is_accepted(self):
        self.assertTrue(cloudflared_svc.token_looks_valid(FAKE_COMPACT))
        self.assertTrue(cloudflared_svc.token_looks_valid(f'"{FAKE_COMPACT}"'))

    def test_three_segment_jwt_is_accepted(self):
        self.assertTrue(cloudflared_svc.token_looks_valid(FAKE_JWT))

    def test_short_and_empty_are_rejected(self):
        self.assertFalse(cloudflared_svc.token_looks_valid(""))
        self.assertFalse(cloudflared_svc.token_looks_valid("eyJ"))
        self.assertFalse(cloudflared_svc.token_looks_valid(None))

    def test_recursing_token_is_rejected_not_raised(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertFalse(cloudflared_svc.token_looks_valid(Recursing()))


class WriteTokenTests(unittest.TestCase):
    def test_dummy_paste_is_coded_invalid_token(self):
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc.start_with_token("t" * 40)
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.invalid_token")

    def test_write_token_rejects_dummy(self):
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc._write_token("t" * 40)
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.invalid_token")

    def test_write_launchagent_rejects_saved_dummy(self):
        tmp = Path(tempfile.mkdtemp(prefix="serverhub-cf-dummy-"))
        token = tmp / "tunnel.token"
        token.write_text("t" * 40)
        with (
            mock.patch.object(cloudflared_svc, "TOKEN_FILE", token),
            mock.patch.object(cloudflared_svc, "_ensure_dirs", lambda: None),
        ):
            with self.assertRaises(HTTPException) as ctx:
                cloudflared_svc._write_launchagent_token()
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.invalid_token")


class BootstrapCrashLoopTests(unittest.TestCase):
    def test_died_process_is_booted_out_and_not_ok(self):
        with (
            mock.patch.object(cloudflared_svc, "_launchctl_bootout") as bootout,
            mock.patch.object(cloudflared_svc, "_path_is_file", return_value=True),
            mock.patch.object(
                cloudflared_svc, "sh",
                return_value=(0, "", ""),
            ),
            mock.patch.object(cloudflared_svc, "_forget_host_state"),
            mock.patch.object(cloudflared_svc, "_is_running", return_value=False),
            mock.patch.object(
                cloudflared_svc, "_launchd_job_info",
                return_value={
                    "loaded": True,
                    "running": False,
                    "state": "spawn scheduled",
                    "runs": 12,
                    "last_exit": 255,
                },
            ),
            mock.patch.object(
                cloudflared_svc, "_recent_tunnel_error",
                return_value=(
                    "Provided tunnel token is not valid. "
                    "Paste a Zero Trust tunnel token (it starts with eyJ)."
                ),
            ),
            mock.patch.object(cloudflared_svc.time, "sleep"),
        ):
            result = cloudflared_svc._launchctl_bootstrap()
        self.assertFalse(result["ok"])
        self.assertIn("token is not valid", result["message"].lower())
        # bootout at the start of bootstrap, then again after the crash loop.
        self.assertGreaterEqual(bootout.call_count, 2)

    def test_start_failed_is_coded_after_bootstrap_death(self):
        with (
            mock.patch.object(cloudflared_svc, "_write_token"),
            mock.patch.object(cloudflared_svc, "_write_launchagent_token"),
            mock.patch.object(
                cloudflared_svc, "_launchctl_bootstrap",
                return_value={"ok": False, "message": "cloudflared exited with code 255"},
            ),
            mock.patch.object(cloudflared_svc, "token_looks_valid", return_value=True),
        ):
            with self.assertRaises(HTTPException) as ctx:
                cloudflared_svc.start_with_token(FAKE_COMPACT)
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.start_failed")

    def test_invalid_token_log_maps_to_invalid_token_code(self):
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc._raise_if_start_failed({
                "ok": False,
                "message": (
                    "Provided tunnel token is not valid. "
                    "Paste a Zero Trust tunnel token (it starts with eyJ)."
                ),
            })
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.invalid_token")

    def test_parse_spawn_scheduled_print(self):
        parsed = cloudflared_svc._parse_launchctl_print(
            "state = spawn scheduled\n\truns = 4826\n\tlast exit code = 255\n"
        )
        self.assertEqual(parsed["state"], "spawn scheduled")
        self.assertEqual(parsed["runs"], 4826)
        self.assertEqual(parsed["last_exit"], 255)


class StatusCrashLoopTests(unittest.TestCase):
    def test_status_surfaces_crash_loop_and_bad_token(self):
        with (
            mock.patch.object(cloudflared_svc, "_ensure_dirs"),
            mock.patch.object(cloudflared_svc, "_load_state", return_value={"mode": "token"}),
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=False),
            mock.patch.object(cloudflared_svc, "_is_running", return_value=False),
            mock.patch.object(cloudflared_svc, "_bin", return_value="/opt/homebrew/bin/cloudflared"),
            mock.patch.object(cloudflared_svc, "_login_process_pending", return_value=False),
            mock.patch.object(cloudflared_svc, "_path_is_file", return_value=True),
            mock.patch.object(cloudflared_svc, "_read_saved_token", return_value="t" * 40),
            mock.patch.object(
                cloudflared_svc, "_launchd_job_info",
                return_value={
                    "loaded": True,
                    "running": False,
                    "state": "spawn scheduled",
                    "runs": 99,
                    "last_exit": 255,
                },
            ),
            mock.patch.object(
                cloudflared_svc, "_recent_tunnel_error",
                return_value="Provided tunnel token is not valid.",
            ),
            mock.patch.object(cloudflared_svc, "LOGIN_URL_FILE") as urlfile,
        ):
            urlfile.is_file.return_value = False
            snap = cloudflared_svc.status()
        json.dumps(snap, allow_nan=False)
        self.assertTrue(snap["crash_loop"])
        self.assertFalse(snap["token_ok"])
        self.assertEqual(snap["last_exit"], 255)
        self.assertIn("token is not valid", snap["status_text"].lower())
