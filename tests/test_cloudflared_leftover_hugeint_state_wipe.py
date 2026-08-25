"""Leftover over-cap ints and numeric ids around the cloudflared state journal.

``json.loads`` of a >4300-digit number literal raises *bare ValueError* (the
decoder's own ``int()`` conversion under CPython's digit cap), not
JSONDecodeError.  ``_load_state`` treated that as a corrupt document, so one
over-cap counter written by an operator script into serverhub-state.json:

- wiped the whole journal to ``{}`` — GET /api/cloudflared/status (and the
  Apps page detail) silently lost ``active_tunnel`` / ``mode``,
- made POST /api/cloudflared/restart answer "Nothing to restart",
- and the next read-modify-write (start / uninstall) persisted the wipe,
  destroying every sibling key on disk.

Separately, an unquoted ``tunnel_name: 123`` parsed as an int, and the plain
``isinstance(value, str)`` gate in ``_tunnel_argv`` refused to restart tunnel
"123" with a coded 400 — a silently-dropped numeric id.

Stays-immune pins: surrogate escapes in state keys AND values loaded from
disk, an already-int over-cap leftover reaching the encoder, and an over-cap
int inside a pasted compact token.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import cloudflared_svc

OVER_CAP_DIGITS = sys.get_int_max_str_digits() + 100
OVER_CAP_LITERAL = "1" * OVER_CAP_DIGITS


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _StateFileHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf-state-")
        self.addCleanup(self.tmp.cleanup)
        self.state_file = Path(self.tmp.name) / "serverhub-state.json"
        for name, value in (
            ("STATE_FILE", self.state_file),
            ("_ensure_dirs", mock.Mock()),
        ):
            patcher = mock.patch.object(cloudflared_svc, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)


class HugeIntStateJournalTests(_StateFileHarness):
    def test_over_cap_literal_does_not_wipe_load_state(self):
        """One over-cap counter used to wipe the whole journal to {}."""
        self.state_file.write_text(
            '{"mode": "token", "tunnel_name": "home", "leftover_counter": %s}'
            % OVER_CAP_LITERAL
        )
        st = cloudflared_svc._load_state()
        self.assertEqual(st.get("tunnel_name"), "home")
        self.assertEqual(st.get("mode"), "token")
        self.assertIsNone(st.get("leftover_counter"))
        _starlette(st)

    def test_over_cap_literal_does_not_hide_active_tunnel_in_status(self):
        """GET /api/cloudflared/status silently lost active_tunnel / mode."""
        self.state_file.write_text(
            '{"mode": "token", "tunnel_name": "home", "leftover_counter": %s}'
            % OVER_CAP_LITERAL
        )
        with (
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=False),
            mock.patch.object(cloudflared_svc, "_is_running", return_value=False),
            mock.patch.object(cloudflared_svc, "_bin", side_effect=Exception("no")),
            mock.patch.object(
                cloudflared_svc, "_login_process_pending", return_value=False
            ),
            mock.patch.object(cloudflared_svc, "_read_login_url", return_value=None),
            mock.patch.object(
                cloudflared_svc, "_path_is_file",
                side_effect=lambda p: Path(p) == self.state_file,
            ),
        ):
            snap = cloudflared_svc.status()
        _starlette(snap)
        self.assertEqual(snap["active_tunnel"], "home")
        self.assertEqual(snap["mode"], "token")

    def test_over_cap_literal_read_modify_write_keeps_siblings(self):
        """The next _load_state → _save_state used to persist the wipe."""
        self.state_file.write_text(
            '{"mode": "token", "tunnel_name": "home", "extra": "keep",'
            ' "leftover_counter": %s}' % OVER_CAP_LITERAL
        )
        st = cloudflared_svc._load_state()
        st.update({"mode": "token", "tunnel_name": "home", "updated": 1.0})
        cloudflared_svc._save_state(st)
        raw = json.loads(self.state_file.read_text())
        self.assertEqual(raw["extra"], "keep")
        self.assertEqual(raw["tunnel_name"], "home")
        self.assertIsNone(raw["leftover_counter"])
        json.dumps(raw, allow_nan=False)

    def test_over_cap_literal_does_not_break_restart(self):
        """POST /api/cloudflared/restart used to answer "Nothing to restart"."""
        self.state_file.write_text(
            '{"mode": "token", "tunnel_name": "home", "leftover_counter": %s}'
            % OVER_CAP_LITERAL
        )
        with (
            mock.patch.object(cloudflared_svc, "_path_is_file", return_value=True),
            mock.patch.object(cloudflared_svc, "token_looks_valid", return_value=True),
            mock.patch.object(cloudflared_svc, "_read_saved_token", return_value="ok"),
            mock.patch.object(cloudflared_svc, "_write_launchagent_token"),
            mock.patch.object(
                cloudflared_svc, "_launchctl_bootstrap", return_value={"ok": True}
            ),
        ):
            out = cloudflared_svc.restart()
        _starlette(out)
        self.assertTrue(out["ok"])
        self.assertEqual(out["active_tunnel"], "home")


class NumericTunnelNameTests(_StateFileHarness):
    def test_numeric_tunnel_name_restarts_instead_of_400(self):
        """Unquoted ``tunnel_name: 123`` was silently refused as invalid_name."""
        self.state_file.write_text('{"tunnel_name": 123}')
        with (
            mock.patch.object(
                cloudflared_svc, "_path_is_file",
                side_effect=lambda p: Path(p) == self.state_file,
            ),
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=True),
            mock.patch.object(
                cloudflared_svc, "start_with_tunnel",
                wraps=lambda tunnel: {"ok": True, "active_tunnel": tunnel},
            ) as start,
        ):
            out = cloudflared_svc.restart()
        self.assertTrue(out["ok"])
        start.assert_called_once_with(123)
        self.assertEqual(cloudflared_svc._tunnel_argv(123), "123")

    def test_over_cap_int_tunnel_is_coded_400_not_500(self):
        """A leftover over-cap int id must stay a coded error, never a bare
        ValueError from ``str()`` under the digit cap."""
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc._tunnel_argv(10 ** (OVER_CAP_DIGITS - 1))
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.invalid_name")

    def test_bool_tunnel_is_coded_400(self):
        """``tunnel_name: true`` is junk, not tunnel "True"."""
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc._tunnel_argv(True)
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.invalid_name")


class StaysImmuneTests(_StateFileHarness):
    def test_surrogate_escape_keys_and_values_from_disk_do_not_500(self):
        """Stays-immune: ``\\ud800`` escapes in state keys AND values."""
        self.state_file.write_text(
            '{"tunnel_name": "home\\ud800", "mode\\ud800": "token\\ud800"}'
        )
        st = cloudflared_svc._load_state()
        _starlette(st)
        blob = json.dumps(st, ensure_ascii=False)
        self.assertNotIn("\ud800", blob)
        self.assertEqual(st["tunnel_name"], "home?")

    def test_already_int_over_cap_leftover_is_dropped_not_500(self):
        """Stays-immune: an over-cap int object reaching the encoder is nulled."""
        out = cloudflared_svc._jsonable_state(
            {"updated": 10 ** (OVER_CAP_DIGITS - 1), "tunnel_name": "home"}
        )
        _starlette(out)
        self.assertIsNone(out["updated"])
        self.assertEqual(out["tunnel_name"], "home")

    def test_over_cap_int_in_pasted_compact_token_is_coded_not_500(self):
        """Stays-immune: json.loads ValueError inside a pasted token stays a
        coded invalid-token, never a 500."""
        import base64

        blob = ('{"a": %s}' % OVER_CAP_LITERAL).encode("ascii")
        token = base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")
        # Compact connector tokens start with base64("{\"") == "eyJ".
        self.assertTrue(token.startswith("eyJ"))
        self.assertFalse(cloudflared_svc.token_looks_valid(token))
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc.start_with_token(token)
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.invalid_token")


if __name__ == "__main__":
    unittest.main()
