"""Leftover 500s / silent losses in the usage + stale-runtime domain.

Four leftovers, each reproduced before the fix:

* ``stale_runtime.pid_exe_path`` of a leftover already-int pid past CPython's
  4300-digit cap ValueError'd ``str(n)`` inside the ps argv and 500'd
  GET /api/health/checks / /api/apps/managed (``int(pid)`` passes an
  already-int through untouched — only a str() probe catches it).
* ``pid_exe_path(True)``: bool is an int, so ``int(True)`` probed pid 1 and
  answered /sbin/launchd for a process that never existed.
* A leftover ``<integer>0x…</integer>`` plist Label parses into an over-cap
  int (hex bypasses the int(str) cap), which ``_as_text`` scrubbed to ""
  — silently dropping the stale agent from scan() and the health page.
* POST /api/storage/spotlight with a vanished mdutil answered the generic
  500 ``admin.failed`` instead of the coded 503 (raid.diskutil_missing /
  smart.smartctl_missing convention: fresh disk probe on the failure path
  only; timeouts and authorization failures keep their original shape).
"""
from __future__ import annotations

import json
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import stale_runtime, usage_svc
from hub.errors import CODES
from hub.routers import nas_storage


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


#: ~5300 decimal digits once parsed — past CPython's int<->str digit cap.
_HEX_OVER_CAP = "0x" + "F" * 4400


def _plist_with_hex_label() -> bytes:
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        b'<plist version="1.0"><dict>'
        b"<key>Label</key><integer>" + _HEX_OVER_CAP.encode() + b"</integer>"
        b"</dict></plist>"
    )


class PidExePathBoolAndDigitPinTests(unittest.TestCase):
    def setUp(self):
        stale_runtime.invalidate_exe_cache()
        self.addCleanup(stale_runtime.invalidate_exe_cache)

    def test_over_cap_already_int_pid_answers_none_not_a_500(self):
        """Pre-fix: str(n) in the ps argv raised the digit-cap ValueError."""
        self.assertIsNone(stale_runtime.pid_exe_path(10 ** 5000))

    def test_over_cap_digit_string_pid_answers_none_too(self):
        self.assertIsNone(stale_runtime.pid_exe_path("9" * 5000))

    def test_bool_pid_never_probes_pid_one(self):
        """Pre-fix: int(True) probed pid 1 and answered launchd's own exe."""
        calls = []

        def probe(cmd, timeout=10, **kw):
            calls.append(list(cmd))
            return 0, "/sbin/launchd", ""

        with (
            mock.patch.object(stale_runtime, "sh", probe),
            mock.patch.object(stale_runtime, "_LIBC", None),
        ):
            self.assertIsNone(stale_runtime.pid_exe_path(True))
            self.assertIsNone(stale_runtime.pid_exe_path(False))
        self.assertEqual(calls, [])

    def test_sane_pid_still_probes_and_answers(self):
        def probe(cmd, timeout=10, **kw):
            return 0, "/usr/bin/python3 -m foo", ""

        with (
            mock.patch.object(stale_runtime, "sh", probe),
            mock.patch.object(stale_runtime, "_LIBC", None),
        ):
            self.assertEqual(
                stale_runtime.pid_exe_path("4242"), "/usr/bin/python3",
            )


class ScanHexIntLabelPinTests(unittest.TestCase):
    def test_hex_int_label_falls_back_to_the_plist_name(self):
        """Pre-fix: the over-cap Label scrubbed to "" and the stale agent
        silently vanished from scan() and GET /api/health/checks."""

        class _Listing:
            def pid_for(self, label):
                return "4242" if label == "local.x" else None

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "local.x.plist").write_bytes(_plist_with_hex_label())
            with (
                mock.patch.object(stale_runtime, "AGENTS_DIR", Path(tmp)),
                mock.patch.object(stale_runtime, "launchd_listing", lambda: _Listing()),
                mock.patch.object(stale_runtime, "pid_exe_path", lambda pid: "/gone"),
            ):
                rows = stale_runtime.scan()
        _starlette(rows)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], "local.x")
        self.assertEqual(rows[0]["pid"], 4242)

    def test_string_label_still_wins_over_the_filename(self):
        class _Listing:
            def pid_for(self, label):
                return "4242" if label == "local.real" else None

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "local.x.plist").write_bytes(
                plistlib.dumps({"Label": "local.real"})
            )
            with (
                mock.patch.object(stale_runtime, "AGENTS_DIR", Path(tmp)),
                mock.patch.object(stale_runtime, "launchd_listing", lambda: _Listing()),
                mock.patch.object(stale_runtime, "pid_exe_path", lambda pid: "/gone"),
            ):
                rows = stale_runtime.scan()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], "local.real")

    def test_over_cap_already_int_listing_pid_renders_zero_not_a_500(self):
        """A leftover over-cap int pid passes int() untouched; pre-fix the
        digit-cap ValueError landed in the JSON encoder for the row."""

        class _Listing:
            def pid_for(self, label):
                return 10 ** 5000

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "local.x.plist").write_bytes(
                plistlib.dumps({"Label": "local.x"})
            )
            with (
                mock.patch.object(stale_runtime, "AGENTS_DIR", Path(tmp)),
                mock.patch.object(stale_runtime, "launchd_listing", lambda: _Listing()),
                mock.patch.object(stale_runtime, "pid_exe_path", lambda pid: "/gone"),
            ):
                rows = stale_runtime.scan()
                checks = stale_runtime.health_checks()
        _starlette(rows)
        _starlette(checks)
        self.assertEqual(rows[0]["pid"], 0)

    def test_bool_listing_pid_skips_the_row_not_the_scan(self):
        class _Listing:
            def pid_for(self, label):
                return True

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "local.x.plist").write_bytes(
                plistlib.dumps({"Label": "local.x"})
            )
            with (
                mock.patch.object(stale_runtime, "AGENTS_DIR", Path(tmp)),
                mock.patch.object(stale_runtime, "launchd_listing", lambda: _Listing()),
                mock.patch.object(stale_runtime, "pid_exe_path", lambda pid: "/gone"),
            ):
                rows = stale_runtime.scan()
        _starlette(rows)
        self.assertEqual(rows, [])


class SpotlightVanishedMdutilTests(unittest.TestCase):
    """The vanished-CLI 503 fires only after a fresh disk probe confirms the
    gone binary, and only on the mutation-failure path."""

    VANISHED = {
        "ok": False, "error": "failed",
        "message": "sh: /usr/bin/mdutil: command not found",
    }

    def _toggle(self, admin_result, on_disk):
        probe = mock.Mock(return_value=on_disk)
        with (
            mock.patch.object(
                usage_svc, "spotlight_status", return_value=[{"volume": "/"}],
            ),
            mock.patch("hub.macos_admin.run_admin", return_value=dict(admin_result)),
            mock.patch.object(usage_svc, "_mdutil_on_disk", probe),
        ):
            result = usage_svc.set_spotlight("/", True)
        return result, probe

    def test_code_status_is_503(self):
        """A demotion would silently turn "the tool is gone" back into a
        generic failure (raid.diskutil_missing / smart.smartctl_missing rule)."""
        self.assertEqual(CODES["usage.mdutil_missing"][0], 503)

    def test_confirmed_gone_classifies(self):
        """Pre-fix this answered the generic 500 ``admin.failed``."""
        result, probe = self._toggle(self.VANISHED, on_disk=False)
        self.assertEqual(result, {"ok": False, "error": "mdutil_missing"})
        probe.assert_called_once_with()

    def test_router_funnel_answers_the_coded_503(self):
        with (
            mock.patch.object(nas_storage, "require_admin_browser", return_value="admin"),
            mock.patch.object(nas_storage, "client_host", return_value="127.0.0.1"),
            mock.patch.object(nas_storage.audit, "record", lambda *a, **k: {}),
            mock.patch.object(
                usage_svc, "spotlight_status", return_value=[{"volume": "/"}],
            ),
            mock.patch("hub.macos_admin.run_admin", return_value=dict(self.VANISHED)),
            mock.patch.object(usage_svc, "_mdutil_on_disk", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                nas_storage.api_storage_spotlight(
                    nas_storage.SpotlightBody(volume="/", enabled=True),
                    mock.Mock(),
                )
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail["code"], "usage.mdutil_missing")

    def test_still_on_disk_keeps_the_raw_failure(self):
        """execve also ENOENTs for a still-present binary whose loader is
        broken: with mdutil confirmably on disk the raw failure is the
        truth, never the tool-absent 503."""
        result, probe = self._toggle(self.VANISHED, on_disk=True)
        self.assertEqual(result["error"], "failed")
        self.assertIn("command not found", result["message"])
        probe.assert_called_once_with()

    def test_non_spawn_message_never_probes(self):
        """A timeout / genuine mdutil exit is not a missing binary: no
        second filesystem look, the original shape survives."""
        result, probe = self._toggle(
            {"ok": False, "error": "failed", "message": "sudo timeout"},
            on_disk=False,
        )
        self.assertEqual(result["error"], "failed")
        probe.assert_not_called()

    def test_authorization_failures_are_never_reclassified(self):
        for error in ("password_required", "password_incorrect", "unavailable"):
            with self.subTest(error=error):
                result, probe = self._toggle(
                    {"ok": False, "error": error}, on_disk=False,
                )
                self.assertEqual(result["error"], error)
                probe.assert_not_called()

    def test_success_path_never_probes(self):
        result, probe = self._toggle({"ok": True}, on_disk=False)
        self.assertTrue(result["ok"])
        self.assertEqual(result["volume"], "/")
        self.assertTrue(result["enabled"])
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
