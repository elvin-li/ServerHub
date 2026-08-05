"""A brew start/stop must drop the shared `brew services list --json` snapshot.

``hub.brew_cache`` memoises that command for 6 seconds because it costs ~1.3s
and four modules want it inside a single request.  The mutating paths --
``brew_svc.service_action``, ``autostart_svc.set_brew_autostart``, and the
native catalog's install/uninstall -- change exactly what the snapshot reports
on, so anything still holding the cached copy answers with the pre-action
state.  The observable symptom is a service that stays "started" in the UI for
up to 6 seconds after the user stops it, and an autostart toggle that snaps
back to its old position on the refresh that follows the click.

These tests pin the invalidation to the mutators rather than to the cache's
TTL, so shortening or lengthening ``_TTL`` cannot silently reintroduce the lag.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import brew_cache  # noqa: E402


class _FakeProc:
    """Stand-in for a completed `subprocess.run` of a brew command."""

    def __init__(self, returncode: int = 0, stdout: str = "ok", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class BrewCacheInvalidationTests(unittest.TestCase):
    def setUp(self):
        # Start every test from a primed cache holding a recognisable snapshot,
        # so "was it dropped?" is a direct observation rather than an inference
        # from timing.
        self.addCleanup(brew_cache.invalidate_brew_services)
        self._prime()

    def _prime(self):
        with brew_cache._lock:
            brew_cache._cache["t"] = float("inf")
            brew_cache._cache["v"] = [{"name": "syncthing", "status": "started"}]

    def _cached(self):
        with brew_cache._lock:
            return brew_cache._cache["v"]

    def test_cache_is_primed_by_the_fixture(self):
        # Guards the fixture itself: if priming stopped working, every other
        # test here would pass trivially.
        self.assertIsNotNone(self._cached())
        self.assertEqual(brew_cache.brew_services()[0]["status"], "started")

    def test_invalidate_drops_the_snapshot(self):
        brew_cache.invalidate_brew_services()
        self.assertIsNone(self._cached())

    def test_service_action_invalidates_the_snapshot(self):
        from hub import brew_svc

        with patch("os.path.isfile", return_value=True), \
                patch("subprocess.run", return_value=_FakeProc()), \
                patch("hub.brew_svc.invalidate_status"):
            result = brew_svc.service_action("syncthing", "stop")

        self.assertTrue(result["ok"])
        self.assertIsNone(
            self._cached(),
            "brew_svc.service_action left the stale snapshot in place; the UI "
            "would report the pre-stop state for up to the cache TTL",
        )

    def test_service_action_invalidates_even_when_brew_reports_failure(self):
        # A non-zero exit does not mean nothing changed -- `brew services stop`
        # can unload the agent and still complain.  Assuming the snapshot is
        # still valid after a failure is exactly how a half-applied change
        # becomes invisible.
        from hub import brew_svc

        with patch("os.path.isfile", return_value=True), \
                patch("subprocess.run", return_value=_FakeProc(returncode=1, stderr="boom")), \
                patch("hub.brew_svc.invalidate_status"):
            result = brew_svc.service_action("syncthing", "restart")

        self.assertFalse(result["ok"])
        self.assertIsNone(self._cached())

    def test_service_action_rejects_bad_action_without_touching_the_cache(self):
        from fastapi import HTTPException

        from hub import brew_svc

        with self.assertRaises(HTTPException):
            brew_svc.service_action("syncthing", "obliterate")
        # Nothing ran, so the snapshot is still truthful and dropping it would
        # only cost a needless 1.3s subprocess on the next read.
        self.assertIsNotNone(self._cached())

    def test_set_brew_autostart_invalidates_the_snapshot(self):
        from hub import autostart_svc

        with patch.object(Path, "is_file", return_value=True), \
                patch("subprocess.run", return_value=_FakeProc()):
            result = autostart_svc.set_brew_autostart("syncthing", False)

        self.assertTrue(result["ok"])
        self.assertIsNone(
            self._cached(),
            "autostart_svc.set_brew_autostart left the stale snapshot in "
            "place; the toggle would snap back on the next refresh",
        )

    def test_set_brew_autostart_invalidates_on_failure_too(self):
        from hub import autostart_svc

        with patch.object(Path, "is_file", return_value=True), \
                patch("subprocess.run", return_value=_FakeProc(returncode=1, stderr="nope")):
            result = autostart_svc.set_brew_autostart("syncthing", True)

        self.assertFalse(result["ok"])
        self.assertIsNone(self._cached())

    def test_native_install_and_uninstall_invalidate_the_snapshot(self):
        # The native catalog installs formulae and starts their services, so it
        # invalidates for the same reason -- verified at the source level
        # because the real paths shell out to brew.
        src = (BASE / "hub" / "native_catalog.py").read_text(encoding="utf-8")
        self.assertIn("invalidate_brew_services", src)
        self.assertEqual(
            src.count("invalidate_brew_services()"),
            2,
            "expected both install_native and uninstall_native to drop the "
            "shared brew snapshot",
        )

    def test_mutators_import_the_invalidator(self):
        # An invalidation call that is not imported is an ImportError at module
        # load, which takes down every route rather than one endpoint.
        for module in ("brew_svc", "autostart_svc", "native_catalog"):
            src = (BASE / "hub" / f"{module}.py").read_text(encoding="utf-8")
            with self.subTest(module=module):
                self.assertIn(
                    "invalidate_brew_services",
                    src.split("\n\n")[0] + src,
                    f"hub/{module}.py calls the invalidator without importing it",
                )
                self.assertRegex(
                    src,
                    r"from hub\.brew_cache import [^\n]*invalidate_brew_services",
                )


if __name__ == "__main__":
    unittest.main()
