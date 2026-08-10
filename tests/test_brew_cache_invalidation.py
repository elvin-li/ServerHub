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
        """The native catalog installs formulae and starts their services.

        This used to count occurrences of ``invalidate_brew_services()`` in the
        source and require exactly two.  Both entry points now share one
        invalidation helper, so that count measured the shape of the code rather
        than the behaviour -- it failed the moment the duplication was removed,
        and would have passed happily if both calls had been left in place and
        moved somewhere unreachable.

        Executors are sealed with ``sh`` and ``subprocess.run`` before either
        installer is called: unsealed, these two reach the host's real Homebrew
        (see tests/test_tests_do_not_mutate_the_host.py).  BREW points at this
        interpreter so the "is Homebrew present?" guard passes on any host.
        """
        from hub import native_catalog

        for fn in (native_catalog.install_native, native_catalog.uninstall_native):
            self._prime()
            with patch.object(native_catalog, "sh", return_value=(0, "", "")), \
                    patch.object(native_catalog, "BREW", sys.executable), \
                    patch.object(native_catalog, "log"), \
                    patch.object(native_catalog, "_brew_list_installed", return_value=set()), \
                    patch.object(native_catalog.subprocess, "run", return_value=_FakeProc()):
                fn("native-syncthing")
            with self.subTest(fn=fn.__name__):
                self.assertIsNone(
                    self._cached(),
                    f"{fn.__name__} left the shared brew snapshot in place, so the "
                    "service it just started or stopped keeps reporting its "
                    "previous state",
                )

    def test_the_invalidation_also_happens_after_the_operation(self):
        """A read that lands mid-install must not survive it.

        Invalidating only on entry is not enough: a brew install runs for
        minutes, and any refresh arriving during those minutes refills the caches
        with pre-install state and stamps it fresh.  The operator then watches a
        successful install go on reporting "not installed".
        """
        from hub import native_catalog

        def _refill_mid_install(*_args, **_kwargs):
            self._prime()
            return _FakeProc()

        self._prime()
        with patch.object(native_catalog, "sh", return_value=(0, "", "")), \
                patch.object(native_catalog, "BREW", sys.executable), \
                patch.object(native_catalog, "log"), \
                patch.object(native_catalog, "_brew_list_installed", return_value=set()), \
                patch.object(native_catalog.subprocess, "run", _refill_mid_install):
            native_catalog.install_native("native-syncthing")

        self.assertIsNone(
            self._cached(),
            "the snapshot taken while the install was running outlived it",
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
