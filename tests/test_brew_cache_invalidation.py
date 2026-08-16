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
        """Both paths must drop the shared brew snapshot.

        Asserted through the helper rather than by counting raw
        ``invalidate_brew_services()`` occurrences.  That count was 2 when install and
        uninstall each inlined the call; they now share ``_stale_app_views()``, which
        ``_single_flight()`` runs *both before and after* the operation -- so the
        occurrence count is 1 while the guarantee is strictly stronger than it was.
        Counting call sites made the refactor look like a regression.
        """
        src = (BASE / "hub" / "native_catalog.py").read_text(encoding="utf-8")
        self.assertIn("invalidate_brew_services", src)

        views = src.index("def _stale_app_views")
        body = src[views: src.index("\ndef ", views + 10)]
        self.assertIn(
            "invalidate_brew_services()", body,
            "_stale_app_views no longer drops the shared brew snapshot",
        )

        flight = src.index("def _single_flight")
        flight_body = src[flight: src.index("\ndef ", flight + 10)]
        self.assertEqual(
            flight_body.count("_stale_app_views()"), 2,
            "an install can take minutes: the snapshot has to be dropped before it "
            "as well as after, or a read arriving during it refills the cache with "
            "pre-install state and gives it a fresh timestamp",
        )

        for entry in ("def install_native", "def uninstall_native"):
            start = src.index(entry)
            self.assertIn(
                "_single_flight(app_id)", src[start: src.index("\ndef ", start + 10)],
                f"{entry} does not go through the invalidating guard",
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


class BrewCacheStaleWhileRevalidateTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(brew_cache.invalidate_brew_services)
        brew_cache.invalidate_brew_services()

    def test_an_expired_snapshot_is_served_without_waiting_for_brew(self):
        with brew_cache._lock:
            brew_cache._cache["t"] = 1.0
            brew_cache._cache["v"] = [{"name": "syncthing", "status": "started"}]
        with patch.object(brew_cache, "_load", return_value=[{"name": "syncthing", "status": "stopped"}]):
            got = brew_cache.brew_services()
        self.assertEqual(got[0]["status"], "started")

    def test_invalidate_does_not_reuse_the_on_disk_snapshot(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "brew-services.cache.json"
            path.write_text('[{"name":"x","status":"started"}]', encoding="utf-8")
            with (
                patch.object(brew_cache, "_DISK", path),
                patch.object(
                    brew_cache, "_load",
                    return_value=[{"name": "x", "status": "fresh"}],
                ) as load,
            ):
                brew_cache.invalidate_brew_services()
                got = brew_cache.brew_services()
        self.assertEqual(got[0]["status"], "fresh")
        load.assert_called()


class BrewCacheTimeoutKeepsSnapshotTests(unittest.TestCase):
    """A hung `brew services list` must not wipe the last good snapshot.

    `_load` used to treat a timeout as "zero services" and write `[]` to
    disk.  Health then rendered no brew rows for the whole TTL, and the
    next refresh logged another timeout into serverhub.err.log.
    """

    def setUp(self):
        self.addCleanup(brew_cache.invalidate_brew_services)
        brew_cache.invalidate_brew_services()

    def test_timeout_keeps_the_in_memory_snapshot(self):
        with brew_cache._lock:
            brew_cache._cache["t"] = 1.0
            brew_cache._cache["v"] = [{"name": "syncthing", "status": "started"}]
        with patch.object(brew_cache, "sh", return_value=(-1, "", "timeout")):
            got = brew_cache._load()
        self.assertEqual(got, [{"name": "syncthing", "status": "started"}])

    def test_timeout_does_not_replace_disk_with_an_empty_list(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "brew-services.cache.json"
            path.write_text('[{"name":"x","status":"started"}]', encoding="utf-8")
            with (
                patch.object(brew_cache, "_DISK", path),
                patch.object(brew_cache, "sh", return_value=(-1, "", "timeout")),
            ):
                brew_cache._disk_ok = True
                got = brew_cache._load()
            self.assertEqual(got[0]["status"], "started")
            on_disk = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(on_disk[0]["status"], "started")

    def test_busy_brew_keeps_the_snapshot_without_spawning(self):
        with brew_cache._lock:
            brew_cache._cache["t"] = 1.0
            brew_cache._cache["v"] = [{"name": "syncthing", "status": "started"}]
        with (
            patch.object(brew_cache, "_brew_busy", return_value=True),
            patch.object(brew_cache, "sh", side_effect=AssertionError("brew must not start")),
        ):
            got = brew_cache._load()
        self.assertEqual(got, [{"name": "syncthing", "status": "started"}])


if __name__ == "__main__":
    unittest.main()
