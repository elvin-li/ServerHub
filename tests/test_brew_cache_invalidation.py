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
                patch.object(brew_svc, "run_capped", return_value=(0, "")), \
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
                patch.object(brew_svc, "run_capped", return_value=(1, "boom")), \
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
                patch.object(autostart_svc, "run_capped", return_value=(0, "")):
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
                patch.object(autostart_svc, "run_capped", return_value=(1, "nope")):
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

    def test_busy_without_a_snapshot_does_not_cache_emptiness(self):
        """invalidate + busy used to `_publish([])` and hide every brew row."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "brew-services.cache.json"
            with (
                patch.object(brew_cache, "_DISK", path),
                patch.object(brew_cache, "_brew_busy", return_value=True),
                patch.object(brew_cache, "sh", side_effect=AssertionError("brew must not start")),
            ):
                brew_cache.invalidate_brew_services()
                got = brew_cache._load()
        self.assertEqual(got, [])
        with brew_cache._lock:
            self.assertIsNone(brew_cache._cache["v"])

    def test_timeout_after_invalidate_serves_disk_not_empty(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "brew-services.cache.json"
            path.write_text('[{"name":"x","status":"started"}]', encoding="utf-8")
            with (
                patch.object(brew_cache, "_DISK", path),
                patch.object(brew_cache, "sh", return_value=(-1, "", "timeout")),
            ):
                brew_cache.invalidate_brew_services()
                got = brew_cache._load()
            self.assertEqual(got[0]["status"], "started")
            self.assertEqual(json.loads(path.read_text())[0]["status"], "started")

    def test_none_and_list_payloads_do_not_500(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "brew-services.cache.json"
            with (
                patch.object(brew_cache, "_DISK", path),
                patch.object(brew_cache, "_brew_busy", return_value=False),
            ):
                brew_cache.invalidate_brew_services()
                with patch.object(brew_cache, "sh", return_value=(0, None, "")):
                    self.assertEqual(brew_cache._load(), [])
                with patch.object(
                    brew_cache, "sh",
                    return_value=(0, [{"name": "syncthing", "status": "started"}], ""),
                ):
                    got = brew_cache._load()
        self.assertEqual(got[0]["name"], "syncthing")

    def test_in_flight_load_does_not_republish_after_invalidate(self):
        import threading

        started = threading.Event()
        release = threading.Event()

        def slow_sh(*args, **kwargs):
            started.set()
            self.assertTrue(release.wait(2), "in-flight load never released")
            return 0, '[{"name":"old","status":"started"}]', ""

        brew_cache.invalidate_brew_services()
        result = {}

        def worker():
            result["v"] = brew_cache.brew_services()

        with (
            patch.object(brew_cache, "_brew_busy", return_value=False),
            patch.object(brew_cache, "sh", slow_sh),
        ):
            thread = threading.Thread(target=worker)
            thread.start()
            self.assertTrue(started.wait(2), "load never started")
            brew_cache.invalidate_brew_services()
            release.set()
            thread.join(timeout=2)
        self.assertTrue(thread.is_alive() is False)
        with brew_cache._lock:
            self.assertIsNone(
                brew_cache._cache["v"],
                "in-flight brew list republished the pre-invalidate snapshot",
            )
        self.assertEqual(result["v"][0]["name"], "old")


class BrewBusyPatternTests(unittest.TestCase):
    """``pgrep -f /opt/homebrew/bin/brew`` matches any argv that mentions brew."""

    def test_patterns_anchor_argv0_and_include_brew_rb(self):
        wrapper, ruby = brew_cache._brew_argv_patterns()
        self.assertTrue(wrapper.startswith("^"), wrapper)
        self.assertIn("Homebrew/brew", ruby)
        self.assertNotEqual(wrapper, brew_cache.BREW)

    def test_busy_check_does_not_pass_the_bare_brew_path(self):
        seen = []

        def fake_run(argv, **kwargs):
            seen.append(list(argv))
            return _FakeProc(returncode=1, stdout="")

        with patch("subprocess.run", side_effect=fake_run):
            self.assertFalse(brew_cache._brew_busy())
        self.assertTrue(seen)
        for argv in seen:
            self.assertEqual(argv[:2], ["/usr/bin/pgrep", "-f"])
            self.assertNotEqual(argv[2], brew_cache.BREW)

    def test_a_hit_on_either_pattern_is_busy(self):
        calls = {"n": 0}

        def fake_run(argv, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return _FakeProc(returncode=1, stdout="")
            return _FakeProc(returncode=0, stdout="12345\n")

        with patch("subprocess.run", side_effect=fake_run):
            self.assertTrue(brew_cache._brew_busy())
        self.assertEqual(calls["n"], 2)

    def test_busy_reads_pids_from_the_temp_file_not_proc_stdout(self):
        def fake_run(argv, **kwargs):
            stdout = kwargs.get("stdout")
            stdout.write(b"4242\n")
            return _FakeProc(returncode=0, stdout=None)

        with patch("subprocess.run", side_effect=fake_run):
            self.assertTrue(brew_cache._brew_busy())

    def test_busy_check_does_not_capture_output(self):
        src = Path(brew_cache.__file__).read_text(encoding="utf-8")
        start = src.index("def _brew_busy")
        body = src[start: src.index("\ndef _load")]
        self.assertNotIn("capture_output=True", body)
        self.assertIn("TemporaryFile", body)


class BrewListTypingTests(unittest.TestCase):
    def test_non_string_status_does_not_500(self):
        from hub import brew_svc

        rows = [
            {"name": "syncthing", "status": True},
            {"name": "nginx", "status": "started"},
            "nope",
        ]
        with (
            patch("os.path.isfile", return_value=True),
            patch.object(brew_svc, "brew_services_list", return_value=rows),
        ):
            items = brew_svc.list_services()
        by_id = {i["id"]: i for i in items}
        self.assertEqual(by_id["syncthing"]["status"], "true")
        self.assertNotIn("nginx", by_id)


if __name__ == "__main__":
    unittest.main()
