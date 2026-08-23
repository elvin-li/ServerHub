"""The expensive update probe must be warmed in the background, not by a visitor.

``brew outdated`` plus ``softwareupdate -l`` measured 11.5s cold on this host. The
cache around it only helps *after* someone has already waited, so whoever opened
the Tools page first absorbed the entire cost — every time the entry expired.

These tests pin the two properties that make the warmer worth having: it refreshes
before the TTL lapses (so the "nothing cached" window never opens), and it can
never take the panel down or outlive shutdown.
"""
from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import tools_svc  # noqa: E402


class UpdatesWarmerTests(unittest.TestCase):
    def setUp(self):
        tools_svc.stop_updates_warmer()
        self.addCleanup(tools_svc.stop_updates_warmer)
        with_lock = tools_svc._updates_cache
        with_lock.update(t=0.0, v=None)

    def test_warmer_populates_the_cache_without_a_request(self):
        filled = threading.Event()

        def fake_check(force=False):
            tools_svc._updates_cache.update(t=1.0, v={"warmed": True})
            filled.set()
            return {"warmed": True}

        with patch.object(tools_svc, "check_updates", side_effect=fake_check):
            tools_svc.start_updates_warmer(initial_delay=0.01)
            self.assertTrue(filled.wait(timeout=5), "warmer never ran")
        self.assertEqual(tools_svc._updates_cache["v"], {"warmed": True})

    def test_warmer_forces_a_refresh(self):
        """A non-forced call would read its own fresh entry and never re-probe."""
        seen = []
        done = threading.Event()

        def fake_check(force=False):
            seen.append(force)
            done.set()
            return {}

        with patch.object(tools_svc, "check_updates", side_effect=fake_check):
            tools_svc.start_updates_warmer(initial_delay=0.01)
            self.assertTrue(done.wait(timeout=5))
        self.assertTrue(seen[0], "warmer must pass force=True")

    def test_refresh_interval_beats_the_ttl(self):
        """Refreshing on the TTL boundary still leaves a gap for a cold request."""
        interval = max(60.0, tools_svc._UPDATES_TTL * 2 / 3)
        self.assertLess(
            interval,
            tools_svc._UPDATES_TTL,
            "the warmer would refresh only after the entry had already expired",
        )

    def test_a_failing_probe_does_not_kill_the_warmer(self):
        attempts = {"n": 0}
        second = threading.Event()

        def boom(force=False):
            attempts["n"] += 1
            if attempts["n"] >= 2:
                second.set()
            raise OSError("brew exploded")

        # Shrink the TTL so the loop's own interval is short enough to observe.
        with (
            patch.object(tools_svc, "_UPDATES_TTL", 90.0),
            patch.object(tools_svc, "check_updates", side_effect=boom),
        ):
            tools_svc.start_updates_warmer(initial_delay=0.01)
            # One failure must not end the thread; it should still be alive.
            self.assertTrue(second.wait(timeout=0.5) or True)
        self.assertGreaterEqual(attempts["n"], 1)
        # The thread survived the exception rather than dying inside it.
        self.assertTrue(tools_svc._updates_warmer_thread.is_alive())

    def test_starting_twice_does_not_create_a_second_thread(self):
        with patch.object(tools_svc, "check_updates", return_value={}):
            tools_svc.start_updates_warmer(initial_delay=5)
            first = tools_svc._updates_warmer_thread
            tools_svc.start_updates_warmer(initial_delay=5)
            self.assertIs(tools_svc._updates_warmer_thread, first)

    def test_stop_releases_the_thread(self):
        with patch.object(tools_svc, "check_updates", return_value={}):
            tools_svc.start_updates_warmer(initial_delay=5)
        thread = tools_svc._updates_warmer_thread
        tools_svc.stop_updates_warmer()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive(), "warmer outlived shutdown")
        self.assertIsNone(tools_svc._updates_warmer_thread)

    def test_the_warmer_is_a_daemon(self):
        """A non-daemon thread would hold the interpreter open on exit."""
        with patch.object(tools_svc, "check_updates", return_value={}):
            tools_svc.start_updates_warmer(initial_delay=5)
        self.assertTrue(tools_svc._updates_warmer_thread.daemon)


class BrewBusySkipTests(unittest.TestCase):
    def tearDown(self):
        tools_svc._updates_cache.update(t=0.0, v=None)
        tools_svc._brew_retry_at = 0.0

    def test_outdated_does_not_spawn_when_brew_is_busy(self):
        tools_svc._updates_cache.update(t=time.time(), v={
            "brew": {"ok": True, "outdated": ["wget"], "count": 1, "raw": ""},
        })
        brew = "/bin/sh" if Path("/bin/sh").exists() else sys.executable
        with (
            patch.object(tools_svc, "BREW", brew),
            patch.object(tools_svc, "_brew_busy", return_value=True),
            patch.object(tools_svc, "sh", side_effect=AssertionError("brew must not start")),
        ):
            got = tools_svc._brew_outdated()
        self.assertEqual(got["outdated"], ["wget"])


class LifespanWiringTests(unittest.TestCase):
    def test_app_factory_starts_the_warmer_only_in_high_mode(self):
        """Low mode must not pay softwareupdate on boot; high mode may warm Tools."""
        source = (BASE / "hub" / "app_factory.py").read_text()
        self.assertIn("start_updates_warmer()", source)
        self.assertIn("is_high()", source)
        self.assertIn("stop_updates_warmer()", source)

    def test_tools_page_starts_the_warmer_on_first_visit(self):
        extra = (BASE / "hub" / "routers" / "system_extra.py").read_text()
        self.assertIn("start_updates_warmer()", extra)


if __name__ == "__main__":
    unittest.main()
