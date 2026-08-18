"""`launchctl list` and `ps aux` are read once per request, by every module.

Both commands had a copy in three or four modules, each with its own timeout, its
own parse and its own cache (or none).  The duplication was invisible to any
measurement that groups spawns by argv, because two of the launchd copies spelled
the command ``launchctl`` and the others ``/bin/launchctl``.

Measured per endpoint, one process each, with a corrected fixture:

    /api/health/checks   9 spawns, 2 waves  ->  7 spawns
    /api/diagnostics    33 spawns, 2 waves  -> 32 spawns, 1 wave
    /api/services       12 spawns, 2 waves  -> 12 spawns, 1 wave
    /api/apps/managed   18 spawns, 6 waves  -> 17 spawns, 4 waves

These tests assert call counts, peak overlap, the loaded/running distinction and
the invalidation contract.  Not elapsed time: that would be a benchmark, and it
would fail on a loaded machine for reasons that have nothing to do with this code.
"""
from __future__ import annotations

import threading
import time
import unittest
from unittest import mock

from hub import launchd_cache, proc_cache

LISTING = (
    "PID\tStatus\tLabel\n"
    "4242\t0\tlocal.alpha\n"
    "-\t0\tlocal.watchdog\n"
    "1337\t0\thomebrew.mxcl.redis\n"
)

PS = (
    "USER  PID  COMMAND\n"
    "me    1    /usr/local/bin/cloudflared tunnel run --config /x.yml\n"
    "me    2    /opt/homebrew/bin/syncthing serve\n"
)


class _CountingSh:
    """Records every argv and answers from a fixture."""

    def __init__(self, out: str):
        self.out = out
        self.calls: list[list[str]] = []
        self.peak = 0
        self._live = 0
        self._lock = threading.Lock()

    def __call__(self, cmd, *a, **kw):
        with self._lock:
            self.calls.append([str(c) for c in cmd])
            self._live += 1
            self.peak = max(self.peak, self._live)
        # Long enough that genuinely concurrent callers overlap here rather than
        # finishing one after another and looking single-flight by accident.
        time.sleep(0.05)
        with self._lock:
            self._live -= 1
        return 0, self.out, ""


class LaunchdListingTests(unittest.TestCase):
    def setUp(self):
        launchd_cache.invalidate_launchd()
        self.addCleanup(launchd_cache.invalidate_launchd)

    def test_loaded_and_running_are_not_the_same_question(self):
        """A KeepAlive watchdog between wakeups is loaded, and has no pid.

        `immich_svc` asks whether its keepalive agent is loaded.  Answering with the
        running set would report a healthy watchdog as missing, and the panel would
        tell the operator to bootstrap an agent that is already there.
        """
        with mock.patch.object(launchd_cache, "sh", lambda *a, **k: (0, LISTING, "")):
            listing = launchd_cache.listing()

        self.assertIn("local.watchdog", listing.loaded)
        self.assertNotIn(
            "local.watchdog", listing.running,
            "a job launchd holds with no pid was reported as running",
        )
        self.assertIn("local.alpha", listing.running)

    def test_the_header_row_is_not_a_job(self):
        """`health_svc` tested the pid column for "not a dash", and `PID` passes it."""
        with mock.patch.object(launchd_cache, "sh", lambda *a, **k: (0, LISTING, "")):
            listing = launchd_cache.listing()

        self.assertNotIn("Label", listing.loaded)
        self.assertNotIn("Label", listing.running)

    def test_the_pid_column_survives_for_the_callers_that_report_it(self):
        """`nginx_svc` renders the pid, so label sets alone would not have served it."""
        with mock.patch.object(launchd_cache, "sh", lambda *a, **k: (0, LISTING, "")):
            listing = launchd_cache.listing()

        self.assertEqual(listing.pid_for("local.alpha"), "4242")
        self.assertIsNone(
            listing.pid_for("local.watchdog"), "a loaded job with no pid got one"
        )
        self.assertIsNone(listing.pid_for("local.absent"))

    def test_every_reader_in_one_request_shares_one_listing(self):
        """The four modules that each ran their own now cost one spawn between them."""
        from hub import autostart_svc, health_svc, immich_svc, nginx_svc

        counting = _CountingSh(LISTING)
        with mock.patch.object(launchd_cache, "sh", counting):
            health_svc._running_labels()
            autostart_svc._loaded_labels()
            nginx_svc.launchd_listing()
            self.assertIsInstance(immich_svc.loaded_labels(), frozenset)

        listings = [c for c in counting.calls if "list" in c]
        self.assertEqual(
            len(listings), 1,
            f"four readers cost {len(listings)} listings",
        )

    def test_concurrent_cold_readers_do_not_each_spawn(self):
        """These arrive together by construction: they are branches of one fan-out."""
        counting = _CountingSh(LISTING)
        with mock.patch.object(launchd_cache, "sh", counting):
            threads = [
                threading.Thread(target=launchd_cache.running_labels) for _ in range(8)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertEqual(
            len(counting.calls), 1,
            f"eight concurrent readers ran {len(counting.calls)} listings",
        )
        self.assertEqual(
            counting.peak, 1, "two listings were in flight at the same time"
        )

    def test_the_command_is_absolute(self):
        """A bare `launchctl` depends on PATH, which a LaunchAgent need not set."""
        counting = _CountingSh(LISTING)
        with mock.patch.object(launchd_cache, "sh", counting):
            launchd_cache.listing()

        self.assertEqual(counting.calls[0][0], "/bin/launchctl")

    def test_a_failed_listing_is_not_remembered_as_truth(self):
        """rc != 0 must not turn into "no job is loaded" for the whole TTL."""
        with mock.patch.object(launchd_cache, "sh", lambda *a, **k: (1, "", "boom")):
            self.assertEqual(launchd_cache.loaded_labels(), frozenset())

        # A caller reading an empty listing falls through to its own per-label probe,
        # which is a degraded answer rather than a false negative -- but the point
        # here is that `force` still gets a real read.
        with mock.patch.object(launchd_cache, "sh", lambda *a, **k: (0, LISTING, "")):
            self.assertIn("local.alpha", launchd_cache.loaded_labels(force=True))

    def test_the_cached_listing_cannot_be_mutated_by_a_caller(self):
        with mock.patch.object(launchd_cache, "sh", lambda *a, **k: (0, LISTING, "")):
            listing = launchd_cache.listing()

        with self.assertRaises(TypeError):
            listing.jobs["local.injected"] = ("1", "0")  # type: ignore[index]


class LaunchdInvalidationTests(unittest.TestCase):
    """A mutation followed by a read must not answer from before the mutation."""

    def setUp(self):
        launchd_cache.invalidate_launchd()
        self.addCleanup(launchd_cache.invalidate_launchd)

    def test_an_autostart_toggle_drops_the_listing(self):
        """Otherwise the refetch after the toggle reads the pre-toggle session.

        This is the failure the TTL would cause and the one an operator would see:
        flip the switch, the row comes back unchanged, and nothing in the log says
        why.
        """
        from hub import autostart_svc

        with mock.patch.object(launchd_cache, "sh", lambda *a, **k: (0, LISTING, "")):
            self.assertIn("local.alpha", autostart_svc._loaded_labels())

        dropped = []
        with (
            mock.patch.object(
                autostart_svc, "invalidate_launchd", lambda: dropped.append(1)
            ),
            mock.patch.object(autostart_svc, "sh", lambda *a, **k: (0, "", "")),
            mock.patch.object(autostart_svc, "_read_plist", lambda p: {"Label": "local.alpha"}),
            mock.patch.object(autostart_svc, "_write_plist", lambda p, d: None),
            mock.patch.object(autostart_svc.Path, "exists", lambda self: True),
        ):
            autostart_svc.set_launchd_autostart("local.alpha", False)

        self.assertTrue(dropped, "the toggle left the pre-change listing cached")

    def test_invalidate_forces_the_next_read_to_spawn(self):
        first = _CountingSh(LISTING)
        with mock.patch.object(launchd_cache, "sh", first):
            launchd_cache.loaded_labels()
            launchd_cache.loaded_labels()
            self.assertEqual(len(first.calls), 1, "the TTL did not hold")
            launchd_cache.invalidate_launchd()
            launchd_cache.loaded_labels()

        self.assertEqual(
            len(first.calls), 2, "invalidate() did not force a fresh listing"
        )


class ProcessTableTests(unittest.TestCase):
    def setUp(self):
        proc_cache.invalidate_processes()
        self.addCleanup(proc_cache.invalidate_processes)

    def test_the_catalog_and_cloudflared_share_one_scan(self):
        """`/api/apps/managed` walks both, and read the table twice for it."""
        from hub import cloudflared_svc, native_catalog

        counting = _CountingSh(PS)
        with mock.patch.object(proc_cache, "sh", counting):
            native_catalog._process_running("syncthing")
            cloudflared_svc._process_running()

        self.assertEqual(
            len(counting.calls), 1,
            f"two readers ran {len(counting.calls)} process scans",
        )

    def test_concurrent_cold_readers_do_not_each_spawn(self):
        counting = _CountingSh(PS)
        with mock.patch.object(proc_cache, "sh", counting):
            threads = [threading.Thread(target=proc_cache.ps_lines) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertEqual(len(counting.calls), 1)
        self.assertEqual(counting.peak, 1)

    def test_a_match_ignores_the_scan_that_found_it(self):
        table = "USER PID COMMAND\nme 1 /bin/ps aux\n"
        with mock.patch.object(proc_cache, "sh", lambda *a, **k: (0, table, "")):
            self.assertFalse(
                proc_cache.process_matches("aux"),
                "the `ps aux` row matched a needle in its own argv",
            )

    def test_an_empty_needle_matches_nothing(self):
        with mock.patch.object(proc_cache, "sh", lambda *a, **k: (0, PS, "")):
            self.assertFalse(proc_cache.process_matches(""))

    def test_a_start_poll_reads_a_fresh_table_each_pass(self):
        """The loop waiting for cloudflared to appear must observe the change.

        With a cached table it would poll the same pre-start snapshot eight times and
        report a successful start as "check the log".
        """
        from hub import cloudflared_svc

        counting = _CountingSh(PS)
        with mock.patch.object(proc_cache, "sh", counting):
            proc_cache.ps_lines()
            self.assertEqual(len(counting.calls), 1)
            cloudflared_svc._forget_host_state()
            proc_cache.ps_lines()

        self.assertEqual(
            len(counting.calls), 2,
            "the poll would have reused the table taken before the start",
        )

    def test_the_tools_page_parses_the_shared_table(self):
        """`top_processes` kept its own `ps aux`; only its row cache is local now."""
        from hub import tools_svc

        table = (
            "USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND\n"
            "me 11 9.5 1.5 100 200 ?? S 1:00PM 0:01.00 /usr/bin/busy --flag\n"
            "me 12 0.5 0.5 100 200 ?? S 1:00PM 0:00.10 /usr/bin/idle\n"
        )
        tools_svc._proc_cache.update(t=0.0, v=None, limit=0)
        self.addCleanup(tools_svc._proc_cache.update, t=0.0, v=None, limit=0)

        counting = _CountingSh(table)
        with mock.patch.object(proc_cache, "sh", counting):
            rows = tools_svc.top_processes(limit=5)

        self.assertEqual([r["pid"] for r in rows], ["11", "12"], rows)
        self.assertEqual(rows[0]["command"], "/usr/bin/busy --flag")
        self.assertEqual(len(counting.calls), 1)

    def test_pid_commands_need_the_eleven_column_aux_layout(self):
        with mock.patch.object(proc_cache, "sh", lambda *a, **k: (0, PS, "")):
            self.assertEqual(proc_cache.ps_pid_commands(), ())
        # The short fixture is still a non-empty table, so the snapshot
        # keeps it.  Drop it before the well-formed rows can be seen.
        proc_cache.invalidate_processes()
        table = (
            "USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND\n"
            "me 11 9.5 1.5 100 200 ?? S 1:00PM 0:01.00 /opt/homebrew/bin/wstunnel server\n"
        )
        with mock.patch.object(proc_cache, "sh", lambda *a, **k: (0, table, "")):
            self.assertEqual(
                proc_cache.ps_pid_commands(),
                ((11, "/opt/homebrew/bin/wstunnel server"),),
            )

    def test_sensors_and_wstunnel_share_the_table(self):
        from hub import sensors_svc, wireguard_wstunnel as wst

        table = (
            "USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND\n"
            "me 11 9.5 1.5 100 2048 ?? S 1:00PM 0:01.00 /opt/homebrew/bin/wstunnel server "
            "--restrict-to 10.0.0.1:51821 ws://0.0.0.0:8444\n"
            "me 12 1.0 0.5 100 512 ?? S 1:00PM 0:00.10 /usr/bin/idle\n"
        )
        counting = _CountingSh(table)
        wst.live.invalidate()
        self.addCleanup(wst.live.invalidate)
        with mock.patch.object(proc_cache, "sh", counting):
            rows = sensors_svc._top_processes(8)
            live = wst.live()
        self.assertEqual(len(counting.calls), 1, counting.calls)
        self.assertEqual(rows[0]["pid"], 11)
        self.assertEqual(rows[0]["name"], "wstunnel")
        self.assertTrue(live["running"])
        self.assertEqual(live["pid"], 11)

    def test_callers_do_not_spawn_a_second_ps_flavor(self):
        from pathlib import Path

        from hub import cloudflared_svc, sensors_svc, wireguard_wstunnel

        for module in (cloudflared_svc, sensors_svc, wireguard_wstunnel):
            source = Path(module.__file__).read_text()
            self.assertNotIn("ps\", \"-A\"", source, module.__name__)
            self.assertNotIn("ps\", \"-ax\"", source, module.__name__)
            self.assertNotIn("ps\", \"axo\"", source, module.__name__)


if __name__ == "__main__":
    unittest.main()
