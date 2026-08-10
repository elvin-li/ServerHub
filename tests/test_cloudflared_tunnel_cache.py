"""A remote API call must not sit uncached on a polling page path.

`cloudflared tunnel list` is a round trip to Cloudflare and was the largest single
cost in the Apps page payload: ~1.6s of ~4.5s, with no cache at all. The inventory
around it caches for 8 seconds, so a browser left on that page re-queried a remote
service every few seconds. Its 30s timeout meant an unreachable Cloudflare could
hang the page for half a minute.

Two properties are pinned here, and the second one is a mistake this cache made on
the first attempt: "the account has no tunnels" is a real, cacheable answer, and
treating it as failure meant such an account never cached and paid the remote call
on every poll. Failure and emptiness have to be distinguishable.
"""
from __future__ import annotations

import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import cloudflared_svc as cf  # noqa: E402

LISTING = (
    "ID NAME CREATED CONNECTIONS\n"
    "11111111-2222-3333-4444-555555555555 home 2026-01-01T00:00:00Z 2xSJC\n"
)


class TunnelCacheTests(unittest.TestCase):
    def setUp(self):
        cf.invalidate_tunnels()
        self.addCleanup(cf.invalidate_tunnels)
        self.reads = 0

    def _sh(self, argv, timeout=None):
        self.reads += 1
        return (0, LISTING, "")

    def test_a_second_reader_does_not_hit_cloudflare(self):
        with (
            patch.object(cf, "_logged_in", return_value=True),
            patch.object(cf, "sh", side_effect=self._sh),
        ):
            first = cf.list_tunnels()
            second = cf.list_tunnels()
        self.assertEqual(self.reads, 1, "the remote list was fetched twice")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["name"], "home")

    def test_an_account_with_no_tunnels_is_still_cached(self):
        """The first version treated empty as failure and never cached it."""
        def empty(argv, timeout=None):
            self.reads += 1
            return (0, "ID NAME CREATED CONNECTIONS\n", "")

        with (
            patch.object(cf, "_logged_in", return_value=True),
            patch.object(cf, "sh", side_effect=empty),
        ):
            self.assertEqual(cf.list_tunnels(), [])
            self.assertEqual(cf.list_tunnels(), [])
        self.assertEqual(
            self.reads, 1,
            "an account with no tunnels re-queried Cloudflare on every call",
        )

    def test_a_failed_read_is_not_cached(self):
        """Caching a network failure would hide every tunnel for the whole TTL."""
        def failing(argv, timeout=None):
            self.reads += 1
            return (1, "", "failed to connect")

        with (
            patch.object(cf, "_logged_in", return_value=True),
            patch.object(cf, "sh", side_effect=failing),
        ):
            cf.list_tunnels()
            cf.list_tunnels()
        self.assertEqual(self.reads, 2, "a failure was cached")

    def test_a_failure_serves_the_previous_answer(self):
        """A stale list beats an empty page when Cloudflare is unreachable."""
        with (
            patch.object(cf, "_logged_in", return_value=True),
            patch.object(cf, "sh", side_effect=self._sh),
        ):
            cf.list_tunnels()

        def failing(argv, timeout=None):
            return (1, "", "network unreachable")

        with (
            patch.object(cf, "_logged_in", return_value=True),
            patch.object(cf, "sh", side_effect=failing),
        ):
            # Force past the TTL so the failing read is actually attempted.
            result = cf.list_tunnels(force=True)
        self.assertEqual(len(result), 1, "a transient failure emptied the tunnel list")

    def test_force_bypasses_the_cache(self):
        with (
            patch.object(cf, "_logged_in", return_value=True),
            patch.object(cf, "sh", side_effect=self._sh),
        ):
            cf.list_tunnels()
            cf.list_tunnels(force=True)
        self.assertEqual(self.reads, 2)

    def test_creating_a_tunnel_invalidates_the_cache(self):
        """A newly created tunnel must appear at once, not after the TTL."""
        source = (BASE / "hub" / "cloudflared_svc.py").read_text()
        start = source.index("def create_tunnel(")
        body = source[start: source.index("\ndef ", start + 10)]
        self.assertIn("invalidate_tunnels()", body)

    def test_concurrent_readers_share_one_remote_call(self):
        release = threading.Event()
        started = threading.Event()

        def slow(argv, timeout=None):
            self.reads += 1
            started.set()
            release.wait(timeout=5)
            return (0, LISTING, "")

        with (
            patch.object(cf, "_logged_in", return_value=True),
            patch.object(cf, "sh", side_effect=slow),
        ):
            with ThreadPoolExecutor(max_workers=4) as ex:
                futures = [ex.submit(cf.list_tunnels) for _ in range(4)]
                self.assertTrue(started.wait(timeout=5))
                release.set()
                results = [f.result(timeout=10) for f in futures]
        self.assertEqual(self.reads, 1, "concurrent readers each called Cloudflare")
        self.assertTrue(all(len(r) == 1 for r in results))

    def test_the_timeout_is_short_enough_for_a_page_load(self):
        captured = {}

        def capture(argv, timeout=None):
            captured["timeout"] = timeout
            return (0, LISTING, "")

        with (
            patch.object(cf, "_logged_in", return_value=True),
            patch.object(cf, "sh", side_effect=capture),
        ):
            cf.list_tunnels(force=True)
        self.assertLessEqual(
            captured["timeout"], 15,
            "a page-path remote call must not be able to hang for 30s",
        )

    def test_no_cert_means_no_remote_call(self):
        with (
            patch.object(cf, "_logged_in", return_value=False),
            patch.object(cf, "sh", side_effect=self._sh),
        ):
            self.assertEqual(cf.list_tunnels(force=True), [])
        self.assertEqual(self.reads, 0)


if __name__ == "__main__":
    unittest.main()
