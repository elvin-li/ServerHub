"""A dependency cache must outlive the caches that consume it.

`brew services list --json` costs 0.7-1.2s and is shared through
``hub/brew_cache.py``. Its TTL was 6s while ``apps_manage_svc._INV_TTL`` was 8s, so
the snapshot always expired *before* the inventory that depends on it. Every
inventory rebuild therefore re-ran the subprocess -- roughly a quarter of the whole
Apps page payload -- and the cache never once saved a call in the polling case it
was written for.

A dependency cache with a shorter lifetime than its consumer guarantees a miss on
every consumer refresh, which is the opposite of what a cache is for. This pins the
ordering so tuning one TTL cannot quietly reintroduce it, and pins the invalidation
that makes a longer window safe.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import apps_manage_svc, brew_cache, cloudflared_svc  # noqa: E402


class TtlOrderingTests(unittest.TestCase):
    def test_brew_snapshot_outlives_the_inventory_that_uses_it(self):
        self.assertGreater(
            brew_cache._TTL,
            apps_manage_svc._INV_TTL,
            "the brew snapshot expires before the inventory does, so every "
            "inventory rebuild pays for `brew services list --json` again",
        )

    def test_tunnel_list_outlives_the_inventory(self):
        """It is a remote API round trip; it must not be re-run per poll."""
        self.assertGreater(
            cloudflared_svc._TUNNELS_TTL,
            apps_manage_svc._INV_TTL,
            "the tunnel list expires before the inventory, so a browser sitting "
            "on the Apps page re-queries Cloudflare every few seconds",
        )

    def test_the_windows_stay_short_enough_to_be_truthful(self):
        # The point is ordering, not indefinite caching: a service started outside
        # the panel must still show up within a reasonable time.
        self.assertLessEqual(brew_cache._TTL, 60.0)
        self.assertLessEqual(cloudflared_svc._TUNNELS_TTL, 900.0)


class PollIntervalOrderingTests(unittest.TestCase):
    """A cache shorter than the page that polls it misses on every sit tick."""

    def test_host_ttl_outlives_dashboard_heavy_low(self):
        from hub.routers import system_extra

        self.assertGreater(
            system_extra._HOST_TTL,
            90.0,
            "host snapshot expires before the 90s dashboard heavy tick",
        )

    def test_inventory_ttl_outlives_apps_poll(self):
        self.assertGreater(
            apps_manage_svc._INV_TTL,
            15.0,
            "app inventory expires before the 15s Apps page poll",
        )

    def test_container_caches_outlive_containers_poll(self):
        from hub import containers_svc

        self.assertGreater(
            containers_svc._LIST_TTL,
            20.0,
            "container list expires before the 20s Containers page poll",
        )
        self.assertGreater(
            containers_svc._STATS_TTL,
            20.0,
            "docker stats expire before the 20s Containers page poll",
        )


class InvalidationMakesLongerWindowsSafeTests(unittest.TestCase):
    """A longer TTL is only acceptable because every mutation drops the cache."""

    def _body(self, module: str, function: str) -> str:
        source = (BASE / "hub" / f"{module}.py").read_text()
        start = source.index(f"def {function}(")
        rest = source[start:]
        end = rest.find("\ndef ")
        return rest if end < 0 else rest[:end]

    def test_service_action_invalidates_the_brew_snapshot(self):
        self.assertIn(
            "invalidate_brew_services()",
            self._body("brew_svc", "service_action"),
            "starting or stopping a service would show the old state for a full TTL",
        )

    def test_creating_a_tunnel_invalidates_the_tunnel_list(self):
        self.assertIn(
            "invalidate_tunnels()",
            self._body("cloudflared_svc", "create_tunnel"),
            "a newly created tunnel would not appear until the TTL lapsed",
        )

    def test_the_invalidation_helpers_actually_clear_state(self):
        brew_cache._cache.update(t=9e9, v=[{"name": "x"}])
        brew_cache.invalidate_brew_services()
        self.assertIsNone(brew_cache._cache["v"])

        cloudflared_svc._tunnels_cache.update(t=9e9, v=[{"name": "x"}])
        cloudflared_svc.invalidate_tunnels()
        self.assertIsNone(cloudflared_svc._tunnels_cache["v"])


if __name__ == "__main__":
    unittest.main()
