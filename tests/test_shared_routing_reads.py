"""`route -n get default` and `ipconfig getifaddr` are read once per request.

The routing table had four implementations -- `host_address.default_interface`,
`power_svc._default_iface`, `wireguard_net_svc._default_wan_interface` and
`network_svc.default_route` -- with three timeouts and two parses between them.
Nothing depended on the differences; they were four copies of one question.

Measured per endpoint, one process each:

    /api/system/host   13 spawns, 5 waves, 2 redundant  ->  11 spawns, 4 waves, 0
    /api/system/power   5 spawns, 3 waves, 1 redundant  ->   4 spawns, 1 wave,  0

`/api/system/power` ran the route lookup twice because the WOL NIC branch and the
Screen Sharing URL each started from scratch; `/api/system/host` also asked
`ipconfig getifaddr en0` twice, once in its interface sweep and once inside
`host_ip()`.

The part worth pinning hardest is `force`. Both reads are memoised now, so a
`force` that stops at the outer cache returns exactly the value the caller said
was stale -- and passing `force` *into* a memoised function is worse, because the
argument becomes part of the cache key and populates a second entry while the
stale one keeps being served to everyone else.
"""
from __future__ import annotations

import threading
import time
import unittest
from unittest import mock

from hub import host_address

ROUTE = (
    "   route to: default\n"
    "destination: default\n"
    "    gateway: 192.168.1.1\n"
    "  interface: en0\n"
    "      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n"
)


class _CountingSh:
    def __init__(self, route: str = ROUTE, address: str = "192.168.1.9"):
        self.route = route
        self.address = address
        self.calls: list[list[str]] = []
        self.peak = 0
        self._live = 0
        self._lock = threading.Lock()

    def __call__(self, cmd, *a, **kw):
        argv = [str(c) for c in cmd]
        with self._lock:
            self.calls.append(argv)
            self._live += 1
            self.peak = max(self.peak, self._live)
        time.sleep(0.05)
        with self._lock:
            self._live -= 1
        if "route" in argv[0]:
            return 0, self.route, ""
        return 0, self.address, ""

    def count(self, needle: str) -> int:
        return sum(1 for c in self.calls if any(needle in part for part in c))


class RoutingSnapshotTests(unittest.TestCase):
    def setUp(self):
        host_address.invalidate_routing()
        self.addCleanup(host_address.invalidate_routing)

    def test_the_four_callers_share_one_lookup(self):
        from hub import network_svc, power_svc, wireguard_net_svc

        counting = _CountingSh()
        with mock.patch.object(host_address, "sh", counting):
            self.assertEqual(host_address.default_interface(), "en0")
            self.assertEqual(power_svc._default_iface(), "en0")
            self.assertEqual(wireguard_net_svc._default_wan_interface(), "en0")
            self.assertEqual(network_svc.default_route()["interface"], "en0")

        self.assertEqual(
            counting.count("route"), 1,
            f"four callers ran the route lookup {counting.count('route')} times",
        )

    def test_the_parsed_shape_is_unchanged(self):
        """`/api/system/network` publishes this dict, so its keys are an API."""
        with mock.patch.object(host_address, "sh", _CountingSh()):
            route = host_address.default_route()

        self.assertEqual(route["gateway"], "192.168.1.1")
        self.assertEqual(route["interface"], "en0")
        self.assertEqual(route["raw"]["destination"], "default")

    def test_a_failed_lookup_reports_none_not_empty_string(self):
        """The previous implementation returned None here, and the SPA tests it."""
        with mock.patch.object(host_address, "sh", lambda *a, **k: (1, "", "no route")):
            route = host_address.default_route()

        self.assertIsNone(route["gateway"])
        self.assertIsNone(route["interface"])
        self.assertEqual(route["raw"], {})
        self.assertEqual(
            host_address.default_interface(), "",
            "the interface-name helper contracted to return a string",
        )

    def test_a_caller_cannot_corrupt_the_shared_answer(self):
        counting = _CountingSh()
        with mock.patch.object(host_address, "sh", counting):
            first = host_address.default_route()
            first["raw"]["gateway"] = "10.0.0.1"
            first["interface"] = "utun9"
            second = host_address.default_route()

        self.assertEqual(second["interface"], "en0")
        self.assertEqual(second["raw"]["gateway"], "192.168.1.1")
        self.assertEqual(counting.count("route"), 1, "the copy cost a second lookup")

    def test_concurrent_cold_callers_do_not_each_spawn(self):
        counting = _CountingSh()
        with mock.patch.object(host_address, "sh", counting):
            threads = [
                threading.Thread(target=host_address.default_interface) for _ in range(8)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertEqual(len(counting.calls), 1)
        self.assertEqual(counting.peak, 1, "two lookups were in flight together")

    def test_force_re_reads_rather_than_keying_a_second_entry(self):
        answers = iter(["en0", "en5"])

        def fake_sh(cmd, *a, **kw):
            return 0, f"  interface: {next(answers)}\n", ""

        with mock.patch.object(host_address, "sh", fake_sh):
            self.assertEqual(host_address.default_interface(), "en0")
            self.assertEqual(host_address.default_interface(), "en0", "TTL did not hold")
            self.assertEqual(
                host_address.default_interface(force=True), "en5",
                "force served the value it was told was stale",
            )
            self.assertEqual(
                host_address.default_interface(), "en5",
                "the forced read left the stale entry in place for everyone else",
            )


class InterfaceAddressTests(unittest.TestCase):
    def setUp(self):
        host_address.invalidate_routing()
        self.addCleanup(host_address.invalidate_routing)

    def test_the_host_sweep_and_the_lan_detection_share_the_default_interface(self):
        from hub.routers import system_extra

        host_address._detect_cache.update(t=0.0, value=None)
        self.addCleanup(host_address._detect_cache.update, t=0.0, value=None)

        counting = _CountingSh()
        with mock.patch.object(host_address, "sh", counting):
            addresses = system_extra._iface_addresses("en0")
            host_address.detect_lan_ip()

        en0_lookups = [
            c for c in counting.calls if c[1:] == ["getifaddr", "en0"]
        ]
        self.assertEqual(
            len(en0_lookups), 1,
            f"en0 was asked for its address {len(en0_lookups)} times in one request",
        )
        self.assertEqual([a["iface"] for a in addresses][0], "en0")

    def test_the_sweep_still_overlaps_across_interfaces(self):
        """Per-key locking, not one global lock: five interfaces, one wave."""
        from hub.routers import system_extra

        counting = _CountingSh()
        with mock.patch.object(host_address, "sh", counting):
            system_extra._iface_addresses("en3")

        self.assertGreater(
            counting.peak, 1,
            "the per-interface lookups serialised; the memo locks per key so that "
            "a sweep stays a fan-out",
        )

    def test_an_empty_interface_name_costs_nothing(self):
        counting = _CountingSh()
        with mock.patch.object(host_address, "sh", counting):
            self.assertEqual(host_address.interface_address(""), "")

        self.assertEqual(counting.calls, [])


class RoutingInvalidationTests(unittest.TestCase):
    def setUp(self):
        host_address.invalidate_routing()
        self.addCleanup(host_address.invalidate_routing)

    def test_a_network_change_drops_the_routing_reads(self):
        """`_bust()` already covered the interface and service-order caches.

        Switching to DHCP or setting a manual address changes which interface holds
        the default route and what address it carries, and each of those handlers
        returns the new state by re-reading it.  Left cached, the handler would
        answer with the configuration it just replaced.
        """
        from hub import network_svc

        counting = _CountingSh()
        with mock.patch.object(host_address, "sh", counting):
            host_address.default_interface()
            self.assertEqual(counting.count("route"), 1)
            network_svc._bust()
            host_address.default_interface()

        self.assertEqual(
            counting.count("route"), 2,
            "_bust() left the pre-change routing table cached",
        )

    def test_bust_also_drops_the_detected_lan_address(self):
        from hub import network_svc

        host_address._detect_cache.update(t=0.0, value=None)
        self.addCleanup(host_address._detect_cache.update, t=0.0, value=None)

        with mock.patch.object(host_address, "sh", _CountingSh(address="192.168.1.9")):
            self.assertEqual(host_address.detect_lan_ip(), "192.168.1.9")
        network_svc._bust()
        with mock.patch.object(host_address, "sh", _CountingSh(address="192.168.1.77")):
            self.assertEqual(
                host_address.detect_lan_ip(), "192.168.1.77",
                "the address from before the network change was still served",
            )


if __name__ == "__main__":
    unittest.main()
