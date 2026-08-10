"""Read paths that were still serial after the first parallelisation pass.

The first pass measured eleven hand-picked endpoints. There are 103 GET endpoints
without path parameters, so a sweep of all of them found work the sample had
missed. Measured with ``subprocess.run`` itself instrumented, the serial depth was:

    /api/diagnostics            33 spawns, 23 deep -- the deepest path in the API
    /api/wireguard/readiness    13 spawns, 13 deep -- zero overlap
    /api/shares                  6 spawns,  6 deep
    /api/settings/datetime       4 spawns,  4 deep
    /api/settings/disk           4 spawns,  4 deep
    /api/settings/power          3 spawns,  3 deep
    /api/vms                     3 spawns,  3 deep

Three kinds of fix appear here and they are not interchangeable:

* **Fewer spawns.** ``collect_diagnostics`` called ``get_power_info()`` twice, once
  for the body and once for the assertion count, running ``pmset`` twice to answer
  one question. ``shares_overview`` called ``file_services()`` twice because the
  response carries the same list under two keys for compatibility.
  ``wireguard_svc.installation`` is both a route guard on every
  ``/api/wireguard/*`` request and a probe inside ``readiness``, so its two
  version probes ran twice per readiness read. These are asserted by counting
  calls, not by timing, because they hold regardless of threading.
* **Overlap**, asserted with a peak-concurrency counter rather than elapsed time.
  A loaded machine serialises threads that an idle one overlaps, so timing bounds
  pass alone and fail under full-suite load.
* **Refusing to overlap.** ``readiness`` fans out seven probes and keeps four on
  the request thread. ``status``, ``nat_installed``, ``daemon_state`` and
  ``pf_enabled`` all reach ``sudo_capture``, which reads the operator's password
  from a ContextVar that a pool worker does not inherit -- so on a worker the read
  returns "" and the call answers ``password_required`` about a password that was
  just supplied. It does not raise and it does not warn. That split is asserted
  here by thread identity, and structurally in
  tests/test_privileged_calls_stay_on_the_request_thread.py.
"""
from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import (  # noqa: E402
    shares_svc,
    system_settings_svc,
    vms_svc,
    wireguard_net_svc,
    wireguard_svc,
)


class Concurrency:
    """Counts how many probes are in flight at once, and on which threads."""

    def __init__(self, delay: float = 0.05):
        self.delay = delay
        self._lock = threading.Lock()
        self.live = 0
        self.peak = 0
        self.tags: list[str] = []
        self.threads: dict[str, str] = {}

    def run(self, tag, result):
        with self._lock:
            self.live += 1
            self.peak = max(self.peak, self.live)
            self.tags.append(tag)
            self.threads[tag] = threading.current_thread().name
        try:
            time.sleep(self.delay)
            return result
        finally:
            with self._lock:
                self.live -= 1

    def count(self, tag) -> int:
        return sum(1 for t in self.tags if t == tag)


# ── /api/wireguard/readiness ─────────────────────────────────────────────────

PRIVILEGED = ("status", "nat_installed", "daemon_state", "pf_enabled")
SAFE = (
    "installation", "settings", "peer_origin_conflict", "endpoint_resolution",
    "runtime_state", "forwarding_enabled", "wan_interface",
)


class ReadinessTests(unittest.TestCase):
    def _readiness(self):
        tracker = Concurrency()
        answers = {
            "installation": {
                "installed": True, "conf_exists": True, "conf_path": "/etc/wg0.conf",
                "tools_version": "wireguard-tools v1.0", "probe_failed": False,
            },
            "status": {"running": True, "state_error": ""},
            "settings": {"interface": "wg0", "endpoint": "vpn.example.com:51820"},
            "nat_installed": {
                "complete": True, "conf_parses": True, "conf_error": "",
                "anchor_present": True, "nat_present": True,
            },
            "daemon_state": {
                "installed": True, "loaded": True, "respawn_loop": False,
                "matches": True, "label": "com.wireguard.wg0",
            },
            "peer_origin_conflict": {"conflict": False, "foreign": 0, "total": 3},
            "endpoint_resolution": {"ok": True, "addresses": ["203.0.113.9"], "error": ""},
            "runtime_state": {"real_interface": "utun4", "stale": False, "claim": ""},
            "forwarding_enabled": True,
            "pf_enabled": True,
            "wan_interface": "en0",
        }
        patches = {
            "peer_origin_conflict": wireguard_net_svc,
            "endpoint_resolution": wireguard_net_svc,
            "forwarding_enabled": wireguard_net_svc,
            "wan_interface": wireguard_net_svc,
            "nat_installed": wireguard_net_svc,
            "daemon_state": wireguard_net_svc,
            "pf_enabled": wireguard_net_svc,
            "installation": wireguard_svc,
            "settings": wireguard_svc,
            "status": wireguard_svc,
            "runtime_state": wireguard_svc,
        }
        import contextlib

        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for name, module in patches.items():
            stack.enter_context(mock.patch.object(
                module, name,
                (lambda n=name: (lambda *a, **k: tracker.run(n, answers[n])))(),
            ))
        # Helpers that format the detail strings read the dicts above.
        for helper in ("_resolution_detail", "_nat_detail", "_daemon_detail"):
            if hasattr(wireguard_net_svc, helper):
                stack.enter_context(
                    mock.patch.object(wireguard_net_svc, helper, lambda *a, **k: "")
                )
        data = wireguard_net_svc.readiness()
        return data, tracker

    def test_the_safe_probes_overlap(self):
        _, tracker = self._readiness()
        self.assertGreater(
            tracker.peak, 1,
            "eleven independent probes ran one after another on the page an "
            "operator opens when the tunnel is already broken",
        )

    def test_every_probe_still_runs_exactly_once(self):
        _, tracker = self._readiness()
        for probe in SAFE + PRIVILEGED:
            self.assertEqual(
                tracker.count(probe), 1, f"{probe} ran {tracker.count(probe)} times"
            )

    def test_the_password_dependent_probes_stay_on_the_request_thread(self):
        """The whole point of the split, asserted by thread identity.

        On a worker, ``sudo_capture`` reads an empty password and answers
        ``password_required`` without raising -- so this cannot be caught by
        watching for errors.
        """
        _, tracker = self._readiness()
        here = threading.current_thread().name
        for probe in PRIVILEGED:
            self.assertEqual(
                tracker.threads[probe], here,
                f"{probe} reaches sudo_capture but ran on {tracker.threads[probe]}; "
                "the operator's password is invisible there and the failure is silent",
            )

    def test_the_safe_probes_really_did_leave_the_request_thread(self):
        """Otherwise the test above passes because nothing was parallelised."""
        _, tracker = self._readiness()
        here = threading.current_thread().name
        moved = [p for p in SAFE if tracker.threads[p] != here]
        self.assertGreater(len(moved), 1, f"only {moved} ran on a worker")

    def test_the_checks_are_unchanged(self):
        data, _ = self._readiness()
        by_id = {c["id"]: c for c in data["checks"]}
        self.assertTrue(by_id["installed"]["ok"])
        self.assertTrue(by_id["conf"]["ok"])
        self.assertTrue(by_id["running"]["ok"])
        self.assertTrue(by_id["endpoint"]["ok"], "the endpoint came from settings()")
        self.assertEqual(by_id["endpoint"]["detail"], "vpn.example.com:51820")
        self.assertTrue(by_id["forwarding"]["ok"])
        self.assertTrue(by_id["pf"]["ok"])
        self.assertTrue(by_id["boot"]["ok"])
        self.assertTrue(by_id["peer_origin"]["ok"])

    def test_check_order_is_preserved(self):
        data, _ = self._readiness()
        ids = [c["id"] for c in data["checks"]]
        expected = ["installed", "conf", "running", "endpoint", "endpoint_resolves",
                    "forwarding", "pf_conf", "nat", "pf", "boot", "peer_origin"]
        self.assertEqual(ids[:len(expected)], expected)


class InstallationVersionProbeTests(unittest.TestCase):
    """The two version probes overlap, and are deliberately not cached.

    Caching them was tried and reverted. It saves two spawns per readiness read --
    ``installation`` is a route guard on every ``/api/wireguard/*`` request as well
    as a probe inside ``readiness`` -- but ``probe_failed`` is derived from the
    result, and that field exists precisely so that a transient timeout is not
    treated as authoritative. A TTL turns a blip into a minute of the panel
    insisting the tools are degraded. tests/test_wireguard_hardening.py owns that
    property; these two assert the part that is safe to change.
    """

    #: Real files, so ``Path(binary).exists()`` is true without patching
    #: ``Path.exists``.  ``wireguard_svc.Path`` *is* ``pathlib.Path``, so patching
    #: its method reaches every path in the process -- the same trap
    #: tests/test_wireguard_hardening.py documents, where it caused services.yaml to
    #: look absent and be recreated from defaults.  An earlier version of these
    #: three tests did that and passed alone while failing alongside other files.
    FAKE_WG = "/bin/echo"
    FAKE_WG_QUICK = "/bin/sh"
    FAKE_WIREGUARD_GO = "/bin/cat"

    def _binaries(self, stack):
        for name, value in (
            ("WG", self.FAKE_WG),
            ("WG_QUICK", self.FAKE_WG_QUICK),
            ("WIREGUARD_GO", self.FAKE_WIREGUARD_GO),
        ):
            stack.enter_context(mock.patch.object(wireguard_svc, name, value))

    def test_the_two_version_probes_overlap(self):
        import contextlib

        tracker = Concurrency()
        with contextlib.ExitStack() as stack:
            self._binaries(stack)
            stack.enter_context(mock.patch.object(
                wireguard_svc, "sh",
                lambda cmd, *a, **k: tracker.run(str(cmd[0]), (0, "wireguard-tools v1.0", "")),
            ))
            info = wireguard_svc.installation()

        self.assertGreater(
            tracker.peak, 1,
            "`wg --version` and `wireguard-go --version` are unrelated binaries and "
            "each carries its own 8s timeout",
        )
        self.assertEqual(info["tools_version"], "wireguard-tools v1.0")

    def test_each_probe_still_reports_its_own_binary(self):
        """A fan-out that mixed up the two would be invisible on a healthy host."""
        import contextlib

        with contextlib.ExitStack() as stack:
            self._binaries(stack)
            stack.enter_context(mock.patch.object(
                wireguard_svc, "sh",
                lambda cmd, *a, **k: (0, f"version of {Path(str(cmd[0])).name}", ""),
            ))
            info = wireguard_svc.installation()

        self.assertEqual(info["tools_version"], "version of echo")
        self.assertEqual(info["userspace_version"], "version of cat")

    def test_a_failed_probe_is_not_remembered(self):
        """Back-to-back calls must each reflect the current state of the host."""
        import contextlib

        with contextlib.ExitStack() as stack:
            self._binaries(stack)
            stack.enter_context(mock.patch.object(
                wireguard_svc, "sh", lambda *a, **k: (1, "", "boom")))
            first = wireguard_svc.installation()
        self.assertTrue(first["installed"], "presence comes from the filesystem")
        self.assertTrue(first["probe_failed"])

        with contextlib.ExitStack() as stack:
            self._binaries(stack)
            stack.enter_context(mock.patch.object(
                wireguard_svc, "sh", lambda *a, **k: (0, "wireguard-tools v1.0", "")))
            second = wireguard_svc.installation()
        self.assertFalse(
            second["probe_failed"],
            "a cached failure outlived the condition that caused it",
        )


# ── /api/diagnostics ─────────────────────────────────────────────────────────

class DiagnosticsBundleTests(unittest.TestCase):
    SECTIONS = ("identity", "datetime", "power", "management", "other", "docker",
                "alias_auto", "recent_alerts", "health", "metrics_latest", "vms")

    def _collect(self, **overrides):
        tracker = Concurrency()
        power = {"disksleep": 0, "womp": 1, "assertions": ["a", "b", "c"]}
        defaults = {
            "get_datetime_info": lambda: tracker.run("datetime", {"now": "x"}),
            "get_power_info": lambda: tracker.run("power", power),
            "get_management_access": lambda: tracker.run("management", {"ok": True}),
            "get_other_settings": lambda: tracker.run("other", {"ok": True}),
            "get_vm_settings": lambda: tracker.run("vms", {"total": 2, "running": 1}),
        }
        defaults.update(overrides)
        import contextlib

        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for name, value in defaults.items():
            stack.enter_context(mock.patch.object(system_settings_svc, name, value))
        stack.enter_context(
            mock.patch.object(system_settings_svc, "_persist_diagnostics",
                              lambda bundle: ("/tmp/x.json", None))
        )
        bundle = system_settings_svc.collect_diagnostics()
        return bundle, tracker

    def test_the_sections_overlap(self):
        _, tracker = self._collect()
        self.assertGreater(
            tracker.peak, 1,
            "eleven sections, several of them whole page payloads, ran in series",
        )

    def test_the_power_snapshot_is_read_once(self):
        """It was read twice: once for the body, once for the assertion count."""
        _, tracker = self._collect()
        self.assertEqual(
            tracker.count("power"), 1,
            f"get_power_info ran {tracker.count('power')} times, so pmset answered "
            "the same question twice",
        )

    def test_the_power_section_still_carries_the_count_and_not_the_list(self):
        bundle, _ = self._collect()
        self.assertEqual(bundle["power"]["assertions_count"], 3)
        self.assertNotIn(
            "assertions", bundle["power"], "the raw assertion list leaked into the bundle"
        )
        self.assertEqual(bundle["power"]["disksleep"], 0)

    def test_section_order_is_preserved(self):
        bundle, _ = self._collect()
        present = [k for k in self.SECTIONS if k in bundle]
        positions = [list(bundle).index(k) for k in present]
        self.assertEqual(positions, sorted(positions), f"bundle order: {list(bundle)}")

    def test_the_header_fields_still_come_first(self):
        bundle, _ = self._collect()
        self.assertEqual(
            list(bundle)[:4], ["generated_at", "platform", "python", "hostname"]
        )

    def test_a_wrapped_section_reports_its_failure_in_place(self):
        """Seven of the eleven sections do this, and keep the rest of the bundle."""
        with mock.patch("hub.identity_svc.get_identity",
                        side_effect=RuntimeError("identity store unreadable")):
            bundle, _ = self._collect()
        self.assertEqual(bundle["identity"], {"error": "identity store unreadable"})
        for key in ("datetime", "power", "management", "other"):
            self.assertIn(key, bundle, "one failing section emptied the bundle")

    def test_no_single_section_can_fail_the_whole_bundle(self):
        """``datetime``, ``power``, ``management`` and ``other`` used to be able to.

        A diagnostics download that 500s because one subsystem is broken is useless
        precisely when it is needed, and the broken section is usually the one the
        operator opened it to read.
        """
        def boom():
            raise RuntimeError("pmset is wedged")

        for name in ("get_datetime_info", "get_power_info",
                     "get_management_access", "get_other_settings"):
            with self.subTest(section=name):
                bundle, _ = self._collect(**{name: boom})
                self.assertTrue(
                    any(
                        isinstance(v, dict) and v.get("error") == "pmset is wedged"
                        for v in bundle.values()
                    ),
                    f"{name} failing did not surface as an error field",
                )
                # And the rest of the bundle is intact.
                for key in ("datetime", "power", "management", "other", "identity"):
                    self.assertIn(key, bundle, f"{name} failing emptied the bundle")

    def test_a_failing_power_read_still_leaves_a_usable_slot(self):
        """The shape has to stay a dict, since callers index into it."""
        def boom():
            raise RuntimeError("pmset gone")

        bundle, _ = self._collect(get_power_info=boom)
        self.assertEqual(bundle["power"], {"error": "pmset gone"})
        self.assertNotIn(
            "assertions", bundle["power"], "the raw assertion list leaked on failure"
        )

    def test_a_failing_vm_read_leaves_the_key_out_entirely(self):
        """Not ``{"vms": None}``.

        The serial version used a bare ``except: pass`` after assigning nothing, so
        the key was absent. The saved bundle is a documented download; inventing a
        null would change its schema.
        """
        def boom():
            raise RuntimeError("no hypervisor")

        bundle, _ = self._collect(get_vm_settings=boom)
        self.assertNotIn("vms", bundle)

    def test_the_save_outcome_is_still_reported_separately(self):
        bundle, _ = self._collect()
        self.assertEqual(bundle["saved_path"], "/tmp/x.json")
        self.assertIsNone(bundle["save_error"])


# ── /api/settings/{datetime,power,disk} ──────────────────────────────────────

class SettingsReadTests(unittest.TestCase):
    def test_the_datetime_reads_overlap(self):
        tracker = Concurrency()
        with (
            mock.patch.object(system_settings_svc, "_clock_now",
                              lambda: tracker.run("now", "2026-08-09 18:00:00 CST")),
            mock.patch.object(system_settings_svc, "_ntp_enabled",
                              lambda: tracker.run("ntp", True)),
            mock.patch.object(system_settings_svc, "_ntp_server",
                              lambda: tracker.run("server", "time.apple.com")),
            mock.patch("hub.identity_svc.time_zone",
                       lambda: tracker.run("tz", "Asia/Shanghai")),
        ):
            info = system_settings_svc.get_datetime_info()
        self.assertGreater(tracker.peak, 1, "two systemsetup reads waited on each other")
        self.assertEqual(info["now"], "2026-08-09 18:00:00 CST")
        self.assertEqual(info["timezone"], "Asia/Shanghai")
        self.assertTrue(info["ntp_enabled"])
        self.assertEqual(info["ntp_server"], "time.apple.com")

    def test_an_unavailable_systemsetup_still_reports_unknown_not_false(self):
        """``None`` and ``False`` mean different things to the page."""
        with mock.patch.object(system_settings_svc, "sh", lambda *a, **k: (1, "", "denied")):
            self.assertIsNone(system_settings_svc._ntp_enabled())
            self.assertIsNone(system_settings_svc._ntp_server())

    def test_the_clock_falls_back_when_date_fails(self):
        with mock.patch.object(system_settings_svc, "sh", lambda *a, **k: (1, "", "")):
            self.assertTrue(system_settings_svc._clock_now())

    def test_the_power_reads_overlap(self):
        tracker = Concurrency()
        with (
            mock.patch.object(system_settings_svc, "_pmset_settings",
                              lambda: tracker.run("settings", {"disksleep": 0})),
            mock.patch.object(system_settings_svc, "_pmset_assertions",
                              lambda: tracker.run("assertions", ["held by x"])),
            mock.patch.object(system_settings_svc, "get_ups_info",
                              lambda: tracker.run("ups", {"source": "ac"})),
        ):
            info = system_settings_svc.get_power_info()
        self.assertGreater(tracker.peak, 1)
        self.assertEqual(info["disksleep"], 0)
        self.assertEqual(info["assertions"], ["held by x"])
        self.assertEqual(info["ups"], {"source": "ac"})

    def test_the_disk_settings_reads_overlap(self):
        tracker = Concurrency()
        with (
            mock.patch.object(system_settings_svc, "get_power_info",
                              lambda: tracker.run("power", {"disksleep": 10})),
            mock.patch.object(system_settings_svc, "_storage_snapshot",
                              lambda: tracker.run("storage", ({"health": "PASSED"}, [1, 2]))),
            mock.patch.object(system_settings_svc, "_power_disks",
                              lambda: tracker.run("disks", [{"id": "disk0"}])),
        ):
            info = system_settings_svc.get_disk_settings()
        self.assertGreater(tracker.peak, 1)
        self.assertEqual(info["disksleep_minutes"], 10)
        self.assertEqual(info["smart"], {"health": "PASSED"})
        self.assertEqual(info["disk_count"], 2)

    def test_a_missing_storage_module_still_yields_a_page(self):
        with mock.patch.dict(sys.modules, {"hub.storage_svc": None}):
            self.assertEqual(system_settings_svc._storage_snapshot(), ({}, []))


# ── /api/shares ──────────────────────────────────────────────────────────────

class SharesOverviewTests(unittest.TestCase):
    def _overview(self):
        tracker = Concurrency()
        with (
            mock.patch.object(shares_svc, "host_ip",
                              lambda: tracker.run("host", "192.168.1.9")),
            mock.patch.object(shares_svc, "system_services",
                              lambda: tracker.run("services", [{"id": "screen_sharing"}])),
            mock.patch.object(shares_svc, "list_smb_shares",
                              lambda: tracker.run("smb", [{"name": "Public"}])),
            mock.patch.object(shares_svc, "file_services",
                              lambda: tracker.run("files", [{"id": "filebrowser"}])),
        ):
            data = shares_svc.shares_overview()
        return data, tracker

    def test_the_four_reads_overlap(self):
        _, tracker = self._overview()
        self.assertGreater(tracker.peak, 1)

    def test_the_file_service_probes_run_once_for_both_keys(self):
        """``services`` is a compatibility alias, not a second read."""
        data, tracker = self._overview()
        self.assertEqual(
            tracker.count("files"), 1,
            f"file_services ran {tracker.count('files')} times to produce two "
            "identical lists",
        )
        self.assertEqual(data["file_services"], data["services"])

    def test_the_payload_is_unchanged(self):
        data, _ = self._overview()
        self.assertEqual(data["host"]["address"], "192.168.1.9")
        self.assertEqual(data["host"]["smb_url"], "smb://192.168.1.9")
        self.assertEqual(data["smb"], [{"name": "Public"}])
        self.assertEqual(data["system_services"], [{"id": "screen_sharing"}])
        self.assertTrue(data["capabilities"]["smb_management"])


class SystemServicesTests(unittest.TestCase):
    def _services(self):
        tracker = Concurrency()
        with (
            mock.patch.object(shares_svc, "_launchd_state",
                              lambda label: tracker.run("launchd", (True, "loaded"))),
            mock.patch.object(shares_svc, "port_open",
                              lambda *a, **k: tracker.run("port", False)),
            mock.patch.object(
                shares_svc, "_systemsetup_state",
                lambda flag, label: tracker.run(
                    flag, (flag == "-getremotelogin", f"detail {flag}")
                ),
            ),
            mock.patch.object(shares_svc, "_content_cache_state",
                              lambda: tracker.run("cache", (False, "off"))),
        ):
            services = shares_svc.system_services()
        return services, tracker

    def test_the_probes_overlap(self):
        _, tracker = self._services()
        self.assertGreater(
            tracker.peak, 1, "systemsetup is slow and both reads waited in turn"
        )

    def test_each_service_keeps_the_state_its_own_probe_reported(self):
        """The risk of a tuple-unpacking fan-out is silently swapped answers."""
        services, _ = self._services()
        by_id = {s["id"]: s for s in services}
        self.assertTrue(by_id["remote_login"]["enabled"])
        self.assertFalse(by_id["remote_apple_events"]["enabled"])
        self.assertFalse(by_id["content_caching"]["enabled"])
        self.assertIn("-getremotelogin", by_id["remote_login"]["detail"])
        self.assertIn("-getremoteappleevents", by_id["remote_apple_events"]["detail"])

    def test_the_screen_sharing_verdict_still_prefers_the_live_port(self):
        services, _ = self._services()
        screen = next(s for s in services if s["id"] == "screen_sharing")
        self.assertTrue(
            screen["enabled"], "the launchd label said loaded and the port said closed"
        )

    def test_the_uncontrollable_services_are_still_listed(self):
        services, _ = self._services()
        ids = [s["id"] for s in services]
        for expected in ("remote_management", "media_sharing", "printer_sharing",
                         "internet_sharing", "bluetooth_sharing"):
            self.assertIn(expected, ids)


# ── /api/vms ─────────────────────────────────────────────────────────────────

class VmListingTests(unittest.TestCase):
    def _list(self):
        tracker = Concurrency()
        with (
            mock.patch.object(vms_svc, "list_utm_vms",
                              lambda: tracker.run("utm", [{"id": "ubuntu"}, {"id": "debian"}])),
            mock.patch.object(vms_svc, "list_orb_machines",
                              lambda: tracker.run("orb", [{"id": "orb-alpine"}])),
            mock.patch.object(vms_svc, "_utm_available", lambda: True),
            mock.patch.object(vms_svc, "_orb_available", lambda: True),
        ):
            data = vms_svc.list_all_vms()
        return data, tracker

    def test_the_two_hypervisors_are_listed_concurrently(self):
        _, tracker = self._list()
        self.assertGreater(tracker.peak, 1, "UTM and OrbStack know nothing of each other")

    def test_utm_rows_still_come_before_orbstack(self):
        data, _ = self._list()
        self.assertEqual([v["id"] for v in data["vms"]], ["ubuntu", "debian", "orb-alpine"])
        self.assertEqual(data["utm_count"], 2)
        self.assertEqual(data["orb_count"], 1)


if __name__ == "__main__":
    unittest.main()


# ── the interface table ──────────────────────────────────────────────────────

class InterfaceTableMemoTests(unittest.TestCase):
    """``ifconfig -a`` and ``networksetup -listallhardwareports``, read once.

    Five call sites read the interface table and three read the hardware ports,
    several of them inside loops. ``/api/system/network/alias/auto`` ran each twice
    per request -- ``interface_addresses`` and ``preferred_active_device`` both need
    the table -- and ``/api/system/network`` many more times, returning identical
    output every time.

    The risk a memo introduces is staleness, and it is a real one here: unlike a
    binary's version string this *is* live state, so an added or removed IP alias
    must not keep reading back the old table. Every mutation in the module reaches
    ``_bust()``, which now clears these two with the caches that were already there.
    Both halves are asserted, because a memo without working invalidation looks
    exactly like a memo with it until someone changes an alias.
    """

    IFCONFIG = (
        "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
        "\tinet 192.168.1.9 netmask 0xffffff00 broadcast 192.168.1.255\n"
        "en1: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500\n"
        "\tinet 10.0.0.5 netmask 0xffffff00 broadcast 10.0.0.255\n"
    )
    PORTS = (
        "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n\n"
        "Hardware Port: Ethernet\nDevice: en1\nEthernet Address: 11:22:33:44:55:66\n"
    )

    def setUp(self):
        from hub import network_svc

        self.net = network_svc
        self._reset()
        self.addCleanup(self._reset)

    def _reset(self):
        self.net.interfaces.invalidate()
        self.net.hardware_ports.invalidate()

    def _counting_sh(self, extra=None):
        calls: list[list[str]] = []
        lock = threading.Lock()

        def fake_sh(cmd, *a, **kw):
            argv = [str(c) for c in cmd]
            with lock:
                calls.append(argv)
            if "ifconfig" in argv[0]:
                return 0, (extra or self.IFCONFIG), ""
            if "-listallhardwareports" in argv:
                return 0, self.PORTS, ""
            return 1, "", ""

        return calls, fake_sh

    def test_repeated_reads_share_one_ifconfig(self):
        calls, fake_sh = self._counting_sh()
        with mock.patch.object(self.net, "sh", fake_sh):
            first = self.net.interfaces()
            second = self.net.interfaces()
        ifconfigs = [c for c in calls if "ifconfig" in c[0]]
        self.assertEqual(
            len(ifconfigs), 1,
            f"two reads ran `ifconfig -a` {len(ifconfigs)} times for identical output",
        )
        self.assertEqual([i["name"] for i in first], ["en0", "en1"])
        self.assertEqual(first, second)

    def test_repeated_reads_share_one_hardware_port_listing(self):
        calls, fake_sh = self._counting_sh()
        with mock.patch.object(self.net, "sh", fake_sh):
            self.net.hardware_ports()
            self.net.hardware_ports()
        listings = [c for c in calls if "-listallhardwareports" in c]
        self.assertEqual(len(listings), 1)

    def test_concurrent_readers_do_not_stampede_a_cold_cache(self):
        """The reason this uses ``ttl_memo`` rather than the older hand-rolled memo.

        These call sites now sit inside fan-outs, so several workers reach a cold
        cache together. A plain check-then-compute lets them all run the command.
        """
        calls = []
        lock = threading.Lock()

        def slow_sh(cmd, *a, **kw):
            with lock:
                calls.append([str(c) for c in cmd])
            time.sleep(0.05)
            return 0, self.IFCONFIG, ""

        with mock.patch.object(self.net, "sh", slow_sh):
            threads = [threading.Thread(target=self.net.interfaces) for _ in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        ifconfigs = [c for c in calls if "ifconfig" in c[0]]
        self.assertEqual(
            len(ifconfigs), 1,
            f"six concurrent readers ran `ifconfig -a` {len(ifconfigs)} times",
        )

    def test_busting_the_caches_reveals_a_new_alias(self):
        """The property that makes the memo safe to have at all."""
        before = self.IFCONFIG
        after = self.IFCONFIG + "\tinet 192.168.1.204 netmask 0xffffffff\n"

        calls, fake_sh = self._counting_sh(extra=before)
        with mock.patch.object(self.net, "sh", fake_sh):
            self.assertNotIn(
                "192.168.1.204",
                str(self.net.interfaces()),
                "the fixture already contained the alias; the test proves nothing",
            )

        _, fake_after = self._counting_sh(extra=after)
        with mock.patch.object(self.net, "sh", fake_after):
            self.assertNotIn(
                "192.168.1.204", str(self.net.interfaces()),
                "the cache should still be serving the old table at this point",
            )
            self.net._bust()
            self.assertIn(
                "192.168.1.204", str(self.net.interfaces()),
                "_bust() did not clear the interface memo, so adding an IP alias "
                "would keep reporting the old table",
            )

    def test_every_state_changing_command_reaches_bust(self):
        """Structural, because a new mutation that forgets it fails silently."""
        import ast

        source = (BASE / "hub" / "network_svc.py").read_text()
        tree = ast.parse(source)
        markers = ("'alias'", "-alias", "-setnetworkserviceenabled", "-setdnsservers",
                   "-setsearchdomains", "-setmanual", "-setdhcp")
        offenders = []
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            body = ast.unparse(node)
            if "sh(" not in body:
                continue
            if any(m in body for m in markers) and "_bust()" not in body:
                offenders.append(node.name)
        self.assertEqual(
            offenders, [],
            "these change network state without invalidating the interface memo, so "
            f"the page would keep showing the previous table: {offenders}",
        )


class AliasAutoStatusTests(unittest.TestCase):
    def test_the_three_opening_reads_overlap(self):
        from hub import network_svc

        tracker = Concurrency()
        conf = {"ips": ["192.168.1.204"], "device": "en0", "enabled": True}
        with (
            mock.patch.object(network_svc, "_alias_settings",
                              lambda: tracker.run("conf", conf)),
            mock.patch.object(network_svc, "preferred_active_device",
                              lambda: tracker.run("preferred", {"device": "en0"})),
            mock.patch.object(network_svc, "interface_addresses",
                              lambda: tracker.run("addresses", [])),
            mock.patch.object(network_svc, "_alias_local_route",
                              lambda ip: {"ok": True, "device": "en0"}),
            mock.patch.object(network_svc, "find_ip_locations",
                              lambda ip, addresses=None: [{"device": "en0"}]),
        ):
            data = network_svc.alias_auto_status()

        self.assertGreater(
            tracker.peak, 1, "three independent opening reads ran in sequence"
        )
        self.assertEqual([s["ip"] for s in data["ips"]], ["192.168.1.204"])
        self.assertTrue(data["ips"][0]["on_preferred"])

    def test_a_failing_route_lookup_still_yields_a_row(self):
        from hub import network_svc

        conf = {"ips": ["192.168.1.204", "192.168.1.205"], "device": "en0"}

        def boom(ip):
            if ip.endswith(".205"):
                raise OSError("no route")
            return {"ok": True, "device": "en0"}

        with (
            mock.patch.object(network_svc, "_alias_settings", lambda: conf),
            mock.patch.object(network_svc, "preferred_active_device", lambda: None),
            mock.patch.object(network_svc, "interface_addresses", lambda: []),
            mock.patch.object(network_svc, "_alias_local_route", boom),
            mock.patch.object(network_svc, "find_ip_locations",
                              lambda ip, addresses=None: []),
        ):
            data = network_svc.alias_auto_status()

        self.assertEqual(
            [s["ip"] for s in data["ips"]],
            ["192.168.1.204", "192.168.1.205"],
            "a raising route lookup dropped its row instead of reporting the failure",
        )
        self.assertFalse(data["ips"][1]["local_route"]["ok"])


# ── /api/cloudflared/status ──────────────────────────────────────────────────

class CloudflaredStatusTests(unittest.TestCase):
    """A local liveness check and a round-trip to Cloudflare, in one wave.

    This endpoint is polled, and the tunnel list is a remote API call, so the page
    used to wait for Cloudflare before it could report whether the daemon was even
    running.

    What is *not* fanned out matters as much: ``_is_running`` short-circuits on
    ``ps`` before touching launchctl, and ``_launchd_running`` tries its second
    label only when the first misses. Overlapping those would add a spawn to the
    healthy path in order to save one on the broken path.
    """

    def _status(self, tunnels=None, running=True):
        from hub import cloudflared_svc

        tracker = Concurrency()
        import contextlib

        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for name, value in {
            "_ensure_dirs": lambda: None,
            "_load_state": lambda: {"mode": "token", "tunnel_name": "home"},
            "_is_running": lambda: tracker.run("running", running),
            "_logged_in": lambda: True,
            "list_tunnels": tunnels or (
                lambda: tracker.run("tunnels", [{"id": "abc", "name": "home"}])
            ),
            "_login_process_pending": lambda: False,
            "_bin": lambda: "/opt/homebrew/bin/cloudflared",
        }.items():
            stack.enter_context(mock.patch.object(cloudflared_svc, name, value))
        return cloudflared_svc.status(), tracker

    def test_the_liveness_check_and_the_tunnel_list_overlap(self):
        _, tracker = self._status()
        self.assertGreater(
            tracker.peak, 1,
            "the daemon state waited behind a network call to Cloudflare",
        )

    def test_the_payload_is_unchanged(self):
        data, _ = self._status()
        self.assertTrue(data["ok"])
        self.assertTrue(data["running"])
        self.assertEqual(data["state"], "ok")
        self.assertEqual(data["tunnels"], [{"id": "abc", "name": "home"}])
        self.assertIsNone(data["tunnels_error"])
        self.assertEqual(data["active_tunnel"], "home")

    def test_a_stopped_daemon_still_reports_its_tunnels(self):
        data, _ = self._status(running=False)
        self.assertFalse(data["running"])
        self.assertEqual(data["state"], "down")
        self.assertEqual(len(data["tunnels"]), 1, "the tunnel list was lost")

    def test_an_unreachable_cloudflare_becomes_an_error_field_not_a_500(self):
        def boom():
            raise RuntimeError("api.cloudflare.com unreachable")

        data, _ = self._status(tunnels=boom)
        self.assertEqual(data["tunnels"], [])
        self.assertIn("unreachable", data["tunnels_error"])
        self.assertTrue(data["ok"], "one failed probe took down the whole status call")
        self.assertTrue(data["running"], "the liveness result was discarded with it")

    def test_a_logged_out_account_is_not_queried(self):
        from hub import cloudflared_svc

        calls = []
        import contextlib

        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for name, value in {
            "_ensure_dirs": lambda: None,
            "_load_state": lambda: {},
            "_is_running": lambda: False,
            "_logged_in": lambda: False,
            "list_tunnels": lambda: calls.append("queried") or [],
            "_login_process_pending": lambda: False,
            "_bin": lambda: "/opt/homebrew/bin/cloudflared",
        }.items():
            stack.enter_context(mock.patch.object(cloudflared_svc, name, value))
        data = cloudflared_svc.status()
        self.assertEqual(calls, [], "queried Cloudflare without a certificate")
        self.assertEqual(data["tunnels"], [])
        self.assertIsNone(data["tunnels_error"])


# ── single-flight, not merely cached ─────────────────────────────────────────

class SingleFlightTests(unittest.TestCase):
    """Two caches that were not single-flight, which under fan-out is barely a cache.

    Both used the check-then-compute shape: take the lock, test the TTL, release it,
    then do the work. That is correct only while callers arrive one at a time. Once
    several branches of a fan-out reach the same read simultaneously they all miss
    the cold cache, all run the command, and the cache never gets a chance to help.

    Measured before the fix: one ``/api/apps/managed`` read ran
    ``route -n get default`` and ``ipconfig getifaddr`` three times apiece for one
    answer, and ``/api/system/network`` ran
    ``networksetup -listnetworkserviceorder`` three times -- better than the six it
    had before any memo, but the remaining three were pure duplication.
    """

    def test_concurrent_lan_ip_detection_probes_once(self):
        from hub import host_address

        host_address._detect_cache.update(t=0.0, value=None)
        self.addCleanup(host_address._detect_cache.update, t=0.0, value=None)

        calls = []
        lock = threading.Lock()

        def slow_sh(cmd, *a, **kw):
            with lock:
                calls.append([str(c) for c in cmd])
            time.sleep(0.05)
            if "route" in str(cmd[0]):
                return 0, "   route to: default\n  interface: en0\n", ""
            return 0, "192.168.1.9", ""

        results = []
        with mock.patch.object(host_address, "sh", slow_sh):
            threads = [
                threading.Thread(target=lambda: results.append(host_address.detect_lan_ip()))
                for _ in range(6)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        routes = [c for c in calls if "route" in c[0]]
        self.assertEqual(
            len(routes), 1,
            f"six concurrent callers ran `route -n get default` {len(routes)} times",
        )
        self.assertEqual(len(results), 6)
        self.assertEqual(set(results), {"192.168.1.9"}, "callers disagreed")

    def test_force_still_bypasses_the_cache(self):
        """``force=True`` is the caller saying the previous answer is known stale."""
        from hub import host_address

        host_address._detect_cache.update(t=0.0, value=None)
        self.addCleanup(host_address._detect_cache.update, t=0.0, value=None)

        answers = iter(["192.168.1.9", "192.168.1.50"])
        calls = []

        def fake_sh(cmd, *a, **kw):
            calls.append([str(c) for c in cmd])
            if "route" in str(cmd[0]):
                return 0, "  interface: en0\n", ""
            return 0, next(answers), ""

        with mock.patch.object(host_address, "sh", fake_sh):
            first = host_address.detect_lan_ip()
            cached = host_address.detect_lan_ip()
            forced = host_address.detect_lan_ip(force=True)

        self.assertEqual(first, "192.168.1.9")
        self.assertEqual(cached, "192.168.1.9", "the second read should be cached")
        self.assertEqual(forced, "192.168.1.50", "force did not re-detect")

    def test_a_configured_host_never_reaches_the_detection(self):
        """Only the subprocess half is cached; the config half stays live."""
        from hub import host_address

        calls = []
        with (
            mock.patch.object(host_address, "configured_host", lambda: "nas.local"),
            mock.patch.object(host_address, "sh",
                              lambda *a, **k: calls.append("probed") or (1, "", "")),
        ):
            self.assertEqual(host_address.host_ip(), "nas.local")
        self.assertEqual(calls, [], "a fixed host still ran the LAN detection")

    def test_concurrent_service_order_reads_run_the_command_once(self):
        from hub import network_svc

        network_svc._network_service_order_entries.invalidate()
        self.addCleanup(network_svc._network_service_order_entries.invalidate)

        calls = []
        lock = threading.Lock()

        def slow_sh(cmd, *a, **kw):
            with lock:
                calls.append([str(c) for c in cmd])
            time.sleep(0.05)
            return 0, "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n", ""

        with mock.patch.object(network_svc, "sh", slow_sh):
            threads = [
                threading.Thread(target=network_svc._network_service_order_entries)
                for _ in range(6)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        orders = [c for c in calls if "-listnetworkserviceorder" in c]
        self.assertEqual(
            len(orders), 1,
            f"six concurrent readers ran the service order {len(orders)} times",
        )

    def test_busting_clears_the_service_order_too(self):
        from hub import network_svc

        network_svc._network_service_order_entries.invalidate()
        self.addCleanup(network_svc._network_service_order_entries.invalidate)

        first = "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n"
        second = first + "(2) Ethernet\n(Hardware Port: Ethernet, Device: en1)\n"
        state = {"out": first}

        with mock.patch.object(
            network_svc, "sh", lambda *a, **k: (0, state["out"], "")
        ):
            before = len(network_svc._network_service_order_entries())
            state["out"] = second
            self.assertEqual(
                len(network_svc._network_service_order_entries()), before,
                "the cache should still be serving the old order here",
            )
            network_svc._bust()
            self.assertGreater(
                len(network_svc._network_service_order_entries()), before,
                "_bust() did not clear the service-order memo, so a reconfigured "
                "network would keep reporting the previous order",
            )
