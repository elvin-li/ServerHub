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

    def test_an_unwrapped_section_still_fails_the_bundle(self):
        """A pre-existing gap, pinned so that closing it is a deliberate edit.

        ``datetime``, ``power``, ``management`` and ``other`` have no try/except, so
        a raise from any of them fails the whole request -- and the page offers this
        as a "download diagnostics" button, which is pressed exactly when something
        is broken. Parallelising did not change this: serially the exception also
        left the function. Worth fixing, but as its own behaviour change rather than
        buried in a performance commit.
        """
        def boom():
            raise RuntimeError("pmset is wedged")

        with self.assertRaises(RuntimeError):
            self._collect(get_management_access=boom)

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
