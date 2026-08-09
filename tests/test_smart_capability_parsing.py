"""What ``smartctl -c`` says a disk can do, and how long it takes.

``_capabilities`` decides two things the disk-health page acts on: which self-tests
appear as buttons, and what the page tells the operator to expect before coming
back.  Both were wrong on every real drive, in ways that looked like working code:

* **No extended test was ever offered.**  The supported-test scan looked for the
  literal ``"long self-test"``.  The ATA spec calls it the *extended* self-test and
  smartctl prints ``Extended self-test routine``, so the token matched nothing,
  ``long`` never reached ``supported``, and ``start_test`` rejected it with
  ``kind_unsupported``.  The short test worked, which is what made this invisible:
  the page looked healthy and simply never grew a "long" button.
* **Every duration was a guess.**  The regex wanted ``(\\d+)\\s*minutes`` and
  smartctl writes ``recommended polling time:  (   2) minutes.`` -- the closing
  paren sits between the digits and the unit.  Nothing matched, so
  ``estimated_minutes`` silently fell back to the hardcoded ``_KIND_HINT_MINUTES``
  and reported 120 minutes for an extended test the drive said would take 74.

Neither is observable without a real disk, which is why they survived: the
fallbacks are plausible values, not blank fields or exceptions.  These tests use
verbatim smartctl output so that the difference is visible without one.

The "no support" answers matter as much as the positive ones.  An empty
``supported`` list is a real and common result -- Apple's internal NVMe controllers
implement SMART attributes but no self-test at all, and USB/Thunderbolt enclosures
on macOS refuse the passthrough entirely -- and those two cases must stay
distinguishable, because only the second one means the disk is fine but untestable.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import smart_test_svc  # noqa: E402
from hub.smart_test_svc import TEST_KINDS, _capabilities  # noqa: E402

#: Verbatim `smartctl -c` output from a spinning SATA disk, tabs included.  The
#: parenthesised polling times and the "Extended" spelling are the whole point.
ATA_CAPS = (
    "General SMART Values:\n"
    "Offline data collection status:  (0x00)\tOffline data collection activity\n"
    "\t\t\t\t\twas never started.\n"
    "Total time to complete Offline\n"
    "data collection: \t\t(  430) seconds.\n"
    "Offline data collection\n"
    "capabilities: \t\t\t (0x5b) SMART execute Offline immediate.\n"
    "\t\t\t\t\tSelf-test supported.\n"
    "SMART capabilities:            (0x0003)\tSaves SMART data before entering\n"
    "\t\t\t\t\tpower-saving mode.\n"
    "Error logging capability:        (0x01)\tError logs supported.\n"
    "Short self-test routine \n"
    "recommended polling time: \t (   2) minutes.\n"
    "Extended self-test routine\n"
    "recommended polling time: \t (  74) minutes.\n"
    "Conveyance self-test routine\n"
    "recommended polling time: \t (   2) minutes.\n"
    "SCT capabilities: \t       (0x103f)\tSCT Status supported.\n"
)

#: A healthy ATA self-test log, so nothing below trips the "unsupported" branch.
ATA_LOG = (
    0,
    "SMART Self-test log structure revision number 1\n"
    "Num  Test_Description    Status                  Remaining  LifeTime(hours)  LBA_of_first_error\n"
    "# 1  Short offline       Completed without error       00%      1234         -\n",
    "",
)


def caps(raw: str, *, rc: int = 0, err: str = "", log=ATA_LOG) -> dict:
    return _capabilities("/dev/disk0", selftest=log, caps_raw=(rc, raw, err))


class ExtendedTestIsOfferedTests(unittest.TestCase):
    """The regression that hid a whole feature."""

    def test_a_drive_that_reports_an_extended_routine_offers_a_long_test(self):
        self.assertIn(
            "long", caps(ATA_CAPS)["supported"],
            'smartctl writes "Extended self-test routine"; scanning for "long '
            'self-test" matched nothing, so the page never offered the extended test',
        )

    def test_every_routine_the_drive_lists_is_offered(self):
        self.assertEqual(
            caps(ATA_CAPS)["supported"], ["short", "long", "conveyance", "offline"]
        )

    def test_the_offered_kinds_are_all_startable(self):
        """``start_test`` validates against ``TEST_KINDS``, so the two must agree.

        A kind in ``supported`` that ``TEST_KINDS`` does not know would render a
        button that always answers ``bad_kind``.
        """
        for kind in caps(ATA_CAPS)["supported"]:
            self.assertIn(kind, TEST_KINDS, f"{kind!r} is offered but not startable")

    def test_the_order_is_the_declared_one(self):
        """The page renders these as buttons in list order."""
        supported = caps(ATA_CAPS)["supported"]
        self.assertEqual(supported, [k for k in TEST_KINDS if k in supported])

    def test_a_drive_that_lists_no_routines_offers_nothing(self):
        self.assertEqual(caps("SMART capabilities: (0x0003)\n")["supported"], [])


class PollingTimeTests(unittest.TestCase):
    """Durations come from the drive, not from a table of guesses."""

    def test_the_drives_own_numbers_are_used(self):
        self.assertEqual(
            caps(ATA_CAPS)["estimated_minutes"],
            {"short": 2, "long": 74, "conveyance": 2},
        )

    def test_the_parenthesised_number_is_read(self):
        """``recommended polling time:  (   2) minutes.`` -- paren, then the unit.

        The previous pattern wanted digits immediately before "minutes", which
        never occurs in smartctl's output.
        """
        minutes = caps(ATA_CAPS)["estimated_minutes"]
        self.assertNotEqual(
            minutes.get("long"), smart_test_svc._KIND_HINT_MINUTES["long"],
            "the extended duration is still the hardcoded 120-minute guess",
        )
        self.assertEqual(minutes["long"], 74)

    def test_a_routine_without_a_polling_line_does_not_borrow_the_next_ones(self):
        """Bounding the gap is what stops a wrong number being shown confidently.

        An unbounded lazy match would run past the missing line into the following
        routine's block and report Conveyance's 9 minutes as the extended test's
        duration.
        """
        partial = (
            "Short self-test routine \n"
            "recommended polling time: \t (   2) minutes.\n"
            "Extended self-test routine\n"
            "Conveyance self-test routine\n"
            "recommended polling time: \t (   9) minutes.\n"
        )
        minutes = caps(partial)["estimated_minutes"]
        self.assertEqual(minutes.get("short"), 2)
        self.assertEqual(minutes.get("conveyance"), 9)
        self.assertNotIn(
            "long", minutes,
            "the extended test has no reported duration and must not claim one",
        )

    def test_the_hint_table_still_covers_a_drive_that_reports_no_times(self):
        """The fallback is correct behaviour, just not the normal case.

        A drive can name its routines without publishing polling times; the page
        still needs to say roughly how long to wait.
        """
        no_times = (
            "Short self-test routine\n"
            "Extended self-test routine\n"
            "Conveyance self-test routine\n"
        )
        result = caps(no_times)
        self.assertEqual(result["supported"], ["short", "long", "conveyance"])
        self.assertEqual(
            result["estimated_minutes"],
            {k: v for k, v in smart_test_svc._KIND_HINT_MINUTES.items()
             if k in result["supported"]},
        )

    def test_a_three_digit_duration_is_read_whole(self):
        wide = (
            "Extended self-test routine\n"
            "recommended polling time: \t ( 255) minutes.\n"
        )
        self.assertEqual(caps(wide)["estimated_minutes"]["long"], 255)

    def test_offline_has_no_polling_time_of_its_own(self):
        """smartctl reports it in seconds under a different heading."""
        self.assertNotIn("offline", smart_test_svc._POLLING_LABELS)
        self.assertNotIn("offline", caps(ATA_CAPS)["estimated_minutes"])


class NoSupportTests(unittest.TestCase):
    """The two ways a disk answers "you cannot test me" are not the same thing."""

    def test_an_nvme_controller_with_no_self_test_says_so(self):
        result = caps(
            "SMART/Health Information (NVMe Log 0x02)\nTemperature: 31 Celsius\n",
            log=(0, "Self-tests not supported\n", ""),
        )
        self.assertEqual(result["supported"], [])
        self.assertEqual(result["reason"], "self_tests_unsupported")
        self.assertTrue(
            result["readable"], "the drive answered; only the self-test is missing"
        )

    def test_an_enclosure_that_refuses_passthrough_is_a_different_reason(self):
        result = caps("", rc=2, err="Not a device of type 'scsi'",
                      log=(2, "", "not supported by device"))
        self.assertEqual(result["supported"], [])
        self.assertEqual(result["reason"], "no_smart_passthrough")
        self.assertFalse(result["readable"])

    def test_a_readable_drive_reports_no_reason(self):
        result = caps(ATA_CAPS)
        self.assertEqual(result["reason"], "")
        self.assertTrue(result["readable"])
        self.assertTrue(result["available"])

    def test_an_unsupported_drive_offers_nothing_even_if_it_names_routines(self):
        """The self-test log's verdict wins over a capability line.

        Otherwise a controller that echoes the routine names would grow buttons
        that every attempt rejects.
        """
        result = caps(ATA_CAPS, log=(0, "Self-tests not supported\n", ""))
        self.assertEqual(result["supported"], [])
        self.assertFalse(result["available"])


class ExtendedTestActuallyRunsTests(unittest.TestCase):
    """What the parse bug cost in practice.

    ``supported`` is not advisory: it gates both entry points.  ``start_test``
    answers ``kind_unsupported``, and the scheduler journals ``error: unsupported``
    and moves on.  So a monthly extended self-test configured through
    ``PUT /api/smart/schedule`` -- which validates ``kind`` against ``TEST_KINDS``
    and accepts "long" happily -- was skipped on every single run, logging a reason
    that reads like a hardware limitation rather than a bad regex.  The disk was
    never scanned, which is the one thing this module exists to do.
    """

    def setUp(self):
        smart_test_svc._device_type_cache.clear()
        smart_test_svc._cache.update(t=0.0, v=None)
        self.addCleanup(smart_test_svc._device_type_cache.clear)
        self.addCleanup(smart_test_svc._cache.update, t=0.0, v=None)
        self.started: list[list[str]] = []
        self.journal: list[dict] = []

    def _raw(self, argv, *, timeout):
        if "-c" in argv:
            return 0, ATA_CAPS, ""
        if "selftest" in argv:
            return ATA_LOG
        return 0, "Device Model: Fake", ""

    def _sh(self, cmd, *a, **kw):
        argv = [str(c) for c in cmd]
        if "-t" in argv:
            self.started.append(argv)
        return 0, "Self-test has begun", ""

    def _patches(self, schedule=None):
        import contextlib

        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        targets = {
            "_raw_smartctl": self._raw,
            "sh": self._sh,
            "_device_nodes": lambda: ["/dev/disk0"],
            "_append_history": self.journal.append,
            "passwordless_available": lambda: True,
            "update_settings": lambda _payload: None,
            "cfg": lambda: {"settings": {"smart_schedule": schedule or {}}},
        }
        for name, value in targets.items():
            stack.enter_context(mock.patch.object(smart_test_svc, name, value))
        return stack

    def test_an_operator_can_start_an_extended_test(self):
        with self._patches():
            result = smart_test_svc.start_test("/dev/disk0", "long")

        self.assertTrue(
            result["ok"],
            f"start_test refused the extended test: {result.get('error')}",
        )
        self.assertEqual(len(self.started), 1, "no smartctl -t was issued")
        self.assertIn("long", self.started[0])
        self.assertIn("/dev/disk0", self.started[0])

    def test_the_estimate_returned_to_the_caller_is_the_drives_own(self):
        """``start_test`` still answers from the hint table, so this is unchanged.

        Pinned because the two numbers now disagree -- the drive says 74, the hint
        says 120 -- and that difference should be a deliberate decision rather than
        an accident of which code path a caller happens to hit.
        """
        with self._patches():
            result = smart_test_svc.start_test("/dev/disk0", "long")
        self.assertEqual(
            result["estimated_minutes"], smart_test_svc._KIND_HINT_MINUTES["long"]
        )

    def test_a_scheduled_extended_test_is_no_longer_skipped(self):
        schedule = {
            "interval": "daily",
            "kind": "long",
            "devices": ["/dev/disk0"],
            "last_run": 0,
        }
        with self._patches(schedule=schedule):
            result = smart_test_svc.run_due_tests()

        self.assertTrue(result["ok"])
        self.assertEqual(
            result["ran"], 1,
            "the scheduled extended test did not start",
        )
        self.assertEqual(len(self.started), 1, "no smartctl -t reached the disk")
        self.assertIn("long", self.started[0])

        unsupported = [r for r in self.journal if r.get("error") == "unsupported"]
        self.assertEqual(
            unsupported, [],
            'the run was journalled as "unsupported" -- the reason a scheduled scan '
            "silently never happened",
        )

    def test_a_scheduled_short_test_still_works(self):
        """The kind that always worked must not regress."""
        schedule = {
            "interval": "daily",
            "kind": "short",
            "devices": ["/dev/disk0"],
            "last_run": 0,
        }
        with self._patches(schedule=schedule):
            result = smart_test_svc.run_due_tests()
        self.assertEqual(result["ran"], 1)
        self.assertIn("short", self.started[0])

    def test_a_drive_with_no_self_test_support_is_still_refused(self):
        """The guard has to keep working, or the fix just moves the failure later."""
        def raw(argv, *, timeout):
            if "-c" in argv:
                return 0, "SMART/Health Information (NVMe Log 0x02)\n", ""
            if "selftest" in argv:
                return 0, "Self-tests not supported\n", ""
            return 0, "Device Model: Fake", ""

        with self._patches(), mock.patch.object(smart_test_svc, "_raw_smartctl", raw):
            result = smart_test_svc.start_test("/dev/disk0", "long")

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "unsupported")
        self.assertEqual(self.started, [], "a command went to a disk that rejects it")


class KindVocabularyTests(unittest.TestCase):
    """The token table and the panel's kind list have to stay in step."""

    def test_every_kind_has_a_token(self):
        self.assertEqual(set(smart_test_svc._KIND_TOKENS), set(TEST_KINDS))

    def test_every_kind_has_a_fallback_duration(self):
        self.assertEqual(set(smart_test_svc._KIND_HINT_MINUTES), set(TEST_KINDS))

    def test_no_token_looks_for_the_panels_own_name_for_the_extended_test(self):
        """The bug in one line: smartctl never writes "long"."""
        self.assertNotIn(
            "long self-test", smart_test_svc._KIND_TOKENS["long"],
            'smartctl spells this "extended"; matching "long" is what broke it',
        )

    def test_the_polling_labels_are_smartctls_spelling(self):
        self.assertEqual(smart_test_svc._POLLING_LABELS["long"], "Extended")


if __name__ == "__main__":
    unittest.main()
