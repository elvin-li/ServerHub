"""A deliberately stopped worker must not be reported as a fault to go fix.

`~/.immich-accelerator/worker.quarantine` is written when the enclosure holding
the media volume has failed isolated F_FULLFSYNC write-barrier tests -- on this
host, with EIO, on a USB path that was never replaced.  keep-immich-alive.sh reads
the same file and refuses to start the worker while it exists.

Two things were wrong once the marker was finally being read:

  * the check still reported `level: "error"`, so a deliberate pause looked
    exactly like a crash, turned the whole health summary red, and invited the one
    action the marker exists to prevent -- resuming writes to hardware that loses
    write barriers;
  * the inverse state had no representation at all.  A worker *running* while the
    marker stands came back `ok: True` purely because a pid existed, which is the
    dangerous case reported as the healthy one.

Detail and fix are error codes rather than prose, resolved by the SPA through its
`err.immich.*` keys, so this also pins that every state's code has a translation.
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import immich_svc  # noqa: E402
from hub.errors import CODES  # noqa: E402

RUNNING = 4321


class WorkerCheckStatesTests(unittest.TestCase):
    def test_running_with_no_marker_is_healthy(self):
        check = immich_svc._worker_check(RUNNING, False)
        self.assertTrue(check["ok"])
        self.assertEqual(check["level"], "ok")
        self.assertIn(str(RUNNING), check["detail"])
        self.assertEqual(check["fix"], "")

    def test_stopped_under_quarantine_is_a_warning_not_an_error(self):
        check = immich_svc._worker_check(None, True)
        self.assertFalse(check["ok"])
        self.assertEqual(
            check["level"],
            "warn",
            "a deliberate pause was reported at the same severity as a crash, "
            "which turns the health summary red for a state nobody should act on",
        )
        self.assertEqual(check["detail"], "immich.worker_quarantined")

    def test_stopped_under_quarantine_does_not_advise_starting_it(self):
        check = immich_svc._worker_check(None, True)
        self.assertNotIn(
            "start-worker-native",
            check["fix"],
            "the remedy column pointed at the one action the marker forbids",
        )
        self.assertEqual(check["fix"], "immich.worker_lift_quarantine")

    def test_stopped_with_no_marker_still_says_how_to_start_it(self):
        # Reading the marker must not swallow the ordinary crashed case.
        check = immich_svc._worker_check(None, False)
        self.assertFalse(check["ok"])
        self.assertEqual(check["level"], "error")
        self.assertEqual(check["detail"], "immich.worker_down")
        self.assertIn("start-worker-native", check["fix"])

    def test_running_despite_the_marker_is_an_error(self):
        check = immich_svc._worker_check(RUNNING, True)
        self.assertFalse(
            check["ok"],
            "a worker writing to quarantined hardware was reported as healthy "
            "because it had a pid",
        )
        self.assertEqual(check["level"], "error")
        self.assertEqual(
            check["detail"], "immich.worker_running_while_quarantined"
        )

    def test_every_state_reports_under_one_id_and_label(self):
        seen = {
            (c["id"], c["name"])
            for c in (
                immich_svc._worker_check(RUNNING, False),
                immich_svc._worker_check(RUNNING, True),
                immich_svc._worker_check(None, True),
                immich_svc._worker_check(None, False),
            )
        }
        self.assertEqual(seen, {("immich_worker", immich_svc.WORKER_LABEL)})

    def test_the_four_states_are_all_distinct(self):
        details = [
            immich_svc._worker_check(*args)["detail"]
            for args in ((RUNNING, False), (RUNNING, True), (None, True), (None, False))
        ]
        self.assertEqual(len(set(details)), 4, details)


class WorkerCodesAreResolvableTests(unittest.TestCase):
    """Every code the check emits needs a registration and three translations."""

    CODES_USED = (
        "immich.worker_down",
        "immich.worker_quarantined",
        "immich.worker_lift_quarantine",
        "immich.worker_running_while_quarantined",
    )

    def test_each_code_is_registered(self):
        for code in self.CODES_USED:
            with self.subTest(code=code):
                self.assertIn(code, CODES)

    def test_each_code_has_a_key_in_every_locale(self):
        for locale in ("zh-CN", "en", "ja"):
            source = (BASE / "web" / "src" / "i18n" / f"{locale}.js").read_text(
                encoding="utf-8"
            )
            for code in self.CODES_USED:
                leaf = code.split(".", 1)[1]
                with self.subTest(locale=locale, code=code):
                    self.assertRegex(
                        source,
                        rf"\b{re.escape(leaf)}\s*:",
                        f"err.{code} has no {locale} translation, so the health "
                        "page would render the raw code",
                    )

    def test_the_marker_path_is_not_on_the_suspect_volume(self):
        # Reading the marker must never touch the volume it is about: a hung mount
        # there would block the whole health page.
        self.assertEqual(immich_svc.QUARANTINE.parent, immich_svc.ACCEL)
        self.assertNotIn("/Volumes/", str(immich_svc.QUARANTINE))

    def test_the_check_emits_no_untranslated_prose(self):
        # The healthy branch is allowed a pid/uptime string; the three fault
        # branches must be codes, or the SPA shows Chinese to an English operator.
        for args in ((None, True), (None, False), (RUNNING, True)):
            check = immich_svc._worker_check(*args)
            with self.subTest(args=args):
                self.assertIn(check["detail"], CODES, json.dumps(check, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
