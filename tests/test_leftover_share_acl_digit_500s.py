"""Leftover >4300-digit numbers in the share-ACL and scheduler parsers.

Prior passes guarded the smartctl / top / pmset digit parsers against
CPython's 4300-digit str->int ValueError (see
test_leftover_smart_power_digit_500s.py).  The ``ls -lde`` ACL parser still
called bare ``int()`` on an unbounded ``(?P<index>\\d+)`` capture: an over-cap
entry index raised ValueError — which is not ShareAclError, the only thing the
routers catch — out of ``parse_acl_listing`` through ``read_acl`` and 500'd
GET /api/shares/acl, and PUT /api/shares/acl through ``set_user_access``'s
before/after reads.

The index is load-bearing (removals run ``chmod -a# <index>``), so the guarded
parser skips the garbled row like any other unparsable line rather than
inventing a position for it.

The battery also pins hunted paths that already survive this class, so a
refactor cannot quietly reintroduce it:

* the ACL ``local_users`` uid parse (guarded ``int()``: the row is skipped);
* the scheduler cron-field parses, whose documented contract is ValueError —
  an over-cap step/range/value stays inside that contract, so ``valid_cron``
  answers False and ``next_run_ts`` answers None instead of 500ing
  GET /api/scheduler/jobs.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest import mock

from hub import scheduler_svc, share_acl_svc

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


#: A real ``ls -lde`` shape whose first ACL row carries an over-cap index.
_POISONED_LISTING = (
    "drwxr-xr-x+ 5 a0000  staff  160 Aug  4 13:42 /Users/a0000/Public\n"
    f" {_HUGE_DIGITS}: user:mallory allow read,write\n"
    " 1: group:everyone deny delete\n"
    " 2: user:alice allow list,search,readattr\n"
)


class ParseAclDigitLimitTests(unittest.TestCase):
    """GET/PUT /api/shares/acl used to 500 on an over-cap entry index."""

    def test_huge_index_skips_the_row_not_the_listing(self):
        parsed = share_acl_svc.parse_acl_listing(_POISONED_LISTING)
        self.assertEqual(parsed["owner"], "a0000")
        self.assertEqual([e["index"] for e in parsed["entries"]], [1, 2])
        self.assertEqual(
            [e["name"] for e in parsed["entries"]], ["everyone", "alice"]
        )
        _starlette(parsed)

    def test_read_acl_serves_the_page_despite_the_poisoned_row(self):
        """``read_acl`` raised ValueError past the routers' ShareAclError catch."""
        with (
            mock.patch.object(
                share_acl_svc, "_validated_dir", return_value=Path("/tmp")
            ),
            mock.patch.object(
                share_acl_svc, "sh", return_value=(0, _POISONED_LISTING, "")
            ),
        ):
            state = share_acl_svc.read_acl("/tmp")
        self.assertEqual(len(state["entries"]), 2)
        _starlette(state)

    def test_skipped_row_never_becomes_a_chmod_removal(self):
        """A guessed index would remove the wrong ACL line (``chmod -a#``)."""
        parsed = share_acl_svc.parse_acl_listing(_POISONED_LISTING)
        commands = share_acl_svc._removal_then_grant(
            parsed["entries"], "mallory", "none"
        )
        self.assertEqual(commands, [])

    def test_a_sane_listing_still_parses_its_indices(self):
        listing = (
            "drwxr-xr-x+ 3 a0000  staff  96 Aug 13 12:00 /Users/a0000/Shared\n"
            " 0: user:alice allow list,search,readattr\n"
        )
        parsed = share_acl_svc.parse_acl_listing(listing)
        self.assertEqual(parsed["entries"][0]["index"], 0)
        self.assertEqual(parsed["entries"][0]["level"], "read")


class LocalUsersDigitPinTests(unittest.TestCase):
    """The uid parse beside the fixed one is already guarded; pin it."""

    def test_huge_uid_skips_the_account_not_the_picker(self):
        listing = (
            f"broken              {_HUGE_DIGITS}\n"
            "a0000                  502\n"
        )

        def fake_sh(argv, timeout=0):
            if "-list" in argv:
                return 0, listing, ""
            return 0, "RealName: A Person\n", ""

        with mock.patch.object(share_acl_svc, "sh", side_effect=fake_sh):
            users = share_acl_svc.local_users()
        self.assertEqual([(u["username"], u["uid"]) for u in users], [("a0000", 502)])
        _starlette(users)


class HuntedSchedulerCronDigitPinTests(unittest.TestCase):
    """Cron parses raise ValueError by contract; over-cap digits stay inside it."""

    def test_huge_step_is_invalid_not_a_500(self):
        # ``isdigit()`` passes, then ``int()`` is ValueError — exactly the
        # exception every parse_cron caller already absorbs.
        self.assertFalse(scheduler_svc.valid_cron(f"*/{_HUGE_DIGITS} * * * *"))

    def test_huge_range_and_value_are_invalid_not_a_500(self):
        self.assertFalse(scheduler_svc.valid_cron(f"0-{_HUGE_DIGITS} * * * *"))
        self.assertFalse(scheduler_svc.valid_cron(f"{_HUGE_DIGITS} * * * *"))

    def test_next_run_ts_answers_none_for_an_over_cap_expression(self):
        """GET /api/scheduler/jobs renders next_run through this path."""
        self.assertIsNone(scheduler_svc.next_run_ts(f"*/{_HUGE_DIGITS} * * * *"))

    def test_a_sane_step_still_parses(self):
        self.assertTrue(scheduler_svc.valid_cron("*/15 * * * *"))


if __name__ == "__main__":
    unittest.main()
