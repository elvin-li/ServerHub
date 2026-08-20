"""Table-driven tests for the scheduler's five-field cron matcher.

The matcher is hand-rolled (no new dependency), so every piece of grammar it
claims to support is pinned here: ``*``, values, lists, ranges, steps, the
0/7-both-mean-Sunday rule, and vixie's day-of-month OR day-of-week semantics.
Boundary dates (month ends, leap day) go through :func:`next_run_ts`, which is
also what the UI shows as "next trigger".
"""
from __future__ import annotations

import sys
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hub import scheduler_svc  # noqa: E402


def _t(year, month, day, hour=0, minute=0):
    """A local struct_time for a specific wall-clock minute."""
    return datetime(year, month, day, hour, minute).timetuple()


class CronMatchTableTests(unittest.TestCase):
    #: (expr, struct_time args, expected)
    CASES = [
        # bare star matches everything
        ("* * * * *", (2026, 8, 13, 0, 0), True),
        ("* * * * *", (2026, 12, 31, 23, 59), True),
        # plain values
        ("30 3 * * *", (2026, 8, 13, 3, 30), True),
        ("30 3 * * *", (2026, 8, 13, 3, 29), False),
        ("30 3 * * *", (2026, 8, 13, 4, 30), False),
        # lists
        ("0,15,30,45 * * * *", (2026, 8, 13, 9, 45), True),
        ("0,15,30,45 * * * *", (2026, 8, 13, 9, 44), False),
        # ranges
        ("* 9-17 * * *", (2026, 8, 13, 9, 0), True),
        ("* 9-17 * * *", (2026, 8, 13, 17, 59), True),
        ("* 9-17 * * *", (2026, 8, 13, 18, 0), False),
        # steps over star
        ("*/15 * * * *", (2026, 8, 13, 1, 0), True),
        ("*/15 * * * *", (2026, 8, 13, 1, 45), True),
        ("*/15 * * * *", (2026, 8, 13, 1, 46), False),
        # steps over a range
        ("10-50/10 * * * *", (2026, 8, 13, 1, 30), True),
        ("10-50/10 * * * *", (2026, 8, 13, 1, 35), False),
        ("10-50/10 * * * *", (2026, 8, 13, 1, 55), False),
        # vixie "n/step" == n-max/step
        ("20/15 * * * *", (2026, 8, 13, 1, 50), True),
        ("20/15 * * * *", (2026, 8, 13, 1, 15), False),
        # list of ranges and values combined
        ("0 0 1-5,15,25-27 * *", (2026, 8, 3, 0, 0), True),
        ("0 0 1-5,15,25-27 * *", (2026, 8, 15, 0, 0), True),
        ("0 0 1-5,15,25-27 * *", (2026, 8, 26, 0, 0), True),
        ("0 0 1-5,15,25-27 * *", (2026, 8, 14, 0, 0), False),
        # months
        ("0 0 1 1,7 *", (2026, 7, 1, 0, 0), True),
        ("0 0 1 1,7 *", (2026, 6, 1, 0, 0), False),
        # month end: Jan 31 exists, matches
        ("59 23 31 * *", (2026, 1, 31, 23, 59), True),
        # 2026-08-16 is a Sunday: both 0 and 7 must match it
        ("0 0 * * 0", (2026, 8, 16, 0, 0), True),
        ("0 0 * * 7", (2026, 8, 16, 0, 0), True),
        ("0 0 * * 0", (2026, 8, 17, 0, 0), False),  # Monday
        ("0 0 * * 1", (2026, 8, 17, 0, 0), True),
        # dow ranges wrap through the 0/7 normalisation
        ("0 0 * * 1-5", (2026, 8, 14, 0, 0), True),   # Friday
        ("0 0 * * 1-5", (2026, 8, 16, 0, 0), False),  # Sunday
        # vixie OR rule: both dom and dow restricted -> either matches
        ("0 0 1 * 1", (2026, 8, 1, 0, 0), True),   # the 1st (a Saturday)
        ("0 0 1 * 1", (2026, 8, 17, 0, 0), True),  # a Monday, not the 1st
        ("0 0 1 * 1", (2026, 8, 18, 0, 0), False),  # neither
        # only dom restricted -> dow does not widen it
        ("0 0 1 * *", (2026, 8, 17, 0, 0), False),
        ("0 0 1 * *", (2026, 8, 1, 0, 0), True),
        # only dow restricted -> dom does not widen it
        ("0 0 * * 1", (2026, 8, 1, 0, 0), False),
    ]

    def test_table(self):
        for expr, when, expected in self.CASES:
            with self.subTest(expr=expr, when=when):
                self.assertIs(
                    scheduler_svc.cron_matches(expr, _t(*when)), expected,
                    f"{expr} at {when}",
                )


class CronValidationTests(unittest.TestCase):
    GOOD = [
        "* * * * *",
        "0 0 1 1 0",
        "59 23 31 12 7",
        "*/5 */2 * * *",
        "1,2,3 4-6 7/2 8-10/2 1-5",
    ]
    BAD = [
        "",
        "* * * *",           # four fields
        "* * * * * *",       # six fields
        "60 * * * *",        # minute out of range
        "* 24 * * *",        # hour out of range
        "* * 0 * *",         # dom below range
        "* * 32 * *",        # dom above range
        "* * * 13 *",        # month above range
        "* * * * 8",         # dow above range
        "*/0 * * * *",       # zero step
        "5-1 * * * *",       # reversed range
        "a * * * *",         # not a number
        "1,,2 * * * *",      # empty list item
        "-5 * * * *",        # negative / option-like
    ]

    def test_valid_expressions(self):
        for expr in self.GOOD:
            with self.subTest(expr=expr):
                self.assertTrue(scheduler_svc.valid_cron(expr))

    def test_invalid_expressions(self):
        for expr in self.BAD:
            with self.subTest(expr=expr):
                self.assertFalse(scheduler_svc.valid_cron(expr))

    def test_dow_seven_normalises_to_sunday(self):
        parsed = scheduler_svc.parse_cron("* * * * 7")
        self.assertEqual(parsed["dow"], frozenset({0}))


class NextRunTests(unittest.TestCase):
    def _after(self, year, month, day, hour=0, minute=0):
        return datetime(year, month, day, hour, minute).timestamp()

    def _next(self, expr, after):
        ts = scheduler_svc.next_run_ts(expr, after)
        self.assertIsNotNone(ts)
        return datetime.fromtimestamp(ts)

    def test_next_minute_is_never_the_current_minute(self):
        after = self._after(2026, 8, 13, 3, 30)
        nxt = self._next("30 3 * * *", after)
        self.assertEqual(nxt, datetime(2026, 8, 14, 3, 30))

    def test_rolls_over_a_short_month(self):
        # There is no April 31; the next match is May 31.
        after = self._after(2026, 4, 1)
        nxt = self._next("0 0 31 * *", after)
        self.assertEqual(nxt, datetime(2026, 5, 31, 0, 0))

    def test_leap_day_schedule_found_years_out(self):
        after = self._after(2026, 3, 1)
        nxt = self._next("0 0 29 2 *", after)
        self.assertEqual(nxt, datetime(2028, 2, 29, 0, 0))

    def test_impossible_date_returns_none(self):
        # April, June, September, November have no 31st.
        self.assertIsNone(scheduler_svc.next_run_ts("0 0 31 4 *"))

    def test_sunday_as_seven(self):
        after = self._after(2026, 8, 13)  # a Thursday
        nxt = self._next("0 9 * * 7", after)
        self.assertEqual(nxt, datetime(2026, 8, 16, 9, 0))

    def test_invalid_expression_returns_none(self):
        self.assertIsNone(scheduler_svc.next_run_ts("not a cron"))

    def test_five_field_list_parses_like_the_string(self):
        parsed = scheduler_svc.parse_cron([0, 4, "*", "*", "*"])
        self.assertEqual(parsed["minute"], frozenset({0}))
        self.assertEqual(parsed["hour"], frozenset({4}))
        self.assertTrue(scheduler_svc.valid_cron(["30", "3", "*", "*", "*"]))
        self.assertTrue(scheduler_svc.cron_matches(
            [30, 3, "*", "*", "*"], _t(2026, 8, 13, 3, 30),
        ))
        nxt = scheduler_svc.next_run_ts([0, 9, "*", "*", 7], self._after(2026, 8, 13))
        self.assertEqual(datetime.fromtimestamp(nxt), datetime(2026, 8, 16, 9, 0))

    def test_non_string_leftovers_are_invalid_not_stringified(self):
        for bad in (None, True, 12345, {"minute": "*"}, ["*", "*", "*"]):
            with self.subTest(bad=bad):
                self.assertFalse(scheduler_svc.valid_cron(bad))
                self.assertIsNone(scheduler_svc.next_run_ts(bad))


if __name__ == "__main__":
    unittest.main(verbosity=2)
