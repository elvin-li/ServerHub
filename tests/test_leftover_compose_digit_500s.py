"""Leftover >4300-digit ``st_mtime`` int on GET /api/compose/{id}.

Prior passes fixed this exact class on the files, shares, backups, logs,
journal, audit, usage and catalog paths: ``int(...)`` wrapped in a try only
guards *conversions*, so a leftover FUSE/SMB stat number that is already a
>4300-digit int passes through untouched and CPython's int->str digit limit
then ValueErrors far from the stat.  This hunt covered the survivor:

* **fixed** — ``compose_svc.get_compose`` clamped ``st.st_mtime`` with
  ``int(...)`` under ``except (TypeError, ValueError, OverflowError)``,
  which stopped the ``inf`` leftover but let a huge *already-int* mtime
  through into the ``"mtime"`` JSON field.  Starlette's ``json.dumps``
  (whose int->str digit cap is ValueError) then 500'd GET /api/compose/{id}
  after the compose had already been read.  ``_finite_mtime`` now applies
  the same ``float()`` junk test as ``files_svc._finite_int``,
  ``logs_svc._stat_size``, ``usage_svc._safe_bytes`` and
  ``catalog._sig_int``, so anything beyond float range falls back to 0.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import compose_svc  # noqa: E402

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_INT = 10 ** 5000
#: Under the digit cap, but far past float range: ``float()`` is the guard.
_BIG_INT = 10 ** 400


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class ComposeFiniteMtimeDigitPinTests(unittest.TestCase):
    """The one mtime GET /api/compose/{id} emits routes through ``_finite_mtime``."""

    def test_huge_digit_int_st_mtime_is_zero_not_a_500(self):
        # int(huge) succeeds — no conversion to trip on — so before the
        # float() junk test the value reached Starlette's json.dumps, whose
        # int->str digit cap is ValueError.
        self.assertEqual(compose_svc._finite_mtime(_HUGE_INT), 0)
        _starlette({"mtime": compose_svc._finite_mtime(_HUGE_INT)})

    def test_under_cap_400_digit_st_mtime_is_zero_too(self):
        # Renders fine as JSON, but the same float() test files_svc applies
        # rejects it: no real filesystem stamps a file at 10^400 seconds.
        self.assertEqual(compose_svc._finite_mtime(_BIG_INT), 0)

    def test_inf_nan_and_junk_still_fall_back(self):
        for value in (float("inf"), float("-inf"), float("nan"), None, "junk"):
            with self.subTest(value=str(value)[:12]):
                self.assertEqual(compose_svc._finite_mtime(value), 0)

    def test_sane_mtime_passes_through(self):
        self.assertEqual(compose_svc._finite_mtime(1_755_000_000.7), 1_755_000_000)


class GetComposeHugeStMtimePinTests(unittest.TestCase):
    """GET /api/compose/{id} renders the compose mtime — a poisoned stat
    must answer 0, not a 500."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="compose-digit-pin-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.compose = self.tmp / "docker-compose.yml"
        self.compose.write_text("services: {}\n")
        self.stack = {
            "id": "x", "name": "x",
            "path": str(self.tmp), "compose_path": str(self.compose),
        }

    def _poisoned_stat(self, mtime):
        real_stat = Path.stat

        def fake_stat(p, *a, **k):
            st = real_stat(p, *a, **k)
            if p.name == "docker-compose.yml":
                return mock.Mock(
                    st_mode=st.st_mode, st_size=st.st_size, st_mtime=mtime
                )
            return st

        return mock.patch.object(Path, "stat", fake_stat)

    def _get(self, mtime):
        with (
            mock.patch.object(compose_svc, "_find_stack", return_value=self.stack),
            self._poisoned_stat(mtime),
        ):
            return compose_svc.get_compose("x")

    def test_get_compose_renders_with_a_huge_st_mtime(self):
        # int(st.st_mtime) succeeded on the already-int leftover, so the
        # old inline clamp never fired and json.dumps got 5001 digits.
        data = self._get(_HUGE_INT)
        self.assertEqual(data["mtime"], 0)
        self.assertEqual(data["content"], "services: {}\n")
        _starlette(data)

    def test_get_compose_renders_with_a_400_digit_st_mtime_too(self):
        data = self._get(_BIG_INT)
        self.assertEqual(data["mtime"], 0)
        _starlette(data)

    def test_a_sane_stat_still_reports_the_real_mtime(self):
        st = self.compose.stat()
        with mock.patch.object(compose_svc, "_find_stack", return_value=self.stack):
            data = compose_svc.get_compose("x")
        self.assertEqual(data["mtime"], int(st.st_mtime))
        _starlette(data)


if __name__ == "__main__":
    unittest.main()
