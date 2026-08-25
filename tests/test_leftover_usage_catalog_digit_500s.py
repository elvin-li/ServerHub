"""Leftover >4300-digit ``st_size`` ints in the usage explorer and catalog sig.

Prior passes fixed this exact class on the files, shares, backups, logs,
journal and audit paths: ``int(...)`` wrapped in a try only guards
*conversions*, so a leftover FUSE/SMB ``st_size`` that is already a
>4300-digit int passes through untouched and CPython's int->str digit limit
then ValueErrors far from the stat.  This hunt covered the two survivors:

* **fixed** — ``usage_svc._safe_bytes`` clamped None/inf but let the
  already-int leftover through, and Starlette's ``json.dumps`` (whose
  int->str digit cap is ValueError) then 500'd GET /api/storage/usage/tree,
  /largest and /duplicates after the walk had already finished.  The helper
  now applies the same ``float()`` junk test as ``files_svc._finite_int``
  and ``logs_svc._stat_size``, so anything beyond float range falls back
  to 0;
* **fixed** — ``catalog._templates_sig`` rendered ``st.st_size`` (and a
  huge already-int ``st.st_mtime``, which slipped past its ``int(...)``
  clamp the same way) straight into the signature f-string.  That ValueError
  raised *outside* the ``except OSError``, 500ing GET /api/catalog and
  /api/catalog/templates before a single template was parsed.  Both stat
  numbers now route through ``catalog._sig_int``, the same helper pattern.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import catalog, usage_svc  # noqa: E402

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_INT = 10 ** 5000
#: Under the digit cap, but far past float range: ``float()`` is the guard.
_BIG_INT = 10 ** 400


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class UsageSafeBytesDigitPinTests(unittest.TestCase):
    """Every size the usage endpoints emit passes through ``_safe_bytes``."""

    def test_huge_digit_int_st_size_is_zero_not_a_500(self):
        # int(huge) succeeds — no conversion to trip on — so before the
        # float() junk test the value reached Starlette's json.dumps, whose
        # int->str digit cap is ValueError.
        self.assertEqual(usage_svc._safe_bytes(_HUGE_INT), 0)
        _starlette({"bytes": usage_svc._safe_bytes(_HUGE_INT)})

    def test_under_cap_400_digit_st_size_is_zero_too(self):
        # Renders fine as JSON, but the same float() test files_svc applies
        # rejects it: no real filesystem reports a 10^400-byte file.
        self.assertEqual(usage_svc._safe_bytes(_BIG_INT), 0)

    def test_inf_nan_negative_and_junk_still_fall_back(self):
        for size in (float("inf"), float("-inf"), float("nan"), -5, None, "junk"):
            with self.subTest(size=str(size)[:12]):
                self.assertEqual(usage_svc._safe_bytes(size), 0)

    def test_sane_size_passes_through(self):
        self.assertEqual(usage_svc._safe_bytes(2048), 2048)


class _PoisonedEntry:
    """Delegates to a real DirEntry but reports a chosen ``st_size``."""

    def __init__(self, entry, size):
        self._entry = entry
        self._size = size

    def __getattr__(self, name):
        return getattr(self._entry, name)

    def stat(self, follow_symlinks=True):
        st = self._entry.stat(follow_symlinks=follow_symlinks)
        return mock.Mock(
            st_size=self._size, st_mtime=st.st_mtime, st_mode=st.st_mode
        )


class _ScandirResult:
    """os.scandir's return is both a context manager and an iterator."""

    def __init__(self, entries):
        self._entries = entries

    def __enter__(self):
        return iter(self._entries)

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        return iter(self._entries)


class UsageEndpointsHugeStSizePinTests(unittest.TestCase):
    """GET /api/storage/usage/tree, /largest and /duplicates render every
    file's ``st_size`` — a poisoned stat must answer 0 bytes, not a 500."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="usage-digit-pin-"))
        (self.root / "movie.mkv").write_bytes(b"x" * 2048)
        self.addCleanup(self._cleanup)
        for name, value in (
            ("_resolve", lambda *a, **kw: self.root),
            ("scan_roots", lambda: []),
        ):
            patched = mock.patch.object(usage_svc, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    def _cleanup(self):
        for child in self.root.iterdir():
            child.unlink()
        self.root.rmdir()

    def _poisoned_scandir(self, size):
        real_scandir = os.scandir

        def scandir(path):
            with real_scandir(path) as it:
                entries = [
                    _PoisonedEntry(e, size)
                    if e.is_file(follow_symlinks=False) else e
                    for e in it
                ]
            return _ScandirResult(entries)

        return mock.patch.object(usage_svc.os, "scandir", scandir)

    def test_tree_renders_with_a_huge_st_size(self):
        with self._poisoned_scandir(_HUGE_INT):
            out = usage_svc.tree()
        files = [c for c in out["children"] if c["kind"] == "file"]
        self.assertEqual([f["name"] for f in files], ["movie.mkv"])
        self.assertEqual(files[0]["bytes"], 0)
        self.assertEqual(out["own_bytes"], 0)
        _starlette(out)

    def test_largest_files_renders_with_a_huge_st_size(self):
        with self._poisoned_scandir(_HUGE_INT):
            out = usage_svc.largest_files()
        self.assertEqual([i["name"] for i in out["items"]], ["movie.mkv"])
        self.assertEqual(out["items"][0]["bytes"], 0)
        self.assertEqual(out["scanned"], 1)
        _starlette(out)

    def test_duplicates_renders_with_a_huge_st_size(self):
        # 0 bytes is under the 1 MB floor, so the poisoned file is simply
        # not a duplicate candidate — the endpoint answers instead of 500ing.
        (self.root / "copy.mkv").write_bytes(b"x" * 2048)
        with self._poisoned_scandir(_HUGE_INT):
            out = usage_svc.duplicates()
        self.assertEqual(out["groups"], [])
        _starlette(out)

    def test_sane_sizes_still_measure(self):
        out = usage_svc.tree()
        files = [c for c in out["children"] if c["kind"] == "file"]
        self.assertEqual(files[0]["bytes"], 2048)
        self.assertEqual(out["own_bytes"], 2048)
        _starlette(out)


class CatalogSigIntDigitPinTests(unittest.TestCase):
    """Both stat numbers in the listing signature route through ``_sig_int``."""

    def test_huge_digit_int_is_zero_not_a_500(self):
        # int(huge) succeeds, so before the float() junk test the value
        # reached the signature f-string, whose int->str digit cap is
        # ValueError — outside _templates_sig's ``except OSError``.
        self.assertEqual(catalog._sig_int(_HUGE_INT), 0)

    def test_under_cap_400_digit_int_is_zero_too(self):
        self.assertEqual(catalog._sig_int(_BIG_INT), 0)

    def test_inf_nan_and_junk_still_fall_back(self):
        for value in (float("inf"), float("-inf"), float("nan"), None, "junk"):
            with self.subTest(value=str(value)[:12]):
                self.assertEqual(catalog._sig_int(value), 0)

    def test_sane_stat_numbers_pass_through(self):
        self.assertEqual(catalog._sig_int(1_755_000_000.7), 1_755_000_000)
        self.assertEqual(catalog._sig_int(4096), 4096)


class CatalogTemplatesSigHugeStSizePinTests(unittest.TestCase):
    """GET /api/catalog and /api/catalog/templates take the signature first."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="catalog-digit-pin-"))
        self.tpl = self.tmp / "ok.yml"
        self.tpl.write_text("---\nname: Ok\n---\nservices: {}\n")
        catalog.invalidate_listing()
        self.addCleanup(catalog.invalidate_listing)
        for target, value in (
            ("TEMPLATES", self.tmp),
            ("SERVICES_ROOT", self.tmp / "services-none"),
        ):
            patched = mock.patch.object(catalog, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        patched = mock.patch.object(
            catalog.catalog_remote, "remote_template_files", return_value=[]
        )
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        self.tpl.unlink()
        self.tmp.rmdir()

    def _poisoned_stat(self, size=_HUGE_INT, mtime=None):
        real_stat = Path.stat

        def fake_stat(p, **kwargs):
            st = real_stat(p, **kwargs)
            if str(p) == str(self.tpl):
                return mock.Mock(
                    st_mode=st.st_mode,
                    st_size=size,
                    st_mtime=st.st_mtime if mtime is None else mtime,
                )
            return st

        return mock.patch.object(Path, "stat", fake_stat)

    def test_signature_renders_with_a_huge_st_size(self):
        with self._poisoned_stat():
            sig = catalog._templates_sig()
        self.assertIsInstance(sig, str)
        self.assertIn("ok.yml:", sig)
        self.assertTrue(sig.endswith(":0"), sig)

    def test_signature_renders_with_a_huge_st_mtime_too(self):
        # int(st.st_mtime) succeeded on the already-int leftover, so the
        # old per-field clamp never fired and the f-string got 5001 digits.
        with self._poisoned_stat(size=4096, mtime=_HUGE_INT):
            sig = catalog._templates_sig()
        self.assertIn("ok.yml:0:4096", sig)

    def test_list_templates_renders_with_a_huge_st_size(self):
        with self._poisoned_stat():
            items = catalog.list_templates(force=True)
        self.assertIn("ok", [row["id"] for row in items])
        _starlette(items)

    def test_a_sane_stat_still_signs_with_real_numbers(self):
        st = self.tpl.stat()
        sig = catalog._templates_sig()
        self.assertIn(f"ok.yml:{int(st.st_mtime)}:{st.st_size}", sig)


if __name__ == "__main__":
    unittest.main()
