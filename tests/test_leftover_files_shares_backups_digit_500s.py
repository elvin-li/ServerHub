"""Leftover >4300-digit stat ints / unbounded int() in the files, shares and
backups remaining parsers.

Prior passes guarded the PhotosHub/files/shares digit parsers (FileBrowser
pids, TM quota strings, ``du -sm``), the backups stat numbers
(``_stat_numbers`` / ``_written_bytes``) and the terminal/logs/audit/jobs
corner against CPython's 4300-digit str<->int ValueError and the inf shapes a
leftover clock makes of the same math.  This hunt covered what those passes
left — hub/files_svc.py's listing/download stat plumbing, hub/backups.py's
config knobs (pg port, prune retain) and hub/shares_svc.py's live dscl read —
and found one real leftover plus a set of already-guarded survivors:

* **fixed** — the file manager's stat numbers (``files_svc._entry`` and the
  ``download`` Content-Length).  ``int(st.st_size)`` inside a try only guards
  *conversions*: a leftover FUSE/SMB stat whose ``st_size`` / ``st_mtime`` is
  already a >4300-digit int passes through untouched, and CPython's int->str
  digit limit then ValueError'd Starlette's ``json.dumps`` — 500ing GET
  /api/files/list after the listing had already been built — and the
  ``str(length)`` Content-Length header on GET /api/files/download.  Both now
  go through ``files_svc._finite_int``, which applies the same
  beyond-float-range junk test hub/backups.py's ``_stat_numbers`` already
  applies: a 400-digit or >4300-digit stat number reads as 0, a finite one is
  kept;
* the pg dump targets (``backups.pg_targets``): an over-cap ``port`` in
  services.yaml is the same ValueError as any other unparsable port, so the
  entry is dropped row-by-row and GET /api/backups / POST
  /api/backups/postgres keep their healthy targets;
* the artefact rotation (``backups._prune``): an over-cap ``retain`` falls
  back to the RETAIN default instead of raising after a successful dump;
* the Time Machine share-point read (``shares_svc.time_machine_records``): a
  leftover dscl dump carrying a >4300-digit ``<integer>`` is a ValueError
  inside ``plistlib.loads`` itself — the live reader answers {} and GET
  /api/shares renders every row without TM attributes, never a 500.
"""
from __future__ import annotations

import asyncio
import json
import stat as stat_mod
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from hub import backups, files_svc, shares_svc

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_INT = 10 ** 5000
_HUGE_DIGITS = "9" * 5000
#: Under the int->str cap but past float range: json.dumps succeeds on the
#: int, so only the beyond-float-range junk test catches it.
_BIG_INT = 10 ** 400


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _drain(resp) -> bytes:
    async def go() -> bytes:
        chunks = []
        async for chunk in resp.body_iterator:
            chunks.append(chunk)
        return b"".join(chunks)

    return asyncio.run(go())


class FilesEntryStatDigitClockTests(unittest.TestCase):
    """GET /api/files/list builds every row through ``_entry``."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="files-entry-pin-"))
        self.file = self.root / "movie.mkv"
        self.file.write_bytes(b"leftover")

    def _fake_lstat(self, *, st_size, st_mtime):
        real_mode = self.file.lstat().st_mode
        fake = SimpleNamespace(st_size=st_size, st_mtime=st_mtime, st_mode=real_mode)
        return mock.patch.object(Path, "lstat", lambda self: fake)

    def test_huge_int_stat_answers_zero_not_a_500(self):
        # int() passes a >4300-digit int through untouched; the ValueError
        # used to come later, out of Starlette's json.dumps, as a 500.
        with self._fake_lstat(st_size=_HUGE_INT, st_mtime=_HUGE_INT):
            entry = files_svc._entry(self.file, self.root)
        self.assertEqual(entry["size"], 0)
        self.assertEqual(entry["mtime"], 0)
        _starlette(entry)

    def test_400_digit_stat_is_junk_like_the_backups_numbers(self):
        # Under the digit cap json.dumps would succeed, but a size beyond
        # float range is leftover junk; read 0, matching backups._stat_numbers.
        with self._fake_lstat(st_size=_BIG_INT, st_mtime=_BIG_INT):
            entry = files_svc._entry(self.file, self.root)
        self.assertEqual(entry["size"], 0)
        self.assertEqual(entry["mtime"], 0)
        _starlette(entry)

    def test_inf_mtime_answers_zero(self):
        # A leftover clock/FUSE inf mtime: int(inf) is OverflowError.
        with self._fake_lstat(st_size=8, st_mtime=float("inf")):
            entry = files_svc._entry(self.file, self.root)
        self.assertEqual(entry["size"], 8)
        self.assertEqual(entry["mtime"], 0)
        _starlette(entry)

    def test_list_dir_renders_with_a_poisoned_stat(self):
        with (
            mock.patch.object(
                files_svc, "_settings", return_value={"roots": [str(self.root)]}
            ),
            self._fake_lstat(st_size=_HUGE_INT, st_mtime=_HUGE_INT),
        ):
            payload = files_svc.list_dir(str(self.root))
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["items"][0]["size"], 0)
        _starlette(payload)

    def test_a_sane_stat_still_measures(self):
        entry = files_svc._entry(self.file, self.root)
        self.assertEqual(entry["size"], 8)
        self.assertGreater(entry["mtime"], 0)
        _starlette(entry)

    def test_finite_int_eats_every_leftover_shape(self):
        for value in (_HUGE_INT, _BIG_INT, float("inf"), float("nan"), None, "junk"):
            with self.subTest(value=value):
                self.assertEqual(files_svc._finite_int(value), 0)
        self.assertEqual(files_svc._finite_int(1234), 1234)
        self.assertEqual(files_svc._finite_int(12.9), 12)


class FilesDownloadDigitPinTests(unittest.TestCase):
    """GET /api/files/download carries the fstat size as Content-Length."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="files-dl-pin-"))
        self.file = self.root / "payload.bin"
        self.content = b"leftover payload"
        self.file.write_bytes(self.content)
        patcher = mock.patch.object(
            files_svc, "_settings", return_value={"roots": [str(self.root)]}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_huge_int_size_answers_zero_length_not_a_500(self):
        # str(length) for the header hit the same int->str digit limit.
        fake = SimpleNamespace(
            st_mode=stat_mod.S_IFREG | 0o644, st_size=_HUGE_INT
        )
        with mock.patch.object(files_svc.os, "fstat", return_value=fake):
            resp = files_svc.download(str(self.file))
        self.assertEqual(resp.headers["Content-Length"], "0")
        # The stream itself is unaffected: the bytes still arrive.
        self.assertEqual(_drain(resp), self.content)

    def test_a_sane_size_still_fills_the_header(self):
        resp = files_svc.download(str(self.file))
        self.assertEqual(resp.headers["Content-Length"], str(len(self.content)))
        self.assertEqual(_drain(resp), self.content)


class BackupsPgPortDigitPinTests(unittest.TestCase):
    """GET /api/backups and POST /api/backups/postgres read pg_targets."""

    def test_over_cap_port_drops_the_entry_not_a_500(self):
        rows = backups.pg_targets([
            {"id": "poisoned", "db": "d", "port": _HUGE_DIGITS},
            {"id": "healthy", "db": "d"},
        ])
        self.assertEqual([row["id"] for row in rows], ["healthy"])
        _starlette(rows)

    def test_a_sane_port_still_parses(self):
        rows = backups.pg_targets([{"id": "t", "db": "d", "port": 5433}])
        self.assertEqual(rows[0]["port"], 5433)


class BackupsPruneRetainDigitPinTests(unittest.TestCase):
    """_prune runs after every successful dump; a bad knob must not raise."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="backups-prune-pin-"))
        for stamp in ("20260101_000001", "20260101_000002", "20260101_000003"):
            (self.root / f"configs_{stamp}.tgz").write_bytes(b"x")

    def test_over_cap_retain_falls_back_to_the_default(self):
        with mock.patch.object(backups, "BACKUP_ROOT", self.root):
            backups._prune("configs_*.tgz", retain=_HUGE_DIGITS)
        self.assertEqual(len(list(self.root.glob("configs_*.tgz"))), 3)

    def test_a_sane_retain_still_prunes(self):
        with mock.patch.object(backups, "BACKUP_ROOT", self.root):
            backups._prune("configs_*.tgz", retain=1)
        self.assertEqual(
            [p.name for p in self.root.glob("configs_*.tgz")],
            ["configs_20260101_000003.tgz"],
        )


_HUGE_INTEGER_PLIST = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
  <dict>
    <key>dsAttrTypeStandard:RecordName</key>
    <array><string>Media</string></array>
    <key>dsAttrTypeNative:backupQuotaSize</key>
    <array><integer>{_HUGE_DIGITS}</integer></array>
  </dict>
</array>
</plist>
"""


class SharesTimeMachinePlistIntegerPinTests(unittest.TestCase):
    """GET /api/shares merges the dscl read into every SMB row."""

    def test_huge_plist_integer_degrades_to_empty_not_a_500(self):
        # The over-cap <integer> is a ValueError inside plistlib.loads
        # itself; the live reader answers {} and the page keeps its rows.
        with mock.patch.object(
            shares_svc, "sh", return_value=(0, _HUGE_INTEGER_PLIST, "")
        ):
            self.assertEqual(shares_svc.time_machine_records(), {})

    def test_a_sane_plist_still_parses(self):
        sane = _HUGE_INTEGER_PLIST.replace(
            f"<integer>{_HUGE_DIGITS}</integer>", "<string>2000000000000</string>"
        )
        with mock.patch.object(shares_svc, "sh", return_value=(0, sane, "")):
            records = shares_svc.time_machine_records()
        self.assertEqual(records["Media"]["tm_quota_gb"], 2000)


if __name__ == "__main__":
    unittest.main()
