"""Leftover sweep over the auth audit trail: hex-YAML huge ints and flock loss.

Two silent-persist-loss shapes, both previously fixed in sibling domains:

* **fixed** — ``audit._jsonable`` passed ints through with no ``str()`` probe,
  unlike ``terminal_svc._jsonable`` and ``hub.errors._jsonable_param``.  A
  >4300-digit int (``yaml.safe_load`` of hex/octal text loads uncapped —
  ``int(x, 16)`` is a power-of-two base, so CPython's int(str) digit cap never
  applies) reached record()'s own ``json.dumps``, whose int->str conversion is
  the digit-cap ValueError, and the *entire* audit line was swallowed by the
  logging-never-breaks-the-request try.  A failed sign-in poisoned this way
  left no trace at all — the exact event the trail exists to keep.  The
  returned entry was unrenderable too: any future caller embedding it in a
  response body would have 500'd Starlette's encoder.  Now the int branch
  probes ``str()`` like its siblings and drops only the field to None; the
  line persists.

* **fixed** — ``secure_io.file_lock`` guarded creating the ``.lock`` file
  (leftover directory, EIO) but not ``fcntl.flock`` itself.  ENOLCK/EIO from
  the flock call — a data/ directory on NFS with lockd down is the classic —
  raised OSError out of the context manager, record()'s swallow-all caught it,
  and the audit line was silently lost even though the trail itself was
  perfectly writable.  The documented fallback ("the context simply runs
  unlocked") now covers the lock call, not just the fd creation.

Already safe, pinned rather than changed:

* ``audit.recent`` skips a huge-digit trail line at ``json.loads`` — that
  raise is ValueError (the int cap), not JSONDecodeError, and the reader
  catches the base class;
* a >4300-digit *string* field round-trips untouched (it is text, not math).
"""
from __future__ import annotations

import errno
import fcntl
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from hub import audit, secure_io

#: yaml.safe_load of hex text builds the int with int(x, 16) — a power-of-two
#: base the CPython digit cap does not apply to — so this is exactly the
#: object a leftover services.yaml / plist hands a record() caller.
_HEX_HUGE = yaml.safe_load("0x" + "F" * 4400)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _TrailCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit-hexint-pin-"))
        self.path = self.dir / "auth-audit.jsonl"
        patched = mock.patch.object(audit, "AUDIT_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        # rmtree, not unlink+rmdir: record() takes secure_io.file_lock, which
        # leaves a lock file beside the trail.
        self.addCleanup(shutil.rmtree, self.dir, True)


class HexYamlHugeIntPersistTests(_TrailCase):
    """A poisoned field must cost that field, never the whole audit line."""

    def test_hex_yaml_int_is_uncapped_and_unrenderable(self):
        # The premise: the cap guards int(str) in decimal, not base-16 loads.
        self.assertIsInstance(_HEX_HUGE, int)
        with self.assertRaises(ValueError):
            str(_HEX_HUGE)

    def test_huge_int_field_is_nulled_and_the_line_persists(self):
        # Pre-fix: record()'s json.dumps raised the int->str ValueError and the
        # swallow-all dropped the whole line — recent() showed no failure at all.
        entry = audit.record(
            "auth.login.failed", username="bob", attempts=_HEX_HUGE
        )
        self.assertIsNone(entry["attempts"])
        self.assertEqual(entry["username"], "bob")
        _starlette(entry)
        rows = audit.recent()
        self.assertEqual([r["event"] for r in rows], ["auth.login.failed"])
        self.assertIsNone(rows[0]["attempts"])
        self.assertEqual(rows[0]["username"], "bob")
        _starlette(rows)

    def test_huge_int_nested_in_a_detail_dict_is_nulled_too(self):
        entry = audit.record(
            "auth.login.failed",
            username="bob",
            detail={"attempts": _HEX_HUGE, "window": [1, _HEX_HUGE]},
        )
        self.assertIsNone(entry["detail"]["attempts"])
        self.assertEqual(entry["detail"]["window"], [1, None])
        _starlette(entry)
        rows = audit.recent()
        self.assertEqual([r["event"] for r in rows], ["auth.login.failed"])
        _starlette(rows)

    def test_renderable_ints_and_digit_strings_pass_untouched(self):
        big_text = "9" * 4400  # text, not math: must round-trip verbatim
        entry = audit.record(
            "auth.login.ok", username="amy", attempts=3, note=big_text
        )
        self.assertEqual(entry["attempts"], 3)
        self.assertEqual(entry["note"], big_text)
        rows = audit.recent()
        self.assertEqual(rows[0]["attempts"], 3)
        self.assertEqual(rows[0]["note"], big_text)
        _starlette(rows)

    def test_recent_keeps_a_huge_digit_line_via_the_parse_int_hook(self):
        # json.loads of a >4300-digit literal raises the int-cap ValueError,
        # which is NOT json.JSONDecodeError — the bare decode would 500 (or,
        # caught, drop the whole row).  recent() now parses with a capped
        # parse_int hook, so the unrenderable number loads as None and the
        # row keeps its event instead of silently vanishing from the trail
        # (the audit7 sweep; same drop terminal_svc.recent_audit applies).
        line = '{"event": "auth.login.failed", "attempts": ' + "9" * 4400 + "}"
        with self.assertRaises(ValueError):
            json.loads(line)
        self.assertNotIsInstance(
            self._loads_error(line), json.JSONDecodeError
        )
        self.path.write_text(
            line + "\n" + '{"event": "auth.login.ok", "username": "amy"}\n',
            encoding="utf-8",
        )
        rows = audit.recent()
        self.assertEqual(
            [r["event"] for r in rows], ["auth.login.failed", "auth.login.ok"]
        )
        self.assertIsNone(rows[0]["attempts"])
        _starlette(rows)

    @staticmethod
    def _loads_error(text):
        try:
            json.loads(text)
        except ValueError as exc:
            return exc
        return None


class FlockFailurePersistTests(_TrailCase):
    """ENOLCK/EIO from flock must degrade to unlocked, not lose the line."""

    def test_enolck_flock_still_persists_the_sign_in(self):
        def bad_flock(fd, op):
            raise OSError(errno.ENOLCK, "no locks available")

        with mock.patch.object(fcntl, "flock", bad_flock):
            audit.record("auth.login.ok", username="amy")
        rows = audit.recent()
        self.assertEqual([r["event"] for r in rows], ["auth.login.ok"])
        _starlette(rows)

    def test_file_lock_runs_the_body_when_flock_raises(self):
        ran = []

        def bad_flock(fd, op):
            raise OSError(errno.EIO, "I/O error")

        with mock.patch.object(fcntl, "flock", bad_flock):
            with secure_io.file_lock(self.path):
                ran.append(True)
        self.assertEqual(ran, [True])
        # The lock fd must not leak when the lock call fails: a second entry
        # still works and the .lock sibling is a regular file, not a leftover.
        with secure_io.file_lock(self.path):
            ran.append(True)
        self.assertEqual(ran, [True, True])

    def test_unlock_failure_after_the_write_does_not_raise(self):
        real_flock = fcntl.flock

        def unlock_fails(fd, op):
            if op == fcntl.LOCK_UN:
                raise OSError(errno.EIO, "I/O error")
            return real_flock(fd, op)

        with mock.patch.object(fcntl, "flock", unlock_fails):
            audit.record("auth.login.ok", username="amy")
        rows = audit.recent()
        self.assertEqual([r["event"] for r in rows], ["auth.login.ok"])


if __name__ == "__main__":
    unittest.main()
