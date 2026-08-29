"""Leftover sweep: record()'s pre-disk shaping ran outside the swallow-all.

``hub/audit.py`` promises "logging never breaks the request", but the try
block only wrapped the file I/O.  ``redact()`` and the ``_jsonable`` entry
build run *before* it, so a poisoned field shape raised straight out of
``record()`` into the route being audited — turning e.g. a failed sign-in
into a 500 of its own, and leaving no trail line at all:

* **fixed** — a >4300-digit int as a nested dict *key* (``yaml.safe_load`` of
  hex/octal text builds ints uncapped — ``int(x, 16)`` is a power-of-two base
  the CPython digit cap does not apply to).  ``_is_secret_key`` did
  ``str(key).lower()`` with no probe, so the digit-cap ValueError propagated
  out of ``redact()`` and out of ``record()``.  The value branch already had
  the ``str()`` probe (test_leftover_audit_hexint_flock_500s); the key branch
  did not.  Now the probe failure classifies the key as not-secret and
  ``_jsonable`` drops the unrenderable key before disk — the line persists.

* **fixed** — ``redact()`` recursed with no depth cap, unlike ``_jsonable``
  (capped at 32).  A leftover deeply-nested or self-referential detail dict
  RecursionError'd out of ``record()``.  Now redact caps like its sibling and
  *drops* the subtree past the cap — never passes it through unredacted.

* **fixed** — belt-and-braces: the whole shaping step now degrades to a
  minimal ``{ts, event}`` line on ValueError/TypeError/RecursionError, so an
  unforeseen poison shape costs detail fields, never the event or the request.

Stays-immune pins (already safe, guarded against regression):

* lone surrogates in nested keys AND values survive record() -> recent() ->
  GET /api/audit/auth and the response is Starlette-encodable;
* a secret nested under an unrenderable key never reaches disk or the
  response body through either redaction layer.

Not applicable to this domain, verified rather than assumed: the audit
journal reads a local file — no CLI subprocess (no vanished-binary 503 path)
and no pid handling (no os.kill / bool-pid class).
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

import yaml  # noqa: E402

from hub import audit  # noqa: E402
from hub.routers import audit_api  # noqa: E402

#: Exactly the object a leftover services.yaml / plist hands a record()
#: caller: hex text loads through int(x, 16), which the digit cap never
#: applies to, so str() on the result raises ValueError.
_HEX_HUGE = yaml.safe_load("0x" + "F" * 4400)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: this raising is the 500."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _TrailCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit-shaping-pin-"))
        self.path = self.dir / "auth-audit.jsonl"
        patched = mock.patch.object(audit, "AUDIT_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        # rmtree: record() takes secure_io.file_lock, which leaves a .lock
        # sibling beside the trail.
        self.addCleanup(shutil.rmtree, self.dir, True)


class HugeIntKeyShapingTests(_TrailCase):
    """A poisoned *key* must cost that key, never the request or the line."""

    def test_premise_hex_yaml_key_is_uncapped_and_unrenderable(self):
        self.assertIsInstance(_HEX_HUGE, int)
        with self.assertRaises(ValueError):
            str(_HEX_HUGE)

    def test_huge_int_key_does_not_raise_out_of_record(self):
        # Pre-fix: _is_secret_key's str(key) raised the digit-cap ValueError
        # through redact() and record() into the calling route — the failed
        # sign-in being audited 500'd AND left no trace.
        entry = audit.record(
            "auth.login.failed",
            username="bob",
            detail={_HEX_HUGE: "seen", "attempts": 3},
        )
        self.assertEqual(entry["username"], "bob")
        self.assertEqual(entry["detail"], {"attempts": 3})
        _starlette(entry)
        rows = audit.recent()
        self.assertEqual([r["event"] for r in rows], ["auth.login.failed"])
        self.assertEqual(rows[0]["detail"], {"attempts": 3})
        _starlette(rows)

    def test_secret_under_huge_int_key_never_reaches_disk_or_response(self):
        secret = "pw-under-poisoned-key"
        audit.record(
            "auth.login.failed",
            username="bob",
            detail={_HEX_HUGE: {"password": secret}},
        )
        self.assertNotIn(secret, self.path.read_text(encoding="utf-8"))
        body = audit_api.auth_audit(limit=50)
        blob = json.dumps(body, ensure_ascii=False, allow_nan=False)
        self.assertNotIn(secret, blob)
        self.assertEqual(body["entries"][0]["username"], "bob")

    def test_secret_string_keys_still_redact_beside_the_probe(self):
        # The probe must not weaken the classifier for normal keys.
        entry = audit.record(
            "auth.login.failed",
            username="bob",
            detail={_HEX_HUGE: "x", "api_key": "k-123", "host": "nas"},
        )
        self.assertNotIn("api_key", entry["detail"])
        self.assertEqual(entry["detail"]["host"], "nas")


class RedactRecursionTests(_TrailCase):
    """redact() runs before the swallow-all, so it must never recurse away."""

    @staticmethod
    def _deep(n: int) -> dict:
        root = cur = {}
        for _ in range(n):
            cur["d"] = {}
            cur = cur["d"]
        return root

    def test_deeply_nested_detail_does_not_recursionerror_record(self):
        # Pre-fix: redact() had no depth cap (unlike _jsonable) and
        # RecursionError'd out of record() into the request.
        entry = audit.record(
            "auth.login.failed", username="bob", detail=self._deep(100_000)
        )
        self.assertEqual(entry["username"], "bob")
        _starlette(entry)
        rows = audit.recent()
        self.assertEqual([r["event"] for r in rows], ["auth.login.failed"])
        self.assertEqual(rows[0]["username"], "bob")
        _starlette(rows)

    def test_self_referential_detail_still_records_the_event(self):
        loop: dict = {}
        loop["x"] = loop
        entry = audit.record("auth.login.failed", username="bob", detail=loop)
        self.assertEqual(entry["username"], "bob")
        _starlette(entry)
        rows = audit.recent()
        self.assertEqual([r["event"] for r in rows], ["auth.login.failed"])

    def test_depth_cap_drops_the_subtree_rather_than_passing_it_unredacted(self):
        # A secret below the cap must be *gone*, not skipped-over: dropping
        # the redaction pass while keeping the data would be worse than the
        # crash it replaces.
        secret = "pw-below-the-cap"
        deep = self._deep(40)
        cur = deep
        while cur.get("d"):
            cur = cur["d"]
        cur["password"] = secret
        audit.record("auth.login.failed", username="bob", detail=deep)
        self.assertNotIn(secret, self.path.read_text(encoding="utf-8"))
        blob = json.dumps(
            audit_api.auth_audit(limit=50), ensure_ascii=False, allow_nan=False
        )
        self.assertNotIn(secret, blob)

    def test_shallow_details_are_untouched_by_the_cap(self):
        entry = audit.record(
            "auth.login.ok",
            username="amy",
            detail={"a": {"b": {"c": [1, "two", None]}}},
        )
        self.assertEqual(entry["detail"], {"a": {"b": {"c": [1, "two", None]}}})


class SurrogateStaysImmuneTests(_TrailCase):
    """Already safe; pinned so the shaping rework cannot regress it."""

    def test_surrogates_in_nested_keys_and_values_round_trip_scrubbed(self):
        entry = audit.record(
            "auth.login.failed",
            username="adm\ud800in",
            detail={"ho\udc00st": "na\ud800s", "port": 22},
        )
        _starlette(entry)
        self.assertNotIn("\ud800", entry["username"])
        body = audit_api.auth_audit(limit=50)
        _starlette(body)
        row = body["entries"][0]
        self.assertEqual(len(body["entries"]), 1)
        self.assertNotIn("\ud800", row["username"])
        self.assertNotIn("\ud800", json.dumps(row, ensure_ascii=False))

    def test_surrogate_event_name_is_scrubbed_not_dropped(self):
        entry = audit.record("auth.\ud800login", username="amy")
        _starlette(entry)
        self.assertNotIn("\ud800", entry["event"])
        rows = audit.recent()
        self.assertEqual(len(rows), 1)
        _starlette(rows)


if __name__ == "__main__":
    unittest.main()
