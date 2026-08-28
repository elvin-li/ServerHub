"""Audit-trail leftover sweep #14: the default ``object.__repr__`` heap
addresses still on the wire.

audit13 sealed the redact/expansion order and the lying-``__class__``
wrong-rank degrades, so a leftover can no longer raise out of record() /
recent() nor smuggle a secret past the classifier.  This sweep re-hunted
the same mounted route (create_app + TestClient,
raise_server_exceptions=False) and the record path for the sweep-14 shapes
— repr leaks, mid-walk snapshots, key coercion, FIFO/torn paths — and
found one live leftover:

* **fixed, heap addresses on the disk trail and the wire** —
  ``_utf8_text``'s free-text coercion arm ran ``str()`` on any leftover
  shape, and for a type that never overrode ``__str__``/``__repr__`` the
  answer is the default ``object.__repr__`` — ``<X object at 0x7f...>``,
  a raw heap address.  A junk field value, a set/list element and (via
  ``_jsonable``'s bare ``str(k)`` key coercion, whose exact-str result
  then rode the verbatim str branch past any scrub) a mapping *key* each
  carried that address verbatim onto the 0600 disk trail and out through
  GET /api/audit/auth — an ASLR-defeating primitive served from the one
  endpoint that exists to answer "who did this".  The sibling surfaces
  (bookmarks, assistant, files, notify13) sealed this with the slot-probe
  + ``_ADDR_REPR_RE`` belt; audit.py never got it.  Only the coercion arm
  is scrubbed — real str/bytes storage is data (an audited shell command
  may legitimately contain the pattern) and stays verbatim — and the belt
  runs before the 64 KB cap so truncation cannot tear an address into an
  unmatchable tail.

Stays-immune pins ride along: custom-``__str__`` coercion keeps its text,
real str data keeps address-shaped content verbatim end to end, control
flow keeps propagating through the probe, and the FIFO-occupied trail
stays a 200 with an empty page.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit
from hub.app_factory import create_app
from hub.auth import require_auth

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: this raising is the 500."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _Junk:
    """A default-render leftover: never overrode __str__ / __repr__, so
    str() answers ``<... _Junk object at 0x7f...>`` — a raw heap address."""


class _JunkKey:
    """Default-render and usable as a mapping key."""

    def __hash__(self):
        return 14


class _IsoJunk:
    """A timestamp-shaped leftover whose isoformat() answers junk."""

    def isoformat(self):
        return _Junk()


class _EmbedsAddress:
    """A custom ``__str__`` whose *rendering* embeds a default repr — what
    the slot probe cannot see and the regex belt must."""

    def __str__(self):
        return "state={!r} done".format(object())


class _HugeTailAddress:
    """Renders past the 64 KB cap with the address at the very end: the
    belt must run before truncation or the torn tail slips the regex."""

    def __str__(self):
        return "x" * 70000 + repr(object())


class _KIStr:
    def __str__(self):
        raise KeyboardInterrupt


class _TrailCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit14-pin-"))
        self.auth_path = self.dir / "auth-audit.jsonl"
        patched = mock.patch.object(audit, "AUDIT_PATH", self.auth_path)
        patched.start()
        self.addCleanup(patched.stop)
        # rmtree: record() takes secure_io.file_lock, which leaves a .lock
        # sibling beside the trail.
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _record(self, event="auth.login.failed", **fields) -> dict:
        entry = audit.record(event, **fields)
        _starlette(entry)
        return entry

    def _disk_text(self) -> str:
        try:
            return self.auth_path.read_text(encoding="utf-8")
        except OSError:
            return ""

    def _http_body(self, url="/api/audit/auth?limit=100") -> dict:
        resp = _client().get(url)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body

    def assertNoAddress(self, text: str, msg: str = "") -> None:
        self.assertNotRegex(text, r" at 0x[0-9a-fA-F]+>", msg)


class ReprAddressLeakTests(_TrailCase):
    """Default-render junk used to carry ``<X object at 0x7f...>`` verbatim
    onto the disk trail and out through GET /api/audit/auth."""

    def test_junk_field_value_never_leaks_an_address(self):
        entry = self._record(username="amy", detail=_Junk())
        self.assertEqual(entry.get("username"), "amy")
        self.assertNoAddress(json.dumps(entry))
        self.assertNoAddress(self._disk_text())
        self.assertNoAddress(json.dumps(self._http_body()))

    def test_junk_mapping_key_never_becomes_an_address_field_name(self):
        entry = self._record(
            username="amy", detail={_JunkKey(): "v", "ok": 1}
        )
        self.assertEqual(entry.get("username"), "amy")
        # The pair costs itself; the honest sibling survives.
        self.assertEqual(entry.get("detail", {}).get("ok"), 1)
        self.assertNoAddress(json.dumps(entry))
        self.assertNoAddress(self._disk_text())
        body = self._http_body()
        self.assertEqual(body["entries"][0].get("detail", {}).get("ok"), 1)
        self.assertNoAddress(json.dumps(body))

    def test_junk_inside_list_and_set_keeps_the_siblings_addressless(self):
        entry = self._record(
            username="amy", xs=[_Junk(), "kept"], bag={_JunkKey(), "b"}
        )
        self.assertIn("kept", entry.get("xs", []))
        self.assertIn("b", entry.get("bag", []))
        self.assertNoAddress(json.dumps(entry))
        self.assertNoAddress(self._disk_text())
        self.assertNoAddress(json.dumps(self._http_body()))

    def test_junk_event_name_never_leaks_an_address(self):
        entry = audit.record(_Junk(), username="amy")
        _starlette(entry)
        self.assertNoAddress(json.dumps(entry))
        self.assertNoAddress(self._disk_text())
        self.assertNoAddress(json.dumps(self._http_body()))

    def test_isoformat_expansion_answering_junk_never_leaks(self):
        entry = self._record(username="amy", stamp=_IsoJunk())
        self.assertEqual(entry.get("username"), "amy")
        self.assertNoAddress(json.dumps(entry))
        self.assertNoAddress(self._disk_text())

    def test_function_and_bound_method_leftovers_never_leak(self):
        # C-level ``__repr__`` overrides the slot probe cannot see: the
        # regex belt must catch what they render.
        entry = self._record(
            username="amy", fn=(lambda: 1), bm=self.setUp, ty=_Junk
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertNoAddress(json.dumps(entry))
        self.assertNoAddress(self._disk_text())
        self.assertNoAddress(json.dumps(self._http_body()))

    def test_custom_str_embedding_a_default_repr_is_belted(self):
        entry = self._record(username="amy", state=_EmbedsAddress())
        self.assertEqual(entry.get("username"), "amy")
        self.assertNoAddress(json.dumps(entry))
        self.assertNoAddress(self._disk_text())

    def test_belt_runs_before_the_cap_so_a_torn_tail_cannot_slip(self):
        entry = self._record(username="amy", blob=_HugeTailAddress())
        # Pre-fix the cap kept 64 KB of the rendering (no belt at all);
        # post-fix the address anywhere in the full text drops the field.
        self.assertEqual(entry.get("blob"), "")
        self.assertEqual(entry.get("username"), "amy")
        self.assertNoAddress(self._disk_text())


class CoercionFidelityPins(_TrailCase):
    """The probe and belt must cost only default-render junk, never data."""

    def test_custom_str_coercion_keeps_its_text(self):
        class _Renders:
            def __str__(self):
                return "renders-fine"

        entry = self._record(username="amy", what=_Renders())
        self.assertEqual(entry.get("what"), "renders-fine")
        self.assertEqual(
            self._http_body()["entries"][0].get("what"), "renders-fine"
        )

    def test_real_str_data_with_address_shaped_content_stays_verbatim(self):
        # An audited shell command may legitimately contain the pattern:
        # str storage is data, only the coercion arm is scrubbed.
        cmd = "kill <worker at 0xdeadbeef> now"
        entry = self._record(username="amy", command=cmd)
        self.assertEqual(entry.get("command"), cmd)
        self.assertIn("0xdeadbeef", self._disk_text())
        self.assertEqual(self._http_body()["entries"][0].get("command"), cmd)

    def test_bytes_data_with_address_shaped_content_stays_verbatim(self):
        entry = self._record(username="amy", blob=b"raw at 0xabc> tail")
        self.assertEqual(entry.get("blob"), "raw at 0xabc> tail")

    def test_honest_non_str_keys_still_render_their_text(self):
        entry = self._record(username="amy", detail={3: "v", None: "w"})
        self.assertEqual(entry.get("detail"), {"3": "v", "None": "w"})
        body = self._http_body()
        self.assertEqual(body["entries"][0].get("detail", {}).get("3"), "v")

    def test_honest_containers_and_scalars_keep_their_shapes(self):
        entry = self._record(
            username="amy",
            detail={"n": 2, "tags": ["a", "b"], "pair": (1, 2), "flag": True},
        )
        self.assertEqual(
            entry.get("detail"),
            {"n": 2, "tags": ["a", "b"], "pair": [1, 2], "flag": True},
        )

    def test_secret_named_fields_still_drop_before_disk(self):
        entry = self._record(username="amy", password="hunter5", pubkey="pk")
        self.assertNotIn("password", entry)
        self.assertEqual(entry.get("pubkey"), "pk")
        self.assertNotIn("hunter5", self._disk_text())


class ControlFlowStillPropagatesTests(_TrailCase):
    """The probe and belt must not eat genuine control flow."""

    def test_keyboardinterrupt_from_a_coerced_str_propagates(self):
        with self.assertRaises(KeyboardInterrupt):
            audit.record("auth.login.failed", what=_KIStr())

    def test_systemexit_from_a_junk_key_str_propagates(self):
        class _SEKey:
            def __hash__(self):
                return 15

            def __str__(self):
                raise SystemExit(4)

        with self.assertRaises(SystemExit):
            audit.record("auth.login.failed", detail={_SEKey(): 1})


class FifoTrailStaysSealedTests(_TrailCase):
    """A leftover FIFO occupying the trail path must stay an OSError the
    reader already handles — a 200 with an empty page, never a hang/500."""

    @unittest.skipUnless(hasattr(os, "mkfifo"), "platform has no mkfifo")
    def test_fifo_occupying_the_trail_answers_200_empty(self):
        os.mkfifo(self.auth_path)
        self.assertTrue(stat.S_ISFIFO(self.auth_path.stat().st_mode))
        body = self._http_body()
        self.assertEqual(body["entries"], [])
        self.assertEqual(body["count"], 0)


if __name__ == "__main__":
    unittest.main()
