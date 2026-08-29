"""Audit-trail leftover sweep #13: the redaction/expansion order hole and
the claimed-base wrong-rank degrades.

audit12 reached every swallow site down to ``except BaseException``, so a
leftover can no longer *raise* out of record() or recent().  This sweep
re-hunted the same mounted route (create_app + TestClient,
raise_server_exceptions=False) and the record path for the sweep-13 shapes
— expansion-order seams, mid-walk mutation, claimed-base fidelity — and
found two live leftovers:

* **fixed, secret plaintext on the disk trail** — record() redacted
  *before* ``_jsonable`` shaped, so structures only the shaping pass
  expands were never redacted at all: a hashable dict-subclass carrying a
  secret-named field inside a set/frozenset (redact's sequence walk
  stopped at list/tuple, so the whole set rode the ``return value``
  fallthrough untouched), and a leftover ``isoformat()`` answering a
  secret-keyed mapping (expanded after redaction, straight into the
  entry).  The route's read-side re-redact kept the value off the wire,
  but the on-disk trail — the copy an operator or an older build reads
  directly — carried the plaintext under its secret name, breaking the
  module's first guarantee.  redact() now walks sets/frozensets, and
  record() redacts again over the exact-typed shaped tree, so nothing an
  expansion produces skips the classifier.

* **fixed, honest content vanished at the wrong rank** — ``_jsonable``
  (and redact) picked the unbound coercion off the *claimed*
  ``__class__``: a genuine tuple lying ``list`` was handed to
  ``list.__iter__``, rejected by the descriptor, and its renderable
  elements vanished to ``[]``; a genuine list-subclass lying ``dict``
  degraded to ``{}``/None; a genuine finite float lying ``int`` was
  refused by ``int.__index__`` and dropped to None.  Every base is now
  tried against the real storage (the audit12 decode-fidelity rule, the
  hub.modules sweep-13 arm): the honest layout wins, a total impostor
  fails every base and degrades exactly as before.

Stays-immune pins ride along: mid-walk mutation hooks cannot tear the
snapshot walks, control flow keeps propagating, the audit9 impostor
drops keep their exact shapes, and honest rows/limits keep theirs.
"""
from __future__ import annotations

import json
import shutil
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


class _HashableDict(dict):
    """A frozendict-style leftover: dict storage, hashable, set-eligible."""

    def __hash__(self):
        return 13


class _IsoMapping:
    """A timestamp-shaped leftover whose isoformat() answers a mapping."""

    def __init__(self, mapping):
        self._mapping = mapping

    def isoformat(self):
        return self._mapping


class _TupleLyingList(tuple):
    """Genuine tuple storage; ``__class__`` claims ``list``."""

    @property
    def __class__(self):  # type: ignore[override]
        return list


class _FrozensetLyingList(frozenset):
    @property
    def __class__(self):  # type: ignore[override]
        return list


class _ListLyingDict(list):
    """Genuine list storage; ``__class__`` claims ``dict``."""

    @property
    def __class__(self):  # type: ignore[override]
        return dict


class _FloatLyingInt(float):
    """Genuine float storage; ``__class__`` claims ``int``."""

    @property
    def __class__(self):  # type: ignore[override]
        return int


class _ListImpostor:
    """Claims ``list`` while carrying none of the four sequence layouts."""

    @property
    def __class__(self):  # type: ignore[override]
        return list


class _DictImpostor:
    """Claims ``dict`` while carrying no container layout at all."""

    @property
    def __class__(self):  # type: ignore[override]
        return dict


class _IntImpostor:
    """Claims ``int`` while carrying no numeric storage."""

    @property
    def __class__(self):  # type: ignore[override]
        return int


class _TrailCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit13-pin-"))
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


class RedactionExpansionLeakTests(_TrailCase):
    """Shapes only _jsonable expands used to carry secret-named fields past
    redaction and onto the disk trail in plaintext."""

    def test_secret_inside_a_set_field_never_reaches_disk(self):
        entry = self._record(
            username="amy",
            bag={_HashableDict({"password": "hunter2", "note": "kept"}), "x"},
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertNotIn("hunter2", json.dumps(entry))
        self.assertNotIn("hunter2", self._disk_text())
        self.assertNotIn("hunter2", json.dumps(self._http_body()))
        # The non-secret sibling inside the expanded element survives.
        self.assertIn("kept", self._disk_text())

    def test_secret_inside_a_frozenset_nested_in_a_list_never_reaches_disk(self):
        entry = self._record(
            username="amy",
            wrap=[frozenset({_HashableDict({"passphrase": "s3cret"})})],
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertNotIn("s3cret", json.dumps(entry))
        self.assertNotIn("s3cret", self._disk_text())

    def test_isoformat_expansion_with_a_secret_key_never_reaches_disk(self):
        entry = self._record(
            username="amy",
            stamp=_IsoMapping({"password": "hunter3", "when": "now"}),
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertNotIn("hunter3", json.dumps(entry))
        self.assertNotIn("hunter3", self._disk_text())
        # The expansion itself still renders: only the secret field drops.
        self.assertEqual(entry.get("stamp", {}).get("when"), "now")
        self.assertEqual(
            self._http_body()["entries"][0].get("stamp", {}).get("when"), "now"
        )

    def test_plain_secret_and_public_exception_keys_keep_their_behavior(self):
        # The extra redaction pass must not move the honest classifier:
        # secret names still drop, the public-name exception still passes.
        entry = self._record(username="amy", password="x", pubkey="pk")
        self.assertNotIn("password", entry)
        self.assertEqual(entry.get("pubkey"), "pk")
        self.assertNotIn('"x"', self._disk_text())

    def test_poisoned_row_from_an_older_writer_stays_off_the_wire(self):
        # A trail written by a pre-fix build (or edited by hand) can already
        # carry the leaked shape; the route's read-side re-redact is the
        # last stop before a browser and must keep holding.
        self.auth_path.write_text(
            json.dumps(
                {
                    "ts": "2026-08-28T00:00:00+0000",
                    "event": "auth.login.failed",
                    "username": "amy",
                    "stamp": {"password": "leaked-old", "when": "now"},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        body = self._http_body()
        self.assertEqual(len(body["entries"]), 1)
        self.assertNotIn("leaked-old", json.dumps(body))
        self.assertEqual(body["entries"][0].get("stamp", {}).get("when"), "now")


class ClaimedBaseRankFidelityTests(_TrailCase):
    """Honest storage behind a lying ``__class__`` used to vanish at the
    wrong rank; a total impostor still degrades exactly as before."""

    def test_tuple_lying_list_keeps_its_elements(self):
        entry = self._record(username="amy", seq=_TupleLyingList(("kept1", "kept2")))
        self.assertEqual(entry.get("seq"), ["kept1", "kept2"])
        self.assertEqual(
            self._http_body()["entries"][0].get("seq"), ["kept1", "kept2"]
        )

    def test_frozenset_lying_list_keeps_its_elements(self):
        entry = self._record(username="amy", seq=_FrozensetLyingList({"only"}))
        self.assertEqual(entry.get("seq"), ["only"])

    def test_list_lying_dict_keeps_its_elements(self):
        entry = self._record(username="amy", seq=_ListLyingDict(["kept3"]))
        self.assertEqual(entry.get("seq"), ["kept3"])
        self.assertEqual(self._http_body()["entries"][0].get("seq"), ["kept3"])

    def test_secret_keys_inside_a_recovered_sequence_still_drop(self):
        # The redact() recovery must recurse: a secret-keyed mapping riding
        # inside the lying container cannot use the recovery as a bypass.
        entry = self._record(
            username="amy",
            seq=_TupleLyingList(({"password": "hunter4", "ok": 1},)),
        )
        self.assertNotIn("hunter4", json.dumps(entry))
        self.assertNotIn("hunter4", self._disk_text())
        self.assertEqual(entry.get("seq"), [{"ok": 1}])

    def test_float_lying_int_keeps_its_finite_value(self):
        entry = self._record(username="amy", num=_FloatLyingInt(2.5))
        self.assertEqual(entry.get("num"), 2.5)
        self.assertEqual(self._http_body()["entries"][0].get("num"), 2.5)

    def test_infinite_float_lying_int_still_drops(self):
        entry = self._record(username="amy", num=_FloatLyingInt("inf"))
        self.assertIsNone(entry.get("num"))
        self.assertEqual(entry.get("username"), "amy")

    def test_total_impostors_still_degrade_exactly_as_before(self):
        entry = self._record(
            username="amy",
            seq=_ListImpostor(),
            d=_DictImpostor(),
            num=_IntImpostor(),
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(entry.get("seq"), [])
        # redact()'s dict arm nulls the impostor before _jsonable sees it,
        # the audit9 shape.
        self.assertIsNone(entry.get("d"))
        self.assertIsNone(entry.get("num"))
        self.assertEqual(self._http_body()["entries"][0].get("username"), "amy")

    def test_overcap_digit_int_subclass_still_drops_field_level(self):
        class _BigInt(int):
            pass

        entry = self._record(username="amy", n=_BigInt(10 ** 4500))
        self.assertIsNone(entry.get("n"))
        self.assertEqual(entry.get("username"), "amy")


class MidwalkMutationStaysSealedTests(_TrailCase):
    """The snapshot walks must hold: a hook whose side effect resizes its
    parent container mid-walk costs at most itself, never the line."""

    def test_dict_value_hook_popping_a_sibling_keeps_the_snapshot(self):
        parent = {}

        class _PopBomb:
            @property
            def __class__(self):  # type: ignore[override]
                parent.pop("later", None)
                raise RuntimeError("mutating class bomb")

        parent.update({"a": _PopBomb(), "later": "still-here"})
        entry = self._record(username="amy", detail=parent)
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(entry.get("detail", {}).get("later"), "still-here")
        self.assertEqual(
            self._http_body()["entries"][0]["detail"].get("later"), "still-here"
        )

    def test_set_element_hook_discarding_a_sibling_keeps_the_snapshot(self):
        bag = set()

        class _DiscardBomb:
            @property
            def __class__(self):  # type: ignore[override]
                bag.discard("later")
                raise RuntimeError("mutating class bomb")

        bag.update({_DiscardBomb(), "later"})
        entry = self._record(username="amy", bag=bag)
        self.assertEqual(entry.get("username"), "amy")
        self.assertIn("later", entry.get("bag", []))
        self.assertIn("later", self._http_body()["entries"][0].get("bag", []))


class ControlFlowStillPropagatesTests(_TrailCase):
    """The widened walks must not eat genuine control flow."""

    def test_keyboardinterrupt_from_a_set_element_propagates(self):
        class _KIBomb:
            def __hash__(self):
                return 17

            @property
            def __class__(self):  # type: ignore[override]
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            audit.record("auth.login.failed", bag={_KIBomb()})

    def test_systemexit_from_an_isoformat_expansion_propagates(self):
        class _SEIso:
            def isoformat(self):
                raise SystemExit(3)

        with self.assertRaises(SystemExit):
            audit.record("auth.login.failed", stamp=_SEIso())


class HonestBehaviorPins(_TrailCase):
    """The reshuffled arms must not move honest rows or limits."""

    def test_honest_containers_round_trip(self):
        entry = self._record(
            username="amy",
            detail={"n": 2, "tags": ["a", "b"], "pair": (1, 2), "flag": True},
        )
        self.assertEqual(
            entry.get("detail"),
            {"n": 2, "tags": ["a", "b"], "pair": [1, 2], "flag": True},
        )
        body = self._http_body()
        self.assertEqual(body["entries"][0].get("detail", {}).get("n"), 2)

    def test_route_limit_junk_stays_4xx(self):
        audit.record("auth.login.ok", username="amy")
        for q in ("9" * 5000, "1e400", "nan", "0x10"):
            resp = _client().get(f"/api/audit/auth?limit={q}")
            self.assertLess(resp.status_code, 500, f"limit={q[:20]}")
            self.assertGreaterEqual(resp.status_code, 400, f"limit={q[:20]}")
            _starlette(resp.json())


if __name__ == "__main__":
    unittest.main()
