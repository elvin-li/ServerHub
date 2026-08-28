"""Thirteenth leftover sweep of the Logs surfaces, over the real app.

logs12 sealed the BaseException-shaped bombs and taught the decode arms to
try both byte layouts instead of trusting the *claimed* ``__class__``.  A
fresh hunt over the same mounted routes (create_app + TestClient,
raise_server_exceptions=False) found no raw 500 left — but it found the
mirror image of the logs12 decode gap still live, on the *entry* gates
this time: ``isinstance`` consults ``value.__class__`` only after the real
MRO check misses, so a lying ``__class__`` steers a value into the arm of
its *claim*, that arm's unbound descriptor rejects the real layout, and
the old unconditional drop threw away honest, perfectly renderable
storage — degrade at the wrong rank (the audit13 recover-the-real-storage
rule):

- a genuine bytes/bytearray id claiming ``str`` reached
  ``_config_text``'s str arm, ``str.__str__`` rejected it, and the whole
  source silently unlisted (and its tail 404'd) although ``b"logid"``
  decodes cleanly; the same shape as a name field silently fell back to
  the id, losing its text;
- an int-subclass or date-subclass id claiming ``str`` lost its "42" /
  isoformat rendering the same way;
- a genuine str path claiming ``bytes``/``bytearray`` entered
  ``_entries``' fs-decode arm, both base decodes rejected the str layout,
  and the row dropped although the real path text named the on-disk file;
- ``_utf8_text`` degraded a genuine str claiming bytes to ``""``;
- ``_stat_size`` degraded a genuine float ``st_size`` claiming int (the
  FUSE-stub threat model in its own docstring) to 0 one arm early.

The failure paths now fall through to the arm that matches the *real*
storage instead of returning early on the claimed rank.  Total impostors
— a claim with no renderable layout underneath — still drop exactly as
logs12 pinned, and the stronger union guards (``except BaseException``
with ``_CONTROL_FLOW`` re-raised) stay untouched around every new path.
"""
from __future__ import annotations

import datetime
import json
import math
import os
import tempfile
import unittest
import urllib.parse
from unittest import mock

from fastapi.testclient import TestClient

from hub import logs_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


# ── honest storage behind a lying ``__class__`` ─────────────────────────
class BytesLyingStr(bytes):
    @property
    def __class__(self):  # type: ignore[override]
        return str


class ByteArrayLyingStr(bytearray):
    @property
    def __class__(self):  # type: ignore[override]
        return str


class StrLyingBytes(str):
    @property
    def __class__(self):  # type: ignore[override]
        return bytes


class StrLyingByteArray(str):
    @property
    def __class__(self):  # type: ignore[override]
        return bytearray


class IntLyingStr(int):
    @property
    def __class__(self):  # type: ignore[override]
        return str


class DateLyingStr(datetime.date):
    @property
    def __class__(self):  # type: ignore[override]
        return str


class FloatLyingInt(float):
    @property
    def __class__(self):  # type: ignore[override]
        return int


class IntLyingFloat(int):
    @property
    def __class__(self):  # type: ignore[override]
        return float


# ── total impostors: a claim with no renderable layout underneath ───────
class StrImpostor:
    @property
    def __class__(self):  # type: ignore[override]
        return str


class BytesImpostor:
    @property
    def __class__(self):  # type: ignore[override]
        return bytes


class IntImpostor:
    @property
    def __class__(self):  # type: ignore[override]
        return int


class FlippingLiar:
    """A ``__class__`` whose answer changes per access (stateful liar)."""

    def __init__(self, answers):
        self._answers = list(answers)

    @property
    def __class__(self):  # type: ignore[override]
        if len(self._answers) > 1:
            return self._answers.pop(0)
        return self._answers[0]


class _LogsSandbox(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.log_path = os.path.join(self._tmp.name, "sane.log")
        with open(self.log_path, "w", encoding="utf-8") as fh:
            fh.write("line-one\nline-two\n")

    def _list(self, cfg_value):
        provider = cfg_value if callable(cfg_value) else (lambda: cfg_value)
        with mock.patch.object(logs_svc, "cfg", provider):
            resp = _client().get("/api/logs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(_strict_utf8(resp))["sources"]

    def _tail(self, cfg_value, source_id, expect=200):
        provider = cfg_value if callable(cfg_value) else (lambda: cfg_value)
        with mock.patch.object(logs_svc, "cfg", provider):
            resp = _client().get(
                "/api/logs/" + urllib.parse.quote(str(source_id), safe=""))
        self.assertEqual(resp.status_code, expect, resp.text[:300])
        return json.loads(_strict_utf8(resp))


class RecoveredRankTests(_LogsSandbox):
    """Honest storage behind a lying ``__class__`` used to drop on the
    claimed arm; it now falls through to the arm its real layout matches,
    so the source keeps listing and tailing."""

    def test_bytes_id_lying_str_keeps_listing_and_tailing(self):
        cfg_value = {"log_sources": [
            {"id": BytesLyingStr(b"logid"), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["exists"]) for r in rows], [("logid", True)])
        self.assertEqual(self._tail(cfg_value, "logid")["lines"], 2)

    def test_bytearray_id_lying_str_keeps_listing_and_tailing(self):
        cfg_value = {"log_sources": [
            {"id": ByteArrayLyingStr(b"logid"), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["exists"]) for r in rows], [("logid", True)])
        self.assertEqual(self._tail(cfg_value, "logid")["lines"], 2)

    def test_bytes_name_lying_str_keeps_its_text(self):
        cfg_value = {"log_sources": [
            {"id": "s1", "name": BytesLyingStr(b"My Log"),
             "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["name"]) for r in rows], [("s1", "My Log")])
        self.assertEqual(self._tail(cfg_value, "s1")["name"], "My Log")

    def test_undecodable_byte_in_a_lying_str_id_degrades_to_replace(self):
        # The recovered arm is the same replace-decode the honest bytes
        # rank gets: one bad byte becomes U+FFFD, never a 500 or a drop.
        cfg_value = {"log_sources": [
            {"id": BytesLyingStr(b"log\xffid"), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["log\ufffdid"])
        self.assertEqual(self._tail(cfg_value, "log\ufffdid")["lines"], 2)

    def test_int_id_lying_str_keeps_its_numeric_rendering(self):
        cfg_value = {"log_sources": [
            {"id": IntLyingStr(42), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["exists"]) for r in rows], [("42", True)])
        self.assertEqual(self._tail(cfg_value, "42")["lines"], 2)

    def test_date_id_lying_str_keeps_its_isoformat_rendering(self):
        cfg_value = {"log_sources": [
            {"id": DateLyingStr(2024, 1, 1), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["2024-01-01"])
        self.assertEqual(self._tail(cfg_value, "2024-01-01")["lines"], 2)

    def test_str_path_lying_bytes_keeps_listing_and_tailing(self):
        cfg_value = {"log_sources": [
            {"id": "s1", "path": StrLyingBytes(self.log_path)}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["path"], r["exists"]) for r in rows],
            [("s1", self.log_path, True)])
        payload = self._tail(cfg_value, "s1")
        self.assertEqual(payload["log"], "line-one\nline-two")
        self.assertEqual(payload["lines"], 2)

    def test_str_path_lying_bytearray_keeps_listing_and_tailing(self):
        cfg_value = {"log_sources": [
            {"id": "s1", "path": StrLyingByteArray(self.log_path)}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["path"], r["exists"]) for r in rows],
            [("s1", self.log_path, True)])
        self.assertEqual(self._tail(cfg_value, "s1")["lines"], 2)


class StaysDroppedTests(_LogsSandbox):
    """Total impostors — a claim with no renderable layout — keep the
    logs12 drop, and the drop stays row-scoped: never a 500."""

    def test_str_impostor_id_still_drops_its_row_alone(self):
        cfg_value = {"log_sources": [
            {"id": StrImpostor(), "path": self.log_path},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)

    def test_bytes_impostor_path_still_drops_its_row_alone(self):
        cfg_value = {"log_sources": [
            {"id": "junk", "path": BytesImpostor()},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)

    def test_flipping_liar_id_still_drops_its_row_alone(self):
        cfg_value = {"log_sources": [
            {"id": FlippingLiar([bytes, str]), "path": self.log_path},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)

    def test_flipping_liar_entry_still_drops_beside_a_sane_sibling(self):
        cfg_value = {"log_sources": [
            FlippingLiar([dict, str, list]),
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)


class StaysImmuneTests(_LogsSandbox):
    """The real-MRO direction never had the gap — ``isinstance`` checks
    the real type before consulting the lie — pinned so a rework of the
    arms cannot introduce it."""

    def test_str_id_lying_bytes_keeps_listing_and_tailing(self):
        cfg_value = {"log_sources": [
            {"id": StrLyingBytes("logid"), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["exists"]) for r in rows], [("logid", True)])
        self.assertEqual(self._tail(cfg_value, "logid")["lines"], 2)

    def test_bytes_path_lying_str_keeps_listing_and_tailing(self):
        cfg_value = {"log_sources": [
            {"id": "s1",
             "path": BytesLyingStr(os.fsencode(self.log_path))}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["path"], r["exists"]) for r in rows],
            [("s1", self.log_path, True)])
        self.assertEqual(self._tail(cfg_value, "s1")["lines"], 2)

    def test_sane_config_renders_identically(self):
        cfg_value = {"log_sources": [
            {"id": "s1", "name": "Sane", "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["name"], r["exists"]) for r in rows],
            [("s1", "Sane", True)])
        payload = self._tail(cfg_value, "s1")
        self.assertEqual(payload["log"], "line-one\nline-two")
        self.assertEqual(payload["lines"], 2)


class ControlFlowStillPropagatesTests(_LogsSandbox):
    """The new fall-through paths must not widen the swallow: genuine
    control flow raised from a lying gate keeps propagating."""

    def test_keyboardinterrupt_from_an_id_class_property_propagates(self):
        class _KIClass:
            @property
            def __class__(self):  # type: ignore[override]
                raise KeyboardInterrupt

        cfg_value = {"log_sources": [
            {"id": _KIClass(), "path": self.log_path}]}
        with mock.patch.object(logs_svc, "cfg", lambda: cfg_value):
            with self.assertRaises(KeyboardInterrupt):
                logs_svc.log_sources()


class SanitizerUnitPins(unittest.TestCase):
    """The recovered arms directly: ``_utf8_text``, ``_config_text`` and
    ``_stat_size`` read the honest storage under the lie, and the
    impostor degrades they replace stay put."""

    def test_utf8_text_recovers_a_str_lying_bytes(self):
        self.assertEqual(logs_svc._utf8_text(StrLyingBytes("hi")), "hi")

    def test_utf8_text_keeps_the_impostor_empty_string(self):
        self.assertEqual(logs_svc._utf8_text(BytesImpostor()), "")

    def test_config_text_recovers_a_bytes_lying_str(self):
        self.assertEqual(logs_svc._config_text(BytesLyingStr(b"hi")), "hi")

    def test_config_text_still_drops_a_str_impostor(self):
        self.assertIsNone(logs_svc._config_text(StrImpostor()))

    class _StatPath:
        def __init__(self, size):
            self._size = size

        def stat(self):
            return type("_Stat", (), {"st_size": self._size})()

    def test_stat_size_recovers_a_float_lying_int(self):
        self.assertEqual(
            logs_svc._stat_size(self._StatPath(FloatLyingInt(1234.0))), 1234)

    def test_stat_size_keeps_the_nan_and_inf_zero_degrades(self):
        self.assertEqual(
            logs_svc._stat_size(self._StatPath(FloatLyingInt(math.nan))), 0)
        self.assertEqual(
            logs_svc._stat_size(self._StatPath(FloatLyingInt(math.inf))), 0)

    def test_stat_size_still_reads_an_int_lying_float(self):
        self.assertEqual(
            logs_svc._stat_size(self._StatPath(IntLyingFloat(77))), 77)

    def test_stat_size_keeps_the_int_impostor_zero(self):
        self.assertEqual(
            logs_svc._stat_size(self._StatPath(IntImpostor())), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
