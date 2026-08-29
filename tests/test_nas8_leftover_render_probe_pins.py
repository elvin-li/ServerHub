"""nas8 companions: the two non-``__class__`` leftovers, plus stays-immune pins.

Two render probes the nas_common/smart copies already guarded were still
bare in the raid/snapshots copies — each a live raw HTTP 500 (traceback,
no JSON body) on the mounted app pre-fix:

* ``raid_svc._jsonable`` walked the *bound* ``value.items()`` and unpacked
  the rows outside its try, so a dict subclass whose ``items()`` answers
  non-pair rows blew ``for k, v in items`` raw on every POST /api/raid/*
  mutation.  The fix reads the unbound ``dict.items`` view (the nas_common
  rule), so the C-level storage salvages and the override never fires.
* ``raid_svc._jsonable`` and ``snapshots_svc._jsonable`` probed
  ``getattr(value, "isoformat", None)`` bare.  getattr's default only
  swallows AttributeError — a leftover whose ``isoformat`` is a *raising
  property* raised out of the probe itself and 500'd POST /api/raid/* and
  POST /api/timemachine/action after the operator had already typed the
  admin password.

The pins hold ground earlier sweeps took, on this hunt's vectors that
turned out already immune:

* a FIFO parked at ``/etc/exports`` (read_text_capped opens O_NONBLOCK and
  refuses non-regular files) renders an empty export table, not a hung or
  500'd GET /api/nfs;
* a torn diskutil plist (ExpatError, not ValueError) renders an empty
  GET /api/raid;
* a >4300-digit number in the SMART history journal (``int()`` raises
  ValueError, not JSONDecodeError, for the *whole* document) drops to None
  and the row's siblings keep GET /api/smart/history alive;
* an ``nfs_svc.read_exports`` that raises outright costs the table, never
  the page.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import nfs_svc, raid_svc, smart_test_svc, snapshots_svc  # noqa: E402
from hub.routers import nas_common  # noqa: E402

_APP = None


def _client():
    global _APP
    from fastapi.testclient import TestClient

    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _ItemsTriplesDict(dict):
    """Passes ``isinstance(x, dict)``; its bound ``items()`` yields non-pairs."""

    def items(self):
        return [("a", "b", "c")]


class _IsoBomb:
    """A leftover whose ``isoformat`` is a raising property."""

    @property
    def isoformat(self):
        raise RuntimeError("isoformat bomb")


def _admin_browser(stack: ExitStack) -> None:
    stack.enter_context(mock.patch.object(
        nas_common.auth, "browser_authenticated", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_username", return_value="admin"))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "is_admin", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_client_id", return_value="127.0.0.1"))


_RAID_SET = {
    "uuid": "AABBCCDD-0000", "name": "arr", "level": "mirror",
    "status": "Online", "members": [], "member_count": 2,
}


def _raid_delete(admin_result):
    with ExitStack() as stack:
        _admin_browser(stack)
        stack.enter_context(mock.patch.object(
            raid_svc, "list_sets", return_value=[dict(_RAID_SET)]))
        stack.enter_context(mock.patch.object(
            raid_svc, "run_admin", return_value=admin_result))
        stack.enter_context(mock.patch.object(
            raid_svc, "_diskutil_on_disk", return_value=True))
        return _client().post("/api/raid/delete", json={
            "set_uuid": "AABBCCDD-0000", "confirm": True, "confirm_phrase": "arr",
        })


class RaidJsonableRenderBombTests(unittest.TestCase):
    def test_items_triples_admin_result_salvages_the_real_storage(self):
        # Pre-fix: ``for k, v in items`` unpacked the subclass's non-pair
        # rows raw — a 500 on POST /api/raid/delete.  The unbound
        # ``dict.items`` view reads the C-level storage instead, so the
        # genuine ok answer survives its own hostile override.
        resp = _raid_delete(_ItemsTriplesDict({"ok": True}))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["ok"], True)

    def test_isoformat_property_bomb_in_ok_payload_degrades_alone(self):
        resp = _raid_delete({"ok": True, "info": _IsoBomb()})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["ok"], True)
        # The bomb field degrades (text or None); the route stays coded.
        self.assertNotIsInstance(payload.get("info"), dict)

    def test_snapshots_isoformat_property_bomb_degrades_alone(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "run_admin",
                return_value={"ok": True, "info": _IsoBomb()}))
            resp = _client().post(
                "/api/timemachine/action", json={"action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["ok"], True)


class NfsFifoExportsStaysImmuneTests(unittest.TestCase):
    """A FIFO parked at /etc/exports must not hang or 500 GET /api/nfs.

    read_text_capped opens O_NONBLOCK and answers OSError(EINVAL) for a
    non-regular file, which read_exports already maps to "nothing
    exported" — pinned so the seam stays sealed.
    """

    def test_fifo_exports_renders_an_empty_table(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("platform has no mkfifo")
        nfs_svc.invalidate()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                fifo = Path(tmp) / "exports"
                os.mkfifo(fifo)
                with mock.patch.object(nfs_svc, "EXPORTS_PATH", fifo):
                    resp = _client().get("/api/nfs?force=1")
        finally:
            nfs_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["entries"], [])
        self.assertEqual(payload["count"], 0)

    def test_read_exports_that_raises_outright_costs_only_the_table(self):
        nfs_svc.invalidate()
        try:
            with mock.patch.object(
                nfs_svc, "read_exports", side_effect=RuntimeError("gone"),
            ):
                resp = _client().get("/api/nfs?force=1")
        finally:
            nfs_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["entries"], [])


class RaidTornPlistStaysImmuneTests(unittest.TestCase):
    def test_torn_plist_renders_an_empty_raid_page(self):
        # ExpatError is not ValueError; _plist already absorbs it — pinned.
        raid_svc.invalidate()
        try:
            with mock.patch.object(
                raid_svc, "sh",
                return_value=(0, '<?xml version="1.0"?><plist><dict><key>torn', ""),
            ):
                resp = _client().get("/api/raid?force=1")
        finally:
            raid_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["sets"], [])
        self.assertEqual(payload["count"], 0)


class SmartHistoryHugeIntStaysImmuneTests(unittest.TestCase):
    def test_over_cap_journal_number_drops_to_none_and_the_row_survives(self):
        # int("9"*5000) inside json.loads raises ValueError (not
        # JSONDecodeError) for the whole document; the parse_int hook
        # already drops just the number — pinned at the route.
        path = smart_test_svc.HISTORY_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        body = '[{"ts": ' + ("9" * 5000) + ', "device": "/dev/disk0"}]'
        path.write_text(body, encoding="utf-8")
        try:
            resp = _client().get("/api/smart/history")
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["history"][0]["device"], "/dev/disk0")
        self.assertIsNone(payload["history"][0]["ts"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
