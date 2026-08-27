"""Eleventh leftover-500s sweep of the NAS surfaces: the poisoned ``sh`` rc.

nas9 sealed the lying-``__class__`` impostor across every NAS payload and
plist shape.  This hunt found the vector one seam earlier, on the *return
code* itself: ``nfs_svc``, ``raid_svc`` and ``snapshots_svc`` never own the
``sh`` they call (tests and tooling patch it), yet each compared the raw
``rc`` slot with ``rc == 0`` / ``rc != 0``.  A leftover rc-*subclass* whose
``__eq__`` / ``__ne__`` raises — the health9 / shares_svc rc class the
sibling NAS modules (smart, usage, storage) already launder through
``_rc_int`` — detonated those bare comparisons outside every guard:

* ``nfs_svc._active_exports`` (``rc != 0``), ``check_exports`` and
  ``statistics`` (``rc == 0``) all run under ``overview()`` / directly in
  the stats route with no try around the comparison — a raw HTTP 500 on
  GET /api/nfs and GET /api/nfs/stats;
* ``snapshots_svc._plist`` (``rc != 0``) is called by ``list_snapshots``
  outside any try under ``overview``'s fan-out, and ``_tm_latest_backup``
  (``rc == 0``) runs directly in ``time_machine_overview``'s fan-out, which
  re-raises a probe's error — a raw HTTP 500 on GET /api/snapshots;
* ``raid_svc._plist`` (``rc != 0``) feeds ``list_sets`` /
  ``candidate_devices`` on the mutation path (``_resolve_set`` /
  ``_check_devices``), outside the ``_listing`` guard that protects the read
  page — a raw HTTP 500 on every POST /api/raid/*.

A *lying* ``__class__`` impostor that answers ``int`` over no real int
storage passes ``isinstance`` the same way and TypeErrors on the unbound
``int.__index__`` read; it too must drop to the failure branch, never 500.

The fix is the ``_rc_int`` rule the other NAS modules already carry:
``int.__index__`` reads the honest exit status underneath a subclass
override, junk degrades to ``-255`` (no honest exit status, distinct from
the ``-1`` spawn sentinel), and every ``rc`` probe compares that laundered
int.  These tests plant the poisoned rc against our own handlers in-process
and assert 200 / coded 4xx with valid UTF-8 JSON, never a 500.
"""
from __future__ import annotations

import json
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import nfs_svc, raid_svc, snapshots_svc  # noqa: E402
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
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _admin_browser(stack: ExitStack) -> None:
    stack.enter_context(mock.patch.object(
        nas_common.auth, "browser_authenticated", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_username", return_value="admin"))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "is_admin", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_client_id", return_value="127.0.0.1"))


class _RcEqBomb(int):
    """An rc slot that carries an honest value but refuses every comparison.

    The health9 / shares_svc rc class: a genuine ``int`` subclass whose
    ``__eq__`` / ``__ne__`` raises.  The bare ``rc == 0`` / ``rc != 0``
    probes ran the *bound* comparison and detonated; ``_rc_int``'s unbound
    ``int.__index__`` reads the real value underneath the override.
    """

    def __eq__(self, other):
        raise ValueError("rc __eq__ bomb")

    def __ne__(self, other):
        raise ValueError("rc __ne__ bomb")

    __hash__ = int.__hash__


class _RcClassLiar:
    """A leftover whose ``__class__`` answers ``int`` over no int storage.

    ``isinstance(x, int)`` honours the lie, so the impostor sails through the
    ``_rc_int`` gate and TypeErrors on the unbound ``int.__index__`` read —
    it must drop to ``-255`` (the failure branch), never 500.
    """

    @property
    def __class__(self):
        return int


def _sh_returning(rc, out="", err=""):
    return lambda *a, **k: (rc, out, err)


class RcIntContractTests(unittest.TestCase):
    """Each module's ``_rc_int`` reads the honest status and drops junk."""

    def test_all_three_modules_expose_the_same_contract(self):
        for module in (nfs_svc, raid_svc, snapshots_svc):
            with self.subTest(module=module.__name__):
                # Honest values read through, comparison-bomb subclass and
                # all, because the unbound index never runs ``__eq__``.
                self.assertEqual(module._rc_int(0), 0)
                self.assertEqual(module._rc_int(4), 4)
                self.assertEqual(module._rc_int(_RcEqBomb(0)), 0)
                self.assertEqual(module._rc_int(_RcEqBomb(1)), 1)
                # A genuine bool rc reads as its int.
                self.assertEqual(module._rc_int(True), 1)
                # Junk shapes degrade to -255 (no honest exit status).
                self.assertEqual(module._rc_int(_RcClassLiar()), -255)
                self.assertEqual(module._rc_int("nope"), -255)
                self.assertEqual(module._rc_int(None), -255)
                # -255 is distinct from the -1 spawn sentinel and from 0.
                self.assertNotIn(module._rc_int(_RcClassLiar()), (0, -1))


class NfsRcBombTests(unittest.TestCase):
    def test_overview_survives_a_comparison_bomb_rc(self):
        # ``sh`` reports the server running (so _active_exports runs its
        # ``rc != 0`` probe) and exports present (so check_exports runs its
        # ``rc == 0`` probe); the rc slot refuses every comparison.
        for rc in (_RcEqBomb(0), _RcClassLiar()):
            with self.subTest(rc=type(rc).__name__):
                nfs_svc.invalidate()
                try:
                    with ExitStack() as stack:
                        stack.enter_context(mock.patch.object(
                            nfs_svc, "sh", _sh_returning(rc, "nfsd is running")))
                        stack.enter_context(mock.patch.object(
                            nfs_svc, "_exports_exists", return_value=True))
                        resp = _client().get("/api/nfs?force=1")
                finally:
                    nfs_svc.invalidate()
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                # A refusing rc reads as failure: no advertised exports.
                self.assertEqual(payload["active"], [])

    def test_stats_route_survives_a_comparison_bomb_rc(self):
        # value-0 bomb reads the honest success; the impostor degrades —
        # both answer 200 with valid JSON, neither 500s.
        for rc, expected_ok in ((_RcEqBomb(0), True), (_RcClassLiar(), False)):
            with self.subTest(rc=type(rc).__name__):
                with mock.patch.object(
                    nfs_svc, "sh", _sh_returning(rc, "Server Info")
                ):
                    resp = _client().get("/api/nfs/stats")
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertIs(payload["ok"], expected_ok)

    def test_active_exports_reads_the_honest_status_underneath_a_bomb(self):
        # ``_RcEqBomb(0)`` refuses ``rc != 0`` but carries an honest 0, so
        # the unbound index reads success and the mounts still parse.
        with mock.patch.object(
            nfs_svc, "sh", _sh_returning(_RcEqBomb(0), "Exports list on host\n/x *")
        ):
            self.assertEqual(nfs_svc._active_exports(), [{"path": "/x", "clients": ["*"]}])
        # A lying-``__class__`` impostor has no honest status: -255, failure.
        with mock.patch.object(
            nfs_svc, "sh", _sh_returning(_RcClassLiar(), "Exports list\n/x *")
        ):
            self.assertEqual(nfs_svc._active_exports(), [])

    def test_check_and_statistics_read_status_underneath_a_bomb(self):
        with mock.patch.object(nfs_svc, "sh", _sh_returning(_RcEqBomb(0), "ok")):
            self.assertIs(nfs_svc.check_exports()["ok"], True)
            self.assertIs(nfs_svc.statistics()["ok"], True)
        # The impostor degrades to failure instead of 500ing the read.
        with mock.patch.object(nfs_svc, "sh", _sh_returning(_RcClassLiar(), "ok")):
            self.assertIs(nfs_svc.check_exports()["ok"], False)
            self.assertIs(nfs_svc.statistics()["ok"], False)


class SnapshotsRcBombTests(unittest.TestCase):
    def test_overview_survives_a_comparison_bomb_rc(self):
        # A poisoned rc on the ``diskutil``/``tmutil`` reads must not escape
        # ``list_snapshots`` / ``_tm_latest_backup`` into fan_out.
        for rc in (_RcEqBomb(0), _RcClassLiar()):
            with self.subTest(rc=type(rc).__name__):
                snapshots_svc.invalidate()
                try:
                    with ExitStack() as stack:
                        stack.enter_context(mock.patch.object(
                            snapshots_svc, "sh",
                            _sh_returning(rc, "<?xml version='1.0'?>")))
                        stack.enter_context(mock.patch.object(
                            snapshots_svc, "snapshot_mounts", return_value=["/"]))
                        resp = _client().get("/api/snapshots?force=1")
                finally:
                    snapshots_svc.invalidate()
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["volumes"][0]["count"], 0)

    def test_plist_and_latest_backup_survive_a_bomb_rc(self):
        # ``_RcEqBomb(0)`` reads the honest success: ``_tm_latest_backup``
        # returns the (real) path text, ``_plist`` returns None only because
        # the stub is not a dict plist — neither read raises.
        with mock.patch.object(
            snapshots_svc, "sh", _sh_returning(_RcEqBomb(0), "/Volumes/TM/latest")
        ):
            self.assertEqual(snapshots_svc._tm_latest_backup(), "/Volumes/TM/latest")
        # The impostor degrades to the failure branch, never a 500.
        with mock.patch.object(
            snapshots_svc, "sh", _sh_returning(_RcClassLiar(), "/Volumes/TM/latest")
        ):
            self.assertEqual(snapshots_svc._tm_latest_backup(), "")
            self.assertIsNone(snapshots_svc._plist(["x"]))

    def test_create_snapshot_reads_a_bomb_rc_as_a_coded_failure(self):
        # The mutation's ``rc != 0`` probe must degrade, not 500 the route.
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "sh", _sh_returning(_RcEqBomb(1), "", "boom")))
            resp = _client().post("/api/snapshots/create")
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")


class RaidRcBombTests(unittest.TestCase):
    _REAL_SET = {
        "AppleRAIDSetUUID": "AAAAAAAA-0000-1111-2222-333333333333",
        "Name": "Media",
        "Level": "Mirror",
        "Status": "Online",
        "AppleRAIDMembers": [],
        "Size": 1024,
        "AppleRAIDSetDeviceNode": "/dev/disk9",
    }

    def test_read_page_survives_a_comparison_bomb_rc(self):
        for rc in (_RcEqBomb(0), _RcClassLiar()):
            with self.subTest(rc=type(rc).__name__):
                raid_svc.invalidate()
                try:
                    with mock.patch.object(
                        raid_svc, "sh",
                        _sh_returning(rc, "<?xml version='1.0'?>")
                    ):
                        resp = _client().get("/api/raid?force=1")
                finally:
                    raid_svc.invalidate()
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["sets"], [])

    def test_mutation_resolver_survives_a_comparison_bomb_rc(self):
        # ``_resolve_set`` -> ``list_sets`` -> ``_plist``'s ``rc != 0`` runs
        # outside the read page's ``_listing`` guard; a poisoned rc used to
        # 500 the delete one seam ahead of the coded not-found.
        for rc in (_RcEqBomb(0), _RcClassLiar()):
            with self.subTest(rc=type(rc).__name__):
                with ExitStack() as stack:
                    _admin_browser(stack)
                    stack.enter_context(mock.patch.object(
                        raid_svc, "sh",
                        _sh_returning(rc, "<?xml version='1.0'?>")))
                    resp = _client().post("/api/raid/delete", json={
                        "set_uuid": "0" * 12,
                        "confirm": True,
                        "confirm_phrase": "x",
                    })
                self.assertEqual(resp.status_code, 404, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["detail"]["code"], "raid.set_not_found")

    def test_plist_reads_a_bomb_rc_as_the_empty_document(self):
        with mock.patch.object(
            raid_svc, "sh", _sh_returning(_RcEqBomb(0), "<?xml version='1.0'?>")
        ):
            self.assertEqual(raid_svc._plist(["x"]), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
