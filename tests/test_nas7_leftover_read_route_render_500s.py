"""Seventh leftover-500s sweep, part two: the NAS *read* payloads.

Every mutation on ``hub/routers/nas_storage.py`` answers through
``raise_service_error``, which cleans its body with
``nas_common._jsonable``; every mutation on ``hub/routers/shares.py``
answers through ``_ok_payload`` (nas5).  The read routes on both pasted
their service payload into the response verbatim — the ``_rendered`` rule
``hub/routers/storage.py`` already carries for the disk pages sitting right
next to them.  Each of these was a live raw HTTP 500 (traceback, no JSON
body) on the mounted app pre-fix, on data the NAS surfaces genuinely carry:

* a lone ``\\ud800`` in an ``/etc/exports`` line, a plist set name, a SMART
  probe detail, a share name or a usage filename 500'd Starlette's UTF-8
  encode of GET /api/nfs, /api/nfs/stats, /api/raid, /api/smart,
  /api/shares and all four /api/storage/usage routes;
* an over-cap already-int (YAML/plist hex loads uncapped through
  ``int(x, 16)``) — a plist ``Size``, a Time Machine quota, a usage
  ``bytes`` — ValueError'd ``json.dumps`` under CPython's int->str digit
  cap on the same routes;
* an ``inf`` snapshot XID, pool figure or ``size_mb`` from a garbled ``du``
  500'd the encoder under ``allow_nan=False``.

The overview builders needed their own guard as well, because a hostile
*listing* raises inside the service before any route-level sanitizer can
run (the ``usage_svc.scan_roots`` / ``storage_pool_svc._candidates``
materialize-under-guard rule): ``nfs_svc.overview`` walked
``read_exports()``, ``snapshots_svc.overview`` walked ``snapshot_mounts()``
and each per-mount result with bare ``len()``/subscripts, ``raid_svc``
counted ``s["degraded"]`` per row, ``shares_svc.time_machine_status``
walked the listing the page fan-out had just rescued, and
``snapshots_svc.delete_all_snapshots`` subscripted every row.
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

from hub import (  # noqa: E402
    nfs_svc,
    raid_svc,
    shares_svc,
    smart_test_svc,
    snapshots_svc,
    usage_svc,
)
from hub.routers import nas_common, nas_storage  # noqa: E402

#: Built arithmetically: int("9" * 5000) itself trips the parse cap.
_HUGE_INT = 10 ** 5000

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


class _IterBombList(list):
    """Passes ``isinstance(x, list)``; raises the moment it is iterated."""

    def __iter__(self):
        raise ValueError("iteration bomb")


class _GetBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises the moment ``.get`` is called."""

    def get(self, *a, **k):
        raise ValueError("get bomb")


class _BoolBomb:
    """A truth value that detonates ``bool()`` itself."""

    def __bool__(self):
        raise ValueError("bool bomb")


def _admin_browser(stack: ExitStack) -> None:
    """An administrator browser session, as nas_common resolves one."""
    stack.enter_context(mock.patch.object(
        nas_common.auth, "browser_authenticated", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_username", return_value="admin"))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "is_admin", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_client_id", return_value="127.0.0.1"))


class NfsOverviewRenderTests(unittest.TestCase):
    """GET /api/nfs renders the export table, never a raw 500."""

    def setUp(self):
        nfs_svc.overview.invalidate()
        self.addCleanup(nfs_svc.overview.invalidate)

    def _overview(self, entries):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                nfs_svc, "read_exports", return_value=entries))
            stack.enter_context(mock.patch.object(
                nfs_svc, "_nfsd_status",
                return_value={"enabled": False, "running": False, "detail": ""}))
            stack.enter_context(mock.patch.object(
                nfs_svc, "_exports_exists", return_value=False))
            return _client().get("/api/nfs?force=true")

    def test_surrogate_export_line_is_scrubbed(self):
        resp = self._overview([{"raw": "/tmp 10.0.0.\ud800", "path": "/tmp"}])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)

    def test_over_cap_int_field_drops_alone(self):
        resp = self._overview([{"raw": "/tmp h", "port": _HUGE_INT}])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIsNone(payload["entries"][0]["port"])
        self.assertEqual(payload["entries"][0]["raw"], "/tmp h")

    def test_inf_field_drops_alone(self):
        resp = self._overview([{"raw": "/tmp h", "size": float("inf")}])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIsNone(payload["entries"][0]["size"])

    def test_iter_bomb_table_recovers_through_the_unbound_walk(self):
        # The listing bomb fires inside overview()'s own walk, before any
        # route sanitizer could help.  Guarded materialization reads the real
        # C-level storage through the unbound list iterator, so the genuine
        # rows survive while the hostile wrapper drops.
        resp = self._overview(_IterBombList([{"raw": "/tmp h"}]))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["entries"], [{"raw": "/tmp h"}])
        self.assertEqual(payload["count"], 1)

    def test_read_exports_raising_costs_the_table_not_the_page(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                nfs_svc, "read_exports", side_effect=ValueError("boom")))
            stack.enter_context(mock.patch.object(
                nfs_svc, "_nfsd_status",
                return_value={"enabled": False, "running": False, "detail": ""}))
            stack.enter_context(mock.patch.object(
                nfs_svc, "_exports_exists", return_value=False))
            resp = _client().get("/api/nfs?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["entries"], [])

    def test_surrogate_nfsstat_text_is_scrubbed(self):
        with mock.patch.object(
            nfs_svc, "statistics", return_value={"ok": True, "text": "x\ud800"},
        ):
            resp = _client().get("/api/nfs/stats")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)

    def test_ordinary_overview_keeps_its_exact_shape(self):
        row = {
            "raw": "/srv/media -alldirs 192.168.1.0/24", "path": "/srv/media",
            "extra_paths": [], "clients": ["192.168.1.0/24"], "network": "",
            "mask": "", "readonly": False, "alldirs": True, "maproot": "",
            "mapall": "", "unparsed": False,
        }
        resp = self._overview([row])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        self.assertEqual(payload["entries"], [row])
        self.assertEqual(payload["count"], 1)


class SnapshotsOverviewRenderTests(unittest.TestCase):
    """GET /api/snapshots renders the volume table, never a raw 500."""

    def setUp(self):
        snapshots_svc.overview.invalidate()
        self.addCleanup(snapshots_svc.overview.invalidate)

    def _overview(self, mounts, snaps):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                snapshots_svc, "snapshot_mounts", return_value=mounts))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "list_snapshots", return_value=snaps))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "time_machine_overview", return_value={}))
            return _client().get("/api/snapshots?force=true")

    def test_inf_xid_drops_alone(self):
        resp = self._overview(["/"], [{
            "date_token": "", "deletable": False, "date": "",
            "xid": float("inf"),
        }])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIsNone(payload["volumes"][0]["snapshots"][0]["xid"])

    def test_surrogate_snapshot_name_is_scrubbed(self):
        resp = self._overview(["/"], [{
            "date_token": "", "deletable": False, "date": "",
            "name": "snap\ud800",
        }])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)

    def test_iter_bomb_mount_listing_keeps_the_boot_volume(self):
        # "/" is pinned (snapshot_mounts always reports it first), so the
        # page still renders while the hostile listing drops.
        resp = self._overview(_IterBombList(["/"]), [])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual([v["mount"] for v in payload["volumes"]], ["/"])

    def test_keyless_snapshot_row_costs_its_volume_not_the_page(self):
        # ``newest["date"]`` / ``s["deletable"]`` used to KeyError the walk.
        resp = self._overview(["/"], [{"no": "keys"}])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["volumes"][0]["newest"], "")
        self.assertEqual(payload["volumes"][0]["deletable"], 0)

    def test_bool_bomb_deletable_flag_counts_as_false(self):
        resp = self._overview(["/"], [{
            "date_token": "", "date": "", "deletable": _BoolBomb(),
        }])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["volumes"][0]["deletable"], 0)

    def test_ordinary_overview_keeps_its_counts(self):
        snap = {
            "mount": "/", "name": "com.apple.TimeMachine.2026-08-01-120000.local",
            "uuid": "U", "xid": 42, "date_token": "2026-08-01-120000",
            "date": "2026-08-01 12:00:00", "purgeable": True,
            "limits_shrink": False, "kind": "timemachine", "deletable": True,
        }
        resp = self._overview(["/"], [snap])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["volumes"][0]["count"], 1)
        self.assertEqual(payload["volumes"][0]["deletable"], 1)
        self.assertEqual(payload["volumes"][0]["newest"], "2026-08-01 12:00:00")


class RaidOverviewRenderTests(unittest.TestCase):
    """GET /api/raid renders the set table, never a raw 500."""

    def setUp(self):
        raid_svc.overview.invalidate()
        self.addCleanup(raid_svc.overview.invalidate)

    def _overview(self, sets, candidates=None):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                raid_svc, "list_sets", return_value=sets))
            stack.enter_context(mock.patch.object(
                raid_svc, "candidate_devices",
                return_value=[] if candidates is None else candidates))
            return _client().get("/api/raid?force=true")

    def test_surrogate_set_name_is_scrubbed(self):
        resp = self._overview([{
            "degraded": False, "rebuilding": False, "name": "tank\ud800",
        }])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)

    def test_over_cap_int_size_drops_alone(self):
        resp = self._overview([{
            "degraded": False, "rebuilding": False, "size_bytes": _HUGE_INT,
        }])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIsNone(payload["sets"][0]["size_bytes"])

    def test_iter_bomb_listings_recover_through_the_unbound_walk(self):
        # Both listings pass ``isinstance(x, list)`` but refuse iteration;
        # the guarded materialization reads the genuine rows out of the
        # C-level storage instead of costing the whole page.
        resp = self._overview(
            _IterBombList([{"degraded": True, "rebuilding": False}]),
            _IterBombList([{"device": "disk9"}]),
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["sets"], [{"degraded": True, "rebuilding": False}])
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["degraded"], 1)

    def test_keyless_and_bomb_rows_count_as_healthy(self):
        # ``s["degraded"]`` used to KeyError, and a __bool__ bomb detonated
        # the truth test itself — both cost the whole page.
        resp = self._overview([
            {"uuid": "a"},
            {"degraded": _BoolBomb(), "rebuilding": False},
            {"degraded": True, "rebuilding": True},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["count"], 3)
        self.assertEqual(payload["degraded"], 1)
        self.assertEqual(payload["rebuilding"], 1)

    def test_list_sets_raising_costs_the_table_not_the_page(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                raid_svc, "list_sets", side_effect=ValueError("boom")))
            stack.enter_context(mock.patch.object(
                raid_svc, "candidate_devices", return_value=[]))
            resp = _client().get("/api/raid?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["sets"], [])


class SmartAndUsageRenderTests(unittest.TestCase):
    """The SMART and usage read routes ride the same sanitizer."""

    def setUp(self):
        smart_test_svc.overview.invalidate()
        self.addCleanup(smart_test_svc.overview.invalidate)

    def test_surrogate_smart_detail_is_scrubbed(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_report",
                return_value={"device": "/dev/disk0", "detail": "bad\ud800"}))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "passwordless_available", return_value=False))
            resp = _client().get("/api/smart")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)

    def test_surrogate_spotlight_detail_is_scrubbed(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                usage_svc, "spotlight_status",
                return_value=[{"volume": "/", "detail": "x\ud800"}]))
            stack.enter_context(mock.patch.object(
                usage_svc, "scan_roots", return_value=[]))
            resp = _client().get("/api/storage/usage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)

    def test_usage_tree_largest_and_duplicates_are_all_rendered(self):
        for label, attr, payload, path, probe in (
            ("tree", "tree", {"children": [{"name": "a\ud800"}]},
             "/api/storage/usage/tree", None),
            ("largest", "largest_files", {"items": [{"bytes": _HUGE_INT}]},
             "/api/storage/usage/largest", ("items", 0, "bytes")),
            ("duplicates", "duplicates", {"reclaimable_gb": float("inf")},
             "/api/storage/usage/duplicates", ("reclaimable_gb",)),
        ):
            with self.subTest(route=label):
                with mock.patch.object(usage_svc, attr, return_value=payload):
                    resp = _client().get(path)
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                body = resp.json()
                _starlette(body)
                self.assertNotIn("\ud800", resp.text)
                if probe is not None:
                    node = body
                    for key in probe:
                        node = node[key]
                    self.assertIsNone(node)

    def test_surrogate_history_row_is_scrubbed(self):
        with mock.patch.object(
            smart_test_svc, "_load_history",
            return_value=[{"device": "/dev/disk0", "message": "x\ud800"}],
        ):
            resp = _client().get("/api/smart/history")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)


class SharesOverviewRenderTests(unittest.TestCase):
    """GET /api/shares was the one shares route with no sanitizer."""

    def _overview(self, smb, services=()):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                shares_svc, "list_smb_shares", return_value=smb))
            stack.enter_context(mock.patch.object(
                shares_svc, "system_services", return_value=list(services)))
            stack.enter_context(mock.patch.object(
                shares_svc, "file_services", return_value=[]))
            return _client().get("/api/shares")

    def test_surrogate_share_name_is_scrubbed(self):
        resp = self._overview([{
            "name": "media\ud800", "record_name": "m", "time_machine": False,
        }])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)

    def test_over_cap_int_quota_drops_alone(self):
        resp = self._overview([{
            "name": "m", "record_name": "m", "time_machine": False,
            "tm_quota_gb": _HUGE_INT,
        }])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIsNone(payload["smb"][0]["tm_quota_gb"])
        self.assertEqual(payload["smb"][0]["name"], "m")

    def test_inf_size_mb_drops_alone(self):
        resp = self._overview([{
            "name": "m", "record_name": "m", "time_machine": False,
            "size_mb": float("inf"),
        }])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIsNone(payload["smb"][0]["size_mb"])

    def test_iter_bomb_listing_answers_an_empty_share_table(self):
        # The bomb fires in time_machine_status, *after* the page fan-out
        # already absorbed its own failures.
        resp = self._overview(_IterBombList([{"record_name": "m"}]))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["time_machine"]["share_count"], 0)

    def test_get_bomb_share_row_counts_through_the_unbound_view(self):
        resp = self._overview([
            _GetBombDict({"record_name": "m", "time_machine": True}),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["time_machine"]["share_count"], 1)

    def test_surrogate_service_detail_is_scrubbed(self):
        resp = self._overview([], [{"id": "remote_login", "detail": "up\ud800"}])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)

    def test_ordinary_overview_keeps_its_share_rows(self):
        share = {
            "record_name": "media", "name": "media", "path": "/tmp",
            "smb_name": "media", "shared": True, "guest": False,
            "readonly": False, "encrypted": False, "size_mb": 12.5,
            "url": "smb://192.0.2.7/media", "time_machine": True,
            "tm_quota_gb": 500,
        }
        resp = self._overview([share])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        self.assertEqual(payload["smb"], [share])
        self.assertEqual(payload["time_machine"]["share_count"], 1)


class DeleteAllSnapshotsHostileListingTests(unittest.TestCase):
    """POST /api/snapshots/delete (all) walks its listing under guard."""

    def _delete_all(self, snaps):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "snapshot_mounts", return_value=["/"]))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "list_snapshots", return_value=snaps))
            return _client().post(
                "/api/snapshots/delete", json={"mount": "/", "confirm": True})

    def test_iter_bomb_listing_answers_nothing_deletable(self):
        resp = self._delete_all(_IterBombList([]))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["ok"], True)
        self.assertEqual(payload["deleted"], 0)

    def test_keyless_row_answers_nothing_deletable(self):
        # ``s["date_token"]`` / ``s["deletable"]`` used to KeyError the walk.
        resp = self._delete_all([{"no": "keys"}])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["deleted"], 0)

    def test_hostile_row_drops_while_its_sibling_still_deletes(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "snapshot_mounts", return_value=["/"]))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "list_snapshots", return_value=[
                    {"deletable": _BoolBomb(), "date_token": "x"},
                    {"deletable": True, "date_token": "2026-08-01-120000"},
                ]))
            run = stack.enter_context(mock.patch.object(
                snapshots_svc, "run_admin_sequence",
                return_value={"ok": True}))
            resp = _client().post(
                "/api/snapshots/delete", json={"mount": "/", "confirm": True})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["deleted"], 1)
        self.assertEqual(
            run.call_args[0][0], [[snapshots_svc.TMUTIL,
                                   "deletelocalsnapshots",
                                   "2026-08-01-120000"]])


class RenderedContractTests(unittest.TestCase):
    """The router helper is the shared sanitizer, not a third copy."""

    def test_rendered_is_the_shared_jsonable(self):
        row = nas_storage._rendered({
            "name": "tank\ud800",
            "size": _HUGE_INT,
            "pct": float("inf"),
            "members": _IterBombList(["disk9"]),
            "count": 1,
        })
        _starlette(row)
        self.assertNotIn("\ud800", row["name"])
        self.assertIsNone(row["size"])
        self.assertIsNone(row["pct"])
        # The unbound base walk reads the real C-level storage.
        self.assertEqual(row["members"], ["disk9"])
        self.assertEqual(row["count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
