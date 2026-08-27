"""Sixth leftover-500s sweep of the Main Array page's backend: the read overviews.

array2..5 sealed the mutation funnels and the FIFO / TM-verb / vanished-CLI
classes.  This sweep re-reproduces the leftover-render classes against the
five *read* overviews the Main Array / Time Machine / array surfaces answer
and that are NOT wrapped in a final ``_jsonable`` — they rely on per-field
sanitization instead: GET /api/raid, GET /api/snapshots, GET /api/smart,
GET /api/nfs and GET /api/storage/usage.  Each is driven over the real
mounted app (``create_app()``, ``TestClient`` with
``raise_server_exceptions=False``) with a leftover bomb planted at the genuine
provider seam (``_plist`` / ``sh`` / ``run_admin`` / ``cfg``), and each must
answer HTTP 200 with a body Starlette's ``allow_nan=False`` / UTF-8 encoder can
render — never a bare 500.

The hunted leftover shapes:

* a lone ``\\ud800`` surrogate in a plist Name / mount / device field;
* a >4300-digit integer past CPython's int->str cap (a plist ``<integer>``
  hex scalar loads uncapped through ``int(x, 16)``);
* a non-finite ``inf`` / ``nan`` real, and a finite ``1e308`` that overflows
  a later ``* 100`` / ``/ 2**30``;
* ``bytes`` where a string field is expected;
* the tools5/modules5 subclass bombs — a dict subclass whose ``.get`` /
  ``items`` raises, a list subclass whose ``__iter__`` raises, an int/float
  subclass whose ``__str__`` / ``__float__`` raises — which pass every
  ``isinstance`` gate and which tests and tooling can plant at the patched
  provider seam these modules deliberately do not own.

Every case here is found sealed on the current tree; the file pins them so
the discipline the array/storage/nas sweeps established stays load-bearing.
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
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8.

    A lone surrogate raises UnicodeEncodeError here; an ``inf`` / ``nan``
    raises ValueError under ``allow_nan=False``; a >4300-digit int raises
    ValueError out of the encoder's own int->str.  Asserting the body
    survives this is asserting the route did not merely dodge the exception
    with a partial body.
    """
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


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
    stack.enter_context(mock.patch.object(
        nas_storage.audit, "record", lambda *a, **k: {}))


class RaidOverviewLeftoverTests(unittest.TestCase):
    """GET /api/raid must render a hostile diskutil plist, not 500."""

    def _plist_for(self, sets_payload, topo_payload, phys_payload, info_payload):
        def fake(argv, *, timeout=15):
            joined = " ".join(str(a) for a in argv)
            if "appleRAID" in joined:
                return sets_payload
            if "physical" in joined:
                return phys_payload
            if "info" in joined:
                return info_payload
            return topo_payload

        return fake

    def test_surrogate_and_overcap_and_inf_fields_render(self):
        raid_set = {
            "AppleRAIDSetUUID": "12345678-9ABC-DEF0-1234-56789ABCDEF0",
            # Lone surrogate in the set name, inf/over-cap in the numbers.
            "Name": "arr\ud800ay",
            "Level": "mirror",
            "Status": "Online",
            "Size": _HUGE_INT,
            "AppleRAIDMembers": [
                {
                    "AppleRAIDMemberDeviceNode": "/dev/disk4",
                    "AppleRAIDMemberUUID": "aa\ud800bb",
                    "MemberStatus": "online",
                    "AppleRAIDMemberRebuildPercent": float("inf"),
                    "Size": float("nan"),
                },
            ],
        }
        sets_payload = {"AppleRAIDSets": [raid_set]}
        topo = {"AllDisksAndPartitions": []}
        phys = {"AllDisksAndPartitions": [
            {"DeviceIdentifier": "disk5", "Size": _HUGE_INT},
        ]}
        info = {"MediaName": "Dev\ud800ice", "TotalSize": float("inf")}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                raid_svc, "_plist",
                self._plist_for(sets_payload, topo, phys, info)))
            raid_svc.invalidate()
            resp = _client().get("/api/raid")
            raid_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["count"], 1)
        self.assertNotIn("\ud800", resp.text)

    def test_non_dict_and_bytes_and_torn_rows_drop_without_500(self):
        # The genuine plist leftover shapes (plistlib yields only plain types,
        # so a subclass ``.get`` bomb cannot arrive here — the run_admin path,
        # not this one, owns that class): a non-dict set row, a member list
        # that is not a list, and ``bytes`` in a device/name field.  list_sets
        # gates each on isinstance and reads through _ident/_size_fields, so
        # the torn rows drop and the healthy set still renders.
        good = {
            "AppleRAIDSetUUID": "0000AAAA-0000-0000-0000-00000000AAAA",
            "Name": b"good-bytes-name",
            "Level": "stripe",
            "Status": "Online",
            # A members value that is not a list must yield no members, not raise.
            "AppleRAIDMembers": "not-a-list",
        }
        sets_payload = {"AppleRAIDSets": ["torn-string-row", 42, good]}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                raid_svc, "_plist",
                self._plist_for(sets_payload, {"AllDisksAndPartitions": []},
                                {"AllDisksAndPartitions": []}, {})))
            raid_svc.invalidate()
            resp = _client().get("/api/raid")
            raid_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["count"], 1)


class SnapshotsOverviewLeftoverTests(unittest.TestCase):
    """GET /api/snapshots must render hostile snapshot / TM plists, not 500."""

    def test_surrogate_name_overcap_xid_and_inf_tm_percent_render(self):
        snap_plist = {
            "Snapshots": [
                {
                    "SnapshotName": "com.apple.TimeMachine.2026-08-03-160000.local\ud800",
                    "SnapshotUUID": "uu\ud800id",
                    "SnapshotXID": _HUGE_INT,
                    "Purgeable": True,
                },
            ]
        }
        tm_status = {
            "Running": True,
            "BackupPhase": "Copy\ud800ing",
            # 1e308 is finite; the * 100 scale overflows to inf downstream.
            "Progress": {"Percent": 1e308},
        }
        tm_dest = {
            "Destinations": [
                {
                    "ID": "d\ud800",
                    "Name": "NAS",
                    # A plist-hex MountPoint arrives already-int, over the cap.
                    "MountPoint": _HUGE_INT,
                    "URL": "smb://x",
                    "LastDestination": True,
                },
            ]
        }

        def fake_plist(argv, *, timeout=15):
            joined = " ".join(str(a) for a in argv)
            if "listSnapshots" in joined:
                return snap_plist
            if "destinationinfo" in joined:
                return tm_dest
            if "status" in joined:
                return tm_status
            return None

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                snapshots_svc, "_plist", fake_plist))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "snapshot_mounts", lambda: ["/"]))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "_tm_latest_backup",
                lambda: "2026-08-03-160000"))
            snapshots_svc.invalidate()
            resp = _client().get("/api/snapshots")
            snapshots_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertNotIn("\ud800", resp.text)
        # The finite-but-overflowing percent lands as null, not inf.
        self.assertIsNone(body["time_machine"]["percent"])

    def test_empty_and_torn_plists_render_the_baseline(self):
        # The "no Time Machine, no snapshots" baseline (every _plist answers
        # None) and a torn plist whose ``Snapshots`` is not a list must both
        # render the empty page, never 500.
        def fake_plist(argv, *, timeout=15):
            joined = " ".join(str(a) for a in argv)
            if "listSnapshots" in joined:
                return {"Snapshots": "not-a-list"}
            return None

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                snapshots_svc, "_plist", fake_plist))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "snapshot_mounts", lambda: ["/"]))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "_tm_latest_backup", lambda: ""))
            snapshots_svc.invalidate()
            resp = _client().get("/api/snapshots")
            snapshots_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["total"], 0)
        self.assertIs(body["time_machine"]["configured"], False)


class SnapshotMutationMountGuardTests(unittest.TestCase):
    """POST /api/snapshots/{delete,thin}: the mount guard stays immune.

    ``_known_mount`` wraps ``snapshot_mounts()`` in try/except so a listing
    that raises outright (a seam replacement, a leftover that slips its own
    guards) degrades to the pinned ``{"/"}`` set rather than 500ing the
    mutation — an unknown mount then earns the coded ``snapshot.bad_mount``
    400, never a bare 500 out of the gate.
    """

    def _post(self, url, payload):
        def boom():
            raise RuntimeError("diskutil seam replaced")

        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                nas_storage.snapshots_svc, "snapshot_mounts", boom))
            return _client().post(url, json=payload)

    def test_delete_unknown_mount_is_the_coded_400(self):
        resp = self._post(
            "/api/snapshots/delete",
            {"mount": "/Volumes/Gone", "confirm": True})
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "snapshot.bad_mount")

    def test_thin_unknown_mount_is_the_coded_400(self):
        resp = self._post(
            "/api/snapshots/thin", {"mount": "/Volumes/Gone", "urgency": 1})
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "snapshot.bad_mount")


class SmartOverviewLeftoverTests(unittest.TestCase):
    """GET /api/smart must render hostile smartctl output / history, not 500."""

    def test_overcap_selftest_columns_and_history_render(self):
        # ``sh`` decodes every stream with ``errors="replace"``, so a
        # smartctl leftover reaches _selftest_log surrogate-free — the genuine
        # residual leftover is an over-cap digit run in the numeric columns
        # (index / power-on-hours), which ``(\\d+)`` captures but ``int()``
        # cannot render.  _parsed_int drops it to 0; the status text still
        # renders and the disk row survives.
        selftest_out = (
            "SMART Self-test log\n"
            "# " + ("9" * 5000) + "  Short offline       Completed without error"
            "       00%      " + ("9" * 5000) + "         -\n"
        )
        caps_out = "Short self-test routine\nrecommended polling time:  (   2) minutes.\n"

        def fake_selftest_raw(device):
            return (0, selftest_out, "")

        def fake_caps_raw(device):
            return (0, caps_out, "")

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: ["/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "device_type", lambda d: ()))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_selftest_raw", fake_selftest_raw))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_caps_raw", fake_caps_raw))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "passwordless_available", lambda: True))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_load_history",
                lambda: [{"ts": _HUGE_INT, "device": "/dev/disk0\ud800",
                          "ok": True, "wear": float("inf")}]))
            smart_test_svc.invalidate()
            resp = _client().get("/api/smart")
            smart_test_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertNotIn("\ud800", resp.text)

    def test_history_route_renders_overcap_and_surrogate_rows(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_load_history",
                lambda: [
                    {"ts": _HUGE_INT, "device": "d\ud800", "ok": True},
                    {"ts": 123, "wear": float("nan"), "device": "d2"},
                ]))
            resp = _client().get("/api/smart/history?limit=100")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)


class NfsOverviewLeftoverTests(unittest.TestCase):
    """GET /api/nfs must render a hostile exports table, not 500."""

    def test_surrogate_export_line_renders(self):
        # read_exports parses each line through _parse_line, which _as_text's
        # every field; a surrogate in the on-disk exports body must not 500.
        exports_body = '/Volumes/Media\ud800 -alldirs -ro 10.0.0.0/24\n'
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                nfs_svc, "read_text_capped", lambda *a, **k: exports_body))
            stack.enter_context(mock.patch.object(
                nfs_svc, "_exports_exists", lambda: True))
            stack.enter_context(mock.patch.object(
                nfs_svc, "_nfsd_status",
                lambda: {"enabled": False, "running": False, "detail": ""}))
            stack.enter_context(mock.patch.object(
                nfs_svc, "check_exports", lambda: {"ok": True, "detail": ""}))
            nfs_svc.invalidate()
            resp = _client().get("/api/nfs")
            nfs_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)


class UsageOverviewLeftoverTests(unittest.TestCase):
    """GET /api/storage/usage must render hostile roots / spotlight, not 500."""

    def test_surrogate_and_overcap_root_fields_render(self):
        # scan_roots pulls default_roots(); a root row with a surrogate name
        # and an already-int over-cap id must render, not 500.
        def fake_default_roots():
            return [
                {"id": _HUGE_INT, "name": "Serv\ud800ices", "path": "/tmp"},
            ]

        def fake_spotlight_query(volume):
            return 0, "Indexing enabled for volume /"

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                usage_svc.files_svc, "default_roots", fake_default_roots))
            stack.enter_context(mock.patch.object(
                usage_svc.files_svc, "is_protected", lambda p: False))
            stack.enter_context(mock.patch.object(
                usage_svc, "_spotlight_query", fake_spotlight_query))
            resp = _client().get("/api/storage/usage")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
