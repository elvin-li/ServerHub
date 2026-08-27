"""Fifth leftover-500s sweep of the Storage routes, over the real mounted app.

The hunted classes were re-reproduced against ``create_app()`` with
``raise_server_exceptions=False``.  Four live leaks survived the
storage/storage2/storage3/storage4 batteries, all of the
passes-``isinstance``-refuses-the-protocol family those pins stopped short
of (pool5's get-bomb and the storage4/pool4 iteration bomb):

* ``storage_svc.storage_overview`` guarded non-dict rows and the render
  (``_jsonable``), but the ``_volume_row`` shaping loop still let a dict
  *subclass* whose ``.get`` raises pass the isinstance gate and raise —
  a bare 500 on GET /api/storage?light=true, and on the full page the
  router's fallback wiped the whole volume table to
  ``{"volumes": [], "disks": [], "error": …}``.  The hostile row now
  drops alone (volume and SMART rows both); its siblings keep rendering.

* ``disk_manage_svc.list_managed_volumes`` 500'd GET /api/storage/manage
  on an iteration-bomb ``AllDisksAndPartitions`` / ``APFSPhysicalStores``
  (a list subclass whose ``__iter__`` raises passes the isinstance gate),
  on a get-bomb node at either tree level (one hostile node cost the whole
  listing, healthy siblings included), and on a raising probe read
  (``fan_out`` re-raises on iteration).  Materialized under guard,
  per-node walk guards, guarded probes.

* GET /api/storage/disks and GET /api/storage/manage answered bare 500s
  when the listing call itself raised, while GET /api/storage already
  degraded the very same sections to ``power_error`` / ``managed.error``.
  The section routes now mirror the full page's fallback (coded
  HTTPExceptions still pass through).

* ``disk_power_svc.sleep_disk`` built ``{d["id"]: d}`` from the cached
  power listing and read ``d["system"]`` / ``d["device"]`` bare: a leftover
  non-dict row, a row without ``id``/``device``, an unhashable id, or a
  get-bomb row KeyError/TypeError'd — a bare 500 on
  POST /api/storage/disks/{id}/power where every junk request value already
  earns its coded refusal.  Unreadable rows now fail closed
  (``disk_power.protected``) and shapeless rows are skipped.

The rest of the battery pins the HTTP layers the probe found already
immune: >4300-digit integer literals in request bodies (``json.loads``
raises ValueError, NOT JSONDecodeError — FastAPI's body-parse guard answers
the coded 400), lone-surrogate JSON escapes in body keys AND values, torn
plist bytes through the ``run_bytes`` seam, a hostile df table (over-cap
block count and a surrogate mount), and the confirmed-vanished-diskutil
503 on the destructive path.
"""
from __future__ import annotations

import json
import plistlib
import unittest
from contextlib import ExitStack
from unittest import mock

from hub import disk_manage_svc, disk_power_svc, disk_snapshot, storage_svc
from hub.routers import storage as storage_router

#: Parsed from real plist bytes: plistlib's ``<integer>`` handler runs
#: ``int(x, 16)`` for the ``0x`` form, which CPython's 4300-digit str->int
#: parse cap does not bound, so the leftover arrives *already-int* and only
#: fails at render time (``str()`` / ``json.dumps``).
_HUGE_INT = plistlib.loads(
    b'<?xml version="1.0"?><plist version="1.0"><dict>'
    b"<key>v</key><integer>0x" + b"F" * 4400 + b"</integer>"
    b"</dict></plist>"
)["v"]

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


class _GetBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises the moment ``.get`` is called."""

    def get(self, *args, **kwargs):
        raise ValueError("get bomb")


class _IterBombList(list):
    """Passes ``isinstance(x, list)``; raises the moment it is iterated."""

    def __iter__(self):
        raise ValueError("iteration bomb")


#: A complete, well-formed volume row: the point of the survival pins is
#: that *this* row keeps rendering next to the hostile ones.
_GOOD_VOLUME = {
    "filesystem": "/dev/disk4s1", "device": "/dev/disk4s1",
    "disk_id": "disk4", "mount": "/Volumes/Data", "kind": "external",
    "total_gb": 100.0, "used_gb": 40.0, "avail_gb": 60.0, "pct": 40,
}


def _fake_plist(tree):
    """A ``disk_manage_svc._plist`` whose device tree is *tree*.

    ``diskutil info -plist <node>`` answers an empty dict, matching what a
    timed-out per-node read degrades to on the real path.
    """
    def _plist(cmd, timeout=30):
        if "list" in cmd:
            return tree
        return {}
    return _plist


class OverviewGetBombRowTests(unittest.TestCase):
    """The pool5 get-bomb class inside the volume/SMART shaping loops —
    these fail on the pre-fix tree."""

    def _light(self, *, volumes, disks):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "list_volumes", return_value=volumes))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", return_value=disks))
            return _client().get("/api/storage?light=true")

    def test_getbomb_volume_row_drops_alone_on_light(self):
        resp = self._light(
            volumes=[_GetBombDict(_GOOD_VOLUME), dict(_GOOD_VOLUME)],
            disks=[],
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # The original leak was a bare 500; the first fix dropped the bombed
        # row alone.  storage9 routed _volume_row's reads through the unbound
        # ``_mapping_get`` (the ups_svc rule), so a subclass that only
        # poisoned its ``.get`` method now keeps its sane C-level data — the
        # stronger degrade: both rows render, nothing raises.
        self.assertEqual(len(body["volumes"]), 2)
        self.assertEqual(
            [v["mount"] for v in body["volumes"]],
            ["/Volumes/Data", "/Volumes/Data"],
        )

    def test_getbomb_smart_row_stays_renderable_on_light(self):
        """The disk loop reads rows through ``_jsonable`` (items(), never
        ``.get``), so a get-bomb SMART row is *readable* and must keep
        rendering next to its sibling — pinned so the new per-row guard
        never turns a salvageable row into a dropped one."""
        resp = self._light(volumes=[], disks=[
            _GetBombDict({"device": "/dev/disk9"}),
            {"device": "/dev/disk0", "id": "disk0"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(
            [d["device"] for d in body["disks"]],
            ["/dev/disk9", "/dev/disk0"],
        )

    def test_getbomb_row_no_longer_wipes_the_full_page(self):
        """Pre-fix the raise fell into the router's overview fallback and
        the whole storage page answered
        ``{"volumes": [], "disks": [], "error": "get bomb"}``."""
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "list_volumes",
                return_value=[_GetBombDict(_GOOD_VOLUME), dict(_GOOD_VOLUME)]))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", return_value=[]))
            stack.enter_context(mock.patch.object(
                storage_router.disk_power_svc, "list_power_disks",
                return_value=[]))
            stack.enter_context(mock.patch.object(
                storage_router.disk_manage_svc, "overview",
                return_value={"volumes": [], "count": 0}))
            resp = _client().get("/api/storage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertNotIn("error", body)
        self.assertEqual(body["volumes"][0]["mount"], "/Volumes/Data")


class ManageListingHostileTreeTests(unittest.TestCase):
    """Hostile ``diskutil list -plist`` trees through the real walk —
    these fail (bare 500) on the pre-fix tree."""

    def setUp(self):
        disk_manage_svc.invalidate_disk_info()
        self.addCleanup(disk_manage_svc.invalidate_disk_info)

    def test_iterbomb_tree_degrades_to_the_empty_listing(self):
        tree = {"AllDisksAndPartitions": _IterBombList([{}])}
        with mock.patch.object(disk_manage_svc, "_plist", _fake_plist(tree)):
            resp = _client().get("/api/storage/manage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["volumes"], [])
        self.assertEqual(body["count"], 0)

    def test_getbomb_top_node_drops_its_subtree_not_the_listing(self):
        tree = {"AllDisksAndPartitions": [
            _GetBombDict({"DeviceIdentifier": "disk9"}),
            {"DeviceIdentifier": "disk4",
             "Partitions": [{"DeviceIdentifier": "disk4s1", "Size": 1000}]},
        ]}
        with mock.patch.object(disk_manage_svc, "_plist", _fake_plist(tree)):
            resp = _client().get("/api/storage/manage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        ids = {v["id"] for v in body["volumes"]}
        self.assertIn("disk4s1", ids)
        self.assertNotIn("disk9", ids)

    def test_getbomb_child_keeps_the_parent_and_its_siblings(self):
        tree = {"AllDisksAndPartitions": [
            {"DeviceIdentifier": "disk4", "Partitions": [
                _GetBombDict({"DeviceIdentifier": "disk4s1"}),
                {"DeviceIdentifier": "disk4s2", "Size": 2000},
            ]},
        ]}
        with mock.patch.object(disk_manage_svc, "_plist", _fake_plist(tree)):
            resp = _client().get("/api/storage/manage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        ids = {v["id"] for v in body["volumes"]}
        # The healthy sibling leaf and the whole-disk summary both render.
        self.assertIn("disk4s2", ids)
        self.assertIn("disk4", ids)
        self.assertNotIn("disk4s1", ids)

    def test_iterbomb_apfs_stores_keeps_the_listing(self):
        tree = {"AllDisksAndPartitions": [{"DeviceIdentifier": "disk4"}]}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_plist", _fake_plist(tree)))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "root_info",
                return_value={"ParentWholeDisk": "disk0",
                              "APFSPhysicalStores": _IterBombList(
                                  [{"APFSPhysicalStore": "disk0"}])}))
            resp = _client().get("/api/storage/manage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual([v["id"] for v in body["volumes"]], ["disk4"])


class SectionRouteDegradeTests(unittest.TestCase):
    """A listing call that raises outright must degrade the section route
    the way the full page already degrades the same section — pre-fix both
    answered a bare 500."""

    def test_disks_route_raising_listing_degrades_like_the_page(self):
        with mock.patch.object(
            storage_router.disk_power_svc, "list_power_disks",
            side_effect=OSError(5, "eio"),
        ):
            resp = _client().get("/api/storage/disks")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["disks"], [])
        self.assertIn("eio", body["error"])

    def test_disks_route_raising_shared_read_degrades_too(self):
        """The realistic seam: the shared physical-disk read raising out of
        the service, not a patched-out listing."""
        disk_power_svc.invalidate_power_disks()
        self.addCleanup(disk_power_svc.invalidate_power_disks)
        with mock.patch.object(
            disk_power_svc, "physical_whole_disks",
            side_effect=OSError(5, "eio"),
        ):
            resp = _client().get("/api/storage/disks")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["disks"], [])

    def test_manage_route_raising_listing_degrades_like_the_page(self):
        # RecursionError is not ValueError; it must still be contained.
        with mock.patch.object(
            storage_router.disk_manage_svc, "overview",
            side_effect=RecursionError("deep"),
        ):
            resp = _client().get("/api/storage/manage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["volumes"], [])
        self.assertEqual(body["count"], 0)

    def test_manage_route_coded_errors_still_pass_through(self):
        """The degrade must not swallow a coded refusal into a 200 body."""
        from hub.errors import api_error

        with mock.patch.object(
            storage_router.disk_manage_svc, "overview",
            side_effect=api_error("disk.system_protected"),
        ):
            resp = _client().get("/api/storage/manage")
        self.assertEqual(resp.status_code, 403, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "disk.system_protected")


class PowerActionRowShapeTests(unittest.TestCase):
    """Malformed cached listing rows behind POST /api/storage/disks/{id}/power
    — every one of these was a bare 500 on the pre-fix tree."""

    def _sleep(self, rows, *, diskutil_on_disk=True):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_power_svc, "list_power_disks", return_value=rows))
            stack.enter_context(mock.patch.object(
                disk_power_svc, "_diskutil_on_disk",
                return_value=diskutil_on_disk))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: {}))
            return _client().post(
                "/api/storage/disks/disk4/power", json={"action": "sleep"})

    def test_missing_id_row_is_the_coded_not_found(self):
        resp = self._sleep([{"system": False, "can_sleep": True}])
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "disk_power.not_found")

    def test_non_dict_and_unhashable_id_rows_are_skipped(self):
        resp = self._sleep(["disk4", {"id": ["disk4"]}, {"id": "disk9"}])
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "disk_power.not_found")

    def test_getbomb_row_fails_closed_as_protected(self):
        """A row whose eligibility cannot be read must never be slept."""
        resp = self._sleep([_GetBombDict({"id": "disk4"})])
        self.assertEqual(resp.status_code, 403, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "disk_power.protected")

    def test_missing_eligibility_fields_fail_closed_as_protected(self):
        resp = self._sleep([{"id": "disk4"}])
        self.assertEqual(resp.status_code, 403, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "disk_power.protected")

    def test_missing_device_falls_back_to_the_validated_id(self):
        calls = []

        def fake_sh(args, timeout=0, **kwargs):
            calls.append(list(args))
            return 0, "ok", ""

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_power_svc, "list_power_disks",
                return_value=[{"id": "disk4", "system": False,
                               "can_sleep": True}]))
            stack.enter_context(mock.patch.object(
                disk_power_svc, "sh", fake_sh))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: {}))
            resp = _client().post(
                "/api/storage/disks/disk4/power", json={"action": "sleep"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["disk"], "disk4")
        # argv got the DISK_RE-validated fallback node, not a KeyError.
        self.assertIn("/dev/disk4", calls[0])


class StorageHttpStaysImmunePins(unittest.TestCase):
    """Layers the storage5 probe found already immune, pinned so a
    regression in any of them cannot ship silently."""

    def test_huge_int_literal_bodies_are_the_coded_400_not_500(self):
        """A >4300-digit integer literal makes ``json.loads`` raise
        ValueError (NOT JSONDecodeError) for the whole document; FastAPI's
        body-parse guard answers the coded 400."""
        for path, raw in (
            ("/api/storage/disks/disk4/power",
             b'{"action": "sleep", "extra": ' + b"9" * 5000 + b"}"),
            ("/api/storage/manage/disk4s1",
             b'{"action": "mount", "extra": ' + b"9" * 5000 + b"}"),
            ("/api/storage/pool/save",
             b'{"mounts": ["/x"], "min_free_gb": ' + b"9" * 5000 + b"}"),
        ):
            resp = _client().post(
                path, content=raw,
                headers={"content-type": "application/json"})
            self.assertEqual(resp.status_code, 400, f"{path}: {resp.text[:200]}")
            self.assertIn("error parsing the body", resp.text)
            # The body must already be valid UTF-8 — decode strictly.
            json.loads(resp.content.decode("utf-8"))

    def test_surrogate_escapes_in_body_keys_and_values_stay_coded(self):
        """``json.loads`` happily materialises lone-surrogate escapes in
        keys AND values; the refusal must stay coded with a UTF-8 body."""
        raw = '{"action": "\\ud800", "\\ud800key": 1}'.encode("ascii")
        resp = _client().post(
            "/api/storage/disks/disk4/power", content=raw,
            headers={"content-type": "application/json"})
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        body = json.loads(resp.content.decode("utf-8"))
        self.assertEqual(body["detail"]["code"], "disk_power.unknown_action")
        self.assertNotIn("\ud800", resp.text)

    def test_surrogate_path_params_stay_coded_with_utf8_bodies(self):
        for path, code in (
            ("/api/storage/manage/%ed%a0%80", "disk.invalid_device"),
            ("/api/storage/disks/%ed%a0%80/power", "disk_power.invalid_id"),
        ):
            resp = _client().post(path, json={"action": "mount"})
            self.assertEqual(resp.status_code, 400, f"{path}: {resp.text[:200]}")
            body = json.loads(resp.content.decode("utf-8"))
            self.assertEqual(body["detail"]["code"], code)
            self.assertNotIn("\ud800", resp.text)

    def test_torn_plist_bytes_keep_the_manage_listing_200(self):
        """ExpatError inside plistlib stays inside ``_plist``."""
        disk_manage_svc.invalidate_disk_info()
        self.addCleanup(disk_manage_svc.invalidate_disk_info)
        with mock.patch.object(
            disk_manage_svc, "run_bytes",
            return_value=(0, b"<plist><dict><key>oops", b""),
        ):
            resp = _client().get("/api/storage/manage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["volumes"], [])

    def test_hostile_df_table_keeps_the_overview_200(self):
        """An over-cap block count drops its row; a surrogate mount is
        scrubbed — neither reaches Starlette's UTF-8 encode raw."""
        table = (
            "Filesystem 1024-blocks Used Avail Capacity Mounted on\n"
            "/dev/disk6s1 " + "9" * 4400 + " 1 1 1% /Volumes/Big\n"
            "/dev/disk7s1 1048576000 104857600 943718400 10% /Volumes/S\ud800urr\n"
        )
        disk_snapshot._df_table.invalidate()
        self.addCleanup(disk_snapshot._df_table.invalidate)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_snapshot, "sh", return_value=(0, table, "")))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", return_value=[]))
            resp = _client().get("/api/storage?light=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        mounts = [v["mount"] for v in resp.json()["volumes"]]
        self.assertIn("/Volumes/S?urr", mounts)
        self.assertNotIn("/Volumes/Big", mounts)
        self.assertNotIn("\ud800", resp.text)

    def test_erase_disk_vanished_diskutil_is_the_coded_503(self):
        """The destructive path keeps the confirmed-vanished contract: the
        503 fires only after the fresh disk probe says the binary is gone."""
        tree = {"AllDisksAndPartitions": []}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_plist", _fake_plist(tree)))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "sh",
                return_value=(127, "", "command not found")))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_on_disk", return_value=False))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: {}))
            resp = _client().post(
                "/api/storage/manage/disk4",
                json={"action": "eraseDisk", "confirm": True, "fs": "APFS"})
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "disk.diskutil_missing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
