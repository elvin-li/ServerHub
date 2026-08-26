"""Seventh leftover-500s sweep of the Storage routes, over the real mounted app.

The hunted classes were re-reproduced against ``create_app()`` with
``raise_server_exceptions=False``.  storage6 upgraded the ``_jsonable``
scrubs to unbound base coercions and sealed the truthiness bombs in the
manage/power mutations; this hunt threw the remaining *self-``__str__``*
subclass shape at the same surfaces — a str subclass whose ``__str__``
returns *self* rides through every ``str()`` "base copy" laundering with
its bound-method bombs still live — and found these leaks:

* every text scrub in the family (``storage_svc._as_text``,
  ``disk_manage_svc._text``, ``disk_power_svc._text`` / ``_req_text``,
  ``routers/storage._as_text``, ``disk_snapshot._as_text`` /
  ``_disk_token``) finished with a *bound* ``value.encode(...)``: a
  self-``__str__`` subclass ``encode`` bomb raised out of the scrub —
  a bare 500 on POST /api/storage/manage/{id} (the ``sh`` seam into the
  run log and the confirmed-erase ``VolumeName`` read), on
  POST /api/storage/disks/{id}/power (sleep, eject and wake legs), and on
  GET /api/storage/disks when the bomb rode ``str(exc)`` into the route's
  own except handler.  On GET /api/storage?light the same raise nulled the
  whole ``volumes`` table for one bad field.  All now finish through the
  unbound ``str.encode`` base call.

* ``disk_manage_svc._req_text`` returned a str *subclass* unlaundered: an
  in-process erase with a str-subclass ``__bool__``-bomb name raised out
  of the ``_req_text(name) or vol_name`` fallback.  ``_ident`` did the
  same, carrying ``__eq__``/``__hash__`` bombs into the listing's set
  membership.  Both now return base copies via unbound ``str.__str__``.

* ``storage_svc._jsonable`` iterated sequences with the *bound* protocol:
  a list-subclass ``__iter__`` bomb nulled the whole field while its real
  elements sat readable in the C-level storage.  Sequence rank now uses
  the unbound ``base.__iter__`` (the ``dict.items`` rule), so the content
  survives.  Its duck-typed ``isoformat`` probe used a bare ``getattr``:
  a leftover whose ``isoformat`` is a *raising property* blew the probe
  and nulled the containing table — a bare 500 on GET /api/storage?light.

* the manage listing walk read the cached ``diskutil info`` raw: a
  dict-subclass ``.get`` bomb dropped the node (with one disk, the whole
  listing) on the first field read, and the bare ``a or b`` chains
  (``Size or TotalSize``, ``Content or Content``, ``MountPoint``,
  ``MediaName or IORegistryEntryName``, ``VolumeName``) reflected into a
  leftover value's own ``__bool__`` with the same node-wide cost.  The
  walk now launders through ``_plain_info`` and scrubs each candidate
  before ``or``, so a bomb costs at most its own field.

No ``json.loads`` seam exists on these routes (the plists go through
``plistlib`` behind ``_plist``'s own guard), so the huge-number
ValueError class from the sibling sweeps does not apply here.
"""
from __future__ import annotations

import json
import unittest
from contextlib import ExitStack
from unittest import mock

from hub import disk_manage_svc, disk_power_svc, disk_snapshot, storage_svc
from hub.routers import storage as storage_router

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


class _SelfStrEncodeBomb(str):
    """``str()`` laundering is a no-op (``__str__`` returns self), so the
    bound ``encode`` bomb survives every coercion that trusts it."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("self-str encode bomb")


class _BoolBombStr(str):
    """Passes every str gate; raises on the ``or``-chain truthiness probe."""

    def __bool__(self):
        raise RuntimeError("str bool bomb")


class _EqBombStr(str):
    """Passes every str gate; raises on set membership / de-dupe compares."""

    def __eq__(self, other):
        raise RuntimeError("str eq bomb")

    __hash__ = str.__hash__


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")


class _IterBombTuple(tuple):
    def __iter__(self):
        raise RuntimeError("tuple iter bomb")


class _IsoBomb:
    @property
    def isoformat(self):
        raise RuntimeError("isoformat property bomb")


class _GetBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises on the ``.get`` field reads."""

    def get(self, *args, **kwargs):
        raise RuntimeError("dict get bomb")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _BombStrException(Exception):
    def __str__(self):
        return _SelfStrEncodeBomb("boom")


_GOOD_VOLUME = {
    "filesystem": "/dev/disk4s1", "device": "/dev/disk4s1",
    "disk_id": "disk4", "mount": "/Volumes/Data", "kind": "external",
    "total_gb": 100.0, "used_gb": 40.0, "avail_gb": 60.0, "pct": 40,
}


class ManageMutationSelfStrEncodeBombTests(unittest.TestCase):
    """Bound-``encode`` bombs behind POST /api/storage/manage/{id} — every
    one of these was a bare 500 on the pre-fix tree."""

    def _action(self, node_info, body, sh_result=(0, "ok", "")):
        disk_manage_svc.invalidate_disk_info()
        self.addCleanup(disk_manage_svc.invalidate_disk_info)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_info", lambda n: node_info))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "sh", lambda *a, **k: sh_result))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "list_managed_volumes", lambda: []))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "root_devices", lambda: frozenset()))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: {}))
            return _client().post("/api/storage/manage/disk4s1", json=body)

    def test_sh_seam_encode_bomb_keeps_the_mount_200(self):
        resp = self._action({}, {"action": "mount"},
                            sh_result=(0, _SelfStrEncodeBomb("ok"), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        # The unbound base encode reads the real text, so it survives.
        self.assertEqual(body["message"], "ok")

    def test_sh_seam_encode_bomb_on_stderr_too(self):
        resp = self._action({}, {"action": "unmount"},
                            sh_result=(1, "", _SelfStrEncodeBomb("busy")))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], False)
        self.assertEqual(body["message"], "busy")

    def test_volume_name_encode_bomb_confirmed_erase_proceeds(self):
        resp = self._action(
            {"VolumeName": _SelfStrEncodeBomb("V")},
            {"action": "eraseVolume", "confirm": True, "confirm_name": "V"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["name"], "V")

    def test_in_process_bool_bomb_name_erases_with_its_real_text(self):
        """The ``_req_text(name) or vol_name`` fallback reflected into a
        str-subclass leftover's own ``__bool__`` for in-process callers."""
        disk_manage_svc.invalidate_disk_info()
        self.addCleanup(disk_manage_svc.invalidate_disk_info)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                lambda n: {"VolumeName": "V"}))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "sh", lambda *a, **k: (0, "ok", "")))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "list_managed_volumes", lambda: []))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "root_devices", lambda: frozenset()))
            out = disk_manage_svc.disk_action(
                "disk4s1", "eraseVolume", name=_BoolBombStr("N"),
                confirm=True, confirm_name="V")
        self.assertIs(out["ok"], True)
        self.assertEqual(out["name"], "N")


class PowerActionSelfStrEncodeBombTests(unittest.TestCase):
    """The same bomb riding the ``sh`` seam into the sleep/eject/wake log
    lines — bare 500s on POST /api/storage/disks/{id}/power pre-fix."""

    _ROW = {"id": "disk4", "system": False, "can_sleep": True,
            "device": "/dev/disk4"}

    def _post(self, body, sh_result):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_power_svc, "list_power_disks",
                return_value=[dict(self._ROW)]))
            stack.enter_context(mock.patch.object(
                disk_power_svc, "sh", lambda *a, **k: sh_result))
            stack.enter_context(mock.patch.object(
                disk_power_svc, "_diskutil_on_disk", return_value=True))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: {}))
            return _client().post(
                "/api/storage/disks/disk4/power", json=body)

    def test_sleep_leg_stays_200(self):
        resp = self._post({"action": "sleep"},
                          (0, _SelfStrEncodeBomb("ok"), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)

    def test_eject_leg_stays_200(self):
        resp = self._post({"action": "eject"},
                          (0, _SelfStrEncodeBomb("ok"), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["action"], "eject")

    def test_wake_leg_stays_200(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_power_svc, "sh",
                lambda *a, **k: (0, _SelfStrEncodeBomb("ok"), "")))
            stack.enter_context(mock.patch.object(
                disk_power_svc, "_dev_exists", lambda n: True))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: {}))
            resp = _client().post(
                "/api/storage/disks/disk4/power", json={"action": "wake"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["message"], "ok")


class OverviewJsonableLeftoverTests(unittest.TestCase):
    """Nested ``_jsonable`` leaks on GET /api/storage?light: the encode
    bomb and the isoformat property bomb nulled the whole volumes table,
    and the sequence iterbomb nulled a field whose content was readable."""

    def _light(self, volumes):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "list_volumes", return_value=volumes))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", return_value=[]))
            return _client().get("/api/storage?light=true")

    def test_encode_bomb_note_keeps_the_table_and_its_text(self):
        resp = self._light([
            {**_GOOD_VOLUME, "note": _SelfStrEncodeBomb("x")},
            dict(_GOOD_VOLUME),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(len(body["volumes"]), 2)
        self.assertEqual(body["volumes"][0]["note"], "x")

    def test_encode_bomb_key_keeps_the_table(self):
        resp = self._light([
            {**_GOOD_VOLUME, _SelfStrEncodeBomb("k"): 1},
            dict(_GOOD_VOLUME),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(len(body["volumes"]), 2)
        self.assertEqual(body["volumes"][0]["k"], 1)

    def test_iterbomb_sequence_note_salvages_its_elements(self):
        resp = self._light([
            {**_GOOD_VOLUME, "note": _IterBombList([1, "a"])},
            dict(_GOOD_VOLUME),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # Pre-fix the field nulled; the unbound base iteration reads the
        # real C-level storage, so the content survives the scrub.
        self.assertEqual(body["volumes"][0]["note"], [1, "a"])

    def test_isoformat_property_bomb_keeps_the_table(self):
        resp = self._light([
            {**_GOOD_VOLUME, "note": _IsoBomb()}, dict(_GOOD_VOLUME),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(len(body["volumes"]), 2)

    def test_jsonable_units(self):
        self.assertEqual(storage_svc._jsonable(_SelfStrEncodeBomb("s")), "s")
        self.assertEqual(
            storage_svc._jsonable(_IterBombList([1, 2])), [1, 2])
        self.assertEqual(
            storage_svc._jsonable(_IterBombTuple((3,))), [3])
        # The property bomb never fires; the leftover reads as its text form.
        self.assertIsInstance(storage_svc._jsonable(_IsoBomb()), str)
        self.assertEqual(storage_svc._as_text(_SelfStrEncodeBomb("t")), "t")


class ManageListingInfoBombTests(unittest.TestCase):
    """The listing walk read the cached ``diskutil info`` raw: a ``.get``
    bomb or a bare ``or``-chain ``__bool__`` bomb dropped the whole node
    (with a single disk, the whole listing)."""

    def setUp(self):
        disk_manage_svc.invalidate_disk_info()
        self.addCleanup(disk_manage_svc.invalidate_disk_info)

    def _manage(self, tree, node_info):
        def _plist(cmd, timeout=30):
            if "list" in cmd:
                return tree
            return node_info

        with mock.patch.object(disk_manage_svc, "_plist", _plist):
            return _client().get("/api/storage/manage")

    _TREE = {"AllDisksAndPartitions": [
        {"DeviceIdentifier": "disk4",
         "Partitions": [{"DeviceIdentifier": "disk4s1", "Size": 1000}]},
    ]}

    def test_get_bomb_info_keeps_both_nodes(self):
        resp = self._manage(self._TREE, _GetBombDict(MountPoint="/Volumes/X"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        ids = {v["id"] for v in body["volumes"]}
        # Pre-fix both nodes dropped (an empty listing); the laundered copy
        # reads the C-level storage, so the fields survive too.
        self.assertEqual(ids, {"disk4", "disk4s1"})
        rows = {v["id"]: v for v in body["volumes"]}
        self.assertEqual(rows["disk4s1"]["mount"], "/Volumes/X")

    def test_bool_bomb_tree_size_keeps_the_whole_disk_row(self):
        tree = {"AllDisksAndPartitions": [
            {"DeviceIdentifier": "disk4", "Size": _BoolBomb(),
             "Partitions": [{"DeviceIdentifier": "disk4s1", "Size": 1000}]},
        ]}
        resp = self._manage(tree, {"TotalSize": 500})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        rows = {v["id"]: v for v in body["volumes"]}
        self.assertIn("disk4", rows)
        # The bombed tree Size costs itself; the info fallback still reads.
        self.assertEqual(rows["disk4"]["size_bytes"], 500)

    def test_encode_bomb_media_name_keeps_the_node(self):
        resp = self._manage(
            self._TREE, {"MediaName": _SelfStrEncodeBomb("Ext HD")})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        rows = {v["id"]: v for v in body["volumes"]}
        self.assertIn("disk4", rows)
        self.assertEqual(rows["disk4"]["name"], "Ext HD")

    def test_eq_bomb_identifier_costs_its_node_only(self):
        """A str-subclass ``__eq__`` bomb identifier used to raise out of
        the post-walk de-dupe — now laundered to a base copy in _ident."""
        tree = {"AllDisksAndPartitions": [
            {"DeviceIdentifier": _EqBombStr("disk4"),
             "Partitions": [{"DeviceIdentifier": "disk4s1", "Size": 1000}]},
            {"DeviceIdentifier": "disk5", "Partitions": []},
        ]}
        resp = self._manage(tree, {})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        ids = {v["id"] for v in body["volumes"]}
        self.assertIn("disk5", ids)
        self.assertIn("disk4", ids)


class RouterErrorScrubTests(unittest.TestCase):
    """``str(exc)`` returning a str-subclass encode bomb used to raise
    *inside* the routes' own except handlers — bare 500s pre-fix."""

    def test_disks_route_degrades_with_the_real_error_text(self):
        with mock.patch.object(
            storage_router.disk_power_svc, "list_power_disks",
            side_effect=_BombStrException(),
        ):
            resp = _client().get("/api/storage/disks")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["disks"], [])
        self.assertEqual(body["error"], "boom")

    def test_manage_route_degrades_the_same_way(self):
        with mock.patch.object(
            storage_router.disk_manage_svc, "overview",
            side_effect=_BombStrException(),
        ):
            resp = _client().get("/api/storage/manage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["volumes"], [])
        self.assertEqual(body["error"], "boom")


class HelperUnitPins(unittest.TestCase):
    """The scrubs must launder to *exact* base types and never raise."""

    def test_text_scrubs_return_exact_str(self):
        for fn in (disk_manage_svc._text, disk_power_svc._text,
                   disk_power_svc._req_text, disk_manage_svc._req_text,
                   storage_svc._as_text, storage_router._as_text,
                   disk_snapshot._as_text, disk_snapshot._disk_token):
            with self.subTest(fn=fn.__module__ + "." + fn.__qualname__):
                out = fn(_SelfStrEncodeBomb("v"))
                self.assertEqual(out, "v")
                self.assertIs(type(out), str)

    def test_ident_launders_the_subclass(self):
        out = disk_manage_svc._ident(_EqBombStr("disk4"))
        self.assertEqual(out, "disk4")
        self.assertIs(type(out), str)

    def test_req_text_launders_the_bool_bomb(self):
        out = disk_manage_svc._req_text(_BoolBombStr("N"))
        self.assertEqual(out, "N")
        self.assertIs(type(out), str)
        self.assertTrue(out or "fallback" == "N")

    def test_surrogates_still_behave_per_scrub(self):
        # Display scrubs replace; the manage _req_text keeps them for the
        # strict validators downstream (the storage6 contract).
        self.assertEqual(storage_svc._as_text("a\ud800b"), "a?b")
        self.assertEqual(disk_manage_svc._req_text("a\ud800b"), "a\ud800b")
        _starlette(storage_svc._as_text("a\ud800b"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
