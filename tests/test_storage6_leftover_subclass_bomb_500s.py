"""Sixth leftover-500s sweep of the Storage routes, over the real mounted app.

The hunted classes were re-reproduced against ``create_app()`` with
``raise_server_exceptions=False``.  The storage3..5 batteries sealed the
get-bombs, iteration bombs and over-cap ints; this hunt threw the tools5 /
modules5 *nested unbound* subclass-bomb class (bound-method and dunder bombs
that pass every ``isinstance`` gate) at the same surfaces and found these
live leaks:

* ``disk_manage_svc.disk_action`` probed the cached ``diskutil info`` dict
  with bare truthiness (``if not info`` / ``if info``): a dict-subclass
  leftover whose ``__bool__``/``__len__`` raises 500'd every manage
  mutation.  The boot-volume guard's ``info.get("Internal") and
  info.get("SolidState")`` chain (and the ``APFSContainerReference`` read)
  blew the same way on ``__bool__``-bomb *values*, and the confirmed-erase
  path's ``VolumeName or MediaName`` fallback reflected into a leftover's
  own ``__bool__`` — all bare 500s on POST /api/storage/manage/{id} where
  the coded refusals are the contract.  ``_plain_info`` now copies through
  the C-level storage, the flags read through ``_truthy``, and a residual
  raise in the eligibility check fails closed as ``disk.system_protected``.

* ``disk_power_svc.sleep_disk`` guarded row *shape* but probed the resolved
  row with ``if not d:`` — a dict-subclass cached row whose ``__bool__``/
  ``__len__`` raises 500'd POST /api/storage/disks/{id}/power on both the
  sleep and eject legs.  Rows are now base-copied (``dict(row)``) so the
  override cannot fire, and the miss check is ``is None``.

* ``storage_svc._json_gb`` caught only the three usual conversion errors:
  an int-subclass ``__float__`` bomb rode a volume row's ``total_gb`` /
  ``used_gb`` / ``avail_gb`` through ``_volume_row``'s str() probe
  untouched and raised out of ``aggregate_capacity`` — a bare 500 on
  GET /api/storage?light=true (and the whole-page error wipe on the full
  route).

* ``storage_svc._jsonable`` ran *bound* calls on the values it scrubbed: an
  int-subclass ``__str__`` bomb (only ValueError was caught), a
  float-subclass ``__eq__`` bomb, a bytes-subclass ``decode`` bomb (in
  values and in dict *keys*) each raised out of the recursion into the
  sequence guard — which nulled the entire ``volumes`` table on
  GET /api/storage and the entire ``disks`` list on GET /api/storage/disks
  while only one nested field was unreadable.  Now upgraded to the
  modules5/nas_common unbound base coercions (``int.__index__``,
  ``float.__float__``, base ``decode``, unbound ``dict.items``), so the
  real content survives the scrub and a bomb costs at most its own field.

* the manage listing dropped a whole node (with a single disk, the whole
  listing) for one bombed *field*: ``_opt_bool``'s ``bool(value)``, the
  ``bool(info.get(...))`` flag reads, ``_text``'s NaN probe and final
  re-encode, and ``_size_bytes``'s ``raw or 0`` all raised on the
  ``__bool__``/``__eq__``/``encode`` bomb classes.  Each now costs its own
  field only.

Stays-immune pins ride along for the vectors this sweep re-tested and found
already dead: subclass ``decode``/``__str__`` bombs riding the ``sh`` seam
into the sleep/wake/manage log lines, an unhashable object as a cached row
id (the set/dict-membership class answers the coded 404), and an iterbomb
rows list behind the power action.
"""
from __future__ import annotations

import json
import unittest
from contextlib import ExitStack
from unittest import mock

from hub import disk_manage_svc, disk_power_svc, storage_svc
from hub.routers import storage as storage_router

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
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


class _BoolBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises on the truthiness probe."""

    def __bool__(self):
        raise RuntimeError("dict bool bomb")


class _LenBombDict(dict):
    """Passes ``isinstance(x, dict)``; ``len()`` (dict truthiness) raises."""

    def __len__(self):
        raise RuntimeError("dict len bomb")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _StrBombInt(int):
    def __str__(self):
        raise RuntimeError("int str bomb")

    __repr__ = __str__


class _FloatBombInt(int):
    def __float__(self):
        raise RuntimeError("int float bomb")


class _EqBombFloat(float):
    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    __hash__ = float.__hash__


class _DecodeBombBytes(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("bytes decode bomb")


class _DecodeBombBytearray(bytearray):
    def decode(self, *args, **kwargs):
        raise RuntimeError("bytearray decode bomb")


class _EncodeBombStr(str):
    def encode(self, *args, **kwargs):
        raise RuntimeError("str encode bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")


class _Unhashable:
    __hash__ = None  # type: ignore[assignment]


_GOOD_VOLUME = {
    "filesystem": "/dev/disk4s1", "device": "/dev/disk4s1",
    "disk_id": "disk4", "mount": "/Volumes/Data", "kind": "external",
    "total_gb": 100.0, "used_gb": 40.0, "avail_gb": 60.0, "pct": 40,
}


def _fake_plist(tree, node_info=None):
    """A ``disk_manage_svc._plist`` whose device tree is *tree* and whose
    per-node ``diskutil info`` answer is *node_info* (default: empty)."""
    def _plist(cmd, timeout=30):
        if "list" in cmd:
            return tree
        return node_info if node_info is not None else {}
    return _plist


class ManageActionTruthinessBombTests(unittest.TestCase):
    """Dict-subclass ``__bool__``/``__len__`` bombs in the cached
    ``diskutil info`` behind POST /api/storage/manage/{id} — every one of
    these was a bare 500 on the pre-fix tree."""

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

    def test_bool_bomb_info_mount_proceeds(self):
        resp = self._action(
            _BoolBombDict(MountPoint="/Volumes/X"), {"action": "mount"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["device"], "disk4s1")

    def test_len_bomb_info_mount_proceeds(self):
        resp = self._action(
            _LenBombDict(MountPoint="/Volumes/X"), {"action": "mount"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], True)

    def test_bool_bomb_internal_flag_keeps_the_coded_contract(self):
        """`info.get("Internal") and info.get("SolidState")` reflected the
        leftover's own ``__bool__`` out of the boot-volume guard."""
        resp = self._action(
            {"Internal": _BoolBomb(), "SolidState": True,
             "ParentWholeDisk": "disk0"},
            {"action": "mount"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], True)

    def test_bool_bomb_apfs_container_reference_too(self):
        resp = self._action(
            {"Internal": True, "SolidState": True, "ParentWholeDisk": "disk0",
             "FilesystemType": "msdos",
             "APFSContainerReference": _BoolBomb()},
            {"action": "mount"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], True)

    def test_bool_bomb_info_confirmed_erase_proceeds(self):
        """The destructive leg read ``VolumeName or MediaName`` bare."""
        resp = self._action(
            _BoolBombDict(VolumeName="V"),
            {"action": "eraseVolume", "confirm": True, "confirm_name": "V"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["name"], "V")

    def test_bool_bomb_volume_name_value_is_the_coded_mismatch(self):
        """A ``__bool__``-bomb VolumeName cannot be confirmed against: the
        refusal must be the coded mismatch, never a bare 500."""
        resp = self._action(
            {"VolumeName": _BoolBomb()},
            {"action": "eraseVolume", "confirm": True, "confirm_name": "V"})
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "disk.confirm_name_mismatch")

    def test_residual_eligibility_raise_fails_closed_as_protected(self):
        """A disk whose eligibility cannot be read must never be mutated:
        the fail-closed contract is the coded refusal, not a 500."""
        disk_manage_svc.invalidate_disk_info()
        self.addCleanup(disk_manage_svc.invalidate_disk_info)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                lambda n: {"MountPoint": "/Volumes/X"}))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_is_system_related",
                side_effect=RuntimeError("residual bomb")))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: {}))
            resp = _client().post(
                "/api/storage/manage/disk4s1", json={"action": "mount"})
        self.assertEqual(resp.status_code, 403, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "disk.system_protected")


class PowerActionRowBombTests(unittest.TestCase):
    """Dict-subclass truthiness bombs in the cached power listing behind
    POST /api/storage/disks/{id}/power — bare 500s pre-fix."""

    def _post(self, rows, body, sh_result=(0, "ok", "")):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_power_svc, "list_power_disks", return_value=rows))
            stack.enter_context(mock.patch.object(
                disk_power_svc, "sh", lambda *a, **k: sh_result))
            stack.enter_context(mock.patch.object(
                disk_power_svc, "_diskutil_on_disk", return_value=True))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: {}))
            return _client().post(
                "/api/storage/disks/disk4/power", json=body)

    _ROW = {"id": "disk4", "system": False, "can_sleep": True,
            "device": "/dev/disk4"}

    def test_bool_bomb_row_sleeps_through_the_base_copy(self):
        resp = self._post([_BoolBombDict(self._ROW)], {"action": "sleep"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["disk"], "disk4")

    def test_len_bomb_row_sleeps_too(self):
        resp = self._post([_LenBombDict(self._ROW)], {"action": "sleep"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], True)

    def test_bool_bomb_row_ejects_too(self):
        resp = self._post([_BoolBombDict(self._ROW)], {"action": "eject"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["action"], "eject")


class OverviewFloatBombCapacityTests(unittest.TestCase):
    """Int-subclass ``__float__`` bombs in the capacity fields raised out
    of ``aggregate_capacity`` — a bare 500 on GET /api/storage?light=true
    on the pre-fix tree."""

    def _light(self, volumes):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "list_volumes", return_value=volumes))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", return_value=[]))
            return _client().get("/api/storage?light=true")

    def test_float_bomb_capacity_fields_stay_http_200(self):
        for key in ("total_gb", "used_gb", "avail_gb"):
            with self.subTest(field=key):
                resp = self._light([
                    {**_GOOD_VOLUME, key: _FloatBombInt(50)},
                    dict(_GOOD_VOLUME),
                ])
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                body = resp.json()
                _starlette(body)
                # The base coercion sees the real number: content survives.
                self.assertEqual(body["volumes"][0][key], 50)
                self.assertEqual(body["volumes"][1]["mount"], "/Volumes/Data")

    def test_json_gb_swallows_the_float_bomb(self):
        self.assertEqual(storage_svc._json_gb(_FloatBombInt(50)), 50.0)
        self.assertEqual(storage_svc._json_gb(float("inf")), 0.0)
        self.assertEqual(storage_svc._json_int(_FloatBombInt(3)), 3)


class JsonableNestedBombWipeTests(unittest.TestCase):
    """Nested unbound-jsonable bombs used to null the *whole* volumes /
    disks table for one unreadable field — the sibling-wipe class."""

    def _light(self, *, volumes=None, disks=None):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "list_volumes", return_value=volumes or []))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", return_value=disks or []))
            return _client().get("/api/storage?light=true")

    def test_int_str_bomb_extra_key_keeps_the_table_and_its_number(self):
        resp = self._light(volumes=[
            {**_GOOD_VOLUME, "note": _StrBombInt(5)}, dict(_GOOD_VOLUME),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(len(body["volumes"]), 2)
        self.assertEqual(body["volumes"][0]["note"], 5)

    def test_overcap_int_wearing_the_bomb_subclass_still_drops(self):
        resp = self._light(volumes=[
            {**_GOOD_VOLUME, "note": _StrBombInt(_HUGE_INT)},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIsNone(body["volumes"][0]["note"])

    def test_bytes_decode_bomb_value_and_key_keep_the_table(self):
        resp = self._light(volumes=[
            {**_GOOD_VOLUME, "note": _DecodeBombBytes(b"x"),
             _DecodeBombBytes(b"k"): 1},
            dict(_GOOD_VOLUME),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(len(body["volumes"]), 2)
        # The base decode sees the real bytes: content survives the scrub.
        self.assertEqual(body["volumes"][0]["note"], "x")
        self.assertEqual(body["volumes"][0]["k"], 1)

    def test_float_eq_bomb_extra_key_keeps_the_table(self):
        resp = self._light(volumes=[
            {**_GOOD_VOLUME, "note": _EqBombFloat(1.5)}, dict(_GOOD_VOLUME),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(len(body["volumes"]), 2)
        self.assertEqual(body["volumes"][0]["note"], 1.5)

    def test_full_page_bomb_does_not_wipe_to_the_error_shape(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "list_volumes",
                return_value=[{**_GOOD_VOLUME, "note": _DecodeBombBytes(b"x")},
                              dict(_GOOD_VOLUME)]))
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
        self.assertEqual(len(body["volumes"]), 2)

    def test_disks_route_bombed_row_field_keeps_the_listing(self):
        with mock.patch.object(
            storage_router.disk_power_svc, "list_power_disks",
            return_value=[{"id": "disk4", "name": _DecodeBombBytes(b"n"),
                           "size_gb": _StrBombInt(3)},
                          {"id": "disk5", "name": "healthy"}],
        ):
            resp = _client().get("/api/storage/disks")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # Pre-fix the whole list nulled; now both rows render with the
        # bombed fields' real content salvaged.
        self.assertEqual(
            [d["id"] for d in body["disks"]], ["disk4", "disk5"])
        self.assertEqual(body["disks"][0]["name"], "n")
        self.assertEqual(body["disks"][0]["size_gb"], 3)

    def test_jsonable_unbound_contract_units(self):
        self.assertEqual(storage_svc._jsonable(_StrBombInt(7)), 7)
        self.assertIsNone(storage_svc._jsonable(_StrBombInt(_HUGE_INT)))
        self.assertEqual(storage_svc._jsonable(_EqBombFloat(2.5)), 2.5)
        self.assertEqual(storage_svc._jsonable(_DecodeBombBytes(b"ab")), "ab")
        self.assertEqual(
            storage_svc._jsonable(_DecodeBombBytearray(b"cd")), "cd")
        self.assertEqual(storage_svc._jsonable(_EncodeBombStr("ef")), "ef")


class ManageListingFieldBombTests(unittest.TestCase):
    """Field-level bombs in a node's ``diskutil info`` used to drop the
    whole node (with a single disk, the whole manage listing).  The field
    now costs itself only."""

    def setUp(self):
        disk_manage_svc.invalidate_disk_info()
        self.addCleanup(disk_manage_svc.invalidate_disk_info)

    _TREE = {"AllDisksAndPartitions": [
        {"DeviceIdentifier": "disk4",
         "Partitions": [{"DeviceIdentifier": "disk4s1", "Size": 1000}]},
    ]}

    def _manage(self, node_info):
        with mock.patch.object(
            disk_manage_svc, "_plist", _fake_plist(self._TREE, node_info),
        ):
            return _client().get("/api/storage/manage")

    def test_bool_bomb_writable_costs_its_field_only(self):
        resp = self._manage({"Writable": _BoolBomb(),
                             "MountPoint": "/Volumes/X"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        rows = {v["id"]: v for v in body["volumes"]}
        self.assertIn("disk4s1", rows)
        self.assertIsNone(rows["disk4s1"]["writable"])
        self.assertEqual(rows["disk4s1"]["mount"], "/Volumes/X")

    def test_bool_bomb_ejectable_costs_its_field_only(self):
        resp = self._manage({"Ejectable": _BoolBomb()})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        rows = {v["id"]: v for v in body["volumes"]}
        self.assertIn("disk4s1", rows)
        self.assertIs(rows["disk4s1"]["ejectable"], False)

    def test_encode_bomb_mount_point_keeps_the_node(self):
        resp = self._manage({"MountPoint": _EncodeBombStr("/Volumes/X")})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        rows = {v["id"]: v for v in body["volumes"]}
        self.assertIn("disk4s1", rows)
        # str() takes a base copy, so the real mount text survives.
        self.assertEqual(rows["disk4s1"]["mount"], "/Volumes/X")

    def test_eq_bomb_float_mount_point_keeps_the_node(self):
        resp = self._manage({"MountPoint": _EqBombFloat(1.5)})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        rows = {v["id"]: v for v in body["volumes"]}
        self.assertIn("disk4s1", rows)
        self.assertEqual(rows["disk4s1"]["mount"], "1.5")

    def test_bool_bomb_size_costs_its_field_only(self):
        resp = self._manage({"TotalSize": _BoolBomb()})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        rows = {v["id"]: v for v in body["volumes"]}
        self.assertIn("disk4", rows)
        # The whole-disk summary reads TotalSize through _size_bytes:
        # the ``raw or 0`` truthiness bomb reads as size unknown.
        self.assertEqual(rows["disk4"]["size_bytes"], 0)

    def test_helper_units(self):
        self.assertIsNone(disk_manage_svc._opt_bool(_BoolBomb()))
        self.assertIs(disk_manage_svc._truthy(_BoolBomb()), False)
        self.assertIs(disk_manage_svc._truthy("x"), True)
        self.assertEqual(disk_manage_svc._size_bytes(_BoolBomb()), 0)
        self.assertEqual(disk_manage_svc._text(_EncodeBombStr("v")), "v")
        self.assertEqual(disk_manage_svc._text(_EqBombFloat(1.5)), "1.5")
        self.assertEqual(disk_manage_svc._plain_info(
            _BoolBombDict(a=1)), {"a": 1})
        self.assertEqual(disk_manage_svc._plain_info("junk"), {})
        self.assertEqual(disk_power_svc._text(_EncodeBombStr("v")), "v")
        self.assertEqual(disk_power_svc._text(_EqBombFloat(1.5)), "1.5")


class StorageHttpStaysImmunePins(unittest.TestCase):
    """Vectors this sweep re-tested and found already dead — pinned."""

    def _power(self, rows, body, sh_result=(0, "ok", "")):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_power_svc, "list_power_disks", return_value=rows))
            stack.enter_context(mock.patch.object(
                disk_power_svc, "sh", lambda *a, **k: sh_result))
            stack.enter_context(mock.patch.object(
                disk_power_svc, "_diskutil_on_disk", return_value=True))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: {}))
            return _client().post(
                "/api/storage/disks/disk4/power", json=body)

    _ROW = {"id": "disk4", "system": False, "can_sleep": True,
            "device": "/dev/disk4"}

    def test_sh_seam_bombs_keep_the_sleep_leg_200(self):
        for out in (_DecodeBombBytes(b"ok"), _StrBombInt(3)):
            with self.subTest(out=type(out).__name__):
                resp = self._power([dict(self._ROW)], {"action": "sleep"},
                                   sh_result=(0, out, ""))
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                body = resp.json()
                _starlette(body)
                self.assertIs(body["ok"], True)

    def test_sh_seam_bombs_keep_the_wake_leg_200(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_power_svc, "sh",
                lambda *a, **k: (0, _DecodeBombBytes(b"ok"), "")))
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

    def test_unhashable_row_id_is_the_coded_not_found(self):
        resp = self._power([{"id": _Unhashable()}], {"action": "sleep"})
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "disk_power.not_found")

    def test_iterbomb_rows_list_is_the_coded_not_found(self):
        resp = self._power(_IterBombList([dict(self._ROW)]),
                           {"action": "sleep"})
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "disk_power.not_found")

    def test_manage_sh_seam_bombs_keep_the_mutation_200(self):
        disk_manage_svc.invalidate_disk_info()
        self.addCleanup(disk_manage_svc.invalidate_disk_info)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_info", lambda n: {}))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "sh",
                lambda *a, **k: (0, _DecodeBombBytes(b"ok"), "")))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: {}))
            resp = _client().post(
                "/api/storage/manage/disk4s1", json={"action": "mount"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["message"], "ok")


if __name__ == "__main__":
    unittest.main(verbosity=2)
