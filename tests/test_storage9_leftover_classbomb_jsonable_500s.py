"""Ninth leftover-500s sweep of the Storage read family.

storage8 sealed the ``disk_snapshot`` sequence-unwrap; this hunt threw the
*``__class__``-property bomb* class (isinstance consults ``value.__class__``
when the exact-type check misses, so a raising property detonates the type
gate itself) plus its lying-``__class__`` and rc-subclass siblings at the
same surfaces over ``create_app()`` with ``raise_server_exceptions=False``,
and found these leaks:

* raw 500s on GET /api/storage?light: a ``list_volumes`` / ``smart_devices``
  *return* wearing a raising ``__class__`` property blew
  ``storage_overview``'s bare ``isinstance(..., list)`` gates one line past
  the catch built for them, and a lying-``__class__`` property claiming
  ``bool`` rode ``_jsonable`` through as-is into Starlette's
  ``allow_nan=False`` encoder (TypeError → 500).

* a raw 500 on GET /api/storage: an overview return class-bomb detonated the
  route's own ``isinstance(data, dict)`` gate, which sits outside the try
  that owns the degraded ``error`` body.

* whole-table wipes (200, wrong body): a class-bomb value / mapping key or a
  lying dict/bytes claim planted in one volume row's unsanitized extra field
  raised inside the final ``_jsonable`` pass and nulled the *entire*
  ``volumes`` list to ``null``; a non-str df table line AttributeError'd
  ``line.split()`` and emptied the table; an rc-subclass ``__eq__`` bomb
  raised out of ``smart_devices`` (every disk row lost) and out of
  ``disk_snapshot._df_table`` (the mount table lost for all three consumer
  modules at once).

* safety-union narrowing: ``disk_snapshot._as_text`` / ``_disk_token``
  raised on a class-bomb token (and on the ``value in (None, False, True,
  "")`` containment probe's reflected ``__eq__``), collapsing the plist arm
  of ``root_whole_disks`` — the set the panel refuses to spin down or eject
  — exactly the storage8 regression class in a new shape.

Fixes follow the sibling sweeps: ``_isa`` guarded isinstance on every gate,
``_mapping_get`` unbound field reads, ``_rc_int`` base coercion for every
``sh()`` return code, guarded unbound ``dict.items`` / ``base.__iter__``
views with per-entry salvage, a hardened ``_decode_bytes``, and router shape
gates so a text-salvaged junk listing keeps the section's list/dict contract.

Stays-immune pins: a class-bomb *whole* volume row (per-row try), a lying
``__class__`` claiming list (guarded unbound ``__iter__``), a raising
listing behind GET /api/storage/disks (route except arm), and a
hash-shadowing ``__eq__``-bomb str-subclass key costing only its own row.

No ``json.loads`` seam exists on these routes (plists go through
``plistlib``), so the huge-number ValueError class from the sibling sweeps
still does not apply; the state file is not read here, so neither does the
FIFO O_NONBLOCK class.
"""
from __future__ import annotations

import json
import unittest
from contextlib import ExitStack
from unittest import mock

from hub import disk_snapshot, storage_svc
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


class _ClassBomb:
    """``isinstance`` consults ``__class__`` when the exact-type check
    misses; a raising property detonates the type gate itself."""

    @property
    def __class__(self):
        raise RuntimeError("class property bomb")


def _lying(claim):
    """An object whose ``__class__`` property *claims* a builtin it is not,
    steering isinstance-driven walkers into unbound base calls."""

    class _Lying:
        @property
        def __class__(self):
            return claim

    return _Lying()


class _RcBomb(int):
    """Passes every int gate; raises on the bare ``==`` / ``in`` probes."""

    def __eq__(self, other):
        raise RuntimeError("rc eq bomb")

    def __ne__(self, other):
        raise RuntimeError("rc ne bomb")

    __hash__ = int.__hash__


class _EqBomb:
    """Raises on any equality probe (the reflected-``__eq__`` class)."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = object.__hash__


class _ShadowKey(str):
    """A str-subclass key whose ``__eq__`` raises: dict probes that hash to
    the same slot run the *stored* key's own comparison."""

    def __eq__(self, other):
        raise RuntimeError("shadow key eq bomb")

    __hash__ = str.__hash__


_GOOD_VOLUME = {
    "filesystem": "/dev/disk4s1", "device": "/dev/disk4s1",
    "disk_id": "disk4", "mount": "/Volumes/Data", "kind": "external",
    "total_gb": 100.0, "used_gb": 40.0, "avail_gb": 60.0, "pct": 40,
}


def _light(volumes, disks=None):
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(
            storage_svc, "list_volumes", lambda: volumes))
        stack.enter_context(mock.patch.object(
            storage_svc, "smart_devices",
            lambda: disks if disks is not None else []))
        return _client().get("/api/storage?light=true")


class OverviewListGateClassBombTests(unittest.TestCase):
    """The bare ``isinstance(..., list)`` gates in storage_overview — each
    of these was a raw 500 on GET /api/storage?light pre-fix."""

    def test_classbomb_volumes_return_degrades_to_empty_table(self):
        resp = _light(_ClassBomb())
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["volumes"], [])

    def test_classbomb_disks_return_keeps_the_volume_table(self):
        resp = _light([dict(_GOOD_VOLUME)], _ClassBomb())
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["disks"], [])
        self.assertEqual(len(body["volumes"]), 1)
        self.assertEqual(body["volumes"][0]["mount"], "/Volumes/Data")


class JsonableClassBombSiblingTests(unittest.TestCase):
    """Class-bomb / lying-``__class__`` leftovers inside one volume row.

    The lying-bool was a raw 500 (it rode the scrub as-is into the
    encoder); the others nulled the *whole* ``volumes`` list to ``null``
    while the healthy sibling row sat readable.
    """

    def _both_rows_kept(self, resp):
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIsInstance(body["volumes"], list)
        self.assertEqual(len(body["volumes"]), 2)
        mounts = {v["mount"] for v in body["volumes"]}
        self.assertEqual(mounts, {"/Volumes/Data"})
        return body

    def test_lying_bool_extra_value_stays_200(self):
        body = self._both_rows_kept(_light([
            {**_GOOD_VOLUME, "note": _lying(bool)}, dict(_GOOD_VOLUME),
        ]))
        # The guarded bool() coercion reads the object's truthiness.
        self.assertIs(body["volumes"][0]["note"], True)

    def test_classbomb_extra_value_salvages_as_text(self):
        body = self._both_rows_kept(_light([
            {**_GOOD_VOLUME, "note": _ClassBomb()}, dict(_GOOD_VOLUME),
        ]))
        self.assertIsInstance(body["volumes"][0]["note"], str)

    def test_classbomb_mapping_key_keeps_both_rows(self):
        self._both_rows_kept(_light([
            {**_GOOD_VOLUME, _ClassBomb(): 1}, dict(_GOOD_VOLUME),
        ]))

    def test_lying_dict_extra_value_keeps_both_rows(self):
        body = self._both_rows_kept(_light([
            {**_GOOD_VOLUME, "note": _lying(dict)}, dict(_GOOD_VOLUME),
        ]))
        # The unbound dict.items view TypeErrors on the impostor; it
        # degrades through the text salvage instead of nulling the table.
        self.assertEqual(body["volumes"][0]["note"], "")

    def test_lying_bytes_extra_value_keeps_both_rows(self):
        body = self._both_rows_kept(_light([
            {**_GOOD_VOLUME, "note": _lying(bytes)}, dict(_GOOD_VOLUME),
        ]))
        self.assertEqual(body["volumes"][0]["note"], "")

    def test_classbomb_total_gb_costs_only_its_field(self):
        body = self._both_rows_kept(_light([
            {**_GOOD_VOLUME, "total_gb": _ClassBomb()}, dict(_GOOD_VOLUME),
        ]))
        # Pre-fix the bare isinstance in _volume_row raised and the whole
        # row dropped; now the field degrades to the numeric default.
        self.assertEqual(body["volumes"][0]["total_gb"], 0.0)
        self.assertEqual(body["volumes"][1]["total_gb"], 100.0)

    def test_classbomb_disk_row_value_keeps_the_disk_row(self):
        resp = _light([dict(_GOOD_VOLUME)],
                      [{"id": "disk0", "smart": _ClassBomb()},
                       {"id": "disk1"}])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        ids = [d.get("id") for d in body["disks"]]
        # Pre-fix the bombed row dropped whole; the field now salvages.
        self.assertEqual(ids, ["disk0", "disk1"])


class ListVolumesPoisonedTableTests(unittest.TestCase):
    """A non-str df table line used to AttributeError ``line.split()`` and
    empty the whole volume table — the healthy sibling line survives now."""

    _HEADER = "Filesystem 1024-blocks Used Available Capacity Mounted on"
    _GOOD_LINE = "/dev/disk4s1 1000000 400000 600000 40% /Volumes/Data"

    def test_classbomb_line_keeps_the_sibling_row(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "df_lines",
                lambda *a, **k: (self._HEADER, _ClassBomb(), self._GOOD_LINE)))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", lambda: []))
            resp = _client().get("/api/storage?light=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        mounts = {v["mount"] for v in body["volumes"]}
        self.assertIn("/Volumes/Data", mounts)

    def test_bytes_line_still_parses_through_the_scrub(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "df_lines",
                lambda *a, **k: (self._HEADER, self._GOOD_LINE.encode())))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", lambda: []))
            resp = _client().get("/api/storage?light=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        mounts = {v["mount"] for v in body["volumes"]}
        self.assertIn("/Volumes/Data", mounts)


class RcSubclassBombTests(unittest.TestCase):
    """rc-subclass ``__eq__`` bombs from a poisoned runner seam."""

    def test_smart_devices_rc_bomb_keeps_a_probed_disk_list(self):
        storage_svc.smart_devices.invalidate()
        self.addCleanup(storage_svc.smart_devices.invalidate)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "list_volumes", lambda: [dict(_GOOD_VOLUME)]))
            stack.enter_context(mock.patch.object(
                storage_svc, "sh",
                lambda *a, **k: (_RcBomb(0), "/dev/disk0 ", "")))
            resp = _client().get("/api/storage?light=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # Pre-fix the bare ``rc == 0`` raised out of smart_devices and the
        # whole disks section vanished; the fallback probe now answers.
        self.assertTrue(body["disks"])
        self.assertEqual(body["disks"][0]["id"], "disk0")
        self.assertEqual(len(body["volumes"]), 1)

    def test_df_table_rc_bomb_salvages_the_honest_zero(self):
        disk_snapshot.invalidate_disks()
        self.addCleanup(disk_snapshot.invalidate_disks)
        with mock.patch.object(
            disk_snapshot, "sh",
            lambda *a, **k: (_RcBomb(0), "hdr\n/dev/disk0s2 1 1 1 1% /", ""),
        ):
            # Pre-fix the bare ``rc == 0`` raised out of the shared read
            # into all three consumer modules at once.
            got = disk_snapshot.df_lines(force=True)
        self.assertEqual(got, ("hdr", "/dev/disk0s2 1 1 1 1% /"))

    def test_df_table_rc_bomb_nonzero_reads_as_failure(self):
        disk_snapshot.invalidate_disks()
        self.addCleanup(disk_snapshot.invalidate_disks)
        with mock.patch.object(
            disk_snapshot, "sh", lambda *a, **k: (_RcBomb(1), "junk", ""),
        ):
            self.assertEqual(disk_snapshot.df_lines(force=True), ())

    def test_physical_whole_disks_rc_bomb_degrades_to_empty(self):
        disk_snapshot.invalidate_disks()
        self.addCleanup(disk_snapshot.invalidate_disks)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_snapshot, "run_bytes",
                lambda *a, **k: (_RcBomb(1), b"", b"")))
            stack.enter_context(mock.patch.object(
                disk_snapshot, "sh", lambda *a, **k: (_RcBomb(1), "", "")))
            self.assertEqual(
                disk_snapshot.physical_whole_disks(force=True), ())


class DiskSnapshotScrubClassBombTests(unittest.TestCase):
    """The two shared scrubs raised on class-bombs and reflected
    ``__eq__`` probes — collapsing the plist arm of the boot-disk safety
    union, the storage8 regression class in a new shape."""

    def test_disk_token_classbomb_degrades_to_empty(self):
        self.assertEqual(disk_snapshot._disk_token(_ClassBomb()), "")

    def test_disk_token_lying_bytes_degrades_to_empty(self):
        self.assertEqual(disk_snapshot._disk_token(_lying(bytes)), "")

    def test_as_text_classbomb_salvages_text(self):
        out = disk_snapshot._as_text(_ClassBomb())
        self.assertIs(type(out), str)
        self.assertTrue(out)

    def test_as_text_eqbomb_no_longer_reflects(self):
        # The old ``value in (None, False, True, "")`` containment probe
        # reflected into the leftover's own ``__eq__`` and raised.
        out = disk_snapshot._as_text(_EqBomb())
        self.assertIs(type(out), str)

    def test_as_text_empty_and_sentinels_unchanged(self):
        for v in (None, False, True, ""):
            self.assertEqual(disk_snapshot._as_text(v), "")
        self.assertEqual(disk_snapshot._as_text("disk0"), "disk0")
        self.assertEqual(disk_snapshot._as_text(["/mnt"]), "/mnt")

    def test_root_whole_disks_classbomb_parent_keeps_store_disk(self):
        disk_snapshot.invalidate_disks()
        self.addCleanup(disk_snapshot.invalidate_disks)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_snapshot, "sh", lambda *a, **k: (-1, "", "not found")))
            stack.enter_context(mock.patch.object(
                disk_snapshot, "df_lines", lambda *a, **k: ()))
            stack.enter_context(mock.patch.object(
                disk_snapshot, "root_info", lambda *a, **k: {
                    "ParentWholeDisk": _ClassBomb(),
                    "APFSPhysicalStores": [{"APFSPhysicalStore": "disk0s2"}],
                }))
            got = disk_snapshot.root_whole_disks(force=True)
        # Pre-fix from_plist raised on the parent token and answered an
        # empty set — the boot disk silently lost eject/sleep protection.
        self.assertIn("disk0", got)


class RouterGateClassBombTests(unittest.TestCase):
    """The route-level gates that sat outside their own try arms."""

    def test_full_page_classbomb_overview_return_degrades(self):
        with mock.patch.object(
            storage_router.storage_svc, "storage_overview",
            lambda: _ClassBomb(),
        ):
            resp = _client().get("/api/storage")
        # Pre-fix ``isinstance(data, dict)`` detonated — a raw 500 where
        # the degraded error body is the contract.
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["volumes"], [])
        self.assertIn("error", body)

    def test_full_page_junk_power_listing_keeps_list_contract(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_router.storage_svc, "storage_overview",
                lambda: {"volumes": [], "disks": []}))
            stack.enter_context(mock.patch.object(
                storage_router.disk_power_svc, "list_power_disks",
                lambda: _ClassBomb()))
            stack.enter_context(mock.patch.object(
                storage_router.disk_manage_svc, "overview",
                lambda: _ClassBomb()))
            resp = _client().get("/api/storage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # The sanitizer salvages the junk as text; the shape gates keep
        # the sections' list/dict contracts with the same degrade the
        # except arms answer.
        self.assertEqual(body["power_disks"], [])
        self.assertIn("power_error", body)
        self.assertEqual(body["managed"]["volumes"], [])

    def test_disks_route_junk_listing_keeps_list_contract(self):
        with mock.patch.object(
            storage_router.disk_power_svc, "list_power_disks",
            lambda: _ClassBomb(),
        ):
            resp = _client().get("/api/storage/disks")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["disks"], [])
        self.assertIn("error", body)

    def test_manage_route_junk_overview_keeps_dict_contract(self):
        with mock.patch.object(
            storage_router.disk_manage_svc, "overview",
            lambda: _ClassBomb(),
        ):
            resp = _client().get("/api/storage/manage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["volumes"], [])
        self.assertIn("error", body)


class StaysImmunePins(unittest.TestCase):
    """Vectors the sweep found already sealed — pinned so they stay so."""

    def test_classbomb_whole_row_drops_alone(self):
        # The per-row try in storage_overview already absorbs a row that
        # cannot even answer isinstance; the sibling survives.
        resp = _light([_ClassBomb(), dict(_GOOD_VOLUME)])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(len(body["volumes"]), 1)
        self.assertEqual(body["volumes"][0]["mount"], "/Volumes/Data")

    def test_lying_list_extra_value_keeps_both_rows(self):
        # The guarded unbound ``list.__iter__`` already TypeErrors the
        # impostor; it degrades through the text salvage.
        resp = _light([
            {**_GOOD_VOLUME, "note": _lying(list)}, dict(_GOOD_VOLUME),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(len(body["volumes"]), 2)

    def test_shadow_key_bomb_row_costs_itself_only(self):
        # A hash-shadowing ``__eq__``-bomb key squatting the ``mount`` slot:
        # the guarded ``_mapping_get`` probe degrades the read to its
        # default, so the unusable row drops alone (no mount, no row).
        resp = _light([
            {_ShadowKey("mount"): "/x"},
            dict(_GOOD_VOLUME),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        mounts = {v["mount"] for v in body["volumes"]}
        self.assertIn("/Volumes/Data", mounts)

    def test_disks_route_raising_listing_still_degrades(self):
        with mock.patch.object(
            storage_router.disk_power_svc, "list_power_disks",
            side_effect=RuntimeError("boom"),
        ):
            resp = _client().get("/api/storage/disks")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["disks"], [])
        self.assertEqual(body["error"], "boom")


class HelperUnitPins(unittest.TestCase):
    """The scrubs must launder to exact base types and never raise."""

    def test_jsonable_classbomb_is_text(self):
        out = storage_svc._jsonable(_ClassBomb())
        self.assertIs(type(out), str)
        _starlette(out)

    def test_jsonable_lying_claims(self):
        self.assertEqual(storage_svc._jsonable(_lying(dict)), "")
        self.assertEqual(storage_svc._jsonable(_lying(bytes)), "")
        self.assertIs(storage_svc._jsonable(_lying(bool)), True)
        _starlette(storage_svc._jsonable(_lying(list)))

    def test_jsonable_classbomb_key_keeps_siblings(self):
        out = storage_svc._jsonable({_ClassBomb(): 1, "ok": 2})
        self.assertEqual(out["ok"], 2)
        _starlette(out)

    def test_as_text_classbomb_is_exact_str(self):
        out = storage_svc._as_text(_ClassBomb())
        self.assertIs(type(out), str)
        self.assertEqual(storage_router._as_text(_ClassBomb()), out)

    def test_json_gb_and_json_int_classbomb_default(self):
        self.assertEqual(storage_svc._json_gb(_ClassBomb()), 0.0)
        self.assertEqual(storage_svc._json_int(_ClassBomb()), 0)

    def test_rc_int_reads_the_real_value(self):
        self.assertEqual(storage_svc._rc_int(_RcBomb(0)), 0)
        self.assertEqual(storage_svc._rc_int(_RcBomb(4)), 4)
        self.assertEqual(storage_svc._rc_int(_ClassBomb()), -255)
        self.assertEqual(disk_snapshot._rc_int(_RcBomb(0)), 0)
        self.assertEqual(disk_snapshot._rc_int("junk"), -255)


if __name__ == "__main__":
    unittest.main(verbosity=2)
