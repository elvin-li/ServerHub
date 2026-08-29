"""Tenth leftover-500s sweep of the Storage read/mutation family.

storage9 sealed the ``__class__``-property bomb class on the *listing*
routes; this hunt threw the same zoo — plus the wave-10 shapes it never
carried (lying ``__class__`` impostors, hash-shadowing ``__eq__`` keys,
rc-subclass ``__eq__``/``__ne__`` bombs, over-cap already-int rcs) — at the
storage *mutation* legs and the SMART routes over ``create_app()`` with
``raise_server_exceptions=False``, and found these leaks:

* raw 500s on POST /api/storage/disks/{id}/power: the sleep/eject/wake legs
  probed the raw ``sh`` return code bare (``rc != 0`` / ``rc == 0`` — an
  rc-subclass ``__ne__``/``__eq__`` bomb detonated them), rendered ``rc=``
  through an f-string (a >4300-digit already-int rc ValueError'd
  ``format()`` itself), and scrubbed stdout/stderr through a ``_text``
  whose *bare* isinstance gates a ``__class__``-property bomb blew before
  any salvage ran; a str-subclass listing-row id whose ``__eq__`` raises
  stored fine and then detonated the ``disks.get(disk_id)`` hash probe.

* raw 500s on POST /api/storage/manage/{id}: ``disk_action``'s ``run()``
  had the same bare ``rc != 0`` probe and bare-isinstance ``_text``, every
  branch built ``"ok": rc == 0`` on the raw rc, and the confirmed-erase
  path's ``fs in (None, "")`` containment probe reflected into a leftover
  fs value's own ``__eq__``.

* raw 500s on the SMART routes: ``node in _known_nodes()`` ran a *stored*
  shadow key's ``__eq__`` during the set probe (POST /api/smart/test,
  POST /api/smart/abort, PUT /api/smart/schedule), and GET /api/smart blew
  up on a junk ``_device_nodes`` return — a lying ``__class__`` claiming
  list raised out of ``overview``'s probe comprehension, and a class-bomb
  *entry* AttributeError'd ``node.rsplit`` inside ``_device_report``'s own
  except arm (``fan_out`` re-raises).

* whole-table / whole-arm wipes (200, wrong body): a *lying* ``__class__``
  claiming str passed the ``_isa(line, str)`` df-table gates and then
  AttributeError'd ``line.split()`` — emptying ``list_volumes``, the
  mount-table arm of ``root_devices`` and every power row's volume list
  for one junk line; ``disk_snapshot._root_info`` / ``disk_manage._plist``
  compared an honest rc-bomb zero bare and read the answer as a failure.

Fixes follow the sibling sweeps: ``_isa`` gates and ``_rc_int`` base
coercion (with the digit-cap probe, junk → -255 never the -1 sentinel) in
disk_power_svc / disk_manage_svc, exact-type df-line gates with
``_as_text``/``_text`` salvage, exact-base-str laundering for listing-row
ids and SMART device nodes (``_node_list``), and an identity + exact-type
fs gate on the confirmed-erase path.

No new i18n keys: every refusal reuses the existing coded errors.
"""
from __future__ import annotations

import json
import plistlib
import unittest
from contextlib import ExitStack
from unittest import mock

from hub import disk_manage_svc, disk_power_svc, disk_snapshot, smart_test_svc, storage_svc
from hub.routers import nas_storage
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
    steering isinstance-driven walkers into calls the real type refuses."""

    class _Lying:
        @property
        def __class__(self):
            return claim

    return _Lying()


class _RcBomb(int):
    """Passes every int gate; raises on the bare ``==``/``!=`` probes."""

    def __eq__(self, other):
        raise RuntimeError("rc eq bomb")

    def __ne__(self, other):
        raise RuntimeError("rc ne bomb")

    __hash__ = int.__hash__


class _ShadowKey(str):
    """A str-subclass whose ``__eq__`` raises: dict/set probes that hash to
    the same slot run the *stored* key's own comparison."""

    def __eq__(self, other):
        raise RuntimeError("shadow key eq bomb")

    __hash__ = str.__hash__


_HUGE = 10 ** 5000

_POWER_ROW = {
    "id": "disk4", "device": "/dev/disk4",
    "system": False, "can_sleep": True,
}


class PowerMutationRcBombTests(unittest.TestCase):
    """POST /api/storage/disks/{id}/power — each of these was a raw 500."""

    def _post(self, sh_ret, rows=None, action="sleep", dev_exists=None):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_power_svc, "list_power_disks",
                mock.Mock(return_value=rows if rows is not None
                          else [dict(_POWER_ROW)])))
            stack.enter_context(mock.patch.object(
                disk_power_svc, "sh", lambda *a, **k: sh_ret))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: None))
            if dev_exists is not None:
                stack.enter_context(mock.patch.object(
                    disk_power_svc, "_dev_exists", lambda node: dev_exists))
            return _client().post(
                "/api/storage/disks/disk4/power", json={"action": action})

    def test_rc_eq_bomb_zero_reads_success(self):
        # Pre-fix the bare ``rc != 0`` ran the bomb's ``__ne__`` — a raw
        # 500 where the honest zero means the unmount succeeded.
        resp = self._post((_RcBomb(0), "", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["action"], "sleep")

    def test_over_cap_rc_reads_failure_not_500(self):
        # Pre-fix ``f"rc={rc}"`` ValueError'd on the >4300-digit already-int
        # (format() renders the digits); _rc_int now reads it as -255.
        resp = self._post((_HUGE, "unmount failed", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], False)
        self.assertIn("unmount failed", body["message"])

    def test_classbomb_stdout_stays_200(self):
        # Pre-fix _text's bare ``isinstance(value, (list, tuple))`` gate
        # detonated on the class-bomb before any salvage ran.
        resp = self._post((0, _ClassBomb(), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)

    def test_lying_bytes_stdout_stays_200(self):
        # Pre-fix the impostor passed the bytes gate and ``bytes(value)``
        # TypeError'd the bare base copy.
        resp = self._post((0, _lying(bytes), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)

    def test_shadow_key_listing_row_id_stays_200(self):
        # Pre-fix the row stored its ``__eq__``-bomb id fine, then
        # ``disks.get("disk4")`` ran the *stored* key's comparison during
        # the hash probe — a raw 500 for a row this request never asked
        # about.  The laundered exact-str key still matches.
        rows = [{**_POWER_ROW, "id": _ShadowKey("disk4")}]
        resp = self._post((0, "", ""), rows=rows)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)

    def test_wake_rc_eq_bomb_stays_200(self):
        # Pre-fix the mountDisk leg's bare ``rc2 != 0`` ran the ``__ne__``
        # bomb — a raw 500 on the wake action.
        resp = self._post((_RcBomb(0), "", ""), action="wake",
                          dev_exists=True)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["action"], "wake")


class ManageMutationRcBombTests(unittest.TestCase):
    """POST /api/storage/manage/{id} — the disk_action ``run()`` seam."""

    def _post(self, sh_ret, body=None, info=None):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                lambda node: info if info is not None
                else {"MountPoint": "/Volumes/Ext"}))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "root_devices",
                lambda *a, **k: frozenset()))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "sh", lambda *a, **k: sh_ret))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: None))
            return _client().post(
                "/api/storage/manage/disk4s2",
                json=body or {"action": "mount"})

    def test_mount_rc_eq_bomb_zero_reads_ok(self):
        # Pre-fix ``run()``'s bare ``rc != 0`` ran the ``__ne__`` bomb and
        # the result build's ``rc == 0`` the ``__eq__`` one — raw 500s.
        resp = self._post((_RcBomb(0), "Mounted", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["message"], "Mounted")

    def test_mount_classbomb_stdout_stays_200(self):
        # Pre-fix _text's bare isinstance gates detonated on the bomb.
        resp = self._post((1, _ClassBomb(), "mount failed"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], False)

    def test_mount_over_cap_rc_reads_failure(self):
        resp = self._post((_HUGE, "", "mount failed"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], False)
        self.assertEqual(body["message"], "mount failed")

    def test_erase_classbomb_volume_name_stays_200(self):
        # Pre-fix the confirmed-erase path's ``_text(info.get("VolumeName"))``
        # detonated the same bare gate — a raw 500 after the operator had
        # already confirmed the destructive action.
        resp = self._post(
            (0, "Erase complete", ""),
            body={"action": "eraseVolume", "confirm": True,
                  "name": "NewVol", "fs": "ExFAT"},
            info={"MountPoint": "/Volumes/Ext", "VolumeName": _ClassBomb()},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["name"], "NewVol")

    def test_erase_shadow_fs_no_longer_reflects_in_process(self):
        # The old ``fs in (None, "")`` containment probe gave a str-subclass
        # fs's own ``__eq__`` priority (subclass reflected rule) — a raise
        # where the value's string form is a perfectly valid answer.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                lambda node: {"MountPoint": "/Volumes/Ext",
                              "VolumeName": "Ext"}))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "root_devices",
                lambda *a, **k: frozenset()))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "sh", lambda *a, **k: (0, "done", "")))
            result = disk_manage_svc.disk_action(
                "disk4s2", "eraseVolume",
                name="NewVol", fs=_ShadowKey("APFS"), confirm=True)
        self.assertIs(result["ok"], True)
        self.assertEqual(result["fs"], "APFS")


class SmartRouteImpostorTests(unittest.TestCase):
    """The SMART routes' device-node identity probes."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(
            nas_storage, "require_admin_browser", lambda request: "admin"))
        smart_test_svc.invalidate()
        self.addCleanup(smart_test_svc.invalidate)

    def test_shadow_device_node_start_test_is_coded(self):
        # Pre-fix ``node not in _known_nodes()`` ran the *stored* shadow
        # key's ``__eq__`` during the set probe — a raw 500 where the
        # matching node should simply be found.
        caps = {"readable": True, "available": False, "supported": [],
                "reason": "self_tests_unsupported", "device_type": "auto",
                "estimated_minutes": {}, "detail": ""}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes",
                lambda: [_ShadowKey("/dev/disk0")]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_capabilities", lambda node, **k: caps))
            resp = _client().post(
                "/api/smart/test",
                json={"device": "/dev/disk0", "kind": "short"})
        self.assertNotEqual(resp.status_code, 500, resp.text[:300])
        self.assertLess(resp.status_code, 500)
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "smart.unsupported")

    def test_shadow_device_node_abort_is_200(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes",
                lambda: [_ShadowKey("/dev/disk0")]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", lambda *a, **k: (0, "aborted", "")))
            resp = _client().post(
                "/api/smart/abort", json={"device": "/dev/disk0"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)

    def test_shadow_device_node_schedule_put_is_200(self):
        # Pre-fix the ``node in known`` probe in set_schedule's cleaner
        # comprehension ran the stored bomb — a raw 500 on
        # PUT /api/smart/schedule.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes",
                lambda: [_ShadowKey("/dev/disk0")]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "update_settings", lambda *a, **k: None))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_schedule_cfg", lambda: {}))
            resp = _client().put(
                "/api/smart/schedule",
                json={"interval": "weekly", "kind": "short",
                      "devices": ["/dev/disk0"]})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)

    def test_classbomb_device_node_get_smart_is_200(self):
        # Pre-fix _device_report's *except arm* AttributeError'd its own
        # ``node.rsplit`` on the class-bomb node and fan_out re-raised — a
        # raw 500 on GET /api/smart while /dev/disk0 sat readable.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes",
                lambda: [_ClassBomb(), "/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", lambda *a, **k: (1, "", "")))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_load_history", lambda: []))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_schedule_cfg", lambda: {}))
            resp = _client().get("/api/smart?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        ids = [d.get("id") for d in body["devices"]]
        self.assertEqual(ids, ["disk0"])

    def test_lying_list_device_nodes_get_smart_is_200(self):
        # Pre-fix the probe comprehension iterated the impostor raw — a
        # TypeError 500 on GET /api/smart.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: _lying(list)))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", lambda *a, **k: (1, "", "")))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_load_history", lambda: []))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_schedule_cfg", lambda: {}))
            resp = _client().get("/api/smart?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["devices"], [])


class LyingStrTableLineTests(unittest.TestCase):
    """A lying ``__class__`` claiming str passed every isinstance gate and
    AttributeError'd ``line.split()`` — whole-table / whole-arm wipes."""

    _HEADER = "Filesystem 1024-blocks Used Available Capacity Mounted on"
    _GOOD_LINE = "/dev/disk4s1 1000000 400000 600000 40% /Volumes/Data"

    def test_lying_str_df_line_keeps_the_sibling_volume(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "df_lines",
                lambda *a, **k: (self._HEADER, _lying(str), self._GOOD_LINE)))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", lambda: []))
            resp = _client().get("/api/storage?light=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        mounts = {v["mount"] for v in body["volumes"]}
        # Pre-fix list_volumes raised and the whole table emptied.
        self.assertIn("/Volumes/Data", mounts)

    def test_lying_str_df_line_keeps_the_root_devices_arm(self):
        with mock.patch.object(
            disk_snapshot, "df_lines",
            lambda *a, **k: ("hdr", _lying(str), "/dev/disk0s2 1 1 1 1% /"),
        ):
            # Pre-fix the mount-table arm of the boot-disk safety union
            # collapsed on the junk line.
            self.assertEqual(disk_snapshot.root_devices(), frozenset({"disk0"}))

    def test_lying_str_df_line_keeps_power_volume_rows(self):
        line = "/dev/disk4s1 1000000 400000 600000 40% /Volumes/Ext"
        with mock.patch.object(
            disk_power_svc, "_df_lines",
            lambda *a, **k: ("hdr", _lying(str), line),
        ):
            vols = disk_power_svc._volumes_on_disk("disk4")
        # Pre-fix the raise degraded every _describe_disk row to None.
        self.assertEqual(len(vols), 1)
        self.assertEqual(vols[0]["mount"], "/Volumes/Ext")


class RootInfoRcBombTests(unittest.TestCase):
    """An honest rc-bomb zero must not read as a failed root-info read."""

    def test_root_info_rc_bomb_zero_salvages_the_plist(self):
        disk_snapshot.invalidate_disks()
        self.addCleanup(disk_snapshot.invalidate_disks)
        payload = plistlib.dumps({"ParentWholeDisk": "disk0"})
        with mock.patch.object(
            disk_snapshot, "run_bytes",
            lambda *a, **k: (_RcBomb(0), payload, b""),
        ):
            info = disk_snapshot.root_info(force=True)
        # Pre-fix the bare ``rc == 0`` raised into the except arm and the
        # plist arm of the safety union read as empty.
        self.assertEqual(info.get("ParentWholeDisk"), "disk0")


class HelperUnitPins(unittest.TestCase):
    """The new helpers must launder to exact base types and never raise."""

    def test_rc_int_reads_the_real_value(self):
        for module in (disk_power_svc, disk_manage_svc):
            self.assertEqual(module._rc_int(_RcBomb(0)), 0)
            self.assertEqual(module._rc_int(_RcBomb(4)), 4)
            self.assertEqual(module._rc_int(True), 1)
            self.assertEqual(module._rc_int("junk"), -255)
            self.assertEqual(module._rc_int(None), -255)
            self.assertEqual(module._rc_int(_ClassBomb()), -255)
            # The digit-cap probe: an over-cap already-int must never
            # reach the ``rc={rc}`` f-strings.
            self.assertEqual(module._rc_int(_HUGE), -255)

    def test_vanished_spawn_rc_bomb_no_longer_reflects(self):
        self.assertIs(
            disk_power_svc._vanished_spawn(_RcBomb(0), "not found", ""),
            False)
        self.assertIs(
            disk_manage_svc._vanished_spawn(_RcBomb(1), "command not found", ""),
            True)

    def test_text_classbomb_salvages_exact_str(self):
        for module in (disk_power_svc, disk_manage_svc):
            out = module._text(_ClassBomb())
            self.assertIs(type(out), str)
            self.assertEqual(out, "")
            self.assertEqual(module._text(_lying(bytes)), "")

    def test_req_text_classbomb_and_liars_degrade(self):
        for module in (disk_power_svc, disk_manage_svc):
            out = module._req_text(_ClassBomb())
            self.assertIs(type(out), str)
            self.assertEqual(module._req_text(_lying(bytes)), "")
        self.assertEqual(disk_manage_svc._req_text(_ShadowKey("APFS")), "APFS")
        self.assertIs(type(disk_manage_svc._req_text(_ShadowKey("APFS"))), str)

    def test_ident_classbomb_degrades_to_empty(self):
        self.assertEqual(disk_manage_svc._ident(_ClassBomb()), "")
        self.assertEqual(disk_manage_svc._ident(_lying(bytes)), "")

    def test_node_list_launders_to_exact_base_strs(self):
        with mock.patch.object(
            smart_test_svc, "_device_nodes",
            lambda: [_ClassBomb(), _ShadowKey("/dev/disk0"),
                     b"/dev/disk1", "/dev/disk2"],
        ):
            nodes = smart_test_svc._node_list()
        self.assertEqual(nodes, ["/dev/disk0", "/dev/disk2"])
        for node in nodes:
            self.assertIs(type(node), str)
        # And the membership set is probe-safe.
        with mock.patch.object(
            smart_test_svc, "_device_nodes",
            lambda: [_ShadowKey("/dev/disk0")],
        ):
            known = smart_test_svc._known_nodes()
        self.assertIn("/dev/disk0", known)

    def test_node_list_lying_list_reads_as_empty(self):
        with mock.patch.object(
            smart_test_svc, "_device_nodes", lambda: _lying(list),
        ):
            self.assertEqual(smart_test_svc._node_list(), [])


class StaysImmunePins(unittest.TestCase):
    """Vectors the sweep found already sealed — pinned so they stay so."""

    def test_power_route_raising_action_still_coded(self):
        # The service's coded refusal path is unchanged.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_power_svc, "list_power_disks",
                mock.Mock(return_value=[dict(_POWER_ROW)])))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: None))
            resp = _client().post(
                "/api/storage/disks/disk4/power", json={"action": "explode"})
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "disk_power.unknown_action")

    def test_manage_route_system_disk_still_protected(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                lambda node: {"MountPoint": "/"}))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: None))
            resp = _client().post(
                "/api/storage/manage/disk1s1", json={"action": "unmount"})
        self.assertEqual(resp.status_code, 403, resp.text[:300])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "disk.system_protected")

    def test_light_overview_classbomb_row_still_drops_alone(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "list_volumes",
                lambda: [_ClassBomb(), {
                    "filesystem": "/dev/disk4s1", "device": "/dev/disk4s1",
                    "disk_id": "disk4", "mount": "/Volumes/Data",
                    "kind": "external", "total_gb": 100.0, "used_gb": 40.0,
                    "avail_gb": 60.0, "pct": 40,
                }]))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", lambda: []))
            resp = _client().get("/api/storage?light=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(len(body["volumes"]), 1)
        self.assertEqual(body["volumes"][0]["mount"], "/Volumes/Data")


if __name__ == "__main__":
    unittest.main(verbosity=2)
