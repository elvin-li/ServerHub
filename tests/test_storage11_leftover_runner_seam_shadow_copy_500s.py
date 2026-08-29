"""Eleventh leftover-500s sweep of the Storage read/mutation family.

storage10 sealed the rc-subclass ``__eq__`` bombs, the lying-``__class__``
impostors and the hash-shadowing *listing-row* ids.  This hunt threw the
same zoo at the two seams that sweep left bare — the ``sh`` runner itself
and the plain-``dict`` *copies* — over ``create_app()`` with
``raise_server_exceptions=False``, and found these leaks:

* raw 500s on the runner seam: every spawn in disk_power_svc /
  disk_manage_svc / smart_test_svc unpacked the raw ``sh`` answer bare
  (``rc, out, err = sh(...)``).  A runner that *raises* instead of
  answering — or answers a wrong arity, or a lying ``__class__`` impostor
  claiming tuple — detonated the unpack one seam before every ``_rc_int``
  guard storage10 built: POST /api/storage/disks/{id}/power (all three
  sleep/eject/wake legs), POST /api/storage/manage/{id} (``disk_action``'s
  ``run()``), GET /api/smart (``passwordless_available`` re-raised out of
  ``overview``'s fan-out), POST /api/smart/test and POST /api/smart/abort
  (their own sudo spawns).  A raising runner also unwound out of
  ``disk_snapshot._df_table`` into all three consumer modules at once —
  the whole-table wipe class, one seam earlier than the df-line bombs
  storage10 sealed.

* raw 500s on the copy seam (the storage9 hash-shadowing rule one
  assignment later): ``dict(...)`` copies keep a str-*subclass* key whose
  ``__eq__`` raises, and every later probe that hashes to its slot runs
  the *stored* key's own comparison.  ``disk_manage._plain_info`` fed the
  confirmed-erase path's bare ``info.get("VolumeName")`` (a raw 500 on
  POST /api/storage/manage/{id} after the operator had already confirmed
  the destructive action); ``smart_test._schedule_cfg``'s ``dict(stored)``
  fed ``get_schedule()``'s ``stored.get("interval")`` (raw 500s on
  GET /api/smart and PUT /api/smart/schedule, and the same raise escaped
  ``schedule_due()`` inside the scheduler tick); ``storage_svc._volume_row``'s
  ``dict(raw)`` detonated its own ``row["mount"] = ...`` assignments (the
  guarded whole-row drop where only the shadowed field is unreadable).

Fixes follow the vms11/network10 convention: a per-module ``_sh3`` answer-
shape launderer (unbound base reads, honest subclass wrappers — the
vanished-spawn sentinel included — survive untouched; junk degrades to
``(-255, "", "")``, nonzero and never ``sh``'s ``-1`` sentinel so an
unusable answer cannot forge the confirmed-vanished 503) plus a ``_spawn``
wrapper that absorbs a raising runner, and exact-base-str key laundering
on every plain-dict copy (``str.__str__`` base copies keep an honest
subclass key's text, so the shadowed field still *reads* instead of
dropping).

No new i18n keys: every refusal reuses the existing coded errors.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
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


def _raising_runner(*a, **k):
    """A leftover runner that raises instead of answering."""
    raise RuntimeError("runner bomb")


class _IterBombTuple(tuple):
    """Honest 3-tuple storage behind a bound ``__iter__`` bomb: the unbound
    base read must recover the real answer, not degrade it."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


def _lying(claim):
    """An object whose ``__class__`` property *claims* a builtin it is not,
    steering isinstance-driven unpacks into calls the real type refuses."""

    class _Lying:
        @property
        def __class__(self):
            return claim

    return _Lying()


class _ShadowKey(str):
    """A str-subclass whose ``__eq__`` raises: dict probes that hash to the
    same slot run the *stored* key's own comparison."""

    def __eq__(self, other):
        raise RuntimeError("shadow key eq bomb")

    __hash__ = str.__hash__


_MODULES = (storage_svc, disk_snapshot, disk_power_svc, disk_manage_svc, smart_test_svc)

_POWER_ROW = {
    "id": "disk4", "device": "/dev/disk4",
    "system": False, "can_sleep": True,
}

_CAPS_OK = {
    "readable": True, "available": True, "supported": ["short"],
    "reason": "", "device_type": "auto", "estimated_minutes": {}, "detail": "",
}


class PowerRunnerSeamTests(unittest.TestCase):
    """POST /api/storage/disks/{id}/power — each of these was a raw 500."""

    def _post(self, sh_fn, action="sleep", dev_exists=None):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_power_svc, "list_power_disks",
                mock.Mock(return_value=[dict(_POWER_ROW)])))
            stack.enter_context(mock.patch.object(disk_power_svc, "sh", sh_fn))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: None))
            if dev_exists is not None:
                stack.enter_context(mock.patch.object(
                    disk_power_svc, "_dev_exists", lambda node: dev_exists))
            return _client().post(
                "/api/storage/disks/disk4/power", json={"action": action})

    def test_raising_runner_sleep_degrades_not_500(self):
        # Pre-fix the bare ``rc, out, err = sh(...)`` unpack re-raised the
        # runner's own exception — a raw 500 on the sleep leg.
        resp = self._post(_raising_runner)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], False)

    def test_raising_runner_cannot_forge_the_vanished_503(self):
        # ``(-255, "", "")`` carries no vanished-CLI marker and is never the
        # ``-1`` sentinel, so a runner that cannot answer must not read as
        # "diskutil is gone" even on a host where the binary is absent.
        resp = self._post(_raising_runner)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertNotIn("diskutil_missing", resp.text)

    def test_two_tuple_answer_sleep_degrades_not_500(self):
        # Pre-fix the wrong-arity answer ValueError'd the unpack itself.
        resp = self._post(lambda *a, **k: (0, "only-two"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], False)

    def test_lying_tuple_answer_sleep_degrades_not_500(self):
        # An impostor claiming tuple over no real sequence storage.
        resp = self._post(lambda *a, **k: _lying(tuple))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], False)

    def test_iter_bomb_wrapper_keeps_the_honest_answer(self):
        # Unbound base reads see the real C-level storage: an honest zero
        # in a subclass wrapper still reads as success, never as junk.
        resp = self._post(lambda *a, **k: _IterBombTuple((0, "", "")),
                          action="wake", dev_exists=True)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["action"], "wake")

    def test_raising_runner_wake_degrades_not_500(self):
        resp = self._post(_raising_runner, action="wake", dev_exists=True)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], False)
        self.assertIn("mount failed", body["message"])


class ManageRunnerSeamTests(unittest.TestCase):
    """POST /api/storage/manage/{id} — the disk_action ``run()`` seam."""

    def _post(self, sh_fn, body=None, info=None):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                lambda node: info if info is not None
                else {"MountPoint": "/Volumes/Ext"}))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "root_devices", lambda *a, **k: frozenset()))
            stack.enter_context(mock.patch.object(disk_manage_svc, "sh", sh_fn))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: None))
            return _client().post(
                "/api/storage/manage/disk4s2",
                json=body or {"action": "mount"})

    def test_raising_runner_mount_degrades_not_500(self):
        resp = self._post(_raising_runner)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], False)

    def test_raising_runner_cannot_forge_the_vanished_503(self):
        resp = self._post(_raising_runner)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertNotIn("diskutil_missing", resp.text)

    def test_two_tuple_answer_never_claims_a_confirmed_erase_succeeded(self):
        # A runner that cannot answer is not consent to claim the most
        # destructive mutation in the panel worked.
        resp = self._post(
            lambda *a, **k: (0, "only-two"),
            body={"action": "eraseVolume", "confirm": True,
                  "name": "NewVol", "fs": "ExFAT"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], False)

    def test_iter_bomb_wrapper_keeps_the_honest_answer(self):
        resp = self._post(lambda *a, **k: _IterBombTuple((0, "Mounted", "")))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["message"], "Mounted")


class ManageShadowCopyTests(unittest.TestCase):
    """The plain-dict copies must not carry a live shadow key downstream."""

    def test_shadow_volume_name_key_erase_stays_200_and_reads(self):
        # Pre-fix ``info.get("VolumeName")`` on the confirmed-erase path ran
        # the *stored* shadow key's ``__eq__`` — a raw 500 after the
        # operator had already confirmed.  The laundered exact-str key
        # keeps the honest value, so confirm_name still matches it.
        info = {_ShadowKey("VolumeName"): "Ext"}
        info["MountPoint"] = "/Volumes/Ext"
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_info", lambda node: info))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "root_devices", lambda *a, **k: frozenset()))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "sh", lambda *a, **k: (0, "done", "")))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: None))
            resp = _client().post(
                "/api/storage/manage/disk4s2",
                json={"action": "eraseVolume", "confirm": True,
                      "confirm_name": "Ext", "name": "NewVol", "fs": "ExFAT"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["name"], "NewVol")

    def test_shadow_root_info_key_keeps_the_manage_listing(self):
        # Pre-fix ``root_details.get("ParentWholeDisk")`` detonated the
        # stored shadow key out of list_managed_volumes — the route's catch
        # turned the whole listing into an error body.
        shadow = {_ShadowKey("ParentWholeDisk"): "disk0"}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_plist",
                lambda *a, **k: {"AllDisksAndPartitions": []}))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "physical_whole_disks", lambda *a, **k: ()))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "root_devices", lambda *a, **k: frozenset()))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "root_info", lambda *a, **k: shadow))
            vols = disk_manage_svc.list_managed_volumes()
        self.assertEqual(vols, [])

    def test_plain_info_launders_to_exact_str_keys(self):
        laundered = disk_manage_svc._plain_info(
            {_ShadowKey("VolumeName"): "Ext", "MountPoint": "/"})
        self.assertEqual(laundered.get("VolumeName"), "Ext")
        for key in laundered:
            self.assertIs(type(key), str)
        # The healthy exact-keyed plist passes through without a copy.
        healthy = {"VolumeName": "Ext"}
        self.assertIs(disk_manage_svc._plain_info(healthy), healthy)


class SmartRunnerSeamTests(unittest.TestCase):
    """GET /api/smart and the SMART mutations over a poisoned runner."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(
            nas_storage, "require_admin_browser", lambda request: "admin"))
        smart_test_svc._device_type_cache.clear()
        self.addCleanup(smart_test_svc._device_type_cache.clear)
        smart_test_svc.invalidate()
        self.addCleanup(smart_test_svc.invalidate)

    def test_raising_runner_get_smart_stays_200(self):
        # Pre-fix ``passwordless_available``'s bare unpack re-raised inside
        # overview()'s fan-out — a raw 500 on GET /api/smart.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: ["/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", _raising_runner))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_load_history", lambda: []))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_schedule_cfg", lambda: {}))
            resp = _client().get("/api/smart?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["passwordless_sudo"], False)
        self.assertEqual([d["id"] for d in body["devices"]], ["disk0"])

    def test_raising_runner_start_test_degrades_not_500(self):
        # Pre-fix the sudo spawn's bare unpack was a raw ASGI 500 on
        # POST /api/smart/test before the authorization-sheet fallback
        # could answer; the runner junk must also never forge the
        # confirmed-vanished ``smartctl_missing`` refusal — the binary is
        # present, so the sheet answers instead and its success renders.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: ["/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_capabilities", lambda node, **k: dict(_CAPS_OK)))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "device_type", lambda node: ()))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", _raising_runner))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_smartctl_installed", lambda: True))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "run_admin",
                lambda *a, **k: {"ok": True, "message": "started"}))
            resp = _client().post(
                "/api/smart/test", json={"device": "/dev/disk0", "kind": "short"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertNotIn("smartctl_missing", resp.text)

    def test_raising_runner_start_test_denied_sheet_is_the_coded_refusal(self):
        # With the sheet denied the route's funnel answers the same coded
        # ``admin.failed`` body an honest sudo denial earns — a rendered
        # refusal, never the raw ASGI 500 the bare unpack used to produce.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: ["/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_capabilities", lambda node, **k: dict(_CAPS_OK)))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "device_type", lambda node: ()))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", _raising_runner))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_smartctl_installed", lambda: True))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "run_admin",
                lambda *a, **k: {"ok": False, "message": "denied"}))
            resp = _client().post(
                "/api/smart/test", json={"device": "/dev/disk0", "kind": "short"})
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")
        self.assertNotIn("smartctl_missing", resp.text)
        # And the service itself answers the plain degraded body.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: ["/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_capabilities", lambda node, **k: dict(_CAPS_OK)))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "device_type", lambda node: ()))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", _raising_runner))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_smartctl_installed", lambda: True))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "run_admin",
                lambda *a, **k: {"ok": False, "message": "denied"}))
            result = smart_test_svc.start_test("/dev/disk0", "short")
        self.assertIs(result["ok"], False)
        self.assertNotEqual(result.get("error"), "smartctl_missing")

    def test_two_tuple_answer_abort_degrades_not_500(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: ["/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "device_type", lambda node: ()))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", lambda *a, **k: (0, "only-two")))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "run_admin",
                lambda *a, **k: {"ok": True, "message": "aborted"}))
            resp = _client().post("/api/smart/abort", json={"device": "/dev/disk0"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)

    def test_honest_vanished_sentinel_still_confirms_on_disk(self):
        # The confirmed-vanished refusal is untouched: sh()'s exact
        # ``(-1, "", "not found")`` sentinel plus a fresh disk probe that
        # answers "gone" still reads as smartctl_missing, and the same
        # sentinel with the binary on disk keeps the sheet fallback.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: ["/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_capabilities", lambda node, **k: dict(_CAPS_OK)))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "device_type", lambda node: ()))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", lambda *a, **k: (-1, "", "not found")))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_smartctl_installed", lambda: False))
            result = smart_test_svc.start_test("/dev/disk0", "short")
        self.assertEqual(result.get("error"), "smartctl_missing")
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: ["/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_capabilities", lambda node, **k: dict(_CAPS_OK)))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "device_type", lambda node: ()))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", lambda *a, **k: (-1, "", "not found")))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_smartctl_installed", lambda: True))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "run_admin",
                lambda *a, **k: {"ok": False, "message": "denied"}))
            result = smart_test_svc.start_test("/dev/disk0", "short")
        self.assertNotEqual(result.get("error"), "smartctl_missing")


class ScheduleShadowCopyTests(unittest.TestCase):
    """``_schedule_cfg``'s copy must not carry a live shadow key downstream."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(
            nas_storage, "require_admin_browser", lambda request: "admin"))
        smart_test_svc.invalidate()
        self.addCleanup(smart_test_svc.invalidate)

    def _cfg(self, stored):
        return {"settings": {"smart_schedule": stored}}

    def test_shadow_interval_key_get_smart_stays_200_and_reads(self):
        # Pre-fix ``stored.get("interval")`` ran the *stored* shadow key's
        # ``__eq__`` — a raw 500 on GET /api/smart, and the same raise
        # escaped schedule_due() inside the scheduler tick.  The laundered
        # exact-str key keeps the honest value.
        stored = {_ShadowKey("interval"): "weekly"}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "cfg", lambda: self._cfg(stored)))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: []))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", lambda *a, **k: (1, "", "")))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_load_history", lambda: []))
            resp = _client().get("/api/smart?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["schedule"]["interval"], "weekly")

    def test_shadow_last_run_key_schedule_put_stays_200(self):
        # Pre-fix set_schedule's ``current.get("last_run")`` detonated the
        # stored shadow key — a raw 500 on PUT /api/smart/schedule.
        stored = {_ShadowKey("last_run"): 5.0}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "cfg", lambda: self._cfg(stored)))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: ["/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "update_settings", lambda *a, **k: None))
            resp = _client().put(
                "/api/smart/schedule",
                json={"interval": "weekly", "kind": "short",
                      "devices": ["/dev/disk0"]})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["schedule"]["last_run"], 5.0)

    def test_shadow_keys_never_escape_the_scheduler_tick(self):
        stored = {_ShadowKey("interval"): "weekly",
                  "devices": ["/dev/disk0"], "last_run": 0}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "cfg", lambda: self._cfg(stored)))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: ["/dev/disk0"]))
            due = smart_test_svc.schedule_due()
        self.assertIs(due, True)


class VolumeRowShadowCopyTests(unittest.TestCase):
    """``_volume_row``'s copy: the shadowed field still reads; the row and
    its healthy siblings survive."""

    _ROW_TAIL = {
        "filesystem": "/dev/disk4s1", "device": "/dev/disk4s1",
        "disk_id": "disk4", "kind": "external",
        "total_gb": 100.0, "used_gb": 40.0, "avail_gb": 60.0, "pct": 40,
    }

    def test_shadow_mount_key_row_survives_on_light_overview(self):
        # Pre-fix the ``dict(raw)`` copy kept the shadow key live and the
        # ``row["mount"] = ...`` assignment detonated it — the whole row
        # dropped (guarded) where only the key's spelling was hostile.
        row = {_ShadowKey("mount"): "/Volumes/Data"}
        row.update(self._ROW_TAIL)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "list_volumes", lambda: [row]))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", lambda: []))
            resp = _client().get("/api/storage?light=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(len(body["volumes"]), 1)
        self.assertEqual(body["volumes"][0]["mount"], "/Volumes/Data")

    def test_volume_row_launders_to_exact_str_keys(self):
        row = {_ShadowKey("total_gb"): 100.0, "mount": "/Volumes/Data"}
        cleaned = storage_svc._volume_row(row)
        self.assertIsNotNone(cleaned)
        self.assertEqual(cleaned["total_gb"], 100.0)
        for key in cleaned:
            self.assertIs(type(key), str)


class ProbeDiskAnswerShapeTests(unittest.TestCase):
    """``_probe_disk`` over a wrong-shape answer: the honest smartctl
    failure branch answers, never an unpack-text exception row — while a
    *raising* runner keeps its own message in the guarded error row (the
    test_hotpath contract, deliberately unchanged)."""

    def test_two_tuple_answer_takes_the_honest_failure_branch(self):
        with mock.patch.object(storage_svc, "sh", lambda *a, **k: (0, "only-two")):
            row = storage_svc._probe_disk("disk9")
        self.assertEqual(row["id"], "disk9")
        self.assertEqual(row["error"], "smartctl unavailable or needs sudo")

    def test_raising_runner_keeps_its_message_in_the_guarded_row(self):
        with mock.patch.object(storage_svc, "sh", _raising_runner):
            row = storage_svc._probe_disk("disk9")
        self.assertEqual(row["id"], "disk9")
        self.assertIn("runner bomb", row["error"])

    def test_raising_runner_smart_devices_keeps_the_fallback_listing(self):
        # smart_devices has no per-row catch above it on the listing read;
        # pre-fix the raise wiped every disk row from GET /api/storage.
        storage_svc.invalidate_smart()
        self.addCleanup(storage_svc.invalidate_smart)
        with mock.patch.object(storage_svc, "sh", _raising_runner):
            rows = storage_svc.smart_devices()
        self.assertEqual([r["id"] for r in rows], ["disk0"])


class DfTableRunnerSeamTests(unittest.TestCase):
    """The shared mount table over a poisoned runner."""

    def setUp(self):
        disk_snapshot.invalidate_disks()
        self.addCleanup(disk_snapshot.invalidate_disks)

    def test_raising_runner_reads_as_a_failed_table(self):
        # Pre-fix the raise unwound out of df_lines into all three consumer
        # modules at once; a failed read (empty, not cached) is the honest
        # degrade this module already ships.
        with mock.patch.object(disk_snapshot, "sh", _raising_runner):
            self.assertEqual(disk_snapshot.df_lines(force=True), ())

    def test_iter_bomb_wrapper_keeps_the_honest_table(self):
        answer = _IterBombTuple(
            (0, "hdr\n/dev/disk0s2 1000000 400000 600000 40% /", ""))
        with mock.patch.object(disk_snapshot, "sh", lambda *a, **k: answer):
            lines = disk_snapshot.df_lines(force=True)
        self.assertEqual(len(lines), 2)
        self.assertIn("/dev/disk0s2", lines[1])

    def test_raising_runner_physical_disks_text_fallback_degrades(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_snapshot, "run_bytes", _raising_runner))
            stack.enter_context(mock.patch.object(
                disk_snapshot, "sh", _raising_runner))
            self.assertEqual(disk_snapshot.physical_whole_disks(force=True), ())


class Sh3HelperPins(unittest.TestCase):
    """Every module's ``_sh3``/``_spawn`` must launder to the same shape."""

    def test_exact_answers_pass_through_untouched(self):
        for module in _MODULES:
            self.assertEqual(module._sh3((0, "a", "b")), (0, "a", "b"))
            # The vanished-spawn sentinel is an honest answer and survives.
            self.assertEqual(
                module._sh3((-1, "", "not found")), (-1, "", "not found"))

    def test_subclass_wrapper_keeps_the_honest_storage(self):
        for module in _MODULES:
            self.assertEqual(
                module._sh3(_IterBombTuple((0, "a", "b"))), (0, "a", "b"))

    def test_junk_degrades_to_minus_255_never_the_sentinel(self):
        for module in _MODULES:
            for junk in (_lying(tuple), _lying(list), (0, "only-two"),
                         (0, "a", "b", "c"), "junk", None, 7):
                rc, out, err = module._sh3(junk)
                self.assertEqual((rc, out, err), (-255, "", ""))
                self.assertNotEqual(rc, -1)

    def test_spawn_absorbs_a_raising_runner(self):
        for module in _MODULES:
            with mock.patch.object(module, "sh", _raising_runner):
                self.assertEqual(module._spawn(["/bin/true"], 5), (-255, "", ""))


class StaysImmunePins(unittest.TestCase):
    """Hunted vectors found already sealed — pinned so they stay so."""

    def test_fifo_history_journal_reads_as_empty(self):
        # read_text_capped opens O_NONBLOCK and refuses a non-regular file
        # with OSError(EINVAL); a leftover FIFO at the journal path used to
        # park the request until a writer appeared.
        if not hasattr(os, "mkfifo"):
            self.skipTest("no mkfifo on this platform")
        root = Path(tempfile.mkdtemp(prefix="storage11-fifo-"))
        fifo = root / "smart-tests.json"
        os.mkfifo(fifo)
        with mock.patch.object(smart_test_svc, "HISTORY_PATH", fifo):
            resp = _client().get("/api/smart/history")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["history"], [])

    def test_over_cap_history_int_drops_the_number_not_the_journal(self):
        # ``json.loads`` of a >4300-digit number is ValueError for the whole
        # document; the parse_int hook drops just the number.
        root = Path(tempfile.mkdtemp(prefix="storage11-hist-"))
        journal = root / "smart-tests.json"
        journal.write_text(
            '[{"ts": %s, "device": "/dev/disk0", "kind": "short", "ok": true}]'
            % ("1" * 5000),
            encoding="utf-8",
        )
        with mock.patch.object(smart_test_svc, "HISTORY_PATH", journal):
            resp = _client().get("/api/smart/history")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(len(body["history"]), 1)
        self.assertIsNone(body["history"][0]["ts"])
        self.assertEqual(body["history"][0]["device"], "/dev/disk0")

    def test_garbage_plist_bytes_read_as_no_info(self):
        # plistlib raises ExpatError (not ValueError) on garbage; both
        # parsers keep it inside their own catch.
        with mock.patch.object(
            disk_manage_svc, "run_bytes",
            lambda *a, **k: (0, b"this is not a plist", b""),
        ):
            self.assertIsNone(disk_manage_svc._plist(["diskutil", "info"]))
        with mock.patch.object(
            disk_power_svc, "run_bytes",
            lambda *a, **k: (0, b"this is not a plist", b""),
        ):
            self.assertEqual(disk_power_svc._diskutil_info("disk4"), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
