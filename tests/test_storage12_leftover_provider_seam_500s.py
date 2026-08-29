"""Twelfth leftover-500s sweep of the Storage read/mutation family.

storage11 sealed the ``sh`` runner seam (answer shape, raising runner) and
the plain-dict shadow copies.  This hunt walked the *other* providers those
routes lean on — the authorization sheet, the transport-flag probe, the
capabilities probe, the diskutil-info cache and the settings writer — over
``create_app()`` with ``raise_server_exceptions=False``, and found these
leaks one provider above everything storage10/11 built:

* raw 500s on the sheet seam: ``start_test`` / ``abort_test`` laundered the
  run_admin *result* (storage11) but called the sheet bare, so a sheet that
  *raises* instead of answering unwound out of POST /api/smart/test and
  POST /api/smart/abort where a denied sheet already earns the coded
  ``admin.failed`` refusal through the route funnel.

* raw 500s on the transport-flag seam: every consumer splatted the raw
  ``device_type`` answer (``list(device_type(node))``, ``[*flags]``,
  ``" ".join(...)``).  A provider that raises — or answers a lying
  ``__class__`` impostor claiming tuple, an ``__iter__``-bomb subclass, or
  non-text entries — detonated POST /api/smart/test and /api/smart/abort
  (and ``_capabilities`` / ``_smartctl`` reached the same splat from
  inside them).

* raw 500s on the capabilities seam: ``start_test`` read the raw probe
  bare (``caps["available"]``, ``test not in caps["supported"]``), so a
  probe that raises, a short/impostor mapping (KeyError), or a
  str-subclass ``supported`` entry whose ``__eq__`` fires during the
  membership walk each 500'd POST /api/smart/test where junk answers earn
  coded refusals.

* a raw 500 on the settings-writer seam: ``set_schedule`` called
  ``update_settings`` bare, so a writer that raises blew
  PUT /api/smart/schedule where a failed persist should ride the funnel
  into the coded ``admin.failed`` refusal.

* a raw 500 on the info-cache seam: ``disk_action`` read
  ``_plain_info(_diskutil_info(did))`` with the *call* unguarded, so a
  provider that raises 500'd POST /api/storage/manage/{id} — and dropped
  every node from the manage listing walk — where the wedged-diskutil
  contract this module already ships is ``{}`` (node renders without
  details, eligibility gates keep failing closed).

* the guarded whole-table wipe on the OrbStack-home seam: ``list_volumes``
  joined ``user_home() / "OrbStack"`` bare, so a raising or junk non-Path
  home emptied the whole volume table (through ``storage_overview``'s
  catch) on GET /api/storage?light where only the home hint is unreadable.

Fixes: a guarded ``run_admin`` call that degrades to the same denied-sheet
result shape, a ``_type_flags`` launderer (exact tuples of exact base strs;
junk reads as smartctl's auto transport, never a torn ``-d nvme`` pair), a
``_probe_caps`` view whose unreadable answer is the existing
``probe_failed`` shape (never ``no_smart_passthrough``, so junk cannot
forge the confirmed-vanished ``smartctl_missing`` refusal), a guarded
``update_settings`` write answering ``{"ok": False, "error": "failed"}``,
a ``_info_read`` guarded provider read answering ``{}``, and a guarded
OrbStack-home join.

No new i18n keys: every refusal reuses the existing coded errors.
"""
from __future__ import annotations

import json
import unittest
from contextlib import ExitStack
from unittest import mock

from hub import disk_manage_svc, smart_test_svc, storage_svc
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


def _raising(*a, **k):
    """A leftover provider that raises instead of answering."""
    raise RuntimeError("provider bomb")


class _IterBombTuple(tuple):
    """Honest tuple storage behind a bound ``__iter__`` bomb: the unbound
    base read must recover the real answer, not degrade it."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


def _lying(claim):
    """An object whose ``__class__`` property *claims* a builtin it is not."""

    class _Lying:
        @property
        def __class__(self):
            return claim

    return _Lying()


class _ShadowKey(str):
    """A str-subclass whose ``__eq__`` raises: membership walks and dict
    probes that hash to the same slot run the *stored* entry's comparison."""

    def __eq__(self, other):
        raise RuntimeError("shadow eq bomb")

    __hash__ = str.__hash__


_CAPS_OK = {
    "readable": True, "available": True, "supported": ["short"],
    "reason": "", "device_type": "auto", "estimated_minutes": {}, "detail": "",
}


class _SmartRouteCase(unittest.TestCase):
    """Shared harness for the SMART mutation routes."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(
            nas_storage, "require_admin_browser", lambda request: "admin"))
        self.stack.enter_context(mock.patch.object(
            smart_test_svc, "_device_nodes", lambda: ["/dev/disk0"]))
        smart_test_svc._device_type_cache.clear()
        self.addCleanup(smart_test_svc._device_type_cache.clear)
        smart_test_svc.invalidate()
        self.addCleanup(smart_test_svc.invalidate)

    def _smart(self, **over):
        for name, value in over.items():
            self.stack.enter_context(mock.patch.object(smart_test_svc, name, value))


class SheetSeamTests(_SmartRouteCase):
    """The run_admin call itself over a sheet that raises."""

    def test_raising_sheet_start_test_is_the_coded_refusal(self):
        # Pre-fix the bare ``run_admin(...)`` call re-raised the sheet's own
        # exception — a raw ASGI 500 on POST /api/smart/test where a denied
        # sheet already earns the coded ``admin.failed`` body.
        self._smart(
            _capabilities=lambda node, **k: dict(_CAPS_OK),
            device_type=lambda node: (),
            sh=lambda *a, **k: (1, "", "denied"),
            _smartctl_installed=lambda: True,
            run_admin=_raising,
        )
        resp = _client().post(
            "/api/smart/test", json={"device": "/dev/disk0", "kind": "short"})
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")
        self.assertNotIn("smartctl_missing", resp.text)

    def test_raising_sheet_abort_is_the_coded_refusal(self):
        self._smart(
            device_type=lambda node: (),
            sh=lambda *a, **k: (1, "", "denied"),
            _smartctl_installed=lambda: True,
            run_admin=_raising,
        )
        resp = _client().post("/api/smart/abort", json={"device": "/dev/disk0"})
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")
        self.assertNotIn("smartctl_missing", resp.text)

    def test_honest_sheet_success_still_renders(self):
        # The healthy fallback is untouched: a sheet that answers ok keeps
        # the 200 success body.
        self._smart(
            _capabilities=lambda node, **k: dict(_CAPS_OK),
            device_type=lambda node: (),
            sh=lambda *a, **k: (1, "", "denied"),
            _smartctl_installed=lambda: True,
            run_admin=lambda *a, **k: {"ok": True, "message": "started"},
        )
        resp = _client().post(
            "/api/smart/test", json={"device": "/dev/disk0", "kind": "short"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)

    def test_raising_sheet_never_claims_the_test_started(self):
        # A sheet that cannot answer is not consent to claim the self-test
        # began: the service body itself reads ok: False.
        self._smart(
            _capabilities=lambda node, **k: dict(_CAPS_OK),
            device_type=lambda node: (),
            sh=lambda *a, **k: (1, "", "denied"),
            _smartctl_installed=lambda: True,
            run_admin=_raising,
        )
        result = smart_test_svc.start_test("/dev/disk0", "short")
        self.assertIs(result["ok"], False)
        self.assertNotEqual(result.get("error"), "smartctl_missing")


class FlagProviderSeamTests(_SmartRouteCase):
    """The transport-flag provider over every wrong shape it can answer."""

    def _post_test(self, provider):
        self._smart(
            _capabilities=lambda node, **k: dict(_CAPS_OK),
            device_type=provider,
            sh=lambda *a, **k: (0, "started", ""),
            _smartctl_installed=lambda: True,
        )
        return _client().post(
            "/api/smart/test", json={"device": "/dev/disk0", "kind": "short"})

    def test_raising_provider_start_test_degrades_to_auto_not_500(self):
        # Pre-fix ``list(device_type(node))`` re-raised the provider's own
        # exception — a raw 500 on POST /api/smart/test.
        resp = self._post_test(_raising)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)

    def test_lying_tuple_provider_degrades_to_auto_not_500(self):
        # An impostor claiming tuple over no real sequence storage used to
        # TypeError the same splat.
        resp = self._post_test(lambda node: _lying(tuple))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)

    def test_junk_entry_provider_abort_degrades_not_500(self):
        self._smart(
            device_type=lambda node: ("-d", 7),
            sh=lambda *a, **k: (0, "aborted", ""),
            _smartctl_installed=lambda: True,
        )
        resp = _client().post("/api/smart/abort", json={"device": "/dev/disk0"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)

    def test_type_flags_exact_answers_pass_through_untouched(self):
        with mock.patch.object(
            smart_test_svc, "device_type", lambda node: ("-d", "nvme")
        ):
            self.assertEqual(
                smart_test_svc._type_flags("/dev/disk0"), ("-d", "nvme"))
        with mock.patch.object(smart_test_svc, "device_type", lambda node: ()):
            self.assertEqual(smart_test_svc._type_flags("/dev/disk0"), ())

    def test_type_flags_subclass_wrapper_keeps_the_honest_storage(self):
        # Unbound base reads see the real C-level storage: an iter-bomb
        # wrapper over honest flags — and an honest str-subclass flag —
        # both keep their text.
        with mock.patch.object(
            smart_test_svc, "device_type",
            lambda node: _IterBombTuple(("-d", "nvme")),
        ):
            self.assertEqual(
                smart_test_svc._type_flags("/dev/disk0"), ("-d", "nvme"))
        with mock.patch.object(
            smart_test_svc, "device_type",
            lambda node: ("-d", _ShadowKey("nvme")),
        ):
            flags = smart_test_svc._type_flags("/dev/disk0")
            self.assertEqual(flags, ("-d", "nvme"))
            for flag in flags:
                self.assertIs(type(flag), str)

    def test_type_flags_junk_degrades_whole_never_a_torn_pair(self):
        # A half-readable ``("-d", <junk>)`` must never hand smartctl a lone
        # ``-d``: every junk shape reads as the auto transport.
        for junk in (
            _lying(tuple), _lying(list), "nvme", 7, None,
            ("-d", 7), ("-d", _lying(str)), ["-d", object()],
        ):
            with mock.patch.object(
                smart_test_svc, "device_type", lambda node, j=junk: j
            ):
                self.assertEqual(smart_test_svc._type_flags("/dev/disk0"), ())
        with mock.patch.object(smart_test_svc, "device_type", _raising):
            self.assertEqual(smart_test_svc._type_flags("/dev/disk0"), ())


class CapsProbeSeamTests(_SmartRouteCase):
    """The capabilities probe over every wrong shape it can answer."""

    def _post_test(self, caps_provider, installed=True):
        self._smart(
            _capabilities=caps_provider,
            device_type=lambda node: (),
            sh=lambda *a, **k: (0, "started", ""),
            _smartctl_installed=lambda: installed,
        )
        return _client().post(
            "/api/smart/test", json={"device": "/dev/disk0", "kind": "short"})

    def test_raising_probe_is_the_coded_unsupported_refusal(self):
        # Pre-fix ``caps["available"]`` re-raised the probe's own exception
        # — a raw 500 on POST /api/smart/test.
        resp = self._post_test(_raising)
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "smart.unsupported")
        self.assertEqual(payload["detail"]["params"]["reason"], "probe_failed")

    def test_short_mapping_probe_refuses_coded_not_keyerror(self):
        resp = self._post_test(lambda node, **k: {})
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "smart.unsupported")

    def test_lying_dict_probe_refuses_coded_not_500(self):
        resp = self._post_test(lambda node, **k: _lying(dict))
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "smart.unsupported")

    def test_raising_probe_cannot_forge_the_vanished_503(self):
        # ``probe_failed`` is never ``no_smart_passthrough``: even on a host
        # where the binary really is absent, a probe that cannot answer must
        # not read as "smartctl is gone" — that classification stays with
        # the honest sentinel + fresh disk probe.
        resp = self._post_test(_raising, installed=False)
        self.assertNotIn("smartctl_missing", resp.text)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_capabilities", _raising))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "device_type", lambda node: ()))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_smartctl_installed", lambda: False))
            result = smart_test_svc.start_test("/dev/disk0", "short")
        self.assertNotEqual(result.get("error"), "smartctl_missing")

    def test_shadow_supported_entry_still_matches_and_starts(self):
        # Pre-fix ``test not in caps["supported"]`` ran the *stored*
        # entry's ``__eq__`` — a raw 500 on POST /api/smart/test.  The
        # laundered exact-str entry keeps the honest text, so the kind
        # still matches and the test starts.
        caps = dict(_CAPS_OK)
        caps["supported"] = [_ShadowKey("short")]
        resp = self._post_test(lambda node, **k: dict(caps))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)

    def test_honest_vanished_probe_still_confirms_on_disk(self):
        # The confirmed-vanished refusal is untouched: the honest
        # ``no_smart_passthrough`` reason plus a fresh disk probe answering
        # "gone" still reads as smartctl_missing.
        caps = {"readable": False, "available": False, "supported": [],
                "reason": "no_smart_passthrough", "device_type": "auto",
                "estimated_minutes": {}, "detail": ""}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_capabilities", lambda node, **k: dict(caps)))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "device_type", lambda node: ()))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_smartctl_installed", lambda: False))
            result = smart_test_svc.start_test("/dev/disk0", "short")
        self.assertEqual(result.get("error"), "smartctl_missing")

    def test_probe_caps_honest_answers_pass_through(self):
        with mock.patch.object(
            smart_test_svc, "_capabilities", lambda node, **k: dict(_CAPS_OK)
        ):
            view = smart_test_svc._probe_caps("/dev/disk0")
        self.assertIs(view["available"], True)
        self.assertEqual(view["reason"], "")
        self.assertEqual(view["supported"], ["short"])

    def test_probe_caps_shadow_key_fails_closed(self):
        # A stored shadow key over the ``available`` slot makes the field
        # unreadable: the view fails closed to the probe_failed shape
        # instead of raising out of the unbound read.
        caps = {_ShadowKey("available"): True, "reason": "",
                "supported": ["short"]}
        with mock.patch.object(
            smart_test_svc, "_capabilities", lambda node, **k: caps
        ):
            view = smart_test_svc._probe_caps("/dev/disk0")
        self.assertIs(view["available"], False)
        self.assertEqual(view["reason"], "probe_failed")


class SchedulePersistSeamTests(_SmartRouteCase):
    """The settings writer over a write that raises."""

    def _put(self):
        return _client().put(
            "/api/smart/schedule",
            json={"interval": "weekly", "kind": "short",
                  "devices": ["/dev/disk0"]})

    def test_raising_writer_is_the_coded_refusal_not_500(self):
        # Pre-fix the bare ``update_settings(...)`` re-raised the writer's
        # own exception — a raw ASGI 500 on PUT /api/smart/schedule.
        self._smart(update_settings=_raising)
        resp = self._put()
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_raising_writer_never_claims_the_schedule_saved(self):
        self._smart(update_settings=_raising)
        result = smart_test_svc.set_schedule(
            interval="weekly", kind="short", devices=["/dev/disk0"])
        self.assertIs(result["ok"], False)

    def test_honest_writer_still_saves(self):
        self._smart(update_settings=lambda *a, **k: None)
        resp = self._put()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)


class ManageInfoProviderSeamTests(unittest.TestCase):
    """The diskutil-info cache over a provider that raises."""

    def _post(self, body=None, device="disk4s2"):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_info", _raising))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "root_devices", lambda *a, **k: frozenset()))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "sh", lambda *a, **k: (0, "Mounted", "")))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: None))
            return _client().post(
                f"/api/storage/manage/{device}",
                json=body or {"action": "mount"})

    def test_raising_info_mount_answers_the_no_info_contract_not_500(self):
        # Pre-fix the bare ``_plain_info(_diskutil_info(did))`` re-raised
        # the provider's own exception — a raw 500 on
        # POST /api/storage/manage/{id} where a wedged diskutil already
        # reads as ``{}`` and mount proceeds on its own answer.
        resp = self._post()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["message"], "Mounted")

    def test_raising_info_keeps_the_boot_disk_refusal(self):
        # Fail-closed pin: an unreadable info answer must never weaken the
        # disk0 protection — the coded refusal still fires from the id
        # alone.
        resp = self._post(device="disk0s2")
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "disk.system_protected")

    def test_raising_info_keeps_the_manage_listing_rows(self):
        # Pre-fix the raise dropped every node through the per-node catch —
        # with a single disk, the whole listing — where ``{}`` keeps the
        # node rendering without details.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_plist",
                lambda *a, **k: {
                    "AllDisksAndPartitions": [{"DeviceIdentifier": "disk4"}]
                }))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "physical_whole_disks",
                lambda *a, **k: ("disk4",)))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "root_devices", lambda *a, **k: frozenset()))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "root_info", lambda *a, **k: {}))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_info", _raising))
            vols = disk_manage_svc.list_managed_volumes()
        self.assertEqual([v["id"] for v in vols], ["disk4"])
        self.assertEqual(vols[0]["name"], "disk4")

    def test_info_read_launders_shapes_and_absorbs_the_raise(self):
        with mock.patch.object(disk_manage_svc, "_diskutil_info", _raising):
            self.assertEqual(disk_manage_svc._info_read("disk4"), {})
        healthy = {"MountPoint": "/Volumes/Ext"}
        with mock.patch.object(
            disk_manage_svc, "_diskutil_info", lambda node: healthy
        ):
            self.assertIs(disk_manage_svc._info_read("disk4"), healthy)


class OrbstackHomeSeamTests(unittest.TestCase):
    """The home provider must not empty the volume table."""

    _TABLE = ("hdr", "/dev/disk0s2 1000000 400000 600000 40% /")

    def _get(self, home_fn):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "user_home", home_fn))
            stack.enter_context(mock.patch.object(
                storage_svc, "df_lines", lambda *a, **k: self._TABLE))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", lambda: []))
            return _client().get("/api/storage?light=true")

    def test_junk_home_keeps_the_volume_table(self):
        # Pre-fix the bare ``home / "OrbStack"`` join TypeError'd on a junk
        # non-Path home and storage_overview's catch wiped the *whole*
        # volume table to [] where only the OrbStack hint is unreadable.
        resp = self._get(lambda: "junk-not-a-path")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual([v["mount"] for v in body["volumes"]], ["/"])

    def test_raising_home_keeps_the_volume_table(self):
        resp = self._get(_raising)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual([v["mount"] for v in body["volumes"]], ["/"])


class StaysImmunePins(unittest.TestCase):
    """Hunted vectors found already sealed — pinned so they stay so."""

    def test_raising_cfg_get_smart_stays_200(self):
        # The try-around-cfg() union guard (storage11) still absorbs a
        # provider that raises: GET /api/smart keeps its 200 shape.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                nas_storage, "require_admin_browser", lambda request: "admin"))
            stack.enter_context(mock.patch.object(smart_test_svc, "cfg", _raising))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: []))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", lambda *a, **k: (1, "", "")))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_load_history", lambda: []))
            smart_test_svc.invalidate()
            self.addCleanup(smart_test_svc.invalidate)
            resp = _client().get("/api/smart?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["schedule"]["interval"], "off")

    def test_sh3_junk_still_degrades_to_minus_255_never_the_sentinel(self):
        # The storage11 union guards stay pinned: junk answers degrade to
        # the (-255, "", "") shape and can never forge sh()'s -1 sentinel.
        for module in (storage_svc, disk_manage_svc, smart_test_svc):
            for junk in (_lying(tuple), (0, "only-two"), None):
                rc, out, err = module._sh3(junk)
                self.assertEqual((rc, out, err), (-255, "", ""))
                self.assertNotEqual(rc, -1)
            self.assertEqual(module._sh3((-1, "", "not found")),
                             (-1, "", "not found"))

    def test_raising_device_type_in_the_overview_keeps_the_disk_row(self):
        # The per-disk report catch keeps GET /api/smart rendering a row
        # for a disk whose transport probe raises — and the row keeps the
        # probe's own message in the guarded ``probe_failed`` shape (the
        # test_disk_storage_leftovers contract, deliberately unchanged by
        # the mutation-path launderer).
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                nas_storage, "require_admin_browser", lambda request: "admin"))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", lambda: ["/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "device_type", _raising))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", lambda *a, **k: (1, "", "")))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_load_history", lambda: []))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_schedule_cfg", lambda: {}))
            smart_test_svc.invalidate()
            self.addCleanup(smart_test_svc.invalidate)
            resp = _client().get("/api/smart?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual([d["id"] for d in body["devices"]], ["disk0"])
        self.assertEqual(
            body["devices"][0]["capabilities"]["reason"], "probe_failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
