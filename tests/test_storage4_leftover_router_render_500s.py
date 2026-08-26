"""Fourth leftover-500s sweep of the Storage routes, over the real mounted app.

The hunted classes (collections that pass ``isinstance`` but refuse
*iteration*, already-int over-cap numbers, lone UTF-8 surrogates) were
re-reproduced against ``create_app()`` with ``raise_server_exceptions=False``.
The NAS sweep (test_nas4_leftover_iterbomb_tmutil_503_500s) sealed those
classes in ``nas_common`` / ``snapshots_svc`` / ``raid_svc`` /
``smart_test_svc``; this hunt found the storage router and its own sanitizer
were skipped.  Each of these was a live HTTP 500 on the pre-fix tree:

* ``storage_svc._jsonable`` iterated ``value.items()`` and sequence members
  unguarded — the exact class the NAS/UPS/Gateway sweeps fixed everywhere
  else: a dict subclass whose ``items()`` raises, or a list subclass whose
  ``__iter__`` raises, passed the ``isinstance`` gate inside a SMART row or
  a volume row and 500'd GET /api/storage?light=true outright.  On the full
  page the same raise fell into the router's overview fallback, which wiped
  the volume table to ``{"volumes": [], "disks": [], "error": …}`` — the
  whole storage page lost to one unreadable field.  Fixed by materializing
  the iteration under its own guard: the unreadable field collapses to
  None, its siblings (and the page) survive;
* ``hub/routers/storage.py`` pasted the ``power_disks`` / ``managed``
  sections and both mutation results into the response body verbatim, with
  no sanitizer at all — unlike every NAS sibling route, whose body passes
  ``nas_common._jsonable`` via ``raise_service_error``.  An over-cap
  *already-int* (YAML/plist hex loads uncapped through ``int(x, 16)``, so
  ``str()`` / ``json.dumps`` raise the digit-cap ValueError), a lone
  ``\\ud800``, or an iteration bomb riding a service result 500'd
  GET /api/storage, GET /api/storage/disks, GET /api/storage/manage,
  POST /api/storage/disks/{id}/power and POST /api/storage/manage/{id}.
  The router now renders those payloads through the shared sanitizer.
"""
from __future__ import annotations

import json
import plistlib
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import storage_svc  # noqa: E402
from hub.routers import storage as storage_router  # noqa: E402

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


class _IterBombList(list):
    """Passes ``isinstance(x, list)``; raises the moment it is iterated."""

    def __iter__(self):
        raise ValueError("iteration bomb")


class _ItemsBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises the moment items() is read."""

    def items(self):
        raise ValueError("items bomb")


#: A complete, well-formed volume row for list_volumes fakes: the point of
#: the page-survival pins is that *this* row keeps rendering.
_GOOD_VOLUME = {
    "filesystem": "/dev/disk4s1", "device": "/dev/disk4s1",
    "disk_id": "disk4", "mount": "/Volumes/Data", "kind": "external",
    "total_gb": 100.0, "used_gb": 40.0, "avail_gb": 60.0, "pct": 40,
}


class StorageJsonableIterationContractTests(unittest.TestCase):
    """The sanitizer's field-isolation contract (fails pre-fix).

    Same contract its NAS siblings already pin
    (test_nas4 ``test_jsonable_field_isolation_contract``): the unreadable
    field collapses to None, its siblings survive.
    """

    def test_items_bomb_salvages_the_field_not_the_row(self):
        # storage6 upgraded the sanitizer to the modules5 unbound
        # ``dict.items`` view (the shares6/nas_common pattern): the hostile
        # override cannot fire, so the real C-level storage survives instead
        # of collapsing to None.  The original point stands either way: the
        # row keeps rendering.
        row = storage_svc._jsonable({
            "mount": "/Volumes/Data",
            "extras": _ItemsBombDict({"x": 1}),
            "pct": 40,
        })
        _starlette(row)
        self.assertEqual(row["mount"], "/Volumes/Data")
        self.assertEqual(row["extras"], {"x": 1})
        self.assertEqual(row["pct"], 40)

    def test_iter_bomb_collapses_the_field_not_the_row(self):
        row = storage_svc._jsonable({
            "mount": "/Volumes/Data",
            "attrs": _IterBombList(["a"]),
            "pct": 40,
        })
        _starlette(row)
        self.assertEqual(row["mount"], "/Volumes/Data")
        self.assertIsNone(row["attrs"])
        self.assertEqual(row["pct"], 40)


class StorageLightIterationBombTests(unittest.TestCase):
    """GET /api/storage?light=true is the overview itself: pre-fix an
    iteration bomb raised out of ``storage_svc._jsonable`` as an unhandled
    500 with no JSON body."""

    def _light(self, *, volumes, disks):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "list_volumes", return_value=volumes))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", return_value=disks))
            return _client().get("/api/storage?light=true")

    def test_items_bomb_smart_dict_salvages_not_the_route(self):
        # storage6: the unbound ``dict.items`` view salvages the real
        # storage, so the SMART block survives instead of collapsing to
        # None.  The route answering 200 is the invariant either way.
        resp = self._light(volumes=[], disks=[
            {"device": "/dev/disk0", "id": "disk0",
             "smart": _ItemsBombDict({"health": "PASSED"})},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["disks"][0]["device"], "/dev/disk0")
        self.assertEqual(body["disks"][0]["smart"], {"health": "PASSED"})

    def test_iter_bomb_smart_attrs_drop_alone(self):
        resp = self._light(volumes=[], disks=[
            {"device": "/dev/disk0", "id": "disk0",
             "smart": {"attrs": _IterBombList(["x"]), "health": "PASSED"}},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        smart = body["disks"][0]["smart"]
        self.assertIsNone(smart["attrs"])
        # The sibling field survives — the whole point of the guard.
        self.assertEqual(smart["health"], "PASSED")

    def test_iter_bomb_extra_key_keeps_the_volume_row(self):
        # _volume_row copies the dict shallowly, so a bomb under a key it
        # does not sanitize rides through to the final _jsonable.
        resp = self._light(
            volumes=[dict(_GOOD_VOLUME, extras=_IterBombList(["y"]))],
            disks=[],
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(len(body["volumes"]), 1)
        self.assertEqual(body["volumes"][0]["mount"], "/Volumes/Data")
        self.assertIsNone(body["volumes"][0]["extras"])


class StorageFullPageSurvivalTests(unittest.TestCase):
    """The full page must not trade one unreadable field for the whole
    volume table.  Pre-fix, the bomb raised out of storage_overview into the
    router's fallback, which answered
    ``{"volumes": [], "disks": [], "error": "iteration bomb"}``."""

    def test_smart_bomb_no_longer_wipes_the_page(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_svc, "list_volumes", return_value=[dict(_GOOD_VOLUME)]))
            stack.enter_context(mock.patch.object(
                storage_svc, "smart_devices", return_value=[
                    {"device": "/dev/disk0", "smart": {"attrs": _IterBombList(["x"])}},
                ]))
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
        self.assertIsNone(body["disks"][0]["smart"]["attrs"])


class StorageRouterSectionRenderTests(unittest.TestCase):
    """The power / manage sections are pasted into GET /api/storage's body;
    pre-fix nothing sanitized them and the render itself 500'd."""

    def _full_page(self, *, power, managed):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_router.storage_svc, "storage_overview",
                return_value={"volumes": [], "disks": []}))
            stack.enter_context(mock.patch.object(
                storage_router.disk_power_svc, "list_power_disks",
                return_value=power))
            stack.enter_context(mock.patch.object(
                storage_router.disk_manage_svc, "overview",
                return_value=managed))
            return _client().get("/api/storage")

    def test_iteration_bombs_in_sections_collapse_not_the_route(self):
        resp = self._full_page(
            power=[{"id": "disk4", "volumes": _IterBombList(["x"])}],
            managed={"volumes": [_ItemsBombDict({"a": 1})], "count": 1},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["power_disks"][0]["id"], "disk4")
        self.assertIsNone(body["power_disks"][0]["volumes"])
        self.assertEqual(body["managed"]["count"], 1)

    def test_over_cap_int_and_surrogate_in_sections_stay_http_200(self):
        resp = self._full_page(
            power=[{"id": "disk4", "size_gb": _HUGE_INT, "name": "d\ud800isk"}],
            managed={"volumes": [{"id": "disk4s1", "size_bytes": _HUGE_INT}]},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # The unrenderable int drops like inf; the surrogate is scrubbed.
        self.assertIsNone(body["power_disks"][0]["size_gb"])
        self.assertEqual(body["power_disks"][0]["name"], "d?isk")
        self.assertIsNone(body["managed"]["volumes"][0]["size_bytes"])
        self.assertNotIn("\ud800", resp.text)

    def test_disks_route_bomb_row_collapses_the_field(self):
        with mock.patch.object(
            storage_router.disk_power_svc, "list_power_disks",
            return_value=[{"id": "disk4", "volumes": _IterBombList(["x"])}],
        ):
            resp = _client().get("/api/storage/disks")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["disks"][0]["id"], "disk4")
        self.assertIsNone(body["disks"][0]["volumes"])

    def test_manage_route_bomb_row_salvages_the_row(self):
        # storage6: the unbound ``dict.items`` view salvages the row's real
        # storage instead of collapsing it to None.
        with mock.patch.object(
            storage_router.disk_manage_svc, "overview",
            return_value={"volumes": [_ItemsBombDict({"a": 1})], "count": 1},
        ):
            resp = _client().get("/api/storage/manage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["volumes"], [{"a": 1}])


class StorageMutationResultRenderTests(unittest.TestCase):
    """Mutation results are the response body; pre-fix a hostile ok payload
    500'd the route after the action had already run."""

    def test_power_action_ok_result_with_bomb_stays_http_200(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_router.disk_power_svc, "disk_power_action",
                return_value={"ok": True, "action": "sleep", "disk": "disk4",
                              "log": _IterBombList(["x"])}))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: {}))
            resp = _client().post(
                "/api/storage/disks/disk4/power", json={"action": "sleep"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertIsNone(body["log"])
        self.assertEqual(body["disk"], "disk4")

    def test_manage_action_ok_result_with_bomb_and_over_cap_int(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                storage_router.disk_manage_svc, "disk_action",
                return_value={"ok": True, "action": "mount", "device": "disk4",
                              "size_bytes": _HUGE_INT,
                              "log": _ItemsBombDict({"a": 1})}))
            stack.enter_context(mock.patch.object(
                storage_router.audit, "record", lambda *a, **k: {}))
            resp = _client().post(
                "/api/storage/manage/disk4", json={"action": "mount"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        # storage6: the unbound ``dict.items`` view salvages the bombed log
        # dict's real storage; the over-cap int still drops like inf.
        self.assertEqual(body["log"], {"a": 1})
        self.assertIsNone(body["size_bytes"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
