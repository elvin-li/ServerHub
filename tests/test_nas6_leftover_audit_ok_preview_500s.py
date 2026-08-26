"""Sixth leftover-500s sweep of the NAS / Time Machine surfaces.

nas5 hardened the older ``hub/routers/shares.py`` copies; this hunt found the
seams still live in the *newer* feature router (``hub/routers/nas_storage.py``)
itself.  Each of these was a raw HTTP 500 (traceback, no JSON body) on the
mounted app pre-fix:

* every mutation route recorded ``ok=bool(result.get("ok"))`` on the **raw**
  service result *before* ``raise_service_error`` laundered it — a leftover
  ``None`` from a privileged helper AttributeError'd the route at the audit
  line, a dict-*subclass* result whose bound ``.get`` raises (the jobs/metrics
  row-bomb class: passes ``isinstance``, refuses the read) blew the same line,
  and a ``__bool__``-bomb ``ok`` value detonated the ``bool()`` itself — all
  one line before the funnel that already knows how to answer coded;
* ``_known_mount`` built ``set(snapshots_svc.snapshot_mounts())`` unguarded —
  a leftover list-subclass listing whose ``__iter__`` raises (passes
  ``isinstance``, refuses iteration), or an unhashable row inside an ordinary
  list, 500'd POST /api/snapshots/delete and /thin out of the gate itself;
* GET /api/nfs/exports/preview walked ``read_exports()`` rows with a bound
  ``e.get("raw")`` and a bare ``for`` — a dict-subclass row whose ``.get``
  raises, or a list-subclass table whose ``__iter__`` raises, 500'd the
  preview instead of rendering the salvageable lines.

The fix routes the audit reads through the shared ``nas_common.result_ok``
(``_plain_result`` + ``_truthy``, the same laundering the funnel applies one
line later), materializes the mount listing under its own guard with ``/``
pinned (``snapshot_mounts`` always reports the boot volume first), and reads
the preview rows through the unbound ``dict.get`` view.
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

from hub.routers import nas_common, nas_storage  # noqa: E402

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

    def get(self, *a, **k):
        raise ValueError("get bomb")


class _BoolBomb:
    """A truth value that detonates ``bool()`` itself."""

    def __bool__(self):
        raise ValueError("bool bomb")


class _IterBombList(list):
    """Passes ``isinstance(x, list)``; raises the moment it is iterated."""

    def __iter__(self):
        raise ValueError("iteration bomb")


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


#: Every nas_storage mutation whose audit line read the raw result:
#: (service module attr, function name, method, path, JSON body or None).
_MUTATIONS = (
    ("nfs_svc", "save_exports", "post", "/api/nfs/exports", {"entries": []}),
    ("nfs_svc", "server_action", "post", "/api/nfs/server",
     {"action": "start"}),
    ("raid_svc", "repair_mirror", "post", "/api/raid/repair",
     {"set_uuid": "ABCDEF01-1111", "device": "disk9", "confirm": True}),
    ("snapshots_svc", "create_snapshot", "post", "/api/snapshots/create",
     None),
    ("snapshots_svc", "time_machine_action", "post", "/api/timemachine/action",
     {"action": "start"}),
    ("smart_test_svc", "start_test", "post", "/api/smart/test",
     {"device": "/dev/disk0", "kind": "short"}),
    ("smart_test_svc", "abort_test", "post", "/api/smart/abort",
     {"device": "/dev/disk0"}),
    ("smart_test_svc", "set_schedule", "put", "/api/smart/schedule",
     {"interval": "off", "kind": "short", "devices": []}),
    ("usage_svc", "set_spotlight", "post", "/api/storage/spotlight",
     {"volume": "/Volumes/data", "enabled": True}),
)


def _call(stack: ExitStack, svc: str, fn: str, method: str, path: str,
          body, result):
    _admin_browser(stack)
    stack.enter_context(mock.patch.object(
        getattr(nas_storage, svc), fn, return_value=result))
    client = _client()
    kwargs = {} if body is None else {"json": body}
    return getattr(client, method)(path, **kwargs)


class AuditLineRawResultTests(unittest.TestCase):
    """The audit's ok field must not read the raw result ahead of the funnel.

    Pre-fix each shape 500'd the route at ``ok=bool(result.get("ok"))`` —
    one line before ``raise_service_error`` would have answered coded.
    """

    def test_none_result_degrades_to_coded_admin_failed_everywhere(self):
        for svc, fn, method, path, body in _MUTATIONS:
            with self.subTest(route=path):
                with ExitStack() as stack:
                    resp = _call(stack, svc, fn, method, path, body, None)
                self.assertEqual(resp.status_code, 500, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_none_result_on_snapshot_delete_and_thin(self):
        for path, body, fn in (
            ("/api/snapshots/delete",
             {"mount": "/", "date_token": "2026-08-01-120000",
              "confirm": True}, "delete_snapshot"),
            ("/api/snapshots/thin", {"mount": "/", "urgency": 1},
             "thin_snapshots"),
        ):
            with self.subTest(route=path):
                with ExitStack() as stack:
                    _admin_browser(stack)
                    stack.enter_context(mock.patch.object(
                        nas_storage.snapshots_svc, "snapshot_mounts",
                        return_value=["/"]))
                    stack.enter_context(mock.patch.object(
                        nas_storage.snapshots_svc, fn, return_value=None))
                    resp = _client().post(path, json=body)
                self.assertEqual(resp.status_code, 500, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_get_bomb_ok_result_still_answers_ok(self):
        # The bound ``.get`` raises, but the C-level storage is intact:
        # the laundered copy answers 200 like any healthy result.
        with ExitStack() as stack:
            resp = _call(
                stack, "snapshots_svc", "create_snapshot",
                "post", "/api/snapshots/create", None,
                _GetBombDict({"ok": True, "name": "snap"}))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["ok"], True)
        self.assertEqual(payload["name"], "snap")

    def test_get_bomb_failure_result_keeps_the_coded_refusal(self):
        with ExitStack() as stack:
            resp = _call(
                stack, "snapshots_svc", "time_machine_action",
                "post", "/api/timemachine/action", {"action": "start"},
                _GetBombDict({"ok": False, "error": "bad_action"}))
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "snapshot.bad_action")

    def test_bool_bomb_ok_value_degrades_to_coded_admin_failed(self):
        # ``bool(result.get("ok"))`` used to detonate the audit line itself;
        # a truth value that cannot answer fails False (the _truthy rule).
        with ExitStack() as stack:
            resp = _call(
                stack, "usage_svc", "set_spotlight",
                "post", "/api/storage/spotlight",
                {"volume": "/Volumes/data", "enabled": True},
                {"ok": _BoolBomb()})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_result_ok_contract(self):
        self.assertIs(nas_common.result_ok(None), False)
        self.assertIs(nas_common.result_ok({"ok": True}), True)
        self.assertIs(nas_common.result_ok({"ok": False}), False)
        self.assertIs(nas_common.result_ok({"ok": _BoolBomb()}), False)
        self.assertIs(
            nas_common.result_ok(_GetBombDict({"ok": True})), True)


class KnownMountHostileListingTests(unittest.TestCase):
    """The mount gate must not 500 on a hostile snapshot_mounts listing."""

    def _thin(self, mounts, mount="/"):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                nas_storage.snapshots_svc, "snapshot_mounts",
                return_value=mounts))
            stack.enter_context(mock.patch.object(
                nas_storage.snapshots_svc, "thin_snapshots",
                return_value={"ok": True, "mount": mount}))
            return _client().post(
                "/api/snapshots/thin", json={"mount": mount, "urgency": 1})

    def test_iter_bomb_listing_keeps_the_boot_volume_operable(self):
        # Pre-fix: set() iterated the bomb and 500'd the gate itself.  "/" is
        # always a snapshot mount (snapshot_mounts pins it first), so the
        # boot volume stays operable while the hostile listing drops.
        resp = self._thin(_IterBombList(["/"]))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())

    def test_iter_bomb_listing_still_refuses_an_unknown_volume(self):
        resp = self._thin(_IterBombList(["/Volumes/data"]),
                          mount="/Volumes/data")
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "snapshot.bad_mount")

    def test_unhashable_row_collapses_the_row_not_the_route(self):
        # Pre-fix: set([..., ["x"]]) was TypeError — an unhandled 500.
        resp = self._thin(["/", ["unhashable"], "/Volumes/data"],
                          mount="/Volumes/data")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())

    def test_ordinary_listing_keeps_the_coded_refusal(self):
        resp = self._thin(["/"], mount="/Volumes/ghost")
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "snapshot.bad_mount")


class NfsPreviewHostileRowsTests(unittest.TestCase):
    """GET /api/nfs/exports/preview renders the salvageable lines, never 500."""

    def _preview(self, entries):
        with mock.patch.object(
                nas_storage.nfs_svc, "read_exports", return_value=entries):
            return _client().get("/api/nfs/exports/preview")

    def test_iter_bomb_table_answers_an_empty_preview(self):
        # Pre-fix: the bare ``for`` iterated the bomb and 500'd the preview.
        resp = self._preview(_IterBombList([{"raw": "/tmp host"}]))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.text, "")

    def test_get_bomb_row_still_renders_through_the_unbound_view(self):
        # dict.get reads the real C-level storage: the row's line survives
        # instead of 500ing the whole preview at the bound ``.get``.
        resp = self._preview([
            _GetBombDict({"raw": "/tmp -ro 10.0.0.1"}),
            {"raw": "/data 10.0.0.2"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.text, "/tmp -ro 10.0.0.1\n/data 10.0.0.2\n")

    def test_surrogate_raw_line_is_scrubbed_not_a_500(self):
        resp = self._preview([{"raw": "/tmp 10.0.0.\ud800"}])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertNotIn("\ud800", resp.text)
        self.assertTrue(resp.text.startswith("/tmp 10.0.0."))

    def test_ordinary_preview_keeps_its_exact_shape(self):
        resp = self._preview([
            {"raw": "/srv/media -alldirs 192.168.1.0/24"},
            {"path": "/skipped", "raw": ""},
            "not-a-dict",
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.text, "/srv/media -alldirs 192.168.1.0/24\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
