"""Seventh leftover-500s sweep of the NAS / shares-adjacent surfaces.

nas6 sealed the router-side audit reads (``nas_common.result_ok``), the
snapshot mount gate and the NFS preview walk.  This hunt found the seam one
call *below* the funnel: ``hub/nfs_svc.py`` was the one NAS service still
reading the ``run_admin_sequence`` payload raw — every sibling
(snapshots/raid/smart/usage/shares/share_acl) launders it first.  Each of
these was a live raw HTTP 500 (traceback, no JSON body) on the mounted app
pre-fix:

* ``save_exports`` read ``result.get("ok")`` on the raw payload — a leftover
  ``None`` AttributeError'd POST /api/nfs/exports, a dict-*subclass* result
  whose bound ``.get`` raises (the jobs/metrics row-bomb class: passes
  ``isinstance``, refuses the read) blew the same line, and a
  ``__bool__``-bomb ``ok`` value detonated the ``if not`` itself;
* ``server_action`` had the same three reads plus ``result["server"] = …``,
  which ran a subclass ``__setitem__`` bomb on POST /api/nfs/server;
* ``_classify_admin_failure`` compared the raw ``error`` field with a bare
  ``==`` and truth-tested the raw ``message`` with a bare ``or`` — an
  ``__eq__``-bomb error or a ``__bool__``-bomb message 500'd the failure
  path that exists precisely to answer coded.

The fix routes both mutations through ``nfs_svc._admin_result`` (the
``shares_svc._plain_result`` laundering: ``dict()`` copies the C-level
storage, ``ok`` becomes a real bool) and probes the classification fields
through ``_as_text``.  The sweep also pins the in-process leftovers the
sibling services already guard for (the ``smart_test_svc.set_schedule`` /
``raid_svc._req_text`` conventions): ``raid_svc._check_devices`` and
``storage_pool_svc._validate`` walked ``xs or []`` on a caller-supplied
list (a list-subclass ``__bool__``/``__iter__`` bomb raised raw),
``snapshots_svc.thin_snapshots`` ran a bare ``urgency not in (1, 2, 3, 4)``
(an int-subclass ``__eq__`` bomb raised raw), and
``nfs_svc._validate_entry`` read the entry with bound ``.get`` and bare
``bool()`` flags.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi import HTTPException  # noqa: E402

from hub import nfs_svc, raid_svc, snapshots_svc, storage_pool_svc  # noqa: E402
from hub.routers import nas_common  # noqa: E402

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
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _GetBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises the moment ``.get`` is called."""

    def get(self, *a, **k):
        raise ValueError("get bomb")


class _SetItemBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises on any ``x[...] = ...`` write."""

    def __setitem__(self, *a, **k):
        raise ValueError("setitem bomb")


class _BoolBomb:
    """A truth value that detonates ``bool()`` itself."""

    def __bool__(self):
        raise ValueError("bool bomb")


class _EqBomb:
    """A value that detonates any ``==`` / ``in`` probe run against it."""

    def __eq__(self, other):
        raise ValueError("eq bomb")

    def __hash__(self):
        return 1


class _IterBombList(list):
    """Passes ``isinstance(x, list)``; raises the moment it is iterated."""

    def __iter__(self):
        raise ValueError("iteration bomb")


class _BoolBombList(list):
    """Passes ``isinstance(x, list)``; raises the moment it is truth-tested."""

    def __bool__(self):
        raise ValueError("bool bomb")


class _IntEqBomb(int):
    """Passes ``isinstance(x, int)``; its own ``__eq__`` raises."""

    def __eq__(self, other):
        raise ValueError("int eq bomb")

    def __hash__(self):
        return 1


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


def _nfs_mutation(stack: ExitStack, seq_result, *, on_disk=True):
    """Common seams for both NFS mutations, with run_admin_sequence poisoned."""
    _admin_browser(stack)
    stack.enter_context(mock.patch.object(
        nfs_svc, "run_admin_sequence", return_value=seq_result))
    stack.enter_context(mock.patch.object(
        nfs_svc, "_nfsd_on_disk", return_value=on_disk))
    stack.enter_context(mock.patch.object(
        nfs_svc, "check_exports", return_value={"ok": True, "detail": ""}))
    stack.enter_context(mock.patch.object(
        nfs_svc, "_nfsd_status",
        return_value={"enabled": True, "running": True, "detail": ""}))


def _save(seq_result, **kwargs):
    with ExitStack() as stack:
        _nfs_mutation(stack, seq_result, **kwargs)
        return _client().post("/api/nfs/exports", json={"entries": []})


def _server(seq_result, **kwargs):
    with ExitStack() as stack:
        _nfs_mutation(stack, seq_result, **kwargs)
        return _client().post("/api/nfs/server", json={"action": "start"})


class NfsRawAdminResultTests(unittest.TestCase):
    """The NFS mutations must not read the raw run_admin_sequence payload.

    Pre-fix each of these shapes 500'd POST /api/nfs/exports and
    /api/nfs/server raw (traceback, no JSON body) — one call below the
    router funnel that already knows how to answer coded.
    """

    def test_none_result_degrades_to_coded_admin_failed(self):
        for label, call in (("save", _save), ("server", _server)):
            with self.subTest(route=label):
                resp = call(None)
                self.assertEqual(resp.status_code, 500, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_get_bomb_ok_result_still_answers_ok(self):
        # The bound ``.get`` raises, but the C-level storage is intact: the
        # laundered copy answers 200 like any healthy result.
        resp = _save(_GetBombDict({"ok": True}))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["ok"], True)
        self.assertEqual(payload["count"], 0)

    def test_setitem_bomb_ok_result_still_carries_the_server_state(self):
        # ``result["server"] = _nfsd_status()`` used to run the subclass
        # ``__setitem__``; the laundered copy takes the write.
        resp = _server(_SetItemBombDict({"ok": True}))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["ok"], True)
        self.assertIs(payload["server"]["running"], True)

    def test_bool_bomb_ok_value_degrades_to_coded_admin_failed(self):
        for label, call in (("save", _save), ("server", _server)):
            with self.subTest(route=label):
                resp = call({"ok": _BoolBomb()})
                self.assertEqual(resp.status_code, 500, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_eq_bomb_error_field_keeps_the_coded_failure(self):
        # Pre-fix: _classify_admin_failure's bare ``== "failed"`` ran the
        # bomb's own __eq__ and 500'd the failure path itself.
        for label, call in (("save", _save), ("server", _server)):
            with self.subTest(route=label):
                resp = call({"ok": False, "error": _EqBomb()})
                self.assertEqual(resp.status_code, 500, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_bool_bomb_message_keeps_the_coded_failure(self):
        # Pre-fix: the vanish classification's ``message or ""`` ran the
        # bomb's __bool__ on the failure path.
        for label, call in (("save", _save), ("server", _server)):
            with self.subTest(route=label):
                resp = call({
                    "ok": False, "error": "failed", "message": _BoolBomb(),
                })
                self.assertEqual(resp.status_code, 500, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_surrogate_message_in_ok_payload_is_scrubbed(self):
        resp = _server({"ok": True, "message": "up\ud800"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)

    def test_over_cap_int_field_in_ok_payload_drops_alone(self):
        resp = _server({"ok": True, "attempts": _HUGE_INT})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["ok"], True)
        self.assertIsNone(payload["attempts"])


class NfsVanishClassificationRegressionTests(unittest.TestCase):
    """The confirmed-vanished nfsd 503 must survive the new laundering."""

    def test_vanished_nfsd_still_answers_the_coded_503(self):
        gone = {
            "ok": False, "error": "failed",
            "message": "sh: /sbin/nfsd: command not found",
        }
        for label, call in (("save", _save), ("server", _server)):
            with self.subTest(route=label):
                resp = call(gone, on_disk=False)
                self.assertEqual(resp.status_code, 503, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(
                    payload["detail"]["code"], "nfs.nfsd_missing")

    def test_on_disk_nfsd_keeps_the_generic_failure(self):
        # The message pattern alone must not classify (the disk-confirm rule).
        resp = _server(
            {"ok": False, "error": "failed", "message": "not found"},
            on_disk=True,
        )
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "admin.failed")

    def test_cancelled_sheet_keeps_its_409_shape(self):
        resp = _server({"ok": False, "error": "cancelled"}, on_disk=False)
        self.assertEqual(resp.status_code, 409, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "admin.cancelled")

    def test_admin_result_contract(self):
        self.assertEqual(
            nfs_svc._admin_result(None), {"ok": False, "error": "failed"})
        self.assertEqual(
            nfs_svc._admin_result(_GetBombDict({"ok": True})), {"ok": True})
        cleaned = nfs_svc._admin_result({"ok": _BoolBomb()})
        self.assertIs(cleaned["ok"], False)


class RaidCheckDevicesHostileListTests(unittest.TestCase):
    """_check_devices walks the C-level storage, never the subclass hooks.

    Pre-fix the old ``(devices or [])`` raised the bomb raw — past the
    router's RaidError catch — where junk devices already earn the coded
    ``raid.bad_device`` refusal.
    """

    def _eligible(self, stack: ExitStack) -> None:
        stack.enter_context(mock.patch.object(
            raid_svc, "candidate_devices",
            return_value=[{"device": "disk9", "eligible": True}]))

    def test_iter_bomb_listing_salvages_its_real_devices(self):
        with ExitStack() as stack:
            self._eligible(stack)
            cleaned = raid_svc._check_devices(
                _IterBombList(["disk9"]), minimum=1)
        self.assertEqual(cleaned, ["disk9"])

    def test_bool_bomb_listing_salvages_its_real_devices(self):
        with ExitStack() as stack:
            self._eligible(stack)
            cleaned = raid_svc._check_devices(
                _BoolBombList(["disk9"]), minimum=1)
        self.assertEqual(cleaned, ["disk9"])

    def test_junk_devices_keep_their_coded_refusals(self):
        with self.assertRaises(raid_svc.RaidError) as ctx:
            raid_svc._check_devices(None, minimum=1)
        self.assertEqual(ctx.exception.code, "raid.too_few_members")
        with self.assertRaises(raid_svc.RaidError) as ctx:
            raid_svc._check_devices(["../evil"], minimum=1)
        self.assertEqual(ctx.exception.code, "raid.bad_device")


class PoolValidateHostileListTests(unittest.TestCase):
    """storage_pool_svc._validate walks the C-level storage the same way."""

    def _candidate(self, stack: ExitStack) -> None:
        stack.enter_context(mock.patch.object(
            storage_pool_svc, "_candidates",
            return_value=[{"mount": "/Volumes/data", "avail_gb": 1.0}]))

    def test_iter_bomb_mounts_salvage_their_real_members(self):
        with ExitStack() as stack:
            self._candidate(stack)
            wanted, members = storage_pool_svc._validate(
                _IterBombList(["/Volumes/data"]), "most-free")
        self.assertEqual(wanted, ["/Volumes/data"])
        self.assertEqual(members[0]["mount"], "/Volumes/data")

    def test_bool_bomb_mounts_keep_the_coded_refusal(self):
        with self.assertRaises(HTTPException) as ctx:
            storage_pool_svc._validate(_BoolBombList([]), "most-free")
        self.assertEqual(
            ctx.exception.detail["code"], "storage_pool.no_members")


class ThinUrgencyHostileIntTests(unittest.TestCase):
    """thin_snapshots' urgency gate cannot be detonated by an __eq__ bomb."""

    def test_int_eq_bomb_urgency_salvages_its_real_value(self):
        # int.__index__ launders the subclass to exact 1 before the probe.
        with mock.patch.object(
            snapshots_svc, "run_admin", return_value={"ok": True},
        ) as run:
            result = snapshots_svc.thin_snapshots("/", _IntEqBomb(1))
        self.assertIs(result["ok"], True)
        self.assertEqual(run.call_args[0][0][-1], "1")

    def test_out_of_range_and_junk_urgency_earn_bad_urgency(self):
        for label, urgency in (
            ("out_of_range", 9),
            ("over_cap_int", _HUGE_INT),
            ("eq_bomb_object", _EqBomb()),
            ("none", None),
        ):
            with self.subTest(urgency=label):
                result = snapshots_svc.thin_snapshots("/", urgency)
                self.assertEqual(
                    result, {"ok": False, "error": "bad_urgency"})


class NfsValidateEntryHostileShapeTests(unittest.TestCase):
    """_validate_entry reads the entry unbound and truth-tests guarded."""

    def test_non_dict_entry_earns_the_coded_refusal(self):
        with self.assertRaises(nfs_svc.NfsConfigError) as ctx:
            nfs_svc._validate_entry("not-a-dict")
        self.assertEqual(ctx.exception.code, "nfs.bad_path")

    def test_get_bomb_entry_reads_its_real_storage(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            entry = _GetBombDict({
                "path": tmp, "clients": ["10.0.0.0/24"],
                "readonly": _BoolBomb(),
            })
            validated = nfs_svc._validate_entry(entry)
        self.assertEqual(validated["clients"], ["10.0.0.0/24"])
        # A __bool__-bomb flag fails False instead of raising raw.
        self.assertIs(validated["readonly"], False)

    def test_iter_bomb_client_table_salvages_its_real_storage(self):
        # The unbound ``list.__iter__`` walk reads the C-level storage, so
        # the hostile override never fires and the real hosts validate —
        # pre-fix the bomb raised raw out of the client loop.
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            validated = nfs_svc._validate_entry({
                "path": tmp, "clients": _IterBombList(["10.0.0.5"]),
            })
        self.assertEqual(validated["clients"], ["10.0.0.5"])

    def test_bool_bomb_entries_list_still_saves(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                nfs_svc, "run_admin_sequence", return_value={"ok": True}))
            stack.enter_context(mock.patch.object(
                nfs_svc, "check_exports",
                return_value={"ok": True, "detail": ""}))
            result = nfs_svc.save_exports(_BoolBombList([]))
        self.assertIs(result["ok"], True)
        self.assertEqual(result["count"], 0)

    def test_ordinary_entry_keeps_its_exact_shape(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            validated = nfs_svc._validate_entry({
                "path": tmp, "clients": ["10.0.0.1"], "readonly": True,
                "alldirs": False, "maproot": "nobody",
            })
        self.assertEqual(validated["clients"], ["10.0.0.1"])
        self.assertIs(validated["readonly"], True)
        self.assertIs(validated["alldirs"], False)
        self.assertEqual(validated["maproot"], "nobody")


if __name__ == "__main__":
    unittest.main(verbosity=2)
