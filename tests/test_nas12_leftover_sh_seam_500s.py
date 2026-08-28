"""Twelfth leftover-500s sweep of the NAS surfaces: the sh *answer* seam.

nas11 laundered the rc *value* (``_rc_int`` in nfs/raid/snapshots), but the
answer's *shape* and the raw slots' *truth* stayed bare — the exact seams the
sibling modules (ups/vms/storage ``_sh3``, autostart's or-rule) already seal:

* ``rc, out, err = sh(...)`` unpacks whatever the seam handed back.  None of
  the three modules owns ``sh`` (tests and tooling patch it), so a leftover
  sequence subclass whose ``__iter__`` raises, a torn two-field answer, or a
  patched ``sh`` that raises outright blew the unpack itself — a raw HTTP 500
  on GET /api/nfs and /api/nfs/stats (``_nfsd_status`` / ``_active_exports``
  / ``check_exports`` / ``statistics``), on GET /api/snapshots (``_plist`` /
  ``_tm_latest_backup`` under ``overview``'s fan-out, which re-raises a
  probe's error), on POST /api/snapshots/create, and on every POST
  /api/raid/* through ``_plist`` on the mutation path (the read page hides
  behind ``_listing``; ``_resolve_set`` / ``_check_devices`` do not).
* nfs read the winning output slot through the bare ``out or err``, so a
  leftover str-subclass ``__bool__`` bomb detonated the pick one step ahead
  of ``_as_text``; ``server_action`` ran the same bare ``or`` (and a bound
  ``.strip()``) on its verb.
* raid's ``_plist`` probed the raw slot with ``not out``, copied bytes
  through the bound ``bytes(out)`` (a subclass ``__bytes__`` fires), and ran
  the bound ``out.find`` — each a raw raise on the mutation walks; and
  ``_check_devices`` ran the unbound ``list.__iter__`` outside any try, so a
  *lying* ``__class__`` claiming list TypeError'd past the RaidError catch.
* snapshots' ``time_machine_overview`` read its plist fields through the
  bare ``entry.get(...) or ""`` / ``bool(...)`` and a ``str()`` that caught
  only ValueError — a ``__bool__`` / ``__str__`` bomb field 500'd
  GET /api/snapshots through fan_out.

The fixes are the module-local ``_sh_triple`` (junk shapes degrade to
``(-255, "", "")`` — nonzero, never the ``-1`` spawn sentinel), the
``_as_text(out) or _as_text(err)`` pick, an exact-str copy before ``_plist``'s
probes, the guarded unbound walk, and ``_opt_text`` / ``_truthy`` on the Time
Machine fields.  These tests plant each poisoned answer against our own
handlers in-process and assert 200 / coded 4xx/5xx bodies with valid UTF-8
JSON, never a raw 500.
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

from hub import nfs_svc, raid_svc, snapshots_svc  # noqa: E402
from hub.routers import nas_common  # noqa: E402

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


def _admin_browser(stack: ExitStack) -> None:
    stack.enter_context(mock.patch.object(
        nas_common.auth, "browser_authenticated", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_username", return_value="admin"))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "is_admin", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_client_id", return_value="127.0.0.1"))


class _IterBombTuple(tuple):
    """An honest-looking sh answer whose bound ``__iter__`` raises.

    The bare ``rc, out, err = sh(...)`` unpack dispatches into exactly this
    override; the unpack detonated before any per-field guard could run.
    """

    def __iter__(self):
        raise ValueError("sh answer __iter__ bomb")


class _BoolBombStr(str):
    """A str output slot that refuses every truth test (the or-seam bomb)."""

    def __bool__(self):
        raise ValueError("output __bool__ bomb")


class _FindBombStr(str):
    """A str output slot whose bound ``.find`` raises (raid's plist probe)."""

    def find(self, *a, **k):
        raise ValueError("output find bomb")


class _BytesBomb(bytes):
    """A bytes output slot whose ``__bytes__`` raises.

    raid's old ``bytes(out)`` copy consulted this very hook.
    """

    def __bytes__(self):
        raise ValueError("output __bytes__ bomb")


class _BoolBombObj:
    """A plist field that refuses truth (Running / LastDestination / MountPoint)."""

    def __bool__(self):
        raise ValueError("field __bool__ bomb")


class _StrBombObj:
    """A plist field whose ``__str__`` raises a non-ValueError.

    The old MountPoint probe caught only the digit-cap ValueError, so this
    class escaped the catch and 500'd GET /api/snapshots raw.
    """

    def __str__(self):
        raise RuntimeError("field __str__ bomb")


class _ListLiar:
    """A leftover whose ``__class__`` answers ``list`` over no list storage."""

    @property
    def __class__(self):
        return list


def _sh_shapes():
    """The junk answer shapes every ``_sh_triple`` must degrade, with labels."""
    def _raiser(*a, **k):
        raise RuntimeError("sh raised outright")

    return [
        ("two_field", lambda *a, **k: (0, "torn")),
        ("iter_bomb", lambda *a, **k: _IterBombTuple((0, "x", ""))),
        ("not_a_sequence", lambda *a, **k: object()),
        ("raiser", _raiser),
    ]


class ShTripleContractTests(unittest.TestCase):
    """Each module's ``_sh_triple`` degrades junk shapes and passes honest ones."""

    def test_all_three_modules_expose_the_same_contract(self):
        for module in (nfs_svc, raid_svc, snapshots_svc):
            for label, bad_sh in _sh_shapes():
                with self.subTest(module=module.__name__, shape=label):
                    with mock.patch.object(module, "sh", bad_sh):
                        answer = module._sh_triple(["x"], timeout=1)
                    self.assertEqual(answer, (-255, "", ""))
                    # -255 is failure, distinct from the -1 spawn sentinel.
                    self.assertNotIn(answer[0], (0, -1))
            with self.subTest(module=module.__name__, shape="honest"):
                with mock.patch.object(
                    module, "sh", lambda *a, **k: (0, "out", "err")
                ):
                    self.assertEqual(
                        module._sh_triple(["x"], timeout=1), (0, "out", "err"))


class NfsShSeamTests(unittest.TestCase):
    def test_overview_survives_sh_shape_bombs(self):
        for label, bad_sh in _sh_shapes():
            with self.subTest(shape=label):
                nfs_svc.invalidate()
                try:
                    with ExitStack() as stack:
                        stack.enter_context(mock.patch.object(
                            nfs_svc, "sh", bad_sh))
                        stack.enter_context(mock.patch.object(
                            nfs_svc, "_exports_exists", return_value=True))
                        resp = _client().get("/api/nfs?force=1")
                finally:
                    nfs_svc.invalidate()
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertIs(payload["server"]["running"], False)
                self.assertEqual(payload["active"], [])
                self.assertIs(payload["check"]["ok"], False)

    def test_overview_survives_a_bool_bomb_output_slot(self):
        # The bomb refuses the old bare ``out or err`` pick; the laundered
        # pick still reads the honest text underneath, so the server status
        # and the checkexports verdict both survive.
        nfs_svc.invalidate()
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(
                    nfs_svc, "sh",
                    lambda *a, **k: (0, _BoolBombStr("nfsd is running"), "")))
                stack.enter_context(mock.patch.object(
                    nfs_svc, "_exports_exists", return_value=True))
                resp = _client().get("/api/nfs?force=1")
        finally:
            nfs_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["server"]["running"], True)
        self.assertIs(payload["check"]["ok"], True)

    def test_stats_route_survives_sh_shape_bombs(self):
        for label, bad_sh in _sh_shapes():
            with self.subTest(shape=label):
                with mock.patch.object(nfs_svc, "sh", bad_sh):
                    resp = _client().get("/api/nfs/stats")
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertIs(payload["ok"], False)

    def test_server_action_bomb_verbs_earn_the_coded_refusal(self):
        # A verb that cannot even answer as text is the coded bad_action,
        # never an AttributeError / __bool__ raise out of the service.
        for verb in (None, 123, _BoolBombStr("junk")):
            with self.subTest(verb=type(verb).__name__):
                result = nfs_svc.server_action(verb)
                self.assertEqual(result, {"ok": False, "error": "bad_action"})

    def test_server_action_reads_the_honest_verb_underneath_a_bomb(self):
        # A __bool__-bomb wrapper around a real verb used to detonate the
        # bare ``(action or "")``; the str() probe reads "stop" through.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                nfs_svc, "run_admin_sequence", return_value={"ok": True}))
            stack.enter_context(mock.patch.object(
                nfs_svc, "sh", lambda *a, **k: (0, "nfsd is not running", "")))
            result = nfs_svc.server_action(_BoolBombStr("stop"))
        self.assertIs(result["ok"], True)
        self.assertIn("server", result)


class RaidShSeamTests(unittest.TestCase):
    _PLIST = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<plist version=\"1.0\"><dict><key>A</key><string>b</string></dict></plist>"
    )

    def test_plist_reads_junk_answers_as_the_empty_document(self):
        shapes = _sh_shapes() + [
            ("bytes_dunder_bomb", lambda *a, **k: (0, _BytesBomb(b"<?xml"), "")),
        ]
        for label, bad_sh in shapes:
            with self.subTest(shape=label):
                with mock.patch.object(raid_svc, "sh", bad_sh):
                    self.assertEqual(raid_svc._plist(["x"]), {})

    def test_plist_reads_the_honest_text_underneath_a_str_subclass_bomb(self):
        # The exact-str copy strips the bound ``find`` / ``__bool__`` bombs
        # off a real answer instead of costing the document.
        for out in (_FindBombStr(self._PLIST), _BoolBombStr(self._PLIST)):
            with self.subTest(bomb=type(out).__name__):
                with mock.patch.object(
                    raid_svc, "sh", lambda *a, **k: (0, out, "")
                ):
                    self.assertEqual(raid_svc._plist(["x"]), {"A": "b"})

    def test_mutation_resolver_survives_sh_shape_bombs(self):
        # ``_resolve_set`` -> ``list_sets`` -> ``_plist`` runs outside the
        # read page's ``_listing`` guard; a shape-bomb sh answer used to
        # 500 the delete one seam ahead of the coded not-found.
        shapes = _sh_shapes() + [
            ("bool_bomb_out",
             lambda *a, **k: (0, _BoolBombStr("<?xml version='1.0'?>"), "")),
        ]
        for label, bad_sh in shapes:
            with self.subTest(shape=label):
                with ExitStack() as stack:
                    _admin_browser(stack)
                    stack.enter_context(mock.patch.object(
                        raid_svc, "sh", bad_sh))
                    resp = _client().post("/api/raid/delete", json={
                        "set_uuid": "0" * 12,
                        "confirm": True,
                        "confirm_phrase": "x",
                    })
                self.assertEqual(resp.status_code, 404, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["detail"]["code"], "raid.set_not_found")

    def test_check_devices_list_liar_earns_the_coded_refusal(self):
        # A lying ``__class__`` claiming list passed the _isa gate with no
        # real sequence storage; the unbound walk's TypeError used to raise
        # raw past the RaidError catch.  An unreadable table is an empty
        # table: too few members, coded.
        with self.assertRaises(raid_svc.RaidError) as caught:
            raid_svc._check_devices(_ListLiar(), minimum=1)
        self.assertEqual(caught.exception.code, "raid.too_few_members")
        with self.assertRaises(raid_svc.RaidError) as caught:
            raid_svc.create_set(
                level="mirror",
                name="Media",
                filesystem="APFS",
                devices=_ListLiar(),
                confirm=True,
                confirm_phrase="ERASE",
            )
        self.assertEqual(caught.exception.code, "raid.too_few_members")


class SnapshotsShSeamTests(unittest.TestCase):
    def test_overview_survives_sh_shape_bombs(self):
        for label, bad_sh in _sh_shapes():
            with self.subTest(shape=label):
                snapshots_svc.invalidate()
                try:
                    with ExitStack() as stack:
                        stack.enter_context(mock.patch.object(
                            snapshots_svc, "sh", bad_sh))
                        stack.enter_context(mock.patch.object(
                            snapshots_svc, "snapshot_mounts",
                            return_value=["/"]))
                        resp = _client().get("/api/snapshots?force=1")
                finally:
                    snapshots_svc.invalidate()
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["volumes"][0]["count"], 0)

    def test_latest_backup_and_plist_degrade_on_a_junk_answer(self):
        for label, bad_sh in _sh_shapes():
            with self.subTest(shape=label):
                with mock.patch.object(snapshots_svc, "sh", bad_sh):
                    self.assertEqual(snapshots_svc._tm_latest_backup(), "")
                    self.assertIsNone(snapshots_svc._plist(["x"]))

    def test_create_route_reads_a_shape_bomb_as_the_coded_failure(self):
        # A torn answer reads as spawn failure (-255): the coded
        # admin.failed body, never a raw unpack traceback.
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "sh", lambda *a, **k: (1, "torn")))
            resp = _client().post("/api/snapshots/create")
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")


class TimeMachineFieldBombTests(unittest.TestCase):
    _ROW = {
        "ID": _BoolBombStr("DEST-1"),
        "Name": _StrBombObj(),
        "Kind": "Local",
        "MountPoint": _BoolBombObj(),
        "URL": None,
        "LastDestination": _BoolBombObj(),
    }

    def _patched(self, stack: ExitStack) -> None:
        stack.enter_context(mock.patch.object(
            snapshots_svc, "_tm_destinations",
            return_value={"Destinations": [dict(self._ROW)]}))
        stack.enter_context(mock.patch.object(
            snapshots_svc, "_tm_status",
            return_value={
                "Running": _BoolBombObj(),
                "BackupPhase": _BoolBombStr("Copying"),
            }))
        stack.enter_context(mock.patch.object(
            snapshots_svc, "_tm_latest_backup", return_value=""))

    def test_service_reads_bomb_fields_as_empty(self):
        with ExitStack() as stack:
            self._patched(stack)
            tm = snapshots_svc.time_machine_overview()
        self.assertIs(tm["running"], False)
        self.assertEqual(tm["phase"], "")
        row = tm["destinations"][0]
        self.assertEqual(row["id"], "")
        self.assertEqual(row["name"], "")
        self.assertEqual(row["kind"], "Local")
        self.assertEqual(row["mount"], "")
        self.assertIs(row["last_used"], False)
        self.assertIs(row["mounted"], False)
        # The row still counts as a configured destination.
        self.assertIs(tm["configured"], True)
        _starlette(tm)

    def test_overview_page_survives_poisoned_tm_plists(self):
        snapshots_svc.invalidate()
        try:
            with ExitStack() as stack:
                self._patched(stack)
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "sh", lambda *a, **k: (0, "", "")))
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "snapshot_mounts", return_value=["/"]))
                resp = _client().get("/api/snapshots?force=1")
        finally:
            snapshots_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        tm = payload["time_machine"]
        self.assertIs(tm["running"], False)
        self.assertEqual(tm["phase"], "")
        self.assertEqual(tm["destinations"][0]["id"], "")

    def test_over_cap_mount_point_reads_as_unmounted(self):
        # A plist-hex MountPoint arrives *already-int* past CPython's
        # int->str digit cap; it can never name a directory.
        row = dict(self._ROW, MountPoint=1 << 20000)
        with ExitStack() as stack:
            self._patched(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "_tm_destinations",
                return_value={"Destinations": [row]}))
            tm = snapshots_svc.time_machine_overview()
        self.assertEqual(tm["destinations"][0]["mount"], "")
        self.assertIs(tm["destinations"][0]["mounted"], False)
        _starlette(tm)


if __name__ == "__main__":
    unittest.main(verbosity=2)
