"""Thirteenth leftover-500s sweep of the NAS surfaces: BaseException-shaped
bombs past ``except Exception``, the runner-call seams, and decode fidelity.

nas12 sealed the sh *answer* seam (``_sh_triple``, the or-pick, the plist
probes, the Time Machine fields) — but every one of those guards, and every
older ``_isa`` / ``_as_text`` / ``_truthy`` / ``_rc_int`` guard beneath them,
stopped at ``except Exception``.  Three leftover classes survived it:

* A leftover whose hooks raise a *BaseException* subclass (the
  watchdog/timeout shape the modules12/logs12/json13 sweeps sealed on their
  own surfaces) sailed past every catch in all three modules at once: a
  patched ``sh`` raising one blew ``_sh_triple`` itself (raw on GET /api/nfs,
  /api/nfs/stats, /api/snapshots and every POST /api/raid/* through
  ``_resolve_set``), a ``__class__``-property bomb blew ``_isa`` — the gate
  every arm stands on — and ``__bool__`` / ``__str__`` / ``__float__`` bombs
  blew ``_truthy`` / ``_as_text`` / the Time Machine percent probe under
  ``overview``'s fan-out, which re-raises a probe's error.  The percent
  probe was worse: its catch named only the arithmetic trio, so even an
  *Exception*-shaped ``__float__`` bomb (RuntimeError) rode out raw.
* The privileged-runner *calls* ran bare (the users12 / share_acl_svc
  ``_sh_call`` rule): none of the three modules owns ``run_admin`` /
  ``run_admin_sequence`` (tests and tooling patch them), and a leftover stub
  that raises instead of answering blew POST /api/nfs/exports, /api/nfs/server,
  every POST /api/raid/* mutation, POST /api/snapshots/delete, /thin and
  /api/timemachine/action one seam ahead of ``_admin_result``'s laundering.
* The claimed-base decode gap (the modules12/logs12 ``_decode_bytes`` rule):
  each bytes arm picked its decode base off the *claimed* ``__class__``, so
  a genuine ``bytearray`` whose ``__class__`` lied ``bytes`` was handed to
  ``bytes.decode``, rejected by the descriptor, and its perfectly decodable
  content degraded at the wrong rank — ``_as_text`` rendered the
  ``bytearray(b'…')`` repr into the page, raid's ``_plist`` read an honest
  plist as the empty document, and ``_ident`` silently dropped a device id.

The fixes are the module-local ``_CONTROL_FLOW`` convention (every guard
re-raises KeyboardInterrupt / SystemExit and launders everything else
BaseException-shaped exactly like its Exception twin), the guarded
``_run_admin`` / ``_admin_sequence`` call seams (a raising runner reads as
the generic coded failure and can never mint the vanished-CLI 503), and the
both-bases first-come decode.  These tests plant each bomb against our own
handlers in-process and assert 200 / coded 4xx/5xx bodies with valid UTF-8
JSON, never a raw raise — and pin control flow still propagating, because
swallowing a Ctrl-C to save one page field would turn the sanitizer into a
hang.
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

_MODULES = (nfs_svc, raid_svc, snapshots_svc)


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


class LeftoverBaseBomb(BaseException):
    """BaseException-shaped, but *not* control flow — a bomb like any other."""


def _base_raising_property():
    return property(
        lambda self: (_ for _ in ()).throw(LeftoverBaseBomb("leftover base bomb")))


class _ClassPropBaseBomb:
    """``__class__`` property raising BaseException — used to blow ``_isa``
    itself, the gate every sanitizer arm stands on."""

    __class__ = _base_raising_property()

    def __str__(self):
        return "still-renderable"


class _BoolBaseBomb:
    """A field whose ``__bool__`` raises BaseException (Running / flags)."""

    def __bool__(self):
        raise LeftoverBaseBomb("bool base bomb")


class _StrBaseBomb:
    """A field whose ``__str__`` raises BaseException (Name / detail)."""

    def __str__(self):
        raise LeftoverBaseBomb("str base bomb")


class _FloatBaseBomb:
    """A Percent whose ``__float__`` raises BaseException."""

    def __float__(self):
        raise LeftoverBaseBomb("float base bomb")


class _FloatRuntimeBomb:
    """A Percent whose ``__float__`` raises RuntimeError.

    The old catch named only (TypeError, ValueError, OverflowError), so even
    this *Exception*-shaped bomb rode out of the probe raw through fan_out.
    """

    def __float__(self):
        raise RuntimeError("float runtime bomb")


class _IterBaseBombTuple(tuple):
    """An honest-looking sh answer whose bound ``__iter__`` raises
    BaseException — the unpack detonated before any per-field guard."""

    def __iter__(self):
        raise LeftoverBaseBomb("sh answer __iter__ base bomb")


class _IntBaseBomb:
    """An rc slot whose ``__int__`` raises BaseException (the _rc_int seam)."""

    def __int__(self):
        raise LeftoverBaseBomb("int base bomb")


class _BytesLiarBytearray(bytearray):
    """A genuine bytearray whose ``__class__`` lies ``bytes``.

    The old decode arms picked the base off this very lie, handed the
    operand to ``bytes.decode``, and the descriptor's TypeError cost the
    perfectly decodable content — degrade at the wrong rank.
    """

    @property
    def __class__(self):
        return bytes


def _base_sh_shapes():
    """sh seams that raise or carry BaseException-shaped bombs, with labels."""
    def _raiser(*a, **k):
        raise LeftoverBaseBomb("sh raised a base bomb")

    return [
        ("raising_sh", _raiser),
        ("iter_base_bomb", lambda *a, **k: _IterBaseBombTuple((0, "x", ""))),
    ]


class GuardContractTests(unittest.TestCase):
    """The shared guards degrade a BaseException-shaped bomb exactly like its
    Exception twin — in all three modules."""

    def test_isa_reads_a_class_prop_base_bomb_as_no_match(self):
        for module in _MODULES:
            with self.subTest(module=module.__name__):
                self.assertIs(module._isa(_ClassPropBaseBomb(), dict), False)

    def test_truthy_reads_a_bool_base_bomb_as_false(self):
        for module in (nfs_svc, snapshots_svc):
            with self.subTest(module=module.__name__):
                self.assertIs(module._truthy(_BoolBaseBomb()), False)

    def test_as_text_reads_a_str_base_bomb_as_empty(self):
        for module in (nfs_svc, snapshots_svc):
            with self.subTest(module=module.__name__):
                self.assertEqual(module._as_text(_StrBaseBomb()), "")

    def test_rc_int_reads_an_int_base_bomb_as_failure(self):
        for module in _MODULES:
            with self.subTest(module=module.__name__):
                self.assertEqual(module._rc_int(_IntBaseBomb()), -255)

    def test_sh_triple_degrades_base_bomb_answers(self):
        for module in _MODULES:
            for label, bad_sh in _base_sh_shapes():
                with self.subTest(module=module.__name__, shape=label):
                    with mock.patch.object(module, "sh", bad_sh):
                        answer = module._sh_triple(["x"], timeout=1)
                    self.assertEqual(answer, (-255, "", ""))


class ControlFlowPassthroughTests(unittest.TestCase):
    """Genuine control flow keeps propagating through every guard —
    swallowing a Ctrl-C to save one page field would turn the sanitizer
    into a hang."""

    def test_sh_triple_reraises_control_flow(self):
        for module in _MODULES:
            for kind in (KeyboardInterrupt, SystemExit):
                with self.subTest(module=module.__name__, kind=kind.__name__):
                    def _raise(*a, _kind=kind, **k):
                        raise _kind()

                    with mock.patch.object(module, "sh", _raise):
                        with self.assertRaises(kind):
                            module._sh_triple(["x"], timeout=1)

    def test_as_text_reraises_control_flow(self):
        for module in (nfs_svc, snapshots_svc):
            for kind in (KeyboardInterrupt, SystemExit):
                with self.subTest(module=module.__name__, kind=kind.__name__):
                    class Bomb:
                        def __str__(self, _kind=kind):
                            raise _kind()

                    with self.assertRaises(kind):
                        module._as_text(Bomb())

    def test_truthy_reraises_control_flow(self):
        for module in (nfs_svc, snapshots_svc):
            for kind in (KeyboardInterrupt, SystemExit):
                with self.subTest(module=module.__name__, kind=kind.__name__):
                    class Bomb:
                        def __bool__(self, _kind=kind):
                            raise _kind()

                    with self.assertRaises(kind):
                        module._truthy(Bomb())

    def test_runner_seams_reraise_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            def _raise(*a, _kind=kind, **k):
                raise _kind()

            with self.subTest(seam="nfs._admin_sequence", kind=kind.__name__):
                with mock.patch.object(nfs_svc, "run_admin_sequence", _raise):
                    with self.assertRaises(kind):
                        nfs_svc._admin_sequence([["x"]], timeout=1)
            with self.subTest(seam="raid._run_admin", kind=kind.__name__):
                with mock.patch.object(raid_svc, "run_admin", _raise):
                    with self.assertRaises(kind):
                        raid_svc._run_admin(["x"], timeout=1)
            with self.subTest(seam="snapshots._run_admin", kind=kind.__name__):
                with mock.patch.object(snapshots_svc, "run_admin", _raise):
                    with self.assertRaises(kind):
                        snapshots_svc._run_admin(["x"], timeout=1)
            with self.subTest(seam="snapshots._admin_sequence", kind=kind.__name__):
                with mock.patch.object(
                    snapshots_svc, "run_admin_sequence", _raise
                ):
                    with self.assertRaises(kind):
                        snapshots_svc._admin_sequence([["x"]], timeout=1)


class RunnerCallSeamTests(unittest.TestCase):
    """The privileged-runner *call* seams read a raising stub as the generic
    coded failure — never the vanished-CLI 503, never a raw raise — and pass
    honest answers through untouched."""

    def _raisers(self):
        def _exc(*a, **k):
            raise RuntimeError("runner raised")

        def _base(*a, **k):
            raise LeftoverBaseBomb("runner raised a base bomb")

        return [("exception", _exc), ("base_bomb", _base)]

    def test_nfs_admin_sequence_reads_a_raising_helper_as_failed(self):
        for label, raiser in self._raisers():
            with self.subTest(shape=label):
                with mock.patch.object(nfs_svc, "run_admin_sequence", raiser):
                    result = nfs_svc._admin_sequence([["x"]], timeout=1)
                self.assertEqual(result, {"ok": False, "error": "failed"})

    def test_raid_run_admin_reads_a_raising_runner_as_failed(self):
        for label, raiser in self._raisers():
            with self.subTest(shape=label):
                with mock.patch.object(raid_svc, "run_admin", raiser):
                    result = raid_svc._run_admin(["x"], timeout=1)
                self.assertEqual(result, {"ok": False, "error": "failed"})

    def test_snapshots_runner_seams_read_a_raising_stub_as_failed(self):
        for label, raiser in self._raisers():
            with self.subTest(seam="_run_admin", shape=label):
                with mock.patch.object(snapshots_svc, "run_admin", raiser):
                    result = snapshots_svc._run_admin(["x"], timeout=1)
                self.assertEqual(result, {"ok": False, "error": "failed"})
            with self.subTest(seam="_admin_sequence", shape=label):
                with mock.patch.object(
                    snapshots_svc, "run_admin_sequence", raiser
                ):
                    result = snapshots_svc._admin_sequence([["x"]], timeout=1)
                self.assertEqual(result, {"ok": False, "error": "failed"})

    def test_honest_answers_keep_riding_the_launder_untouched(self):
        with mock.patch.object(
            nfs_svc, "run_admin_sequence", lambda *a, **k: {"ok": True}
        ):
            self.assertEqual(
                nfs_svc._admin_sequence([["x"]], timeout=1), {"ok": True})
        with mock.patch.object(
            snapshots_svc, "run_admin_sequence",
            lambda *a, **k: {"ok": False, "error": "cancelled"},
        ):
            result = snapshots_svc._admin_sequence([["x"]], timeout=1)
        # cancelled keeps its own shape: the guarded call must not flatten
        # an honest refusal into the generic failure.
        self.assertEqual(result.get("error"), "cancelled")

    def test_nfs_server_route_answers_coded_over_a_raising_helper(self):
        def _base(*a, **k):
            raise LeftoverBaseBomb("runner raised a base bomb")

        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                nfs_svc, "run_admin_sequence", _base))
            resp = _client().post("/api/nfs/server", json={"action": "stop"})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        # The generic coded failure, never the vanished-CLI 503: a runner
        # that cannot answer carries no marker text to classify.
        self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_timemachine_route_answers_coded_over_a_raising_runner(self):
        def _base(*a, **k):
            raise LeftoverBaseBomb("runner raised a base bomb")

        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "run_admin", _base))
            resp = _client().post(
                "/api/timemachine/action", json={"action": "start"})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")


class NfsBaseBombRouteTests(unittest.TestCase):
    def test_overview_survives_a_base_bomb_sh(self):
        for label, bad_sh in _base_sh_shapes():
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
                self.assertIs(payload["check"]["ok"], False)

    def test_stats_route_survives_a_base_bomb_sh(self):
        for label, bad_sh in _base_sh_shapes():
            with self.subTest(shape=label):
                with mock.patch.object(nfs_svc, "sh", bad_sh):
                    resp = _client().get("/api/nfs/stats")
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertIs(payload["ok"], False)

    def test_entry_rows_salvage_a_base_bomb_listing(self):
        class BombList(list):
            def __iter__(self):
                raise LeftoverBaseBomb("listing iter base bomb")

        # The unbound base walk reads the real storage, so the honest rows
        # survive the bound ``__iter__`` bomb; a ``__class__``-property
        # base bomb that cannot even answer the gate reads as no entries.
        self.assertEqual(nfs_svc._entry_rows(BombList([{"x": 1}])), [{"x": 1}])
        self.assertEqual(nfs_svc._entry_rows(_ClassPropBaseBomb()), [])

    def test_validate_entry_base_bomb_earns_the_coded_refusal(self):
        # A ``__class__``-property base bomb entry used to detonate the
        # _isa gate itself past the router's NfsConfigError catch.
        with self.assertRaises(nfs_svc.NfsConfigError) as caught:
            nfs_svc._validate_entry(_ClassPropBaseBomb())
        self.assertEqual(caught.exception.code, "nfs.bad_path")


class RaidBaseBombRouteTests(unittest.TestCase):
    def test_mutation_resolver_survives_a_base_bomb_sh(self):
        # ``_resolve_set`` -> ``list_sets`` -> ``_plist`` -> ``_sh_triple``
        # runs outside the read page's ``_listing`` guard; a BaseException
        # riding the seam used to 500 the delete raw one step ahead of the
        # coded not-found.
        for label, bad_sh in _base_sh_shapes():
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
                self.assertEqual(
                    payload["detail"]["code"], "raid.set_not_found")

    def test_listing_degrades_a_base_bomb_provider(self):
        def _raise():
            raise LeftoverBaseBomb("provider base bomb")

        self.assertEqual(raid_svc._listing(_raise), [])

    def test_plain_map_and_row_list_degrade_base_bomb_shapes(self):
        class BombDict(dict):
            def keys(self):
                raise LeftoverBaseBomb("keys base bomb")

        class BombList(list):
            def __iter__(self):
                raise LeftoverBaseBomb("iter base bomb")

        # The C-level copies read the real storage, so honest rows survive
        # their subclass's bound bombs; a ``__class__``-property base bomb
        # that cannot even answer the gate reads as junk.
        self.assertEqual(raid_svc._plain_map(BombDict(a=1)), {"a": 1})
        self.assertEqual(raid_svc._row_list(BombList([1])), [1])
        self.assertIsNone(raid_svc._plain_map(_ClassPropBaseBomb()))
        self.assertEqual(raid_svc._row_list(_ClassPropBaseBomb()), [])


class SnapshotsBaseBombRouteTests(unittest.TestCase):
    def test_overview_survives_a_base_bomb_sh(self):
        for label, bad_sh in _base_sh_shapes():
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

    def _tm_patched(self, stack: ExitStack, status: dict) -> None:
        stack.enter_context(mock.patch.object(
            snapshots_svc, "_tm_destinations",
            return_value={"Destinations": [{
                "ID": _StrBaseBomb(),
                "Name": _StrBaseBomb(),
                "Kind": "Local",
                "MountPoint": _BoolBaseBomb(),
                "URL": None,
                "LastDestination": _BoolBaseBomb(),
            }]}))
        stack.enter_context(mock.patch.object(
            snapshots_svc, "_tm_status", return_value=status))
        stack.enter_context(mock.patch.object(
            snapshots_svc, "_tm_latest_backup", return_value=""))

    def test_time_machine_reads_base_bomb_fields_as_empty(self):
        with ExitStack() as stack:
            self._tm_patched(stack, {
                "Running": _BoolBaseBomb(),
                "BackupPhase": _StrBaseBomb(),
            })
            tm = snapshots_svc.time_machine_overview()
        self.assertIs(tm["running"], False)
        self.assertEqual(tm["phase"], "")
        row = tm["destinations"][0]
        self.assertEqual(row["id"], "")
        self.assertEqual(row["name"], "")
        self.assertEqual(row["kind"], "Local")
        self.assertEqual(row["mount"], "")
        self.assertIs(row["last_used"], False)
        _starlette(tm)

    def test_percent_float_bombs_read_as_no_percent(self):
        # The old catch named only (TypeError, ValueError, OverflowError):
        # a RuntimeError-shaped ``__float__`` bomb — let alone the
        # BaseException twin — rode out raw through fan_out, which
        # re-raises a probe's error, and 500'd GET /api/snapshots.
        for bomb in (_FloatRuntimeBomb(), _FloatBaseBomb()):
            with self.subTest(bomb=type(bomb).__name__):
                with ExitStack() as stack:
                    self._tm_patched(stack, {
                        "Running": False,
                        "Progress": {"Percent": bomb},
                    })
                    tm = snapshots_svc.time_machine_overview()
                self.assertIsNone(tm["percent"])
                _starlette(tm)

    def test_overview_page_survives_a_percent_bomb(self):
        snapshots_svc.invalidate()
        try:
            with ExitStack() as stack:
                self._tm_patched(stack, {
                    "Running": False,
                    "Progress": {"Percent": _FloatRuntimeBomb()},
                })
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
        self.assertIsNone(payload["time_machine"]["percent"])


class DecodeFidelityTests(unittest.TestCase):
    """A genuine bytearray whose ``__class__`` lies ``bytes`` decodes through
    its real layout instead of degrading at the wrong rank."""

    _PLIST = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<plist version=\"1.0\"><dict><key>A</key><string>b</string></dict></plist>"
    )

    def test_as_text_reads_the_honest_text_not_the_repr(self):
        liar = _BytesLiarBytearray(b"nfsd is running")
        for module in (nfs_svc, snapshots_svc):
            with self.subTest(module=module.__name__):
                # The old claimed-base pick fell to the str() probe and
                # rendered "bytearray(b'nfsd is running')" into the page.
                self.assertEqual(module._as_text(liar), "nfsd is running")

    def test_nfs_status_detail_carries_the_decoded_text(self):
        nfs_svc.invalidate()
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(
                    nfs_svc, "sh",
                    lambda *a, **k: (
                        0, _BytesLiarBytearray(b"nfsd is running"), "")))
                stack.enter_context(mock.patch.object(
                    nfs_svc, "_exports_exists", return_value=True))
                resp = _client().get("/api/nfs?force=1")
        finally:
            nfs_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["server"]["running"], True)
        self.assertEqual(payload["server"]["detail"], "nfsd is running")

    def test_raid_plist_reads_the_honest_document_underneath_the_lie(self):
        with mock.patch.object(
            raid_svc, "sh",
            lambda *a, **k: (0, _BytesLiarBytearray(self._PLIST.encode()), ""),
        ):
            self.assertEqual(raid_svc._plist(["x"]), {"A": "b"})

    def test_raid_ident_and_req_text_keep_the_decoded_value(self):
        liar = _BytesLiarBytearray(b"disk0s2")
        self.assertEqual(raid_svc._ident(liar), "disk0s2")
        self.assertEqual(raid_svc._req_text(liar), "disk0s2")

    def test_jsonable_keeps_the_decoded_message(self):
        liar = _BytesLiarBytearray(b"operation failed")
        for module in (raid_svc, snapshots_svc):
            with self.subTest(module=module.__name__):
                self.assertEqual(module._jsonable(liar), "operation failed")

    def test_honest_bytes_still_decode_first_come(self):
        for module in (nfs_svc, snapshots_svc):
            with self.subTest(module=module.__name__):
                self.assertEqual(module._as_text(b"plain"), "plain")
                self.assertEqual(module._as_text(bytearray(b"plain")), "plain")


class ProductVersionPin(unittest.TestCase):
    def test_product_version_stays_pinned(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.5")


if __name__ == "__main__":
    unittest.main(verbosity=2)
