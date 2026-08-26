"""Sixth leftover-500s sweep of the usage / snapshots surfaces, over the real app.

The hunted classes were re-reproduced against ``create_app()`` with
``raise_server_exceptions=False``.  The walk/scan surfaces (tree, largest,
duplicates, scan_roots) were found sealed by the usage3/4/5 and array5
batteries.  Four live leaks survived, all on the seam between a raw
``sh`` / ``run_admin`` / ``run_admin_sequence`` payload and the hardened
router funnel — each an unhandled 500 pre-fix:

* ``snapshots_svc._jsonable`` predated the modules5 unbound conventions
  that ``nas_common._jsonable`` already carries: an int-subclass
  ``__str__`` bomb raised a non-ValueError past the digit-cap probe, a
  float-subclass ``__eq__``/``__ne__`` bomb blew the NaN/inf probes, a
  bytes-subclass bound ``.decode`` bomb raised at rank, and a dict
  subclass whose ``items()`` yields *non-pairs* unpacked outside the
  guard — each 500'd POST /api/snapshots/delete, /api/snapshots/thin and
  /api/timemachine/action out of ``_admin_result``.  Scalars now take the
  base coercions (``int.__index__`` / ``float.__float__`` / unbound
  ``bytes.decode``) and torn item rows drop alone; the items-*bomb*
  mapping keeps its nas4-pinned drop-to-None contract.

* ``snapshots_svc.delete_all_snapshots`` read ``result.get("ok")`` on the
  **raw** run_admin_sequence payload before ``_admin_result`` ever
  laundered it: a dict-subclass ``.get`` bomb (and a ``__bool__``-bomb ok
  under the ``if``) 500'd POST /api/snapshots/delete on the delete-all
  path only — the token path was already clean.  The scrub now runs
  first; ``deleted`` is stamped onto the plain laundered dict.

* ``usage_svc.set_spotlight`` handled the raw ``run_admin`` payload
  bare: a dict-subclass ``.get`` bomb fired at ``result.get("ok")``, a
  ``__setitem__`` bomb at ``result["volume"] = target``, a
  ``__bool__``-bomb ok at the ``if``, and a ``__bool__``-bomb message at
  the vanish classification's ``result.get("message") or ""`` — each
  500'd POST /api/storage/spotlight ahead of the funnel's own laundering
  (which these same classes cannot touch, as raise_service_error already
  proves).  The result is dict()-copied through the C-level storage
  (nas_common._plain_result rule), the ok read fails False, and an
  unreadable ok flag is rewritten so the route's own audit read cannot
  re-fire the bomb one frame later.

* ``usage_svc._spotlight_query`` computed ``_as_text(text or err)``
  *outside* its guard: a ``__bool__``-bomb (or decode-bomb bytes
  subclass) in sh() output raised out of fan_out and 500'd
  GET /api/storage/usage and POST /api/storage/spotlight.  Both module
  ``_as_text`` copies also decoded bytes through bound/copy paths a
  subclass could poison (``value.decode`` in usage_svc, ``bytes(value)``
  consulting ``__bytes__`` in snapshots_svc — the latter 500'd
  GET /api/snapshots out of ``_plist``); both now use the unbound base
  decode.

The rest pins classes the probe proved immune at the HTTP layer so a
regression cannot ship silently: surrogate keys/values and over-cap
already-ints in privileged payloads render scrubbed, a torn plist and a
huge-int rc cost the snapshot listing nothing, and the vanished-mdutil
classification keeps answering its coded 503 only after the fresh disk
probe confirms the binary is gone.
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

from hub import snapshots_svc, usage_svc  # noqa: E402
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
    stack.enter_context(mock.patch.object(
        nas_storage.audit, "record", lambda *a, **k: {}))


class _GetBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises the moment ``.get`` is called."""

    def get(self, *args, **kwargs):
        raise ValueError("get bomb")


class _SetItemBombDict(dict):
    """Passes the isinstance gate; raises when a key is written back."""

    def __setitem__(self, *args):
        raise ValueError("setitem bomb")


class _BoolBomb:
    """A leftover whose truthiness itself raises."""

    def __bool__(self):
        raise ValueError("bool bomb")

    def __str__(self):
        return "boolbomb"


class _IntStrBomb(int):
    """Passes ``isinstance(x, int)``; its ``__str__`` raises a
    *non-ValueError*, sailing past a bare digit-cap probe."""

    def __str__(self):
        raise RuntimeError("int str bomb")


class _FloatCmpBomb(float):
    """Passes ``isinstance(x, float)``; comparison itself raises, blowing
    the bare NaN/inf probes."""

    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    def __ne__(self, other):
        raise RuntimeError("float ne bomb")

    __hash__ = float.__hash__


class _BytesDecodeBomb(bytes):
    """Passes ``isinstance(x, bytes)``; the bound ``.decode`` raises."""

    def decode(self, *args, **kwargs):
        raise RuntimeError("decode bomb")


class _BytesDunderBomb(bytes):
    """Poisons the ``bytes(value)`` copy path via ``__bytes__``."""

    def __bytes__(self):
        raise RuntimeError("bytes bomb")


class _NonPairItems(dict):
    """items() yields torn rows: the two-target unpack is the bomb."""

    def items(self):
        return [("good", 1), ("torn",), ("wide", 1, 2)]


class _ItemsBombDict(dict):
    """items() raises outright — the nas4-pinned drop-to-None class."""

    def items(self):
        raise ValueError("items bomb")


#: A real diskutil listSnapshots plist with one deletable snapshot, so the
#: delete-all path builds a non-empty command sequence.
_SNAP_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Snapshots</key><array>
    <dict>
      <key>SnapshotName</key><string>com.apple.TimeMachine.2026-08-03-160000.local</string>
      <key>SnapshotUUID</key><string>AAAA-BBBB</string>
      <key>SnapshotXID</key><integer>7</integer>
    </dict>
  </array>
</dict></plist>
"""


def _sh_with_snapshots(argv, timeout=0):
    if argv[:3] == [snapshots_svc.DISKUTIL, "apfs", "listSnapshots"]:
        return 0, _SNAP_PLIST, ""
    return 0, "", ""


class SnapshotsJsonableSubclassBombHttpTests(unittest.TestCase):
    """Nested scalar-subclass bombs in a run_admin result must cost their
    own field, never the mutation route (these fail on the pre-fix tree)."""

    def _tm_action(self, result):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "run_admin", return_value=result))
            return _client().post(
                "/api/timemachine/action", json={"action": "enable"})

    def test_int_subclass_str_bomb_value_coerces_to_the_exact_int(self):
        resp = self._tm_action({"ok": True, "xid": _IntStrBomb(7)})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["xid"], 7)

    def test_float_subclass_cmp_bomb_value_coerces_to_the_exact_float(self):
        resp = self._tm_action({"ok": True, "pct": _FloatCmpBomb(1.5)})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["pct"], 1.5)

    def test_bytes_subclass_decode_bomb_value_decodes_from_the_buffer(self):
        resp = self._tm_action({"ok": True, "raw": _BytesDecodeBomb(b"z")})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["raw"], "z")

    def test_non_pair_items_rows_drop_alone_and_the_pairs_survive(self):
        resp = self._tm_action(
            {"ok": True, "detail": _NonPairItems({"ignored": 0})})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"], {"good": 1})

    def test_thin_route_shares_the_same_scrub(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "snapshot_mounts", return_value=["/"]))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "run_admin",
                return_value={"ok": True, "freed": _IntStrBomb(3)}))
            resp = _client().post(
                "/api/snapshots/thin", json={"mount": "/", "urgency": 1})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["freed"], 3)

    def test_surrogate_key_and_value_render_scrubbed(self):
        resp = self._tm_action({"ok": True, "k\ud800ey": "v\ud800"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        resp.text.encode("utf-8")
        self.assertNotIn("\ud800", resp.text)
        self.assertEqual(resp.json()["k?ey"], "v?")

    def test_over_cap_already_int_value_drops_like_its_inf_sibling(self):
        resp = self._tm_action({"ok": True, "xid": 10 ** 5000})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIsNone(resp.json()["xid"])


class SnapshotsJsonableUnitContractTests(unittest.TestCase):
    """Service-level contract, independent of the router mount."""

    def test_scalar_subclass_bombs_take_the_base_coercions(self):
        row = snapshots_svc._jsonable({
            "i": _IntStrBomb(7),
            "f": _FloatCmpBomb(1.5),
            "b": _BytesDecodeBomb(b"z"),
            "keep": "x",
        })
        _starlette(row)
        self.assertEqual(row["i"], 7)
        self.assertIs(type(row["i"]), int)
        self.assertEqual(row["f"], 1.5)
        self.assertIs(type(row["f"]), float)
        self.assertEqual(row["b"], "z")
        self.assertEqual(row["keep"], "x")

    def test_non_pair_items_salvage_the_well_formed_pairs(self):
        self.assertEqual(
            snapshots_svc._jsonable(_NonPairItems({"ignored": 0})),
            {"good": 1},
        )

    def test_items_bomb_mapping_keeps_the_nas4_drop_contract(self):
        """The nas4 pin: a mapping whose items() *raises* has nothing to
        salvage and drops to None — this sweep must not regress it."""
        self.assertIsNone(snapshots_svc._jsonable(_ItemsBombDict({"a": 1})))

    def test_as_text_survives_a_dunder_bytes_bomb(self):
        """``bytes(value)`` consulted the subclass ``__bytes__``; the
        unbound base decode reads the real buffer instead."""
        self.assertEqual(snapshots_svc._as_text(_BytesDunderBomb(b"ok")), "ok")
        self.assertEqual(snapshots_svc._as_text(_BytesDecodeBomb(b"ok")), "ok")


class DeleteAllRawResultBombTests(unittest.TestCase):
    """POST /api/snapshots/delete (delete-all path) read the raw
    run_admin_sequence payload before laundering it — a dict-subclass
    ``.get`` bomb, a ``__bool__``-bomb ok and a nested scalar bomb each
    500'd the route pre-fix."""

    def _delete_all(self, result):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "sh", side_effect=_sh_with_snapshots))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "run_admin_sequence", return_value=result))
            return _client().post(
                "/api/snapshots/delete", json={"mount": "/", "confirm": True})

    def test_get_bomb_result_still_answers_the_deleted_count(self):
        resp = self._delete_all(_GetBombDict({"ok": True}))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["deleted"], 1)

    def test_bool_bomb_ok_scrubs_before_the_truthiness_read(self):
        resp = self._delete_all({"ok": _BoolBomb()})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["deleted"], 1)

    def test_nested_int_str_bomb_costs_its_field_not_the_route(self):
        resp = self._delete_all({"ok": True, "xid": _IntStrBomb(7)})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["deleted"], 1)
        self.assertEqual(body["xid"], 7)

    def test_plain_ok_keeps_the_original_shape(self):
        resp = self._delete_all({"ok": True})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json(), {"ok": True, "deleted": 1})


class SpotlightRawResultBombTests(unittest.TestCase):
    """usage_svc.set_spotlight handled the raw run_admin payload bare;
    every bomb class here was an unhandled 500 on
    POST /api/storage/spotlight pre-fix."""

    def _toggle(self, result, *, on_disk=False):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                usage_svc, "spotlight_status",
                return_value=[{"volume": "/"}]))
            stack.enter_context(mock.patch(
                "hub.macos_admin.run_admin", return_value=result))
            stack.enter_context(mock.patch.object(
                usage_svc, "_mdutil_on_disk", return_value=on_disk))
            return _client().post(
                "/api/storage/spotlight", json={"volume": "/", "enabled": True})

    def test_get_bomb_result_copies_through_the_storage(self):
        resp = self._toggle(_GetBombDict({"ok": True}))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["volume"], "/")
        self.assertIs(body["enabled"], True)

    def test_setitem_bomb_result_still_takes_the_volume_stamp(self):
        resp = self._toggle(_SetItemBombDict({"ok": True}))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["volume"], "/")

    def test_bool_bomb_ok_reads_as_the_coded_failure(self):
        """Pre-fix the raise was an unhandled 500 with no coded body; the
        honest answer for an unreadable flag is the coded admin.failed —
        and the route's own audit read must not re-fire the bomb."""
        resp = self._toggle({"ok": _BoolBomb()})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "admin.failed")

    def test_bool_bomb_message_on_the_failure_path_keeps_the_coded_shape(self):
        resp = self._toggle(
            {"ok": False, "error": "failed", "message": _BoolBomb()})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "admin.failed")

    def test_confirmed_vanished_mdutil_keeps_the_coded_503(self):
        """Regression guard for the branch this sweep touched: the 503
        fires only after the fresh disk probe confirms mdutil is gone."""
        vanished = {
            "ok": False, "error": "failed",
            "message": "sh: /usr/bin/mdutil: command not found",
        }
        resp = self._toggle(dict(vanished), on_disk=False)
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "usage.mdutil_missing")
        # An on-disk mdutil keeps the raw failure: execve also ENOENTs for
        # a present binary whose loader is broken, and the 503 would lie.
        resp = self._toggle(dict(vanished), on_disk=True)
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "admin.failed")

    def test_unit_bool_bomb_ok_is_rewritten_for_the_audit_read(self):
        with (
            mock.patch.object(
                usage_svc, "spotlight_status",
                return_value=[{"volume": "/"}]),
            mock.patch(
                "hub.macos_admin.run_admin",
                return_value={"ok": _BoolBomb()}),
            mock.patch.object(usage_svc, "_mdutil_on_disk", return_value=True),
        ):
            result = usage_svc.set_spotlight("/", True)
        self.assertIs(result["ok"], False)
        # The route reads bool(result.get("ok")) for its audit row.
        self.assertIs(bool(result.get("ok")), False)


class SpotlightShSeamBombTests(unittest.TestCase):
    """A hostile sh() payload inside _spotlight_query must cost its own
    row, never GET /api/storage/usage (fan_out re-raises; pre-fix both
    shapes were unhandled 500s)."""

    class _BoolBombStr(str):
        def __bool__(self):
            raise ValueError("bool bomb")

    def _usage(self, out):
        with mock.patch.object(
            usage_svc, "sh", return_value=(0, out, ""),
        ):
            return _client().get("/api/storage/usage")

    def test_bool_bomb_str_output_renders_its_row(self):
        resp = self._usage(self._BoolBombStr("Indexing enabled."))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        states = {row["volume"]: row["state"] for row in body["spotlight"]}
        self.assertEqual(states["/"], "enabled")

    def test_decode_bomb_bytes_output_decodes_from_the_buffer(self):
        resp = self._usage(_BytesDecodeBomb(b"Indexing enabled."))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        states = {r["volume"]: r["state"] for r in resp.json()["spotlight"]}
        self.assertEqual(states["/"], "enabled")

    def test_dunder_bytes_bomb_output_stays_immune(self):
        resp = self._usage(_BytesDunderBomb(b"Indexing disabled."))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        states = {r["volume"]: r["state"] for r in resp.json()["spotlight"]}
        self.assertEqual(states["/"], "disabled")

    def test_over_cap_rc_and_none_output_stay_immune(self):
        for ret in ((10 ** 5000, "x", ""), (0, None, None), (0, "x")):
            with self.subTest(ret=ret), mock.patch.object(
                usage_svc, "sh", return_value=ret,
            ):
                resp = _client().get("/api/storage/usage")
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                _starlette(resp.json())


class SnapshotsShSeamBombTests(unittest.TestCase):
    """GET /api/snapshots reads every sh() payload through _plist/_as_text;
    the __bytes__-bomb subclass was a live 500 pre-fix, the rest are
    stays-immune pins."""

    def _overview(self, sh_impl):
        with mock.patch.object(snapshots_svc, "sh", side_effect=sh_impl):
            return _client().get("/api/snapshots", params={"force": "true"})

    def _snapshot_names(self, resp) -> list[str]:
        return [
            snap["name"]
            for volume in resp.json()["volumes"]
            for snap in volume["snapshots"]
        ]

    def test_dunder_bytes_bomb_plist_output_still_lists_the_snapshot(self):
        resp = self._overview(
            lambda argv, timeout=0: (0, _BytesDunderBomb(_SNAP_PLIST.encode()), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertIn(
            "com.apple.TimeMachine.2026-08-03-160000.local",
            self._snapshot_names(resp),
        )

    def test_decode_bomb_plist_output_still_lists_the_snapshot(self):
        resp = self._overview(
            lambda argv, timeout=0: (0, _BytesDecodeBomb(_SNAP_PLIST.encode()), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIn(
            "com.apple.TimeMachine.2026-08-03-160000.local",
            self._snapshot_names(resp),
        )

    def test_torn_plist_and_over_cap_rc_stay_immune(self):
        payloads = [
            lambda argv, timeout=0: (0, "<?xml version='1.0'?><plist><dict><key>Snap", ""),
            lambda argv, timeout=0: (10 ** 5000, "x", ""),
        ]
        for sh_impl in payloads:
            resp = self._overview(sh_impl)
            self.assertEqual(resp.status_code, 200, resp.text[:200])
            body = resp.json()
            _starlette(body)
            self.assertEqual(self._snapshot_names(resp), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
