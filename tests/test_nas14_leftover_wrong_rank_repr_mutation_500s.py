"""Fourteenth leftover-500s sweep of the NAS surfaces: mid-walk mutation
snapshots, default ``object.__repr__`` heap-address leaks, and wrong-rank
recovery behind a lying ``__class__``.

nas13 sealed the BaseException bomb family on nfs/raid/snapshots; four
leftover classes were still live — three of them on the shared router file
``hub/routers/nas_common.py`` whose guards had never left ``except
Exception``:

* **Mid-walk mutation 500s.**  ``raid_svc._jsonable`` and
  ``nas_common._jsonable`` iterated the *live* ``dict.items()`` view, so a
  nested cell whose guarded hook (a raising ``isoformat`` property that
  getattr's default swallows) mutates its own mapping mid-walk
  RuntimeError'd the ``for`` header itself — outside every net.  Through
  ``_admin_result`` that was a raw 500 on every POST /api/raid/* mutation
  one step past the laundering; through ``_rendered`` it was a raw 500 on
  every NAS read route.  The walks now snapshot ``list(dict.items(...))``
  first.
* **Default ``object.__repr__`` heap-address leaks.**  Every free-text
  coercion arm (``_as_text`` in nfs/snapshots, ``_utf8_text`` in
  nas_common, ``_jsonable``'s fallback and ``_req_text`` in raid) ran the
  dispatching ``str()`` on any leftover shape, so a plain-object detail /
  name / message cell served ``<X object at 0x7f...>`` — a raw heap
  address — verbatim onto the wire, the dict-key paths served the same
  address as a JSON *key*, and the coded refusals' own params
  (``nfs.bad_client``, ``raid.bad_device``) echoed it back.  The coercion
  arms gain the maint14 slot probe + address belt; real str storage stays
  data and a legible ``__str__`` still renders.
* **Wrong-rank drops behind a lying ``__class__``.**  ``isinstance``
  consults ``value.__class__`` only after the real-MRO check misses, so a
  lying claim steered a leftover into the arm of its *claim*, the unbound
  descriptor there refused the real layout, and an early return threw
  honest renderable storage away: a genuine str claiming int wiped to
  null, a genuine bytearray claiming bytes dropped its decodable message
  (``nas_common._decode_bytes`` still picked the claimed base), a genuine
  tuple claiming list vanished whole, and ``raid_svc._ident`` wiped a
  genuine str device id claiming bytes to "" — the store silently dropped
  from the boot-disk union.  The rejected arms now fall through to the arm
  the *real* storage matches; total impostors keep their established
  drops (the nas9 pins hold).
* **Bound nested walks vaporising honest storage.**
  ``snapshots_svc._jsonable`` read the mapping through the *bound*
  ``value.items()`` and both raid/snapshots sequence arms through the
  bound comprehension, so a real subclass's ``items()``/``__iter__`` bomb
  cost perfectly walkable C-level storage even though the raise was
  absorbed.  Unbound materialized views, real layout first-come.

nas_common's guards also all stopped at ``except Exception`` (nas13 sealed
only the three svc modules), so a nested ``__class__``-property bomb
raising a *BaseException* subclass sailed past every catch in the funnels
and ``_rendered`` at once.  Every rewritten guard is ``except
BaseException`` with the ``_CONTROL_FLOW`` re-raise — and these tests pin
genuine control flow still propagating, because swallowing a Ctrl-C to
save one payload field would turn the sanitizer into a hang.

These tests plant each shape against our own handlers in-process
(create_app + TestClient(raise_server_exceptions=False)) and assert 200 /
coded 4xx/5xx bodies with valid UTF-8 JSON, never a raw raise and never a
heap address on the wire.
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
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

_ADDR = re.compile(r" at 0x[0-9a-fA-F]+>")


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


class _MutatingHook:
    """A cell whose *guarded* hook mutates its parent mapping mid-walk.

    ``getattr(value, "isoformat", None)`` swallows the AttributeError this
    property raises, so no guard ever sees a bomb — but the pop has
    already shrunk the mapping, and the next ``for`` header ``next()`` on
    a live ``dict.items`` view RuntimeErrors from outside every net.
    """

    def __init__(self, parent: dict):
        self._parent = parent

    @property
    def isoformat(self):
        for key in list(self._parent.keys()):
            self._parent.pop(key, None)
        raise AttributeError("gone")


def _mutating_result(ok) -> dict:
    result = {"ok": ok}
    result["boom"] = _MutatingHook(result)
    result["kept_int"] = 7
    result["kept_str"] = "still here"
    return result


class _Plain:
    """A type that never overrode ``__str__``/``__repr__``: its only text
    is the default ``object.__repr__`` — ``<X object at 0x7f...>``."""


class _Legible:
    """A leftover with its own message: must keep rendering."""

    def __str__(self):
        return "legible detail"


class _AddrRepr:
    """A custom ``__repr__`` embedding a heap address the slot probe cannot
    see — the belt must still catch the rendered shape."""

    def __repr__(self):
        return "<thing at 0xdeadbeef>"


class _StrLiesInt(str):
    @property
    def __class__(self):
        return int


class _StrLiesBytes(str):
    @property
    def __class__(self):
        return bytes


class _FloatLiesInt(float):
    @property
    def __class__(self):
        return int


class _BytearrayLiesBytes(bytearray):
    @property
    def __class__(self):
        return bytes


class _TupleLiesList(tuple):
    @property
    def __class__(self):
        return list


class _ListLiesDict(list):
    @property
    def __class__(self):
        return dict


def _liar(kind):
    """A total impostor: claims *kind*, holds no usable layout underneath."""

    class _Impostor:
        @property
        def __class__(self):
            return kind

    return _Impostor()


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class _ItemsBombDict(dict):
    def items(self):
        raise RuntimeError("items bomb")


_FAKE_SET = {
    "uuid": "ABABABABABAB", "name": "tank", "level": "mirror",
    "status": "Online", "degraded": False, "redundant": True,
    "device": "disk9", "size_bytes": 1, "size_gb": 1.0,
    "members": [], "member_count": 2, "rebuilding": False,
}


class MidWalkMutationTests(unittest.TestCase):
    """A nested cell mutating its mapping mid-walk costs its own field,
    never the route: the walks snapshot ``list(dict.items(...))`` first."""

    def test_raid_jsonable_survives_a_mid_walk_mutation(self):
        cleaned = raid_svc._jsonable(_mutating_result(ok=False))
        _starlette(cleaned)
        self.assertEqual(cleaned["kept_int"], 7)
        self.assertEqual(cleaned["kept_str"], "still here")
        self.assertIsNone(cleaned["boom"])

    def test_nas_common_jsonable_survives_a_mid_walk_mutation(self):
        cleaned = nas_common._jsonable(_mutating_result(ok=True))
        _starlette(cleaned)
        self.assertEqual(cleaned["kept_int"], 7)
        self.assertEqual(cleaned["kept_str"], "still here")
        self.assertEqual(cleaned["boom"], "")

    def test_snapshots_jsonable_keeps_its_materialized_walk(self):
        # snapshots already materialized; the sibling fields must keep
        # surviving — and the mutating cell must not leak its default
        # repr (a raw heap address) the way it used to.
        cleaned = snapshots_svc._jsonable(_mutating_result(ok=True))
        _starlette(cleaned)
        self.assertEqual(cleaned["kept_int"], 7)
        self.assertNotIn("0x", json.dumps(cleaned))

    def test_raid_mutation_route_answers_coded_over_a_mutating_result(self):
        # ``_admin_result`` runs ``_jsonable`` on the raw ``run_admin``
        # answer with no try around it: the RuntimeError out of the live
        # view used to 500 POST /api/raid/delete raw, one step past the
        # laundering built to absorb junk shapes.
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                raid_svc, "list_sets", return_value=[dict(_FAKE_SET)]))
            stack.enter_context(mock.patch.object(
                raid_svc, "run_admin",
                lambda *a, **k: _mutating_result(ok=False)))
            resp = _client().post("/api/raid/delete", json={
                "set_uuid": "ABABABABABAB",
                "confirm": True,
                "confirm_phrase": "tank",
            })
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_read_route_answers_over_a_mutating_payload(self):
        # ``_rendered`` exists to sanitize the service payload before
        # Starlette renders it; a top-level mapping mutating mid-walk used
        # to detonate the sanitizer itself and 500 GET /api/nfs/stats raw.
        with mock.patch.object(
            nfs_svc, "statistics", lambda: _mutating_result(ok=True)
        ):
            resp = _client().get("/api/nfs/stats")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["kept_int"], 7)
        self.assertEqual(payload["kept_str"], "still here")


class ReprAddressLeakTests(unittest.TestCase):
    """The default ``object.__repr__`` — a raw heap address — never
    renders; a legible ``__str__`` and real str data keep rendering."""

    def test_coercion_arms_scrub_the_default_repr(self):
        self.assertEqual(nfs_svc._as_text(_Plain()), "")
        self.assertEqual(snapshots_svc._as_text(_Plain()), "")
        self.assertEqual(nas_common._utf8_text(_Plain()), "")
        self.assertEqual(raid_svc._req_text(_Plain()), "")
        self.assertIsNone(raid_svc._jsonable(_Plain()))
        self.assertEqual(snapshots_svc._jsonable(_Plain()), "")
        self.assertEqual(nas_common._jsonable(_Plain()), "")

    def test_address_belt_catches_a_custom_repr_address(self):
        self.assertEqual(nfs_svc._as_text(_AddrRepr()), "")
        self.assertEqual(snapshots_svc._as_text(_AddrRepr()), "")
        self.assertEqual(nas_common._utf8_text(_AddrRepr()), "")
        self.assertEqual(raid_svc._req_text(_AddrRepr()), "")
        self.assertIsNone(raid_svc._jsonable(_AddrRepr()))

    def test_legible_leftovers_keep_rendering(self):
        self.assertEqual(nfs_svc._as_text(_Legible()), "legible detail")
        self.assertEqual(snapshots_svc._as_text(_Legible()), "legible detail")
        self.assertEqual(nas_common._utf8_text(_Legible()), "legible detail")
        self.assertEqual(nas_common._jsonable(_Legible()), "legible detail")

    def test_real_str_storage_stays_data(self):
        # The belt applies to the coercion arms only: an /etc/exports line
        # or stderr tail *quoting* a repr is data and serves verbatim.
        quoted = "saw <thing at 0xdeadbeef> in the log"
        self.assertEqual(nfs_svc._as_text(quoted), quoted)
        self.assertEqual(snapshots_svc._as_text(quoted), quoted)
        self.assertEqual(nas_common._utf8_text(quoted), quoted)
        self.assertEqual(raid_svc._req_text(quoted), quoted)

    def test_plain_object_keys_drop_their_entry_alone(self):
        for module in (raid_svc, snapshots_svc, nas_common):
            with self.subTest(module=module.__name__):
                cleaned = module._jsonable({_Plain(): 1, "keep": 2})
                _starlette(cleaned)
                self.assertEqual(cleaned, {"keep": 2})

    def test_time_machine_destination_never_serves_an_address(self):
        snapshots_svc.invalidate()
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "_tm_destinations",
                    return_value={"Destinations": [{
                        "ID": "dest-1",
                        "Name": _Plain(),
                        "Kind": "Local",
                        "MountPoint": None,
                        "URL": None,
                        "LastDestination": False,
                    }]}))
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "_tm_status", return_value={}))
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "_tm_latest_backup", return_value=""))
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "sh", lambda *a, **k: (0, "", "")))
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "snapshot_mounts", return_value=["/"]))
                resp = _client().get("/api/snapshots?force=1")
        finally:
            snapshots_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIsNone(_ADDR.search(resp.text), resp.text[:300])
        row = resp.json()["time_machine"]["destinations"][0]
        self.assertEqual(row["id"], "dest-1")
        self.assertEqual(row["name"], "")

    def test_nfs_refusal_params_never_echo_an_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(nfs_svc.NfsConfigError) as caught:
                nfs_svc._validate_entry({"path": tmp, "clients": [_Plain()]})
            self.assertEqual(caught.exception.code, "nfs.bad_client")
            self.assertEqual(caught.exception.params.get("client"), "")
            with self.assertRaises(nfs_svc.NfsConfigError) as caught:
                nfs_svc._validate_entry({
                    "path": tmp, "clients": ["10.0.0.1"], "maproot": _Plain(),
                })
            self.assertEqual(caught.exception.code, "nfs.bad_mapping")
            self.assertEqual(caught.exception.params.get("value"), "")

    def test_raid_refusal_params_never_echo_an_address(self):
        with self.assertRaises(raid_svc.RaidError) as caught:
            raid_svc._check_devices([_Plain()], minimum=1)
        self.assertEqual(caught.exception.code, "raid.bad_device")
        self.assertEqual(caught.exception.params.get("device"), "")


class WrongRankRecoveryTests(unittest.TestCase):
    """Honest storage behind a lying ``__class__`` recovers on the arm its
    *real* layout matches; total impostors keep their established drops."""

    def test_jsonable_recovers_honest_storage_behind_the_lie(self):
        for module in (raid_svc, snapshots_svc, nas_common):
            with self.subTest(module=module.__name__):
                self.assertEqual(module._jsonable(_StrLiesInt("hello")), "hello")
                self.assertEqual(module._jsonable(_StrLiesBytes("hello")), "hello")
                self.assertEqual(module._jsonable(_FloatLiesInt(2.5)), 2.5)
                self.assertEqual(
                    module._jsonable(_BytearrayLiesBytes(b"msg")), "msg")
                self.assertEqual(module._jsonable(_TupleLiesList((1, 2))), [1, 2])
                self.assertEqual(module._jsonable(_ListLiesDict([1, 2])), [1, 2])

    def test_nas_common_decode_bytes_reads_both_bases_first_come(self):
        # The last claimed-base pick on the NAS surfaces: a genuine
        # bytearray lying ``bytes`` was handed to ``bytes.decode``, refused
        # by the descriptor, and its decodable content dropped to None in
        # ``_jsonable`` — and rendered as the ``bytearray(b'…')`` repr
        # through ``_utf8_text``'s str() probe.
        self.assertEqual(
            nas_common._decode_bytes(_BytearrayLiesBytes(b"msg")), "msg")
        self.assertEqual(
            nas_common._utf8_text(_BytearrayLiesBytes(b"msg")), "msg")
        self.assertIsNone(nas_common._decode_bytes(_liar(bytes)))

    def test_raid_ident_recovers_a_genuine_str_behind_a_bytes_claim(self):
        # A genuine str device id whose ``__class__`` lied bytes wiped to
        # "" — the physical store silently dropped from the boot-disk
        # union, offering the boot disk as a RAID member.
        self.assertEqual(raid_svc._ident(_StrLiesBytes("disk0s2")), "disk0s2")
        self.assertEqual(raid_svc._req_text(_StrLiesBytes("disk0s2")), "disk0s2")
        self.assertEqual(raid_svc._ident(_liar(str)), "")
        self.assertEqual(raid_svc._ident(_liar(bytes)), "")

    def test_total_impostors_keep_their_established_drops(self):
        # The nas9 pins hold: a claim with no usable layout underneath is
        # junk, not data.
        for kind in (bool, bytes, dict, list):
            with self.subTest(kind=kind.__name__):
                self.assertIsNone(nas_common._jsonable(_liar(kind)))
                self.assertIsNone(raid_svc._jsonable(_liar(kind)))
                self.assertIsNone(snapshots_svc._jsonable(_liar(kind)))

    def test_genuine_bools_and_exact_types_still_render(self):
        for module in (raid_svc, snapshots_svc, nas_common):
            with self.subTest(module=module.__name__):
                self.assertIs(module._jsonable(True), True)
                self.assertEqual(module._jsonable(3), 3)
                self.assertEqual(module._jsonable(2.5), 2.5)
                self.assertEqual(module._jsonable("x"), "x")
                self.assertEqual(module._jsonable(b"x"), "x")


class NestedUnboundWalkTests(unittest.TestCase):
    """A real subclass's bound ``items()``/``__iter__`` bomb cannot
    vaporise its perfectly walkable C-level storage."""

    def test_iter_bomb_lists_keep_their_rows(self):
        for module in (raid_svc, snapshots_svc, nas_common):
            with self.subTest(module=module.__name__):
                self.assertEqual(module._jsonable(_IterBombList([1, 2])), [1, 2])

    def test_items_bomb_dicts_keep_their_rows(self):
        for module in (raid_svc, snapshots_svc, nas_common):
            with self.subTest(module=module.__name__):
                self.assertEqual(
                    module._jsonable(_ItemsBombDict({"keep": 1})), {"keep": 1})

    def test_nested_bombs_inside_a_result_keep_their_siblings(self):
        result = {
            "ok": True,
            "rows": _IterBombList(["a", "b"]),
            "info": _ItemsBombDict({"keep": 1}),
        }
        for module in (raid_svc, snapshots_svc, nas_common):
            with self.subTest(module=module.__name__):
                cleaned = module._jsonable(dict(result))
                _starlette(cleaned)
                self.assertEqual(cleaned["rows"], ["a", "b"])
                self.assertEqual(cleaned["info"], {"keep": 1})


class RouterBaseExceptionTests(unittest.TestCase):
    """nas13 sealed the svc modules; nas_common's guards all stopped at
    ``except Exception``, so a nested BaseException-shaped ``__class__``
    bomb sailed past every catch in the funnels and ``_rendered``."""

    class _LeftoverBaseBomb(BaseException):
        pass

    def _class_prop_bomb(self):
        kind = self._LeftoverBaseBomb

        class _Bomb:
            @property
            def __class__(self):
                raise kind("leftover base bomb")

        return _Bomb()

    def test_funnel_degrades_a_nested_base_bomb(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                nfs_svc, "run_admin_sequence",
                lambda *a, **k: {"ok": True, "info": self._class_prop_bomb()}))
            stack.enter_context(mock.patch.object(
                nfs_svc, "sh", lambda *a, **k: (0, "nfsd is running", "")))
            resp = _client().post("/api/nfs/server", json={"action": "stop"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["ok"], True)
        # The bomb field degrades (its type never overrode __str__, so the
        # slot probe answers "") while the payload survives.
        self.assertEqual(payload["info"], "")

    def test_jsonable_degrades_a_base_bomb_value_and_keeps_siblings(self):
        cleaned = nas_common._jsonable(
            {"boom": self._class_prop_bomb(), "keep": 1})
        _starlette(cleaned)
        self.assertEqual(cleaned["keep"], 1)
        self.assertEqual(cleaned["boom"], "")

    def test_control_flow_keeps_propagating(self):
        for kind in (KeyboardInterrupt, SystemExit):
            class _CtrlBomb:
                @property
                def __class__(self, _kind=kind):
                    raise _kind()

            with self.subTest(kind=kind.__name__, gate="_isa"):
                with self.assertRaises(kind):
                    nas_common._isa(_CtrlBomb(), dict)
            with self.subTest(kind=kind.__name__, gate="_jsonable"):
                with self.assertRaises(kind):
                    nas_common._jsonable(_CtrlBomb())
            with self.subTest(kind=kind.__name__, gate="_utf8_text"):
                class _StrCtrl:
                    def __str__(self, _kind=kind):
                        raise _kind()

                with self.assertRaises(kind):
                    nas_common._utf8_text(_StrCtrl())


class ProductVersionPin(unittest.TestCase):
    def test_product_version_stays_pinned(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.5")


if __name__ == "__main__":
    unittest.main(verbosity=2)
