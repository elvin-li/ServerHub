"""Seventh leftover-500s sweep of the VMs surfaces, over the real app.

vms6 sealed the console-slot leak and the apps suspend mapping and pinned
the orbctl/utmctl/YAML zoos.  What it never touched: hub/vms_svc.py's own
coercers — ``_as_text``, ``_display_text``, ``_id_text`` and the local
``_jsonable`` — plus the listing/row walks, which still called bound
subclass methods everywhere the tree-wide convention
(``hub.modules._jsonable``'s unbound ``dict.items`` / ``base.__iter__`` /
``int.__index__`` / ``float.__float__`` / base ``bytes.decode`` /
``str.encode``) uses base operations.  On the pre-fix tree:

* POST /api/vms/{id}/action — a ``sh`` stdout/stderr leftover that is a
  str subclass whose ``__str__`` answers *self* (so ``str()`` skips
  CPython's exact-str copy and its bound ``encode`` bomb stays live), or a
  bytes subclass whose ``__bytes__``/``decode`` raises, 500'd the action
  reply out of ``_as_text`` — on the ``start`` tail and on the separate
  ``ip`` assembly path alike;
* GET /api/vms — the same bombs in the *listing* text threw away every UTM
  machine (``_listing_rows`` caught the raise and answered ``[]``);
* GET /api/vms — a listing that returns a list subclass whose ``__iter__``
  raises detonated in ``_listing_rows``'s ``list(rows)`` call, which sat
  *outside* its try, and re-raised through ``fan_out`` into a 500; a
  dict-subclass row whose ``items()`` raises detonated in the final
  ``_jsonable`` pass; ``discover_vms`` (the /api/status feed) raised on a
  row with a bombing ``.get`` and on a state value whose reflected
  ``__eq__`` raises;
* ``_jsonable`` / ``_display_text`` / ``_id_text`` — an int subclass whose
  ``__float__`` raises (or lies past the overflow probe, so a >4300-digit
  value reached ``str()`` / the encoder and ValueError'd on CPython's
  digit cap), a float subclass whose ``__eq__`` blows the NaN/inf probes,
  and an ``isoformat`` probe on an object whose ``__getattr__`` raises;
* POST /api/vms/{id}/action — a leftover orb row with a bombing ``.get``
  or a str-subclass ``orb_name`` whose reflected ``__eq__`` raises 500'd
  ``_parse_id`` instead of dispatching;
* the console-session mint — ``utm_vm_running`` ran bound ``.get`` on
  leftover rows, and ``vm_console._entry_for`` ran a bound ``items()`` on
  a dict-subclass allowlist (settings_section only launders the top-level
  section), turning the coded 404 into a 500.

Fixes in hub/vms_svc.py and hub/vm_console.py, all the established
conventions: base ``bytes.decode`` / ``str.encode``, the full unbound set
in ``_jsonable`` plus a guarded ``isoformat`` getattr, unbound iteration
inside ``_listing_rows``'s guard, unbound ``dict.get`` +
``str.__eq__``-against-exact-text in ``discover_vms`` / ``_parse_id`` /
``utm_vm_running``, and exact-str copies in vm_console's text probes.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit, vm_console, vms_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
UTM_LISTING = (
    "UUID                                 Status   Name\n"
    f"{_UUID} started  Ubuntu\n"
)

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _starlette(payload) -> str:
    """What Starlette's JSONResponse does: ensure_ascii=False then encode."""
    return json.dumps(payload, ensure_ascii=False, allow_nan=False).encode(
        "utf-8"
    ).decode("utf-8")


class _StrEncodeBomb(str):
    """``__str__`` answers *self*, so ``str()`` skips CPython's exact-str
    copy and the bound ``encode`` bomb stays live on the result."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("leftover encode bomb")


class _StrEqBomb(str):
    """Reflected ``__eq__`` bomb: ``exact == subclass`` calls this first."""

    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    __ne__ = __eq__
    __hash__ = str.__hash__


class _StrBoolBomb(str):
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _BytesBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("leftover decode bomb")

    def __bytes__(self):
        raise RuntimeError("leftover __bytes__ bomb")


class _DictItemsBomb(dict):
    def items(self):
        raise RuntimeError("leftover items bomb")


class _DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("leftover get bomb")


class _ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _TupleIterBomb(tuple):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _SetIterBomb(set):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _FrozenIterBomb(frozenset):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _IntFloatBomb(int):
    def __float__(self):
        raise RuntimeError("leftover __float__ bomb")


class _IntLyingFloat(int):
    """Answers the overflow probe with 1.0 while holding >4300 digits."""

    def __float__(self):
        return 1.0


class _FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    __ne__ = __eq__
    __hash__ = float.__hash__


class _IsoGetattrBomb:
    """getattr(value, "isoformat", None) only defaults AttributeError."""

    def __getattr__(self, name):
        raise RuntimeError("leftover __getattr__ bomb")


class JsonableZooTests(unittest.TestCase):
    """Every subclass bomb costs its value at most, never the document."""

    def test_dict_items_bomb_keeps_its_real_storage(self):
        out = vms_svc._jsonable({"s": _DictItemsBomb({"a": 1})})
        self.assertEqual(out, {"s": {"a": 1}})
        _starlette(out)

    def test_container_iter_bombs_keep_their_real_elements(self):
        for bomb in (
            _ListIterBomb([1, "x"]),
            _TupleIterBomb((1, "x")),
            _SetIterBomb({1}),
            _FrozenIterBomb({1}),
        ):
            out = vms_svc._jsonable({"v": bomb})
            self.assertTrue(out["v"], bomb)
            _starlette(out)

    def test_int_float_bomb_keeps_its_value_and_lying_huge_drops(self):
        self.assertEqual(vms_svc._jsonable(_IntFloatBomb(7)), 7)
        # The base coercion runs before the overflow probe, so the lie no
        # longer smuggles >4300 digits into the encoder's ValueError.
        self.assertIsNone(vms_svc._jsonable(_IntLyingFloat(10 ** 5000)))

    def test_float_eq_bomb_keeps_its_value_and_inf_drops(self):
        self.assertEqual(vms_svc._jsonable(_FloatEqBomb(1.5)), 1.5)
        self.assertIsNone(vms_svc._jsonable(_FloatEqBomb(float("inf"))))

    def test_bytes_bomb_still_decodes_the_real_bytes(self):
        self.assertEqual(vms_svc._jsonable(_BytesBomb(b"ok\xff")), "ok\ufffd")

    def test_self_str_encode_bomb_is_scrubbed_not_raised(self):
        out = vms_svc._jsonable(_StrEncodeBomb("a\ud800b"))
        self.assertEqual(out, "a?b")
        self.assertIs(type(out), str)

    def test_bombed_mapping_keys_cost_the_key_not_the_document(self):
        raw = {}
        dict.__setitem__(raw, _BytesBomb(b"k\xff"), 1)
        raw["fine"] = 2
        out = vms_svc._jsonable(raw)
        self.assertEqual(out, {"k\ufffd": 1, "fine": 2})
        _starlette(out)

    def test_getattr_bomb_object_drops_not_raises(self):
        out = vms_svc._jsonable({"v": _IsoGetattrBomb()})
        self.assertEqual(out, {"v": None})
        _starlette(out)


class TextCoercerZooTests(unittest.TestCase):
    def test_as_text_survives_decode_and_encode_bombs(self):
        self.assertEqual(vms_svc._as_text(_BytesBomb(b"ok\xff")), "ok\ufffd")
        out = vms_svc._as_text(_StrEncodeBomb("done\ud800"))
        self.assertEqual(out, "done?")
        self.assertIs(type(out), str)

    def test_display_text_bomb_zoo_keeps_values_or_falls_back(self):
        cases = [
            (_FloatEqBomb(1.5), "1.5"),
            (_FloatEqBomb(float("inf")), "fb"),
            (_IntFloatBomb(7), "7"),
            (_IntLyingFloat(10 ** 5000), "fb"),
            (_BytesBomb(b"x\xff"), "x\ufffd"),
            (_StrEncodeBomb("a\ud800"), "a?"),
            (_StrBoolBomb("x"), "x"),
        ]
        for value, expected in cases:
            with self.subTest(value=type(value).__name__):
                out = vms_svc._display_text(value, "fb")
                self.assertEqual(out, expected)
                self.assertIs(type(out), str)

    def test_id_text_bomb_zoo_keeps_ids_or_falls_back(self):
        cases = [
            (_StrEncodeBomb("mid\ud800"), "mid?"),
            (_StrBoolBomb("mid"), "mid"),
            (_IntFloatBomb(7), "7"),
            (_IntLyingFloat(10 ** 5000), "fb"),
            (_FloatEqBomb(1.5), "fb"),
            (_BytesBomb(b"x"), "fb"),
        ]
        for value, expected in cases:
            with self.subTest(value=type(value).__name__):
                out = vms_svc._id_text(value, "fb")
                self.assertEqual(out, expected)
                self.assertIs(type(out), str)


class _Vms7Case(unittest.TestCase):
    """Shared plumbing: hypervisor CLI fakes over the mounted app."""

    def setUp(self):
        self.client = _client()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def _patched(self, sh):
        return (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "UTMCTL", "/usr/local/bin/utmctl"),
            mock.patch.object(vms_svc, "ORBCTL", "/usr/local/bin/orbctl"),
            mock.patch.object(vms_svc, "sh", side_effect=sh),
            mock.patch.object(audit, "record"),
        )

    def _assert_clean(self, resp, status=200):
        self.assertEqual(resp.status_code, status, resp.text[:200])
        resp.content.decode("utf-8")
        self.assertNotIn("\ud800", resp.text)


def _sh_with_action_out(out, err=""):
    def fake(cmd, **kw):
        cmd = [str(c) for c in cmd]
        if cmd[1:2] == ["list"]:
            return (0, UTM_LISTING if "utmctl" in cmd[0] else "", "")
        return (0, out, err)
    return fake


class ActionReplyBombTests(_Vms7Case):
    """POST /api/vms/{id}/action: bombed CLI output costs characters only."""

    CASES = {
        "encode-bomb-out": _StrEncodeBomb("done\ud800"),
        "bytes-bomb-out": _BytesBomb(b"done\xff"),
    }

    def test_action_tail_answers_200_with_the_real_text(self):
        for label, out in self.CASES.items():
            with self.subTest(case=label):
                vms_svc.invalidate_vm_lists()
                p = self._patched(_sh_with_action_out(out))
                with p[0], p[1], p[2], p[3], p[4], p[5]:
                    resp = self.client.post(
                        f"/api/vms/{_UUID}/action", json={"action": "start"},
                    )
                self._assert_clean(resp)
                body = resp.json()
                self.assertTrue(body["ok"])
                self.assertTrue(body["message"].startswith("done"))

    def test_ip_assembly_path_answers_200(self):
        for label, out in self.CASES.items():
            with self.subTest(case=label):
                vms_svc.invalidate_vm_lists()
                p = self._patched(_sh_with_action_out(out))
                with p[0], p[1], p[2], p[3], p[4], p[5]:
                    resp = self.client.post(
                        f"/api/vms/{_UUID}/action", json={"action": "ip"},
                    )
                self._assert_clean(resp)
                self.assertTrue(resp.json()["ips"][0].startswith("done"))


class BombedListingTextTests(_Vms7Case):
    """A bombed utmctl listing string no longer throws away the machines."""

    def test_listing_survives_encode_and_decode_bombs(self):
        cases = {
            "encode-bomb-listing": _StrEncodeBomb(UTM_LISTING + "\ud800"),
            "bytes-bomb-listing": _BytesBomb(UTM_LISTING.encode("utf-8")),
        }
        for label, listing in cases.items():
            def fake(cmd, **kw):
                cmd = [str(c) for c in cmd]
                if cmd[1:2] == ["list"] and "utmctl" in cmd[0]:
                    return (0, listing, "")
                return (0, "", "")
            with self.subTest(case=label):
                vms_svc.invalidate_vm_lists()
                p = self._patched(fake)
                with p[0], p[1], p[2], p[3], p[4], p[5]:
                    resp = self.client.get("/api/vms")
                self._assert_clean(resp)
                names = {v["name"] for v in resp.json()["vms"]}
                # Pre-fix: the raise was swallowed by _listing_rows and the
                # whole UTM inventory answered [].
                self.assertIn("Ubuntu", names)


_ROW = {
    "id": "Ubuntu", "uuid": _UUID, "name": "Ubuntu", "backend": "utm",
    "status": "started", "state": "ok", "detail": "UTM · started",
    "url": None, "group": "UTM", "actions": ["stop"], "ips": [],
}


class BombedListingRowsTests(_Vms7Case):
    """Leftover subclass rows out of a listing cost nothing but themselves."""

    CASES = {
        "iter-bomb-rows": _ListIterBomb([dict(_ROW)]),
        "dict-items-bomb-row": [_DictItemsBomb(_ROW)],
        "dict-get-bomb-row": [_DictGetBomb(_ROW)],
        "eq-bomb-state-row": [dict(_ROW, state=_StrEqBomb("ok"))],
        "bool-bomb-group-row": [dict(_ROW, group=_StrBoolBomb("UTM"))],
    }

    def _listings(self, rows):
        return (
            mock.patch.object(
                vms_svc, "list_utm_vms", lambda force=False: rows
            ),
            mock.patch.object(
                vms_svc, "list_orb_machines", lambda force=False: []
            ),
        )

    def test_get_vms_stays_200_with_the_row_data(self):
        for label, rows in self.CASES.items():
            with self.subTest(case=label):
                p = self._listings(rows)
                with p[0], p[1]:
                    resp = self.client.get("/api/vms")
                self._assert_clean(resp)
                names = {v["name"] for v in resp.json()["vms"]}
                self.assertIn("Ubuntu", names)

    def test_discover_vms_keeps_the_row_and_its_actions(self):
        for label, rows in self.CASES.items():
            with self.subTest(case=label):
                p = self._listings(rows)
                with p[0], p[1]:
                    items = vms_svc.discover_vms()
                self.assertEqual(len(items), 1, label)
                self.assertEqual(items[0]["name"], "Ubuntu")
                # The real "ok" state still buys restart/stop.
                self.assertEqual(items[0]["actions"], ["restart", "stop"])
                _starlette(items)


class ParseIdBombedOrbRowsTests(_Vms7Case):
    """POST /api/vms/{id}/action: leftover orb rows cannot 500 _parse_id."""

    CASES = {
        "get-bomb-row": [_DictGetBomb({"orb_name": "web", "id": "orb:web"})],
        "eq-bomb-name-row": [{"orb_name": _StrEqBomb("web"), "id": "orb:web"}],
        "bool-bomb-name-row": [
            {"orb_name": _StrBoolBomb("web"), "id": "orb:web"}
        ],
        "iter-bomb-machines": _ListIterBomb(
            [{"orb_name": "web", "id": "orb:web"}]
        ),
    }

    def test_action_still_dispatches_to_the_orb_machine(self):
        for label, machines in self.CASES.items():
            with self.subTest(case=label):
                vms_svc.invalidate_vm_lists()
                p = self._patched(_sh_with_action_out("info ok"))
                with p[0], p[1], p[2], p[3], p[4], p[5], mock.patch.object(
                    vms_svc, "list_orb_machines", lambda force=False: machines
                ):
                    resp = self.client.post(
                        "/api/vms/web/action", json={"action": "info"},
                    )
                # For every case — including the __iter__ bomb, whose real
                # rows the unbound base iteration still reads — the machine
                # resolves and the action dispatches.
                self._assert_clean(resp)
                body = resp.json()
                self.assertTrue(body["ok"])
                self.assertEqual(body["id"], "web")
                self.assertEqual(body["message"], "info ok")


class UtmVmRunningBombedRowsTests(_Vms7Case):
    """The console mint's liveness re-check survives leftover rows."""

    def test_bombed_rows_answer_false_or_the_real_state(self):
        cases = {
            "get-bomb-row": [_DictGetBomb(dict(_ROW))],
            "iter-bomb-rows": _ListIterBomb([dict(_ROW)]),
        }
        for label, rows in cases.items():
            with self.subTest(case=label):
                with mock.patch.object(
                    vms_svc, "list_utm_vms", lambda force=False: rows
                ), mock.patch.object(
                    vms_svc, "_utm_available", return_value=True
                ), mock.patch.object(
                    vms_svc, "_utm_status", return_value="started"
                ):
                    running = vms_svc.utm_vm_running(_UUID)
                # The unbound base reads recover the real row under either
                # bomb, so the live state still answers True.
                self.assertTrue(running, label)


class ConsoleAllowlistSubclassTests(unittest.TestCase):
    """vm_console: subclass allowlists resolve or refuse — never raise."""

    _ENTRY = {"enabled": True, "port": 5900}

    def test_items_bomb_allowlist_still_resolves_the_real_entry(self):
        section = {"allowlist": _DictItemsBomb({_UUID: dict(self._ENTRY)})}
        with mock.patch.object(
            vm_console, "settings_section", lambda name: section
        ):
            target = vm_console.resolve_target(f"utm:{_UUID}")
        self.assertIsNotNone(target)
        self.assertEqual(target.port, 5900)
        self.assertEqual(target.vm_uuid, _UUID)

    def test_get_bomb_entry_is_laundered_not_raised(self):
        section = {"allowlist": {_UUID: _DictGetBomb(self._ENTRY)}}
        with mock.patch.object(
            vm_console, "settings_section", lambda name: section
        ):
            target = vm_console.resolve_target(f"utm:{_UUID}")
        self.assertIsNotNone(target)
        self.assertEqual(target.port, 5900)

    def test_str_subclass_key_and_host_bombs_refuse_or_resolve_cleanly(self):
        cases = {
            "encode-bomb-key": {
                "allowlist": _DictItemsBomb(
                    {_StrEncodeBomb(_UUID): dict(self._ENTRY)}
                )
            },
            "bool-bomb-host": {
                "allowlist": {
                    _UUID: dict(self._ENTRY, host=_StrBoolBomb("127.0.0.1"))
                }
            },
            "bytes-bomb-host": {
                "allowlist": {
                    _UUID: dict(self._ENTRY, host=_BytesBomb(b"127.0.0.1"))
                }
            },
        }
        for label, section in cases.items():
            with self.subTest(case=label):
                with mock.patch.object(
                    vm_console, "settings_section", lambda name, s=section: s
                ):
                    target = vm_console.resolve_target(f"utm:{_UUID}")
                # Resolution succeeds off the real characters; the point is
                # that no subclass bomb raised out of the resolver.
                self.assertIsNotNone(target, label)
                self.assertEqual(target.host, "127.0.0.1")

    def test_capability_on_a_bombed_allowlist_stays_a_plain_dict(self):
        section = {"allowlist": _DictItemsBomb({_UUID: dict(self._ENTRY)})}
        with mock.patch.object(
            vm_console, "settings_section", lambda name: section
        ):
            cap = vm_console.capability(
                backend="utm", vm_uuid=_UUID, running=True
            )
        self.assertTrue(cap["available"])
        _starlette(cap)


if __name__ == "__main__":
    unittest.main(verbosity=2)
