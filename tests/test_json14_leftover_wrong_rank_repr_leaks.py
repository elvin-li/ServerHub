"""JSON sweep #14: wrong-rank drops behind a lying ``__class__``, default
``object.__repr__`` heap-address leaks, and bound materialisers vaporising
honest storage — in the error sanitizer itself.

json13 sealed the BaseException bomb family; every guard in hub/errors.py
re-raises genuine control flow and launders the rest.  What stayed live is
the maint14/account14/bookmarks14 leftover family, on the one module whose
output *is* the HTTP error body:

* **Wrong-rank drops behind a lying ``__class__``** — ``isinstance``
  consults ``value.__class__`` only after the real-MRO check misses, so a
  lying claim steered a param into the arm of its *claim*, the unbound base
  operation there rejected the real layout, and the old early ``return
  None`` threw honest renderable storage away at the wrong rank: a genuine
  str ip claiming int wiped to null, a genuine int claiming bool vanished,
  a genuine bytes name claiming str went dark, a genuine list claiming dict
  dropped whole.  The rejected arms now fall through to the arm the *real*
  storage (``type(value)``, which the lie cannot swap) matches; a total
  impostor keeps its established json9 ``None`` drop.

* **Default ``object.__repr__`` heap-address leaks** — the ``str(value)``
  tail, the ``str(k)`` key coercion, ``_clean_code``'s ``str(code)``
  degrade, ``error_payload``'s raw ``template.format(**params)`` step and
  ``exc_detail``'s ``str(exc)`` tail each ran a dispatching render on any
  leftover shape, so a type that never overrode ``__str__``/``__repr__``
  served ``<X object at 0x7f...>`` — a raw heap address — verbatim in the
  coded error's params, as a JSON *key*, in both the ``code`` and
  ``message`` slots of a built 500 body, in a formatted message, and in a
  coded ``{detail}`` param.  The slot probe on the real type drops the
  shape and the address-regex belt catches what the probe cannot see
  (function/bound-method C-level reprs, a custom ``__repr__`` embedding
  one).  Both run on the *coercion* arms only: real str storage is data —
  a param quoting a Python repr serves verbatim.

* **Bound nested materialisers** — ``list(value.items())`` and
  ``list(value)`` dispatched a real subclass's overridden hook, so an
  ``items()``/``__iter__`` bomb whose C-level storage was perfectly
  walkable vaporised to null even though the raise was absorbed.  The dict
  arm now copies through the C-level storage and snapshots
  ``list(dict.items(...))`` first; the sequence arm iterates through the
  unbound bases, real layout first-come.  The json7/json9/json13 pins that
  asserted the dropped shape are updated to the recovered shape (the
  maint14/bookmarks14 rule).

Also pinned so a refactor cannot reopen them: the mid-walk mutation seal
(the item snapshots keep siblings rendering when a nested value's guarded
hook mutates its own container), healthy messages staying byte-identical
through the new format proxy, real str data carrying an address-shaped
substring staying verbatim, the json9 total-impostor drops, and control
flow propagating through every new seam.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import errors, wireguard_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_ADDR = " at 0x"


def _renderable(out) -> None:
    """Whatever reaches Starlette's allow_nan=False encoder must survive it."""
    json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")


class Plain:
    """No ``__str__``/``__repr__`` override: rendering it can only answer the
    default ``object.__repr__`` — a raw heap address."""


class AddrRepr:
    """A custom ``__repr__`` embedding the CPython angle-repr shape — the
    slot probe cannot see it; the address belt must."""

    def __repr__(self):
        return f"<AddrRepr thing at 0x{id(self):x}>"


def _lie(cls):
    return property(lambda self: cls)


class StrClaimsInt(str):
    """Genuine str storage whose ``__class__`` lies int — the int arm's
    ``int.__index__`` refused it and the old early return wiped the text."""

    __class__ = _lie(int)


class IntClaimsBool(int):
    """Genuine int storage claiming bool — used to vanish at the bool gate."""

    __class__ = _lie(bool)


class IntClaimsStr(int):
    """Genuine int storage claiming str — the unbound encode refused it."""

    __class__ = _lie(str)


class FloatClaimsInt(float):
    __class__ = _lie(int)


class BytesClaimsStr(bytes):
    __class__ = _lie(str)


class ByteArrayClaimsStr(bytearray):
    __class__ = _lie(str)


class ListClaimsDict(list):
    """Genuine list storage claiming dict — the dict arm's copy still reads
    no mapping (a scalar list is not pairs), so the walk must fall through
    to the sequence arm instead of the old whole-node drop."""

    __class__ = _lie(dict)


class DictClaimsInt(dict):
    __class__ = _lie(int)


class TupleClaimsBytes(tuple):
    __class__ = _lie(bytes)


class StrKeyClaimsBytes(str):
    """A genuine str mapping *key* claiming bytes — the old key path handed
    it to the bytes copy, which refused it, and dropped the whole entry."""

    __class__ = _lie(bytes)


class BytesKeyClaimsStr(bytes):
    """A genuine bytes key claiming str — the unbound encode refused it and
    the entry vanished instead of decoding."""

    __class__ = _lie(str)


def _total_liar(cls):
    """Real type is a plain object; the claim is pure fiction — keeps the
    established json9 ``None`` drop (its honest ``__str__`` is *not*
    laundered into data at a rank it never earned)."""


    class Liar:
        __class__ = _lie(cls)

        def __str__(self):
            return "liar-text"

    return Liar()


class ItemsBombDict(dict):
    def items(self):
        raise RuntimeError("items bomb")


class NonPairItemsDict(dict):
    def items(self):
        return [1, 2]


class IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class IterBombTuple(tuple):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class IterBombSet(set):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class MutatesParentMidWalk:
    """A nested value whose guarded render hook mutates its own container —
    the snapshot walk must keep every sibling answering (stays-sealed pin
    for the maint14 mutation shape)."""

    def __init__(self):
        self.parent = None

    def __str__(self):
        container = self.parent
        if isinstance(container, dict):
            for k in [k for k in container if k != "bomb"]:
                container.pop(k, None)
        elif isinstance(container, list):
            del container[:]
        return "mutated"


class WrongRankRecoveryPins(unittest.TestCase):
    """A lying ``__class__`` cannot make the sanitizer throw honest storage
    away at the wrong rank — the real layout's arm picks the value up."""

    def test_str_storage_claiming_int_keeps_its_text(self):
        out = errors._jsonable_param(StrClaimsInt("10.0.0.7"))
        self.assertEqual(out, "10.0.0.7")
        self.assertIs(type(out), str)
        _renderable(out)

    def test_int_storage_claiming_bool_keeps_its_number(self):
        out = errors._jsonable_param(IntClaimsBool(7))
        self.assertEqual(out, 7)
        self.assertIs(type(out), int)
        _renderable(out)

    def test_int_storage_claiming_str_keeps_its_number(self):
        out = errors._jsonable_param(IntClaimsStr(42))
        self.assertEqual(out, 42)
        self.assertIs(type(out), int)

    def test_float_storage_claiming_int_keeps_its_number(self):
        out = errors._jsonable_param(FloatClaimsInt(1.5))
        self.assertEqual(out, 1.5)
        self.assertIs(type(out), float)

    def test_bytes_storage_claiming_str_decodes(self):
        self.assertEqual(errors._jsonable_param(BytesClaimsStr(b"name")),
                         "name")
        self.assertEqual(
            errors._jsonable_param(ByteArrayClaimsStr(b"name")), "name")

    def test_list_storage_claiming_dict_keeps_its_elements(self):
        out = errors._jsonable_param(ListClaimsDict([1, 2]))
        self.assertEqual(out, [1, 2])
        _renderable(out)

    def test_dict_storage_claiming_int_keeps_its_entries(self):
        out = errors._jsonable_param(DictClaimsInt(a=1))
        self.assertEqual(out, {"a": 1})
        _renderable(out)

    def test_tuple_storage_claiming_bytes_keeps_its_elements(self):
        out = errors._jsonable_param(TupleClaimsBytes(("x", 2)))
        self.assertEqual(out, ["x", 2])
        _renderable(out)

    def test_total_impostors_keep_the_json9_none_drop(self):
        for cls in (bool, int, float, str, bytes, bytearray, dict,
                    list, tuple, set, frozenset):
            with self.subTest(claim=cls.__name__):
                self.assertIsNone(errors._jsonable_param(_total_liar(cls)))

    def test_str_key_claiming_bytes_keeps_its_entry(self):
        out = errors._jsonable_param({StrKeyClaimsBytes("k"): "v", "ok": 1})
        self.assertEqual(out, {"k": "v", "ok": 1})
        _renderable(out)

    def test_bytes_key_claiming_str_keeps_its_entry(self):
        out = errors._jsonable_param({BytesKeyClaimsStr(b"k"): "v", "ok": 1})
        self.assertEqual(out, {"k": "v", "ok": 1})
        _renderable(out)

    def test_lying_impostor_keys_still_drop_alone(self):
        # The json9 key contract holds: a claim with no text storage
        # underneath drops just its entry.
        out = errors._jsonable_param(
            {_total_liar(str): "gone", _total_liar(bytes): "gone", "ok": 1})
        self.assertEqual(out, {"ok": 1})
        _renderable(out)


class ReprAddressLeakPins(unittest.TestCase):
    """No coercion arm in the module may serve a raw heap address."""

    def test_plain_object_param_drops_instead_of_leaking(self):
        self.assertIsNone(errors._jsonable_param(Plain()))

    def test_function_object_param_drops_instead_of_leaking(self):
        # C-level reprs (`<function f at 0x...>`) carry the same address
        # shape without the default-slot signature — the belt's job.
        self.assertIsNone(errors._jsonable_param(lambda: None))

    def test_custom_repr_embedding_an_address_drops(self):
        self.assertIsNone(errors._jsonable_param(AddrRepr()))

    def test_plain_object_mapping_key_drops_its_entry_alone(self):
        out = errors._jsonable_param({Plain(): "gone", "ok": 1})
        self.assertEqual(out, {"ok": 1})
        _renderable(out)

    def test_honest_non_str_keys_still_coerce(self):
        out = errors._jsonable_param({1: "a", 2.5: "b"})
        self.assertEqual(out, {"1": "a", "2.5": "b"})

    def test_real_str_data_with_address_shape_stays_verbatim(self):
        # The account14 rule: the belt runs on coercion arms only — real str
        # storage quoting a Python repr is data.
        text = "worker <Thread(w0) at 0xdeadbeef> died"
        self.assertEqual(errors._jsonable_param(text), text)

    def test_plain_object_code_takes_the_placeholder_not_the_address(self):
        status, body = errors.error_payload(Plain())
        self.assertEqual(status, 500)
        self.assertEqual(body["detail"]["code"], "error.unrenderable")
        self.assertNotIn(_ADDR, json.dumps(body))
        _renderable(body)

    def test_plain_object_param_cannot_leak_into_the_message(self):
        # The raw format step used to render the default repr straight into
        # the coded message; it now degrades exactly like a __format__ bomb.
        status, body = errors.error_payload("wg.subnet_full", subnet=Plain())
        self.assertEqual(status, 409)
        self.assertEqual(body["detail"]["message"],
                         "no free address left in {subnet}")
        self.assertIsNone(body["detail"]["params"]["subnet"])
        self.assertNotIn(_ADDR, json.dumps(body))
        _renderable(body)

    def test_custom_format_rendering_an_address_degrades_too(self):
        class AddrFormat:
            def __format__(self, spec):
                return f"<AddrFormat at 0x{id(self):x}>"

        status, body = errors.error_payload(
            "wg.subnet_full", subnet=AddrFormat())
        self.assertEqual(status, 409)
        self.assertEqual(body["detail"]["message"],
                         "no free address left in {subnet}")
        self.assertNotIn(_ADDR, json.dumps(body))

    def test_exc_detail_degrades_the_address_to_the_error_token(self):
        # The same "error" token every other unreadable-message arm answers
        # (the bookmarks14 ``_error_text`` seam builds on it).
        out = errors.exc_detail(Exception(Plain()))
        self.assertEqual(out, "error")
        self.assertNotIn(_ADDR, out)

    def test_soft_fail_shares_the_belt(self):
        out = errors.soft_fail("power.bad_key", key=Plain())
        self.assertEqual(out["ok"], False)
        self.assertEqual(out["code"], "power.bad_key")
        self.assertNotIn(_ADDR, json.dumps(out))
        _renderable(out)

    def test_api_error_from_params_cannot_leak_an_address(self):
        class Bomb(Exception):
            code = "wg.ip_in_use"
            params = {"ip": Plain()}

        exc = errors.api_error_from(Bomb())
        self.assertEqual(exc.status_code, 409)
        self.assertIsNone(exc.detail["params"]["ip"])
        self.assertNotIn(_ADDR, json.dumps({"detail": exc.detail}))


class UnboundMaterialiserPins(unittest.TestCase):
    """Real subclass storage recovers through the C-level reads; total
    impostors keep their drops."""

    def test_items_bomb_dict_recovers_its_entries(self):
        out = errors._jsonable_param(ItemsBombDict(a=1, b="x"))
        self.assertEqual(out, {"a": 1, "b": "x"})
        _renderable(out)

    def test_non_pair_items_dict_recovers_its_entries(self):
        out = errors._jsonable_param(NonPairItemsDict(a=1))
        self.assertEqual(out, {"a": 1})

    def test_iter_bomb_list_recovers_its_elements(self):
        self.assertEqual(errors._jsonable_param(IterBombList([1, 2])), [1, 2])

    def test_iter_bomb_tuple_recovers_its_elements(self):
        self.assertEqual(
            errors._jsonable_param(IterBombTuple(("a", 3))), ["a", 3])

    def test_iter_bomb_set_recovers_its_elements(self):
        out = errors._jsonable_param(IterBombSet({5}))
        self.assertEqual(out, [5])

    def test_nested_bombs_recover_inside_a_healthy_mapping(self):
        out = errors._jsonable_param(
            {"rows": ItemsBombDict(a=1), "seq": IterBombList([2]), "ok": "k"})
        self.assertEqual(out, {"rows": {"a": 1}, "seq": [2], "ok": "k"})
        _renderable(out)


class MidWalkMutationPins(unittest.TestCase):
    """The item snapshots hold: a nested value's guarded hook mutating its
    own container mid-walk cannot vaporise the siblings (stays-sealed)."""

    def test_dict_walk_survives_a_mutating_value(self):
        bomb = MutatesParentMidWalk()
        parent = {"a": 1, "bomb": bomb, "z": 2}
        bomb.parent = parent
        out = errors._jsonable_param(parent)
        self.assertEqual(out, {"a": 1, "bomb": "mutated", "z": 2})
        _renderable(out)

    def test_list_walk_survives_a_mutating_element(self):
        bomb = MutatesParentMidWalk()
        parent = ["a", bomb, "z"]
        bomb.parent = parent
        out = errors._jsonable_param(parent)
        self.assertEqual(out, ["a", "mutated", "z"])
        _renderable(out)


class HealthyFormatPins(unittest.TestCase):
    """The format proxy keeps every healthy message byte-identical."""

    def test_str_int_and_subclass_params_format_unchanged(self):
        status, body = errors.error_payload(
            "wg.subnet_full", subnet="10.0.0.0/24")
        self.assertEqual(body["detail"]["message"],
                         "no free address left in 10.0.0.0/24")
        status, body = errors.error_payload("auth.rate_limited", retry=30)
        self.assertEqual(body["detail"]["message"],
                         "too many attempts, retry in 30 seconds")

    def test_real_str_param_with_address_shape_stays_verbatim_in_message(self):
        status, body = errors.error_payload(
            "files.not_found", path="log <tail at 0xdead> marker")
        self.assertEqual(body["detail"]["message"],
                         "not found: log <tail at 0xdead> marker")
        self.assertEqual(body["detail"]["params"]["path"],
                         "log <tail at 0xdead> marker")

    def test_unreferenced_bomb_params_stay_dormant(self):
        # ``str.format`` renders only the fields the template names — a bomb
        # in an unreferenced param must not change the message.
        class Bomb:
            def __format__(self, spec):
                raise RuntimeError("format bomb")

        status, body = errors.error_payload(
            "files.not_found", path="/x", junk=Bomb())
        self.assertEqual(body["detail"]["message"], "not found: /x")


class ControlFlowPassthroughPins(unittest.TestCase):
    """Genuine control flow keeps propagating through every new seam."""

    def test_key_coercion_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(kind=kind.__name__):
                class Bomb:
                    def __hash__(self):
                        return 14

                    def __str__(self, _kind=kind):
                        raise _kind()

                with self.assertRaises(kind):
                    errors._jsonable_param({Bomb(): "v"})

    def test_format_proxy_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(kind=kind.__name__):
                class Bomb:
                    def __format__(self, spec, _kind=kind):
                        raise _kind()

                with self.assertRaises(kind):
                    errors.error_payload("files.not_found", path=Bomb())

    def test_clean_code_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(kind=kind.__name__):
                class Bomb:
                    def __str__(self, _kind=kind):
                        raise _kind()

                with self.assertRaises(kind):
                    errors.error_payload(Bomb())


class HttpRoutePins(unittest.TestCase):
    """Over the real mounted stack: the sealed leaks and wrong-rank drops
    answer coded JSON with honest params and no heap address."""

    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def _coded_json(self, resp) -> dict:
        body = resp.json()
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return body["detail"]

    def test_plain_object_param_cannot_leak_an_address_over_http(self):
        def _raise():
            raise wireguard_svc.WireGuardError("wg.subnet_full",
                                               subnet=Plain())

        client = self._client()
        with mock.patch.object(wireguard_svc, "next_ip", _raise):
            resp = client.get("/api/wireguard/next-ip")
        self.assertEqual(resp.status_code, 409, resp.text[:400])
        detail = self._coded_json(resp)
        self.assertEqual(detail["code"], "wg.subnet_full")
        self.assertEqual(detail["message"], "no free address left in {subnet}")
        self.assertIsNone(detail["params"]["subnet"])
        self.assertNotIn(_ADDR, resp.text)

    def test_wrong_rank_param_recovers_over_http(self):
        def _raise():
            raise wireguard_svc.WireGuardError("wg.ip_in_use",
                                               ip=StrClaimsInt("10.0.0.9"))

        client = self._client()
        with mock.patch.object(wireguard_svc, "next_ip", _raise):
            resp = client.get("/api/wireguard/next-ip")
        self.assertEqual(resp.status_code, 409, resp.text[:400])
        detail = self._coded_json(resp)
        self.assertEqual(detail["code"], "wg.ip_in_use")
        self.assertEqual(detail["params"], {"ip": "10.0.0.9"})
        self.assertEqual(detail["message"], "10.0.0.9 is already assigned")

    def test_healthy_typed_errors_keep_their_exact_http_shape(self):
        def _raise():
            raise wireguard_svc.WireGuardError(
                "wg.subnet_full", subnet="10.0.0.0/24")

        client = self._client()
        with mock.patch.object(wireguard_svc, "next_ip", _raise):
            resp = client.get("/api/wireguard/next-ip")
        self.assertEqual(resp.status_code, 409, resp.text[:400])
        detail = self._coded_json(resp)
        self.assertEqual(detail["code"], "wg.subnet_full")
        self.assertEqual(detail["message"],
                         "no free address left in 10.0.0.0/24")
        self.assertEqual(detail["params"], {"subnet": "10.0.0.0/24"})

    def test_product_version_stays_pinned(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.5")


if __name__ == "__main__":
    unittest.main()
