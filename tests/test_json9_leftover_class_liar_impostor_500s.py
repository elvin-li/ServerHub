"""JSON sweep #9: lying-``__class__`` impostor 500s in the coded-error body.

Sweep #8 wrapped every ``isinstance`` in ``hub.errors._jsonable_param`` behind
``_isinst`` so a *raising* ``__class__`` property falls through to the guarded
``str(value)`` tail.  What that left open is the modules9 class: an impostor
whose ``__class__`` property *answers* a builtin type.  ``isinstance`` honours
the lie, so the value passes an arm's gate — and then that arm's unbound base
operation rejects the foreign operand with a ``TypeError`` outside any try.
Driven over the real mounted app (``create_app()`` + TestClient with
``raise_server_exceptions=False``), each of these turned a coded 4xx into a
raw HTTP 500 while building its own error body:

* a **bool liar** passed the very first gate and was returned *raw*;
  ``bool`` is final, so Starlette's ``allow_nan=False`` encoder (which checks
  the real type) raised ``TypeError: Object of type bool is not JSON
  serializable`` while rendering the response;
* a **str liar** passed ``_isinst(value, str)`` and blew the unbound
  ``str.encode(value, ...)`` — the descriptor is bound to the real str layout;
* a **bytes / bytearray liar** blew the ``bytes(value)`` copy the same way;
* a **str-lying / bytes-lying mapping key** inside a real dict param blew the
  key coercions (``bytes(k)`` / unbound ``str.encode(k, ...)``);
* an ``items()`` that yields **non-pairs** (an overriding dict subclass, or a
  dict-lying impostor's own ``items()``) blew the ``for k, v in items`` tuple
  unpack outside the ``list(value.items())`` try.

The fix keeps the modules9 convention: each unbound base call runs in a try
(a raise means "not really this type", so the impostor drops to ``None`` like
the lying numeric coercions), hostile mapping *entries* drop alone so healthy
siblings keep rendering, and the bool gate renders only ``type(value) is
bool``.  ``_isinst`` and the json5-8 pins are unchanged.

Also pinned here — vectors that were *already* immune, so a later refactor
cannot silently reopen them:

* dict / list / tuple / set / frozenset liars (``list(value.items())`` /
  ``list(value)`` already ran in a try, so they drop to ``None``);
* real bools, healthy scalars, and the real-subclass laundering the json6/7
  sweeps pinned (an int/str subclass carrying a real value still answers).
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import errors, ollama_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import settings_api


def _liar(cls, text):
    """An object whose ``__class__`` property answers *cls* while its real
    type is a plain object — it passes ``isinstance`` gates it has no right
    to, then the arm's unbound base operation rejects it."""

    class Liar:
        __class__ = property(lambda self: cls)

        def __str__(self):
            return text

    return Liar()


class NonPairItemsDict(dict):
    """A real dict subclass whose ``items()`` yields non-pairs: the bound
    call itself succeeds, so the old ``for k, v in items`` unpack blew."""

    def items(self):
        return [1, 2]


class DictLiarWithItems:
    """A dict-lying impostor carrying its *own* ``items()`` that yields
    non-pairs — the bound ``value.items()`` succeeds, the unpack used to
    blow."""

    __class__ = property(lambda self: dict)

    def items(self):
        return ["not-a-pair"]


def _renderable(out) -> None:
    """Whatever the sanitizer returns must survive Starlette's own encoder."""
    json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")


class JsonableParamLiarPins(unittest.TestCase):
    """The helper never raises on a lying ``__class__`` impostor, and never
    returns one raw to the ``allow_nan=False`` encoder."""

    def test_bool_liar_drops_to_null_not_raw(self):
        out = errors._jsonable_param(_liar(bool, "bool-payload"))
        self.assertIsNone(out)
        _renderable(out)

    def test_str_liar_drops_to_null_not_typeerror(self):
        out = errors._jsonable_param(_liar(str, "str-payload"))
        self.assertIsNone(out)
        _renderable(out)

    def test_bytes_and_bytearray_liars_drop_to_null(self):
        for cls in (bytes, bytearray):
            with self.subTest(cls=cls.__name__):
                out = errors._jsonable_param(_liar(cls, "b-payload"))
                self.assertIsNone(out)
                _renderable(out)

    def test_liars_nested_in_dict_keep_siblings(self):
        out = errors._jsonable_param({
            "bool": _liar(bool, "x"),
            "str": _liar(str, "x"),
            "bytes": _liar(bytes, "x"),
            "ok": "keep",
        })
        self.assertIsNone(out["bool"])
        self.assertIsNone(out["str"])
        self.assertIsNone(out["bytes"])
        self.assertEqual(out["ok"], "keep")
        _renderable(out)

    def test_liars_nested_in_list_keep_siblings(self):
        out = errors._jsonable_param([_liar(bool, "x"), "keep",
                                      _liar(str, "x")])
        self.assertEqual(out, [None, "keep", None])
        _renderable(out)

    def test_str_liar_mapping_key_drops_the_entry_alone(self):
        out = errors._jsonable_param({_liar(str, "k"): "gone", "ok": 1})
        self.assertEqual(out, {"ok": 1})
        _renderable(out)

    def test_bytes_liar_mapping_key_drops_the_entry_alone(self):
        for cls in (bytes, bytearray):
            with self.subTest(cls=cls.__name__):
                out = errors._jsonable_param({_liar(cls, "k"): "gone", "ok": 1})
                self.assertEqual(out, {"ok": 1})
                _renderable(out)

    def test_non_pair_items_subclass_drops_entries_not_raises(self):
        out = errors._jsonable_param(NonPairItemsDict(a=1))
        self.assertEqual(out, {})
        _renderable(out)

    def test_dict_liar_with_non_pair_items_drops_entries_not_raises(self):
        out = errors._jsonable_param(DictLiarWithItems())
        self.assertEqual(out, {})
        _renderable(out)


class AlreadyImmuneLiarPins(unittest.TestCase):
    """Vectors the try-wrapped ``list(...)`` arms already defused — pinned so
    a refactor cannot reopen them."""

    def test_container_liars_stay_dropped(self):
        for cls in (dict, list, tuple, set, frozenset):
            with self.subTest(cls=cls.__name__):
                out = errors._jsonable_param(_liar(cls, "c-payload"))
                self.assertIsNone(out)
                _renderable(out)

    def test_real_bools_stay_identical(self):
        self.assertIs(errors._jsonable_param(True), True)
        self.assertIs(errors._jsonable_param(False), False)

    def test_healthy_scalars_untouched(self):
        self.assertEqual(errors._jsonable_param("plain"), "plain")
        self.assertEqual(errors._jsonable_param(42), 42)
        self.assertEqual(errors._jsonable_param(3.5), 3.5)
        self.assertIsNone(errors._jsonable_param(None))

    def test_real_subclasses_still_launder_their_payloads(self):
        """The json6/7 contract: a well-behaved subclass carrying a real
        value keeps answering — only impostors drop."""

        class SelfStr(str):
            def __str__(self):
                return self

        self.assertEqual(errors._jsonable_param(SelfStr("svc-9")), "svc-9")
        self.assertEqual(errors._jsonable_param(bytes(b"port")), "port")
        self.assertEqual(
            errors._jsonable_param({SelfStr("k9"): "v"}), {"k9": "v"})


class ErrorPayloadLiarPins(unittest.TestCase):
    """``error_payload`` / ``api_error`` / ``soft_fail`` build the coded body
    over a lying-``__class__`` param instead of raising or handing Starlette
    an unserializable object."""

    def _bombs(self):
        return (
            _liar(bool, "b"), _liar(str, "s"), _liar(bytes, "y"),
            _liar(bytearray, "ya"), NonPairItemsDict(a=1),
            DictLiarWithItems(),
        )

    def test_api_error_survives_liar_params(self):
        for bomb in self._bombs():
            with self.subTest(bomb=type(bomb).__name__):
                exc = errors.api_error("services.not_found", id=bomb)
                self.assertEqual(exc.status_code, 404)
                self.assertEqual(exc.detail["code"], "services.not_found")
                _renderable({"detail": exc.detail})

    def test_error_payload_survives_liar_params(self):
        for bomb in self._bombs():
            with self.subTest(bomb=type(bomb).__name__):
                status, body = errors.error_payload(
                    "services.not_found", id=bomb)
                self.assertEqual(status, 404)
                self.assertEqual(body["detail"]["code"], "services.not_found")
                self.assertIn("id", body["detail"]["params"])
                _renderable(body)

    def test_soft_fail_survives_liar_param(self):
        out = errors.soft_fail("power.bad_key", key=_liar(bool, "k"))
        self.assertEqual(out["ok"], False)
        self.assertEqual(out["code"], "power.bad_key")
        _renderable(out)

    def test_jsonable_error_detail_survives_liars(self):
        out = errors.jsonable_error_detail(
            [{"loc": ["body", "x"], "msg": "bad",
              "input": _liar(str, "gone")}]
        )
        self.assertIsNone(out[0]["input"])
        self.assertEqual(out[0]["msg"], "bad")
        _renderable(out)


class CodedErrorRouteLiarPin(unittest.TestCase):
    """Over the real mounted stack: a handler that raises a coded error whose
    param is a lying-``__class__`` impostor answers the coded status, not a
    raw 500.  A leftover cannot ride a JSON request body, so it is injected at
    the one boundary a route reads it from — mirroring the json7/json8 pins.
    Before the fix, the bool liar rode the built body into Starlette's
    encoder (500 while *rendering* the coded 400) and the str liar raised
    ``TypeError`` inside ``api_error`` itself."""

    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def test_put_settings_bad_ollama_url_answers_coded_400_not_500(self):
        for bomb in (_liar(bool, "b"), _liar(str, "s"), _liar(bytes, "y")):
            with self.subTest(bomb=type(bomb).__name__):
                def _raise(_url, _bomb=bomb):
                    raise errors.api_error("ollama.bad_url", url=_bomb)

                client = self._client()
                with mock.patch.object(
                        ollama_svc, "validate_settings_url", _raise), \
                        mock.patch.object(settings_api.ollama_svc,
                                          "validate_settings_url", _raise):
                    resp = client.put("/api/settings",
                                      json={"ollama": {"url": "http://x"}})
                self.assertEqual(resp.status_code, 400, resp.text[:400])
                self.assertEqual(resp.json()["detail"]["code"],
                                 "ollama.bad_url")
                json.dumps(resp.json(), ensure_ascii=False,
                           allow_nan=False).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
