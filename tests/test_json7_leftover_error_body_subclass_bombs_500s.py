"""JSON sweep #7: subclass-bomb 500s in the coded-error body builder.

Every read-side ``_jsonable`` in the panel was hardened, sweep by sweep,
against the *leftover subclass* zoo — an ``int`` whose ``__index__``/``__str__``
raises (settings8/modules5), a ``float`` whose ``__eq__`` blows the NaN/inf
probe, a ``str`` subclass whose ``__str__`` returns itself so a bound
``.encode`` dispatches into its override (the json6 self-``__str__`` encode
bomb), a ``bytes`` subclass whose ``decode`` raises (modules5), and a
``dict``/``list`` subclass whose ``items()``/``__iter__`` raises (json5).

``hub.errors._jsonable_param`` — the *write* side that renders a coded
error's ``detail.params`` for Starlette's ``allow_nan=False`` encoder — was
the one shared jsonable helper that never got that treatment.  It had been
sealed for lone surrogates, ``.inf``, over-cap decimal ints and
``RecursionError``, but it still:

* ``str(value)`` an ``int`` subclass with a ValueError-only catch (an
  ``__index__``/``__str__`` bomb raised straight through);
* probed ``value != value`` / ``value in (inf, -inf)`` on a ``float``
  subclass, reflecting into its ``__eq__``;
* called the *bound* ``value.encode`` on a ``str`` subclass, and
  ``value.decode`` on a ``bytes`` subclass;
* iterated ``value.items()`` / the sequence comprehension unguarded.

So a coded 4xx whose param carried any such leftover turned into a raw HTTP
500 *while encoding its own error body* — the exact failure mode this helper
exists to prevent, one class of leftover behind the read-side siblings.

The fix is the established convention: base coercions
(``int.__index__`` / ``float.__float__``), unbound base ops
(``str.encode`` / ``bytes(...).decode``), and guarded ``list(...)`` /
``list(items())`` — with the carried text *preserved* (a subclass carrying a
real id/name still answers), only its overridden methods defused.
``error_payload``'s pre-clean ``template.format(**params)`` (which formats a
raw leftover referenced by a ``{placeholder}``) and its param-key encode are
sealed the same way.
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


# --- the leftover subclass zoo (carrying real, recoverable payloads) ---
class SelfStrEncode(str):
    """``str(x)`` keeps the subclass (``__str__`` returns self); the bound
    ``.encode`` then dispatches into the bomb — the json6 class."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("encode bomb")


class IndexStrInt(int):
    """An int subclass whose ``__index__`` and ``__str__`` both raise —
    past the old ValueError-only digit-cap catch."""

    def __index__(self):
        raise RuntimeError("index bomb")

    def __str__(self):
        raise RuntimeError("str bomb")


class EqFloat(float):
    """A float subclass whose ``__eq__`` blows the NaN/inf probe."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = float.__hash__


class DecodeBytes(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


class ItemsDict(dict):
    def items(self, *a, **k):
        raise RuntimeError("items bomb")


class IterList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class FormatBomb:
    """A ``{placeholder}`` param whose ``__format__`` raises — the raw format
    pass in ``error_payload`` runs before params are cleaned."""

    def __format__(self, spec):
        raise RuntimeError("format bomb")

    def __str__(self):
        raise RuntimeError("str bomb")


_OVER_CAP_INT = 1 << 20000  # str(x) ValueErrors on CPython's int->str cap
_SURROGATE = "a\ud800b"


class JsonableParamBombPins(unittest.TestCase):
    """The helper itself: every leftover launders, healthy values are kept."""

    def _renderable(self, out) -> None:
        # Whatever it returns must survive the same encoder Starlette uses.
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_self_str_encode_bomb_keeps_its_text(self):
        out = errors._jsonable_param(SelfStrEncode("svc-7"))
        self.assertEqual(out, "svc-7")
        self.assertIs(type(out), str)
        self._renderable(out)

    def test_int_index_str_bomb_recovers_the_real_value(self):
        # ``int.__index__`` reads the C-level value under the override, so the
        # real number is kept (as an exact int) rather than dropped.
        out = errors._jsonable_param(IndexStrInt(5))
        self.assertEqual(out, 5)
        self.assertIs(type(out), int)
        self._renderable(out)

    def test_float_eq_bomb_recovers_the_real_value(self):
        out = errors._jsonable_param(EqFloat(1.5))
        self.assertEqual(out, 1.5)
        self.assertIs(type(out), float)
        self._renderable(out)

    def test_bytes_decode_bomb_launders(self):
        out = errors._jsonable_param(DecodeBytes(b"port"))
        self.assertEqual(out, "port")
        self._renderable(out)

    def test_dict_items_bomb_recovers_its_real_entries(self):
        # json14 (the maint14/bookmarks14 rule): the dict arm copies through
        # the C-level storage, so a real subclass's ``items()`` bomb no
        # longer vaporises perfectly walkable entries to null.
        out = errors._jsonable_param(ItemsDict({"a": 1}))
        self.assertEqual(out, {"a": 1})
        self._renderable(out)

    def test_list_iter_bomb_recovers_its_real_elements(self):
        # json14: the sequence arm iterates through the unbound bases, so a
        # real subclass's ``__iter__`` bomb cannot vaporise its storage.
        out = errors._jsonable_param(IterList([1, 2]))
        self.assertEqual(out, [1, 2])
        self._renderable(out)

    def test_self_str_encode_bomb_as_dict_key_keeps_text(self):
        out = errors._jsonable_param({SelfStrEncode("k7"): "v"})
        self.assertEqual(out, {"k7": "v"})
        self._renderable(out)

    def test_nested_bomb_inside_healthy_structure(self):
        out = errors._jsonable_param(
            {"ok": "fine", "bad": IterList([1]), "n": SelfStrEncode("keep")}
        )
        self.assertEqual(out["ok"], "fine")
        # json14: the iter-bomb's real elements recover through the unbound
        # bases instead of the old null drop.
        self.assertEqual(out["bad"], [1])
        self.assertEqual(out["n"], "keep")
        self._renderable(out)

    def test_still_handles_the_old_reachable_leftovers(self):
        # The classes the helper was already written for must keep working.
        self.assertIsNone(errors._jsonable_param(_OVER_CAP_INT))
        self.assertIsNone(errors._jsonable_param(float("inf")))
        self.assertEqual(errors._jsonable_param(_SURROGATE), "a?b")
        self.assertEqual(errors._jsonable_param(b"\xff\xfe"), "\ufffd\ufffd")

    def test_healthy_scalars_untouched(self):
        self.assertEqual(errors._jsonable_param("plain"), "plain")
        self.assertEqual(errors._jsonable_param(42), 42)
        self.assertEqual(errors._jsonable_param(3.5), 3.5)
        self.assertIs(errors._jsonable_param(True), True)
        self.assertIsNone(errors._jsonable_param(None))


class ErrorPayloadBombPins(unittest.TestCase):
    """``error_payload`` / ``api_error`` / ``soft_fail`` build the coded body
    over a leftover param instead of raising out of the builder."""

    def _renderable(self, body) -> None:
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_api_error_construction_survives_bomb_params(self):
        for bomb in (
            SelfStrEncode("bad"), IndexStrInt(1), EqFloat(2.0),
            DecodeBytes(b"x"), ItemsDict({"a": 1}), IterList([1]),
            _OVER_CAP_INT, _SURROGATE,
        ):
            with self.subTest(bomb=type(bomb).__name__):
                exc = errors.api_error("services.not_found", id=bomb)
                self.assertEqual(exc.status_code, 404)
                self.assertEqual(exc.detail["code"], "services.not_found")
                self._renderable({"detail": exc.detail})

    def test_self_str_param_keeps_its_text_in_body(self):
        status, body = errors.error_payload("services.not_found", id=SelfStrEncode("svc-7"))
        self.assertEqual(status, 404)
        self.assertEqual(body["detail"]["params"]["id"], "svc-7")
        self._renderable(body)

    def test_format_bomb_in_referenced_placeholder_degrades(self):
        # ``vms.unknown_backend`` = "... {vm}" — the raw format pass touches
        # the leftover before the clean loop; a __format__ bomb used to 500.
        status, body = errors.error_payload("vms.unknown_backend", vm=FormatBomb())
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "vms.unknown_backend")
        self._renderable(body)

    def test_soft_fail_survives_bomb_params(self):
        out = errors.soft_fail("power.bad_key", key=SelfStrEncode("disksleep7"))
        self.assertEqual(out["ok"], False)
        self.assertEqual(out["code"], "power.bad_key")
        self.assertEqual(out["params"]["key"], "disksleep7")
        self._renderable(out)

    def test_jsonable_error_detail_survives_bomb(self):
        out = errors.jsonable_error_detail(
            [{"loc": ["body", "x"], "msg": "bad", "input": SelfStrEncode("keep")}]
        )
        self.assertEqual(out[0]["input"], "keep")
        self._renderable(out)


class CodedErrorRouteBombPin(unittest.TestCase):
    """Over the real mounted stack: a handler that raises a coded error whose
    param is a leftover answers the coded status, not a raw 500.

    A leftover subclass cannot ride a JSON request body (the parser yields
    plain types), so the poisoned param is injected at the one boundary a
    route reads it from — mirroring how the read-side sweeps mock ``cfg()``.
    Before the fix, ``api_error`` raised ``RuntimeError`` *inside* the handler
    while building the body, so PUT /api/settings answered 500 with no code.
    """

    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def test_put_settings_bad_ollama_url_answers_coded_400_not_500(self):
        def _raise(_url):
            raise errors.api_error("ollama.bad_url", url=SelfStrEncode("http://bad"))

        client = self._client()
        with mock.patch.object(ollama_svc, "validate_settings_url", _raise), \
                mock.patch.object(settings_api.ollama_svc, "validate_settings_url", _raise):
            resp = client.put("/api/settings", json={"ollama": {"url": "http://x"}})
        self.assertEqual(resp.status_code, 400, resp.text[:400])
        self.assertEqual(resp.json()["detail"]["code"], "ollama.bad_url")
        # The body Starlette encoded must re-encode under its own contract.
        json.dumps(resp.json(), ensure_ascii=False, allow_nan=False).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
