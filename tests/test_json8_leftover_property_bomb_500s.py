"""JSON sweep #8: raising-*property* 500s in the coded-error body builder.

Sweep #7 sealed ``hub.errors._jsonable_param`` against the leftover *subclass*
zoo — an ``int`` whose ``__index__``/``__str__`` raises, a ``float`` whose
``__eq__`` blows the NaN/inf probe, a ``str`` subclass whose bound ``.encode``
is a bomb, a ``bytes`` subclass whose ``decode`` raises, and ``dict``/``list``
subclasses whose ``items()``/``__iter__`` raises.  Every one of those overrides
a *method*.

Two leftover shapes survived that: a raising **descriptor**.

* ``__class__`` as a property that raises.  ``isinstance(value, int)`` (and the
  five sibling checks) read ``value.__class__`` when the concrete type is not
  an exact/subtype match, so the very first ``isinstance`` in the sanitizer
  raised straight out of it — a raw HTTP 500 while building a coded error's own
  body, the exact failure mode the helper exists to prevent.  This is the
  account8 ``__class__``-property class, reaching the shared *write*-side
  jsonable that the read-side siblings were hardened against.

* ``isoformat`` as a property that raises.  ``getattr(value, "isoformat",
  None)`` returns the default only on ``AttributeError``; a raising descriptor
  is not ``AttributeError``, so the date-probe lookup itself raised before
  ``callable`` ever ran.

The fix keeps the file's convention: ``isinstance`` goes through a guarded
``_isinst`` (a raising ``__class__`` is treated as "none of these types" and
laundered by the ``str(value)`` tail), and the ``isoformat`` lookup is wrapped
so a raising descriptor drops to ``None`` instead of escaping.  Well-behaved
subclasses and real ``date``/``datetime`` params keep answering.

Also pinned here — vectors that were *already* immune, so a later refactor
cannot silently reopen them:

* a ``dict`` mapping key that is a ``str`` subclass with a self-``__str__`` and
  a bomb ``.encode`` (sealed by the unbound ``str.encode`` on keys);
* ``__bool__`` / ``__len__`` / ``__getitem__`` scalar bombs (the sanitizer
  never tests truthiness, length or subscript, so they fall to ``str(value)``);
* an ``isoformat`` *method* (not property) that raises (already in a try).
"""
from __future__ import annotations

import datetime
import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import errors, ollama_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import settings_api


# --- raising descriptors (the two live sweep-8 bombs) ---
class ClassPropBomb:
    """``__class__`` is a property that raises: every ``isinstance`` in the
    sanitizer reads it, so the type dispatch used to blow out of the helper."""

    @property
    def __class__(self):  # noqa: D401 - descriptor, not a type
        raise RuntimeError("class bomb")

    def __str__(self):
        return "cp-payload"


class IsoPropBomb:
    """``isoformat`` is a property that raises — ``getattr`` does not swallow a
    raising descriptor, so the date probe lookup used to escape."""

    @property
    def isoformat(self):
        raise RuntimeError("iso prop bomb")

    def __str__(self):
        return "iso-payload"


# --- already-immune leftovers, pinned so they stay immune ---
class SelfStrEncodeKey(str):
    """A str-subclass mapping key: ``str(x)`` keeps the subclass, so a *bound*
    ``.encode`` would dispatch into the bomb — the unbound ``str.encode`` on
    keys already defuses it."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("key encode bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")

    def __str__(self):
        return "bool-payload"


class LenBomb:
    def __len__(self):
        raise RuntimeError("len bomb")

    def __str__(self):
        return "len-payload"


class GetItemBomb:
    def __getitem__(self, key):
        raise RuntimeError("getitem bomb")

    def __str__(self):
        return "getitem-payload"


class IsoMethodBomb:
    """``isoformat`` as a *method* that raises — the call is already in a try;
    pinned so it stays that way alongside the new property guard."""

    def isoformat(self):
        raise RuntimeError("iso method bomb")

    def __str__(self):
        return "isom-payload"


def _renderable(out) -> None:
    """Whatever the sanitizer returns must survive Starlette's own encoder."""
    json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")


class JsonableParamPropertyBombPins(unittest.TestCase):
    """The helper never raises on a raising descriptor, and returns renderable
    output while keeping the value's carried text where it can."""

    def test_class_prop_bomb_launders_not_raises(self):
        out = errors._jsonable_param(ClassPropBomb())
        self.assertIsInstance(out, str)
        _renderable(out)

    def test_class_prop_bomb_nested_in_list(self):
        out = errors._jsonable_param([ClassPropBomb(), "keep"])
        self.assertIsInstance(out[0], str)
        self.assertEqual(out[1], "keep")
        _renderable(out)

    def test_class_prop_bomb_nested_in_dict_keeps_siblings(self):
        out = errors._jsonable_param({"bad": ClassPropBomb(), "ok": "keep"})
        self.assertIsInstance(out["bad"], str)
        self.assertEqual(out["ok"], "keep")
        _renderable(out)

    def test_iso_prop_bomb_launders_to_its_text(self):
        out = errors._jsonable_param(IsoPropBomb())
        self.assertEqual(out, "iso-payload")
        _renderable(out)

    def test_iso_prop_bomb_nested_keeps_siblings(self):
        out = errors._jsonable_param({"bad": IsoPropBomb(), "ok": "keep"})
        self.assertEqual(out["bad"], "iso-payload")
        self.assertEqual(out["ok"], "keep")
        _renderable(out)

    # --- stays-immune pins ---
    def test_self_str_encode_mapping_key_stays_immune(self):
        out = errors._jsonable_param({SelfStrEncodeKey("mykey"): "v"})
        self.assertEqual(out, {"mykey": "v"})
        _renderable(out)

    def test_bool_bomb_scalar_stays_immune(self):
        self.assertEqual(errors._jsonable_param(BoolBomb()), "bool-payload")

    def test_len_bomb_scalar_stays_immune(self):
        self.assertEqual(errors._jsonable_param(LenBomb()), "len-payload")

    def test_getitem_bomb_scalar_stays_immune(self):
        self.assertEqual(errors._jsonable_param(GetItemBomb()), "getitem-payload")

    def test_iso_method_bomb_stays_immune(self):
        self.assertEqual(errors._jsonable_param(IsoMethodBomb()), "isom-payload")

    def test_real_date_still_isoformats(self):
        out = errors._jsonable_param(datetime.date(2026, 1, 2))
        self.assertEqual(out, "2026-01-02")

    def test_real_datetime_still_isoformats(self):
        out = errors._jsonable_param(datetime.datetime(2026, 1, 2, 3, 4, 5))
        self.assertEqual(out, "2026-01-02T03:04:05")

    def test_healthy_scalars_untouched(self):
        self.assertEqual(errors._jsonable_param("plain"), "plain")
        self.assertEqual(errors._jsonable_param(42), 42)
        self.assertEqual(errors._jsonable_param(3.5), 3.5)
        self.assertIs(errors._jsonable_param(True), True)
        self.assertIsNone(errors._jsonable_param(None))


class ErrorPayloadPropertyBombPins(unittest.TestCase):
    """``error_payload`` / ``api_error`` / ``soft_fail`` build the coded body
    over a raising-descriptor param instead of raising out of the builder."""

    def test_api_error_survives_property_bombs(self):
        for bomb in (ClassPropBomb(), IsoPropBomb()):
            with self.subTest(bomb=type(bomb).__name__):
                exc = errors.api_error("services.not_found", id=bomb)
                self.assertEqual(exc.status_code, 404)
                self.assertEqual(exc.detail["code"], "services.not_found")
                _renderable({"detail": exc.detail})

    def test_error_payload_survives_property_bombs(self):
        for bomb in (ClassPropBomb(), IsoPropBomb()):
            with self.subTest(bomb=type(bomb).__name__):
                status, body = errors.error_payload("services.not_found", id=bomb)
                self.assertEqual(status, 404)
                self.assertEqual(body["detail"]["code"], "services.not_found")
                self.assertIn("id", body["detail"]["params"])
                _renderable(body)

    def test_soft_fail_survives_property_bomb(self):
        out = errors.soft_fail("power.bad_key", key=ClassPropBomb())
        self.assertEqual(out["ok"], False)
        self.assertEqual(out["code"], "power.bad_key")
        _renderable(out)

    def test_jsonable_error_detail_survives_property_bomb(self):
        out = errors.jsonable_error_detail(
            [{"loc": ["body", "x"], "msg": "bad", "input": IsoPropBomb()}]
        )
        self.assertEqual(out[0]["input"], "iso-payload")
        _renderable(out)


class CodedErrorRoutePropertyBombPin(unittest.TestCase):
    """Over the real mounted stack: a handler that raises a coded error whose
    param is a raising-descriptor leftover answers the coded status, not a raw
    500.  A leftover cannot ride a JSON request body, so it is injected at the
    one boundary a route reads it from — mirroring the read-side sweeps that
    mock ``cfg()``.  Before the fix, ``api_error`` raised ``RuntimeError``
    inside the handler while building the body, so PUT /api/settings 500'd."""

    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def test_put_settings_bad_ollama_url_answers_coded_400_not_500(self):
        def _raise(_url):
            raise errors.api_error("ollama.bad_url", url=ClassPropBomb())

        client = self._client()
        with mock.patch.object(ollama_svc, "validate_settings_url", _raise), \
                mock.patch.object(settings_api.ollama_svc, "validate_settings_url", _raise):
            resp = client.put("/api/settings", json={"ollama": {"url": "http://x"}})
        self.assertEqual(resp.status_code, 400, resp.text[:400])
        self.assertEqual(resp.json()["detail"]["code"], "ollama.bad_url")
        json.dumps(resp.json(), ensure_ascii=False, allow_nan=False).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
