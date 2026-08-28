"""JSON sweep #13: BaseException-shaped bombs past ``except Exception`` in
the error sanitizer itself.

json11 laundered the code slot and the coded-detail unwrap; json12 sealed the
typed-error seam with ``api_error_from``.  Every one of those guards — and
every older ``_jsonable_param`` guard beneath them — stopped at ``except
Exception``.  hub/errors.py is the *last* sanitizer between a coded error and
Starlette's encoder, so a leftover whose hooks raise a *BaseException*
subclass (the watchdog/timeout shape the modules12/logs12/notify12 sweeps
sealed on their own surfaces) sailed past every catch in the module at once
and turned the coded body into a raw HTTP 500 built by the very machinery
that exists to prevent one:

* a ``__class__`` property raising BaseException blew ``_isinst`` — the gate
  every arm of ``_jsonable_param``, ``_clean_code``, ``exc_detail`` and
  ``api_error_from`` stands on;
* a param ``__format__``/``__str__`` BaseException bomb blew
  ``error_payload``'s format step and ``_jsonable_param``'s str tail;
* the json12 seam re-opened one step at a time: a typed error's ``code`` /
  ``params`` property, its params ``items()`` rebuild and its key laundering
  each raised the same BaseException straight back out of the guard that had
  just sealed the Exception-shaped twin;
* ``exc_detail``'s per-field unwrap (the detail read, the unbound
  ``dict.get`` probes, the ``bool(params)`` pick) blew the same way inside
  callers' own except clauses.

The fix is the modules12/logs12 convention: every guard re-raises genuine
control flow (KeyboardInterrupt, SystemExit) and launders everything else
BaseException-shaped exactly like its Exception twin — drop the poisoned
value or entry alone, keep the code/message beside it answering.

Also pinned — so a refactor cannot reopen them: control flow itself keeps
propagating through every builder (swallowing a Ctrl-C to save one error
body would turn the sanitizer into a hang), and the healthy shapes of the
json11/json12 contracts are unchanged.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi import HTTPException
from fastapi.testclient import TestClient

from hub import errors, wireguard_svc
from hub.app_factory import create_app
from hub.auth import require_auth


def _renderable(out) -> None:
    """Whatever reaches Starlette's allow_nan=False encoder must survive it."""
    json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")


class LeftoverBaseBomb(BaseException):
    """BaseException-shaped, but *not* control flow — a bomb like any other."""


def _base_raising_property():
    return property(
        lambda self: (_ for _ in ()).throw(LeftoverBaseBomb("leftover base bomb")))


class ClassPropBaseBomb:
    """``__class__`` property raising BaseException — used to blow ``_isinst``
    itself, the gate every sanitizer arm stands on."""

    __class__ = _base_raising_property()

    def __str__(self):
        return "still-renderable"


class StrTailBaseBomb:
    """``str(value)`` tail bomb: not a scalar, no isoformat, ``__str__``
    raises BaseException."""

    def __str__(self):
        raise LeftoverBaseBomb("str tail bomb")


class FormatBaseBomb:
    """A param whose ``__format__`` raises BaseException — the format step
    runs *before* ``_jsonable_param`` can drop the value."""

    def __format__(self, spec):
        raise LeftoverBaseBomb("format bomb")

    def __str__(self):
        raise LeftoverBaseBomb("str bomb")


class ItemsBaseBombDict(dict):
    """A real dict whose bound ``items()`` raises BaseException.

    Two contracts meet this class: ``_jsonable_param``'s dict arm reads the
    bound ``items()`` and drops the whole node to null (the json7 pin), while
    ``api_error_from`` rebuilds over unbound ``dict.items`` — the C-level
    storage — and keeps the honest entries (the json12 pin).  Both used to
    let the BaseException twin fly."""

    def items(self):
        raise LeftoverBaseBomb("items bomb")


class IterBaseBombList(list):
    """A list subclass whose ``__iter__`` raises BaseException."""

    def __iter__(self):
        raise LeftoverBaseBomb("iter bomb")


class IsoBaseBomb:
    """``isoformat`` is a *property* that raises BaseException — the getattr
    lookup itself used to blow before ``callable`` ever ran."""

    isoformat = _base_raising_property()

    def __str__(self):
        return "2026-08-28"


class KeyStrBaseBomb:
    """A mapping key whose ``__str__`` raises BaseException — must drop
    alone, keeping its siblings."""

    def __str__(self):
        raise LeftoverBaseBomb("key str bomb")

    def __hash__(self):
        return 13


class BoolBaseBombDict(dict):
    """A params value whose ``__bool__`` raises BaseException — the
    ``exc_detail`` pick."""

    def __bool__(self):
        raise LeftoverBaseBomb("bool bomb")


class DetailPropBaseBomb(HTTPException):
    """An HTTPException subclass whose ``detail`` read raises BaseException."""

    def __init__(self):
        Exception.__init__(self)

    status_code = 404
    detail = _base_raising_property()


class JsonableParamPins(unittest.TestCase):
    """``_jsonable_param`` / ``jsonable_error_detail`` never raise on a
    BaseException-shaped bomb, and whatever they keep still renders."""

    def test_class_prop_base_bomb_launders_to_its_text(self):
        out = errors.jsonable_error_detail(ClassPropBaseBomb())
        self.assertEqual(out, "still-renderable")
        _renderable(out)

    def test_str_tail_base_bomb_drops_to_none(self):
        self.assertIsNone(errors.jsonable_error_detail(StrTailBaseBomb()))

    def test_items_base_bomb_dict_drops_to_none(self):
        # The json7 contract for the bound-items dict arm: drop the node to
        # null; entry salvage is api_error_from's unbound-read job.
        self.assertIsNone(errors.jsonable_error_detail(ItemsBaseBombDict(a=1)))

    def test_iter_base_bomb_list_drops_to_none(self):
        self.assertIsNone(
            errors.jsonable_error_detail(IterBaseBombList([1, 2])))

    def test_isoformat_base_bomb_falls_to_the_str_tail(self):
        out = errors.jsonable_error_detail(IsoBaseBomb())
        self.assertEqual(out, "2026-08-28")
        _renderable(out)

    def test_key_base_bomb_drops_alone_siblings_survive(self):
        out = errors.jsonable_error_detail({KeyStrBaseBomb(): "junk", "ok": 1})
        self.assertEqual(out, {"ok": 1})
        _renderable(out)


class ErrorPayloadPins(unittest.TestCase):
    """``error_payload`` / ``api_error`` / ``soft_fail`` degrade a
    BaseException-shaped bomb exactly like its Exception twin."""

    def test_format_base_bomb_param_keeps_the_codes_status(self):
        status, body = errors.error_payload(
            "files.not_found", path=FormatBaseBomb())
        self.assertEqual(status, 404)
        self.assertEqual(body["detail"]["code"], "files.not_found")
        # The unformattable message falls back to the raw template; the
        # unrenderable param drops to null.
        self.assertEqual(body["detail"]["message"], "not found: {path}")
        self.assertEqual(body["detail"]["params"], {"path": None})
        _renderable(body)

    def test_class_prop_base_bomb_code_takes_the_placeholder(self):
        class NoTextAtAll:
            __class__ = _base_raising_property()

            def __str__(self):
                raise LeftoverBaseBomb("no text at all")

        status, body = errors.error_payload(NoTextAtAll())
        self.assertEqual(status, 500)
        self.assertEqual(body["detail"]["code"], "error.unrenderable")
        _renderable(body)

    def test_soft_fail_shares_the_laundering(self):
        out = errors.soft_fail("power.bad_key", key=FormatBaseBomb())
        self.assertEqual(out["ok"], False)
        self.assertEqual(out["code"], "power.bad_key")
        _renderable(out)


class ExcDetailPins(unittest.TestCase):
    """The coded-detail unwrap degrades field-level over BaseException bombs
    instead of raising inside a caller's own except clause."""

    def test_detail_base_prop_bomb_falls_to_error(self):
        self.assertEqual(errors.exc_detail(DetailPropBaseBomb()), "error")

    def test_bool_base_bomb_params_still_keeps_the_message(self):
        exc = HTTPException(
            404, {"message": "kept", "params": BoolBaseBombDict(a=1)})
        self.assertEqual(errors.exc_detail(exc), "kept")

    def test_str_base_bomb_exception_falls_to_error(self):
        class Bomb(Exception):
            def __str__(self):
                raise LeftoverBaseBomb("str bomb")

        self.assertEqual(errors.exc_detail(Bomb()), "error")


class ApiErrorFromPins(unittest.TestCase):
    """The json12 typed-error seam holds against the BaseException twins of
    all four shapes it sealed."""

    def test_code_base_prop_bomb_takes_the_placeholder(self):
        class Bomb(Exception):
            code = _base_raising_property()
            params = {}

        exc = errors.api_error_from(Bomb())
        self.assertEqual(exc.status_code, 500)
        self.assertEqual(exc.detail["code"], "error.unrenderable")
        _renderable({"detail": exc.detail})

    def test_params_base_prop_bomb_keeps_the_codes_status(self):
        class Bomb(Exception):
            code = "wg.bad_ip"
            params = _base_raising_property()

        exc = errors.api_error_from(Bomb())
        self.assertEqual(exc.status_code, 400)
        self.assertEqual(exc.detail["code"], "wg.bad_ip")
        self.assertNotIn("params", exc.detail)
        _renderable({"detail": exc.detail})

    def test_items_base_bomb_params_still_answer_their_real_entries(self):
        class Bomb(Exception):
            code = "wg.ip_in_use"
            params = ItemsBaseBombDict(ip="10.0.0.7")

        exc = errors.api_error_from(Bomb())
        self.assertEqual(exc.status_code, 409)
        self.assertEqual(exc.detail["params"], {"ip": "10.0.0.7"})
        _renderable({"detail": exc.detail})

    def test_key_base_bomb_drops_alone_siblings_survive(self):
        class Bomb(Exception):
            code = "wg.ip_in_use"
            params = {KeyStrBaseBomb(): "junk", "ip": "10.0.0.8"}

        exc = errors.api_error_from(Bomb())
        self.assertEqual(exc.status_code, 409)
        self.assertEqual(exc.detail["params"], {"ip": "10.0.0.8"})
        _renderable({"detail": exc.detail})


class ControlFlowPassthroughPins(unittest.TestCase):
    """Genuine control flow keeps propagating through every builder —
    swallowing a Ctrl-C to save one error body would turn the sanitizer
    into a hang."""

    def _ctrl(self, kind):
        return property(lambda self: (_ for _ in ()).throw(kind()))

    def test_jsonable_param_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(kind=kind.__name__):
                class Bomb:
                    def __str__(self, _kind=kind):
                        raise _kind()

                with self.assertRaises(kind):
                    errors.jsonable_error_detail(Bomb())

    def test_error_payload_reraises_control_flow_from_a_param(self):
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(kind=kind.__name__):
                class Bomb:
                    def __format__(self, spec, _kind=kind):
                        raise _kind()

                with self.assertRaises(kind):
                    errors.error_payload("files.not_found", path=Bomb())

    def test_api_error_from_reraises_control_flow_from_the_code_slot(self):
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(kind=kind.__name__):
                class Bomb(Exception):
                    code = self._ctrl(kind)
                    params = {}

                with self.assertRaises(kind):
                    errors.api_error_from(Bomb())

    def test_exc_detail_reraises_control_flow_from_the_detail_read(self):
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(kind=kind.__name__):
                class Bomb(HTTPException):
                    def __init__(self):
                        Exception.__init__(self)

                    status_code = 404
                    detail = self._ctrl(kind)

                with self.assertRaises(kind):
                    errors.exc_detail(Bomb())


class _WgBaseBomb:
    """WireGuardError subclasses whose hooks raise BaseException, so the
    router's typed except clause still fires but every pre-fix guard blew."""

    @staticmethod
    def code_prop():
        class Bomb(wireguard_svc.WireGuardError):
            def __init__(self):
                ValueError.__init__(self, "leftover")
                self.params = {}
            code = _base_raising_property()

        return Bomb()

    @staticmethod
    def params_prop():
        class Bomb(wireguard_svc.WireGuardError):
            def __init__(self):
                ValueError.__init__(self, "wg.bad_ip")
                self.code = "wg.bad_ip"
            params = _base_raising_property()

        return Bomb()

    @staticmethod
    def format_param():
        class Bomb(wireguard_svc.WireGuardError):
            def __init__(self):
                ValueError.__init__(self, "wg.subnet_full")
                self.code = "wg.subnet_full"
                self.params = {"subnet": FormatBaseBomb()}

        return Bomb()


class HttpRoutePins(unittest.TestCase):
    """Over the real mounted stack: the closed 500s answer coded JSON."""

    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def _coded_json(self, resp) -> dict:
        body = resp.json()
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return body["detail"]

    def test_wireguard_next_ip_answers_coded_over_base_bombs(self):
        """Each shape used to raise BaseException out of ``api_error_from``
        inside the router's except clause — past Starlette's own
        ``except Exception`` error middleware, so not even the generic
        traceback 500 answered."""
        cases = (
            ("params_prop", _WgBaseBomb.params_prop, 400, "wg.bad_ip"),
            ("format_param", _WgBaseBomb.format_param, 409, "wg.subnet_full"),
            ("code_prop", _WgBaseBomb.code_prop, 500, "error.unrenderable"),
        )
        for label, make, want_status, want_code in cases:
            with self.subTest(bomb=label):
                def _raise(_make=make):
                    raise _make()

                client = self._client()
                with mock.patch.object(wireguard_svc, "next_ip", _raise):
                    resp = client.get("/api/wireguard/next-ip")
                self.assertEqual(resp.status_code, want_status, resp.text[:400])
                self.assertEqual(self._coded_json(resp)["code"], want_code)

    def test_healthy_typed_errors_keep_their_exact_http_shape(self):
        """The strengthened guards must not change a single healthy answer."""
        def _raise():
            raise wireguard_svc.WireGuardError(
                "wg.subnet_full", subnet="10.0.0.0/24")

        client = self._client()
        with mock.patch.object(wireguard_svc, "next_ip", _raise):
            resp = client.get("/api/wireguard/next-ip")
        self.assertEqual(resp.status_code, 409, resp.text[:400])
        detail = self._coded_json(resp)
        self.assertEqual(detail["code"], "wg.subnet_full")
        self.assertEqual(detail["message"], "no free address left in 10.0.0.0/24")
        self.assertEqual(detail["params"], {"subnet": "10.0.0.0/24"})

    def test_product_version_stays_pinned(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.3")


if __name__ == "__main__":
    unittest.main()
