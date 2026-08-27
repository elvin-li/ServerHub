"""JSON sweep #11: leftover bombs riding the *code slot* and the coded-detail
unwrap.

The json5-9 sweeps hardened ``_jsonable_param`` (params, mapping entries,
lying ``__class__`` impostors).  What stayed open is everything *around* the
params: the ``code`` argument itself reached the ``CODES`` lookup and the
response body raw, and ``exc_detail``'s coded-detail unwrap trusted the
``detail`` attribute, its ``.get``, its stored keys and its values.  Driven
over the real mounted app (``create_app()`` + TestClient with
``raise_server_exceptions=False``), each of these turned a coded answer into a
raw HTTP 500 — or silently vanished healthy rows:

* a str-subclass code whose ``__hash__`` raises blew ``CODES.get`` inside
  ``error_payload`` / ``api_error`` / ``soft_fail``;
* a str-subclass code that *hash-shadows* a real code's slot and raises from
  ``__eq__`` blew the same lookup during the collision probe (the dict
  compares the **stored** exact key against the query, and the reflected
  comparison dispatches into the subclass first);
* a lying-``__class__`` code claiming str skipped the str() coercion and blew
  the unbound ``str.encode(message, ...)`` outside any try;
* a non-str code object — and an exact-str code carrying a lone surrogate —
  rode into ``detail["code"]`` untouched and 500'd Starlette's own render
  (``TypeError: not JSON serializable`` / ``UnicodeEncodeError``);
* ``exc_detail`` blew on an HTTPException subclass whose ``detail`` is a
  *raising property*, on a detail dict subclass whose bound ``.get`` raises,
  on a stored key hash-shadowing "params"/"message"/"code" with a raising
  ``__eq__``, on a params value whose ``__bool__`` bombs the pick, and on a
  picked str-subclass whose ``__bool__`` bombs the emptiness check — inside
  ``_nginx_pair``'s own except clause that raise vaporized the whole nginx
  pair from GET /api/health/checks.

The fix launders the code to an exact, UTF-8-renderable str *before* the
``CODES`` lookup (a hash-bomb wrapper around a real code still answers that
code's status), and rebuilds the ``exc_detail`` unwrap on guarded unbound
``dict.get`` with per-field trys so healthy siblings keep answering.

Also pinned — vectors that were already immune, so a refactor cannot reopen
them: FastAPI's body-parse boundary answers 400 (not 500) for a >4300-digit
JSON number (``json.loads`` raises the digit-cap *ValueError*, not
JSONDecodeError) and 422 for ``Infinity``; healthy codes, subclass codes and
the json5-9 ``_jsonable_param`` contracts are unchanged.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi import HTTPException
from fastapi.testclient import TestClient

from hub import errors, health_svc, ollama_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import settings_api


def _renderable(out) -> None:
    """Whatever the builders return must survive Starlette's own encoder."""
    json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")


class HashBombStr(str):
    """A genuine str subclass whose ``__hash__`` raises — ``CODES.get`` used
    to blow before the laundering."""

    def __hash__(self):
        raise RuntimeError("leftover hash bomb")


class ShadowEqStr(str):
    """Hash-shadows a *real* code's slot, then raises from ``__eq__`` during
    the dict's collision probe."""

    def __hash__(self):
        return hash("auth.login_required")

    def __eq__(self, other):
        raise RuntimeError("leftover eq bomb")


class StrLiar:
    """Lying ``__class__`` claiming str while the real type is a plain
    object — passes ``_isinst`` gates, then the unbound descriptor rejects
    the foreign operand outside any try."""

    __class__ = property(lambda self: str)

    def __str__(self):
        return "liar-code"


class GetBombDict(dict):
    """A real dict subclass whose bound ``.get`` raises."""

    def get(self, *a, **k):
        raise RuntimeError("leftover get bomb")


class BoolBombDict(dict):
    """A real dict subclass whose ``__bool__`` raises — the params pick."""

    def __bool__(self):
        raise RuntimeError("leftover bool bomb")


class BoolBombStr(str):
    """A str subclass whose ``__bool__`` raises — the ``and picked`` check."""

    def __bool__(self):
        raise RuntimeError("leftover str bool bomb")


def _shadow_key(target: str):
    """A stored mapping key that hash-shadows *target* and raises from
    ``__eq__`` when the lookup probes its slot."""

    class StoredShadowKey(str):
        def __new__(cls):
            return super().__new__(cls, "shadow:" + target)

        def __hash__(self):
            return hash(target)

        def __eq__(self, other):
            raise RuntimeError("leftover stored-key eq bomb")

    return StoredShadowKey()


class DetailPropBomb(HTTPException):
    """An HTTPException subclass whose ``detail`` is a raising *property* —
    the unwrap's very first read used to blow."""

    def __init__(self):
        Exception.__init__(self)

    status_code = 404
    detail = property(
        lambda self: (_ for _ in ()).throw(RuntimeError("detail prop bomb")))


class PoisonedCodePins(unittest.TestCase):
    """``error_payload`` / ``api_error`` / ``soft_fail`` never raise on a
    leftover riding the code slot, and the built body always renders."""

    def test_hash_bomb_code_keeps_the_real_codes_status(self):
        status, body = errors.error_payload(
            HashBombStr("files.not_found"), path="/x")
        self.assertEqual(status, 404)
        self.assertEqual(body["detail"]["code"], "files.not_found")
        self.assertIs(type(body["detail"]["code"]), str)
        _renderable(body)

    def test_shadow_eq_code_still_resolves_by_text(self):
        status, body = errors.error_payload(ShadowEqStr("files.not_found"))
        self.assertEqual(status, 404)
        self.assertEqual(body["detail"]["code"], "files.not_found")
        _renderable(body)

    def test_str_liar_code_degrades_to_its_text(self):
        status, body = errors.error_payload(StrLiar())
        self.assertEqual(status, 500)
        self.assertEqual(body["detail"]["code"], "liar-code")
        self.assertIs(type(body["detail"]["code"]), str)
        _renderable(body)

    def test_non_str_code_object_no_longer_render_bombs(self):
        status, body = errors.error_payload(object())
        self.assertEqual(status, 500)
        self.assertIs(type(body["detail"]["code"]), str)
        _renderable(body)

    def test_surrogate_code_is_laundered_for_utf8(self):
        status, body = errors.error_payload("bad.\ud800code")
        self.assertEqual(status, 500)
        _renderable(body)  # UnicodeEncodeError used to fire here

    def test_unrenderable_code_drops_to_placeholder(self):
        class NoStr:
            __class__ = property(lambda self: str)

            def __str__(self):
                raise RuntimeError("no text at all")

        status, body = errors.error_payload(NoStr())
        self.assertEqual(status, 500)
        self.assertEqual(body["detail"]["code"], "error.unrenderable")
        _renderable(body)

    def test_api_error_and_soft_fail_share_the_laundering(self):
        exc = errors.api_error(HashBombStr("files.not_found"), path="/x")
        self.assertEqual(exc.status_code, 404)
        self.assertEqual(exc.detail["code"], "files.not_found")
        _renderable({"detail": exc.detail})

        out = errors.soft_fail(HashBombStr("power.bad_key"), key="k")
        self.assertEqual(out["ok"], False)
        self.assertEqual(out["code"], "power.bad_key")
        _renderable(out)

    def test_healthy_and_unknown_plain_codes_unchanged(self):
        status, body = errors.error_payload("files.not_found", path="/x")
        self.assertEqual(status, 404)
        self.assertEqual(body["detail"]["message"], "not found: /x")
        status, body = errors.error_payload("no.such_code")
        self.assertEqual(status, 500)
        self.assertEqual(body["detail"]["code"], "no.such_code")


class ExcDetailUnwrapPins(unittest.TestCase):
    """The coded-detail unwrap degrades field-level instead of raising."""

    def test_detail_property_bomb_falls_to_error(self):
        self.assertEqual(errors.exc_detail(DetailPropBomb()), "error")

    def test_get_bomb_subclass_is_bypassed_by_unbound_get(self):
        exc = HTTPException(404, GetBombDict(code="nginx.conf_missing"))
        self.assertEqual(errors.exc_detail(exc), "nginx.conf_missing")

    def test_bool_bomb_params_still_keeps_the_message(self):
        exc = HTTPException(
            404, {"message": "kept", "params": BoolBombDict(a=1)})
        self.assertEqual(errors.exc_detail(exc), "kept")

    def test_bool_bomb_picked_str_launders_before_truthiness(self):
        exc = HTTPException(404, {"code": BoolBombStr("c-11")})
        self.assertEqual(errors.exc_detail(exc), "c-11")

    def test_stored_shadow_params_key_falls_to_the_code(self):
        detail = {_shadow_key("params"): 1, "code": "real.code"}
        self.assertEqual(errors.exc_detail(HTTPException(404, detail)),
                         "real.code")

    def test_stored_shadow_message_key_falls_to_the_code(self):
        detail = {_shadow_key("message"): 1, "params": {"a": 1},
                  "code": "real.code"}
        self.assertEqual(errors.exc_detail(HTTPException(404, detail)),
                         "real.code")

    def test_str_liar_picked_falls_to_the_guarded_tail(self):
        out = errors.exc_detail(HTTPException(404, {"code": StrLiar()}))
        self.assertIs(type(out), str)
        _renderable(out)

    def test_healthy_unwrap_and_plain_exceptions_unchanged(self):
        exc = HTTPException(404, {"code": "nginx.conf_missing",
                                  "message": "nginx.conf is missing"})
        self.assertEqual(errors.exc_detail(exc), "nginx.conf_missing")
        exc = HTTPException(404, {"code": "c", "message": "msg",
                                  "params": {"a": 1}})
        self.assertEqual(errors.exc_detail(exc), "msg")
        self.assertEqual(errors.exc_detail(ValueError("boom")), "boom")
        self.assertEqual(errors.exc_detail(ValueError("long"), cap=2), "lo")


class HttpRoutePins(unittest.TestCase):
    """Over the real mounted stack: the closed 500s answer coded statuses."""

    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def test_poisoned_code_answers_the_coded_400_not_500(self):
        """A hash-bomb code riding ``api_error`` used to RuntimeError out of
        ``CODES.get`` while the route built its own coded rejection."""
        for bomb in (HashBombStr("ollama.bad_url"),
                     ShadowEqStr("ollama.bad_url")):
            with self.subTest(bomb=type(bomb).__name__):
                def _raise(_url, _bomb=bomb):
                    raise errors.api_error(_bomb, url="http://x")

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

    def test_health_checks_keep_the_nginx_row_over_a_poisoned_detail(self):
        """``exc_detail`` raising inside ``_nginx_pair``'s except clause used
        to vaporize the whole nginx pair from GET /api/health/checks."""
        def _boom():
            raise HTTPException(404, GetBombDict(code="nginx.conf_missing"))

        client = self._client()
        with mock.patch.object(health_svc, "nginx_overview", _boom):
            resp = client.get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:400])
        rows = [c for c in resp.json()["checks"]
                if isinstance(c, dict) and c.get("id") == "nginx"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["detail"], "nginx.conf_missing")

    def test_huge_json_number_body_is_400_not_500(self):
        """``json.loads`` of a >4300-digit literal raises the digit-cap
        *ValueError* (not JSONDecodeError); FastAPI's body-parse boundary
        answers its generic 400 — pinned so a framework bump that narrows the
        catch back to JSONDecodeError is caught here."""
        client = self._client()
        body = ('{"username": "u", "password": ' + "1" * 5000 + "}").encode()
        resp = client.post("/api/auth/login", content=body,
                           headers={"content-type": "application/json"})
        self.assertEqual(resp.status_code, 400, resp.text[:400])
        json.dumps(resp.json(), ensure_ascii=False,
                   allow_nan=False).encode("utf-8")

    def test_infinity_json_body_is_422_not_500(self):
        client = self._client()
        resp = client.post("/api/auth/login",
                           content=b'{"username": Infinity, "password": "p"}',
                           headers={"content-type": "application/json"})
        self.assertEqual(resp.status_code, 422, resp.text[:400])
        json.dumps(resp.json(), ensure_ascii=False,
                   allow_nan=False).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
