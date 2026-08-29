"""JSON sweep #12: leftover bombs riding the *typed-error seam* into api_error.

json11 laundered the code slot inside ``error_payload`` and guarded
``exc_detail``'s coded-detail unwrap.  What stayed open is the step *before*
either runs: the routers that translate typed service errors into coded HTTP
errors did it with bare attribute reads and a bare ``**`` unpack inside their
except clauses —

    except wireguard_svc.WireGuardError as exc:
        raise api_error(exc.code, **exc.params)

(nas_storage's NFS save and RAID funnel had the same shape; shares read
``error.code`` bare on all five ShareValidationError / ShareAclError sites).
Driven over the real mounted app (``create_app()`` + TestClient with
``raise_server_exceptions=False``), a leftover typed-error *subclass* riding
that seam turned the coded refusal into a raw HTTP 500 four different ways,
each one step ahead of every guard ``error_payload`` carries:

* ``code`` as a *raising property* blew the attribute read itself;
* ``params`` as a raising property did the same;
* a non-mapping ``params`` TypeError'd CPython's ``**`` keyword rebuild
  before the call even began;
* a mapping ``params`` carrying a non-str key blew the same rebuild with
  "keywords must be strings".

The fix is ``errors.api_error_from``: guarded reads for both slots — an
unreadable/absent code takes the ``error.unrenderable`` placeholder (the
json11 unknown-code contract: HTTP 500, but as valid JSON instead of a
crash), and the params mapping is rebuilt over unbound ``dict.items`` (the
C-level storage, matching what a healthy ``**`` unpack reads) with each key
laundered to an exact str and each unusable entry dropped alone.  Values
stay raw so ``error_payload``'s existing laundering and message formatting
are unchanged for healthy params.

Also pinned — already immune, so a refactor cannot reopen them: a dict
*subclass* params whose ``items()``/``keys()`` raise still answers its real
entries (both the ``**`` unpack and the unbound read see the C storage),
and healthy typed errors keep their exact coded shape through every
converted site.
"""
from __future__ import annotations

import json
import unittest
from contextlib import ExitStack
from unittest import mock

from fastapi.testclient import TestClient

from hub import errors, nfs_svc, raid_svc, share_acl_svc, shares_svc, wireguard_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import nas_common


def _renderable(out) -> None:
    """Whatever reaches Starlette's allow_nan=False encoder must survive it."""
    json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _raising_property():
    return property(lambda self: (_ for _ in ()).throw(RuntimeError("leftover prop bomb")))


class _CodePropBomb(Exception):
    """A typed-error leftover whose ``code`` read itself raises."""

    code = _raising_property()
    params = {}


class _ParamsPropBomb(Exception):
    """``code`` is honest; the ``params`` read raises."""

    code = "wg.bad_ip"
    params = _raising_property()


class _ParamsNotMapping(Exception):
    """``**exc.params`` used to TypeError CPython's keyword rebuild."""

    code = "wg.bad_ip"
    params = ["not", "a", "mapping"]


class _ParamsNonStrKey(Exception):
    """A non-str key used to blow the rebuild with 'keywords must be strings'."""

    code = "wg.bad_ip"
    params = {1: "one"}


class _ItemsBombDict(dict):
    """A real dict whose bound ``items()``/``keys()`` raise — the C-level
    storage still holds the honest entries."""

    def items(self):
        raise RuntimeError("items bomb")

    def keys(self):
        raise RuntimeError("keys bomb")


class _DictLiar:
    """Lying ``__class__`` claiming dict — the unbound read rejects it."""

    __class__ = property(lambda self: dict)

    def items(self):
        return [("ip", "10.0.0.9")]


class _KeyStrBomb:
    """A mapping key that can neither pass the str gate nor be str()'d."""

    def __str__(self):
        raise RuntimeError("key str bomb")

    def __hash__(self):
        return 12


class ApiErrorFromPins(unittest.TestCase):
    """``api_error_from`` never raises on a poisoned typed error, and the
    detail it builds always renders."""

    def test_code_property_bomb_takes_the_placeholder(self):
        exc = errors.api_error_from(_CodePropBomb())
        self.assertEqual(exc.status_code, 500)
        self.assertEqual(exc.detail["code"], "error.unrenderable")
        _renderable({"detail": exc.detail})

    def test_missing_code_takes_the_placeholder(self):
        exc = errors.api_error_from(ValueError("no code slot at all"))
        self.assertEqual(exc.status_code, 500)
        self.assertEqual(exc.detail["code"], "error.unrenderable")
        _renderable({"detail": exc.detail})

    def test_params_property_bomb_keeps_the_codes_status(self):
        exc = errors.api_error_from(_ParamsPropBomb())
        self.assertEqual(exc.status_code, 400)
        self.assertEqual(exc.detail["code"], "wg.bad_ip")
        self.assertNotIn("params", exc.detail)
        _renderable({"detail": exc.detail})

    def test_non_mapping_params_keeps_the_codes_status(self):
        exc = errors.api_error_from(_ParamsNotMapping())
        self.assertEqual(exc.status_code, 400)
        self.assertEqual(exc.detail["code"], "wg.bad_ip")
        self.assertNotIn("params", exc.detail)
        _renderable({"detail": exc.detail})

    def test_non_str_key_is_laundered_not_fatal(self):
        exc = errors.api_error_from(_ParamsNonStrKey())
        self.assertEqual(exc.status_code, 400)
        self.assertEqual(exc.detail["params"], {"1": "one"})
        _renderable({"detail": exc.detail})

    def test_items_bomb_subclass_still_answers_its_real_entries(self):
        class Bomb(Exception):
            code = "wg.ip_in_use"
            params = _ItemsBombDict(ip="10.0.0.7")

        exc = errors.api_error_from(Bomb())
        self.assertEqual(exc.status_code, 409)
        self.assertEqual(exc.detail["params"], {"ip": "10.0.0.7"})
        self.assertEqual(exc.detail["message"], "10.0.0.7 is already assigned")
        _renderable({"detail": exc.detail})

    def test_dict_liar_params_drop_and_the_code_still_answers(self):
        class Bomb(Exception):
            code = "wg.bad_ip"
            params = _DictLiar()

        exc = errors.api_error_from(Bomb())
        self.assertEqual(exc.status_code, 400)
        self.assertEqual(exc.detail["code"], "wg.bad_ip")
        self.assertNotIn("params", exc.detail)
        _renderable({"detail": exc.detail})

    def test_unlaunderable_key_drops_alone_siblings_survive(self):
        class Bomb(Exception):
            code = "wg.ip_in_use"
            params = {_KeyStrBomb(): "junk", "ip": "10.0.0.8"}

        exc = errors.api_error_from(Bomb())
        self.assertEqual(exc.status_code, 409)
        self.assertEqual(exc.detail["params"], {"ip": "10.0.0.8"})
        _renderable({"detail": exc.detail})

    def test_healthy_typed_errors_match_api_error_exactly(self):
        for make, args in (
            (wireguard_svc.WireGuardError, ("wg.subnet_full", {"subnet": "10.0.0.0/24"})),
            (nfs_svc.NfsConfigError, ("nfs.path_missing", {"path": "/x"})),
            (raid_svc.RaidError, ("raid.too_few_members", {"minimum": 2})),
        ):
            with self.subTest(error=make.__name__):
                code, params = args
                via_from = errors.api_error_from(make(code, **params))
                direct = errors.api_error(code, **params)
                self.assertEqual(via_from.status_code, direct.status_code)
                self.assertEqual(via_from.detail, direct.detail)

    def test_codeless_share_errors_keep_their_coded_shape(self):
        via_from = errors.api_error_from(
            shares_svc.ShareValidationError("shares.bad_name"))
        self.assertEqual(via_from.status_code, 400)
        self.assertEqual(via_from.detail, errors.api_error("shares.bad_name").detail)
        via_from = errors.api_error_from(
            share_acl_svc.ShareAclError("shares.acl_bad_level"))
        self.assertEqual(via_from.status_code, 400)
        self.assertEqual(via_from.detail["code"], "shares.acl_bad_level")


class _WgBomb:
    """Builds WireGuardError subclasses so the router's except clause fires."""

    @staticmethod
    def params_prop():
        class Bomb(wireguard_svc.WireGuardError):
            def __init__(self):
                ValueError.__init__(self, "wg.bad_ip")
                self.code = "wg.bad_ip"
            params = _raising_property()

        return Bomb()

    @staticmethod
    def code_prop():
        class Bomb(wireguard_svc.WireGuardError):
            def __init__(self):
                ValueError.__init__(self, "leftover")
                self.params = {}
            code = _raising_property()

        return Bomb()

    @staticmethod
    def params_list():
        class Bomb(wireguard_svc.WireGuardError):
            def __init__(self):
                ValueError.__init__(self, "wg.bad_ip")
                self.code = "wg.bad_ip"
                self.params = ["not", "a", "mapping"]

        return Bomb()

    @staticmethod
    def params_int_key():
        class Bomb(wireguard_svc.WireGuardError):
            def __init__(self):
                ValueError.__init__(self, "wg.bad_ip")
                self.code = "wg.bad_ip"
                self.params = {1: "one"}

        return Bomb()


class HttpRoutePins(unittest.TestCase):
    """Over the real mounted stack: the closed 500s answer coded statuses."""

    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def _admin_browser(self, stack: ExitStack) -> None:
        """An administrator browser session, as nas_common resolves one."""
        stack.enter_context(mock.patch.object(
            nas_common.auth, "browser_authenticated", return_value=True))
        stack.enter_context(mock.patch.object(
            nas_common.auth, "request_username", return_value="admin"))
        stack.enter_context(mock.patch.object(
            nas_common.auth, "is_admin", return_value=True))
        stack.enter_context(mock.patch.object(
            nas_common.auth, "request_client_id", return_value="127.0.0.1"))

    def _coded_json(self, resp) -> dict:
        body = resp.json()
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return body["detail"]

    def test_wireguard_next_ip_answers_coded_over_every_seam_bomb(self):
        """Each of these shapes was a raw HTTP 500 (traceback body, no JSON)
        out of wireguard_api._call's own except clause pre-fix."""
        cases = (
            ("params_prop", _WgBomb.params_prop, 400, "wg.bad_ip"),
            ("params_list", _WgBomb.params_list, 400, "wg.bad_ip"),
            ("params_int_key", _WgBomb.params_int_key, 400, "wg.bad_ip"),
            ("code_prop", _WgBomb.code_prop, 500, "error.unrenderable"),
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

    def test_nfs_save_answers_coded_over_a_params_prop_bomb(self):
        class Bomb(nfs_svc.NfsConfigError):
            def __init__(self):
                ValueError.__init__(self, "nfs.bad_path")
                self.code = "nfs.bad_path"
            params = _raising_property()

        def _raise(entries):
            raise Bomb()

        client = self._client()
        with ExitStack() as stack:
            self._admin_browser(stack)
            stack.enter_context(mock.patch.object(nfs_svc, "save_exports", _raise))
            resp = client.post("/api/nfs/exports", json={"entries": []})
        self.assertEqual(resp.status_code, 400, resp.text[:400])
        self.assertEqual(self._coded_json(resp)["code"], "nfs.bad_path")

    def test_raid_delete_answers_coded_over_a_params_prop_bomb(self):
        class Bomb(raid_svc.RaidError):
            def __init__(self):
                ValueError.__init__(self, "raid.confirm_required")
                self.code = "raid.confirm_required"
            params = _raising_property()

        def _raise(**kwargs):
            raise Bomb()

        client = self._client()
        with ExitStack() as stack:
            self._admin_browser(stack)
            stack.enter_context(mock.patch.object(raid_svc, "delete_set", _raise))
            resp = client.post("/api/raid/delete", json={
                "set_uuid": "0FA5C0DE-0000-0000-0000-000000000000",
            })
        self.assertEqual(resp.status_code, 400, resp.text[:400])
        self.assertEqual(self._coded_json(resp)["code"], "raid.confirm_required")

    def test_share_create_answers_json_over_a_code_prop_bomb(self):
        """The raw traceback 500 becomes the unknown-code contract's *valid
        JSON* 500 when the leftover cannot even answer its code."""
        class Bomb(shares_svc.ShareValidationError):
            def __init__(self):
                ValueError.__init__(self, "leftover")
            code = _raising_property()

        def _raise(**kwargs):
            raise Bomb()

        client = self._client()
        with ExitStack() as stack:
            self._admin_browser(stack)
            stack.enter_context(mock.patch.object(
                shares_svc, "create_smb_share", _raise))
            resp = client.post("/api/shares/smb", json={
                "name": "media", "smb_name": "media", "path": "/tmp",
            })
        self.assertEqual(resp.status_code, 500, resp.text[:400])
        self.assertEqual(self._coded_json(resp)["code"], "error.unrenderable")

    def test_healthy_typed_errors_keep_their_exact_http_shape(self):
        """The conversion must not change a single healthy answer."""
        def _raise_wg():
            raise wireguard_svc.WireGuardError("wg.subnet_full", subnet="10.0.0.0/24")

        client = self._client()
        with mock.patch.object(wireguard_svc, "next_ip", _raise_wg):
            resp = client.get("/api/wireguard/next-ip")
        self.assertEqual(resp.status_code, 409, resp.text[:400])
        detail = self._coded_json(resp)
        self.assertEqual(detail["code"], "wg.subnet_full")
        self.assertEqual(detail["message"], "no free address left in 10.0.0.0/24")
        self.assertEqual(detail["params"], {"subnet": "10.0.0.0/24"})

        def _raise_share(**kwargs):
            raise shares_svc.ShareValidationError("shares.bad_name")

        client = self._client()
        with ExitStack() as stack:
            self._admin_browser(stack)
            stack.enter_context(mock.patch.object(
                shares_svc, "create_smb_share", _raise_share))
            resp = client.post("/api/shares/smb", json={
                "name": "media", "smb_name": "media", "path": "/tmp",
            })
        self.assertEqual(resp.status_code, 400, resp.text[:400])
        self.assertEqual(self._coded_json(resp)["code"], "shares.bad_name")


if __name__ == "__main__":
    unittest.main()
