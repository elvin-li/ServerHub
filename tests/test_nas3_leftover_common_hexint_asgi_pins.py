"""Third leftover-500s sweep of the shared NAS helper, over real ASGI.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the uncapped YAML/plist hex form that arrives
already-int — vanished-CLI 503-vs-500) were re-reproduced against the routes
that render a privileged result through ``hub/routers/nas_common.py``.  One
live leak was found and is fixed alongside this file:

* ``nas_common._jsonable`` passed ints through without the ``str()`` probe its
  siblings (``power_svc._jsonable``, ``system_settings_svc._json_tree``,
  ``status._jsonable``) all carry, so an over-cap int in a privileged ok
  payload raised the int->str digit-cap ValueError inside Starlette's
  ``json.dumps`` and 500'd every route whose response body is
  ``raise_for_admin_result`` / ``raise_service_error``'s cleaned dict —
  POST /api/wireguard/interface|forwarding, POST /api/snapshots/create, the
  NFS / RAID / SMART / Time Machine actions in nas_storage.  The huge-int
  pins here fail on the pre-fix tree.

Everything else in the helper's blast radius was found immune, so the rest of
this file pins the stays-immune corners at the HTTP layer — request routing,
response rendering and the strict UTF-8 decode of the body:

* an over-cap int riding a *failure* result into ``raise_service_error``'s
  extra params (dropped by ``api_error``'s own ``_jsonable_param``) and into
  ``raise_for_admin_result``'s ``detail`` (``_utf8_text`` eats the ValueError);
* PUT /api/ups/halt, whose privileged pmset result passes through
  ``raise_for_admin_result`` but is not itself the response body;
* surrogate keys AND values in an ok payload across a real ASGI cycle.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest import mock
from urllib.parse import quote

import yaml
from fastapi import FastAPI, HTTPException

from hub.routers import nas_common, nas_storage, ups_api, wireguard_api

#: Loaded from real YAML text: the 1.1 resolver parses ``0xF…`` through
#: ``int(x, 16)``, which CPython's 4300-digit str->int cap does not bound,
#: so the leftover arrives *already-int* and only fails at render time.
_HUGE_INT = yaml.safe_load("v: 0x" + "F" * 4400)["v"]


async def _asgi_request(method, path, *, body=None):
    """Drive the nas_common-backed routers through a real ASGI cycle."""
    app = FastAPI()
    app.include_router(nas_storage.router)
    app.include_router(wireguard_api.router)
    app.include_router(ups_api.router)
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": payload, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": quote(path, safe="/").encode(),
        "query_string": b"", "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    # The body must already be valid UTF-8 JSON — decode strictly on purpose.
    return status, json.loads(raw.decode("utf-8")) if raw else None


def request(method, path, *, body=None):
    return asyncio.run(_asgi_request(method, path, body=body))


def _admin_browser():
    """An administrator browser session, as nas_common resolves one."""
    return (
        mock.patch.object(nas_common.auth, "browser_authenticated", return_value=True),
        mock.patch.object(nas_common.auth, "request_username", return_value="admin"),
        mock.patch.object(nas_common.auth, "is_admin", return_value=True),
        mock.patch.object(nas_common.auth, "request_client_id", return_value="127.0.0.1"),
    )


class NasCommonJsonableDigitCapTests(unittest.TestCase):
    """The sanitizer contract itself — these fail on the pre-fix tree."""

    def test_over_cap_int_is_dropped_like_inf(self):
        self.assertIsNone(nas_common._jsonable(_HUGE_INT))
        cleaned = nas_common._jsonable({"ok": True, "xid": _HUGE_INT, "port": 51820})
        self.assertIsNone(cleaned["xid"])
        self.assertEqual(cleaned["port"], 51820)
        self.assertIs(cleaned["ok"], True)
        json.dumps(cleaned, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_over_cap_int_nested_in_list_is_dropped(self):
        cleaned = nas_common._jsonable({"ok": True, "peers": [1, _HUGE_INT, 3]})
        self.assertEqual(cleaned["peers"], [1, None, 3])
        json.dumps(cleaned, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_over_cap_int_key_still_drops_whole_entry(self):
        cleaned = nas_common._jsonable({_HUGE_INT: "gone", "kept": 1})
        self.assertEqual(cleaned, {"kept": 1})

    def test_bool_and_ordinary_int_are_served_verbatim(self):
        self.assertIs(nas_common._jsonable(True), True)
        self.assertIs(nas_common._jsonable(False), False)
        self.assertEqual(nas_common._jsonable(10**100), 10**100)
        self.assertEqual(nas_common._jsonable(-1), -1)


class WireguardOkPayloadRenderTests(unittest.TestCase):
    """POST /api/wireguard/interface returns raise_for_admin_result's cleaned
    dict as the response body — the huge-int case 500'd pre-fix."""

    def _interface(self, result):
        patches = _admin_browser() + (
            mock.patch.object(
                wireguard_api.wireguard_svc, "installation",
                return_value={"installed": True},
            ),
            mock.patch.object(
                wireguard_api.wireguard_svc, "interface_action", return_value=result,
            ),
            mock.patch.object(wireguard_api.audit, "record", lambda *a, **k: {}),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
            return request(
                "POST", "/api/wireguard/interface", body={"action": "restart"},
            )

    def test_huge_int_in_ok_payload_stays_http_200(self):
        status, body = self._interface({
            "ok": True, "action": "restart",
            "handshake_age": _HUGE_INT, "message": "restarted\ud800",
        })
        self.assertEqual(status, 200)
        self.assertIs(body["ok"], True)
        # over-cap int dropped like inf; the surrogate is scrubbed
        self.assertIsNone(body["handshake_age"])
        self.assertEqual(body["message"], "restarted?")

    def test_nan_and_surrogate_key_in_ok_payload_stay_http_200(self):
        status, body = self._interface({
            "ok": True, "up\ud800": "kept", "since": float("nan"),
        })
        self.assertEqual(status, 200)
        self.assertIsNone(body["since"])
        self.assertEqual(body["up?"], "kept")


class SnapshotCreateOkPayloadRenderTests(unittest.TestCase):
    """POST /api/snapshots/create renders the privileged tmutil result through
    nas_common._jsonable — an over-cap XID 500'd it pre-fix."""

    def _create(self, result):
        patches = _admin_browser() + (
            mock.patch.object(
                nas_storage.snapshots_svc, "create_snapshot", return_value=result,
            ),
            mock.patch.object(nas_storage.audit, "record", lambda *a, **k: {}),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            return request("POST", "/api/snapshots/create")

    def test_huge_xid_in_ok_payload_stays_http_200(self):
        status, body = self._create({
            "ok": True, "name": "com.apple.TimeMachine.2026-08-25\ud800",
            "xid": _HUGE_INT,
        })
        self.assertEqual(status, 200)
        self.assertIs(body["ok"], True)
        self.assertIsNone(body["xid"])
        self.assertNotIn("\ud800", body["name"])


class ServiceErrorParamStaysImmunePins(unittest.TestCase):
    """A failure result's extras ride into api_error's params — the over-cap
    int is dropped by errors._jsonable_param, never a 500."""

    def test_huge_int_param_keeps_the_coded_400(self):
        patches = _admin_browser() + (
            mock.patch.object(
                nas_storage.snapshots_svc, "time_machine_action",
                return_value={
                    "ok": False, "error": "bad_action",
                    "hint": _HUGE_INT, "action": "spin",
                },
            ),
            mock.patch.object(nas_storage.audit, "record", lambda *a, **k: {}),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            status, body = request(
                "POST", "/api/timemachine/action", body={"action": "start"},
            )
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "snapshot.bad_action")

    def test_huge_int_failure_message_keeps_the_coded_error(self):
        # _utf8_text's str() probe eats the digit-cap ValueError; the coded
        # admin.failed survives with an empty detail instead of a 500.
        with self.assertRaises(HTTPException) as ctx:
            nas_common.raise_for_admin_result({
                "ok": False, "error": "failed", "message": _HUGE_INT,
            })
        detail = ctx.exception.detail
        self.assertEqual(detail["code"], "admin.failed")
        json.dumps(detail, ensure_ascii=False, allow_nan=False).encode("utf-8")


class UpsHaltStaysImmunePins(unittest.TestCase):
    """PUT /api/ups/halt feeds the privileged pmset result through
    raise_for_admin_result but answers with a fresh ups_svc snapshot; the
    over-cap leftover in that result must not break the write path."""

    def test_huge_int_in_pmset_result_stays_http_200(self):
        patches = _admin_browser() + (
            mock.patch.object(
                ups_api.macos_admin, "run_admin",
                return_value={"ok": True, "ticks": _HUGE_INT, "note": "ok\ud800"},
            ),
            mock.patch.object(
                ups_api.ups_svc, "ups_status", return_value={"present": False},
            ),
            mock.patch.object(
                ups_api.ups_policy, "public_state", return_value={"armed": False},
            ),
            mock.patch.object(ups_api.audit, "record", lambda *a, **k: {}),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7]:
            status, body = request("PUT", "/api/ups/halt", body={"haltlevel": 50})
        self.assertEqual(status, 200)
        self.assertIs(body["ok"], True)
        self.assertIs(body["ups"]["present"], False)
        self.assertIs(body["ups"]["shutdown_state"]["armed"], False)


if __name__ == "__main__":
    unittest.main()
