"""Third leftover-500s sweep of the Pool / RAID surface, over real ASGI.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the uncapped YAML/plist hex form that arrives
already-int — numeric YAML ids, vanished-CLI 503-vs-500) were re-reproduced
against every route the Pool page and the AppleRAID panel mount:

    GET  /api/storage/pool          POST /api/storage/pool/plan
    POST /api/storage/pool/save     POST /api/storage/pool/clear
    GET  /api/raid                  POST /api/raid/sets
    POST /api/raid/delete           POST /api/raid/members/remove

No live leak was found: the pool2 pass hardened the services
(``storage_pool_svc._text`` str() probe, ``raid_svc._req_text`` /
``_jsonable`` / ``_size_fields``, the ``_diskutil_on_disk`` disk-confirmed
503) and the shared layers (``errors._jsonable_param``, ``nas_common
._jsonable``) already cover the rest.  But those pins live at the service
and funnel level — none of them exercises request routing, Pydantic body
parsing, the audit write, or Starlette's strict UTF-8 render of the final
body.  A regression in any of those layers (a route handler echoing a raw
request field into an error param, a refactor swapping ``_req_text`` back
to ``str()``) would ship without failing a test.  This battery pins the
whole cycle at the HTTP layer:

* GET /api/storage/pool renders a hostile volume table + hand-edited YAML
  (surrogate mounts on both sides of the member join, an over-cap
  already-int member, a numeric member that must read as its string form,
  bytes / inf / non-dict rows) as HTTP 200 whose body decodes strictly;
* a >4300-digit integer literal anywhere in a request body: ``json.loads``
  raises ValueError (NOT JSONDecodeError) for the whole document, and
  FastAPI's body-parse guard answers the coded 400, never a 500;
* a JSON ``\\ud800`` escape (which json.loads happily materialises as a
  lone surrogate str) in ``policy`` / RAID mutation fields earns the coded
  refusal with scrubbed params — the error body itself must survive the
  UTF-8 encode;
* the vanished-diskutil 503 fires through the real route (existing pins
  only call ``_raid_call`` directly), and a genuine privileged failure
  whose message carries a surrogate + a 5000-digit tail keeps the coded
  ``admin.failed`` shape with a cleanly rendered body;
* a privileged ok payload with a surrogate KEY and an over-cap int rides
  ``raise_service_error`` to a strict-UTF-8 200 (key scrubbed, int dropped
  like inf).
"""
from __future__ import annotations

import asyncio
import json
import plistlib
import unittest
from unittest import mock
from urllib.parse import quote

from fastapi import FastAPI

from hub import raid_svc, storage_pool_svc, storage_svc
from hub.routers import nas_common, nas_storage
from hub.routers import storage as storage_router

#: Parsed from real plist bytes: plistlib's ``<integer>`` handler runs
#: ``int(x, 16)`` for the ``0x`` form, which CPython's 4300-digit str->int
#: parse cap does not bound, so the leftover arrives *already-int* and only
#: fails at render time (``str()`` / ``json.dumps``).
_HUGE_INT = plistlib.loads(
    b'<?xml version="1.0"?><plist version="1.0"><dict>'
    b"<key>v</key><integer>0x" + b"F" * 4400 + b"</integer>"
    b"</dict></plist>"
)["v"]

_HEX_4400 = "F" * 4400


async def _asgi_request(method, path, *, body=None, raw_body=None, query=b""):
    """Drive the pool + NAS routers through a real ASGI cycle."""
    app = FastAPI()
    app.include_router(storage_router.router)
    app.include_router(nas_storage.router)
    payload = raw_body if raw_body is not None else (
        b"" if body is None else json.dumps(body).encode("utf-8")
    )
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
        "query_string": query, "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    # The body must already be valid UTF-8 — decode strictly on purpose.
    return status, raw.decode("utf-8")


def request(method, path, *, body=None, raw_body=None, query=b""):
    return asyncio.run(_asgi_request(method, path, body=body, raw_body=raw_body, query=query))


def _admin_browser():
    """An administrator browser session, as nas_common resolves one."""
    return (
        mock.patch.object(nas_common.auth, "browser_authenticated", return_value=True),
        mock.patch.object(nas_common.auth, "request_username", return_value="admin"),
        mock.patch.object(nas_common.auth, "is_admin", return_value=True),
        mock.patch.object(nas_common.auth, "request_client_id", return_value="127.0.0.1"),
    )


_VAULT = {
    "device": "/dev/disk6s1",
    "mount": "/Volumes/Vault",
    "kind": "external",
    "total_gb": 10,
    "used_gb": 1,
    "avail_gb": 9,
    "pct": 10,
    "disk_id": "disk6",
    "filesystem": "apfs",
}


class PoolOverviewHostileHttpPins(unittest.TestCase):
    """GET /api/storage/pool over the real route, with the full leftover zoo
    on both sides of the member join."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def test_hostile_volumes_and_yaml_stay_http_200(self):
        volumes = [
            dict(_VAULT),
            # Surrogate mount that must still match the identically-broken
            # YAML member below — both sides scrub before the lookup.
            dict(_VAULT, mount="/Volumes/Su\ud800rr", used_gb=_HUGE_INT,
                 avail_gb="9" * 5000),
            dict(_VAULT, mount=b"/Volumes/By\xfftes", disk_id=b"disk7",
                 total_gb=float("inf"), pct=float("nan")),
            # An over-cap already-int mount cannot name a directory: the row
            # can only drop, never raise.
            dict(_VAULT, mount=_HUGE_INT, filesystem=float("-inf")),
            "not-a-dict",
            None,
        ]
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=volumes),
            mock.patch.object(
                storage_pool_svc, "cfg",
                return_value={"settings": {"storage_pool": {
                    "name": "p\ud800ool",
                    # str member, surrogate member, over-cap already-int,
                    # numeric YAML id, unmounted path.
                    "members": ["/Volumes/Vault", "/Volumes/Su\ud800rr",
                                _HUGE_INT, 123, "/gone"],
                    "policy": "least-used-pct",
                    "min_free_gb": float("inf"),
                }}},
            ),
        ):
            status, raw = request("GET", "/api/storage/pool", query=b"force=true")
        self.assertEqual(status, 200)
        body = json.loads(raw)
        # The surrogate name is scrubbed, not silently defaulted away.
        self.assertEqual(body["name"], "p?ool")
        mounts = [m["mount"] for m in body["members"]]
        self.assertIn("/Volumes/Vault", mounts)
        # The surrogate member matched the identically-broken volume mount.
        self.assertIn("/Volumes/Su?rr", mounts)
        # The numeric YAML member reads as its string form and is *visible*
        # as missing — the over-cap int is the only one that can drop.
        self.assertIn("123", body["missing_members"])
        self.assertIn("/gone", body["missing_members"])
        for missing in body["missing_members"]:
            self.assertNotIn("\ud800", missing)
        self.assertIsInstance(body["summary"]["total_gb"], (int, float))


def _pool_write_env(test):
    """list_volumes + a coherent cfg/update_settings pair for save tests."""
    test.settings = {}

    def fake_update(patch: dict) -> dict:
        test.settings.update(patch)
        return test.settings

    for patcher in (
        mock.patch.object(storage_svc, "list_volumes", return_value=[dict(_VAULT)]),
        mock.patch.object(storage_pool_svc, "update_settings", side_effect=fake_update),
        mock.patch.object(storage_pool_svc, "cfg",
                          side_effect=lambda: {"settings": test.settings}),
    ):
        patcher.start()
        test.addCleanup(patcher.stop)


class PoolPlanSaveHttpPins(unittest.TestCase):
    """The plan/save/clear POST routes across the full request cycle."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)
        _pool_write_env(self)

    def test_surrogate_policy_is_the_coded_400_with_scrubbed_params(self):
        """json.loads materialises the ``\\ud800`` escape as a lone
        surrogate str; the coded refusal's own body must render."""
        status, raw = request(
            "POST", "/api/storage/pool/plan",
            raw_body=b'{"mounts": ["/Volumes/Vault"], "policy": "\\ud800bad"}',
        )
        self.assertEqual(status, 400)
        detail = json.loads(raw)["detail"]
        self.assertEqual(detail["code"], "storage_pool.bad_policy")
        self.assertNotIn("\ud800", detail["message"])
        self.assertNotIn("\ud800", detail["params"]["policy"])

    def test_surrogate_mount_earns_not_poolable_with_scrubbed_params(self):
        status, raw = request(
            "POST", "/api/storage/pool/plan",
            raw_body=b'{"mounts": ["/Volumes/V\\ud800"], "policy": "most-free"}',
        )
        self.assertEqual(status, 400)
        detail = json.loads(raw)["detail"]
        self.assertEqual(detail["code"], "storage_pool.not_poolable")
        self.assertNotIn("\ud800", detail["params"]["mount"])

    def test_huge_json_int_mount_is_the_coded_400_not_500(self):
        """A >4300-digit integer literal in the body: json.loads raises
        ValueError, NOT JSONDecodeError, for the whole document — FastAPI's
        body-parse guard answers the coded 400."""
        raw_body = b'{"mounts": [' + b"9" * 5000 + b'], "policy": "most-free"}'
        status, raw = request("POST", "/api/storage/pool/plan", raw_body=raw_body)
        self.assertEqual(status, 400)
        self.assertIn("error parsing the body", raw)

    def test_huge_json_int_min_free_is_the_coded_400_not_500(self):
        raw_body = (b'{"mounts": ["/Volumes/Vault"], "min_free_gb": '
                    + b"9" * 5000 + b"}")
        status, raw = request("POST", "/api/storage/pool/save", raw_body=raw_body)
        self.assertEqual(status, 400)
        self.assertIn("error parsing the body", raw)

    def test_huge_digit_string_mount_keeps_the_coded_refusal(self):
        """A 5000-digit *string* mount is parse-capped before it can become
        an int: it must keep behaving as a string and earn not_poolable."""
        status, raw = request(
            "POST", "/api/storage/pool/plan",
            body={"mounts": ["9" * 5000], "policy": "most-free"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw)["detail"]["code"], "storage_pool.not_poolable")

    def test_save_scrubs_surrogate_name_and_drops_inf_floor(self):
        status, raw = request(
            "POST", "/api/storage/pool/save",
            raw_body=(b'{"mounts": ["/Volumes/Vault"], "policy": "most-free",'
                      b' "name": "va\\ud800ult", "min_free_gb": 1e999}'),
        )
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertIs(body["applied"], True)
        self.assertNotIn("\ud800", body["name"])
        saved = self.settings["storage_pool"]
        self.assertNotIn("\ud800", saved["name"])
        saved["name"].encode("utf-8")
        self.assertEqual(saved["min_free_gb"], 0.0)
        self.assertEqual(saved["members"], ["/Volumes/Vault"])

    def test_save_huge_digit_string_floor_saves_zero(self):
        """float("9"*5000) is inf — the floor drops to 0.0, never a raise."""
        status, raw = request(
            "POST", "/api/storage/pool/save",
            body={"mounts": ["/Volumes/Vault"], "min_free_gb": "9" * 5000},
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.settings["storage_pool"]["min_free_gb"], 0.0)
        self.assertIs(json.loads(raw)["applied"], True)

    def test_clear_stays_http_200(self):
        status, raw = request("POST", "/api/storage/pool/clear")
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertIs(body["configured"], False)
        self.assertEqual(self.settings["storage_pool"]["members"], [])


#: Hostile diskutil plists fed through the real ``sh`` -> ``_plist`` ->
#: plistlib pipeline: over-cap plist-hex ints (uuid, Size, MountPoint, the
#: APFS physical store), ``<data>`` names, ``<date>`` strings, an inf rebuild
#: percent.
_RAID_PLIST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
    "<key>AppleRAIDSets</key><array><dict>"
    "<key>AppleRAIDSetUUID</key><integer>0x" + _HEX_4400 + "</integer>"
    "<key>Name</key><data>eA==</data>"
    "<key>Level</key><string>mirror</string>"
    "<key>Status</key><date>2026-08-25T00:00:00Z</date>"
    "<key>Size</key><integer>0x" + _HEX_4400 + "</integer>"
    "<key>AppleRAIDMembers</key><array><dict>"
    "<key>AppleRAIDMemberUUID</key><string>m1</string>"
    "<key>MemberStatus</key><string>Online</string>"
    "<key>AppleRAIDMemberRebuildPercent</key><real>inf</real>"
    "<key>Size</key><integer>0x" + _HEX_4400 + "</integer>"
    "</dict></array></dict></array></dict></plist>"
)
_LIST_PLIST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
    "<key>AllDisksAndPartitions</key><array><dict>"
    "<key>DeviceIdentifier</key><string>disk4</string>"
    "<key>Size</key><integer>0x" + _HEX_4400 + "</integer>"
    "<key>Partitions</key><array><dict>"
    "<key>DeviceIdentifier</key><string>disk4s1</string>"
    "<key>MountPoint</key><integer>0x" + _HEX_4400 + "</integer>"
    "<key>VolumeName</key><data>eA==</data>"
    "</dict></array>"
    "<key>APFSPhysicalStores</key><array><dict>"
    "<key>DeviceIdentifier</key><integer>0x" + _HEX_4400 + "</integer>"
    "</dict></array>"
    "</dict></array></dict></plist>"
)
_INFO_PLIST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
    "<key>TotalSize</key><integer>0x" + _HEX_4400 + "</integer>"
    "<key>MediaName</key><data>eA==</data>"
    "<key>Internal</key><true/>"
    "<key>SolidState</key><true/>"
    "<key>BusProtocol</key><date>2026-08-25T00:00:00Z</date>"
    "</dict></plist>"
)


def _fake_diskutil_sh(argv, timeout=0, **kwargs):
    if "appleRAID" in argv:
        return 0, _RAID_PLIST, ""
    if "info" in argv:
        return 0, _INFO_PLIST, ""
    if "list" in argv:
        return 0, _LIST_PLIST, ""
    return 1, "", ""


class RaidOverviewHostilePlistHttpPins(unittest.TestCase):
    """GET /api/raid through the real sh -> plistlib pipeline."""

    def test_hostile_plists_stay_http_200(self):
        raid_svc.invalidate()
        try:
            with mock.patch.object(raid_svc, "sh", _fake_diskutil_sh):
                status, raw = request("GET", "/api/raid", query=b"force=true")
        finally:
            raid_svc.invalidate()
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertEqual(len(body["sets"]), 1)
        entry = body["sets"][0]
        # The over-cap plist-hex Size can only drop; the set row survives.
        self.assertIsNone(entry["size_bytes"])
        self.assertIsNone(entry["size_gb"])
        self.assertEqual(entry["members"][0]["status"], "Online")
        self.assertIsNone(entry["members"][0]["rebuild_percent"])
        self.assertIs(entry["rebuilding"], False)
        # The candidate row built from an over-cap TotalSize + <data> name.
        self.assertEqual(len(body["candidates"]), 1)
        self.assertEqual(body["candidates"][0]["device"], "disk4")
        self.assertIsNone(body["candidates"][0]["size_bytes"])


_MIRROR = {
    "uuid": "abcd1234", "name": "Mirror", "level": "mirror",
    "members": [
        {"uuid": "m1", "healthy": True},
        {"uuid": "m2", "healthy": True},
        {"uuid": "m3", "healthy": True},
    ],
    "member_count": 3,
}


class RaidMutationHttpPins(unittest.TestCase):
    """The /api/raid mutations across the full request cycle, admin session
    resolved through the real nas_common gate."""

    def _with_admin(self, extra, fn):
        patches = _admin_browser() + tuple(extra)
        try:
            for p in patches:
                p.start()
            return fn()
        finally:
            for p in patches:
                p.stop()

    def test_surrogate_mutation_fields_earn_the_coded_400(self):
        raw_body = (
            b'{"level": "\\ud800", "name": "n\\udfff", "filesystem": "x\\ud800",'
            b' "devices": ["d\\ud800"], "confirm": true, "confirm_phrase": "\\ud800"}'
        )
        status, raw = self._with_admin(
            (), lambda: request("POST", "/api/raid/sets", raw_body=raw_body)
        )
        self.assertEqual(status, 400)
        detail = json.loads(raw)["detail"]
        self.assertEqual(detail["code"], "raid.bad_level")
        self.assertNotIn("\ud800", detail["message"])
        self.assertNotIn("\ud800", detail["params"]["level"])

    def test_huge_json_int_device_is_the_coded_400_not_500(self):
        raw_body = (
            b'{"level": "mirror", "name": "M", "filesystem": "APFS",'
            b' "devices": [' + b"9" * 5000 + b'],'
            b' "confirm": true, "confirm_phrase": "ERASE"}'
        )
        status, raw = self._with_admin(
            (), lambda: request("POST", "/api/raid/sets", raw_body=raw_body)
        )
        self.assertEqual(status, 400)
        self.assertIn("error parsing the body", raw)

    def test_vanished_diskutil_answers_503_through_the_real_route(self):
        """Existing pins call _raid_call directly; this drives the mounted
        POST /api/raid/delete, audit write included."""
        extra = (
            mock.patch.object(raid_svc, "list_sets", return_value=[dict(_MIRROR)]),
            mock.patch.object(raid_svc, "run_admin", return_value={
                "ok": False, "error": "failed",
                "message": "sh: /usr/sbin/diskutil: command not found",
            }),
            mock.patch.object(raid_svc, "invalidate"),
            mock.patch.object(raid_svc, "_diskutil_on_disk", return_value=False),
        )
        status, raw = self._with_admin(extra, lambda: request(
            "POST", "/api/raid/delete",
            body={"set_uuid": "abcd1234", "confirm": True, "confirm_phrase": "Mirror"},
        ))
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(raw)["detail"]["code"], "raid.diskutil_missing")

    def test_ok_payload_surrogate_key_and_over_cap_int_stay_http_200(self):
        extra = (
            mock.patch.object(raid_svc, "list_sets", return_value=[dict(_MIRROR)]),
            mock.patch.object(raid_svc, "run_admin", return_value={
                "ok": True, "me\ud800ssage": "done", "n": _HUGE_INT,
                "detail": "x\ud800", "when": float("inf"),
            }),
            mock.patch.object(raid_svc, "invalidate"),
        )
        status, raw = self._with_admin(extra, lambda: request(
            "POST", "/api/raid/delete",
            body={"set_uuid": "abcd1234", "confirm": True, "confirm_phrase": "Mirror"},
        ))
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertIs(body["ok"], True)
        self.assertIn("me?ssage", body)
        self.assertIsNone(body["n"])
        self.assertIsNone(body["when"])
        self.assertNotIn("\ud800", body["detail"])

    def test_genuine_failure_with_hostile_message_keeps_the_coded_shape(self):
        """diskutil still on disk: the raw failure is the truth.  Its message
        carries a surrogate and a 5000-digit tail — the coded admin.failed
        body must still render as strict UTF-8, never crash the encoder."""
        extra = (
            mock.patch.object(raid_svc, "list_sets", return_value=[dict(_MIRROR)]),
            mock.patch.object(raid_svc, "run_admin", return_value={
                "ok": False, "error": "failed",
                "message": "boom \ud800 " + "9" * 5000,
            }),
            mock.patch.object(raid_svc, "invalidate"),
            mock.patch.object(raid_svc, "_diskutil_on_disk", return_value=True),
        )
        status, raw = self._with_admin(extra, lambda: request(
            "POST", "/api/raid/delete",
            body={"set_uuid": "abcd1234", "confirm": True, "confirm_phrase": "Mirror"},
        ))
        # The deliberate coded shape for a real privileged failure — not a
        # crash: the body decoded strictly above and names the code.
        self.assertEqual(status, 500)
        detail = json.loads(raw)["detail"]
        self.assertEqual(detail["code"], "admin.failed")
        self.assertNotIn("\ud800", raw)

    def test_surrogate_member_uuid_is_the_coded_404(self):
        extra = (
            mock.patch.object(raid_svc, "list_sets", return_value=[dict(_MIRROR)]),
        )
        status, raw = self._with_admin(extra, lambda: request(
            "POST", "/api/raid/members/remove",
            raw_body=(b'{"set_uuid": "abcd1234", "member_uuid": "m\\ud800",'
                      b' "confirm": true}'),
        ))
        self.assertEqual(status, 404)
        detail = json.loads(raw)["detail"]
        self.assertEqual(detail["code"], "raid.member_not_found")
        self.assertNotIn("\ud800", detail["params"]["uuid"])


if __name__ == "__main__":
    unittest.main()
