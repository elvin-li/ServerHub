"""Third leftover-500s sweep of the NAS storage routes, over real ASGI.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the uncapped YAML/plist hex form that arrives
already-int — vanished-CLI 503-vs-500) were re-reproduced against the
snapshots / SMART / NFS / Time Machine routes in ``hub/routers/nas_storage.py``.
One live leak was found and is fixed alongside this file:

* ``snapshots_svc.time_machine_overview`` read a destination's mount with a
  bare ``str(entry.get("MountPoint") or "")``.  plistlib parses
  ``<integer>0xF…</integer>`` through ``int(x, 16)``, which CPython's
  4300-digit str->int parse cap does not bound, so a leftover plist-hex
  MountPoint arrives *already-int* and the bare ``str()`` raised the
  int->str digit-cap ValueError.  ``fan_out`` re-raises it on iteration
  inside ``snapshots_svc.overview()``, so the whole of GET /api/snapshots
  answered 500 — snapshot inventory included, not just the Time Machine
  card.  The MountPoint pins here fail on the pre-fix tree.

Everything else in the blast radius was found immune, so the rest of this
file pins the stays-immune corners at the HTTP layer — request routing,
response rendering and the strict UTF-8 decode of the body:

* a >4300-digit integer literal in the request body (``urgency`` on
  POST /api/snapshots/thin): ``json.loads`` raises ValueError (NOT
  JSONDecodeError) for the whole document, and FastAPI's body-parse guard
  answers the coded 400, never a 500;
* an over-cap int and a lone surrogate riding a privileged SMART ok payload
  through ``raise_service_error`` (the union's ``nas_common._jsonable``
  str() probe drops the int like inf and scrubs the surrogate);
* GET /api/nfs/exports/preview rendering an exports row whose ``raw`` is an
  over-cap int (``_utf8_text``'s str() probe eats the ValueError, the row
  drops, its siblings survive).
"""
from __future__ import annotations

import asyncio
import json
import plistlib
import unittest
from unittest import mock
from urllib.parse import quote

from fastapi import FastAPI

from hub import snapshots_svc
from hub.routers import nas_common, nas_storage

#: Parsed from real plist bytes: plistlib's ``<integer>`` handler runs
#: ``int(x, 16)`` for the ``0x`` form, which CPython's 4300-digit str->int
#: parse cap does not bound, so the leftover arrives *already-int* and only
#: fails at render time (``str()`` / ``json.dumps``).
_HUGE_INT = plistlib.loads(
    b'<?xml version="1.0"?><plist version="1.0"><dict>'
    b"<key>v</key><integer>0x" + b"F" * 4400 + b"</integer>"
    b"</dict></plist>"
)["v"]

#: What ``tmutil destinationinfo -X`` looks like with the hostile MountPoint,
#: fed through the real ``sh`` -> ``_plist`` -> plistlib pipeline.
_DESTINATIONS_PLIST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<plist version="1.0"><dict>'
    "<key>Destinations</key><array><dict>"
    "<key>Name</key><string>TM Disk</string>"
    "<key>ID</key><string>ABCD-1234</string>"
    "<key>Kind</key><string>Local</string>"
    "<key>MountPoint</key><integer>0x" + "F" * 4400 + "</integer>"
    "<key>LastDestination</key><integer>1</integer>"
    "</dict></array></dict></plist>"
)


def _fake_sh(argv, timeout=0, **kwargs):
    """Only ``tmutil destinationinfo`` answers; every other CLI read fails."""
    if "destinationinfo" in argv:
        return 0, _DESTINATIONS_PLIST, ""
    return 1, "", ""


async def _asgi_request(method, path, *, body=None, raw_body=None):
    """Drive the nas_storage router through a real ASGI cycle."""
    app = FastAPI()
    app.include_router(nas_storage.router)
    if raw_body is not None:
        payload = raw_body
    else:
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
    # The body must already be valid UTF-8 — decode strictly on purpose.
    return status, raw.decode("utf-8")


def request(method, path, *, body=None, raw_body=None):
    return asyncio.run(_asgi_request(method, path, body=body, raw_body=raw_body))


def _admin_browser():
    """An administrator browser session, as nas_common resolves one."""
    return (
        mock.patch.object(nas_common.auth, "browser_authenticated", return_value=True),
        mock.patch.object(nas_common.auth, "request_username", return_value="admin"),
        mock.patch.object(nas_common.auth, "is_admin", return_value=True),
        mock.patch.object(nas_common.auth, "request_client_id", return_value="127.0.0.1"),
    )


class TimeMachineMountPointDigitCapTests(unittest.TestCase):
    """The live leak — these fail on the pre-fix tree."""

    def test_over_cap_plist_hex_mountpoint_does_not_raise(self):
        with mock.patch.object(snapshots_svc, "sh", _fake_sh):
            out = snapshots_svc.time_machine_overview()
        self.assertEqual(len(out["destinations"]), 1)
        dest = out["destinations"][0]
        # An unrenderable mount can never name a directory: reported as
        # unmounted, the rest of the destination row survives.
        self.assertEqual(dest["mount"], "")
        self.assertIs(dest["mounted"], False)
        self.assertEqual(dest["name"], "TM Disk")
        self.assertIs(dest["last_used"], True)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_get_snapshots_stays_http_200(self):
        snapshots_svc.invalidate()
        try:
            with mock.patch.object(snapshots_svc, "sh", _fake_sh):
                status, raw = request("GET", "/api/snapshots")
        finally:
            snapshots_svc.invalidate()
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertEqual(len(body["time_machine"]["destinations"]), 1)
        self.assertEqual(body["time_machine"]["destinations"][0]["mount"], "")
        # The snapshot inventory renders too — the pre-fix raise cost the
        # whole page, not just the Time Machine card.
        self.assertIn("volumes", body)


class ThinUrgencyHugeJsonBodyStaysImmunePins(unittest.TestCase):
    """A >4300-digit integer literal in the request body: ``json.loads``
    raises ValueError, NOT JSONDecodeError, for the whole document.  FastAPI's
    body-parse guard answers the coded 400 — never a 500, and never the
    handler (so no admin session is needed for the pin)."""

    def test_huge_int_urgency_is_the_coded_400_not_500(self):
        raw = b'{"mount": "/", "urgency": ' + b"9" * 5000 + b"}"
        status, body = request("POST", "/api/snapshots/thin", raw_body=raw)
        self.assertEqual(status, 400)
        self.assertIn("error parsing the body", body)


class SmartTestOkPayloadStaysImmunePins(unittest.TestCase):
    """POST /api/smart/test renders the service result through
    ``raise_service_error`` -> ``nas_common._jsonable``: the over-cap int
    drops like inf and the surrogate is scrubbed, across a real ASGI cycle."""

    def test_huge_int_and_surrogate_in_ok_payload_stay_http_200(self):
        patches = _admin_browser() + (
            mock.patch.object(
                nas_storage.smart_test_svc, "start_test",
                return_value={
                    "ok": True, "device": "/dev/disk4", "kind": "short",
                    "estimated_minutes": _HUGE_INT, "message": "started\ud800",
                },
            ),
            mock.patch.object(nas_storage.audit, "record", lambda *a, **k: {}),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            status, raw = request(
                "POST", "/api/smart/test",
                body={"device": "/dev/disk4", "kind": "short"},
            )
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertIs(body["ok"], True)
        self.assertIsNone(body["estimated_minutes"])
        self.assertEqual(body["message"], "started?")


class NfsPreviewOverCapRawStaysImmunePins(unittest.TestCase):
    """GET /api/nfs/exports/preview builds a PlainTextResponse from each
    row's ``raw``: ``_utf8_text``'s str() probe eats the digit-cap
    ValueError, so the poisoned row drops and its siblings survive."""

    def test_over_cap_and_surrogate_raw_rows_stay_http_200(self):
        with mock.patch.object(
            nas_storage.nfs_svc, "read_exports",
            return_value=[
                {"raw": _HUGE_INT},
                {"raw": "/srv/media -alldirs 10.0.0.0/24"},
                {"raw": "/srv/tm\ud800 -alldirs everyone"},
                "not-a-dict",
            ],
        ):
            status, body = request("GET", "/api/nfs/exports/preview")
        self.assertEqual(status, 200)
        self.assertIn("/srv/media -alldirs 10.0.0.0/24", body)
        # The surrogate is scrubbed, not the row dropped …
        self.assertIn("/srv/tm?", body)
        # … while the unrenderable int can only drop.
        self.assertNotIn("9999", body)


if __name__ == "__main__":
    unittest.main()
