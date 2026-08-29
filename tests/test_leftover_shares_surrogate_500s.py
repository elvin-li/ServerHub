"""Leftover surrogate 500s on the mounted Shares routes, proven at HTTP level.

The shares3 pass pinned the surrogate-bearing inputs at the service layer as
"the coded admin failure the router maps" — but that coded failure is
``failed`` → ``shares.authorization_failed``, an HTTP **500**, and it fires
*after* the SPA's password dialog already made the operator type the macOS
administrator password for a request that could never succeed:

* a share/record name carrying a lone ``\\ud800`` (JSON bodies may) passed
  ``_NAME_RE`` — a surrogate is neither a slash nor a control character — and
  died at the spawn, because ``as_argv`` refuses surrogate argv;
* a *real* directory whose on-disk name holds undecodable bytes (``os.fsdecode``
  hands the ``\\xff`` byte back as the lone surrogate ``\\udcff``) resolved and
  ``is_dir()``'d straight through ``validate_share_path`` and died the same
  way.

No filesystem can hold a lone surrogate as UTF-8 and no spawn will accept it,
so both are bad input: ``_validate_name`` / ``validate_share_path`` now refuse
them with the coded 400s (``shares.bad_name`` / ``shares.bad_path``) before
any password prompt or privileged spawn — the same refusal
``nfs_svc._validate_entry`` already applies to NFS export paths.

The battery drives the *mounted* routes through the same dependency chain the
app factory installs (``require_auth`` + ``admin_password_scope``), so the
password-header path is exercised end to end, and pins the neighbours that are
already immune at the HTTP layer:

* GET /api/shares stays 200 and keeps its rows when ``sharing -l -f json``
  carries a >4300-digit integer (the CPython int cap bypass) — the poisoned
  field loads as None instead of wiping the listing;
* GET /api/shares/acl on an undecodable *existing* share directory answers the
  coded ``shares.acl_read_failed`` with a clean UTF-8 JSON body, not a raw
  UnicodeEncodeError escaping the route.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import Depends, FastAPI

from hub import shares_svc
from hub.app_factory import admin_password_scope
from hub.auth import require_auth
from hub.routers.shares import router as shares_router

_PASSWORD_HEADER = {
    "x-admin-password": base64.b64encode(b"hunter2").decode("ascii"),
}


async def _asgi_request(
    method: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    payload: dict | None = None,
) -> tuple[int, bytes]:
    app = FastAPI()
    # The same dependency pair create_app() installs on this router, so the
    # base64 password header reaches macos_admin's contextvar exactly as it
    # does in production.
    app.include_router(
        shares_router,
        dependencies=[Depends(require_auth), Depends(admin_password_scope)],
    )
    body = json.dumps(payload).encode() if payload is not None else b""
    sent = False
    messages: list[dict] = []

    async def receive() -> dict:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": urlencode(query or {}).encode(),
        "root_path": "",
        "headers": [
            (name.lower().encode(), value.encode())
            for name, value in (headers or {}).items()
        ],
        "server": ("localhost", 8086),
        "client": ("127.0.0.1", 12345),
        "state": {},
    }
    await app(scope, receive, send)
    status = next(
        message["status"]
        for message in messages
        if message["type"] == "http.response.start"
    )
    raw = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return status, raw


def asgi_request(*args, **kwargs) -> tuple[int, bytes]:
    return asyncio.run(_asgi_request(*args, **kwargs))


def _undecodable_dir(parent: Path) -> str:
    """A real directory whose name cannot decode as UTF-8, or skip."""
    raw = os.path.join(os.fsencode(str(parent)), b"me\xffdia")
    try:
        os.mkdir(raw)
    except OSError as error:  # pragma: no cover - APFS refuses the byte
        raise unittest.SkipTest(f"filesystem refuses undecodable names: {error}")
    return os.fsdecode(raw)


@contextmanager
def _admin_browser():
    with ExitStack() as stack:
        for target in (
            ("hub.auth.setup_required", False),
            ("hub.auth.browser_authenticated", True),
            ("hub.auth.request_username", "admin"),
            ("hub.auth.is_admin", True),
        ):
            stack.enter_context(patch(target[0], return_value=target[1]))
        yield


class SurrogateShareNameIs400Tests(unittest.TestCase):
    """POST/PUT /api/shares/smb with a lone-surrogate name is 400, not 500."""

    def setUp(self):
        self.headers = {"content-type": "application/json", **_PASSWORD_HEADER}

    def test_create_with_surrogate_record_name(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            folder = Path(tmp) / "Media"
            folder.mkdir()
            with (
                _admin_browser(),
                patch.object(shares_svc, "_find_share", return_value=None),
                patch.object(
                    shares_svc,
                    "run_admin_sequence",
                    return_value={"ok": False, "error": "failed"},
                ) as admin,
            ):
                status, raw = asgi_request(
                    "POST", "/api/shares/smb",
                    headers=self.headers,
                    payload={
                        "path": str(folder), "name": "Media\ud800",
                        "smb_name": "Media", "guest": False,
                        "readonly": False, "encrypted": False,
                    },
                )
        body = json.loads(raw)
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "shares.bad_name")
        # The refusal must land before the password is spent on a spawn.
        admin.assert_not_called()

    def test_update_with_surrogate_smb_name(self):
        existing = {
            "record_name": "Media", "name": "Media", "path": "/tmp/Media",
            "smb_name": "Media", "shared": True, "guest": False,
            "readonly": False, "encrypted": False,
            "time_machine": False, "tm_quota_gb": None,
        }
        with (
            _admin_browser(),
            patch.object(shares_svc, "_find_share", return_value=existing),
            patch.object(
                shares_svc,
                "run_admin_sequence",
                return_value={"ok": False, "error": "failed"},
            ) as admin,
        ):
            status, raw = asgi_request(
                "PUT", "/api/shares/smb/Media",
                headers=self.headers,
                payload={
                    "smb_name": "Media\ud800", "guest": False,
                    "readonly": False, "encrypted": False,
                },
            )
        body = json.loads(raw)
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "shares.bad_name")
        admin.assert_not_called()


class UndecodableShareDirectoryIs400Tests(unittest.TestCase):
    """POST /api/shares/smb on a real undecodable directory is 400, not 500."""

    def test_create_on_surrogate_path(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            path = _undecodable_dir(Path(tmp))
            with (
                _admin_browser(),
                patch.object(shares_svc, "_find_share", return_value=None),
                patch.object(
                    shares_svc,
                    "run_admin_sequence",
                    return_value={"ok": False, "error": "failed"},
                ) as admin,
            ):
                status, raw = asgi_request(
                    "POST", "/api/shares/smb",
                    headers={"content-type": "application/json", **_PASSWORD_HEADER},
                    payload={
                        "path": path, "name": "Media", "smb_name": "Media",
                        "guest": False, "readonly": False, "encrypted": False,
                    },
                )
        body = json.loads(raw)
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "shares.bad_path")
        admin.assert_not_called()
        # The coded body itself must survive Starlette's strict UTF-8 encode.
        raw.decode("utf-8")


class OverviewHugeIntStaysListedTests(unittest.TestCase):
    """GET /api/shares keeps its rows when sharing JSON carries a >4300-digit int.

    HTTP-layer pin of the shares3 service fix: ``json.loads`` of the huge
    number is ValueError (CPython's int cap), not JSONDecodeError, and it used
    to wipe the whole listing.  The poisoned field now loads as None and the
    row survives all the way into the mounted route's 200 payload.
    """

    def test_overview_is_200_and_keeps_the_share_row(self):
        huge = "9" * 5000
        poisoned = json.dumps({
            "Media": {
                "path": "/tmp/Media", "smb_name": "Media",
                "smb_shared": 1, "smb_guest_access": 0,
                "smb_read_only": 0, "smb_sealed": 0,
            },
        }).replace('"smb_shared": 1', f'"smb_shared": 1, "leftover": {huge}')

        def fake_sh(cmd, timeout=10, **kwargs):
            if list(cmd[:4]) == [shares_svc.SHARING, "-l", "-f", "json"]:
                return 0, poisoned, ""
            return 1, "", "unavailable"

        with (
            _admin_browser(),
            patch.object(shares_svc, "sh", side_effect=fake_sh),
            patch.object(shares_svc, "port_open", return_value=False),
            patch.object(shares_svc, "_dir_size_mb", return_value=None),
        ):
            status, raw = asgi_request("GET", "/api/shares")
        self.assertEqual(status, 200)
        body = json.loads(raw)
        records = [share.get("record_name") for share in body.get("smb", [])]
        self.assertIn("Media", records)
        raw.decode("utf-8")


class AclOnUndecodableShareStaysCodedTests(unittest.TestCase):
    """PUT /api/shares/acl on an undecodable existing share stays coded.

    A query string cannot deliver a lone surrogate (percent-decoding replaces
    it), but a JSON body can (``"\\udcff"`` escapes survive ``json.loads``),
    so the write route is where the surrogate share path actually lands.
    ``as_argv`` refuses the surrogate ``ls -lde`` argv, so the read-back
    answers the stable ``shares.acl_read_failed`` body — never a raw
    UnicodeEncodeError escaping the mounted route without a JSON body.
    """

    def test_acl_write_is_the_coded_failure_with_a_clean_body(self):
        from hub import share_acl_svc

        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            path = _undecodable_dir(Path(tmp))
            share_row = {"record_name": "Media", "path": path}
            with (
                _admin_browser(),
                patch.object(
                    shares_svc, "list_smb_shares", return_value=[share_row],
                ),
                patch.object(
                    share_acl_svc, "local_users",
                    return_value=[{"username": "alice", "uid": 501, "real_name": ""}],
                ),
            ):
                status, raw = asgi_request(
                    "PUT", "/api/shares/acl",
                    headers={"content-type": "application/json", **_PASSWORD_HEADER},
                    payload={"path": path, "username": "alice", "level": "read"},
                )
        body = json.loads(raw)
        self.assertEqual(status, 500)
        self.assertEqual(body["detail"]["code"], "shares.acl_read_failed")
        text = raw.decode("utf-8")
        self.assertNotIn("\udcff", text)


if __name__ == "__main__":
    unittest.main()
