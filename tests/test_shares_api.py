from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import Depends, FastAPI

from hub import auth
from hub.auth import require_auth
from hub.routers.shares import router as shares_router


async def _asgi_request(
    method: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    payload: dict | None = None,
) -> tuple[int, dict]:
    app = FastAPI()
    app.include_router(shares_router, dependencies=[Depends(require_auth)])
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
    response = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return status, json.loads(response or b"{}")


def asgi_request(*args, **kwargs) -> tuple[int, dict]:
    return asyncio.run(_asgi_request(*args, **kwargs))


class SharesAPIContractTests(unittest.TestCase):
    def setUp(self):
        self.json_headers = {"content-type": "application/json"}
        self.valid_create = {
            "path": "/Users/example/Media",
            "name": "Media",
            "smb_name": "Media",
            "guest": False,
            "readonly": False,
            "encrypted": True,
            "time_machine": False,
            "tm_quota_gb": None,
        }

    def _admin_patches(self):
        return (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="admin"),
            patch("hub.auth.is_admin", return_value=True),
        )

    @contextmanager
    def _admin_context(self):
        with ExitStack() as stack:
            for manager in self._admin_patches():
                stack.enter_context(manager)
            yield

    def test_setup_required_wins_before_route_authorization(self):
        with patch("hub.auth.setup_required", return_value=True):
            status, body = asgi_request(
                "PUT",
                "/api/shares/system/remote_login",
                headers=self.json_headers,
                payload={"enabled": True},
            )
        self.assertEqual(status, 401)
        self.assertEqual(body["detail"]["code"], "auth.setup_required")

    def test_anonymous_browser_cannot_mutate_sharing(self):
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=False),
            patch("hub.shares_svc.set_system_service") as mutate,
        ):
            status, body = asgi_request(
                "PUT",
                "/api/shares/system/remote_login",
                headers=self.json_headers,
                payload={"enabled": True},
            )
        self.assertEqual(status, 401)
        self.assertEqual(body["detail"]["code"], "auth.login_required")
        mutate.assert_not_called()

    def test_member_browser_cannot_mutate_sharing(self):
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="member"),
            patch("hub.auth.is_admin", return_value=False),
            patch("hub.shares_svc.set_system_service") as mutate,
        ):
            status, body = asgi_request(
                "PUT",
                "/api/shares/system/remote_login",
                headers=self.json_headers,
                payload={"enabled": True},
            )
        self.assertEqual(status, 403)
        self.assertEqual(body["detail"]["code"], "shares.admin_required")
        mutate.assert_not_called()

    def test_local_token_cannot_read_or_mutate_sharing(self):
        with tempfile.TemporaryDirectory() as temporary:
            token_file = Path(temporary) / ".local-client-token"
            token_file.write_text("local-token", encoding="utf-8")
            headers = {
                "content-type": "application/json",
                auth.LOCAL_TOKEN_HEADER: "local-token",
            }
            with (
                patch.object(auth, "LOCAL_TOKEN_FILE", token_file),
                patch("hub.auth.setup_required", return_value=False),
                patch("hub.auth.browser_authenticated", return_value=False),
                patch("hub.shares_svc.shares_overview") as overview,
                patch("hub.shares_svc.set_system_service") as mutate,
            ):
                read_status, read_body = asgi_request("GET", "/api/shares", headers=headers)
                write_status, write_body = asgi_request(
                    "PUT",
                    "/api/shares/system/remote_login",
                    headers=headers,
                    payload={"enabled": True},
                )
        self.assertEqual(read_status, 403)
        self.assertEqual(read_body["detail"]["code"], "auth.admin_required")
        self.assertEqual(write_status, 401)
        self.assertEqual(write_body["detail"]["code"], "shares.browser_session_required")
        overview.assert_not_called()
        mutate.assert_not_called()

    def test_admin_can_create_update_remove_and_toggle(self):
        created = {"ok": True, "share": {"record_name": "Media"}}
        updated = {"ok": True, "share": {"record_name": "Media", "readonly": True}}
        toggled = {"ok": True, "service": {"id": "remote_login", "enabled": True}}
        with (
            self._admin_context(),
            patch("hub.shares_svc.create_smb_share", return_value=created) as create_mock,
            patch("hub.shares_svc.update_smb_share", return_value=updated) as update,
            patch("hub.shares_svc.remove_smb_share", return_value={"ok": True}) as remove,
            patch("hub.shares_svc.set_system_service", return_value=toggled) as toggle,
            patch("hub.audit.record") as audit_record,
        ):
            responses = [
                asgi_request(
                    "POST", "/api/shares/smb",
                    headers=self.json_headers, payload=self.valid_create,
                ),
                asgi_request(
                    "PUT", "/api/shares/smb/Media",
                    headers=self.json_headers,
                    payload={
                        "smb_name": "Media", "guest": False,
                        "readonly": True, "encrypted": True,
                    },
                ),
                asgi_request(
                    "DELETE", "/api/shares/smb/Media",
                    query={"confirm": "true"},
                ),
                asgi_request(
                    "PUT", "/api/shares/system/remote_login",
                    headers=self.json_headers, payload={"enabled": True},
                ),
            ]
        self.assertEqual([status for status, _ in responses], [200, 200, 200, 200])
        create_mock.assert_called_once_with(**self.valid_create)
        update.assert_called_once_with(
            "Media", smb_name="Media", guest=False, readonly=True, encrypted=True,
            time_machine=False, tm_quota_gb=None,
        )
        remove.assert_called_once_with("Media")
        toggle.assert_called_once_with("remote_login", True)
        self.assertEqual(audit_record.call_count, 4)
        create_audit = audit_record.call_args_list[0].kwargs
        self.assertEqual(create_audit["folder"], "Media")
        self.assertNotIn(self.valid_create["path"], repr(audit_record.call_args_list))

    def test_remove_requires_explicit_confirmation(self):
        with (
            self._admin_context(),
            patch("hub.shares_svc.remove_smb_share") as remove,
        ):
            status, body = asgi_request("DELETE", "/api/shares/smb/Media")
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "shares.confirm_required")
        remove.assert_not_called()

    def test_strict_boolean_and_extra_fields_are_rejected(self):
        with (
            self._admin_context(),
            patch("hub.shares_svc.set_system_service") as mutate,
        ):
            responses = [
                asgi_request(
                    "PUT", "/api/shares/system/remote_login",
                    headers=self.json_headers, payload={"enabled": value},
                )
                for value in ("false", 0, 1, None)
            ]
            responses.append(asgi_request(
                "PUT", "/api/shares/system/remote_login",
                headers=self.json_headers,
                payload={"enabled": True, "command": "whoami"},
            ))
        self.assertEqual([status for status, _ in responses], [422] * 5)
        mutate.assert_not_called()

    def test_create_rejects_extra_fields_before_service_call(self):
        payload = {**self.valid_create, "launchd_label": "com.example.evil"}
        with (
            self._admin_context(),
            patch("hub.shares_svc.create_smb_share") as create,
        ):
            status, _ = asgi_request(
                "POST", "/api/shares/smb",
                headers=self.json_headers, payload=payload,
            )
        self.assertEqual(status, 422)
        create.assert_not_called()

    def test_unknown_system_service_returns_stable_error(self):
        with (
            self._admin_context(),
            patch(
                "hub.shares_svc.set_system_service",
                return_value={"ok": False, "error": "unknown_service"},
            ),
            patch("hub.audit.record"),
        ):
            status, body = asgi_request(
                "PUT", "/api/shares/system/internet_sharing",
                headers=self.json_headers, payload={"enabled": True},
            )
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "shares.unknown_service")
        self.assertEqual(body["detail"]["params"], {"service": "internet_sharing"})

    def test_time_machine_fields_pass_through_to_the_service(self):
        created = {"ok": True, "share": {"record_name": "Backups", "time_machine": True}}
        payload = {
            **self.valid_create,
            "name": "Backups", "smb_name": "Backups",
            "time_machine": True, "tm_quota_gb": 500,
        }
        with (
            self._admin_context(),
            patch("hub.shares_svc.create_smb_share", return_value=created) as create,
            patch("hub.audit.record") as audit_record,
        ):
            status, _ = asgi_request(
                "POST", "/api/shares/smb",
                headers=self.json_headers, payload=payload,
            )
        self.assertEqual(status, 200)
        create.assert_called_once_with(**payload)
        self.assertTrue(audit_record.call_args.kwargs["time_machine"])

    def test_quota_must_be_a_strict_integer(self):
        with (
            self._admin_context(),
            patch("hub.shares_svc.create_smb_share") as create,
        ):
            responses = [
                asgi_request(
                    "POST", "/api/shares/smb",
                    headers=self.json_headers,
                    payload={**self.valid_create, "time_machine": True, "tm_quota_gb": bad},
                )
                for bad in ("500", 1.5)
            ]
        self.assertEqual([status for status, _ in responses], [422, 422])
        create.assert_not_called()

    def test_quota_domain_errors_surface_as_machine_readable_codes(self):
        from hub.shares_svc import ShareValidationError

        cases = {
            "shares.bad_quota": {**self.valid_create, "time_machine": True, "tm_quota_gb": 0},
            "shares.quota_requires_time_machine": {**self.valid_create, "tm_quota_gb": 100},
        }
        for code, payload in cases.items():
            with (
                self.subTest(code=code),
                self._admin_context(),
                patch(
                    "hub.shares_svc.create_smb_share",
                    side_effect=ShareValidationError(code),
                ),
            ):
                status, body = asgi_request(
                    "POST", "/api/shares/smb",
                    headers=self.json_headers, payload=payload,
                )
                self.assertEqual(status, 400)
                self.assertEqual(body["detail"]["code"], code)

    def test_authorization_cancel_maps_to_conflict(self):
        with (
            self._admin_context(),
            patch(
                "hub.shares_svc.set_system_service",
                return_value={"ok": False, "error": "cancelled"},
            ),
            patch("hub.audit.record"),
        ):
            status, body = asgi_request(
                "PUT", "/api/shares/system/remote_login",
                headers=self.json_headers, payload={"enabled": True},
            )
        self.assertEqual(status, 409)
        self.assertEqual(body["detail"]["code"], "shares.authorization_cancelled")


if __name__ == "__main__":
    unittest.main()
