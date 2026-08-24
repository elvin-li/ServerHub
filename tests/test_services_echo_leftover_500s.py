"""Leftover ``\\ud800`` echo 500s on Services / container mutation responses.

A JSON body value of ``"\\ud800"`` (a lone surrogate — ``json.loads`` accepts
the escape, Starlette's UTF-8 response encode does not) was stored verbatim
and echoed back by PUT /api/services/{sid}/override, PUT
/api/services/signatures, POST /api/services/{sid}/adopt, PUT
/api/services/scripts/{sid} and POST /api/containers/batch.  The mutation was
already applied when the response render raised, so the operator got a bare
500 for a change that had in fact happened.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from hub import containers_svc, service_signatures
from hub import services_manage_svc as sms
from hub.errors import api_error


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


SUR = "ok\ud800"


class OverrideEchoLeftoverTests(unittest.TestCase):
    def test_surrogate_patch_is_cleaned_not_500(self):
        """JSON ``{"name": "\\ud800"}`` used to 500 PUT override's echo."""
        stored: dict = {}

        def fake_set_override(sid, clean):
            stored.update(clean)
            return dict(clean)

        with (
            patch.object(sms, "set_override", fake_set_override),
            patch.object(sms, "invalidate_status"),
        ):
            out = sms.update_override("nginx", {
                "name": SUR, "group": SUR, "url": "http://h\ud800ost/x",
            })
        self.assertNotIn("\ud800", stored["name"])
        self.assertNotIn("\ud800", stored["group"])
        self.assertNotIn("\ud800", stored["url"])
        self.assertNotIn("\ud800", out["override"]["name"])
        _starlette(out)

    def test_poisoned_existing_override_echo_is_cleaned_not_500(self):
        """A hand-edited services.yaml override merged into the echo."""
        with (
            patch.object(
                sms, "set_override",
                return_value={"name": SUR, "port": float("inf")},
            ),
            patch.object(sms, "invalidate_status"),
        ):
            out = sms.update_override("nginx", {"hide": True})
        self.assertNotIn("\ud800", out["override"]["name"])
        self.assertIsNone(out["override"]["port"])
        _starlette(out)


class SignatureEchoLeftoverTests(unittest.TestCase):
    def test_surrogate_fields_are_cleaned_not_500(self):
        """JSON ``"\\ud800"`` name/category/procs used to 500 PUT signatures."""
        parsed = service_signatures.parse_signature({
            "slug": "my-app", "name": SUR, "category": SUR, "procs": [SUR],
        })
        self.assertIsNotNone(parsed)
        self.assertNotIn("\ud800", parsed["name"])
        self.assertNotIn("\ud800", parsed["category"])
        for proc in parsed["procs"]:
            self.assertNotIn("\ud800", proc)
        row = service_signatures.remember_into({}, parsed)
        _starlette(row)

    def test_upsert_signature_echo_is_encodable(self):
        applied: dict = {}

        def fake_mutate(fn):
            fn(applied)
            return applied

        with (
            patch.object(sms.config, "mutate", fake_mutate),
            patch.object(sms, "invalidate_status"),
        ):
            out = sms.upsert_signature({
                "slug": "my-app", "name": SUR, "category": SUR, "procs": [SUR],
            })
        self.assertTrue(out["ok"])
        self.assertNotIn("\ud800", out["signature"]["name"])
        _starlette(out)


class BatchActionEchoLeftoverTests(unittest.TestCase):
    def test_surrogate_name_echo_is_cleaned_not_500(self):
        """A ``"\\ud800"`` container name echoed as ``id`` used to 500 batch."""
        with patch.object(
            containers_svc, "container_action",
            side_effect=api_error("container.bad_container_name"),
        ):
            out = containers_svc.batch_action([SUR], "start")
        self.assertFalse(out["ok"])
        self.assertNotIn("\ud800", out["results"][0]["id"])
        _starlette(out)

    def test_surrogate_name_success_echo_is_cleaned_not_500(self):
        with patch.object(
            containers_svc, "container_action", return_value={"ok": True},
        ):
            out = containers_svc.batch_action([SUR], "start")
        self.assertTrue(out["ok"])
        self.assertNotIn("\ud800", out["results"][0]["id"])
        _starlette(out)

    def test_recursing_exception_message_does_not_500(self):
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with patch.object(
            containers_svc, "container_action", side_effect=Recursing(),
        ):
            out = containers_svc.batch_action(["web"], "start")
        self.assertFalse(out["ok"])
        _starlette(out)


class AdoptEchoLeftoverTests(unittest.TestCase):
    def test_surrogate_patch_is_cleaned_not_500(self):
        """JSON ``"\\ud800"`` name/group/start used to 500 POST adopt's echo."""
        auto = {
            "id": "auto:1", "name": "node", "kind": "auto",
            "meta": {"pid": 0, "process": "node", "ports": [3000]},
        }
        applied: dict = {}

        def fake_mutate(fn):
            fn(applied)
            return applied

        with (
            patch.object(sms, "find_service", return_value=auto),
            patch.object(sms, "_full_process_name", return_value=""),
            patch.object(sms, "_process_command_path", return_value=""),
            patch.object(sms, "configured_signatures", return_value=[]),
            patch.object(sms.config, "mutate", fake_mutate),
            patch.object(sms, "invalidate_status"),
        ):
            out = sms.adopt_service("auto:1", {
                "name": SUR, "group": SUR, "start": SUR, "remember": False,
            })
        self.assertTrue(out["ok"])
        entry = out["entry"]
        self.assertNotIn("\ud800", entry["name"])
        self.assertNotIn("\ud800", entry["group"])
        self.assertNotIn("\ud800", entry.get("start") or "")
        stored = applied["scripts"][0]
        self.assertNotIn("\ud800", stored["name"])
        _starlette(out)


class ScriptEchoLeftoverTests(unittest.TestCase):
    def _mutate_on(self, data: dict):
        def fake_mutate(fn):
            fn(data)
            return data

        return fake_mutate

    def test_update_script_surrogate_patch_is_cleaned_not_500(self):
        """JSON ``"\\ud800"`` name/group/url used to 500 PUT scripts' echo."""
        data = {"scripts": [{"id": "s1", "name": "old", "ports": [3000]}]}
        with (
            patch.object(sms, "cfg", return_value=data),
            patch.object(sms.config, "mutate", self._mutate_on(data)),
            patch.object(sms, "invalidate_status"),
        ):
            out = sms.update_script("s1", {
                "name": SUR, "group": SUR, "url": "http://h\ud800ost/x",
                "start": SUR,
            })
        entry = out["entry"]
        self.assertNotIn("\ud800", entry["name"])
        self.assertNotIn("\ud800", entry["group"])
        self.assertNotIn("\ud800", entry["url"])
        self.assertNotIn("\ud800", entry.get("start") or "")
        self.assertNotIn("\ud800", data["scripts"][0]["name"])
        _starlette(out)

    def test_forget_script_poisoned_entry_echo_is_cleaned_not_500(self):
        """A hand-edited entry with ``\\ud800`` / inf used to 500 the DELETE echo."""
        data = {"scripts": [{"id": "s1", "name": SUR, "ports": [float("inf")]}]}
        with (
            patch.object(sms.config, "mutate", self._mutate_on(data)),
            patch.object(sms, "invalidate_status"),
        ):
            out = sms.forget_script("s1")
        self.assertTrue(out["ok"])
        self.assertNotIn("\ud800", out["removed"]["name"])
        _starlette(out)

    def test_clean_cmd_surrogate_is_cleaned(self):
        cleaned = sms._clean_cmd(SUR)
        self.assertIsNotNone(cleaned)
        self.assertNotIn("\ud800", cleaned)
        _starlette({"start": cleaned})


class OverrideRouteEndToEndTests(unittest.TestCase):
    """Through the app: the exact request that used to answer a bare 500."""

    def test_put_override_surrogate_body_is_200(self):
        from fastapi.testclient import TestClient

        from hub import audit
        from hub.app_factory import create_app
        from hub.auth import require_auth

        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        client = TestClient(app, raise_server_exceptions=False)
        body = '{"name": "\\ud800", "group": "\\ud800"}'
        with (
            patch.object(sms, "set_override", lambda sid, clean: dict(clean)),
            patch.object(sms, "invalidate_status"),
            patch.object(audit, "record"),
        ):
            resp = client.put(
                "/api/services/nginx/override",
                content=body.encode("ascii"),
                headers={"content-type": "application/json"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertNotIn("\\ud800", resp.text)


if __name__ == "__main__":
    unittest.main()
