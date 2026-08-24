"""Leftover ``\\ud800`` echo 500s on the VM display-rename response.

A JSON body value of ``"\\ud800"`` (a lone surrogate — ``json.loads`` accepts
the escape, Starlette's UTF-8 response encode does not) was stored verbatim
in the services.yaml override by POST /api/vms/{vm_id}/action with action
``rename`` and echoed back in ``name`` and ``message``.  The rename was
already applied when the response render raised, so the operator got a bare
500 for a change that had in fact happened.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from hub import config, vms_svc


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


SUR = "vm\ud800"
UTM_UUID = "0be47bcd-8442-4f2d-8181-b1fdad2c0b17"


class RenameEchoLeftoverTests(unittest.TestCase):
    def _capture_set_override(self, stored: dict):
        def fake_set_override(key, patch_):
            stored[key] = dict(patch_)
            return dict(patch_)

        return fake_set_override

    def test_utm_surrogate_name_is_cleaned_not_500(self):
        """JSON ``{"name": "\\ud800"}`` used to 500 the rename echo (UTM)."""
        stored: dict = {}
        with patch.object(
            config, "set_override", self._capture_set_override(stored),
        ):
            out = vms_svc.rename_vm_display(UTM_UUID, SUR)
        self.assertTrue(out["ok"])
        self.assertNotIn("\ud800", out["name"])
        self.assertNotIn("\ud800", out["message"])
        self.assertNotIn("\ud800", stored[UTM_UUID]["name"])
        # The rename must still land as a real name, not be dropped.
        self.assertTrue(stored[UTM_UUID]["name"].strip())
        _starlette(out)

    def test_orb_surrogate_name_is_cleaned_not_500(self):
        """The orb: branch stores through the same override and echoed raw."""
        stored: dict = {}
        with (
            patch.object(config, "set_override", self._capture_set_override(stored)),
            patch.object(config, "override", return_value={}),
        ):
            out = vms_svc.rename_vm_display("orb:web", SUR)
        self.assertTrue(out["ok"])
        self.assertNotIn("\ud800", out["name"])
        self.assertNotIn("\ud800", out["message"])
        self.assertNotIn("\ud800", stored["web"]["name"])
        _starlette(out)

    def test_blank_and_whitespace_names_stay_coded_400(self):
        """Sanitizing must not weaken the existing coded validation."""
        for bad in ("", "   ", None):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc.rename_vm_display(UTM_UUID, bad)
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertEqual(
                ctx.exception.detail.get("code"), "vms.name_required",
            )


class RenameRouteEndToEndTests(unittest.TestCase):
    """Through the app: the exact request that used to answer a bare 500."""

    def test_post_rename_surrogate_body_is_200(self):
        from fastapi.testclient import TestClient

        from hub import audit
        from hub.app_factory import create_app
        from hub.auth import require_auth

        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        client = TestClient(app, raise_server_exceptions=False)
        body = '{"action": "rename", "name": "\\ud800"}'
        with (
            patch.object(vms_svc, "_utm_available", return_value=True),
            patch.object(config, "set_override", lambda key, p: dict(p)),
            patch.object(audit, "record"),
        ):
            resp = client.post(
                f"/api/vms/{UTM_UUID}/action",
                content=body.encode("ascii"),
                headers={"content-type": "application/json"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertNotIn("\\ud800", resp.text)


if __name__ == "__main__":
    unittest.main()
