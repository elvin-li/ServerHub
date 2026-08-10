"""The install endpoint must pass the installer's verdict through unchanged.

Two things are easy to get wrong between `install_native` and the browser, and
both look like "the app store is broken" from the panel:

  * a failed install answered with HTTP 200 and `ok: false` is correct, and the
    route must not turn it into a 500 or drop the message the operator needs;
  * the 409 raised when the same app is already being installed must arrive as
    409, because the SPA shows `detail` for a non-2xx and would otherwise report
    a generic failure.

Installing software is also one of the highest-privilege things this panel does,
so the unauthenticated case is pinned here rather than left to the general
middleware tests.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import native_catalog  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402
from hub.errors import api_error  # noqa: E402

APP_ID = "native-wireguard"
URL = f"/api/catalog/{APP_ID}/install"
BODY = {"confirm": True, "variables": {}}


class InstallRouteTests(unittest.TestCase):
    def setUp(self):
        # Seal the execution boundary for the whole class.  Driving an install
        # over HTTP never mentions `install_native`, so nothing stops a route
        # test from reaching the host's real Homebrew -- POSTing to a valid app id
        # with an unpatched executor runs `brew install` for real.
        sealed = patch.object(native_catalog, "sh", return_value=(0, "", ""))
        sealed.start()
        self.addCleanup(sealed.stop)
        run_sealed = patch.object(
            native_catalog.subprocess, "run", side_effect=AssertionError(
                "a route test reached subprocess.run; patch install_native instead"
            )
        )
        run_sealed.start()
        self.addCleanup(run_sealed.stop)

        self.app = create_app()
        # Only the session check is overridden. Everything the route does after
        # that -- body parsing, catalog dispatch, response shaping -- stays real.
        self.app.dependency_overrides[require_auth] = lambda: None
        self.client = TestClient(self.app)
        self.addCleanup(self.app.dependency_overrides.clear)

    def test_a_failed_install_is_a_200_with_ok_false(self):
        # Not a 500: the operator needs the message, and the SPA only renders the
        # install log for a response it could parse.
        with patch.object(
            native_catalog,
            "install_native",
            return_value={"ok": False, "message": "以下包安装失败：wireguard-go"},
        ):
            response = self.client.post(URL, json=BODY)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertIn("wireguard-go", payload["message"])

    def test_a_successful_install_is_reported_as_such(self):
        with patch.object(
            native_catalog,
            "install_native",
            return_value={"ok": True, "message": "Pouring", "url": "http://x:1"},
        ):
            response = self.client.post(URL, json=BODY)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])

    def test_a_concurrent_install_is_a_409_that_says_why(self):
        # The real exception, not a stand-in: the SPA looks up detail.code to
        # pick a translation, so a raw-string HTTPException would reach the
        # operator untranslated even though the status was right.
        with patch.object(
            native_catalog,
            "install_native",
            side_effect=api_error("catalog.install_busy", app=APP_ID),
        ):
            response = self.client.post(URL, json=BODY)
        self.assertEqual(response.status_code, 409)
        detail = response.json()["detail"]
        self.assertEqual(detail["code"], "catalog.install_busy")
        self.assertEqual(detail["params"], {"app": APP_ID})

    def test_an_unknown_app_is_a_404(self):
        response = self.client.post("/api/catalog/native-does-not-exist/install", json=BODY)
        self.assertEqual(response.status_code, 404)


class InstallRouteAuthTests(unittest.TestCase):
    def test_installing_without_a_session_is_refused(self):
        client = TestClient(create_app())
        with patch.object(native_catalog, "install_native") as installer:
            response = client.post(URL, json=BODY)
        self.assertEqual(response.status_code, 401)
        self.assertFalse(
            installer.called,
            "the installer ran before the session was checked",
        )


if __name__ == "__main__":
    unittest.main()
