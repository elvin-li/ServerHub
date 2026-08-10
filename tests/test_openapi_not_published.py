"""The API blueprint must not be readable without a session.

FastAPI serves /docs, /redoc and /openapi.json by default, and it serves them
outside the auth dependency.  The individual operations still return 401, but the
schema itself enumerates them -- container exec, file upload and delete, nginx and
cloudflared control, the terminal websocket -- which hands an unauthenticated LAN
client the whole attack surface in one request.

This was fixed once by passing docs_url/redoc_url/openapi_url=None, and then came
back: nothing asserted it, so a later edit to create_app() silently republished the
schema.  The live panel was serving `{"openapi":"3.1.0",...,"paths":{...}}` to any
unauthenticated caller again.  Hence this file.

Note what is *not* being asserted: that the schema cannot be generated.  Six test
modules call ``create_app().openapi()`` to check route contracts, and that has to
keep working.  The requirement is only that no unauthenticated HTTP route publishes
it.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub.app_factory import create_app  # noqa: E402

#: Every path FastAPI would mount for the interactive docs.
DOC_PATHS = ("/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc")


class SchemaNotPublishedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = TestClient(cls.app)

    def test_no_doc_path_returns_the_schema(self):
        for path in DOC_PATHS:
            with self.subTest(path=path):
                response = self.client.get(path)
                # The SPA fallback answers unknown paths with index.html, so a
                # 200 is expected and fine.  What must never appear is the schema:
                # JSON with an "openapi" key, or the Swagger/ReDoc loader HTML.
                body = response.text[:4000].lower()
                self.assertNotIn('"openapi"', body, f"{path} served the schema")
                self.assertNotIn("swagger-ui", body, f"{path} served Swagger UI")
                self.assertNotIn("redoc.standalone", body, f"{path} served ReDoc")

    def test_openapi_json_is_not_json(self):
        # The sharpest single check: the regression served application/json here.
        response = self.client.get("/openapi.json")
        self.assertNotIn(
            "application/json",
            (response.headers.get("content-type") or "").lower(),
            "/openapi.json is publishing the schema again",
        )

    def test_no_doc_route_is_registered_at_all(self):
        # Belt and braces: catches the case where the SPA fallback is what is
        # hiding the schema rather than the schema being unpublished.
        registered = set()
        stack = list(self.app.routes)
        while stack:
            route = stack.pop()
            inner = getattr(route, "original_router", None)
            if inner is not None:
                stack.extend(getattr(inner, "routes", []))
                continue
            path = getattr(route, "path", None)
            if path:
                registered.add(path)
        for path in DOC_PATHS:
            with self.subTest(path=path):
                self.assertNotIn(path, registered)

    def test_the_schema_is_still_generatable_in_process(self):
        # Several test modules read route contracts out of this; disabling the
        # HTTP routes must not have disabled schema generation.
        spec = self.app.openapi()
        self.assertIn("paths", spec)
        self.assertIn("/api/auth/status", spec["paths"])


if __name__ == "__main__":
    unittest.main()
