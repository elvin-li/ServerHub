"""A rejected request body must not 500 while FastAPI renders the 422.

FastAPI's stock validation handler echoes the offending value back in
``detail[].input``, and Starlette renders responses with ``allow_nan=False``.
``json.loads`` accepts the ``Infinity`` / ``NaN`` extensions and turns plain
RFC ``1e999`` into ``inf``, so any of those in a body made ``json.dumps``
raise *inside* the handler.  Every route taking a JSON body answered a bare
``500 Internal Server Error`` instead of 422 -- POST /api/auth/login included,
which is reachable before authentication.
"""
from __future__ import annotations

import json
import unittest

from fastapi.testclient import TestClient

from hub.app_factory import create_app

NON_FINITE_BODIES = [
    '{"name": Infinity}',
    '{"name": -Infinity}',
    '{"name": NaN}',
    # Valid RFC 8259 syntax: no strict parser would reject it, json.loads
    # still yields inf.
    '{"name": 1e999}',
    '{"name": [1e999]}',
    '{"name": {"nested": NaN}}',
]

# ``json.loads`` accepts the ``"\\ud800"`` escape (a lone surrogate) and hands
# the resulting string to pydantic.  Constrained str fields (LoginBody's
# password carries min/max length) reject it with ``string_unicode`` — and the
# stock handler then echoes the surrogate back in ``detail[].input``, whose
# UTF-8 render would 500 without the sanitizing handler.
SURROGATE_BODIES = [
    '{"password": "\\ud800secret!!"}',
    '{"password": ["\\udfff"]}',
    '{"password": {"nested": "\\ud800"}}',
]


class ValidationErrorEncodingTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(create_app())

    def test_non_finite_numbers_are_rejected_with_422(self):
        for body in NON_FINITE_BODIES:
            with self.subTest(body=body):
                r = self.client.post(
                    "/api/auth/login",
                    content=body,
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(r.status_code, 422, r.text)
                # Starlette's own encoder settings: the body has to survive them.
                json.dumps(r.json(), ensure_ascii=False, allow_nan=False)

    def test_lone_surrogates_are_rejected_with_422_and_do_not_echo(self):
        for body in SURROGATE_BODIES:
            with self.subTest(body=body):
                r = self.client.post(
                    "/api/auth/login",
                    content=body,
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(r.status_code, 422, r.text)
                # Starlette's own encoder settings: the body has to survive
                # them, i.e. the echoed ``input`` was sanitized.
                json.dumps(
                    r.json(), ensure_ascii=False, allow_nan=False
                ).encode("utf-8")
                self.assertNotIn("\ud800", r.text)
                self.assertNotIn("\udfff", r.text)

    def test_the_422_body_keeps_its_shape(self):
        r = self.client.post(
            "/api/auth/login",
            content='{"name": Infinity}',
            headers={"Content-Type": "application/json"},
        )
        detail = r.json()["detail"]
        self.assertIsInstance(detail, list)
        self.assertTrue(detail)
        first = detail[0]
        self.assertIn("type", first)
        self.assertIn("loc", first)
        self.assertIn("msg", first)

    def test_ordinary_validation_errors_are_unchanged(self):
        r = self.client.post("/api/auth/login", json={"name": "admin"})
        self.assertEqual(r.status_code, 422)
        detail = r.json()["detail"]
        self.assertEqual(detail[0]["type"], "missing")
        self.assertEqual(detail[0]["loc"], ["body", "password"])


if __name__ == "__main__":
    unittest.main()
