"""The SPA catch-all must not 500 on a URL the filesystem cannot represent.

Found by feeding hostile values to every parameterised GET endpoint. Two request
paths made the catch-all raise:

  * a few thousand characters -> OSError "File name too long" from Path.resolve()
  * %00 -> decodes to an embedded null, which Path rejects with ValueError

Both surfaced as 500 Internal Server Error with a traceback in the log. Any scanner,
crawler or stale bookmark hitting the panel produced one, which reads like a broken
server rather than a bad URL -- and buries real errors in the log.

An unrepresentable path is by definition not a static file, so the SPA shell is the
correct answer. The traversal guard must keep working while that is true.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub.app_factory import create_app  # noqa: E402
from hub.paths import STATIC_DIR  # noqa: E402


@unittest.skipUnless(
    STATIC_DIR.is_dir() and (STATIC_DIR / "index.html").exists(),
    "the SPA catch-all only exists when a built frontend is present",
)
class SpaFallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(create_app(), raise_server_exceptions=False)

    def test_an_over_long_path_serves_the_shell(self):
        resp = self.client.get("/" + "a" * 4096)
        self.assertEqual(resp.status_code, 200, "over-long path raised instead")
        self.assertIn(b"<!doctype html", resp.content[:64].lower())

    def test_a_percent_encoded_null_serves_the_shell(self):
        resp = self.client.get("/%00")
        self.assertEqual(resp.status_code, 200, "embedded null raised instead")

    def test_a_null_inside_a_longer_path_serves_the_shell(self):
        resp = self.client.get("/assets%00/../etc/passwd")
        self.assertLess(resp.status_code, 500)

    def test_deeply_nested_path_serves_the_shell(self):
        resp = self.client.get("/" + "/".join(["seg"] * 200))
        self.assertEqual(resp.status_code, 200)

    def test_traversal_still_cannot_escape_the_static_root(self):
        """The hardening must not have loosened the path-traversal guard."""
        for attempt in (
            "/../../etc/passwd",
            "/..%2f..%2fetc%2fpasswd",
            "/assets/../../../../etc/passwd",
        ):
            with self.subTest(attempt=attempt):
                resp = self.client.get(attempt)
                self.assertEqual(resp.status_code, 200)
                self.assertNotIn(b"root:", resp.content, f"{attempt} leaked a system file")

    def test_an_unknown_api_path_is_still_a_404(self):
        """The catch-all must not swallow API routes into the shell."""
        for path in ("/api/nope", "/api/", "/api"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)

    def test_a_normal_spa_route_serves_the_shell(self):
        for path in ("/wireguard", "/settings", "/apps"):
            with self.subTest(path=path):
                resp = self.client.get(path)
                self.assertEqual(resp.status_code, 200)

    def test_no_parameterised_get_endpoint_returns_5xx_for_hostile_input(self):
        """A broad sweep, so the next such bug is caught here rather than in use."""
        hostile = [
            "..", "../../etc/passwd", "%2e%2e%2f", "-1", "0",
            "999999999999999999999", "abc", "; id", "$(id)", "`id`",
            "a" * 2048, "' OR '1'='1", "\u202e", "🙂",
        ]
        # Endpoints whose work is genuinely slow; input handling is covered by the
        # rest and sweeping them would dominate the runtime.
        slow = {
            "/api/storage", "/api/storage/usage/tree", "/api/storage/usage/largest",
            "/api/storage/usage/duplicates", "/api/tools/syslog", "/api/tools/updates",
            "/api/apps/managed", "/api/containers", "/api/diagnostics",
            "/api/tools/hardware", "/api/smart", "/api/nfs/stats",
        }
        spec = create_app().openapi()
        failures = []
        for path, ops in spec["paths"].items():
            if "get" not in ops or path in slow or "ws" in path:
                continue
            params = ops["get"].get("parameters") or []
            query = [p["name"] for p in params if p.get("in") == "query"]
            if not query or "{" in path:
                continue
            for value in hostile:
                url = f"{path}?" + "&".join(f"{name}={value}" for name in query)
                resp = self.client.get(url)
                if resp.status_code >= 500:
                    failures.append(f"{path} value={value!r} -> {resp.status_code}")
        self.assertEqual(
            failures, [], "unhandled exceptions:\n" + "\n".join(failures[:20])
        )


if __name__ == "__main__":
    unittest.main()
