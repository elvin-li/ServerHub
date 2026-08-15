"""log_sources must not tail protected paths."""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from hub import files_svc, logs_svc
from hub.paths import BASE


class ProtectedLogSourceTests(unittest.TestCase):
    def test_a_protected_path_is_omitted_from_the_source_list(self):
        secret = BASE / "data" / ".session-secret"
        with patch("hub.logs_svc.cfg", return_value={
            "log_sources": [
                {"id": "secret", "name": "secret", "path": str(secret)},
                {"id": "ok", "name": "ok", "path": str(Path.home() / "Library/Logs/serverhub.err.log")},
            ],
        }):
            ids = {row["id"] for row in logs_svc.log_sources()}
        self.assertNotIn("secret", ids)
        self.assertIn("ok", ids)

    def test_tail_refuses_a_protected_path_even_if_listed(self):
        secret = BASE / "data" / ".session-secret"
        self.assertTrue(files_svc.is_protected(secret))
        with (
            patch.object(
                logs_svc,
                "log_sources",
                return_value=[{
                    "id": "secret",
                    "name": "secret",
                    "path": str(secret),
                    "exists": True,
                    "size": 1,
                }],
            ),
        ):
            with self.assertRaises(HTTPException) as raised:
                logs_svc.tail_log("secret")
        self.assertEqual(raised.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
