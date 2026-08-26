"""Settings7 leftover sweep: bad-port URLs through the settings gates.

``urlsplit`` parses lazily: the netloc tail is only turned into a number
when ``.port`` is read.  Every URL gate built on ``http_guard._url_parts``
(the ollama settings URL, notify webhook URLs, the photoshub Immich origin)
therefore accepted spellings whose port can never exist —
``http://127.0.0.1:x``, ``:-1``, ``:99999``, ``:0x50`` — because nothing
ever read ``.port`` at validation time.

That let PUT /api/settings persist an ``ollama.url`` the panel can never
dial: every later probe died in ``http.client.InvalidURL`` (misreported as
the daemon being down), and ``ollama_svc.health_checks()`` read
``urlsplit(base_url()).port`` *outside* its try — the ValueError collapsed
every Ollama health row (duplicate-agent warnings included) into one
generic "check failed" row.  Exactly the class catalog6 fixed for
``catalog_remote.validate_source_url`` with a ``parts.port`` probe inside
the validation try; ``_url_parts`` now applies the same rule, so:

* the mutate routes answer the coded 400 (``ollama.bad_url`` /
  ``notify.bad_url``) and services.yaml stays untouched, and
* an already-persisted leftover (hand-edited YAML) is rejected by the
  origin gate at *read* time — ``base_url()`` falls back to the default,
  ``url_was_rejected()`` warns in the UI, and the health port read holds.

A bare trailing colon (``http://127.0.0.1:``) stays accepted: ``.port``
answers None for it and urllib dials the scheme default.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock
from urllib.parse import urlsplit

import yaml
from fastapi.testclient import TestClient

from hub import auth, config, ollama_svc
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"

#: Every lazy-port spelling ``urlsplit(...).port`` raises ValueError on.
BAD_PORT_URLS = (
    "http://127.0.0.1:x",
    "http://127.0.0.1:-1",
    "http://127.0.0.1:99999",
    "http://[::1]:x",
    "http://[::1]:0x50",
)

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir; a fresh authenticated client per test."""

    #: Appended after the auth block, inside the settings mapping (2-space indent).
    settings_extra = ""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data = self.root / "data"
        data.mkdir()
        self.yaml_path = self.root / "services.yaml"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
            (auth, "SECRET_FILE", data / ".session-secret"),
            (auth, "SETUP_TOKEN_FILE", data / ".setup-token"),
            (auth, "LOCAL_TOKEN_FILE", data / ".local-client-token"),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        auth._secret_cache = None
        auth._login_attempts.clear()
        self.yaml_path.write_text(
            "settings:\n"
            "  auth:\n"
            "    enabled: true\n"
            "    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n'
            + self.settings_extra
        )
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)
        response = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        assert response.status_code == 200, response.text

    def stored_settings(self) -> dict:
        return (yaml.safe_load(self.yaml_path.read_text()) or {}).get("settings") or {}


class BadPortOllamaUrlPutTests(_AppSandbox):
    """PUT /api/settings must refuse an undialable ollama.url, coded."""

    def test_bad_port_spellings_are_coded_400_and_never_persist(self):
        for url in BAD_PORT_URLS:
            with self.subTest(url=url):
                response = self.client.put(
                    "/api/settings", json={"ollama": {"url": url}}
                )
                self.assertEqual(response.status_code, 400, response.text[:200])
                self.assertEqual(
                    response.json()["detail"]["code"], "ollama.bad_url"
                )
        # None of the rejected saves landed anything on disk.
        self.assertNotIn("ollama", self.stored_settings())

    def test_valid_and_default_port_spellings_still_land(self):
        for url, expect in (
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
            # ``.port`` is None for a bare trailing colon and urllib dials
            # the scheme default, so the gate must keep accepting it.
            ("http://127.0.0.1:", "http://127.0.0.1:"),
        ):
            with self.subTest(url=url):
                response = self.client.put(
                    "/api/settings", json={"ollama": {"url": url}}
                )
                self.assertEqual(response.status_code, 200, response.text[:200])
                self.assertEqual(self.stored_settings()["ollama"]["url"], expect)

    def test_torn_ipv6_paste_stays_the_coded_400(self):
        response = self.client.put(
            "/api/settings", json={"ollama": {"url": "http://[::1"}}
        )
        self.assertEqual(response.status_code, 400, response.text[:200])
        self.assertEqual(response.json()["detail"]["code"], "ollama.bad_url")


class BadPortChannelUrlTests(_AppSandbox):
    """The same lazy-port spellings through the notify webhook gate."""

    def test_bad_port_webhook_url_is_coded_400(self):
        response = self.client.post("/api/alerts/channels", json={
            "type": "webhook",
            "name": "w",
            "config": {},
            "secrets": {"url": "http://203.0.113.9:99999/hook"},
        })
        self.assertEqual(response.status_code, 400, response.text[:200])
        self.assertEqual(response.json()["detail"]["code"], "notify.bad_url")
        self.assertNotIn("notify", self.stored_settings())


class LeftoverBadPortUrlOnDiskTests(_AppSandbox):
    """A hand-edited leftover bad-port URL must degrade, never poison reads."""

    settings_extra = (
        "  ollama:\n"
        '    url: "http://127.0.0.1:99999"\n'
    )

    def test_base_url_falls_back_and_the_ui_is_told(self):
        self.assertEqual(ollama_svc.base_url(), ollama_svc.DEFAULT_URL)
        self.assertTrue(ollama_svc.url_was_rejected())
        # The exact read health_checks() performs outside its try: it must
        # never raise over the leftover.
        self.assertEqual(urlsplit(ollama_svc.base_url()).port, 11434)

    def test_health_checks_keep_their_rows_over_the_leftover(self):
        """health_checks() used to collapse into one generic failure row:
        ``urlsplit(base_url()).port`` ValueError'd before the API probe."""
        with (
            mock.patch.object(
                ollama_svc, "binary_path", return_value="/opt/homebrew/bin/ollama"
            ),
            mock.patch.object(ollama_svc, "discover_label", return_value=""),
            mock.patch.object(ollama_svc, "_candidate_labels", return_value=[]),
            mock.patch.object(
                ollama_svc, "_api",
                side_effect=ConnectionRefusedError(61, "refused"),
            ),
        ):
            rows = ollama_svc.health_checks()
        api_rows = [r for r in rows if r.get("id") == "ollama_api"]
        self.assertEqual(len(api_rows), 1, rows)
        # The row names the *default* port the probe actually dialed.
        self.assertIn(":11434", api_rows[0]["name"])
        json.dumps(rows, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_settings_and_status_routes_answer_200(self):
        response = self.client.get("/api/settings")
        self.assertEqual(response.status_code, 200, response.text[:200])
        # settings_text passes the raw stored string through so the form
        # shows what the operator wrote.
        self.assertEqual(
            response.json()["ollama"]["url"], "http://127.0.0.1:99999"
        )
        status = self.client.get("/api/ollama/status")
        self.assertLess(status.status_code, 500, status.text[:300])


if __name__ == "__main__":
    unittest.main()
