"""Stays-immune pins: FIFOs squatting the auth token files (seventh sweep).

The sixth sweep pinned FIFO leftovers on ``twofa.json``, ``api-keys.json``,
the audit journal, the config lock and ``services.yaml`` — but never on the
three mode-0600 token files hub/auth.py itself owns.  A plain ``open()`` of
a FIFO parks the caller until a writer appears, which is a *hang*, not a
500, and these paths sit on the sign-in path:

* ``data/.setup-token`` is read by GET /api/auth/setup-token and by every
  POST /api/auth/setup that carries a token (``_persistent_token`` →
  ``read_text_capped``, which opens O_NONBLOCK and refuses non-regular
  files with EINVAL);
* ``data/.session-secret`` is read by ``_secret()`` on every login and
  cookie verification (guarded by its ``stat.S_ISREG`` check);
* ``data/.local-client-token`` is read whenever a direct-loopback request
  presents the menu-bar header.

All three already degrade correctly on this tree — the FIFO is unlinked and
a fresh token minted in its place — so these pins hold the O_NONBLOCK /
S_ISREG guards in place: the request answers (no park), never 500s, and the
path is a regular file again afterwards.
"""
from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, twofa_svc
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir; a fresh client per test."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data = self.root / "data"
        data.mkdir()
        self.data = data
        self.yaml_path = self.root / "services.yaml"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
            (auth, "SECRET_FILE", data / ".session-secret"),
            (auth, "SETUP_TOKEN_FILE", data / ".setup-token"),
            (auth, "LOCAL_TOKEN_FILE", data / ".local-client-token"),
            (twofa_svc, "STORE_FILE", data / "twofa.json"),
            (api_keys, "STORE_FILE", data / "api-keys.json"),
            (audit, "AUDIT_PATH", data / "auth-audit.jsonl"),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        auth._secret_cache = None
        auth._login_attempts.clear()
        self.yaml_path.write_text(
            "settings:\n  auth:\n    enabled: true\n", encoding="utf-8"
        )
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)

    def claim(self) -> None:
        auth.set_password(PASSWORD, "admin")

    def _mkfifo(self, path: Path) -> None:
        if path.exists() or path.is_symlink():
            path.unlink()
        os.mkfifo(path)


class SetupTokenFifoTests(_AppSandbox):
    """A FIFO at data/.setup-token must not park or 500 the setup flow."""

    def test_fifo_does_not_hang_setup_token_disclosure(self):
        self._mkfifo(self.data / ".setup-token")
        with mock.patch.object(auth, "is_direct_loopback", lambda request: True):
            response = self.client.get("/api/auth/setup-token")
        self.assertEqual(response.status_code, 200, response.text[:300])
        token = response.json()["setup_token"]
        self.assertTrue(token)
        # The FIFO was cleared and a real mode-0600 token minted in its place.
        self.assertTrue((self.data / ".setup-token").is_file())

    def test_fifo_does_not_hang_or_500_the_setup_claim(self):
        self._mkfifo(self.data / ".setup-token")
        # Wrong token: the comparison still has to mint/read the real token
        # behind the FIFO — this used to be the parking read.
        rejected = self.client.post(
            "/api/auth/setup",
            json={"username": "admin", "password": "brand-new-pass-1",
                  "setup_token": "not-the-token"},
        )
        self.assertEqual(rejected.status_code, 403, rejected.text[:300])
        self.assertEqual(rejected.json()["detail"]["code"], "auth.bad_setup_token")
        token_file = self.data / ".setup-token"
        self.assertTrue(token_file.is_file())
        # The minted token completes the claim.
        token = token_file.read_text(encoding="utf-8").strip()
        accepted = self.client.post(
            "/api/auth/setup",
            json={"username": "admin", "password": "brand-new-pass-1",
                  "setup_token": token},
        )
        self.assertEqual(accepted.status_code, 200, accepted.text[:300])
        self.assertTrue(accepted.json()["ok"])


class SessionSecretFifoTests(_AppSandbox):
    """A FIFO at data/.session-secret must not park or 500 login/cookies."""

    def test_fifo_does_not_hang_login_and_the_cookie_verifies(self):
        self.claim()
        self._mkfifo(self.data / ".session-secret")
        response = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertTrue(response.json()["ok"])
        # The freshly minted secret is a regular file again and the cookie
        # it signed verifies on a session-cookie route.
        self.assertTrue((self.data / ".session-secret").is_file())
        cookie = {auth.COOKIE_NAME: response.cookies.get(auth.COOKIE_NAME)}
        check = self.client.get("/api/auth/totp", cookies=cookie)
        self.assertEqual(check.status_code, 200, check.text[:300])


class LocalClientTokenFifoTests(_AppSandbox):
    """A FIFO at data/.local-client-token must not park the menu-bar check."""

    def test_fifo_does_not_hang_a_local_token_request(self):
        self.claim()
        self._mkfifo(self.data / ".local-client-token")
        with mock.patch.object(auth, "is_direct_loopback", lambda request: True):
            response = self.client.get(
                "/api/status", headers={auth.LOCAL_TOKEN_HEADER: "junk-token"}
            )
        # The junk header is a plain auth failure — the read behind it must
        # neither park on the FIFO nor 500.
        self.assertEqual(response.status_code, 401, response.text[:300])
        self.assertTrue((self.data / ".local-client-token").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
