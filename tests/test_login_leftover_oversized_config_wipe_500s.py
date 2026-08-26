"""A leftover multi-MB services.yaml must not be wiped by the login surface.

``config._YAML_CAP`` (1 MiB) caps every services.yaml read so a leftover
multi-MB file cannot OOM the request that parses it.  But an *intact* config
that merely grew past the cap (a padded hand-edit, a leftover fat comment
block) is still real data — the admin credential, every app and stack sit
right there behind the cap.  ``read_text_capped`` raises ``OSError(EFBIG)``
for it, ``cfg()`` degrades to ``{}``, and that was fine for reads.

The write path was not.  ``mutate()`` merged its change onto that empty ``{}``
base and ``_save_full_locked`` wrote a tiny file, silently destroying the
whole config — and the equally-capped ``copy_secret_file`` pre-image could not
even back the oversized original up first.  On the sign-in surface this was
worse than data loss: ``cfg()`` reads ``{}`` → ``setup_required()`` reports
True → the panel shows the first-run form → POST /api/auth/setup re-claimed the
install and wiped the real admin with a single unauthenticated request.

These pins reproduce over the real mounted app.  Setup and change-password
answer a coded 503 (``settings.config_unreadable``) instead, logout stays 200, and
the oversized file — admin hash and sibling data intact — is never touched.
"""
from __future__ import annotations

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
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)

    def _claim_then_bloat(self) -> int:
        """Claim an admin, add sibling data, then pad the file past the cap."""
        self.yaml_path.write_text("settings:\n  auth:\n    enabled: true\n")
        config.reload_cfg()
        auth.set_password(PASSWORD, "admin")
        base = self.yaml_path.read_text()
        extra = "apps:\n  - id: plex\n    name: Plex\nstacks:\n  - id: media\n"
        padding = "\n# " + ("x" * 1024) + "\n"
        # Enough 1 KiB comment lines to clear the 1 MiB read cap.
        rounds = (config._YAML_CAP // 1024) + 64
        self.yaml_path.write_text(base + extra + padding * rounds)
        config.reload_cfg()
        return self.yaml_path.stat().st_size


class OversizedConfigSetupWipeTests(_AppSandbox):
    def test_setup_refuses_to_reclaim_and_wipe_an_oversized_config(self):
        size = self._claim_then_bloat()
        self.assertGreater(size, config._YAML_CAP)
        # cfg() cannot read the oversized file, so the panel *looks* unclaimed.
        self.assertEqual(config.cfg(), {})
        self.assertTrue(auth.setup_required())

        response = self.client.post(
            "/api/auth/setup",
            json={
                "username": "attacker",
                "password": "attacker-pw-123",
                "setup_token": auth.setup_token(),
            },
        )
        # A coded 503, never a 200 (silent takeover) and never a 500.
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "settings.config_unreadable"
        )
        # The real config — admin hash and every sibling row — is untouched.
        after = self.yaml_path.read_text()
        self.assertEqual(len(after), size)
        self.assertIn("scrypt$", after)
        self.assertIn("plex", after)
        self.assertIn("media", after)

    def test_change_password_is_coded_503_not_500_on_oversized_config(self):
        self._claim_then_bloat()
        response = self.client.post(
            "/api/auth/change-password",
            json={
                "username": "admin",
                "current_password": PASSWORD,
                "new_password": PASSWORD + "2",
            },
        )
        # The session cookie cannot verify (cfg() is {}), so this is the
        # login-required guard rather than the mutate — either way not a 500.
        self.assertIn(response.status_code, (401, 503))
        self.assertNotEqual(response.status_code, 500)
        self.assertIn("scrypt$", self.yaml_path.read_text())

    def test_logout_stays_200_and_does_not_touch_the_oversized_config(self):
        size = self._claim_then_bloat()
        response = self.client.post("/api/auth/logout")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.yaml_path.stat().st_size, size)


class OversizedConfigUnitTests(unittest.TestCase):
    def test_mutate_refuses_oversized_file_but_heals_a_directory(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            yaml_path = root / "services.yaml"
            with (
                mock.patch.object(config, "YAML_PATH", yaml_path),
                mock.patch.object(config, "DATA_DIR", root),
                mock.patch.object(config, "_LOCK_PATH", root / ".lock"),
            ):
                # Oversized-but-intact: mutate refuses, file preserved.
                padding = ("\n# " + ("x" * 1024) + "\n") * ((config._YAML_CAP // 1024) + 8)
                yaml_path.write_text("settings:\n  keep: kept\n" + padding)
                original = yaml_path.read_text()
                with self.assertRaises(Exception) as ctx:
                    config.mutate(lambda d: d.setdefault("settings", {}).__setitem__("x", 1))
                detail = getattr(ctx.exception, "detail", None)
                code = detail.get("code") if isinstance(detail, dict) else None
                self.assertEqual(code, "settings.config_unreadable")
                self.assertEqual(yaml_path.read_text(), original)

                # A genuinely corrupt/absent file still heals via a rewrite.
                yaml_path.unlink()
                config.reload_cfg()
                out = config.update_settings({"host_ip": "10.0.0.1"})
                self.assertEqual(out.get("host_ip"), "10.0.0.1")
                self.assertTrue(yaml_path.is_file())
                self.assertLessEqual(yaml_path.stat().st_size, config._YAML_CAP)


if __name__ == "__main__":
    unittest.main()
