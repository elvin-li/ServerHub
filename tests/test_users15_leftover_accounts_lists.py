"""Users-page leftover sweep #15: leftover leftover lists/JSON on the panel.

GET /api/auth/accounts used to 500 when a leftover grants field was not a
list (``list(int)`` / mapping walk) and when one row's field raise escaped
the list comprehension.  GET /api/users used to 500 when leftover overview
rows were not mappings or ``admin`` truth-tested a bomb.  Resource writes
walk leftover grants through ``_isinst`` + ``_iter_list`` so a mapping or
``__iter__`` bomb fails closed to no grants instead of a 500.

Keep stronger union guards.  No new error codes.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import api_keys, audit, auth, config, twofa_svc, users_svc  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.routers import accounts_api  # noqa: E402

PASSWORD = "correct-horse-battery"

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


class _IterBomb(list):
    def __iter__(self):
        raise RuntimeError("leftover resources iter")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover admin truth")


class _AppSandbox(unittest.TestCase):
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
        api_keys._last_seen.clear()
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)
        self.yaml_path.write_text(
            "settings:\n"
            "  auth:\n"
            "    enabled: true\n"
            "    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n',
            encoding="utf-8",
        )
        config.reload_cfg()
        auth._login_attempts.clear()
        signed = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        self.assertEqual(signed.status_code, 200)


class ResourceIdsUnitTests(unittest.TestCase):
    def test_leftover_mapping_or_int_is_empty(self):
        self.assertEqual(accounts_api._resource_ids({0: "plex"}), [])
        self.assertEqual(accounts_api._resource_ids(12), [])
        self.assertEqual(accounts_api._resource_ids(None), [])

    def test_honest_list_stays(self):
        self.assertEqual(accounts_api._resource_ids(["plex", "immich"]), ["plex", "immich"])

    def test_iter_bomb_list_subclass_is_empty_not_raise(self):
        self.assertEqual(accounts_api._resource_ids(_IterBomb(["plex"])), ["plex"])


class CleanResourcesUnitTests(unittest.TestCase):
    def test_leftover_mapping_fails_closed(self):
        self.assertEqual(auth._clean_resources({0: "plex"}), [])

    def test_iter_bomb_reads_real_storage(self):
        self.assertEqual(auth._clean_resources(_IterBomb(["plex"])), ["plex"])

    def test_str_bomb_item_costs_itself(self):
        class _StrBomb:
            def __str__(self):
                raise RuntimeError("leftover id")

        self.assertEqual(auth._clean_resources([_StrBomb(), "ok"]), ["ok"])


class AccountsListLeftoverHttpTests(_AppSandbox):
    def test_leftover_resources_int_does_not_500_listing(self):
        healthy = {
            "username": "mom",
            "role": "member",
            "resources": ["plex"],
        }
        poisoned = {
            "username": "kid",
            "role": "member",
            "resources": 12,
        }
        with mock.patch.object(
            auth,
            "accounts",
            return_value={"admin": {"username": "admin", "role": "admin", "resources": []},
                          "kid": poisoned, "mom": healthy},
        ):
            response = self.client.get("/api/auth/accounts")
        self.assertEqual(response.status_code, 200)
        by_name = {r["username"]: r for r in response.json()["accounts"]}
        self.assertEqual(by_name["mom"]["resources"], ["plex"])
        self.assertEqual(by_name["kid"]["resources"], [])

    def test_leftover_resources_mapping_does_not_500_listing(self):
        with mock.patch.object(
            auth,
            "accounts",
            return_value={"kid": {"username": "kid", "role": "member", "resources": {0: "plex"}}},
        ):
            response = self.client.get("/api/auth/accounts")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["accounts"][0]["resources"], [])

    def test_public_view_none_for_non_mapping(self):
        self.assertIsNone(accounts_api._public_view("not-a-row"))
        self.assertIsNone(accounts_api._public_view(None))


class UsersOverviewLeftoverTests(unittest.TestCase):
    def test_leftover_non_list_overview_is_empty(self):
        with mock.patch.object(users_svc, "list_users", return_value={0: {"admin": True}}):
            body = users_svc.overview()
        self.assertEqual(body["users"], [])
        self.assertEqual(body["count"], 0)
        self.assertEqual(body["admins"], 0)

    def test_leftover_admin_truth_costs_the_row_count_only(self):
        rows = [
            {"name": "root", "uid": 0, "admin": True, "groups": []},
            {"name": "bomb", "uid": 501, "admin": _BoolBomb(), "groups": []},
        ]
        with mock.patch.object(users_svc, "list_users", return_value=rows):
            body = users_svc.overview()
        names = [u["name"] for u in body["users"]]
        self.assertIn("root", names)
        self.assertIn("bomb", names)
        self.assertEqual(body["count"], 2)
        self.assertEqual(body["admins"], 1)
