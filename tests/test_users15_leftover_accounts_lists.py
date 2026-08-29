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
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import auth, users_svc  # noqa: E402
from hub.routers import accounts_api  # noqa: E402


class _IterBomb(list):
    def __iter__(self):
        raise RuntimeError("leftover resources iter")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover admin truth")


class ResourceIdsUnitTests(unittest.TestCase):
    def test_leftover_mapping_or_int_is_empty(self):
        self.assertEqual(accounts_api._resource_ids({0: "plex"}), [])
        self.assertEqual(accounts_api._resource_ids(12), [])
        self.assertEqual(accounts_api._resource_ids(None), [])

    def test_honest_list_stays(self):
        self.assertEqual(accounts_api._resource_ids(["plex", "immich"]), ["plex", "immich"])

    def test_iter_bomb_list_subclass_reads_real_storage(self):
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


class PublicViewLeftoverTests(unittest.TestCase):
    def test_leftover_resources_int_is_empty(self):
        view = accounts_api._public_view({
            "username": "kid",
            "role": "member",
            "resources": 12,
        })
        self.assertEqual(view["username"], "kid")
        self.assertEqual(view["resources"], [])

    def test_leftover_resources_mapping_is_empty(self):
        view = accounts_api._public_view({
            "username": "kid",
            "role": "member",
            "resources": {0: "plex"},
        })
        self.assertEqual(view["resources"], [])

    def test_honest_resources_stay(self):
        view = accounts_api._public_view({
            "username": "mom",
            "role": "member",
            "resources": ["plex"],
        })
        self.assertEqual(view["resources"], ["plex"])

    def test_public_view_none_for_non_mapping(self):
        self.assertIsNone(accounts_api._public_view("not-a-row"))
        self.assertIsNone(accounts_api._public_view(None))

    def test_missing_username_is_empty_string_not_none_word(self):
        view = accounts_api._public_view({"role": "member", "resources": []})
        self.assertEqual(view["username"], "")


class UsersOverviewLeftoverTests(unittest.TestCase):
    def test_leftover_non_list_overview_is_empty(self):
        with mock.patch.object(users_svc, "list_users", return_value={0: {"admin": True}}):
            body = users_svc.overview()
        self.assertEqual(body["users"], [])
        self.assertEqual(body["count"], 0)
        self.assertEqual(body["admins"], 0)

    def test_leftover_admin_truth_keeps_the_row(self):
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
