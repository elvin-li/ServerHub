"""Account-panel leftover leftover lists/JSON on GET/PUT /api/auth/accounts.

``_text`` used to run bare ``str()``, so a default-repr leftover as a username
or grant id leaked a heap address into the accounts table JSON.  A mapping or
int as ``resources`` still 500'd the list walk before the union ``_isinst`` +
``_iter_list`` net.  Keep stronger union guards.  No new error codes.
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, BASE.as_posix())

from hub.routers import accounts_api  # noqa: E402

ADDR = re.compile(r" at 0x[0-9a-fA-F]+>")


class Blank:
    """Never overrides __str__/__repr__: str() answers object.__repr__."""


class _IterBomb(list):
    def __iter__(self):
        raise RuntimeError("leftover resources iter")


class ResourceIdsLeftoverTests(unittest.TestCase):
    def test_mapping_or_int_is_empty(self):
        self.assertEqual(accounts_api._resource_ids({0: "plex"}), [])
        self.assertEqual(accounts_api._resource_ids(12), [])
        self.assertEqual(accounts_api._resource_ids(None), [])

    def test_honest_list_stays(self):
        self.assertEqual(
            accounts_api._resource_ids(["plex", "immich"]),
            ["plex", "immich"],
        )

    def test_iter_bomb_list_subclass_reads_real_storage(self):
        self.assertEqual(accounts_api._resource_ids(_IterBomb(["plex"])), ["plex"])

    def test_default_repr_grant_is_dropped_not_address(self):
        ids = accounts_api._resource_ids([Blank(), "plex"])
        self.assertEqual(ids, ["plex"])
        self.assertFalse(any(ADDR.search(i) for i in ids))


class PublicViewLeftoverTests(unittest.TestCase):
    def test_default_repr_username_is_empty_not_address(self):
        view = accounts_api._public_view({
            "username": Blank(),
            "role": "member",
            "resources": [Blank()],
        })
        self.assertEqual(view["username"], "")
        self.assertEqual(view["resources"], [])
        dumped = json.dumps(view, ensure_ascii=False, allow_nan=False)
        self.assertFalse(ADDR.search(dumped))

    def test_leftover_resources_mapping_is_empty(self):
        view = accounts_api._public_view({
            "username": "kid",
            "role": "member",
            "resources": {0: "plex"},
        })
        self.assertEqual(view["username"], "kid")
        self.assertEqual(view["resources"], [])

    def test_non_mapping_row_is_none(self):
        self.assertIsNone(accounts_api._public_view(["kid"]))
        self.assertIsNone(accounts_api._public_view(None))

    def test_missing_username_is_empty_string_not_none_word(self):
        view = accounts_api._public_view({"role": "member", "resources": []})
        self.assertEqual(view["username"], "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
