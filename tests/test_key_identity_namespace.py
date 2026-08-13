"""The ``key:<name>`` synthetic identity must never resolve to a panel account.

Member API keys act under the synthetic identity ``key:<name>``
(auth.request_username).  The audit showed that an *account* whose username is
literally ``key:mon`` would collide with the synthetic identity of an API key
named ``mon`` — may_use_resource("key:mon", ...) resolved the account and the
key inherited its resource grants.

Two layers pin the namespaces apart:

* ``create_account`` refuses ``:`` outright (USERNAME_RE has no colon), and
* ``accounts()`` — the single entrance every lookup goes through — drops any
  name containing ``:``, which also covers hand-written services.yaml entries
  (legacy ``settings.auth.username`` and the ``accounts`` list) that never
  went through create_account.
"""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi import Request

from hub import auth


def _cfg(accounts_list=None, legacy_username="admin", legacy_hash="scrypt$x"):
    return {
        "username": legacy_username,
        "password_hash": legacy_hash,
        "accounts": accounts_list or [],
    }


def _member_key_request(name: str) -> Request:
    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/api/status",
        "headers": [],
        "scheme": "http",
        "server": ("localhost", 8086),
        "client": ("203.0.113.9", 12345),
    })
    request.state.serverhub_api_key = {"id": "ak_1", "name": name, "role": "member"}
    return request


class UsernameCharsetTests(unittest.TestCase):
    def test_create_account_refuses_names_with_a_colon(self):
        for name in ("key:mon", "a:b", ":lead", "trail:"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError) as ctx:
                    auth.create_account(name, "long-enough-password")
                self.assertEqual(str(ctx.exception), "bad_username")

    def test_username_re_has_no_colon(self):
        self.assertIsNone(auth.USERNAME_RE.match("key:mon"))
        self.assertIsNotNone(auth.USERNAME_RE.match("mon"))


class SyntheticIdentityIsolationTests(unittest.TestCase):
    """Even a hand-written services.yaml cannot arm the collision."""

    def setUp(self):
        handwritten = [
            {
                "username": "key:mon",
                "password_hash": "scrypt$forged",
                "role": "member",
                "resources": ["jellyfin"],
            },
            {
                "username": "mom",
                "password_hash": "scrypt$real",
                "role": "member",
                "resources": ["navidrome"],
            },
        ]
        patcher = mock.patch.object(auth, "_auth_cfg", lambda: _cfg(handwritten))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_colon_account_never_resolves(self):
        self.assertNotIn("key:mon", auth.accounts())
        self.assertIsNone(auth.account("key:mon"))

    def test_the_synthetic_identity_gets_no_resources(self):
        self.assertFalse(auth.may_use_resource("key:mon", "jellyfin"))
        self.assertEqual(auth.allowed_resources("key:mon"), [])
        # And it certainly is not an administrator.
        self.assertFalse(auth.is_admin("key:mon"))
        self.assertEqual(auth.role_of("key:mon"), auth.ROLE_MEMBER)

    def test_request_username_synthetic_identity_misses_the_account_table(self):
        identity = auth.request_username(_member_key_request("mon"))
        self.assertEqual(identity, "key:mon")
        self.assertIsNone(auth.account(identity))
        self.assertFalse(auth.may_use_resource(identity, "jellyfin"))

    def test_ordinary_accounts_are_untouched_by_the_filter(self):
        self.assertIn("mom", auth.accounts())
        self.assertTrue(auth.may_use_resource("mom", "navidrome"))
        self.assertFalse(auth.may_use_resource("mom", "jellyfin"))


class LegacyAdminPairTests(unittest.TestCase):
    def test_a_legacy_admin_name_with_a_colon_fails_closed(self):
        with mock.patch.object(
            auth, "_auth_cfg", lambda: _cfg([], legacy_username="key:root")
        ):
            self.assertNotIn("key:root", auth.accounts())
            self.assertFalse(auth.is_admin("key:root"))
            self.assertFalse(auth.may_use_resource("key:root", "anything"))

    def test_a_normal_legacy_admin_still_resolves(self):
        with mock.patch.object(auth, "_auth_cfg", lambda: _cfg([])):
            self.assertIn("admin", auth.accounts())
            self.assertTrue(auth.is_admin("admin"))


if __name__ == "__main__":
    unittest.main()
