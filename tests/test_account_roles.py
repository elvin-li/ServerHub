"""Behaviour of the account registry and role resolution in ``hub.auth``.

These helpers decide who may act on what once a family account exists, so each
one is exercised directly rather than through a session.  The properties that
matter are the fail-closed ones: an unknown name must not resolve to an admin,
and a member with no resource list must reach nothing rather than everything.

Config is supplied through a patched ``_auth_cfg`` so nothing here reads or
writes services.yaml, and no live account is touched.
"""
from __future__ import annotations

import copy
import hashlib
import unittest
from unittest.mock import patch

from fastapi import HTTPException, Request

from hub import auth, status
from hub.routers import services_api

LEGACY_ONLY = {
    "enabled": True,
    "username": "admin",
    "password_hash": "hash-admin",
}

WITH_FAMILY = {
    "enabled": True,
    "username": "admin",
    "password_hash": "hash-admin",
    "accounts": [
        {
            "username": "mom",
            "password_hash": "hash-mom",
            "role": "member",
            "resources": ["jellyfin", "immich"],
        },
        {
            "username": "kid",
            "password_hash": "hash-kid",
            "role": "member",
            "resources": [],
        },
    ],
}


def with_cfg(cfg: dict):
    return patch.object(auth, "_auth_cfg", return_value=cfg)


class AccountsRegistryTests(unittest.TestCase):
    """``accounts()`` is the single source of truth for who exists."""

    def test_legacy_single_pair_is_presented_as_the_admin_account(self):
        # An installation that never saw a second account must keep working, so
        # the old username/password_hash pair still resolves to a full record.
        with with_cfg(LEGACY_ONLY):
            reg = auth.accounts()
        self.assertEqual(list(reg), ["admin"])
        self.assertEqual(reg["admin"]["role"], auth.ROLE_ADMIN)
        self.assertEqual(reg["admin"]["password_hash"], "hash-admin")

    def test_explicit_accounts_are_added_alongside_the_admin(self):
        with with_cfg(WITH_FAMILY):
            reg = auth.accounts()
        self.assertEqual(sorted(reg), ["admin", "kid", "mom"])
        self.assertEqual(reg["mom"]["role"], auth.ROLE_MEMBER)

    def test_an_explicit_entry_overrides_the_legacy_pair_for_the_same_name(self):
        # This is what makes promoting the admin into the list a safe migration:
        # the two shapes must not produce two conflicting records.
        cfg = {
            "enabled": True,
            "username": "admin",
            "password_hash": "legacy-hash",
            "accounts": [
                {"username": "admin", "password_hash": "new-hash", "role": "admin"},
            ],
        }
        with with_cfg(cfg):
            reg = auth.accounts()
        self.assertEqual(list(reg), ["admin"])
        self.assertEqual(reg["admin"]["password_hash"], "new-hash")

    def test_an_unrecognised_role_falls_back_to_member(self):
        cfg = {
            "enabled": True,
            "username": "admin",
            "password_hash": "hash-admin",
            "accounts": [
                {"username": "guest", "password_hash": "h", "role": "superuser"},
            ],
        }
        with with_cfg(cfg):
            reg = auth.accounts()
        # A typo or a hand-edited yaml must not mint an administrator.
        self.assertEqual(reg["guest"]["role"], auth.ROLE_MEMBER)

    def test_entries_without_a_username_are_ignored(self):
        cfg = {
            "enabled": True,
            "username": "admin",
            "password_hash": "hash-admin",
            "accounts": ["not-a-dict", {}, {"username": "   "}],
        }
        with with_cfg(cfg):
            reg = auth.accounts()
        self.assertEqual(list(reg), ["admin"])

    def test_a_fresh_install_with_no_credential_has_no_accounts(self):
        with with_cfg({"enabled": True}):
            self.assertEqual(auth.accounts(), {})


class AccountLookupTests(unittest.TestCase):
    def test_returns_the_record_for_a_known_name(self):
        with with_cfg(WITH_FAMILY):
            self.assertEqual(auth.account("mom")["username"], "mom")

    def test_returns_none_for_an_unknown_name(self):
        with with_cfg(WITH_FAMILY):
            self.assertIsNone(auth.account("stranger"))

    def test_returns_none_for_empty_input(self):
        with with_cfg(WITH_FAMILY):
            self.assertIsNone(auth.account(""))
            self.assertIsNone(auth.account(None))


class RoleResolutionTests(unittest.TestCase):
    def test_admin_account_resolves_to_admin(self):
        with with_cfg(WITH_FAMILY):
            self.assertEqual(auth.role_of("admin"), auth.ROLE_ADMIN)
            self.assertTrue(auth.is_admin("admin"))

    def test_family_account_resolves_to_member(self):
        with with_cfg(WITH_FAMILY):
            self.assertEqual(auth.role_of("mom"), auth.ROLE_MEMBER)
            self.assertFalse(auth.is_admin("mom"))

    def test_unknown_name_is_never_an_admin(self):
        # The fail-closed property: a lookup miss must not grant privilege.
        with with_cfg(WITH_FAMILY):
            self.assertEqual(auth.role_of("stranger"), auth.ROLE_MEMBER)
            self.assertFalse(auth.is_admin("stranger"))
            self.assertFalse(auth.is_admin(None))
            self.assertFalse(auth.is_admin(""))


class AllowedResourceTests(unittest.TestCase):
    def test_member_resources_are_reported(self):
        with with_cfg(WITH_FAMILY):
            self.assertEqual(auth.allowed_resources("mom"), ["jellyfin", "immich"])

    def test_unknown_account_has_no_resources(self):
        with with_cfg(WITH_FAMILY):
            self.assertEqual(auth.allowed_resources("stranger"), [])
            self.assertEqual(auth.allowed_resources(None), [])

    def test_a_caller_cannot_widen_its_own_permissions_by_mutating(self):
        """Mutating the returned list must not grant a resource.

        The earlier version of this test appended to the list and re-read
        ``allowed_resources``, which could never fail: ``accounts()`` rebuilds
        its records on every call, so the re-read was always clean regardless of
        whether a copy was made.  Asserting on the *permission decision* and on
        the underlying config instead makes the escalation itself the thing
        under test.
        """
        with with_cfg(WITH_FAMILY):
            got = auth.allowed_resources("mom")
            got.append("root-shell")

            self.assertFalse(
                auth.may_use_resource("mom", "root-shell"),
                "appending to the returned list must not grant that resource",
            )

        # The config the registry is built from must be untouched, or the
        # mutation would leak into every later lookup in the process.
        self.assertEqual(
            WITH_FAMILY["accounts"][0]["resources"],
            ["jellyfin", "immich"],
            "the account's stored resource list was mutated in place",
        )


class ResourcePermissionTests(unittest.TestCase):
    """``may_use_resource`` is the check every gated route will call."""

    def test_admin_reaches_every_resource(self):
        with with_cfg(WITH_FAMILY):
            self.assertTrue(auth.may_use_resource("admin", "jellyfin"))
            self.assertTrue(auth.may_use_resource("admin", "anything-at-all"))

    def test_member_reaches_only_listed_resources(self):
        with with_cfg(WITH_FAMILY):
            self.assertTrue(auth.may_use_resource("mom", "jellyfin"))
            self.assertTrue(auth.may_use_resource("mom", "immich"))
            self.assertFalse(auth.may_use_resource("mom", "postgres"))

    def test_member_with_an_empty_list_reaches_nothing(self):
        # Empty must mean "none", never "unrestricted": a half-configured
        # account is the likeliest way this would be got wrong.
        with with_cfg(WITH_FAMILY):
            self.assertFalse(auth.may_use_resource("kid", "jellyfin"))
            self.assertFalse(auth.may_use_resource("kid", "immich"))

    def test_unknown_account_reaches_nothing(self):
        with with_cfg(WITH_FAMILY):
            self.assertFalse(auth.may_use_resource("stranger", "jellyfin"))
            self.assertFalse(auth.may_use_resource(None, "jellyfin"))

    def test_a_missing_resource_id_is_refused_for_members(self):
        with with_cfg(WITH_FAMILY):
            self.assertFalse(auth.may_use_resource("mom", None))
            self.assertFalse(auth.may_use_resource("mom", ""))


class MemberStatusFilteringTests(unittest.TestCase):
    def test_filter_keeps_only_assigned_safe_fields_without_mutating_cache(self):
        snapshot = {
            "version": "3.9.0",
            "ts": "12:00:00",
            "system": {"hostname": "private-host"},
            "links": [{"name": "admin-only"}],
            "engine_up": True,
            "adaptive": {"nginx_sites": ["private"]},
            "groups": [
                {
                    "group": "Media",
                    "services": [
                        {
                            "id": "jellyfin",
                            "name": "Jellyfin",
                            "state": "ok",
                            "url": "http://host:8096",
                            "actions": ["open", "detail", "logs", "stop"],
                            "meta": {"mount": "/private/media"},
                        },
                        {
                            "id": "postgres",
                            "name": "Database",
                            "state": "down",
                            "detail": "private database",
                        },
                    ],
                }
            ],
        }
        original = copy.deepcopy(snapshot)

        filtered = status.filter_status_for_resources(snapshot, ["jellyfin"])

        self.assertEqual(snapshot, original, "filtering must not mutate the admin cache")
        self.assertEqual(filtered["service_total"], 1)
        self.assertEqual(filtered["counts"]["ok"], 1)
        self.assertEqual(filtered["system"], {})
        self.assertEqual(filtered["links"], [])
        self.assertEqual(filtered["adaptive"], {})
        service = filtered["groups"][0]["services"][0]
        self.assertEqual(service["id"], "jellyfin")
        self.assertEqual(service["actions"], ["open", "detail"])
        self.assertNotIn("meta", service)
        self.assertNotIn("postgres", repr(filtered))

    def test_empty_resource_list_exposes_no_services(self):
        filtered = status.filter_status_for_resources(
            {"groups": [{"group": "All", "services": [{"id": "secret", "state": "ok"}]}]},
            [],
        )
        self.assertEqual(filtered["groups"], [])
        self.assertEqual(filtered["service_total"], 0)


class MemberServiceRouteTests(unittest.TestCase):
    @staticmethod
    def _request() -> Request:
        return Request({
            "type": "http",
            "method": "GET",
            "path": "/api/services/jellyfin/detail",
            "headers": [],
            "scheme": "http",
            "server": ("localhost", 8086),
            "client": ("127.0.0.1", 12345),
        })

    def test_member_detail_is_allowlisted_and_field_limited(self):
        detail = {
            "id": "jellyfin",
            "name": "Jellyfin",
            "kind": "container",
            "state": "ok",
            "detail": "running",
            "url": "http://host:8096",
            "group": "Media",
            "port": 8096,
            "ports": ["8096:8096"],
            "actions": ["open", "detail", "logs", "stop"],
            "meta": {"secret": "value"},
            "mounts": [{"source": "/private/media"}],
            "program": "/private/bin/start",
        }
        with (
            patch.object(auth, "request_username", return_value="mom"),
            patch.object(auth, "is_admin", return_value=False),
            patch.object(auth, "may_use_resource", return_value=True),
            patch.object(services_api.services_manage_svc, "service_detail", return_value=detail),
        ):
            result = services_api.services_detail("jellyfin", self._request())

        self.assertEqual(result["id"], "jellyfin")
        self.assertEqual(result["actions"], ["open", "detail"])
        self.assertFalse(result["can_logs"])
        self.assertFalse(result["can_hide"])
        self.assertFalse(result["can_edit"])
        self.assertNotIn("meta", result)
        self.assertNotIn("mounts", result)
        self.assertNotIn("program", result)

    def test_member_cannot_read_unassigned_detail(self):
        with (
            patch.object(auth, "request_username", return_value="mom"),
            patch.object(auth, "is_admin", return_value=False),
            patch.object(auth, "may_use_resource", return_value=False),
            patch.object(services_api.services_manage_svc, "service_detail") as detail,
        ):
            with self.assertRaises(HTTPException) as raised:
                services_api.services_detail("postgres", self._request())
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(raised.exception.detail["code"], "auth.admin_required")
        detail.assert_not_called()


class AccountSessionVersionTests(unittest.TestCase):
    """The stamp that ties a session to one account's current credential."""

    def test_admin_stamp_matches_the_pre_multi_account_formula(self):
        # Backward compatibility: cookies issued before multi-account support
        # must keep verifying, so this value may not change for the admin.
        expected = hashlib.sha256(b"hash-admin").hexdigest()[:16]
        with with_cfg(LEGACY_ONLY):
            self.assertEqual(auth.account_session_version("admin"), expected)

    def test_each_account_has_its_own_stamp(self):
        with with_cfg(WITH_FAMILY):
            admin = auth.account_session_version("admin")
            mom = auth.account_session_version("mom")
        self.assertNotEqual(admin, mom)

    def test_stamp_changes_when_that_accounts_hash_changes(self):
        with with_cfg(WITH_FAMILY):
            before = auth.account_session_version("mom")
        rotated = dict(WITH_FAMILY)
        rotated["accounts"] = [
            {"username": "mom", "password_hash": "hash-mom-v2", "role": "member"},
        ]
        with with_cfg(rotated):
            self.assertNotEqual(auth.account_session_version("mom"), before)

    def test_unknown_account_stamp_does_not_collide_with_a_real_one(self):
        with with_cfg(WITH_FAMILY):
            stranger = auth.account_session_version("stranger")
            self.assertNotEqual(stranger, auth.account_session_version("admin"))
            self.assertNotEqual(stranger, auth.account_session_version("mom"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
