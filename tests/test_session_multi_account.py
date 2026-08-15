"""Session-layer regressions that block multi-account support.

Three properties of the current single-admin session format have to change
before a family account can exist.  Each is pinned here as a falsifiable test
against the *real* ``hub.auth`` functions, with config supplied through a patched
``_auth_cfg`` so nothing touches services.yaml or a live account.

  1. Identity is compared against one configured username, so a validly signed
     token for any other account is rejected outright.  A second account cannot
     hold a session at all.

  2. The session "version" is derived from a single ``password_hash``.  Rotating
     the admin password must invalidate the admin's own sessions -- that part is
     correct and is pinned below -- but under one shared version it would also
     invalidate every other account's session, and conversely a family member's
     rotation could not invalidate their own.

  3. The payload is ``username|exp|version`` split with ``split("|", 2)``.  A
     username containing "|" shifts the field boundaries, so the parsed exp and
     version come from attacker-chosen text.  This is the one item that is a
     defect today rather than merely a limitation, because ``create_session`` is
     reachable with whatever username setup stored.

These tests are deliberately written so they keep passing once the format grows
an account id and a per-account version: they assert *behaviour* (who may hold a
session, what a rotation invalidates, that separators cannot be forged), not the
byte layout of the token.
"""
from __future__ import annotations

import hashlib
import time
import unittest
from unittest.mock import patch

from hub import auth


def cfg_for(username: str, password_hash: str = "hash-admin") -> dict:
    return {"enabled": True, "username": username, "password_hash": password_hash}


def cfg_with_family(
    admin_hash: str = "hash-admin",
    family_hash: str = "hash-mom",
    resources: list[str] | None = None,
) -> dict:
    """Admin plus one family account, the shape these tests are about.

    An earlier draft of this file minted sessions for "mom" against a config
    holding only "admin".  Those refusals were *correct* -- an account that does
    not exist must not hold a session -- so the tests were asserting the wrong
    thing rather than exposing the limitation they described.
    """
    return {
        "enabled": True,
        "username": "admin",
        "password_hash": admin_hash,
        "accounts": [
            {
                "username": "mom",
                "password_hash": family_hash,
                "role": auth.ROLE_MEMBER,
                "resources": resources if resources is not None else ["jellyfin"],
            },
        ],
    }


class SessionIdentityTests(unittest.TestCase):
    """A session must be usable by the account it was issued to."""

    def test_admin_session_round_trips(self):
        with patch.object(auth, "_auth_cfg", return_value=cfg_for("admin")):
            token = auth.create_session("admin")
            self.assertTrue(auth.verify_session(token))
            self.assertEqual(auth.session_username(token), "admin")

    def test_a_configured_second_account_can_hold_a_session(self):
        """The blocker for family accounts.

        "mom" is a real configured account here, and the token is correctly
        signed and unexpired.  Before multi-account support this was still
        refused, for one reason only: verify_session compared the name against
        the single ``settings.auth.username`` instead of asking whether an
        account by that name exists.
        """
        family = cfg_with_family()
        with patch.object(auth, "_auth_cfg", return_value=family):
            token = auth.create_session("mom")
            self.assertTrue(
                auth.verify_session(token),
                "a signed, unexpired session for a configured second account "
                "must be accepted",
            )
            self.assertEqual(auth.session_username(token), "mom")

    def test_unknown_account_is_still_rejected(self):
        """Multi-account must not become "any name signs in"."""
        with patch.object(auth, "_auth_cfg", return_value=cfg_for("admin")):
            token = auth.create_session("nobody-here")
            # With only "admin" configured, an unrelated name has no account.
            # This stays true after the change: membership is what is checked,
            # instead of equality with one name.
            self.assertFalse(
                auth.verify_session(token) and auth.session_username(token) == "nobody-here"
                and "nobody-here" not in {"admin"},
                "a name with no account must never yield a usable session",
            )

    def test_tampered_signature_is_rejected(self):
        with patch.object(auth, "_auth_cfg", return_value=cfg_for("admin")):
            token = auth.create_session("admin")
            forged = token[:-4] + ("aaaa" if not token.endswith("aaaa") else "bbbb")
            self.assertFalse(auth.verify_session(forged))

    def test_expired_session_is_rejected(self):
        with patch.object(auth, "_auth_cfg", return_value=cfg_for("admin")):
            with patch.object(auth, "SESSION_TTL", -1):
                token = auth.create_session("admin")
            self.assertFalse(auth.verify_session(token))


class SessionRotationTests(unittest.TestCase):
    """Password rotation must invalidate exactly the right sessions."""

    def test_rotating_a_password_invalidates_that_accounts_sessions(self):
        with patch.object(auth, "_auth_cfg", return_value=cfg_for("admin", "hash-v1")):
            token = auth.create_session("admin")
            self.assertTrue(auth.verify_session(token))

        with patch.object(auth, "_auth_cfg", return_value=cfg_for("admin", "hash-v2")):
            self.assertFalse(
                auth.verify_session(token),
                "a session minted under the old password must not survive a rotation",
            )

    def test_rotation_scope_is_per_account(self):
        """One shared version couples unrelated accounts together.

        Today the version comes from the single ``password_hash``, so changing
        the admin password would also sign every family member out.  Asserting
        the *scope* rather than the mechanism keeps this test meaningful after
        the version becomes per-account.
        """
        with patch.object(
            auth, "_auth_cfg", return_value=cfg_with_family(admin_hash="hash-admin-v1")
        ):
            family_token = auth.create_session("mom")
            admin_token = auth.create_session("admin")

        # Only the admin's credential changed.  The family account keeps the
        # same hash, so its own version stamp is unchanged.
        with patch.object(
            auth, "_auth_cfg", return_value=cfg_with_family(admin_hash="hash-admin-v2")
        ):
            self.assertTrue(
                auth.verify_session(family_token),
                "rotating the admin password must not sign out other accounts",
            )
            self.assertFalse(
                auth.verify_session(admin_token),
                "the rotated account's own sessions must still be invalidated",
            )


class SessionPayloadDelimiterTests(unittest.TestCase):
    """``username|exp|version`` cannot survive a username containing "|"."""

    def test_pipe_in_username_cannot_shift_the_expiry_field(self):
        # A username carrying its own separators plus a far-future expiry. If
        # the payload is split positionally, the parsed exp/version come from
        # this string instead of from the fields create_session wrote.
        forever = int(time.time()) + 10 * 365 * 24 * 3600
        version = hashlib.sha256(b"hash-admin").hexdigest()[:16]
        hostile = f"mom|{forever}|{version}"

        with patch.object(auth, "_auth_cfg", return_value=cfg_for(hostile)):
            # Mint with a TTL already in the past: the only way this verifies is
            # if the expiry was read out of the username text.
            with patch.object(auth, "SESSION_TTL", -1):
                token = auth.create_session(hostile)
            self.assertFalse(
                auth.verify_session(token),
                "an expired session must stay expired even when the username "
                "contains the field separator",
            )

    def test_an_account_whose_name_contains_the_separator_still_works(self):
        """Assert unconditionally -- the earlier ``if verify_session(...)`` guard
        made this vacuous.

        Under a left-to-right split, ``a|b|exp|version`` parses its username as
        "a", which matches no account, so the session is refused and the guarded
        assertion never ran.  Mutation testing caught that: reverting the parser
        to ``split("|", 2)`` left this test green.  Stating both halves outright
        is what makes the parser's behaviour observable.
        """
        with patch.object(auth, "_auth_cfg", return_value=cfg_for("a|b")):
            token = auth.create_session("a|b")
            self.assertTrue(
                auth.verify_session(token),
                "an account whose name contains '|' must still hold a session",
            )
            self.assertEqual(
                auth.session_username(token),
                "a|b",
                "session_username must not stop at the first separator",
            )


class AccountPasswordTests(unittest.TestCase):
    """Login must verify the named account, not only the legacy admin pair."""

    def test_a_family_account_verifies_against_its_own_hash(self):
        family_hash = auth.hash_password("family-password-123")
        admin_hash = auth.hash_password("admin-password-123")
        cfg = cfg_with_family(admin_hash=admin_hash, family_hash=family_hash)
        with patch.object(auth, "_auth_cfg", return_value=cfg):
            self.assertTrue(auth.verify_account_password("mom", "family-password-123"))
            self.assertFalse(auth.verify_account_password("mom", "admin-password-123"))
            self.assertTrue(auth.verify_account_password("admin", "admin-password-123"))
            self.assertFalse(auth.verify_account_password("nobody", "family-password-123"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
