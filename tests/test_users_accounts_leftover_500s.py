"""Users-page leftovers: over-cap ints that wiped 2FA / 500'd /api/users,
and int-keyed session epochs that silently stopped revoking sessions.

Second sweep over the Users page surface (GET /api/users, the panel-accounts
CRUD, and the 2FA state those rows display).  What was still broken:

* **The whole twofa.json store read as empty on one huge number literal.**
  A >4300-digit number is valid JSON, but the default ``int()`` conversion
  raises CPython's digit-cap ValueError — a *plain* ValueError, not
  JSONDecodeError — and ``_load``'s corrupt-document fallback returned ``{}``.
  Every account's 2FA was silently off (login stopped asking for the second
  factor) and the next ``_save`` rewrote the file without the enrollments,
  losing them permanently.  ``_load`` now parses ints through a capped hook
  so the one oversized field degrades and the document survives.

* **An already-int over-cap uid/gid 500'd GET /api/users for every row.**
  ``int(pw_uid)`` succeeds when the value is *already* an int (no string
  conversion happens), so the digit-cap probe never fired and the huge number
  only exploded at Starlette's ``json.dumps``.  Same class in
  ``twofa_svc._as_int`` (GET /api/auth/totp echoed ``confirmed_at``) and
  ``twofa_svc._json_safe`` (one poisoned field cost the entire ``_save``,
  so a just-spent code's ``last_counter`` never landed — replayable).

* **A numeric account name's logout epoch was invisible behind an int key.**
  YAML round-trips ``session_epochs: {2024: 5}`` with an *int* key, and the
  strict string ``.get()`` read epoch 0 for account "2024": pre-logout tokens
  kept verifying (revocation silently lost), ``bump_session_epoch`` wrote a
  second string-keyed copy *below* the real counter, and ``delete_account``
  left the stale row behind.  Keys now normalise through the same ``str()``
  probe as account usernames (bools included — ``true:`` is how YAML spells
  an account literally named "True"), lone-surrogate keys are scrubbed
  before they can become lookup keys, and when both spellings exist the
  larger counter wins.

Audited for the other two sweep classes, nothing to fix: the Users backend
spawns no CLI (``pwd``/``grp`` are libc, accounts/2FA writes are file-based),
so there is no vanished-binary 503 path, and it holds no pids to ``os.kill``
— the only OverflowError surface is ``getgrouplist``/``getgrgid`` on a
leftover gid, whose tolerance is pinned below.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import unittest
from collections import namedtuple
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml

from hub import auth, totp, twofa_svc, users_svc

NOW = 1_700_000_000
#: Never expires within any test run; the pinned tokens must die on their
#: version, not their clock.
FAR_FUTURE = 9_999_999_999

#: What a leftover ``0xF…`` (5000 hex digits) in a plist/YAML loads as, and
#: what a 5000-digit JSON number literal *would* convert to: ``int(x, 16)``
#: and JSON parsing are exempt from CPython's str<->int digit cap, so the
#: value exists fine as an int and only explodes at str()/dump time.
HUGE_INT = int("F" * 5000, 16)
HUGE_DIGITS = "9" * 5000


def _starlette_json(payload) -> bytes:
    """Starlette JSONResponse encoding: allow_nan=False + UTF-8."""
    return json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class TwofaStoreHugeNumberTests(unittest.TestCase):
    """A huge number literal must not read the whole 2FA store as empty."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Path(tmp.name) / "twofa.json"
        patcher = mock.patch.object(twofa_svc, "STORE_FILE", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _write_enrolled(self, *, last_counter: str = "0", extra: str = "") -> str:
        secret = totp.generate_secret()
        self.store.write_text(
            '{"admin": {"enabled": true, "secret": "%s", '
            '"last_counter": %s, "recovery": ["aa"]%s}}'
            % (secret, last_counter, extra)
        )
        return secret

    def test_huge_last_counter_does_not_silently_disable_twofa(self):
        """json.loads of the huge literal is plain ValueError, not
        JSONDecodeError; the corrupt-document fallback read {} and the login
        form silently stopped asking for the second factor."""
        secret = self._write_enrolled(last_counter=HUGE_DIGITS)
        self.assertTrue(twofa_svc.enabled("admin"))
        code = totp.totp_at(secret, NOW)
        self.assertTrue(twofa_svc.verify_totp_code("admin", code, timestamp=NOW))
        stored = json.loads(self.store.read_text())
        json.dumps(stored, allow_nan=False)
        self.assertIsInstance(stored["admin"]["last_counter"], int)

    def test_huge_literal_does_not_wipe_sibling_enrollments_on_save(self):
        """The next _save used to rewrite the store without the rows the
        empty read had dropped — the enrollments were gone for good."""
        self._write_enrolled(last_counter=HUGE_DIGITS)
        twofa_svc.begin_enrollment("kid")
        stored = json.loads(self.store.read_text())
        self.assertIn("admin", stored)
        self.assertTrue(stored["admin"]["enabled"])
        self.assertIn("kid", stored)
        json.dumps(stored, allow_nan=False)

    def test_huge_confirmed_at_is_dropped_not_500(self):
        """GET /api/auth/totp echoes confirmed_at; the huge literal must
        degrade instead of 500ing the status JSON (or wiping the row)."""
        self._write_enrolled(extra=', "confirmed_at": ' + HUGE_DIGITS)
        snap = twofa_svc.status("admin")
        _starlette_json(snap)
        self.assertTrue(snap["enabled"])
        self.assertIsNone(snap["confirmed_at"])
        self.assertEqual(snap["recovery_remaining"], 1)

    def test_truly_corrupt_store_still_reads_empty(self):
        """The corrupt-document fallback stays: garbage is {} — the fix is
        only for documents that *parse*."""
        self.store.write_text('{"admin": not-json')
        self.assertEqual(twofa_svc._load(), {})

    def test_as_int_probes_an_already_int_over_cap_value(self):
        self.assertEqual(twofa_svc._as_int(HUGE_INT), 0)
        self.assertIsNone(twofa_svc._as_int(HUGE_INT, default=None))
        self.assertEqual(twofa_svc._as_int(7), 7)

    def test_save_with_over_cap_field_still_persists_the_rest(self):
        """json.dumps of the huge already-int raised the same digit-cap
        ValueError and _save returned early — the whole write (a fresh
        last_counter, a consumed recovery code) was silently dropped."""
        twofa_svc._save({"admin": {"enabled": True, "secret": "S", "note": HUGE_INT}})
        self.assertTrue(self.store.is_file())
        row = json.loads(self.store.read_text())["admin"]
        self.assertEqual(row["secret"], "S")
        self.assertIsNone(row["note"])
        json.dumps(row, allow_nan=False)


_Pw = namedtuple("Pw", "pw_name pw_passwd pw_uid pw_gid pw_gecos pw_dir pw_shell")


class UsersOverviewHugeIdTests(unittest.TestCase):
    """One poisoned directory record must not 500 GET /api/users."""

    def _overview(self, entries, *, getgrouplist=None):
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=entries),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
            mock.patch.object(users_svc.grp, "getgrgid", side_effect=KeyError),
            mock.patch.object(
                users_svc.os, "getgrouplist",
                side_effect=getgrouplist, return_value=[20],
            ),
        ):
            return users_svc.overview()

    def test_already_int_over_cap_uid_is_skipped_not_500(self):
        """int(pw_uid) succeeds on an *already-int* huge value — no string
        conversion happens — so the row sailed through to Starlette's
        json.dumps and 500'd the page for every healthy sibling."""
        bad = _Pw("eve", "x", HUGE_INT, 20, "Eve", "/Users/eve", "/bin/zsh")
        good = _Pw("dave", "x", 504, 20, "Dave", "/Users/dave", "/bin/zsh")
        out = self._overview([bad, good])
        _starlette_json(out)
        self.assertEqual([u["name"] for u in out["users"]], ["dave"])

    def test_already_int_over_cap_gid_is_skipped_not_500(self):
        bad = _Pw("gil", "x", 505, HUGE_INT, "Gil", "/Users/gil", "/bin/zsh")
        good = _Pw("dave", "x", 504, 20, "Dave", "/Users/dave", "/bin/zsh")
        out = self._overview([bad, good])
        _starlette_json(out)
        self.assertEqual([u["name"] for u in out["users"]], ["dave"])

    def test_getgrouplist_overflow_on_leftover_gid_does_not_500(self):
        """No os.kill exists on this surface; the OverflowError family here
        is getgrouplist on a leftover gid, and it must cost only the groups
        column, never the row or the page."""
        entry = _Pw("carol", "x", 503, 20, "Carol", "/Users/carol", "/bin/zsh")
        out = self._overview([entry], getgrouplist=OverflowError("gid out of range"))
        _starlette_json(out)
        self.assertEqual(out["users"][0]["name"], "carol")
        self.assertEqual(out["users"][0]["groups"], [])

    def test_bool_uid_row_is_filtered_like_any_system_account(self):
        """pw_uid=True is int 1 — a system-range uid, not a crash."""
        entry = _Pw("flag", "x", True, True, "Flag", "/Users/flag", "/bin/zsh")
        out = self._overview([entry])
        _starlette_json(out)
        self.assertEqual(out["users"], [])


class SessionEpochIntKeyTests(unittest.TestCase):
    """YAML int/bool keys in session_epochs must still name their account."""

    def test_int_keyed_epoch_is_read_for_a_numeric_username(self):
        cfg = {
            "username": "admin",
            "password_hash": "hash-admin",
            "session_epochs": {2024: 5},
        }
        with mock.patch.object(auth, "_auth_cfg", return_value=cfg):
            self.assertEqual(auth._session_epoch("2024"), 5)

    def test_int_keyed_epoch_revokes_pre_logout_sessions(self):
        """The strict string .get() read epoch 0 for account "2024", so a
        token captured before its five logouts verified forever — the
        revocation the counter recorded was silently lost."""
        cfg = {
            "username": "admin",
            "password_hash": "hash-admin",
            "accounts": [
                {"username": "2024", "password_hash": "hash-kid", "role": "member"},
            ],
            "session_epochs": {2024: 5},
        }
        with (
            mock.patch.object(auth, "_auth_cfg", return_value=cfg),
            mock.patch.object(auth, "_secret", return_value=b"x" * 32),
        ):
            # A pre-logout token: its version omits the epoch entirely.
            stale_version = hashlib.sha256(b"hash-kid").hexdigest()[:16]
            payload = auth._session_payload("2024", FAR_FUTURE, stale_version)
            sig = hmac.new(b"x" * 32, payload, hashlib.sha256).digest()
            stale = base64.urlsafe_b64encode(payload + b"." + sig).decode().rstrip("=")
            self.assertFalse(auth.verify_session(stale))
            # Freshly minted sessions still verify — the account is not locked out.
            self.assertTrue(auth.verify_session(auth.create_session("2024")))

    def test_bump_lands_past_the_int_keyed_leftover(self):
        """The bump used to write a *lower* string-keyed copy beside the int
        key ({2024: 5, "2024": 1}), un-revoking the recorded logouts and
        persisting both spellings forever."""
        data = {"settings": {"auth": {"session_epochs": {2024: 5}}}}
        with mock.patch.object(auth, "config_mutate", side_effect=lambda fn: fn(data)):
            auth.bump_session_epoch("2024")
        self.assertEqual(data["settings"]["auth"]["session_epochs"], {"2024": 6})
        yaml.safe_dump(data)  # what config.mutate does on save

    def test_delete_account_drops_the_int_keyed_epoch(self):
        """The stale counter must not outlive the account: a recreated
        namesake would inherit logouts that predate it."""
        data = {"settings": {"auth": {
            "accounts": [{"username": "2024", "password_hash": "x", "role": "member"}],
            "session_epochs": {2024: 5},
        }}}
        with (
            mock.patch.object(
                auth, "account",
                return_value={"username": "2024", "role": auth.ROLE_MEMBER},
            ),
            mock.patch.object(auth, "config_mutate", side_effect=lambda fn: fn(data)),
        ):
            auth.delete_account("2024")
        self.assertEqual(data["settings"]["auth"]["accounts"], [])
        self.assertEqual(data["settings"]["auth"]["session_epochs"], {})

    def test_bool_keyed_epoch_matches_its_account(self):
        """YAML spells an account literally named "True" as a bool key —
        the same str() rendering accounts() applies to a bool username."""
        cfg = {"username": "admin", "password_hash": "h", "session_epochs": {True: 3}}
        with mock.patch.object(auth, "_auth_cfg", return_value=cfg):
            self.assertEqual(auth._session_epoch("True"), 3)

    def test_key_collision_keeps_the_larger_counter(self):
        """When both spellings exist, the smaller copy must not quietly
        un-revoke sessions the larger one had already revoked."""
        cfg = {
            "username": "admin",
            "password_hash": "h",
            "session_epochs": {2024: 5, "2024": 1},
        }
        with mock.patch.object(auth, "_auth_cfg", return_value=cfg):
            self.assertEqual(auth._session_epoch("2024"), 5)
        self.assertEqual(auth._clean_epochs({2024: 5, "2024": 1}), {"2024": 5})

    def test_surrogate_epoch_key_is_scrubbed_before_lookup(self):
        """A lone-surrogate key can never equal a real account name; it is
        dropped at the single entrance instead of riding every auth write."""
        cleaned = auth._clean_epochs({"\ud800kid": 2, "ok": 1})
        self.assertEqual(cleaned, {"ok": 1})
        yaml.safe_dump({"session_epochs": cleaned}, allow_unicode=True)
        cfg = {"username": "admin", "password_hash": "h",
               "session_epochs": {"\ud800kid": 2}}
        with mock.patch.object(auth, "_auth_cfg", return_value=cfg):
            self.assertEqual(auth._session_epoch("\ud800kid"), 0)

    def test_over_cap_hex_epoch_key_and_value_semantics_hold(self):
        """The earlier sweep's pins survive the key normalisation: a huge
        key is dropped, a huge value reads as 1 (logged out at least once),
        and the bump lands past the corrupt window."""
        self.assertEqual(auth._clean_epochs({HUGE_INT: 3, "kid": HUGE_INT}), {"kid": 1})
        cfg = {"username": "admin", "password_hash": "h",
               "session_epochs": {"admin": HUGE_INT}}
        with mock.patch.object(auth, "_auth_cfg", return_value=cfg):
            self.assertEqual(auth._session_epoch("admin"), 1)
        data = {"settings": {"auth": {"session_epochs": {"admin": HUGE_INT}}}}
        with mock.patch.object(auth, "config_mutate", side_effect=lambda fn: fn(data)):
            auth.bump_session_epoch("admin")
        self.assertEqual(data["settings"]["auth"]["session_epochs"], {"admin": 2})
        yaml.safe_dump(data)


if __name__ == "__main__":
    unittest.main()
