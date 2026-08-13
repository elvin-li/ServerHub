"""Filesystem-ACL share access: parsing, command building, write verification.

The parser samples are real ``ls -lde`` output captured on this machine
(macOS 26.5), including the normalisation quirks that make naive string
comparison wrong: ``read,execute`` comes back as ``list,search`` on a
directory, and freshly added deny entries sort above allow entries.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest import mock

from fastapi import HTTPException

from hub import share_acl_svc
from hub.routers import shares as shares_router

#: Verbatim ls -lde output of the one real share point on this machine.
PUBLIC_FOLDER = (
    "drwxr-xr-x+ 5 a0000  staff  160 Aug  4 13:42 /Users/a0000/Public\n"
    " 0: group:everyone deny delete\n"
)

#: Verbatim output after `chmod +a "user:a0000 allow read,execute,readattr,
#: readextattr,readsecurity,list,search"` then `chmod +a "group:everyone deny
#: delete"` on a scratch directory — macOS folded read/execute into
#: list/search and put the deny entry first.
SCRATCH_TWO_ENTRIES = (
    "drwx------@ 2 a0000  wheel  64 Aug 13 20:32 /tmp/serverhub-acl-test.ETw5\n"
    " 0: group:everyone deny delete\n"
    " 1: user:a0000 allow list,search,readattr,readextattr,readsecurity\n"
)

READWRITE_ENTRY = (
    "drwxr-xr-x+ 3 a0000  staff  96 Aug 13 12:00 /Users/a0000/Shared\n"
    " 0: user:alice allow list,add_file,search,add_subdirectory,delete_child,"
    "readattr,writeattr,readextattr,writeextattr,readsecurity,"
    "file_inherit,directory_inherit\n"
)

INHERITED_ENTRY = (
    "drwxr-xr-x+ 3 a0000  staff  96 Aug 13 12:00 /Users/a0000/Shared/sub\n"
    " 0: user:alice inherited allow list,search,readattr\n"
)


class ParseAclTests(unittest.TestCase):
    def test_parses_the_real_public_folder_listing(self):
        parsed = share_acl_svc.parse_acl_listing(PUBLIC_FOLDER)
        self.assertEqual(parsed["mode"], "drwxr-xr-x+")
        self.assertEqual(parsed["owner"], "a0000")
        self.assertEqual(parsed["group"], "staff")
        self.assertEqual(len(parsed["entries"]), 1)
        entry = parsed["entries"][0]
        self.assertEqual(entry["kind"], "group")
        self.assertEqual(entry["name"], "everyone")
        self.assertEqual(entry["effect"], "deny")
        self.assertEqual(entry["perms"], ["delete"])
        # A deny entry has no read/readwrite classification.
        self.assertIsNone(entry["level"])

    def test_parses_normalised_tokens_and_multiple_entries(self):
        parsed = share_acl_svc.parse_acl_listing(SCRATCH_TWO_ENTRIES)
        self.assertEqual([e["index"] for e in parsed["entries"]], [0, 1])
        allow = parsed["entries"][1]
        self.assertEqual(allow["name"], "a0000")
        # list/search/readattr… carry no write-capable token → read level.
        self.assertEqual(allow["level"], "read")

    def test_classifies_normalised_write_tokens_as_readwrite(self):
        parsed = share_acl_svc.parse_acl_listing(READWRITE_ENTRY)
        self.assertEqual(parsed["entries"][0]["level"], "readwrite")

    def test_marks_inherited_entries(self):
        parsed = share_acl_svc.parse_acl_listing(INHERITED_ENTRY)
        entry = parsed["entries"][0]
        self.assertTrue(entry["inherited"])
        self.assertEqual(entry["effect"], "allow")

    def test_garbage_raises_the_stable_code(self):
        for bad in ("", "not a listing"):
            with self.assertRaises(share_acl_svc.ShareAclError) as raised:
                share_acl_svc.parse_acl_listing(bad)
            self.assertEqual(raised.exception.code, "shares.acl_read_failed")


class CommandBuildingTests(unittest.TestCase):
    ENTRIES = [
        {"index": 0, "kind": "group", "name": "everyone", "effect": "deny",
         "perms": ["delete"], "inherited": False, "level": None},
        {"index": 1, "kind": "user", "name": "alice", "effect": "allow",
         "perms": ["list"], "inherited": False, "level": "read"},
        {"index": 2, "kind": "user", "name": "alice", "effect": "deny",
         "perms": ["delete"], "inherited": False, "level": None},
        {"index": 3, "kind": "user", "name": "alice", "effect": "allow",
         "perms": ["list"], "inherited": True, "level": "read"},
    ]

    def test_removals_run_highest_index_first_and_skip_inherited(self):
        commands = share_acl_svc._removal_then_grant(self.ENTRIES, "alice", "none")
        self.assertEqual(
            commands,
            [
                [share_acl_svc.CHMOD, "-a#", "2", "__PATH__"],
                [share_acl_svc.CHMOD, "-a#", "1", "__PATH__"],
            ],
        )

    def test_grant_is_appended_after_removals(self):
        commands = share_acl_svc._removal_then_grant(self.ENTRIES, "alice", "readwrite")
        self.assertEqual(commands[-1][0], share_acl_svc.CHMOD)
        self.assertEqual(commands[-1][1], "+a")
        self.assertIn("user:alice allow", commands[-1][2])
        self.assertIn("write", commands[-1][2])
        self.assertIn("file_inherit", commands[-1][2])

    def test_read_grant_carries_no_write_token(self):
        commands = share_acl_svc._removal_then_grant([], "bob", "read")
        spec = commands[-1][2]
        self.assertIn("read", spec)
        for token in ("write", "delete", "append"):
            self.assertNotIn(token, spec.replace("readattr", "").replace(
                "readextattr", "").replace("readsecurity", ""))

    def test_other_users_entries_are_untouched(self):
        commands = share_acl_svc._removal_then_grant(self.ENTRIES, "bob", "read")
        removals = [c for c in commands if c[1] == "-a#"]
        self.assertEqual(removals, [])


class LocalUsersTests(unittest.TestCase):
    def test_filters_service_accounts_and_low_uids(self):
        listing = (
            "_spotlight              89\n"
            "root                     0\n"
            "daemon                   1\n"
            "a0000                  502\n"
            "guestshare             503\n"
        )

        def fake_sh(argv, timeout=0):
            if "-list" in argv:
                return 0, listing, ""
            if argv[-1] == "RealName":
                name = argv[-2].rsplit("/", 1)[-1]
                return 0, f"RealName:\n {name.title()} Example\n", ""
            return 1, "", ""

        with mock.patch.object(share_acl_svc, "sh", side_effect=fake_sh):
            users = share_acl_svc.local_users()
        self.assertEqual(
            [(u["username"], u["uid"]) for u in users],
            [("a0000", 502), ("guestshare", 503)],
        )
        self.assertEqual(users[0]["real_name"], "A0000 Example")

    def test_dscl_failure_yields_an_empty_list(self):
        with mock.patch.object(share_acl_svc, "sh", return_value=(1, "", "err")):
            self.assertEqual(share_acl_svc.local_users(), [])


class SetUserAccessTests(unittest.TestCase):
    def _patch_common(self, stack, *, owned=True, after_level="read"):
        after_perms = (
            "list,add_file,search,delete" if after_level == "readwrite"
            else "list,search,readattr"
        )
        reads = [
            # before: alice holds one entry at index 0
            {
                "path": "/share", "mode": "drwx------+", "owner": "x", "group": "y",
                "owned_by_panel": owned,
                "entries": [{
                    "index": 0, "kind": "user", "name": "alice", "effect": "allow",
                    "perms": ["list"], "inherited": False, "level": "read",
                }],
            },
            # after: whatever the test wants verified
            {
                "path": "/share", "mode": "drwx------+", "owner": "x", "group": "y",
                "owned_by_panel": owned,
                "entries": [] if after_level == "none" else [{
                    "index": 0, "kind": "user", "name": "alice", "effect": "allow",
                    "perms": after_perms.split(","), "inherited": False,
                    "level": after_level,
                }],
            },
        ]
        stack.enter_context(mock.patch.object(
            share_acl_svc, "read_acl", side_effect=reads
        ))
        stack.enter_context(mock.patch.object(
            share_acl_svc, "_validated_dir", return_value="/share"
        ))
        stack.enter_context(mock.patch.object(
            share_acl_svc, "_validate_username", side_effect=lambda u: u
        ))

    def test_owned_path_runs_unprivileged_and_verifies(self):
        with ExitStack() as stack:
            self._patch_common(stack, owned=True, after_level="readwrite")
            run = stack.enter_context(mock.patch.object(
                share_acl_svc, "_run_unprivileged", return_value={"ok": True}
            ))
            admin = stack.enter_context(mock.patch.object(
                share_acl_svc.macos_admin, "run_admin_sequence"
            ))
            result = share_acl_svc.set_user_access("/share", "alice", "readwrite")
        self.assertTrue(result["ok"])
        admin.assert_not_called()
        commands = run.call_args[0][0]
        # Removal of the old entry, then the new grant — path substituted in.
        self.assertEqual(commands[0], [share_acl_svc.CHMOD, "-a#", "0", "/share"])
        self.assertEqual(commands[1][3], "/share")

    def test_unowned_path_goes_through_the_admin_password_path(self):
        with ExitStack() as stack:
            self._patch_common(stack, owned=False, after_level="read")
            admin = stack.enter_context(mock.patch.object(
                share_acl_svc.macos_admin, "run_admin_sequence",
                return_value={"ok": True},
            ))
            result = share_acl_svc.set_user_access("/share", "alice", "read")
        self.assertTrue(result["ok"])
        admin.assert_called_once()

    def test_password_required_bubbles_up_for_the_spa_dialog(self):
        with ExitStack() as stack:
            self._patch_common(stack, owned=False)
            stack.enter_context(mock.patch.object(
                share_acl_svc.macos_admin, "run_admin_sequence",
                return_value={"ok": False, "error": "password_required"},
            ))
            result = share_acl_svc.set_user_access("/share", "alice", "read")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "password_required")

    def test_write_that_does_not_stick_reports_verification_failure(self):
        with ExitStack() as stack:
            # asked for readwrite, disk says read → verification must fail
            self._patch_common(stack, owned=True, after_level="read")
            stack.enter_context(mock.patch.object(
                share_acl_svc, "_run_unprivileged", return_value={"ok": True}
            ))
            result = share_acl_svc.set_user_access("/share", "alice", "readwrite")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "verification_failed")

    def test_revoking_verifies_the_entries_are_gone(self):
        with ExitStack() as stack:
            self._patch_common(stack, owned=True, after_level="none")
            stack.enter_context(mock.patch.object(
                share_acl_svc, "_run_unprivileged", return_value={"ok": True}
            ))
            result = share_acl_svc.set_user_access("/share", "alice", "none")
        self.assertTrue(result["ok"])

    def test_bad_level_is_refused_before_touching_anything(self):
        with self.assertRaises(share_acl_svc.ShareAclError) as raised:
            share_acl_svc.set_user_access("/share", "alice", "everything")
        self.assertEqual(raised.exception.code, "shares.acl_bad_level")


class RouterScopeTests(unittest.TestCase):
    """The ACL endpoints only ever touch directories that are shared."""

    def test_a_directory_that_is_not_a_share_point_is_refused(self):
        with (
            mock.patch.object(
                shares_router.shares_svc, "list_smb_shares",
                return_value=[{"path": "/Users/a0000/Public"}],
            ),
            mock.patch.object(
                shares_router.Path, "resolve", autospec=True,
                side_effect=lambda self, strict=False: self,
            ),
        ):
            with self.assertRaises(HTTPException) as raised:
                shares_router._share_directory("/etc")
        self.assertEqual(raised.exception.detail["code"], "shares.acl_not_share")

    def test_the_real_share_point_resolves(self):
        with (
            mock.patch.object(
                shares_router.shares_svc, "list_smb_shares",
                return_value=[{"path": "/Users/a0000/Public"}],
            ),
            mock.patch.object(
                shares_router.Path, "resolve", autospec=True,
                side_effect=lambda self, strict=False: self,
            ),
        ):
            resolved = shares_router._share_directory("/Users/a0000/Public")
        self.assertEqual(resolved, "/Users/a0000/Public")


if __name__ == "__main__":
    unittest.main(verbosity=2)
