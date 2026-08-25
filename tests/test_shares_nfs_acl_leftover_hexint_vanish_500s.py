"""Leftover 500s / silent-loss classes on the Shares / NFS / share-ACL domain.

Reproduced before the fix, in three families:

* **already-int hex leftovers past CPython's 4300-digit cap** — XML plists
  load ``<integer>0x…</integer>`` with ``int(x, 16)`` (exempt from the
  int(str) parse cap), so the value exists in memory and only ``str()``
  explodes.  ``shares_svc._plist_first``'s bare ``str()`` raised the
  digit-cap ValueError out of the record loop: one poisoned SharePoints
  attribute wiped *every* share's Time Machine state (the live reader
  swallows Exception into ``{}``), and leftover dscl-dump callers got an
  untyped raise.  The same already-int class reached the bare ``str()`` in
  ``shares_svc._validate_name``, ``share_acl_svc._validate_username`` and
  ``nfs_svc._validate_entry`` (path / clients / maproot / mapall), turning
  the coded refusal into a 500.  Fixed with str() probes — NOT
  ``isinstance(str)`` gates: numeric leftover ids keep behaving as their
  string form (pinned).

* **huge JSON literals** — ``json.loads`` of a >4300-digit number raises
  ValueError (the digit cap), not JSONDecodeError, so one poisoned field in
  ``sharing -l -f json`` wiped the whole SMB listing: the page silently lost
  every share, the ACL gate 400-lied "not a share point" and update/remove
  404-lied.  A ``parse_int`` hook loads the huge literal as None; siblings
  survive.

* **vanished CLIs** — with ``/usr/sbin/sharing`` gone, update/remove
  answered the 404 lie ``not_found`` and create the generic 500
  ``shares.operation_failed``; a gone ``/sbin/nfsd`` made every NFS
  mutation the generic 500 ``admin.failed``; a gone ``ls`` / ``chmod`` made
  the ACL endpoints ``shares.acl_read_failed`` /
  ``shares.operation_failed`` 500s.  Each now answers its coded 503
  (``shares.sharing_missing`` / ``nfs.nfsd_missing`` /
  ``shares.acl_tool_missing``) only after a fresh on-disk Path probe on the
  FAILURE path; timeouts and authorization outcomes keep their shape.

* **stays immune** — lone surrogates in ``sharing -l -f json`` keys AND
  values are scrubbed by ``_as_text`` before the payload; pinned so the
  funnel cannot regress.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import nfs_svc, share_acl_svc, shares_svc
from hub.routers import nas_storage
from hub.routers import shares as shares_router

#: Loads as an int past CPython's 4300-digit str<->int cap: hex conversion is
#: uncapped, so the value exists in memory and only str() explodes.
HUGE_INT = int("f" * 4400, 16)
HUGE_DIGITS = "1" * 4400


def _tm_plist(quota_field: str, name_field: str = "<string>Media</string>") -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<plist version="1.0"><array>'
        "<dict>"
        f"<key>dsAttrTypeStandard:RecordName</key><array>{name_field}</array>"
        "<key>dsAttrTypeNative:timeMachineBackup</key><array><string>1</string></array>"
        f"<key>dsAttrTypeNative:backupQuotaSize</key><array>{quota_field}</array>"
        "</dict>"
        "<dict>"
        "<key>dsAttrTypeStandard:RecordName</key><array><string>Docs</string></array>"
        "<key>dsAttrTypeNative:timeMachineBackup</key><array><string>1</string></array>"
        "</dict>"
        "</array></plist>"
    )


_HEX_INT_FIELD = "<integer>0x" + "f" * 4400 + "</integer>"


class TmPlistHexIntLeftoverTests(unittest.TestCase):
    def test_hex_int_quota_keeps_sibling_records(self):
        """One >cap quota used to raise str()'s ValueError out of the loop."""
        records = shares_svc.parse_time_machine_records(_tm_plist(_HEX_INT_FIELD))
        self.assertIn("Docs", records)
        self.assertTrue(records["Docs"]["time_machine"])
        # The poisoned attribute is dropped, not the record carrying it.
        self.assertIn("Media", records)
        self.assertIsNone(records["Media"]["tm_quota_gb"])

    def test_hex_int_record_name_drops_only_that_record(self):
        plist = _tm_plist(
            "<string>5000000000</string>", name_field=_HEX_INT_FIELD,
        )
        records = shares_svc.parse_time_machine_records(plist)
        self.assertEqual(list(records), ["Docs"])

    def test_live_reader_is_not_wiped_by_one_hex_int(self):
        """time_machine_records() used to swallow the raise into {} — every
        share silently lost its Time Machine attributes."""
        with mock.patch.object(
            shares_svc, "sh", return_value=(0, _tm_plist(_HEX_INT_FIELD), ""),
        ):
            records = shares_svc.time_machine_records()
        self.assertIn("Docs", records)

    def test_numeric_record_id_still_renders(self):
        """str() probe, not isinstance(str): a numeric leftover id survives."""
        plist = _tm_plist(
            "<string>5000000000</string>", name_field="<integer>42</integer>",
        )
        records = shares_svc.parse_time_machine_records(plist)
        self.assertIn("42", records)
        self.assertEqual(records["42"]["tm_quota_gb"], 5)


class SharingJsonHugeNumberTests(unittest.TestCase):
    def test_json_shares_keeps_row_with_huge_literal(self):
        """json.loads of a >4300-digit literal is ValueError, not
        JSONDecodeError — it used to wipe the whole listing."""
        output = (
            '{"Media": {"path": "/tmp/media", "smb_name": "Media",'
            ' "smb_shared": 1, "smb_directory_mask": ' + HUGE_DIGITS + "}}"
        )
        rows = shares_svc._json_shares(output)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["record_name"], "Media")
        self.assertTrue(rows[0]["shared"])

    def test_list_smb_shares_does_not_wipe_listing(self):
        poisoned = (
            '{"Media": {"path": "/tmp/media", "smb_name": "Media",'
            ' "smb_shared": 1, "smb_directory_mask": ' + HUGE_DIGITS + "}}"
        )

        def fake_sh(cmd, timeout=10, **kwargs):
            if cmd[0] == shares_svc.SHARING and "-f" in cmd:
                return 0, poisoned, ""
            # Legacy listing and dscl are unavailable: the JSON body must
            # carry the row on its own.
            return 1, "", ""

        with (
            mock.patch.object(shares_svc, "sh", side_effect=fake_sh),
            mock.patch.object(shares_svc, "host_ip", return_value="127.0.0.1"),
        ):
            shares = shares_svc.list_smb_shares(include_sizes=False)
        self.assertEqual([s["record_name"] for s in shares], ["Media"])

    def test_surrogate_keys_and_values_stay_scrubbed(self):
        """Stays-immune pin: lone surrogates in keys AND values are dropped
        before the payload, so Starlette's UTF-8 encode cannot 500."""
        output = json.dumps(
            {"\ud800Media": {"path": "/tmp/\udcffmedia", "smb_name": "M\ud800"}},
            ensure_ascii=True,
        )
        rows = shares_svc._json_shares(output)
        body = json.dumps(rows, ensure_ascii=False)
        body.encode("utf-8")  # must not raise UnicodeEncodeError
        self.assertNotIn("\ud800", rows[0]["record_name"])
        self.assertNotIn("\udcff", rows[0]["path"])


class SharingVanishedCliTests(unittest.TestCase):
    def test_update_missing_cli_is_coded_503_not_404_lie(self):
        """With the CLI gone the listing cannot answer, so not_found lied."""
        with (
            mock.patch.object(shares_svc, "_find_share", return_value=None),
            mock.patch.object(shares_svc, "_sharing_on_disk", return_value=False),
        ):
            result = shares_svc.update_smb_share(
                "Media", smb_name="Media", guest=False,
                readonly=False, encrypted=False,
            )
        self.assertEqual(result, {"ok": False, "error": "sharing_missing"})

    def test_update_not_found_stays_with_cli_on_disk(self):
        with (
            mock.patch.object(shares_svc, "_find_share", return_value=None),
            mock.patch.object(shares_svc, "_sharing_on_disk", return_value=True),
        ):
            result = shares_svc.update_smb_share(
                "Media", smb_name="Media", guest=False,
                readonly=False, encrypted=False,
            )
        self.assertEqual(result, {"ok": False, "error": "not_found"})

    def test_remove_missing_cli_is_coded_503_not_404_lie(self):
        with (
            mock.patch.object(shares_svc, "_find_share", return_value=None),
            mock.patch.object(shares_svc, "_sharing_on_disk", return_value=False),
        ):
            result = shares_svc.remove_smb_share("Media")
        self.assertEqual(result, {"ok": False, "error": "sharing_missing"})

    def test_create_admin_failure_is_classified_by_fresh_probe(self):
        failure = {
            "ok": False, "error": "failed",
            "message": "sh: /usr/sbin/sharing: command not found",
        }
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            with (
                mock.patch.object(shares_svc, "_find_share", return_value=None),
                mock.patch.object(shares_svc, "run_admin_sequence", return_value=failure),
                mock.patch.object(shares_svc, "_sharing_on_disk", return_value=False),
            ):
                result = shares_svc.create_smb_share(
                    path=tmp, name="Media", smb_name="Media",
                    guest=False, readonly=False, encrypted=False,
                )
        self.assertEqual(result, {"ok": False, "error": "sharing_missing"})

    def test_timeouts_and_authorization_keep_their_shape(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            for failure, expected in (
                ({"ok": False, "error": "failed", "message": "timeout"}, "failed"),
                # A cancelled sheet mentioning "not found" is still cancelled.
                ({"ok": False, "error": "cancelled", "message": "not found"}, "cancelled"),
                ({"ok": False, "error": "password_required", "message": ""}, "password_required"),
            ):
                with (
                    mock.patch.object(shares_svc, "_find_share", return_value=None),
                    mock.patch.object(shares_svc, "run_admin_sequence", return_value=failure),
                    mock.patch.object(shares_svc, "_sharing_on_disk", return_value=False),
                ):
                    result = shares_svc.create_smb_share(
                        path=tmp, name="Media", smb_name="Media",
                        guest=False, readonly=False, encrypted=False,
                    )
                self.assertEqual(result["error"], expected)

    def test_probe_never_runs_on_the_success_path(self):
        actual = {
            "record_name": "Media", "smb_name": "Media", "shared": True,
            "guest": False, "readonly": False, "encrypted": False,
            "time_machine": False, "tm_quota_gb": None,
        }
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            with (
                mock.patch.object(
                    shares_svc, "_find_share", side_effect=[None, actual],
                ),
                mock.patch.object(
                    shares_svc, "run_admin_sequence", return_value={"ok": True},
                ),
                mock.patch.object(shares_svc, "_sharing_on_disk") as probe,
            ):
                result = shares_svc.create_smb_share(
                    path=tmp, name="Media", smb_name="Media",
                    guest=False, readonly=False, encrypted=False,
                )
        self.assertTrue(result["ok"])
        probe.assert_not_called()

    def test_router_maps_sharing_missing_to_coded_503(self):
        body = shares_router.SMBUpdate(smb_name="Media")
        with (
            mock.patch.object(shares_router.auth, "browser_authenticated", return_value=True),
            mock.patch.object(shares_router.auth, "request_username", return_value="admin"),
            mock.patch.object(shares_router.auth, "is_admin", return_value=True),
            mock.patch.object(shares_router.auth, "request_client_id", return_value="client"),
            mock.patch.object(shares_router.audit, "record"),
            mock.patch.object(
                shares_router.shares_svc, "update_smb_share",
                return_value={"ok": False, "error": "sharing_missing"},
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                shares_router.update_share("Media", body, mock.Mock())
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail["code"], "shares.sharing_missing")


class NfsdVanishedTests(unittest.TestCase):
    def test_server_action_missing_nfsd_is_coded(self):
        failure = {
            "ok": False, "error": "failed",
            "message": "sh: /sbin/nfsd: command not found",
        }
        with (
            mock.patch.object(nfs_svc, "run_admin_sequence", return_value=failure),
            mock.patch.object(nfs_svc, "_nfsd_on_disk", return_value=False),
        ):
            result = nfs_svc.server_action("restart")
        self.assertEqual(result, {"ok": False, "error": "nfsd_missing"})

    def test_server_action_timeout_keeps_its_shape(self):
        failure = {"ok": False, "error": "failed", "message": "timeout"}
        with (
            mock.patch.object(nfs_svc, "run_admin_sequence", return_value=failure),
            mock.patch.object(nfs_svc, "_nfsd_on_disk", return_value=False),
        ):
            result = nfs_svc.server_action("restart")
        self.assertEqual(result["error"], "failed")

    def test_server_action_with_nfsd_on_disk_keeps_its_shape(self):
        failure = {"ok": False, "error": "failed", "message": "not found"}
        with (
            mock.patch.object(nfs_svc, "run_admin_sequence", return_value=failure),
            mock.patch.object(nfs_svc, "_nfsd_on_disk", return_value=True),
        ):
            result = nfs_svc.server_action("restart")
        self.assertEqual(result["error"], "failed")

    def test_save_exports_missing_nfsd_is_coded(self):
        failure = {"ok": False, "error": "failed", "message": "not found"}
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            with (
                mock.patch.object(nfs_svc, "run_admin_sequence", return_value=failure),
                mock.patch.object(nfs_svc, "_nfsd_on_disk", return_value=False),
            ):
                result = nfs_svc.save_exports(
                    [{"path": tmp, "clients": ["10.0.0.0/24"]}],
                )
        self.assertEqual(result, {"ok": False, "error": "nfsd_missing"})

    def test_server_router_maps_nfsd_missing_to_coded_503(self):
        with (
            mock.patch.object(nas_storage, "require_admin_browser", return_value="admin"),
            mock.patch.object(nas_storage, "client_host", return_value="client"),
            mock.patch.object(nas_storage.audit, "record"),
            mock.patch.object(
                nas_storage.nfs_svc, "server_action",
                return_value={"ok": False, "error": "nfsd_missing"},
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                nas_storage.api_nfs_server(
                    nas_storage.NfsServerActionBody(action="restart"), mock.Mock(),
                )
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail["code"], "nfs.nfsd_missing")

    def test_save_router_maps_nfsd_missing_to_coded_503(self):
        with (
            mock.patch.object(nas_storage, "require_admin_browser", return_value="admin"),
            mock.patch.object(nas_storage, "client_host", return_value="client"),
            mock.patch.object(nas_storage.audit, "record"),
            mock.patch.object(
                nas_storage.nfs_svc, "save_exports",
                return_value={"ok": False, "error": "nfsd_missing"},
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                nas_storage.api_nfs_save(nas_storage.NfsSaveBody(entries=[]), mock.Mock())
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail["code"], "nfs.nfsd_missing")


class AclToolVanishedTests(unittest.TestCase):
    def test_read_acl_missing_ls_is_coded_503(self):
        """rc -1 with sh's "not found" sentinel used to 500 acl_read_failed."""
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            with (
                mock.patch.object(share_acl_svc, "sh", return_value=(-1, "", "not found")),
                mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False),
            ):
                with self.assertRaises(share_acl_svc.ShareAclError) as ctx:
                    share_acl_svc.read_acl(tmp)
        self.assertEqual(ctx.exception.code, "shares.acl_tool_missing")

    def test_read_acl_failure_with_ls_on_disk_keeps_its_code(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            with (
                mock.patch.object(share_acl_svc, "sh", return_value=(1, "", "not found")),
                mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=True),
            ):
                with self.assertRaises(share_acl_svc.ShareAclError) as ctx:
                    share_acl_svc.read_acl(tmp)
        self.assertEqual(ctx.exception.code, "shares.acl_read_failed")

    def test_set_user_access_missing_chmod_is_coded(self):
        users = [{"username": "alice", "uid": 501, "real_name": ""}]
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            acl_state = {
                "path": tmp, "mode": "drwxr-xr-x", "owner": "panel",
                "group": "staff", "entries": [], "owned_by_panel": True,
            }
            with (
                mock.patch.object(share_acl_svc, "local_users", return_value=users),
                mock.patch.object(share_acl_svc, "read_acl", return_value=acl_state),
                mock.patch.object(share_acl_svc, "sh", return_value=(-1, "", "not found")),
                mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False),
            ):
                result = share_acl_svc.set_user_access(tmp, "alice", "read")
        self.assertEqual(result, {"ok": False, "error": "acl_tool_missing"})

    def test_set_user_access_authorization_keeps_its_shape(self):
        users = [{"username": "alice", "uid": 501, "real_name": ""}]
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            acl_state = {
                "path": tmp, "mode": "drwxr-xr-x", "owner": "root",
                "group": "staff", "entries": [], "owned_by_panel": False,
            }
            with (
                mock.patch.object(share_acl_svc, "local_users", return_value=users),
                mock.patch.object(share_acl_svc, "read_acl", return_value=acl_state),
                mock.patch.object(
                    share_acl_svc.macos_admin, "run_admin_sequence",
                    return_value={"ok": False, "error": "cancelled", "message": "not found"},
                ),
                mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False),
            ):
                result = share_acl_svc.set_user_access(tmp, "alice", "read")
        self.assertEqual(result["error"], "cancelled")


class StrProbeRefusalTests(unittest.TestCase):
    def test_share_name_hex_int_is_coded_refusal(self):
        """The bare str() used to raise the digit-cap ValueError past the router."""
        with self.assertRaises(shares_svc.ShareValidationError) as ctx:
            shares_svc._validate_name(HUGE_INT)
        self.assertEqual(ctx.exception.code, "shares.bad_name")

    def test_numeric_share_name_still_accepted(self):
        self.assertEqual(shares_svc._validate_name(42), "42")

    def test_acl_username_hex_int_is_coded_refusal(self):
        with self.assertRaises(share_acl_svc.ShareAclError) as ctx:
            share_acl_svc._validate_username(HUGE_INT)
        self.assertEqual(ctx.exception.code, "shares.acl_bad_user")

    def test_nfs_path_hex_int_is_coded_refusal(self):
        with self.assertRaises(nfs_svc.NfsConfigError) as ctx:
            nfs_svc._validate_entry({"path": HUGE_INT, "clients": ["everyone"]})
        self.assertEqual(ctx.exception.code, "nfs.bad_path")

    def test_nfs_client_hex_int_is_coded_refusal(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            with self.assertRaises(nfs_svc.NfsConfigError) as ctx:
                nfs_svc._validate_entry({"path": tmp, "clients": [HUGE_INT]})
        self.assertEqual(ctx.exception.code, "nfs.bad_client")

    def test_nfs_numeric_client_still_accepted(self):
        """str() probe, not isinstance(str): a numeric leftover id survives."""
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            entry = nfs_svc._validate_entry({"path": tmp, "clients": [10]})
        self.assertEqual(entry["clients"], ["10"])

    def test_nfs_mapping_hex_int_is_coded_refusal(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            with self.assertRaises(nfs_svc.NfsConfigError) as ctx:
                nfs_svc._validate_entry(
                    {"path": tmp, "clients": ["everyone"], "maproot": HUGE_INT},
                )
        self.assertEqual(ctx.exception.code, "nfs.bad_mapping")


if __name__ == "__main__":
    unittest.main()
