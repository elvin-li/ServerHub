"""Fifth leftover-500s sweep of the Shares page, over the real mounted app.

The hunted classes (vanished-CLI 503-vs-500, huge-number JSON bodies where
``json.loads`` raises ValueError not JSONDecodeError, lone UTF-8 surrogates
in keys AND values, the CPython 4300-digit int cap including the plist hex
form that arrives *already-int*) were re-reproduced against the routes
Shares.vue drives through ``create_app()`` with
``raise_server_exceptions=False``.

Three live leftovers were found and fixed, all in the confirmed-vanish
family the sharing CLI itself already had:

* **PUT /api/shares/system/{id}** — a systemsetup / launchctl /
  AssetCacheManagerUtil that vanished before the spawn surfaced as the
  generic 500 ``shares.authorization_failed`` *after* the operator already
  typed the administrator password.  ``set_system_service`` now hands
  ``_admin_failure`` the tool each toggle actually spawns
  (``_SERVICE_TOOLS``), and the coded 503 ``shares.system_tool_missing``
  fires only on the failure path, only for the generic ``failed`` shape,
  and only after the fresh on-disk probe confirms the tool is gone.  The
  power router's screensharing enable/disable aliases ride the same fix.

* **POST /api/shares/open-system-settings** — a vanished ``/usr/bin/open``
  answered the 500 ``shares.settings_open_failed``, blaming System Settings
  for a missing tool.  Same confirmed-vanish 503.

* **GET/PUT /api/shares/acl** — with the sharing CLI gone,
  ``list_smb_shares`` returns an empty set, so ``_share_directory`` answered
  the 400 lie ``shares.acl_not_share`` ("not a current SMB share point")
  for a directory nobody can even list — the same family as the
  update/remove 404 lie fixed earlier.  The gate now answers the coded 503
  ``shares.sharing_missing`` only when the share set is empty AND the fresh
  disk probe confirms the CLI is gone; an honestly empty share set with the
  CLI on disk keeps the honest 400.

The battery also pins the funnel that gates the reclassification (sentinel
message with the tool still on disk keeps the raw 500; authorization
outcomes keep their shape) and the neighbours already immune at the HTTP
layer, so they cannot silently regress at the layer the SPA actually calls:

* a >4300-digit int literal in a Shares JSON body is the parse 400
  (``request.json()`` raises ValueError, not JSONDecodeError — FastAPI's
  generic body-parse handler must keep catching it);
* GET /api/shares stays 200 with its rows when ``sharing -l -f json``
  carries lone surrogates in keys AND values next to a >4300-digit literal,
  and when the SharePoints plist carries an over-cap ``<integer>0x…</integer>``
  quota that arrives *already-int* (hex parse is exempt from the cap).
"""
from __future__ import annotations

import json
import unittest
from contextlib import ExitStack, contextmanager
from unittest import mock

from fastapi.testclient import TestClient

from hub import auth, shares_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_HUGE_DIGITS = "9" * 5000

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


@contextmanager
def _admin_browser():
    with ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(auth, "browser_authenticated", return_value=True))
        stack.enter_context(
            mock.patch.object(auth, "request_username", return_value="admin"))
        stack.enter_context(mock.patch.object(auth, "is_admin", return_value=True))
        yield


def _vanished_sh(cmd, timeout=10, **kwargs):
    """Every spawn answers sh()'s FileNotFoundError sentinel."""
    return -1, "", "not found"


_VANISH_ADMIN = {
    "ok": False,
    "error": "failed",
    "message": "sh: /usr/sbin/systemsetup: command not found",
}


class SystemToggleVanishedTool503Tests(unittest.TestCase):
    """PUT /api/shares/system/{id}: confirmed-vanished tool is the coded 503."""

    def _toggle(self, service_id: str, *, message: str, on_disk: bool):
        admin_result = {"ok": False, "error": "failed", "message": message}
        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=_vanished_sh),
            mock.patch.object(shares_svc, "port_open", return_value=False),
            mock.patch.object(shares_svc, "_tool_on_disk", return_value=on_disk),
            mock.patch.object(
                shares_svc, "run_admin_sequence", return_value=admin_result),
        ):
            return _client().put(
                f"/api/shares/system/{service_id}", json={"enabled": True})

    def test_vanished_systemsetup_is_503(self):
        for service_id in ("remote_login", "remote_apple_events"):
            with self.subTest(service_id=service_id):
                response = self._toggle(
                    service_id,
                    message="sh: /usr/sbin/systemsetup: command not found",
                    on_disk=False,
                )
                self.assertEqual(response.status_code, 503)
                self.assertEqual(
                    response.json()["detail"]["code"], "shares.system_tool_missing")

    def test_vanished_launchctl_is_503(self):
        response = self._toggle(
            "screen_sharing",
            message="sh: /bin/launchctl: No such file or directory",
            on_disk=False,
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.system_tool_missing")

    def test_vanished_assetcache_is_503(self):
        response = self._toggle(
            "content_caching",
            message="sh: /usr/bin/AssetCacheManagerUtil: command not found",
            on_disk=False,
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.system_tool_missing")

    def test_sentinel_with_the_tool_on_disk_keeps_the_raw_500(self):
        """The message alone must not reclassify; the disk probe decides."""
        response = self._toggle(
            "remote_login",
            message="sh: /usr/sbin/systemsetup: command not found",
            on_disk=True,
        )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed")

    def test_cancelled_authorization_keeps_its_shape(self):
        """Only the generic ``failed`` shape is eligible for the vanish 503."""
        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=_vanished_sh),
            mock.patch.object(shares_svc, "port_open", return_value=False),
            mock.patch.object(shares_svc, "_tool_on_disk", return_value=False),
            mock.patch.object(
                shares_svc, "run_admin_sequence",
                return_value={
                    "ok": False, "error": "cancelled",
                    "message": "command not found",
                },
            ),
        ):
            response = _client().put(
                "/api/shares/system/remote_login", json={"enabled": True})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_cancelled")

    def test_power_router_screensharing_alias_rides_the_same_503(self):
        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=_vanished_sh),
            mock.patch.object(shares_svc, "port_open", return_value=False),
            mock.patch.object(shares_svc, "_tool_on_disk", return_value=False),
            mock.patch.object(
                shares_svc, "run_admin_sequence",
                return_value={
                    "ok": False, "error": "failed",
                    "message": "sh: /bin/launchctl: command not found",
                },
            ),
        ):
            response = _client().post("/api/system/screensharing/enable")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.system_tool_missing")


class OpenSettingsVanished503Tests(unittest.TestCase):
    """POST /api/shares/open-system-settings: vanished ``open`` is 503."""

    def _post(self, *, on_disk: bool):
        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=_vanished_sh),
            mock.patch.object(shares_svc, "_tool_on_disk", return_value=on_disk),
        ):
            return _client().post("/api/shares/open-system-settings")

    def test_confirmed_vanished_open_is_503(self):
        response = self._post(on_disk=False)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.system_tool_missing")

    def test_open_on_disk_keeps_the_coded_open_failure(self):
        response = self._post(on_disk=True)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.settings_open_failed")


class AclGateVanishedCli503Tests(unittest.TestCase):
    """The ACL share gate must not 400-lie when the sharing CLI is gone."""

    def test_get_acl_with_vanished_sharing_cli_is_503(self):
        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=_vanished_sh),
            mock.patch.object(shares_svc, "_tool_on_disk", return_value=False),
        ):
            response = _client().get("/api/shares/acl", params={"path": "/tmp"})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.sharing_missing")

    def test_put_acl_with_vanished_sharing_cli_is_503(self):
        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=_vanished_sh),
            mock.patch.object(shares_svc, "_tool_on_disk", return_value=False),
        ):
            response = _client().put(
                "/api/shares/acl",
                json={"path": "/tmp", "username": "alice", "level": "read"},
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.sharing_missing")

    def test_honestly_empty_share_set_keeps_the_honest_400(self):
        """No shares configured, CLI on disk: the refusal is not a lie."""
        def empty_sh(cmd, timeout=10, **kwargs):
            if list(cmd[:4]) == [shares_svc.SHARING, "-l", "-f", "json"]:
                return 0, "{}", ""
            return 1, "", "unavailable"

        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=empty_sh),
            mock.patch.object(shares_svc, "_tool_on_disk", return_value=True),
        ):
            response = _client().get("/api/shares/acl", params={"path": "/tmp"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_not_share")

    def test_unshared_path_next_to_real_shares_keeps_the_honest_400(self):
        """A populated share set answers the honest refusal without probing."""
        with (
            _admin_browser(),
            mock.patch.object(
                shares_svc, "list_smb_shares",
                return_value=[{"record_name": "Media", "path": "/Users/a/Public"}],
            ),
            mock.patch.object(shares_svc, "_tool_on_disk") as probe,
        ):
            response = _client().get("/api/shares/acl", params={"path": "/tmp"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_not_share")
        probe.assert_not_called()


class SharesBodyAndOverviewStayImmuneTests(unittest.TestCase):
    """Hunted classes that already answer cleanly, pinned at the HTTP layer."""

    def test_huge_int_literal_body_is_the_parse_400_not_500(self):
        """``request.json()`` raises ValueError (the digit cap), and FastAPI's
        body-parse guard must keep turning it into a 400."""
        body = (
            '{"path": "/tmp/x", "name": "M", "smb_name": "M", '
            '"tm_quota_gb": ' + _HUGE_DIGITS + "}"
        ).encode()
        with _admin_browser():
            response = _client().post(
                "/api/shares/smb",
                content=body,
                headers={"content-type": "application/json"},
            )
        self.assertEqual(response.status_code, 400)
        response.content.decode("utf-8")

    def test_overview_survives_surrogates_and_huge_int_in_sharing_json(self):
        """Surrogates in keys AND values plus a >4300-digit literal cost each
        field only itself; the rows survive into a clean 200 body."""
        payload = (
            '{"Me\\ud800dia": {"path": "/tmp/M\\udcffedia", '
            '"smb_name": "M\\ud800", "smb_shared": 1, '
            '"leftover": ' + _HUGE_DIGITS + '}, '
            '"Good": {"path": "/tmp/Good", "smb_name": "Good", "smb_shared": 1}}'
        )

        def fake_sh(cmd, timeout=10, **kwargs):
            if list(cmd[:4]) == [shares_svc.SHARING, "-l", "-f", "json"]:
                return 0, payload, ""
            return 1, "", "unavailable"

        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=fake_sh),
            mock.patch.object(shares_svc, "port_open", return_value=False),
            mock.patch.object(shares_svc, "_dir_size_mb", return_value=None),
        ):
            response = _client().get("/api/shares")
        self.assertEqual(response.status_code, 200)
        text = response.content.decode("utf-8")
        self.assertNotIn("\ud800", text)
        records = [row.get("record_name") for row in response.json()["smb"]]
        self.assertIn("Good", records)
        # _as_text scrubs via str.encode(..., "replace"), whose substitute is
        # "?": the poisoned row survives, identifiable, surrogate-free.
        self.assertIn("Me?dia", records)

    def test_overview_survives_already_int_hex_quota_in_the_tm_plist(self):
        """``<integer>0x…</integer>`` loads uncapped through int(x, 16); the
        over-cap already-int quota drops only itself, not the share row."""
        plist = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<plist version="1.0"><array><dict>'
            "<key>dsAttrTypeStandard:RecordName</key>"
            "<array><string>Media</string></array>"
            "<key>dsAttrTypeNative:timeMachineBackup</key>"
            "<array><string>1</string></array>"
            "<key>dsAttrTypeNative:backupQuotaSize</key>"
            "<array><integer>0x" + "F" * 4400 + "</integer></array>"
            "</dict></array></plist>"
        )
        shares_json = json.dumps({
            "Media": {"path": "/tmp/Media", "smb_name": "Media", "smb_shared": 1},
        })

        def fake_sh(cmd, timeout=10, **kwargs):
            if list(cmd[:4]) == [shares_svc.SHARING, "-l", "-f", "json"]:
                return 0, shares_json, ""
            if cmd[0] == shares_svc.DSCL:
                return 0, plist, ""
            return 1, "", "unavailable"

        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=fake_sh),
            mock.patch.object(shares_svc, "port_open", return_value=False),
            mock.patch.object(shares_svc, "_dir_size_mb", return_value=None),
            mock.patch.object(shares_svc, "_dns_sd_advertised", return_value=None),
        ):
            response = _client().get("/api/shares")
        self.assertEqual(response.status_code, 200)
        rows = response.json()["smb"]
        self.assertEqual([row["record_name"] for row in rows], ["Media"])
        # The flag survives; only the unrenderable quota is dropped.
        self.assertTrue(rows[0]["time_machine"])
        self.assertIsNone(rows[0]["tm_quota_gb"])


if __name__ == "__main__":
    unittest.main()
