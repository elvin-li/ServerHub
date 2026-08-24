"""The remaining privileged mutations must leave an audit record.

App installs materialise stacks on the host and uninstalls can delete their
data; the credential store writes to the keychain; a Cloudflare tunnel
exposes this panel to the public internet; a compose save is arbitrary
container config awaiting the next stack run; the file manager deletes and
plants content; and the launcher can stop the panel itself.  None of it
recorded who did it.

Secrets stay out by construction: template variables, the connector token,
the credential password and the compose YAML are never passed to record().
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import audit  # noqa: E402
from hub.routers import catalog as catalog_router  # noqa: E402
from hub.routers import cloudflared_api, files_api, launcher_api, modules_api  # noqa: E402
from hub.routers import nas_storage, settings_api, wireguard_api  # noqa: E402
from hub.routers import storage as storage_router  # noqa: E402
from hub.routers import system_extra, unraid_parity  # noqa: E402


class _AuditSandbox(unittest.TestCase):
    module = None  # set by subclasses

    def setUp(self):
        self.calls: list = []

        def _record(event, **fields):
            self.calls.append((event, fields))

        for patched in (
            mock.patch.object(self.module.audit, "record", _record),
            mock.patch.object(self.module.auth, "request_username", lambda r: "admin"),
            mock.patch.object(self.module.auth, "request_client_id", lambda r: "10.0.0.9"),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def only_call(self):
        self.assertEqual(len(self.calls), 1, self.calls)
        return self.calls[0]

    def assert_operator(self, fields):
        self.assertEqual(fields["username"], "admin")
        self.assertEqual(fields["client"], "10.0.0.9")


class CatalogAuditTests(_AuditSandbox):
    module = catalog_router

    def test_install_records_the_template_but_not_its_variables(self):
        with mock.patch.object(catalog_router.catalog, "install_template",
                               return_value={"ok": True}):
            catalog_router.install(
                "immich",
                catalog_router.InstallBody(variables={"DB_PASSWORD": "hunter2"}),
                request=mock.Mock(),
            )
        event, fields = self.only_call()
        self.assertEqual(event, audit.APP_INSTALLED)
        self.assert_operator(fields)
        self.assertEqual(fields["template"], "immich")
        self.assertNotIn("variables", fields)
        self.assertNotIn("hunter2", str(fields))

    def test_uninstall_records_whether_data_was_removed(self):
        with mock.patch.object(catalog_router.catalog, "uninstall_template",
                               return_value={"ok": True}):
            catalog_router.uninstall(
                "immich",
                catalog_router.UninstallBody(confirm=True, remove_data=True),
                request=mock.Mock(),
            )
        event, fields = self.only_call()
        self.assertEqual(event, audit.APP_UNINSTALLED)
        self.assertIs(fields["remove_data"], True)

    def test_credential_save_records_service_and_account_never_the_password(self):
        body = catalog_router.CredentialSaveBody(
            service_id="docker:immich", username="admin",
            password="super-secret-1", apply_to_service=False,
        )
        with mock.patch.object(catalog_router, "_require_browser_session"), \
             mock.patch.object(catalog_router.service_credentials, "adapter_for",
                               return_value=None), \
             mock.patch.object(catalog_router.service_credentials, "store",
                               return_value={"id": "docker:immich"}):
            catalog_router.save_app_credential(body, request=mock.Mock())
        event, fields = self.only_call()
        self.assertEqual(event, audit.APP_CREDENTIAL_SAVED)
        self.assert_operator(fields)
        self.assertEqual(fields["service"], "docker:immich")
        self.assertEqual(fields["account"], "admin")
        self.assertNotIn("super-secret-1", str(fields))

    def test_managed_action_records_target_and_action(self):
        with mock.patch.object(catalog_router.apps_manage_svc, "action",
                               return_value={"ok": True}):
            catalog_router.apps_managed_action(
                catalog_router.ManagedActionBody(id="docker:immich", action="stop"),
                request=mock.Mock(),
            )
        event, fields = self.only_call()
        self.assertEqual(event, audit.APP_ACTION)
        self.assertEqual(fields["target"], "docker:immich")
        self.assertEqual(fields["action"], "stop")

    def test_autostart_toggle_is_recorded(self):
        with mock.patch.object(catalog_router.autostart_svc, "set_autostart",
                               return_value={"ok": True}):
            catalog_router.apps_autostart_set(
                catalog_router.AutostartBody(id="docker:immich", enabled=False),
                request=mock.Mock(),
            )
        event, fields = self.only_call()
        self.assertEqual(event, audit.APP_AUTOSTART_CHANGED)
        self.assertIs(fields["enabled"], False)


class CloudflaredAuditTests(_AuditSandbox):
    module = cloudflared_api

    def test_route_dns_records_tunnel_and_hostname(self):
        with mock.patch.object(cloudflared_api.cloudflared_svc, "route_dns",
                               return_value={"ok": True}):
            cloudflared_api.cf_route(
                cloudflared_api.RouteBody(tunnel="home", hostname="panel.example.com"),
                request=mock.Mock(),
            )
        event, fields = self.only_call()
        self.assertEqual(event, audit.TUNNEL_CHANGED)
        self.assert_operator(fields)
        self.assertEqual(fields["action"], "route_dns")
        self.assertEqual(fields["hostname"], "panel.example.com")

    def test_start_token_never_records_the_connector_token(self):
        token = "t" * 60
        with mock.patch.object(cloudflared_api.cloudflared_svc, "start_with_token",
                               return_value={"ok": True}):
            cloudflared_api.cf_start_token(
                cloudflared_api.StartTokenBody(token=token, label="home"),
                request=mock.Mock(),
            )
        _, fields = self.only_call()
        self.assertEqual(fields["action"], "start_token")
        self.assertNotIn(token, str(fields))


class ModulesAuditTests(_AuditSandbox):
    module = modules_api

    def test_compose_save_records_size_but_not_content(self):
        content = "services:\n  db:\n    environment:\n      - PASSWORD=hunter2\n"
        with mock.patch.object(modules_api.compose_svc, "save_compose",
                               return_value={"ok": True}):
            modules_api.compose_put(
                "media", modules_api.ComposeSave(content=content),
                request=mock.Mock(),
            )
        event, fields = self.only_call()
        self.assertEqual(event, audit.COMPOSE_CHANGED)
        self.assert_operator(fields)
        self.assertEqual(fields["stack"], "media")
        self.assertEqual(fields["bytes"], len(content))
        self.assertNotIn("hunter2", str(fields))

    def test_brew_action_shares_the_service_action_event(self):
        with mock.patch.object(modules_api.brew_svc, "service_action",
                               return_value={"ok": True}):
            modules_api.brew_action("postgresql",
                                    modules_api.BrewAction(action="stop"),
                                    request=mock.Mock())
        event, fields = self.only_call()
        self.assertEqual(event, audit.SERVICE_ACTION)
        self.assertEqual(fields["target"], "brew:postgresql")

    def test_nginx_reload_is_recorded(self):
        with mock.patch.object(modules_api.nginx_svc, "reload_nginx",
                               return_value={"ok": True}):
            modules_api.nginx_reload(request=mock.Mock())
        event, _ = self.only_call()
        self.assertEqual(event, audit.NGINX_RELOADED)


class FilesAuditTests(_AuditSandbox):
    module = files_api

    def test_delete_records_the_path(self):
        with mock.patch.object(files_api.files_svc, "delete_path",
                               return_value={"ok": True}):
            files_api.files_delete(files_api.PathBody(path="/srv/media/x"),
                                   request=mock.Mock())
        event, fields = self.only_call()
        self.assertEqual(event, audit.FILES_CHANGED)
        self.assert_operator(fields)
        self.assertEqual(fields["action"], "delete")
        self.assertEqual(fields["path"], "/srv/media/x")

    def test_reads_are_not_recorded(self):
        with mock.patch.object(files_api.files_svc, "list_dir",
                               return_value={"entries": []}):
            files_api.files_list(path="/srv")
        self.assertEqual(self.calls, [])


class LauncherAuditTests(_AuditSandbox):
    module = launcher_api

    def test_panel_stop_is_recorded_before_the_panel_goes_away(self):
        with mock.patch.object(launcher_api, "_require_admin_browser",
                               return_value="admin"), \
             mock.patch.object(launcher_api.launcher_svc, "schedule_panel_action",
                               return_value={"ok": True}):
            launcher_api.launcher_panel("stop", request=mock.Mock())
        event, fields = self.only_call()
        self.assertEqual(event, audit.LAUNCHER_CHANGED)
        self.assert_operator(fields)
        self.assertEqual(fields["action"], "stop")


class VmAuditTests(_AuditSandbox):
    module = system_extra

    def test_vm_action_records_target_and_action(self):
        with mock.patch.object(system_extra.vms_svc, "vm_action",
                               return_value={"ok": True}):
            system_extra.vm_action(
                "utm:debian",
                system_extra.VmActionBody(action="stop"),
                request=mock.Mock(),
            )
        event, fields = self.only_call()
        self.assertEqual(event, audit.VM_CHANGED)
        self.assert_operator(fields)
        self.assertEqual(fields["action"], "stop")
        self.assertEqual(fields["target"], "utm:debian")


class StorageAuditTests(_AuditSandbox):
    module = storage_router

    def test_pool_save_records_members_and_policy(self):
        with mock.patch.object(storage_router.storage_pool_svc, "save_pool",
                               return_value={"ok": True}):
            storage_router.storage_pool_save(
                storage_router.PoolSaveBody(
                    mounts=["/Volumes/a", "/Volumes/b"], policy="most-free"
                ),
                request=mock.Mock(),
            )
        event, fields = self.only_call()
        self.assertEqual(event, audit.POOL_CHANGED)
        self.assert_operator(fields)
        self.assertEqual(fields["action"], "save")
        self.assertEqual(fields["mounts"], "/Volumes/a,/Volumes/b")
        self.assertEqual(fields["policy"], "most-free")


class IdentityAuditTests(_AuditSandbox):
    module = unraid_parity

    def test_rename_records_the_new_name(self):
        with mock.patch.object(unraid_parity.identity_svc, "set_identity",
                               return_value={"ok": True}):
            unraid_parity.api_identity_put(
                unraid_parity.IdentityBody(computer_name="atlas"),
                request=mock.Mock(),
            )
        event, fields = self.only_call()
        self.assertEqual(event, audit.IDENTITY_CHANGED)
        self.assert_operator(fields)
        self.assertEqual(fields["computer_name"], "atlas")

    def test_power_pref_travels_under_a_name_redaction_keeps(self):
        with mock.patch.object(unraid_parity.system_settings_svc,
                               "set_power_pref", return_value={"ok": True}):
            unraid_parity.api_settings_power_set(
                unraid_parity.PowerPrefBody(key="displaysleep", value=15),
                request=mock.Mock(),
            )
        event, fields = self.only_call()
        self.assertEqual(event, audit.SETTINGS_POWER_CHANGED)
        self.assert_operator(fields)
        # A field literally named "key" would be dropped by the redactor.
        self.assertNotIn("key", fields)
        self.assertEqual(fields["pref"], "displaysleep")
        self.assertEqual(fields["value"], 15)


class _NasCommonSandbox(unittest.TestCase):
    """Routers built on nas_common resolve the operator through
    require_admin_browser / client_host instead of the auth module."""

    module = None  # set by subclasses

    def setUp(self):
        self.calls: list = []

        def _record(event, **fields):
            self.calls.append((event, fields))

        for patched in (
            mock.patch.object(self.module.audit, "record", _record),
            mock.patch.object(self.module, "require_admin_browser",
                              lambda request: "admin"),
            mock.patch.object(self.module, "client_host",
                              lambda request: "10.0.0.9"),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def only_call(self):
        self.assertEqual(len(self.calls), 1, self.calls)
        return self.calls[0]

    def assert_operator(self, fields):
        self.assertEqual(fields["username"], "admin")
        self.assertEqual(fields["client"], "10.0.0.9")


class SmartAuditTests(_NasCommonSandbox):
    module = nas_storage

    def test_abort_records_the_device(self):
        with mock.patch.object(nas_storage.smart_test_svc, "abort_test",
                               return_value={"ok": True}):
            nas_storage.api_smart_abort(
                nas_storage.SmartAbortBody(device="disk0"), request=mock.Mock()
            )
        event, fields = self.only_call()
        self.assertEqual(event, audit.SMART_TEST_ABORTED)
        self.assert_operator(fields)
        self.assertEqual(fields["device"], "disk0")
        self.assertTrue(fields["ok"])

    def test_schedule_change_records_interval_kind_and_devices(self):
        with mock.patch.object(nas_storage.smart_test_svc, "set_schedule",
                               return_value={"ok": True}):
            nas_storage.api_smart_schedule(
                nas_storage.SmartScheduleBody(
                    interval="weekly", kind="short", devices=["disk0", "disk2"]
                ),
                request=mock.Mock(),
            )
        event, fields = self.only_call()
        self.assertEqual(event, audit.SMART_SCHEDULE_CHANGED)
        self.assert_operator(fields)
        self.assertEqual(fields["interval"], "weekly")
        self.assertEqual(fields["kind"], "short")
        self.assertEqual(fields["devices"], "disk0,disk2")


class WireguardSettingsAuditTests(_NasCommonSandbox):
    module = wireguard_api

    def setUp(self):
        super().setUp()
        patched = mock.patch.object(
            wireguard_api.wireguard_svc, "installation",
            return_value={"installed": True},
        )
        patched.start()
        self.addCleanup(patched.stop)

    def test_settings_put_records_changed_keys_but_never_values(self):
        with mock.patch.object(wireguard_api.wireguard_svc, "save_settings",
                               return_value={"endpoint": "vpn.example.com"}):
            wireguard_api.api_wireguard_settings_put(
                wireguard_api.WgSettingsBody(
                    endpoint="vpn.example.com", lan_cidr="192.168.7.0/24"
                ),
                request=mock.Mock(),
            )
        event, fields = self.only_call()
        self.assertEqual(event, audit.WIREGUARD_SETTINGS_CHANGED)
        self.assert_operator(fields)
        self.assertEqual(fields["fields"], "endpoint,lan_cidr")
        # The values map the network for whoever reads the trail later.
        self.assertNotIn("vpn.example.com", str(fields))
        self.assertNotIn("192.168.7.0/24", str(fields))

    def test_sync_records_the_reload_even_when_it_fails(self):
        with mock.patch.object(wireguard_api.wireguard_svc, "apply_live",
                               return_value={"ok": False}):
            with self.assertRaises(Exception):
                wireguard_api.api_wireguard_sync(request=mock.Mock())
        event, fields = self.only_call()
        self.assertEqual(event, audit.WIREGUARD_INTERFACE)
        self.assert_operator(fields)
        self.assertEqual(fields["action"], "sync")
        self.assertFalse(fields["ok"])


class BackupRunAuditTests(unittest.TestCase):
    def setUp(self):
        self.calls: list = []

        def _record(event, **fields):
            self.calls.append((event, fields))

        for patched in (
            mock.patch.object(settings_api.audit, "record", _record),
            mock.patch.object(settings_api, "request_username",
                              lambda r: "admin"),
            mock.patch.object(settings_api, "request_client_id",
                              lambda r: "10.0.0.9"),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def test_each_backup_kind_is_recorded_with_its_outcome(self):
        for kind, route, svc in (
            ("postgres", settings_api.do_pg_backup, "backup_postgres"),
            ("immich", settings_api.do_immich_backup, "backup_immich"),
            ("configs", settings_api.do_cfg_backup, "backup_configs"),
        ):
            with self.subTest(kind=kind):
                self.calls.clear()
                with mock.patch.object(settings_api.backups, svc,
                                       return_value={"ok": True}):
                    route(request=mock.Mock())
                self.assertEqual(len(self.calls), 1, self.calls)
                event, fields = self.calls[0]
                self.assertEqual(event, audit.BACKUP_RUN)
                self.assertEqual(fields["username"], "admin")
                self.assertEqual(fields["client"], "10.0.0.9")
                self.assertEqual(fields["kind"], kind)
                self.assertTrue(fields["ok"])


if __name__ == "__main__":
    unittest.main()
