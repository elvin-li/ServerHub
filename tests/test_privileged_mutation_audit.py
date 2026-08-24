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


if __name__ == "__main__":
    unittest.main()
