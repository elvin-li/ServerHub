"""Machine-readable API errors.

The panel ships a localized SPA (zh-CN / en / ja).  Any user-facing text that
originates in Python cannot be translated by the frontend, so handlers raise
*codes* instead of prose.  ``detail`` is a dict:

    {"code": "files.path_outside_root", "params": {"path": "/etc"},
     "message": "path is outside the allowed roots"}

``code``    stable identifier the SPA maps to an i18n key (``err.<code>``).
``params``  interpolation values for the translated string.
``message`` untranslated English fallback, used by curl/menubar/logs and by the
            SPA when it has no key for the code yet.
"""
from __future__ import annotations

from fastapi import HTTPException

# code -> (http status, English fallback).  ``{name}`` placeholders are filled
# from params.  Keep codes stable: they are part of the public API contract.
CODES: dict[str, tuple[int, str]] = {
    # ── auth ────────────────────────────────────────────────────────────────
    "auth.setup_required": (401, "administrator password is not set yet"),
    "auth.login_required": (401, "login required"),
    "auth.bad_credentials": (401, "incorrect username or password"),
    "auth.rate_limited": (429, "too many attempts, retry in {retry} seconds"),
    "auth.already_setup": (409, "administrator password is already set"),
    "auth.bad_setup_token": (403, "invalid first-run setup token"),
    "auth.setup_token_localhost_only": (403, "the setup token is only visible to localhost clients"),
    "auth.cannot_disable": (400, "authentication cannot be disabled"),
    "auth.password_too_short": (400, "password must be at least {min} characters"),
    "auth.password_reused": (400, "the new password must differ from the current one"),
    "auth.username_required": (400, "username is required"),
    "auth.admin_required": (403, "administrator access is required"),
    "auth.cross_site_denied": (403, "cross-site write requests are refused"),
    "auth.bad_origin": (400, "invalid Origin header"),
    "auth.local_token_required": (400, "localhost clients require a dedicated token"),
    # ── auth: two-factor (TOTP) ──────────────────────────────────────────────
    "auth.totp_required": (401, "a two-factor code is required to finish signing in"),
    "auth.bad_totp": (401, "invalid two-factor code"),
    "auth.totp_pending_invalid": (401, "the two-factor sign-in window expired — sign in again"),
    "auth.totp_already_enabled": (409, "two-factor authentication is already enabled"),
    "auth.totp_not_pending": (400, "no two-factor enrollment is awaiting confirmation"),
    "auth.totp_not_enabled": (400, "two-factor authentication is not enabled for this account"),
    # ── auth: panel accounts (multi-user) ────────────────────────────────────
    "accounts.bad_username": (400, "usernames are 1-64 letters, digits and . _ @ + - starting with a letter or digit"),
    "accounts.exists": (409, "an account with this username already exists"),
    "accounts.not_found": (404, "no such panel account"),
    "accounts.not_member": (400, "only member accounts can be managed here"),
    "accounts.too_many": (400, "too many panel accounts — remove unused accounts first"),
    # ── auth: API keys ───────────────────────────────────────────────────────
    "auth.bad_api_key": (401, "invalid, revoked or expired API key"),
    "apikeys.name_required": (400, "a key name of 1-64 characters is required"),
    "apikeys.bad_role": (400, "the key role must be admin or member"),
    "apikeys.bad_expiry": (400, "the key expiry must be between 1 and 3650 days"),
    "apikeys.too_many": (400, "too many API keys — revoke unused keys first"),
    "apikeys.not_found": (404, "no such API key"),
    # ── native launcher ───────────────────────────────────────────────────────
    "launcher.browser_session_required": (401, "a signed-in browser session is required"),
    "launcher.admin_required": (403, "administrator access is required"),
    "launcher.bad_action": (400, "unsupported panel action: {action}"),
    "launcher.not_installed": (404, "ServerHub.app is not installed in Applications"),
    # ── macOS sharing ────────────────────────────────────────────────────────
    "shares.browser_session_required": (401, "a signed-in browser session is required"),
    "shares.admin_required": (403, "administrator access is required"),
    "shares.bad_name": (400, "share names must be 1-64 characters without slashes"),
    "shares.bad_path": (400, "the shared path must be an existing absolute directory"),
    "shares.protected_path": (403, "this directory is protected and cannot be shared"),
    "shares.exists": (409, "a share with this record name already exists"),
    "shares.not_found": (404, "the requested share was not found"),
    "shares.bad_quota": (400, "the Time Machine quota must be a whole number of gigabytes between 1 and 1000000"),
    "shares.quota_requires_time_machine": (400, "a backup quota only applies when the share is a Time Machine destination"),
    "shares.unknown_service": (400, "unsupported macOS sharing service: {service}"),
    "shares.confirm_required": (400, "removing a share requires confirm=true"),
    "shares.authorization_cancelled": (409, "macOS administrator authorization was cancelled"),
    "shares.authorization_unavailable": (503, "macOS administrator authorization is unavailable"),
    "shares.authorization_failed": (500, "macOS administrator authorization failed"),
    "shares.verification_failed": (409, "macOS did not report the requested sharing state"),
    "shares.operation_failed": (500, "the macOS sharing operation failed"),
    "shares.settings_open_failed": (500, "System Settings could not be opened on this Mac"),
    # ── per-user share access (filesystem ACLs) ─────────────────────────────
    "shares.acl_not_share": (400, "this directory is not a current SMB share point"),
    "shares.acl_read_failed": (500, "the directory's access control list could not be read"),
    "shares.acl_bad_user": (400, "unknown local macOS user"),
    "shares.acl_bad_level": (400, "the access level must be none, read or readwrite"),
    # ── terminal ─────────────────────────────────────────────────────────────
    "terminal.timeout": (504, "command timed out after {seconds} seconds"),
    "terminal.empty_command": (400, "command is empty"),
    "terminal.command_too_long": (400, "command exceeds {max} characters"),
    "terminal.host_disabled": (403, "the host terminal is disabled"),
    "terminal.no_container": (400, "no container selected"),
    "terminal.bad_target": (400, "unknown terminal target: {target}"),
    # ── VM console ──────────────────────────────────────────────────────────
    "vm_console.browser_session_required": (401, "a browser session is required for VM consoles"),
    "vm_console.unavailable": (404, "a console is not available for this VM"),
    "vm_console.bad_configuration": (503, "the configured VM console endpoint is invalid"),
    "vm_console.invalid_ticket": (401, "the VM console ticket is invalid or has already been used"),
    "vm_console.ticket_expired": (401, "the VM console ticket has expired"),
    "vm_console.too_many_sessions": (429, "too many VM console sessions"),
    "vm_console.connect_failed": (502, "the configured VM console could not be reached"),
    # ── files ───────────────────────────────────────────────────────────────
    "files.no_roots": (400, "no browsable root directory is configured"),
    "files.unknown_root": (400, "unknown root: {root_id}"),
    "files.path_outside_root": (403, "path is outside the allowed roots"),
    "files.path_protected": (403, "this path is protected and cannot be browsed"),
    "files.not_found": (404, "not found: {path}"),
    "files.not_a_dir": (400, "not a directory"),
    "files.parent_not_a_dir": (400, "parent path is not a directory"),
    "files.permission_denied": (403, "permission denied: {path}"),
    "files.bad_name": (400, "invalid name"),
    "files.exists": (400, "already exists"),
    "files.dest_exists": (400, "destination already exists"),
    "files.cannot_delete_root": (400, "cannot delete a root directory"),
    "files.file_only": (400, "only files can be downloaded"),
    "files.dest_not_a_dir": (400, "destination is not a directory"),
    "files.upload_too_large": (400, "exceeds the {max_mb}MB upload limit"),
    "files.upload_would_overwrite": (409, "a file named {name} already exists"),
    "files.bad_filename": (400, "invalid file name"),
    # ── service uninstall ───────────────────────────────────────────────────
    "services.uninstall_unknown": (404, "no launch agent named {id}"),
    "services.uninstall_not_supported": (400, "{id} is not an uninstallable launch agent"),
    "services.uninstall_protected": (403, "{id} runs this panel and cannot be uninstalled here"),
    "services.uninstall_failed": (500, "could not uninstall {id}: {error}"),
    "services.uninstall_browser_session_required": (
        401, "uninstalling {id} requires a browser session",
    ),
    # ── disk management (diskutil) ──────────────────────────────────────────
    "disk.system_protected": (403, "system disks and system volumes cannot be managed"),
    "disk.name_required": (400, "a new name of 1-64 characters is required"),
    "disk.confirm_required": (400, "destructive operations require confirm=true"),
    "disk.confirm_name_mismatch": (
        400,
        "confirm_name must equal the volume name {name} or the device id {id}",
    ),
    "disk.unsupported_fs": (400, "unsupported filesystem {fs}; choose one of {choices}"),
    "disk.whole_disk_only": (400, "eraseDisk only applies to a whole disk (diskN)"),
    "disk.unknown_action": (400, "unknown action: {action}"),
    "disk.invalid_device": (400, "invalid device id: {device}"),
    # ── optional FileBrowser process ────────────────────────────────────────
    "files.fb_not_installed": (404, "FileBrowser is not installed (~/Services/filebrowser)"),
    "files.fb_start_failed": (500, "could not start FileBrowser"),
    # ── storage pool (JBOD union planner) ───────────────────────────────────
    "storage_pool.bad_policy": (400, "unknown placement policy: {policy}"),
    "storage_pool.no_members": (400, "select at least one volume for the pool"),
    "storage_pool.not_poolable": (400, "{mount} cannot join a pool (system or unmounted)"),
    "files.fb_no_plist": (404, "local.filebrowser.plist not found"),
    "files.fb_bad_plist": (500, "local.filebrowser.plist is not a valid LaunchAgent"),
    # ── macOS administrator authorization ───────────────────────────────────
    # Shared by every endpoint that runs a privileged command through
    # hub/macos_admin.py.  One set of codes rather than a per-feature copy: the
    # outcomes are identical whatever the caller was trying to do.  The
    # password_* pair drives the SPA's in-browser password dialog — the panel is
    # routinely managed from phones and other machines, where a native macOS
    # authorization sheet on the server's own display is unreachable.
    "admin.browser_session_required": (401, "a signed-in browser session is required"),
    "admin.admin_required": (403, "administrator access is required"),
    "admin.cancelled": (409, "macOS administrator authorization was cancelled"),
    "admin.unavailable": (503, "macOS administrator authorization is unavailable"),
    "admin.failed": (500, "the privileged macOS operation failed"),
    "admin.password_required": (409, "this operation needs the macOS administrator password"),
    "admin.password_incorrect": (403, "the macOS administrator password was incorrect"),
    # ── NFS exports (/etc/exports + nfsd) ───────────────────────────────────
    "nfs.bad_path": (400, "an NFS export path must be an absolute directory"),
    "nfs.path_missing": (400, "the export path does not exist: {path}"),
    "nfs.protected_path": (403, "this directory is protected and cannot be exported: {path}"),
    "nfs.bad_client": (400, "invalid client specification: {client}"),
    "nfs.no_clients": (400, "list at least one client, or choose everyone"),
    "nfs.bad_mapping": (400, "invalid {field} value: {value}"),
    "nfs.map_conflict": (400, "maproot and mapall cannot both be set"),
    "nfs.duplicate_path": (409, "{path} is exported more than once"),
    "nfs.bad_action": (400, "unsupported nfsd action: {action}"),
    # ── AppleRAID sets ──────────────────────────────────────────────────────
    "raid.bad_device": (400, "invalid device identifier: {device}"),
    "raid.duplicate_device": (400, "{device} is listed twice"),
    "raid.too_few_members": (400, "a RAID set needs at least {minimum} members"),
    "raid.device_not_eligible": (403, "{device} cannot be used as a RAID member"),
    "raid.bad_level": (400, "unsupported RAID level {level}; choose one of {choices}"),
    "raid.bad_filesystem": (400, "unsupported filesystem {fs}; choose one of {choices}"),
    "raid.bad_name": (400, "a RAID set name of 1-63 characters is required"),
    "raid.confirm_required": (400, "destructive RAID operations require confirm=true"),
    "raid.confirm_phrase_mismatch": (400, "type ERASE to confirm that every member is wiped"),
    "raid.confirm_name_mismatch": (400, "confirm_phrase must equal the set name {name}"),
    "raid.bad_set": (400, "invalid RAID set identifier"),
    "raid.set_not_found": (404, "no RAID set with id {uuid}"),
    "raid.not_a_mirror": (400, "only a mirror can be repaired"),
    "raid.stripe_not_growable": (400, "a stripe set cannot gain members"),
    "raid.member_not_found": (404, "no member with id {uuid} in this set"),
    "raid.last_redundant_member": (400, "removing this member would leave the mirror unprotected"),
    # ── APFS snapshots / Time Machine ───────────────────────────────────────
    "snapshot.bad_token": (400, "invalid snapshot date"),
    "snapshot.confirm_required": (400, "deleting a restore point requires confirm=true"),
    "snapshot.bad_action": (400, "unsupported Time Machine action: {action}"),
    "snapshot.bad_urgency": (400, "snapshot thinning urgency must be 1-4"),
    "snapshot.bad_mount": (400, "unknown volume: {mount}"),
    # ── SMART self-tests ────────────────────────────────────────────────────
    "smart.bad_device": (400, "unknown disk device"),
    "smart.bad_kind": (400, "unsupported self-test type"),
    "smart.unsupported": (400, "this disk does not offer SMART self-tests"),
    "smart.kind_unsupported": (400, "this disk does not offer that self-test type"),
    "smart.bad_interval": (400, "unsupported schedule interval"),
    # ── usage explorer / Spotlight ──────────────────────────────────────────
    "usage.bad_volume": (400, "unknown volume"),
    # ── settings export ──────────────────────────────────────────────────────
    "system_settings.export_failed": (500, "the configuration file could not be read for export"),
    "settings.invalid_locale": (400, "invalid locale: {locale}"),
    "settings.invalid_theme": (400, "invalid theme: {theme}"),
    "settings.invalid_density": (400, "invalid density: {density}"),
    "settings.invalid_resource_mode": (400, "invalid resource mode: {mode}"),
    "settings.empty_patch": (400, "empty patch"),
    "metrics.bad_window": (400, "until must be greater than since"),
    "metrics.bad_range": (400, "invalid range (expected e.g. 48h, 30d, 1y)"),
    "actions.bad_process_name": (400, "invalid application process name"),
    "actions.empty_script": (400, "empty script command"),
    "actions.bad_action": (400, "unsupported action {action} for {kind}"),
    "actions.unknown_target": (404, "unknown target: {target}"),
    "catalog.no_free_port": (409, "no free host port available at or above {port}"),
    "catalog.unknown_app": (404, "unknown native app: {app}"),
    "catalog.unsupported_script": (400, "unsupported script_id: {script}"),
    "catalog.unsupported_method": (400, "unsupported method: {method}"),
    "catalog.unsupported_uninstall": (400, "unsupported uninstall method: {method}"),
    # ── WireGuard ───────────────────────────────────────────────────────────
    "wg.not_installed": (503, "wireguard-tools is not installed"),
    "wg.no_conf": (404, "no WireGuard config at {path}"),
    "wg.bad_interface": (400, "invalid interface name: {interface}"),
    "wg.bad_subnet": (400, "invalid subnet: {subnet}"),
    "wg.bad_endpoint": (400, "invalid public endpoint: {endpoint}"),
    "wg.bad_wstunnel_url": (400, "invalid wstunnel URL: {url}"),
    "wg.bad_wstunnel_target": (400, "invalid wstunnel restrict-to: {target}"),
    "wg.wstunnel_missing": (503, "wstunnel is not installed"),
    "wg.wstunnel_install_unverified": (
        500,
        "the wstunnel daemon was not installed as requested; "
        "root is running listen={listen} restrict-to={restrict_to}",
    ),
    "wg.bad_number": (400, "{field} is out of range"),
    "wg.bad_name": (400, "a peer name of 1-32 characters is required"),
    "wg.bad_mode": (400, "unsupported tunnel mode {mode}; choose full or split"),
    "wg.bad_count": (400, "batch size must be between 1 and 50"),
    "wg.bad_action": (400, "unsupported WireGuard action: {action}"),
    "wg.bad_key": (400, "invalid WireGuard key"),
    "wg.keygen_failed": (500, "could not generate a WireGuard key"),
    "wg.bad_ip": (400, "invalid tunnel address: {ip}"),
    "wg.ip_outside_subnet": (400, "{ip} is outside the tunnel subnet {subnet}"),
    "wg.ip_in_use": (409, "{ip} is already assigned"),
    "wg.subnet_full": (409, "no free address left in {subnet}"),
    "wg.peer_not_found": (404, "no peer with public key {pubkey}"),
    "wg.peer_exists": (409, "a peer with public key {pubkey} already exists"),
    "wg.peer_unknown": (404, "peer {pubkey} was not created by this panel"),
    "wg.peer_not_reissuable": (
        409, "peer {pubkey} has no stored private key, so its config cannot be regenerated",
    ),
    "wg.sync_failed": (500, "the running interface could not be reloaded"),
    "wg.confirm_required": (400, "revoking a peer requires confirm=true"),
    "wg.bad_format": (400, "unsupported export format: {format}"),
    # ── containers / compose ────────────────────────────────────────────────
    "container.job_running": (409, "another container job is already running"),
    "container.engine_down": (503, "the Docker engine is not running"),
    "container.image_ref_required": (400, "an image id or name is required"),
    "container.image_required": (400, "a valid image name is required"),
    "container.bad_image_name": (400, "invalid image name"),
    "container.bad_container_name": (400, "invalid container name"),
    "container.bad_new_name": (400, "invalid new name"),
    "container.volume_name_required": (400, "a volume name is required"),
    "container.bad_volume_name": (400, "invalid volume name"),
    "container.network_name_required": (400, "a network name is required"),
    "container.bad_network_name": (400, "invalid network name"),
    "container.builtin_network": (400, "built-in networks cannot be removed"),
    "container.no_compose_file": (400, "this stack has no compose file"),
    "container.bad_shell": (400, "unsupported container exec shell"),
    "container.bad_policy": (400, "unsupported restart policy: {policy}"),
    "container.bad_action": (400, "unsupported container action: {action}"),
    "container.empty_names": (400, "at least one container name is required"),
    "container.unknown_stack": (404, "unknown stack: {stack}"),
    "container.not_found": (404, "container not found"),
    "container.empty_command": (400, "command is empty"),
    "container.list_failed": (500, "could not list {kind}"),
    "compose.unknown_stack": (404, "unknown stack: {stack}"),
    "compose.bad_stack_id": (400, "stack id must be 1-41 letters, digits, underscore or dash"),
    "compose.empty_content": (400, "compose file content is empty"),
    "compose.path_forbidden": (403, "compose path must be under ~/Services"),
    "compose.invalid": (400, "compose file is invalid: {detail}"),
    "compose.exists": (409, "stack already exists: {path}"),
    "compose.file_missing": (404, "compose file not found: {path}"),
    "logs.unknown_source": (404, "unknown log source"),
    "logs.protected": (403, "that log path is protected"),
    "logs.read_failed": (500, "the log file could not be read"),
    "brew.bad_action": (400, "unsupported brew action: {action}"),
    "brew.not_found": (503, "Homebrew is not installed"),
    "cli.invalid_value": (400, "invalid {label}"),
    # ── maintenance jobs ────────────────────────────────────────────────────
    "maintenance.job_running": (409, "a maintenance task is already running"),
    "maintenance.unknown_task": (404, "unknown maintenance task"),
    # ── immich hybrid stack (health-check prose, resolved by the SPA) ───────
    "immich.worker_down": (
        503,
        "not running — uploads get no thumbnails, no transcoding, no face recognition",
    ),
    "immich.worker_quarantined": (
        409,
        "quarantined — the media volume had write faults, so the worker is "
        "deliberately kept stopped (delete ~/.immich-accelerator/worker.quarantine "
        "once the hardware is repaired)",
    ),
    "immich.worker_lift_quarantine": (
        409,
        "repair the media volume's USB link first, then delete the quarantine marker",
    ),
    # ── 2026-08 backend i18n sweep ───────────────────────────────────────────
    "network.invalid_ip": (400, 'invalid IP address / netmask'),
    "network.invalid_router": (400, 'invalid gateway address'),
    "network.invalid_netmask": (400, 'invalid netmask'),
    "network.invalid_dns": (400, 'invalid DNS server: {server}'),
    "network.order_required": (400, 'the full service order list is required'),
    "network.unknown_service": (400, 'unknown network service: {service}'),
    "network.services_unreadable": (500, 'could not read network services'),
    "network.bad_profile": (400, 'profile must be one of: wifi | ethernet | wifi_only | ethernet_only'),
    "network.invalid_device": (400, 'invalid interface name: {device}'),
    "network.device_not_found": (404, 'no such interface: {device}'),
    "network.invalid_service_name": (400, 'invalid network service name'),
    "network.service_not_found": (404, 'network service not found: {service}'),
    "network.invalid_hostname": (400, 'invalid hostname'),
    "network.docker_args_required": (400, 'network and container are required'),
    "network.builtin_network_connect": (400, 'cannot connect to the host/none network'),
    "network.container_not_found": (404, 'container not found: {name}'),
    "network.image_unresolvable": (400, "could not resolve the container's image"),
    "network.bad_wifi_state": (400, "Wi-Fi state must be on or off"),
    "cloudflared.not_installed": (503, 'cloudflared is not installed (install "Cloudflared (native)" from the app store first)'),
    "cloudflared.tunnel_required": (400, 'a tunnel name or UUID is required'),
    "cloudflared.not_logged_in": (400, 'not signed in to Cloudflare (cert.pem missing); sign in first'),
    "cloudflared.token_fetch_failed": (400, 'could not fetch the tunnel token: {error}'),
    "cloudflared.invalid_token": (400, 'invalid token (too short)'),
    "cloudflared.no_token": (400, 'no tunnel token saved yet'),
    "cloudflared.invalid_name": (400, 'invalid tunnel name (letters, digits, . _ - only)'),
    "cloudflared.login_required": (400, 'sign in to Cloudflare first'),
    "cloudflared.route_args_required": (400, 'tunnel and hostname are required'),
    "apps.bad_id": (400, 'id must be kind:source, e.g. docker:plex / native:native-redis / launchd:label / vm:uuid'),
    "apps.launchd_not_found": (404, "launch agent not found"),
    "apps.cloudflared_token_required": (400, 'select a tunnel or paste a token and start it once before enabling autostart'),
    "apps.autostart_unsupported": (400, 'this native app does not support toggling login autostart (it may require System Settings)'),
    "apps.vm_autostart_external": (400, 'configure VM autostart in UTM / OrbStack'),
    "apps.bad_autostart_kind": (400, 'autostart is not supported for kind: {kind}'),
    "apps.docker_action_unsupported": (400, 'unsupported docker action: {action}'),
    "apps.native_action_unsupported": (400, 'unsupported native app action: {action}'),
    "apps.unknown_kind": (400, "unknown app kind: {kind}"),
    "apps.native_not_found": (404, "native app not found"),
    "apps.vm_not_found": (404, "vm not found"),
    "disk_power.protected": (403, 'system disks and non-sleepable disks cannot be slept or ejected'),
    "disk_power.unknown_action": (400, "unknown disk power action: {action}"),
    "disk_power.invalid_id": (400, "invalid disk id"),
    "disk_power.not_found": (404, "disk not found: {disk}"),
    "credentials.bad_service_id": (400, 'invalid service id'),
    "credentials.username_required": (400, 'username is required'),
    "credentials.password_too_short": (400, 'the service password must be at least {min} characters'),
    "credentials.keychain_write_failed": (503, 'could not write to the macOS Keychain: {error}'),
    "credentials.index_save_failed": (500, 'could not save the credential index: {error}'),
    "credentials.bad_username": (400, 'usernames may only contain letters, digits and . _ @ + - and must start with a letter or digit'),
    "credentials.filebrowser_missing": (404, 'File Browser is not installed or its database is missing'),
    "credentials.filebrowser_stop_failed": (503, 'could not pause File Browser; the password was not changed'),
    "credentials.filebrowser_update_failed": (400, 'File Browser rejected the password change: {error}'),
    "credentials.teslamate_gateway_missing": (409, 'the TeslaMate password gateway is not installed'),
    "credentials.htpasswd_failed": (503, 'could not generate the TeslaMate password digest: {error}'),
    "credentials.teslamate_apply_failed": (503, 'the TeslaMate password was not applied and has been rolled back: {error}'),
    "credentials.adapter_unsupported": (400, 'this service does not support automated password changes; the credential can still be saved'),
    "autostart.self_protected": (400, "{label} is ServerHub's own login task and cannot be disabled here; use the 'Start at login' switch on the Settings page instead"),
    "autostart.bad_id": (400, 'id must be kind:name'),
    "autostart.unknown_kind": (400, "unknown autostart kind: {kind}"),
    "autostart.plist_missing": (404, "plist not found for {label}"),
    "autostart.script_missing": (404, "autostart.sh not found"),
    "nginx.conf_missing": (404, "nginx.conf is missing"),
    "power.unknown_action": (400, 'unknown power action: {action} (choose one of {choices})'),
    "power.confirm_required": (400, 'power actions require confirm=true'),
    "power.bad_key": (400, "unsupported power setting: {key}"),
    "power.bad_value": (400, "value must be an integer"),
    "power.value_range": (400, "value is out of range 0–180"),
    "vms.name_required": (400, 'a new name is required'),
    "vms.utm_unavailable": (503, 'utmctl is not available; install UTM'),
    "vms.utm_unsupported_action": (400, 'UTM does not support action: {action}'),
    "vms.orb_unavailable": (503, 'orbctl is not available'),
    "vms.orb_unsupported_action": (400, 'OrbStack does not support action: {action}'),
    "vms.distro_required": (400, 'distro is required, e.g. ubuntu or ubuntu:24.04'),
    "vms.bad_distro": (400, 'invalid distro'),
    "vms.bad_machine_name": (400, 'invalid machine name'),
    "vms.unknown_backend": (400, "unknown VM backend for {vm}"),
    "services.docker_unavailable": (400, 'the docker CLI is not available'),
    "services.bad_action": (400, "action must be start, stop, restart or run"),
    # ── adopting auto-discovered services ────────────────────────────────────
    "services.adopt_not_found": (404, "service not found: {id}"),
    "services.adopt_not_auto": (400, "{id} is not an auto-discovered service"),
    "services.adopt_no_port": (400, "{id} has no detected listen port to adopt"),
    "services.script_not_found": (404, "no managed script named {id}"),
    "services.signature_invalid": (400, "recognition rule needs a slug of letters, digits and hyphens"),
    "services.signature_not_found": (404, "no recognition rule named {slug}"),
    "services.not_found": (404, "service not found: {id}"),
    "services.no_logs": (404, "no logs for {id}"),
    "services.bad_port": (400, "port must be an integer"),
    "jobs.already_running": (409, 'a maintenance task is already running; wait for it to finish'),
    # ── panel scheduler (user-defined cron jobs) ─────────────────────────────
    "scheduler.not_found": (404, "no scheduled job with id {id}"),
    "scheduler.bad_id": (400, "job ids are 1-64 letters, digits, . _ -"),
    "scheduler.exists": (409, "a scheduled job with id {id} already exists"),
    "scheduler.bad_cron": (400, "invalid cron expression: {cron}"),
    "scheduler.bad_type": (400, "unsupported job type: {type}"),
    "scheduler.bad_params": (400, "invalid job parameter: {field}"),
    "scheduler.bad_name": (400, "a job name of 1-80 characters is required"),
    "scheduler.running": (409, "this job is currently running; wait for it to finish"),
    "scheduler.readonly": (400, "this entry is managed elsewhere and cannot be edited here"),
    # ── rsync backups ────────────────────────────────────────────────────────
    "rsync.unavailable": (503, "no usable rsync binary was found on this host"),
    "rsync.bad_direction": (400, "direction must be push or pull"),
    "rsync.bad_path": (400, "{field} must be an absolute local path"),
    "rsync.bad_dest": (400, "{field} must be an absolute path or user@host:path"),
    "rsync.bad_exclude": (400, "invalid exclude pattern: {pattern}"),
    "rsync.bad_params": (400, "invalid rsync parameter: {field}"),
    # ── compose stack (appdata) backups ──────────────────────────────────────
    "backup.stack_unknown": (404, "no compose stack named {stack}"),
    "backup.stack_no_compose": (400, "stack {stack} has no compose file to back up"),
    "backup.engine_down": (503, "the Docker engine is not running, so the stack cannot be backed up"),
    # ── notification channels ────────────────────────────────────────────────
    "notify.bad_type": (400, "unsupported channel type: {type}"),
    "notify.bad_id": (400, "channel ids are 1-64 lowercase letters, digits, . _ -"),
    "notify.not_found": (404, "no notification channel with id {id}"),
    "notify.bad_level": (400, "min_level must be one of: info | warn | down"),
    "notify.missing_field": (400, "required field is missing: {field}"),
    "notify.bad_url": (400, "{field} must be an http(s) URL"),
    "notify.exists": (409, "a channel with id {id} already exists"),
    "notify.no_match": (404, "no notification channel matched"),
    "notify.type_immutable": (400, "the type of channel {id} cannot be changed; delete it and create a new one"),
    "notify.secret_control_chars": (400, "{field} contains control characters (a pasted newline or tab?)"),
    # ── UPS / battery ────────────────────────────────────────────────────────
    "ups.empty_patch": (400, "the settings patch is empty"),
    "ups.policy_no_condition": (400, "enable at least one trigger condition (battery % or minutes remaining) before enabling the shutdown policy"),
    "ups.bad_stack_id": (400, "invalid stack or service id: {id}"),
    "ups.halt_bad_level": (400, "haltlevel must be -1 (off) or between 5 and 95"),
    # ── rsync dry-run preview ────────────────────────────────────────────────
    "rsync.preview_busy": (409, "a dry-run preview for this job is already running; wait for it to finish"),
    # ── tools (ping / dns / prune) ──────────────────────────────────────────
    # Soft refusals: tools_svc returns {ok:false, code, message} so Tools.vue
    # can keep rendering the dict.  Codes still live here so the English
    # fallback and the SPA err.* keys stay in one place.
    "tools.bad_host": (400, "hostname contains invalid characters"),
    "tools.empty_name": (400, "domain name is empty"),
    "tools.confirm_required": (400, "confirm=true is required"),
    "tools.bad_prune": (400, "unknown prune type: {what}"),
    # ── PhotosHub ────────────────────────────────────────────────────────────
    "photoshub.status_failed": (500, "PhotosHub status could not be read: {detail}"),
    "photoshub.pending_failed": (502, "could not list pending-delete photos: {detail}"),
    "photoshub.bad_ids": (400, "select at least one photo"),
    "photoshub.remove_failed": (502, "could not remove photos from the pending album: {detail}"),
    "photoshub.bad_action": (400, "unknown PhotosHub action: {action}"),
    "photoshub.action_failed": (500, "PhotosHub action failed: {detail}"),
    "photoshub.bad_log": (400, "unknown PhotosHub log name"),
    "photoshub.not_installed": (404, "PhotosHub is not installed on this Mac"),
    "photoshub.bad_immich_url": (400, "Immich API URL must be a private or loopback http(s) address"),
    "photoshub.album_missing": (404, "the pending-delete album was not found"),
    "photoshub.key_missing": (503, "the Immich API key is missing"),
    "photoshub.script_missing": (404, "the PhotosHub people-album script is not on disk"),
    "photoshub.bad_config": (400, "PhotosHub config.json is missing or not valid JSON"),
    "photoshub.config_failed": (500, "PhotosHub settings could not be saved: {detail}"),
    "photoshub.bad_name": (400, "a person name must be 1–40 characters with no control characters"),
    "photoshub.bad_birthday": (400, "birthday must be YYYY-MM or YYYY-MM-DD"),
    "photoshub.bad_album": (400, "album names are 1–80 characters and cannot contain slashes"),
    "photoshub.bad_person": (400, "only yuanbao and erbao can be edited here"),
    "photoshub.bad_link_url": (400, "that link must be an http(s) URL with a hostname"),
    "photoshub.thumb_failed": (502, "the photo preview could not be fetched from Immich: {detail}"),
    "photoshub.immich_response": (502, "Immich returned a response that could not be used: {detail}"),
}


def error_payload(code: str, /, **params) -> tuple[int, dict]:
    """(http status, response body) for *code* — the shape the SPA parses.

    Middleware cannot raise HTTPException (there is no handler above it to catch
    it), so it needs the body directly.  Sharing this builder keeps middleware
    rejections translatable instead of falling back to hardcoded prose.
    """
    status, template = CODES.get(code, (500, code))
    try:
        message = template.format(**params) if params else template
    except (KeyError, IndexError):
        message = template
    detail: dict = {"code": code, "message": message}
    if params:
        detail["params"] = params
    return status, {"detail": detail}


def soft_fail(code: str, **params) -> dict:
    """``{ok: false, code, message}`` for endpoints that return a dict.

    Tools ping/dns/prune and Settings power prefs keep a dict contract so the
    SPA can render the payload without treating validation as an HTTP error.
    The English fallback still comes from CODES.
    """
    _, body = error_payload(code, **params)
    detail = body["detail"]
    out = {"ok": False, "code": detail["code"], "message": detail["message"]}
    if "params" in detail:
        out["params"] = detail["params"]
    return out


def api_error(code: str, /, **params) -> HTTPException:
    """Build an HTTPException carrying a machine-readable code.

    Unknown codes degrade to HTTP 500 with the code as the message rather than
    raising, so a typo in a rarely-hit branch never masks the real failure.
    """
    status, body = error_payload(code, **params)
    return HTTPException(status, body["detail"])
