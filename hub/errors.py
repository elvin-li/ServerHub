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

#: Real control flow must keep propagating even through the bomb guards
#: (the modules12/logs12 convention): swallowing a Ctrl-C or an interpreter
#: shutdown to save one error body would turn the sanitizer into a hang.
#: Everything else BaseException-shaped that a leftover raises out of its
#: own hooks is a bomb like any other — and this module is the *last*
#: sanitizer between a coded error and Starlette's encoder, so a raise out
#: of any guard here is a raw HTTP 500 for the coded body by definition.
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

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
    # Confirmed-vanished sharing CLI (fresh disk probe on the failure path
    # only).  503 like the other tool-absent states (raid.diskutil_missing,
    # smart.smartctl_missing, usage.mdutil_missing).
    "shares.sharing_missing": (503, "the macOS sharing tool is missing on this host"),
    # Confirmed-vanished systemsetup / launchctl / AssetCacheManagerUtil /
    # open (fresh disk probe on the failure path only).
    "shares.system_tool_missing": (503, "a macOS system tool required for this operation is missing on this host"),
    # ── per-user share access (filesystem ACLs) ─────────────────────────────
    "shares.acl_not_share": (400, "this directory is not a current SMB share point"),
    "shares.acl_read_failed": (500, "the directory's access control list could not be read"),
    "shares.acl_bad_user": (400, "unknown local macOS user"),
    "shares.acl_bad_level": (400, "the access level must be none, read or readwrite"),
    # Confirmed-vanished ls/chmod (fresh disk probe on the failure path only).
    "shares.acl_tool_missing": (503, "the macOS ACL tools are missing on this host"),
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
    # The disk write itself failed mid-upload (ENOSPC on a full volume, EIO
    # on a dying FUSE/SMB mount).  503 like compose.save_failed /
    # settings.save_failed: a disk that cannot be written is a dependency
    # state, not a defect in the upload — the raw OSError used to escape as
    # an uncoded HTTP 500 after validation had already passed.
    "files.upload_write_failed": (503, "the uploaded file could not be written: {error}"),
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
    # A diskutil confirmed vanished by a fresh disk probe on the mutation
    # failure path.  503 like the other tool-absent states
    # (raid.diskutil_missing, smart.smartctl_missing, snapshot.tmutil_missing);
    # the bare "not found" body it replaced read like a missing *disk*.
    "disk.diskutil_missing": (503, "diskutil is missing on this host"),
    # ── optional FileBrowser process ────────────────────────────────────────
    "files.fb_not_installed": (404, "FileBrowser is not installed (~/Services/filebrowser)"),
    "files.fb_start_failed": (500, "could not start FileBrowser"),
    # The FileBrowser binary vanished between the installed gate and the
    # spawn.  503 like the other tool-absent states (backup.tool_missing,
    # vms.orb_unavailable, photoshub.ctl_missing).
    "files.fb_missing": (503, "the FileBrowser binary is missing (~/Services/filebrowser)"),
    # ── storage pool (JBOD union planner) ───────────────────────────────────
    "storage_pool.bad_policy": (400, "unknown placement policy: {policy}"),
    "storage_pool.no_members": (400, "select at least one volume for the pool"),
    "storage_pool.not_poolable": (400, "{mount} cannot join a pool (system or unmounted)"),
    # The pool name is persisted into services.yaml.  Unbounded, a multi-MB
    # label was refused only by the whole-file save cap as a
    # settings.save_failed 503 — blaming the disk for oversized input — and a
    # label just under the cap ballooned services.yaml toward the 1MB read
    # cap for every sibling writer.  400 like the other persisted-value caps
    # (vms.name_too_long, identity.value_too_long, disk.name_required).
    "storage_pool.name_too_long": (400, "the pool name is too long (max {max} characters)"),
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
    # Confirmed-vanished nfsd (fresh disk probe on the failure path only).
    # 503 like the other tool-absent states (raid.diskutil_missing,
    # smart.smartctl_missing, usage.mdutil_missing).
    "nfs.nfsd_missing": (503, "nfsd is missing on this host"),
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
    # Confirmed-vanished diskutil (fresh disk probe on the failure path only).
    # 503 like the other tool-absent states (smart.smartctl_missing,
    # backup.tool_missing, files.fb_missing, photoshub.ctl_missing).
    "raid.diskutil_missing": (503, "diskutil is missing on this host"),
    # ── APFS snapshots / Time Machine ───────────────────────────────────────
    "snapshot.bad_token": (400, "invalid snapshot date"),
    "snapshot.confirm_required": (400, "deleting a restore point requires confirm=true"),
    "snapshot.bad_action": (400, "unsupported Time Machine action: {action}"),
    "snapshot.bad_urgency": (400, "snapshot thinning urgency must be 1-4"),
    "snapshot.bad_mount": (400, "unknown volume: {mount}"),
    # Confirmed-vanished tmutil (fresh disk probe on the failure path only).
    # 503 like the other tool-absent states (nfs.nfsd_missing,
    # raid.diskutil_missing, smart.smartctl_missing, usage.mdutil_missing) —
    # the old shape was the generic admin.failed 500, which sent the operator
    # back to a password dialog that cannot help.
    "snapshot.tmutil_missing": (503, "tmutil is missing on this host"),
    # ── SMART self-tests ────────────────────────────────────────────────────
    "smart.bad_device": (400, "unknown disk device"),
    "smart.bad_kind": (400, "unsupported self-test type"),
    "smart.unsupported": (400, "this disk does not offer SMART self-tests"),
    "smart.kind_unsupported": (400, "this disk does not offer that self-test type"),
    "smart.bad_interval": (400, "unsupported schedule interval"),
    # The smartctl binary vanished between the capability gate and the spawn
    # (confirmed by a fresh disk probe).  503 like the other tool-absent
    # states (backup.tool_missing, files.fb_missing, photoshub.ctl_missing).
    "smart.smartctl_missing": (503, "smartctl is not installed on this host"),
    # ── usage explorer / Spotlight ──────────────────────────────────────────
    "usage.bad_volume": (400, "unknown volume"),
    # Confirmed-vanished mdutil (fresh disk probe on the failure path only).
    # 503 like the other tool-absent states (raid.diskutil_missing,
    # smart.smartctl_missing, backup.tool_missing, files.fb_missing).
    "usage.mdutil_missing": (503, "mdutil is missing on this host"),
    # ── settings export ──────────────────────────────────────────────────────
    "system_settings.export_failed": (500, "the configuration file could not be read for export"),
    "settings.invalid_locale": (400, "invalid locale: {locale}"),
    "settings.invalid_theme": (400, "invalid theme: {theme}"),
    "settings.invalid_density": (400, "invalid density: {density}"),
    "settings.invalid_resource_mode": (400, "invalid resource mode: {mode}"),
    "settings.empty_patch": (400, "empty patch"),
    "settings.save_failed": (503, "the configuration file could not be saved"),
    # services.yaml exists but cannot be read back (grown past the 1MB read
    # cap by a hand edit or a restored backup, torn to non-UTF-8 bytes,
    # unparseable, or replaced whole by a stray paste).  Refusing the write
    # is what keeps the on-disk file recoverable; a 503 names the dependency,
    # not the input — the notify.secrets_unreadable shape for the main config.
    "settings.config_unreadable": (503, "services.yaml cannot be read back; fix or restore it before saving"),
    "metrics.bad_window": (400, "until must be greater than since"),
    "metrics.bad_range": (400, "invalid range (expected e.g. 48h, 30d, 1y)"),
    "actions.bad_process_name": (400, "invalid application process name"),
    "actions.empty_script": (400, "empty script command"),
    "actions.bad_action": (400, "unsupported action {action} for {kind}"),
    "actions.unknown_target": (404, "unknown target: {target}"),
    "actions.crash_loop": (503, "LaunchAgent {label} is crash-looping (last exit {exit}); the start command ran but the process died. Check the service log."),
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
    # sh()'s vanished-binary sentinel confirmed by a fresh disk probe on the
    # ping failure path only — the network.ping_missing / tools.ping_missing
    # convention on the peer-ping surface.
    "wg.ping_missing": (503, "ping is missing on this host"),
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
    # A leftover non-empty directory occupying wg0.conf or a data/ staging
    # file: nothing was written, so removing the occupant and retrying is
    # the whole repair — a dependency problem, not an input one, hence 503.
    "wg.write_failed": (503, "could not write {path}; remove whatever occupies that path and retry"),
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
    # The live compose write itself failed (disk full, read-only or dying
    # mount, permissions lost mid-request).  503 like settings.save_failed:
    # a disk that cannot be written is a dependency state, not a defect in
    # the operator's YAML — the raw OSError used to escape as HTTP 500
    # *after* validation had already passed.
    "compose.save_failed": (503, "the compose file could not be saved: {detail}"),
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
    # networksetup vanished from disk (confirmed by a fresh on-disk probe on
    # the empty-listing failure path only).  503 like the other tool-absent
    # states (identity.scutil_missing, raid.diskutil_missing) — the old shape
    # was the services_unreadable 500, which blamed the server for a missing
    # host tool.
    "network.networksetup_missing": (503, 'networksetup is missing on this host'),
    "network.ifconfig_missing": (503, 'ifconfig is missing on this host'),
    # The same confirmed-vanished rule for the remaining host tools the alias
    # / failover / dns-lookup flows spawn: the disk probe runs on the spawn
    # sentinel failure path only, and a present-but-failing tool keeps its
    # honest answer.  Before these codes, a vanished /sbin/route churned the
    # managed aliases and answered 200 "local route still broken", a vanished
    # /sbin/ping read as "gateway unreachable" and switched the Wi-Fi radio
    # on, and a vanished dscacheutil+dig pair answered 200 "not found" — which
    # reads like the host does not resolve.
    "network.route_missing": (503, 'the route tool is missing on this host'),
    "network.ping_missing": (503, 'ping is missing on this host'),
    "network.lookup_tools_missing": (503, 'the DNS lookup tools (dscacheutil/dig) are missing on this host'),
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
    "cloudflared.invalid_token": (400, 'invalid Cloudflare tunnel token; paste the connector token from Zero Trust → Tunnels (it starts with eyJ)'),
    "cloudflared.start_failed": (503, 'the tunnel process died after start: {error}'),
    "cloudflared.plist_write_failed": (503, 'could not write the tunnel LaunchAgent plist: {error}'),
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
    # A diskutil confirmed vanished by a fresh disk probe on the failure
    # path.  503 like disk.diskutil_missing: the pre-fix answers — a bare
    # "not found" body, or the 404 "disk not found" when the vanished binary
    # emptied the listing — both misdirected the operator at the disk.
    "disk_power.diskutil_missing": (503, "diskutil is missing on this host"),
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
    "autostart.bad_plist": (400, "the LaunchAgent plist for {label} is unreadable or has no Label"),
    "autostart.script_missing": (404, "autostart.sh not found"),
    "nginx.conf_missing": (404, "nginx.conf is missing"),
    "nginx.not_found": (503, "nginx is not installed"),
    "power.unknown_action": (400, 'unknown power action: {action} (choose one of {choices})'),
    "power.confirm_required": (400, 'power actions require confirm=true'),
    "power.bad_key": (400, "unsupported power setting: {key}"),
    "power.bad_value": (400, "value must be an integer"),
    "power.value_range": (400, "value is out of range 0–180"),
    # pmset vanished from disk between boot and the WOL toggle (confirmed by a
    # fresh on-disk probe on the failure path).  503 like the other tool-absent
    # states (identity.scutil_missing, network.networksetup_missing) — the old
    # shape was an ok:false answer whose message told the operator to run
    # ``sudo pmset`` by hand, blaming privileges for a binary that is gone.
    "power.pmset_missing": (503, "pmset is missing on this host"),
    "identity.bad_name": (400, "computer name is invalid"),
    # comment / host_ip are persisted into services.yaml.  Unbounded, a
    # multi-MB value used to be refused only by the whole-file save cap as a
    # settings.save_failed 503 — blaming the disk for oversized input (and a
    # value just under the cap crowded every sibling writer toward it).  400
    # like the other persisted-value caps (vms.name_too_long,
    # notify.value_too_long).
    "identity.value_too_long": (400, "{field} is too long (max {max} characters)"),
    # scutil vanished from disk between boot and the rename (confirmed by a
    # fresh on-disk probe on the failure path).  503 like the other
    # tool-absent states (raid.diskutil_missing, vms.utm_unavailable) — the
    # old shape was an ok:true answer whose message blamed missing
    # administrator privileges, so the lost rename surfaced nowhere.
    "identity.scutil_missing": (503, "scutil is missing on this host"),
    "vms.name_required": (400, 'a new name is required'),
    # The display name is persisted into services.yaml overrides.  Unbounded, a
    # multi-MB rename wrote a config larger than the 1MB read cap and every
    # later cfg() answered {} — the admin account and every sibling key
    # disappeared from the panel's view, and the next mutate() persisted the
    # wipe.  64 matches the accounts/apikeys/disk name caps.
    "vms.name_too_long": (400, "the display name must be 1-64 characters"),
    "vms.bad_id": (400, "invalid virtual machine id"),
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
    "services.group_rule_invalid": (400, "grouping rule needs a target group and a slug of letters, digits and hyphens"),
    "services.group_rule_not_found": (404, "no grouping rule named {id}"),
    "services.not_found": (404, "service not found: {id}"),
    "services.no_logs": (404, "no logs for {id}"),
    "services.bad_port": (400, "port must be an integer"),
    "services.bad_command": (400, "start/stop command contains characters that cannot be encoded"),
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
    # A backup job's own binary (pg_dump, tar) is gone — never installed, or
    # uninstalled between a probe and the spawn.  503 like the other
    # tool-absent states (brew.not_found, wg.not_installed, rsync.unavailable).
    "backup.tool_missing": (503, "{tool} is not installed on this host"),
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
    # Unbounded channel values used to grow services.yaml (config fields) or
    # notify-credentials.json (secrets) past their read caps — after which
    # every read answered {} and the next write wiped every sibling row.
    "notify.value_too_long": (400, "{field} is too long (max {max} characters)"),
    "notify.list_too_long": (400, "{field} has too many entries (max {max})"),
    "notify.too_many": (400, "too many notification channels — remove unused channels first"),
    "notify.secrets_too_large": (400, "the stored notification secrets would exceed the size limit — remove unused channels first"),
    # The credentials file exists but cannot be read back (oversized, torn,
    # or a dying disk).  Refusing the write is what keeps the sibling
    # channels' secrets on disk; a 503 names the dependency, not the input.
    "notify.secrets_unreadable": (503, "the stored notification secrets cannot be read; fix or remove data/notify-credentials.json first"),
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
    "tools.no_update": (409, "this panel is already on the latest GitHub release"),
    "tools.dirty_tree": (409, "the checkout has local changes; commit, stash or reset before installing a GitHub update"),
    "tools.not_a_git_checkout": (400, "this install is not a git checkout; re-run install.sh from a clone"),
    "tools.github_unreachable": (503, "could not reach GitHub: {error}"),
    "tools.brew_busy": (409, "Homebrew is busy or not installed; try again in a few minutes"),
    # Confirmed-vanished net-helper CLIs (fresh disk probe on the spawn-
    # sentinel failure path only — the network.ping_missing /
    # network.lookup_tools_missing rule on the Tools tab's own routes).
    "tools.ping_missing": (503, "the ping tool is missing on this host"),
    "tools.dns_flush_tools_missing": (503, "the macOS DNS flush tools (dscacheutil/killall) are missing on this host"),
    # ── PhotosHub ────────────────────────────────────────────────────────────
    "photoshub.status_failed": (500, "PhotosHub status could not be read: {detail}"),
    "photoshub.pending_failed": (502, "could not list pending-delete photos: {detail}"),
    "photoshub.bad_ids": (400, "select at least one photo"),
    "photoshub.remove_failed": (502, "could not remove photos from the pending album: {detail}"),
    "photoshub.bad_action": (400, "unknown PhotosHub action: {action}"),
    "photoshub.action_failed": (500, "PhotosHub action failed: {detail}"),
    "photoshub.bad_log": (400, "unknown PhotosHub log name"),
    "photoshub.not_installed": (404, "PhotosHub is not installed on this Mac"),
    # The photoctl helper (or the people-album python) vanished between the
    # installed()/script gate and the spawn.  503 like the other tool-absent
    # states (backup.tool_missing, vms.orb_unavailable, wg.not_installed).
    "photoshub.ctl_missing": (503, "{tool} is missing from the PhotosHub tree"),
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


def _isinst(value, types) -> bool:
    """``isinstance`` that never escapes a raising ``__class__`` property.

    ``isinstance`` reads ``value.__class__`` when the concrete type is not an
    exact/subtype match, so a leftover whose ``__class__`` is a *property that
    raises* (the account8 class) blew the unguarded type dispatch below
    straight out of the sanitizer — a raw HTTP 500 while building a coded
    error's own body.  Treat such an object as "none of these types" and let
    it fall through to the guarded ``str(value)`` tail, which launders it to a
    renderable string or drops it — the code/message beside it still answer.

    ``except BaseException``: the json8 guard stopped at ``Exception``, so a
    leftover whose ``__class__`` property raises a *BaseException* subclass
    (the watchdog/timeout shape the modules12/logs12 sweeps sealed on their
    own surfaces) sailed past this catch — and past every sibling guard in
    this module, because each one stopped at ``Exception`` too — straight
    out of the sanitizer while it was building a coded error's own body: a
    raw HTTP 500 riding the very machinery that exists to prevent one.
    Only genuine control flow keeps propagating.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _jsonable_param(value, depth: int = 0):
    """Coerce leftover params so Starlette's allow_nan=False encoder cannot 500.

    A coded 409 whose ``port`` was YAML ``.inf`` used to become HTTP 500 while
    encoding the error body.  ``bytes`` / dates / ``!!set`` in params did the
    same via TypeError.
    """
    if depth > 8:
        return None
    if value is None:
        return value
    if _isinst(value, bool):
        # ``bool`` is final, so a value that answers this gate while its real
        # type is not ``bool`` is a *lying* ``__class__`` impostor, not a
        # genuine bool.  The old arm returned it raw, handing Starlette's
        # ``allow_nan=False`` encoder a non-serializable object that 500'd
        # the coded error's own body (the modules9 bool-liar).  Only a real
        # bool renders; the impostor drops to ``None`` like the lying
        # numeric coercions below.
        if type(value) is bool:
            return value
        return None
    if _isinst(value, int):
        try:
            # Base coercion to an exact int first: an int *subclass* whose
            # ``__index__``/``__str__`` bombs (the settings8/modules5 class)
            # used to raise past the ValueError-only digit-cap catch and turn
            # the coded 4xx into a raw 500 while building its own error body —
            # the same subclass rule every ``_jsonable`` sibling now follows.
            value = int.__index__(value)
            str(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Past CPython's int->str digit cap the encoder cannot render the
            # number at all — ``json.dumps`` raises the same ValueError.  A str
            # param is parse-capped before it can become an int, but YAML/plist
            # hex text loads uncapped (``int(x, 16)`` is a power-of-two base),
            # so an already-int leftover reached Starlette untouched — the
            # photoshub/immich ``_jsonable`` drop.
            return None
        return value
    if _isinst(value, float):
        try:
            # Base coercion to an exact float: a subclass ``__eq__``/``__ne__``
            # bomb used to blow the NaN/inf probes below (the modules5 rule).
            value = float.__float__(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isinst(value, str):
        # Unbound str.encode, not the bound ``.encode``: ``str(x)`` of a str
        # *subclass* whose ``__str__`` returns itself keeps the subclass, so a
        # bound ``.encode`` dispatched into a leftover override — the json6
        # self-``__str__`` encode bomb — and raised out of the error body.
        # The unbound descriptor is bound to the real str layout, so a
        # *lying* ``__class__`` claiming str (real type is not) rejected the
        # foreign operand with a TypeError outside any try — a raw 500 for
        # the coded body.  A raise means "not really a str"; the impostor
        # drops to ``None`` like the lying numeric coercions above.
        try:
            return str.encode(value, "utf-8", "replace").decode("utf-8")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isinst(value, (bytes, bytearray)):
        # bytes(...) first: a bytes subclass whose decode() bombs (the
        # modules5 class) must not raise out of the sanitizer.  The copy
        # itself rejects a *lying* ``__class__`` claiming bytes/bytearray
        # (real type is neither) with a TypeError that used to escape — a
        # raise means "not really bytes", so the impostor drops to ``None``.
        try:
            return bytes(value).decode("utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isinst(value, dict):
        out = {}
        try:
            items = list(value.items())
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A dict *subclass* whose items() raises (the json5 bomb class)
            # must not 500 the error body — drop the node like an unrenderable
            # scalar; the code/message beside it in ``detail`` still render.
            return None
        for entry in items:
            try:
                k, v = entry
            except _CONTROL_FLOW:
                raise
            except BaseException:
                # An items() that yields non-pairs (an overriding dict
                # subclass, or a lying-``__class__`` impostor's own items()):
                # the tuple unpack used to raise TypeError outside any try —
                # drop the entry, keep the rest of the mapping.
                continue
            if _isinst(k, (bytes, bytearray)):
                try:
                    k = bytes(k).decode("utf-8", "replace")
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    # A lying-``__class__`` key claiming bytes rejects the
                    # copy — drop just this entry, keep the siblings.
                    continue
            elif not _isinst(k, str):
                try:
                    k = str(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            try:
                key = str.encode(k, "utf-8", "replace").decode("utf-8")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                # A lying-``__class__`` key claiming str skipped the str(k)
                # coercion above, and the unbound encode rejects the foreign
                # operand — drop the entry rather than 500 the error body.
                continue
            out[key] = _jsonable_param(v, depth + 1)
        return out
    if _isinst(value, (list, tuple, set, frozenset)):
        try:
            seq = list(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A list/set subclass whose __iter__ raises drops to null rather
            # than raising out of the encode; the error body survives.
            return None
        return [_jsonable_param(v, depth + 1) for v in seq]
    try:
        # getattr, not attribute access: a leftover whose ``isoformat`` is a
        # *property that raises* (not a method) blew this lookup out of the
        # sanitizer before ``callable`` ever ran — a raw 500 for the coded
        # body.  A raising descriptor is not AttributeError, so the getattr
        # default does not catch it; the try does.
        iso = getattr(value, "isoformat", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 a coded error body.
            return _jsonable_param(iso(), depth + 1)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    try:
        text = str(value)
    except RecursionError:
        # Type name used to leak into params as ``"Recursing"`` and look like a
        # real stack id; drop the value instead.
        return None
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    if not _isinst(text, str):
        return None
    try:
        return str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def jsonable_error_detail(value):
    """Sanitize a non-coded error body for Starlette's allow_nan=False encoder.

    Coded errors go through ``error_payload`` and are cleaned there.  FastAPI's
    own validation handler builds its body from the request, so it needs the
    same treatment before the response is rendered.
    """
    return _jsonable_param(value)


def _clean_code(code) -> str:
    """Launder *code* to an exact, UTF-8-renderable str before it is used.

    The code a caller hands ``error_payload`` used to reach the ``CODES``
    lookup and the response body *raw*, so a leftover riding the code slot
    500'd the error path four different ways:

    * a str subclass whose ``__hash__`` raises blew ``CODES.get`` itself;
    * a str subclass that hash-shadows a real code's slot and raises from
      ``__eq__`` blew the same lookup during the collision probe (the dict
      compares the *stored* exact key against the query, and the reflected
      comparison dispatches into the subclass first);
    * a lying-``__class__`` impostor claiming str skipped the str() coercion
      and blew the unbound ``str.encode(message, ...)`` outside any try;
    * a non-str object (or an exact str carrying a lone surrogate) rode into
      ``detail["code"]`` untouched and 500'd Starlette's own render —
      ``TypeError: not JSON serializable`` / ``UnicodeEncodeError``.

    A genuine str subclass keeps its text (a hash-bomb wrapper around a real
    code still answers that code's status), an impostor degrades through
    ``str()``, and an unrenderable leftover drops to a stable placeholder —
    the unknown-code 500 contract, but as valid JSON instead of a crash.
    """
    if _isinst(code, str):
        try:
            # Unbound str.encode: launders a genuine subclass to an exact str
            # (dropping its __hash__/__eq__/encode overrides with it) and
            # rejects a lying-``__class__`` impostor with TypeError.
            return str.encode(code, "utf-8", "replace").decode("utf-8")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass  # not really a str — degrade through str() below
    try:
        text = str(code)
        return str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return "error.unrenderable"


def error_payload(code: str, /, **params) -> tuple[int, dict]:
    """(http status, response body) for *code* — the shape the SPA parses.

    Middleware cannot raise HTTPException (there is no handler above it to catch
    it), so it needs the body directly.  Sharing this builder keeps middleware
    rejections translatable instead of falling back to hardcoded prose.
    """
    # Launder first: CODES keys are exact strs, so once the code is one too
    # the lookup below cannot dispatch into a leftover __hash__/__eq__.
    code = _clean_code(code)
    status, template = CODES.get(code, (500, code))
    try:
        message = template.format(**params) if params else template
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # RecursionError: leftover recursive ``__format__``/``__str__`` is not
        # ValueError; OverflowError: leftover inf width/precision.  A leftover
        # param referenced by a ``{placeholder}`` is formatted *raw*, before
        # the clean loop below sees it, so a subclass ``__format__``/``__str__``
        # bomb (RuntimeError, not one of the arithmetic errors) used to raise
        # straight out here — a raw 500 for the coded error's own body.
        # ``except BaseException``: the json9 guard stopped at ``Exception``,
        # so the same bomb raising a *BaseException* subclass kept 500'ing
        # every coded route that formatted the poisoned param — the format
        # step runs before ``_jsonable_param`` can drop the value.
        message = template
    # Leftover ``\\ud800`` in a formatted param used to 500 the error body
    # under Starlette's UTF-8 encode even after params themselves were cleaned.
    if not isinstance(message, str):
        try:
            message = str(message)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            message = template if isinstance(template, str) else code
    # Unbound str.encode: ``str.format`` yields an exact str, but the
    # ``str(message)`` fallback above keeps a str *subclass* whose ``__str__``
    # returns itself, so a bound ``.encode`` could dispatch into a leftover
    # override — the json6 self-``__str__`` encode bomb.
    message = str.encode(message, "utf-8", "replace").decode("utf-8")
    detail: dict = {"code": code, "message": message}
    if params:
        clean = {}
        for k, v in params.items():
            if not isinstance(k, str):
                try:
                    k = str(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            k = str.encode(k, "utf-8", "replace").decode("utf-8")
            clean[k] = _jsonable_param(v)
        detail["params"] = clean
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


def exc_detail(exc, cap: int = 200) -> str:
    """Safe exception text for coded errors.

    RecursionError on ``str(e)`` is not ValueError; leftover ``\\ud800`` in
    the message used to 500 Starlette's UTF-8 encode of GET /api/photoshub.
    """
    # ``str(HTTPException)`` is ``"404: {'code': 'nginx.conf_missing',
    # 'message': 'nginx.conf is missing'}"`` -- a Python dict repr, which the
    # health page rendered verbatim when nginx_overview() raised through
    # _nginx_pair().  Unwrap it: a bare code is what errText() translates, and
    # a params-bearing error keeps the already-formatted English message
    # because errText() would only surface its unfilled {placeholders}.
    try:
        # One read, inside a try: a leftover HTTPException subclass whose
        # ``detail`` is a *raising property* used to blow the unwrap itself
        # (and ``isinstance`` reads a raising ``__class__`` — the json8 rule).
        detail = exc.detail if _isinst(exc, HTTPException) else None
    except _CONTROL_FLOW:
        raise
    except BaseException:
        detail = None
    if _isinst(detail, dict):
        # Unbound dict.get, each lookup in its own try: a detail dict
        # *subclass* whose bound ``.get`` is overridden to raise, and a stored
        # key that hash-shadows "params"/"message"/"code" with a raising
        # ``__eq__`` (the dict compares the *stored* key against the query)
        # each used to raise straight out of the coded-error path.  Per-field
        # guards keep the healthy siblings answering instead of dropping the
        # whole unwrap to the repr tail.
        try:
            params = dict.get(detail, "params")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            params = None
        try:
            has_params = bool(params)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A params value whose ``__bool__`` bombs is still params-bearing
            # — keep the already-formatted message like any coded error whose
            # params filled its {placeholders}.
            has_params = True
        try:
            picked = dict.get(detail, "message" if has_params else "code")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            picked = None
        if picked is None and has_params:
            # The message slot is missing or hash-shadowed by a bomb key —
            # a bare code still beats the dict-repr tail below.
            try:
                picked = dict.get(detail, "code")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                picked = None
        if _isinst(picked, str):
            try:
                text = str.encode(picked, "utf-8", "replace").decode("utf-8")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                # A lying-``__class__`` impostor claiming str rejects the
                # unbound encode — fall through to the guarded str(exc) tail.
                text = ""
            # Truthiness on the laundered *exact* str: ``and picked`` used to
            # dispatch into a str-subclass ``__bool__`` bomb.
            if text:
                return text[: max(0, cap)]
    try:
        text = str(exc)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return "error"
    if not isinstance(text, str):
        try:
            text = str(text)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return "error"
    # Unbound base encode: ``str(exc)`` hands back the exception's *message
    # object* when it is already a str — a str-subclass ``encode`` bomb riding
    # an exception message used to raise out of the coded-error path itself
    # and turn the coded response into an uncoded 500.
    return str.encode(text, "utf-8", "replace").decode("utf-8")[: max(0, cap)]


def api_error(code: str, /, **params) -> HTTPException:
    """Build an HTTPException carrying a machine-readable code.

    Unknown codes degrade to HTTP 500 with the code as the message rather than
    raising, so a typo in a rarely-hit branch never masks the real failure.
    """
    status, body = error_payload(code, **params)
    return HTTPException(status, body["detail"])


def api_error_from(exc) -> HTTPException:
    """:func:`api_error` from a typed service error's ``code``/``params`` slots.

    Routers translate typed service errors (WireGuardError, NfsConfigError,
    RaidError, ShareValidationError, ShareAclError) into coded HTTP errors
    inside their ``except`` clauses.  The old shape read ``exc.code`` bare and
    unpacked ``**exc.params`` *at the call site* — one step ahead of every
    guard ``error_payload`` carries — so a leftover subclass riding the
    typed-error seam turned the coded 4xx into a raw HTTP 500 four ways:

    * ``code`` as a *raising property* blew the attribute read itself;
    * ``params`` as a raising property did the same;
    * a non-mapping ``params`` TypeError'd CPython's ``**`` keyword rebuild
      before the call even began;
    * a mapping carrying a non-str key blew the same rebuild with
      "keywords must be strings".

    Guarded reads instead: an unreadable/absent code takes the same
    ``error.unrenderable`` placeholder as :func:`_clean_code` (the
    unknown-code 500 contract, as valid JSON instead of a crash); the params
    mapping is rebuilt over unbound ``dict.items`` — the C-level storage,
    matching what a healthy ``**`` unpack reads, so a subclass ``items()``
    bomb cannot vaporize honest entries — with each key laundered to an
    exact str and each unusable entry dropped alone.  Values stay raw here:
    ``error_payload`` already launders them, and pre-coercing would change
    the formatted message for healthy params.

    ``except BaseException`` on every guard (the modules12/logs12 rule): the
    json12 seam stopped at ``Exception``, so the *same four shapes* raising a
    BaseException subclass out of their hooks sailed past every catch above
    and 500'd the same converted routes all over again — the property read,
    the items rebuild and the key laundering each re-opened one step of the
    seam they had just sealed.  Only genuine control flow keeps propagating.
    """
    try:
        code = getattr(exc, "code", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A raising ``code`` property is not AttributeError, so the getattr
        # default does not catch it; the try does.
        code = None
    if code is None:
        code = "error.unrenderable"
    try:
        raw = getattr(exc, "params", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        raw = None
    params: dict = {}
    if _isinst(raw, dict):
        try:
            items = list(dict.items(raw))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A lying-``__class__`` impostor claiming dict rejects the
            # unbound read — the code alone still answers its status.
            items = []
        for entry in items:
            try:
                k, v = entry
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
            if not _isinst(k, str):
                try:
                    k = str(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            try:
                key = str.encode(k, "utf-8", "replace").decode("utf-8")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
            params[key] = v
    status, body = error_payload(code, **params)
    return HTTPException(status, body["detail"])
