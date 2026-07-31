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
    "auth.cannot_disable": (400, "authentication cannot be disabled"),
    "auth.password_too_short": (400, "password must be at least {min} characters"),
    "auth.password_reused": (400, "the new password must differ from the current one"),
    "auth.username_required": (400, "username is required"),
    "auth.admin_required": (403, "administrator access is required"),
    "auth.cross_site_denied": (403, "cross-site write requests are refused"),
    "auth.bad_origin": (400, "invalid Origin header"),
    "auth.local_token_required": (400, "localhost clients require a dedicated token"),
    # ── native launcher ───────────────────────────────────────────────────────
    "launcher.browser_session_required": (401, "a signed-in browser session is required"),
    "launcher.admin_required": (403, "administrator access is required"),
    "launcher.bad_action": (400, "unsupported panel action: {action}"),
    # ── macOS sharing ────────────────────────────────────────────────────────
    "shares.browser_session_required": (401, "a signed-in browser session is required"),
    "shares.admin_required": (403, "administrator access is required"),
    "shares.bad_name": (400, "share names must be 1-64 characters without slashes"),
    "shares.bad_path": (400, "the shared path must be an existing absolute directory"),
    "shares.protected_path": (403, "this directory is protected and cannot be shared"),
    "shares.exists": (409, "a share with this record name already exists"),
    "shares.not_found": (404, "the requested share was not found"),
    "shares.unknown_service": (400, "unsupported macOS sharing service: {service}"),
    "shares.confirm_required": (400, "removing a share requires confirm=true"),
    "shares.authorization_cancelled": (409, "macOS administrator authorization was cancelled"),
    "shares.authorization_unavailable": (503, "macOS administrator authorization is unavailable"),
    "shares.authorization_failed": (500, "macOS administrator authorization failed"),
    "shares.verification_failed": (409, "macOS did not report the requested sharing state"),
    "shares.operation_failed": (500, "the macOS sharing operation failed"),
    "shares.settings_open_failed": (500, "System Settings could not be opened on this Mac"),
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
    # ── optional FileBrowser process ────────────────────────────────────────
    "files.fb_not_installed": (404, "FileBrowser is not installed (~/Services/filebrowser)"),
    "files.fb_start_failed": (500, "could not start FileBrowser"),
    # ── storage pool (JBOD union planner) ───────────────────────────────────
    "storage_pool.bad_policy": (400, "unknown placement policy: {policy}"),
    "storage_pool.no_members": (400, "select at least one volume for the pool"),
    "storage_pool.not_poolable": (400, "{mount} cannot join a pool (system or unmounted)"),
    "files.fb_no_plist": (404, "local.filebrowser.plist not found"),
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


def api_error(code: str, /, **params) -> HTTPException:
    """Build an HTTPException carrying a machine-readable code.

    Unknown codes degrade to HTTP 500 with the code as the message rather than
    raising, so a typo in a rarely-hit branch never masks the real failure.
    """
    status, body = error_payload(code, **params)
    return HTTPException(status, body["detail"])
