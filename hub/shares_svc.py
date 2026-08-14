"""macOS sharing settings and configured file-service overview.

System mutations are deliberately narrow: request models supply values, this
module builds fixed argv for Apple tools, and every operation is verified by a
fresh read. No API caller can submit a command, launchd label, or executable.
"""
from __future__ import annotations

import json
import os
import re
import socket
from pathlib import Path

from hub.config import cfg
from hub.host_address import host_ip, resolve_value
from hub.macos_admin import run_admin, run_admin_sequence
from hub.path_policy import path_inside, sensitive_export_roots
from hub.util import fan_out, port_open, sh

SHARING = "/usr/sbin/sharing"
SYSTEMSETUP = "/usr/sbin/systemsetup"
LAUNCHCTL = "/bin/launchctl"
OPEN = "/usr/bin/open"
ASSET_CACHE = "/usr/bin/AssetCacheManagerUtil"
SCREEN_SHARING_PLIST = "/System/Library/LaunchDaemons/com.apple.screensharing.plist"
SETTINGS_URL = "x-apple.systempreferences:com.apple.Sharing-Settings.extension"
VNC_PORT = 5900

_NAME_RE = re.compile(r"^[^/\\\x00-\x1f\x7f]{1,64}$")
_SYSTEM_ROOTS = tuple(
    Path(value).resolve()
    for value in (
        "/System", "/Library", "/bin", "/sbin", "/usr", "/private",
        "/etc", "/var", "/dev",
    )
)
_SENSITIVE_ROOTS = sensitive_export_roots()


class ShareValidationError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _field_value(line: str, key: str) -> str | None:
    """Parse legacy ``sharing -l`` key/value output."""
    stripped = line.strip()
    prefix = key + ":"
    if not stripped.startswith(prefix):
        return None
    value = stripped[len(prefix):].strip().lstrip("\t ")
    if len(value) >= 2 and value[0] in "\"“'" and value[-1] in "\"”'":
        value = value[1:-1]
    return value


def _legacy_shares(output: str) -> list[dict]:
    shares: list[dict] = []
    current: dict | None = None
    in_smb = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("name:") and not in_smb:
            name = _field_value(line, "name") or ""
            raw = line.split(":", 1)[1].strip().lstrip("\t ") if ":" in line else name
            if current:
                shares.append(current)
            current = {
                "record_name": raw or name,
                "name": raw or name,
                "path": None,
                "smb_name": None,
                "shared": None,
                "guest": None,
                "readonly": None,
                "encrypted": None,
            }
            in_smb = False
            continue
        if not current:
            continue
        if stripped.startswith("path:"):
            current["path"] = _field_value(line, "path")
        elif stripped.startswith("smb:"):
            in_smb = True
        elif in_smb and stripped.startswith("}"):
            in_smb = False
        elif in_smb:
            if stripped.startswith("name:"):
                current["smb_name"] = line.split(":", 1)[1].strip().lstrip("\t ")
            elif stripped.startswith("shared:"):
                current["shared"] = stripped.split(":", 1)[1].strip() in ("1", "true", "yes")
            elif stripped.startswith("guest access:"):
                current["guest"] = stripped.split(":", 1)[1].strip() in ("1", "true", "yes")
            elif stripped.startswith("read-only:"):
                current["readonly"] = stripped.split(":", 1)[1].strip() in ("1", "true", "yes")
            elif stripped.startswith("sealed:"):
                current["encrypted"] = stripped.split(":", 1)[1].strip() in ("1", "true", "yes")
    if current:
        shares.append(current)
    return shares


def _flag(value: object) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _json_shares(output: str) -> list[dict]:
    parsed = json.loads(output)
    if not isinstance(parsed, dict):
        raise ValueError("sharing JSON is not an object")
    result = []
    for record_name, raw in parsed.items():
        if not isinstance(raw, dict):
            continue
        path = raw.get("path")
        smb_name = raw.get("smb_name") or str(record_name)
        result.append({
            "record_name": str(record_name),
            "name": str(record_name),
            "path": str(path) if path else None,
            "smb_name": str(smb_name),
            "shared": _flag(raw.get("smb_shared")),
            "guest": _flag(raw.get("smb_guest_access")),
            "readonly": _flag(raw.get("smb_read_only")),
            "encrypted": _flag(raw.get("smb_sealed")),
        })
    return result


def _dir_size_mb(path: str) -> float | None:
    expanded = os.path.expanduser(path)
    if not os.path.isdir(expanded):
        return None
    rc, output, _ = sh(["/usr/bin/du", "-sm", expanded], timeout=15)
    if rc != 0 or not output:
        return None
    try:
        return float(output.split()[0])
    except (ValueError, IndexError):
        return None


def _connection_url(smb_name: str | None) -> str | None:
    if not smb_name:
        return None
    return f"smb://{host_ip()}/{smb_name}"


def list_smb_shares(*, include_sizes: bool = True) -> list[dict]:
    rc, output, _ = sh([SHARING, "-l", "-f", "json"], timeout=8)
    shares: list[dict]
    if rc == 0 and output:
        try:
            shares = _json_shares(output)
        except (TypeError, ValueError, json.JSONDecodeError):
            shares = []
    else:
        shares = []
    if not shares:
        legacy_rc, legacy_output, _ = sh([SHARING, "-l"], timeout=8)
        shares = _legacy_shares(legacy_output) if legacy_rc == 0 else []
    # `du -sm` per share, and on a share holding real data it runs for seconds --
    # the timeout is 15 of them.  Serially the listing cost the sum, so a handful of
    # populated shares could hold the page past a minute; they are separate trees
    # with no shared state, so they are walked concurrently.  `fan_out` preserves the
    # order `sharing` reported, which is what the table renders.
    wanted = [
        index
        for index, share in enumerate(shares)
        if include_sizes and share.get("path")
    ]
    measured = fan_out(lambda i: _dir_size_mb(str(shares[i]["path"])), wanted)
    sizes = dict(zip(wanted, measured))
    for index, share in enumerate(shares):
        share["size_mb"] = sizes.get(index)
        share["url"] = _connection_url(share.get("smb_name"))
    return shares


def _validate_name(value: str) -> str:
    normalized = str(value or "").strip()
    if not _NAME_RE.fullmatch(normalized):
        raise ShareValidationError("shares.bad_name")
    # Every current call site puts the name in a flag-argument slot (`-n <name>`,
    # `-e <record>`, `-r <record>`), where getopt consumes it unconditionally.
    # That is what makes a leading hyphen harmless *today* -- which is a property
    # of the argv layout, not of the value, so it stops holding the moment an
    # argument is repositioned.  A share name starting with "-" is never
    # intentional, so pin it here instead of relying on `sharing`'s parser.
    # Not cli_args._SAFE_POSITIONAL: that demands an ASCII alphanumeric first
    # character and would reject legitimate non-Latin share names.
    if normalized.startswith("-"):
        raise ShareValidationError("shares.bad_name")
    return normalized


def _inside(path: Path, root: Path) -> bool:
    return path_inside(path, root)


def validate_share_path(value: str) -> Path:
    raw = Path(str(value or "")).expanduser()
    if not raw.is_absolute():
        raise ShareValidationError("shares.bad_path")
    try:
        resolved = raw.resolve(strict=True)
    except OSError as error:
        raise ShareValidationError("shares.bad_path") from error
    if not resolved.is_dir() or resolved == Path("/"):
        raise ShareValidationError("shares.bad_path")
    if any(_inside(resolved, root) for root in _SYSTEM_ROOTS):
        raise ShareValidationError("shares.protected_path")
    # Also reject a parent of a protected tree. Sharing ~/Services, for example,
    # would expose the ServerHub state nested below it even though the selected
    # directory itself is not inside STATE_ROOT.
    if any(
        _inside(resolved, root) or _inside(root, resolved)
        for root in _SENSITIVE_ROOTS
    ):
        raise ShareValidationError("shares.protected_path")
    return resolved


def _find_share(record_name: str) -> dict | None:
    return next(
        (share for share in list_smb_shares(include_sizes=False) if share["record_name"] == record_name),
        None,
    )


def _sharing_flags(*, guest: bool, readonly: bool, encrypted: bool) -> list[str]:
    return [
        "-s", "001",
        "-g", "001" if guest else "000",
        "-R", "1" if readonly else "0",
        "-E", "1" if encrypted else "0",
    ]


def _admin_failure(result: dict) -> dict:
    return {
        "ok": False,
        "error": result.get("error") or "failed",
        "message": result.get("message") or "",
    }


def create_smb_share(
    *, path: str, name: str, smb_name: str, guest: bool,
    readonly: bool, encrypted: bool,
) -> dict:
    directory = validate_share_path(path)
    record = _validate_name(name)
    smb = _validate_name(smb_name)
    if _find_share(record):
        return {"ok": False, "error": "exists"}
    command = [
        SHARING, "-a", str(directory), "-n", record, "-S", smb,
        *_sharing_flags(guest=guest, readonly=readonly, encrypted=encrypted),
    ]
    result = run_admin(command)
    if not result.get("ok"):
        return _admin_failure(result)
    actual = _find_share(record)
    expected = {
        "smb_name": smb, "shared": True, "guest": guest,
        "readonly": readonly, "encrypted": encrypted,
    }
    if not actual or any(actual.get(key) != value for key, value in expected.items()):
        return {"ok": False, "error": "verification_failed"}
    return {"ok": True, "share": actual}


def update_smb_share(
    record_name: str, *, smb_name: str, guest: bool,
    readonly: bool, encrypted: bool,
) -> dict:
    record = _validate_name(record_name)
    smb = _validate_name(smb_name)
    if not _find_share(record):
        return {"ok": False, "error": "not_found"}
    command = [
        SHARING, "-e", record, "-S", smb,
        *_sharing_flags(guest=guest, readonly=readonly, encrypted=encrypted),
    ]
    result = run_admin(command)
    if not result.get("ok"):
        return _admin_failure(result)
    actual = _find_share(record)
    expected = {
        "smb_name": smb, "shared": True, "guest": guest,
        "readonly": readonly, "encrypted": encrypted,
    }
    if not actual or any(actual.get(key) != value for key, value in expected.items()):
        return {"ok": False, "error": "verification_failed"}
    return {"ok": True, "share": actual}


def remove_smb_share(record_name: str) -> dict:
    record = _validate_name(record_name)
    if not _find_share(record):
        return {"ok": False, "error": "not_found"}
    result = run_admin([SHARING, "-r", record])
    if not result.get("ok"):
        return _admin_failure(result)
    if _find_share(record):
        return {"ok": False, "error": "verification_failed"}
    return {"ok": True}


def _probe_port(port) -> bool | None:
    """Port reachability that never raises, for use inside the pool."""
    try:
        return port_open(port)
    except Exception:
        return False


def file_services() -> list[dict]:
    services = [
        {"id": "filebrowser", "name": "FileBrowser", "port": 8125, "url": None},
        {"id": "onedrive-share", "name": "OneDrive Share", "port": 8281, "url": None},
    ]
    host = host_ip()
    links = {
        link["name"]: link["url"]
        for link in resolve_value(cfg().get("quick_links") or [])
    }
    # Each probe waits out the full connect timeout when nothing is listening, so
    # in series the shares page paid that once per service before rendering.
    # Only the socket waits fan out -- no privileged call is involved here, which
    # matters because this module also uses run_admin, and the administrator
    # password is not visible inside a worker thread.
    reachable = fan_out(_probe_port, [service["port"] for service in services])
    for service, up in zip(services, reachable):
        service["url"] = links.get(service["name"], f"http://{host}:{service['port']}")
        service["state"] = "ok" if up else "down"
        service["detail"] = f"port :{service['port']} " + ("reachable" if up else "unreachable")
    return services


def _launchd_state(label: str) -> tuple[bool | None, str]:
    rc, output, error = sh([LAUNCHCTL, "print", f"system/{label}"], timeout=4)
    if rc == 0:
        match = re.search(r"^\s*state\s*=\s*(\S+)", output, re.MULTILINE)
        state = match.group(1) if match else "loaded"
        return True, state
    rc, output, _ = sh([LAUNCHCTL, "print-disabled", "system"], timeout=4)
    if rc == 0:
        match = re.search(rf'"?{re.escape(label)}"?\s*=>\s*(enabled|disabled|true|false)', output)
        if match:
            token = match.group(1)
            return token in {"enabled", "false"}, token
    return None, (error or "unknown")[-160:]


def _systemsetup_state(option: str, label: str) -> tuple[bool | None, str]:
    rc, output, error = sh([SYSTEMSETUP, option], timeout=8)
    combined = (output or error or "").strip()
    if rc == 0:
        lowered = combined.lower()
        if ": on" in lowered or lowered.endswith(" on"):
            return True, combined
        if ": off" in lowered or lowered.endswith(" off"):
            return False, combined
    fallback, detail = _launchd_state(label)
    return fallback, combined or detail


def _content_cache_state() -> tuple[bool | None, str]:
    rc, output, error = sh([ASSET_CACHE, "status"], timeout=12)
    combined = (output or error or "").strip()
    if rc != 0:
        return None, combined[-300:] or "unknown"
    activated = re.search(r"^\s*Activated:\s*(true|false)", output, re.I | re.M)
    active = re.search(r"^\s*Active:\s*(true|false)", output, re.I | re.M)
    if not activated:
        return None, "status unavailable"
    enabled = activated.group(1).lower() == "true"
    detail = "active" if active and active.group(1).lower() == "true" else ("starting" if enabled else "inactive")
    return enabled, detail


def _service(
    id_: str, enabled: bool | None, *, controllable: bool,
    requires_admin: bool, detail: str, confidence: str,
) -> dict:
    return {
        "id": id_,
        "enabled": enabled,
        "controllable": controllable,
        "requires_admin": requires_admin,
        "detail": detail,
        "confidence": confidence,
        "settings_url": SETTINGS_URL,
    }


def system_services() -> list[dict]:
    """macOS sharing services, probed together.

    Five unrelated questions: a launchd label, a VNC connect, two `systemsetup`
    reads and the content-cache status. `systemsetup` in particular is slow enough
    to notice on its own, and asking these in turn made the page cost their sum.
    """
    (
        (screen_launchd, screen_detail),
        screen_port,
        (remote_login, remote_login_detail),
        (apple_events, apple_events_detail),
        (content_cache, content_detail),
    ) = fan_out(
        lambda probe: probe(),
        [
            lambda: _launchd_state("com.apple.screensharing"),
            lambda: bool(port_open(VNC_PORT, host="localhost", timeout=0.4)),
            lambda: _systemsetup_state("-getremotelogin", "com.openssh.sshd"),
            lambda: _systemsetup_state("-getremoteappleevents", "com.apple.AEServer"),
            _content_cache_state,
        ],
        max_workers=5,
    )
    screen_enabled = True if screen_port else screen_launchd
    return [
        _service(
            "screen_sharing", screen_enabled, controllable=True, requires_admin=True,
            detail=(f"VNC :{VNC_PORT} listening" if screen_port else screen_detail),
            confidence="high" if screen_port or screen_launchd is not None else "unknown",
        ),
        _service(
            "remote_login", remote_login, controllable=True, requires_admin=True,
            detail=remote_login_detail, confidence="high" if remote_login is not None else "unknown",
        ),
        _service(
            "remote_apple_events", apple_events, controllable=True, requires_admin=True,
            detail=apple_events_detail, confidence="high" if apple_events is not None else "unknown",
        ),
        _service(
            "content_caching", content_cache, controllable=True, requires_admin=True,
            detail=content_detail, confidence="high" if content_cache is not None else "unknown",
        ),
        *[
            _service(
                id_, None, controllable=False, requires_admin=True,
                detail="Manage this service in System Settings", confidence="unknown",
            )
            for id_ in (
                "remote_management", "media_sharing", "printer_sharing",
                "internet_sharing", "bluetooth_sharing",
            )
        ],
    ]


_SERVICE_COMMANDS = {
    "remote_login": lambda enabled: [[SYSTEMSETUP, "-setremotelogin", "on" if enabled else "off"]],
    "remote_apple_events": lambda enabled: [[SYSTEMSETUP, "-setremoteappleevents", "on" if enabled else "off"]],
    "content_caching": lambda enabled: [[ASSET_CACHE, "activate" if enabled else "deactivate"]],
    "screen_sharing": lambda enabled: (
        [
            [LAUNCHCTL, "enable", "system/com.apple.screensharing"],
            [LAUNCHCTL, "bootstrap", "system", SCREEN_SHARING_PLIST],
        ]
        if enabled else [
            [LAUNCHCTL, "bootout", "system/com.apple.screensharing"],
            [LAUNCHCTL, "disable", "system/com.apple.screensharing"],
        ]
    ),
}


def set_system_service(service_id: str, enabled: bool) -> dict:
    if service_id not in _SERVICE_COMMANDS:
        return {"ok": False, "error": "unknown_service"}
    current = next(item for item in system_services() if item["id"] == service_id)
    if current["enabled"] is enabled:
        return {"ok": True, "service": current}

    result = run_admin_sequence(_SERVICE_COMMANDS[service_id](enabled))
    actual = next(item for item in system_services() if item["id"] == service_id)
    if actual["enabled"] is enabled:
        return {"ok": True, "service": actual}
    if not result.get("ok"):
        return _admin_failure(result)
    return {"ok": False, "error": "verification_failed", "service": actual}


def open_system_settings() -> dict:
    rc, output, error = sh([OPEN, SETTINGS_URL], timeout=12)
    if rc != 0:
        rc, output, error = sh([OPEN, "-a", "System Settings"], timeout=12)
    return {
        "ok": rc == 0,
        "message": (error or output or "")[-300:],
    }


def shares_overview() -> dict:
    """The shares page payload.

    `host_ip`, the macOS service probes, the SMB share list and the file-service
    probes are independent of one another, so they go in one wave rather than four.
    `file_services()` is read once and used for both keys: the `services` key is a
    compatibility alias for clients released before the grouped response, and
    calling the function twice ran every file-service probe twice to produce two
    identical lists.
    """
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = ""
    host, services, smb, files = fan_out(
        lambda probe: probe(),
        [host_ip, system_services, list_smb_shares, file_services],
        max_workers=4,
    )
    return {
        "host": {
            "name": hostname,
            "address": host,
            "smb_url": f"smb://{host}",
            "vnc_url": f"vnc://{host}:{VNC_PORT}",
        },
        "system_services": services,
        "smb": smb,
        "file_services": files,
        # Compatibility for clients released before the grouped response.
        "services": files,
        "capabilities": {
            "smb_management": True,
            "system_settings_fallback": True,
            "password_handling": "macos-native-dialog",
        },
    }
