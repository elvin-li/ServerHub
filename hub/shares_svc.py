"""macOS sharing settings and configured file-service overview.

System mutations are deliberately narrow: request models supply values, this
module builds fixed argv for Apple tools, and every operation is verified by a
fresh read. No API caller can submit a command, launchd label, or executable.
"""
from __future__ import annotations

import json
import os
import plistlib
import re
import signal
import socket
import subprocess
import threading
from pathlib import Path
from uuid import uuid4

from hub.config import cfg
from hub.host_address import host_ip, resolve_value
from hub.macos_admin import run_admin, run_admin_sequence
from hub.paths import BASE, STATE_ROOT, user_home
from hub.util import fan_out, iter_capped_lines, port_open, safe_json_loads, sh, ttl_memo, utf8_env

SHARING = "/usr/sbin/sharing"
DSCL = "/usr/bin/dscl"
DNS_SD = "/usr/bin/dns-sd"
SMB_PORT = 445
_SHAREPOINTS = "/SharePoints"
SYSTEMSETUP = "/usr/sbin/systemsetup"
LAUNCHCTL = "/bin/launchctl"
OPEN = "/usr/bin/open"
ASSET_CACHE = "/usr/bin/AssetCacheManagerUtil"
SCREEN_SHARING_PLIST = "/System/Library/LaunchDaemons/com.apple.screensharing.plist"
SETTINGS_URL = "x-apple.systempreferences:com.apple.Sharing-Settings.extension"
VNC_PORT = 5900

_NAME_RE = re.compile(r"^[^/\\\x00-\x1f\x7f]{1,64}$")


def _safe_resolve(path: Path) -> Path:
    """``Path.resolve`` leftover symlink loops raise RuntimeError, not OSError."""
    try:
        return path.resolve()
    except (OSError, RuntimeError, ValueError):
        return path


_SYSTEM_ROOTS = tuple(
    _safe_resolve(Path(value))
    for value in (
        "/System", "/Library", "/bin", "/sbin", "/usr", "/private",
        "/etc", "/var", "/dev",
    )
)
def _home_sensitive_roots() -> tuple[Path, ...]:
    """Skip leftover HOME unset/NUL instead of failing the shares import."""
    home = user_home()
    if home is None:
        return ()
    out: list[Path] = []
    for parts in ((".ssh",), (".aws",), (".gnupg",), (".kube",), ("Library", "Keychains")):
        try:
            out.append(home.joinpath(*parts).resolve())
        except (OSError, RuntimeError, ValueError):
            continue
    return tuple(out)


_SENSITIVE_ROOTS = (
    _safe_resolve(BASE),
    _safe_resolve(STATE_ROOT),
) + _home_sensitive_roots()


class ShareValidationError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _as_text(value) -> str:
    """``sharing`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used to 500 GET /api/shares."""
    if isinstance(value, (bytes, bytearray)):
        # Unbound base decode (the brew6 rule): a leftover bytes-subclass
        # whose bound ``.decode`` raises used to escape list_smb_shares'
        # parse guards and 500 GET /api/shares/acl through the share gate.
        base = bytes if isinstance(value, bytes) else bytearray
        value = base.decode(value, "utf-8", "replace")
    elif value is None:
        return ""
    else:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    return value.encode("utf-8", "replace").decode("utf-8")


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb (fails False)."""
    try:
        return bool(value)
    except Exception:
        return False


def _plain_result(result) -> dict:
    """A privileged-helper result as a plain dict with a real bool ``ok``.

    A leftover dict-*subclass* result from run_admin / run_admin_sequence
    (the jobs/metrics row-bomb class: passes an isinstance gate, then
    ``.get()`` raises) used to 500 every share mutation right out of
    ``if not result.get("ok")``, and a ``__bool__``-bomb ``ok`` value blew
    the same read.  ``dict()`` copies through the C-level storage, so an
    overridden method cannot fire; junk shapes degrade to the coded failure.
    """
    if isinstance(result, dict):
        try:
            plain = dict(result)
        except Exception:
            return {"ok": False, "error": "failed"}
    else:
        return {"ok": False, "error": "failed"}
    plain["ok"] = _truthy(plain.get("ok"))
    return plain


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
    for line in _as_text(output).splitlines():
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


def _int_capped(digits: str):
    """``json.loads`` *parse_int* hook that survives >4300-digit literals.

    CPython's int(str) digit cap makes the decoder itself raise ValueError —
    not JSONDecodeError — on a leftover huge number, so one poisoned field in
    ``sharing -l -f json`` used to wipe the *whole* SMB listing: the page and
    the ACL share gate silently lost every share and update/remove answered a
    404 lie.  A number past the cap cannot be rendered by any JSON encoder
    anyway, so it loads as None (the docker_cli.parse_int_capped drop).
    """
    try:
        return int(digits)
    except ValueError:
        return None


def _json_shares(output: str) -> list[dict]:
    try:
        parsed = safe_json_loads(output, parse_int=_int_capped)
    except (TypeError, ValueError, RecursionError) as e:
        # RecursionError: leftover deeply-nested ``sharing -l -f json`` is
        # not ValueError; GET /api/shares used to 500.
        raise ValueError("sharing JSON is not an object") from e
    if not isinstance(parsed, dict):
        raise ValueError("sharing JSON is not an object")
    result = []
    for record_name, raw in parsed.items():
        if not isinstance(raw, dict):
            continue
        path = raw.get("path")
        smb_name = raw.get("smb_name") or str(record_name)
        result.append({
            "record_name": _as_text(record_name),
            "name": _as_text(record_name),
            "path": _as_text(path) if path else None,
            "smb_name": _as_text(smb_name),
            "shared": _flag(raw.get("smb_shared")),
            "guest": _flag(raw.get("smb_guest_access")),
            "readonly": _flag(raw.get("smb_read_only")),
            "encrypted": _flag(raw.get("smb_sealed")),
        })
    return result


# ── Time Machine destination attributes ─────────────────────────────────────
#
# `sharing` on this macOS (26.5, checked with `man sharing` and the tool's own
# usage text) has no Time Machine flag at all, so the panel writes the
# share-point record attributes directly with `dscl`, the same records
# `sharing` itself edits.  Attribute-name provenance, since no GUI-enabled TM
# share existed on the dev machine to copy from:
#
# * flag + UUID: the dslocal sharepoint records documented since OS X Server
#   spell them ``timeMachineBackup`` (0/1) and ``timeMachineBackupUUID``, and
#   the File Sharing advanced-options sheet of *this* macOS version
#   (Sharing.appex on 26.5.2) exposes matching ``timeMachineBackupUUID`` /
#   ``isTimeMachineBackupDestination`` properties.
# * quota: Sharing.appex names it ``backupQuotaSize``; assumed to be bytes
#   (every neighbouring Apple quota knob — .com.apple.TimeMachine.quota.plist
#   GlobalQuota, APFS quotas — is bytes).
#
# None of these were verified against a real GUI-created TM share.  That is
# survivable because every write below is verified by a fresh read of the same
# attributes: if Apple renamed them, enabling fails loudly with
# ``verification_failed`` instead of pretending the share is a backup target.
_TM_FLAG_ATTR = "dsAttrTypeNative:timeMachineBackup"
_TM_UUID_ATTR = "dsAttrTypeNative:timeMachineBackupUUID"
_TM_QUOTA_ATTR = "dsAttrTypeNative:backupQuotaSize"
#: Read-side tolerance: spellings reported for GUI-enabled shares on other
#: macOS versions (community dscl dumps), so a share configured outside the
#: panel is still recognized.  Canonical name first.
_TM_FLAG_READ_ATTRS = (_TM_FLAG_ATTR, "dsAttrTypeNative:timemachine")
_TM_QUOTA_READ_ATTRS = (_TM_QUOTA_ATTR, "dsAttrTypeNative:timemachine_quota")
_TM_QUOTA_MAX_GB = 1_000_000
_GB = 1_000_000_000  # decimal, matching how macOS reports disk sizes


def _plist_first(record: dict, key: str) -> str | None:
    """First value of a dscl plist attribute (they are always string arrays).

    A str() probe, not an ``isinstance(str)`` gate: a numeric leftover record
    id must keep behaving as its string form.  XML plists load
    ``<integer>0x…</integer>`` with ``int(x, 16)`` — exempt from CPython's
    int(str) digit cap — so a >4300-digit *already-int* leftover reached the
    bare ``str()`` here, whose digit-cap ValueError escaped the whole record
    loop: every share's Time Machine attributes were wiped (the live reader
    swallows Exception into ``{}``) and leftover dscl-dump callers got an
    untyped raise.  Only the unusable value is dropped; siblings survive.
    """
    values = record.get(key)
    if isinstance(values, list) and values:
        try:
            return str(values[0])
        except ValueError:
            return None
    return None


def parse_time_machine_records(plist_text: str | bytes) -> dict[str, dict]:
    """RecordName -> Time Machine attributes, from `dscl -plist . -readall`."""
    data = plist_text.encode() if isinstance(plist_text, str) else plist_text
    try:
        records = plistlib.loads(data)
    except RecursionError as e:
        # RecursionError: leftover deeply-nested SharePoints plist is not
        # ValueError.  The live reader swallows Exception; this parser is
        # also used on leftover dscl dumps and used to raise untyped.
        raise ValueError("SharePoints plist is not an array") from e
    if not isinstance(records, list):
        raise ValueError("SharePoints plist is not an array")
    result: dict[str, dict] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        name = _plist_first(record, "dsAttrTypeStandard:RecordName")
        if not name:
            continue
        flag = next(
            (value for key in _TM_FLAG_READ_ATTRS
             if (value := _plist_first(record, key)) is not None),
            None,
        )
        quota_raw = next(
            (value for key in _TM_QUOTA_READ_ATTRS
             if (value := _plist_first(record, key)) is not None),
            None,
        )
        try:
            quota_bytes = int(quota_raw) if quota_raw is not None else 0
        except (TypeError, ValueError, OverflowError):
            quota_bytes = 0
        # 0 and absent both mean "no cap" (server-era backupQuota = 0).
        # A 400-digit leftover used to OverflowError the float division and
        # drop every share's TM attributes (the reader wraps this parse).
        try:
            quota_gb = round(quota_bytes / _GB) if quota_bytes > 0 else 0
        except (OverflowError, ValueError):
            quota_gb = 0
        if quota_gb in (float("inf"), float("-inf")) or quota_gb != quota_gb:
            quota_gb = 0
        result[name] = {
            "time_machine": _flag(flag) if flag is not None else False,
            "tm_quota_gb": quota_gb or None,
            "uuid": _plist_first(record, _TM_UUID_ATTR),
        }
    return result


def time_machine_records() -> dict[str, dict]:
    """Live Time Machine state of every share point; {} when unreadable.

    Reading the local directory node needs no privileges, unlike the writes.
    """
    rc, output, _ = sh([DSCL, "-plist", ".", "-readall", _SHAREPOINTS], timeout=8)
    if rc != 0 or not output:
        return {}
    try:
        return parse_time_machine_records(output)
    except Exception:
        return {}


def smb_service_running() -> bool:
    """Whether smbd is accepting connections (File Sharing is on)."""
    try:
        return bool(port_open(SMB_PORT, host="localhost", timeout=0.4))
    except Exception:
        return False


def dns_sd_instances(output: str) -> list[str]:
    """Instance names from `dns-sd -B` browse output ("Add" rows only)."""
    instances = []
    for line in output.splitlines():
        tokens = line.split()
        # Timestamp  A/R  Flags  if  Domain  Service Type  Instance Name…
        if len(tokens) >= 7 and tokens[1] == "Add":
            instances.append(" ".join(tokens[6:]))
    return instances


def _dns_sd_advertised(service_type: str, *, wait: float = 2.5) -> bool | None:
    """Whether any `service_type` instance is advertised on the LAN right now.

    `dns-sd -B` browses forever, so it can never simply be awaited.  Its
    stdout is read line by line and the browse is killed **as soon as the
    first "Add" row arrives** — sharingd usually answers within milliseconds,
    and waiting out the full window on every call held the shares page for
    the whole 2.5s even when the answer was already in.  The window is only
    paid in full when nothing is advertised.  None means the probe itself
    failed, not that nothing is advertised.
    """
    try:
        proc = subprocess.Popen(
            [DNS_SD, "-B", service_type, "local."],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
            env=utf8_env(),
            start_new_session=True,
        )
    except (OSError, ValueError, TypeError):
        # Leftover ``\\ud800`` env UnicodeEncodeError is ValueError, not OSError;
        # GET /api/shares used to 500 the Bonjour browse.
        return None
    if proc.stdout is None:
        return None
    found = threading.Event()

    def _scan():
        # Reader thread because the pipe read blocks and dns-sd never exits
        # on its own; the main thread waits on the event with a deadline.
        # ``for line in stdout`` buffered a whole line — a leftover huge
        # instance name RSS-bombed GET /api/shares for the browse window.
        try:
            for line in iter_capped_lines(proc.stdout, 4096):
                if dns_sd_instances(line):
                    found.set()
                    return
        except (OSError, ValueError):
            pass

    reader = threading.Thread(target=_scan, daemon=True, name="dns-sd-browse")
    reader.start()
    found.wait(wait)
    try:
        try:
            pgid = os.getpgid(proc.pid)
        except (ProcessLookupError, PermissionError, OSError):
            pgid = None
        if pgid is not None and pgid == proc.pid and pgid != os.getpgrp():
            os.killpg(pgid, signal.SIGTERM)
        else:
            proc.kill()
        proc.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass
    reader.join(timeout=1)
    close = getattr(proc.stdout, "close", None)
    if close is not None:
        try:
            close()
        except OSError:
            pass
    return bool(found.is_set())


@ttl_memo(60.0)
def _adisk_advertised() -> bool | None:
    """The `_adisk._tcp` browse, cached for a minute (single-flight).

    Every ``GET /api/shares`` re-ran the browse while a TM share existed —
    up to 2.5s of wall time per page load for an answer that only changes
    when File Sharing or the share set changes.
    """
    return _dns_sd_advertised("_adisk._tcp")


def time_machine_status(shares: list[dict] | None = None) -> dict:
    """Prerequisite state for serving Time Machine clients.

    A share point flagged for Time Machine is only reachable while smbd runs
    (File Sharing in System Settings), and only discoverable in the clients'
    destination picker once sharingd advertises ``_adisk._tcp``.  Both are
    outside the share record itself, so they are reported instead of silently
    assumed; the SPA and the health page turn them into actionable hints.
    """
    if shares is None:
        shares = list_smb_shares(include_sizes=False)
    tm_count = sum(1 for share in shares if share.get("time_machine"))
    return {
        "share_count": tm_count,
        "smb_service_running": smb_service_running(),
        # The Bonjour browse can cost its full window, so it only runs when
        # there is a TM share whose advertisement is worth confirming.
        "adisk_advertised": _adisk_advertised() if tm_count else None,
    }


def _dir_size_mb(path: str) -> float | None:
    try:
        expanded = os.path.expanduser(str(path or ""))
        if not os.path.isdir(expanded):
            return None
    except (TypeError, ValueError, OSError, RuntimeError):
        # RuntimeError: leftover HOME unset on a ``~/…`` share path.
        # ``fan_out`` re-raises, so one row used to 500 GET /api/shares.
        return None
    rc, output, _ = sh(["/usr/bin/du", "-sm", expanded], timeout=15)
    output = _as_text(output)
    if rc != 0 or not output:
        return None
    try:
        value = float(output.split()[0])
    except (ValueError, IndexError):
        return None
    # Starlette JSON-encodes with allow_nan=False; inf from a garbled `du`
    # used to 500 GET /api/shares.
    if value != value or value in (float("inf"), float("-inf")):
        return None
    return value


def _connection_url(smb_name: str | None) -> str | None:
    if not smb_name:
        return None
    return f"smb://{host_ip()}/{smb_name}"


def list_smb_shares(*, include_sizes: bool = True) -> list[dict]:
    rc, output, _ = sh([SHARING, "-l", "-f", "json"], timeout=8)
    shares: list[dict]
    if rc == 0 and output:
        try:
            shares = _json_shares(_as_text(output))
        except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
            # RecursionError: leftover deeply-nested ``sharing -l -f json`` is
            # not ValueError; GET /api/shares/acl and /api/storage/usage used
            # to 500.
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
    # `sharing -l` knows nothing about the Time Machine attributes, so the
    # share-point records are read once and merged into every row.
    tm_records = time_machine_records()
    for index, share in enumerate(shares):
        share["size_mb"] = sizes.get(index)
        share["url"] = _connection_url(share.get("smb_name"))
        tm = tm_records.get(share["record_name"]) or {}
        share["time_machine"] = bool(tm.get("time_machine"))
        share["tm_quota_gb"] = tm.get("tm_quota_gb") if share["time_machine"] else None
    return shares


def _validate_name(value: str) -> str:
    try:
        # A str() probe, not an isinstance gate: a numeric leftover name keeps
        # behaving as its string form, while a >4300-digit *already-int*
        # (YAML/plist hex loads with int(x, 16), exempt from the int(str)
        # parse cap) earns the coded refusal instead of the digit-cap
        # ValueError this bare str() used to raise past the router.
        normalized = str(value or "").strip()
    except ValueError as error:
        raise ShareValidationError("shares.bad_name") from error
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
    try:
        normalized.encode("utf-8")
    except UnicodeEncodeError as error:
        # JSON bodies may carry a lone ``\ud800``; it passes _NAME_RE (a
        # surrogate is neither a slash nor a control character) but no
        # filesystem can hold it, and as_argv refuses surrogate argv — so the
        # create/update used to prompt for the administrator password and
        # *then* answer the 500 "authorization failed".  Refuse it as the
        # coded bad input it is, before any password or spawn.
        raise ShareValidationError("shares.bad_name") from error
    return normalized


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def validate_share_path(value: str) -> Path:
    try:
        raw = Path(str(value or "")).expanduser()
    except (ValueError, TypeError, RuntimeError, OSError) as error:
        # RuntimeError: leftover HOME unset on ``~/Media``.
        # ValueError: leftover ``\\ud800`` (UnicodeEncodeError).
        raise ShareValidationError("shares.bad_path") from error
    if not raw.is_absolute():
        raise ShareValidationError("shares.bad_path")
    try:
        resolved = raw.resolve(strict=True)
        is_dir = resolved.is_dir()
    except (OSError, ValueError, RuntimeError) as error:
        # Symlink loops raise RuntimeError, not OSError — that used to 500 create.
        # resolve() raises ValueError on an embedded NUL (Path() itself does not).
        # is_dir() still raises EIO/ESTALE on a dying mount after resolve().
        raise ShareValidationError("shares.bad_path") from error
    if not is_dir or resolved == Path("/"):
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
    try:
        str(resolved).encode("utf-8")
    except UnicodeEncodeError as error:
        # A real directory whose on-disk name holds undecodable bytes arrives
        # from os.fsdecode as lone ``\udcXX`` surrogates.  It resolves and
        # is_dir()s fine, but as_argv refuses surrogate argv, so the create
        # used to burn the operator's password prompt and answer the 500
        # "authorization failed".  Same refusal as nfs_svc._validate_entry.
        raise ShareValidationError("shares.bad_path") from error
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


def _validate_quota(time_machine: bool, quota_gb) -> int | None:
    if quota_gb is None:
        return None
    if not time_machine:
        raise ShareValidationError("shares.quota_requires_time_machine")
    if (
        isinstance(quota_gb, bool)
        or not isinstance(quota_gb, int)
        or not 1 <= quota_gb <= _TM_QUOTA_MAX_GB
    ):
        raise ShareValidationError("shares.bad_quota")
    return quota_gb


def _time_machine_commands(
    record: str, *, time_machine: bool, quota_gb: int | None, current: dict,
) -> list[list[str]]:
    """dscl argv that reconciles a record's TM attributes with the request.

    Values are always written with ``-create`` (which replaces) rather than
    toggled with ``-delete``: deleting an attribute that is absent — or that an
    older macOS spelled differently — makes the whole privileged sequence
    report failure for a state that is actually correct.
    """
    target = f"{_SHAREPOINTS}/{record}"
    commands: list[list[str]] = []
    if time_machine:
        commands.append([DSCL, ".", "-create", target, _TM_FLAG_ATTR, "1"])
        if not current.get("uuid"):
            # Clients key their backup sets to this identity, so it is minted
            # once and never rotated on subsequent edits.
            commands.append(
                [DSCL, ".", "-create", target, _TM_UUID_ATTR, str(uuid4()).upper()],
            )
        if quota_gb:
            commands.append(
                [DSCL, ".", "-create", target, _TM_QUOTA_ATTR, str(quota_gb * _GB)],
            )
        elif current.get("tm_quota_gb"):
            commands.append([DSCL, ".", "-create", target, _TM_QUOTA_ATTR, "0"])
    else:
        if current.get("time_machine"):
            commands.append([DSCL, ".", "-create", target, _TM_FLAG_ATTR, "0"])
        if current.get("tm_quota_gb"):
            commands.append([DSCL, ".", "-create", target, _TM_QUOTA_ATTR, "0"])
        # The UUID attribute survives a disable: it names the existing backup
        # sets, and keeping it lets a re-enabled share adopt them again.
    return commands


def _tool_on_disk(path: str) -> bool:
    """Fresh disk probe for the mutation-failure paths only (raid/vms rule).

    ``Path.is_file()`` can itself raise on a dying volume (EIO/ESTALE); a disk
    that cannot even answer for /usr/sbin is not confirmably carrying it.
    """
    try:
        return Path(path).is_file()
    except (OSError, ValueError):
        return False


def _sharing_on_disk() -> bool:
    return _tool_on_disk(SHARING)


#: What a spawn of a gone binary reads like through run_admin / sh: the
#: shell's own refusal (``sh: /usr/sbin/sharing: command not found`` / ``No
#: such file or directory``) or sh()'s FileNotFoundError sentinel (``not
#: found``).  Purely a message-pattern gate: classification additionally
#: requires the fresh :func:`_sharing_on_disk` probe to confirm the binary is
#: really gone, and only the generic ``failed`` shape is eligible — timeouts,
#: cancelled sheets and password failures keep their original shape.
_VANISH_MARKERS = ("command not found", "no such file or directory", "not found")


def _admin_failure(
    result: dict, *, sharing_cli: bool = False, system_tool: str | None = None,
) -> dict:
    # _truthy before the ``or``: a leftover ``__bool__``-bomb error/message
    # value used to raise out of the fallback chain itself (callers hand in
    # a _plain_result copy, so the ``.get`` reads themselves are safe).
    raw_error = result.get("error")
    raw_message = result.get("message")
    failure = {
        "ok": False,
        "error": raw_error if _truthy(raw_error) else "failed",
        "message": raw_message if _truthy(raw_message) else "",
    }
    # A sharing CLI that vanished between the listing and the spawn used to
    # surface as the generic 500 "the macOS sharing operation failed", which
    # sends the operator back to a password dialog that cannot help.  The
    # coded 503 fires only on this failure path, after a fresh disk probe.
    # ``system_tool`` is the same rule for the system-service toggles, whose
    # vanished systemsetup/launchctl/AssetCacheManagerUtil used to answer the
    # generic 500 "authorization failed" — after the password was spent.
    if failure["error"] == "failed" and (sharing_cli or system_tool):
        message = _as_text(failure["message"]).lower()
        if any(marker in message for marker in _VANISH_MARKERS):
            if sharing_cli and not _sharing_on_disk():
                return {"ok": False, "error": "sharing_missing"}
            if system_tool and not _tool_on_disk(system_tool):
                return {"ok": False, "error": "system_tool_missing"}
    return failure


def _verify_share_state(
    record: str, *, smb: str, guest: bool, readonly: bool, encrypted: bool,
    time_machine: bool, quota_gb: int | None,
) -> dict:
    """Fresh read after a privileged write; the read is the source of truth."""
    actual = _find_share(record)
    expected = {
        "smb_name": smb, "shared": True, "guest": guest,
        "readonly": readonly, "encrypted": encrypted,
        "time_machine": time_machine,
        "tm_quota_gb": quota_gb if time_machine else None,
    }
    if not actual or any(actual.get(key) != value for key, value in expected.items()):
        return {"ok": False, "error": "verification_failed"}
    return {"ok": True, "share": actual}


def create_smb_share(
    *, path: str, name: str, smb_name: str, guest: bool,
    readonly: bool, encrypted: bool,
    time_machine: bool = False, tm_quota_gb: int | None = None,
) -> dict:
    directory = validate_share_path(path)
    record = _validate_name(name)
    smb = _validate_name(smb_name)
    quota = _validate_quota(time_machine, tm_quota_gb)
    if _find_share(record):
        return {"ok": False, "error": "exists"}
    commands = [[
        SHARING, "-a", str(directory), "-n", record, "-S", smb,
        *_sharing_flags(guest=guest, readonly=readonly, encrypted=encrypted),
    ]]
    if time_machine:
        commands += _time_machine_commands(
            record, time_machine=True, quota_gb=quota,
            current={},  # brand-new record: no UUID, no quota
        )
    # One sequence, one authorization: the dscl attribute writes ride the same
    # admin approval as the share creation itself.
    result = _plain_result(run_admin_sequence(commands))
    if not result.get("ok"):
        return _admin_failure(result, sharing_cli=True)
    return _verify_share_state(
        record, smb=smb, guest=guest, readonly=readonly, encrypted=encrypted,
        time_machine=time_machine, quota_gb=quota,
    )


def update_smb_share(
    record_name: str, *, smb_name: str, guest: bool,
    readonly: bool, encrypted: bool,
    time_machine: bool = False, tm_quota_gb: int | None = None,
) -> dict:
    record = _validate_name(record_name)
    smb = _validate_name(smb_name)
    quota = _validate_quota(time_machine, tm_quota_gb)
    existing = _find_share(record)
    if not existing:
        # With the sharing CLI gone the listing cannot answer at all, so
        # "not found" would be a 404 lie.  Fresh probe on this failure path
        # only, never on a successful lookup.
        if not _sharing_on_disk():
            return {"ok": False, "error": "sharing_missing"}
        return {"ok": False, "error": "not_found"}
    current = {
        "time_machine": existing.get("time_machine"),
        "tm_quota_gb": existing.get("tm_quota_gb"),
        # The UUID is not part of the share rows; it is only needed here, to
        # decide whether enabling has to mint one.
        "uuid": (time_machine_records().get(record) or {}).get("uuid")
        if time_machine else None,
    }
    commands = [[
        SHARING, "-e", record, "-S", smb,
        *_sharing_flags(guest=guest, readonly=readonly, encrypted=encrypted),
    ]]
    commands += _time_machine_commands(
        record, time_machine=time_machine, quota_gb=quota, current=current,
    )
    result = _plain_result(run_admin_sequence(commands))
    if not result.get("ok"):
        return _admin_failure(result, sharing_cli=True)
    return _verify_share_state(
        record, smb=smb, guest=guest, readonly=readonly, encrypted=encrypted,
        time_machine=time_machine, quota_gb=quota,
    )


def remove_smb_share(record_name: str) -> dict:
    record = _validate_name(record_name)
    if not _find_share(record):
        # Same 404-lie guard as update: a vanished CLI, not a vanished share.
        if not _sharing_on_disk():
            return {"ok": False, "error": "sharing_missing"}
        return {"ok": False, "error": "not_found"}
    result = _plain_result(run_admin([SHARING, "-r", record]))
    if not result.get("ok"):
        return _admin_failure(result, sharing_cli=True)
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
    raw_links = resolve_value(cfg().get("quick_links") or [])
    links = {}
    for link in raw_links if isinstance(raw_links, list) else []:
        if not isinstance(link, dict):
            continue
        name = link.get("name")
        url = link.get("url")
        # YAML `.inf` / bytes leftover used to land in the payload and 500
        # Starlette's allow_nan=False JSON encoder. Leftover ``\\ud800`` in a
        # URL did the same via UnicodeEncodeError.
        if isinstance(name, str) and isinstance(url, str) and name and url:
            name, url = _as_text(name), _as_text(url)
            if name and url:
                links[name] = url
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
    output, error = _as_text(output), _as_text(error)
    if rc == 0:
        match = re.search(r"^\s*state\s*=\s*(\S+)", output, re.MULTILINE)
        state = match.group(1) if match else "loaded"
        return True, state
    rc, output, _ = sh([LAUNCHCTL, "print-disabled", "system"], timeout=4)
    output = _as_text(output)
    if rc == 0:
        match = re.search(rf'"?{re.escape(label)}"?\s*=>\s*(enabled|disabled|true|false)', output)
        if match:
            token = match.group(1)
            return token in {"enabled", "false"}, token
    return None, (error or "unknown")[-160:]


def _systemsetup_state(option: str, label: str) -> tuple[bool | None, str]:
    rc, output, error = sh([SYSTEMSETUP, option], timeout=8)
    combined = _as_text(output or error).strip()
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
    output, error = _as_text(output), _as_text(error)
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
    def _safe(item):
        probe, fallback = item
        try:
            return probe()
        except Exception:
            return fallback

    # fan_out re-raises on iteration; one probe must not blank Sharing.
    (
        (screen_launchd, screen_detail),
        screen_port,
        (remote_login, remote_login_detail),
        (apple_events, apple_events_detail),
        (content_cache, content_detail),
    ) = fan_out(
        _safe,
        [
            (lambda: _launchd_state("com.apple.screensharing"), (None, "unknown")),
            (lambda: bool(port_open(VNC_PORT, host="localhost", timeout=0.4)), False),
            (lambda: _systemsetup_state("-getremotelogin", "com.openssh.sshd"), (None, "unknown")),
            (lambda: _systemsetup_state("-getremoteappleevents", "com.apple.AEServer"), (None, "unknown")),
            (_content_cache_state, (None, "unknown")),
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


#: The binary each toggle actually spawns, for the confirmed-vanish probe on
#: the failure path.  screen_sharing runs launchctl twice; one probe covers it.
_SERVICE_TOOLS = {
    "remote_login": SYSTEMSETUP,
    "remote_apple_events": SYSTEMSETUP,
    "content_caching": ASSET_CACHE,
    "screen_sharing": LAUNCHCTL,
}

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

    result = _plain_result(run_admin_sequence(_SERVICE_COMMANDS[service_id](enabled)))
    actual = next(item for item in system_services() if item["id"] == service_id)
    if actual["enabled"] is enabled:
        return {"ok": True, "service": actual}
    if not result.get("ok"):
        # A systemsetup/launchctl/AssetCacheManagerUtil that vanished before
        # the spawn used to surface as the generic 500 "authorization failed"
        # — after the operator already typed the administrator password.  The
        # coded 503 fires only on this failure path, after a fresh disk probe.
        return _admin_failure(result, system_tool=_SERVICE_TOOLS[service_id])
    return {"ok": False, "error": "verification_failed", "service": actual}


def open_system_settings() -> dict:
    rc, output, error = sh([OPEN, SETTINGS_URL], timeout=12)
    if rc != 0:
        rc, output, error = sh([OPEN, "-a", "System Settings"], timeout=12)
    message = _as_text(error or output)[-300:]
    if rc != 0:
        # A vanished /usr/bin/open used to answer the 500 "System Settings
        # could not be opened", blaming the app for a missing tool.  Coded
        # 503 only after the fresh disk probe on this failure path; every
        # other failure keeps its shape.
        if any(marker in message.lower() for marker in _VANISH_MARKERS) and not _tool_on_disk(OPEN):
            return {"ok": False, "error": "system_tool_missing", "message": message}
    return {"ok": rc == 0, "message": message}


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
        hostname = _as_text(socket.gethostname())
    except OSError:
        hostname = ""
    def _safe(item):
        probe, fallback = item
        try:
            return probe()
        except Exception:
            return fallback

    # fan_out re-raises on iteration; one collector must not 500 the page.
    host, services, smb, files = fan_out(
        _safe,
        [
            (host_ip, ""),
            (system_services, []),
            (list_smb_shares, []),
            (file_services, []),
        ],
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
        # After the wave, not in it: this reads the share list gathered above,
        # and its Bonjour browse only runs when a TM share actually exists.
        "time_machine": time_machine_status(smb),
        "capabilities": {
            "smb_management": True,
            "system_settings_fallback": True,
            "password_handling": "macos-native-dialog",
        },
    }
