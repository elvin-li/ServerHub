"""NFS server management — the export protocol OMV treats as a first-class citizen.

macOS ships a complete NFS server (``nfsd``) driven by ``/etc/exports``, but no
graphical surface for it: System Settings only exposes SMB.  That makes NFS the
single biggest gap between this panel and OMV, because NFS is what Linux clients,
Proxmox hosts and Kubernetes ``nfs`` volumes actually want to mount.

Design notes
------------
``/etc/exports`` is root-owned, so edits are staged as an unprivileged temporary
file this process generates from validated input and then installed with one
authorization sheet (:mod:`hub.macos_admin`).  Request data never reaches argv:
every export line is rebuilt here from parsed, pattern-checked fields, so a
client spec cannot smuggle in an option or a second export.

``nfsd checkexports`` runs before the file is accepted, so a syntactically broken
export is rejected while the previous configuration is still live.
"""
from __future__ import annotations

import re
import shlex
from pathlib import Path

from hub.macos_admin import run_admin_sequence
from hub.paths import DATA_DIR
from hub.secure_io import replace_secret_text
from hub.util import cached_snapshot, read_text_capped, sh, strftime_now

NFSD = "/sbin/nfsd"
SHOWMOUNT = "/usr/bin/showmount"
NFSSTAT = "/usr/bin/nfsstat"
CP = "/bin/cp"
CHMOD = "/bin/chmod"
CHOWN = "/usr/sbin/chown"

EXPORTS_PATH = Path("/etc/exports")
_STAGE_PATH = DATA_DIR / "exports.staged"
#: Leftover multi-MB ``/etc/exports`` used to OOM GET /api/nfs.
_EXPORTS_CAP = 256 * 1024

#: Host specifications accepted in a client list: bare IPv4, IPv4/prefix,
#: hostname, or the literal ``everyone``.  Anything outside this set is refused
#: rather than escaped, because an exports(5) line is whitespace-delimited and a
#: permissive quote would still let a value introduce a new option.
_HOST_RE = re.compile(r"^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2})?|[A-Za-z0-9][A-Za-z0-9.-]{0,253})$")

#: ``-maproot=`` / ``-mapall=`` values: ``user`` or ``user:group``.
_MAP_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,63})?$")

#: Directories whose export would hand a client the whole machine.
_PROTECTED_ROOTS = (
    "/", "/etc", "/var", "/private", "/System", "/Library", "/bin", "/sbin",
    "/usr", "/dev", "/cores", "/Applications",
)

_CACHE_TTL = 15.0


class NfsConfigError(ValueError):
    """Raised with a stable ``code`` the router maps to an API error."""

    def __init__(self, code: str, **params):
        super().__init__(code)
        self.code = code
        self.params = params


def _as_text(value) -> str:
    """``sh`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used to 500 GET /api/nfs."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
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


def _nfsd_on_disk() -> bool:
    """Fresh disk probe for the mutation-failure paths only (raid/vms rule).

    ``Path.is_file()`` can itself raise on a dying volume (EIO/ESTALE); a disk
    that cannot even answer for /sbin is not confirmably carrying nfsd.
    """
    try:
        return Path(NFSD).is_file()
    except (OSError, ValueError):
        return False


#: What a spawn of a gone binary reads like through run_admin / sh: the
#: shell's own refusal (``sh: /sbin/nfsd: command not found`` / ``No such
#: file or directory``) or sh()'s FileNotFoundError sentinel (``not found``).
#: Purely a message-pattern gate: classification additionally requires the
#: fresh :func:`_nfsd_on_disk` probe, and only the generic ``failed`` shape is
#: eligible — timeouts, cancelled sheets and password failures keep their
#: original shape.
_VANISH_MARKERS = ("command not found", "no such file or directory", "not found")


def _classify_admin_failure(result: dict) -> dict:
    """An nfsd confirmed vanished answers the coded 503, not admin.failed.

    The generic 500 "the privileged macOS operation failed" sends the
    operator back to a password dialog that cannot help.  The probe runs only
    on this failure path, never on a successful mutation.
    """
    if not isinstance(result, dict):
        return {"ok": False, "error": "failed"}
    if not result.get("ok") and (result.get("error") or "failed") == "failed":
        message = _as_text(result.get("message") or "").lower()
        if any(marker in message for marker in _VANISH_MARKERS) and not _nfsd_on_disk():
            return {"ok": False, "error": "nfsd_missing"}
    return result


# ── parsing ──────────────────────────────────────────────────────────────────

def _parse_line(line: str) -> dict | None:
    """One exports(5) line → structured entry, or None for blanks/comments."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        return {"raw": _as_text(stripped), "path": "", "clients": [], "unparsed": True}
    if not tokens:
        return None

    paths: list[str] = []
    options: list[str] = []
    clients: list[str] = []
    for token in tokens:
        if token.startswith("-"):
            options.append(token)
        elif not options:
            paths.append(token)
        else:
            clients.append(token)

    readonly = any(o in ("-ro", "-o") for o in options)
    alldirs = "-alldirs" in options
    maproot = ""
    mapall = ""
    network = ""
    mask = ""
    for i, opt in enumerate(options):
        if opt.startswith("-maproot="):
            maproot = opt.split("=", 1)[1]
        elif opt.startswith("-mapall="):
            mapall = opt.split("=", 1)[1]
        elif opt == "-network" and i + 1 < len(options):
            network = options[i + 1]
        elif opt == "-mask" and i + 1 < len(options):
            mask = options[i + 1]
    # ``-network 10.0.0.0`` puts the value in the client position, not options,
    # because it does not start with a dash.  Recover it from the client list.
    if "-network" in options and not network and clients:
        network = clients.pop(0)
    if "-mask" in options and not mask and clients:
        mask = clients.pop(0)

    return {
        "raw": _as_text(stripped),
        "path": _as_text(paths[0] if paths else ""),
        "extra_paths": [_as_text(p) for p in paths[1:]],
        "clients": [_as_text(c) for c in clients],
        "network": _as_text(network),
        "mask": _as_text(mask),
        "readonly": readonly,
        "alldirs": alldirs,
        "maproot": _as_text(maproot),
        "mapall": _as_text(mapall),
        "unparsed": False,
    }


def _exports_exists() -> bool:
    """``/etc/exports`` presence.  EIO/ESTALE is "unreadable", not a 500."""
    try:
        return EXPORTS_PATH.exists()
    except OSError:
        return False


def read_exports() -> list[dict]:
    """Current ``/etc/exports`` entries.  Missing file means "nothing exported"."""
    try:
        text = read_text_capped(EXPORTS_PATH, _EXPORTS_CAP, errors="replace")
    except FileNotFoundError:
        return []
    except OSError:
        return []
    entries = []
    for line in text.splitlines():
        parsed = _parse_line(line)
        if parsed:
            entries.append(parsed)
    return entries


# ── rendering ────────────────────────────────────────────────────────────────

def _validate_entry(entry: dict) -> dict:
    """Normalize one caller-supplied export, raising NfsConfigError on refusal."""
    try:
        # A str() probe, not an isinstance gate: a numeric leftover keeps
        # behaving as its string form, while a >4300-digit *already-int*
        # (YAML/plist hex loads with int(x, 16), exempt from the int(str)
        # parse cap) earns the coded refusal instead of the digit-cap
        # ValueError a bare str() raises past the router.
        path = str(entry.get("path") or "").strip()
    except ValueError:
        raise NfsConfigError("nfs.bad_path")
    # Control characters before Path(): a NUL never reaches the later check,
    # and Path("…\0…") raises ValueError instead of NfsConfigError.
    if (
        not path
        or not path.startswith("/")
        or any(ord(c) < 0x20 or ord(c) == 0x7F for c in path)
        or '"' in path
    ):
        raise NfsConfigError("nfs.bad_path")
    try:
        resolved = Path(path)
    except ValueError:
        raise NfsConfigError("nfs.bad_path")
    try:
        is_dir = resolved.is_dir()
    except OSError:
        # is_dir() raises ESTALE/EIO on a dying mount; pathlib only swallows
        # ENOENT/ELOOP. resolve() is the later catch — this used to 500 first.
        raise NfsConfigError("nfs.bad_path")
    if not is_dir:
        raise NfsConfigError("nfs.path_missing", path=path)
    try:
        real = str(resolved.resolve())
    except (OSError, RuntimeError, ValueError):
        # resolve() raises RuntimeError on a symlink loop; OSError on a
        # vanished mount. Neither is a 500.
        raise NfsConfigError("nfs.bad_path")
    if real in _PROTECTED_ROOTS or any(
        real == p or (p != "/" and real.startswith(p + "/")) for p in _PROTECTED_ROOTS if p != "/"
    ):
        raise NfsConfigError("nfs.protected_path", path=real)
    try:
        real.encode("utf-8")
    except UnicodeEncodeError as error:
        # A directory whose on-disk name holds undecodable bytes arrives as
        # lone ``\udcXX`` surrogates (os.fsdecode).  The staged exports file
        # is written — and read back — as strict UTF-8, so such a path cannot
        # round-trip through the table; the stage write's UnicodeEncodeError
        # (a ValueError, not the OSError save_exports maps) used to 500
        # POST /api/nfs/exports after validation had already passed.
        raise NfsConfigError("nfs.bad_path") from error

    clients_raw = entry.get("clients") or []
    if isinstance(clients_raw, str):
        clients_raw = [c for c in re.split(r"[\s,]+", clients_raw) if c]
    elif not isinstance(clients_raw, list):
        clients_raw = []
    clients: list[str] = []
    everyone = False
    for client in clients_raw:
        try:
            value = str(client).strip()
        except ValueError:
            # An already-int hex leftover past the digit cap can never be a
            # host spec; refuse it like any other bad client, not a 500.
            raise NfsConfigError("nfs.bad_client", client="")
        if not value:
            continue
        if value.lower() == "everyone":
            everyone = True
            continue
        if not _HOST_RE.match(value):
            raise NfsConfigError("nfs.bad_client", client=value[:60])
        clients.append(value)
    if not clients and not everyone:
        raise NfsConfigError("nfs.no_clients")

    try:
        maproot = str(entry.get("maproot") or "").strip()
        mapall = str(entry.get("mapall") or "").strip()
    except ValueError:
        # The digit-cap ValueError of a huge already-int leftover; the value
        # could never match _MAP_RE anyway.
        raise NfsConfigError("nfs.bad_mapping", field="maproot", value="")
    for label, value in (("maproot", maproot), ("mapall", mapall)):
        if value and not _MAP_RE.match(value):
            raise NfsConfigError("nfs.bad_mapping", field=label, value=value[:60])
    if maproot and mapall:
        raise NfsConfigError("nfs.map_conflict")

    return {
        "path": real,
        "clients": clients,
        "everyone": everyone,
        "readonly": bool(entry.get("readonly")),
        "alldirs": bool(entry.get("alldirs", True)),
        "maproot": maproot,
        "mapall": mapall,
    }


def _quote_path(path: str) -> str:
    """Quote a path that would otherwise split into several exports(5) fields.

    Any whitespace, not just a literal space: the field separator in exports(5)
    is whitespace generally, so a tab in a directory name used to produce extra
    fields that nfsd read as further paths and options.  Validation now rejects
    control characters outright, and this is the second layer -- render_line is
    also what the panel displays, so the two must not disagree.
    """
    return f'"{path}"' if any(c.isspace() for c in path) else path


def render_line(entry: dict) -> str:
    """Structured export → one exports(5) line."""
    parts = [_quote_path(entry["path"])]
    if entry.get("alldirs"):
        parts.append("-alldirs")
    if entry.get("readonly"):
        parts.append("-ro")
    if entry.get("maproot"):
        parts.append(f"-maproot={entry['maproot']}")
    if entry.get("mapall"):
        parts.append(f"-mapall={entry['mapall']}")
    if entry.get("everyone"):
        # exports(5) treats an option-only line with no host list as "any host".
        # Spell it out with a wildcard network so the intent is visible in the file.
        parts += ["-network", "0.0.0.0", "-mask", "0.0.0.0"]
    else:
        parts += entry["clients"]
    return " ".join(parts)


def render_exports(entries: list[dict]) -> str:
    """Full ``/etc/exports`` body for *entries* (already validated)."""
    header = [
        "# Managed by ServerHub. Edits made here are replaced on the next save.",
        f"# Last written: {strftime_now('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    lines = [render_line(e) for e in entries]
    return "\n".join(header + lines) + "\n"


# ── nfsd state ───────────────────────────────────────────────────────────────

def _nfsd_status() -> dict:
    rc, out, err = sh([NFSD, "status"], timeout=8)
    text = _as_text(out or err).strip()
    lowered = text.lower()
    enabled = "is enabled" in lowered or "is running" in lowered
    running = "is running" in lowered
    return {"enabled": enabled, "running": running, "detail": text[:300]}


def _active_exports() -> list[dict]:
    """What the running server actually advertises (``showmount -e``).

    Short timeout on purpose: with ``nfsd`` stopped this RPC hangs until it gives
    up, and the page must not block for that long.
    """
    rc, out, _ = sh([SHOWMOUNT, "-e", "localhost"], timeout=4)
    if rc != 0:
        return []
    rows = []
    for line in _as_text(out).splitlines()[1:]:
        parts = line.split()
        if not parts:
            continue
        rows.append({"path": parts[0], "clients": parts[1:]})
    return rows


def check_exports() -> dict:
    """Validate the live ``/etc/exports`` without changing anything."""
    rc, out, err = sh([NFSD, "checkexports"], timeout=10)
    text = _as_text(out or err).strip()
    return {"ok": rc == 0, "detail": text[:600]}


@cached_snapshot(_CACHE_TTL)
def overview(force: bool = False) -> dict:
    entries = read_exports()
    status = _nfsd_status()
    data = {
        "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
        "server": status,
        "exports_path": str(EXPORTS_PATH),
        "exports_exists": _exports_exists(),
        "entries": entries,
        "count": len(entries),
        "active": _active_exports() if status["running"] else [],
        "check": check_exports() if _exports_exists() else {"ok": True, "detail": ""},
    }
    return data


def invalidate() -> None:
    overview.invalidate()


# ── mutations ────────────────────────────────────────────────────────────────

def save_exports(entries: list[dict]) -> dict:
    """Validate, stage and install a complete export table.

    The whole file is replaced rather than patched: a partial edit of a
    root-owned file needs either a privileged editor or a read-modify-write race,
    and the panel is the declared owner of this file anyway.
    """
    validated = [_validate_entry(e) for e in (entries or [])]
    seen: set[str] = set()
    for entry in validated:
        if entry["path"] in seen:
            raise NfsConfigError("nfs.duplicate_path", path=entry["path"])
        seen.add(entry["path"])

    body = render_exports(validated)
    # Reused stage file: O_TRUNC mid-write left an empty table that the
    # admin copy then installed over /etc/exports.
    try:
        replace_secret_text(_STAGE_PATH, body)
    except (OSError, ValueError) as exc:
        # ENOSPC / EIO on the stage file used to 500 POST /api/nfs/exports.
        # ValueError is UnicodeEncodeError's base: _validate_entry now refuses
        # surrogate-bearing paths, and this is the second layer — render_line
        # is also what the panel displays, so the two must not disagree.
        return {"ok": False, "error": "failed", "message": _as_text(exc)[:200]}

    result = run_admin_sequence(
        [
            [CP, str(_STAGE_PATH), str(EXPORTS_PATH)],
            [CHOWN, "root:wheel", str(EXPORTS_PATH)],
            [CHMOD, "644", str(EXPORTS_PATH)],
            # Re-read the table so a running server picks the change up without
            # a restart; harmless when nfsd is stopped.
            [NFSD, "update"],
        ],
        timeout=180,
    )
    invalidate()
    if not result.get("ok"):
        return _classify_admin_failure(result)
    check = check_exports()
    return {"ok": True, "count": len(validated), "check": check}


_SERVER_ACTIONS = {
    "enable": [[NFSD, "enable"]],
    "disable": [[NFSD, "disable"]],
    "start": [[NFSD, "start"]],
    "stop": [[NFSD, "stop"]],
    "restart": [[NFSD, "restart"]],
    "update": [[NFSD, "update"]],
}


def server_action(action: str) -> dict:
    commands = _SERVER_ACTIONS.get((action or "").strip().lower())
    if not commands:
        return {"ok": False, "error": "bad_action"}
    result = run_admin_sequence(commands, timeout=120)
    invalidate()
    if result.get("ok"):
        result["server"] = _nfsd_status()
        return result
    return _classify_admin_failure(result)


def statistics() -> dict:
    """Server-side NFS counters, useful when a client reports slow mounts."""
    rc, out, _ = sh([NFSSTAT, "-s"], timeout=6)
    return {"ok": rc == 0, "text": _as_text(out)[:4000]}
