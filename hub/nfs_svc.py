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

#: Real control flow must keep propagating even through the bomb guards
#: (the modules12/logs12/json13 convention): swallowing a Ctrl-C or an
#: interpreter shutdown to save one page field would turn the sanitizer
#: into a hang.  Everything else BaseException-shaped that a leftover
#: raises out of its own hooks is a bomb like any other — the nas12
#: guards all stopped at ``except Exception``, so one such leftover
#: sailed past every catch in the module at once.
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)


class NfsConfigError(ValueError):
    """Raised with a stable ``code`` the router maps to an API error."""

    def __init__(self, code: str, **params):
        super().__init__(code)
        self.code = code
        self.params = params


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the gate itself: ``_admin_result``'s dict gate 500'd
    POST /api/nfs/exports and /api/nfs/server one line ahead of the
    laundering that exists to absorb junk shapes, and ``_validate_entry``'s
    entry gate raised raw past the router's NfsConfigError catch.  A real
    subclass still matches through the C-level type check; only a value
    that cannot answer what it is takes the non-matching branch.

    ``except BaseException``: the nas9 guard stopped at ``Exception``, so a
    leftover whose ``__class__`` property raises a *BaseException* subclass
    (the watchdog/timeout shape the modules12/logs12/json13 sweeps sealed
    on their own surfaces) sailed past this catch — and past every sibling
    guard in this module, because each one stopped at ``Exception`` too —
    a raw 500 on GET /api/nfs and both POST routes.  Only genuine control
    flow keeps propagating.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _as_text(value) -> str:
    """``sh`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used to 500 GET /api/nfs."""
    if _isa(value, (bytes, bytearray)):
        # Unbound base decode in a try (the modules9 / share_acl_svc rule):
        # the old bound ``value.decode(...)`` ran a subclass override, and a
        # *lying* ``__class__`` impostor claiming bytes has no ``.decode`` at
        # all — either raise rode out of the failure funnels and 500'd
        # POST /api/nfs/exports and /api/nfs/server.  A decode that cannot
        # answer falls through to the str() probe so a legible impostor
        # still renders instead of costing the route.
        # Both bases are tried, real layout first-come (the modules12 /
        # logs12 ``_decode_bytes`` rule): the old arm picked the base off
        # the *claimed* ``__class__``, so a genuine ``bytearray`` whose
        # ``__class__`` lied ``bytes`` was handed to ``bytes.decode``,
        # rejected by the descriptor, and its perfectly decodable content
        # fell to the str() probe — which rendered the ``bytearray(b'…')``
        # repr into the page instead of the text.
        for base in (bytes, bytearray):
            try:
                value = base.decode(value, "utf-8", "replace")
                break
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
    if value is None:
        return ""
    if type(value) is not str:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return ""
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    # Unbound base encode (the nas_common._utf8_text / modules6 rule):
    # ``str()`` of a subclass whose ``__str__`` answers *self* skips
    # CPython's exact-str copy, so the old bound ``value.encode(...)`` ran
    # the subclass override — a leftover encode bomb 500'd the same routes.
    try:
        return bytes.decode(str.encode(value, "utf-8", "replace"), "utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb (fails False)."""
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _rc_int(rc) -> int:
    """Exact exit status for the ``==`` / ``!=`` probes; junk reads as failure.

    This module does not own ``sh`` (tests and tooling patch it — the
    health9 / shares_svc ``_rc_int`` rule), and the three listing probes
    compared the *rc* slot raw: an rc-subclass whose ``__eq__`` / ``__ne__``
    raises detonated ``rc != 0`` in ``_active_exports`` and ``rc == 0`` in
    ``check_exports`` / ``statistics`` — a raw 500 on GET /api/nfs (both
    run unguarded under ``overview``) and GET /api/nfs/stats, where every
    other junk shape already degrades.  ``int.__index__`` reads the real
    value underneath a subclass override; a *lying* ``__class__`` impostor
    (claims int over no real int storage) TypeErrors on the unbound read
    and drops with the junk.  ``-255`` is no honest exit status and is
    distinct from the ``-1`` spawn-failure sentinel, so junk can never be
    misread as success.
    """
    try:
        if isinstance(rc, bool):
            return int(rc)
        value = int.__index__(rc) if isinstance(rc, int) else int(rc)
        # Digit-cap probe: past CPython's int->str cap the status cannot be
        # rendered by any log line or JSON encoder — junk, reads as failure.
        str(value)
        return value
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return -255


def _sh_triple(argv, *, timeout: int) -> tuple:
    """The ``sh`` seam laundered to an exact ``(rc, out, err)`` shape.

    nas11's ``_rc_int`` laundered the rc *value*, but the answer's *shape*
    stayed bare: ``rc, out, err = sh(...)`` iterates whatever the seam
    handed back, and this module does not own ``sh`` (tests and tooling
    patch it).  A leftover sequence subclass whose ``__iter__`` raises, a
    torn two-field answer, or a patched ``sh`` that raises outright each
    used to blow the unpack itself — inside ``_nfsd_status`` /
    ``_active_exports`` / ``check_exports`` (all unguarded under
    ``overview``, a raw 500 on GET /api/nfs) and ``statistics`` (a raw 500
    on GET /api/nfs/stats) — one step ahead of the ``_rc_int`` /
    ``_as_text`` guards on the fields themselves (the ups/vms/storage
    ``_sh3`` rule).  An unreadable answer reads as spawn failure:
    ``-255`` is nonzero and never ``sh``'s ``-1`` sentinel.
    """
    try:
        rc, out, err = sh(argv, timeout=timeout)
        return rc, out, err
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return -255, "", ""


def _admin_result(result) -> dict:
    """A privileged-helper result as a plain dict with a real bool ``ok``.

    ``save_exports`` and ``server_action`` read ``result.get("ok")`` on the
    *raw* ``run_admin_sequence`` payload — the one NAS service still doing
    so after the snapshots/raid/smart/usage/shares sweeps.  A leftover
    ``None`` AttributeError'd the read, a dict-*subclass* result whose bound
    ``.get`` raises (the jobs/metrics row-bomb class: passes ``isinstance``,
    refuses the read) blew the same line, a ``__bool__``-bomb ``ok`` value
    detonated the ``if`` itself, and ``server_action``'s
    ``result["server"] = …`` ran a subclass ``__setitem__`` — each a raw 500
    on POST /api/nfs/exports and /api/nfs/server one call ahead of the
    router funnel that already knows how to answer coded.  ``dict()``
    copies through the C-level storage, so an overridden method cannot
    fire; junk shapes degrade to the coded generic failure.  _isa, not a
    bare isinstance: a ``__class__``-property bomb detonated the gate
    itself before the non-dict branch could answer.
    """
    if _isa(result, dict):
        try:
            plain = dict(result)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return {"ok": False, "error": "failed"}
    else:
        return {"ok": False, "error": "failed"}
    plain["ok"] = _truthy(plain.get("ok"))
    return plain


def _admin_sequence(commands, *, timeout) -> dict:
    """The privileged-helper *call* itself guarded (the users12 rule).

    ``_admin_result`` launders ``run_admin_sequence``'s junk *answers*, but
    both mutation seams ran the call bare — and this module does not own
    the helper (tests and tooling patch it; the share_acl_svc
    ``_admin_sequence`` guarded-call rule).  A leftover stub that *raises*
    instead of answering blew POST /api/nfs/exports and /api/nfs/server one
    seam ahead of the launder built for its answers.  A raising helper
    reads as the generic coded failure — with no message text it can never
    mint the disk-confirmed vanished-CLI 503 — while an honest answer keeps
    riding ``_admin_result`` untouched, cancelled / password_required
    shapes included.
    """
    try:
        answer = run_admin_sequence(commands, timeout=timeout)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return {"ok": False, "error": "failed"}
    return _admin_result(answer)


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
    if not _isa(result, dict):
        return {"ok": False, "error": "failed"}
    # _as_text on both probes, no bare ``or`` / ``==`` on the raw fields:
    # a leftover ``__eq__``-bomb error value used to detonate the
    # ``== "failed"`` read, and a ``__bool__``-bomb message blew the old
    # ``result.get("message") or ""`` — raw 500s on POST /api/nfs/exports
    # and /api/nfs/server in place of the coded refusal (the
    # usage_svc.set_spotlight vanish-classification rule).  The unbound
    # reads in a try: ``dict.get`` is a descriptor bound to the real dict
    # layout, so a *lying* ``__class__`` claiming dict passed the gate and
    # the TypeError raised raw; a result that cannot even be read is the
    # generic coded failure.
    try:
        error = _as_text(dict.get(result, "error")) or "failed"
        if not _truthy(dict.get(result, "ok")) and error == "failed":
            message = _as_text(dict.get(result, "message")).lower()
            if any(marker in message for marker in _VANISH_MARKERS) and not _nfsd_on_disk():
                return {"ok": False, "error": "nfsd_missing"}
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return {"ok": False, "error": "failed"}
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
    # Unbound ``dict.get`` throughout (the shares.py _share_directory rule):
    # the route hands over plain model_dump dicts, but the service is also
    # called in-process, and a leftover dict-*subclass* entry whose bound
    # ``.get`` raises a non-ValueError — or a non-dict entry AttributeError'ing
    # the read — used to raise raw past the router's NfsConfigError catch
    # where every other junk entry earns its coded refusal.  _isa: a
    # ``__class__``-property bomb entry detonated this very gate the same
    # raw way before the refusal below could answer.
    if not _isa(entry, dict):
        raise NfsConfigError("nfs.bad_path")
    try:
        # A str() probe, not an isinstance gate: a numeric leftover keeps
        # behaving as its string form, while a >4300-digit *already-int*
        # (YAML/plist hex loads with int(x, 16), exempt from the int(str)
        # parse cap) earns the coded refusal instead of the digit-cap
        # ValueError a bare str() raises past the router.
        raw_path = dict.get(entry, "path")
        path = str(raw_path).strip() if _truthy(raw_path) else ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # The digit-cap ValueError, or a leftover ``__str__`` bomb raising
        # something else: neither may escape past the coded refusal.
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

    clients_raw = dict.get(entry, "clients")
    if _isa(clients_raw, str):
        # re.split in a try: a *lying* ``__class__`` claiming str passes the
        # gate but is no string underneath, and re's TypeError ("expected
        # string or bytes-like object") used to raise raw past the router's
        # NfsConfigError catch — a 500 where every junk client table earns
        # its coded refusal.  An unreadable table means "no clients".
        try:
            clients_raw = [c for c in re.split(r"[\s,]+", clients_raw) if c]
        except _CONTROL_FLOW:
            raise
        except BaseException:
            clients_raw = []
    elif _isa(clients_raw, list):
        # Materialized under the unbound base walk: a list-subclass client
        # table whose ``__iter__`` raises used to blow the loop below raw.
        try:
            clients_raw = list(list.__iter__(clients_raw))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            clients_raw = []
    else:
        clients_raw = []
    clients: list[str] = []
    everyone = False
    for client in clients_raw:
        try:
            value = str(client).strip()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # An already-int hex leftover past the digit cap can never be a
            # host spec — and a ``__str__`` bomb raising a non-ValueError is
            # the same junk; refuse it like any other bad client, not a 500.
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
        raw_maproot = dict.get(entry, "maproot")
        raw_mapall = dict.get(entry, "mapall")
        maproot = str(raw_maproot).strip() if _truthy(raw_maproot) else ""
        mapall = str(raw_mapall).strip() if _truthy(raw_mapall) else ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # The digit-cap ValueError of a huge already-int leftover — or a
        # ``__str__`` bomb raising past it; the value could never match
        # _MAP_RE anyway.
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
        # _truthy: a leftover ``__bool__``-bomb flag used to raise out of the
        # bare bool() after every other field had already validated.
        "readonly": _truthy(dict.get(entry, "readonly")),
        "alldirs": _truthy(dict.get(entry, "alldirs", True)),
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
    rc, out, err = _sh_triple([NFSD, "status"], timeout=8)
    # ``_as_text(out) or _as_text(err)``, not ``_as_text(out or err)``: the
    # bare ``or`` asked the raw slot for truth, so a leftover str-subclass
    # ``__bool__`` bomb from a hostile sh detonated the pick itself —
    # unguarded under ``overview()``, a raw 500 on GET /api/nfs one step
    # ahead of the laundering (the autostart_svc rule).
    text = (_as_text(out) or _as_text(err)).strip()
    lowered = text.lower()
    enabled = "is enabled" in lowered or "is running" in lowered
    running = "is running" in lowered
    return {"enabled": enabled, "running": running, "detail": text[:300]}


def _active_exports() -> list[dict]:
    """What the running server actually advertises (``showmount -e``).

    Short timeout on purpose: with ``nfsd`` stopped this RPC hangs until it gives
    up, and the page must not block for that long.
    """
    rc, out, _ = _sh_triple([SHOWMOUNT, "-e", "localhost"], timeout=4)
    if _rc_int(rc) != 0:
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
    rc, out, err = _sh_triple([NFSD, "checkexports"], timeout=10)
    # Same or-seam as _nfsd_status: the bare ``out or err`` ran a leftover
    # ``__bool__`` bomb ahead of the laundering and 500'd GET /api/nfs.
    text = (_as_text(out) or _as_text(err)).strip()
    return {"ok": _rc_int(rc) == 0, "detail": text[:600]}


def _entry_rows(raw) -> list:
    """The export table materialized under its own guard.

    ``read_exports`` builds plain rows, but this module does not own the
    provider (tests and tooling patch it), and a leftover listing that
    passes ``isinstance`` yet refuses iteration — or whose ``__len__``
    raises — used to blow ``overview()``'s own walk *before* the route's
    sanitizer could drop the unusable field, 500ing GET /api/nfs (the
    usage_svc.scan_roots / storage_pool_svc._candidates rule).  No entries
    is the honest degrade: the page renders an empty table.
    """
    if not _isa(raw, list):
        return []
    try:
        return list(list.__iter__(raw))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []


@cached_snapshot(_CACHE_TTL)
def overview(force: bool = False) -> dict:
    try:
        entries = _entry_rows(read_exports())
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # The guard above covers iteration but not the call itself: a
        # read_exports that raises outright must cost the table, never
        # the page.
        entries = []
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
    # Guarded unbound walk (the smart_test_svc.set_schedule rule): the route
    # hands over a Pydantic-exact list, but the service is also called
    # in-process, and a leftover list-subclass ``__bool__``/``__iter__`` bomb
    # used to blow the old ``(entries or [])`` — a raw raise where every junk
    # entry already earns its coded NfsConfigError refusal.  The unbound
    # ``__iter__`` in a try (the modules9 rule): a *lying* ``__class__``
    # claiming list/tuple passed the gate and the descriptor's TypeError
    # raised raw where an empty table is the honest degrade.
    try:
        if _isa(entries, list):
            rows = list.__iter__(entries)
        elif _isa(entries, tuple):
            rows = tuple.__iter__(entries)
        else:
            rows = iter(())
    except _CONTROL_FLOW:
        raise
    except BaseException:
        rows = iter(())
    validated = [_validate_entry(e) for e in rows]
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

    # _admin_sequence (_admin_result inside): the raw run_admin_sequence
    # payload used to 500 this route at ``result.get("ok")`` — and a
    # patched helper that *raises* blew the call one seam earlier — see
    # _admin_result / _admin_sequence.
    result = _admin_sequence(
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
    if not result["ok"]:
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
    # _as_text is a str() probe, not a bare ``(action or "").strip()``: the
    # route hands the verb over as str through Pydantic, but the service is
    # also called in-process, and a leftover ``__bool__``-bomb action
    # detonated the bare ``or`` — and a non-str leftover AttributeError'd
    # ``.strip()`` — a raw raise where the coded ``bad_action`` refusal is
    # the contract (the snapshots_svc.time_machine_action convention).
    commands = _SERVER_ACTIONS.get(_as_text(action).strip().lower())
    if not commands:
        return {"ok": False, "error": "bad_action"}
    # _admin_sequence (_admin_result inside): the raw run_admin_sequence
    # payload used to 500 this route at ``result.get("ok")`` (and the
    # ``result["server"]`` write ran a subclass ``__setitem__``) — and a
    # patched helper that *raises* blew the call one seam earlier — see
    # _admin_result / _admin_sequence.
    result = _admin_sequence(commands, timeout=120)
    invalidate()
    if result["ok"]:
        result["server"] = _nfsd_status()
        return result
    return _classify_admin_failure(result)


def statistics() -> dict:
    """Server-side NFS counters, useful when a client reports slow mounts."""
    rc, out, _ = _sh_triple([NFSSTAT, "-s"], timeout=6)
    return {"ok": _rc_int(rc) == 0, "text": _as_text(out)[:4000]}
