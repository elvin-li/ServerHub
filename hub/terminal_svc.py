"""Terminal: run a command in a container, or on the host behind two gates.

A host shell is remote code execution on the whole machine, so it is *off* by
default and stays off until the operator makes two separate, deliberate choices:

  1. an administrator password exists (``require_auth`` already refuses every
     privileged route with ``auth.setup_required`` until then), and
  2. ``settings.terminal.host_enabled`` is turned on in Settings.

Container exec only needs the usual panel auth: the blast radius is one
container, and ``docker exec`` was already reachable from the Containers page.

Every accepted one-shot command is appended to ``data/terminal-audit.jsonl``.
The interactive PTY transport in :mod:`hub.terminal_pty` uses the same policy
switch and audit file, but deliberately has stricter browser-session and Origin
checks because a persistent WebSocket shell is a higher-risk capability.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from hub import cli_args, secure_io
from hub.config import settings_section
from hub.docker_cli import engine_up, looks_engine_down
from hub.errors import CODES, api_error
from hub.paths import DATA_DIR, DOCKER, user_home
from hub.util import iter_capped_lines, safe_json_loads, tail_file_lines, utf8_env

AUDIT_PATH = DATA_DIR / "terminal-audit.jsonl"

#: Hard ceiling on a single command.  Long jobs belong in Maintenance tasks.
DEFAULT_TIMEOUT = 30
MAX_TIMEOUT = 120

#: Truncate captured output so one `cat` of a huge file cannot blow up the
#: response (or the browser).
MAX_OUTPUT = 200_000

CODES.setdefault("terminal.host_disabled", (
    403,
    "the host terminal is disabled: enable it in Settings -> Terminal, and note "
    "that it grants full command access to this machine",
))
CODES.setdefault("terminal.empty_command", (400, "command is empty"))
CODES.setdefault("terminal.bad_command", (400, "command contains invalid characters"))
CODES.setdefault("terminal.no_container", (400, "no container selected"))
CODES.setdefault("terminal.bad_target", (400, "unknown target: {target}"))
CODES.setdefault("terminal.timeout", (504, "command timed out after {seconds}s"))
CODES.setdefault("terminal.command_too_long", (400, "command exceeds {max} characters"))
CODES.setdefault("terminal.too_many_sessions", (429, "too many interactive terminal sessions"))
CODES.setdefault("terminal.runtime_not_found", (503, "terminal runtime is unavailable"))

MAX_COMMAND_LEN = 8000

#: Sentinel used to read the shell's final working directory out of stdout.
#: Random per-process so a command that echoes the literal string cannot forge
#: a cwd (it would have to guess this run's token).
_CWD_MARKER = "__serverhub_cwd_" + os.urandom(8).hex() + "__"


def _color_env() -> dict[str, str]:
    """Environment that convinces CLI tools to emit ANSI colour.

    Output is a pipe, not a tty, so ``ls``/``grep``/``git`` all disable colour
    by default.  The UI renders ANSI, so ask for it: BSD tools honour
    ``CLICOLOR_FORCE``, GNU/most others honour ``FORCE_COLOR``.
    """
    env = dict(os.environ)
    env.update({
        "CLICOLOR_FORCE": "1",
        "FORCE_COLOR": "1",
        "TERM": "xterm-256color",
        # Stop pagers from hanging forever waiting for a keypress that a
        # request/response console can never deliver.
        "PAGER": "cat",
        "GIT_PAGER": "cat",
        "LESS": "FRX",
    })
    return utf8_env(env)


def _sh_quote(value: str) -> str:
    """POSIX single-quote *value* for safe interpolation into a shell string.

    Used only for the container cwd, which arrives from the browser and is
    spliced into a ``cd ...`` prefix; without quoting, a directory name
    containing ``;`` or ``$(...)`` would be executed as a command.
    """
    return "'" + str(value).replace("'", "'\\''") + "'"


def _wrap_with_cwd(command: str) -> str:
    """Run *command*, then report the directory it finished in.

    ``cd /tmp`` in a one-shot shell is normally lost the moment the process
    exits, which makes a request/response console feel broken.  Appending
    ``pwd`` behind a marker lets the caller carry the new cwd into the next
    command, so ``cd`` appears to persist.  ``$?`` is captured before the extra
    commands run and re-raised as the exit status, so the reported rc stays the
    user's, not ``pwd``'s.
    """
    return (
        f"{command}\n"
        "__sh_rc=$?\n"
        f"printf '\\n%s' '{_CWD_MARKER}'\n"
        "pwd\n"
        "exit $__sh_rc\n"
    )


def _split_cwd(stdout: str, fallback: str) -> tuple[str, str]:
    """Peel the trailing cwd marker off *stdout* -> (clean stdout, cwd)."""
    idx = stdout.rfind(_CWD_MARKER)
    if idx < 0:
        # Command killed by a signal, or it exec'd something that replaced the
        # shell: no marker, so keep the output verbatim and the old cwd.
        return stdout, fallback
    tail = stdout[idx + len(_CWD_MARKER):].strip()
    body = stdout[:idx]
    # The marker is printed after a leading \n we added; drop just that one.
    if body.endswith("\n"):
        body = body[:-1]
    return body, (tail or fallback)


def _home_dir() -> str:
    """Best-effort home.  ``Path.home()`` RuntimeError must not 500 the terminal."""
    home = user_home()
    if home is not None:
        return str(home)
    # HOME unset: expanduser raises RuntimeError, not OSError.
    return (os.environ.get("HOME") or "").strip() or "/"


def _resolve_cwd(requested: str | None) -> str:
    """Pick a working directory: caller's, then configured, then $HOME.

    The requested value comes from the browser, so it is only ever used when it
    is an existing directory.  This is not a sandbox — the shell it feeds can
    ``cd`` anywhere the user can — it just keeps a stale tab from failing every
    command against a directory that has since been deleted.
    """
    # _cfg_value, not ``candidate or ""``: a leftover configured cwd with a
    # bombing ``__bool__`` used to raise out of the bare truthiness probe —
    # a 500 on POST /api/terminal/run and an unhandled exception out of the
    # PTY handshake before the session was even reserved.
    for candidate in (requested, _cfg_value(_terminal_cfg(), "cwd"), _home_dir()):
        # _config_text: a leftover hex-int cwd from YAML used to ValueError
        # the bare str() here (POST /api/terminal/run and the PTY handshake);
        # it also returns an *exact* str, so a leftover subclass ``.strip()``
        # bomb cannot raise here either.
        value = _config_text(candidate).strip()
        if not value:
            continue
        try:
            resolved = Path(value).expanduser()
            if resolved.is_dir():
                return str(resolved)
        except (OSError, ValueError, RuntimeError):
            # is_dir() raises EIO/ESTALE on a dying mount; expanduser("~")
            # RuntimeError's when HOME cannot be resolved.
            continue
    return _home_dir()


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover ``settings.terminal`` value whose ``__class__`` is
    a *raising property* detonated the bare type gates themselves —
    ``_config_text``'s str gate 500'd GET /api/terminal and
    POST /api/terminal/run (and raised out of the PTY handshake's
    ``_resolve_cwd``) one line ahead of the laundering built to absorb junk
    scalars.  A real subclass still matches through the C-level type check;
    only a value that cannot answer what it is takes the non-matching branch
    (the storage_svc/vms_svc rule).
    """
    try:
        return isinstance(value, kinds)
    except Exception:
        return False


def _mapping_get(mapping, key, default=None):
    """Field read that a hostile mapping *key* cannot 500.

    The unbound ``dict.get`` bypasses a subclass ``.get`` override, but the
    hash probe still runs the *stored keys'* own ``__eq__`` — a leftover
    str-subclass key whose hash shadows ``host_enabled``/``cwd``/``shell``
    and whose ``__eq__`` raises used to detonate ``host_enabled()`` /
    ``_cfg_value`` — a 500 on GET /api/terminal and POST /api/terminal/run,
    and an unhandled exception out of the PTY handshake's RCE gate (the
    ups_svc/storage_pool rule).  Only the shadowed field degrades to its
    default.
    """
    try:
        return dict.get(mapping, key, default)
    except Exception:
        return default


def _terminal_cfg() -> dict:
    # The dict() launder itself in a try: settings_section already refuses
    # bombing containers, but tests and tooling patch the name, and a
    # section whose ``keys()``/``__iter__`` bombs used to raise out of the
    # copy — the same union guard config.settings_section applies.
    try:
        return dict(settings_section("terminal"))
    except Exception:
        return {}


def _cfg_truthy(value) -> bool:
    """``bool(value)`` that a leftover ``__bool__``/``__len__`` bomb cannot
    raise through.

    ``settings.terminal`` values are laundered into a plain dict, but the
    *values* survive as-is: a leftover subclass whose ``__bool__`` raises
    used to blow every bare truthiness probe (``host_enabled``, the
    ``value or fallback`` chains) — a 500 on GET /api/terminal and
    POST /api/terminal/run, and an unhandled exception straight out of the
    PTY WebSocket handshake.  An unreadable truthiness is treated as unset,
    which for the ``host_enabled`` RCE gate is also the safe default.
    """
    try:
        return bool(value)
    except Exception:
        return False


def _cfg_value(section: dict, key: str):
    """``section.get(key) or None`` without a bare truthiness probe.

    ``_mapping_get``, not the bare unbound ``dict.get``: the hash probe
    still runs hostile stored keys' own ``__eq__`` (see ``_mapping_get``).
    """
    value = _mapping_get(section, key)
    return value if _cfg_truthy(value) else None


def _config_text(value) -> str:
    """``str(value)`` for a config scalar, or "" when it cannot be rendered.

    YAML ``0xFFF…`` loads as an int past CPython's 4300-digit str cap (hex
    parsing has no digit limit), so a bare ``str()`` on a leftover
    ``settings.terminal.cwd``/``shell`` raised ValueError before any sanitizer
    ran — a 500 on GET /api/terminal and POST /api/terminal/run.

    Always returns an *exact* ``str``: a leftover str subclass used to ride
    through the ``isinstance`` pass untouched, and its bombing ``.strip()``
    then raised out of ``_resolve_cwd`` — a 500 on POST /api/terminal/run and
    an unhandled exception out of the PTY handshake.
    """
    if value is None:
        return ""
    # _isa: a leftover whose ``__class__`` is a raising property used to
    # detonate this bare gate itself — a 500 on GET /api/terminal and
    # POST /api/terminal/run one line ahead of the laundering below.
    if _isa(value, str):
        try:
            if type(value) is str:
                return value
            # Unbound base copy: drops the subclass (and its method bombs).
            return str.__str__(value)
        except Exception:
            # A lying ``__class__`` (claims str, is not) TypeErrors the
            # unbound copy: unreadable, same "" as any unrenderable scalar.
            return ""
    try:
        text = str(value)
    except Exception:
        # ValueError past the digit cap; RecursionError from a leftover
        # self-referencing __str__.  Either way the scalar is unusable.
        return ""
    # A subclass ``__str__`` may hand back another subclass instance.
    return text if type(text) is str else str.__str__(text)


def host_enabled() -> bool:
    """True when the operator has explicitly switched the host shell on."""
    return _cfg_truthy(_mapping_get(_terminal_cfg(), "host_enabled", False))


def status() -> dict:
    """What the Terminal page needs to render its target picker."""
    tc = _terminal_cfg()
    # _config_text: a leftover YAML ``cwd: 0xFFF…`` is an int past the 4300
    # digit str cap — the bare str() 500'd GET /api/terminal before the
    # payload ever reached the sanitizer.  Unrenderable values fall back.
    # _cfg_value, not ``tc.get(...) or ""``: a leftover value with a bombing
    # ``__bool__`` used to raise out of the bare truthiness probe — a 500.
    cwd = _config_text(_cfg_value(tc, "cwd"))
    payload = {
        "host_enabled": host_enabled(),
        "shell": _config_text(_cfg_value(tc, "shell")) or _default_shell(),
        "cwd": cwd or _home_dir(),
        "default_timeout": DEFAULT_TIMEOUT,
        "max_timeout": MAX_TIMEOUT,
        # Advertised so the UI can explain *why* the host tab is locked without
        # hardcoding the policy in JS.
        "host_requires": ["admin password", "settings.terminal.host_enabled"],
        # The PTY endpoint still performs its own strict session and Origin
        # checks; this flag only advertises transport availability to the UI.
        "interactive": True,
        "max_output": MAX_OUTPUT,
    }
    # Leftover YAML ``cwd: "\\ud800"`` / ``shell: .inf`` used to 500 GET /api/terminal.
    cleaned = _jsonable(payload)
    return cleaned if isinstance(cleaned, dict) else payload


def _default_shell() -> str:
    shell = os.environ.get("SHELL") or "/bin/zsh"
    try:
        ok = Path(shell).exists()
    except (OSError, ValueError):
        # exists() still raises EIO/ESTALE on a dying mount; pathlib only
        # swallows ENOENT/ELOOP.
        ok = False
    return shell if ok else "/bin/sh"


#: Rotation bounds for the audit trail.  Append-only with no trim, the log grew
#: without limit (every alerts/metrics file here is bounded; this one was not),
#: and recent_audit() reads the whole file per history request.
_AUDIT_MAX_BYTES = 512 * 1024
_AUDIT_KEEP_LINES = 1000
#: Serialises append + trim.  The trim is a read-tail-then-rename; a command
#: audited by another request thread inside that window vanished with the
#: temp-file swap, and this trail is the only record of what was typed into
#: a root-capable shell.
_AUDIT_LOCK = threading.Lock()
#: Longest string one field may contribute to a trail line.  Unbounded, a
#: leftover runaway field wrote a line wider than every tail window this
#: module uses: the reader's seek landed mid-line and the torn-row prefix
#: drop hid every intact command row behind it, and the trim's own tail-read
#: held no complete line.  hub/audit.py bounds its trail the same way; the
#: cap is applied to the *audit* payload only — ``_response`` still carries
#: run output up to MAX_OUTPUT untouched.  64 KB keeps the largest
#: legitimate field (MAX_COMMAND_LEN is 8000) intact many times over.
_AUDIT_STR_CAP = 64 * 1024


def _now() -> int:
    """Finite unix timestamp. Leftover ``time.time() = inf`` OverflowError'd run/audit."""
    try:
        return int(time.time())
    except (TypeError, ValueError, OverflowError):
        return 0


def _duration_ms(started, ended) -> int:
    """Finite non-negative milliseconds between two clock reads.

    Leftover ``time.time() = inf`` made the elapsed time nan/inf here:
    ``int(nan)`` is ValueError and ``int(inf)`` OverflowError, which used to
    500 POST /api/terminal/run *after* the command had already executed — and
    the same math in the PTY / VM-console end audits raised out of a
    ``finally``, skipping the session release and the socket close.
    """
    try:
        ms = int((ended - started) * 1000)
    except (TypeError, ValueError, OverflowError):
        return 0
    return ms if ms >= 0 else 0


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500."""
    try:
        base = bytes if isinstance(value, bytes) else bytearray
        return base.decode(value, "utf-8", "replace")
    except Exception:
        # A lying ``__class__`` (claims bytes, is not) TypeErrors the unbound
        # decode: unreadable, same "" as any undecodable leftover.
        return ""


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    # _isa on the bytes gate, try on the decode: a ``__class__``-property
    # bomb used to detonate the bare isinstance itself.
    if _isa(value, (bytes, bytearray)):
        return _decode_bytes(value)
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    if type(text) is not str:
        # A subclass ``__str__`` may hand back another subclass whose bound
        # ``.encode`` bombs; the unbound base copy drops the override.
        text = str.__str__(text)
    return text.encode("utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Python ``json.loads`` accepts ``Infinity`` in a leftover audit line;
    Starlette's response encoder does not.  ``!!binary`` / bytes ``who`` and
    a lone-surrogate command used to raise out of ``_audit`` after the
    command had already run.  A leftover ``\\ud800`` *key* on an audit line
    still 500'd GET /api/terminal/history (values were scrubbed, keys were not).
    Nested subclass bombs (bound ``items``/``decode``/``__iter__``/``__str__``
    raising) still blew the probes themselves — hence the unbound base-type
    calls below, the modules5 convention every sibling service already uses.
    _isa on every rank gate: a leftover whose ``__class__`` is a raising
    property used to detonate the bare isinstance itself, one line ahead of
    the coercion built to absorb the value (the vms_svc/system rule).
    """
    if depth > 32:
        return None
    # ``type(value) is bool``, not ``_isa(value, bool)``: bool cannot be
    # subclassed, so anything else that answers the bool gate is a *liar*
    # whose ``__class__`` property returns ``bool``.  Passed through raw, the
    # impostor escaped every launder below and TypeError'd Starlette's
    # encoder — a raw 500 on POST /api/terminal/run after the command had
    # already executed.  The liar falls through to the int gate (bool is an
    # int to ``isinstance``) where the unbound ``int.__index__`` copy
    # refuses it and it degrades to None like every other impostor.
    if value is None or type(value) is bool:
        return value
    if _isa(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__``
                # bomb used to blow the digit-cap probe below.
                value = int.__index__(value)
            except Exception:
                return None
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if _isa(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except Exception:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isa(value, str):
        return _utf8_text(value)
    if _isa(value, (bytes, bytearray)):
        return _decode_bytes(value)
    if _isa(value, dict):
        # Unbound base view: a dict subclass whose ``items()`` raises used
        # to blow the walk itself.  In a try: a lying ``__class__`` (claims
        # dict, is not) TypeErrors the unbound view — the node is unreadable.
        try:
            items = list(dict.items(value))
        except Exception:
            return None
        out = {}
        for k, v in items:
            if _isa(k, (bytes, bytearray)):
                k = _decode_bytes(k)
            elif not _isa(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if _isa(value, (list, tuple, set, frozenset)):
        for base in (list, tuple, set, frozenset):
            if _isa(value, base):
                # Unbound base iteration: a subclass ``__iter__`` bomb
                # cannot raise and the real elements still survive.  In a
                # try: a lying ``__class__`` TypeErrors the unbound call.
                try:
                    members = list(base.__iter__(value))
                except Exception:
                    return None
                return [_jsonable(v, depth + 1) for v in members]
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # getattr's default only swallows AttributeError; a property or
        # ``__getattr__`` bomb still raised out of the probe itself.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 POST /api/terminal/run.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _response(result: dict) -> dict:
    """JSON-safe run payload. Leftover ``cwd: \\ud800`` used to 500 the encoder."""
    cleaned = _jsonable(result)
    return cleaned if isinstance(cleaned, dict) else result


#: Every field ``run_host``/``run_container`` reads or mutates on a run
#: receipt.  ``-255`` is the same no-honest-exit-status junk sentinel
#: ``_rc_int`` answers, so an unreadable receipt reads as one failed
#: command, never a crash.
_RECEIPT_DEFAULTS = {
    "ok": False,
    "rc": -255,
    "stdout": "",
    "stderr": "",
    "truncated": False,
    "duration_ms": 0,
}

#: Fields ``run_host``/``run_container`` *write* onto the receipt after the
#: command ran.  They are not transport fields, so ``_RECEIPT_DEFAULTS`` does
#: not seed them — which left their hash buckets open: a leftover str-subclass
#: key whose ``__hash__`` lands on ``target``/``container``/``cwd`` slipped
#: through the copy (no seeded key to collide with, so its ``__eq__`` never
#: ran) and the bare ``result["target"] = ...`` writes then probed that bucket
#: and ran the stored key's own raising ``__eq__`` — a raw 500 on
#: POST /api/terminal/run *after* the command had already executed.  Seeding a
#: placeholder makes every such collider drop at insert time exactly like the
#: transport-field shadows; untouched placeholders are stripped again so the
#: response shape is unchanged.
_MUTATED_FIELDS = ("target", "container", "cwd")
_UNSET = object()


def _receipt_map(result) -> dict:
    """Plain-dict copy of a ``_run`` receipt with every transport field present.

    ``run_host``/``run_container`` do not own the receipt (tests and tooling
    patch ``_run``), and the callers used to index and *mutate* it bare:

    * a dict-*subclass* receipt whose ``.get``/``__getitem__``/``__setitem__``
      raises detonated ``result["stdout"]`` / ``result["target"] = ...``;
    * a receipt missing a field KeyError'd the same reads;
    * a leftover str-subclass *key* whose hash shadows ``rc``/``stderr`` and
      whose ``__eq__`` raises detonated the probe lookups themselves —

    each a raw 500 on POST /api/terminal/run *after* the command had already
    executed.  The unbound ``dict.items`` view bypasses subclass overrides; a
    lying ``__class__`` (claims dict, is not) TypeErrors it and the whole
    receipt degrades to the failed-command stub.  Each insert is guarded on
    its own: a hostile key that collides with a seeded field runs its *own*
    ``__eq__`` inside the probe, and only that key's entry drops.
    """
    out = dict(_RECEIPT_DEFAULTS)
    # Placeholders for the post-run mutation fields: a collider key whose
    # hash lands on ``target``/``container``/``cwd`` now meets a seeded
    # exact-str key at insert time and drops here, instead of detonating
    # the later bare ``result[...] = ...`` writes (see _MUTATED_FIELDS).
    for field in _MUTATED_FIELDS:
        out[field] = _UNSET
    if _isa(result, dict):
        try:
            items = list(dict.items(result))
        except Exception:
            items = []
        for key, val in items:
            try:
                out[key] = val
            except Exception:
                # Unhashable key, or a hash-shadowing key whose __eq__
                # raised against the seeded exact-str field: the seeded
                # default stays and only this entry degrades.
                continue
    # Strip the placeholders the receipt did not overwrite, so a host run's
    # payload still has no ``container`` key and the response shape is
    # byte-for-byte what it was before the seeding.
    for field in _MUTATED_FIELDS:
        if out.get(field) is _UNSET:
            del out[field]
    return out


def _clip_audit_text(text: str) -> str:
    """One audit field, bounded.  Same marker shape as util.py's log tailer;
    slicing is by code point, so the clip cannot mint a torn surrogate."""
    if len(text) > _AUDIT_STR_CAP:
        return text[:_AUDIT_STR_CAP] + " …[truncated]"
    return text


def _clip_audit(value):
    """Bound every string in an already-``_jsonable`` audit payload.

    Runs on write (so a runaway field can never mint a trail line wider
    than the tail windows) and on read (so a leftover fat field already on
    disk is bounded on its way to the browser).  The input is post-shaping
    plain JSON types, so plain bound calls are safe here.
    """
    if isinstance(value, str):
        return _clip_audit_text(value)
    if isinstance(value, dict):
        return {_clip_audit_text(k): _clip_audit(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clip_audit(v) for v in value]
    return value


def _audit(entry: dict[str, Any]) -> None:
    """Append one line to the audit log; never let logging break the request."""
    try:
        payload = _jsonable(entry)
        if not isinstance(payload, dict):
            return
        # Clip after shaping: a leftover unbounded field (the auth trail's
        # found case was a 300 KB command) used to write a line wider than
        # the trim's own 512 KB tail window, turning the next trim into a
        # rewrite that kept nothing.
        payload = _clip_audit(payload)
        # create_secret_text first, so the file is 0600 from the moment it
        # exists.  Appending and *then* chmod'ing left the first write at the
        # umask default -- 0644 on this host -- and this log holds whatever the
        # operator typed into a root-capable shell, which is the one thing in it
        # that cannot be un-leaked.  Create-if-absent rather than write, because
        # write_secret_text opens with O_TRUNC and would empty the trail.
        # The locks cover append *and* trim: without them, a line appended by
        # a concurrent request between the tail-read and the rename was lost.
        # The flock matters beyond this interpreter: the packaged .app and
        # the LaunchAgent panel share one data/, and a trim in one process
        # used to swap away a command line the other had just appended.
        with _AUDIT_LOCK, secure_io.file_lock(AUDIT_PATH):
            secure_io.create_secret_text(AUDIT_PATH, "")
            secure_io.append_text(
                AUDIT_PATH,
                json.dumps(payload, ensure_ascii=False, allow_nan=False, default=str) + "\n",
                mode=0o600,
            )
            os.chmod(AUDIT_PATH, 0o600)
            if AUDIT_PATH.stat().st_size > _AUDIT_MAX_BYTES:
                # Tail + atomic replace: a full slurp of a 512KB+ trail was
                # pointless, and write_secret_text (O_TRUNC) emptied the log
                # if the process died mid-rewrite.
                lines = tail_file_lines(
                    AUDIT_PATH, _AUDIT_KEEP_LINES, max_bytes=_AUDIT_MAX_BYTES
                )
                # Refuse the rewrite when the tail window holds no complete
                # line (a leftover torn fat line glued to the append).  The
                # unguarded rewrite emptied the *entire* command history on
                # the next audited command — the one loss this trail exists
                # to prevent.  hub/audit.py's _trim has the same guard.
                if lines:
                    secure_io.replace_secret_text(
                        AUDIT_PATH, "\n".join(lines) + "\n"
                    )
    except (OSError, ValueError, TypeError, OverflowError, UnicodeError, RecursionError):
        # RecursionError: leftover nested terminal audit after _jsonable is not
        # ValueError; POST /api/terminal/run used to 500 after the command ran.
        pass


def _reap_group(proc: subprocess.Popen) -> None:
    for sig, grace in ((signal.SIGTERM, 2), (signal.SIGKILL, 2)):
        if proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            continue


def _drain_capped(stream, limit: int) -> tuple[str, bool]:
    """Read *stream* line-capped, keep at most *limit* characters."""
    parts: list[str] = []
    total = 0
    clipped = False
    try:
        for line in iter_capped_lines(stream, 4096):
            if total >= limit:
                clipped = True
                continue
            room = limit - total
            if len(line) > room:
                parts.append(line[:room])
                total = limit
                clipped = True
            else:
                parts.append(line)
                total += len(line)
                if total < limit:
                    parts.append("\n")
                    total += 1
    except (OSError, ValueError):
        pass
    return "".join(parts), clipped


def _run(argv: list[str], timeout: int, cwd: str | None = None) -> dict:
    """Run *argv* with a byte cap and a process-group watchdog.

    ``subprocess.run(capture_output=True)`` buffered the whole pipe until
    exit.  ``yes`` / ``find /`` / ``cat`` of a huge file could RSS-bomb the
    panel for up to :data:`MAX_TIMEOUT` seconds before ``_drain_capped`` ran.
    """
    started = time.time()
    timeout = _clamp_timeout(timeout)
    try:
        proc = subprocess.Popen(
            list(argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            cwd=cwd or None,
            env=_color_env(),
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except FileNotFoundError:
        return {
            "ok": False, "rc": 127, "stdout": "", "stderr": f"not found: {argv[0]}",
            "truncated": False, "duration_ms": 0,
        }
    except (OSError, ValueError, TypeError):
        # cwd EIO/ESTALE is OSError, not FileNotFoundError.  NUL argv is
        # ValueError.  Either used to 500 POST /api/terminal/run.
        return {
            "ok": False, "rc": 127, "stdout": "", "stderr": "invalid argument",
            "truncated": False, "duration_ms": 0,
        }
    timed_out = threading.Event()

    def _on_deadline():
        if proc.poll() is None:
            timed_out.set()
            _reap_group(proc)

    watchdog = threading.Timer(timeout, _on_deadline)
    watchdog.daemon = True
    watchdog.start()
    out_box: list[tuple[str, bool]] = []
    err_box: list[tuple[str, bool]] = []

    def _read_out():
        out_box.append(_drain_capped(proc.stdout, MAX_OUTPUT))

    def _read_err():
        err_box.append(_drain_capped(proc.stderr, MAX_OUTPUT))

    readers = [
        threading.Thread(target=_read_out, daemon=True),
        threading.Thread(target=_read_err, daemon=True),
    ]
    for t in readers:
        t.start()
    try:
        proc.wait()
    finally:
        watchdog.cancel()
        if timed_out.is_set() or proc.poll() is None:
            _reap_group(proc)
        for t in readers:
            t.join(timeout=2)
        for stream in (proc.stdout, proc.stderr):
            close = getattr(stream, "close", None)
            if close is not None:
                try:
                    close()
                except OSError:
                    pass
    if timed_out.is_set():
        raise api_error("terminal.timeout", seconds=timeout)
    out, out_clipped = out_box[0] if out_box else ("", False)
    err, err_clipped = err_box[0] if err_box else ("", False)
    return {
        "ok": proc.returncode == 0,
        "rc": proc.returncode if proc.returncode is not None else -1,
        "stdout": out,
        "stderr": err,
        "truncated": out_clipped or err_clipped,
        "duration_ms": _duration_ms(started, time.time()),
    }


def _clamp_timeout(timeout: int | None) -> int:
    # _isa: a leftover timeout whose ``__class__`` is a raising property used
    # to detonate the bare bool gate itself before the int() launder ran.
    if _isa(timeout, bool) or timeout is None:
        value = DEFAULT_TIMEOUT
    else:
        try:
            # Bare except-Exception, not the usual numeric trio: int() of a
            # leftover int *subclass* runs the subclass's own ``__int__``,
            # and a bomb there raises an arbitrary type.  On success int()
            # always answers an exact int, so the clamp below is safe.
            value = int(timeout)
        except Exception:
            value = DEFAULT_TIMEOUT
    return max(1, min(value, MAX_TIMEOUT))


def _spawn_receipt(argv: list[str], timeout: int, cwd: str | None = None) -> dict:
    """``_run`` through the seam guard, laundered into a plain receipt.

    ``run_host``/``run_container`` do not own the runner (tests and tooling
    patch ``_run``), and the call itself was bare: a patched runner that
    *raises* — any exception type at all — used to unwind straight out of
    POST /api/terminal/run as a raw 500 (the vms11/storage11 runner-seam
    rule).  Coded ``HTTPException``s pass through untouched, because
    ``_run``'s own timeout answer *is* the coded 504 and must stay it.
    Anything else degrades to the failed-command stub: rc ``-255`` — never
    ``127`` and never ``-1`` — with an empty stderr, so an unusable runner
    answer can neither forge the vanished-CLI confirm nor read like the
    engine-down phrases; the caller's 503 still requires honest evidence.
    """
    try:
        return _receipt_map(_run(argv, timeout, cwd=cwd))
    except HTTPException:
        raise
    except Exception:
        return _receipt_map({})


def _looks_engine_down(blob: str) -> bool:
    """``looks_engine_down`` through the seam guard.

    The classifier's answer fed a bare ``or`` truthiness probe, and the call
    itself was unguarded: a patched classifier that raises, or one answering
    a leftover whose ``__bool__`` bombs, used to detonate the failure branch
    — a raw 500 on POST /api/terminal/run *after* the command had already
    executed.  An unreadable answer is no classification: the run keeps its
    own receipt, the same non-matching branch honest output takes.
    """
    try:
        return _cfg_truthy(looks_engine_down(blob))
    except Exception:
        return False


def _engine_confirmed_down() -> bool:
    """Forced ``engine_up`` probe through the seam guard, inverted.

    The coded 503 replaces the command's own output, so it requires a
    *confirmed* down answer.  The bare ``not engine_up(force=True)`` ran a
    raising patched probe — and a probe answering a ``__bool__``-bombing
    leftover — straight into a raw 500 after the command had executed.  An
    unreadable probe answer confirms nothing (``_cfg_truthy`` alone would
    read the bomb as falsy and *mint* the 503 from junk): the receipt is
    handed back verbatim, exactly what the route answered before the
    classifier existed.  Only an honest falsy answer confirms down.
    """
    try:
        answer = engine_up(force=True)
    except Exception:
        return False
    try:
        return not bool(answer)
    except Exception:
        return False


def _check_command(command: str) -> str:
    # _isa + _config_text: a leftover command whose ``__class__`` is a
    # raising property used to detonate the bare isinstance, and a str
    # subclass ``.strip()`` bomb raised one line later.  An unreadable
    # command degrades to the coded 400, never a 500.
    if not _isa(command, str):
        raise api_error("terminal.empty_command")
    cmd = _config_text(command).strip()
    if not cmd:
        raise api_error("terminal.empty_command")
    if "\x00" in cmd:
        raise api_error("terminal.bad_command")
    if len(cmd) > MAX_COMMAND_LEN:
        raise api_error("terminal.command_too_long", max=MAX_COMMAND_LEN)
    return cmd


def run_host(
    command: str,
    timeout: int | None = None,
    who: str = "",
    cwd: str = "",
) -> dict:
    """Run *command* on the host through a login-less shell.

    Gated on ``settings.terminal.host_enabled``.  The command string is passed
    to ``$SHELL -c`` verbatim: this is an admin console, so pipes, redirection
    and globbing are the point.  There is deliberately no allowlist — a partial
    one would imply a safety property we cannot actually deliver.  The real
    control is that reaching this function at all requires an authenticated
    session plus an explicit opt-in.

    *cwd* lets a console tab carry its working directory between commands, so
    ``cd`` behaves the way it does in a real shell.
    """
    if not host_enabled():
        raise api_error("terminal.host_disabled")
    cmd = _check_command(command)
    secs = _clamp_timeout(timeout)
    tc = _terminal_cfg()
    # _config_text: a leftover hex-int shell from YAML used to ValueError the
    # bare str() here, 500'ing the run before the command ever started.
    # _cfg_value: a leftover shell with a bombing ``__bool__`` used to raise
    # out of the bare ``or`` truthiness probe the same way.
    shell = _config_text(_cfg_value(tc, "shell")) or _default_shell()
    start_cwd = _resolve_cwd(cwd)

    # _spawn_receipt: run_host does not own ``_run`` (tests and tooling
    # patch it) — a runner that *raises* used to unwind out of the route as
    # a raw 500, and a dict-subclass receipt whose item hooks raise, a
    # receipt missing a field, or a hash-shadowing key used to detonate
    # the bare ``result[...]`` reads and writes below — a raw 500 after the
    # command had already executed.  _config_text on stdout: a non-str (or
    # a str subclass whose ``rfind``/``endswith`` raises) used to blow
    # ``_split_cwd`` the same way.
    result = _spawn_receipt([shell, "-c", _wrap_with_cwd(cmd)], secs, cwd=start_cwd)
    result["stdout"], end_cwd = _split_cwd(
        _config_text(_mapping_get(result, "stdout", "")), start_cwd
    )
    _audit({
        "ts": _now(),
        "target": "host",
        "who": who,
        # The directory the command *ran in* is the useful audit fact; where it
        # ended up is only state for the next request.
        "cwd": start_cwd,
        "shell": shell,
        "command": cmd,
        "rc": _mapping_get(result, "rc", -255),
        "duration_ms": _mapping_get(result, "duration_ms", 0),
    })
    result["target"] = "host"
    # Echoed back so the client can carry it into the next command, making `cd`
    # appear to persist across an inherently stateless transport.
    result["cwd"] = end_cwd
    return _response(result)


def _rc_int(rc) -> int:
    """Exact exit status for the ``!=`` probes; a bomb reads as failure.

    ``run_container`` does not own ``_run``'s receipt (tests and tooling
    patch it), and an rc *subclass* whose ``__eq__``/``__ne__`` raises used
    to detonate ``result["rc"] != 0`` past the spawn try — a raw 500 on
    POST /api/terminal/run *after* the command had already executed (the
    wireguard_svc._ping_rc / health9 rule).  ``-255`` is no honest exit
    status, so a bomb reads as one failed command, never a crash.
    """
    if _isa(rc, bool) or rc is None:
        return -255
    try:
        # Unbound base read: bypasses subclass ``__eq__``/``__index__`` bombs.
        return int.__index__(rc)
    except Exception:
        return -255


def _docker_vanished(result: dict) -> bool:
    """True when the run receipt is ``_run``'s docker spawn sentinel and the
    CLI is confirmed gone from disk.

    ``_run`` collapses a FileNotFoundError spawn into ``rc 127`` +
    ``"not found: <argv[0]>"``.  For a container run that argv[0] is the
    docker CLI, so a binary that vanished between requests (OrbStack
    uninstalled mid-session, a dying mount) used to come back as the
    command's *own* output — a raw untranslated receipt the SPA cannot
    explain, while the Containers page answers the coded 503 for the same
    state.  The sentinel alone is not proof (a container command can print
    the same words): confirm on the filesystem, on this failure path only
    — the docker_cli ``looks_cli_vanished`` convention — and the caller
    still forces the ``engine_up`` probe, which cannot answer "up" while
    the CLI is gone.
    """
    # _rc_int: an rc-subclass ``__ne__`` bomb in a patched receipt used to
    # detonate the bare comparison (the run_container rc probe rule).
    # _mapping_get, not the bound ``.get``: a dict-subclass receipt whose
    # ``.get`` raises, or a hash-shadowing stored key whose ``__eq__``
    # raises, used to detonate the probe read itself the same way.
    if _rc_int(_mapping_get(result, "rc")) != 127:
        return False
    if _config_text(_mapping_get(result, "stderr")).strip() != f"not found: {DOCKER}":
        return False
    try:
        return not Path(DOCKER).exists()
    except (OSError, ValueError):
        # exists() raises EIO/ESTALE on a dying mount: the CLI is not
        # spawnable from there either way.
        return True


def run_container(
    container: str,
    command: str,
    shell: str = "/bin/sh",
    timeout: int | None = None,
    who: str = "",
    cwd: str = "",
) -> dict:
    """Run *command* inside *container* via ``docker exec``.

    Deliberately *not* gated on ``host_enabled``: the blast radius is one
    container, and ``docker exec`` was already reachable from the Containers
    page.  Only the usual authenticated panel session is required.

    *cwd* is the directory inside the container, carried between commands the
    same way the host shell does it.
    """
    # _isa + _config_text on every caller-supplied string: a leftover whose
    # ``__class__`` is a raising property used to detonate the bare
    # isinstance gates, and a str-subclass ``.strip()``/``__bool__`` bomb
    # raised out of the launder one line later.  Unreadable values degrade
    # to the coded 400s, never a 500.
    if not _isa(container, str):
        raise api_error("terminal.no_container")
    name = _config_text(container).strip()
    if not name:
        raise api_error("terminal.no_container")
    name = cli_args.require_positional(name, label="container name")
    cmd = _check_command(command)
    secs = _clamp_timeout(timeout)
    # ``container`` and ``target`` already tolerate leftover non-str values;
    # a non-str shell used to AttributeError on .strip() here.
    sh = _config_text(shell if _isa(shell, str) else "").strip() or "/bin/sh"
    # A container path cannot be validated from the host, so pass it through and
    # let the shell fall back to its own default if the directory is gone.
    start_cwd = _config_text(cwd).strip()
    wrapped = _wrap_with_cwd(cmd)
    if start_cwd:
        wrapped = f"cd {_sh_quote(start_cwd)} 2>/dev/null || true\n{wrapped}"

    # _spawn_receipt: the same seam guard + launder run_host applies — a
    # raising patched runner, a dict-subclass receipt, a missing field or a
    # hash-shadowing key used to detonate the route after the command
    # already executed.
    result = _spawn_receipt([DOCKER, "exec", "--", name, sh, "-c", wrapped], secs)
    result["stdout"], end_cwd = _split_cwd(
        _config_text(_mapping_get(result, "stdout", "")), start_cwd
    )
    _audit({
        "ts": _now(),
        "target": "container",
        "container": name,
        "who": who,
        "cwd": start_cwd,
        "shell": sh,
        "command": cmd,
        "rc": _mapping_get(result, "rc", -255),
        "duration_ms": _mapping_get(result, "duration_ms", 0),
    })
    # _rc_int / _config_text on the probe inputs: run_container does not own
    # ``_run``'s receipt (tests and tooling patch it), and an rc-subclass
    # ``__ne__`` bomb or a stdout/stderr subclass whose ``__bool__``/``__str__``
    # raises used to detonate the bare comparison / or-truthiness f-string —
    # a raw 500 after the command had already executed.  _mapping_get on the
    # reads: a stateful hostile key that survived the launder still cannot
    # 500 the probe lookups themselves.  _looks_engine_down /
    # _engine_confirmed_down: the classifier and the forced probe are patched
    # seams too — a raising probe, or one answering a ``__bool__``-bombing
    # leftover, used to detonate the bare ``or`` / ``not`` right here.
    if (
        _rc_int(_mapping_get(result, "rc")) != 0
        and (
            _looks_engine_down(
                f"{_config_text(_mapping_get(result, 'stderr'))}\n"
                f"{_config_text(_mapping_get(result, 'stdout'))}"
            )
            or _docker_vanished(result)
        )
        and _engine_confirmed_down()
    ):
        # A dead daemon used to be presented as the command's own output
        # (raw untranslated stderr).  Coded 503 like the Containers page;
        # raised after the audit line so the trail still records the attempt.
        # The probe is forced (5s memo) and only runs on this failure path —
        # a command whose own output quotes these strings while the engine
        # answers "up" keeps its output verbatim.  A docker CLI that vanished
        # before the spawn (``_run``'s rc-127 "not found" sentinel, confirmed
        # absent on disk) is the same docker-unreachable state and used to be
        # handed back as the command's own rc-127 receipt.
        raise api_error("container.engine_down")
    result["target"] = "container"
    result["container"] = name
    result["cwd"] = end_cwd
    return _response(result)


def execute(
    target: str,
    command: str,
    container: str = "",
    shell: str = "",
    timeout: int | None = None,
    who: str = "",
    cwd: str = "",
) -> dict:
    # _isa + _config_text: the same class-property / subclass-method bomb
    # guard every other caller-supplied string above gets.
    if not _isa(target, str):
        raise api_error("terminal.bad_target", target="")
    tgt = (_config_text(target) or "host").strip().lower()
    if tgt == "host":
        return run_host(command, timeout=timeout, who=who, cwd=cwd)
    if tgt == "container":
        return run_container(
            container, command, shell=shell or "/bin/sh", timeout=timeout,
            who=who, cwd=cwd,
        )
    raise api_error("terminal.bad_target", target=tgt)


def _capped_json_int(text):
    """``json.loads`` parse_int hook: an over-cap digit run drops to None.

    ``int()`` of a >4300-digit number is the digit-cap *ValueError* (not
    JSONDecodeError) for the whole line, so one absurd number in a single
    audit entry (a hand-edited ``ts``/``rc``, a restored backup) used to make
    :func:`recent_audit` skip the entire row — silently hiding a command line
    from the only record of what was typed into a root-capable shell.  The
    hook loads the huge literal as None and the rest of the row survives.
    """
    try:
        return int(text)
    except ValueError:
        return None


def recent_audit(limit: int = 50) -> list[dict]:
    """Tail of the audit log, newest last.  Used by the Terminal history pane."""
    # _isa + except-Exception: the _clamp_timeout rule — a class-property
    # bomb detonated the bare bool gate, and int() of a leftover int
    # subclass runs the subclass's own bombing ``__int__``.
    if _isa(limit, bool) or limit is None:
        n = 50
    else:
        try:
            n = int(limit)
        except Exception:
            n = 50
    n = max(1, min(n, 500))
    try:
        if not AUDIT_PATH.exists():
            return []
        # The byte window must match what the trim legitimately keeps
        # (_AUDIT_MAX_BYTES), not tail_file_lines' 256 KB default.  With the
        # smaller window, one leftover fat line at the tail put the seek
        # mid-line and the torn-row prefix-drop then discarded every complete
        # row in the window — GET /api/terminal/history answered an empty
        # pane while intact command rows sat on disk right before the fat
        # line.  The same undersizing quietly under-filled honest requests:
        # 500 rows of ~1 KB each need ~500 KB.  hub/audit.recent fixed the
        # identical mismatch for the auth trail.
        lines = tail_file_lines(AUDIT_PATH, n, max_bytes=_AUDIT_MAX_BYTES)
    except OSError:
        return []
    out: list[dict] = []
    for raw in lines:
        try:
            parsed = safe_json_loads(raw, parse_int=_capped_json_int)
        except (ValueError, RecursionError):
            continue
        if isinstance(parsed, dict):
            cleaned = _jsonable(parsed)
            if isinstance(cleaned, dict):
                # Clip on read too: a leftover fat field written by an older
                # build (or another writer) is bounded before Starlette
                # renders it, the same both-ways clip the auth trail applies.
                out.append(_clip_audit(cleaned))
    return out
