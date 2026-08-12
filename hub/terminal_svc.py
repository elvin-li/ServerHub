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
import subprocess
import time
from pathlib import Path
from typing import Any

from hub import secure_io
from hub.config import cfg
from hub.errors import CODES, api_error
from hub.paths import DATA_DIR, DOCKER

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
    return env


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


def _resolve_cwd(requested: str | None) -> str:
    """Pick a working directory: caller's, then configured, then $HOME.

    The requested value comes from the browser, so it is only ever used when it
    is an existing directory.  This is not a sandbox — the shell it feeds can
    ``cd`` anywhere the user can — it just keeps a stale tab from failing every
    command against a directory that has since been deleted.
    """
    for candidate in (requested, _terminal_cfg().get("cwd"), str(Path.home())):
        value = str(candidate or "").strip()
        if value and Path(value).expanduser().is_dir():
            return str(Path(value).expanduser())
    return str(Path.home())


def _terminal_cfg() -> dict:
    return dict(((cfg().get("settings") or {}).get("terminal") or {}))


def host_enabled() -> bool:
    """True when the operator has explicitly switched the host shell on."""
    return bool(_terminal_cfg().get("host_enabled", False))


def status() -> dict:
    """What the Terminal page needs to render its target picker."""
    tc = _terminal_cfg()
    return {
        "host_enabled": host_enabled(),
        "shell": str(tc.get("shell") or _default_shell()),
        "cwd": str(tc.get("cwd") or str(Path.home())),
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


def _default_shell() -> str:
    shell = os.environ.get("SHELL") or "/bin/zsh"
    return shell if Path(shell).exists() else "/bin/sh"


#: Rotation bounds for the audit trail.  Append-only with no trim, the log grew
#: without limit (every alerts/metrics file here is bounded; this one was not),
#: and recent_audit() reads the whole file per history request.
_AUDIT_MAX_BYTES = 512 * 1024
_AUDIT_KEEP_LINES = 1000


def _audit(entry: dict[str, Any]) -> None:
    """Append one line to the audit log; never let logging break the request."""
    try:
        # create_secret_text first, so the file is 0600 from the moment it
        # exists.  Appending and *then* chmod'ing left the first write at the
        # umask default -- 0644 on this host -- and this log holds whatever the
        # operator typed into a root-capable shell, which is the one thing in it
        # that cannot be un-leaked.  Create-if-absent rather than write, because
        # write_secret_text opens with O_TRUNC and would empty the trail.
        secure_io.create_secret_text(AUDIT_PATH, "")
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        os.chmod(AUDIT_PATH, 0o600)
        if AUDIT_PATH.stat().st_size > _AUDIT_MAX_BYTES:
            lines = AUDIT_PATH.read_text(errors="replace").splitlines(keepends=True)
            secure_io.write_secret_text(
                AUDIT_PATH, "".join(lines[-_AUDIT_KEEP_LINES:])
            )
    except OSError:
        pass


def _clip(text: str) -> tuple[str, bool]:
    if len(text) <= MAX_OUTPUT:
        return text, False
    return text[:MAX_OUTPUT], True


def _run(argv: list[str], timeout: int, cwd: str | None = None) -> dict:
    started = time.time()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd or None,
            env=_color_env(),
            # A console command must never inherit an interactive stdin.
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        raise api_error("terminal.timeout", seconds=timeout)
    except FileNotFoundError:
        # e.g. docker missing entirely
        return {
            "ok": False, "rc": 127, "stdout": "", "stderr": f"not found: {argv[0]}",
            "truncated": False, "duration_ms": 0,
        }
    out, out_clipped = _clip(proc.stdout or "")
    err, err_clipped = _clip(proc.stderr or "")
    return {
        "ok": proc.returncode == 0,
        "rc": proc.returncode,
        "stdout": out,
        "stderr": err,
        "truncated": out_clipped or err_clipped,
        "duration_ms": int((time.time() - started) * 1000),
    }


def _clamp_timeout(timeout: int | None) -> int:
    try:
        value = int(timeout or DEFAULT_TIMEOUT)
    except (TypeError, ValueError):
        value = DEFAULT_TIMEOUT
    return max(1, min(value, MAX_TIMEOUT))


def _check_command(command: str) -> str:
    cmd = (command or "").strip()
    if not cmd:
        raise api_error("terminal.empty_command")
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
    shell = str(tc.get("shell") or _default_shell())
    start_cwd = _resolve_cwd(cwd)

    result = _run([shell, "-c", _wrap_with_cwd(cmd)], secs, cwd=start_cwd)
    result["stdout"], end_cwd = _split_cwd(result["stdout"], start_cwd)
    _audit({
        "ts": int(time.time()),
        "target": "host",
        "who": who,
        # The directory the command *ran in* is the useful audit fact; where it
        # ended up is only state for the next request.
        "cwd": start_cwd,
        "shell": shell,
        "command": cmd,
        "rc": result["rc"],
        "duration_ms": result["duration_ms"],
    })
    result["target"] = "host"
    # Echoed back so the client can carry it into the next command, making `cd`
    # appear to persist across an inherently stateless transport.
    result["cwd"] = end_cwd
    return result


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
    name = (container or "").strip()
    if not name:
        raise api_error("terminal.no_container")
    cmd = _check_command(command)
    secs = _clamp_timeout(timeout)
    sh = (shell or "/bin/sh").strip() or "/bin/sh"
    # A container path cannot be validated from the host, so pass it through and
    # let the shell fall back to its own default if the directory is gone.
    start_cwd = str(cwd or "").strip()
    wrapped = _wrap_with_cwd(cmd)
    if start_cwd:
        wrapped = f"cd {_sh_quote(start_cwd)} 2>/dev/null || true\n{wrapped}"

    result = _run([DOCKER, "exec", name, sh, "-c", wrapped], secs)
    result["stdout"], end_cwd = _split_cwd(result["stdout"], start_cwd)
    _audit({
        "ts": int(time.time()),
        "target": "container",
        "container": name,
        "who": who,
        "cwd": start_cwd,
        "shell": sh,
        "command": cmd,
        "rc": result["rc"],
        "duration_ms": result["duration_ms"],
    })
    result["target"] = "container"
    result["container"] = name
    result["cwd"] = end_cwd
    return result


def execute(
    target: str,
    command: str,
    container: str = "",
    shell: str = "",
    timeout: int | None = None,
    who: str = "",
    cwd: str = "",
) -> dict:
    tgt = (target or "host").strip().lower()
    if tgt == "host":
        return run_host(command, timeout=timeout, who=who, cwd=cwd)
    if tgt == "container":
        return run_container(
            container, command, shell=shell or "/bin/sh", timeout=timeout,
            who=who, cwd=cwd,
        )
    raise api_error("terminal.bad_target", target=tgt)


def recent_audit(limit: int = 50) -> list[dict]:
    """Tail of the audit log, newest last.  Used by the Terminal history pane."""
    if not AUDIT_PATH.exists():
        return []
    try:
        lines = AUDIT_PATH.read_text(errors="replace").splitlines()
    except OSError:
        return []
    out: list[dict] = []
    for raw in lines[-max(1, min(limit, 500)):]:
        try:
            out.append(json.loads(raw))
        except ValueError:
            continue
    return out
