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
    for candidate in (requested, _terminal_cfg().get("cwd"), _home_dir()):
        # _config_text: a leftover hex-int cwd from YAML used to ValueError
        # the bare str() here (POST /api/terminal/run and the PTY handshake).
        value = _config_text(candidate or "").strip()
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


def _terminal_cfg() -> dict:
    return dict(settings_section("terminal"))


def _config_text(value) -> str:
    """``str(value)`` for a config scalar, or "" when it cannot be rendered.

    YAML ``0xFFF…`` loads as an int past CPython's 4300-digit str cap (hex
    parsing has no digit limit), so a bare ``str()`` on a leftover
    ``settings.terminal.cwd``/``shell`` raised ValueError before any sanitizer
    ran — a 500 on GET /api/terminal and POST /api/terminal/run.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:
        # ValueError past the digit cap; RecursionError from a leftover
        # self-referencing __str__.  Either way the scalar is unusable.
        return ""


def host_enabled() -> bool:
    """True when the operator has explicitly switched the host shell on."""
    return bool(_terminal_cfg().get("host_enabled", False))


def status() -> dict:
    """What the Terminal page needs to render its target picker."""
    tc = _terminal_cfg()
    # _config_text: a leftover YAML ``cwd: 0xFFF…`` is an int past the 4300
    # digit str cap — the bare str() 500'd GET /api/terminal before the
    # payload ever reached the sanitizer.  Unrenderable values fall back.
    cwd = _config_text(tc.get("cwd") or "")
    payload = {
        "host_enabled": host_enabled(),
        "shell": _config_text(tc.get("shell") or "") or _default_shell(),
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


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    return text.encode("utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Python ``json.loads`` accepts ``Infinity`` in a leftover audit line;
    Starlette's response encoder does not.  ``!!binary`` / bytes ``who`` and
    a lone-surrogate command used to raise out of ``_audit`` after the
    command had already run.  A leftover ``\\ud800`` *key* on an audit line
    still 500'd GET /api/terminal/history (values were scrubbed, keys were not).
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
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


def _audit(entry: dict[str, Any]) -> None:
    """Append one line to the audit log; never let logging break the request."""
    try:
        payload = _jsonable(entry)
        if not isinstance(payload, dict):
            return
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
                secure_io.replace_secret_text(
                    AUDIT_PATH, "\n".join(lines) + ("\n" if lines else "")
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
    if isinstance(timeout, bool) or timeout is None:
        value = DEFAULT_TIMEOUT
    else:
        try:
            value = int(timeout)
        except (TypeError, ValueError, OverflowError):
            value = DEFAULT_TIMEOUT
    return max(1, min(value, MAX_TIMEOUT))


def _check_command(command: str) -> str:
    if not isinstance(command, str):
        raise api_error("terminal.empty_command")
    cmd = command.strip()
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
    shell = _config_text(tc.get("shell") or "") or _default_shell()
    start_cwd = _resolve_cwd(cwd)

    result = _run([shell, "-c", _wrap_with_cwd(cmd)], secs, cwd=start_cwd)
    result["stdout"], end_cwd = _split_cwd(result["stdout"], start_cwd)
    _audit({
        "ts": _now(),
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
    return _response(result)


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
    if result.get("rc") != 127:
        return False
    if _config_text(result.get("stderr")).strip() != f"not found: {DOCKER}":
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
    if not isinstance(container, str):
        raise api_error("terminal.no_container")
    name = (container or "").strip()
    if not name:
        raise api_error("terminal.no_container")
    name = cli_args.require_positional(name, label="container name")
    cmd = _check_command(command)
    secs = _clamp_timeout(timeout)
    # ``container`` and ``target`` already tolerate leftover non-str values;
    # a non-str shell used to AttributeError on .strip() here.
    sh = (shell if isinstance(shell, str) else "").strip() or "/bin/sh"
    # A container path cannot be validated from the host, so pass it through and
    # let the shell fall back to its own default if the directory is gone.
    start_cwd = str(cwd or "").strip()
    wrapped = _wrap_with_cwd(cmd)
    if start_cwd:
        wrapped = f"cd {_sh_quote(start_cwd)} 2>/dev/null || true\n{wrapped}"

    result = _run([DOCKER, "exec", "--", name, sh, "-c", wrapped], secs)
    result["stdout"], end_cwd = _split_cwd(result["stdout"], start_cwd)
    _audit({
        "ts": _now(),
        "target": "container",
        "container": name,
        "who": who,
        "cwd": start_cwd,
        "shell": sh,
        "command": cmd,
        "rc": result["rc"],
        "duration_ms": result["duration_ms"],
    })
    if (
        result["rc"] != 0
        and (
            looks_engine_down(f"{result.get('stderr') or ''}\n{result.get('stdout') or ''}")
            or _docker_vanished(result)
        )
        and not engine_up(force=True)
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
    if not isinstance(target, str):
        raise api_error("terminal.bad_target", target="")
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
    if isinstance(limit, bool) or limit is None:
        n = 50
    else:
        try:
            n = int(limit)
        except (TypeError, ValueError, OverflowError):
            n = 50
    n = max(1, min(n, 500))
    try:
        if not AUDIT_PATH.exists():
            return []
        lines = tail_file_lines(AUDIT_PATH, n)
    except OSError:
        return []
    out: list[dict] = []
    for raw in lines:
        try:
            parsed = safe_json_loads(raw)
        except (ValueError, RecursionError):
            continue
        if isinstance(parsed, dict):
            cleaned = _jsonable(parsed)
            if isinstance(cleaned, dict):
                out.append(cleaned)
    return out
