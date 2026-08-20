"""Run fixed macOS system commands with root privileges.

Callers must build argv from allowlisted constants and validated values.

Authorization comes from one of two places, in this order:

1. **Web-entered password.**  The SPA can ask the operator for their macOS
   administrator password in a browser dialog (this is the only path that works
   when the panel is managed from another device).  The password travels in a
   request header, is held in a request-scoped :class:`~contextvars.ContextVar`
   for the duration of the call and is fed to ``sudo -S`` on stdin.  It is never
   written to disk, never put on a command line and never logged.
2. **Passwordless sudo rules.**  For a single command, the packaged
   ``deploy/sudoers.d/serverhub`` rules may allow it outright; ``sudo -n`` is
   tried before declaring that a password is needed.

The older native ``osascript`` authorization sheet is deliberately gone: it only
ever appears on the machine's own display, so an operator managing the panel from
a phone or another computer could never see or answer it — every privileged
action silently timed out.  Without a password this module now returns
``{"ok": False, "error": "password_required"}`` instead, and the SPA turns that
into its own password dialog.
"""
from __future__ import annotations

import logging
import shlex
import subprocess
import tempfile
from collections.abc import Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

from hub.util import sh, utf8_env


def _as_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    elif value is None:
        return ""
    else:
        try:
            value = str(value)
        except Exception:
            return ""
    return value.encode("utf-8", "replace").decode("utf-8")


SUDO = "/usr/bin/sudo"

# Failure diagnostics only: command argv plus the tool's own stderr tail.  The
# password is never part of either — it travels on stdin and stays there.
log = logging.getLogger("serverhub.admin")

#: sudo scrubs the environment to a bare PATH (/usr/bin:/bin:/usr/sbin:/sbin),
#: which hides Homebrew.  Scripts with `#!/usr/bin/env …` shebangs then resolve
#: to the old system copies (bash 3.2, python 2.7…), so every shell sequence
#: gets the Homebrew prefixes back before anything runs.
_PATH_PREFIX = (
    'PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:$PATH"; '
    "export PATH; "
)

#: Request-scoped macOS administrator password supplied by the web UI.  Set by
#: the API layer for exactly one request, read here, reset afterwards.
_admin_password: ContextVar[str] = ContextVar("serverhub_admin_password", default="")


def admin_password_supplied() -> bool:
    return bool(_admin_password.get())


@contextmanager
def use_admin_password(password: str | None) -> Iterator[None]:
    """Scope a web-entered password to the current request."""
    token = _admin_password.set(str(password or ""))
    try:
        yield
    finally:
        _admin_password.reset(token)


def _validate(commands: Sequence[Sequence[str]]) -> str | None:
    """Shared argv hygiene; returns the joined shell command or an error code."""
    if not commands or any(not command for command in commands):
        return None
    if any("\x00" in str(part) for command in commands for part in command):
        return None
    # A semicolon is intentional: some idempotent launchctl commands report an
    # error when the requested state already exists.  The caller always verifies
    # the resulting system state instead of trusting this process status alone.
    return "; ".join(
        shlex.join([str(part) for part in command]) for command in commands
    )


#: Privileged CLIs (``tmutil``, ``diskutil``, ``wg-quick``) can chatter for the
#: full timeout.  ``capture_output=True`` used to keep that pipe in RAM.
_ADMIN_CAP = 64 * 1024


def _sudo_run(argv, *, timeout: int, password: str | None = None) -> tuple[int, str, str]:
    """Run *argv*, keep at most :data:`_ADMIN_CAP` trailing bytes of each stream."""
    from hub.cli_args import as_argv

    argv = as_argv(argv)
    if argv is None:
        return -1, "", "invalid argv"
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.run(
                argv,
                input=(_as_text(password) + "\n").encode("utf-8")
                if password is not None
                else None,
                stdout=out,
                stderr=err,
                timeout=timeout,
                env=utf8_env(),
            )
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
        except (OSError, ValueError, TypeError) as exc:
            return -1, "", _as_text(exc)[:200]

        # Tests (and any caller that stubs ``subprocess.run``) return a
        # CompletedProcess with captured strings.  A real run redirected
        # the pipes into *out*/*err*, so ``proc.stdout`` is None.
        if proc.stdout is not None or proc.stderr is not None:
            return (
                rc,
                _as_text(proc.stdout).strip()[-_ADMIN_CAP:],
                _as_text(proc.stderr).strip()[-_ADMIN_CAP:],
            )

        def _tail(fh) -> str:
            try:
                size = fh.seek(0, 2)
                fh.seek(max(0, size - _ADMIN_CAP))
                return fh.read().decode("utf-8", "replace").strip()
            except OSError:
                return ""

        return rc, _tail(out), _tail(err)


def _run_with_password(shell_command: str, password: str, timeout: int) -> dict:
    """Run the sequence as root via ``sudo -S`` with the web-entered password.

    ``-p ''`` suppresses the prompt text; the password is handed over on stdin so
    it never appears in argv (visible to ``ps``) or in any log.  The sequence
    runs in one ``/bin/sh -c`` because sudo cannot match a semicolon-joined
    multi-command line against sudoers rules — authentication here is the
    password itself, validated by sudo against the account's real credentials.
    """
    rc, output, error = _sudo_run(
        [SUDO, "-S", "-p", "", "/bin/sh", "-c", _PATH_PREFIX + shell_command],
        timeout=timeout,
        password=password,
    )
    if rc == -1 and error == "timeout":
        log.warning("sudo timeout: %s", shell_command)
        return {"ok": False, "error": "failed", "message": "sudo timeout"}
    if rc == -1:
        return {"ok": False, "error": "unavailable", "message": _as_text(error)[:200]}
    if rc == 0:
        return {"ok": True}
    # sudo prints these to stderr when the password does not validate; the
    # command itself never ran, so this is an authorization failure, not an
    # operation failure — the SPA asks for the password again.
    auth_failure_markers = (
        "sorry, try again",
        "incorrect password",
        "a password is required",
        "no password was provided",
        "authentication failure",
    )
    lowered = error.lower()
    if any(marker in lowered for marker in auth_failure_markers):
        return {"ok": False, "error": "password_incorrect"}
    log.warning("privileged command failed (rc=%s): %s | %s", rc, shell_command, (error or output)[:500])
    return {"ok": False, "error": "failed", "message": _as_text(error or output)[-500:]}


def run_admin_sequence(
    commands: Sequence[Sequence[str]],
    *,
    timeout: int = 120,
) -> dict:
    """Run validated argv sequences with root privileges.

    Returns ``{"ok": True}`` on success, or ``{"ok": False, "error": ...}`` with
    one of: ``invalid_command``, ``password_required``, ``password_incorrect``,
    ``unavailable``, ``failed``.
    """
    shell_command = _validate(commands)
    if shell_command is None:
        return {"ok": False, "error": "invalid_command"}

    password = _admin_password.get()
    if password:
        return _run_with_password(shell_command, password, timeout)

    # No web password: a single command may still be covered by a passwordless
    # sudoers rule.  Multiple commands can only run through a shell, which no
    # packaged rule permits, so go straight to asking for the password.
    if len(commands) == 1:
        rc, _, _ = sh([SUDO, "-n", *[str(part) for part in commands[0]]], timeout=timeout)
        if rc == 0:
            return {"ok": True}
    return {"ok": False, "error": "password_required"}


def run_admin(command: Sequence[str], *, timeout: int = 120) -> dict:
    return run_admin_sequence([command], timeout=timeout)


def prime_sudo_ticket(*, timeout: int = 30) -> dict:
    """Validate the web-entered password and cache a sudo ticket for this user.

    Homebrew cask installs that wrap ``/usr/sbin/installer`` call ``sudo`` from
    the panel's own UID.  Priming with ``sudo -v`` lets those inner calls reuse
    the ticket without a tty — the same pattern an operator would use after
    typing ``sudo -v`` once in Terminal.
    """
    password = _admin_password.get()
    if not password:
        return {"ok": False, "error": "password_required"}
    rc, _, error = _sudo_run(
        [SUDO, "-S", "-p", "", "-v"],
        timeout=timeout,
        password=password,
    )
    if rc == -1 and error == "timeout":
        return {"ok": False, "error": "failed", "message": "sudo timeout"}
    if rc == -1:
        return {"ok": False, "error": "unavailable", "message": _as_text(error)[:200]}
    if rc == 0:
        return {"ok": True}
    lowered = error.lower()
    if any(
        marker in lowered
        for marker in (
            "sorry, try again",
            "incorrect password",
            "authentication failure",
        )
    ):
        return {"ok": False, "error": "password_incorrect"}
    return {"ok": False, "error": "failed", "message": _as_text(error)[-500:]}


#: What sudo says when it declines to run something at all, as opposed to running
#: it and having it fail.  Everything here is printed by sudo itself, before the
#: command is executed.
_SUDO_REFUSALS = (
    "a password is required",
    "no password was provided",
    "sorry, try again",
    "is not allowed to execute",
    "may not run",
    "no tty present",
    "command not allowed",
    "unable to initialize policy",
)


def sudo_refused(stderr: str) -> bool:
    """Whether ``sudo -n`` declined, rather than the command having failed.

    The distinction decides which of two very different things the operator is
    told.  A refusal means "this needs a password", which the SPA can act on by
    asking for one.  A non-zero exit from a command sudo *did* run means the
    operation itself failed, and the only useful answer is that tool's own error
    text.  Collapsing the two -- retrying every failure through the password path
    and reporting ``password_required`` when it also failed -- put a password
    prompt in front of problems no password could fix, and hid the real cause.
    """
    lowered = _as_text(stderr).lower()
    return any(marker in lowered for marker in _SUDO_REFUSALS)


def sudo_capture(command: Sequence[str], *, timeout: int = 10) -> tuple[int, str, str]:
    """(rc, stdout, stderr) for a read-only command that needs root.

    Status polls like ``wg show <iface> dump`` must report live state while the
    operator is managing the panel from another device, so when this request
    carries a web-entered password it is reused for the read; otherwise the
    packaged passwordless sudoers rules are tried via ``sudo -n``.
    """
    argv = [str(part) for part in command]
    password = _admin_password.get()
    if password:
        return _sudo_run(
            [SUDO, "-S", "-p", "", *argv],
            timeout=timeout,
            password=password,
        )
    return sh([SUDO, "-n", *argv], timeout=timeout)
