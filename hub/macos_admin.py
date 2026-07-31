"""Run fixed macOS system commands through the native administrator dialog.

Callers must build argv from allowlisted constants and validated values. Passwords
never enter ServerHub: ``osascript`` asks macOS to display its own authorization
sheet and returns only the command's exit status and output.
"""
from __future__ import annotations

import json
import shlex
from collections.abc import Sequence

from hub.util import sh

OSASCRIPT = "/usr/bin/osascript"


def _apple_script(shell_command: str) -> str:
    return (
        "do shell script "
        + json.dumps(shell_command)
        + " with administrator privileges"
    )


def run_admin_sequence(
    commands: Sequence[Sequence[str]],
    *,
    timeout: int = 120,
) -> dict:
    """Run validated argv sequences after one native administrator prompt."""
    if not commands or any(not command for command in commands):
        return {"ok": False, "error": "invalid_command"}
    if any("\x00" in str(part) for command in commands for part in command):
        return {"ok": False, "error": "invalid_command"}

    # A semicolon is intentional: some idempotent launchctl commands report an
    # error when the requested state already exists. The caller always verifies
    # the resulting system state instead of trusting this process status alone.
    shell_command = "; ".join(
        shlex.join([str(part) for part in command]) for command in commands
    )
    rc, output, error = sh(
        [OSASCRIPT, "-e", _apple_script(shell_command)],
        timeout=timeout,
    )
    message = (error or output or "").strip()
    lowered = message.lower()
    cancelled = rc == 1 and (
        "(-128)" in message
        or "user canceled" in lowered
        or "user cancelled" in lowered
        or "用户取消" in message
    )
    if cancelled:
        return {"ok": False, "error": "cancelled"}
    if rc == -1 or "not found" in lowered:
        return {"ok": False, "error": "unavailable"}
    if rc != 0:
        return {
            "ok": False,
            "error": "failed",
            "message": message[-500:],
        }
    return {"ok": True}


def run_admin(command: Sequence[str], *, timeout: int = 120) -> dict:
    return run_admin_sequence([command], timeout=timeout)
