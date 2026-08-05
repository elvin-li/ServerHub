"""Native ServerHub.app and panel LaunchAgent management.

The browser API uses this module instead of exposing launchctl arguments.  All
paths and labels are fixed, and mutating routes additionally require an
authenticated administrator browser session.
"""
from __future__ import annotations

import os
import plistlib
import shlex
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Literal

from hub.paths import BASE
from hub.util import sh

PANEL_LABEL = "local.serverhub.panel"
LAUNCHER_LABEL = "local.serverhub.launcher"
LEGACY_MENUBAR_LABEL = "local.serverhub.menubar"
UID = os.getuid()
DOMAIN = f"gui/{UID}"
AGENTS_DIR = Path.home() / "Library" / "LaunchAgents"
LAUNCHER_PLIST = AGENTS_DIR / f"{LAUNCHER_LABEL}.plist"
PANEL_PLIST = AGENTS_DIR / f"{PANEL_LABEL}.plist"

#: The same two jobs have shipped under three naming schemes: ``install.sh``
#: writes the dotted labels above, ``ServerHubLauncher.swift`` writes hyphenated
#: ``local.serverhub`` ones, and distribution builds use a ``com.elvin`` prefix.
#: Hard-coding only the dotted spelling made this module describe a job that does
#: not exist on native or distribution installs: ``status()`` reported the panel
#: as unregistered while it was serving the request, and restart/stop asked
#: launchd for a missing label and failed with "Could not find service".
PANEL_LABEL_ALTERNATES = ("local.serverhub", "com.elvin.serverhub")
LAUNCHER_LABEL_ALTERNATES = (
    "local.serverhub-launcher",
    "com.elvin.serverhub-launcher",
)
LEGACY_MENUBAR_ALTERNATES = (
    "local.serverhub-menubar",
    "com.elvin.serverhub-menubar",
)
APP_CANDIDATES = (
    Path("/Applications/ServerHub.app"),
    Path.home() / "Applications" / "ServerHub.app",
)
_UNRESOLVED_APP_PATH = object()


def _resolve(primary_path: Path, primary: str, alternates: tuple[str, ...]) -> tuple[Path, str]:
    """Return the (plist, label) pair for the install that is actually present.

    *primary* wins whenever its plist exists, so a source install keeps its
    dotted label.  Only when that plist is absent does an installed alternate
    take over; with nothing installed the primary is still returned so callers
    have a stable label to write and to report.
    """
    if primary_path.is_file():
        return primary_path, primary
    for label in alternates:
        candidate = AGENTS_DIR / f"{label}.plist"
        if candidate.is_file():
            return candidate, label
    return primary_path, primary


def resolve_panel() -> tuple[Path, str]:
    return _resolve(PANEL_PLIST, PANEL_LABEL, PANEL_LABEL_ALTERNATES)


def resolve_launcher() -> tuple[Path, str]:
    return _resolve(LAUNCHER_PLIST, LAUNCHER_LABEL, LAUNCHER_LABEL_ALTERNATES)


def resolve_legacy_menubar() -> tuple[Path, str]:
    return _resolve(
        AGENTS_DIR / f"{LEGACY_MENUBAR_LABEL}.plist",
        LEGACY_MENUBAR_LABEL,
        LEGACY_MENUBAR_ALTERNATES,
    )


def _job_state(label: str) -> str | None:
    """Return launchd's top-level job state, not a nested activity state."""
    rc, output, _ = sh(
        ["/bin/launchctl", "print", f"{DOMAIN}/{label}"], timeout=5
    )
    if rc != 0:
        return None
    depth = 0
    for line in output.splitlines():
        stripped = line.strip()
        if depth == 1 and stripped.startswith("state = "):
            return stripped.removeprefix("state = ").strip()
        depth += line.count("{") - line.count("}")
    return "unknown"


def _loaded(label: str) -> bool:
    return _job_state(label) is not None


def _app_path() -> Path | None:
    return next((path for path in APP_CANDIDATES if path.is_dir()), None)


def _app_running(app: Path | None | object = _UNRESOLVED_APP_PATH) -> bool:
    if app is _UNRESOLVED_APP_PATH:
        app = _app_path()
    if app is None:
        return False
    executable = app / "Contents" / "MacOS" / "ServerHub"
    # Match the current user's complete argv exactly. A loose ``pgrep -f`` also
    # matches shell/diagnostic commands that merely contain this path and makes
    # the panel claim the menu-bar app is running after it has quit.
    return sh(
        ["/usr/bin/pgrep", "-u", str(UID), "-f", "-x", str(executable)],
        timeout=5,
    )[0] == 0


def status() -> dict:
    app = _app_path()
    panel_plist, panel_label = resolve_panel()
    launcher_plist, launcher_label = resolve_launcher()
    _, legacy_label = resolve_legacy_menubar()
    # These probes each spawn an independent, read-only system command. Running
    # them concurrently keeps the settings page latency near the slowest probe
    # instead of adding four subprocess startup times together.
    with ThreadPoolExecutor(max_workers=4) as executor:
        app_running = executor.submit(_app_running, app) if app is not None else None
        panel_state = executor.submit(_job_state, panel_label)
        launcher_loaded = executor.submit(_loaded, launcher_label)
        legacy_loaded = executor.submit(_loaded, legacy_label)
        def probe_result(future, default):
            try:
                return future.result()
            except Exception:
                return default

        running = probe_result(app_running, False) if app_running is not None else False
        panel = probe_result(panel_state, None)
        launcher = probe_result(launcher_loaded, False)
        legacy = probe_result(legacy_loaded, False)
    return {
        "app_installed": app is not None,
        "app_path": str(app) if app else None,
        "app_running": running,
        "panel_running": panel == "running",
        "panel_job_state": panel,
        "panel_registered": panel_plist.is_file(),
        "login_enabled": launcher_plist.is_file(),
        "launcher_registered": launcher,
        "legacy_menubar_registered": legacy,
        "runtime_path": str(BASE),
    }


def _atomic_plist(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        try:
            handle = os.fdopen(fd, "wb")
        except Exception:
            os.close(fd)
            raise
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def set_login_enabled(enabled: bool) -> dict:
    app = _app_path() if enabled else None
    if enabled and app is None:
        return {"ok": False, "message": "ServerHub.app is not installed in Applications"}

    target = f"{DOMAIN}/{LAUNCHER_LABEL}"
    if enabled:
        logs = Path.home() / "Library" / "Logs"
        try:
            logs.mkdir(parents=True, exist_ok=True)
            _atomic_plist(LAUNCHER_PLIST, {
                "Label": LAUNCHER_LABEL,
                "ProgramArguments": ["/usr/bin/open", "-gj", str(app)],
                "RunAtLoad": True,
                "ProcessType": "Interactive",
                "LimitLoadToSessionType": "Aqua",
                "StandardOutPath": str(logs / "serverhub-launcher.out.log"),
                "StandardErrorPath": str(logs / "serverhub-launcher.err.log"),
            })
        except OSError as exc:
            return {"ok": False, "message": str(exc)}
        sh(["/bin/launchctl", "bootout", target], timeout=8)
        sh(["/bin/launchctl", "enable", target], timeout=5)
        rc, out, err = sh(
            ["/bin/launchctl", "bootstrap", DOMAIN, str(LAUNCHER_PLIST)], timeout=10
        )
        ok = rc == 0 or _loaded(LAUNCHER_LABEL)
        message = (
            (out or "enabled")
            if ok
            else (err or out or f"launchctl bootstrap failed with exit {rc}")
        )
        return {"ok": ok, "message": message}

    bootout_rc, bootout_out, bootout_err = sh(
        ["/bin/launchctl", "bootout", target], timeout=8
    )
    sh(["/bin/launchctl", "disable", target], timeout=5)
    try:
        LAUNCHER_PLIST.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        return {"ok": False, "message": str(exc)}
    if _loaded(LAUNCHER_LABEL):
        message = bootout_out or bootout_err or (
            f"launchctl bootout failed with exit {bootout_rc}"
        )
        return {"ok": False, "message": message}
    return {"ok": not LAUNCHER_PLIST.exists(), "message": "disabled"}


def open_app() -> dict:
    app = _app_path()
    if app is None:
        return {"ok": False, "message": "ServerHub.app is not installed in Applications"}
    rc, out, err = sh(["/usr/bin/open", "-gj", str(app)], timeout=10)
    message = (
        out or "opened"
        if rc == 0
        else err or out or f"open failed with exit {rc}"
    )
    return {"ok": rc == 0, "message": message}


def schedule_panel_action(action: Literal["restart", "stop"]) -> dict:
    if action not in ("restart", "stop"):
        return {"ok": False, "message": f"unsupported panel action: {action}"}
    # Target the label this host actually installed.  Hard-coding the dotted
    # spelling made restart/stop fail with "Could not find service" on native and
    # distribution installs, where the very same job is registered as
    # ``local.serverhub`` or ``com.elvin.serverhub``.
    _, panel_label = resolve_panel()
    target = f"{DOMAIN}/{panel_label}"
    command = (
        ["/bin/launchctl", "kickstart", "-k", target]
        if action == "restart"
        else ["/bin/launchctl", "bootout", target]
    )
    # This endpoint runs inside the job being restarted/stopped.  A detached
    # helper waits until the response is on the wire before asking launchd to
    # replace or unload that job.
    script = "sleep 0.6; exec " + shlex.join(command)
    try:
        subprocess.Popen(
            ["/bin/sh", "-c", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": True, "message": f"panel {action} scheduled"}
