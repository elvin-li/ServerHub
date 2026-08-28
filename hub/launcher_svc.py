"""Native ServerHub.app and panel LaunchAgent management.

The browser API uses this module instead of exposing launchctl arguments.  All
paths and labels are fixed, and mutating routes additionally require an
authenticated administrator browser session.
"""
from __future__ import annotations

import os
import plistlib
import re
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Literal

from hub.errors import soft_fail
from hub.launchd_cache import invalidate_launchd
from hub.paths import BASE, user_home
from hub.util import LazyPool, sh, utf8_env

_pool = LazyPool(4, "hub-launcher")
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def shutdown_executor() -> None:
    _pool.shutdown()

PANEL_LABEL = "local.serverhub.panel"
LAUNCHER_LABEL = "local.serverhub.launcher"
LEGACY_MENUBAR_LABEL = "local.serverhub.menubar"
UID = os.getuid()
DOMAIN = f"gui/{UID}"
from hub.paths import AGENTS_DIR  # noqa: E402
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


def _default_app_candidates() -> tuple[Path, ...]:
    """User Applications fallback.  ``Path.home()`` leftover must not 500 import."""
    home = user_home()
    extra = () if home is None else (home / "Applications" / "ServerHub.app",)
    return (Path("/Applications/ServerHub.app"),) + extra


APP_CANDIDATES = _default_app_candidates()
_UNRESOLVED_APP_PATH = object()


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _resolve(primary_path: Path, primary: str, alternates: tuple[str, ...]) -> tuple[Path, str]:
    """Return the (plist, label) pair for the install that is actually present.

    *primary* wins whenever its plist exists, so a source install keeps its
    dotted label.  Only when that plist is absent does an installed alternate
    take over; with nothing installed the primary is still returned so callers
    have a stable label to write and to report.
    """
    if _is_file(primary_path):
        return primary_path, primary
    for label in alternates:
        candidate = AGENTS_DIR / f"{label}.plist"
        if _is_file(candidate):
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


def _as_text(value) -> str:
    if value is None:
        return ""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str(value)
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
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _job_state(label: str) -> str | None:
    """Return launchd's top-level job state, not a nested activity state."""
    rc, output, _ = sh(
        ["/bin/launchctl", "print", f"{DOMAIN}/{label}"], timeout=5
    )
    if rc != 0:
        return None
    depth = 0
    for line in _as_text(output).splitlines():
        stripped = line.strip()
        if depth == 1 and stripped.startswith("state = "):
            return stripped.removeprefix("state = ").strip()
        depth += line.count("{") - line.count("}")
    return "unknown"


def _loaded(label: str) -> bool:
    return _job_state(label) is not None


def _app_path() -> Path | None:
    return next((path for path in APP_CANDIDATES if _is_dir(path)), None)


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
    def submit(fn, *args, default=None, skip=False):
        if skip:
            return None, default, True
        try:
            return _pool.submit(fn, *args), default, False
        except RuntimeError:
            # Pool was shut down (reload / lifespan).  Running inline keeps
            # GET /api/launcher from 500-ing while workers drain.
            try:
                return None, fn(*args), True
            except Exception:
                return None, default, True

    def finish(future, default, done):
        if done:
            return default
        try:
            return future.result()
        except Exception:
            return default

    app_running = submit(_app_running, app, default=False, skip=app is None)
    panel_state = submit(_job_state, panel_label, default=None)
    launcher_loaded = submit(_loaded, launcher_label, default=False)
    legacy_loaded = submit(_loaded, legacy_label, default=False)
    running = finish(*app_running)
    panel = finish(*panel_state)
    launcher = finish(*launcher_loaded)
    legacy = finish(*legacy_loaded)
    panel_state_text = None if panel is None else _as_text(panel)
    return {
        "app_installed": app is not None,
        "app_path": str(app) if app else None,
        "app_running": running,
        "panel_running": panel_state_text == "running",
        "panel_job_state": panel_state_text,
        "panel_registered": _is_file(panel_plist),
        "login_enabled": _is_file(launcher_plist),
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
        return soft_fail("launcher.not_installed")

    # Write and unload the launcher this host actually installed, the same pair
    # ``status()`` reports on.  Hard-coding the dotted label/plist here while
    # ``status()`` used the resolved ones meant the toggle read one job and wrote
    # another, and it failed in both directions on native and distribution
    # installs:
    #   * Off: bootout/disable named a label launchd does not have, unlink() hit
    #     FileNotFoundError on the absent dotted plist, and success was judged by
    #     that same absent path -- so the API answered ok/"disabled" while the
    #     real ``com.elvin.serverhub-launcher`` stayed registered.  The status
    #     poll that follows still saw ``login_enabled``, so the switch snapped
    #     back to ON and login autostart could not be turned off at all.
    #   * On: beside an already installed ``local.serverhub-launcher`` this added
    #     a second, dotted plist, so login ran ``open -gj ServerHub.app`` twice.
    # With none of the three spellings installed ``_resolve()`` returns the
    # primary pair, which is the correct target for a fresh install: a new host
    # should register under the canonical dotted name.
    launcher_plist, launcher_label = resolve_launcher()
    target = f"{DOMAIN}/{launcher_label}"
    if enabled:
        home = user_home()
        if home is None:
            return {"ok": False, "message": "home directory is unavailable"}
        logs = home / "Library" / "Logs"
        try:
            logs.mkdir(parents=True, exist_ok=True)
            _atomic_plist(launcher_plist, {
                # Must match the resolved label: launchd rejects a job whose
                # Label disagrees with the plist it was bootstrapped from.
                "Label": launcher_label,
                "ProgramArguments": ["/usr/bin/open", "-gj", str(app)],
                "RunAtLoad": True,
                "ProcessType": "Interactive",
                "LimitLoadToSessionType": "Aqua",
                "StandardOutPath": str(logs / "serverhub-launcher.out.log"),
                "StandardErrorPath": str(logs / "serverhub-launcher.err.log"),
            })
        except OSError as exc:
            return {"ok": False, "message": _as_text(exc)}
        sh(["/bin/launchctl", "bootout", target], timeout=8)
        sh(["/bin/launchctl", "enable", target], timeout=5)
        rc, out, err = sh(
            ["/bin/launchctl", "bootstrap", DOMAIN, str(launcher_plist)], timeout=10
        )
        # The launcher agent is one of the jobs the autostart and services pages list
        # out of the shared listing (hub/launchd_cache.py).
        invalidate_launchd()
        ok = rc == 0 or _loaded(launcher_label)
        message = (
            (_as_text(out) or "enabled")
            if ok
            else (_as_text(err or out) or f"launchctl bootstrap failed with exit {rc}")
        )
        return {"ok": ok, "message": message}

    bootout_rc, bootout_out, bootout_err = sh(
        ["/bin/launchctl", "bootout", target], timeout=8
    )
    sh(["/bin/launchctl", "disable", target], timeout=5)
    invalidate_launchd()
    # Remove, and judge success against, the resolved plist -- the one whose
    # existence ``status()`` reports back as ``login_enabled``.  Deleting the
    # dotted constant instead meant FileNotFoundError on a path that was never
    # there, swallowed as "already gone", and then ``ok`` computed from that same
    # absent path: a guaranteed ok/"disabled" no matter what launchd still had.
    try:
        launcher_plist.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        return {"ok": False, "message": _as_text(exc)}
    if _loaded(launcher_label):
        message = _as_text(bootout_out or bootout_err) or (
            f"launchctl bootout failed with exit {bootout_rc}"
        )
        return {"ok": False, "message": message}
    return {"ok": not _exists(launcher_plist), "message": "disabled"}


def open_app() -> dict:
    app = _app_path()
    if app is None:
        return soft_fail("launcher.not_installed")
    rc, out, err = sh(["/usr/bin/open", "-gj", str(app)], timeout=10)
    message = (
        _as_text(out) or "opened"
        if rc == 0
        else _as_text(err or out) or f"open failed with exit {rc}"
    )
    return {"ok": rc == 0, "message": message}


def schedule_panel_action(action: Literal["restart", "stop"]) -> dict:
    if action not in ("restart", "stop"):
        return soft_fail("launcher.bad_action", action=action)
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
            env=utf8_env(),
        )
    except (OSError, ValueError, TypeError) as exc:
        # Leftover ``\\ud800`` in the launchctl label UnicodeEncodeError'd Popen
        # (ValueError, not OSError) and 500'd POST /api/launcher/panel.
        return {"ok": False, "message": _as_text(exc) or "spawn failed"}
    return {"ok": True, "message": f"panel {action} scheduled"}
