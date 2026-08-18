"""Restart LaunchAgents whose interpreter was deleted under them.

Why this exists: Homebrew's ``python@3.12`` formula upgrades by removing the
old Cellar path (``3.12.13_4``) and installing a new one (``3.12.14``).
KeepAlive LaunchAgents keep the PID that launched against the deleted
binary.  TCP still accepts connections, so the services table and the
panel watchdog both stay green, while the first real request dies inside
the process (ESPHome's aiohttp ``connection_made`` raising
``OSError: [Errno 22] Invalid argument`` after the 2026-08-17 brew
upgrade is the incident this guards against).

Watching launchd state therefore cannot catch this failure class: the job
*is* running.  ``proc_pidpath`` still reports the vanished Cellar path, and
``Path.exists()`` is the verdict.  The health page surfaces the set; the
alerter kickstarts them (panel labels last, so ESPHome is back before we
SIGKILL ourselves).
"""
from __future__ import annotations

import ctypes
import logging
import plistlib
import threading
import time
from pathlib import Path

from hub.launchd_cache import invalidate_launchd, listing as launchd_listing
from hub.paths import AGENTS_DIR, UID
from hub.util import sh

log = logging.getLogger("serverhub.stale_runtime")

#: Same three spellings as ``hub.launcher_svc.PANEL_LABEL`` /
#: ``PANEL_LABEL_ALTERNATES``.  Kickstarted last so other daemons come back
#: before this process is replaced.
PANEL_LABELS = frozenset({
    "local.serverhub.panel",
    "local.serverhub",
    "com.elvin.serverhub",
})

KICK_COOLDOWN_SEC = 600
#: A failed kickstart is not a success.  Waiting the full ten minutes left a
#: still-dead agent sitting in warn after a transient ``not loaded``.
KICK_FAIL_COOLDOWN_SEC = 60

_PROC_PIDPATH_MAX = 4096
_last_kick: dict[str, float] = {}
#: ``proc_pidpath`` is cheap; the lsof fallback is not.  Status and health
#: both ask this question for the same PIDs within one poll window.
_EXE_TTL = 30.0
_EXE_CACHE_MAX = 256
_exe_cache: dict[int, tuple[float, str | None]] = {}
_exe_lock = threading.Lock()

try:
    _LIBC = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    _LIBC.proc_pidpath.argtypes = [
        ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
    ]
    _LIBC.proc_pidpath.restype = ctypes.c_int
except Exception:  # pragma: no cover - libSystem is always there on macOS
    _LIBC = None


def _exe_from_lsof(pid: int) -> str | None:
    """First ``txt`` mapping from lsof.  Next.js sets a process title so
    ``proc_pidpath`` returns empty while the deleted Cellar ``node`` is
    still mapped; lsof still names that path.
    """
    _rc, out, _err = sh(
        ["/usr/sbin/lsof", "-a", "-p", str(pid), "-d", "txt", "-Fn"],
        timeout=3,
    )
    # Deleted Cellar binaries often make lsof exit 1 while still printing
    # the vanished path on stdout — that is the row we need.
    if not (out or "").strip():
        return None
    skip_suffixes = (".dylib", ".so", ".bundle")
    for line in out.splitlines():
        if not line.startswith("n/"):
            continue
        path = line[1:].strip()
        if not path or path.endswith(skip_suffixes):
            # A deleted Homebrew dylib can be the first ``txt`` mapping
            # while the interpreter itself is still on disk.  Kickstarting
            # on that would restart a healthy daemon.
            continue
        return path
    return None


def invalidate_exe_cache() -> None:
    """Drop cached ``proc_pidpath`` / lsof answers (after a kickstart wave)."""
    with _exe_lock:
        _exe_cache.clear()


def pid_exe_path(pid) -> str | None:
    """Absolute executable path for *pid*, or None when it cannot be read.

    ``proc_pidpath`` is the source of truth: it keeps returning the Cellar
    path after Homebrew deletes it, which is exactly the signal we need.
    ``ps -o command=`` is a fallback for tests and for the rare pid whose
    path does not fit the proc_pidpath buffer; ctypes ``argtypes`` must be
    set or the call returns an empty path.  Next.js ``next-server`` titles
    blank ``proc_pidpath`` and a non-absolute ``ps`` command, so lsof
    ``txt`` is the last resort — without it Gravity Next stayed green on
    a deleted Homebrew ``node``.
    """
    try:
        n = int(pid)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    now = time.time()
    with _exe_lock:
        hit = _exe_cache.get(n)
        if hit is not None and now - hit[0] < _EXE_TTL:
            return hit[1]
    path = _pid_exe_path_uncached(n)
    with _exe_lock:
        if len(_exe_cache) >= _EXE_CACHE_MAX:
            cutoff = now - _EXE_TTL
            for key, (stamp, _) in list(_exe_cache.items()):
                if stamp < cutoff:
                    del _exe_cache[key]
            if len(_exe_cache) >= _EXE_CACHE_MAX:
                _exe_cache.clear()
        _exe_cache[n] = (now, path)
    return path


def _pid_exe_path_uncached(n: int) -> str | None:
    if _LIBC is not None:
        buf = ctypes.create_string_buffer(_PROC_PIDPATH_MAX)
        try:
            got = _LIBC.proc_pidpath(n, buf, _PROC_PIDPATH_MAX)
        except Exception:
            got = 0
        if got > 0:
            path = buf.value.decode("utf-8", "replace")
            if path:
                return path
    rc, out, _ = sh(["/bin/ps", "-p", str(n), "-o", "command="], timeout=3)
    if rc == 0 and (out or "").strip():
        cmd = out.strip()
        if cmd.startswith("/"):
            return cmd.split(None, 1)[0]
    return _exe_from_lsof(n)


def scan() -> list[dict]:
    """Running LaunchAgents whose executable path no longer exists on disk.

    Skips ``Disabled`` plists and calendar/interval jobs (kicking a nightly
    job mid-run is worse than leaving it).  Does **not** skip ``hide``:
    a hidden agent can still own a zombie listener after a brew upgrade.
    """
    listing = launchd_listing()
    stale: list[dict] = []
    agents = Path(AGENTS_DIR)
    try:
        paths = sorted(agents.glob("*.plist"))
    except OSError:
        return []
    for path in paths:
        try:
            with open(path, "rb") as fh:
                pl = plistlib.load(fh)
        except Exception:
            continue
        if not isinstance(pl, dict):
            continue
        if pl.get("Disabled"):
            continue
        if pl.get("StartInterval") or pl.get("StartCalendarInterval"):
            continue
        label = str(pl.get("Label") or path.stem)
        pid = listing.pid_for(label)
        if not pid:
            continue
        exe = pid_exe_path(pid)
        if not exe:
            continue
        try:
            missing = not Path(exe).exists()
        except OSError:
            missing = True
        if not missing:
            continue
        try:
            pid_n = int(pid)
        except (TypeError, ValueError):
            pid_n = pid
        stale.append({"label": label, "pid": pid_n, "exe": exe})
    return stale


def health_checks() -> list[dict]:
    """Zero or one health-page row.  Side-effect free; the alerter kickstarts."""
    stale = scan()
    if not stale:
        return []
    labels = ", ".join(item["label"] for item in stale)
    detail = f"{len(stale)} running on deleted binaries: {labels}"
    return [{
        "id": "stale_runtime",
        "name": "LaunchAgents on missing interpreter",
        "level": "warn",
        "ok": False,
        "detail": detail[:160],
        "fix": "; ".join(
            f"launchctl kickstart -k gui/$(id -u)/{item['label']}"
            for item in stale[:4]
        ),
    }]


def remediate(now: int | float | None = None) -> list:
    """Kickstart each stale agent at most once per :data:`KICK_COOLDOWN_SEC`.

    Direct ``launchctl``, not ``actions.run_action``: this runs on the alerter
    thread, which has no action-registry session.  Returns the alerts
    ``emit_alert`` recorded so ``check_once`` can include them in its list.
    """
    now = int(time.time() if now is None else now)
    stale = scan()
    if not stale:
        return []
    ordered = sorted(
        stale,
        key=lambda item: (item["label"] in PANEL_LABELS, item["label"]),
    )
    emitted: list = []
    kicked = False
    for item in ordered:
        label = item["label"]
        last = _last_kick.get(label, 0)
        if now - last < KICK_COOLDOWN_SEC:
            continue
        # Claim the slot so two overlapping sweeps cannot double-kick.
        _last_kick[label] = now
        rc, _, err = sh(
            ["/bin/launchctl", "kickstart", "-k", f"gui/{UID}/{label}"],
            timeout=20,
        )
        kicked = True
        if rc != 0:
            _last_kick[label] = now - KICK_COOLDOWN_SEC + KICK_FAIL_COOLDOWN_SEC
            log.warning("kickstart %s failed rc=%s %s", label, rc, (err or "")[:160])
        try:
            from hub.alerts import emit_alert
            if rc == 0:
                message = (
                    f"Restarted {label}: pid {item['pid']} was running "
                    f"on missing interpreter {item['exe']}"
                )
            else:
                detail = (err or "").strip() or f"rc={rc}"
                message = (
                    f"Could not restart {label} (pid {item['pid']} on missing "
                    f"interpreter {item['exe']}): {detail[:120]}"
                )
            emitted.append(emit_alert(
                kind="runtime",
                level="warn",
                alert_id=f"stale_runtime:{label}",
                title="ServerHub runtime",
                message=message,
            ))
        except Exception:
            log.exception("stale_runtime alert for %s", label)
    if kicked:
        try:
            invalidate_launchd()
        except Exception:
            pass
        try:
            invalidate_exe_cache()
        except Exception:
            pass
    return emitted
