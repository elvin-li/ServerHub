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
import re
import threading
import time
from pathlib import Path

from hub.launchd_cache import invalidate_launchd, listing as launchd_listing
from hub.paths import AGENTS_DIR, UID
from hub.util import read_bytes_capped, sh

log = logging.getLogger("serverhub.stale_runtime")
#: Leftover multi-MB LaunchAgent plist used to OOM GET /api/health/checks.
_PLIST_CAP = 256 * 1024

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _as_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
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
_kick_lock = threading.Lock()
#: ``proc_pidpath`` is cheap; the lsof fallback is not.  Status and health
#: both ask this question for the same PIDs within one poll window.
_EXE_TTL = 30.0
_EXE_CACHE_MAX = 256
_exe_cache: dict[int, tuple[float, str | None]] = {}
#: Bumped by :func:`invalidate_exe_cache`.  The probe below runs outside
#: ``_exe_lock`` -- it spawns ``ps`` and ``lsof`` -- so a kickstart wave can
#: land between reading the path and storing it, and storing it then would put
#: the pre-kickstart answer back for a full TTL.  That is the case the
#: invalidate exists for: ``kick_stale`` restarts the agent precisely because
#: its interpreter is gone, and the next ``scan()`` must not be told the dead
#: pid is still on the deleted Cellar path.  A probe from a superseded
#: generation returns its value to its own caller and publishes nothing.
_exe_generation = 0
_exe_lock = threading.Lock()

try:
    _LIBC = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    _LIBC.proc_pidpath.argtypes = [
        ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
    ]
    _LIBC.proc_pidpath.restype = ctypes.c_int
except _CONTROL_FLOW:
    raise
except BaseException:  # pragma: no cover - libSystem is always there on macOS
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
    text = _as_text(out)
    if not text.strip():
        return None
    skip_suffixes = (".dylib", ".so", ".bundle")
    for line in text.splitlines():
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
    global _exe_generation
    with _exe_lock:
        _exe_generation += 1
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
    if isinstance(pid, bool):
        # ``int(True)`` is 1: a leftover bool pid used to probe launchd
        # itself and answer /sbin/launchd for a process that never existed.
        # ``isinstance``, deliberately: a real bool always matches the
        # C-level exact-type check, and a *lying* ``__class__`` claiming
        # bool is junk that reads fail-closed as unreadable here.
        return None
    try:
        n = int(pid)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Total, not (TypeError, ValueError, OverflowError): a leftover pid
        # whose ``__int__``/``__index__`` raises RuntimeError escaped the
        # old tuple and rode scan() into the health fan-out, collapsing the
        # stale-runtime row to the generic warn shape.
        return None
    if n <= 0:
        return None
    try:
        # str() probe, not a range gate: a leftover already-int pid past
        # CPython's 4300-digit cap ValueError'd ``str(n)`` inside the ps
        # argv below and 500'd GET /api/health/checks and /api/apps/managed.
        str(n)
    except ValueError:
        return None
    now = time.time()
    with _exe_lock:
        hit = _exe_cache.get(n)
        if hit is not None and now - hit[0] < _EXE_TTL:
            return hit[1]
        began = _exe_generation
    path = _pid_exe_path_uncached(n)
    with _exe_lock:
        if began != _exe_generation:
            # A kickstart wave landed while we shelled out.  Answer this
            # caller -- it asked before the wave, and re-probing on its behalf
            # buys nothing -- but leave the cache empty so the next reader
            # sees the world the kickstart made.
            return path
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
        except _CONTROL_FLOW:
            raise
        except BaseException:
            got = 0
        if got > 0:
            path = buf.value.decode("utf-8", "replace")
            if path:
                return path
    rc, out, _ = sh(["/bin/ps", "-p", str(n), "-o", "command="], timeout=3)
    cmd = _as_text(out).strip()
    if rc == 0 and cmd.startswith("/"):
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
    try:
        agents = Path(AGENTS_DIR)
        paths = sorted(agents.glob("*.plist"))
    except (OSError, TypeError, ValueError):
        # A None/NUL AGENTS_DIR used to TypeError health_checks() and
        # empty GET /api/health/checks once the wrapper was not in place.
        return []
    for path in paths:
        try:
            pl = plistlib.loads(read_bytes_capped(path, _PLIST_CAP))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        if not isinstance(pl, dict):
            continue
        if pl.get("Disabled"):
            continue
        if pl.get("StartInterval") or pl.get("StartCalendarInterval"):
            continue
        # str() probe via _as_text, with the plist filename as the fallback:
        # a leftover ``<integer>0x…</integer>`` Label parses past CPython's
        # int->str digit cap (hex has no cap), scrubbed to "" — which used to
        # silently drop the agent from the stale scan instead of matching it
        # by its on-disk name.
        label = _as_text(pl.get("Label") or path.stem) or _as_text(path.stem)
        if not label:
            continue
        try:
            # Per-agent guard: ``pid_for`` on a leftover listing — or the
            # ``not pid`` truthiness probe on a ``__bool__``-bomb pid —
            # used to raise out of the whole scan, costing every healthy
            # agent's row instead of the one poisoned entry.
            pid = listing.pid_for(label)
            if not pid or isinstance(pid, bool):
                continue
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        try:
            exe = pid_exe_path(pid)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            exe = None
        if not exe:
            continue
        try:
            missing = not Path(exe).exists()
        except (OSError, ValueError, TypeError):
            missing = True
        if not missing:
            continue
        try:
            pid_n = int(pid)
            # A leftover over-cap already-int pid passes int() untouched and
            # the digit-cap ValueError then lands in the JSON encoder.
            str(pid_n)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Total: a pid whose ``__int__`` raises RuntimeError must read
            # as unknown (0), not drop the row it warns about.
            pid_n = 0
        stale.append({"label": label, "pid": pid_n, "exe": _as_text(exe)})
    return stale


def health_checks() -> list[dict]:
    """Zero or one health-page row.  Side-effect free; the alerter kickstarts."""
    stale = scan()
    if not stale:
        return []
    labels = ", ".join(_as_text(item.get("label")) for item in stale)
    detail = f"{len(stale)} running on deleted binaries: {labels}"
    return [{
        "id": "stale_runtime",
        "name": "LaunchAgents on missing interpreter",
        "level": "warn",
        "ok": False,
        "detail": _as_text(detail)[:160],
        "fix": _as_text("; ".join(
            f"launchctl kickstart -k gui/$(id -u)/{_as_text(item.get('label'))}"
            for item in stale[:4]
        )),
    }]


def remediate(now: int | float | None = None) -> list:
    """Kickstart each stale agent at most once per :data:`KICK_COOLDOWN_SEC`.

    Direct ``launchctl``, not ``actions.run_action``: this runs on the alerter
    thread, which has no action-registry session.  Returns the alerts
    ``emit_alert`` recorded so ``check_once`` can include them in its list.
    """
    try:
        now = int(time.time() if now is None else now)
    except (TypeError, ValueError, OverflowError):
        try:
            now = int(time.time())
        except (TypeError, ValueError, OverflowError):
            # Leftover ``time.time() = inf`` OverflowError'd the alerter kickstart.
            now = 0
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
        # Claim under the lock: a bare get-then-set let two overlapping
        # alerter sweeps both see last=0 and kickstart the same agent.
        with _kick_lock:
            last = _last_kick.get(label, 0)
            if now - last < KICK_COOLDOWN_SEC:
                continue
            _last_kick[label] = now
        rc, _, err = sh(
            ["/bin/launchctl", "kickstart", "-k", f"gui/{UID}/{label}"],
            timeout=20,
        )
        kicked = True
        if rc != 0:
            with _kick_lock:
                _last_kick[label] = now - KICK_COOLDOWN_SEC + KICK_FAIL_COOLDOWN_SEC
            log.warning("kickstart %s failed rc=%s %s", label, rc, _as_text(err)[:160])
        try:
            from hub.alerts import emit_alert
            if rc == 0:
                message = (
                    f"Restarted {label}: pid {item['pid']} was running "
                    f"on missing interpreter {item['exe']}"
                )
            else:
                detail = _as_text(err).strip() or f"rc={rc}"
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
        except _CONTROL_FLOW:
            raise
        except BaseException:
            log.exception("stale_runtime alert for %s", label)
    if kicked:
        try:
            invalidate_launchd()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
        try:
            invalidate_exe_cache()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    return emitted
