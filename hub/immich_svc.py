"""Immich hybrid-stack health checks.

Immich here is not a plain compose stack, so `docker ps` alone cannot tell you
whether it works.  The pieces that must all be alive:

  * container immich_server  — API only (web UI on :2283)
  * container immich_redis   — valkey, the BullMQ broker on 127.0.0.1:6379
  * native worker            — microservices/`dist/main.js`, does the actual
                               transcode + ML jobs.  Immich rewrites
                               process.title to "immich", so it can only be
                               located through its pidfile, never by pgrep on
                               the script path.
  * native ML service        — Swift/Metal CLIP + Vision on :3003
  * PostgreSQL 18            — 127.0.0.1:5433, separate cluster from PG17
                               (TeslaMate), so a PG17-only check says nothing
                               about Immich.
  * ffmpeg VideoToolbox shim — the wrapper that turns Immich's software encode
                               request into hevc_videotoolbox.

Everything below is read-only: sockets, HTTP GETs, pidfile stats.  No action is
taken and no secret is read (the DB password lives in the accelerator config and
is deliberately not touched — reachability is probed at the socket level).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from hub.docker_cli import engine_up
from hub.http_guard import RedirectRefused, no_redirect_opener
from hub.launchd_cache import loaded_labels
from hub.paths import user_home
from hub.util import cached_snapshot, port_open, read_text_capped, sh, strftime_now

_OPENER = no_redirect_opener()

_TTL = 30.0


def _home_dir() -> Path:
    """Best-effort HOME.  ``Path.home()`` leftover must not 500 import."""
    return user_home() or Path("/var/empty/serverhub-immich")


_HOME = _home_dir()
BASE = _HOME / "Services" / "immich"
ACCEL = _HOME / ".immich-accelerator"
WORKER_PID = ACCEL / "pids" / "worker.pid"
#: Leftover multi-MB start-worker-native.sh used to OOM GET /api/health.
_SCRIPT_CAP = 256 * 1024
#: Explicit quarantine marker written by ops/keepalive when the media volume
#: shows write faults; keep-immich-alive.sh refuses to start the worker while
#: it exists, so "worker stopped" has a different meaning in that state.
QUARANTINE = ACCEL / "worker.quarantine"
#: The wrapper is installed as plain `bin/ffmpeg` so it wins on PATH ahead of
#: the real binary; it is not named *-wrapper.sh on disk.
FFMPEG_SHIM = ACCEL / "bin" / "ffmpeg"

WEB_PORT = 2283
ML_PORT = 3003
REDIS_PORT = 6379
PG_PORT = 5433


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


def _as_text(value) -> str:
    """docker ps / ping leftovers: bytes used to TypeError ``partition`` / ``in``."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif not isinstance(value, str):
        return ""
    return value.encode("utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Inf in a leftover ping body was already dropped; a leftover ``\\ud800`` in
    docker ps / ping text still 500'd GET /api/health at UTF-8 encode time.
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
            # the number at all — ``json.dumps`` raises the same ValueError
            # this guard eats (hex/octal text loads uncapped, so a leftover
            # dodges the int(str) parse limit) — same drop as backups/jobs.
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
            if isinstance(k, (bytes, bytearray)):
                k = k.decode("utf-8", "replace")
            elif not isinstance(k, str):
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
            return _jsonable(iso(), depth + 1)
        except Exception:
            pass
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _path_is_file(path: Path) -> bool:
    """``is_file()`` EIO on a dying volume used to 500 GET /api/health."""
    try:
        return path.is_file()
    except OSError:
        return False


def _path_is_exec(path: Path) -> bool:
    try:
        return path.is_file() and os.access(path, os.X_OK)
    except OSError:
        return False


def _check(id_: str, name: str, level: str, ok: bool, detail: str, fix: str = "") -> dict:
    return {
        "id": id_,
        "name": name,
        "level": "ok" if ok else level,
        "ok": ok,
        "detail": _as_text(detail),
        "fix": "" if ok else _as_text(fix),
    }


def _http(url: str, timeout: float = 3.0):
    """GET url, returning (status, body) or (None, error-string)."""
    try:
        req = urllib.request.Request(url, method="GET")
        with _OPENER.open(req, timeout=timeout) as r:
            return r.status, _as_text(r.read(4096))
    except urllib.error.HTTPError as e:
        return e.code, ""
    except RedirectRefused as e:
        return None, _utf8_text(e)
    except Exception as e:  # URLError, socket.timeout, ...
        return None, _utf8_text(e)


def worker_pid() -> int | None:
    """Return the live native-worker pid, or None.

    The pidfile alone is not proof: after a crash the number can be recycled by
    an unrelated process.  Require that the pid exists *and* that its command is
    Immich's ("immich" after the process.title rewrite, or a node/main.js form if
    a future version stops renaming itself).
    """
    try:
        # Line 1 is the pid; start-worker-native.sh writes the process' `lstart`
        # on line 2 so a recycled pid can be told apart from the real worker.
        # Cap the read: ``read_text()`` of a leftover multi-MB pidfile used
        # to OOM GET /api/photoshub.
        with open(WORKER_PID, encoding="utf-8", errors="replace") as fh:
            raw = fh.read(256)
        # Cap leaves a str; index lines, not characters — raw[1] was the digit
        # after the first pid char and always failed the lstart match.
        lines = raw.splitlines()
        line = lines[0].strip()
    except (OSError, ValueError, IndexError, TypeError):
        return None
    if isinstance(line, float) and (line != line or line in (float("inf"), float("-inf"))):
        return None
    try:
        pid = int(line)
    except (TypeError, ValueError, OverflowError):
        return None
    if pid <= 1:
        return None
    rc, out, _ = sh(["/bin/ps", "-o", "lstart=,command=", "-p", str(pid)], timeout=4)
    line = _as_text(out).strip()
    if rc != 0 or not line:
        return None
    # `ps -o lstart=` prints a fixed-width 24-char date, then the command.
    started, cmd = line[:24].strip(), line[24:].strip()

    # Both conditions must hold; either one alone gives a false positive.
    #
    # Command alone: a loose substring test ("immich" in cmd) accepts any
    # unrelated process whose arguments merely mention an immich path, e.g.
    # `tail -f ~/Services/immich/logs/worker.log`.
    #
    # Start time alone: a recycled pid whose lstart happens to be written into a
    # stale pidfile would pass — which is exactly what a crash-then-reuse looks
    # like.  So require the command to be the worker as well.
    #
    # Immich rewrites process.title to "immich", so that is the expected value;
    # "dist/main.js" covers a future version that stops renaming itself.
    if cmd != "immich" and "dist/main.js" not in cmd:
        return None
    recorded = lines[1].strip() if len(lines) > 1 else ""
    if recorded and started and recorded != started:
        return None  # pid was recycled by a different process
    return pid


def _worker_uptime(pid: int) -> str:
    rc, out, _ = sh(["/bin/ps", "-o", "etime=", "-p", str(pid)], timeout=4)
    text = _as_text(out).strip()
    return text if rc == 0 and text else "?"


#: One definition so the four worker states cannot drift apart in the UI.
WORKER_LABEL = "Native worker (transcode/ML queue)"


def _worker_check(pid: int | None, quarantined: bool) -> dict:
    """The worker's health check — four states, not two.

    A stopped worker is only a fault when nobody meant to stop it.  While the
    quarantine marker stands, the remedy is the opposite of "start it", so this
    reports a *warning* naming the marker rather than an error whose fix column
    resumes writes to a volume that failed write-barrier testing.  Reporting it at
    error level was the whole problem: it made the panel look like it had an
    ordinary failure that a restart would clear.

    And a worker running *despite* the marker is the dangerous state rather than
    the healthy one, so it is the loudest of the four -- that case previously came
    back "ok" simply because a pid existed.

    Detail and fix are error codes, not prose: the SPA resolves them through its
    ``err.*`` keys, so hub/ does not grow hardcoded user-facing text.  Pure, so the
    four branches are testable without probing the host.
    """
    if pid and not quarantined:
        return _check(
            "immich_worker", WORKER_LABEL, "error", True,
            f"pid={pid} up {_worker_uptime(pid)}",
        )
    if pid:
        return _check(
            "immich_worker", WORKER_LABEL, "error", False,
            "immich.worker_running_while_quarantined",
            "immich.worker_lift_quarantine",
        )
    if quarantined:
        return _check(
            "immich_worker", WORKER_LABEL, "warn", False,
            "immich.worker_quarantined",
            "immich.worker_lift_quarantine",
        )
    return _check(
        "immich_worker", WORKER_LABEL, "error", False,
        "immich.worker_down",
        "~/Services/immich/start-worker-native.sh",
    )


def _container_state(name: str) -> tuple[bool, str]:
    from hub.paths import DOCKER

    rc, out, _ = sh(
        [DOCKER, "ps", "-a", "--filter", f"name=^{name}$",
         "--format", "{{.State}}\t{{.Status}}"],
        timeout=8,
    )
    text = _as_text(out).strip()
    if rc != 0 or not text:
        return False, "container not found"
    state, _, status = text.partition("\t")
    return state == "running" and "unhealthy" not in status, status or state


@cached_snapshot(_TTL)
def run_checks(force: bool = False) -> dict:

    checks: list[dict] = []

    # --- containers ---
    if engine_up():
        for cname, label in (("immich_server", "Immich Server container"),
                             ("immich_redis", "Immich Valkey container")):
            ok, detail = _container_state(cname)
            checks.append(_check(
                f"immich_ct_{cname}", label, "error", ok, detail,
                f"cd ~/Services/immich && docker compose up -d {cname}",
            ))
    else:
        checks.append(_check(
            "immich_engine", "Container engine", "error", False, "OrbStack is not running",
            "open -a OrbStack",
        ))

    # --- web UI ---
    status, body = _http(f"http://127.0.0.1:{WEB_PORT}/api/server/ping")
    body = _as_text(body)
    pong = status == 200 and "pong" in body
    checks.append(_check(
        "immich_web", f"Immich Web/API :{WEB_PORT}", "error", pong,
        "ping ok" if pong else f"no response ({status or body[:60]})",
        "docker compose restart immich-server",
    ))

    # --- native worker ---
    # Failure prose lives in errors.CODES + the SPA's err.* i18n keys (the
    # panel translates codes like api_error payloads); hub/ must not grow
    # hardcoded user-facing Chinese.
    checks.append(_worker_check(worker_pid(), _path_is_file(QUARANTINE)))

    # --- native ML ---
    status, body = _http(f"http://127.0.0.1:{ML_PORT}/ping", timeout=3)
    body = _as_text(body)
    ml_ok = status == 200
    checks.append(_check(
        "immich_ml", f"Native ML service :{ML_PORT} (CLIP/faces/OCR)", "error", ml_ok,
        "ping ok" if ml_ok else f"no response ({status or body[:60]})",
        "~/Services/immich/start-ml-native.sh",
    ))

    # --- valkey / queue broker ---
    redis_ok = bool(port_open(REDIS_PORT, "127.0.0.1"))
    checks.append(_check(
        "immich_redis_port", f"Queue Valkey :{REDIS_PORT}", "error", redis_ok,
        "port reachable" if redis_ok else "port unreachable — queue jobs cannot be dispatched",
        "docker compose restart redis",
    ))

    # --- PostgreSQL 18 (Immich cluster, distinct from PG17/TeslaMate) ---
    pg_ok = bool(port_open(PG_PORT, "127.0.0.1"))
    checks.append(_check(
        "immich_pg18", f"PostgreSQL 18 :{PG_PORT} (Immich database)", "error", pg_ok,
        "port reachable" if pg_ok else "port unreachable",
        "brew services start postgresql@18",
    ))

    # --- VideoToolbox ffmpeg shim ---
    shim_ok = _path_is_exec(FFMPEG_SHIM)
    checks.append(_check(
        "immich_ffmpeg_shim", "VideoToolbox ffmpeg wrapper", "warn", shim_ok,
        str(FFMPEG_SHIM) if shim_ok else "missing or not executable — transcoding falls back to CPU software encoding",
        "~/Services/immich/patch-ffmpeg-shim.sh",
    ))

    # --- ML URL contamination guard ---
    # Saving any setting makes the *container* broadcast ConfigUpdate carrying
    # its own IMMICH_MACHINE_LEARNING_URL (host.docker.internal), a name the host
    # cannot resolve; ml_url_shim.js rewrites it back to 127.0.0.1.  Without the
    # shim, CLIP/face/OCR fail silently after the next settings save.
    shim_js = BASE / "hooks" / "ml_url_shim.js"
    wired = False
    try:
        # Leftover multi-MB start-worker-native.sh used to OOM GET /api/health.
        wired = "ml_url_shim" in read_text_capped(
            BASE / "start-worker-native.sh", _SCRIPT_CAP,
            encoding="utf-8", errors="replace",
        )
    except OSError:
        pass
    guard_ok = _path_is_file(shim_js) and wired
    checks.append(_check(
        "immich_ml_url_shim", "ML URL contamination guard", "warn", guard_ok,
        "loaded (saving settings will not break ML)" if guard_ok
        else "not active: ML fails silently after any settings save",
        "verify hooks/ml_url_shim.js exists and is --require'd in start-worker-native.sh",
    ))

    # --- keepalive agent ---
    # "Loaded", not "running": this is a KeepAlive watchdog agent, and launchd holds
    # it with no pid between its 120s wakeups.  Asking whether it has a pid right now
    # would report a perfectly healthy watchdog as absent.
    #
    # The listing is shared (hub/launchd_cache.py).  This ran its own, in the same
    # fan-out wave as health_svc's -- both reading the same session listing, which is
    # two of the three that /api/health/checks used to spawn.
    ka = "local.immich-keepalive" in loaded_labels()
    checks.append(_check(
        "immich_keepalive", "Worker keepalive LaunchAgent", "warn", ka,
        "loaded (checks every 120s)" if ka else "not loaded — the worker will not recover automatically after a crash",
        "launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.immich-keepalive.plist",
    ))

    errors = sum(1 for c in checks if not c["ok"] and c["level"] == "error")
    warns = sum(1 for c in checks if not c["ok"] and c["level"] == "warn")
    v = {
        "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "ok": sum(1 for c in checks if c["ok"]),
            "warn": warns,
            "error": errors,
            "total": len(checks),
        },
        "checks": checks,
        "healthy": errors == 0,
    }
    return _jsonable(v)


if __name__ == "__main__":
    print(json.dumps(run_checks(force=True), ensure_ascii=False, indent=2, allow_nan=False))
