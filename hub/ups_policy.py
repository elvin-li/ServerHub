"""UPS safe-shutdown policy: the panel's soft-landing layer.

Two layers protect this machine when wall power fails, and they are
deliberately different things:

* **This module (soft landing, first).**  When the UPS has been carrying the
  box long enough to cross the configured floor (charge %, estimated runtime,
  or both), the panel gracefully stops compose stacks in a configured order
  and optionally stops script/launchd services, so databases flush and
  containers exit cleanly while there is still battery left.  When wall power
  returns it starts back **exactly what it stopped** — nothing the operator
  had stopped by hand.
* **pmset halt thresholds (last resort, second).**  ``pmset -u haltlevel/
  haltafter/haltremain`` is macOS's own emergency shutdown, executed by the
  OS whether or not this panel is alive.  The panel reads those values
  (``ups_svc.ups_snapshot``) and can write ``haltlevel`` through the admin
  authorization flow, but never runs ``shutdown`` itself: the soft landing is
  tuned to fire *before* the halt level so the OS-level cutoff only ever acts
  on an already-quiesced system.

State machine (persisted in ``DATA_DIR/ups-policy-state.json``, so a panel
restart mid-outage resumes instead of forgetting)::

      idle ──(on battery ∧ trigger conditions)──▶ engaged ──(back on AC)──▶ restoring ──▶ idle
                                                     │  ▲
                                                     └──┘  latched: no re-trigger while
                                                           the same outage lasts

* **Latched**: one power-loss event triggers at most one stop sequence.  A
  charge level flapping around the floor (49% ↔ 51%) cannot re-fire, because
  leaving ``engaged`` requires seeing AC power — not a recovered percentage.
* **Crash-safe**: each stack is recorded in the state file *before* its
  ``compose stop`` is issued (the same marker-first discipline as
  ``backups._write_inflight``).  If the panel dies mid-sequence, the next
  sweep — possibly in a fresh process — resumes the remaining stops while
  still on battery, or starts everything recorded once AC is back.
* **No sensor, no action**: an empty/unparseable pmset read never triggers
  and never resets; the machine stays in whatever phase it was in.

Everything slow (compose stop/start, service actions) runs on a worker
thread; the sweep tick called from :func:`hub.alerts.check_once` only reads
the 30s-cached snapshot, the small state file, and spawns workers.
"""
from __future__ import annotations

import fcntl
import json
import logging
import os
import threading
import time
from contextlib import contextmanager

from hub.paths import DATA_DIR

log = logging.getLogger("serverhub.ups_policy")

STATE_FILE = DATA_DIR / "ups-policy-state.json"
_LOCK_PATH = STATE_FILE.with_name(STATE_FILE.name + ".lock")

PHASE_IDLE = "idle"
PHASE_ENGAGED = "engaged"
PHASE_RESTORING = "restoring"

#: Same ceiling a stack backup gives one compose stop/start.
_COMPOSE_TIMEOUT = 300

_state_lock = threading.Lock()
_sweep_lock = threading.Lock()
_spawn_lock = threading.Lock()
#: A stop/restore worker is running in this process.  Spawn guard only —
#: correctness across restarts comes from the persisted phase, not from this.
_worker_active = threading.Event()
#: Re-entrancy depth for _file_lock, per thread.  Lets the sweep hold the
#: cross-process lock across its whole decision while the nested _mutate /
#: _engage calls on the same thread reuse it instead of self-deadlocking on a
#: second flock of the same file.
_lock_depth = threading.local()


@contextmanager
def _file_lock():
    """Exclusive cross-process lock around every state read-modify-write.

    The in-process locks are not enough on their own: a packaged
    ServerHub.app and the LaunchAgent panel can share one ``data/`` directory
    (the deployment ``hub/config.py`` and ``twofa_svc`` already flock for), and
    two interpreters that each evaluate the trigger and latch independently
    would *both* engage and *both* spawn a stop sequence.  The decision has to
    be atomic across processes, not just across threads.  Same shape as
    ``twofa_svc._file_lock``: a separate ``.lock`` file, because the state
    itself is swapped in by ``os.replace`` and a lock on the old inode would
    silently stop excluding anybody.  Re-entrant per thread so the sweep can
    hold it across ``_engage``/``_mutate`` without a second flock.
    """
    depth = getattr(_lock_depth, "n", 0)
    if depth:
        _lock_depth.n = depth + 1
        try:
            yield
        finally:
            _lock_depth.n -= 1
        return
    _LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        _lock_depth.n = 1
        try:
            yield
        finally:
            _lock_depth.n = 0
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# ── seams ─────────────────────────────────────────────────────────────────────
# Every subprocess / cross-module read the workers depend on goes through one
# of these, so the tests can replace each with a fake and no test ever stops a
# real container, runs a real script stop command, or reads real pmset state.

def _ups_status() -> dict:
    from hub import ups_svc
    return ups_svc.ups_status()


def _run_argv(argv: list[str], *, timeout: int) -> tuple[int, str, str]:
    """(rc, stdout, stderr); must report, never raise (worker-thread caller)."""
    import subprocess
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001 — a policy step must record, not raise
        return -1, "", str(e)


def _engine_up() -> bool:
    from hub.docker_cli import engine_up
    return engine_up()


def _list_stacks() -> list[dict]:
    """Compose stacks with live status ("ok" means running containers)."""
    from hub import containers_svc
    return containers_svc.list_stacks()


def _service_states() -> dict[str, str]:
    """service id -> state ("ok"/"warn"/"down"/...), from the shared status."""
    from hub.status import full_status
    out: dict[str, str] = {}
    for g in full_status(force=False).get("groups") or []:
        for s in g.get("services") or []:
            out[str(s.get("id"))] = str(s.get("state") or "unknown")
    return out


def _svc_action(sid: str, action: str) -> tuple[int, str, str]:
    """Stop/start a script or launchd service through the shared action path."""
    from hub import actions
    return actions.run_action(sid, action)


def _spawn(target) -> bool:
    """Start *target* on the single policy worker thread; False when one runs.

    Both the alerter thread and ``POST /api/alerts/check`` can tick the sweep
    concurrently, so the check-and-set is atomic.  The flag is cleared in the
    worker's ``finally``; the persisted phase — not this flag — is what makes
    the policy survive a panel death.
    """
    with _spawn_lock:
        if _worker_active.is_set():
            return False
        _worker_active.set()

    # Persist which process owns the worker so a sibling sharing data/ sees it
    # and holds off.  Cleared in finally; a crash leaves it for _worker_busy's
    # liveness probe to reap.
    _mutate(lambda s: s.update(worker_owner={"pid": os.getpid(), "ts": int(time.time())}))

    def run():
        try:
            target()
        except Exception:
            # A worker crash must not leave a stack half-handled *silently*;
            # the state file keeps whatever was recorded, and the next sweep
            # respawns from it.
            log.exception("ups policy worker failed")
        finally:
            _worker_active.clear()
            try:
                _mutate(lambda s: s.pop("worker_owner", None))
            except OSError:
                pass

    threading.Thread(target=run, daemon=True, name="ups-policy").start()
    return True


# ── persisted state ───────────────────────────────────────────────────────────

def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text())
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
    return {}


def _save_state(st: dict) -> None:
    """Atomic publish, same tmp+replace shape as alerts._save_state: a crash
    mid-write must never leave a truncated file that reads as "idle" while
    stacks are actually stopped."""
    STATE_FILE.parent.mkdir(exist_ok=True)
    payload = json.dumps(st, ensure_ascii=False, indent=2)
    tmp = STATE_FILE.with_name(f"{STATE_FILE.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(payload)
        os.replace(tmp, STATE_FILE)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _mutate(fn) -> dict:
    """Read-modify-write the state file under the cross-process + thread lock."""
    with _file_lock(), _state_lock:
        st = _load_state()
        fn(st)
        _save_state(st)
        return st


def public_state() -> dict:
    """What the UI renders: current phase plus the last completed cycle."""
    st = _load_state()
    return {
        "phase": st.get("phase") or PHASE_IDLE,
        "engaged_at": st.get("engaged_at"),
        "reason": st.get("reason") or "",
        "steps": st.get("steps") or [],
        "last": st.get("last"),
    }


# ── policy / plan ─────────────────────────────────────────────────────────────

def shutdown_settings() -> dict:
    from hub import ups_svc
    return ups_svc.ups_settings().get("shutdown") or {}


def _condition(status: dict, policy: dict) -> tuple[bool, str]:
    """Whether the trigger holds right now, and the human-readable reason.

    Only readable values count: pmset omits the runtime estimate for a while
    after a power event ("(no estimate)"), and an unreadable value simply
    fails its condition — the policy never fires on the unknown.  With
    ``require_both`` an unreadable estimate therefore *blocks* the trigger
    until pmset produces one; that is the conservative reading of "both".
    """
    if not status.get("on_battery"):
        return False, ""
    pct_floor = policy.get("trigger_pct")
    min_floor = policy.get("trigger_remaining_min")
    checks: list[tuple[bool, str]] = []
    if pct_floor is not None:
        pct = status.get("battery_percent")
        hit = pct is not None and float(pct) <= float(pct_floor)
        checks.append((hit, f"battery {pct}% ≤ {int(pct_floor)}%" if hit else ""))
    if min_floor is not None:
        remain = status.get("time_remaining_min")
        hit = remain is not None and float(remain) <= float(min_floor)
        checks.append((hit, f"≈{remain} min left ≤ {int(min_floor)} min" if hit else ""))
    if not checks:
        # Enabled but no condition configured: never fires.  The settings API
        # refuses to save this shape, but a hand-edited services.yaml can
        # still produce it, and "never" beats guessing a floor.
        return False, ""
    hits = [reason for ok, reason in checks if ok]
    triggered = len(hits) == len(checks) if policy.get("require_both") and len(checks) > 1 else bool(hits)
    return triggered, " and ".join(hits) if triggered else ""


def build_plan(policy: dict | None = None) -> list[dict]:
    """The ordered action sequence the policy would execute, resolved live.

    Stacks first (in configured order — "all" follows stack enumeration
    order), then the optional script/launchd services.  Each step carries
    ``running`` so the drill can show, and the executor can honour, the rule
    that only running things are stopped: a stack the operator stopped by
    hand must not be touched — and, more importantly, must not be *started*
    by the restore pass.
    """
    policy = policy if policy is not None else shutdown_settings()
    steps: list[dict] = []
    try:
        stacks = _list_stacks()
    except Exception:
        stacks = []
    by_id = {str(s.get("id")): s for s in stacks}
    wanted = policy.get("stacks")
    if isinstance(wanted, list):
        ordered = [str(x) for x in wanted]
    else:  # "all"
        ordered = [str(s.get("id")) for s in stacks]
    # Dedupe, first occurrence wins: steps are addressed by (kind, id) in the
    # state file, so a duplicated id would leave one entry forever unresolved.
    seen: set[str] = set()
    ordered = [sid for sid in ordered if not (sid in seen or seen.add(sid))]
    for sid in ordered:
        stack = by_id.get(sid)
        steps.append({
            "kind": "stack",
            "id": sid,
            "name": str((stack or {}).get("name") or sid),
            "running": bool(stack and stack.get("status") == "ok"),
            "known": stack is not None,
        })
    # Separate namespace: steps are addressed by (kind, id), so a service id
    # that happens to match a stack id is a different step, not a duplicate.
    seen_svc: set[str] = set()
    script_ids = [str(x) for x in (policy.get("stop_scripts") or [])]
    script_ids = [sid for sid in script_ids if not (sid in seen_svc or seen_svc.add(sid))]
    if script_ids:
        try:
            states = _service_states()
        except Exception:
            states = {}
        for sid in script_ids:
            state = states.get(sid)
            steps.append({
                "kind": "service",
                "id": sid,
                "name": sid,
                # Treat only a positively-running service as stoppable; a
                # down or unknown one is left alone so restore cannot start
                # something the operator had shut off.
                "running": state in ("ok", "warn"),
                "known": state is not None,
            })
    return steps


def _catalog() -> dict:
    """Everything the policy *could* act on, for the settings pickers.

    Distinct from the plan: the plan resolves the configured selection, while
    the form needs the full menu — every compose stack (configured or
    auto-scanned) and every script entry from services.yaml.
    """
    try:
        stacks = _list_stacks()
    except Exception:
        stacks = []
    from hub.config import cfg
    scripts = []
    for s in cfg().get("scripts") or []:
        if isinstance(s, dict) and s.get("id"):
            scripts.append({
                "id": str(s["id"]),
                "name": str(s.get("name") or s["id"]),
                # Without a stop command run_action degrades to a no-op stop,
                # so the form marks these rather than hiding them.
                "has_stop": bool(s.get("stop")),
            })
    return {
        "stacks": [
            {"id": str(s.get("id")), "name": str(s.get("name") or s.get("id")),
             "running": s.get("status") == "ok"}
            for s in stacks
        ],
        "scripts": scripts,
    }


def drill() -> dict:
    """Dry-run for the "simulate power loss" button: report, change nothing.

    Evaluates the trigger against the *current* snapshot and resolves the
    live action sequence, but issues no stop, writes no state and emits no
    alert.  Safe to call while idle, on battery, or even while engaged.
    """
    policy = shutdown_settings()
    try:
        status = _ups_status()
    except Exception:
        status = {"present": False}
    would, reason = (_condition(status, policy) if status.get("present") else (False, ""))
    return {
        "enabled": bool(policy.get("enabled")),
        "would_trigger_now": bool(policy.get("enabled")) and would,
        "reason": reason,
        "sensor_present": bool(status.get("present")),
        "on_battery": bool(status.get("on_battery")),
        "battery_percent": status.get("battery_percent"),
        "time_remaining_min": status.get("time_remaining_min"),
        "steps": build_plan(policy),
        "catalog": _catalog(),
        "settings": policy,
        "state": public_state(),
    }


# ── sweep (called from hub.alerts.check_once) ────────────────────────────────

def sweep(now: int) -> list[dict]:
    """One state-machine tick.  Returns the alerts it emitted (already
    appended + notified via alerts.emit_alert; the list is informational,
    matching what the other checks hand back to check_once)."""
    # File lock (outer) so only one process advances the state machine per
    # tick; thread lock (inner) so the alerter thread and POST /api/alerts/check
    # cannot tick concurrently within this process.
    with _file_lock(), _sweep_lock:
        return _sweep_locked(int(now))


def _sweep_locked(now: int) -> list[dict]:
    st = _load_state()
    phase = st.get("phase") or PHASE_IDLE
    policy = shutdown_settings()

    try:
        status = _ups_status()
    except Exception:
        status = None
    # Sensor unreadable (pmset failed / empty output → present False): never
    # trigger on the unknown, and never *reset* on it either — leaving an
    # outage latched until AC power is positively seen is the safe direction.
    if not status or not status.get("present"):
        return []

    if phase == PHASE_IDLE:
        if not policy.get("enabled"):
            return []
        hit, reason = _condition(status, policy)
        if not hit:
            return []
        return [_engage(now, reason, policy)]

    # engaged / restoring: latched until AC is seen, however the charge moves.
    if status.get("on_ac"):
        if not _worker_busy(st):
            _mutate(lambda s: s.update(phase=PHASE_RESTORING))
            _spawn(_run_restore_sequence)
        return []
    # Still on battery.  A panel death mid-sequence lands here on restart:
    # phase engaged, steps not all resolved, no worker anywhere yet.
    if phase == PHASE_ENGAGED and not st.get("stop_done") and not _worker_busy(st):
        _spawn(_run_stop_sequence)
    return []


def _worker_busy(st: dict) -> bool:
    """Whether a stop/restore worker is running — in this process or a sibling.

    ``_worker_active`` only knows about this interpreter.  When two processes
    share ``data/`` the owner is persisted in the state, so a sibling can see
    it and not spawn a second sequence.  The shared-``data/`` deployment is a
    single Mac, so ``os.kill(pid, 0)`` is a valid liveness probe; a dead owner
    (the crash-mid-sequence case) reads as free so the next sweep resumes.
    """
    if _worker_active.is_set():
        return True
    owner = st.get("worker_owner")
    if not isinstance(owner, dict) or not isinstance(owner.get("pid"), int):
        return False
    # A claim older than a day is treated as stale even if the pid now happens
    # to be alive (pid reuse across a reboot), so it can never wedge forever.
    if int(time.time()) - int(owner.get("ts") or 0) > 86400:
        return False
    try:
        os.kill(owner["pid"], 0)
        return True
    except OSError:
        return False


def _engage(now: int, reason: str, policy: dict) -> dict:
    """Latch, announce, then act — strictly in that order.

    The alert goes out *before* any stop is issued: early in an outage the
    network gear on the same UPS is still alive, so the notification has its
    best chance of leaving the building while nothing has been shut down yet.
    """
    from hub import alerts, audit

    steps = build_plan(policy)
    planned = [s for s in steps if s.get("running")]

    def latch(s: dict) -> None:
        last = s.get("last")  # keep the previous cycle's record visible
        s.clear()
        s.update({
            "phase": PHASE_ENGAGED,
            "engaged_at": now,
            "reason": reason,
            "steps": steps,
            "stop_done": False,
        })
        if last:
            s["last"] = last

    _mutate(latch)
    targets = ", ".join(f"{p['id']}" for p in planned) or "nothing running"
    alert = alerts.emit_alert(
        kind="ups",
        level="down",
        alert_id="ups:shutdown",
        title="ServerHub UPS shutdown policy",
        message=(
            f"UPS shutdown policy triggered ({reason}): "
            f"stopping {len(planned)} target(s) in order: {targets}"
        ),
    )
    try:
        audit.record(audit.UPS_POLICY_TRIGGERED, reason=reason,
                     targets=[p["id"] for p in planned])
    except Exception:
        pass
    _spawn(_run_stop_sequence)
    return alert


def _step_ref(st: dict, kind: str, sid: str) -> dict | None:
    for step in st.get("steps") or []:
        if step.get("kind") == kind and step.get("id") == sid:
            return step
    return None


def _record_step(kind: str, sid: str, **fields) -> None:
    def apply(st: dict) -> None:
        step = _step_ref(st, kind, sid)
        if step is not None:
            step.update(fields)
    _mutate(apply)


def _run_stop_sequence() -> None:
    """Stop every planned-and-running target, in order, recording as it goes.

    Marker-first per stack: ``stop_issued`` is persisted *before* the
    ``compose stop`` runs, so a panel killed mid-stop still knows on restart
    that this stack must be started when power returns (the same contract as
    the stack-backup inflight marker).  Steps already resolved are skipped,
    which is what makes a resumed sequence idempotent.
    """
    from hub import audit
    from hub.paths import DOCKER

    st = _load_state()
    steps = list(st.get("steps") or [])
    stack_steps = [s for s in steps if s.get("kind") == "stack"]
    engine = _engine_up() if any(s.get("running") for s in stack_steps) else True

    try:
        from hub.containers_svc import _stack_paths
        compose_by_id = {str(s.get("id")): s.get("compose_path") for s in _stack_paths()}
    except Exception:
        compose_by_id = {}

    for step in steps:
        # Power can return mid-sequence: the sweep flips the phase to
        # restoring, and stopping the remaining targets only to start them
        # right back would be churn for nothing.  Whatever was already
        # stopped carries its stop_issued marker and is restored normally.
        if (_load_state().get("phase") or PHASE_IDLE) != PHASE_ENGAGED:
            return
        if step.get("done"):
            continue
        kind, sid = step.get("kind"), str(step.get("id"))
        if not step.get("running"):
            _record_step(kind, sid, done=True, skipped="not_running")
            continue
        if kind == "stack":
            compose_path = compose_by_id.get(sid)
            if not engine:
                _record_step(kind, sid, done=True, skipped="engine_down")
                continue
            if not compose_path:
                _record_step(kind, sid, done=True, skipped="no_compose_file")
                continue
            _record_step(kind, sid, stop_issued=True, compose_path=str(compose_path))
            rc, out, err = _run_argv(
                [DOCKER, "compose", "-f", str(compose_path), "stop"],
                timeout=_COMPOSE_TIMEOUT,
            )
            detail = "" if rc == 0 else (err or out or f"exit {rc}").strip()[:200]
            _record_step(kind, sid, done=True, stop_ok=rc == 0, detail=detail)
        else:
            _record_step(kind, sid, stop_issued=True)
            try:
                rc, out, err = _svc_action(sid, "stop")
            except Exception as e:  # unknown target etc. — record, keep going
                rc, out, err = -1, "", str(e)
            detail = "" if rc == 0 else (err or out or f"exit {rc}").strip()[:200]
            _record_step(kind, sid, done=True, stop_ok=rc == 0, detail=detail)
        try:
            audit.record(audit.UPS_POLICY_STEP, action="stop", kind=kind,
                         target=sid, ok=rc == 0, detail=detail)
        except Exception:
            pass

    _mutate(lambda s: s.update(stop_done=True))


def _run_restore_sequence() -> None:
    """Start back exactly what the policy stopped, then return to idle.

    ``stop_issued`` is the whole contract: a stack the policy never touched
    (not running, engine down, unknown) is not started, so an operator's
    deliberate "stopped" state survives the outage.  An *attempted* stop
    counts as touched even if its result was never recorded — compose start
    is idempotent, and starting a stack that was only half-stopped is
    strictly better than leaving it down.
    """
    from hub import alerts, audit
    from hub.paths import DOCKER
    from hub.status import invalidate_status

    st = _load_state()
    steps = list(st.get("steps") or [])
    now = int(time.time())
    failures: list[str] = []
    started: list[str] = []

    for step in steps:
        if not step.get("stop_issued"):
            continue
        kind, sid = step.get("kind"), str(step.get("id"))
        if kind == "stack":
            compose_path = step.get("compose_path")
            if not compose_path:
                _record_step(kind, sid, start_ok=False, start_detail="no compose path recorded")
                failures.append(sid)
                continue
            rc, out, err = _run_argv(
                [DOCKER, "compose", "-f", str(compose_path), "start"],
                timeout=_COMPOSE_TIMEOUT,
            )
        else:
            try:
                rc, out, err = _svc_action(sid, "start")
            except Exception as e:
                rc, out, err = -1, "", str(e)
        detail = "" if rc == 0 else (err or out or f"exit {rc}").strip()[:200]
        _record_step(kind, sid, start_ok=rc == 0, start_detail=detail)
        (started if rc == 0 else failures).append(sid)
        try:
            audit.record(audit.UPS_POLICY_STEP, action="start", kind=kind,
                         target=sid, ok=rc == 0, detail=detail)
        except Exception:
            pass

    def finish(s: dict) -> None:
        s["last"] = {
            "engaged_at": s.get("engaged_at"),
            "reason": s.get("reason"),
            "steps": s.get("steps") or [],
            "restored_at": now,
            "restarted": started,
            "failed": failures,
        }
        s["phase"] = PHASE_IDLE
        for key in ("engaged_at", "reason", "steps", "stop_done"):
            s.pop(key, None)

    _mutate(finish)
    try:
        audit.record(audit.UPS_POLICY_RESET, restarted=started, failed=failures)
    except Exception:
        pass
    if failures:
        message = (
            "Power restored; UPS shutdown policy could not restart: "
            f"{', '.join(failures)} — start them manually"
            + (f" (restarted: {', '.join(started)})" if started else "")
        )
        alerts.emit_alert(kind="ups", level="warn", alert_id="ups:shutdown",
                          title="ServerHub UPS shutdown policy", message=message)
    else:
        message = (
            "Power restored: UPS shutdown policy reset"
            + (f", restarted {len(started)} target(s): {', '.join(started)}"
               if started else " (nothing had been stopped)")
        )
        alerts.emit_alert(kind="ups", level="ok", alert_id="ups:shutdown",
                          title="ServerHub UPS shutdown policy recovered",
                          message=message, event="resolved")
    try:
        invalidate_status()
    except Exception:
        pass
