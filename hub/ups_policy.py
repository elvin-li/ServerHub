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
from hub.secure_io import replace_bytes
from hub.util import read_text_capped, safe_json_loads

log = logging.getLogger("serverhub.ups_policy")

STATE_FILE = DATA_DIR / "ups-policy-state.json"
#: Leftover multi-MB state used to OOM GET /api/ups.
_STATE_CAP = 256 * 1024
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
    itself is swapped in by ``replace_bytes`` and a lock on the old inode would
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


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500."""
    base = bytes if isinstance(value, bytes) else bytearray
    return base.decode(value, "utf-8", "replace")


def _as_text(value) -> str:
    """Exception/subprocess text that cannot RecursionError leftover ``str(e)``."""
    if isinstance(value, (bytes, bytearray)):
        return _decode_bytes(value)
    if value is None:
        return ""
    try:
        value = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    # Unbound base encode: a str-subclass ``.encode`` bomb cannot raise out
    # of the laundering pass itself.
    return str.encode(value, "utf-8", "replace").decode("utf-8")


def _run_argv(argv: list[str], *, timeout: int) -> tuple[int, str, str]:
    """(rc, stdout, stderr); must report, never raise (worker-thread caller)."""
    from hub.util import run_capped
    try:
        rc, text = run_capped(argv, timeout=timeout, cap=4000)
        return rc, text, ""
    except Exception as e:  # noqa: BLE001 — a policy step must record, not raise
        return -1, "", _as_text(e)


def _engine_up() -> bool:
    from hub.docker_cli import engine_up
    return engine_up()


def _now() -> int:
    """Finite unix timestamp. Leftover ``time.time() = inf`` OverflowError'd UPS restore."""
    try:
        return int(time.time())
    except (TypeError, ValueError, OverflowError):
        return 0


def _list_stacks() -> list[dict]:
    """Compose stacks with live status ("ok" means running containers)."""
    from hub import containers_svc
    return containers_svc.list_stacks()


def _jsonable(value, depth: int = 0):
    """Drop leftovers so Starlette's allow_nan=False encoder cannot 500.

    A leftover ``engaged_at: 1e400`` in the state file used to 500 GET /api/ups.
    ``json.dumps`` without ``allow_nan=False`` used to rewrite Infinity back
    onto disk from ``_save_state``.
    A >4300-digit leftover int still passed through untouched: CPython's
    int->str digit limit then ValueError'd ``json.dumps`` itself.
    A *subclass* scalar still ran its own dunders through the probes: an int
    ``__str__`` bomb, a float ``__eq__`` bomb, a bytes ``decode`` bomb and a
    str ``encode`` bomb (value or key) each used to raise out of this scrub
    (the hub.modules unbound-base rule).
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__``
                # bomb used to blow the digit-cap probe below.
                value = int.__index__(value)
            except Exception:
                return None
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if isinstance(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except Exception:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        # str() then unbound base encode: a str-subclass ``encode`` bomb
        # used to raise out of the surrogate laundering itself.
        try:
            value = str(value)
        except Exception:
            return None
        return str.encode(value, "utf-8", "replace").decode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return _decode_bytes(value)
    if isinstance(value, dict):
        try:
            items = list(value.items())
        except Exception:
            # A mapping that refuses iteration (odd dict subclass): there is
            # nothing to salvage from it, but its *siblings* must survive —
            # the raise used to ride out of drill()'s scrub and 500 the
            # route (the nginx_svc._jsonable rule).
            return None
        out = {}
        for pair in items:
            # Per-pair unpack guard: a torn non-pair row from a subclass
            # ``items()`` used to ValueError out of the loop head and take
            # every sane sibling pair down with it.
            try:
                k, v = pair
            except Exception:
                continue
            if isinstance(k, (bytes, bytearray)):
                k = _decode_bytes(k)
            elif not isinstance(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            # A str *key* skipped the string sanitizer below: a leftover JSON
            # ``"\ud800…"`` key in the state file's steps/last used to 500
            # Starlette's UTF-8 encode of GET /api/ups — and _save_state's own
            # encode failed the same way, so every _mutate silently stopped
            # persisting while the poisoned key sat there.  str() + unbound
            # base encode also keeps a str-subclass ``encode`` bomb key from
            # raising out of the laundering itself.
            try:
                k = str(k)
            except Exception:
                continue
            k = str.encode(k, "utf-8", "replace").decode("utf-8")
            out[k] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        try:
            return [_jsonable(v, depth + 1) for v in value]
        except Exception:
            # Same class as the mapping above, at sequence rank: only this
            # field drops, never the row or the route.
            return None
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # getattr's default only swallows AttributeError; a property or
        # ``__getattr__`` bomb still raised out of the probe itself.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/ups.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _as_text(value)
    except Exception:
        return None


def _row_get(row, key):
    """Seam-row field read that a dict-subclass ``.get`` bomb cannot 500.

    ``isinstance(s, dict)`` passes an odd subclass whose ``get`` raises (the
    disk_power_svc pool5 class); one such row from the stack/script/status
    seams used to raise out of build_plan()/_catalog() and 500
    GET /api/ups/shutdown/plan and POST /api/ups/shutdown/drill with every
    sane sibling row.  ``dict.get`` reads the real storage underneath the
    override, so a subclass that only poisoned its method keeps its data.
    """
    if not isinstance(row, dict):
        return None
    try:
        return row.get(key)
    except Exception:
        try:
            return dict.get(row, key)
        except Exception:
            return None


def _seam_eq(value, expected) -> bool:
    """Guarded ``==`` against a raw seam value.

    ``value == "ok"`` dispatches to the value's own ``__eq__`` first, so one
    subclass eq-bomb ``status`` in a stack row from the ``_list_stacks`` seam
    used to raise out of ``build_plan``/``_catalog``'s ``running`` probe and
    500 GET /api/ups/shutdown/plan and POST /api/ups/shutdown/drill with
    every sane sibling row — and the same raise escaped ``_engage``'s plan
    build during a real outage.  An unreadable status reads as not-running,
    the conservative direction (never stop, never restore-start it).
    """
    try:
        return bool(value == expected)
    except Exception:
        return False


def _truthy(value) -> bool:
    """``bool()`` that a raw seam value's ``__bool__`` bomb cannot raise out of."""
    try:
        return bool(value)
    except Exception:
        return False


def _service_states() -> dict[str, str]:
    """service id -> state ("ok"/"warn"/"down"/...), from the shared status."""
    from hub.status import full_status
    out: dict[str, str] = {}
    try:
        groups = full_status(force=False).get("groups") or []
        # Materialize under the guard: a list *subclass* passes the
        # isinstance gate but one whose ``__iter__`` raises used to abort
        # this reader mid-scan and wipe every sibling's state with it.
        groups = list(groups) if isinstance(groups, list) else []
    except Exception:
        groups = []
    for g in groups:
        if not isinstance(g, dict):
            continue
        # _row_get: a group whose ``get`` raises used to abort the whole
        # scan and wipe every sibling group's states along with its own.
        # isinstance, not ``or []``: truth-testing a __bool__ bomb value
        # would raise the same way.
        services = _row_get(g, "services")
        if not isinstance(services, list):
            continue
        try:
            services = list(services)
        except Exception:
            # One group's services refusing iteration drops that group
            # alone; the states already collected keep their rows honest.
            continue
        for s in services:
            if not isinstance(s, dict):
                continue
            # str() probe, not a bare render: an already-int over-cap id or
            # state (YAML hex) used to ValueError here and drop every
            # sibling service's state along with its own.
            sid = _cfg_text(_row_get(s, "id"))
            if not sid:
                continue
            out[sid] = _cfg_text(_row_get(s, "state")) or "unknown"
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
    _mutate(lambda s: s.update(worker_owner={"pid": os.getpid(), "ts": _now()}))

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

def _capped_json_int(text):
    """``json.loads`` parse_int hook: an over-cap digit run drops to None.

    ``int()`` of a >4300-digit number is the digit-cap *ValueError* (not
    JSONDecodeError) for the whole document: one leftover huge number in the
    state file (a hand-edited ``engaged_at``, a stray counter) used to make
    :func:`_load_state` read the entire policy state as ``{}`` — mid-outage
    the latched ``engaged`` phase and every recorded stop marker silently
    read as idle, so the restore pass never ran, and the next ``_mutate``
    persisted that wipe for real.  The one unrenderable number drops alone
    (``_jsonable`` could never render it anyway) and the siblings survive.
    """
    try:
        return int(text)
    except ValueError:
        return None


def _load_state() -> dict:
    try:
        if not STATE_FILE.exists():
            return {}
        data = safe_json_loads(
            read_text_capped(STATE_FILE, _STATE_CAP),
            parse_int=_capped_json_int,
        )
        if isinstance(data, dict):
            return data
    except (OSError, ValueError, TypeError, RecursionError):
        pass
    return {}


def _save_state(st: dict) -> None:
    """Atomic publish, same tmp+replace shape as alerts._save_state: a crash
    mid-write must never leave a truncated file that reads as "idle" while
    stacks are actually stopped."""
    try:
        STATE_FILE.parent.mkdir(exist_ok=True)
        payload = json.dumps(
            _jsonable(st), ensure_ascii=False, indent=2, allow_nan=False, default=str,
        )
        # O_EXCL|O_NOFOLLOW tmp: write_text followed a planted `{name}.{pid}.tmp`
        # symlink and then os.replace'd that link onto the live state file.
        replace_bytes(STATE_FILE, payload.encode("utf-8"))
    except (OSError, ValueError, TypeError, OverflowError, UnicodeError, RecursionError):
        # RecursionError: leftover nested UPS state after _jsonable is not ValueError.
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
    phase = st.get("phase")
    if not isinstance(phase, str) or not phase:
        phase = PHASE_IDLE
    steps = st.get("steps")
    if not isinstance(steps, list):
        steps = []
    reason = st.get("reason")
    if not isinstance(reason, str):
        reason = ""
    last = st.get("last")
    return _jsonable({
        "phase": phase,
        "engaged_at": st.get("engaged_at"),
        "reason": reason,
        "steps": [s for s in steps if isinstance(s, dict)],
        "last": last if isinstance(last, dict) else None,
    })


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

    Status reads go through ``_row_get`` + ``_truthy``: a dict-subclass
    ``.get``/``__bool__`` bomb from the ``_ups_status`` seam used to 500
    the plan/drill routes out of this evaluation — and to raise out of
    ``sweep()`` into check_once's containment, silently killing the tick.
    """
    if not _truthy(_row_get(status, "on_battery")):
        return False, ""
    pct_floor = policy.get("trigger_pct")
    min_floor = policy.get("trigger_remaining_min")
    checks: list[tuple[bool, str]] = []
    if pct_floor is not None:
        pct = _row_get(status, "battery_percent")
        try:
            hit = pct is not None and float(pct) <= float(pct_floor)
        except (TypeError, ValueError, OverflowError):
            hit = False
        checks.append((hit, f"battery {pct}% ≤ {pct_floor}%" if hit else ""))
    if min_floor is not None:
        remain = _row_get(status, "time_remaining_min")
        try:
            hit = remain is not None and float(remain) <= float(min_floor)
        except (TypeError, ValueError, OverflowError):
            hit = False
        checks.append((hit, f"≈{remain} min left ≤ {min_floor} min" if hit else ""))
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
    # Materialize inside the guard: a list *subclass* passes isinstance but
    # one whose ``__iter__`` raises used to blow up the scrub comprehension
    # *outside* this try and 500 GET /api/ups/shutdown/plan and
    # POST /api/ups/shutdown/drill (the nginx overview() rule).
    try:
        stacks = [s for s in _list_stacks() if isinstance(s, dict)]
    except Exception:
        stacks = []
    # _cfg_text probe, not a bare str(): an already-int over-cap id (YAML
    # hex, exempt from the digit cap) in one row used to ValueError here and
    # wipe every sane sibling out of the plan with the 500.  _row_get, not a
    # bare ``.get``: a dict-subclass row whose ``get`` raises used to 500 the
    # plan/drill routes the same way.
    by_id: dict[str, dict] = {}
    for s in stacks:
        sid = _cfg_text(_row_get(s, "id"))
        if sid and sid not in by_id:
            by_id[sid] = s
    wanted = policy.get("stacks")
    if isinstance(wanted, list):
        ordered = [_cfg_text(x) for x in wanted]
    else:  # "all"
        ordered = [_cfg_text(_row_get(s, "id")) for s in stacks]
    # Dedupe, first occurrence wins: steps are addressed by (kind, id) in the
    # state file, so a duplicated id would leave one entry forever unresolved.
    # An id with no renderable text cannot be addressed at all and drops.
    seen: set[str] = set()
    ordered = [sid for sid in ordered if sid and not (sid in seen or seen.add(sid))]
    for sid in ordered:
        stack = by_id.get(sid)
        # ``stack is not None`` rather than truth-testing: a dict-subclass
        # row whose ``__bool__`` raises used to 500 the plan out of the old
        # ``bool(stack and …)`` expression.
        steps.append({
            "kind": "stack",
            "id": sid,
            # Same probe for the label: an over-cap int name falls back to
            # the id instead of 500ing the whole plan.
            "name": _cfg_text(_row_get(stack, "name")) or sid,
            # _seam_eq: a subclass eq-bomb status used to 500 the plan out
            # of this bare ``== "ok"`` compare.
            "running": stack is not None
            and _seam_eq(_row_get(stack, "status"), "ok"),
            "known": stack is not None,
        })
    # Separate namespace: steps are addressed by (kind, id), so a service id
    # that happens to match a stack id is a different step, not a duplicate.
    seen_svc: set[str] = set()
    raw_scripts = policy.get("stop_scripts")
    script_ids = [_cfg_text(x) for x in (raw_scripts if isinstance(raw_scripts, list) else [])]
    script_ids = [sid for sid in script_ids if sid and not (sid in seen_svc or seen_svc.add(sid))]
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


def _cfg_text(value) -> str:
    """Renderable text for a raw services.yaml scalar, or "" when it has none.

    ``yaml.safe_load`` parses ``id: 0xFFF…`` through ``int(raw, 16)``, which is
    exempt from CPython's 4300-digit str->int cap, so a hand-edited leftover
    arrived *already-int* and the bare ``str()`` in ``_catalog`` raised the
    int->str digit-cap ValueError — 500ing GET /api/ups/shutdown/plan and
    POST /api/ups/shutdown/drill, i.e. the whole UPS settings form.  An
    unrenderable scalar reads as "no value" (the backups pg_targets rule);
    a sane numeric id keeps its old ``str()`` coercion.  An int-*subclass*
    ``__str__`` bomb escaped the digit-cap ``except ValueError`` and 500'd
    GET /api/ups/shutdown/plan and POST /api/ups/shutdown/drill out of the
    script/stack pickers; the unbound base coercion renders its real value.

    The result is always an *exact* ``str``: ``str(x)`` returns whatever a
    subclass ``__str__`` hands back, so a str subclass whose ``__str__``
    returns *itself* rode out of the old base copy still carrying its dunder
    bombs — its ``__hash__``/``__eq__`` then blew up ``build_plan``'s dedupe
    set, its by-id index and the service-state compare, 500ing the plan and
    drill routes with every sane sibling row.  The unbound ``str.__str__``
    base copy strips the subclass while keeping its rendered text.
    """
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, int):
        try:
            # Unbound base coercion first, so the str() probe never runs a
            # subclass ``__str__``; past the digit cap it stays ValueError.
            return str(int.__index__(value))
        except Exception:
            return ""
    if isinstance(value, str) and type(value) is str:
        return value
    try:
        text = str(value)
    except Exception:
        return ""
    if type(text) is str:
        return text
    try:
        return str.__str__(text)
    except Exception:
        return ""


def _catalog() -> dict:
    """Everything the policy *could* act on, for the settings pickers.

    Distinct from the plan: the plan resolves the configured selection, while
    the form needs the full menu — every compose stack (configured or
    auto-scanned) and every script entry from services.yaml.
    """
    # Same materialize-under-guard as build_plan: an iteration-refusing
    # list subclass from the seam used to 500 the plan/drill routes.
    try:
        stacks = [s for s in _list_stacks() if isinstance(s, dict)]
    except Exception:
        stacks = []
    from hub.config import cfg
    scripts = []
    try:
        raw_scripts = cfg().get("scripts")
        # A scripts list whose iteration raises passed the isinstance gate
        # and 500'd the catalog the same way; an unreadable list means an
        # empty picker, never a dead settings form.
        raw_scripts = list(raw_scripts) if isinstance(raw_scripts, list) else []
    except Exception:
        raw_scripts = []
    for s in raw_scripts:
        if not isinstance(s, dict):
            continue
        # _row_get: a dict-subclass row whose ``get`` raises used to 500 the
        # plan/drill routes out of this loop with every sane sibling.
        sid = _cfg_text(_row_get(s, "id"))
        if not sid:
            # No renderable id: the entry cannot be selected or acted on, so
            # it drops alone rather than 500ing the whole picker catalog.
            continue
        try:
            # Without a stop command run_action degrades to a no-op stop,
            # so the form marks these rather than hiding them.  Guarded: a
            # __bool__ bomb stop value used to 500 the whole catalog where
            # "no usable stop" is the honest reading.
            has_stop = bool(_row_get(s, "stop"))
        except Exception:
            has_stop = False
        scripts.append({
            "id": sid,
            "name": _cfg_text(_row_get(s, "name")) or sid,
            "has_stop": has_stop,
        })
    stack_rows = []
    for s in stacks:
        # _cfg_text probe, matching the scripts side above: one row whose
        # already-int over-cap id/name (YAML hex) fails str() drops alone
        # instead of 500ing the whole picker catalog with its siblings —
        # and _row_get keeps a ``.get`` bomb row from doing the same.
        sid = _cfg_text(_row_get(s, "id"))
        if not sid:
            continue
        stack_rows.append({
            "id": sid,
            "name": _cfg_text(_row_get(s, "name")) or sid,
            # _seam_eq: a subclass eq-bomb status used to 500 the whole
            # picker catalog out of this bare ``== "ok"`` compare.
            "running": _seam_eq(_row_get(s, "status"), "ok"),
        })
    return {
        "stacks": stack_rows,
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
    # _row_get + _truthy on every status read: a dict-subclass ``.get`` or
    # ``__bool__`` bomb from the _ups_status seam used to 500 both
    # GET /api/ups/shutdown/plan and POST /api/ups/shutdown/drill.
    present = isinstance(status, dict) and _truthy(_row_get(status, "present"))
    would, reason = (_condition(status, policy) if present else (False, ""))
    return _jsonable({
        "enabled": bool(policy.get("enabled")),
        "would_trigger_now": bool(policy.get("enabled")) and would,
        "reason": reason,
        "sensor_present": present,
        "on_battery": _truthy(_row_get(status, "on_battery")),
        "battery_percent": _row_get(status, "battery_percent"),
        "time_remaining_min": _row_get(status, "time_remaining_min"),
        "steps": build_plan(policy),
        "catalog": _catalog(),
        "settings": policy,
        "state": public_state(),
    })


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
    # _row_get + _truthy: a dict-subclass ``.get``/``__bool__`` bomb from the
    # seam used to raise out of sweep() into check_once's containment and
    # silently kill every UPS tick.
    if not isinstance(status, dict) or not _truthy(_row_get(status, "present")):
        return []

    if phase == PHASE_IDLE:
        if not policy.get("enabled"):
            return []
        hit, reason = _condition(status, policy)
        if not hit:
            return []
        return [_engage(now, reason, policy)]

    # engaged / restoring: latched until AC is seen, however the charge moves.
    if _truthy(_row_get(status, "on_ac")):
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
    if not isinstance(owner, dict):
        return False
    pid = owner.get("pid")
    # bool passes isinstance(int); a leftover ``pid: true`` used to probe
    # pid 1 (always alive) and read as busy for up to a day.  Zero/negative
    # pids probe this process / a whole process group, never a real owner.
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    # A claim older than a day is treated as stale even if the pid now happens
    # to be alive (pid reuse across a reboot), so it can never wedge forever.
    try:
        claimed = int(owner.get("ts") or 0)
    except (TypeError, ValueError, OverflowError):
        return False
    if _now() - claimed > 86400:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OverflowError:
        # A leftover pid past the C long range is no real process.  os.kill
        # raises OverflowError, not OSError, and it used to escape sweep():
        # check_once's containment ate it, so the whole UPS policy tick
        # silently aborted every sweep — never engaging, never restoring —
        # for as long as the leftover sat in the state file.
        return False
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
        if isinstance(step, dict) and step.get("kind") == kind and step.get("id") == sid:
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
    steps = [s for s in (st.get("steps") or []) if isinstance(s, dict)]
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
                rc, out, err = -1, "", _as_text(e)
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
    steps = [s for s in (st.get("steps") or []) if isinstance(s, dict)]
    now = _now()
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
                rc, out, err = -1, "", _as_text(e)
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
