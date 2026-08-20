"""SMART self-tests, schedules and history — Unraid's disk health tab, on macOS.

``hub/storage_svc.py`` already reads SMART *attributes*.  What both Unraid and OMV
add on top, and what actually catches a dying disk before it takes data with it,
is the *self-test*: the drive's own internal scan, run on a schedule, with its
result log kept over time.

Three practical macOS constraints shape this module:

* ``smartctl -t`` writes to the device, so it needs root.  Attribute reads usually
  do not.  Each call therefore tries unprivileged first, then passwordless
  ``sudo -n``, and only falls back to the interactive authorization sheet for
  operator-initiated runs.  A scheduled run has no operator to click the sheet, so
  it requires the passwordless rule from ``deploy/sudoers.d/serverhub`` and reports
  clearly when that rule is missing instead of failing silently.
* Apple NVMe controllers expose no ATA self-test.  Capability is probed per device
  and the UI is told which tests a given disk actually supports.
* Results outlive the process, so history is journalled to ``data/`` rather than
  held in memory.
"""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

from hub.config import cfg, update_settings
from hub.macos_admin import run_admin
from hub.paths import DATA_DIR, SMARTCTL
from hub.secure_io import replace_bytes
from hub.util import cached_snapshot, fan_out, read_text_capped, sh, strftime_now

HISTORY_PATH = DATA_DIR / "smart-tests.json"
#: Leftover multi-MB smart-tests.json used to OOM GET /api/smart.
_HISTORY_CAP = 256 * 1024

#: ``/dev/disk4`` — the only device shape accepted into any argv here.
_DEV_RE = re.compile(r"^/dev/disk\d{1,3}$")

TEST_KINDS = ("short", "long", "conveyance", "offline")

#: Rough ceilings so the UI can say "come back later" instead of polling forever.
#: Only a fallback: a drive that reports its own polling times overrides these.
_KIND_HINT_MINUTES = {"short": 2, "conveyance": 5, "long": 120, "offline": 30}

#: How ``smartctl -c`` names each kind, which is not how the panel names them.
#:
#: The ATA spec -- and therefore smartctl -- calls the full surface scan the
#: *extended* self-test; ``smartctl -t`` still takes ``long`` as the argument, so
#: the panel uses "long" throughout.  Scanning the output for "long self-test"
#: matched nothing on any real drive, so ``long`` never reached ``supported``:
#: :func:`start_test` answered ``kind_unsupported``, and a schedule configured for
#: it was journalled as ``unsupported`` and skipped on every run, so the disk was
#: never actually scanned.  ``offline`` is keyed off the offline-data-collection
#: block rather than a routine line, which is where smartctl reports it.
_KIND_TOKENS: dict[str, tuple[str, ...]] = {
    "short": ("short self-test",),
    "long": ("extended self-test",),
    "conveyance": ("conveyance self-test",),
    "offline": ("offline data collection",),
}

#: The routine-line label whose recommended polling time gives each kind's duration.
#: ``offline`` is absent: its cost is reported as "Total time to complete Offline
#: data collection" in seconds, not as a polling time in minutes.
_POLLING_LABELS = {"short": "Short", "long": "Extended", "conveyance": "Conveyance"}


def _polling_time_pattern(label: str) -> str:
    """Match *label*'s recommended polling time in minutes.

    Two details that the previous ``(\\d+)\\s*minutes`` got wrong:

    * smartctl parenthesises the number -- ``recommended polling time: (   2)
      minutes.`` -- so the closing paren sits between the digits and the unit and
      nothing ever matched.  Every duration therefore came from
      :data:`_KIND_HINT_MINUTES` instead of from the drive.
    * the gap may not cross into another routine's block.  A drive that names a
      routine but omits its polling line would otherwise borrow the next
      routine's number, reporting a 2-minute conveyance scan as the extended
      test's duration.
    """
    gap = r"(?:(?!self-test routine).){0,80}?"
    return (
        rf"{label} self-test routine{gap}recommended polling time"
        rf".{{0,40}}?\(\s*(\d+)\s*\)\s*minutes"
    )

SCHEDULE_INTERVALS = {
    "off": 0,
    "daily": 86400,
    "weekly": 7 * 86400,
    "biweekly": 14 * 86400,
    "monthly": 30 * 86400,
}

_history_lock = threading.Lock()
_scheduler_stop: threading.Event | None = None
_scheduler_thread: threading.Thread | None = None

_CACHE_TTL = 30.0


# ── smartctl plumbing ────────────────────────────────────────────────────────

#: Device-type flags smartctl needs per transport, tried in order.
#:
#: This list is short on purpose.  macOS does not give userspace a SCSI/ATA
#: passthrough for USB and Thunderbolt bridges the way Linux does: every
#: ``-d sat``, ``-d scsi`` and ``-d usb*`` variant answers "Not a device of type
#: 'scsi'" for an external enclosure, so probing them only burns a process spawn
#: per disk per boot.  In practice ``smartctl --scan`` finds exactly one thing on
#: an Apple-silicon Mac: the internal NVMe controller.  External-disk health is
#: therefore reported as unavailable-by-transport rather than as a drive fault.
_DEVICE_TYPE_CANDIDATES: tuple[tuple[str, ...], ...] = ((), ("-d", "nvme"))

#: device node → the flag tuple that worked, so the probe runs once per process.
_device_type_cache: dict[str, tuple[str, ...]] = {}

#: One lock per device node, guarding that device's transport probe.
_device_type_locks: dict[str, threading.Lock] = {}
_device_type_locks_guard = threading.Lock()

#: Concurrent per-disk SMART reads. Each disk is an independent controller
#: conversation, so the ceiling is about not queueing dozens of smartctl processes
#: on a host with a large enclosure rather than about contention.
_DEVICE_WORKERS = 8


def _raw_smartctl(argv: list[str], *, timeout: int) -> tuple[int, str, str]:
    """Run smartctl unprivileged, retrying under ``sudo -n`` on a denial.

    smartctl uses the exit status as a bitfield: bit 0 (value 1) means the command
    line itself was wrong, and bit 2 (value 4) means a SMART command failed while
    the returned data is still usable.  Only a permission complaint justifies the
    privileged retry.
    """
    rc, out, err = sh([SMARTCTL, *argv], timeout=timeout)
    out, err = _as_text(out), _as_text(err)
    blob = f"{out}\n{err}".lower()
    if rc not in (0, 4) and any(
        token in blob for token in ("permission", "operation not permitted", "access denied")
    ):
        rc, out, err = sh(["/usr/bin/sudo", "-n", SMARTCTL, *argv], timeout=timeout)
        out, err = _as_text(out), _as_text(err)
    return rc, out, err


def _unsupported(out: str, err: str) -> bool:
    return "not supported by device" in f"{out}\n{err}".lower()


def _device_type_lock(device: str) -> threading.Lock:
    with _device_type_locks_guard:
        lock = _device_type_locks.get(device)
        if lock is None:
            lock = _device_type_locks[device] = threading.Lock()
        return lock


def device_type(device: str) -> tuple[str, ...]:
    """The smartctl ``-d`` flags this device answers to (possibly none).

    Single-flight per device. The probe costs up to two ``smartctl -i`` spawns, and
    now that disks are read concurrently, threads arriving on a cold cache would
    each pay for it and then race to store the same answer. The fast path stays
    lock-free, and the check is repeated inside the lock because the winner fills
    the cache while the others are still waiting on it.
    """
    cached = _device_type_cache.get(device)
    if cached is not None:
        return cached
    with _device_type_lock(device):
        cached = _device_type_cache.get(device)
        if cached is not None:
            return cached
        for flags in _DEVICE_TYPE_CANDIDATES:
            rc, out, err = _raw_smartctl([*flags, "-i", device], timeout=12)
            if rc in (0, 4) and not _unsupported(out, err):
                _device_type_cache[device] = flags
                return flags
        _device_type_cache[device] = ()
        return ()


def _smartctl(args: list[str], *, timeout: int = 20) -> tuple[int, str, str]:
    """Run smartctl for a device, injecting the transport flags it needs.

    The device node is the last element of *args*, matching smartctl's own usage.
    """
    if args and str(args[-1]).startswith("/dev/"):
        flags = device_type(args[-1])
        argv = [*args[:-1], *flags, args[-1]]
    else:
        argv = list(args)
    return _raw_smartctl(argv, timeout=timeout)


def passwordless_available() -> bool:
    """Whether ``sudo -n smartctl`` works, i.e. scheduled tests can run headless."""
    rc, _, _ = sh(["/usr/bin/sudo", "-n", SMARTCTL, "-V"], timeout=6)
    return rc == 0


def _device_nodes() -> list[str]:
    """Physical whole disks, as ``/dev/diskN``."""
    rc, out, _ = sh(["/usr/sbin/diskutil", "list", "physical"], timeout=10)
    out = _as_text(out)
    nodes: list[str] = []
    if rc == 0:
        for match in re.finditer(r"/dev/(disk\d+)\s", out):
            node = f"/dev/{match.group(1)}"
            if node not in nodes:
                nodes.append(node)
    return nodes or ["/dev/disk0"]


def _selftest_raw(device: str) -> tuple[int, str, str]:
    """Raw ``smartctl -l selftest`` output for *device*.

    Split out because two callers need it -- :func:`_capabilities` reads its
    wording to tell "no self-test support" apart from "no controller access", and
    :func:`_selftest_log` parses its rows.  They used to each run the command, so
    building the page cost two identical ~45ms subprocesses per disk.
    """
    return _smartctl(["-l", "selftest", device], timeout=15)


def _caps_raw(device: str) -> tuple[int, str, str]:
    """Raw ``smartctl -c`` output for *device*.

    Shared for the same reason as :func:`_selftest_raw`: :func:`_capabilities` reads
    it for the supported-test list and :func:`_in_progress` reads it for the
    percentage, and running it twice asked one command the same question twice.
    """
    return _smartctl(["-c", device], timeout=15)


def _capabilities(
    device: str,
    selftest: tuple[int, str, str] | None = None,
    caps_raw: tuple[int, str, str] | None = None,
) -> dict:
    """Which self-tests *this* device offers, plus its estimated durations.

    An empty ``supported`` list is a real and common answer, not a parse failure:
    Apple's internal NVMe controllers implement SMART attributes but no self-test
    at all.  ``reason`` carries the drive's own wording so the page can explain
    why there is no button rather than showing an inert one.

    *selftest* and *caps_raw* let a caller that already ran :func:`_selftest_raw` or
    :func:`_caps_raw` pass the output in instead of paying for it again.
    """
    rc, out, err = caps_raw if caps_raw is not None else _caps_raw(device)
    out, err = _as_text(out), _as_text(err)
    text = out or ""
    lowered = text.lower()
    log_rc, log_out, log_err = selftest if selftest is not None else _selftest_raw(device)
    log_blob = f"{_as_text(log_out)}\n{_as_text(log_err)}".lower()

    # Two different failures used to collapse into one message.  "The controller
    # will not talk to us at all" (every external enclosure on macOS) is not the
    # same as "the drive answered and says it has no self-test" (Apple NVMe), and
    # only the second one means the disk is fine but untestable.
    no_access = _unsupported(out, err) or (rc not in (0, 4) and not text)
    selftest_unsupported = (
        "self-tests not supported" in log_blob or "self-test not supported" in lowered
    )

    supported: list[str] = []
    if not no_access and not selftest_unsupported:
        for kind in TEST_KINDS:
            if any(token in lowered for token in _KIND_TOKENS[kind]):
                supported.append(kind)

    minutes: dict[str, int] = {}
    for kind, label in _POLLING_LABELS.items():
        m = re.search(_polling_time_pattern(label), text, re.IGNORECASE | re.DOTALL)
        if m:
            minutes[kind] = int(m.group(1))

    if no_access:
        reason = "no_smart_passthrough"
    elif selftest_unsupported:
        reason = "self_tests_unsupported"
    else:
        reason = ""

    del log_rc  # the log is read for its wording, not its exit status
    return {
        "readable": not no_access and rc in (0, 4) and bool(text),
        "available": bool(supported),
        "supported": supported,
        "reason": reason,
        "device_type": " ".join(device_type(device)) or "auto",
        "estimated_minutes": minutes or {k: v for k, v in _KIND_HINT_MINUTES.items() if k in supported},
        "detail": (err or log_err or "").strip()[:200],
    }


_SELFTEST_ROW = re.compile(
    r"^#\s*(\d+)\s+(.+?)\s{2,}(.+?)\s{2,}(\d+%)\s+(\d+)\s*(.*)$"
)


def _selftest_log(device: str, selftest: tuple[int, str, str] | None = None) -> list[dict]:
    """Parse ``smartctl -l selftest`` into rows, newest first.

    Two output shapes exist: the ATA table (``# 1  Short offline  Completed …``)
    and the NVMe self-test log.  Both are handled; unknown shapes yield nothing
    rather than guessed values.
    """
    rc, out, _ = selftest if selftest is not None else _selftest_raw(device)
    if rc not in (0, 4) or not out:
        return []
    rows: list[dict] = []
    for line in out.splitlines():
        stripped = line.rstrip()
        m = _SELFTEST_ROW.match(stripped.strip())
        if m:
            num, kind, status, remaining, hours, lba = m.groups()
            rows.append({
                "index": int(num),
                "kind": kind.strip(),
                "status": status.strip(),
                "passed": "without error" in status.lower() or "completed" == status.strip().lower(),
                "remaining": remaining,
                "power_on_hours": int(hours),
                "failing_lba": lba.strip() or "",
            })
            continue
        # NVMe: "Self-test status: No self-test in progress" / result table rows
        if stripped.lower().startswith("self-test status"):
            rows.append({
                "index": 0,
                "kind": "nvme",
                "status": stripped.split(":", 1)[1].strip(),
                "passed": "no self-test" in stripped.lower() or "success" in stripped.lower(),
                "remaining": "",
                "power_on_hours": 0,
                "failing_lba": "",
            })
    rows.sort(key=lambda r: r["index"])
    return rows


def _in_progress(device: str, caps_raw: tuple[int, str, str] | None = None) -> dict:
    """Whether a self-test is currently running on *device*, and how far along.

    *caps_raw* lets :func:`_device_report` reuse the ``smartctl -c`` output that
    :func:`_capabilities` also reads, instead of spawning it a second time.
    """
    rc, out, _ = caps_raw if caps_raw is not None else _caps_raw(device)
    out = _as_text(out)
    if rc not in (0, 4) or not out:
        return {"running": False, "percent_remaining": None}
    m = re.search(r"Self-test routine in progress.*?(\d+)%\s*of test remaining", out, re.DOTALL | re.IGNORECASE)
    if not m:
        m2 = re.search(r"of test remaining[.:\s]*(\d+)%", out, re.IGNORECASE)
        if not m2:
            return {"running": False, "percent_remaining": None}
        m = m2
    remaining = int(m.group(1))
    return {"running": True, "percent_remaining": remaining, "percent_done": 100 - remaining}


# ── history journal ──────────────────────────────────────────────────────────

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
    """``sh`` leftovers arrive as bytes/None; parsers and JSON need text."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif value is None:
        return ""
    else:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    return value.encode("utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's ``allow_nan=False`` encoder cannot 500.

    ``last_run: .inf`` in settings was already clamped; a history row with
    ``ts: Infinity`` still 500'd GET /api/smart.  Leftover ``!!binary``,
    a YAML date, a ``!!set``, or ``\\ud800`` still 500'd the same encoder.
    """
    if depth > 16:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
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
            if not isinstance(k, (str, bytes, bytearray)):
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
            # used to skip the float sanitizer and 500 GET /api/smart.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _load_history() -> list[dict]:
    try:
        data = json.loads(read_text_capped(HISTORY_PATH, _HISTORY_CAP))
    except (OSError, TypeError, ValueError, RecursionError):
        return []
    if not isinstance(data, list):
        return []
    return [_jsonable(row) for row in data if isinstance(row, dict)]


def _append_history(record: dict) -> None:
    with _history_lock:
        history = _load_history()
        history.append(_jsonable(record) if isinstance(record, dict) else {})
        # Bounded so a daily schedule cannot grow the file without limit.
        del history[:-500]
        try:
            HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
            replace_bytes(
                HISTORY_PATH,
                json.dumps(history, indent=2, ensure_ascii=False, allow_nan=False).encode("utf-8"),
            )
        except (OSError, TypeError, ValueError, RecursionError):
            # RecursionError: leftover nested SMART history after _jsonable is
            # not ValueError; POST /api/smart/test used to 500 the append.
            pass


def history(limit: int = 100) -> list[dict]:
    records = _load_history()
    try:
        n = max(1, min(int(limit or 100), 500))
    except (TypeError, ValueError, OverflowError):
        n = 100
    return [_jsonable(row) for row in reversed(records[-n:]) if isinstance(row, dict)]


# ── schedule ─────────────────────────────────────────────────────────────────

def _schedule_cfg() -> dict:
    stored = ((cfg().get("settings") or {}).get("smart_schedule") or {})
    return stored if isinstance(stored, dict) else {}


def _now() -> int:
    """Finite unix timestamp. Leftover ``time.time() = inf`` OverflowError'd SMART runs."""
    try:
        return int(time.time())
    except (TypeError, ValueError, OverflowError):
        return 0


def _schedule_epoch(raw) -> float:
    # Leftover YAML ``last_run: true`` is a bool subclass of int;
    # ``float(True)`` is 1.0 and made every schedule look overdue.
    if isinstance(raw, bool) or raw is None:
        return 0.0
    try:
        value = float(raw or 0)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    # ``last_run: .inf`` in settings used to OverflowError ``int(inf)``
    # on GET /api/smart, and Starlette's allow_nan=False encoder 500'd
    # the schedule payload itself.
    if value != value or value in (float("inf"), float("-inf")):
        return 0.0
    return value


def get_schedule() -> dict:
    stored = _schedule_cfg()
    interval = str(stored.get("interval") or "off").lower()
    if interval not in SCHEDULE_INTERVALS:
        interval = "off"
    kind = str(stored.get("kind") or "short").lower()
    if kind not in TEST_KINDS:
        kind = "short"
    devices = stored.get("devices")
    return {
        "interval": interval,
        "kind": kind,
        "last_run": _schedule_epoch(stored.get("last_run")),
        "devices": [d for d in (devices if isinstance(devices, list) else []) if _DEV_RE.match(str(d))],
        "intervals": list(SCHEDULE_INTERVALS),
        "kinds": list(TEST_KINDS),
    }


def set_schedule(*, interval: str, kind: str, devices: list[str]) -> dict:
    interval = (interval or "off").strip().lower()
    if interval not in SCHEDULE_INTERVALS:
        return {"ok": False, "error": "bad_interval"}
    kind = (kind or "short").strip().lower()
    if kind not in TEST_KINDS:
        return {"ok": False, "error": "bad_kind"}
    known = set(_device_nodes())
    cleaned = [str(d) for d in (devices or []) if _DEV_RE.match(str(d)) and str(d) in known]
    current = _schedule_cfg()
    update_settings({
        "smart_schedule": {
            "interval": interval,
            "kind": kind,
            "devices": cleaned,
            "last_run": _schedule_epoch(current.get("last_run")),
        }
    })
    invalidate()
    return {"ok": True, "schedule": get_schedule()}


def _mark_ran() -> None:
    stored = dict(_schedule_cfg())
    stored["last_run"] = _now()
    update_settings({"smart_schedule": stored})


def schedule_due() -> bool:
    schedule = get_schedule()
    period = SCHEDULE_INTERVALS.get(schedule["interval"], 0)
    if not period or not schedule["devices"]:
        return False
    return time.time() - float(schedule["last_run"] or 0) >= period


def run_due_tests() -> dict:
    """Start scheduled self-tests when the interval has elapsed.

    Uses ``sudo -n`` only.  A scheduled run cannot answer an authorization sheet,
    so without the passwordless rule this records a skipped run rather than
    blocking a background thread on a dialog nobody will see.
    """
    if not schedule_due():
        return {"ok": True, "ran": 0, "reason": "not_due"}
    schedule = get_schedule()
    if not passwordless_available():
        _append_history({
            "ts": _now(),
            "device": "",
            "kind": schedule["kind"],
            "origin": "schedule",
            "ok": False,
            "error": "sudo_required",
        })
        _mark_ran()
        return {"ok": False, "ran": 0, "error": "sudo_required"}

    started = 0
    for device in schedule["devices"]:
        caps = _capabilities(device)
        if schedule["kind"] not in caps["supported"]:
            _append_history({
                "ts": _now(),
                "device": device,
                "kind": schedule["kind"],
                "origin": "schedule",
                "ok": False,
                "error": "unsupported",
                "message": caps["reason"],
            })
            continue
        flags = list(device_type(device))
        rc, out, err = sh(
            ["/usr/bin/sudo", "-n", SMARTCTL, "-t", schedule["kind"], *flags, device], timeout=60
        )
        ok = rc in (0, 4)
        started += 1 if ok else 0
        _append_history({
            "ts": _now(),
            "device": device,
            "kind": schedule["kind"],
            "origin": "schedule",
            "ok": ok,
            "message": (_as_text(out) or _as_text(err)).strip()[-300:],
        })
    _mark_ran()
    invalidate()
    return {"ok": True, "ran": started}


def start_scheduler(check_interval: int = 900) -> None:
    """Poll for a due schedule in the background.

    Deliberately a coarse poll rather than a timer aimed at a wall-clock instant:
    a laptop-class Mac sleeps, and a missed absolute deadline would silently skip
    a month of tests.  Checking every 15 minutes catches up after any wake.
    """
    global _scheduler_stop, _scheduler_thread
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    from hub.worker_health import loop_interval
    check_interval = loop_interval(check_interval, 900, minimum=1)
    stop = threading.Event()

    def loop():
        from hub import worker_health
        worker_health.register("smart-schedule", check_interval)
        while not stop.wait(check_interval):
            try:
                worker_health.beat("smart-schedule")
                run_due_tests()
            except Exception:
                # A background health task must never take the panel down.
                pass

    _scheduler_stop = stop
    _scheduler_thread = threading.Thread(target=loop, daemon=True, name="smart-schedule")
    _scheduler_thread.start()


def stop_scheduler(timeout: float = 3.0) -> None:
    global _scheduler_stop, _scheduler_thread
    if _scheduler_stop is not None:
        _scheduler_stop.set()
    # A deliberately stopped worker must not be reported as a dead one.
    from hub import worker_health
    worker_health.unregister("smart-schedule")
    thread = _scheduler_thread
    if thread and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=timeout)
    _scheduler_stop = None
    _scheduler_thread = None


# ── operator-initiated runs ──────────────────────────────────────────────────

def start_test(device: str, kind: str) -> dict:
    """Begin a self-test on *device* now."""
    node = str(device or "").strip()
    if not _DEV_RE.match(node) or node not in set(_device_nodes()):
        return {"ok": False, "error": "bad_device"}
    test = (kind or "").strip().lower()
    if test not in TEST_KINDS:
        return {"ok": False, "error": "bad_kind"}

    caps = _capabilities(node)
    if not caps["available"]:
        # Refusing here beats issuing a command the controller will reject, and
        # lets the UI say which drives can actually be tested.
        return {"ok": False, "error": "unsupported", "reason": caps["reason"], "device": node}
    if test not in caps["supported"]:
        return {"ok": False, "error": "kind_unsupported", "supported": caps["supported"], "device": node}

    flags = list(device_type(node))
    rc, out, err = sh(["/usr/bin/sudo", "-n", SMARTCTL, "-t", test, *flags, node], timeout=60)
    if rc not in (0, 4):
        # No passwordless rule: ask macOS for one-shot authorization instead.
        admin = run_admin([SMARTCTL, "-t", test, *flags, node], timeout=120)
        ok = bool(admin.get("ok")) if isinstance(admin, dict) else False
        message = _as_text((admin or {}).get("message") if isinstance(admin, dict) else "")
    else:
        ok = True
        message = (_as_text(out) or _as_text(err)).strip()

    _append_history({
        "ts": _now(),
        "device": node,
        "kind": test,
        "origin": "manual",
        "ok": ok,
        "message": message[-300:],
    })
    invalidate()
    return {
        "ok": ok,
        "device": node,
        "kind": test,
        "estimated_minutes": _KIND_HINT_MINUTES.get(test),
        "message": message[-300:],
    }


def abort_test(device: str) -> dict:
    """Cancel a running self-test on *device*."""
    node = str(device or "").strip()
    if not _DEV_RE.match(node) or node not in set(_device_nodes()):
        return {"ok": False, "error": "bad_device"}
    flags = list(device_type(node))
    rc, out, err = sh(["/usr/bin/sudo", "-n", SMARTCTL, "-X", *flags, node], timeout=30)
    if rc not in (0, 4):
        result = run_admin([SMARTCTL, "-X", *flags, node], timeout=60)
        invalidate()
        cleaned = _jsonable(result) if isinstance(result, dict) else {}
        return cleaned if isinstance(cleaned, dict) else {"ok": False, "error": "failed"}
    invalidate()
    return {"ok": True, "message": (_as_text(out) or _as_text(err)).strip()[-300:]}


# ── page payload ─────────────────────────────────────────────────────────────

def _device_report(node: str) -> dict:
    """Everything the page shows for one disk.

    Cannot raise: this runs inside :func:`fan_out`, where an escaping exception is
    re-raised on iteration and would cost every other disk's report as well as this
    one. A disk that fails to answer is reported as unreadable, which is what the
    page already renders for external enclosures.
    """
    try:
        # Resolve the transport flags first. Both reads below need them, and probing
        # from inside the pair would make one of them wait on the other's probe.
        device_type(node)
        # `smartctl -l selftest` and `smartctl -c` are separate conversations with
        # the drive and neither parses the other's output.
        selftest, caps_raw = fan_out(
            lambda probe: probe(),
            [lambda: _selftest_raw(node), lambda: _caps_raw(node)],
            max_workers=2,
        )
        caps = _capabilities(node, selftest=selftest, caps_raw=caps_raw)
        log = _selftest_log(node, selftest=selftest)
        progress = _in_progress(node, caps_raw=caps_raw)
        failures = [r for r in log if r["index"] and not r["passed"]]
        return {
            "device": node,
            "id": node.rsplit("/", 1)[-1],
            "capabilities": caps,
            "log": log[:20],
            "log_count": len(log),
            "last_result": log[0]["status"] if log else "",
            "failures": len(failures),
            "progress": progress,
        }
    except Exception as e:  # noqa: BLE001 -- see docstring
        return {
            "device": node,
            "id": node.rsplit("/", 1)[-1],
            "capabilities": {
                "readable": False,
                "available": False,
                "supported": [],
                "reason": "probe_failed",
                "device_type": "auto",
                "estimated_minutes": {},
                # Leftover ``\\ud800`` in a raised message used to 500 GET /api/smart.
                "detail": _as_text(e)[:200],
            },
            "log": [],
            "log_count": 0,
            "last_result": "",
            "failures": 0,
            "progress": {"running": False, "percent_remaining": None},
        }


def _smartctl_installed() -> bool:
    """``Path.exists()`` raises EIO/ESTALE on a dying mount; pathlib only
    swallows ENOENT/ELOOP.  That used to 500 GET /api/smart."""
    try:
        return Path(SMARTCTL).exists()
    except (OSError, ValueError):
        return False


@cached_snapshot(_CACHE_TTL)
def overview() -> dict:

    nodes = _device_nodes()
    # One disk's SMART reads tell you nothing about another's, but in series the page
    # cost grew with every attached disk, and each smartctl read is tens of
    # milliseconds at best -- far worse on a drive that is spinning up or already
    # failing, which is the situation this page exists for. `passwordless_available`
    # joins the same wave rather than trailing it. `fan_out` preserves
    # `diskutil list physical` order, so the table does not reshuffle between
    # refreshes, and `_device_report` absorbs its own failures.
    probes = [(lambda n=node: _device_report(n)) for node in nodes]
    results = fan_out(
        lambda probe: probe(),
        probes + [passwordless_available],
        max_workers=min(len(probes) + 1, _DEVICE_WORKERS),
    )
    devices, passwordless = list(results[:-1]), results[-1]

    schedule = get_schedule()
    period = SCHEDULE_INTERVALS.get(schedule["interval"], 0)
    next_due = 0
    if period:
        try:
            next_due = int(_schedule_epoch(schedule.get("last_run")) + period)
        except (TypeError, ValueError, OverflowError):
            next_due = 0
    data = {
        "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
        "devices": devices,
        "schedule": schedule,
        "next_due": next_due,
        "overdue": bool(period) and schedule_due(),
        "passwordless_sudo": passwordless,
        "smartctl": SMARTCTL,
        "smartctl_installed": _smartctl_installed(),
        "history": history(30),
    }
    return data


def invalidate() -> None:
    overview.invalidate()
