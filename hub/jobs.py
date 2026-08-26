"""Background maintenance job runner."""
from __future__ import annotations

import os
import signal
import subprocess
import threading

from hub import cli_args
from hub.config import cfg, maintenance_env
from hub.errors import api_error
from hub.status import invalidate_status
from hub.util import iter_capped_lines, strftime_now, utf8_env

_jobs = {}
_jobs_lock = threading.Lock()

#: Per-line character cap for captured output.  The line-count trim below
#: bounds how many lines are retained, but a single line has no natural
#: bound — one giant line (a dumped blob, a \r-driven progress bar) used to
#: be buffered whole before the trim could see it.
LOG_LINE_CAP = 4096
#: Total characters retained across the log window.  The 800-line trim alone
#: still admits 800 × LOG_LINE_CAP ≈ 3 MB per job of pathological output;
#: past this cap the oldest lines are dropped first, same direction as the
#: line trim.
LOG_TOTAL_CAP = 512 * 1024

#: Default / ceiling for ``threading.Timer`` on the watchdog thread.
JOB_TIMEOUT_DEFAULT = 600
JOB_TIMEOUT_MAX = 24 * 3600


def _clamp_timeout(raw, default: int = JOB_TIMEOUT_DEFAULT) -> int:
    """Positive seconds for ``threading.Timer`` / ``Event.wait``.

    YAML ``timeout: true`` is a bool subclass of int (1s). ``1e308`` and a
    400-digit leftover int used to OverflowError the Timer thread
    (``finished.wait`` → C ``_PyTime_t``). Inf/NaN/bytes/datetime took the
    same path after a bare ``int()``.
    """
    if isinstance(raw, bool) or raw is None:
        return default
    if isinstance(raw, (bytes, bytearray)):
        return default
    if isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
        return default
    try:
        n = int(raw)
    except (TypeError, ValueError, OverflowError):
        return default
    if n < 1:
        return default
    if n > JOB_TIMEOUT_MAX:
        return JOB_TIMEOUT_MAX
    return n


def run_watchdog(argv, *, timeout, log, env=None, cwd=None):
    """Run *argv* under a kill-the-group watchdog, streaming output into *log*.

    Extracted from :func:`start_job` so the scheduler engine
    (hub/scheduler_svc.py) reuses the exact same executor semantics instead of
    growing a second, subtly different one:

    * ``for line in p.stdout`` blocks until the child writes or closes the
      pipe, so the deadline cannot be enforced from inside the read loop: a
      silent command (no output at all) never iterates once.  A watchdog timer
      runs independently and kills the process group, which closes the pipe
      and releases the reader.  ``start_new_session`` lets killpg take the
      child's descendants down with it.
    * *log* is a caller-owned list; it is trimmed in place so a chatty command
      cannot grow memory without bound.  The caller keeps whatever reference it
      handed in, so live tailing keeps working.
    * Output is additionally byte-capped, per line and in total
      (:data:`LOG_LINE_CAP` / :data:`LOG_TOTAL_CAP`): the line trim alone
      cannot defend against one enormous line, which ``for line in stdout``
      would buffer whole before the trim ever saw it.

    Returns the exit code: 124 on timeout (matching GNU timeout), the child's
    own code otherwise, and -1 when the process could not be run at all.
    """
    timed_out = threading.Event()
    argv = cli_args.as_argv(argv)
    if argv is None:
        log.append("!! invalid argv")
        return -1
    timeout = _clamp_timeout(timeout)
    try:
        with subprocess.Popen(
            argv,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            # errors="replace": a stray non-UTF-8 byte in job output must
            # degrade to a replacement character, not kill the read loop.
            text=True, errors="replace", env=utf8_env(env), cwd=cwd, start_new_session=True,
        ) as p:
            def _reap():
                """Signal the whole group; SIGTERM first, then SIGKILL."""
                for sig, grace in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
                    if p.poll() is not None:
                        return
                    try:
                        os.killpg(os.getpgid(p.pid), sig)
                    except (ProcessLookupError, PermissionError):
                        return
                    try:
                        p.wait(timeout=grace)
                        return
                    except subprocess.TimeoutExpired:
                        continue

            def _on_deadline():
                if p.poll() is None:
                    timed_out.set()
                    log.append(f"!! timeout after {timeout}s - terminating")
                    _reap()

            watchdog = threading.Timer(timeout, _on_deadline)
            watchdog.daemon = True
            watchdog.start()
            try:
                # Cheap running total; recomputed after every line trim so
                # the two caps cannot drift apart.  Seeded from the caller's
                # pre-existing lines (the "$ command" header and friends).
                total = sum(len(x) for x in log)
                for line in iter_capped_lines(p.stdout, LOG_LINE_CAP):
                    log.append(line)
                    total += len(line)
                    if len(log) > 800:
                        del log[:200]
                        total = sum(len(x) for x in log)
                    while total > LOG_TOTAL_CAP and len(log) > 1:
                        total -= len(log.pop(0))
            finally:
                watchdog.cancel()
                # stdout EOF usually means the child is done, but it may not
                # have been reaped yet.  Killing the group immediately is a
                # SIGTERM race against a child that closed its pipe and is
                # still finishing up: a maintenance/scheduler command that
                # closed stdout before its last step finished rc -15 instead
                # of its real exit code (the same leftover race
                # containers_svc._stream_job_command already fixed).  Wait
                # first; only reap if it is actually still running.
                if p.poll() is None:
                    try:
                        p.wait(timeout=2)
                        # After stdout EOF the child is normally exiting; this
                        # wait is the reap, not a second blocking pipe read.
                    except subprocess.TimeoutExpired:
                        _reap()
        if timed_out.is_set():
            return 124
        return p.returncode if p.returncode is not None else -1
    except Exception as e:
        log.append(f"!! error: {_utf8_text(e)}")
        return -1


def _plain_dict(value) -> dict | None:
    """*value* as a plain ``dict``, or None.

    A leftover dict-*subclass* row (the usage5/metrics5 row-bomb class:
    passes the isinstance gate, then ``.get()`` / ``.items()`` / ``__bool__``
    raises) used to 500 all three Maintenance routes — GET /api/maintenance
    via job_state, the log route via job_log, and POST run via start_job's
    mutex scan.  ``dict()`` copies through the C-level storage, so an
    overridden method cannot fire.
    """
    if type(value) is dict:
        return value
    if isinstance(value, dict):
        try:
            return dict(value)
        except Exception:
            return None
    return None


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb.

    Fails closed to False: a bomb row is junk, not a live job, so treating
    it as "running" would wedge the single-runner mutex forever.
    """
    try:
        return bool(value)
    except Exception:
        return False


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500."""
    base = bytes if isinstance(value, bytes) else bytearray
    return base.decode(value, "utf-8", "replace")


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500.

    The scrub itself goes through the *unbound* base method
    (``str.encode``, the audit._utf8_text convention): ``str()`` may hand
    back a subclass instance (it only checks the type, it does not copy)
    when ``__str__`` returns ``self``, so a leftover str-subclass whose
    ``encode`` raised used to blow this scrub from outside every net and
    500 GET /api/maintenance and the log route.  The unbound call also
    guarantees an *exact* ``str`` return, so callers' own ``.strip()`` /
    ``.replace()`` / truth tests cannot hit a subclass override either.
    """
    if isinstance(value, (bytes, bytearray)):
        return _decode_bytes(value)
    if isinstance(value, str):
        text = value
    else:
        try:
            text = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    try:
        return str.encode(text, "utf-8", "replace").decode("utf-8")
    except Exception:
        return ""


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    YAML ``name: .inf`` / ``desc: .nan`` were already dropped; ``!!binary``
    names, ``!!set`` descriptions, and inf ``rc`` in a live job row still
    leaked into GET /api/maintenance. A leftover ``\\ud800`` in a task name
    still 500'd the same encoder (``ensure_ascii=False`` then UTF-8).
    A >4300-digit ``rc`` in a junk job row still passed through untouched:
    CPython's int->str digit limit then ValueError'd ``json.dumps`` itself.
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a leftover subclass
                # ``__str__`` bomb used to blow the digit-cap probe below
                # (only ValueError was caught) and 500 GET /api/maintenance
                # — the modules5 unbound convention.
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
                # Base coercion to an exact float: a leftover subclass
                # ``__eq__``/``__ne__`` bomb used to blow the NaN/inf
                # probes below and 500 GET /api/maintenance.
                value = float.__float__(value)
            except Exception:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, (bytes, bytearray)):
        # Unbound base decode: a leftover bytes-subclass ``decode`` bomb
        # (a poisoned task name — or a bytes mapping *key*, which reaches
        # _utf8_text below) used to 500 the encoder walk.
        return _decode_bytes(value)
    if isinstance(value, dict):
        if type(value) is not dict:
            # dict() copies through the C-level storage, ignoring overridden
            # items()/keys()/__iter__ — a leftover subclass method bomb
            # cannot fire (same guard as metrics/sensors _jsonable).
            try:
                value = dict(value)
            except Exception:
                return None
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
        try:
            items = list(value)
        except Exception:
            # Leftover sequence subclass whose __iter__ raises.
            return None
        return [_jsonable(v, depth + 1) for v in items]
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # Property bomb / __getattr__ raising something that is not
        # AttributeError escapes getattr's default.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/maintenance.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _task_id(raw) -> str:
    """Configured task identity as text; ``""`` drops the entry.

    YAML hex/octal (``id: 0x2A5F``) loads *already-int* — uncapped, because
    ``int(x, 16)`` is exempt from CPython's 4300-digit conversion limit —
    and the strict ``isinstance(str)`` gate silently hid the whole task
    from GET /api/maintenance (the logs_svc._config_text rule).  A
    renderable int coerces through the ``str()`` probe; an over-cap
    leftover — whose ``str()`` raises the same digit-cap ValueError
    ``json.dumps`` would — drops only its entry.  bool passes
    ``isinstance(int)`` and must not become ``"True"``.

    The result is surrogate-scrubbed *before* it becomes the mapping key:
    ``_jsonable`` already scrubbed the row's ``id`` value, so a leftover
    ``\\ud800`` id was listed with the scrubbed ``?`` form while the key kept the
    raw surrogate — POST /api/maintenance/{tid}/run could never match the
    id the list showed, and the mapping itself was not UTF-8 encodable.

    Newlines get the same treatment: Starlette's ``{tid:path}`` convertor is
    ``.*`` compiled without DOTALL, and ``.`` matches every decoded path
    character *except* ``\\n`` — so a YAML literal-block / ``"a\\nb"`` id was
    listed with a Run button whose percent-encoded ``%0A`` request could
    never match the run or log route (the maint4 slash-id class again; every
    other control character routes fine).  The id is only ever a mapping
    key, so folding the newline to a space keeps the task runnable.
    """
    if isinstance(raw, str):
        text = _utf8_text(raw).replace("\r\n", "\n").replace("\n", " ")
        return text.strip()
    if isinstance(raw, bool) or not isinstance(raw, int):
        return ""
    if type(raw) is not int:
        try:
            # Base coercion first: an int-subclass id whose ``__str__``
            # raised anything but the digit-cap ValueError used to 500
            # GET /api/maintenance for every task.
            raw = int.__index__(raw)
        except Exception:
            return ""
    try:
        return str(raw)
    except ValueError:
        return ""


def maintenance_tasks():
    out = {}
    raw = cfg().get("maintenance")
    if isinstance(raw, list):
        try:
            # list() through the C storage: a leftover list-subclass whose
            # __iter__ raises used to 500 GET /api/maintenance.
            rows = list(raw)
        except Exception:
            rows = []
    else:
        rows = []
    for t in rows:
        # _plain_dict, not a bare isinstance: a leftover dict-subclass row
        # whose .get() raised used to 500 the list route one line later.
        row = _plain_dict(t)
        if row is None:
            continue
        tid = _task_id(row.get("id"))
        if not tid:
            continue
        row = dict(row)
        row["id"] = tid
        cleaned = _jsonable(row)
        if isinstance(cleaned, dict):
            # tid is already scrubbed, so this key equals cleaned["id"] —
            # the id the list serves is the id the run/log routes can find.
            out[tid] = cleaned
    return out


def job_state(tid):
    empty = {"running": False, "rc": None, "finished": None}
    if not isinstance(tid, str):
        return empty
    # _plain_dict + _truthy: a leftover dict-subclass row (or a __bool__-bomb
    # ``running`` value) used to 500 GET /api/maintenance for every task.
    j = _plain_dict(_jobs.get(tid))
    if j is None:
        return empty
    cleaned = _jsonable({
        "running": _truthy(j.get("running")),
        "rc": j.get("rc"),
        "finished": j.get("finished"),
    })
    return cleaned if isinstance(cleaned, dict) else empty


def get_job(tid):
    if not isinstance(tid, str):
        return None
    # The plain-dict copy also neutralises a subclass .get() bomb for the
    # only caller (job_log); rows this module writes are already plain.
    return _plain_dict(_jobs.get(tid))


def _log_lines(raw) -> list[str]:
    """String lines from a leftover job-row ``log`` field.  Never raises."""
    if isinstance(raw, str):
        return [raw] if raw else []
    if not isinstance(raw, (list, tuple)):
        return []
    try:
        # A leftover list-subclass whose __iter__ raises used to 500 the
        # log route past the isinstance gate.
        items = list(raw)
    except Exception:
        return []
    out: list[str] = []
    for item in items:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, (bytes, bytearray)):
            # Unbound base decode: a bytes-subclass ``decode`` bomb in a
            # leftover log list used to 500 GET /api/maintenance/{tid}/log.
            out.append(_decode_bytes(item))
    return out


def job_log(tid):
    """Live tail payload for GET /api/maintenance/{tid}/log.  Never raises.

    A junk in-memory row used to AttributeError; an incomplete dict still
    KeyError'd, and ``log: [bytes, None]`` TypeError'd ``str.join``.
    """
    missing = {"running": False, "rc": None, "log": "(not run yet)"}
    if not isinstance(tid, str):
        return missing
    j = get_job(tid)
    if j is None:
        return missing
    text = "\n".join(_log_lines(j.get("log")))
    cleaned = _jsonable({
        "running": _truthy(j.get("running")),
        "rc": j.get("rc"),
        "started": j.get("started"),
        "finished": j.get("finished"),
        "log": text or "(waiting for output…)",
    })
    return cleaned if isinstance(cleaned, dict) else missing


def _row_running(j) -> bool:
    """Whether a (possibly junk) ``_jobs`` row counts as a live job.

    ``isinstance(j, dict) and j.get("running")`` let a leftover dict-subclass
    row raise from ``.get()`` — or a ``__bool__``-bomb value raise inside
    ``any()`` — and 500 POST /api/maintenance/{tid}/run for every task.
    """
    row = _plain_dict(j)
    if row is None:
        return False
    return _truthy(row.get("running"))


def start_job(task):
    task = _plain_dict(task)
    tid = task.get("id") if task is not None else None
    if not isinstance(tid, str):
        return None
    # Exact-str copy before the emptiness probe and the ``_jobs`` insert:
    # a leftover str-*subclass* id (tools_svc hands start_job its own
    # dicts) whose ``__bool__`` / ``__hash__`` raised used to blow ``not
    # tid`` or the mapping insert straight into the calling route.
    tid = _utf8_text(tid)
    if not tid:
        return None
    with _jobs_lock:
        if any(_row_running(j) for j in _jobs.values()):
            raise api_error("jobs.already_running")
        _jobs[tid] = {"running": True, "rc": None, "log": [],
                      "started": strftime_now("%H:%M:%S"), "finished": None}

    def run():
        j = _jobs[tid]
        try:
            env = dict(os.environ)
            env.update(maintenance_env())
            timeout = _clamp_timeout(task.get("timeout"))
            command = task.get("command")
            if not isinstance(command, str) or not command.strip():
                # A task with no usable command (missing from services.yaml,
                # or a junk leftover _jsonable dropped to None) used to finish
                # rc -1 with an EMPTY log: the modal showed "(waiting for
                # output…)" under a failure badge with nothing to say why.
                j["log"].append("!! invalid command")
                j["rc"] = -1
                return
            j["rc"] = run_watchdog(
                ["/bin/bash", "-c", command],
                timeout=timeout, log=j["log"], env=env,
            )
        except Exception as e:
            # Same silent loss one layer up: a failure before run_watchdog
            # (a poisoned maintenance_env read, a junk row) left rc -1 with
            # no explanation at all.
            try:
                j["log"].append(f"!! error: {_utf8_text(e)}")
            except Exception:
                pass
            j["rc"] = -1
        finally:
            j["running"] = False
            j["finished"] = strftime_now("%H:%M:%S")
            invalidate_status()
    threading.Thread(target=run, daemon=True).start()
