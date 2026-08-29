"""Background maintenance job runner."""
from __future__ import annotations

import os
import re
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

# Real control flow must keep propagating even through the bomb guards
# (the nas13/modules12/logs12/json13 convention): swallowing a Ctrl-C or
# an interpreter shutdown to save one JSON field would turn the sanitizer
# into a hang.  Everything else BaseException-shaped that a leftover raises
# out of its own hooks is a bomb like any other — every guard below used to
# stop at ``except Exception``, so a leftover whose hooks raise a
# *BaseException* subclass sailed past all three Maintenance routes' nets
# at once.
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)


def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so a value whose ``__class__`` is a raising
    property blew every bare ``isinstance`` gate in this module — at cfg
    root, row, id, nested-value, ``_jobs``-row and log-line rank — straight
    out of all three Maintenance routes and the scheduler's callers
    (the modules8/bookmarks8 rule).
    A lying ``__class__`` (answers ``int``) is *not* an error and still
    reports its claim here; the numeric arms' unbound base coercion then
    drops it, exactly as before.

    ``except BaseException``: the old guard stopped at ``Exception``, so a
    leftover whose ``__class__`` property raises a *BaseException* subclass
    sailed past this catch — the gate every sanitizer arm in this module
    stands on — and 500'd all three Maintenance routes raw.  Only genuine
    control flow keeps propagating.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _real(value, types) -> bool:
    """True when the *real* storage layout is this type.

    ``type(value)`` reads the C-level type slot, which a lying ``__class__``
    property cannot swap, so this is the probe for the recover-the-real-
    storage fall-throughs below (the modules14/assistant14/bookmarks14
    rule): ``isinstance`` consults ``value.__class__`` only after the
    real-MRO check misses, so a lying claim steered a leftover into the arm
    of its claim, the unbound descriptor there refused the real layout, and
    the old early return threw honest renderable storage away at the wrong
    rank.  After a claimed arm rejects the operand, only the arm the *real*
    layout matches may pick the value up — the lie must not steer the walk
    a second time.  Fail-closed like ``_isinst``.
    """
    try:
        return issubclass(type(value), types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _clamp_timeout(raw, default: int = JOB_TIMEOUT_DEFAULT) -> int:
    """Positive seconds for ``threading.Timer`` / ``Event.wait``.

    YAML ``timeout: true`` is a bool subclass of int (1s). ``1e308`` and a
    400-digit leftover int used to OverflowError the Timer thread
    (``finished.wait`` → C ``_PyTime_t``). Inf/NaN/bytes/datetime took the
    same path after a bare ``int()``.
    """
    # ``type(raw) is bool``, not isinstance: bool cannot be subclassed, and
    # the exact check never reads a leftover's bombing ``__class__``.
    if type(raw) is bool or raw is None:
        return default
    if _isinst(raw, (bytes, bytearray)):
        return default
    if _isinst(raw, float):
        if type(raw) is not float:
            try:
                # Base coercion first: a float-subclass timeout whose
                # ``__eq__``/``__ne__`` raised used to blow the NaN probe
                # below straight out of run_watchdog's pre-try clamp.
                raw = float.__float__(raw)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return default
        if raw != raw or raw in (float("inf"), float("-inf")):
            return default
    try:
        n = int(raw)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Broad on purpose: an int-subclass ``__int__``/``__index__`` bomb
        # (or a ``__class__`` bomb with no numeric protocol at all) raised
        # RuntimeError here, past the old (TypeError, ValueError,
        # OverflowError) net — and a BaseException-shaped bomb rode past
        # even the broad Exception net into the watchdog thread.
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
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        # BaseException too: a leftover Popen stub (tests and tooling patch
        # it) raising a BaseException subclass used to sail past the old
        # ``except Exception`` and kill the job/scheduler thread with the
        # row parked "running" — the run was never journalled.
        log.append(f"!! error: {_error_text(e)}")
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
    # _isinst, not a bare isinstance: a leftover non-dict row whose
    # ``__class__`` is a raising property used to detonate the gate itself
    # (the real-type fast check misses, CPython reaches for ``__class__``)
    # and 500 all three Maintenance routes before the copy ever ran.
    if _isinst(value, dict):
        try:
            return dict(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A liar whose ``__class__`` merely answers dict has no C-level
            # storage, so ``dict()`` falls back to its keys()/__iter__ hooks
            # — and a hook raising a BaseException subclass used to sail
            # past the old ``except Exception`` and 500 the listing.
            return None
    return None


def _mapping_get(mapping, key, default=None):
    """Field read that a leftover hash-shadowing mapping *key* cannot 500.

    The vms_svc/ups_svc rule this module never got: ``_plain_dict`` returns
    the row (or a ``dict()`` copy) with its *keys* intact, and even a plain
    ``dict.get`` probe still compares the probe against every stored key
    whose hash collides — dispatching into that key's own ``__eq__``.  A
    leftover str-subclass key whose text shadows a real field name and whose
    ``__eq__`` raises (or returns a ``__bool__``-bomb) used to detonate
    ``row.get("id")`` in :func:`maintenance_tasks` (500 on the list AND run
    routes), ``j.get(...)`` in :func:`job_state` / :func:`job_log` (500 on
    the list and log routes), and ``row.get("running")`` in
    :func:`_row_running` (500 on the run route).  Only the shadowed field
    degrades to its default; sibling fields and rows keep their sane data.
    """
    if not _isinst(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A raise can only come from a poisoned stored key (or a liar whose
        # ``__class__`` merely answers dict, which the unbound descriptor
        # refuses): the field is junk-shadowed either way.  BaseException
        # too — a shadow key whose ``__eq__`` raises a BaseException subclass
        # used to sail past the old ``except Exception`` and 500 all three
        # routes.
        return default


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb.

    Fails closed to False: a bomb row is junk, not a live job, so treating
    it as "running" would wedge the single-runner mutex forever.  A
    ``__bool__`` bomb raising a BaseException subclass (a leftover ``running``
    value in a ``_jobs`` row) used to escape the old ``except Exception``
    and 500 GET /api/maintenance through job_state.
    """
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _str_text(value):
    """Exact text of *really-str* storage, or ``None`` for an impostor.

    ``str.__str__`` is a descriptor bound to the real str layout: any real
    str (or subclass — even one riding a ``__str__``/``encode`` bomb)
    answers its character data without dispatching the override, while a
    *lying* ``__class__`` that only claims str rejects the operand.  The
    old dispatching path handed such an impostor to the encode scrub and
    wiped honest non-str storage — a genuine int id claiming str — to
    ``""`` at the wrong rank; ``None`` here lets the caller fall through to
    the arm the real storage matches.  The encode-replace pass scrubs lone
    surrogates exactly as before, and only genuine control flow keeps
    propagating.
    """
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _decode_or_none(value):
    """Both bases, real layout first-come — or ``None`` for a total liar.

    The maint14 seam ``_decode_bytes``'s plain-``""`` contract cannot
    express (the notify13 ``_decode_bytes_or_none`` convention): ``None``
    distinguishes "real type is neither base" from a decode that
    legitimately answered ``""``, so the callers below fall through to the
    arm the *real* storage matches — a genuine str name claiming bytes
    keeps its text — instead of wiping honest data at the wrong rank.
    """
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    return None


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500.

    Both bases, real layout first-come (the modules12/nas13 rule): the old
    pick chose the base off the *claimed* ``__class__``, so a genuine
    ``bytearray`` whose ``__class__`` lied ``bytes`` was handed to
    ``bytes.decode``, refused by the descriptor, and its perfectly decodable
    content degraded to ``""`` — a task name vanished from the listing and a
    log line went blank at the wrong rank.  A total liar (real type is
    neither base) still degrades to ``""``, which used to ride out of
    _jsonable's bytes arm and 500 GET /api/maintenance.
    """
    decoded = _decode_or_none(value)
    if decoded is not None:
        return decoded
    # A total liar of the byte layouts: recover genuine str storage
    # (jobs13/jobs14 — a str name claiming bytes used to wipe to "").
    text = _str_text(value)
    return text if text is not None else ""


#: CPython's angle-repr shape (``<X object at 0x7f...>`` and the function /
#: bound-method variants) — a raw heap address, never Maintenance data.
#: Applied to the *coercion* arms only: real str storage is data (a job's
#: own log line quoting a Python repr serves verbatim).
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500.

    The scrub itself goes through the *unbound* base methods
    (``str.__str__`` / ``str.encode``, the audit._utf8_text convention):
    ``str()`` may hand back a subclass instance (it only checks the type,
    it does not copy) when ``__str__`` returns ``self``, so a leftover
    str-subclass whose ``encode`` raised used to blow this scrub from
    outside every net and 500 GET /api/maintenance and the log route.  The
    unbound calls also guarantee an *exact* ``str`` return, so callers' own
    ``.strip()`` / ``.replace()`` / truth tests cannot hit a subclass
    override either.

    maint14: a *lying* ``__class__`` claim no longer wipes honest storage
    at the wrong rank — a rejected bytes/str claim falls through to the arm
    the real layout matches (a genuine str claiming bytes keeps its text, a
    genuine int claiming str coerces to its number).  And the free-text arm
    no longer runs the dispatching ``str()`` on a type that never overrode
    ``__str__``/``__repr__``: the answer there is the default
    ``object.__repr__`` — ``<X object at 0x7f...>``, a raw heap address —
    which a junk ``rc`` / ``desc`` / ``started`` cell used to carry
    verbatim into the JSON body of the list and log routes.  The slot probe
    reads the real ``type(value)`` (a flickering ``__class__`` property
    cannot swap it) and the address belt drops a rendered heap address the
    probe cannot see (a custom ``__repr__`` embedding one).
    """
    if _isinst(value, (bytes, bytearray)):
        decoded = _decode_or_none(value)
        if decoded is not None:
            return decoded
        # A lying-bytes claim: real str storage recovers on the arm below;
        # everything else falls to the coercion arm's own probes.
    if _isinst(value, str):
        text = _str_text(value)
        if text is not None:
            return text
        # A lying-str claim refused the unbound read: coerce off whatever
        # the real storage renders instead of the old "" wipe.
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
        # A ``__str__`` bomb raising a BaseException subclass used to
        # sail past the ``except Exception`` here and 500 the list and
        # log routes from outside every net.
        return ""
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _key_text(k):
    """One mapping key as text, or ``None`` to drop just its entry.

    ``_jsonable``'s old key path ran bare ``str(k)`` on any non-str/bytes
    key, and for a type that never overrode ``__str__``/``__repr__`` the
    answer is the default ``object.__repr__`` — ``<X object at 0x7f...>``,
    a raw heap address — which a junk key in a nested ``_jobs``-row cell
    carried verbatim as a JSON *key* on the list and log routes (the
    assistant14 ``_key_text`` rule).  Same slot probe + address belt as
    ``_utf8_text``'s coercion arm; real str/bytes key storage — behind a
    lying ``__class__`` too — keeps its text verbatim, and a lying-str
    claim with no text storage no longer files its value under a
    fabricated ``""`` key.
    """
    if _isinst(k, (bytes, bytearray)):
        decoded = _decode_or_none(k)
        if decoded is not None:
            return decoded
        # A lying-bytes claim: real str storage recovers just below.
    if _isinst(k, str):
        text = _str_text(k)
        if text is not None:
            return text
        # A lying-str claim: coerce off whatever the real storage renders.
    try:
        cls = type(k)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return None
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    try:
        text = str(k)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A raising ``__str__`` key keeps dropping its entry, like before.
        return None
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    return None if _ADDR_REPR_RE.search(text) else text


def _error_text(exc) -> str:
    """``!! error:`` detail that cannot carry a heap address into a log tail.

    An exception's ``str()`` renders its *message objects*, so a leftover
    Popen stub / env seam raising with a junk arg answered the default
    ``object.__repr__`` — ``<X object at 0x7f...>``, a raw heap address —
    which the job log carried verbatim onto GET /api/maintenance/{tid}/log
    (real str storage is data to ``_log_lines``, so the walk scrub never
    saw it; the belt belongs at the seam where the exception is coerced).
    ``_utf8_text`` scrubs the address shape to ``""``; the type name keeps
    the diagnosis a failure line exists to give.
    """
    text = _utf8_text(exc)
    if text:
        return text
    try:
        return type(exc).__name__
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return "error"


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    YAML ``name: .inf`` / ``desc: .nan`` were already dropped; ``!!binary``
    names, ``!!set`` descriptions, and inf ``rc`` in a live job row still
    leaked into GET /api/maintenance. A leftover ``\\ud800`` in a task name
    still 500'd the same encoder (``ensure_ascii=False`` then UTF-8).
    A >4300-digit ``rc`` in a junk job row still passed through untouched:
    CPython's int->str digit limit then ValueError'd ``json.dumps`` itself.

    maint14 (the modules14/assistant14/bookmarks14 shape): ``isinstance``
    consults ``value.__class__`` only after the real-MRO check misses, so a
    lying ``__class__`` steered a leftover into the arm of its *claim*, the
    unbound descriptor there rejected the real layout, and an early return
    threw honest renderable storage away at the wrong rank — a genuine str
    desc claiming int wiped to ``None``, a genuine float claiming int
    dropped, a genuine bytes cell claiming str went blank.  The rejected
    arms now fall through to the arm the *real* storage matches, probed via
    ``_real`` so the lie cannot steer the walk twice; a total impostor — a
    claim with no usable layout underneath — keeps its established
    ``None``/``""`` drop.  The dict walk also snapshots its items first (a
    nested cell mutating the mapping mid-walk used to RuntimeError the live
    view iteration, a raw 500 on all three routes), keys go through
    ``_key_text`` (a plain-object key used to serve its default
    ``object.__repr__`` — a raw heap address — as a JSON key), and the
    sequence arm iterates through the unbound bases so a real subclass's
    ``__iter__`` bomb cannot vaporise its perfectly walkable storage.
    """
    if depth > 32:
        return None
    # ``type(value) is bool``, not isinstance: a liar whose ``__class__``
    # *answers* bool passed the old gate and rode raw into json.dumps
    # (TypeError, 500); bool cannot be subclassed, so the exact check is
    # complete and the impostor falls to the int arm's unbound coercion.
    if value is None or type(value) is bool:
        return value
    if _isinst(value, int):
        num = value if type(value) is int else None
        if num is None:
            try:
                # Base coercion to an exact int: a leftover subclass
                # ``__str__`` bomb used to blow the digit-cap probe below
                # (only ValueError was caught) and 500 GET /api/maintenance
                # — the modules5 unbound convention.
                num = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                num = None
        if num is not None:
            try:
                str(num)
            except ValueError:
                # Past CPython's int->str digit cap the encoder cannot
                # render the number at all — same drop as its inf float
                # sibling.
                return None
            return num
        if not _real(value, (float, str, bytes, bytearray, dict,
                             list, tuple, set, frozenset)):
            # A total impostor claiming int/bool keeps the old None drop.
            return None
        # The descriptor refused the operand, so the claimed ``int`` was a
        # lie — but the real storage matches a later arm: fall through.
    if _isinst(value, float):
        num = value if type(value) is float else None
        if num is None:
            try:
                # Base coercion to an exact float: a leftover subclass
                # ``__eq__``/``__ne__`` bomb used to blow the NaN/inf
                # probes below and 500 GET /api/maintenance.
                num = float.__float__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                num = None
        if num is not None:
            if num != num or num in (float("inf"), float("-inf")):
                return None
            return num
        if not _real(value, (str, bytes, bytearray, dict,
                             list, tuple, set, frozenset)):
            # A total impostor claiming float keeps the old None drop.
            return None
        # Genuine text / container behind a lying-float claim falls through.
    if _isinst(value, str):
        # ``_str_text``, not the dispatching path: real str storage (any
        # subclass) keeps its scrubbed text; a lying-str claim over genuine
        # bytes / container storage falls through to the arm one rank below
        # instead of the old "" wipe.
        text = _str_text(value)
        if text is not None:
            return text
        if not _real(value, (bytes, bytearray, dict,
                             list, tuple, set, frozenset)):
            # A total impostor claiming str keeps the established "" drop
            # (the coercion arm's slot probe + address belt: its default
            # repr — a heap address — must never render).
            return _utf8_text(value)
    if _isinst(value, (bytes, bytearray)):
        # Unbound base decode: a leftover bytes-subclass ``decode`` bomb
        # (a poisoned task name — or a bytes mapping *key*, which reaches
        # _key_text below) used to 500 the encoder walk.
        decoded = _decode_or_none(value)
        if decoded is not None:
            return decoded
        if not _real(value, (dict, list, tuple, set, frozenset)):
            # A total impostor claiming bytes keeps the established "" drop
            # (the maint9 nested-liar pin).
            return ""
        # Genuine mapping / sequence behind a lying-bytes claim falls
        # through to the arm that reads its real storage.
    if _isinst(value, dict):
        plain = value if type(value) is dict else None
        if plain is None:
            # dict() copies through the C-level storage, ignoring overridden
            # items()/keys()/__iter__ — a leftover subclass method bomb
            # cannot fire (same guard as metrics/sensors _jsonable).
            try:
                plain = dict(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                plain = None
        if plain is not None:
            # Materialized (``list(...)``), not the live view: a nested
            # cell whose guarded ``isoformat`` hook mutates this mapping
            # mid-walk used to RuntimeError the live ``.items()`` iteration
            # — outside every net — and 500 GET /api/maintenance through
            # job_state's merge AND the run route through
            # maintenance_tasks's row laundering.  Only genuine control
            # flow keeps propagating.
            try:
                items = list(dict.items(plain))
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
            out = {}
            for k, v in items:
                key = _key_text(k)
                if key is None:
                    # A key that cannot render (raising ``__str__``, a
                    # total lying impostor, a default-repr heap address)
                    # drops just this entry, keeps the rest of the mapping.
                    continue
                out[key] = _jsonable(v, depth + 1)
            return out
        if not _real(value, (list, tuple, set, frozenset)):
            # A total impostor claiming dict keeps the old None drop.
            return None
        # Genuine sequence storage behind a lying-dict ``__class__`` falls
        # through: its elements render below instead of vanishing whole.
    if _isinst(value, (list, tuple, set, frozenset)):
        # Unbound base iteration, real layout first-come (the jobs13/nas13
        # decode rule at sequence rank): the bound ``list(value)``
        # dispatched a real subclass's overridden ``__iter__``, so an
        # iter-bomb whose C-level storage was perfectly walkable — a
        # leftover ``rc`` list in a live ``_jobs`` row — vaporised to None
        # even though the raise was absorbed.  Materialized inside the try:
        # an element whose hook mutates the container mid-walk cannot blow
        # the comprehension below.  A total impostor (every base descriptor
        # refuses it) keeps the old None drop; only genuine control flow
        # keeps propagating.
        for base in (list, tuple, set, frozenset):
            try:
                items = list(base.__iter__(value))
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
            return [_jsonable(v, depth + 1) for v in items]
        return None
    try:
        iso = getattr(value, "isoformat", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Property bomb / __getattr__ raising something that is not
        # AttributeError escapes getattr's default — including one raising
        # a BaseException subclass past the old ``except Exception``.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/maintenance.
            return _jsonable(iso(), depth + 1)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    try:
        return _utf8_text(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
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
    if _isinst(raw, str):
        # _str_text returns an exact str for real str storage, so a bombing
        # subclass cannot reach the bound calls below.  A *lying* claim
        # (real type is no str at all) answers None and falls through: a
        # genuine int id claiming str used to wipe to "" right here and
        # vanish its task from the listing at the wrong rank; the numeric
        # arm below now recovers it, while total junk keeps dropping.
        text = _str_text(raw)
        if text is not None:
            return text.replace("\r\n", "\n").replace("\n", " ").strip()
    if type(raw) is bool or not _isinst(raw, int):
        return ""
    if type(raw) is not int:
        try:
            # Base coercion first: an int-subclass id whose ``__str__``
            # raised anything but the digit-cap ValueError used to 500
            # GET /api/maintenance for every task.
            raw = int.__index__(raw)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    try:
        return str(raw)
    except ValueError:
        return ""


def maintenance_tasks():
    out = {}
    # Guarded snapshot + unbound ``dict.get`` (the config.settings_section
    # convention): a leftover cfg() root that is a dict *subclass* with a
    # bombing ``.get`` — or a snapshot provider that raises outright — used
    # to 500 GET /api/maintenance AND POST /api/maintenance/{tid}/run (which
    # walks this list before matching the id), while the log route stayed up
    # over the very same poisoned state.  The unbound builtin reads the
    # C-level storage underneath the override.
    try:
        data = cfg()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A snapshot provider raising a BaseException subclass (the nas13
        # watchdog shape) used to sail past the old ``except Exception``
        # and 500 GET /api/maintenance and the run route's task walk.
        data = None
    if _isinst(data, dict):
        try:
            raw = dict.get(data, "maintenance")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # The unbound builtin is a descriptor bound to the real dict
            # layout: a liar whose ``__class__`` merely *answers* dict (the
            # modules9 impostor class — real type is no dict at all) passes
            # _isinst above and then TypeErrors right here, which used to
            # 500 GET /api/maintenance AND POST /api/maintenance/{tid}/run
            # from outside every net.  A raise means "not really a dict":
            # the impostor root degrades to the empty listing.
            raw = None
    else:
        raw = None
    if _isinst(raw, list):
        # Unbound base iteration, real layout first-come (the maint14
        # recovery of the jobs13/nas13 rule at sequence rank): a leftover
        # list-subclass whose __iter__ raises used to 500
        # GET /api/maintenance — one raising a BaseException subclass kept
        # doing so past the old ``except Exception`` — and the guarded
        # bound ``list()`` that sealed it still dispatched the override,
        # vaporising perfectly walkable real rows to the empty listing.
        # ``list.__iter__`` / ``tuple.__iter__`` read the C-level storage
        # underneath the bomb; a total impostor claiming list (every
        # descriptor refuses it) keeps degrading to the empty listing, and
        # only genuine control flow keeps propagating.
        rows = None
        for base in (list, tuple):
            try:
                rows = list(base.__iter__(raw))
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
            break
        if rows is None:
            rows = []
    else:
        rows = []
    for t in rows:
        # _plain_dict, not a bare isinstance: a leftover dict-subclass row
        # whose .get() raised used to 500 the list route one line later.
        row = _plain_dict(t)
        if row is None:
            continue
        # _mapping_get, not row.get: a leftover hash-shadowing key whose
        # ``__eq__`` bombs used to 500 the list route AND the run route
        # (which walks this listing) straight out of the plain-dict probe.
        tid = _task_id(_mapping_get(row, "id"))
        if not tid:
            continue
        cleaned = _jsonable(row)
        if _isinst(cleaned, dict):
            # The id is written onto the *cleaned* copy, whose keys are all
            # laundered exact strs — assigning through the poisoned source
            # row used to dispatch a shadowing bomb key's ``__eq__`` on the
            # insert probe.  tid is already scrubbed, so this key equals
            # cleaned["id"] — the id the list serves is the id the run/log
            # routes can find.
            cleaned["id"] = tid
            out[tid] = cleaned
    return out


def lookup_maintenance_task(tid):
    """One configured task for POST /api/maintenance/{tid}/run.  Never raises.

    The run route used to walk ``maintenance_tasks().get(tid)`` and then
    ``if not task`` — a leftover dict-*subclass* listing whose bound
    ``.get`` bombs (or a hash-shadowing key on the returned table) 500'd
    every Run, and a leftover value whose ``__bool__`` bombs detonated the
    emptiness probe the same way.  ``_mapping_get`` reads through the
    unbound builtin; ``_plain_dict`` copies C-level storage so a subclass
    row cannot fire on the caller; a raise or a non-mapping degrades to
    None (unknown task), and only genuine control flow keeps propagating.
    """
    if not _isinst(tid, str):
        return None
    try:
        tasks = maintenance_tasks()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    row = _plain_dict(_mapping_get(tasks, tid))
    return row if row else None


def _jobs_row(tid: str):
    """``_jobs.get(tid)`` that survives a leftover bomb *key* — or a leftover
    bomb *table*.

    A plain ``dict.get`` still compares the probe against every stored key
    whose hash collides, and that comparison dispatches into the stored
    key's own ``__eq__`` — so a leftover str-*subclass* key with a bombing
    ``__eq__`` (same text as a configured id, hence the same hash) used to
    raise straight out of ``job_state`` / ``get_job`` and 500 all three
    Maintenance routes.  On a poisoned lookup, fall back to a scan that
    compares through the unbound base (``str.__eq__`` reads the C-level
    character storage, so no override can fire).

    The lookup and the rescue scan both go through the *unbound* dict
    builtins: a leftover ``_jobs`` table that is itself a dict-*subclass*
    with a bombing ``.get`` used to detonate the old bound call, and its
    bombing ``.items()`` then blew the rescue scan — the scan existed to
    save exactly these routes and 500'd them instead.  A liar table whose
    ``__class__`` merely *answers* dict (no real dict at all) makes the
    unbound descriptors refuse with TypeError; a raise there means "no
    usable table", and the row degrades to None (the not-run-yet shape).
    """
    try:
        return dict.get(_jobs, tid)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A stored bomb key whose ``__eq__`` raises a BaseException subclass
        # used to escape the old ``except Exception`` and 500 the listing
        # before the rescue scan below ever ran.
        pass
    try:
        items = list(dict.items(_jobs))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Not really a dict (the modules9 impostor class): there is no
        # C-level storage to read, so there is no row to find.
        return None
    for k, v in items:
        if not _isinst(k, str):
            continue
        try:
            same = str.__eq__(k, tid)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A liar whose ``__class__`` *answers* str (the modules9
            # impostor class — real type is no str at all) passes the
            # _isinst gate above, and the unbound descriptor then
            # refuses it with TypeError — out of the rescue scan
            # itself, which used to 500 the list and log routes the
            # scan exists to save.  A raise means "not really a str":
            # the impostor key is junk and cannot be the probed tid.
            continue
        if same is True:
            return v
    return None


def job_state(tid):
    empty = {"running": False, "rc": None, "finished": None}
    if not _isinst(tid, str):
        return empty
    # _plain_dict + _truthy: a leftover dict-subclass row (or a __bool__-bomb
    # ``running`` value) used to 500 GET /api/maintenance for every task.
    j = _plain_dict(_jobs_row(tid))
    if j is None:
        return empty
    # _mapping_get: the plain-dict copy keeps a leftover hash-shadowing bomb
    # key, whose ``__eq__`` used to detonate these probes and 500 the list
    # route; only the shadowed field degrades.
    cleaned = _jsonable({
        "running": _truthy(_mapping_get(j, "running")),
        "rc": _mapping_get(j, "rc"),
        "finished": _mapping_get(j, "finished"),
    })
    return cleaned if _isinst(cleaned, dict) else empty


def get_job(tid):
    if not _isinst(tid, str):
        return None
    # The plain-dict copy also neutralises a subclass .get() bomb for the
    # only caller (job_log); rows this module writes are already plain.
    return _plain_dict(_jobs_row(tid))


def _log_lines(raw) -> list[str]:
    """String lines from a leftover job-row ``log`` field.  Never raises.

    Only *exact* strs come back: ``job_log`` joins the result with
    ``str.join``, and a liar whose ``__class__`` answers str (not a real
    str at all) used to TypeError that join outside every net.

    maint14: the materialiser reads through the unbound bases (real layout
    first-come, the jobs13/nas13 decode rule at sequence rank) — the bound
    ``list(raw)`` dispatched a real subclass's overridden ``__iter__``, so
    an iter-bomb log whose C-level lines were perfectly walkable showed
    "(waiting for output…)" over a finished job's real output; and a
    genuine list whose ``__class__`` lied str used to wipe every honest
    line to ``""`` in the old str arm.
    """
    if _isinst(raw, str):
        # Laundered before the truth test: a str-subclass ``__bool__``/
        # ``__len__`` bomb used to blow ``if raw`` right here.  A lying-str
        # claim answers None and falls through to the arm the real storage
        # matches.
        text = _str_text(raw)
        if text is not None:
            return [text] if text else []
    if not _isinst(raw, (list, tuple)) and not _real(raw, (list, tuple)):
        return []
    items = None
    for base in (list, tuple):
        try:
            # Unbound: a leftover list-subclass whose __iter__ raises used
            # to 500 the log route past the isinstance gate — and, once
            # guarded, still vaporised its perfectly walkable real lines.
            items = list(base.__iter__(raw))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        break
    if items is None:
        return []
    out: list[str] = []
    for item in items:
        if _isinst(item, str):
            # _str_text launders a str-subclass line to an exact str: a
            # leftover whose bound methods bomb cannot reach str.join or
            # the encoder downstream. Empty laundered junk is dropped, and
            # a lying-str claim over real bytes storage decodes below.
            text = _str_text(item)
            if text:
                out.append(text)
            if text is not None:
                continue
        if _isinst(item, (bytes, bytearray)):
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
    if not _isinst(tid, str):
        return missing
    j = get_job(tid)
    if j is None:
        return missing
    # _mapping_get throughout: a leftover hash-shadowing bomb key in the row
    # used to 500 this route from any of the five field probes.
    text = "\n".join(_log_lines(_mapping_get(j, "log")))
    cleaned = _jsonable({
        "running": _truthy(_mapping_get(j, "running")),
        "rc": _mapping_get(j, "rc"),
        "started": _mapping_get(j, "started"),
        "finished": _mapping_get(j, "finished"),
        "log": text or "(waiting for output…)",
    })
    return cleaned if _isinst(cleaned, dict) else missing


def maintenance_view() -> list:
    """Fully-laundered list rows for GET /api/maintenance.  Never raises.

    maint11 laundered what :func:`maintenance_tasks` *returns*, but the list
    route re-derived the row it actually *emits* with bare reads on that
    output — ``t["id"]``, ``t.get("name") or t["id"]``, ``t.get("desc", "")``,
    ``bool(t.get("confirm"))`` and ``**job_state(...)`` — one step outside
    every sanitizer this module carries.  A row reaching that shaping with a
    ``__bool__``-bomb ``confirm`` value, or a hash-shadowing bomb key riding
    ``id`` / ``name`` / ``confirm`` (same text, ``__eq__`` raising), detonated
    the route's own ``bool(...)`` / ``.get(...)`` / ``[...]`` probes and 500'd
    GET /api/maintenance from the surface the SPA reads — the exact
    ``_mapping_get`` / ``_truthy`` seam maint11 sealed *inside*
    ``maintenance_tasks``, left bare at the emitted-view rank.

    Owning the shape here keeps the union guards in one place: ``_plain_dict``
    absorbs a subclass row, ``_mapping_get`` degrades a shadowed field to its
    default, ``_truthy`` fails a ``__bool__``-bomb closed, and ``_jsonable``
    launders the whole entry before it reaches Starlette's encoder.  A row
    that cannot answer anything but its id still lists under that id.

    maint13: every guard along this pipe stopped at ``except Exception``, so
    a leftover whose hook raises a *BaseException* subclass (the
    nas13/modules12 watchdog shape) sailed past all of them at once — a
    ``__class__`` bomb blew ``_isinst`` (the gate every arm stands on), an
    ``__eq__`` bomb blew ``_mapping_get`` / ``_jobs_row``, ``__bool__`` blew
    ``_truthy`` under job_state's merge, ``__str__`` / ``__iter__`` blew
    ``_utf8_text`` / ``_jsonable`` / the row materialisers, and a raising
    cfg() blew ``maintenance_tasks`` — each a raw 500 on GET /api/maintenance.
    Every guard now re-raises genuine control flow (KeyboardInterrupt,
    SystemExit) and launders everything else BaseException-shaped exactly
    like its Exception twin.
    """
    out: list = []
    try:
        tasks = maintenance_tasks()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return out
    try:
        items = list(dict.items(tasks)) if _isinst(tasks, dict) else []
    except _CONTROL_FLOW:
        raise
    except BaseException:
        items = []
    for tid, task in items:
        if not _isinst(tid, str):
            continue
        row = _plain_dict(task)
        if row is None:
            row = {}
        # ``name or id`` through the fail-closed truthy guard: a leftover
        # ``name`` whose ``__bool__`` bombs used to blow the route's ``or``.
        name = _mapping_get(row, "name")
        if not _truthy(name):
            name = tid
        entry = {
            "id": tid,
            "name": name,
            "desc": _mapping_get(row, "desc", ""),
            # ``bool(...)`` at the route dispatched a leftover ``confirm``'s
            # ``__bool__`` bomb; ``_truthy`` fails it closed instead.
            "confirm": _truthy(_mapping_get(row, "confirm")),
        }
        state = job_state(tid)
        if _isinst(state, dict):
            for field in ("running", "rc", "finished"):
                entry[field] = _mapping_get(state, field)
        cleaned = _jsonable(entry)
        out.append(cleaned if _isinst(cleaned, dict) else {"id": tid})
    return out


def _jobs_values() -> list:
    """Snapshot of the table's rows through the unbound builtin.

    ``_jobs.values()`` dispatched into a leftover dict-subclass table's
    bombing override — and a liar table whose ``__class__`` answers dict has
    no values at all — which used to 500 POST /api/maintenance/{tid}/run's
    single-runner scan for every task.  No usable table means no live rows.
    """
    try:
        return list(dict.values(_jobs))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []


def _store_job_row(tid: str, row: dict) -> None:
    """Insert *row* under the exact-str *tid*; never raises.

    Callers hold ``_jobs_lock``.  The plain insert compares tid against any
    stored key whose hash collides, dispatching into that key's ``__eq__`` —
    so a leftover subclass bomb key with the same text used to 500
    POST /api/maintenance/{tid}/run.  The insert goes through the unbound
    ``dict.__setitem__`` (a subclass table's overridden setitem cannot
    fire), and on a raise the table is rebuilt with laundered exact-str
    keys: rows this module writes already are, so a subclass key is a
    leftover by definition and its laundered twin is simply overwritten by
    the fresh row.  A liar table whose ``__class__`` answers dict has no
    C-level storage to rebuild from and is replaced outright.
    """
    global _jobs
    try:
        dict.__setitem__(_jobs, tid, row)
        return
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        items = list(dict.items(_jobs))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        items = []
    table: dict = {}
    for k, v in items:
        key = _utf8_text(k)
        if key:
            table[key] = v
    table[tid] = row
    _jobs = table


def _row_running(j) -> bool:
    """Whether a (possibly junk) ``_jobs`` row counts as a live job.

    ``isinstance(j, dict) and j.get("running")`` let a leftover dict-subclass
    row raise from ``.get()`` — or a ``__bool__``-bomb value raise inside
    ``any()`` — and 500 POST /api/maintenance/{tid}/run for every task.
    ``_mapping_get``, not ``row.get``: a hash-shadowing bomb *key* in an
    otherwise-plain row took the same route down through the copy.
    """
    row = _plain_dict(j)
    if row is None:
        return False
    return _truthy(_mapping_get(row, "running"))


def start_job(task):
    task = _plain_dict(task)
    # _mapping_get: a leftover hash-shadowing bomb key beside "id" (tools_svc
    # hands start_job its own dicts) used to detonate this probe straight
    # into the calling route.
    tid = _mapping_get(task, "id")
    # _isinst: a leftover id whose ``__class__`` is a raising property
    # (tools_svc hands start_job its own dicts) used to detonate this gate
    # straight into the calling route.
    if not _isinst(tid, str):
        return None
    # Exact-str copy before the emptiness probe and the ``_jobs`` insert:
    # a leftover str-*subclass* id (tools_svc hands start_job its own
    # dicts) whose ``__bool__`` / ``__hash__`` raised used to blow ``not
    # tid`` or the mapping insert straight into the calling route.
    tid = _utf8_text(tid)
    if not tid:
        return None
    row = {"running": True, "rc": None, "log": [],
           "started": strftime_now("%H:%M:%S"), "finished": None}
    with _jobs_lock:
        # _jobs_values / _store_job_row, not bound calls: a leftover table
        # that is itself a dict-subclass (or a ``__class__`` liar) used to
        # 500 this route from its own ``.values()`` / insert overrides.
        if any(_row_running(j) for j in _jobs_values()):
            raise api_error("jobs.already_running")
        _store_job_row(tid, row)

    def run():
        # The captured row, not a ``_jobs[tid]`` re-lookup: a leftover bomb
        # key sharing tid's hash used to blow the lookup inside the job
        # thread — before the try block below — leaving the row parked
        # "running" forever and the single-runner mutex wedged.
        j = row
        try:
            env = dict(os.environ)
            env.update(maintenance_env())
            # _mapping_get: a shadowing bomb key beside "timeout"/"command"
            # is caught by the except below either way, but degrading field-
            # level keeps the "!! invalid command" diagnosis instead of an
            # opaque "!! error" for the whole job.
            timeout = _clamp_timeout(_mapping_get(task, "timeout"))
            command = _str_text(_mapping_get(task, "command")) or ""
            if not command.strip():
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
        except _CONTROL_FLOW:
            raise
        except BaseException as e:
            # Same silent loss one layer up: a failure before run_watchdog
            # (a poisoned maintenance_env read, a junk row) left rc -1 with
            # no explanation at all.  BaseException too: a bomb riding the
            # env/field seams used to kill the job thread past the old
            # ``except Exception`` with the log empty.
            try:
                j["log"].append(f"!! error: {_error_text(e)}")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                pass
            j["rc"] = -1
        finally:
            j["running"] = False
            j["finished"] = strftime_now("%H:%M:%S")
            invalidate_status()
    threading.Thread(target=run, daemon=True).start()
