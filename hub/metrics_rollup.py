"""Tiered long-term metrics history: 5-minute and 1-hour rollups.

The raw layer (hub/metrics.py, data/metrics.jsonl) keeps ~48-72h of 90s
samples.  This module derives two aggregate layers from it so the dashboard
can chart a year of history without the raw file growing:

    data/metrics-5m.jsonl   5-minute windows, retained ~30 days  (~8640 rows)
    data/metrics-1h.jsonl   1-hour windows,   retained ~400 days (~9600 rows)

Row shape is isomorphic with the raw rows: the same field name carries the
window *average*, and every numeric field additionally gets a ``<field>_max``
peak.  Peaks matter for gauges (CPU / memory pressure / disk %): a 30-second
spike would otherwise be averaged away in a 1-hour window.  ``t`` is the
window *start*, wall-clock aligned (t % 300 == 0 for 5m rows, t % 3600 == 0
for 1h rows, epoch/UTC alignment), and ``n`` counts the raw samples behind
the row.

Semantics that are deliberate (and pinned by tests/test_metrics_rollup.py):

* Rollup work rides on the existing sampler thread (metrics._loop calls
  maybe_rollup() each tick).  No thread of its own: each tick pays only an
  integer comparison unless a wall-clock window boundary has been crossed.
* Sampling holes (machine asleep, panel down) stay holes.  A window with no
  source samples produces *no* row -- nothing is interpolated.
* Watermarks (exclusive end of the last aggregated window, per tier) are
  persisted to data/metrics-rollup-state.json so a panel restart neither
  re-aggregates nor skips a segment.  Recovery also consults the last row of
  each aggregate file, so a crash between "append rows" and "save state"
  cannot double-aggregate a window.
* A clock step backwards (NTP correction) never moves a watermark back: when
  now's current window starts before the watermark the pass is a no-op, and
  raw rows stamped earlier than the watermark are ignored rather than
  re-counted.
* Aggregation reads only the source file's tail: a backwards chunked read
  that grows until it demonstrably covers the watermark.  Byte offsets are
  never remembered across passes because the raw file is periodically
  rewritten in place by its ring-buffer trim.
* Aggregate files are trimmed with the same pattern as metrics.py: an
  in-memory time gate (_TRIM_INTERVAL) so the check itself is rare, a cheap
  first-line age probe so nothing is read in full unless needed, a slack
  window so the rewrite happens ~daily/~weekly rather than on every pass,
  and an atomic tmp+rename rewrite.
"""
from __future__ import annotations

import errno
import json
import os
import stat
import threading
import time

from hub import secure_io
from hub.paths import DATA_DIR
from hub.util import read_text_capped, safe_json_loads

FILE_5M = DATA_DIR / "metrics-5m.jsonl"
FILE_1H = DATA_DIR / "metrics-1h.jsonl"
STATE_FILE = DATA_DIR / "metrics-rollup-state.json"
#: Leftover multi-MB metrics-rollup-state.json used to OOM GET /api/metrics?range=.
_STATE_CAP = 256 * 1024
#: Leftover multi-GB metrics-5m.jsonl used to OOM GET /api/metrics?range= via
#: unbounded ``_rows_since`` (chunk *= 4 until the whole file was in RAM).
_ROWS_CAP = 16 * 1024 * 1024

WIN_5M = 300
WIN_1H = 3600
RETAIN_5M = 30 * 86400   # ~8640 rows at one per 5 minutes
RETAIN_1H = 400 * 86400  # ~9600 rows at one per hour

# Spans this far past retention accumulate before a trim rewrite is worth the
# IO: ~1 day of extra 5m rows (288) / ~1 week of extra 1h rows (168).  Same
# idea as metrics._TRIM_SLACK, expressed in time because these layers retain
# by age, not by row count.
_TRIM_SLACK = {"5m": 86400, "1h": 7 * 86400}
_RETAIN = {"5m": RETAIN_5M, "1h": RETAIN_1H}
# Check for trimming at most hourly per tier (mirrors metrics._TRIM_INTERVAL).
# The check is a first-line read, the rewrite inside it is further gated by
# the slack above.
_TRIM_INTERVAL = 3600.0
_last_trim = {"5m": 0.0, "1h": 0.0}

# Exclusive end of the last aggregated window per tier == start of the next
# window to aggregate.  0 means "never rolled up" and is clamped to the
# oldest available source row on the first pass.
_state: dict[str, int] = {"w5": 0, "w1h": 0}
_state_loaded = False
_lock = threading.Lock()

# Query-side caps.  1500 points is plenty for a dashboard-width chart and
# keeps a 1-year response ~300KB instead of several MB.
MAX_QUERY_POINTS = 1500
# Spans up to this long are served from the raw layer (when it reaches back
# far enough -- see _pick_tier).
RAW_QUERY_SPAN = 48 * 3600


# --------------------------------------------------------------------------
# small file helpers

def _sample_ts(raw) -> int | None:
    """Finite epoch seconds, or None.  Same rules as metrics.sample_ts."""
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return None
        try:
            raw = int(text)
        except ValueError:
            try:
                raw = float(text)
            except ValueError:
                return None
    if not isinstance(raw, (int, float)):
        return None
    # Same leftover as metrics.sample_ts: a 400-digit int is not inf, but
    # ``time.time() - since`` and ``float(n)`` OverflowError it.
    try:
        as_float = float(raw)
    except OverflowError:
        return None
    if as_float != as_float or as_float in (float("inf"), float("-inf")):
        return None
    try:
        return int(raw)
    except (OverflowError, ValueError):
        return None


def _finite_num(raw):
    """Finite int/float, or None.  Bools and inf/nan are not numbers here."""
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return None
        try:
            raw = float(text)
        except ValueError:
            return None
    if not isinstance(raw, (int, float)):
        return None
    if raw != raw or raw in (float("inf"), float("-inf")):
        return None
    try:
        return float(raw)
    except OverflowError:
        return None


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


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Infinity in a leftover rollup row was already dropped; a leftover
    ``\\ud800`` field or key still 500'd ``GET /api/metrics?range=``.
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
            # the number at all — same drop as its inf float sibling.
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
        if type(value) is not dict:
            # dict() copies through the C-level storage, ignoring overridden
            # items()/keys()/__iter__ — a leftover subclass method bomb
            # cannot fire (same guard as sensors_svc._jsonable).
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
            # used to skip the float sanitizer and 500 GET /api/metrics?range=.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _open_journal_rb(path):
    """Binary handle to a *regular* journal file.

    A leftover FIFO occupying metrics-5m.jsonl / metrics-1h.jsonl (or the raw
    journal reached through the tier probe) used to park a bare ``open()``
    until a writer appeared — hanging GET /api/metrics?range= and the rollup
    pass forever.  ``O_NONBLOCK`` makes the FIFO open return at once and the
    regular-file check turns any non-regular node into the OSError every
    caller here already handles.
    """
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(path))
    except Exception:
        os.close(fd)
        raise
    return os.fdopen(fd, "rb")


def _first_row_ts(path) -> int | None:
    """Timestamp of the first parseable row, reading only the file head."""
    try:
        with _open_journal_rb(path) as f:
            head = f.read(8192)
    except OSError:
        return None
    for ln in head.decode(errors="replace").splitlines():
        try:
            t = _sample_ts(safe_json_loads(ln).get("t"))
        except (ValueError, AttributeError, RecursionError):
            # ValueError, not just JSONDecodeError: a leftover >4300-digit
            # number raises CPython's str->int digit-cap ValueError out of
            # json.loads, which used to 500 GET /api/metrics?range= through
            # the tier probe (and abort the rollup pass).
            continue
        if t is not None:
            return t
    return None


def _last_row_ts(path) -> int | None:
    """Timestamp of the last parseable row, reading only the file tail."""
    try:
        with _open_journal_rb(path) as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 8192))
            tail = f.read()
    except OSError:
        return None
    for ln in reversed(tail.decode(errors="replace").splitlines()):
        try:
            t = _sample_ts(safe_json_loads(ln).get("t"))
        except (ValueError, AttributeError, RecursionError):
            # Same digit-cap ValueError as _first_row_ts.
            continue
        if t is not None:
            return t
    return None


def _rows_since(path, since_ts: int) -> list[dict]:
    """Rows with t >= since_ts, reading only as much of the tail as needed.

    Starts with a 64KB tail chunk and grows it geometrically until the chunk
    provably covers since_ts (its first parsed row is already older) or spans
    the whole file.  Timestamps, not byte offsets, decide coverage, so a
    ring-buffer rewrite of the source file between passes cannot corrupt the
    read.  Rows are append-ordered by the sampler; a small NTP step inside
    one chunk is harmless because every row is still filtered by ``t``.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    chunk = min(64 * 1024, _ROWS_CAP)
    while True:
        offset = max(0, size - chunk)
        try:
            with _open_journal_rb(path) as f:
                f.seek(offset)
                data = f.read()
        except OSError:
            return []
        lines = data.decode(errors="replace").splitlines()
        if offset > 0 and lines:
            lines = lines[1:]  # first line of a mid-file chunk may be partial
        rows: list[dict] = []
        covered = offset == 0
        for ln in lines:
            try:
                o = safe_json_loads(ln)
            except (ValueError, RecursionError):
                # ValueError, not just JSONDecodeError: a leftover
                # >4300-digit number raises CPython's str->int digit-cap
                # ValueError out of json.loads, which used to 500
                # GET /api/metrics?range= on that line.
                continue
            t = _sample_ts(o.get("t") if isinstance(o, dict) else None)
            if t is None:
                continue
            o = _jsonable(o) if isinstance(o, dict) else None
            if not isinstance(o, dict):
                continue
            o["t"] = t
            if t < since_ts:
                covered = True
                continue
            rows.append(o)
        if covered or offset == 0 or chunk >= _ROWS_CAP:
            return rows
        chunk = min(chunk * 4, _ROWS_CAP)


def _atomic_write(path, payload: str) -> None:
    # Predictable `{name}.{pid}.tmp` + write_text followed a planted symlink
    # and then os.replace'd it onto the live journal.
    secure_io.replace_bytes(path, payload.encode("utf-8"))


# --------------------------------------------------------------------------
# aggregation

def _round(v: float):
    """Compact on-disk numbers: 2 decimals normally, integers once the value
    is large enough (network bps) that decimals are noise."""
    if v != v or v in (float("inf"), float("-inf")):
        return 0
    if abs(v) >= 1000:
        return int(round(v))
    return round(float(v), 2)


def _aggregate_window(rows: list[dict], window_start: int) -> dict:
    """Fold *rows* into one aggregate row for the window starting at
    *window_start*.

    Works for both directions: raw rows count with weight 1 and their own
    value as the peak; aggregate rows (they carry ``n`` and ``<f>_max``)
    contribute their average weighted by ``n`` and their stored peak, so
    5m -> 1h keeps exact means instead of averaging averages.
    Fields absent (or null) in every source row are simply absent from the
    output -- a per-field hole, never a fabricated zero.
    """
    sums: dict[str, float] = {}
    weights: dict[str, float] = {}
    maxes: dict[str, float] = {}
    total_n = 0
    for row in rows:
        w = _finite_num(row.get("n", 1))
        w = int(w) if w is not None and w > 0 else 1
        total_n += w
        for key, val in row.items():
            if key in ("t", "n") or key.endswith("_max"):
                continue
            num = _finite_num(val)
            if num is None:
                continue
            sums[key] = sums.get(key, 0.0) + num * w
            weights[key] = weights.get(key, 0.0) + w
            peak = _finite_num(row.get(f"{key}_max", num))
            if peak is None:
                peak = num
            if key not in maxes or peak > maxes[key]:
                maxes[key] = peak
    out: dict = {"t": int(window_start), "n": total_n}
    for key in sums:
        out[key] = _round(sums[key] / weights[key])
        out[f"{key}_max"] = _round(maxes[key])
    return out


# --------------------------------------------------------------------------
# rollup passes

def _load_state_locked() -> None:
    global _state_loaded
    if _state_loaded:
        return
    saved: dict = {}
    try:
        loaded = safe_json_loads(read_text_capped(STATE_FILE, _STATE_CAP))
        if isinstance(loaded, dict):
            saved = loaded
    except (OSError, json.JSONDecodeError, ValueError, RecursionError):
        # RecursionError: leftover deeply-nested watermark is not ValueError.
        saved = {}
    for key, path, win in (("w5", FILE_5M, WIN_5M), ("w1h", FILE_1H, WIN_1H)):
        from_state = saved.get(key)
        from_state = _sample_ts(from_state) or 0
        # A row for window t means everything through t+win is aggregated.
        # Taking the max of both sources makes the watermark survive a lost
        # state file (no re-aggregation) and a state file written just before
        # a crash that lost the append (no skipped window: state is only
        # saved *after* a successful append).
        last = _last_row_ts(path)
        from_file = last + win if last is not None else 0
        _state[key] = max(_state[key], from_state, from_file)
    _state_loaded = True


def _save_state_locked() -> None:
    try:
        STATE_FILE.parent.mkdir(exist_ok=True)
        _atomic_write(STATE_FILE, json.dumps(_jsonable(_state), allow_nan=False))
    except (OSError, ValueError, TypeError, RecursionError):
        # Non-fatal: the last-row recovery in _load_state_locked keeps a stale
        # state file from causing duplicates.
        # RecursionError: leftover nested rollup state after _jsonable is not ValueError.
        pass


def _rollup_tier_locked(src_path, dst_path, win: int, key: str, target: int) -> int:
    """Aggregate every complete *win*-second window in [_state[key], target).

    Returns how many windows produced a row.  The watermark advances to
    *target* even when no rows were produced (those windows are holes), but
    only after the destination append succeeded, so an IO failure is retried
    on the next boundary instead of losing the segment.
    """
    start = _state[key]
    oldest = _first_row_ts(src_path)
    if oldest is None:
        # No source data at all: everything before target is a hole.
        _state[key] = max(start, target)
        return 0
    # Never aggregate below what the source can still prove; windows before
    # its oldest row are unrecoverable holes (first run, or source trimmed
    # past the watermark after long downtime).
    start = max(start, (oldest // win) * win)
    if start >= target:
        _state[key] = max(_state[key], target)
        return 0
    buckets: dict[int, list[dict]] = {}
    for row in _rows_since(src_path, start):
        t = _sample_ts(row.get("t"))
        if t is None:
            continue
        # Upper bound excludes the still-open window; lower bound drops rows
        # stamped before the watermark (already aggregated, or re-stamped by
        # a clock step backwards -- counting them again would double them).
        if t < start or t >= target:
            continue
        buckets.setdefault((t // win) * win, []).append(row)
    if buckets:
        try:
            lines = "".join(
                json.dumps(_jsonable(_aggregate_window(rows, wt)), ensure_ascii=False, allow_nan=False) + "\n"
                for wt, rows in sorted(buckets.items())
            )
            dst_path.parent.mkdir(exist_ok=True)
            # A leftover FIFO/dir occupying the aggregate file would fail
            # this append on every pass (append_text refuses non-regular
            # nodes); drop it so the tier self-heals instead of stalling
            # its watermark forever.
            secure_io.drop_leftover_nonfile(dst_path)
            secure_io.append_text(dst_path, lines)
        except (OSError, TypeError, ValueError, RecursionError):
            # RecursionError: leftover nested aggregate after _jsonable is not
            # ValueError. Do not advance the watermark — retry next sweep.
            return 0
    _state[key] = target
    return len(buckets)


def _maybe_trim_locked(tier: str, path, now: float) -> bool:
    """Age-based trim with the metrics.py time-gate pattern.

    Hourly gate -> 8KB first-line probe -> full rewrite only once the file
    holds more than retention+slack of history.  Rewrites keep rows newer
    than the retention cutoff and are atomic (tmp + rename), so a reader
    never sees a half-written file.
    """
    if now - _last_trim[tier] < _TRIM_INTERVAL:
        return False
    _last_trim[tier] = now
    oldest = _first_row_ts(path)
    if oldest is None or oldest >= now - _RETAIN[tier] - _TRIM_SLACK[tier]:
        return False
    cutoff = now - _RETAIN[tier]
    try:
        try:
            size = os.path.getsize(path)
        except OSError:
            return False
        kept = []
        # Stream: ``read_text().splitlines()`` loaded the whole tier just to
        # drop the old prefix.  errors="replace" so a torn/binary byte does
        # not raise UnicodeDecodeError past the OSError guard and disable
        # trim forever (same failure class as metrics.py's ring buffer).
        # Leftover multi-GB jsonl: only the tail is kept (trim is dropping
        # the old prefix anyway) so the rewrite cannot OOM the sampler.
        # _open_journal_rb: a leftover FIFO used to park this open forever.
        with _open_journal_rb(path) as fh:
            if size > _ROWS_CAP:
                fh.seek(max(0, size - _ROWS_CAP))
                if fh.tell() > 0:
                    fh.readline()
            for raw in fh:
                ln = raw.decode("utf-8", "replace").rstrip("\n")
                try:
                    parsed = safe_json_loads(ln)
                except (ValueError, RecursionError):
                    # corrupt / leftover nested / >4300-digit line (json.loads
                    # digit-cap ValueError is not JSONDecodeError): dropped
                    # with the trim instead of aborting it.
                    continue
                t = _sample_ts(parsed.get("t") if isinstance(parsed, dict) else None)
                if t is not None and t >= cutoff:
                    kept.append(ln)
        _atomic_write(path, "\n".join(kept) + "\n" if kept else "")
        return True
    except OSError:
        return False


def maybe_rollup(now: float | None = None) -> dict:
    """One rollup opportunity; called from the sampler thread every tick.

    Cheap unless a wall-clock boundary was crossed: the 5m tier runs when a
    new 5-minute window has completed since the watermark, the 1h tier when a
    new hour has completed *and* the 5m tier has caught up to it (the hour is
    aggregated from 5m rows, so running ahead of them would under-count).
    Returns {"w5": n, "w1h": m} window counts, mostly for tests.
    """
    from hub import metrics  # late import: metrics imports us lazily too

    if now is None:
        now = time.time()
    else:
        # Leftover YAML ``now: .inf`` / ``!!binary`` used to raise
        # ``int(now // 300)`` and take down the first rollup pass.
        try:
            now_f = float(now)
        except (TypeError, ValueError, OverflowError):
            now_f = time.time()
        if isinstance(now, bool) or now_f != now_f or now_f in (float("inf"), float("-inf")) or abs(now_f) > 1e18:
            now_f = time.time()
        now = now_f
    done = {"w5": 0, "w1h": 0}
    with _lock:
        _load_state_locked()
        dirty = False

        cur5 = int(now // WIN_5M) * WIN_5M
        if cur5 > _state["w5"]:
            # Samples for the just-completed window may still sit in the
            # write buffer (flush cadence is up to 5 minutes); put them on
            # disk before reading the tail.  No forced trim: that stays on
            # metrics.py's own hourly gate.
            try:
                metrics.flush_pending()
            except Exception:
                pass
            try:
                done["w5"] = _rollup_tier_locked(
                    metrics.METRICS_FILE, FILE_5M, WIN_5M, "w5", cur5
                )
                dirty = True
            except OSError:
                pass
            _maybe_trim_locked("5m", FILE_5M, now)

        # Clamped to the 5m watermark: if the 5m pass failed above, the hour
        # target shrinks with it and the segment is retried later rather than
        # aggregated from incomplete 5m data.
        cur1h = min(int(now // WIN_1H), _state["w5"] // WIN_1H) * WIN_1H
        if cur1h > _state["w1h"]:
            try:
                done["w1h"] = _rollup_tier_locked(
                    FILE_5M, FILE_1H, WIN_1H, "w1h", cur1h
                )
                dirty = True
            except OSError:
                pass
            _maybe_trim_locked("1h", FILE_1H, now)

        if dirty:
            _save_state_locked()
    return done


# --------------------------------------------------------------------------
# query side (/api/metrics?range=...)

def parse_range(text: str) -> int:
    """'48h' / '30d' / '1y' -> seconds.  Raises ValueError on anything else."""
    s = str(text or "").strip().lower()
    if len(s) < 2 or not s[:-1].isdigit():
        raise ValueError(f"invalid range: {text!r}")
    n, unit = int(s[:-1]), s[-1]
    mult = {"h": 3600, "d": 86400, "w": 7 * 86400, "y": 365 * 86400}.get(unit)
    if mult is None or n <= 0:
        raise ValueError(f"invalid range: {text!r}")
    # Nothing outlives the 1h layer's retention; clamping keeps the window
    # math bounded for absurd inputs like 99y.
    return min(n * mult, RETAIN_1H)


def _covers(path, since: int) -> bool:
    oldest = _first_row_ts(path)
    return oldest is not None and oldest <= since


def _reaches_further(path_a, path_b) -> bool:
    """True when *path_a*'s history starts strictly earlier than *path_b*'s."""
    oa = _first_row_ts(path_a)
    if oa is None:
        return False
    ob = _first_row_ts(path_b)
    return ob is None or oa < ob


def _pick_tier(since: int, until: int) -> str:
    """Span decides the tier; coverage breaks the tie.

    Short spans want the raw layer's 90s resolution, but the raw layer's
    reach depends on the configured sample interval (MAX_POINTS is fixed, the
    interval is not), so when raw demonstrably does not reach back to *since*
    and the aggregate layer does, the aggregate layer wins.  Same rule one
    level down for 5m vs 1h.
    """
    from hub import metrics

    span = until - since
    if span <= RAW_QUERY_SPAN:
        if not _covers(metrics.METRICS_FILE, since) and _reaches_further(
            FILE_5M, metrics.METRICS_FILE
        ):
            return "5m"
        return "raw"
    if span <= RETAIN_5M + 86400:
        if not _covers(FILE_5M, since) and _reaches_further(FILE_1H, FILE_5M):
            return "1h"
        return "5m"
    return "1h"


def _decimate(rows: list[dict], since: int, until: int, max_points: int) -> list[dict]:
    """Re-bucket *rows* onto a coarser grid so len(result) <= max_points.

    Buckets are keyed by time, not by index: an empty bucket produces no
    output row, so sampling holes survive decimation instead of being
    bridged by their neighbours.
    """
    if len(rows) <= max_points:
        return rows
    span = max(1, until - since)
    bucket_sec = -(-span // max_points)  # ceil
    buckets: dict[int, list[dict]] = {}
    for row in rows:
        t = _sample_ts(row.get("t") if isinstance(row, dict) else None)
        if t is None:
            continue
        idx = (t - since) // bucket_sec
        buckets.setdefault(idx, []).append(row)
    return [
        _aggregate_window(group, since + idx * bucket_sec)
        for idx, group in sorted(buckets.items())
    ]


def query_range(since: int, until: int, max_points: int = MAX_QUERY_POINTS) -> dict:
    """Points for [since, until], tier picked automatically, count capped.

    Raw-tier responses below the cap pass through untouched (plain raw rows);
    anything decimated -- and every aggregate-tier row -- carries avg under
    the plain field name plus ``<field>_max`` peaks.
    """
    from hub import metrics

    since_i, until_i = _sample_ts(since), _sample_ts(until)
    if since_i is None or until_i is None:
        return {"points": [], "tier": "raw"}
    since, until = since_i, until_i
    try:
        max_points = max(1, min(int(max_points), MAX_QUERY_POINTS))
    except (TypeError, ValueError, OverflowError):
        max_points = MAX_QUERY_POINTS
    tier = _pick_tier(since, until)
    if tier == "raw":
        # history() merges the on-disk file with the not-yet-flushed buffer;
        # minutes is measured back from *now*, so stretch it to reach since.
        # Leftover inf ``time.time()`` OverflowError'd ``int(inf)`` and 500'd
        # GET /api/metrics?range=.
        now_ts = _sample_ts(time.time())
        try:
            minutes = max(1, int(((now_ts if now_ts is not None else 0) - since) // 60) + 2)
        except (TypeError, ValueError, OverflowError):
            minutes = max(1, RAW_QUERY_SPAN // 60)
        rows = [
            o for o in metrics.history(minutes)
            if _sample_ts(o.get("t")) is not None and since <= o["t"] <= until
        ]
    else:
        path = FILE_5M if tier == "5m" else FILE_1H
        rows = [
            o for o in _rows_since(path, since)
            if _sample_ts(o.get("t")) is not None and o["t"] <= until
        ]
    rows.sort(key=lambda o: _sample_ts(o.get("t")) or 0)
    return {"points": _decimate(rows, since, until, max_points), "tier": tier}
