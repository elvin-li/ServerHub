"""Read-only view of the authentication audit trail.

``hub/audit.py`` records sign-ins, failures, logouts, setup claims and password
rotations, but a log nobody can read is only half a feature: the point of
recording "who did this and when" is being able to answer that question later
without shell access to the box.

Two deliberate limits:

* **Read-only.**  There is no endpoint here to write, edit or clear the trail.
  An audit log an operator can quietly rewrite from the UI does not serve its
  purpose, and clearing it is a decision that belongs at the filesystem, not
  behind a button.

* **No new authorisation semantics.**  This router mounts under the same
  ``require_auth`` dependency as the rest of the protected API, exactly like
  ``terminal_api``'s history endpoint.  It neither grants nor refuses anything
  that was not already gated, and it does not consult roles -- wiring roles into
  route authorisation is a separate change.

Redaction is applied **again** on the way out, even though ``audit.record``
already drops secrets before anything reaches disk.  That is not redundancy:
``record`` is not the only thing that can put bytes in that file.  An operator
edit, a log from an older build, a future writer that forgets, or a
half-written line all end up in the same path, and this reader is the last
point at which a raw credential can be stopped from reaching a browser.
Filtering here costs one pass over at most a few hundred rows.
"""
from __future__ import annotations

from fastapi import APIRouter, Query

from hub import audit

router = APIRouter(tags=["audit"])

#: Ceiling on one page of history.  Large enough to scan a brute-force burst,
#: small enough that the response stays renderable.
MAX_LIMIT = 500

#: Real control flow must keep propagating; every other BaseException-shaped
#: leftover from recent()/redact() used to 500 this read-only listing.
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)


def _page_rows(limit: int) -> list:
    """Fail-close leftover lists/mappings from the trail reader.

    ``recent()`` is supposed to return a list of dicts, but this route is
    the last encoder before Starlette: a leftover mapping (``.map``/list-comp
    then walks keys), a hostile list subclass, or a redact() bomb on one
    row used to 500 the whole page.  Non-mapping rows are dropped; the
    honest siblings stay.  ``_jsonable`` after redact keeps Infinity / lone
    surrogates off the wire even when a row skipped shaping.
    """
    try:
        raw = audit.recent(limit)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []
    if not audit._isa(raw, (list, tuple)):
        return []
    try:
        seq = list(raw)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []
    out = []
    for row in seq:
        try:
            shaped = audit._jsonable(audit.redact(row))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        if audit._isa(shaped, dict):
            out.append(shaped)
    return out


@router.get("/api/audit/auth")
def auth_audit(limit: int = Query(100, ge=1, le=MAX_LIMIT)):
    """Recent authentication events, newest last.

    ``limit`` is clamped by FastAPI's validation rather than by this function, so
    an out-of-range value is a 422 instead of being silently reinterpreted.
    """
    # Re-redact on read.  See the module docstring: record() is not the only
    # writer to this file, so the reader must not assume the bytes are clean.
    entries = _page_rows(limit)
    return {
        "entries": entries,
        "count": len(entries),
        # Advertised so the UI can say "showing the last N of at most M" without
        # hardcoding the policy in JavaScript.
        "max_limit": MAX_LIMIT,
        "retained_lines": audit.MAX_LINES,
    }
