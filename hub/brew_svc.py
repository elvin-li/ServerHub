"""Homebrew services management — macOS-native module."""
from __future__ import annotations

import os

from hub import cli_args
from hub.errors import api_error
from hub.brew_cache import brew_services_list, invalidate_brew_services
from hub.status import invalidate_status
from hub.util import run_capped, sh

# One definition, in hub.paths: it tries `which brew` before the two standard
# prefixes, so a Homebrew in a custom prefix is found too. Local copies of this
# fallback drifted from it and disagreed about whether brew existed.
from hub.paths import BREW  # noqa: E402


def _isinstance(value, types) -> bool:
    """isinstance that survives a leftover raising ``__class__`` property.

    When the type check fails, CPython's isinstance consults
    ``value.__class__`` — so a leftover object whose ``__class__`` is a
    raising property blew every ``isinstance`` gate that runs outside a try:
    the snapshot gate in :func:`list_services` and the fallback-tail
    ``rc``/``out`` probes each used to 500 GET /api/brew/services.  A real
    subclass never reaches the ``__class__`` lookup (the type check answers
    first), so degrading the raise to False only reclassifies impostors.
    """
    try:
        return isinstance(value, types)
    except Exception:
        return False


def _as_text(value) -> str:
    # Unbound through the base types: a leftover bytes-subclass whose bound
    # ``.decode`` raises (or a str-subclass whose ``.encode`` does) used to
    # 500 the post-spawn tail of service_action, which runs outside its try.
    # Guarded isinstance throughout: a leftover whose ``__class__`` property
    # raises used to blow the chain itself and cost every sibling row.
    if _isinstance(value, bytes):
        text = bytes.decode(value, "utf-8", "replace")
    elif _isinstance(value, bytearray):
        text = bytearray.decode(value, "utf-8", "replace")
    elif _isinstance(value, str):
        text = value
    elif value is None:
        return ""
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
    return str.encode(text, "utf-8", "replace").decode("utf-8")


def _json_safe(value, depth: int = 0):
    """Starlette encodes with allow_nan=False; leftover NaN/bytes 500 the list.

    ``exit_code`` was the first field brew put NaN in.  ``user`` / ``file``
    still passed through, so a non-finite or bytes leftover 500'd GET
    ``/api/brew/services`` the same way.  A leftover ``\\ud800`` in ``name``
    still 500'd the UTF-8 encode.

    Base-type coercions throughout (``int.__index__``, ``float.__float__``,
    unbound ``str.encode`` / ``bytes.decode``): a leftover subclass whose
    ``__str__``/``__eq__``/``encode``/``decode`` raises used to raise out of
    this launderer instead of costing only the poisoned value — the
    docker_cli/modules ``_jsonable`` convention.

    Guarded isinstance throughout (see :func:`_isinstance`): a leftover
    field whose ``__class__`` property raises used to blow the very first
    probe here and wipe every sibling row into the text fallback.  The depth
    cap matches brew_cache._json_safe: a two-object ``isoformat`` cycle used
    to recurse until wherever RecursionError happened to land.
    """
    if depth > 16:
        return None
    if _isinstance(value, bool) or value is None:
        return value
    if _isinstance(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__`` bomb
                # used to blow the digit-cap probe below (only ValueError
                # was caught).
                value = int.__index__(value)
            except Exception:
                return None
        try:
            str(value)
        except ValueError:
            # YAML hex/octal leftovers dodge CPython's str->int digit cap, so
            # an over-cap ``exit_code`` / ``user`` arrived here intact and
            # Starlette's json.dumps ValueError'd GET /api/brew/services —
            # same drop as its inf float sibling.
            return None
        return value
    if _isinstance(value, float):
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
    if _isinstance(value, str):
        # Unbound base encode: a str-subclass ``.encode`` bomb cannot fire.
        return str.encode(value, "utf-8", "replace").decode("utf-8")
    if _isinstance(value, bytes):
        return bytes.decode(value, "utf-8", "replace")
    if _isinstance(value, bytearray):
        return bytearray.decode(value, "utf-8", "replace")
    if _isinstance(value, (list, tuple, set, frozenset)):
        return None
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # Property bomb / ``__getattr__`` raising non-AttributeError past
        # getattr's default.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/brew/services.
            stamped = iso()
        except Exception:
            return None
        if stamped is value:
            return None
        return _json_safe(stamped, depth + 1)
    return None


def _plain_rc(value):
    """Exact-type spawn rc for service_action's tail.

    The vanished-brew sentinel check and the ``ok``/``exit`` rendering must
    run *outside* the spawn try (its broad except used to swallow the coded
    503 raise), so a leftover numeric-subclass rc whose ``__eq__`` /
    ``__float__`` raises used to 500 POST /api/brew/services/{name}/action
    after the run had already finished.  Unbound base-type calls dodge the
    override; anything non-numeric degrades to None ("exit unknown").
    Guarded isinstance: a leftover rc whose ``__class__`` property raises
    used to blow the first probe here — this helper runs outside every try.
    """
    if _isinstance(value, bool):
        return int(value)
    if _isinstance(value, int):
        try:
            return int.__index__(value)
        except Exception:
            return None
    if _isinstance(value, float):
        try:
            return float.__float__(value)
        except Exception:
            return None
    return None


def _brew_env() -> dict:
    env = dict(os.environ)
    path = env.get("PATH", "")
    for p in ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"):
        if p not in path:
            path = p + ":" + path
    env["PATH"] = path
    env.setdefault("HOMEBREW_NO_AUTO_UPDATE", "1")
    env.setdefault("HOMEBREW_NO_ANALYTICS", "1")
    return env


# nginx is run only via local.onedrive-nginx (custom conf); hide idle brew formula
_HIDE_BREW = {"nginx"}


def _brew_present() -> bool:
    """``os.path.isfile`` re-raises EIO/ESTALE; that used to 500 GET /api/brew."""
    try:
        return os.path.isfile(BREW)
    except OSError:
        return False


def list_services() -> list:
    if not _brew_present():
        return []
    # Shared TTL cache: `brew services list --json` costs ~1.3s and four
    # modules ask for it while rendering one page.
    items = []
    try:
        data = brew_services_list()
    except Exception:
        data = []
    rows = []
    # Guarded isinstance: a leftover snapshot object whose ``__class__``
    # property raises used to blow this gate — it runs outside the try
    # above — and 500 GET /api/brew/services.
    if _isinstance(data, list):
        # Unbound base iteration into an exact list before the truth test:
        # ``isinstance(data, list) and data`` ran *outside* the try above, so
        # a leftover list-subclass whose ``__bool__``/``__len__`` raises
        # 500'd GET /api/brew/services at the gate, and an ``__iter__`` bomb
        # inside the loop wiped every row into the text fallback.  The
        # per-element probe is guarded too: one ``__class__``-bomb element
        # used to blow the filter and wipe every sibling row.
        try:
            rows = [s for s in list.__iter__(data) if _isinstance(s, dict)]
        except Exception:
            rows = []
    if rows:
        try:
            for s in rows:
                # Unbound dict reads, the brew_cache._json_safe convention: a
                # dict-subclass row whose ``get`` raises used to cost every
                # sibling row instead of nothing.
                name = _as_text(dict.get(s, "name")).strip()
                if not name or name in _HIDE_BREW:
                    continue
                status = _as_text(dict.get(s, "status")).lower()

                # started|stopped|error|none
                state = "ok" if status in ("started", "running") else (
                    "warn" if status in ("error",) else "down"
                )
                items.append({
                    "id": name,
                    "name": name,
                    "status": status or "unknown",
                    "state": state,
                    "user": _json_safe(dict.get(s, "user")),
                    "file": _json_safe(dict.get(s, "file")),
                    "exit_code": _json_safe(dict.get(s, "exit_code")),
                    "actions": ["restart", "stop"] if state == "ok" else ["start"],
                })
            return items
        except Exception:
            items = []
    # fallback text parse
    try:
        rc, out, err = sh([BREW, "services", "list"], timeout=20)
    except Exception:
        return items
    # This tail runs outside the try above, so a leftover numeric-subclass rc
    # whose ``__ne__`` raises used to 500 GET /api/brew/services from the
    # fallback path; _plain_rc's unbound base calls dodge the override and a
    # non-numeric rc reads as failure.
    if _plain_rc(rc) != 0:
        return []
    # Guarded: a leftover stdout whose ``__class__`` property raises used to
    # blow this probe (it runs outside the spawn try) and 500 the fallback.
    if _isinstance(out, (str, bytes, bytearray)):
        # _as_text, not bound ``.decode``/raw str: a bytes-subclass whose
        # ``decode`` raises (or a str-subclass whose ``splitlines`` does)
        # used to 500 the same fallback; the unbound base calls yield an
        # exact, surrogate-scrubbed str.
        out = _as_text(out)
    else:
        return items
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        # Fallback used to pass leftover ``\ud800`` / bytes straight through
        # and UnicodeEncodeError GET /api/brew/services.  The JSON path
        # already runs name/status/user through _as_text/_json_safe.
        name = _as_text(parts[0]).strip()
        if not name or name in _HIDE_BREW:
            continue
        status = _as_text(parts[1]).lower()
        state = "ok" if status == "started" else "down"
        items.append({
            "id": name,
            "name": name,
            "status": status or "unknown",
            "state": state,
            "user": _json_safe(parts[2] if len(parts) > 2 else None),
            "file": None,
            "actions": ["restart", "stop"] if state == "ok" else ["start"],
        })
    return items


def service_action(name: str, action: str) -> dict:
    if action not in ("start", "stop", "restart"):
        raise api_error("brew.bad_action", action=action)
    # `^[\w@.+-]+$` matched `--all`, so `brew services stop --all` stopped every
    # service on the host instead of one.  The shared guard anchors the first
    # character to an alphanumeric.
    name = cli_args.require_positional(name, label="service name")
    if not _brew_present():
        raise api_error("brew.not_found")
    try:
        rc, msg = run_capped(
            [BREW, "services", action, name],
            timeout=120, env=_brew_env(), cap=2000,
        )
    except Exception as e:
        # Leftover ``\ud800`` in a raised message used to 500 the action
        # JSON the same way a leftover brew-list name 500'd the list.
        return {"ok": False, "message": _as_text(e)}
    rc = _plain_rc(rc)
    if rc == -1 and _as_text(msg).strip() == "not found":
        # run_capped reports a FileNotFoundError spawn as (-1, "not found") —
        # a sentinel, never a real brew exit.  Homebrew vanished between the
        # _brew_present() check and the spawn, so answer with the same coded
        # 503 that check raises instead of an uncoded {ok: false,
        # message: "not found"} the SPA cannot translate.  (This must sit
        # outside the try above: the broad except used to swallow the raise
        # into exactly that uncoded shape.)  Confirmed against the
        # filesystem, mirroring set_brew_autostart and the docker
        # classifiers' forced engine probe: a signal-killed brew is also
        # rc -1, so a brew that is still present keeps its raw result
        # instead of a false "Homebrew is not installed".
        if not _brew_present():
            raise api_error("brew.not_found")
    # The shared `brew services list --json` snapshot has a 6s TTL, so
    # without this the UI re-reads the pre-action state right after a
    # start/stop and shows the service back in its old state until the TTL
    # lapses.  Drop it here, next to invalidate_status(), so the refresh
    # that follows the action is truthful.
    invalidate_brew_services()
    invalidate_status()
    # run_capped is str; a bytes leftover from a stub (or a future
    # binary-capped helper) used to TypeError Starlette's encoder.
    text = _as_text(msg).strip()
    if not text:
        if rc is None:
            text = "exit unknown"
        else:
            try:
                text = f"exit {rc}"
            except (ValueError, TypeError, RecursionError, OverflowError):
                # Past CPython's int->str digit cap an over-cap rc cannot be
                # rendered at all; the f-string used to ValueError and 500
                # POST /api/brew/services/{name}/action after the run finished.
                text = "exit unknown"
    return {
        "ok": rc == 0,
        "message": text,
    }
