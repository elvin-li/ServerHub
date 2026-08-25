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


def _as_text(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        text = value.decode("utf-8", "replace")
    elif isinstance(value, str):
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
    return text.encode("utf-8", "replace").decode("utf-8")


def _json_safe(value):
    """Starlette encodes with allow_nan=False; leftover NaN/bytes 500 the list.

    ``exit_code`` was the first field brew put NaN in.  ``user`` / ``file``
    still passed through, so a non-finite or bytes leftover 500'd GET
    ``/api/brew/services`` the same way.  A leftover ``\\ud800`` in ``name``
    still 500'd the UTF-8 encode.
    """
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # YAML hex/octal leftovers dodge CPython's str->int digit cap, so
            # an over-cap ``exit_code`` / ``user`` arrived here intact and
            # Starlette's json.dumps ValueError'd GET /api/brew/services —
            # same drop as its inf float sibling.
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, (list, tuple, set, frozenset)):
        return None
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/brew/services.
            stamped = iso()
        except Exception:
            return None
        if stamped is value:
            return None
        return _json_safe(stamped)
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
    if isinstance(data, list) and data:
        try:
            for s in data:
                if not isinstance(s, dict):
                    continue
                name = _as_text(s.get("name")).strip()
                if not name or name in _HIDE_BREW:
                    continue
                status = _as_text(s.get("status")).lower()

                # started|stopped|error|none
                state = "ok" if status in ("started", "running") else (
                    "warn" if status in ("error",) else "down"
                )
                items.append({
                    "id": name,
                    "name": name,
                    "status": status or "unknown",
                    "state": state,
                    "user": _json_safe(s.get("user")),
                    "file": _json_safe(s.get("file")),
                    "exit_code": _json_safe(s.get("exit_code")),
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
    if rc != 0:
        return []
    if isinstance(out, (bytes, bytearray)):
        out = out.decode("utf-8", "replace")
    elif not isinstance(out, str):
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
