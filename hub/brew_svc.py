"""Homebrew services management — macOS-native module."""
from __future__ import annotations

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

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
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _mapping_get(mapping, key, default=None):
    """Row field read that a hostile mapping *key* cannot cost the row.

    The ups_svc/vms_svc/health11 rule this module's unbound ``dict.get``
    calls never got: the unbound builtin bypasses a subclass ``.get``
    override, but the C-level lookup still runs the *stored keys'* own
    ``__eq__`` whenever the probe's hash lands on their slot.  A leftover
    str-subclass key whose hash shadows ``user``/``file``/``exit_code``
    (raising ``__eq__``) therefore raised inside the per-row try and
    dropped that whole service from GET /api/brew/services — one poisoned
    field cost the row its name, status and actions.  Only the shadowed
    field degrades to its default now.
    """
    if not _isinstance(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return default


def _sh_answer(value) -> tuple:
    """Exact ``(rc, out, err)`` storage from a possibly-poisoned ``sh`` answer.

    The docker11/health11 answer-shape rule: this module does not own
    ``sh`` (tests and tooling patch it), so the bare ``rc, out, err =
    sh(…)`` unpack in :func:`list_services` dispatched into the answer's
    *own* iteration — a tuple/list subclass whose ``__iter__`` raises, or a
    lying-``__class__`` impostor over no real sequence storage.  The
    surrounding ``except`` swallowed that raise into "no rows", so an
    honest listing riding inside a subclass wrapper was thrown away.
    Unbound base reads keep it; junk degrades to ``(None, None, None)``,
    which :func:`_plain_rc` reads as failure — never ``0``, and never the
    ``-1`` vanished-spawn sentinel.
    """
    if type(value) is tuple:
        items = value
    elif _isinstance(value, tuple):
        try:
            items = tuple(tuple.__iter__(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return (None, None, None)
    elif _isinstance(value, list):
        try:
            items = tuple(list.__iter__(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return (None, None, None)
    else:
        return (None, None, None)
    if len(items) != 3:
        return (None, None, None)
    return items


def _spawn_pair(value) -> tuple:
    """Exact ``(rc, message)`` storage from a possibly-poisoned ``run_capped``.

    Same answer-shape class as :func:`_sh_answer`, one slot narrower.  The
    bare ``rc, msg = run_capped(…)`` unpack ran inside the spawn try, so a
    subclass ``__iter__`` bomb — or any wrong-arity/non-iterable leftover —
    was reported to the SPA as a *failed action* carrying a raw Python
    unpack message ("cannot unpack non-iterable Liar object"), even when
    the honest answer inside the wrapper said exit 0.  Unbound base reads
    recover that answer; junk degrades to ``(None, None)``, which renders
    as ``exit unknown`` and can never forge the ``-1`` sentinel that maps a
    vanished Homebrew to the coded 503.
    """
    if type(value) is tuple:
        items = value
    elif _isinstance(value, tuple):
        try:
            items = tuple(tuple.__iter__(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return (None, None)
    elif _isinstance(value, list):
        try:
            items = tuple(list.__iter__(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return (None, None)
    else:
        return (None, None)
    if len(items) != 2:
        return (None, None)
    return items


def _as_text(value) -> str:
    # Unbound through the base types: a leftover bytes-subclass whose bound
    # ``.decode`` raises (or a str-subclass whose ``.encode`` does) used to
    # 500 the post-spawn tail of service_action, which runs outside its try.
    # Guarded isinstance throughout: a leftover whose ``__class__`` property
    # raises used to blow the chain itself and cost every sibling row.
    #
    # The unbound base calls run inside a ``try`` (the health10 rule): a
    # *lying*-``__class__`` impostor — ``isinstance`` answers bytes/str, the
    # real object is neither — passes the gate but makes the unbound
    # ``bytes.decode`` / ``str.encode`` descriptor itself raise TypeError.
    # A bytes/str-liar stdout used to 500 GET /api/brew/services from the
    # fallback tail, and a liar ``msg`` 500'd POST
    # /api/brew/services/{name}/action after the run had finished.  A liar
    # falls through to the generic guarded ``str()`` probe instead.
    text = None
    if _isinstance(value, bytes):
        try:
            text = bytes.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            text = None
    elif _isinstance(value, bytearray):
        try:
            text = bytearray.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            text = None
    elif _isinstance(value, str):
        text = value
    elif value is None:
        return ""
    if text is None:
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
            return ""
    try:
        return str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A str-liar rode the ``_isinstance(value, str)`` branch as *text*
        # itself, and unbound ``str.encode`` cannot apply to it — one last
        # guarded ``str()`` renders its honest ``__str__`` instead of 500ing.
        try:
            return str.encode(str(value), "utf-8", "replace").decode("utf-8")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            try:
                return type(value).__name__
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return ""


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

    The unbound base calls run inside a ``try`` (the health10/modules9
    rule): a *lying*-``__class__`` impostor — ``isinstance`` answers the
    claimed type, the real object is something else — passes the gate but
    makes the unbound descriptor itself raise TypeError.  A bool-liar
    ``user``/``file``/``exit_code`` used to ride through the old
    ``return value`` arm raw and 500 Starlette's encoder on GET
    /api/brew/services; a str/bytes-liar field raised out of this launderer
    and wiped every sibling row into the text fallback.
    """
    if depth > 16:
        return None
    if value is None:
        return value
    if _isinstance(value, bool):
        if type(value) is bool:
            return value
        # Only a lying ``__class__`` property lands here (bool is final).
        # It used to ride through as-is and 500 Starlette's encoder.
        try:
            return bool(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isinstance(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__`` bomb
                # used to blow the digit-cap probe below (only ValueError
                # was caught).
                value = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
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
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isinstance(value, str):
        # Unbound base encode: a str-subclass ``.encode`` bomb cannot fire.
        # Guarded: a str-liar the descriptor refuses drops to None instead
        # of raising out and wiping every sibling row.
        try:
            return str.encode(value, "utf-8", "replace").decode("utf-8")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isinstance(value, bytes):
        try:
            return bytes.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isinstance(value, bytearray):
        try:
            return bytearray.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isinstance(value, (list, tuple, set, frozenset)):
        return None
    try:
        iso = getattr(value, "isoformat", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Property bomb / ``__getattr__`` raising non-AttributeError past
        # getattr's default.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/brew/services.
            stamped = iso()
        except _CONTROL_FLOW:
            raise
        except BaseException:
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
    The bool arm's coercion is guarded too (bool is final, so only a
    *lying*-``__class__`` impostor can fail it): ``int(liar)`` used to
    TypeError out of this helper and 500 both GET /api/brew/services'
    fallback tail and POST /api/brew/services/{name}/action.
    """
    if _isinstance(value, bool):
        try:
            return int(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isinstance(value, int):
        try:
            return int.__index__(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isinstance(value, float):
        try:
            return float.__float__(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
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


# Formulae replaced by a custom LaunchAgent / container on this host.
# `brew services` still lists them as none/error, which paints the Tools page red.
# nginx → local.system-nginx; cloudflared → local.cloudflared-tunnel;
# redis → Immich Valkey on :6379 (Homebrew Redis KeepAlive crash-loops EADDRINUSE);
# ollama → com.kiro.ollama on :11434.
_HIDE_BREW = {"nginx", "cloudflared", "ollama"}
# Starting these from the Tools API recopies a KeepAlive plist and the dummy
# agent crash-loops.  redis is also dummy here but tests call
# service_action("redis", ...) for vanished-brew leftovers, so redis is
# pinned by local.pin-dummy-brew instead of this gate.
_BLOCK_BREW_START = frozenset({"cloudflared", "nginx", "ollama"})


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
    except _CONTROL_FLOW:
        raise
    except BaseException:
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
        except _CONTROL_FLOW:
            raise
        except BaseException:
            rows = []
    if rows:
        try:
            for s in rows:
                # Per-row guard: a *lying*-``__class__`` impostor row —
                # ``isinstance`` answers dict, the real object is not one —
                # passes the filter above and then the unbound ``dict.get``
                # descriptor refuses it with TypeError; under the old
                # loop-wide try that one row wiped every sibling into the
                # text fallback.  It now costs only itself.
                try:
                    # _mapping_get, not bare unbound ``dict.get``: the
                    # unbound read already dodged a dict-subclass ``get``
                    # override, but the hash probe still ran the *stored
                    # keys'* ``__eq__`` — a leftover key shadowing
                    # ``user``/``file``/``exit_code`` raised inside this
                    # per-row try and cost the whole service its row.
                    name = _as_text(_mapping_get(s, "name")).strip()
                    if not name or name in _HIDE_BREW:
                        continue
                    status = _as_text(_mapping_get(s, "status")).lower()

                    # started|stopped|error|none
                    state = "ok" if status in ("started", "running") else (
                        "warn" if status in ("error",) else "down"
                    )
                    items.append({
                        "id": name,
                        "name": name,
                        "status": status or "unknown",
                        "state": state,
                        "user": _json_safe(_mapping_get(s, "user")),
                        "file": _json_safe(_mapping_get(s, "file")),
                        "exit_code": _json_safe(_mapping_get(s, "exit_code")),
                        "actions": ["restart", "stop"] if state == "ok" else ["start"],
                    })
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            return items
        except _CONTROL_FLOW:
            raise
        except BaseException:
            items = []
    # fallback text parse
    try:
        answer = sh([BREW, "services", "list"], timeout=20)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return items
    # _sh_answer, not a bare unpack: the answer object is not ours (tests
    # and tooling patch ``sh``), and a tuple-subclass ``__iter__`` bomb
    # around an honest listing used to raise into the except above and
    # throw those rows away.  Junk reads as a failed spawn below.
    rc, out, _err = _sh_answer(answer)
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
    if name in _BLOCK_BREW_START and action in ("start", "restart"):
        return {
            "ok": False,
            "message": (
                f"{name} is replaced by a custom LaunchAgent on this host; "
                f"do not brew services {action} {name}"
            ),
        }
    if not _brew_present():
        raise api_error("brew.not_found")
    try:
        answer = run_capped(
            [BREW, "services", action, name],
            timeout=120, env=_brew_env(), cap=2000,
        )
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        # Leftover ``\ud800`` in a raised message used to 500 the action
        # JSON the same way a leftover brew-list name 500'd the list.
        return {"ok": False, "message": _as_text(e)}
    # _spawn_pair, not a bare ``rc, msg = …`` unpack inside the try above:
    # a subclass ``__iter__`` bomb (or any wrong-arity leftover) reported a
    # raw Python unpack message as the action's failure text, discarding an
    # honest exit status riding inside the wrapper.
    rc, msg = _spawn_pair(answer)
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
    #
    # Guarded: neither cache belongs to this module, both calls sit outside
    # the spawn try, and a leftover hash-shadowing str-subclass key planted
    # in either module cache raised out of the C-level insert compare —
    # a raw 500 on POST /api/brew/services/{name}/action *after* the
    # start/stop had already run.  A cache that refuses to be dropped costs
    # the SPA one stale refresh window, never the action's answer.
    try:
        invalidate_brew_services()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        invalidate_status()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
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
