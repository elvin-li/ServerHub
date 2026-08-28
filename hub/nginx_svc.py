"""System nginx reverse proxy management."""
from __future__ import annotations

import os
import re
from pathlib import Path

from fastapi import HTTPException

from hub.adaptive import nginx_sites
from hub.errors import api_error
from hub.launchd_cache import invalidate_launchd, listing as launchd_listing
from hub.paths import NGINX as NGINX_BIN
from hub.paths import user_home
from hub.status import invalidate_status
from hub.util import sh

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _user_home() -> Path | None:
    """Guard the ``user_home`` provider seam so a leftover cannot 500 the import.

    ``hub.paths.user_home`` guards ``Path.home()`` and answers a ``Path`` or
    ``None`` today, but the call was joined *bare* here — ``home / "Services"
    / "nginx"`` assumed the answer was a Path.  A provider that raises outside
    that helper's caught ``(OSError, RuntimeError, ValueError)`` trio (a
    ``KeyError`` from a ``pwd`` lookup on a uid with no passwd entry — the
    container/sandbox "leftover HOME" this module's docstring already names),
    or one that answers text / bytes / junk instead of a Path (the seam tests
    and tooling patch), detonated :func:`_default_root` at
    ``NGINX_ROOT = _default_root()`` import time — a raise, or a ``TypeError``
    on ``str.__truediv__`` — and took the whole module down with it, so
    GET /api/nginx and POST /api/nginx/test|reload answered HTTP 500 (the
    router never mounted) instead of the sentinel root's coded shapes.  This
    runs *before* ``_isinst`` / ``_as_text`` are defined, so it launders
    self-contained (the backups12 ``_user_home`` rule): a real Path passes; a
    textual answer still names a real directory and is kept as a Path
    (surrogates via ``surrogateescape``); a raise or junk degrades to ``None``
    and the caller takes the ``/var/empty`` sentinel.  A leftover whose
    ``__class__`` is a raising property blows the ``isinstance`` gate too —
    that also degrades to ``None`` rather than escaping.
    """
    try:
        home = user_home()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    try:
        if isinstance(home, Path):
            return home
        if isinstance(home, (str, bytes)):
            return Path(os.fsdecode(home))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    return None


def _default_root() -> Path:
    """Nginx tree under ``~/Services/nginx``.  A leftover ``user_home`` provider
    must not 500 the import (see :func:`_user_home`); junk takes the sentinel."""
    home = _user_home()
    return (home / "Services" / "nginx") if home is not None else Path("/var/empty/serverhub-nginx")


NGINX_ROOT = _default_root()
NGINX_CONF = NGINX_ROOT / "nginx.conf"
CONF_D = NGINX_ROOT / "conf.d"
LABEL = "local.system-nginx"


def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so a leftover whose ``__class__`` is a
    raising property blew every unguarded ``isinstance`` gate below — at
    site-row rank, nested value and mapping-key rank inside ``_jsonable``,
    at the whole-``sites``-return rank in ``overview()``, and through
    ``_as_text`` on the ``sh`` out/err seam — and 500'd GET /api/nginx and
    POST /api/nginx/test|reload.  A lying ``__class__`` (answers ``int``)
    is *not* an error and still reports its claim here; the numeric arms'
    unbound base coercion then drops it, exactly as before.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _decode_bytes(value) -> str | None:
    """Unbound base decode; ``None`` when *value* only lies about being bytes."""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    return None


def _as_text(value) -> str:
    """Leftover ``\\ud800`` in ``nginx -t`` used to 500 Settings → Test/Reload."""
    if value is None:
        return ""
    decoded = _decode_bytes(value)
    if decoded is not None:
        return decoded
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        value = str(value)
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
        text = str.encode(value, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _sh_message(err, out, fallback: str = "") -> str:
    return (_as_text(err) or _as_text(out) or fallback).strip()


def _rc_int(rc) -> int:
    """Exact int from an ``sh()`` return code; junk reads as -255.

    ``rc == 0`` / ``rc == -1`` / ``rc != 0`` run a leftover int-subclass's
    own ``__eq__``/``__ne__``; ``int.__index__`` reads the real value
    underneath a subclass override, so an honest exit in a bombed wrapper
    survives, while a *lying* ``__class__`` impostor (claims int/bool over
    no real int storage) TypeErrors on the unbound read and drops with the
    junk.  Junk degrades to ``-255`` (the vms10/shares10 rule), never
    ``-1``: that value is the ``sh`` spawn-failure *sentinel*, and a junk
    rc that read as -1 beside a leftover "not found" stderr could forge
    the vanished-CLI classifier in :func:`_raise_if_cli_vanished` — a
    coded 503 minted out of a poisoned object instead of a real missing
    binary.  -255 is no honest nginx exit, so junk always keeps the plain
    failure branch.  An over-cap exact int (>4300 digits — YAML/plist hex
    loads dodge the parse-time cap) is unrenderable and reads as junk too.
    """
    if type(rc) is int:
        pass
    elif rc is True:
        return 1
    elif rc is False:
        return 0
    elif _isinst(rc, int):
        try:
            rc = int.__index__(rc)
        except Exception:
            return -255
        if type(rc) is not int:
            return -255
    else:
        return -255
    try:
        str(rc)
    except ValueError:
        return -255
    return rc


def _sh3(value) -> tuple:
    """Exact ``(rc, out, err)`` storage from a possibly-poisoned ``sh`` answer.

    A real spawn always answers an exact 3-tuple, but this module does not
    own ``sh``: a tuple/list *subclass* whose bound ``__iter__`` bombs — or
    a lying ``__class__`` impostor claiming tuple/list over no real sequence
    storage — raised straight out of the callers' unpack, and a wrong-arity
    answer was a ValueError the same way.  The unbound base reads see the
    real C-level storage, so an honest answer in a subclass wrapper survives
    untouched, while junk degrades to ``(-255, "", "")``: nonzero (a
    poisoned answer is not consent to claim success) and never the ``-1``
    sentinel (an unusable answer cannot forge the vanished-CLI 503).
    """
    if type(value) is tuple:
        items = value
    elif _isinst(value, tuple):
        try:
            items = tuple(tuple.__iter__(value))
        except Exception:
            return (-255, "", "")
    elif _isinst(value, list):
        try:
            items = tuple(list.__getitem__(value, slice(None)))
        except Exception:
            return (-255, "", "")
    else:
        return (-255, "", "")
    if len(items) != 3:
        return (-255, "", "")
    return items


def _sh_triple(cmd, timeout: int) -> tuple:
    """Spawn with the unpack inside the guard (the brew_svc.service_action rule).

    ``test_config``/``reload_nginx`` do not own the runner: the production
    ``sh`` never raises and always answers ``(rc, out, err)``, but a patched
    or odd one (the same class ``_sh_message`` guards at value rank) can
    raise outright or answer a wrong-arity tuple / bare None — both used to
    ride to Starlette uncaught and 500 POST /api/nginx/test and /reload.
    A raising runner keeps the ``(-1, "", text)`` spawn shape (gateway5:
    the vanished-CLI classification stays with the callers, disk-confirmed,
    so a raise whose text merely reads "not found" is never misclassified
    while nginx is still on disk); an unusable *answer* degrades through
    :func:`_sh3` / :func:`_rc_int` to -255 instead, so a poisoned object
    can never forge the spawn sentinel.
    """
    try:
        answer = sh(cmd, timeout=timeout)
    except Exception as exc:
        return -1, "", _as_text(exc)
    rc, out, err = _sh3(answer)
    return _rc_int(rc), out, err


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's ``allow_nan=False`` encoder cannot 500.

    ``overview()`` does not own the sites parser: the real
    ``adaptive.nginx_sites`` scrubs its output, but a patched or odd one (the
    same class ``_sh_message`` guards for ``sh`` and ``_pid_text`` for the
    listing) can answer rows the production parser never does.  Every other
    field of the payload was scrubbed; a lone surrogate in a site key or
    value rode raw to Starlette's UTF-8 encode, and an already-int over-cap
    number (YAML/plist hex loads uncapped — ``int(x, 16)`` is exempt from
    CPython's 4300-digit cap) ValueError'd Starlette's own ``json.dumps`` at
    int->str time — both used to 500 GET /api/nginx.
    """
    if depth > 32:
        return None
    # ``type(x) is bool``, not ``_isinst``: a *bool-liar* (a lying
    # ``__class__`` property answering ``bool`` over no real bool storage)
    # passed the guarded isinstance and rode raw into Starlette's
    # ``json.dumps`` — a TypeError 500 on GET /api/nginx.  It now falls to
    # the int arm (bool claims int too), where the unbound ``int.__index__``
    # drops the impostor to null; real bools keep passing through.
    if value is None or type(value) is bool:
        return value
    if _isinst(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int (the modules5 unbound
                # convention): an int subclass whose ``__str__`` raises used
                # to blow the digit-cap probe below out of overview() and
                # 500 GET /api/nginx.
                value = int.__index__(value)
            except Exception:
                return None
        try:
            # A str() probe, never an isinstance(x, str) gate: the finite
            # numeric listen ports the Gateway table renders must pass
            # through as ints, only the unrenderable over-cap ones drop.
            str(value)
        except ValueError:
            return None
        return value
    if _isinst(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a float subclass whose
                # ``__eq__``/``__ne__`` raises used to blow the NaN/inf
                # probes below the same way.
                value = float.__float__(value)
            except Exception:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isinst(value, str):
        return _as_text(value)
    if _isinst(value, (bytes, bytearray)):
        # Unbound base decode: ``bytes(value)`` re-enters a subclass
        # ``__bytes__`` bomb before the copy, and a bound ``.decode`` bomb
        # was live for bytearray shapes — both used to 500 GET /api/nginx.
        # ``None`` means a lying ``__class__`` impostor with no real byte
        # storage (the unbound descriptor TypeError'd out of this arm and
        # 500'd GET /api/nginx pre-fix): degrade to its text.
        decoded = _decode_bytes(value)
        return decoded if decoded is not None else _as_text(value)
    if _isinst(value, dict):
        # Unbound base view: a dict subclass whose ``items()`` raises used
        # to wipe its whole row (pre-fix the raise escaped overview()'s
        # comprehension and 500'd the route, taking every sane sibling site
        # down with it); the base view cannot raise off real storage.  A
        # lying ``__class__`` impostor claiming dict over no real mapping
        # storage TypeErrors the descriptor itself — that blew out of this
        # arm at row and value rank and 500'd GET /api/nginx; it degrades
        # to its text now.
        try:
            items = list(dict.items(value))
        except Exception:
            return _as_text(value)
        out = {}
        for k, v in items:
            if _isinst(k, (bytes, bytearray)):
                decoded = _decode_bytes(k)
                if decoded is not None:
                    k = decoded
                else:
                    # A lying-bytes key: str(k) off the real type, the same
                    # fallback every other non-str key takes.
                    try:
                        k = str(k)
                    except Exception:
                        continue
            elif not _isinst(k, str):
                try:
                    k = str(k)
                except Exception:
                    # The over-cap int key: the entry drops, not the row.
                    continue
            out[_as_text(k)] = _jsonable(v, depth + 1)
        return out
    if _isinst(value, (list, tuple, set, frozenset)):
        for base in (list, tuple, set, frozenset):
            if _isinst(value, base):
                # Unbound base iteration: a subclass ``__iter__`` bomb used
                # to drop the whole field — the real elements survive now.
                # A lying ``__class__`` impostor claiming the base over no
                # real sequence storage TypeErrors the descriptor — that
                # used to 500 GET /api/nginx; it degrades to its text.
                try:
                    elems = list(base.__iter__(value))
                except Exception:
                    return _as_text(value)
                return [_jsonable(v, depth + 1) for v in elems]
    return _as_text(value)


def _pid_text(value) -> str | None:
    """Pid shapes that dodge ``Listing``'s coercion must not poison the payload.

    ``overview()`` does not own the listing object, so a patched or odd one
    (the same class ``_sh_message`` guards for ``sh``) can answer shapes the
    production ``Listing`` never does:

    * an *already-int* over-cap pid — YAML/plist hex loads uncapped, and
      ``str()`` of it is CPython's 4300-digit ValueError, which used to ride
      to Starlette's own ``json.dumps`` and 500 GET /api/nginx.  A str()
      probe, not a strict ``isinstance(pid, str)`` gate: a finite numeric
      pid must keep reporting running;
    * ``True`` — bool is int's subclass, and ``true`` in JSON made the
      SPA's ``Number(true)`` render the lie "pid 1";
    * digit runs past pid_t (signed 32-bit) are no real process — the same
      bound cloudflared_svc applies before ``os.kill``.
    """
    # ``type(x) is bool`` (the bool-liar rule _jsonable applies): a lying
    # ``__class__`` claiming bool falls to the int arm, where the unbound
    # coercion drops it; a real True can never render as "pid 1".
    if value is None or type(value) is bool:
        return None
    if _isinst(value, int):
        if type(value) is not int:
            try:
                # Base coercion first (the modules5 unbound convention): an
                # int subclass whose ``__str__`` raises non-ValueError used
                # to escape into overview()'s guard and flip ``running`` to
                # a false "stopped" while nginx held a real pid.
                value = int.__index__(value)
            except Exception:
                return None
        try:
            value = str(value)
        except ValueError:
            return None
    text = _as_text(value).strip()
    if not text.isascii() or not text.isdigit():
        return None
    try:
        n = int(text)
    except ValueError:
        return None
    if n < 1 or n > 2**31 - 1:
        return None
    return text


def _nginx_present() -> bool:
    """``os.path.isfile`` re-raises EIO/ESTALE; that must not 500 Test/Reload.

    The two arms answer *opposite* defaults on purpose.  An OSError is the
    disk speaking (dying mount, stale handle) and keeps the historical
    "cannot see it -> not present" answer.  Anything else means the probe
    itself is junk — a patched or odd ``NGINX_BIN`` whose ``__fspath__``
    bombs TypeErrors ``os.stat`` past the OSError-only catch, which used to
    500 POST /api/nginx/test|reload right at the vanished-CLI classify.
    Junk answers "present": an unreadable probe is no *confirmation* that
    the binary left the disk, so it can never mint the coded 503 (the same
    no-forgery rule ``_rc_int`` applies to the -1 spawn sentinel).
    """
    try:
        return os.path.isfile(NGINX_BIN)
    except OSError:
        return False
    except Exception:
        return True


def _conf_present() -> bool:
    """Strict-bool ``NGINX_CONF.is_file()`` that junk cannot 500 through.

    ``test_config`` does not own the conf constant at call time (tests and
    tooling patch it): a patched or odd path object whose ``is_file`` raises
    outside the historical ``(OSError, ValueError)`` pair — or answers a
    ``__bool__``-bombing leftover that detonated the bare ``not present``
    truth-test — used to ride to Starlette uncaught and 500 POST
    /api/nginx/test and /reload.  An unreadable probe reads "missing", the
    same coded 404 a dying-mount EIO already answered.
    """
    try:
        return bool(NGINX_CONF.is_file())
    except Exception:
        return False


def _conf_arg() -> str:
    """The ``-c`` argv text; a conf whose ``str()`` bombs must not 500 the spawn.

    ``str(NGINX_CONF)`` ran bare inside the argv literal — *before*
    ``_sh_triple``'s guard could see it — so a patched or odd conf object
    whose ``__str__`` raises blew POST /api/nginx/test and both spawn ranks
    of /reload out of the handler as a raw 500.  ``_as_text`` degrades it to
    ""; nginx then fails the run honestly and the coded failure shape holds.
    """
    return _as_text(NGINX_CONF)


def _invalidate_quietly(*invalidators) -> None:
    """Cache invalidation after a reload/kickstart must not 500 the answer.

    ``reload_nginx`` does not own the shared caches: the production
    ``invalidate_launchd`` / ``invalidate_status`` never raise, but a patched
    or odd one (the same class ``_sh_message`` guards for ``sh``) used to
    detonate *after* the kickstart — and even after a fully successful
    reload — turning a completed action into HTTP 500, so the operator
    retried a reload that had already happened.  A stale cache self-heals on
    its short TTL; a lost answer does not.
    """
    for invalidate in invalidators:
        try:
            invalidate()
        except Exception:
            pass


def _probe_answer(probe) -> tuple[bool, str]:
    """Exact ``(ok, message)`` from a possibly-poisoned config-probe answer.

    ``reload_nginx`` reads the probe through the module global, which tests
    and tooling patch, so the answer is a seam like ``sh``: the bare
    ``t["ok"]`` / ``not t["ok"]`` / ``t.get("message")`` reads used to 500
    POST /api/nginx/reload for

    * a dict *subclass* whose bound ``__getitem__``/``get``/``__bool__``
      raise (the honest fields underneath survive the unbound reads now);
    * a *hash-shadowing* stored key — a str-subclass key over the ``ok`` or
      ``message`` slot whose ``__eq__`` raises: the C lookup compares the
      *stored* key against the query, so even an exact-str probe detonated
      the stored bomb (the shape ``dict.get`` cannot dodge, only the guard
      can catch);
    * an ``ok`` value whose ``__bool__`` bombs, and non-dict answers
      (None / str) that blew the subscript outright.

    Junk never consents: an unreadable ``ok`` reads False, so a poisoned
    probe keeps the "Invalid configuration; not reloaded" branch instead of
    reloading on evidence that cannot be read.  An honest exact answer is
    untouched.
    """
    if not _isinst(probe, dict):
        return False, _as_text(probe) if probe is not None else ""
    try:
        ok = dict.get(probe, "ok")
    except Exception:
        ok = False
    try:
        ok = bool(ok)
    except Exception:
        ok = False
    try:
        message = dict.get(probe, "message")
    except Exception:
        message = None
    return ok, _as_text(message)


def _raise_if_cli_vanished(rc: int, message: str) -> None:
    """Classify the ``sh`` spawn sentinel as the coded 503, disk-confirmed.

    ``sh`` reports a FileNotFoundError spawn as ``(-1, "", "not found")`` —
    a sentinel, never a real nginx exit.  That used to leak to the Gateway
    card as an uncoded ``{ok: false, message: "not found"}`` (and Reload
    mislabelled it "Invalid configuration; not reloaded").  Answer with a
    coded 503 like ``brew.not_found`` instead — but only after confirming
    against the filesystem, on the failure path only: a signal-killed or
    vanished-cwd spawn is also rc -1, so an nginx that is still on disk
    keeps its raw result, and a genuine nginx exit whose stderr merely
    reads "not found" is never reclassified.
    """
    if rc == -1 and message == "not found" and not _nginx_present():
        raise api_error("nginx.not_found")


def overview() -> dict:
    # GET /api/nginx used to 500 when one unreadable ``*.conf`` raised inside
    # ``nginx_sites`` (MemoryError / ValueError are not OSError).
    try:
        sites = nginx_sites()
    except Exception:
        sites = []
    # _isinst, not a bare isinstance: a sites *return* whose ``__class__``
    # is a raising property blew this gate outside the try above and 500'd
    # GET /api/nginx before a single row was read.
    if not _isinst(sites, list):
        sites = []
    # Field-level scrub of rows overview() does not own (see _jsonable):
    # surrogate keys/values and already-int over-cap numbers used to 500 the
    # encode.  Non-dict rows are dropped before site_count counts them — the
    # SPA keys the table on ``s.file``.
    #
    # Materialize before scrubbing: ``isinstance(sites, list)`` passes for a
    # list *subclass*, and one whose ``__iter__`` raises used to blow up the
    # comprehension outside the try above and 500 GET /api/nginx.  Row-level
    # isolation after that: a row whose scrub collapses (a mapping that
    # refuses ``items()``) drops alone — pre-fix it took every sane sibling
    # site down with the 500.
    try:
        rows = list(sites)
    except Exception:
        rows = []
    sites = []
    for row in rows:
        # _isinst at row rank: a leftover row whose ``__class__`` is a
        # raising property used to blow this gate out of the loop and 500
        # the route, taking every sane sibling site down with it.
        if not _isinst(row, dict):
            continue
        scrubbed = _jsonable(row)
        if _isinst(scrubbed, dict):
            sites.append(scrubbed)
    # The shared listing (hub/launchd_cache.py) rather than this module's own
    # `launchctl list`: the health page calls this *and* two other readers of the
    # same listing, so the bundle used to spawn three of them.
    #
    # Exact label match now, where this scanned for `LABEL in line` -- a substring
    # test that would have matched a different job whose label merely contains
    # `local.system-nginx`.
    try:
        pid = _pid_text(launchd_listing().pid_for(LABEL))
    except Exception:
        pid = None
    running = pid is not None
    # ``str(path)`` verbatim used to 500 the encode: these two derive from
    # ``Path.home()``, and a HOME whose on-disk name is undecodable arrives
    # through os.environ's surrogateescape as a str carrying a lone
    # ``\udcff`` — every sibling field here is scrubbed, the conf paths were not.
    return {
        "label": LABEL,
        "conf": _as_text(NGINX_CONF),
        "conf_d": _as_text(CONF_D),
        "running": running,
        "pid": pid,
        "sites": sites,
        "site_count": len(sites),
        "hint": "New site: drop a *.conf into conf.d/ and click \"Reload\"",
    }


def test_config() -> dict:
    # Dying mount EIO / a NUL leftover used to 500 Settings → Test/Reload;
    # _conf_present also strict-bools the answer and holds the wider guard
    # (a patched or odd conf object raising past OSError/ValueError, or an
    # is_file() answering a __bool__ bomb, each used to 500 the same way).
    if not _conf_present():
        raise api_error("nginx.conf_missing")
    # ``sh`` swallows FileNotFoundError / TimeoutExpired; a missing binary
    # used to 500 Settings → Reload instead of returning a coded failure.
    rc, out, err = _sh_triple([NGINX_BIN, "-t", "-c", _conf_arg()], timeout=15)
    # bytes/None from a patched or odd `sh` used to TypeError when Reload
    # concatenated the probe text onto a str prefix.
    message = _sh_message(err, out)
    _raise_if_cli_vanished(rc, message)
    return {"ok": rc == 0, "message": message}


def reload_nginx() -> dict:
    # The probe read via the module global is a seam (tests and tooling
    # patch it).  A coded raise stays itself — conf_missing 404 and
    # nginx.not_found 503 keep their contract — but a junk raise used to
    # ride to Starlette uncaught and 500 POST /api/nginx/reload; an
    # unreadable probe is not consent to reload, so it keeps the invalid
    # branch with the raise's text.
    try:
        probe_ok, probe_msg = _probe_answer(test_config())
    except HTTPException:
        raise
    except Exception as exc:
        probe_ok, probe_msg = False, _as_text(exc)
    if not probe_ok:
        return {
            "ok": False,
            "message": "Invalid configuration; not reloaded\n" + probe_msg,
        }
    rc, out, err = _sh_triple(
        [NGINX_BIN, "-c", _conf_arg(), "-s", "reload"], timeout=15,
    )
    if rc != 0:
        # nginx vanished between ``-t`` and ``-s reload``: a coded 503,
        # not a launchd kickstart aimed at a binary that is gone.
        _raise_if_cli_vanished(rc, _sh_message(err, out))
        uid = os.getuid()
        rc2, out2, err2 = _sh_triple(
            ["/bin/launchctl", "kickstart", "-k", f"gui/{uid}/{LABEL}"],
            timeout=30,
        )
        _invalidate_quietly(invalidate_launchd, invalidate_status)
        return {
            "ok": rc2 == 0,
            "message": _sh_message(err2, out2, probe_msg or "kickstart"),
        }
    _invalidate_quietly(invalidate_status)
    return {"ok": True, "message": "Reloaded\n" + probe_msg}
