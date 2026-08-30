"""Dockge-inspired compose stack YAML read/write/validate."""
from __future__ import annotations

import errno
import os
import re
from pathlib import Path

import yaml

from hub import cli_args, secure_io
from hub.containers_svc import _field_text, _plain_job, _stack_paths
from hub.docker_cli import (
    _isa, _rc_int, cli_on_disk, engine_up, looks_cli_vanished, looks_engine_down,
)
from hub.errors import api_error, exc_detail, soft_fail
from hub.paths import DOCKER, user_home
from hub.status import invalidate_status as inv
from hub.util import read_text_capped, run_capped

#: Leftover multi-MB junk occupying docker-compose.yml used to OOM GET /api/compose.
_COMPOSE_CAP = 1024 * 1024
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _utf8_text(value) -> str:
    """Drop leftover ``\\ud800`` so compose writes and Starlette cannot 500.

    catalog14/docker13 rule: both bases first-come, BaseException nets with
    control-flow passthrough, recover honest str behind a lying bytes claim,
    and scrub default ``object.__repr__`` heap addresses off the coercion arm.
    """
    if value is None:
        return ""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
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
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _finite_mtime(value) -> int:
    """A ``st_mtime`` the JSON body can carry, or 0.

    ``int(...)`` with a try only guards *conversions*: a leftover FUSE/SMB
    ``st_mtime`` that is already a >4300-digit int passed through untouched,
    and CPython's int->str digit limit then ValueError'd Starlette's
    ``json.dumps`` — 500ing GET /api/compose/{id} after the compose had
    already been read.  ``float()`` rejects anything beyond float range,
    the same junk test files_svc._finite_int, logs_svc._stat_size,
    usage_svc._safe_bytes and catalog._sig_int apply to their stat numbers.

    ``except Exception``, not the four stat-flavored classes: ``int(...)``
    dispatches into a subclass's ``__int__``/``__index__``/``__trunc__``,
    so a leftover FUSE/SMB ``st_mtime`` riding an int- or float-*subclass*
    whose coercion hook raises RuntimeError blew straight through the old
    tuple and 500'd GET /api/compose/{id} (the docker10 ``_rc_int`` rule).
    The result is re-coerced to an *exact* int through the unbound base
    ``__index__``: a subclass ``__int__`` that answers self would otherwise
    hand its ``__repr__`` bomb to the JSON encoder one funnel later.
    """
    try:
        value = int(value)
        if type(value) is not int:
            value = int.__index__(value)
        float(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return 0
    return value


def _disk_text(value) -> str | None:
    """A reader-seam return as an *exact* ``str``, or None for junk.

    ``read_text_capped`` returns exact text, but the reader is a seam
    (tests and tooling patch it — the files14 runner-seam rule) and
    ``get_compose``/``save_compose`` consumed its return raw: a leftover
    str-subclass whose ``__len__`` raises blew the ``size`` probe, a
    ``__class__``-property bomb blew ``_utf8_text``'s old bare entry gate,
    and a non-str (bytes/None/int) TypeError'd ``replace_secret_text``
    inside a handler that only caught OSError — each one a raw 500 on
    GET/PUT /api/compose/{id} and POST /api/compose/{id}/validate.
    ``str.__str__`` copies through the C storage, so laundering cannot
    itself detonate; bytes decode through the unbound base type; anything
    else is junk and reads as "no usable text".
    """
    if type(value) is str:
        return value
    if _isa(value, (bytes, bytearray)):
        try:
            base = bytes if _isa(value, bytes) else bytearray
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isa(value, str):
        try:
            return str.__str__(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    return None


def _home_path():
    """Best-effort HOME through the module seam (never raises, Path or None).

    ``hub.paths.user_home`` already guards ``Path.home()`` — but the seam
    itself is a provider like ``cfg`` (tests and tooling patch it — the
    backups12 / gateway12 rule) and this module consumed its answer bare:
    a provider that *raises* escaped ``save_compose`` / ``create_stack`` /
    ``validate_compose_text`` before any catch, and a *textual* answer
    detonated the ``home / "Services"`` joins (TypeError on
    ``str.__truediv__``) — ``validate_compose_text`` builds its default
    working directory and ``create_stack`` its stack root *outside* every
    try, so each one was a raw 500 on POST /api/compose/validate and
    POST /api/compose.  A textual answer still names a real directory, so
    it is kept as a Path (surrogates in an undecodable HOME are legitimate
    there); junk that cannot name one degrades to None — the same "no
    home" answer an unresolvable HOME already gets.
    """
    try:
        home = user_home()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    if home is None:
        return None
    text = _disk_text(home)
    if text is None:
        # Path and any real os.PathLike; a lying-``__class__`` impostor has
        # no ``__fspath__`` to answer with and drops here.  The round-trip
        # also flattens a Path subclass carrying bound method bombs.
        try:
            text = os.fspath(home)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
        text = _disk_text(text)
    if not text:
        return None
    try:
        return Path(text)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _row_get(row, key):
    """Unbound ``dict.get`` through the C storage; junk rows read as empty.

    Stack rows normally come out of ``_stack_paths`` as plain dicts, but
    ``_find_stack`` is itself a seam (tests and tooling patch it) and its
    return used to be consumed with *bound* ``.get``: a dict-subclass row
    whose ``.get`` raises, or a str-subclass key whose ``__eq__`` bomb wins
    the reflected compare on hash collision, 500'd GET/PUT
    /api/compose/{id} and POST /api/compose/{id}/validate (the docker7
    unbound-``dict.get`` convention).  Junk that is not a mapping reads as
    an empty row.
    """
    if not _isa(row, dict):
        return None
    try:
        return dict.get(row, key)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _find_stack(stack_id: str) -> dict:
    """The plain-dict stack row for *stack_id*, or the coded 404.

    ``_stack_paths`` launders what it builds, but the *call* is a listing
    seam (tests and tooling patch it — the files14 runner-seam rule) and
    this loop consumed its answer raw: a provider that raises, a non-list
    answer, or a list-subclass whose ``__iter__`` bombs took down every
    compose route at once, a non-dict row AttributeError'd the bound
    ``.get``, and an ``id`` whose ``__eq__`` raises detonated the match
    probe — each one a raw 500 on GET/PUT /api/compose/{id},
    POST /api/compose/{id}/validate and POST /api/compose.  Junk rows are
    junk, not stacks: they drop (the empty-row rule) and an honest row
    later in the listing still matches.
    """
    try:
        rows = _stack_paths()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        rows = []
    if _isa(rows, (list, tuple)):
        try:
            # list() through the C storage: a list-subclass ``__iter__``
            # bomb cannot fire mid-loop.
            rows = list(rows)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            rows = []
    else:
        rows = []
    for s in rows:
        # _plain_job: C-level dict copy with laundered keys, junk rows None.
        s = _plain_job(s)
        if s is None:
            continue
        # Exact-str copy before ``==``: the route's stack_id is a plain str,
        # and comparing two exact strs never dispatches into a subclass.
        sid = _disk_text(_row_get(s, "id"))
        if sid is not None and sid == stack_id:
            return s
    raise api_error("compose.unknown_stack", stack=stack_id)


def _io_compose_path(s: dict):
    """The os-level compose path text for file I/O against stack *s*.

    The published ``compose_path`` is scrubbed for Starlette's UTF-8 encode,
    so for a surrogateescape directory name (one non-UTF-8 byte on disk) its
    ``?``-replacement text names nothing: GET /api/compose/{id} answered 400
    ``no_compose_file`` for a compose the stack scan had just globbed, and a
    save would have written a brand-new ``?``-named tree beside the real one.
    Same convention as the logs tail: read through the raw name the listing
    found, publish the scrubbed text.
    """
    # _row_get + _isa + exact-str copy, not bound ``.get`` and a bare
    # isinstance: a row whose path field is a ``__class__``-property bomb
    # used to detonate the gate itself, and a str-subclass field carrying a
    # ``__len__``/``__eq__`` bomb detonated the truthiness probe or the
    # Path()/read that consumed the raw value one call later (the compose11
    # ``_disk_text`` convention, applied to the row seam).
    path = _row_get(s, "os_compose_path")
    path = _disk_text(path) if _isa(path, str) else None
    if path:
        return path
    path = _row_get(s, "compose_path")
    return _disk_text(path) if _isa(path, str) else None


def _spawnable_dir(text):
    """*text* when it can ride in a subprocess argv, else None.

    ``cli_args.as_argv`` refuses argv it cannot UTF-8-encode, so a
    surrogateescape working directory would fail ``docker compose config``
    with the opaque ``invalid argv`` sentinel.  Falling back to None lets
    ``validate_compose_text`` use its clean ~/Services default instead.
    """
    # _isa + exact-str copy: a ``__class__``-property-bomb workdir used to
    # detonate the bare isinstance, and a str-subclass whose ``__len__`` or
    # bound ``.encode`` raises blew the truthiness probe / the encode probe
    # below — each a raw 500 on POST /api/compose/{id}/validate.
    text = _disk_text(text) if _isa(text, str) else None
    if not text:
        return None
    try:
        text.encode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    return text


def get_compose(stack_id: str) -> dict:
    s = _find_stack(stack_id)
    path = _io_compose_path(s)
    if type(path) is not str or not path:
        raise api_error("container.no_compose_file")
    try:
        # is_file-then-read raced: a compose deleted between the check and
        # read_text raised FileNotFoundError and 500'd the Compose page.
        # Path() itself raises ValueError on NUL / TypeError on a list leftover,
        # which used to escape this handler.
        p = Path(path)
        text = read_text_capped(
            p, _COMPOSE_CAP, encoding="utf-8", errors="replace"
        )
        st = p.stat()
    except (OSError, ValueError, TypeError):
        raise api_error("container.no_compose_file")
    # FUSE ``st_mtime = inf`` OverflowError'd GET /api/compose/{id};
    # OverflowError is not ValueError, so it escaped the handler above.
    # A huge *already-int* leftover slipped past that ``int(...)`` clamp
    # the same way it did in catalog/_templates_sig — _finite_mtime adds
    # the float() junk test.  The attribute read itself is guarded too: a
    # leftover stat wrapper whose ``st_mtime`` is a *raising property*
    # used to detonate one line outside the try above and 500 the read.
    try:
        raw_mtime = st.st_mtime
    except _CONTROL_FLOW:
        raise
    except BaseException:
        raw_mtime = 0
    mtime = _finite_mtime(raw_mtime)
    # _disk_text: the reader seam's return is laundered once, and both the
    # published content and its ``size`` come from the same exact-str copy —
    # a str-subclass ``__len__`` bomb riding the raw text used to 500 the
    # ``len()`` probe after the compose had already been read.
    content = _disk_text(text)
    if content is None:
        raise api_error("container.no_compose_file")
    # _row_get + _isa + exact-str copies, not bound ``.get`` and bare
    # isinstance gates: ``_find_stack`` is a seam, and a row whose id/name/
    # path is a ``__class__``-property bomb used to detonate the gates here
    # — a raw 500 on GET /api/compose/{id} after the compose was in hand.
    raw_id = _row_get(s, "id")
    sid = (_disk_text(raw_id) if _isa(raw_id, str) else None) or ""
    sid = _utf8_text(sid) if sid else ""
    if not sid:
        sid = "stack"
    raw_name = _row_get(s, "name")
    name = (_disk_text(raw_name) if _isa(raw_name, str) else None) or ""
    name = _utf8_text(name) if name else ""
    if not name:
        name = sid
    stack_path = _row_get(s, "path")
    stack_path = _disk_text(stack_path) if _isa(stack_path, str) else None
    return {
        "id": sid,
        "name": name,
        "path": _utf8_text(stack_path) if stack_path is not None else None,
        "compose_path": _utf8_text(path),
        "content": _utf8_text(content),
        "size": len(content),
        "mtime": mtime,
    }


def save_compose(stack_id: str, content: str, validate: bool = True) -> dict:
    s = _find_stack(stack_id)
    path = _io_compose_path(s)
    if type(path) is not str or not path:
        raise api_error("container.no_compose_file")
    # _disk_text, not a bare isinstance + bound decode: a bytes-subclass
    # ``.decode`` bomb, a ``__class__``-property bomb and a str-subclass
    # whose ``strip``/``__len__`` raises each used to detonate this entry
    # gate raw (the direct-call seam — the compose11 validate-gate rule).
    # Bytes still decode; junk still reads as "no content".
    content = _disk_text(content)
    if content is None or not content.strip():
        raise api_error("compose.empty_content")
    content = _utf8_text(content)
    # basic safety: no path escape in content writing
    # _home_path, not the bare seam: a raising or text-answering provider
    # used to fail this join (and a raise escaped as a raw 500 on PUT).
    home = _home_path()
    if home is None:
        raise api_error("container.no_compose_file")
    try:
        p = Path(path).resolve()
        services_root = (home / "Services").resolve()
    except (OSError, ValueError, TypeError, RuntimeError):
        # Path.resolve() raises RuntimeError on a leftover symlink loop.
        raise api_error("container.no_compose_file")
    if services_root not in p.parents and p.parent != services_root:
        # allow only under ~/Services
        raise api_error("compose.path_forbidden")
    if validate:
        # _spawnable_dir: a surrogateescape parent cannot ride in argv, so the
        # check runs from the clean ~/Services default instead of failing the
        # whole save with as_argv's opaque "invalid argv" sentinel.
        v = validate_compose_text(content, cwd=_spawnable_dir(str(p.parent)))
        if not v.get("ok"):
            _raise_validation_failure(v)
    # A compose file carries the generated database and admin passwords for the
    # stack, which is the payload secure_io was written for.  write_text() then
    # chmod() creates the file at the umask default -- 0644 here -- so both the
    # backup and the new content were world-readable for the length of the write.
    # replace_secret_text does the same temp-file-then-rename atomically, with the
    # restrictive mode applied from the first byte.
    bak = p.with_suffix(p.suffix + ".bak")
    try:
        # exists-then-read raced and FileNotFoundError 500'd the save.
        # A leftover directory at compose_path is IsADirectoryError (OSError).
        # _disk_text between the read and the write: the reader is a seam,
        # and a non-str leftover riding its return (bytes/None/int, a
        # ``__class__``-property bomb) used to TypeError inside
        # replace_secret_text — not OSError — and 500 the save.  Junk prior
        # content is not worth backing up (the EFBIG rule); still save over it.
        prior = _disk_text(
            read_text_capped(p, _COMPOSE_CAP, encoding="utf-8", errors="replace")
        )
        if prior is not None:
            secure_io.replace_secret_text(bak, prior)
    except FileNotFoundError:
        pass
    except OSError as exc:
        # Leftover multi-MB junk is not worth backing up; still save over it.
        if getattr(exc, "errno", None) != errno.EFBIG:
            raise api_error("container.no_compose_file")
    try:
        secure_io.replace_secret_text(p, content)
    except OSError as exc:
        # The *live* write is the one line the whole request exists for, and
        # it was the one line left unguarded: ENOSPC / EROFS / a dying FUSE
        # EIO here escaped as a raw HTTP 500 after validation had already
        # passed.  The backup above has its own handler; this one carries the
        # coded 503 so the SPA can point at the real remedy (free the disk /
        # remount) instead of a generic server error.
        raise api_error("compose.save_failed", detail=exc_detail(exc, 200))
    inv()
    # The write went through the raw os-level name; the *response* body must
    # be UTF-8-encodable, so the echoed paths are scrubbed like every other
    # published path field (a lone surrogate here 500'd the save that had
    # already succeeded on disk).
    return {
        "ok": True,
        "path": _utf8_text(str(p)),
        "message": "Saved",
        "backup": _utf8_text(str(bak)),
    }


def _raise_validation_failure(v: dict):
    """Fail a compose save/create with the code the validation reported.

    An engine that is off is a dependency state (coded 503), not a defect in
    the operator's YAML (``compose.invalid``, 400).
    """
    if v.get("code") == "container.engine_down":
        raise api_error("container.engine_down")
    raise api_error("compose.invalid", detail=v.get("message") or "compose invalid")


def validate_compose_text(content: str, cwd: str | None = None) -> dict:
    """docker compose config -q via a 0600 temp file.

    NamedTemporaryFile in ~/Services was born at the umask (0644 here) and
    held the same generated passwords as the live compose until unlink.
    """
    # _isa, not bare isinstance: a leftover content whose ``__class__`` is a
    # raising property used to detonate this gate outside the blanket try
    # below (the nas8 rule); it now degrades to the coded YAML refusal.
    if not _isa(content, str) and not _isa(content, (bytes, bytearray)):
        return {"ok": False, "message": "compose file must be a YAML mapping"}
    content = _utf8_text(content)
    if not content:
        return {"ok": False, "message": "compose file must be a YAML mapping"}
    if "!!python" in content.lower():
        return {"ok": False, "message": "python YAML tags are not allowed"}
    try:
        doc = yaml.safe_load(content)
    except (
        yaml.YAMLError, RecursionError, TypeError, ValueError, AttributeError, KeyError,
    ) as e:
        # RecursionError: leftover deeply-nested compose YAML is not YAMLError.
        # TypeError/ValueError/AttributeError/KeyError: leftover ``!!timestamp .inf``,
        # ``2026-13-01``, a 5000-digit int, or ``!!bool 2`` are not YAMLError.
        return {"ok": False, "message": exc_detail(e, 800)}
    if not isinstance(doc, dict):
        return {"ok": False, "message": "compose file must be a YAML mapping"}
    # _disk_text + _isa, not a bare isinstance + bound strip: a leftover
    # cwd whose ``__class__`` is a raising property, or a str-subclass
    # whose ``strip`` raises, used to detonate this gate *outside* the
    # blanket try below.  And the default-home branch consumed the
    # ``user_home`` seam bare: a raising provider escaped, and a textual
    # answer TypeError'd the ``home / "Services"`` join — both raw 500s on
    # POST /api/compose/validate and every save/create that validates.
    work = _disk_text(cwd) if _isa(cwd, str) else None
    if work is None or not work.strip():
        home = _home_path()
        if home is None:
            return {"ok": False, "message": "invalid working directory"}
        try:
            work = str(home / "Services")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return {"ok": False, "message": "invalid working directory"}
    # NUL / control bytes never reach docker compose: Path() can store them
    # and unlink() then raises ValueError (not OSError) out of finally.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in work):
        return {"ok": False, "message": "invalid working directory"}
    try:
        tmp = Path(work) / f".compose-check.{os.getpid()}.yml"
    except (OSError, ValueError, TypeError):
        return {"ok": False, "message": "invalid working directory"}
    try:
        Path(work).mkdir(parents=True, exist_ok=True)
        # create, not write: write_secret_text O_TRUNCs a pre-created
        # guessable ".compose-check.<pid>.yml" and fills it with the
        # same generated passwords as the live compose.
        if not secure_io.create_secret_text(tmp, content):
            tmp.unlink(missing_ok=True)
            if not secure_io.create_secret_text(tmp, content):
                return {"ok": False, "message": "temp compose file exists"}
        rc, text = run_capped(
            [DOCKER, "compose", "-f", str(tmp), "config", "-q"],
            cwd=work,
            timeout=30,
            env={**os.environ, "PATH": "/opt/homebrew/bin:/usr/local/bin:" + os.environ.get("PATH", "")},
            cap=800,
        )
        # _rc_int: the runner is a seam (tests and tooling patch it — the
        # docker10 rule), and the raw rc fed the ``== 0`` / ``== -1`` probes
        # below.  An int-subclass ``__eq__`` bomb was only saved by the
        # blanket except (misreporting the bomb's repr as a YAML error), and
        # junk must never read as the ``-1`` vanished-CLI sentinel: -255 is
        # no honest exit status, so it stays a plain "invalid" verdict.
        rc = _rc_int(rc)
        # Leftover bytes used to land in the JSON body; a leftover int
        # AttributeError'd .strip and was only saved by the blanket except.
        # _utf8_text, not a bare decode/str(): the "message" field goes to
        # Starlette verbatim on POST /api/compose/validate, so a lone
        # ``\ud800`` in the CLI text 500'd the UTF-8 encode *outside* this
        # function's blanket except, and ``str()`` of an already-int
        # leftover past CPython's digit cap is itself the ValueError.
        text = _utf8_text(text)
        ok = rc == 0
        unreachable = looks_engine_down(text) or (
            # FileNotFoundError spawn collapses to ``(-1, "not found")``.
            # Requiring ``not cli_on_disk()`` skipped this path on runners
            # that still have a docker binary (catalog leftover HTTP).
            # Forced ``engine_up`` below still refuses to classify while up.
            rc == -1 and looks_cli_vanished(text)
        )
        if not ok and unreachable and not engine_up(force=True):
            # The compose file may be perfectly valid: the CLI could not reach
            # the daemon.  Reporting that as "compose file is invalid" (400 on
            # save/create) told the operator their YAML was broken and pointed
            # away from the real remedy (start the engine).  The probe is
            # forced -- same convention as containers_svc._raise_list_failure:
            # the memoised answer has a 5s TTL and the seconds right after the
            # engine stops are when a stale "up" would misclassify this.  The
            # message-pattern guard matters too: ``docker compose config`` is
            # mostly client-side, so a genuine YAML error with the engine
            # coincidentally off must keep reporting the YAML error.
            return soft_fail("container.engine_down")
        return {
            "ok": ok,
            "message": (text or ("valid" if ok else "invalid")).strip()[:800],
        }
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        return {"ok": False, "message": exc_detail(e, 800)}
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except (OSError, ValueError):
            pass


def validate_stack(stack_id: str) -> dict:
    s = _find_stack(stack_id)
    data = get_compose(stack_id)
    # cwd from the os-level directory text, never the published scrubbed
    # twin: validate_compose_text mkdir()s its working directory, so the
    # ``?``-replacement text of a surrogateescape stack directory used to
    # *create a brand-new sibling tree* next to the real stack on every
    # validate click.  A genuinely unspawnable raw name falls back to the
    # clean ~/Services default via _spawnable_dir.
    # _row_get + _isa + exact-str copies (the row seam again): a bomb
    # ``os_path`` used to detonate the bare isinstance one line before
    # ``_spawnable_dir`` got a chance to refuse it.
    workdir = _row_get(s, "os_path")
    workdir = _disk_text(workdir) if _isa(workdir, str) else None
    if not workdir:
        raw = _row_get(s, "path")
        workdir = _disk_text(raw) if _isa(raw, str) else None
    return validate_compose_text(data["content"], cwd=_spawnable_dir(workdir))


def create_stack(stack_id: str, name: str | None, content: str) -> dict:
    """Create new stack under ~/Services/<id>/docker-compose.yml"""
    stack_id = cli_args.require_positional(stack_id, label="stack id", max_len=41)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,40}", stack_id):
        raise api_error("compose.bad_stack_id")
    # _disk_text, not a bare isinstance + bound decode (the direct-call
    # seam): a bytes-subclass ``.decode`` bomb used to detonate here raw.
    # Junk that is no text stays as-is — ``validate_compose_text`` is fully
    # guarded and answers the coded YAML refusal for it.
    text = _disk_text(content)
    if text is not None:
        content = _utf8_text(text)
    # _field_text probe before the name lands in services.yaml: a JSON body
    # ``{"name": "\ud800"}`` (json.loads accepts the escape) was persisted
    # verbatim — latent corruption every later reader had to re-scrub — and
    # a leftover already-int name past CPython's digit cap 503'd the mutate
    # (settings.save_failed) *after* the stack directory and compose file
    # were already created.  Unusable names fall back to the stack id.
    name = _field_text(name) or None
    # _home_path, not the bare seam: a raising provider escaped this call
    # and a textual answer TypeError'd the ``home / "Services"`` join two
    # lines down — both raw 500s on POST /api/compose (outside every try).
    home = _home_path()
    if home is None:
        raise api_error("compose.invalid", detail="home directory is unavailable")
    root = home / "Services" / stack_id
    try:
        taken = root.exists() and (root / "docker-compose.yml").exists()
    except (OSError, ValueError):
        # Dying FUSE/SMB: exists() re-raises EIO/ESTALE.
        taken = False
    if taken:
        raise api_error("compose.exists", path=str(root))
    v = validate_compose_text(content, cwd=str(home / "Services"))
    if not v.get("ok"):
        _raise_validation_failure(v)
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        # A leftover file occupying ~/Services/<id> used to FileExistsError 500.
        raise api_error("compose.exists", path=str(root))
    try:
        (root / "data").mkdir(exist_ok=True)
    except OSError:
        pass
    compose = root / "docker-compose.yml"
    # 0600 from the first byte, O_EXCL so exists() losing a race cannot
    # truncate an operator-edited compose.
    try:
        created = secure_io.create_secret_text(compose, content)
    except OSError:
        raise api_error("compose.exists", path=str(root))
    if not created:
        raise api_error("compose.exists", path=str(root))
    # Register in services.yaml stacks if not present, through config.mutate: it
    # re-reads inside the write lock, so this only ever *adds* the stack.  The old
    # save_full(deepcopy(cfg())) wrote a snapshot taken before the lock was held,
    # reverting whatever another process had committed since -- routine, not rare,
    # on a machine running the packaged app alongside a source checkout.
    from hub.config import mutate

    def apply(data: dict) -> None:
        stacks = data.get("stacks")
        if not isinstance(stacks, list):
            stacks = []
            data["stacks"] = stacks
        if any(isinstance(entry, dict) and entry.get("id") == stack_id for entry in stacks):
            return
        stacks.append({
            "id": stack_id,
            "name": name or stack_id,
            "path": str(root),
            "compose_file": "docker-compose.yml",
        })

    mutate(apply)
    inv()
    return {"ok": True, "path": str(compose), "id": stack_id}
