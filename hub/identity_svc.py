"""System identification (Unraid Identification settings)."""
from __future__ import annotations

import platform
import re
from pathlib import Path

from fastapi import HTTPException

from hub.config import cfg, update_settings
from hub.errors import api_error
from hub.host_address import configured_host, host_ip as effective_host_ip
from hub.util import LazyPool, sh, ttl_memo

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

_pool = LazyPool(7, "hub-identity")

#: The one binary :func:`set_identity` spawns.  Module-level so the
#: vanished-CLI probe re-checks the exact path the spawn used.
SCUTIL = "/usr/sbin/scutil"

#: Caps for the two free-text identity fields persisted into services.yaml.
#: Unbounded, a multi-MB PUT /api/identity used to be refused only by the
#: whole-file save cap — a settings.save_failed 503 that blamed the disk for
#: oversized input — and a value just under that cap crowded every sibling
#: writer toward it.  256 is generous for a server comment; 253 is the DNS
#: hostname maximum, which also covers any literal address.
MAX_COMMENT = 256
MAX_HOST_IP = 253


def _scutil_missing(rc, err) -> bool:
    """Whether an ``sh()`` result means scutil itself is gone.

    ``sh`` reports a FileNotFoundError spawn as ``(-1, "", "not found")`` — a
    sentinel, never a real scutil exit.  The sentinel alone must not classify:
    rc -1 is also what a timeout or a signal-killed run reports, so the disk
    is re-probed *on this failure path only* (the vms ``_cli_missing`` /
    docker ``cli_on_disk`` rule — a successful spawn never pays the stat).
    Timeouts keep their own sentinel and are deliberately not classified;
    an authorization failure is a real scutil exit and never matches.
    """
    # _rc_int: an rc-subclass ``__eq__``/``__ne__`` bomb from a patched/odd
    # ``sh`` used to detonate this bare probe out of PUT /api/identity.  A
    # bomb reads as -255, which is not the spawn sentinel, so the 503 is
    # still only ever raised after an honest sentinel plus the disk confirm.
    if _rc_int(rc) != -1 or _as_text(err).strip() != "not found":
        return False
    try:
        return not Path(SCUTIL).is_file()
    except (OSError, ValueError):
        # An unreadable /usr/sbin must not upgrade the failure to a 503.
        return False


def shutdown_executor() -> None:
    _pool.shutdown()


def _isa(value, kinds) -> bool:
    """``isinstance`` that a leftover ``__class__``-property bomb cannot 500.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property* —
    planted as the stored server comment — detonated ``_as_text``'s bytes
    gate itself and 500'd GET /api/identity (the dash9 host_address rule).
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _rc_int(rc) -> int:
    """Exact exit status for the ``==``/``!=`` probes; a bomb reads as failure.

    This module does not own ``sh`` (tests and tooling patch it), and an
    rc-*subclass* whose ``__eq__``/``__ne__`` raises used to detonate the
    bare ``rc == 0`` probes in ``get_identity``'s return dict — a raw 500
    on GET /api/identity (the health9 / dash9 host_address rule).  ``-255``
    is no honest exit status, so a bomb keeps the failure branch.
    """
    try:
        if type(rc) is bool:
            return int(rc)
        if _isa(rc, int):
            return int.__index__(rc)
        return int(rc)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return -255


def _sh3(value) -> tuple:
    """Exact ``(rc, out, err)`` storage from a possibly-poisoned ``sh`` answer.

    A real spawn always answers an exact 3-tuple, but this module does not
    own ``sh``, and the bare ``rc, out, err = sh(...)`` unpack dispatched
    into the *answer's* own iteration: a tuple/list subclass whose bound
    ``__iter__`` bombs, a lying-``__class__`` sequence impostor, or a torn
    two-field answer each raised straight out of :func:`get_identity`'s
    future reads and :func:`set_identity`'s scutil spawn — raw 500s on
    GET and PUT /api/identity that ``_rc_int`` alone never saw, because
    the crash happened one step before any rc probe (the vms/system
    ``_sh3`` rule).  The unbound base reads see the real C-level storage,
    so an honest answer in a subclass wrapper survives untouched — the
    vanished-spawn sentinel included — while junk degrades to
    ``(-255, "", "")``: nonzero (an unusable answer is not consent to
    claim success) and never the ``-1`` sentinel, so shape junk cannot
    forge the vanished-scutil 503 in :func:`_scutil_missing` either.
    """
    if type(value) is tuple:
        items = value
    elif _isa(value, tuple):
        try:
            items = tuple(tuple.__iter__(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return (-255, "", "")
    elif _isa(value, list):
        try:
            items = tuple(list.__iter__(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return (-255, "", "")
    else:
        return (-255, "", "")
    try:
        if len(items) != 3:
            return (-255, "", "")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return (-255, "", "")
    return items


def _spawn(argv, timeout) -> tuple:
    """One guarded spawn: an ``sh``-laundered 3-tuple even when the runner raises.

    ``hub.util.sh`` itself never raises — every failure is a return code —
    but this module does not own it, and :func:`set_identity` called it
    bare: a leftover runner that raises instead of answering 500'd
    PUT /api/identity after validation had already passed, and blew the
    fire-and-forget LocalHostName follow-up after ComputerName had already
    been set (the vms11 runner-seam rule).  A raising runner reads as
    ``(-255, "", "")`` — nonzero, and never the ``-1`` spawn *sentinel*,
    so it cannot forge the vanished-scutil 503: that stays reserved for an
    honest sentinel plus the on-disk confirm.
    """
    try:
        return _sh3(sh(argv, timeout=timeout))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return (-255, "", "")


def _as_text(value) -> str:
    """JSON-encodable scutil/sysctl field.  Leftover ``\\ud800`` used to 500 GET /api/identity."""
    decoded = None
    # _isa, not a bare isinstance: a ``__class__``-property bomb planted as
    # the stored comment used to detonate this gate one step ahead of the scrub.
    if _isa(value, (bytes, bytearray)):
        for base in (bytes, bytearray):
            try:
                decoded = base.decode(value, "utf-8", "replace")
                break
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
    if decoded is not None:
        value = decoded
    elif value is None:
        return ""
    else:
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
    # Unbound base encode (the modules6 rule): ``str()`` of a subclass whose
    # ``__str__`` answers *self* skips CPython's exact-str copy, so a leftover
    # bound ``encode`` bomb in sh output rode this line to a raw 500 on
    # GET /api/identity.
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
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


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb (fails False)."""
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _mapping_get(mapping, key, default=None):
    """Field read that a leftover hash-shadowing key cannot detonate.

    The laundered ``dict(raw)`` copy in :func:`get_identity` bypasses a
    subclass's bound ``.get``, but the C-level lookup still calls the
    *stored* key's ``__eq__`` when the probe's hash lands on its slot — a
    leftover key carrying ``hash("server_comment")`` with a raising
    ``__eq__`` used to 500 GET /api/identity straight out of the compare
    (the alerts/system_settings ``_mapping_get`` rule).
    """
    if not _isa(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return default


def _pick(value, fallback):
    """``value or fallback`` that a leftover ``__bool__`` bomb cannot 500."""
    return value if _truthy(value) else fallback


def _encodable(text: str) -> bool:
    """False for a lone surrogate — no encoder (scutil argv, Bonjour, JSON)
    can carry it, so it is a bad name, not a spawn-time ValueError."""
    try:
        text.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


@ttl_memo(300.0)
def platform_string() -> str:
    """``platform.platform()``, which is not the string formatting it looks like.

    On macOS it shells out twice: ``uname -p``, and then ``file -b`` on the Python
    binary via ``platform.architecture()``. ``platform.uname()`` is cached inside the
    standard library but ``architecture()`` is not, and two callers reaching it
    concurrently on a cold interpreter each pay -- which is what one
    ``/api/diagnostics`` bundle did, since both this module and the bundle header want
    the string. Single-flight, so they share one answer.

    Process-static in practice: the OS version and the interpreter do not change under
    a running panel.
    """
    # Leftover ``\\ud800`` in ``uname`` used to 500 GET /api/diagnostics
    # (``_diag_host`` / Tools About) under Starlette's UTF-8 encoder.
    return _as_text(platform.platform())


def get_identity() -> dict:
    # Seven independent reads that used to run partly in series: five in a pool, and
    # then `platform.platform()` (two spawns) and the LAN address (two more) after it,
    # in the return dict itself -- four spawns of pure tail on a request the Settings
    # page makes on every open. Nothing here feeds anything else, so it is one wave.
    f_host = _pool.submit(sh, ["/bin/hostname"], timeout=3)
    f_comp = _pool.submit(sh, ["/usr/sbin/scutil", "--get", "ComputerName"], timeout=3)
    f_local = _pool.submit(sh, ["/usr/sbin/scutil", "--get", "LocalHostName"], timeout=3)
    f_model = _pool.submit(sh, ["/usr/sbin/sysctl", "-n", "hw.model"], timeout=3)
    f_tz = _pool.submit(time_zone)
    f_platform = _pool.submit(platform_string)
    f_ip = _pool.submit(effective_host_ip)

    def _result(fut, fallback):
        try:
            return fut.result()
        except Exception:
            return fallback

    # `.result()` re-raises; one scutil/sysctl miss must not 500 Settings.
    # _sh3 on every triple: the futures absorb a *raising* sh, but a patched
    # sh that *answers* junk — a torn two-field tuple, a scalar, a sequence
    # subclass whose ``__iter__`` bombs — used to detonate these bare
    # unpacks themselves and 500 GET /api/identity one step ahead of the
    # _rc_int probes.
    rc, hostname, _ = _sh3(_result(f_host, (1, "", "")))
    rc2, comp, _ = _sh3(_result(f_comp, (1, "", "")))
    rc3, local, _ = _sh3(_result(f_local, (1, "", "")))
    rc4, model, _ = _sh3(_result(f_model, (1, "", "")))
    # _pick, not ``or``: these three answers come from seams this module
    # does not own (time_zone rides a patched sh; platform_string and
    # effective_host_ip are patched by tests and tooling), and a leftover
    # ``__bool__`` bomb answered into the bare ``or`` used to detonate the
    # truth test itself — a raw 500 on GET /api/identity before _as_text
    # ever saw the value.
    tz = _pick(_result(f_tz, ""), "")
    platform_name = _pick(_result(f_platform, ""), "")
    host_ip = _pick(_result(f_ip, ""), "")
    # dict.get + a laundered copy (the config.settings_section rule): a
    # leftover dict-*subclass* planted as the config root or the settings
    # block passes ``isinstance`` and its bound ``.get`` bomb used to raise
    # straight out of this read and 500 GET /api/identity.  The try around
    # ``cfg()`` itself and ``_isa`` on the root are the same rule one step
    # earlier: a raising config read or a ``__class__``-property bomb as
    # the root used to 500 the route before the laundering ever ran.
    try:
        root = cfg()
    except Exception:
        root = None
    raw = None
    if _isa(root, dict):
        try:
            raw = dict.get(root, "settings")
        except Exception:
            raw = None
    if _isa(raw, dict):
        try:
            s = dict(raw)
        except Exception:
            s = {}
    else:
        s = {}
    # Fallbacks (platform.node / machine, configured_host) used to skip
    # `_as_text`; leftover ``\ud800`` there 500'd GET /api/identity.
    # _rc_int on every probe: an rc-subclass ``__eq__`` bomb from a
    # patched/odd ``sh`` used to detonate the bare ``rc == 0`` reads here.
    # configured_host() under its own try: this module does not own the
    # host_address seam, and a raising provider ran bare inside the return
    # dict — the one identity field whose failure still 500'd the route
    # while its host_ip sibling (pool + _result) already degraded.
    try:
        host_cfg = configured_host()
    except Exception:
        host_cfg = ""
    # platform.node()/machine() under their own try (the configured_host
    # rule one block up): these are module-level seams tests and tooling
    # patch, and both ran bare inside the return dict — a raising machine()
    # 500'd GET /api/identity outright through the ``arch`` field, and a
    # raising node() did the same the moment the hostname spawn missed and
    # the fallback branch was actually taken.  Each now costs only its own
    # field, like every sibling above.
    try:
        node_name = platform.node()
    except Exception:
        node_name = ""
    try:
        machine = platform.machine()
    except Exception:
        machine = ""
    return {
        "hostname": _as_text(hostname if _rc_int(rc) == 0 else node_name),
        "computer_name": _as_text(comp) if _rc_int(rc2) == 0 else "",
        "local_hostname": _as_text(local) if _rc_int(rc3) == 0 else "",
        "model": _as_text(model if _rc_int(rc4) == 0 else machine),
        "platform": _as_text(platform_name),
        "arch": _as_text(machine),
        "host_ip": _as_text(host_ip),
        "host_ip_config": _as_text(host_cfg),
        # _pick, not ``or``: a leftover ``__bool__``-bomb comment value used
        # to detonate the truth test itself and 500 GET /api/identity.
        # _mapping_get, not the laundered ``.get``: a hash-shadowing key in
        # the stored settings raised inside the C-level compare the same way.
        "comment": _as_text(_pick(
            _mapping_get(s, "server_comment"),
            _pick(_mapping_get(s, "description"), ""),
        )),
        "timezone": _as_text(tz),
    }


@ttl_memo(60.0)
def time_zone() -> str:
    """The zone name behind /etc/localtime.

    Memoised because two of the sections in one ``/api/diagnostics`` bundle want it --
    ``get_datetime_info`` and ``get_identity`` -- and they run concurrently, so the
    read happened twice per request. The panel has no path that changes the timezone
    (the Settings page points the operator at System Settings for it), and the symlink
    does not move on its own, so a short TTL is enough and there is nothing to
    invalidate on.

    Single-flight matters here rather than incidentally: both callers sit inside the
    same fan-out, so without it they miss the cold cache together and each pays.

    The second probe is a fallback, not a second question: `ls -l` is tried first
    because it works when /etc/localtime is a regular file, and `readlink` covers the
    symlink case. Only one of them runs on a given host.
    """
    # _spawn + _rc_int (the get_identity seam rule): a raising or
    # shape-junk sh answer used to blow the unpack / the bare ``rc == 0``
    # out of this memoised probe instead of degrading to "unknown zone".
    rc, out, _ = _spawn(["/bin/ls", "-l", "/etc/localtime"], 3)
    text = _as_text(out)
    if _rc_int(rc) == 0 and "zoneinfo/" in text:
        return text.split("zoneinfo/")[-1].strip()
    rc, out, _ = _spawn(["/usr/bin/readlink", "/etc/localtime"], 3)
    text = _as_text(out)
    if "zoneinfo/" in text:
        return text.split("zoneinfo/")[-1].strip()
    return ""


def set_identity(computer_name: str | None = None, comment: str | None = None, host_ip: str | None = None) -> dict:
    """Update panel-stored identity; ComputerName needs user approval via scutil (may need admin)."""
    patch = {}
    msgs = []
    if comment is not None:
        # Scrubbed before it becomes YAML/JSON: a lone ``\ud800`` in the body
        # used to be persisted raw into services.yaml, where every consumer
        # had to re-scrub it forever (and the patch dict itself could never
        # be JSON-encoded again).
        comment_text = _as_text(comment)
        if len(comment_text) > MAX_COMMENT:
            raise api_error("identity.value_too_long", field="comment", max=MAX_COMMENT)
        patch["server_comment"] = comment_text
    if host_ip is not None:
        host_ip_text = _as_text(host_ip).strip()
        if len(host_ip_text) > MAX_HOST_IP:
            raise api_error("identity.value_too_long", field="host_ip", max=MAX_HOST_IP)
        patch["host_ip"] = host_ip_text
    if patch:
        # The saver is a seam this module does not own (tests and tooling
        # patch it, and hub.config's own failures arrive as coded
        # HTTPExceptions).  A leftover saver that raises a *plain* exception
        # used to 500 PUT /api/identity raw after validation had already
        # passed; the honest coded 503s (settings.save_failed /
        # settings.config_unreadable) still pass through untouched, and
        # anything else is laundered to the same coded save 503 — the save
        # cannot be claimed either way, so "Panel settings updated" is
        # never appended off a raise.
        try:
            update_settings(patch)
        except HTTPException:
            raise
        except Exception:
            raise api_error("settings.save_failed")
        msgs.append("Panel settings updated")
    if computer_name:
        name = str(computer_name).strip()
        if (
            not name
            or len(name) > 63
            or name.startswith("-")
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in name)
            or not _encodable(name)
        ):
            raise api_error("identity.bad_name")
        # Try without sudo first.  _spawn, not bare sh: a leftover runner
        # that raises — or answers a torn shape the unpack cannot take —
        # used to 500 PUT /api/identity here, after the panel settings
        # above had already been persisted.
        rc, out, err = _spawn([SCUTIL, "--set", "ComputerName", name], 5)
        # _rc_int: an rc-subclass ``__ne__`` bomb from a patched/odd ``sh``
        # used to detonate this bare probe and 500 PUT /api/identity; a bomb
        # reads as failure and takes the privileges-message branch.
        if _rc_int(rc) != 0:
            if _scutil_missing(rc, err):
                # A vanished scutil used to answer ok:true with a message
                # blaming administrator privileges — the rename was silently
                # lost.  Coded so the panel can say what actually happened.
                raise api_error("identity.scutil_missing")
            # Leftover ``\ud800`` in scutil stderr used to 500 PUT /api/identity.
            # _pick, not ``or``: a ``__bool__``-bomb stderr used to raise out
            # of the fallback chain itself before _as_text could scrub it.
            msgs.append(
                "Setting ComputerName needs administrator privileges: "
                + _as_text(_pick(err, out))
            )
        else:
            msgs.append("ComputerName set")
            # _spawn even though the answer is discarded: a raising runner
            # used to 500 the request here, after ComputerName had already
            # been renamed through the guarded spawn above.
            _spawn([SCUTIL, "--set", "LocalHostName", name.replace(" ", "-")[:63]], 5)
    try:
        identity = get_identity()
    except Exception:
        identity = {}
    if not isinstance(identity, dict):
        identity = {}
    return {
        "ok": True,
        "message": _as_text("; ".join(msgs) or "No changes"),
        "identity": identity,
    }
