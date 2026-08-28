"""VM management: UTM (utmctl) + OrbStack Linux machines (orbctl)."""
from __future__ import annotations

import re
import threading
import time
from typing import Any

from fastapi import HTTPException

from hub import cli_args, vm_console
from hub.config import override
from hub.errors import api_error
from hub.paths import ORBCTL, UTMCTL
from hub.util import cached_snapshot, fan_out, port_open, safe_json_loads, sh

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


# Short TTL shared by status feed, bookmarks, and /api/vms (dedupe utmctl/orbctl).
# Must stay LONGER than hub.status._STATUS_TTL (35s): the status feed is polled
# on that cadence, so a shorter TTL here guaranteed a miss on every refresh and
# paid ~390ms for utmctl+orbctl every single time.  Correctness after a VM
# start/stop comes from invalidate_vm_lists(), not from the TTL lapsing.
_LIST_TTL = 45.0



def invalidate_vm_lists():
    """Bust UTM/Orb list caches only (no status re-entry)."""
    _utm_snapshot.invalidate()
    _orb_snapshot.invalidate()


def _invalidate():
    invalidate_vm_lists()
    try:
        from hub.status import invalidate_status
        invalidate_status()
    except Exception:
        pass

# Common OrbStack distros for create UI
ORB_DISTROS = [
    "ubuntu", "debian", "fedora", "arch", "alpine", "centos",
    "rocky", "alma", "opensuse", "kali", "nixos",
]


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the bare type gates themselves — planted as a listing return
    (``_listing_rows`` raised through ``fan_out`` and 500'd GET /api/vms),
    a row value or mapping key inside the final ``_jsonable`` pass, an
    ``list_orb_machines`` return probed by ``_parse_id`` /
    ``utm_vm_running`` (a 500 on the action and the console-session mint),
    or a row in ``discover_vms``.  A real subclass still matches through
    the C-level type check; only a value that cannot answer what it is
    takes the non-matching branch (the storage_pool/system/status rule).
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _mapping_get(mapping, key, default=None):
    """Field read that a hostile mapping *key* cannot 500.

    The ups_svc/storage_pool rule this module's unbound ``dict.get`` calls
    never got: the unbound builtin bypasses a subclass ``.get`` override,
    but the hash probe still runs the *stored keys'* own ``__eq__`` — a
    leftover str-subclass key whose hash shadows the real key and whose
    ``__eq__`` raises used to detonate ``dict.get`` in ``_parse_id`` /
    ``utm_vm_running`` / ``discover_vms`` (a 500 on the action and the
    console mint, a lost status feed).  Only the shadowed field degrades
    to its default; sibling fields and rows keep their sane data.
    """
    if not _isa(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return default


def _override(sid) -> dict:
    """Per-row override read that a leftover config bomb cannot cost rows.

    ``config.override`` reads ``cfg()`` bare, so a snapshot provider that
    raises took the *whole* UTM/Orb listing with it (``_listing_rows``
    swallowed the raise into ``[]``), and the laundering ``dict(val)`` copy
    keeps hostile hash-shadowing keys — a bombing ``ov.get("hide")`` also
    cost every row.  Here the read degrades to ``{}`` and each field is
    fetched via :func:`_mapping_get`, so only the poisoned override is lost.
    """
    try:
        ov = override(sid)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return {}
    if type(ov) is dict:
        return ov
    if not _isa(ov, dict):
        return {}
    try:
        return dict(ov)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return {}


def _truthy(value) -> bool:
    """Truthiness that a leftover value's ``__bool__`` bomb cannot 500."""
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _rc_int(value) -> int:
    """Exact int from an ``sh()`` return code; junk reads as -255.

    ``rc == 0`` / ``rc != -1`` ran a leftover int-subclass's own
    ``__eq__`` / ``__ne__`` — one bombed rc from a poisoned runner 500'd
    the action reply (the ``ok``/``message`` assembly runs outside every
    listing catch) straight through ``_cli_missing``.  ``int.__index__``
    reads the real value underneath a subclass override; a *lying*
    ``__class__`` impostor (claims int over no real int storage — the
    vms10 class) TypeErrors on the unbound read and drops with the junk.

    Junk degrades to ``-255`` (the shares10/network10/tools10 rule), never
    ``-1``: that value is the ``sh`` spawn-failure *sentinel*, and a junk
    rc that read as -1 could forge the vanished-CLI classifier in
    :func:`_cli_missing` — a coded 503 minted out of a poisoned object
    instead of a real missing binary.  -255 is no honest exit status, so
    junk always keeps the plain failure branch.  An over-cap exact int
    (>4300 digits — YAML/JSON hex leftovers dodge the parse-time caps) is
    unrenderable by any log line or encoder and reads as junk too.
    """
    if type(value) is int:
        rc = value
    elif value is True:
        return 1
    elif value is False:
        return 0
    elif _isa(value, int):
        try:
            rc = int.__index__(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
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
    own ``sh`` (tests and tooling patch it), and the bare
    ``rc, out, err = sh(...)`` unpack dispatched into the answer's own
    iteration: a tuple/list *subclass* whose bound ``__iter__`` bombs — or
    a lying ``__class__`` impostor claiming tuple/list over no real
    sequence storage — raised straight out of ``_utm_action`` /
    ``_orb_action`` / ``_utm_status`` / ``create_orb_machine`` (raw 500s
    on POST /api/vms/{id}/action and /api/vms/create, outside every
    listing catch) and threw whole inventories away through the
    ``_listing_rows`` catch (the network10 ``_sh_triple`` rule).  The
    unbound base reads see the real C-level storage, so an honest answer
    in a subclass wrapper survives untouched — the vanished-spawn sentinel
    included — while junk degrades to ``(-255, "", "")``: nonzero (a
    poisoned answer is not consent to claim success) and never the ``-1``
    sentinel (an unusable answer cannot forge the vanished-CLI 503).
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
            items = tuple(list.__getitem__(value, slice(None)))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return (-255, "", "")
    else:
        return (-255, "", "")
    if len(items) != 3:
        return (-255, "", "")
    return items


def _spawn(argv, timeout) -> tuple:
    """One guarded spawn: an ``sh``-laundered 3-tuple even when the runner raises.

    ``hub.util.sh`` itself never raises — every failure is a return code —
    but this module does not own it (tests and tooling patch it, the same
    seam ``_sh3`` launders for the *answer shape*), and every spawning
    action called it bare: a leftover runner that raises instead of
    answering 500'd POST /api/vms/{id}/action and /api/vms/create outside
    every listing catch, escaped ``_utm_status`` into the console-session
    mint (``utm_vm_running``'s try only covers the listing read), and blew
    the fire-and-forget ``utmctl stop --force`` inside the delete action
    after its status probe had already answered.  The files14/catalog12
    runner-seam rule: a raising runner reads as ``(-255, "", "")`` —
    nonzero (a runner that cannot answer is not consent to claim success)
    and never the ``-1`` spawn *sentinel*, so it cannot forge the
    vanished-CLI 503 in :func:`_cli_missing` either (the ``_rc_int`` junk
    rule).  The listings inherit the same degrade: a raising runner loses
    that inventory refresh, never the route.
    """
    try:
        return _sh3(sh(argv, timeout=timeout))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return (-255, "", "")


def _bin_present(path) -> bool:
    if not path:
        return False
    try:
        return __import__("pathlib").Path(path).exists()
    except (OSError, TypeError, ValueError):
        # Dying FUSE/SMB mounts raise EIO; a NUL leftover raises ValueError.
        return False


def _utm_available() -> bool:
    return _bin_present(UTMCTL)


def _orb_available() -> bool:
    return _bin_present(ORBCTL)


def _cli_missing(rc, err, binary) -> bool:
    """Whether an ``sh()`` result means the hypervisor CLI itself is gone.

    ``sh`` reports a FileNotFoundError spawn as ``(-1, "", "not found")`` — a
    sentinel, never a real utmctl/orbctl exit.  The availability check runs
    before the spawn, so an uninstall in between used to answer the action
    with an uncoded ``{ok: false, message: "not found"}`` instead of the same
    coded 503 the up-front check raises.  A timeout keeps its own sentinel and
    is deliberately not classified: a slow CLI is not a missing one.

    The sentinel alone used to classify.  rc -1 is also what a signal-killed
    run reports, so a *still-present* CLI that printed exactly ``not found``
    and died mid-request was answered with the vanished-binary 503 instead of
    its raw result — the same "defer to a fresh probe" rule the docker paths
    follow via ``engine_up``.  The disk re-check runs only on this failure
    path (after the sentinel matched), never on a successful spawn.
    """
    # _rc_int, not bare ``rc != -1``: a leftover int-subclass rc whose
    # ``__ne__`` raises detonated the classifier itself, one line ahead of
    # the disk re-check.  Junk reads -255 there, never -1 — so a poisoned
    # rc beside a leftover "not found" stderr can no longer forge the
    # vanished-CLI 503; only the real spawn sentinel reaches the disk
    # confirm below.
    if _rc_int(rc) != -1 or _as_text(err).strip() != "not found":
        return False
    return not _bin_present(binary)


def _decode_bytes(value) -> str | None:
    """Unbound base decode; ``None`` when *value* only lies about being bytes.

    The unbound call bypasses a leftover subclass ``.decode`` bomb, but it
    used to run *outside* any try — so a lying ``__class__`` impostor
    (passes the ``_isa`` bytes gate over no real byte storage — the vms10
    class) TypeError'd the launder itself and 500'd the action reply and
    the final ``_jsonable`` pass one line ahead of every scrub.  ``None``
    lets each caller fall back to its own junk rendering.
    """
    try:
        for base in (bytes, bytearray):
            try:
                return base.decode(value, "utf-8", "replace")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
        return None
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _as_text(value) -> str:
    """Drop leftover ``\\ud800`` so GET /api/vms cannot UTF-8 500."""
    if _isa(value, (bytes, bytearray)):
        # Unbound base decode: ``bytes(value)`` ran a subclass ``__bytes__``
        # bomb, and the bound ``.decode`` was the subclass's own — either one
        # 500'd the action reply (``_utm_action`` message assembly runs
        # outside every listing catch).  A lying-``__class__`` impostor
        # answers None and renders like any other junk object below.
        decoded = _decode_bytes(value)
        if decoded is not None:
            value = decoded
    if value is None:
        return ""
    if not _isa(value, str):
        # str instances skip str(): a subclass ``__str__`` bomb would trade
        # the real text for "", and a ``__str__`` that answers *self* skips
        # CPython's exact-str copy anyway.
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
    # Unbound base encode (the hub.modules._utf8_text rule): a str subclass
    # carrying a bound ``encode`` bomb rode this line to a 500 on
    # POST /api/vms/{id}/action and threw away the whole UTM listing on
    # GET /api/vms.  The round-trip also hands back an exact str, so the
    # ``.strip()`` / ``or`` that follow cannot hit another override.
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
        try:
            value = str(value)
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


def _display_text(value, fallback: str = "") -> str:
    """JSON-safe display string for a leftover YAML/JSON field.

    ``name: .inf``, ``group: 2026-08-19``, ``!!binary`` and a ``!!set`` each
    used to leak into GET /api/vms and fail Starlette's allow_nan=False encoder.

    ``_isa`` on every type gate, not bare ``isinstance``: a leftover whose
    ``__class__`` is a raising property detonated the first gate itself.
    """
    if value is None or _isa(value, bool):
        return fallback
    if _isa(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return fallback
        if value != value or value in (float("inf"), float("-inf")):
            return fallback
        return str(value)
    if _isa(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__float__``
                # bomb used to blow the overflow probe, and one *lying*
                # about a >4300-digit value smuggled it into ``str()``,
                # whose digit-cap ValueError 500'd the caller.
                value = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return fallback
        try:
            float(value)
        except OverflowError:
            return fallback
        return str(value)
    if _isa(value, str):
        # Unbound exact-str copy through the C storage: a lying
        # ``__class__`` impostor claiming str TypeErrors here and takes
        # the fallback instead of detonating ``_as_text``'s encode (the
        # shares10 ``str.__str__`` launder).
        try:
            value = str.__str__(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return fallback
        return _as_text(value)
    if _isa(value, (bytes, bytearray)):
        text = _decode_bytes(value)
        return text if text is not None else fallback
    if _isa(value, (dict, list, tuple, set, frozenset)):
        return fallback
    try:
        text = str(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return fallback
    # Scrub before the truthiness test: ``str()`` may hand back a subclass
    # (a ``__str__`` answering *self*) whose ``__bool__`` raises.
    text = _as_text(text)
    return text if text else fallback


def _optional_text(value) -> str | None:
    text = _display_text(value, "")
    return text or None


def _id_text(value, fallback: str) -> str:
    """Machine id/uuid from leftover orbctl JSON: Infinity/objects are not ids."""
    if _isa(value, str):
        # Unbound exact-str copy first: a lying ``__class__`` impostor
        # claiming str used to detonate ``_as_text``'s encode; it reads as
        # no id at all, never as its repr.
        try:
            value = str.__str__(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return fallback
        # Scrub before the truthiness test: a str-subclass ``__bool__`` bomb
        # used to raise out of ``_orb_item`` and cost the whole listing.
        text = _as_text(value)
        return text if text else fallback
    if _isa(value, int) and not _isa(value, bool):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__float__``
                # bomb (or one lying about a >4300-digit value, whose
                # ``str()`` then ValueError'd on the digit cap) cannot 500.
                value = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return fallback
        try:
            float(value)
        except OverflowError:
            return fallback
        return str(value)
    return fallback


def _jsonable(value, depth: int = 0):
    """Drop leftover inf/bytes/huge ints/``\\ud800`` so Starlette cannot 500 GET /api/vms.

    Subclass bombs (the hub.modules._jsonable unbound convention this copy
    never got) each 500'd GET /api/vms straight through this final guard: a
    dict row whose ``items()`` raises, a container whose ``__iter__``
    raises, a float whose ``__eq__`` blows the NaN/inf probes, an int whose
    ``__float__`` blows the overflow probe (or lies past it, so the encoder
    itself ValueError'd on a >4300-digit render), bytes whose ``decode``
    raises, a str carrying a bound ``encode`` bomb, and an ``isoformat``
    probe on an object whose ``__getattr__`` raises (getattr's default only
    swallows AttributeError).

    ``_isa`` on every gate, not bare ``isinstance``: this pass runs
    *outside* the ``_listing_rows`` catch, so a leftover row value — or a
    mapping key — whose ``__class__`` is a raising property detonated the
    first gate itself and 500'd GET /api/vms one line ahead of every scrub
    below.
    """
    if depth > 32:
        return None
    if value is None or type(value) is bool:
        # ``type``, not ``_isa``: bool admits no subclass, so anything that
        # only *claims* bool through a lying ``__class__`` used to pass
        # this gate raw and 500 the response encoder one layer later (the
        # vms10 bool-liar class).  A liar falls through and degrades at
        # the int gate like any other junk.
        return value
    if _isa(value, float):
        if type(value) is not float:
            try:
                value = float.__float__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isa(value, (bytes, bytearray)):
        # None marks a lying-``__class__`` impostor: no byte storage to
        # decode, and nothing below can match what it claims to be.
        return _decode_bytes(value)
    if _isa(value, dict):
        # Unbound base view: a dict-subclass row whose ``items()`` raises
        # cannot 500, and the real storage underneath still comes through.
        # In a try: a lying impostor claiming dict TypeErrors on the view
        # itself, which used to 500 GET /api/vms out of this final pass.
        try:
            pairs = dict.items(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
        out = {}
        for k, v in pairs:
            if _isa(k, (bytes, bytearray)):
                key = _decode_bytes(k)
            elif _isa(k, str):
                key = k
            else:
                key = None
            if key is None:
                # Non-text keys and lying-``__class__`` impostor keys
                # (their unbound decode answered None) render as repr.
                try:
                    key = str(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            out[_as_text(key)] = _jsonable(v, depth + 1)
        return out
    if _isa(value, (list, tuple, set, frozenset)):
        for base in (list, tuple, set, frozenset):
            if _isa(value, base):
                # Unbound base iteration: a subclass ``__iter__`` bomb
                # cannot 500 and the real elements still survive.  In a
                # try: a lying impostor claiming list/tuple TypeErrors on
                # the unbound read itself — it degrades instead of 500ing.
                try:
                    return [_jsonable(v, depth + 1) for v in base.__iter__(value)]
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    return None
    if _isa(value, int):
        if type(value) is not int:
            try:
                value = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        try:
            float(value)
        except OverflowError:
            return None
        return value
    if _isa(value, str):
        return _as_text(value)
    try:
        iso = getattr(value, "isoformat", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # getattr's default only swallows AttributeError; a property or
        # ``__getattr__`` bomb still raised out of the probe itself.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/vms.
            return _jsonable(iso(), depth + 1)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    return None


def _rows_list(value) -> list:
    """Exact list from a possibly-poisoned listing/pool answer; junk reads [].

    The laundering half of :func:`_listing_rows`, split out because the
    *pool* answers need it too: this module does not own ``fan_out`` (tests
    and tooling patch it, the same seam :func:`_spawn` launders for the
    runner), and the batch it hands back rode into bare unpacks and ``+``
    concatenation with no gate of its own.  ``_isa`` on the gates and
    unbound base iteration, for the same reasons as everywhere else: a
    ``__class__``-property bomb, a subclass ``__iter__`` bomb, or a lying
    impostor claiming list/tuple each degrade to [] instead of raising.
    """
    for base in (list, tuple):
        if _isa(value, base):
            try:
                return [row for row in base.__iter__(value)]
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return []
    return []


def _listing_rows(probe) -> list:
    """One hypervisor's inventory, or [] if that listing is leftover/broken.

    ``fan_out`` re-raises, so a single ``utmctl`` blow-up used to 500 GET /api/vms
    (including the OrbStack rows that had already succeeded).  The ``_isa``
    gate and unbound base iteration live in :func:`_rows_list`: a probe
    answering a leftover whose ``__class__`` is a raising property (or whose
    subclass ``__iter__`` bombs) used to detonate *outside* this try,
    re-raise through ``fan_out`` and 500 GET /api/vms with both inventories.
    """
    try:
        rows = probe()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []
    return _rows_list(rows)


def _listing_pair(answers) -> tuple[list, list]:
    """Exactly two laundered inventories from a possibly-poisoned pool answer.

    ``hub.util.fan_out`` maps :func:`_listing_rows` in order and never
    raises past its guarded workers — but this module does not own the pool
    (tests and tooling patch it, the ``wireguard_svc.installation`` rule),
    and ``list_all_vms`` unpacked its answer *bare*, outside every listing
    catch: a pool that raises, answers None / a scalar / a wrong-length
    batch, a tuple-subclass whose ``__iter__`` bombs, or a right-length
    pair of non-list junk each 500'd GET /api/vms raw — and, through the
    same call, the Apps inventory and the settings export that embed it.
    Junk reads as two empty inventories: a pool that cannot answer loses
    that refresh, never the route.
    """
    items = _rows_list(answers)
    if len(items) != 2:
        return [], []
    return _rows_list(items[0]), _rows_list(items[1])


def _probe_port(port) -> bool | None:
    """Port reachability that never raises, so one VM cannot cost the listing.

    ``fan_out`` re-raises on iteration, which would turn a single unreachable
    host into an empty VM list rather than one row reading "warn".
    """
    try:
        return port_open(port)
    except Exception:
        return False


def _list_utm_vms_uncached() -> list[dict]:
    if not _utm_available():
        return []
    rc, out, err = _spawn([UTMCTL, "list"], 10)
    if _rc_int(rc) != 0:
        return []
    out = _as_text(out)
    # Parsed first, probed second, assembled third.  The per-VM work in the old
    # single loop was a TCP connect against the VM's configured port, which costs
    # the full 0.6s timeout whenever the guest is not listening yet -- so a host
    # with several port-mapped VMs paid that serially on every refresh.  Parsing
    # and override lookups stay on this thread; only the socket waits fan out.
    rows = []
    for line in out.splitlines()[1:]:
        # UUID Status Name (name may have spaces)
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        uuid, status, name = _as_text(parts[0]), _as_text(parts[1]), _as_text(parts[2])
        # _override / _mapping_get: a raising ``config.override`` (a cfg
        # snapshot provider bomb) or a laundered override that kept a
        # hash-shadowing key bomb used to raise out of this per-row loop and
        # cost the *whole* UTM inventory via the ``_listing_rows`` catch.
        ov = _override(name) or _override(uuid) or {}
        if _truthy(_mapping_get(ov, "hide")):
            continue
        rows.append({"uuid": uuid, "status": status, "name": name, "ov": ov})

    # None where no port is configured, matching the previous conditional.
    # _truthy, not a bare ``if port``: a leftover override port whose
    # ``__bool__`` raises used to detonate inside the fan_out worker,
    # re-raise on iteration and cost the *whole* UTM inventory through the
    # ``_listing_rows`` catch instead of degrading one row's probe.
    #
    # The pool call itself is guarded too (the _listing_pair rule): this
    # module does not own ``fan_out``, and a pool that raises — or answers
    # a junk shape, which the bare ``zip`` below silently *truncated the
    # rows to* — used to throw every already-parsed row away through the
    # ``_listing_rows`` catch.  A poisoned pool now loses only the port
    # probes (each row reads as unprobed, exactly like a row with no
    # configured port), never the inventory.
    try:
        probes = fan_out(
            lambda port: _probe_port(port) if _truthy(port) else None,
            [_mapping_get(row["ov"], "port") for row in rows],
        )
    except Exception:
        probes = []
    probes = _rows_list(probes)
    if len(probes) != len(rows):
        probes = [None] * len(rows)

    items = []
    for row, p in zip(rows, probes):
        uuid, status, name, ov = row["uuid"], row["status"], row["name"], row["ov"]
        started = status in ("started", "running")
        suspended = status in ("paused", "suspended")
        stopped = status in ("stopped", "stop", "shutdown")
        # ok=运行 / warn=挂起或端口异常 / stopped=主动停止(灰) / down=意外异常(红)
        if started and p is False:
            state = "warn"
        elif started:
            state = "ok"
        elif suspended:
            state = "warn"
        elif stopped:
            state = "stopped"
        else:
            state = "down"
        actions = []
        if started:
            actions = ["stop", "restart", "suspend", "ip", "rename"]
        elif suspended:
            actions = ["start", "stop", "delete", "rename"]
        else:
            actions = ["start", "clone", "delete", "rename"]
        items.append({
            "id": name,
            "uuid": uuid,
            # Console authorisation is keyed by UUID, never by the display name:
            # renaming a VM must not move an allowlist entry to another machine.
            "console_id": vm_console.console_id_for_utm(uuid),
            "console": vm_console.capability(backend="utm", vm_uuid=uuid, running=started),
            "name": _display_text(_mapping_get(ov, "name"), name) or name,
            "backend": "utm",
            "status": status,
            "state": state,
            "detail": f"UTM · {status}",
            "url": _optional_text(_mapping_get(ov, "url")),
            "group": _display_text(_mapping_get(ov, "group"), "UTM") or "UTM",
            "actions": actions,
            "ips": [],
        })
    return items


@cached_snapshot(_LIST_TTL)
def _utm_snapshot() -> list[dict]:
    return _list_utm_vms_uncached()


def list_utm_vms(force: bool = False) -> list[dict]:
    """UTM inventory, cached for _LIST_TTL with one in-flight refresh.

    The copy is deliberate and predates the shared helper: callers concatenate and
    sort these lists, and handing out the cached object would let one of them mutate
    what every later reader sees.

    The lock used to be released before `_list_utm_vms_uncached()` ran, so
    overlapping callers all missed and each spawned its own `utmctl list` plus a port
    probe per VM.
    """
    return list(_utm_snapshot(force))


def _capped_json_int(digits: str):
    """``json.loads`` *parse_int* hook that survives >4300-digit literals.

    ``json.loads`` of a number past CPython's digit cap raises ValueError —
    NOT JSONDecodeError — for the whole document, so one leftover huge field
    in ``orbctl list -f json`` used to throw away every machine's JSON row
    (uuid, distro, console capability) and fall to the degraded text listing
    — or to nothing when that second spawn failed too.  A number past the
    cap cannot be rendered by any JSON encoder anyway, so it loads as None
    and only its own field is lost (the docker_cli.parse_int_capped drop).
    """
    try:
        return int(digits)
    except ValueError:
        return None


def _list_orb_machines_uncached() -> list[dict]:
    if not _orb_available():
        return []
    # orbctl list -f json if available, else text
    rc, out, err = _spawn([ORBCTL, "list", "-f", "json"], 15)
    items: list[dict] = []
    out = _as_text(out)
    if _rc_int(rc) == 0 and out.strip().startswith(("[", "{")):
        try:
            data = safe_json_loads(out, parse_int=_capped_json_int)
        except (TypeError, ValueError, RecursionError):
            # RecursionError: leftover deeply-nested ``orbctl list -f json``
            # is not ValueError; GET /api/vms used to 500.
            data = None
        except Exception:
            # This module does not own the loader either (the _spawn /
            # _listing_pair seam rule): one that raises outside the typed
            # set above used to skip the degraded ``orbctl list`` text
            # fallback below and throw the whole OrbStack inventory away
            # through the ``_listing_rows`` catch.  An unusable JSON parse
            # loses the JSON rows, never the text listing.
            data = None
        try:
            if data is not None:
                if isinstance(data, dict):
                    data = data.get("machines") or data.get("items") or []
                if not isinstance(data, list):
                    data = []
                for m in data:
                    if not isinstance(m, dict):
                        continue
                    # orbctl JSON names must be strings. Coercing ``name: 1``
                    # used to invent a machine called "1" on GET /api/vms.
                    raw_name = m.get("name")
                    if raw_name is None:
                        raw_name = m.get("Name")
                    if raw_name is None:
                        raw_name = m.get("id")
                    if not isinstance(raw_name, str):
                        continue
                    name = _as_text(raw_name).strip()
                    if not name:
                        continue
                    raw_status = m.get("state") or m.get("status") or m.get("Status") or ""
                    if not isinstance(raw_status, str):
                        raw_status = str(raw_status) if raw_status is not None else ""
                    status = _as_text(raw_status).lower()
                    item = _orb_item(name, status, m)
                    if item:
                        items.append(item)
                if items:
                    return items
        except Exception:
            pass
    rc, out, err = _spawn([ORBCTL, "list"], 15)
    if _rc_int(rc) != 0:
        return []
    # parse table: NAME  STATE  ...
    lines = [ln for ln in _as_text(out).splitlines() if ln.strip()]
    if not lines:
        return []
    # skip header if present
    start = 1 if re.search(r"name|state|status", lines[0], re.I) else 0
    for line in lines[start:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        name, status = _as_text(parts[0]), _as_text(parts[1]).lower()
        if name.lower() in ("name", "id"):
            continue
        item = _orb_item(name, status, {})
        if item:
            items.append(item)
    return items


@cached_snapshot(_LIST_TTL)
def _orb_snapshot() -> list[dict]:
    return _list_orb_machines_uncached()


def list_orb_machines(force: bool = False) -> list[dict]:
    """OrbStack inventory. Copied and single-flight for the same reasons as above."""
    return list(_orb_snapshot(force))


def _orb_item(name: str, status: str, raw: dict) -> dict | None:
    name, status = _as_text(name), _as_text(status)
    # _override / _mapping_get: same per-row degrade as the UTM builder — a
    # raising override read or a hash-shadowing key bomb loses only this
    # row's override, never the whole OrbStack inventory.
    ov = _override(f"orb-{name}") or _override(name) or {}
    if _truthy(_mapping_get(ov, "hide")):
        return None
    running = status in ("running", "started", "up")
    stopped = status in ("stopped", "stop", "exited", "created", "shutdown")
    if running:
        state = "ok"
    elif stopped or not status:
        state = "stopped"
    else:
        state = "down"
    if running:
        actions = ["stop", "restart", "shell", "delete", "rename"]
    else:
        actions = ["start", "delete", "clone", "rename"]
    uuid = _id_text(_mapping_get(raw, "id"), name)
    distro = _mapping_get(raw, "distro") or _mapping_get(raw, "image") or ""
    return {
        "id": f"orb:{name}",
        "uuid": uuid,
        "name": _display_text(_mapping_get(ov, "name"), name) or name,
        "orb_name": name,
        "backend": "orb",
        "status": status or "unknown",
        "state": state,
        "detail": f"OrbStack · {status or 'unknown'}",
        "url": _optional_text(_mapping_get(ov, "url")),
        "group": _display_text(_mapping_get(ov, "group"), "OrbStack Linux") or "OrbStack Linux",
        "actions": actions,
        "distro": _display_text(distro, ""),
        "ips": [],
        # OrbStack Linux machines are headless by design.  Reporting the reason
        # (rather than omitting the key) lets the UI explain why there is no
        # console button instead of rendering one that could never connect.
        "console_id": None,
        "console": vm_console.capability(backend="orb", vm_uuid=uuid, running=running),
    }


def list_all_vms() -> dict:
    """Both hypervisors' inventories.

    UTM and OrbStack are separate binaries that know nothing about each other, so
    one listing does not inform the other. `fan_out` keeps them in order, which is
    what puts UTM's rows ahead of OrbStack's in the combined list.
    """
    # Guarded pool call + _listing_pair, not a bare 2-way unpack: the pool
    # seam is not this module's to trust (see _listing_pair) and this is
    # the one fan_out whose answer rode straight into the route.
    try:
        answers = fan_out(
            _listing_rows, [list_utm_vms, list_orb_machines], max_workers=2
        )
    except Exception:
        answers = ([], [])
    utm, orb = _listing_pair(answers)
    return _jsonable({
        "vms": utm + orb,
        "utm_count": len(utm),
        "orb_count": len(orb),
        "utm_available": _utm_available(),
        "orb_available": _orb_available(),
        "utmctl": UTMCTL,
        "orbctl": ORBCTL,
        "orb_distros": ORB_DISTROS,
    })


def discover_vms() -> list:
    """Status feed format for services dashboard."""
    items = []
    for v in _listing_rows(list_utm_vms) + _listing_rows(list_orb_machines):
        if not _isa(v, dict):
            continue
        # _mapping_get, and laundered text for the ``==`` / ``or`` probes: a
        # leftover dict-subclass row with a bombing ``.get`` (unbound
        # ``dict.get`` bypasses it), a hash-shadowing key bomb (the unbound
        # builtin's probe still ran the stored key's ``__eq__``), a row whose
        # ``__class__`` is a raising property (the bare ``isinstance`` gate
        # detonated), or a state/group whose reflected ``__eq__`` /
        # ``__bool__`` raises each used to take the whole status feed with
        # it.  The emitted values are sealed by the final ``_jsonable`` pass.
        state = _display_text(_mapping_get(v, "state"), "")
        if state == "ok":
            actions = ["restart", "stop"]
        else:
            actions = ["start"]
        group = _display_text(_mapping_get(v, "group"), "")
        items.append({
            "id": _mapping_get(v, "id"),
            "kind": "vm",
            "name": _mapping_get(v, "name"),
            "state": _mapping_get(v, "state"),  # ok | warn | stopped | down
            "detail": _mapping_get(v, "detail"),
            "url": _mapping_get(v, "url"),
            "group": group or "Virtual Machines",
            "actions": actions,
            "backend": _mapping_get(v, "backend"),
        })
    return _jsonable(items) or []


def rename_vm_display(vm_id: str, new_name: str) -> dict:
    """Rename display name via services.yaml overrides (utmctl has no rename)."""
    from hub.config import set_override

    if not isinstance(new_name, str) or not new_name.strip():
        raise api_error("vms.name_required")
    # _as_text: a JSON ``"\ud800"`` name (a lone surrogate — json.loads accepts
    # the escape, Starlette's UTF-8 response encode does not) used to be stored
    # verbatim in the override and echoed back, so the rename was already
    # applied when the response render raised a bare 500.
    new_name = _as_text(new_name).strip()
    if not new_name:
        raise api_error("vms.name_required")
    # Bounded because it is *persisted*: the override lands in services.yaml,
    # and an unbounded name (one 2MB rename was enough) grew the file past
    # config._YAML_CAP — after which every cfg() read answered {} and the next
    # mutate() rewrote the config from that emptiness, wiping the admin
    # account and every sibling key.  64 matches accounts/apikeys/disk names.
    if len(new_name) > 64:
        raise api_error("vms.name_too_long")
    backend, name = _parse_id(vm_id)
    name = (name or "").strip()
    if not name:
        raise api_error("vms.name_required")
    # key used by list_* for overrides
    if backend == "orb":
        key = name  # override(name) or override(orb-name)
        # prefer existing key.  _override, not the raw config read: a
        # leftover cfg snapshot provider bomb (or a returned object whose
        # ``__bool__`` raises under the bare truthiness probe) used to
        # 500 the rename action here, one call ahead of the write (vms10;
        # the listings got the same guard in vms9).
        if _override(f"orb-{name}"):
            key = f"orb-{name}"
        else:
            key = name
    else:
        key = name
    try:
        set_override(key, {"name": new_name})
    except HTTPException:
        # mutate() already answers coded refusals (settings.config_unreadable
        # for an unparseable services.yaml) — keep them.
        raise
    except Exception:
        # The write funnels through cfg()/mutate(); a leftover snapshot
        # provider bomb or an unwritable services.yaml used to answer a
        # raw 500.  Nothing was persisted, so report the same coded 503
        # every other failed config persist answers.
        raise api_error("settings.save_failed")
    _invalidate()
    return {"ok": True, "action": "rename", "id": vm_id, "name": new_name, "message": f"Display name changed to {new_name}"}


def _argv_name(value: str, *, code: str = "vms.bad_id") -> str:
    """A VM name that cannot be read as a utmctl/orbctl option.

    UTM display names may contain spaces (``Windows 11``), so this is not
    :func:`cli_args.require_positional`.  A leading hyphen is enough to turn
    ``utmctl start --help`` / ``orbctl clone src --all``.
    """
    text = str(value or "").strip()
    if (
        not text
        or len(text) > 255
        or text.startswith("-")
        or any(ord(c) < 0x20 or ord(c) == 0x7F for c in text)
    ):
        # 255: cli_args.MAX_POSITIONAL_LEN.  No listed machine has a longer
        # name, and an unbounded one rode into utmctl/orbctl argv (and, via
        # rename, into the services.yaml override key).
        raise api_error(code)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate (JSON ``"\ud800"`` body, a services.yaml leftover
        # routed through actions.py) can never name a listed machine — the
        # listings are UTF-8-cleaned — and echoing it back in ``id`` or the
        # ``orb -m {name}`` shell hint used to 500 Starlette's UTF-8 encode.
        raise api_error(code)
    return text


def _parse_id(vm_id: str) -> tuple[str, str]:
    """Return (backend, name)."""
    raw = str(vm_id or "").strip()
    if not raw or any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
        raise api_error("vms.bad_id")
    if raw.startswith("orb:"):
        return "orb", _argv_name(raw[4:])
    # Refused before the UUID shape, not after it: ``-`` is inside the class,
    # so a 36-char dash-led id (``-…`` / all dashes) *matched* the uuid branch
    # and rode into ``utmctl start {ident}`` argv as an option — the exact
    # injection ``_argv_name`` closes for every non-uuid name.  A real UUID
    # starts with a hex digit, never a hyphen.
    if raw.startswith("-"):
        raise api_error("vms.bad_id")
    # uuid style → utm
    if re.match(r"^[0-9A-Fa-f-]{36}$", raw):
        return "utm", raw
    # check orb first by listing
    try:
        machines = list_orb_machines()
    except Exception:
        machines = []
    # _isa: a listing return whose ``__class__`` is a raising property
    # detonated the bare gate and 500'd the action ahead of the walk below.
    if _isa(machines, list):
        try:
            machines = [m for m in list.__iter__(machines)]
        except Exception:
            machines = []
    else:
        machines = []
    for m in machines:
        if not _isa(m, dict):
            continue
        # _mapping_get and str.__eq__ against the exact request text: a
        # leftover dict-subclass row (bombing ``.get``), a hash-shadowing
        # key bomb (the unbound ``dict.get`` probe still ran the stored
        # key's ``__eq__``), or a str-subclass value (reflected ``__eq__``
        # / ``__bool__`` bomb) used to 500 the action instead of answering
        # the coded vms.bad_id.
        orb_name = _mapping_get(m, "orb_name")
        row_id = _mapping_get(m, "id")
        if (_isa(orb_name, str) and str.__eq__(raw, orb_name) is True) or (
            _isa(row_id, str) and str.__eq__(raw, row_id) is True
        ):
            # Unbound exact-str copy: a lying ``__class__`` impostor riding
            # ``orb_name`` beside a healthy matching ``id`` used to detonate
            # ``_as_text``'s encode (vms10); it now falls back to the exact
            # request text that matched.
            name_text = ""
            if _isa(orb_name, str):
                try:
                    name_text = _as_text(str.__str__(orb_name))
                except Exception:
                    name_text = ""
            return "orb", _argv_name(name_text or raw)
    return "utm", _argv_name(raw)


def vm_action(vm_id: str, action: str, **kwargs) -> dict[str, Any]:
    backend, ident = _parse_id(vm_id)
    action = (action or "").strip().lower()

    if backend == "utm":
        return _utm_action(ident, action, **kwargs)
    if backend == "orb":
        return _orb_action(ident, action, **kwargs)
    raise api_error("vms.unknown_backend", vm=vm_id)


def _utm_action(ident: str, action: str, **kwargs) -> dict:
    if not _utm_available():
        raise api_error("vms.utm_unavailable")
    if action == "start":
        rc, out, err = _spawn([UTMCTL, "start", ident], 90)
    elif action == "stop":
        force = kwargs.get("force", True)
        args = [UTMCTL, "stop", ident]
        if force:
            args.append("--force")
        else:
            args.append("--request")
        rc, out, err = _spawn(args, 180)
    elif action == "kill":
        rc, out, err = _spawn([UTMCTL, "stop", ident, "--kill"], 60)
    elif action == "suspend":
        rc, out, err = _spawn([UTMCTL, "suspend", ident], 120)
    elif action == "restart":
        return _utm_restart_async(ident)
    elif action == "delete":
        # must be stopped
        st = _utm_status(ident)
        if st in ("started", "running"):
            # _spawn even though the answer is discarded: a raising runner
            # used to 500 the delete here, after the status probe had
            # already answered through the guarded path.
            _spawn([UTMCTL, "stop", ident, "--force"], 120)
            time.sleep(2)
        rc, out, err = _spawn([UTMCTL, "delete", ident], 60)
    elif action == "clone":
        new_name = kwargs.get("name")
        args = [UTMCTL, "clone", ident]
        if new_name is not None and new_name != "":
            if not isinstance(new_name, str):
                raise api_error("vms.bad_machine_name")
            args += ["--name", _argv_name(new_name, code="vms.bad_machine_name")]
        rc, out, err = _spawn(args, 300)
    elif action == "ip":
        rc, out, err = _spawn([UTMCTL, "ip-address", ident], 15)
        if _cli_missing(rc, err, UTMCTL):
            raise api_error("vms.utm_unavailable")
        text = _as_text(out)
        ips = [ln.strip() for ln in text.splitlines() if ln.strip()]
        _invalidate()
        return {
            "ok": _rc_int(rc) == 0, "action": action, "id": ident, "ips": ips,
            "message": text or _as_text(err),
        }
    elif action == "rename":
        return rename_vm_display(ident, kwargs.get("name") or "")
    elif action == "status":
        st = _utm_status(ident)
        return {"ok": True, "action": action, "id": ident, "status": st}
    else:
        raise api_error("vms.utm_unsupported_action", action=action)
    if _cli_missing(rc, err, UTMCTL):
        raise api_error("vms.utm_unavailable")
    _invalidate()
    return {
        "ok": _rc_int(rc) == 0, "action": action, "id": ident,
        "message": _as_text(out) if _rc_int(rc) == 0 else (_as_text(err) or _as_text(out)),
    }


def _utm_status(name: str) -> str:
    rc, out, _ = _spawn([UTMCTL, "status", name], 10)
    return _as_text(out).strip() if _rc_int(rc) == 0 else "unknown"


def utm_vm_running(vm_uuid: str) -> bool:
    """True when the UTM VM with *vm_uuid* is currently started.

    Looked up by UUID and re-queried live rather than trusting a cached list or
    a display name: console authorisation must not follow a renamed VM, and a
    machine that stopped since the page loaded must not accept a bridge.
    """
    uuid = str(vm_uuid or "").strip().lower()
    if not uuid or not _utm_available():
        return False
    try:
        vms = list_utm_vms(force=True)
    except Exception:
        return False
    # _isa: a listing return whose ``__class__`` is a raising property
    # detonated this bare gate and 500'd the console-session mint (and the
    # WebSocket upgrade's running re-check) instead of reading as absent.
    if _isa(vms, list):
        try:
            vms = [vm for vm in list.__iter__(vms)]
        except Exception:
            return False
    else:
        return False
    for vm in vms:
        if not _isa(vm, dict):
            continue
        # _mapping_get + _as_text: a leftover dict-subclass row (bombing
        # ``.get``) or a hash-shadowing key bomb riding the unbound
        # ``dict.get`` probe used to raise out of the console-session mint
        # instead of the coded 404.
        if _as_text(_mapping_get(vm, "uuid")).strip().lower() != uuid:
            continue
        return _utm_status(_as_text(_mapping_get(vm, "id"))) in ("started", "running")
    return False


def _utm_restart_async(name: str) -> dict:
    def job():
        # _spawn over sh(), not bare subprocess.run: a TimeoutExpired from
        # stop/start escaped this worker thread, abandoning the restart
        # halfway with the VM left stopped.  sh() bounds every call and
        # reports failure as a return code instead of raising — and _spawn
        # keeps a leftover raising runner from crashing the worker between
        # the stop and the start for the same abandoned-halfway result.
        _spawn([UTMCTL, "stop", name, "--force"], 180)
        for _ in range(40):
            _, out, _ = _spawn([UTMCTL, "status", name], 10)
            if _as_text(out).strip() == "stopped":
                break
            time.sleep(2)
        _spawn([UTMCTL, "start", name], 90)
        _invalidate()

    threading.Thread(target=job, daemon=True).start()
    return {"ok": True, "action": "restart", "id": name, "message": "Restart started (takes about 1–2 minutes)"}


def _orb_action(ident: str, action: str, **kwargs) -> dict:
    if not _orb_available():
        raise api_error("vms.orb_unavailable")
    if action == "start":
        rc, out, err = _spawn([ORBCTL, "start", ident], 120)
    elif action == "stop":
        rc, out, err = _spawn([ORBCTL, "stop", ident], 120)
    elif action == "restart":
        rc, out, err = _spawn([ORBCTL, "restart", ident], 180)
    elif action == "delete":
        # orbctl delete NAME -y if exists
        rc, out, err = _spawn([ORBCTL, "delete", ident, "-f"], 180)
        if _rc_int(rc) != 0:
            rc, out, err = _spawn([ORBCTL, "delete", ident], 180)
    elif action == "clone":
        new_name = kwargs.get("name")
        if new_name is None or new_name == "":
            new_name = f"{ident}-clone"
        elif not isinstance(new_name, str):
            raise api_error("vms.bad_machine_name")
        new_name = _argv_name(new_name, code="vms.bad_machine_name")
        rc, out, err = _spawn([ORBCTL, "clone", ident, new_name], 600)
    elif action == "shell":
        # Hint only.  ``orbctl ssh`` is an interactive session and used to sit
        # on the request thread until the 10s sh() timeout.
        return {
            "ok": True,
            "action": "shell",
            "id": ident,
            "message": f"Run in a terminal: orb -m {ident}",
            "command": f"orb -m {ident}",
        }
    elif action == "info":
        rc, out, err = _spawn([ORBCTL, "info", ident], 15)
        if _cli_missing(rc, err, ORBCTL):
            raise api_error("vms.orb_unavailable")
        return {
            "ok": _rc_int(rc) == 0, "action": "info", "id": ident,
            "message": _as_text(out) or _as_text(err),
        }
    elif action == "rename":
        return rename_vm_display(f"orb:{ident}", kwargs.get("name") or "")
    else:
        raise api_error("vms.orb_unsupported_action", action=action)
    if _cli_missing(rc, err, ORBCTL):
        raise api_error("vms.orb_unavailable")
    _invalidate()
    return {
        "ok": _rc_int(rc) == 0, "action": action, "id": ident,
        "message": _as_text(out) if _rc_int(rc) == 0 else (_as_text(err) or _as_text(out)),
    }


def create_orb_machine(distro: str, name: str | None = None, arch: str | None = None) -> dict:
    """orbctl create DISTRO[:VERSION] [NAME]"""
    if not _orb_available():
        raise api_error("vms.orb_unavailable")
    distro = (distro or "").strip()
    if not distro:
        raise api_error("vms.distro_required")
    # ``^[a-zA-Z0-9._:-]+$`` matched ``--help`` because ``-`` is in the class
    # with no first-character anchor — ``orbctl create --help``.
    if not cli_args.is_safe_positional(distro):
        raise api_error("vms.bad_distro")
    args = [ORBCTL, "create", distro]
    if name:
        if not isinstance(name, str):
            raise api_error("vms.bad_machine_name")
        name = name.strip()
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$", name):
            raise api_error("vms.bad_machine_name")
        args.append(name)
    if arch in ("arm64", "amd64"):
        args += ["--arch", arch]
    rc, out, err = _spawn(args, 600)
    if _cli_missing(rc, err, ORBCTL):
        raise api_error("vms.orb_unavailable")
    _invalidate()
    return {
        "ok": _rc_int(rc) == 0,
        "action": "create",
        "distro": distro,
        "name": name,
        "message": _as_text(out) if _rc_int(rc) == 0 else (_as_text(err) or _as_text(out)),
    }
