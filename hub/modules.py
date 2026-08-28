"""Extensible module registry — inspired by CasaOS / plugin dashboards.

Each module declares id, title, APIs it owns, and dashboard widgets.
Keeps ServerHub feature surface discoverable and documentable.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields


@dataclass
class ModuleInfo:
    id: str
    name: str
    description: str
    category: str  # system | docker | storage | network | apps | ops
    apis: list[str] = field(default_factory=list)
    ui_routes: list[str] = field(default_factory=list)
    inspired_by: list[str] = field(default_factory=list)
    enabled: bool = True


MODULES: list[ModuleInfo] = [
    ModuleInfo(
        id="dashboard",
        name="Dashboard",
        description="System tiles, trends, anomalies, ports and scheduled digests",
        category="system",
        apis=["/api/status", "/api/metrics", "/api/health"],
        ui_routes=["/"],
    ),
    ModuleInfo(
        id="services",
        name="Services",
        description="Unified discovery and start/stop for launchd, scripts, apps and the OrbStack engine",
        category="system",
        apis=["/api/status", "/api/action"],
        ui_routes=["/services"],
    ),
    ModuleInfo(
        id="brew",
        name="Homebrew Services",
        description="brew services list/start/stop/restart",
        category="system",
        apis=["/api/brew/services", "/api/brew/services/{name}/action"],
        ui_routes=["/brew", "/tools"],
    ),
    ModuleInfo(
        id="docker",
        name="Docker / OrbStack",
        description="Container table, batch actions, update checks, console, log SSE",
        category="docker",
        apis=["/api/containers", "/api/images", "/api/volumes", "/api/networks"],
        ui_routes=["/containers"],
    ),
    ModuleInfo(
        id="compose",
        name="Compose Stacks",
        description="Stack list, YAML editing, validation, pull/up/down",
        category="docker",
        apis=["/api/stacks", "/api/compose/{stack_id}"],
        ui_routes=["/apps", "/compose"],
    ),
    ModuleInfo(
        id="catalog",
        name="App Catalog",
        description="One-click deploys from template variable forms",
        category="apps",
        apis=["/api/catalog"],
        ui_routes=["/apps"],
    ),
    ModuleInfo(
        id="storage",
        name="Storage Array",
        description="Multiple volumes + multi-disk SMART + HDD sleep/wake",
        category="storage",
        apis=["/api/storage", "/api/storage/disks", "/api/storage/disks/{id}/power"],
        ui_routes=["/main"],
    ),
    ModuleInfo(
        id="shares",
        name="Shares",
        description="SMB + file service status",
        category="storage",
        apis=["/api/shares"],
        ui_routes=["/shares"],
    ),
    ModuleInfo(
        id="network",
        name="Network",
        description="Interfaces / listening ports / routes",
        category="network",
        apis=["/api/system/network"],
        ui_routes=["/network"],
    ),
    ModuleInfo(
        id="gateway",
        name="System Nginx Gateway",
        description="Site-wide reverse proxy · automatic conf.d site discovery · reload",
        category="network",
        apis=["/api/nginx", "/api/nginx/reload"],
        ui_routes=["/gateway"],
    ),
    ModuleInfo(
        id="adaptive",
        name="Adaptive Discovery",
        description="LaunchAgent port inference, orphaned listeners, Compose/site scanning",
        category="system",
        apis=["/api/status", "/api/adaptive/compose-scan"],
        ui_routes=["/", "/services"],
    ),
    ModuleInfo(
        id="bookmarks",
        name="Bookmark Probes",
        description="HTTP health checks for quick-access links",
        category="apps",
        apis=["/api/bookmarks"],
        ui_routes=["/", "/bookmarks"],
    ),
    ModuleInfo(
        id="sensors",
        name="Sensors",
        description="CPU load details, memory, disk I/O sampling",
        category="system",
        apis=["/api/system/sensors"],
        ui_routes=["/", "/tools"],
    ),
    ModuleInfo(
        id="logs",
        name="Log Center",
        description="Multi-source tail / filter / download",
        category="ops",
        apis=["/api/logs"],
        ui_routes=["/logs"],
    ),
    ModuleInfo(
        id="alerts",
        name="Alerts",
        description="State changes + HA notifications",
        category="ops",
        apis=["/api/alerts"],
        ui_routes=["/alerts"],
    ),
    ModuleInfo(
        id="backups",
        name="Backups",
        description="PG dumps / config tarballs",
        category="ops",
        apis=["/api/backups"],
        ui_routes=["/backups"],
    ),

    ModuleInfo(
        id="photoshub",
        name="PhotosHub",
        description="Family photo pipeline: originals rate, Photos to Immich bridge, delete-review, external HDD backup",
        category="apps",
        apis=["/api/photoshub/status", "/api/photoshub/action", "/api/photoshub/pending-delete", "/api/photoshub/config"],
        ui_routes=["/photoshub"],
    ),

    ModuleInfo(
        id="tools",
        name="Tools",
        description="Diagnostics, processes, Docker usage, scheduled tasks",
        category="ops",
        apis=["/api/system/diagnostics", "/api/system/processes"],
        ui_routes=["/tools"],
    ),
]


# Real control flow must keep propagating even through the bomb guards:
# swallowing a Ctrl-C or an interpreter shutdown to save one JSON row would
# turn the sanitizer into a hang.  Everything else BaseException-shaped that
# a leftover raises out of its own hooks is a bomb like any other.
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)


def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so a value whose ``__class__`` is a raising
    property blew every ``isinstance`` gate below — at value, nested,
    mapping-key and whole-row rank — straight out of the unguarded handler.
    A lying ``__class__`` (answers ``int``) is *not* an error and still
    reports its claim here; the numeric arms' unbound base coercion then
    drops it, exactly as before.

    ``except BaseException``: the modules8 guard stopped at ``Exception``,
    so a leftover whose ``__class__`` property raises a *BaseException*
    subclass (a watchdog/timeout-style leftover) sailed past this catch —
    and past every sibling guard below — straight out of GET /api/modules
    as a raw 500.  Only genuine control flow keeps propagating.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _decode_bytes(value):
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500.

    Returns ``None`` for a *lying* ``__class__`` that answers ``bytes`` /
    ``bytearray`` while the real type is neither: the unbound base decode
    is a descriptor bound to the real ``bytes``/``bytearray`` layout, so it
    rejects the foreign operand with a ``TypeError`` outside any try — the
    same seam the numeric arms already close via ``int.__index__`` /
    ``float.__float__``.  A raise means "not really this type"; the caller
    drops the impostor exactly as it drops a lying ``int``/``float``.

    Both bases are tried, real layout first-come: the old arm picked the
    base off the *claimed* ``__class__`` (``bytes if _isinst(value, bytes)``),
    so a genuine ``bytearray`` whose ``__class__`` lied ``bytes`` was handed
    to ``bytes.decode``, rejected, and its perfectly decodable content
    vanished to ``None`` — degrade at the wrong rank.  Now the descriptor
    that matches the real storage wins and the content survives; a total
    impostor still fails both and drops exactly as before.
    """
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    return None


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if _isinst(value, (bytes, bytearray)):
        decoded = _decode_bytes(value)
        if decoded is not None:
            return decoded
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
        # A ``__str__`` bomb raising a *BaseException* subclass used to
        # sail past the ``except Exception`` here and 500 GET /api/modules
        # at value, nested and mapping-key rank.
        return ""
    # Unbound base encode: ``str()`` of a subclass whose ``__str__`` answers
    # *self* skips CPython's exact-str copy, so a leftover bound ``encode``
    # bomb rode this line to a 500 — at value, nested and mapping-key rank,
    # through the dataclass arm, and as a ``by_category`` group key.
    return str.encode(text, "utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    YAML ``name: 2026-08-19``, ``!!binary`` ids, ``enabled: .inf``, and a
    ``!!set`` of APIs each used to 500 GET /api/modules. A leftover
    ``\\ud800`` name still 500'd the same encoder (``ensure_ascii=False``
    then UTF-8).
    A >4300-digit leftover int still passed through untouched: CPython's
    int->str digit limit then ValueError'd ``json.dumps`` itself.
    """
    if depth > 32:
        return None
    if value is None:
        return value
    if _isinst(value, bool):
        # ``bool`` is final, so a value that answers the ``bool`` gate while
        # its real type is not ``bool`` is a *lying* ``__class__`` impostor,
        # not a genuine bool.  The old arm returned it raw, handing the
        # ``allow_nan=False`` encoder a non-serializable object that 500'd
        # GET /api/modules — at value rank and as ``enabled``.  Only a real
        # bool renders; the impostor drops to ``None`` like its numeric
        # siblings' lying-``__class__`` coercion does.
        if type(value) is bool:
            return value
        return None
    if _isinst(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__``
                # bomb used to blow the digit-cap probe below.
                value = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if _isinst(value, float):
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
    if _isinst(value, str):
        return _utf8_text(value)
    if _isinst(value, (bytes, bytearray)):
        # A lying ``__class__`` claiming ``bytes``/``bytearray`` makes the
        # unbound base decode reject the foreign operand; drop it.
        return _decode_bytes(value)
    if _isinst(value, dict):
        # Unbound base view: a dict subclass whose ``items()`` raises
        # or yields non-pairs used to 500 GET /api/modules, nested and
        # (since the ``dict(m)`` pre-copy fell) at row rank too.  ``dict.items``
        # is itself a descriptor bound to the real dict layout, so a *lying*
        # ``__class__`` claiming ``dict`` (real type is neither) blew the
        # call outside any try — drop the impostor like a lying ``int``.
        #
        # Snapshot the entries (``list(...)``) before walking: the walk
        # below runs each value's own hooks (``__class__`` probes, key
        # ``__str__`` coercion), and a leftover hook that resizes its
        # parent mapping mid-walk made the live ``dict_items`` view raise
        # ``RuntimeError: dictionary changed size during iteration`` —
        # outside every try, straight out of GET /api/modules as a raw
        # 500, at row and nested rank alike, in exact dicts as much as
        # subclasses.  ``list()`` of the view copies pure C 2-tuples off
        # the real storage without running any leftover code, so the walk
        # is immune to whatever the hooks do to the original afterwards
        # and every entry captured at snapshot time still renders.
        try:
            items = list(dict.items(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
        out = {}
        for k, v in items:
            if _isinst(k, (bytes, bytearray)):
                k = _decode_bytes(k)
                if k is None:
                    # A lying ``__class__`` key claiming bytes — drop just
                    # this entry, keep the rest of the mapping.
                    continue
            elif not _isinst(k, str):
                try:
                    k = str(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if _isinst(value, (list, tuple, set, frozenset)):
        for base in (list, tuple, set, frozenset):
            if _isinst(value, base):
                # Unbound base iteration: a subclass ``__iter__`` bomb
                # cannot 500 and the real elements still survive.  The
                # unbound ``__iter__`` is bound to the real sequence layout,
                # so a *lying* ``__class__`` claiming this base (real type is
                # not) makes it reject the operand.
                #
                # Snapshot before walking, same seam as the dict arm: the
                # element walk runs each element's own hooks, and a
                # leftover hook that resizes its parent *set* mid-walk
                # made the live set iterator raise ``RuntimeError: Set
                # changed size during iteration`` outside every try — a
                # raw 500 out of GET /api/modules.  ``list()`` of the
                # genuine base iterator copies the elements without
                # running any of their code, so the walk is stable.
                #
                # ``continue`` on rejection, not ``return None``: the old
                # arm picked the base off the *claimed* ``__class__``, so
                # a genuine tuple whose ``__class__`` lied ``list`` was
                # handed to ``list.__iter__``, rejected, and its perfectly
                # renderable elements vanished — the same wrong-rank
                # degrade the decode arm shed in the previous sweep.  The
                # descriptor matching the real storage wins on a later
                # pass; a total impostor (real type is none of the four)
                # fails every base and drops exactly as before.
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
        # getattr's default only swallows AttributeError; a property or
        # ``__getattr__`` bomb still raised out of the probe itself —
        # including one raising a BaseException subclass past the old
        # ``except Exception``.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/modules.
            # An ``isoformat`` raising a BaseException subclass rode past
            # the old ``except Exception`` here to the same raw 500.
            return _jsonable(iso(), depth + 1)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    try:
        return _utf8_text(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _module_row(m) -> dict | None:
    """Serialize one registry entry. Junk rows used to 500 GET /api/modules."""
    if _isinst(m, ModuleInfo):
        try:
            row = asdict(m)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Field-level salvage: ``asdict`` walks every field eagerly
            # (``getattr`` then ``copy.deepcopy``), so one raising property
            # on a leftover ``ModuleInfo`` subclass — or one nested value
            # whose ``__reduce_ex__``/``__deepcopy__`` bombs — used to drop
            # the *whole* row even though every other field was sane.  Pull
            # each declared field individually; a bombed field vanishes
            # alone and ``_jsonable`` still sanitizes whatever survives.
            # Both tries reach past ``Exception``: a field property or a
            # nested deepcopy hook raising a *BaseException* subclass used
            # to skip the salvage entirely and 500 the route raw.
            row = {}
            for f in fields(ModuleInfo):
                try:
                    row[f.name] = getattr(m, f.name)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            if not row:
                # A lying ``__class__`` claiming ModuleInfo carries none of
                # the declared fields — drop the impostor like before.
                return None
    elif _isinst(m, dict):
        # No pre-copy: ``dict(m)`` on a subclass that overrides
        # ``__iter__`` abandons CPython's fast storage copy for the
        # generic mapping path, running the subclass's ``keys()`` and
        # ``__getitem__`` — a bomb in either (or a junk ``keys()``
        # return) 500'd GET /api/modules before ``_jsonable`` ever saw
        # the row.  Its dict arm already copies via unbound
        # ``dict.items``, straight off the real storage.
        row = m
    else:
        return None
    row = _jsonable(row)
    if not isinstance(row, dict):
        return None
    cat = row.get("category")
    if not isinstance(cat, str):
        # A list leftover (``category: [ops]``) is unhashable and 500'd
        # ``modules_by_category`` via setdefault.
        row["category"] = "other"
    if not isinstance(row.get("enabled"), bool):
        row["enabled"] = True
    return row


def _registry_entries() -> list:
    """Snapshot the registry off its real storage; a leftover cannot 500.

    ``for m in MODULES`` dispatched through the *bound* ``__iter__``, so a
    leftover registry object — a list subclass whose ``__iter__`` raises or
    answers a generator that bombs mid-walk, a dict/str subclass with the
    same override, or a lying ``__class__`` impostor claiming ``list`` —
    blew the very first opcode of the walk, outside any try, and rode out
    of GET /api/modules as a raw 500 wiping the entire response.  The
    unbound base ``__iter__`` reads the real C-level storage (the modules5
    sequence rule at registry rank), so every genuine row still renders;
    an impostor whose real layout the descriptor rejects fails closed to
    an empty registry instead of a 500.
    """
    reg = MODULES
    if type(reg) is list:
        return list(reg)
    for base in (list, tuple, set, frozenset):
        if _isinst(reg, base):
            try:
                return list(base.__iter__(reg))
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return []
    return []


def list_modules() -> list[dict]:
    out = []
    for m in _registry_entries():
        row = _module_row(m)
        if row is not None:
            out.append(row)
    return out


def modules_by_category() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for row in list_modules():
        cat = row.get("category")
        if not isinstance(cat, str):
            cat = "other"
        try:
            out.setdefault(cat, []).append(row)
        except TypeError:
            out.setdefault("other", []).append(row)
    return out
