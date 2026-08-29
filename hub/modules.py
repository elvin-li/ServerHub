"""Extensible module registry — inspired by CasaOS / plugin dashboards.

Each module declares id, title, APIs it owns, and dashboard widgets.
Keeps ServerHub feature surface discoverable and documentable.
"""
from __future__ import annotations

import re
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


#: CPython's angle-repr shape (``<X object at 0x7f...>`` and the function /
#: bound-method variants) — a raw heap address, never module data (the
#: bookmarks/assistant rule).  Only the free-text *coercion* arms are
#: scrubbed with it; real str/bytes storage is data and stays verbatim.
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


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


def _real(value, types) -> bool:
    """True when the *real* storage is this type.

    ``type(value)`` reads the C-level type slot, which a lying ``__class__``
    property cannot swap, so this is the probe for the recover-the-real-
    storage fall-throughs below: after a claimed arm's unbound descriptor
    rejects the operand, only the arm the *real* layout matches may pick
    the value up — the lie must not steer the walk a second time.
    Fail-closed like ``_isinst``.
    """
    try:
        return issubclass(type(value), types)
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
        if not _isinst(value, str):
            # A total impostor claiming bytes carries nothing the str
            # read below could recover either — degrade like before.
            return ""
        # Honest str storage behind a lying-bytes ``__class__`` (the
        # files16/notify13 recover-the-real-storage rule): the gate above
        # matches through the *lie*, both base decodes reject the str
        # layout, and the real text renders verbatim one arm below.
    if _isinst(value, str):
        # Unbound base read, not the dispatching ``str()``: real str
        # storage keeps its text even when the subclass ``__str__`` /
        # ``encode`` is poisoned, while a *lying* ``__class__`` that only
        # claims str rejects the descriptor and falls to the coercion arm
        # below instead of leaking its repr.  The encode-replace pass
        # scrubs lone surrogates the same way as before.
        try:
            return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    # Only a type that renders *itself* may coerce.  This free-text arm ran
    # ``str()`` on any leftover shape, and for a type that never overrode
    # ``__str__`` / ``__repr__`` the answer is the default ``object.__repr__``
    # — ``<X object at 0x7f...>``, a raw heap address — which a junk name,
    # description or nested field carried verbatim into the GET /api/modules
    # body (the bookmarks/assistant slot-probe rule).  A slot probe on the
    # real ``type(value)``: a flickering ``__class__`` property cannot swap
    # the real type out.
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
        # A ``__str__`` bomb raising a *BaseException* subclass used to
        # sail past the ``except Exception`` here and 500 GET /api/modules
        # at value, nested and mapping-key rank.
        return ""
    # CPython usually TypeError's a non-str ``__str__``, but a leftover
    # that answers another str *subclass* (or a lying claim that slips
    # a non-str through) used to reach the unbound encode with the wrong
    # layout and 500 GET /api/modules outside any try — the util._exc_text
    # belt.  Drop just this field.
    if not _isinst(text, str):
        return ""
    # Unbound base encode: ``str()`` of a subclass whose ``__str__`` answers
    # *self* skips CPython's exact-str copy, so a leftover bound ``encode``
    # bomb rode this line to a 500 — at value, nested and mapping-key rank,
    # through the dataclass arm, and as a ``by_category`` group key.
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    # Belt for what the slot probe cannot see: a function / bound-method
    # leftover (C-level ``__repr__`` override) and a value whose *rendering*
    # embeds a default repr still answered an address.  Only this coercion
    # arm is scrubbed — real str/bytes storage above is data and stays.
    try:
        return "" if _ADDR_REPR_RE.search(text) else text
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""


def _key_text(k) -> str | None:
    """Render a mapping key, or ``None`` to drop just that entry.

    Keys keep the modules4 rule — a key that cannot render drops its own
    entry, never the row — so the coercion failures here answer ``None``
    where ``_utf8_text`` degrades values to ``""``.  Two leftovers fixed
    against the same rule:

    * a genuine str key behind a lying-bytes ``__class__`` matched the
      bytes gate through the lie, both base decodes rejected the str
      layout, and the old ``continue`` dropped an entry whose real key
      text renders verbatim — degrade at the wrong rank;
    * a key type that never overrode ``__str__``/``__repr__`` coerced to
      the default ``object.__repr__`` — ``<X object at 0x7f...>``, a raw
      heap address, leaked verbatim as a JSON *key* by GET /api/modules.
      The slot probe (and the ``_ADDR_REPR_RE`` belt for C-level repr
      overrides like functions) drops the entry instead.
    """
    if _isinst(k, (bytes, bytearray)):
        decoded = _decode_bytes(k)
        if decoded is not None:
            return decoded
        if not _isinst(k, str):
            # A total impostor claiming bytes — drop just this entry.
            return None
        # Honest str storage behind the lying-bytes claim falls through.
    if _isinst(k, str):
        try:
            return str.encode(str.__str__(k), "utf-8", "replace").decode("utf-8")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass  # a lying-str claim — coerce off whatever renders below
    try:
        cls = type(k)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return None
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    try:
        text = str(k)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A raising ``__str__`` key keeps dropping its entry (RecursionError
        # included) — the modules4 shape.
        return None
    if not _isinst(text, str):
        return None
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    try:
        return None if _ADDR_REPR_RE.search(text) else text
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


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
    # ``type(value) is bool``, not the isinstance gate: ``bool`` is final,
    # so only a real bool may render raw.  A *lying* ``__class__`` claiming
    # bool now falls through — ``bool`` subtypes ``int``, so the int arm's
    # unbound ``int.__index__`` recovers genuine int storage behind the lie
    # (the old arm dropped it to ``None`` at the wrong rank) and still
    # drops a total impostor exactly as before.
    if type(value) is bool:
        return value
    if _isinst(value, int):
        num = value if type(value) is int else None
        if num is None:
            try:
                # Base coercion to an exact int: a subclass ``__str__``
                # bomb used to blow the digit-cap probe below.
                num = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                num = None
        if num is not None:
            try:
                str(num)
            except ValueError:
                # Past CPython's int->str digit cap the encoder cannot
                # render the number at all — same drop as its inf float
                # sibling.
                return None
            return num
        if not _real(value, (float, str, bytes, bytearray, dict,
                             list, tuple, set, frozenset)):
            # A total impostor claiming int/bool keeps the old None drop.
            return None
        # The descriptor refused the operand, so the claimed ``int`` was a
        # lie — but the real storage matches a later arm (the files16/
        # notify13 recover-the-real-storage rule): a genuine str / float /
        # container behind that lie used to vanish to ``None`` at the
        # wrong rank while its value rendered fine one gate below.
    if _isinst(value, float):
        num = value if type(value) is float else None
        if num is None:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                num = float.__float__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                num = None
        if num is not None:
            if num != num or num in (float("inf"), float("-inf")):
                return None
            return num
        if not _real(value, (str, bytes, bytearray, dict,
                             list, tuple, set, frozenset)):
            # A total impostor claiming float keeps the old None drop.
            return None
        # Genuine text / container behind a lying-float claim falls through.
    if _isinst(value, str):
        if not _real(value, (dict, list, tuple, set, frozenset)):
            return _utf8_text(value)
        # Genuine mapping / sequence storage behind a lying-str
        # ``__class__`` used to render as its ``str()`` text blob here —
        # the wrong rank; the arm its real storage matches walks it below.
    if _isinst(value, (bytes, bytearray)):
        decoded = _decode_bytes(value)
        if decoded is not None:
            return decoded
        if not _real(value, (dict, list, tuple, set, frozenset)):
            # A total impostor claiming bytes keeps the old None drop.
            return None
        # Genuine mapping / sequence behind a lying-bytes claim falls
        # through to the arm that reads its real storage.
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
            items = None
        if items is not None:
            out = {}
            for pair in items:
                # Unbound ``dict.items`` yields 2-tuples off real dict
                # storage, but a leftover snapshot that is not a pair
                # (the ups/shares torn-row shape) used to ValueError the
                # two-target unpack *outside* every try — a raw 500.
                # Drop just that entry; siblings still render.
                try:
                    k, v = pair
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
                key = _key_text(k)
                if key is None:
                    # A key that cannot render (raising ``__str__``, a
                    # total lying-bytes impostor, a default-repr address)
                    # drops just this entry, keeps the rest of the mapping.
                    continue
                out[key] = _jsonable(v, depth + 1)
            return out
        if not _real(value, (list, tuple, set, frozenset)):
            # A total impostor claiming dict keeps the old None drop.
            return None
        # Genuine sequence storage behind a lying-dict ``__class__`` falls
        # through: its elements render below instead of vanishing whole.
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
                out = []
                for v in items:
                    try:
                        out.append(_jsonable(v, depth + 1))
                    except _CONTROL_FLOW:
                        raise
                    except BaseException:
                        out.append(None)
                return out
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
    row = None
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
            salvage = {}
            for f in fields(ModuleInfo):
                try:
                    salvage[f.name] = getattr(m, f.name)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            if salvage:
                row = salvage
            # A lying ``__class__`` claiming ModuleInfo carries none of
            # the declared fields — but the claim may sit on *genuine
            # dict storage* whose entries render fine one arm below (the
            # files16/notify13 recover-the-real-storage rule): the old
            # early return unlisted that whole row at the wrong rank.
            # Fall through; a total impostor still drops like before.
    if row is None and _real(m, dict):
        # No pre-copy: ``dict(m)`` on a subclass that overrides
        # ``__iter__`` abandons CPython's fast storage copy for the
        # generic mapping path, running the subclass's ``keys()`` and
        # ``__getitem__`` — a bomb in either (or a junk ``keys()``
        # return) 500'd GET /api/modules before ``_jsonable`` ever saw
        # the row.  Its dict arm already copies via unbound
        # ``dict.items``, straight off the real storage.
        row = m
    if row is None:
        return None
    row = _jsonable(row)
    if not _isinst(row, dict):
        return None
    try:
        cat = dict.get(row, "category")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        cat = None
    if not _isinst(cat, str):
        # A list leftover (``category: [ops]``) is unhashable and 500'd
        # ``modules_by_category`` via setdefault.
        try:
            dict.__setitem__(row, "category", "other")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    try:
        enabled = dict.get(row, "enabled")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        enabled = None
    if type(enabled) is not bool:
        try:
            dict.__setitem__(row, "enabled", True)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
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
                # ``continue``, not ``return []``: the old arm stopped at
                # the *claimed* base, so a genuine tuple registry whose
                # ``__class__`` lied ``list`` was handed to
                # ``list.__iter__``, rejected by the descriptor, and every
                # perfectly renderable row it really held vanished — the
                # whole Modules page wiped at registry rank, the same
                # wrong-rank degrade the value-rank sequence arm already
                # shed.  The descriptor matching the real storage wins on
                # a later pass; a total impostor (real type is none of the
                # four) still fails every base and drops to the empty
                # registry exactly as before.
                continue
    return []


def list_modules() -> list[dict]:
    out = []
    for m in _registry_entries():
        try:
            row = _module_row(m)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        if row is not None:
            out.append(row)
    return out


def modules_by_category() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for row in list_modules():
        try:
            cat = dict.get(row, "category") if _isinst(row, dict) else None
        except _CONTROL_FLOW:
            raise
        except BaseException:
            cat = None
        if not _isinst(cat, str):
            cat = "other"
        try:
            out.setdefault(cat, []).append(row)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            try:
                out.setdefault("other", []).append(row)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
    return out
