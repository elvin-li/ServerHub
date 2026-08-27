"""In-panel assistant: find a page, or brief the current host via Ollama.

Finding a panel is a catalog match — no GPU.  Status / Q&A reuse the cached
``/api/status`` snapshot and the resident Ollama model (``MAX_LOADED_MODELS=1``
on this class of host).  The model is only called when the operator asks;
there is no background summarizer.  If the daemon is down, a deterministic
brief is returned so the drawer still works.

Localized titles, aliases and intent phrases live in JSON next to this
module so this file stays ASCII (the CJK ratchet scans ``hub/*.py``).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from hub.errors import CODES, api_error
from hub.util import read_text_capped, safe_json_loads

CODES.setdefault("assistant.query_required", (400, "a question or page name is required"))
CODES.setdefault("assistant.bad_action", (400, "action must be auto, find, brief, ask, or page"))

ACTIONS = frozenset({"auto", "find", "brief", "ask", "page"})
MAX_QUERY_CHARS = 500
MAX_HISTORY = 6
MAX_NUM_PREDICT = 192

_HERE = Path(__file__).resolve().parent
#: Leftover multi-MB catalog next to this module used to OOM import / ask.
_CATALOG_CAP = 256 * 1024


def _capped_json_int(text):
    """``json.loads`` parse_int hook: an over-cap digit run drops to None.

    ``int()`` of a >4300-digit number literal is the digit-cap *ValueError*
    (not JSONDecodeError) for the whole document: one poisoned number in
    assistant_panels.json used to make :func:`_load_json` return ``None``,
    which silently wiped the entire panel catalog — find, page and the
    Cmd+K catalog all answered empty until the file was hand-fixed.
    """
    try:
        return int(text)
    except ValueError:
        return None


def _load_json(name: str):
    try:
        return safe_json_loads(
            read_text_capped(_HERE / name, _CATALOG_CAP, encoding="utf-8"),
            parse_int=_capped_json_int,
        )
    except (OSError, ValueError, RecursionError):
        # RecursionError: leftover deeply-nested catalog JSON is not ValueError.
        return None


def _isa(value, types) -> bool:
    """``isinstance`` that survives a raising ``__class__`` property.

    ``isinstance`` consults ``value.__class__`` whenever the real type does
    not already match, so a leftover object whose ``__class__`` is a raising
    property blew up the *gate itself* — every ``isinstance(panel, dict)``
    outside a try, including the ones ``suggest_panels`` runs inside the
    router's own error fallback, where the re-raise was a guaranteed 500 on
    POST /api/assistant/ask.  A value the probe cannot classify is junk the
    caller's existing not-a-match branch already handles.
    """
    try:
        return isinstance(value, types)
    except Exception:
        return False


def _safe_int(raw, default: int = 0) -> int:
    if _isa(raw, bool) or raw is None:
        return default
    if _isa(raw, int) and type(raw) is not int:
        # Base coercion to an exact int: a subclass ``__int__``/``__str__``
        # bomb used to blow int() / the digit-cap probe below, wiping the
        # whole snapshot to the minimal brief.
        try:
            raw = int.__index__(raw)
        except Exception:
            return default
    if _isa(raw, float):
        if type(raw) is not float:
            # Base coercion first: a float-subclass ``__eq__`` bomb used to
            # blow the NaN/inf probes below, outside every catch.
            try:
                raw = float.__float__(raw)
            except Exception:
                return default
        if raw != raw or raw in (float("inf"), float("-inf")):
            return default
    try:
        value = int(raw)
        # An *already-int* leftover past CPython's int->str digit cap (YAML /
        # plist hex loads uncapped) passes int() but blows every later str()
        # — fallback_brief's f-strings and the JSON encoder both 500'd.
        str(value)
    except Exception:
        # Exception, not (TypeError, ValueError, OverflowError): an object
        # whose ``__int__`` raises anything else escaped the narrow tuple.
        return default
    return value


def _decode_bytes(value):
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500.

    Returns ``None`` for a *lying* ``__class__`` that answers ``bytes`` /
    ``bytearray`` while the real type is neither: ``_isa`` reports the lie at
    face value, and the unbound base decode is a descriptor bound to the real
    bytes layout, so it rejected the foreign operand with a TypeError outside
    every try — ``_title`` runs it inside ``suggest_panels``, which the
    router's own error fallback calls again with the same poisoned row: a
    raw 500 on POST /api/assistant/ask.  A raise means "not really bytes";
    the impostor drops like a lying ``int``/``float`` does.
    """
    base = bytes if _isa(value, bytes) else bytearray
    try:
        return base.decode(value, "utf-8", "replace")
    except Exception:
        return None


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if _isa(value, (bytes, bytearray)):
        # ``or ""``: a lying-``__class__`` impostor decodes to None — drop
        # the cell to empty, never its repr and never a raise.
        return _decode_bytes(value) or ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    # Unbound base encode: ``str()`` of a subclass whose ``__str__`` answers
    # *self* skips CPython's exact-str copy, so a leftover bound ``encode``
    # bomb rode a catalog path straight to a 500 on GET /api/assistant/catalog.
    return str.encode(text, "utf-8", "replace").decode("utf-8")


def _truthy(value) -> bool:
    """``bool()`` that cannot raise: a subclass ``__bool__``/``__len__`` bomb
    is just falsy.  ``fallback_brief`` runs inside the router's own error
    fallback, where a re-raise is a guaranteed 500."""
    try:
        return bool(value)
    except Exception:
        return False


def _dget(mapping, key):
    """Mapping read that survives a dict-subclass ``get`` bomb.

    The ups/ollama settings rule: ``dict.get`` reads the real storage
    underneath the override, so a subclass that only poisoned its method
    keeps its sane data.  Non-dicts answer ``None``.

    The items-walk fallback covers the *stored key* being the bomb: a
    str-subclass key whose ``__eq__`` raises shares ``"system"``'s hash, so
    even ``dict.get`` hits the poisoned comparison in the probe — the whole
    section under that key used to silently drop from the snapshot even
    though the sane value sat right there.  ``str.__eq__`` with the exact
    probe key on the left compares character data without dispatching to
    the subclass.
    """
    if not _isa(mapping, dict):
        return None
    try:
        return mapping.get(key)
    except Exception:
        pass
    try:
        return dict.get(mapping, key)
    except Exception:
        pass
    try:
        for k, v in dict.items(mapping):
            if _isa(k, str) and str.__eq__(key, k) is True:
                return v
    except Exception:
        pass
    return None


def _list_rows(value) -> list:
    """Real elements of a list-shaped leftover; junk answers ``[]``.

    ``list.__iter__`` is a descriptor bound to the real list layout, so a
    *lying* ``__class__`` that answers ``list`` while the real type is not
    rejected the operand with a TypeError at call sites outside every try:
    one impostor aliases cell wiped the whole Cmd+K catalog to ``[]`` and
    degraded every find to the brief, an impostor problems / resident list
    dropped the snapshot section, and ``fallback_brief`` walks problems
    inside the router's own error fallback.
    """
    if not _isa(value, list):
        return []
    try:
        return list(list.__iter__(value))
    except Exception:
        return []


def _dict_len(mapping) -> int:
    """Unbound ``dict.__len__`` that cannot raise: a lying ``__class__``
    that answers ``dict`` rejects the descriptor — report it empty so the
    caller's existing fallback path runs instead of a blanket except."""
    try:
        return dict.__len__(mapping)
    except Exception:
        return 0


def _reply_text(value) -> str:
    """A chat-result cell as text; falsy junk stays the old empty drop.

    Coerce-first: a str-subclass ``__bool__`` bomb as the model's reply used
    to raise out of the bare ``or`` truthiness *outside* _run_llm's try —
    the whole turn then fell to the router's rebuilt fallback, losing the
    answer this call already had.  The exact-str coercion keeps its real
    text; non-text junk (0, False, []) keeps the old falsy-drop semantics.
    """
    if value is None or _isa(value, bool):
        return ""
    if _isa(value, (str, bytes, bytearray)):
        return _utf8_text(value)
    return _utf8_text(value) if _truthy(value) else ""


def _exact_number(raw):
    """Exact ``int``/``float`` or ``None`` — a numeric-subclass comparison
    bomb (``__ge__``/``__eq__``) cannot ride a threshold check."""
    if _isa(raw, bool) or raw is None:
        return None
    if _isa(raw, int):
        if type(raw) is not int:
            try:
                raw = int.__index__(raw)
            except Exception:
                return None
        return raw
    if _isa(raw, float):
        if type(raw) is not float:
            try:
                raw = float.__float__(raw)
            except Exception:
                return None
        if raw != raw or raw in (float("inf"), float("-inf")):
            return None
        return raw
    return None


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Finite floats, dicts and lists were already walked; a bytes load string or a
    tuple of ``inf`` (``os.getloadavg``-shaped leftovers) still leaked into the
    POST /api/assistant/ask body and failed the encoder. A leftover ``\\ud800``
    in the snapshot, the find-query echo, or a catalog title still 500'd the
    same body (``ensure_ascii=False`` then UTF-8).
    """
    if depth > 32:
        return None
    if value is None:
        return value
    if _isa(value, bool):
        # ``bool`` is final, so a value that answers this gate while its
        # real type is not ``bool`` is a lying-``__class__`` impostor, not a
        # genuine bool.  The old arm returned it raw, handing the response
        # encoder a non-serializable object: a leftover engine_up / uptime /
        # problem-state / ups-percent cell 500'd POST /api/assistant/ask on
        # every action at once.  Only a real bool renders; the impostor
        # drops to None like its lying int/float siblings.
        return value if type(value) is bool else None
    if _isa(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: an int-subclass truthiness /
                # comparison bomb used to survive this walk untouched, then
                # 500 fallback_brief and suggest_panels *inside the router's
                # own error fallback* — twice, with nothing above to catch it.
                value = int.__index__(value)
            except Exception:
                return None
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if _isa(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__ge__`` bomb
                # used to survive the NaN/inf probes, then 500 the disk
                # threshold in suggest_panels on both raises of the turn.
                value = float.__float__(value)
            except Exception:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isa(value, str):
        return _utf8_text(value)
    if _isa(value, (bytes, bytearray)):
        return _decode_bytes(value)
    if _isa(value, dict):
        # Unbound base view: a nested dict-subclass ``items()`` bomb used to
        # wipe the whole snapshot to the minimal brief.  The descriptor is
        # bound to the real dict layout, so a lying ``__class__`` claiming
        # ``dict`` blew the call itself outside every try — drop the
        # impostor like a lying int.
        try:
            items = dict.items(value)
        except Exception:
            return None
        out = {}
        for k, v in items:
            if _isa(k, (bytes, bytearray)):
                k = _decode_bytes(k)
                if k is None:
                    # A lying-``__class__`` key claiming bytes: drop just
                    # this entry, keep the rest of the mapping.
                    continue
            elif not _isa(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            try:
                k = _utf8_text(k)
            except Exception:
                continue
            out[k] = _jsonable(v, depth + 1)
        return out
    if _isa(value, (list, tuple, set, frozenset)):
        for base in (list, tuple, set, frozenset):
            if _isa(value, base):
                # Unbound base iteration: a subclass ``__iter__`` bomb
                # cannot raise and the real elements still survive.  A
                # lying ``__class__`` claiming this base rejects the
                # descriptor — drop the impostor, never the response.
                try:
                    rows = base.__iter__(value)
                except Exception:
                    return None
                return [_jsonable(v, depth + 1) for v in rows]
        return None
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # getattr's default only swallows AttributeError; a property or
        # ``__getattr__`` bomb still raised out of the probe itself.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 POST /api/assistant/ask.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    return None


def _panel_id(raw) -> str:
    """Catalog row identity as text; ``""`` drops the row.

    The ``jobs._task_id`` rule.  The strict ``isinstance(pid, str)`` gate
    silently wiped a numeric-id row (a hand-edited ``"id": 42`` — or a YAML /
    plist loader swap, which loads hex/octal *already-int* and uncapped) from
    every assistant answer at once: GET /api/assistant/catalog lost the Cmd+K
    row, ``match_panels`` stopped matching its aliases, and a page turn on its
    path lost the ``here`` context.  A renderable int coerces through the
    ``str()`` probe; an over-cap leftover — whose ``str()`` raises the same
    digit-cap ValueError ``json.dumps`` would — drops only its row.  bool
    passes ``isinstance(int)`` and must not become ``"True"``.
    """
    if _isa(raw, str):
        return _utf8_text(raw).strip()
    if _isa(raw, bool) or not _isa(raw, int):
        return ""
    try:
        # int.__index__ first: an int-subclass ``__str__`` bomb that raised
        # anything but the digit-cap ValueError escaped the old bare str()
        # here and 500'd POST /api/assistant/ask via suggest_panels' by-id
        # map — inside the router's error fallback too.  The base coercion
        # keeps the renderable value instead of dropping the row.
        return str(int.__index__(raw))
    except Exception:
        return ""


def _load_object(name: str) -> dict:
    data = _load_json(name)
    return data if isinstance(data, dict) else {}


def _load_list(name: str) -> list[dict]:
    data = _load_json(name)
    if not isinstance(data, list):
        return []
    return [row for row in data if isinstance(row, dict)]


def _compile(pattern: object) -> re.Pattern[str]:
    text = str(pattern or "")
    if not text:
        return re.compile(r"(?!)")
    try:
        return re.compile(text, re.I)
    except re.error:
        return re.compile(r"(?!)")


_INTENTS = _load_object("assistant_intents.json")
_LEADIN_RE = _compile(_INTENTS.get("leadin"))
_FIND_RE = _compile(_INTENTS.get("find"))
_BRIEF_RE = _compile(_INTENTS.get("brief"))
_QUESTION_RE = _compile(_INTENTS.get("question"))
_PAGE_RE = _compile(_INTENTS.get("page"))
_panel_word = _INTENTS.get("panel_word")
# ``w is not None`` + _utf8_text, not bare str(): the parse_int hook maps an
# over-cap number literal to None, and str(None) minted a "none" panel word
# that blanked the literal query "none"; an *already-int* over-cap leftover
# (a future loader swap) would ValueError the whole import.
_PANEL_WORDS = tuple(
    text.lower() for w in _panel_word
    if w is not None and (text := _utf8_text(w))
) if isinstance(_panel_word, list) else ()
PANELS: tuple[dict[str, Any], ...] = tuple(_load_list("assistant_panels.json"))
_BLURBS: dict[str, dict[str, str]] = {
    str(key): value
    for key, value in _load_object("assistant_blurbs.json").items()
    if isinstance(value, dict)
}


def normalize_locale(raw: str | None) -> str:
    text = str(raw or "").strip().lower()
    if text.startswith("zh"):
        return "zh-CN"
    if text.startswith("ja"):
        return "ja"
    return "en"


def _title(panel: dict, locale: str) -> str:
    # _dget, not bound ``.get``: a dict-subclass ``get`` bomb as the title
    # map used to raise out of suggest_panels — inside the router's error
    # fallback too, which nothing above catches: a raw 500.
    raw_titles = _dget(panel, "title")
    titles = raw_titles if _isa(raw_titles, dict) else {}
    # _utf8_text with fallthrough, not one bare str(): an over-cap already-int
    # title (>4300 digits — the int->str digit cap) used to ValueError out of
    # catalog()/match_panels()/resolve_path(), which wiped the whole Cmd+K
    # catalog to [] and silently degraded find/page turns to the generic brief.
    for candidate in (_dget(titles, locale), _dget(titles, "en"), _dget(panel, "id")):
        # ``is None`` + _truthy, not bare ``not candidate``: a subclass
        # truthiness bomb must skip the candidate, never raise.
        if candidate is None or not _truthy(candidate):
            continue
        text = _utf8_text(candidate)
        if text:
            return text
    return ""


def _blurb(panel_id: str, locale: str) -> str:
    raw_row = _dget(_BLURBS, panel_id)
    row = raw_row if _isa(raw_row, dict) else {}
    for candidate in (_dget(row, locale), _dget(row, "en")):
        if candidate is None or not _truthy(candidate):
            continue
        text = _utf8_text(candidate)
        if text:
            return text
    return ""


def resolve_path(path: str | None, locale: str | None = None) -> dict | None:
    """Map a SPA path to a catalog row, or None."""
    loc = normalize_locale(locale)
    raw = str(path or "").strip().split("?", 1)[0] or "/"
    if not raw.startswith("/"):
        raw = "/" + raw
    if raw != "/" and raw.endswith("/"):
        raw = raw.rstrip("/")
    hit = None
    # _dget + the _utf8_text coercion, not bound ``.get`` and a raw ``==``:
    # a dict-subclass ``get`` bomb or a str-subclass ``__eq__`` bomb on one
    # row used to kill the page turn for *every* row at once.
    for panel in PANELS:
        if not _isa(panel, dict):
            continue
        pth = _dget(panel, "path")
        if _isa(pth, str) and _utf8_text(pth) == raw:
            hit = panel
            break
    if hit is None:
        for panel in PANELS:
            if not _isa(panel, dict):
                continue
            pth = _dget(panel, "path")
            if _isa(pth, str):
                text = _utf8_text(pth)
                if text != "/" and raw.startswith(text + "/"):
                    hit = panel
                    break
    if hit is None:
        return None
    # _panel_id, not an isinstance(pid, str) gate: a numeric-id row used to
    # lose the page turn's ``here`` context even though its path matched.
    pid, pth = _panel_id(_dget(hit, "id")), _dget(hit, "path")
    if not pid or not _isa(pth, str):
        return None
    return {
        "id": pid,
        "path": _utf8_text(pth),
        "title": _title(hit, loc),
        "blurb": _blurb(pid, loc),
    }


def catalog(locale: str | None = None) -> list[dict]:
    loc = normalize_locale(locale)
    out = []
    for panel in PANELS:
        if not _isa(panel, dict):
            continue
        # _panel_id, not an isinstance(pid, str) gate: a numeric-id row used
        # to vanish from the Cmd+K catalog (the numeric-YAML-ids rule).  The
        # path stays a str gate — it is the SPA navigation target, and a
        # non-string path is junk the palette cannot open.
        pid = _panel_id(_dget(panel, "id"))
        path = _dget(panel, "path")
        # _list_rows, not a bare ``list.__iter__`` behind an _isa gate: a
        # lying-``__class__`` aliases cell passed the gate, rejected the
        # unbound descriptor and wiped the whole catalog to [].
        aliases = _list_rows(_dget(panel, "aliases"))
        if not pid or not _isa(path, str):
            continue
        out.append({
            "id": pid,
            # _utf8_text, not the raw value: a str-subclass path whose
            # ``__str__`` answers itself carried its bound ``encode`` bomb
            # through the route's try into the final _jsonable and 500'd
            # GET /api/assistant/catalog.
            "path": _utf8_text(path),
            "title": _title(panel, loc),
            # ``a is not None``: the parse_int hook maps an over-cap number
            # literal to None; a "None" alias must not start matching queries.
            # _utf8_text, not bare str(): an over-cap *already-int* alias used
            # to ValueError here and wipe the whole catalog to [] — drop just
            # the unrenderable alias, like its inf float sibling.
            # _list_rows: a subclass iterator bomb or a lying-``__class__``
            # impostor drops nothing but itself.
            "aliases": [
                text for a in aliases
                if a is not None and (text := _utf8_text(a))
            ],
        })
    return out


def _score_panel(panel: dict, needle: str, locale: str) -> int:
    if not needle:
        return 0
    title = _title(panel, locale).lower()
    # _dget + a str gate, not ``str(panel.get("path") or "")``: a subclass
    # ``get`` or truthiness bomb must score zero, not raise out of the find.
    raw_path = _dget(panel, "path")
    path = _utf8_text(raw_path).lower() if _isa(raw_path, str) else ""
    raw_aliases = _dget(panel, "aliases")
    # _utf8_text, not bare str(): an over-cap already-int alias used to
    # ValueError out of match_panels() and turn every find into the brief.
    # _list_rows: a lying-``__class__`` aliases cell used to reject the
    # unbound ``list.__iter__`` the same way and degrade every find too.
    aliases = [
        text.lower() for a in _list_rows(raw_aliases)
        if a is not None and (text := _utf8_text(a))
    ]
    # _panel_id, not bare str(): callers gate rows on the probe, but this
    # comparison must not be the one bare int->str left to re-raise.
    if needle == title or needle == _panel_id(_dget(panel, "id")) or needle == path.lstrip("/"):
        return 100
    if needle in aliases:
        return 90
    if title.startswith(needle) or any(a.startswith(needle) for a in aliases):
        return 80
    if needle in title or needle in path:
        return 70
    if any(needle in a or a in needle for a in aliases if len(a) >= 2):
        return 60
    return 0


def match_panels(query: str, locale: str | None = None, limit: int = 6) -> list[dict]:
    """Ranked catalog hits for a free-text page name."""
    loc = normalize_locale(locale)
    raw = str(query or "").strip()
    needle = _LEADIN_RE.sub("", raw).strip().lower()
    for word in _PANEL_WORDS:
        if needle == word:
            needle = ""
            break
        if needle.endswith(word) and len(needle) > len(word):
            needle = needle[: -len(word)].strip()
            break
    if not needle:
        return []
    scored: list[tuple[int, dict]] = []
    for panel in PANELS:
        if not _isa(panel, dict):
            continue
        # _panel_id, not an isinstance(pid, str) gate: a find used to skip a
        # numeric-id row even when the query hit its alias dead-on.
        pid, pth = _panel_id(_dget(panel, "id")), _dget(panel, "path")
        if not pid or not _isa(pth, str):
            continue
        score = _score_panel(panel, needle, loc)
        if score <= 0:
            continue
        scored.append((score, {
            "id": pid,
            # _utf8_text: the dedupe set below hashes this value, and a
            # str-subclass ``__hash__`` bomb must not raise out of the find.
            "path": _utf8_text(pth),
            "title": _title(panel, loc),
            "score": score,
        }))
    scored.sort(key=lambda item: (-item[0], item[1]["id"]))
    seen: set[str] = set()
    out: list[dict] = []
    for _score, row in scored:
        if row["path"] in seen:
            continue
        seen.add(row["path"])
        out.append(row)
        if len(out) >= limit:
            break
    return out


def classify_intent(query: str, action: str = "auto") -> str:
    act = str(action or "auto").strip().lower()
    if act not in ACTIONS:
        raise api_error("assistant.bad_action")
    if act != "auto":
        return act
    text = str(query or "").strip()
    if not text:
        return "brief"
    if _BRIEF_RE.search(text):
        return "brief"
    if _PAGE_RE.search(text):
        return "page"
    if _QUESTION_RE.search(text):
        return "ask"
    if _FIND_RE.search(text):
        return "find"
    hits = match_panels(text)
    if hits and hits[0]["score"] >= 80:
        return "find"
    return "ask"


def build_snapshot() -> dict:
    """Compact host facts for the model — cached collectors only when possible."""
    from hub.status import full_status, peek_status

    try:
        status = peek_status()
        # Unbound ``dict.__len__``, not the bare ``or`` truthiness: a
        # dict-subclass ``__bool__`` bomb on the cached snapshot used to
        # fall into this except and wipe every field even though the real
        # rows were right there.  _dict_len, not the bare descriptor: a
        # lying-``__class__`` peek result rejected the call into the same
        # except and skipped the full_status() retry the sane path still had.
        if not (_isa(status, dict) and _dict_len(status)):
            status = full_status()
    except Exception:
        status = {}
    if not _isa(status, dict):
        status = {}
    # _dget, not bound ``.get``: a dict-subclass ``get`` bomb used to raise
    # out of here and wipe the whole snapshot to the minimal brief.
    system = _dget(status, "system")
    system = system if _isa(system, dict) else {}
    counts = _dget(status, "counts")
    counts = counts if _isa(counts, dict) else {}
    raw_problems = _dget(status, "problems")
    problems = []
    # _list_rows: a subclass iterator bomb or a lying-``__class__`` impostor
    # drops nothing but itself.
    rows = _list_rows(raw_problems)[:8]
    for row in rows:
        if not _isa(row, dict):
            continue
        detail = _dget(row, "detail")
        name = _dget(row, "name")
        if not _truthy(name):
            name = _dget(row, "id")
        problems.append({
            "name": name,
            "state": _dget(row, "state"),
            # _utf8_text, not bare str(): a >4300-digit leftover detail used
            # to ValueError here and lose the whole snapshot.
            "detail": _utf8_text(detail if detail is not None else "")[:80],
        })
    snap: dict[str, Any] = {
        "load": _dget(system, "load"),
        "cpu_load_pct": _dget(system, "load_pct"),
        "mem_used_pct": _dget(system, "mem_used_pct"),
        "mem_total_gb": _dget(system, "mem_total_gb"),
        "disk_root_pct": _dget(system, "disk_pct"),
        # _utf8_text, not a bare f-string: a >4300-digit leftover disk size
        # used to ValueError the int->str here and lose the whole snapshot.
        "disk_root": f"{_utf8_text(_dget(system, 'disk_used_gb'))}/{_utf8_text(_dget(system, 'disk_total_gb'))} GB",
        "uptime": _dget(system, "uptime"),
        "engine_up": _dget(status, "engine_up"),
        "counts": {
            key: _safe_int(_dget(counts, key)) for key in ("ok", "warn", "down", "stopped")
        },
        "problems": problems,
    }
    try:
        from hub import ollama_svc
        ollama = ollama_svc.status()
    except Exception:
        ollama = None
    if _isa(ollama, dict):
        # _dget / _truthy / list.__iter__, not bound ``.get`` and bare
        # truthiness: a dict-subclass ``get`` bomb on the status wrapper (or
        # on one resident row) used to fall into the old blanket except and
        # drop the whole ollama section even though the sane rows were right
        # underneath — the ups/ollama settings rule.
        raw_resident = _dget(ollama, "resident")
        rows = _list_rows(raw_resident)[:2]
        snap["ollama"] = {
            "reachable": _truthy(_dget(ollama, "reachable")),
            "resident": [
                name for row in rows
                if _isa(row, dict) and _truthy(name := _dget(row, "name"))
            ],
        }
    try:
        from hub.ups_svc import ups_snapshot
        ups = ups_snapshot()
    except Exception:
        ups = None
    # Same rule: a ``get`` bomb on the ups wrapper used to drop the whole
    # ups block, so the brief lost a real on-battery state.
    if _isa(ups, dict) and _truthy(_dget(ups, "present")):
        snap["ups"] = {
            "source": _dget(ups, "source"),
            "percent": _dget(ups, "percent"),
            "charging": _dget(ups, "charging"),
        }
    return _jsonable(snap)


def suggest_panels(snapshot: dict, locale: str) -> list[dict]:
    """Pages that match the current snapshot — no model required."""
    loc = normalize_locale(locale)
    wanted: list[str] = []
    # Everything here runs a second time inside the router's own error
    # fallback with the same snapshot; a raise there is a guaranteed 500.
    counts = _dget(snapshot, "counts")
    counts = counts if _isa(counts, dict) else {}
    if _safe_int(_dget(counts, "down")) or _safe_int(_dget(counts, "warn")):
        wanted.extend(["services", "health", "logs"])
    # _exact_number, not a raw ``>=`` on the snapshot value: a float-subclass
    # ``__ge__`` bomb used to raise out of this threshold on both passes of
    # the turn and 500 POST /api/assistant/ask.
    disk = _exact_number(_dget(snapshot, "disk_root_pct"))
    if disk is not None and disk >= 85:
        wanted.append("main")
    ollama = _dget(snapshot, "ollama")
    ollama = ollama if _isa(ollama, dict) else {}
    if _truthy(ollama) and not _truthy(_dget(ollama, "reachable")):
        wanted.append("ollama")
    ups = _dget(snapshot, "ups")
    ups = ups if _isa(ups, dict) else {}
    # _utf8_text, not a bare set-membership on the raw value: an unhashable
    # leftover source (a YAML ``source: [battery]`` list, or a dict) used to
    # TypeError this ``in {...}`` — and the router's error fallback calls
    # suggest_panels again with the same poisoned snapshot, so the raise
    # escaped everything and 500'd POST /api/assistant/ask.  The probe
    # coerces a bytes leftover to its text and drops junk shapes.
    if _utf8_text(_dget(ups, "source")) in {"battery", "ups"}:
        wanted.append("dashboard")
    if not wanted:
        wanted.extend(["dashboard", "health"])
    # _panel_id keys the map the same way catalog()/match_panels() gate rows,
    # and the emitted id is the coerced text — never the raw (possibly int)
    # value, which _jsonable would null out past the digit cap.  _dget, not
    # bound ``.get``: a dict-subclass ``get`` bomb on one row used to 500
    # the whole turn from right here.  _isa, not bare isinstance: a row (or
    # its id) whose ``__class__`` is a raising property blew the gate itself
    # on both passes of the turn — a raw 500 from inside the router's own
    # error fallback.
    by_id = {
        pid: panel
        for panel in PANELS
        if _isa(panel, dict) and (pid := _panel_id(_dget(panel, "id")))
    }
    out: list[dict] = []
    seen: set[str] = set()
    for panel_id in wanted:
        panel = by_id.get(panel_id)
        # ``is None``, not truthiness: a dict-subclass ``__bool__`` bomb on
        # the row must not raise out of the guard itself.
        path = _dget(panel, "path") if panel is not None else None
        if panel is None or not _isa(path, str):
            continue
        # _utf8_text before the dedupe set: a str-subclass ``__hash__`` bomb
        # used to raise out of this membership probe on both passes.
        text = _utf8_text(path)
        if text in seen:
            continue
        seen.add(text)
        out.append({"id": panel_id, "path": text, "title": _title(panel, loc)})
    return out


def _brief_cell(value, *, keep_zero: bool = False) -> str:
    """One brief field as text.  A bare f-string used to ValueError on a
    >4300-digit leftover int (CPython's int->str digit cap) — inside the
    router's own error fallback, which is a guaranteed 500."""
    if value is None:
        return "—"
    # _truthy, not bare ``not value``: an int-subclass ``__bool__`` bomb as
    # the load cell used to raise here — inside the router's error fallback
    # too, which nothing above catches: a raw 500.
    if not keep_zero and not _truthy(value):
        return "—"
    return _utf8_text(value) or "—"


def fallback_brief(snapshot: dict, locale: str | None = None) -> str:
    """English template status when Ollama is down.  The SPA localizes this."""
    del locale  # locale is applied by the drawer; keep the signature stable.
    # This whole function runs inside the router's own error fallback, so a
    # raise anywhere below is a guaranteed 500: _dget instead of bound
    # ``.get``, _truthy instead of bare truthiness.
    counts = _dget(snapshot, "counts")
    counts = counts if _isa(counts, dict) else {}
    # _truthy: an int-subclass ``__bool__`` bomb as engine_up used to raise
    # out of this conditional on both passes of the turn.
    engine = "on" if _truthy(_dget(snapshot, "engine_up")) else "off"
    raw_problems = _dget(snapshot, "problems")
    # _list_rows: a lying-``__class__`` problems cell used to reject the
    # unbound ``list.__iter__`` right here — inside the router's own error
    # fallback, where the re-raise is a guaranteed 500.
    problems = [p for p in _list_rows(raw_problems) if _isa(p, dict)]
    lines = [
        f"Overview: load {_brief_cell(_dget(snapshot, 'load'))} (~{_brief_cell(_dget(snapshot, 'cpu_load_pct'), keep_zero=True)}%)"
        f" · memory used {_brief_cell(_dget(snapshot, 'mem_used_pct'), keep_zero=True)}%"
        f" · root disk {_brief_cell(_dget(snapshot, 'disk_root_pct'), keep_zero=True)}%"
        f" ({_brief_cell(_dget(snapshot, 'disk_root'))}) · up {_brief_cell(_dget(snapshot, 'uptime'))}",
        f"Services: {_safe_int(_dget(counts, 'ok'))} ok · {_safe_int(_dget(counts, 'warn'))} warn"
        f" · {_safe_int(_dget(counts, 'down'))} down · Docker {engine}",
    ]
    if problems:
        lines.append("Needs attention:")
        lines.extend(
            f"- {_brief_cell(_dget(p, 'name'))} · {_brief_cell(_dget(p, 'state'))} · {_brief_cell(_dget(p, 'detail'))}"
            for p in problems[:6]
        )
    else:
        lines.append("No service alerts need attention.")
    return "\n".join(lines)


def _pick_model() -> str | None:
    from hub import ollama_svc

    snap = ollama_svc.status()
    # _dget / _truthy / list.__iter__, not bound ``.get`` and bare
    # truthiness: a dict-subclass ``get`` bomb on the status wrapper used to
    # raise into _run_llm's blanket except and silently skip the model the
    # sane data underneath still named — every turn fell to the template
    # brief while the daemon was up.
    if not _isa(snap, dict) or not _truthy(_dget(snap, "reachable")):
        return None
    for key in ("resident", "models"):
        rows = _dget(snap, key)
        for row in _list_rows(rows):
            if not _isa(row, dict):
                continue
            name = _dget(row, "name")
            # _utf8_text, not bare str(): an over-cap already-int name used
            # to ValueError here and skip the sane sibling rows too.
            text = _utf8_text(name if name is not None else "").strip()
            if text:
                return text
    return None


def _lang_name(locale: str) -> str:
    return {"zh-CN": "Simplified Chinese", "ja": "Japanese"}.get(locale, "English")


def _system_prompt(snapshot: dict, locale: str) -> str:
    loc = normalize_locale(locale)
    # _dget + _utf8_text, not bound ``.get`` and a raw subscript: a
    # dict-subclass ``get`` bomb on one catalog row used to raise into
    # _run_llm's blanket except — one poisoned row wiped the model's answer
    # for every turn.  Junk drops the row, never the prompt.
    pages = ", ".join(
        f"{_title(p, loc)} {_utf8_text(pth)}"
        for p in PANELS
        if _isa(p, dict) and _isa(pth := _dget(p, "path"), str)
    )
    try:
        snap_json = json.dumps(
            _jsonable(snapshot),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError, RecursionError):
        # RecursionError: leftover nested snapshot after _jsonable is not ValueError.
        snap_json = "{}"
    return (
        f"You are ServerHub's local assistant on this Mac. Answer in {_lang_name(loc)}. "
        "Be concise (4-8 short lines). Do not invent numbers; use only the snapshot. "
        "If a page would help, name it and its path.\n"
        f"Snapshot:\n{snap_json}\n"
        f"Pages: {pages}"
    )


def _brief_user_prompt() -> str:
    return (
        "Write a system-status brief from the snapshot. Overall first, then "
        "what needs attention, then 1-2 panel paths to open."
    )


def _page_user_prompt() -> str:
    return (
        "Explain the current ServerHub page in snapshot.here. What it is for, "
        "what to check on it, and one next click. Use snapshot.here.blurb; "
        "do not invent features."
    )


def _run_llm(user_text: str, locale: str, snapshot: dict, history: list[dict] | None) -> dict:
    from hub import ollama_svc

    try:
        model = _pick_model()
        if not model:
            return {}
        messages = [{"role": "system", "content": _system_prompt(snapshot, locale)}]
        raw_hist = history if _isa(history, list) else []
        for raw in raw_hist[-MAX_HISTORY:]:
            if not isinstance(raw, dict):
                continue
            role = str(raw.get("role") or "")
            content = str(raw.get("content") or "").strip()
            if role in {"user", "assistant"} and content:
                messages.append({"role": role, "content": content[:MAX_QUERY_CHARS]})
        messages.append({"role": "user", "content": user_text})
        result = ollama_svc.chat(model, messages, MAX_NUM_PREDICT)
    except Exception:
        return {}
    # _isa, not bare isinstance: this gate runs *outside* the try above, so
    # a chat result whose ``__class__`` is a raising property used to drop
    # the whole turn to the router's rebuilt fallback.
    if not _isa(result, dict):
        return {}
    # _dget + _reply_text, not bound ``.get`` and a bare ``or``: everything
    # below runs *outside* the try above, so a dict-subclass ``get`` bomb on
    # the chat result (or a content ``__bool__`` bomb) used to raise out of
    # here and drop the whole turn to the router's rebuilt fallback, losing
    # the answer this call already had.  _reply_text keeps the earlier fixes
    # too: bytes content decodes instead of answering its repr, and an
    # over-cap already-int drops the cell, never the turn.
    text = _reply_text(_dget(result, "content")).strip() or _reply_text(_dget(result, "thinking")).strip()
    if not text:
        return {}
    picked = _dget(result, "model")
    # str gate: a non-text model cell (a ``__class__`` bomb, a numeric id)
    # would only be nulled by the final _jsonable — keep the model this
    # call actually picked instead.
    return {
        "text": text,
        "thinking": _reply_text(_dget(result, "thinking")),
        "model": picked if _isa(picked, str) and _truthy(picked) else model,
        "duration_s": _jsonable(_dget(result, "duration_s")),
    }


def _find_text(hits: list[dict], query: str) -> str:
    if not hits:
        return f"No panel matches “{query}”. Try another name, or open the dashboard."
    return "Matching panels:"


def ask(
    query: str,
    *,
    locale: str = "zh-CN",
    action: str = "auto",
    history: list[dict] | None = None,
    path: str | None = None,
) -> dict:
    """One assistant turn.  Find and page-catalog never call the model."""
    loc = normalize_locale(locale)
    text = str(query or "").strip()
    if len(text) > MAX_QUERY_CHARS:
        raise api_error("ollama.prompt_too_long", max=MAX_QUERY_CHARS)
    kind = classify_intent(text, action)
    if kind == "ask" and not text:
        raise api_error("assistant.query_required")

    snapshot = build_snapshot()
    here = resolve_path(path, loc)
    if here:
        snapshot["here"] = here
    suggested = suggest_panels(snapshot, loc)

    if kind == "find":
        hits = match_panels(text, loc) if text else catalog(loc)[:12]
        return _jsonable({
            "ok": True,
            "kind": "find",
            "text": _find_text(hits, text),
            "thinking": "",
            "panels": hits or suggested[:3],
            "snapshot": snapshot,
            "model": None,
            "used_llm": False,
            "duration_s": 0,
        })

    if kind == "page":
        page = here or resolve_path("/", loc)
        panels = [page] if page else []
        fallback = (page or {}).get("blurb") or fallback_brief(snapshot, loc)
        llm = _run_llm(_page_user_prompt(), loc, snapshot, history)
        if llm:
            return _jsonable({
                "ok": True,
                "kind": "page",
                "text": llm["text"],
                "thinking": llm.get("thinking") or "",
                "panels": panels,
                "snapshot": snapshot,
                "model": llm.get("model"),
                "used_llm": True,
                "duration_s": llm.get("duration_s"),
            })
        return _jsonable({
            "ok": True,
            "kind": "page",
            "text": fallback,
            "thinking": "",
            "panels": panels,
            "snapshot": snapshot,
            "model": None,
            "used_llm": False,
            "duration_s": 0,
        })

    user_prompt = text if kind == "ask" else (_brief_user_prompt() if not text else text)
    llm = _run_llm(user_prompt, loc, snapshot, history)
    if llm:
        extra = match_panels(text, loc) if text else []
        panels = extra or suggested
        return _jsonable({
            "ok": True,
            "kind": "brief" if kind == "brief" else "answer",
            "text": llm["text"],
            "thinking": llm.get("thinking") or "",
            "panels": panels[:6],
            "snapshot": snapshot,
            "model": llm.get("model"),
            "used_llm": True,
            "duration_s": llm.get("duration_s"),
        })

    return _jsonable({
        "ok": True,
        "kind": "brief" if kind == "brief" else "answer",
        "text": fallback_brief(snapshot, loc),
        "thinking": "",
        "panels": suggested,
        "snapshot": snapshot,
        "model": None,
        "used_llm": False,
        "duration_s": 0,
    })
