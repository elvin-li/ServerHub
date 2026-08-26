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


def _safe_int(raw, default: int = 0) -> int:
    if isinstance(raw, bool) or raw is None:
        return default
    if isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
        return default
    try:
        value = int(raw)
        # An *already-int* leftover past CPython's int->str digit cap (YAML /
        # plist hex loads uncapped) passes int() but blows every later str()
        # — fallback_brief's f-strings and the JSON encoder both 500'd.
        str(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return value


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
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
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, (str, bytes, bytearray)):
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
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
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
    if isinstance(raw, str):
        return _utf8_text(raw).strip()
    if isinstance(raw, bool) or not isinstance(raw, int):
        return ""
    try:
        return str(raw)
    except ValueError:
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
    titles = panel.get("title") if isinstance(panel.get("title"), dict) else {}
    # _utf8_text with fallthrough, not one bare str(): an over-cap already-int
    # title (>4300 digits — the int->str digit cap) used to ValueError out of
    # catalog()/match_panels()/resolve_path(), which wiped the whole Cmd+K
    # catalog to [] and silently degraded find/page turns to the generic brief.
    for candidate in (titles.get(locale), titles.get("en"), panel.get("id")):
        if not candidate:
            continue
        text = _utf8_text(candidate)
        if text:
            return text
    return ""


def _blurb(panel_id: str, locale: str) -> str:
    row = _BLURBS.get(panel_id) or {}
    for candidate in (row.get(locale), row.get("en")):
        if not candidate:
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
    for panel in PANELS:
        if not isinstance(panel, dict):
            continue
        if panel.get("path") == raw:
            hit = panel
            break
    if hit is None:
        for panel in PANELS:
            if not isinstance(panel, dict):
                continue
            pth = panel.get("path")
            if isinstance(pth, str) and pth != "/" and raw.startswith(pth + "/"):
                hit = panel
                break
    if hit is None:
        return None
    # _panel_id, not an isinstance(pid, str) gate: a numeric-id row used to
    # lose the page turn's ``here`` context even though its path matched.
    pid, pth = _panel_id(hit.get("id")), hit.get("path")
    if not pid or not isinstance(pth, str):
        return None
    return {
        "id": pid,
        "path": pth,
        "title": _title(hit, loc),
        "blurb": _blurb(pid, loc),
    }


def catalog(locale: str | None = None) -> list[dict]:
    loc = normalize_locale(locale)
    out = []
    for panel in PANELS:
        if not isinstance(panel, dict):
            continue
        # _panel_id, not an isinstance(pid, str) gate: a numeric-id row used
        # to vanish from the Cmd+K catalog (the numeric-YAML-ids rule).  The
        # path stays a str gate — it is the SPA navigation target, and a
        # non-string path is junk the palette cannot open.
        pid = _panel_id(panel.get("id"))
        path = panel.get("path")
        aliases = panel.get("aliases")
        if not pid or not isinstance(path, str):
            continue
        if not isinstance(aliases, list):
            aliases = []
        out.append({
            "id": pid,
            "path": path,
            "title": _title(panel, loc),
            # ``a is not None``: the parse_int hook maps an over-cap number
            # literal to None; a "None" alias must not start matching queries.
            # _utf8_text, not bare str(): an over-cap *already-int* alias used
            # to ValueError here and wipe the whole catalog to [] — drop just
            # the unrenderable alias, like its inf float sibling.
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
    path = str(panel.get("path") or "").lower()
    raw_aliases = panel.get("aliases")
    # _utf8_text, not bare str(): an over-cap already-int alias used to
    # ValueError out of match_panels() and turn every find into the brief.
    aliases = [
        text.lower() for a in raw_aliases
        if a is not None and (text := _utf8_text(a))
    ] if isinstance(raw_aliases, list) else []
    # _panel_id, not bare str(): callers gate rows on the probe, but this
    # comparison must not be the one bare int->str left to re-raise.
    if needle == title or needle == _panel_id(panel.get("id")) or needle == path.lstrip("/"):
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
        if not isinstance(panel, dict):
            continue
        # _panel_id, not an isinstance(pid, str) gate: a find used to skip a
        # numeric-id row even when the query hit its alias dead-on.
        pid, pth = _panel_id(panel.get("id")), panel.get("path")
        if not pid or not isinstance(pth, str):
            continue
        score = _score_panel(panel, needle, loc)
        if score <= 0:
            continue
        scored.append((score, {
            "id": pid,
            "path": pth,
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
        status = peek_status() or full_status()
    except Exception:
        status = {}
    if not isinstance(status, dict):
        status = {}
    system = status.get("system") if isinstance(status.get("system"), dict) else {}
    counts = status.get("counts") if isinstance(status.get("counts"), dict) else {}
    problems = []
    for row in (status.get("problems") if isinstance(status.get("problems"), list) else [])[:8]:
        if not isinstance(row, dict):
            continue
        problems.append({
            "name": row.get("name") or row.get("id"),
            "state": row.get("state"),
            # _utf8_text, not bare str(): a >4300-digit leftover detail used
            # to ValueError here and lose the whole snapshot.
            "detail": _utf8_text(row.get("detail") or "")[:80],
        })
    snap: dict[str, Any] = {
        "load": system.get("load"),
        "cpu_load_pct": system.get("load_pct"),
        "mem_used_pct": system.get("mem_used_pct"),
        "mem_total_gb": system.get("mem_total_gb"),
        "disk_root_pct": system.get("disk_pct"),
        # _utf8_text, not a bare f-string: a >4300-digit leftover disk size
        # used to ValueError the int->str here and lose the whole snapshot.
        "disk_root": f"{_utf8_text(system.get('disk_used_gb'))}/{_utf8_text(system.get('disk_total_gb'))} GB",
        "uptime": system.get("uptime"),
        "engine_up": status.get("engine_up"),
        "counts": {
            key: _safe_int(counts.get(key)) for key in ("ok", "warn", "down", "stopped")
        },
        "problems": problems,
    }
    try:
        from hub import ollama_svc
        ollama = ollama_svc.status()
        snap["ollama"] = {
            "reachable": bool(ollama.get("reachable")),
            "resident": [m.get("name") for m in (ollama.get("resident") or [])[:2] if m.get("name")],
        }
    except Exception:
        pass
    try:
        from hub.ups_svc import ups_snapshot
        ups = ups_snapshot()
        if ups.get("present"):
            snap["ups"] = {
                "source": ups.get("source"),
                "percent": ups.get("percent"),
                "charging": ups.get("charging"),
            }
    except Exception:
        pass
    return _jsonable(snap)


def suggest_panels(snapshot: dict, locale: str) -> list[dict]:
    """Pages that match the current snapshot — no model required."""
    loc = normalize_locale(locale)
    wanted: list[str] = []
    counts = snapshot.get("counts") if isinstance(snapshot.get("counts"), dict) else {}
    if _safe_int(counts.get("down")) or _safe_int(counts.get("warn")):
        wanted.extend(["services", "health", "logs"])
    disk = snapshot.get("disk_root_pct")
    if isinstance(disk, (int, float)) and disk >= 85:
        wanted.append("main")
    ollama = snapshot.get("ollama") if isinstance(snapshot.get("ollama"), dict) else {}
    if ollama and not ollama.get("reachable"):
        wanted.append("ollama")
    ups = snapshot.get("ups") if isinstance(snapshot.get("ups"), dict) else {}
    if ups.get("source") in {"battery", "ups"}:
        wanted.append("dashboard")
    if not wanted:
        wanted.extend(["dashboard", "health"])
    # _panel_id keys the map the same way catalog()/match_panels() gate rows,
    # and the emitted id is the coerced text — never the raw (possibly int)
    # value, which _jsonable would null out past the digit cap.
    by_id = {
        pid: panel
        for panel in PANELS
        if isinstance(panel, dict) and (pid := _panel_id(panel.get("id")))
    }
    out: list[dict] = []
    seen: set[str] = set()
    for panel_id in wanted:
        panel = by_id.get(panel_id)
        path = panel.get("path") if panel else None
        if not panel or not isinstance(path, str) or path in seen:
            continue
        seen.add(path)
        out.append({"id": panel_id, "path": path, "title": _title(panel, loc)})
    return out


def _brief_cell(value, *, keep_zero: bool = False) -> str:
    """One brief field as text.  A bare f-string used to ValueError on a
    >4300-digit leftover int (CPython's int->str digit cap) — inside the
    router's own error fallback, which is a guaranteed 500."""
    if value is None:
        return "—"
    if not keep_zero and not value:
        return "—"
    return _utf8_text(value) or "—"


def fallback_brief(snapshot: dict, locale: str | None = None) -> str:
    """English template status when Ollama is down.  The SPA localizes this."""
    del locale  # locale is applied by the drawer; keep the signature stable.
    counts = snapshot.get("counts") if isinstance(snapshot.get("counts"), dict) else {}
    engine = "on" if snapshot.get("engine_up") else "off"
    raw_problems = snapshot.get("problems")
    problems = [p for p in raw_problems if isinstance(p, dict)] if isinstance(raw_problems, list) else []
    lines = [
        f"Overview: load {_brief_cell(snapshot.get('load'))} (~{_brief_cell(snapshot.get('cpu_load_pct'), keep_zero=True)}%)"
        f" · memory used {_brief_cell(snapshot.get('mem_used_pct'), keep_zero=True)}%"
        f" · root disk {_brief_cell(snapshot.get('disk_root_pct'), keep_zero=True)}%"
        f" ({_brief_cell(snapshot.get('disk_root'))}) · up {_brief_cell(snapshot.get('uptime'))}",
        f"Services: {_safe_int(counts.get('ok'))} ok · {_safe_int(counts.get('warn'))} warn"
        f" · {_safe_int(counts.get('down'))} down · Docker {engine}",
    ]
    if problems:
        lines.append("Needs attention:")
        lines.extend(
            f"- {_brief_cell(p.get('name'))} · {_brief_cell(p.get('state'))} · {_brief_cell(p.get('detail'))}"
            for p in problems[:6]
        )
    else:
        lines.append("No service alerts need attention.")
    return "\n".join(lines)


def _pick_model() -> str | None:
    from hub import ollama_svc

    snap = ollama_svc.status()
    if not isinstance(snap, dict) or not snap.get("reachable"):
        return None
    for key in ("resident", "models"):
        rows = snap.get(key)
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "").strip()
            if name:
                return name
    return None


def _lang_name(locale: str) -> str:
    return {"zh-CN": "Simplified Chinese", "ja": "Japanese"}.get(locale, "English")


def _system_prompt(snapshot: dict, locale: str) -> str:
    loc = normalize_locale(locale)
    pages = ", ".join(
        f"{_title(p, loc)} {p['path']}"
        for p in PANELS
        if isinstance(p, dict) and isinstance(p.get("path"), str)
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
        raw_hist = history if isinstance(history, list) else []
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
    if not isinstance(result, dict):
        return {}
    # _utf8_text, not bare str(): bytes content used to answer its Python
    # repr (``b'...'``), and an over-cap already-int used to ValueError
    # *outside* the try above — the whole turn then fell to the router's
    # rebuilt fallback, losing the page context this call already had.
    text = _utf8_text(result.get("content") or "").strip() or _utf8_text(result.get("thinking") or "").strip()
    if not text:
        return {}
    return {
        "text": text,
        "thinking": _utf8_text(result.get("thinking") or ""),
        "model": result.get("model") or model,
        "duration_s": _jsonable(result.get("duration_s")),
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
