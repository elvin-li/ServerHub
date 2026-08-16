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

CODES.setdefault("assistant.query_required", (400, "a question or page name is required"))
CODES.setdefault("assistant.bad_action", (400, "action must be auto, find, brief, ask, or page"))

ACTIONS = frozenset({"auto", "find", "brief", "ask", "page"})
MAX_QUERY_CHARS = 500
MAX_HISTORY = 6
MAX_NUM_PREDICT = 192

_HERE = Path(__file__).resolve().parent


def _load_json(name: str):
    return json.loads((_HERE / name).read_text(encoding="utf-8"))


_INTENTS = _load_json("assistant_intents.json")
_LEADIN_RE = re.compile(_INTENTS["leadin"], re.I)
_FIND_RE = re.compile(_INTENTS["find"], re.I)
_BRIEF_RE = re.compile(_INTENTS["brief"], re.I)
_QUESTION_RE = re.compile(_INTENTS["question"], re.I)
_PANEL_WORDS = tuple(str(w).lower() for w in _INTENTS["panel_word"])
_PAGE_RE = re.compile(_INTENTS["page"], re.I)
PANELS: tuple[dict[str, Any], ...] = tuple(_load_json("assistant_panels.json"))
_BLURBS: dict[str, dict[str, str]] = _load_json("assistant_blurbs.json")


def normalize_locale(raw: str | None) -> str:
    text = str(raw or "").strip().lower()
    if text.startswith("zh"):
        return "zh-CN"
    if text.startswith("ja"):
        return "ja"
    return "en"


def _title(panel: dict, locale: str) -> str:
    titles = panel.get("title") or {}
    return str(titles.get(locale) or titles.get("en") or panel.get("id") or "")


def _blurb(panel_id: str, locale: str) -> str:
    row = _BLURBS.get(panel_id) or {}
    return str(row.get(locale) or row.get("en") or "")


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
        if panel["path"] == raw:
            hit = panel
            break
    if hit is None:
        for panel in PANELS:
            if panel["path"] != "/" and raw.startswith(panel["path"] + "/"):
                hit = panel
                break
    if hit is None:
        return None
    return {
        "id": hit["id"],
        "path": hit["path"],
        "title": _title(hit, loc),
        "blurb": _blurb(hit["id"], loc),
    }


def catalog(locale: str | None = None) -> list[dict]:
    loc = normalize_locale(locale)
    return [
        {
            "id": panel["id"],
            "path": panel["path"],
            "title": _title(panel, loc),
            "aliases": list(panel["aliases"]),
        }
        for panel in PANELS
    ]


def _score_panel(panel: dict, needle: str, locale: str) -> int:
    if not needle:
        return 0
    title = _title(panel, locale).lower()
    path = str(panel["path"]).lower()
    aliases = [str(a).lower() for a in panel["aliases"]]
    if needle == title or needle == panel["id"] or needle == path.lstrip("/"):
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
        score = _score_panel(panel, needle, loc)
        if score <= 0:
            continue
        scored.append((score, {
            "id": panel["id"],
            "path": panel["path"],
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

    status = peek_status() or full_status()
    system = status.get("system") or {}
    counts = status.get("counts") or {}
    problems = []
    for row in (status.get("problems") or [])[:8]:
        problems.append({
            "name": row.get("name") or row.get("id"),
            "state": row.get("state"),
            "detail": str(row.get("detail") or "")[:80],
        })
    snap: dict[str, Any] = {
        "load": system.get("load"),
        "cpu_load_pct": system.get("load_pct"),
        "mem_used_pct": system.get("mem_used_pct"),
        "mem_total_gb": system.get("mem_total_gb"),
        "disk_root_pct": system.get("disk_pct"),
        "disk_root": f"{system.get('disk_used_gb')}/{system.get('disk_total_gb')} GB",
        "uptime": system.get("uptime"),
        "engine_up": status.get("engine_up"),
        "counts": {key: int(counts.get(key) or 0) for key in ("ok", "warn", "down", "stopped")},
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
    return snap


def suggest_panels(snapshot: dict, locale: str) -> list[dict]:
    """Pages that match the current snapshot — no model required."""
    loc = normalize_locale(locale)
    wanted: list[str] = []
    counts = snapshot.get("counts") or {}
    if int(counts.get("down") or 0) or int(counts.get("warn") or 0):
        wanted.extend(["services", "health", "logs"])
    disk = snapshot.get("disk_root_pct")
    if isinstance(disk, (int, float)) and disk >= 85:
        wanted.append("main")
    ollama = snapshot.get("ollama") or {}
    if ollama and not ollama.get("reachable"):
        wanted.append("ollama")
    ups = snapshot.get("ups") or {}
    if ups.get("source") in {"battery", "ups"}:
        wanted.append("dashboard")
    if not wanted:
        wanted.extend(["dashboard", "health"])
    by_id = {panel["id"]: panel for panel in PANELS}
    out: list[dict] = []
    seen: set[str] = set()
    for panel_id in wanted:
        panel = by_id.get(panel_id)
        if not panel or panel["path"] in seen:
            continue
        seen.add(panel["path"])
        out.append({"id": panel["id"], "path": panel["path"], "title": _title(panel, loc)})
    return out


def fallback_brief(snapshot: dict, locale: str | None = None) -> str:
    """English template status when Ollama is down.  The SPA localizes this."""
    del locale  # locale is applied by the drawer; keep the signature stable.
    counts = snapshot.get("counts") or {}
    engine = "on" if snapshot.get("engine_up") else "off"
    problems = snapshot.get("problems") or []
    lines = [
        f"Overview: load {snapshot.get('load') or '—'} (~{snapshot.get('cpu_load_pct') if snapshot.get('cpu_load_pct') is not None else '—'}%)"
        f" · memory used {snapshot.get('mem_used_pct') if snapshot.get('mem_used_pct') is not None else '—'}%"
        f" · root disk {snapshot.get('disk_root_pct') if snapshot.get('disk_root_pct') is not None else '—'}%"
        f" ({snapshot.get('disk_root') or '—'}) · up {snapshot.get('uptime') or '—'}",
        f"Services: {counts.get('ok', 0)} ok · {counts.get('warn', 0)} warn · {counts.get('down', 0)} down"
        f" · Docker {engine}",
    ]
    if problems:
        lines.append("Needs attention:")
        lines.extend(
            f"- {p.get('name')} · {p.get('state')} · {p.get('detail') or '—'}"
            for p in problems[:6]
        )
    else:
        lines.append("No service alerts need attention.")
    return "\n".join(lines)


def _pick_model() -> str | None:
    from hub import ollama_svc

    snap = ollama_svc.status()
    if not snap.get("reachable"):
        return None
    for row in snap.get("resident") or []:
        name = str(row.get("name") or "").strip()
        if name:
            return name
    for row in snap.get("models") or []:
        name = str(row.get("name") or "").strip()
        if name:
            return name
    return None


def _lang_name(locale: str) -> str:
    return {"zh-CN": "Simplified Chinese", "ja": "Japanese"}.get(locale, "English")


def _system_prompt(snapshot: dict, locale: str) -> str:
    loc = normalize_locale(locale)
    pages = ", ".join(f"{_title(p, loc)} {p['path']}" for p in PANELS)
    return (
        f"You are ServerHub's local assistant on this Mac. Answer in {_lang_name(loc)}. "
        "Be concise (4-8 short lines). Do not invent numbers; use only the snapshot. "
        "If a page would help, name it and its path.\n"
        f"Snapshot:\n{json.dumps(snapshot, ensure_ascii=False, separators=(',', ':'))}\n"
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

    model = _pick_model()
    if not model:
        return {}
    messages = [{"role": "system", "content": _system_prompt(snapshot, locale)}]
    for raw in (history or [])[-MAX_HISTORY:]:
        if not isinstance(raw, dict):
            continue
        role = str(raw.get("role") or "")
        content = str(raw.get("content") or "").strip()
        if role in {"user", "assistant"} and content:
            messages.append({"role": role, "content": content[:MAX_QUERY_CHARS]})
    messages.append({"role": "user", "content": user_text})
    try:
        result = ollama_svc.chat(model, messages, MAX_NUM_PREDICT)
    except Exception:
        return {}
    text = str(result.get("content") or "").strip() or str(result.get("thinking") or "").strip()
    if not text:
        return {}
    return {
        "text": text,
        "thinking": str(result.get("thinking") or ""),
        "model": result.get("model") or model,
        "duration_s": result.get("duration_s"),
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
        return {
            "ok": True,
            "kind": "find",
            "text": _find_text(hits, text),
            "thinking": "",
            "panels": hits or suggested[:3],
            "snapshot": snapshot,
            "model": None,
            "used_llm": False,
            "duration_s": 0,
        }

    if kind == "page":
        page = here or resolve_path("/", loc)
        panels = [page] if page else []
        fallback = (page or {}).get("blurb") or fallback_brief(snapshot, loc)
        llm = _run_llm(_page_user_prompt(), loc, snapshot, history)
        if llm:
            return {
                "ok": True,
                "kind": "page",
                "text": llm["text"],
                "thinking": llm.get("thinking") or "",
                "panels": panels,
                "snapshot": snapshot,
                "model": llm.get("model"),
                "used_llm": True,
                "duration_s": llm.get("duration_s"),
            }
        return {
            "ok": True,
            "kind": "page",
            "text": fallback,
            "thinking": "",
            "panels": panels,
            "snapshot": snapshot,
            "model": None,
            "used_llm": False,
            "duration_s": 0,
        }

    user_prompt = text if kind == "ask" else (_brief_user_prompt() if not text else text)
    llm = _run_llm(user_prompt, loc, snapshot, history)
    if llm:
        extra = match_panels(text, loc) if text else []
        panels = extra or suggested
        return {
            "ok": True,
            "kind": "brief" if kind == "brief" else "answer",
            "text": llm["text"],
            "thinking": llm.get("thinking") or "",
            "panels": panels[:6],
            "snapshot": snapshot,
            "model": llm.get("model"),
            "used_llm": True,
            "duration_s": llm.get("duration_s"),
        }

    return {
        "ok": True,
        "kind": "brief" if kind == "brief" else "answer",
        "text": fallback_brief(snapshot, loc),
        "thinking": "",
        "panels": suggested,
        "snapshot": snapshot,
        "model": None,
        "used_llm": False,
        "duration_s": 0,
    }
