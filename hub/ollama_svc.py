"""Ollama local-LLM integration — status, model management, quick tests.

The daemon on this class of host is *not* the stock `brew services` job: it is
typically a user-authored LaunchAgent wrapping `ollama serve` with tuned
environment (pinned OLLAMA_HOST, KEEP_ALIVE=-1 so the working model stays
resident, MAX_LOADED_MODELS=1).  This module therefore never manages the
process itself — it *discovers* the owning launchd label and reports it, so
the UI can drive start/stop/restart through the existing ``/api/action``
channel, which already knows how to bootstrap/bootout/kickstart any agent.

Everything the panel reads comes from the daemon's own HTTP API on
``settings.ollama.url`` (default http://127.0.0.1:11434): ``/api/version``,
``/api/tags`` (installed models) and ``/api/ps`` (resident models).  Reads are
short-timeout urllib GETs with bounded bodies, cached behind one 30s snapshot.

Mutations are deliberately narrow:

* pull   — `ollama pull <name>` under the shared watchdog runner
            (:func:`hub.jobs.run_watchdog`: output caps, deadline, group kill),
            one at a time; the model name is validated against
            :data:`MODEL_NAME_RE` before it ever reaches an argv.
* delete — `ollama rm <name>`, argv (never a shell), explicit confirm upstream.
* unload — POST /api/generate {"keep_alive": 0}, which asks the daemon to drop
            the resident model without touching its configured default.
* test   — one non-streaming /api/generate with a capped prompt and capped
            num_predict, returning the text plus timing.
* chat   — multi-turn /api/chat.  The router streams NDJSON (``stream: true``);
            :func:`chat` is the non-streaming twin used by tests and as a
            fallback.  History, prompt length and num_predict share the
            quick-test caps.
"""
from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from hub.config import cfg
from hub.errors import CODES, api_error
from hub.jobs import run_watchdog
from hub.paths import AGENTS_DIR
from hub.util import cached_snapshot

_TTL = 30.0

DEFAULT_URL = "http://127.0.0.1:11434"

#: Ollama model references (name[:tag], optionally registry/namespace prefixed).
#: The first character must be alphanumeric so an argv can never start with
#: ``-`` — `ollama pull -rf` must die here, not in the CLI's flag parser.
MODEL_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")

#: Quick-test guardrails: the box is for "is the model alive and how fast",
#: not for chat, so both the prompt and the generation length are capped.
MAX_PROMPT_CHARS = 2000
MAX_NUM_PREDICT = 256
GENERATE_TIMEOUT = 120.0
#: In-panel chat: last N turns, then a total-character trim so a long paste
#: cannot blow the 4b context on this class of host.
MAX_CHAT_MESSAGES = 24
MAX_CHAT_HISTORY_CHARS = 8000
#: One NDJSON line from a streaming /api/chat is a token or two; anything
#: near this cap is not the daemon we think it is.
MAX_NDJSON_LINE = 64 * 1024
CHAT_ROLES = frozenset({"user", "assistant", "system"})
#: Unloading only frees memory; it should be near-instant but give it slack.
UNLOAD_TIMEOUT = 30.0
#: Probes against a localhost daemon.
PROBE_TIMEOUT = 3.0
#: A model is gigabytes; an hour covers a slow WAN link without letting a dead
#: registry connection pin the job slot forever.
PULL_TIMEOUT = 3600
RM_TIMEOUT = 120
#: Bound on any daemon response body we will parse (tags with many models is
#: tens of KB; anything near this cap is not the API we think it is).
MAX_BODY_BYTES = 4 * 1024 * 1024

#: Ollama encodes keep_alive=-1 (stay resident forever) as a far-future
#: expires_at; anything past this year reads as "never expires".
_FOREVER_YEAR = 2100

CODES.setdefault("ollama.not_installed", (
    503, "ollama is not installed (install \"Ollama (brew)\" from the app catalog first)",
))
CODES.setdefault("ollama.unreachable", (503, "the Ollama API did not respond: {error}"))
CODES.setdefault("ollama.bad_model_name", (400, "invalid model name: {model}"))
CODES.setdefault("ollama.pull_running", (
    409, "a model pull is already running ({model}); wait for it to finish",
))
CODES.setdefault("ollama.confirm_required", (400, "deleting a model requires confirm=true"))
CODES.setdefault("ollama.rm_failed", (500, "could not remove the model: {error}"))
CODES.setdefault("ollama.unload_failed", (502, "the model could not be unloaded: {error}"))
CODES.setdefault("ollama.generate_failed", (502, "the test generation failed: {error}"))
CODES.setdefault("ollama.chat_failed", (502, "the chat request failed: {error}"))
CODES.setdefault("ollama.prompt_too_long", (400, "the prompt exceeds {max} characters"))
CODES.setdefault("ollama.prompt_required", (400, "a prompt is required"))
CODES.setdefault("ollama.messages_required", (400, "at least one chat message is required"))
CODES.setdefault("ollama.bad_message", (400, "each chat message needs a role of user, assistant or system"))
CODES.setdefault("ollama.status_failed", (500, "the Ollama status could not be read"))


def _settings() -> dict:
    return (cfg().get("settings") or {}).get("ollama") or {}


def base_url() -> str:
    """The daemon base URL (hand-edited ``settings.ollama.url``), no trailing /."""
    return str(_settings().get("url") or DEFAULT_URL).rstrip("/")


def binary_path() -> str | None:
    """The ollama CLI, or None.  PATH first, then the Homebrew prefixes."""
    found = shutil.which("ollama")
    if found:
        return found
    for prefix in ("/opt/homebrew/bin", "/usr/local/bin"):
        p = Path(prefix) / "ollama"
        if p.is_file():
            return str(p)
    return None


def _cli_env() -> dict:
    """Environment for `ollama pull/rm`, pointed at the panel's daemon.

    Without OLLAMA_HOST the CLI assumes 127.0.0.1:11434; setting it from the
    configured URL keeps the CLI and the status probes talking to the same
    daemon when the port was moved.
    """
    env = dict(os.environ)
    netloc = urlsplit(base_url()).netloc
    if netloc:
        env["OLLAMA_HOST"] = netloc
    return env


# ── HTTP ─────────────────────────────────────────────────────────────────────

def _api(path: str, payload: dict | None = None, timeout: float = PROBE_TIMEOUT):
    """One request to the daemon; returns the parsed JSON body.

    GET when *payload* is None, POST otherwise.  Raises URLError/HTTPError/
    ValueError on failure — callers decide whether that is a warn row, an
    api_error, or an unreachable flag.  The body read is bounded.
    """
    url = base_url() + path
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="GET" if payload is None else "POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(MAX_BODY_BYTES)
    if len(raw) >= MAX_BODY_BYTES:
        raise ValueError("response body exceeds the parse cap")
    return json.loads(raw) if raw else {}


# ── parsing (pure, unit-tested against captured payloads) ────────────────────

def _expires_forever(expires_at: str) -> bool:
    """keep_alive=-1 shows up as a far-future expires_at (year 2318 and alike)."""
    m = re.match(r"(\d{4})-", expires_at or "")
    return bool(m) and int(m.group(1)) >= _FOREVER_YEAR


def parse_tags(payload: dict) -> list[dict]:
    """Installed models from /api/tags, one flat dict per model."""
    out = []
    for m in (payload or {}).get("models") or []:
        details = m.get("details") or {}
        out.append({
            "name": m.get("name") or m.get("model") or "",
            "size": int(m.get("size") or 0),
            "family": details.get("family") or "",
            "parameter_size": details.get("parameter_size") or "",
            "quantization": details.get("quantization_level") or "",
            "context_length": details.get("context_length"),
            "capabilities": [str(c) for c in (m.get("capabilities") or [])],
            "modified": m.get("modified_at") or "",
        })
    return out


def parse_ps(payload: dict) -> list[dict]:
    """Resident models from /api/ps, one flat dict per loaded model."""
    out = []
    for m in (payload or {}).get("models") or []:
        expires = m.get("expires_at") or ""
        out.append({
            "name": m.get("name") or m.get("model") or "",
            "size": int(m.get("size") or 0),
            "size_vram": int(m.get("size_vram") or 0),
            "context_length": m.get("context_length"),
            "expires_at": expires,
            "forever": _expires_forever(expires),
        })
    return out


# ── owning launchd job discovery ─────────────────────────────────────────────

def _plist_label_if_ollama(path: Path) -> str | None:
    """The plist's Label when its content references ollama at all.

    Matching the parsed content rather than the filename: a custom agent may be
    called anything, but its program arguments, environment (OLLAMA_*), or log
    paths name ollama somewhere.  Parse failures are skipped — a plist launchd
    cannot read is not running ollama for us either.
    """
    try:
        with open(path, "rb") as f:
            pl = plistlib.load(f)
    except Exception:
        return None
    if not isinstance(pl, dict):
        return None
    if "ollama" not in repr(pl).lower():
        return None
    return str(pl.get("Label") or path.stem)


def _candidate_labels() -> list[str]:
    """Every on-disk LaunchAgent that references ollama, alphabetical, unique.

    Two plists can share a Label (a leftover copy); the set collapses them so
    the UI warning is about distinct agents, not duplicate files.
    """
    seen: set[str] = set()
    for path in AGENTS_DIR.glob("*.plist"):
        label = _plist_label_if_ollama(path)
        if label:
            seen.add(label)
    return sorted(seen)


def discover_label(
    loaded: frozenset[str] | None = None,
    running: frozenset[str] | None = None,
) -> str | None:
    """The launchd label owning ollama on this host, or None.

    ``settings.ollama.label`` wins when set.  Otherwise every LaunchAgent plist
    is scanned for an ollama reference.  A label that is actually *running*
    (live pid) wins over one that is merely loaded — a crashed ``brew services``
    agent stays in the listing with no pid, and must not steal the start/stop
    target from the custom wrapper that is serving :11434.  Loaded-but-idle
    still beats an on-disk-only plist.  Remaining ties break alphabetically
    so the answer is stable between calls.

    *loaded* / *running* are injectable so the health path can pass empty sets
    instead of triggering a launchctl spawn.
    """
    configured = str(_settings().get("label") or "").strip()
    if configured:
        return configured
    candidates = _candidate_labels()
    if not candidates:
        return None
    if loaded is None:
        try:
            from hub.launchd_cache import listing

            jobs = listing()
            loaded = jobs.loaded
            if running is None:
                running = jobs.running
        except Exception:
            loaded = frozenset()
    running = running or frozenset()
    for label in candidates:
        if label in running:
            return label
    for label in candidates:
        if label in loaded:
            return label
    return candidates[0]


def _service_state(*, reachable: bool = False) -> dict:
    """The owning launchd job as the UI needs it: label + loaded/running/pid.

    ``launchctl list`` is not ground truth for "is ollama serving".  A sandbox
    or a hung listing comes back empty (``hub.launchd_cache`` already turns a
    timeout into ``_EMPTY`` rather than raising); the job can also be missing
    from a successful listing.  When the HTTP API already answered, the
    service is running — Start must stay disabled and the badge must say so.
    ``inferred`` tells the UI the pid came from nowhere because launchd
    never named the job.
    """
    from hub.launchd_cache import listing

    try:
        jobs = listing()
    except Exception:
        jobs = None
    label = discover_label(
        loaded=jobs.loaded if jobs else frozenset(),
        running=jobs.running if jobs else frozenset(),
    )
    state = {
        "label": label,
        "loaded": False,
        "running": False,
        "pid": None,
        "candidates": _candidate_labels(),
        "inferred": False,
    }
    if label and jobs:
        state["loaded"] = label in jobs.loaded
        pid = jobs.pid_for(label)
        state["running"] = pid is not None
        state["pid"] = int(pid) if pid else None
    if reachable and not state["running"]:
        state["running"] = True
        state["loaded"] = True
        state["inferred"] = True
    return state


# ── status snapshot ──────────────────────────────────────────────────────────

@cached_snapshot(_TTL)
def status() -> dict:
    """Whole-page snapshot: daemon, service, installed + resident models."""
    reachable = False
    error = ""
    version = ""
    models: list[dict] = []
    resident: list[dict] = []
    try:
        version = str(_api("/api/version").get("version") or "")
        reachable = True
    except Exception as e:
        error = str(e)[:200]
    if reachable:
        try:
            models = parse_tags(_api("/api/tags"))
            resident = parse_ps(_api("/api/ps"))
        except Exception as e:
            # Version answered but tags/ps failed: still "reachable", but say why.
            error = str(e)[:200]
    binary = binary_path()
    service = _service_state(reachable=reachable)
    return {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "url": base_url(),
        "installed": bool(binary or service.get("label")),
        "binary": binary,
        "reachable": reachable,
        "version": version,
        "error": error,
        "service": service,
        "models": models,
        "resident": resident,
        "pull": pull_state(),
    }


# ── model name validation ────────────────────────────────────────────────────

def validate_model_name(name: str) -> str:
    name = str(name or "").strip()
    if not MODEL_NAME_RE.match(name):
        raise api_error("ollama.bad_model_name", model=name[:80])
    return name


# ── pull job (single-flight, watchdog-run) ───────────────────────────────────

_pull = {
    "running": False, "rc": None, "model": None,
    "started": None, "finished": None, "log": [],
}
_pull_lock = threading.Lock()


def pull_state() -> dict:
    return {
        "running": _pull["running"],
        "rc": _pull["rc"],
        "model": _pull["model"],
        "started": _pull["started"],
        "finished": _pull["finished"],
    }


def pull_log() -> dict:
    """State + joined log, same shape the maintenance log endpoint serves."""
    return {**pull_state(), "log": "\n".join(_pull["log"])}


def start_pull(name: str) -> dict:
    """Start `ollama pull <name>` in the background; refuse a concurrent pull.

    The runner is :func:`hub.jobs.run_watchdog` — per-line and total output
    caps, a hard deadline, and a process-group kill — with the log list living
    in the module store so the UI can tail it while the job runs.
    """
    name = validate_model_name(name)
    binary = binary_path()
    if not binary:
        raise api_error("ollama.not_installed")
    with _pull_lock:
        if _pull["running"]:
            raise api_error("ollama.pull_running", model=_pull.get("model") or "")
        _pull.update(
            running=True, rc=None, model=name,
            started=time.strftime("%H:%M:%S"), finished=None,
            log=[f"$ ollama pull {name}"],
        )

    def run():
        try:
            _pull["rc"] = run_watchdog(
                [binary, "pull", name],
                timeout=PULL_TIMEOUT, log=_pull["log"], env=_cli_env(),
            )
        finally:
            _pull["running"] = False
            _pull["finished"] = time.strftime("%H:%M:%S")
            status.invalidate()  # the tags list just changed

    threading.Thread(target=run, daemon=True, name="ollama-pull").start()
    return pull_state()


# ── delete / unload / quick test ─────────────────────────────────────────────

def delete_model(name: str) -> dict:
    """`ollama rm <name>` — argv, never a shell; confirm is enforced upstream."""
    name = validate_model_name(name)
    binary = binary_path()
    if not binary:
        raise api_error("ollama.not_installed")
    with _pull_lock:
        if _pull["running"]:
            # rm during a pull of the same blob corrupts neither, but the
            # combination has no legitimate use; keep the story simple.
            raise api_error("ollama.pull_running", model=_pull.get("model") or "")
    log: list[str] = []
    rc = run_watchdog([binary, "rm", name], timeout=RM_TIMEOUT, log=log, env=_cli_env())
    status.invalidate()
    if rc != 0:
        raise api_error("ollama.rm_failed", error="\n".join(log)[-300:] or f"exit {rc}")
    return {"ok": True, "model": name, "message": "\n".join(log)[-300:]}


def unload_model(name: str) -> dict:
    """Ask the daemon to drop a resident model now (keep_alive: 0).

    This is a one-shot request-scoped keep_alive — the daemon's own configured
    default (e.g. KEEP_ALIVE=-1 in the LaunchAgent) is not modified, so the
    next generation loads and pins the model exactly as before.
    """
    name = validate_model_name(name)
    try:
        _api("/api/generate", {"model": name, "keep_alive": 0}, timeout=UNLOAD_TIMEOUT)
    except Exception as e:
        raise api_error("ollama.unload_failed", error=str(e)[:200])
    status.invalidate()
    return {"ok": True, "model": name}


def quick_test(name: str, prompt: str, num_predict: int = 128) -> dict:
    """One bounded, non-streaming generation; returns the text plus timing."""
    name = validate_model_name(name)
    prompt = str(prompt or "")
    if not prompt.strip():
        raise api_error("ollama.prompt_required")
    if len(prompt) > MAX_PROMPT_CHARS:
        raise api_error("ollama.prompt_too_long", max=MAX_PROMPT_CHARS)
    num_predict = max(1, min(int(num_predict or 128), MAX_NUM_PREDICT))
    payload = {
        "model": name,
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": num_predict},
    }
    t0 = time.monotonic()
    try:
        resp = _api("/api/generate", payload, timeout=GENERATE_TIMEOUT)
    except Exception as e:
        raise api_error("ollama.generate_failed", error=str(e)[:200])
    elapsed = time.monotonic() - t0
    eval_count = int(resp.get("eval_count") or 0)
    eval_ns = int(resp.get("eval_duration") or 0)
    return {
        "ok": True,
        "model": name,
        "response": str(resp.get("response") or ""),
        # Thinking-capable models (qwen3.5 and friends) spend their token
        # budget reasoning before they answer; with a capped num_predict the
        # whole budget can go there and ``response`` comes back empty.  The
        # trace is returned so the UI still has output to show — verified
        # against the real daemon, where "hi" @ num_predict=32 yielded
        # thinking-only output.
        "thinking": str(resp.get("thinking") or ""),
        "duration_s": round(elapsed, 2),
        "eval_count": eval_count,
        "tokens_per_s": round(eval_count / (eval_ns / 1e9), 1) if eval_ns else None,
    }


# ── in-panel chat ────────────────────────────────────────────────────────────

def normalize_chat_messages(messages) -> list[dict]:
    """Validate, cap, and flatten a chat history for /api/chat.

    Roles are restricted to the three Ollama accepts.  Each body is capped at
    :data:`MAX_PROMPT_CHARS`; the list is then trimmed to the last
    :data:`MAX_CHAT_MESSAGES` and a total-character budget so a pasted novel
    cannot pin the resident 4b.  The last turn must be a non-empty user
    message — that is the prompt being sent.
    """
    if not isinstance(messages, list) or not messages:
        raise api_error("ollama.messages_required")
    out: list[dict] = []
    for raw in messages:
        if not isinstance(raw, dict):
            raise api_error("ollama.bad_message")
        role = str(raw.get("role") or "").strip()
        if role not in CHAT_ROLES:
            raise api_error("ollama.bad_message")
        content = str(raw.get("content") or "")
        if len(content) > MAX_PROMPT_CHARS:
            raise api_error("ollama.prompt_too_long", max=MAX_PROMPT_CHARS)
        out.append({"role": role, "content": content})
    out = out[-MAX_CHAT_MESSAGES:]
    total = sum(len(m["content"]) for m in out)
    while len(out) > 1 and total > MAX_CHAT_HISTORY_CHARS:
        dropped = out.pop(0)
        total -= len(dropped["content"])
    last = out[-1]
    if last["role"] != "user" or not last["content"].strip():
        raise api_error("ollama.prompt_required")
    return out


def _chat_payload(name: str, messages: list, num_predict: int, *, stream: bool) -> dict:
    name = validate_model_name(name)
    msgs = normalize_chat_messages(messages)
    num_predict = max(1, min(int(num_predict or 128), MAX_NUM_PREDICT))
    return {
        "model": name,
        "messages": msgs,
        "stream": stream,
        "options": {"num_predict": num_predict},
    }


def _tokens_per_s(resp: dict) -> float | None:
    eval_count = int(resp.get("eval_count") or 0)
    eval_ns = int(resp.get("eval_duration") or 0)
    return round(eval_count / (eval_ns / 1e9), 1) if eval_ns else None


def chat(name: str, messages: list, num_predict: int = 128) -> dict:
    """One bounded, non-streaming /api/chat turn; returns content plus thinking.

    Same guardrails as :func:`quick_test`.  Thinking-capable models can spend
    the whole ``num_predict`` budget on ``thinking`` and leave ``content``
    empty — both fields are returned so the UI still has something to show.
    """
    payload = _chat_payload(name, messages, num_predict, stream=False)
    t0 = time.monotonic()
    try:
        resp = _api("/api/chat", payload, timeout=GENERATE_TIMEOUT)
    except Exception as e:
        raise api_error("ollama.chat_failed", error=str(e)[:200])
    msg = resp.get("message") or {}
    eval_count = int(resp.get("eval_count") or 0)
    return {
        "ok": True,
        "model": payload["model"],
        "role": str(msg.get("role") or "assistant"),
        "content": str(msg.get("content") or ""),
        "thinking": str(msg.get("thinking") or ""),
        "duration_s": round(time.monotonic() - t0, 2),
        "eval_count": eval_count,
        "tokens_per_s": _tokens_per_s(resp),
    }


def _open_chat_http(payload: dict):
    """POST /api/chat and return the raw HTTPResponse (caller closes it)."""
    url = base_url() + "/api/chat"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        return urllib.request.urlopen(req, timeout=GENERATE_TIMEOUT)
    except urllib.error.HTTPError as e:
        err = ""
        try:
            err = e.read(400).decode("utf-8", "replace")
        except Exception:
            err = str(e)
        raise api_error("ollama.chat_failed", error=(err or str(e))[:200])
    except Exception as e:
        raise api_error("ollama.chat_failed", error=str(e)[:200])


def start_chat_stream(name: str, messages: list, num_predict: int = 128):
    """Validate + open a streaming /api/chat; yield raw NDJSON lines.

    Connection failures raise :func:`api_error` *before* any bytes are
    produced so the router can still return a coded JSON 502.  The iterator
    closes the HTTP response in ``finally``.
    """
    payload = _chat_payload(name, messages, num_predict, stream=True)
    resp = _open_chat_http(payload)

    def lines():
        try:
            while True:
                line = resp.readline(MAX_NDJSON_LINE)
                if not line:
                    break
                if len(line) >= MAX_NDJSON_LINE and not line.endswith(b"\n"):
                    # Drain the rest of this monster line; do not forward it.
                    while True:
                        more = resp.readline(MAX_NDJSON_LINE)
                        if not more or more.endswith(b"\n"):
                            break
                    continue
                yield line if line.endswith(b"\n") else line + b"\n"
        finally:
            try:
                resp.close()
            except Exception:
                pass

    return lines()


# ── health checks (hub/health_svc fan-out; must never spawn a subprocess) ────

def health_checks() -> list[dict]:
    """Rows for the health page — [] on hosts that do not run ollama at all.

    Gating and probing are subprocess-free by contract: binary presence is a
    PATH/stat scan, label discovery reads plists, and liveness is two bounded
    HTTP GETs.  ``loaded=frozenset()`` keeps discovery off launchctl — for a
    yes/no gate any ollama-referencing plist is claim enough.
    """
    label = discover_label(loaded=frozenset())
    if not binary_path() and not label:
        return []
    rows: list[dict] = []
    candidates = _candidate_labels()
    if len(candidates) > 1:
        rows.append({
            "id": "ollama_duplicate_agents",
            "name": "Ollama LaunchAgents",
            "level": "warn",
            "ok": False,
            "detail": (
                f"{len(candidates)} ollama agents on disk: {', '.join(candidates)}. "
                "A second KeepAlive job crash-loops on EADDRINUSE."
            ),
            "fix": (
                f"Stop the unused agent (typically homebrew.mxcl.ollama) so "
                f"Start/Stop target {label or candidates[0]}"
            ),
        })
    port = urlsplit(base_url()).port or 11434
    row_name = f"Ollama local LLM API :{port}"
    try:
        version = str(_api("/api/version").get("version") or "")
        resident = parse_ps(_api("/api/ps"))
    except Exception as e:
        rows.append({
            "id": "ollama_api",
            "name": row_name,
            "level": "warn",
            "ok": False,
            "detail": f"API unreachable ({str(e)[:100]})",
            "fix": f"launchctl kickstart -k gui/$(id -u)/{label}" if label
                   else "brew services start ollama",
        })
        return rows
    names = ", ".join(m["name"] for m in resident) or "none resident"
    rows.append({
        "id": "ollama_api",
        "name": row_name,
        "level": "ok",
        "ok": True,
        "detail": f"v{version} · {len(resident)} model(s) loaded ({names})",
        "fix": "",
    })
    return rows


if __name__ == "__main__":
    print(json.dumps(status(), ensure_ascii=False, indent=2))
