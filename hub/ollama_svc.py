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

import errno
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
from hub.errors import CODES, api_error, exc_detail
from hub.http_guard import (
    RedirectRefused,
    _ip_from_host,
    is_local_http_origin,
    local_connect_peer,
    no_redirect_opener,
    pinned_no_redirect_opener,
)
from hub.jobs import run_watchdog
from hub.paths import AGENTS_DIR
from hub.util import cached_snapshot, read_bytes_capped, safe_json_loads, strftime_now

_OPENER = no_redirect_opener()

_TTL = 30.0
#: Leftover multi-MB LaunchAgent plist used to OOM GET /api/ollama/status.
_PLIST_CAP = 256 * 1024

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
CODES.setdefault("ollama.bad_url", (
    400, "Ollama URL must be a local or private HTTP origin",
))
CODES.setdefault("ollama.bad_label", (400, "invalid launchd label: {label}"))

#: launchd Label: reverse-DNS, no spaces or shell metacharacters.
LABEL_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


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

    Inf in /api/tags was already dropped; YAML timestamps, ``!!binary`` names,
    inf keys, and tuple-inf still leaked into GET /api/ollama/status.
    A leftover ``\\ud800`` in a model name, generate ``response``, or chat
    ``content`` still 500'd the same encoder.
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            # A >4300-digit int (a hex plist/YAML leftover dodges the
            # str->int digit cap on parse) passes this coercer untouched and
            # then ValueError's json.dumps itself at int->str time.
            str(value)
        except ValueError:
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
            if isinstance(k, (bytes, bytearray)):
                k = k.decode("utf-8", "replace")
            elif not isinstance(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            return _jsonable(iso(), depth + 1)
        except Exception:
            pass
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _safe_int(raw, default: int = 0) -> int:
    """``int(inf)`` OverflowError is not ValueError; leftover 1e400 used to 500."""
    if isinstance(raw, bool) or raw in (None, ""):
        return default
    if isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
        return default
    try:
        n = int(raw)
    except (TypeError, ValueError, OverflowError):
        return default
    try:
        # int(raw) does not convert an *already-int* over-cap value, so the
        # digit-cap ValueError never fired here and the leftover survived
        # into Starlette's json.dumps, which raises the same ValueError.
        str(n)
    except ValueError:
        return default
    return n


def _as_text(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif not isinstance(value, str):
        return ""
    return value.encode("utf-8", "replace").decode("utf-8")


def settings_text(value) -> str:
    """A hand-edited settings scalar as sanitized text.

    ``_as_text`` gates on ``isinstance(str)``, which silently dropped numeric
    YAML values: a hand-edited ``label: 2023`` read back as int, discovery
    fell through to the plist scan, and Start/Stop targeted a different
    agent.  A ``str()`` probe keeps the numeric id — guarded, because a YAML
    hex/octal integer is parsed via ``int(raw, 16)``/``int(raw, 8)`` (exempt
    from CPython's 4300-digit cap) and an over-cap leftover would otherwise
    ValueError at ``str()`` time.  bool/inf/NaN and collections stay "".
    """
    if isinstance(value, (str, bytes, bytearray)):
        return _as_text(value)
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        return ""
    if not isinstance(value, (int, float)):
        return ""
    try:
        text = str(value)
    except ValueError:
        return ""
    return text.encode("utf-8", "replace").decode("utf-8")


def _settings() -> dict:
    # Read through this module's ``cfg`` so tests can patch it.
    # A leftover list/string settings (same shape that 500'd /api/ups) must
    # not AttributeError on .get("ollama").
    settings = cfg().get("settings")
    raw = settings.get("ollama") if isinstance(settings, dict) else None
    return raw if isinstance(raw, dict) else {}


def configured_url() -> str:
    """The operator-edited URL, unvalidated.

    ``settings_text``, not ``_as_text``: a numeric YAML leftover coerces to
    text and is then *visibly* rejected by :func:`base_url` (url_rejected
    warns in the UI) instead of silently reading as unconfigured.
    """
    return settings_text(_settings().get("url")).strip().rstrip("/") or DEFAULT_URL


def base_url() -> str:
    """The daemon URL the panel is allowed to contact.

    ``settings.ollama.url`` is operator-edited (Settings UI or YAML).  A
    public or metadata origin would turn every status poll and chat POST
    into SSRF, so a rejected override falls back to the loopback default
    rather than being fetched.
    """
    raw = configured_url()
    return raw if is_local_http_origin(raw) else DEFAULT_URL


def url_was_rejected() -> bool:
    return configured_url() != base_url()


def validate_settings_url(url: str) -> str:
    """Normalize a settings write; refuse anything the panel must not fetch."""
    text = str(url or "").strip().rstrip("/")
    if not text:
        return DEFAULT_URL
    if not is_local_http_origin(text):
        raise api_error("ollama.bad_url")
    return text


def validate_settings_label(label: str) -> str:
    """Empty means auto-discover; anything else must look like a launchd Label."""
    text = str(label or "").strip()
    if text and not LABEL_RE.match(text):
        raise api_error("ollama.bad_label", label=text[:80])
    return text


def binary_path() -> str | None:
    """The ollama CLI, or None. Known prefixes first, then PATH.

    pull/rm run this binary; a PATH hijack would replace the model store
    operations the panel attributes to the installed ollama.
    """
    for prefix in ("/opt/homebrew/bin", "/usr/local/bin"):
        p = Path(prefix) / "ollama"
        try:
            if p.is_file():
                return str(p)
        except OSError:
            continue
    try:
        found = shutil.which("ollama")
    except (OSError, ValueError):
        found = None
    return found if found and Path(found).is_absolute() else None


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

def _ollama_open(req, timeout):
    """Open *req* pinned to the first local IP the daemon URL resolved to."""
    host = (urlsplit(base_url()).hostname or "").strip("[]")
    peer = local_connect_peer(host) if host else None
    if not peer:
        raise ValueError("ollama url resolved off-LAN")
    dest_ip = peer if _ip_from_host(peer) is not None else None
    opener = pinned_no_redirect_opener(dest_ip) if dest_ip else _OPENER
    return opener.open(req, timeout=timeout)


def _capped_json_int(text):
    """``json.loads`` parse_int hook: an over-cap digit run drops to None.

    ``int()`` of a >4300-digit number is the digit-cap *ValueError* (not
    JSONDecodeError) for the whole document, so one unrenderable literal in a
    daemon body used to wipe the entire payload: a huge ``size`` in /api/tags
    emptied the models AND resident lists behind a "response is not json" lie
    on GET /api/ollama/status, and a huge ``eval_count`` beside a perfectly
    good generation discarded the whole answer into the 502
    ``generate_failed``/``chat_failed`` — for unload, *after* the daemon had
    already dropped the model.  Loading the number as None keeps the payload;
    ``_safe_int`` / ``_jsonable`` then bound the field (the docker_cli /
    brew_cache / shares_svc drop).
    """
    try:
        return int(text)
    except ValueError:
        return None


def _api(path: str, payload: dict | None = None, timeout: float = PROBE_TIMEOUT):
    """One request to the daemon; returns the parsed JSON body.

    GET when *payload* is None, POST otherwise.  Raises URLError/HTTPError/
    ValueError on failure — callers decide whether that is a warn row, an
    api_error, or an unreachable flag.  The body read is bounded.
    """
    url = base_url() + path
    # Leftover inf in a generate/chat body used to send Infinity and 500
    # under ``allow_nan=False``. RecursionError after ``_jsonable`` is not
    # ValueError; leftover nested generate/chat used to 500 the request.
    data = None
    if payload is not None:
        try:
            data = json.dumps(_jsonable(payload), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, OverflowError, RecursionError):
            raise ValueError("request is not json")
    req = urllib.request.Request(
        url,
        data=data,
        method="GET" if payload is None else "POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with _ollama_open(req, timeout) as r:
            raw = r.read(MAX_BODY_BYTES)
    except RedirectRefused as e:
        # leftover ``str(e)`` RecursionError used to 500 GET /api/ollama/*.
        raise ValueError(exc_detail(e) or "redirect refused") from e
    if len(raw) >= MAX_BODY_BYTES:
        raise ValueError("response body exceeds the parse cap")
    try:
        parsed = safe_json_loads(raw, parse_int=_capped_json_int) if raw else {}
    except (ValueError, RecursionError):
        # RecursionError: leftover deeply-nested daemon JSON is not ValueError.
        raise ValueError("response is not json")
    if not isinstance(parsed, dict):
        raise ValueError("response is not an object")
    return parsed


#: Connection-level errnos that mean "nothing is accepting on that port".
_DOWN_ERRNOS = frozenset({
    errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED,
    errno.EHOSTUNREACH, errno.EHOSTDOWN, errno.ENETUNREACH, errno.ENETDOWN,
})


def _looks_engine_down(exc) -> bool:
    """True for connection-level failures — the daemon is not accepting at all.

    Timeouts (``socket.timeout`` is ``TimeoutError``) and HTTP answers from a
    live daemon (including auth failures) are NOT this shape: they keep their
    original coded error.  URLError wraps the socket error in ``reason``.
    """
    for _ in range(4):
        if isinstance(exc, urllib.error.HTTPError):
            return False
        if isinstance(exc, urllib.error.URLError):
            exc = exc.reason
            continue
        break
    if isinstance(exc, TimeoutError):
        return False
    if isinstance(exc, ConnectionError):
        return True
    return isinstance(exc, OSError) and exc.errno in _DOWN_ERRNOS


def _engine_confirmed_down() -> bool:
    """Fresh /api/version probe; runs only on a failure path, never on success."""
    try:
        _api("/api/version")
        return False
    except Exception:
        return True


def _daemon_error(exc, fallback_code: str):
    """The coded error for a failed daemon request.

    unload/test/chat used to map a stopped daemon to their generic 502
    (``unload_failed``/``generate_failed``/``chat_failed``) — the coded 503
    ``ollama.unreachable`` was defined and translated but never raised.  Same
    rule as the vanished-CLI 503 in :func:`delete_model` and docker's
    ``engine_up(force=True)``: the reclassification fires only after a fresh
    probe on this failure path confirms the daemon is down.  Timeouts, a
    connection dropped by a daemon that is still answering, and HTTP-level
    failures (auth included) keep *fallback_code*'s original shape.
    """
    if _looks_engine_down(exc) and _engine_confirmed_down():
        return api_error("ollama.unreachable", error=exc_detail(exc))
    return api_error(fallback_code, error=exc_detail(exc))


# ── parsing (pure, unit-tested against captured payloads) ────────────────────

def _expires_forever(expires_at: str) -> bool:
    """keep_alive=-1 shows up as a far-future expires_at (year 2318 and alike)."""
    text = expires_at if isinstance(expires_at, str) else ""
    m = re.match(r"(\d{4})-", text)
    return bool(m) and int(m.group(1)) >= _FOREVER_YEAR


def parse_tags(payload: dict) -> list[dict]:
    """Installed models from /api/tags, one flat dict per model."""
    out = []
    models = (payload or {}).get("models") if isinstance(payload, dict) else None
    if not isinstance(models, list):
        models = []
    for m in models:
        if not isinstance(m, dict):
            continue
        details = m.get("details") or {}
        if not isinstance(details, dict):
            details = {}
        caps = m.get("capabilities")
        out.append(_jsonable({
            "name": _as_text(m.get("name")) or _as_text(m.get("model")),
            "size": _safe_int(m.get("size")),
            "family": _as_text(details.get("family")),
            "parameter_size": _as_text(details.get("parameter_size")),
            "quantization": _as_text(details.get("quantization_level")),
            "context_length": details.get("context_length"),
            "capabilities": [_as_text(c) for c in caps] if isinstance(caps, list) else [],
            "modified": _as_text(m.get("modified_at")),
        }))
    return out


def parse_ps(payload: dict) -> list[dict]:
    """Resident models from /api/ps, one flat dict per loaded model."""
    out = []
    models = (payload or {}).get("models") if isinstance(payload, dict) else None
    if not isinstance(models, list):
        models = []
    for m in models:
        if not isinstance(m, dict):
            continue
        expires = m.get("expires_at")
        expires = expires if isinstance(expires, str) else ""
        out.append(_jsonable({
            "name": _as_text(m.get("name")) or _as_text(m.get("model")),
            "size": _safe_int(m.get("size")),
            "size_vram": _safe_int(m.get("size_vram")),
            "context_length": m.get("context_length"),
            "expires_at": expires,
            "forever": _expires_forever(expires),
        }))
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
        pl = plistlib.loads(read_bytes_capped(path, _PLIST_CAP))
    except Exception:
        return None
    if not isinstance(pl, dict):
        return None
    try:
        haystack = repr(pl)
    except (ValueError, RecursionError):
        # RecursionError: leftover nested LaunchAgent is not
        # InvalidFileException.  ValueError: a leftover hex ``<integer>``
        # (plistlib parses 0x… via int(raw, 16), past CPython's 4300-digit
        # cap) makes repr() itself raise at int->str time.  Either used to
        # 500 GET /api/ollama/status through _candidate_labels.
        return None
    if "ollama" not in haystack.lower():
        return None
    # _as_text on the stem too: an undecodable filename surfaces here as a
    # lone-surrogate str (surrogateescape), which used to reach the
    # health_checks fix strings raw and 500 Starlette's UTF-8 encode.
    return _as_text(pl.get("Label")) or _as_text(path.stem)


def origins_allow_lan(origins: str) -> bool:
    """True when ``OLLAMA_ORIGINS`` would accept a LAN browser Origin header.

    Setting the variable replaces Ollama's localhost defaults.  A list of only
    ``chrome-extension://*`` (the previous plist) 403s Open WebUI and every
    other LAN page that sends ``Origin: http://192.168…``.
    """
    text = _as_text(origins)
    for part in text.split(","):
        token = part.strip()
        if not token:
            continue
        if token == "*":
            return True
        low = token.lower()
        if "192.168." in low or "10.10." in low or "10.0." in low:
            return True
    return False


def _agent_origins(label: str | None = None) -> str:
    """``OLLAMA_ORIGINS`` from the owning LaunchAgent, or empty."""
    name = _as_text(label).strip()
    if not name:
        return ""
    path = Path(AGENTS_DIR) / f"{name}.plist"
    try:
        pl = plistlib.loads(read_bytes_capped(path, _PLIST_CAP))
    except Exception:
        return ""
    if not isinstance(pl, dict):
        return ""
    env = pl.get("EnvironmentVariables")
    if not isinstance(env, dict):
        return ""
    return _as_text(env.get("OLLAMA_ORIGINS")).strip()


def _candidate_labels() -> list[str]:
    """Every on-disk LaunchAgent that references ollama, alphabetical, unique.

    Two plists can share a Label (a leftover copy); the set collapses them so
    the UI warning is about distinct agents, not duplicate files.
    """
    seen: set[str] = set()
    try:
        paths = list(AGENTS_DIR.glob("*.plist"))
    except OSError:
        # Unreadable LaunchAgents used to 500 GET /api/ollama/status.
        paths = []
    for path in paths:
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
    # settings_text, not _as_text: a hand-edited numeric YAML label
    # (``label: 2023``) used to be silently ignored here, so discovery fell
    # through to the plist scan and Start/Stop targeted a different agent.
    configured = settings_text(_settings().get("label")).strip()
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
        state["pid"] = _safe_int(pid) if pid else None
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
        version = _as_text(_api("/api/version").get("version"))
        reachable = True
    except Exception as e:
        error = exc_detail(e)
    if reachable:
        try:
            models = parse_tags(_api("/api/tags"))
            resident = parse_ps(_api("/api/ps"))
        except Exception as e:
            # Version answered but tags/ps failed: still "reachable", but say why.
            error = exc_detail(e)
    binary = binary_path()
    service = _service_state(reachable=reachable)
    snap = {
        "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
        "url": base_url(),
        "url_rejected": url_was_rejected(),
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
    return _jsonable(snap)


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
    """Pull-job state as the UI polls it.  Never raises.

    The maintenance twin (:func:`hub.jobs.job_state`) already coerces a junk
    in-memory row; this one served ``_pull`` raw.  GET /api/ollama/status
    survived only because :func:`status` re-walks the whole snapshot through
    ``_jsonable`` — GET /api/ollama/pull/log had no such pass, so a leftover
    inf ``rc`` (or one past the int->str digit cap) 500'd the encoder there.
    """
    state = _jsonable({
        "running": bool(_pull.get("running")),
        "rc": _pull.get("rc"),
        "model": _pull.get("model"),
        "started": _pull.get("started"),
        "finished": _pull.get("finished"),
    })
    return state if isinstance(state, dict) else {
        "running": False, "rc": None, "model": None,
        "started": None, "finished": None,
    }


def _pull_log_lines(raw) -> list[str]:
    """String lines from a leftover pull-row ``log`` field.  Never raises.

    The ``jobs._log_lines`` rule: ``log: [bytes, None, 5]`` in a junk
    in-memory row TypeError'd ``str.join`` out of GET /api/ollama/pull/log.
    """
    if isinstance(raw, str):
        return [raw] if raw else []
    if not isinstance(raw, (list, tuple)):
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, (bytes, bytearray)):
            out.append(item.decode("utf-8", "replace"))
    return out


def pull_log() -> dict:
    """State + joined log, same shape the maintenance log endpoint serves.

    ``_utf8_text`` on the joined tail: a leftover lone surrogate in one line
    used to 500 Starlette's strict UTF-8 encode of the response body.
    """
    return {**pull_state(), "log": _utf8_text("\n".join(_pull_log_lines(_pull.get("log"))))}


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
            started=strftime_now("%H:%M:%S"), finished=None,
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
            _pull["finished"] = strftime_now("%H:%M:%S")
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
        # rc -1 is run_watchdog's could-not-run sentinel — but it is also
        # what a SIGHUP-killed rm reports, so the sentinel alone must not
        # classify.  Only when a fresh disk probe confirms the CLI vanished
        # between the check above and the spawn does this become the same
        # coded 503 the up-front gate raises; a still-present binary keeps
        # its raw rm_failed result.  The re-check runs only on this failure
        # path, never on a successful rm.
        if rc == -1 and binary_path() is None:
            raise api_error("ollama.not_installed")
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
        raise _daemon_error(e, "ollama.unload_failed")
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
    num_predict = max(1, min(_safe_int(num_predict, 128) or 128, MAX_NUM_PREDICT))
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
        raise _daemon_error(e, "ollama.generate_failed")
    elapsed = time.monotonic() - t0
    eval_count = _safe_int(resp.get("eval_count"))
    return _jsonable({
        "ok": True,
        "model": name,
        "response": resp.get("response") or "",
        # Thinking-capable models (qwen3.5 and friends) spend their token
        # budget reasoning before they answer; with a capped num_predict the
        # whole budget can go there and ``response`` comes back empty.  The
        # trace is returned so the UI still has output to show — verified
        # against the real daemon, where "hi" @ num_predict=32 yielded
        # thinking-only output.
        "thinking": resp.get("thinking") or "",
        "duration_s": round(elapsed, 2),
        "eval_count": eval_count,
        "tokens_per_s": _tokens_per_s(resp),
    })


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
    num_predict = max(1, min(_safe_int(num_predict, 128) or 128, MAX_NUM_PREDICT))
    return {
        "model": name,
        "messages": msgs,
        "stream": stream,
        "options": {"num_predict": num_predict},
    }


def _tokens_per_s(resp: dict) -> float | None:
    # Same junk types as the eval_count field on chat(); int() used to 500.
    # inf from JSON 1e400 is OverflowError, which is not ValueError.
    # A finite leftover ``1e308`` / 400-digit integer still OverflowError's the
    # division (or yields inf) and 500'd POST /api/ollama/test at encode time.
    eval_count = _safe_int(resp.get("eval_count"))
    eval_ns = _safe_int(resp.get("eval_duration"))
    if not eval_ns:
        return None
    try:
        rate = round(eval_count / (eval_ns / 1e9), 1)
    except (OverflowError, ValueError, ZeroDivisionError):
        return None
    if rate != rate or rate in (float("inf"), float("-inf")):
        return None
    return rate


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
        raise _daemon_error(e, "ollama.chat_failed")
    msg = resp.get("message") if isinstance(resp.get("message"), dict) else {}
    eval_count = _safe_int(resp.get("eval_count"))
    return _jsonable({
        "ok": True,
        "model": payload["model"],
        "role": msg.get("role") or "assistant",
        "content": msg.get("content") or "",
        "thinking": msg.get("thinking") or "",
        "duration_s": round(time.monotonic() - t0, 2),
        "eval_count": eval_count,
        "tokens_per_s": _tokens_per_s(resp),
    })


def _open_chat_http(payload: dict):
    """POST /api/chat and return the raw HTTPResponse (caller closes it)."""
    url = base_url() + "/api/chat"
    try:
        data = json.dumps(_jsonable(payload), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError):
        # RecursionError: leftover nested chat body after _jsonable is not
        # ValueError; POST /api/ollama/chat used to 500 before the HTTP open.
        raise api_error("ollama.chat_failed", error="request is not json")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        return _ollama_open(req, GENERATE_TIMEOUT)
    except urllib.error.HTTPError as e:
        err = ""
        try:
            err = e.read(400).decode("utf-8", "replace")
        except Exception:
            err = exc_detail(e)
        raise api_error("ollama.chat_failed", error=(err or exc_detail(e))[:200])
    except Exception as e:
        raise _daemon_error(e, "ollama.chat_failed")


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
        version = _as_text(_api("/api/version").get("version"))
        resident = parse_ps(_api("/api/ps"))
    except Exception as e:
        rows.append({
            "id": "ollama_api",
            "name": row_name,
            "level": "warn",
            "ok": False,
            "detail": f"API unreachable ({exc_detail(e, 100)})",
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
    origins = _agent_origins(label)
    if not origins_allow_lan(origins):
        rows.append({
            "id": "ollama_lan_origins",
            "name": "Ollama LAN CORS",
            "level": "warn",
            "ok": False,
            "detail": (
                "OLLAMA_ORIGINS does not allow LAN browser origins; "
                "pages that send Origin: http://192.168… get 403"
            ),
            "fix": (
                "Add * (keep chrome-extension://* for translation add-ons) to "
                f"OLLAMA_ORIGINS on {label or 'the Ollama LaunchAgent'} and kickstart it"
            ),
        })
    return rows


if __name__ == "__main__":
    print(json.dumps(status(), ensure_ascii=False, indent=2, allow_nan=False))
