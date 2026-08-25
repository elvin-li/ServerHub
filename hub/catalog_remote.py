"""Remote template catalog source (admin-triggered, offline-first).

The built-in ``templates/`` directory ships with the app and always works
offline.  This module adds an *optional* remote HTTPS source an administrator
can point the panel at.  The source is a static file host serving::

    index.json            the manifest (shape below)
    <path per entry>      one compose template per manifest entry

Manifest shape::

    {
      "version": 1,
      "generated": "2026-08-01T00:00:00Z",
      "signature": "",
      "templates": [
        {"id": "jellyfin", "version": "1.2.0", "path": "jellyfin.yml",
         "sha256": "<hex sha256 of the template file>", "size": 1234}
      ]
    }

Downloaded templates land in ``data/catalog-remote/`` (0700) and shadow the
built-in template with the same id; deleting the override ("restore built-in")
falls straight back to the shipped file, so the panel keeps working with the
catalog it was installed with even if the remote source disappears forever.

Integrity model — sha256 manifest over HTTPS, not a real signature
──────────────────────────────────────────────────────────────────
The right design is an Ed25519-signed manifest with the public key pinned in
this file, so a compromised web host cannot alter templates.  That needs an
asymmetric-crypto primitive, and this project's runtime dependency set
(requirements.txt) deliberately contains none — no ``cryptography``, no
``pynacl`` — and the stdlib offers only hashing/HMAC.  Rather than pull in a
new dependency for this feature, the shipped compromise is:

  * transport trust: HTTPS only, certificate-verified by the stdlib opener,
    and redirects may not leave HTTPS;
  * content pinning: every template file must hash (sha256) to exactly what
    the manifest declares, so a CDN or mirror cannot substitute files without
    also controlling the manifest;
  * blast-radius limits: per-file size cap, manifest entry cap, and every
    template must survive the same parser the catalog uses before it is
    accepted.

This is strictly weaker than a signature — whoever controls the manifest URL
controls the catalog — which is why the manifest already carries a reserved
``signature`` field: when a signing-capable dependency lands, verification can
be added here without changing the published manifest format.  Until then the
administrator's choice of source URL is the root of trust, template *content*
is still only rendered through render_template()'s injection guards, and
installing anything remains an explicit admin action.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml

from hub import audit, secure_io
from hub.errors import CODES, api_error
from hub.paths import DATA_DIR
from hub.util import read_text_capped, safe_json_loads, strftime_now

REMOTE_DIR = DATA_DIR / "catalog-remote"
STATE_PATH = REMOTE_DIR / "state.json"
#: Leftover multi-MB state used to OOM GET /api/catalog/remote.
_STATE_CAP = 256 * 1024

#: One template is a compose file plus front matter; the largest shipped one is
#: under 4 KB, so 64 KB leaves generous headroom while keeping a hostile source
#: from streaming megabytes into memory per file.
MAX_TEMPLATE_BYTES = 64 * 1024
#: The manifest lists at most MAX_TEMPLATES small entries; 512 KB is roomy.
MAX_MANIFEST_BYTES = 512 * 1024
MAX_TEMPLATES = 500
FETCH_TIMEOUT = 20.0

#: Template ids become ``<id>.yml`` filenames inside REMOTE_DIR, so the charset
#: must exclude path separators and anything shell-hostile.
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_MAX = 64

# Machine-readable error codes (HTTP-level failures; per-template rejections
# travel inside the summary payload instead).  Registered here so the mapping
# lives with the module that raises them, mirroring hub/catalog.py.
CODES.setdefault("catalog_remote.not_configured", (400, "no remote catalog source is configured"))
CODES.setdefault("catalog_remote.bad_url", (400, "the catalog source must be a plain https:// URL"))
CODES.setdefault("catalog_remote.fetch_failed", (502, "could not fetch the remote catalog: {reason}"))
CODES.setdefault("catalog_remote.bad_manifest", (422, "the remote catalog manifest is invalid: {reason}"))
CODES.setdefault(
    "catalog_remote.too_many_templates",
    (422, "the remote catalog lists {count} templates (limit {limit})"),
)
CODES.setdefault("catalog_remote.bad_id", (400, "invalid template id: {id}"))
CODES.setdefault("catalog_remote.not_remote", (404, "template {id} has no remote override"))
CODES.setdefault(
    "catalog_remote.browser_session_required",
    (401, "sign in from a browser to manage the catalog source"),
)
CODES.setdefault("catalog_remote.admin_required", (403, "administrator access is required"))
CODES.setdefault(
    "catalog_remote.write_failed",
    (500, "could not write the remote catalog: {reason}"),
)

#: Audit event names (kept local: hub/audit.py is shared with parallel work).
EVENT_SOURCE_CHANGED = "catalog.remote.source_changed"
EVENT_SYNC = "catalog.remote.sync"
EVENT_RESTORED = "catalog.remote.restored"

#: Per-template rejection reasons (machine-readable, stable).
REJECT_BAD_ENTRY = "bad_entry"
REJECT_BAD_ID = "bad_id"
REJECT_DUPLICATE_ID = "duplicate_id"
REJECT_BAD_URL = "bad_url"
REJECT_TOO_LARGE = "too_large"
REJECT_SHA256_MISMATCH = "sha256_mismatch"
REJECT_FETCH_FAILED = "fetch_failed"
REJECT_PARSE_FAILED = "parse_failed"
REJECT_WRITE_FAILED = "write_failed"


class _FetchError(Exception):
    """Transport-level failure fetching one URL (network, TLS, HTTP status)."""


class _TooLargeError(Exception):
    """The response body exceeded the caller's size cap."""


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects that leave the manifest's HTTPS origin.

    urllib follows redirects transparently, including an https -> http
    downgrade, which would silently void the transport half of the integrity
    story.  Staying on HTTPS is not enough: a 302 to
    ``https://169.254.169.254/`` is still SSRF (the same hole notify already
    closed).  Pin to the original netloc; template paths are already origin
    pinned by :func:`_entry_url`.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        src = urllib.parse.urlsplit(getattr(req, "full_url", "") or "")
        dest = urllib.parse.urlsplit(newurl)
        if dest.scheme != "https":
            raise urllib.error.URLError("redirect left https")
        if dest.username is not None or dest.password is not None:
            raise urllib.error.URLError("redirect has credentials")
        if dest.netloc.lower() != src.netloc.lower():
            raise urllib.error.URLError("redirect left origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(
    _HttpsOnlyRedirect(),
    # Env HTTP(S)_PROXY would bypass the host check and fetch the
    # unsigned manifest through whatever the process inherited.
    urllib.request.ProxyHandler({}),
)


def _fetch(url: str, max_bytes: int) -> bytes:
    """GET *url*, capped at *max_bytes*.  The single seam tests mock."""
    req = urllib.request.Request(url, headers={"User-Agent": "ServerHub-catalog"})
    try:
        with _opener.open(req, timeout=FETCH_TIMEOUT) as resp:
            data = resp.read(max_bytes + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise _FetchError(_as_text(exc)) from exc
    if len(data) > max_bytes:
        raise _TooLargeError(f"response exceeds {max_bytes} bytes")
    return data


def validate_source_url(url: str) -> str:
    """Normalise and vet a catalog source URL ("" clears the source)."""
    url = (url or "").strip()
    if not url:
        return ""
    parts = urllib.parse.urlsplit(url)
    # HTTPS-only, no embedded credentials: the URL is stored in services.yaml
    # and echoed by the status API, so a user:pass@host form would persist a
    # secret in plain sight (and Basic-auth sources are not supported anyway).
    if parts.scheme != "https" or not parts.hostname or "@" in parts.netloc:
        raise api_error("catalog_remote.bad_url")
    # Same IMDS / link-local block as notify webhooks.  An administrator
    # pointing the catalog at ``https://169.254.169.254/`` is SSRF, not a
    # template source.
    from hub.http_guard import is_allowed_notify_host

    if not is_allowed_notify_host(parts.hostname):
        raise api_error("catalog_remote.bad_url")
    return url


def source_url() -> str:
    from hub.config import settings_section

    section = settings_section("catalog_remote")
    return str(section.get("url") or "").strip()


def set_source_url(url: str, operator: str = "", client: str = "") -> dict:
    from hub.config import update_settings

    clean = validate_source_url(url)
    update_settings({"catalog_remote": {"url": clean}})
    # `username=` is the field the Audit page renders as the operator, and
    # `client=` its Source column.  Both arrive from the router; these three
    # entry points are explicit admin actions, never background jobs.
    audit.record(EVENT_SOURCE_CHANGED, username=operator, client=client,
                 url=clean or "(cleared)")
    return {"ok": True, "url": clean}


# ── state ─────────────────────────────────────────────────────────────────────


def _as_text(value) -> str:
    """Exception text that cannot RecursionError leftover ``str(exc)`` or UTF-8 500."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif value is None:
        return ""
    else:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    return value.encode("utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Drop leftover inf/NaN/``\\ud800`` so GET /api/catalog/remote cannot 500."""
    if depth > 32:
        return None
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, (bytes, bytearray)):
                key = k.decode("utf-8", "replace")
            else:
                try:
                    key = k if isinstance(k, str) else str(k)
                except Exception:
                    continue
            try:
                key = key.encode("utf-8", "replace").decode("utf-8")
            except Exception:
                continue
            out[key] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/catalog/remote.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _as_text(value)
    except Exception:
        return None


def _capped_json_int(text):
    """``json.loads`` parse_int hook: an over-cap digit run drops to None.

    ``int()`` of a >4300-digit decimal is ValueError (not JSONDecodeError)
    for the *whole* document.  In ``_load_state`` one poisoned number made
    the load return ``{}`` — every synced override's version, warnings and
    the last-check stamp silently lost, and the next sync re-downloaded the
    entire catalog.  In ``check_updates`` the same number in one manifest
    entry failed the whole sync as ``bad_manifest`` instead of that entry.
    Dropping just the number matches the ``_jsonable`` rule for an int the
    encoder cannot render (same hook as smart_test_svc._capped_json_int).
    """
    try:
        return int(text)
    except ValueError:
        return None


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _ensure_dir() -> None:
    try:
        secure_io.make_secret_dir(REMOTE_DIR)
        if _is_dir(REMOTE_DIR):
            return
    except OSError as exc:
        raise api_error("catalog_remote.write_failed", reason=_as_text(exc))
    raise api_error(
        "catalog_remote.write_failed",
        reason="remote catalog path is not a directory",
    )


def _load_state() -> dict:
    try:
        data = safe_json_loads(
            read_text_capped(STATE_PATH, _STATE_CAP, encoding="utf-8"),
            # A >4300-digit leftover number is ValueError for the whole
            # document; without the hook it wiped every override's version
            # and warnings, not just the poisoned value.
            parse_int=_capped_json_int,
        )
    except (OSError, ValueError, RecursionError):
        # RecursionError: leftover deeply-nested state is not ValueError.
        return {}
    data = _jsonable(data)
    return data if isinstance(data, dict) else {}


def _save_state(state: dict) -> None:
    _ensure_dir()
    payload = _jsonable(state)
    if not isinstance(payload, dict):
        payload = {}
    try:
        secure_io.replace_secret_text(
            STATE_PATH, json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False)
        )
    except (OSError, TypeError, ValueError, RecursionError) as exc:
        # RecursionError: leftover nested remote state after _jsonable is not
        # ValueError; leftover ``str(exc)`` RecursionError used to 500 the write.
        raise api_error("catalog_remote.write_failed", reason=_as_text(exc))


def _invalidate_catalog_cache() -> None:
    from hub import catalog

    catalog.invalidate_listing()


# ── read side used by hub.catalog ─────────────────────────────────────────────


def remote_template_files() -> list[Path]:
    """Downloaded template files, sorted by name.  Missing dir -> empty."""
    try:
        return sorted(p for p in REMOTE_DIR.glob("*.yml") if _is_file(p))
    except OSError:
        return []


def remote_template_path(template_id: str) -> Path | None:
    """The remote override for *template_id*, or None."""
    if not _ID_RE.match(str(template_id or "")):
        return None
    p = REMOTE_DIR / f"{template_id}.yml"
    return p if _is_file(p) else None


def remote_versions() -> dict[str, str]:
    """id -> manifest version for every synced override."""
    templates = _load_state().get("templates")
    if not isinstance(templates, dict):
        return {}
    out: dict[str, str] = {}
    for tid, info in templates.items():
        if isinstance(info, dict):
            out[str(tid)] = str(info.get("version") or "")
    return out


def status() -> dict:
    from hub import catalog

    state = _load_state()
    versions = remote_versions()
    warnings = remote_warnings()
    overrides = []
    for p in remote_template_files():
        tid = p.stem
        builtin = any(
            _exists(catalog.TEMPLATES / f"{tid}{suffix}")
            for suffix in (".yml", ".yaml")
        )
        overrides.append({
            "id": tid,
            "version": versions.get(tid, ""),
            "builtin_available": builtin,
            "warnings": warnings.get(tid, []),
        })
    last_check = state.get("last_check")
    last_result = state.get("last_result")
    payload = {
        "url": source_url(),
        "configured": bool(source_url()),
        "last_check": last_check if isinstance(last_check, str) else "",
        "last_result": last_result if isinstance(last_result, dict) else None,
        "overrides": overrides,
        "count": len(overrides),
        "limits": {
            "max_template_bytes": MAX_TEMPLATE_BYTES,
            "max_templates": MAX_TEMPLATES,
        },
        # Honest capability flag for the UI: content is sha256-pinned but the
        # manifest is only transport-trusted (see module docstring).
        "signature_verified": False,
    }
    # Through _jsonable: an override id comes from a *filename* stem, and a
    # leftover file named with surrogateescape bytes (or a hand-edited
    # services.yaml url carrying a lone ``\ud800``) kept the raw surrogate
    # here while every synced field was clean — Starlette's UTF-8 encode
    # then 500'd GET /api/catalog/remote.
    cleaned = _jsonable(payload)
    return cleaned if isinstance(cleaned, dict) else {"configured": False, "overrides": []}


# ── validation ────────────────────────────────────────────────────────────────


def _validate_template_text(text: str, expected_id: str = "") -> str:
    """"" when *text* is an acceptable template, else a short reason.

    Stricter than catalog._parse_template(), which deliberately swallows
    front-matter errors at runtime so one broken file cannot take the whole
    store down.  For *ingest* the opposite is right: a template that would be
    listed with degraded metadata is refused before it can shadow a working
    built-in.
    """
    from hub import catalog

    # SafeLoader rejects !!python/* at parse time, but a quoted or commented
    # tag would still be written onto disk and later fed to any consumer that
    # is not SafeLoader (docker-compose v1).  Refuse the substring outright.
    if "!!python" in text.lower():
        return "python YAML tags are not allowed"
    m = catalog.FM_RE.match(text)
    if not m:
        return "missing front matter"
    try:
        meta = yaml.safe_load(m.group(1))
    except (
        yaml.YAMLError, RecursionError, TypeError, ValueError, AttributeError, KeyError,
    ) as exc:
        # RecursionError: leftover deeply-nested front matter is not YAMLError.
        # TypeError/ValueError/AttributeError/KeyError: leftover ``!!timestamp .inf``,
        # ``2026-13-01``, a 5000-digit int, or ``!!bool 2`` are not YAMLError.
        return "front matter is not valid YAML: " + _as_text(exc)
    if not isinstance(meta, dict):
        return "front matter is not a mapping"
    # _as_text, not bare str(): YAML's hex/octal int forms dodge CPython's
    # decimal digit cap, so a leftover ``name: 0xfff…`` (4000 hex digits)
    # arrives as an int ``str()`` cannot render — the ValueError fired here,
    # after the YAML try/except had already passed, and 500'd the whole
    # POST /api/catalog/remote/check instead of rejecting one template.
    # A *sane* numeric name/desc/id still renders (str() probe, not an
    # isinstance(str) gate that would silently drop numeric YAML ids).
    if not _as_text(meta.get("name") or "").strip():
        return "front matter lacks a name"
    if not _as_text(meta.get("desc") or "").strip():
        return "front matter lacks a desc"
    # The listing id comes from the *filename*, but a front-matter `id:` key
    # overrides it in _parse_template().  A template that claims another id
    # would impersonate a different catalog entry, so the two must agree.
    if expected_id and _as_text(meta.get("id") or expected_id) != expected_id:
        return "front matter id does not match the manifest id"
    body = m.group(2)
    # The same trap tests/test_template_metadata.py pins for shipped templates:
    # an unquoted `default: {{X}}` parses as a YAML flow mapping and destroys
    # the listing, so it is refused at the door.
    for line in m.group(1).splitlines():
        stripped = line.strip()
        if stripped.startswith("default:") and stripped.split("default:", 1)[1].strip().startswith("{{"):
            return "unquoted {{...}} default in front matter"
    # Render with dummy values, then insist the compose body is real YAML with
    # a non-empty services mapping.  catalog.render_template() is not usable
    # here (it requires the caller to supply every variable), so substitute the
    # same placeholder grammar it consumes.
    rendered = catalog.VAR_RE.sub("1", body)
    try:
        doc = yaml.safe_load(rendered)
    except (
        yaml.YAMLError, RecursionError, TypeError, ValueError, AttributeError, KeyError,
    ) as exc:
        # RecursionError: leftover deeply-nested compose body is not YAMLError.
        # TypeError/ValueError/AttributeError/KeyError: leftover ``!!timestamp .inf``,
        # ``2026-13-01``, a 5000-digit int, or ``!!bool 2`` are not YAMLError.
        return "compose body is not valid YAML: " + _as_text(exc)
    if not isinstance(doc, dict) or not isinstance(doc.get("services"), dict) or not doc["services"]:
        return "compose body has no services mapping"
    return ""


#: Compose directives worth flagging on an ingested template.  Stable machine
#: codes; the SPA translates them (catalog_remote.warn_<code>).
WARN_PRIVILEGED = "privileged"
WARN_CAP_ADD = "cap_add"
WARN_DOCKER_SOCKET = "docker_socket"
WARN_HOST_NETWORK = "host_network"
WARN_DEVICES = "devices"


def scan_compose_directives(text: str) -> list[str]:
    """Elevated-access compose directives used by template *text*, sorted.

    Defence in depth, not a gate: the administrator's choice of source URL is
    the root of trust (module docstring), and plenty of legitimate templates
    need e.g. a device or the Docker socket.  But a remote override installs
    exactly like the built-in it shadows, with only a small badge to tell them
    apart — so anything that would widen a container's blast radius is
    recorded at ingest and shown prominently in the install dialog instead of
    being silently accepted.  Returns machine codes, never rejects.
    """
    from hub import catalog

    m = catalog.FM_RE.match(text)
    body = m.group(2) if m else text
    try:
        doc = yaml.safe_load(catalog.VAR_RE.sub("1", body))
    except (
        yaml.YAMLError, RecursionError, TypeError, ValueError, AttributeError, KeyError,
    ):
        # RecursionError: leftover deeply-nested compose body is not YAMLError.
        # TypeError/ValueError/AttributeError/KeyError: leftover ``!!timestamp .inf``,
        # ``2026-13-01``, a 5000-digit int, or ``!!bool 2`` are not YAMLError.
        return []
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        return []
    hits: set[str] = set()
    for service in services.values():
        if not isinstance(service, dict):
            continue
        if service.get("privileged"):
            hits.add(WARN_PRIVILEGED)
        if service.get("cap_add"):
            hits.add(WARN_CAP_ADD)
        if service.get("devices"):
            hits.add(WARN_DEVICES)
        # _as_text, not bare str(): a leftover hex-huge ``network_mode`` or
        # volume entry is an over-digit-cap int whose str() is ValueError —
        # it fired here after ingest validation had already accepted the
        # template, 500ing POST /api/catalog/remote/check on the last step.
        if _as_text(service.get("network_mode") or "").strip().lower() == "host":
            hits.add(WARN_HOST_NETWORK)
        volumes = service.get("volumes")
        if not isinstance(volumes, list):
            continue
        for volume in volumes:
            # Both list forms: "sock:/sock" strings and {source: ...} maps.
            source = volume.get("source") if isinstance(volume, dict) else volume
            if "docker.sock" in _as_text(source or ""):
                hits.add(WARN_DOCKER_SOCKET)
    return sorted(hits)


def remote_warnings() -> dict[str, list[str]]:
    """id -> elevated-access directive codes for every synced override.

    Populated at ingest by check_updates(); an override synced before this
    field existed simply reports no warnings until its next sync.
    """
    templates = _load_state().get("templates")
    if not isinstance(templates, dict):
        return {}
    out: dict[str, list[str]] = {}
    for tid, info in templates.items():
        if isinstance(info, dict):
            warnings = info.get("warnings")
            out[str(tid)] = [str(w) for w in warnings] if isinstance(warnings, list) else []
    return out


def _validate_entry(entry: Any) -> str:
    """"" when a manifest entry is well-formed, else a short reason."""
    if not isinstance(entry, dict):
        return "entry is not an object"
    if not _ID_RE.match(str(entry.get("id") or "")):
        return "bad id"
    sha = str(entry.get("sha256") or "").lower()
    if not _SHA256_RE.match(sha):
        return "bad sha256"
    if len(str(entry.get("version") or "")) > _VERSION_MAX:
        return "version too long"
    path = str(entry.get("path") or entry.get("url") or f"{entry.get('id')}.yml")
    if not path or "\\" in path:
        return "bad path"
    return ""


def _entry_url(index_url: str, entry: dict) -> str:
    """Absolute HTTPS URL for one manifest entry, or "" when unacceptable.

    Resolved relative to the manifest and pinned to the manifest's host: a
    manifest must not be able to point the panel at arbitrary third-party
    hosts, even over HTTPS.
    """
    rel = str(entry.get("path") or entry.get("url") or f"{entry.get('id')}.yml")
    resolved = urllib.parse.urljoin(index_url, rel)
    a, b = urllib.parse.urlsplit(resolved), urllib.parse.urlsplit(index_url)
    if a.scheme != "https" or a.netloc != b.netloc:
        return ""
    return resolved


# ── sync ──────────────────────────────────────────────────────────────────────


def check_updates(url: str | None = None, operator: str = "", client: str = "") -> dict:
    """Fetch the manifest and swap in every template that passes validation.

    Explicit admin action only — there is deliberately no background poll.
    Partial success is expected and reported: one bad entry lands in
    ``rejected`` with a machine-readable reason and never blocks its
    neighbours.  Files are staged in a temp dir inside REMOTE_DIR and moved
    into place with os.replace(), so a crash or rejection can never leave a
    half-written template shadowing a built-in.
    """
    index_url = validate_source_url(url if url is not None else source_url())
    if not index_url:
        raise api_error("catalog_remote.not_configured")

    try:
        raw = _fetch(index_url, MAX_MANIFEST_BYTES)
    except _TooLargeError as exc:
        raise api_error("catalog_remote.fetch_failed", reason=_as_text(exc))
    except _FetchError as exc:
        raise api_error("catalog_remote.fetch_failed", reason=_as_text(exc))

    try:
        # parse_int hook: a >4300-digit number in *one* entry (a bogus
        # ``size``) is ValueError for the whole document and used to fail
        # the entire sync as bad_manifest; dropping just the number lets
        # per-entry validation reject only what deserves it.
        manifest = safe_json_loads(raw.decode("utf-8"), parse_int=_capped_json_int)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise api_error(
            "catalog_remote.bad_manifest", reason="not JSON: " + _as_text(exc)
        )
    if not isinstance(manifest, dict) or not isinstance(manifest.get("templates"), list):
        raise api_error("catalog_remote.bad_manifest", reason="missing templates list")
    entries = manifest["templates"]
    if len(entries) > MAX_TEMPLATES:
        raise api_error(
            "catalog_remote.too_many_templates", count=len(entries), limit=MAX_TEMPLATES
        )

    _ensure_dir()
    state = _load_state()
    known = state.get("templates") if isinstance(state.get("templates"), dict) else {}

    added: list[str] = []
    updated: list[str] = []
    unchanged: list[str] = []
    rejected: list[dict] = []
    seen: set[str] = set()

    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=REMOTE_DIR))
    try:
        for entry in entries:
            reason = _validate_entry(entry)
            tid = str(entry.get("id") or "?") if isinstance(entry, dict) else "?"
            if reason:
                code = REJECT_BAD_ID if reason == "bad id" else REJECT_BAD_ENTRY
                rejected.append({"id": tid, "reason": code, "detail": reason})
                continue
            if tid in seen:
                rejected.append(
                    {"id": tid, "reason": REJECT_DUPLICATE_ID, "detail": "listed twice"}
                )
                continue
            seen.add(tid)
            sha = str(entry["sha256"]).lower()
            version = str(entry.get("version") or "")

            current = known.get(tid) if isinstance(known.get(tid), dict) else {}
            final = REMOTE_DIR / f"{tid}.yml"
            if current.get("sha256") == sha and _is_file(final):
                unchanged.append(tid)
                continue

            file_url = _entry_url(index_url, entry)
            if not file_url:
                rejected.append(
                    {"id": tid, "reason": REJECT_BAD_URL,
                     "detail": "resolved outside the manifest's https origin"}
                )
                continue
            try:
                blob = _fetch(file_url, MAX_TEMPLATE_BYTES)
            except _TooLargeError:
                rejected.append(
                    {"id": tid, "reason": REJECT_TOO_LARGE,
                     "detail": f"larger than {MAX_TEMPLATE_BYTES} bytes"}
                )
                continue
            except _FetchError as exc:
                rejected.append(
                    {"id": tid, "reason": REJECT_FETCH_FAILED, "detail": _as_text(exc)}
                )
                continue
            if hashlib.sha256(blob).hexdigest() != sha:
                rejected.append(
                    {"id": tid, "reason": REJECT_SHA256_MISMATCH,
                     "detail": "file hash does not match the manifest"}
                )
                continue
            text = blob.decode("utf-8", errors="replace")
            parse_reason = _validate_template_text(text, expected_id=tid)
            if parse_reason:
                rejected.append(
                    {"id": tid, "reason": REJECT_PARSE_FAILED, "detail": parse_reason}
                )
                continue

            # replace_secret_text is 0600 from the first byte and does not
            # O_TRUNC the published template if the process dies mid-write.
            # A leftover directory named <id>.yml used to raise IsADirectoryError
            # / PermissionError and 500 the whole sync.
            try:
                secure_io.replace_secret_text(final, text)
            except OSError as exc:
                rejected.append(
                    {"id": tid, "reason": REJECT_WRITE_FAILED, "detail": _as_text(exc)}
                )
                continue
            (updated if current else added).append(tid)
            known[tid] = {
                "version": version,
                "sha256": sha,
                "synced": _now(),
                # Elevated-access directives are accepted but remembered, so
                # the install dialog can warn before anything runs.
                "warnings": scan_compose_directives(text),
            }
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    state["templates"] = known
    state["source_url"] = index_url
    state["last_check"] = _now()
    summary = {
        "ok": True,
        "checked": len(entries),
        "added": sorted(added),
        "updated": sorted(updated),
        "unchanged": len(unchanged),
        "rejected": rejected,
    }
    state["last_result"] = {
        "added": len(added),
        "updated": len(updated),
        "unchanged": len(unchanged),
        "rejected": len(rejected),
        "at": state["last_check"],
    }
    _save_state(state)
    _invalidate_catalog_cache()
    audit.record(
        EVENT_SYNC,
        username=operator,
        client=client,
        url=index_url,
        added=len(added),
        updated=len(updated),
        unchanged=len(unchanged),
        rejected=len(rejected),
    )
    # Leftover JSON ``\ud800`` in a rejected manifest id used to UnicodeEncodeError
    # POST /api/catalog/remote/check (Starlette allow_nan=False + UTF-8).
    cleaned = _jsonable(summary)
    return cleaned if isinstance(cleaned, dict) else {"ok": False, "rejected": []}


def restore_builtin(template_id: str, operator: str = "", client: str = "") -> dict:
    """Delete the remote override so the built-in template shows again."""
    tid = str(template_id or "")
    if not _ID_RE.match(tid):
        raise api_error("catalog_remote.bad_id", id=tid)
    path = REMOTE_DIR / f"{tid}.yml"
    try:
        # unlink() decides existence and removal in one step; a separate
        # is_file() probe could answer wrongly between check and delete.
        path.unlink()
    except FileNotFoundError:
        raise api_error("catalog_remote.not_remote", id=tid)
    except OSError:
        # A leftover directory named <id>.yml is not an override file; macOS
        # raises EPERM here rather than EISDIR, which used to 500 restore.
        raise api_error("catalog_remote.not_remote", id=tid)
    state = _load_state()
    templates = state.get("templates")
    if isinstance(templates, dict):
        templates.pop(tid, None)
        _save_state(state)
    _invalidate_catalog_cache()
    audit.record(EVENT_RESTORED, username=operator, client=client, template=tid)
    from hub import catalog

    builtin = any(
        _exists(catalog.TEMPLATES / f"{tid}{suffix}") for suffix in (".yml", ".yaml")
    )
    return {"ok": True, "id": tid, "builtin_available": builtin}


def _now() -> str:
    # Leftover inf clock OverflowError'd POST /api/catalog/remote/check timestamps.
    return strftime_now("%Y-%m-%dT%H:%M:%S%z")
