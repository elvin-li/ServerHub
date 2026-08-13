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
import os
import re
import shutil
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml

from hub import audit, secure_io
from hub.errors import CODES, api_error
from hub.paths import DATA_DIR

REMOTE_DIR = DATA_DIR / "catalog-remote"
STATE_PATH = REMOTE_DIR / "state.json"

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


class _FetchError(Exception):
    """Transport-level failure fetching one URL (network, TLS, HTTP status)."""


class _TooLargeError(Exception):
    """The response body exceeded the caller's size cap."""


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects that leave HTTPS.

    urllib follows redirects transparently, including an https -> http
    downgrade, which would silently void the transport half of the integrity
    story.  The sha256 pinning would still catch altered *template* bytes, but
    the manifest itself has no pin, so the downgrade must be refused outright.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise urllib.error.URLError("redirect left https")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_HttpsOnlyRedirect())


def _fetch(url: str, max_bytes: int) -> bytes:
    """GET *url*, capped at *max_bytes*.  The single seam tests mock."""
    req = urllib.request.Request(url, headers={"User-Agent": "ServerHub-catalog"})
    try:
        with _opener.open(req, timeout=FETCH_TIMEOUT) as resp:
            data = resp.read(max_bytes + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise _FetchError(str(exc)) from exc
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
    return url


def source_url() -> str:
    from hub.config import cfg

    section = (cfg().get("settings") or {}).get("catalog_remote") or {}
    return str(section.get("url") or "").strip()


def set_source_url(url: str, operator: str = "") -> dict:
    from hub.config import update_settings

    clean = validate_source_url(url)
    update_settings({"catalog_remote": {"url": clean}})
    # `username=` is the field the Audit page renders as the operator.
    audit.record(EVENT_SOURCE_CHANGED, username=operator, url=clean or "(cleared)")
    return {"ok": True, "url": clean}


# ── state ─────────────────────────────────────────────────────────────────────


def _ensure_dir() -> None:
    secure_io.make_secret_dir(REMOTE_DIR)


def _load_state() -> dict:
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_state(state: dict) -> None:
    _ensure_dir()
    secure_io.replace_secret_text(
        STATE_PATH, json.dumps(state, ensure_ascii=False, indent=2)
    )


def _invalidate_catalog_cache() -> None:
    from hub import catalog

    catalog._list_cache["t"] = 0
    catalog._list_cache["items"] = None


# ── read side used by hub.catalog ─────────────────────────────────────────────


def remote_template_files() -> list[Path]:
    """Downloaded template files, sorted by name.  Missing dir -> empty."""
    try:
        return sorted(p for p in REMOTE_DIR.glob("*.yml") if p.is_file())
    except OSError:
        return []


def remote_template_path(template_id: str) -> Path | None:
    """The remote override for *template_id*, or None."""
    if not _ID_RE.match(str(template_id or "")):
        return None
    p = REMOTE_DIR / f"{template_id}.yml"
    return p if p.is_file() else None


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
    overrides = []
    for p in remote_template_files():
        tid = p.stem
        builtin = any(
            (catalog.TEMPLATES / f"{tid}{suffix}").exists()
            for suffix in (".yml", ".yaml")
        )
        overrides.append(
            {"id": tid, "version": versions.get(tid, ""), "builtin_available": builtin}
        )
    return {
        "url": source_url(),
        "configured": bool(source_url()),
        "last_check": state.get("last_check") or "",
        "last_result": state.get("last_result") or None,
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

    m = catalog.FM_RE.match(text)
    if not m:
        return "missing front matter"
    try:
        meta = yaml.safe_load(m.group(1))
    except Exception as exc:  # noqa: BLE001 - carry the real cause upward
        return f"front matter is not valid YAML: {exc}"
    if not isinstance(meta, dict):
        return "front matter is not a mapping"
    if not str(meta.get("name") or "").strip():
        return "front matter lacks a name"
    if not str(meta.get("desc") or "").strip():
        return "front matter lacks a desc"
    # The listing id comes from the *filename*, but a front-matter `id:` key
    # overrides it in _parse_template().  A template that claims another id
    # would impersonate a different catalog entry, so the two must agree.
    if expected_id and str(meta.get("id") or expected_id) != expected_id:
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
    except Exception as exc:  # noqa: BLE001
        return f"compose body is not valid YAML: {exc}"
    if not isinstance(doc, dict) or not isinstance(doc.get("services"), dict) or not doc["services"]:
        return "compose body has no services mapping"
    return ""


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


def check_updates(url: str | None = None, operator: str = "") -> dict:
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
        raise api_error("catalog_remote.fetch_failed", reason=str(exc))
    except _FetchError as exc:
        raise api_error("catalog_remote.fetch_failed", reason=str(exc))

    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise api_error("catalog_remote.bad_manifest", reason=f"not JSON: {exc}")
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
            if current.get("sha256") == sha and final.is_file():
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
                    {"id": tid, "reason": REJECT_FETCH_FAILED, "detail": str(exc)}
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

            # Fully validated: write to staging, then atomically into place.
            staged = staging / f"{tid}.yml"
            staged.write_text(text, encoding="utf-8")
            staged.chmod(0o600)
            os.replace(staged, final)
            (updated if current else added).append(tid)
            known[tid] = {"version": version, "sha256": sha, "synced": _now()}
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
        url=index_url,
        added=len(added),
        updated=len(updated),
        unchanged=len(unchanged),
        rejected=len(rejected),
    )
    return summary


def restore_builtin(template_id: str, operator: str = "") -> dict:
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
    state = _load_state()
    templates = state.get("templates")
    if isinstance(templates, dict):
        templates.pop(tid, None)
        _save_state(state)
    _invalidate_catalog_cache()
    audit.record(EVENT_RESTORED, username=operator, template=tid)
    from hub import catalog

    builtin = any(
        (catalog.TEMPLATES / f"{tid}{suffix}").exists() for suffix in (".yml", ".yaml")
    )
    return {"ok": True, "id": tid, "builtin_available": builtin}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")
