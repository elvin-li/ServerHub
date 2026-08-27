"""App catalog: one-click deploy templates (Unraid CA / CasaOS style).

Templates live in templates/*.yml with optional YAML frontmatter:
  name, desc, category, tags, ports, url_template, featured, notes, vars
"""
from __future__ import annotations

import copy
import errno
import json
import os
import plistlib
import re
import secrets
import shutil
import socket
import string
import threading
from pathlib import Path
from typing import Any

import yaml
from fastapi import HTTPException

from hub import catalog_remote
from hub import cli_args
from hub import secure_io
from hub.docker_cli import _jsonable, cli_on_disk, engine_up, looks_cli_vanished, looks_engine_down
from hub.errors import CODES, api_error, soft_fail
from hub.host_address import host_ip
from hub.paths import BASE, DOCKER, user_home
from hub.util import fan_out, read_bytes_capped, read_text_capped, run_capped

TEMPLATES = BASE / "templates"


def _default_services_root() -> Path:
    """Services tree under ``~/Services``.  ``Path.home()`` leftover must not 500 import."""
    home = user_home()
    return (home / "Services") if home is not None else Path("/var/empty/serverhub-services")


SERVICES_ROOT = _default_services_root()
#: Leftover multi-MB ``*.yml`` used to OOM GET /api/catalog.
_TEMPLATE_CAP = 64 * 1024
#: Port scan only needs the compose ports block, not a leftover multi-MB file.
_COMPOSE_SCAN_CAP = 256 * 1024
#: Leftover huge ``.GlobalPreferences.plist`` used to OOM host_languages().
_PREFS_CAP = 256 * 1024

# Catalog-owned error codes.  Registered here (rather than inlined in
# hub/errors.py) so the code -> status mapping travels with the module that
# raises it; api_error() would otherwise degrade these to HTTP 500.
CODES.setdefault("catalog.unknown_template", (404, "unknown template: {id}"))
CODES.setdefault("catalog.missing_var", (400, "missing required variable {name}"))
CODES.setdefault("catalog.bad_var_value", (400, "{name} may not contain line breaks"))
CODES.setdefault(
    "catalog.missing_token",
    (400, "{name} is required and cannot be blank: paste the real token "
          "from Cloudflare Zero Trust"),
)
CODES.setdefault("catalog.already_installed", (409, "already installed at {path}"))
CODES.setdefault("catalog.not_installed", (404, "not installed: {id}"))
CODES.setdefault("catalog.confirm_required", (400, "confirm=true is required"))
CODES.setdefault(
    "catalog.port_in_use",
    (409, "host port {port} is already in use on this machine"),
)
CODES.setdefault(
    "catalog.port_claimed",
    (409, "host port {port} is already claimed by the installed stack {stack}"),
)
CODES.setdefault(
    "catalog.browser_session_required",
    (401, "sign in from a browser to manage service credentials"),
)

FM_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.S)
VAR_RE = re.compile(r"\{\{\s*([A-Z0-9_]+)\s*\}\}")

#: Placeholders the server fills in automatically.  They must never appear as
#: blank required fields in the install form, and templates must use them
#: instead of absolute paths so the catalog is not tied to one developer's home
#: directory.
AUTO_VARS = ("HOST_IP", "HOME", "SERVICES", "TZ", "OCR_LANG", "UI_LANGS")

# Fallback categories by template id prefix / name
CATEGORY_HINTS = {
    "wg": "network",
    "wireguard": "network",
    "tailscale": "network",
    "cloudflare": "network",
    "adguard": "network",
    "pihole": "network",
    "npm": "network",
    "nginx-proxy": "network",
    "traefik": "network",
    "vnc": "remote",
    "webtop": "remote",
    "rustdesk": "remote",
    "guacamole": "remote",
    "rdp": "remote",
    "jellyfin": "media",
    "plex": "media",
    "navidrome": "media",
    "immich": "media",
    "qbittorrent": "download",
    "transmission": "download",
    "vaultwarden": "security",
    "authelia": "security",
    "code-server": "dev",
    "gitea": "dev",
    "postgres": "data",
    "mariadb": "data",
    "redis": "data",
    "minio": "data",
    "mosquitto": "iot",
    "frigate": "iot",
    "uptime": "monitor",
    "dozzle": "monitor",
    "netdata": "monitor",
    "watchtower": "ops",
    "portainer": "ops",
    "dockge": "ops",
    "homarr": "dashboard",
    "glance": "dashboard",
    "homepage": "dashboard",
    "filebrowser": "files",
    "syncthing": "files",
    "nextcloud": "files",
    "paperless": "productivity",
    "stirling": "productivity",
    "it-tools": "productivity",
    "ntfy": "notify",
    "duplicati": "backup",
}

CATEGORIES = [
    {"id": "all", "label": "All"},
    {"id": "featured", "label": "Featured"},
    {"id": "native", "label": "Native first"},
    {"id": "docker", "label": "Docker"},
    {"id": "network", "label": "Network / VPN"},
    {"id": "remote", "label": "Remote Desktop"},
    {"id": "media", "label": "Media"},
    {"id": "download", "label": "Downloads"},
    {"id": "files", "label": "Files / Sync"},
    {"id": "security", "label": "Security"},
    {"id": "dashboard", "label": "Dashboards"},
    {"id": "monitor", "label": "Monitoring"},
    {"id": "ops", "label": "Ops"},
    {"id": "dev", "label": "Development"},
    {"id": "data", "label": "Database / Storage"},
    {"id": "iot", "label": "Smart Home"},
    {"id": "productivity", "label": "Productivity"},
    {"id": "notify", "label": "Notifications"},
    {"id": "backup", "label": "Backup"},
    {"id": "other", "label": "Other"},
]


def _plain_str(value, default: str = "") -> str:
    """JSON-safe string. YAML leftover ``.inf`` / ``\\ud800`` used to 500 the store."""
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray)):
        # Unbound base decode: a leftover subclass ``.decode`` bomb cannot fire.
        base = bytes if isinstance(value, bytes) else bytearray
        text = base.decode(value, "utf-8", "replace")
    elif isinstance(value, bool) or value is None:
        return default
    elif isinstance(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except Exception:
                return default
        if value != value or value in (float("inf"), float("-inf")):
            return default
        text = str(value)
    elif isinstance(value, (dict, list, tuple, set, frozenset)):
        return default
    else:
        try:
            text = str(value)
        except Exception:
            return default
    try:
        # Unbound base encode — ``str()`` of a str subclass whose ``__str__``
        # returns self keeps the subclass, so a bound ``.encode`` bomb could
        # still fire (the modules5 unbound convention, like docker_cli).
        return str.encode(text, "utf-8", "replace").decode("utf-8")
    except Exception:
        return default


def _isinst(value, types) -> bool:
    """``isinstance`` a leftover ``__class__``-property bomb cannot 500 through.

    The hub.jobs / hub.auth rule: CPython's ``isinstance`` reads the operand's
    ``__class__`` whenever the real-type fast check misses, so a value whose
    ``__class__`` is a raising property detonates a bare ``isinstance`` gate.
    ``catalog_overview`` merges the *native* catalog's rows — another module's
    payload — into GET /api/catalog, and the row filter's bare
    ``isinstance(a, dict)`` ran before ``_jsonable`` could launder anything: a
    single poisoned row raised straight out of the store overview instead of
    being dropped while its siblings (and the whole docker half) survived.
    A lying ``__class__`` (answers ``dict``) is not an error and still reports
    its claim; ``_jsonable`` then copies it through the C-level storage.
    """
    try:
        return isinstance(value, types)
    except Exception:
        return False


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _plain_str_list(raw) -> list[str]:
    if isinstance(raw, list):
        items = raw
    elif raw in (None, "", False):
        return []
    else:
        items = [raw]
    out: list[str] = []
    for item in items:
        text = _plain_str(item)
        if text:
            out.append(text)
    return out


def _plain_ports(raw) -> list:
    if not isinstance(raw, list):
        return []
    out: list = []
    for port in raw:
        if port is None or isinstance(port, bool):
            continue
        if isinstance(port, int):
            if type(port) is not int:
                try:
                    # Base coercion to an exact int: a subclass ``__str__``
                    # bomb used to blow the digit-cap probe below (only
                    # ValueError was caught).
                    port = int.__index__(port)
                except Exception:
                    continue
            # YAML hex/octal ints dodge CPython's int(str) digit cap, so a
            # leftover ``ports: [0xfff…]`` arrives as a >4300-digit int that
            # renders nowhere: ``str(port_spec)`` in the url_hint fallback and
            # Starlette's json.dumps both ValueError on it — 500ing
            # GET /api/catalog/templates (and silently emptying the docker
            # half of GET /api/catalog) after the parse already succeeded.
            try:
                str(port)
            except ValueError:
                continue
            out.append(port)
        else:
            if isinstance(port, float):
                if type(port) is not float:
                    try:
                        # Base coercion: a subclass ``__eq__`` bomb used to
                        # blow the NaN/inf probes below.
                        port = float.__float__(port)
                    except Exception:
                        continue
                if port != port or port in (float("inf"), float("-inf")):
                    continue
            text = _plain_str(port)
            if text:
                out.append(text)
    return out


def _guess_category(tid: str, meta: dict) -> str:
    if meta.get("category"):
        return _plain_str(meta["category"], "other") or "other"
    low = (tid or "").lower()
    for key, cat in CATEGORY_HINTS.items():
        if key in low:
            return cat
    return "other"


def _rand_password(n: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def host_timezone() -> str:
    """The host's IANA timezone, e.g. ``Europe/Berlin``.

    Containers do not inherit the host clock's zone; without an explicit TZ they
    run on UTC and every timestamp a user sees in Jellyfin, Paperless or
    qBittorrent is offset from the machine those apps run on.  Templates used to
    hardcode the author's own zone, which is wrong for everyone else, so they
    ask for this instead and each install picks up whatever the host is set to.
    """
    try:
        target = os.readlink("/etc/localtime")
    except OSError:
        return "UTC"
    # /etc/localtime points into the zoneinfo tree; the zone is the tail after
    # the database directory, which is a two-part name for most regions
    # (Asia/Shanghai) but a single part for a few (UTC, GMT, Zulu).
    _, sep, zone = target.partition("zoneinfo/")
    zone = zone.strip("/") if sep else ""
    return zone or "UTC"


# macOS keeps the user's ordered language preference here.  Reading the plist
# directly avoids a `defaults read` subprocess on a path that runs for every
# variable of every template on every catalog listing.
def _default_global_prefs() -> Path:
    """``Path.home()`` leftover used to 500 import of catalog."""
    home = user_home()
    if home is None:
        return Path("/var/empty/serverhub-global-prefs")
    return home / "Library/Preferences/.GlobalPreferences.plist"


_GLOBAL_PREFS = _default_global_prefs()

#: BCP-47 primary subtag -> (tesseract OCR code, Stirling PDF locale).  Only
#: languages both projects actually ship models/translations for; anything else
#: falls through to English rather than requesting a pack that does not exist.
_LANG_CODES = {
    "en": ("eng", "en_GB"),
    "zh-hans": ("chi_sim", "zh_CN"),
    "zh-hant": ("chi_tra", "zh_TW"),
    "ja": ("jpn", "ja_JP"),
    "ko": ("kor", "ko_KR"),
    "de": ("deu", "de_DE"),
    "fr": ("fra", "fr_FR"),
    "es": ("spa", "es_ES"),
    "it": ("ita", "it_IT"),
    "pt": ("por", "pt_BR"),
    "ru": ("rus", "ru_RU"),
}

_lang_cache: tuple[int, tuple[str, ...]] | None = None


def _normalise_lang(tag: str) -> str:
    """Map an AppleLanguages tag onto a key of _LANG_CODES.

    Tags carry a region and sometimes a script: ``en-CN``, ``zh-Hans-CN``,
    ``pt-BR``.  Chinese is the one language where the script matters, because
    Simplified and Traditional need different OCR models.
    """
    parts = (tag or "").lower().replace("_", "-").split("-")
    if not parts or not parts[0]:
        return ""
    base = parts[0]
    if base == "zh":
        if "hant" in parts or any(p in ("tw", "hk", "mo") for p in parts):
            return "zh-hant"
        return "zh-hans"
    return base


def host_languages() -> tuple[str, ...]:
    """The user's preferred languages, most preferred first."""
    global _lang_cache
    try:
        mtime = _GLOBAL_PREFS.stat().st_mtime_ns
    except OSError:
        return ("en",)
    cached = _lang_cache
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        # read_bytes_capped, not a bare open(): stat() answers fine for a
        # leftover FIFO occupying .GlobalPreferences.plist, and the plain open
        # that followed parked until a writer appeared — hanging GET
        # /api/catalog (the store overview reads the host languages) forever.
        # The capped reader opens O_NONBLOCK, refuses non-regular files, and
        # keeps the oversize refusal as OSError(EFBIG).
        blob = read_bytes_capped(_GLOBAL_PREFS, _PREFS_CAP)
        prefs = plistlib.loads(blob)
        raw = prefs.get("AppleLanguages") if isinstance(prefs, dict) else []
    except Exception:
        raw = []
    if not isinstance(raw, list):
        # A scalar leftover used to raise on `for tag in 3` and 500 the store.
        raw = []
    seen: list[str] = []
    for tag in raw:
        # leftover RecursionError on ``str(tag)`` used to 500 GET /api/catalog.
        key = _normalise_lang(_plain_str(tag))
        if key in _LANG_CODES and key not in seen:
            seen.append(key)
    value = tuple(seen) or ("en",)
    _lang_cache = (mtime, value)
    return value


def _host_lang_list(index: int, separator: str) -> str:
    """Render the host's languages using column *index* of _LANG_CODES."""
    codes = [_LANG_CODES[key][index] for key in host_languages()]
    english = _LANG_CODES["en"][index]
    # Always keep English available: it is the fallback UI language, and OCR
    # accuracy on the latin text that appears in almost every document drops
    # sharply without the English model.
    if english not in codes:
        codes.append(english)
    return separator.join(codes)


def host_ocr_languages() -> str:
    """Tesseract language list for the host, e.g. ``eng+chi_sim``."""
    return _host_lang_list(0, "+")


def host_ui_languages() -> str:
    """Stirling PDF locale list for the host, e.g. ``en_GB,zh_CN``."""
    return _host_lang_list(1, ",")


def auto_var_values() -> dict[str, str]:
    """Values for the placeholders the server fills in on its own."""
    home = user_home()
    return {
        "HOST_IP": host_ip(),
        "HOME": str(home) if home is not None else "",
        "SERVICES": str(SERVICES_ROOT),
        "TZ": host_timezone(),
        "OCR_LANG": host_ocr_languages(),
        "UI_LANGS": host_ui_languages(),
    }


def _expand_auto(text: str) -> str:
    """Substitute AUTO_VARS in *text* and leave every other placeholder alone.

    Var *defaults* may reference auto-vars (e.g. ``{{SERVICES}}/media``) so no
    template has to hardcode an absolute home path.  render_template() only
    walks the compose body, so without this the raw ``{{SERVICES}}/media``
    string would be shown in the install form and written into the deployed
    compose file verbatim.
    """
    if "{{" not in text:
        return text
    for name, val in auto_var_values().items():
        text = re.sub(r"\{\{\s*" + name + r"\s*\}\}", val.replace("\\", "\\\\"), text)
    return text


def _parse_template(path: Path) -> tuple[dict, str]:
    text = read_text_capped(path, _TEMPLATE_CAP, errors="replace")
    meta: dict[str, Any] = {
        "id": path.stem,
        "name": path.stem.replace("-", " ").title(),
        "vars": [],
    }
    body = text
    m = FM_RE.match(text)
    if m:
        try:
            loaded = yaml.safe_load(m.group(1)) or {}
        except (
            yaml.YAMLError, RecursionError, TypeError, ValueError, AttributeError, KeyError,
        ):
            # RecursionError: leftover deeply-nested front matter is not YAMLError.
            # TypeError/ValueError/AttributeError/KeyError: leftover ``!!timestamp .inf``,
            # ``2026-13-01``, a 5000-digit int, or ``!!bool 2`` are not YAMLError.
            loaded = {}
        if isinstance(loaded, dict):
            meta.update(loaded)
        body = m.group(2)
    found = sorted(set(VAR_RE.findall(body)))
    declared = meta.get("vars")
    if not isinstance(declared, list):
        declared = []
    by_name: dict[str, dict] = {}
    for v in declared:
        if isinstance(v, str) and v:
            name = _plain_str(v)
            if not name:
                continue
            by_name[name] = {"name": name, "default": "", "label": name, "required": True}
        elif isinstance(v, dict):
            name = _plain_str(v.get("name"))
            if not name:
                continue
            # Keep __RANDOM__ literal until install time (never mint secrets on list).
            # Always _plain_str: leftover YAML ``"\\ud800"`` is a str and used to
            # skip the inf-only branch, then 500 GET /api/catalog.
            default = _plain_str(v.get("default", ""))
            label = _plain_str(v.get("label")) or name
            help_text = _plain_str(v.get("help"))
            by_name[name] = {
                "name": name,
                "default": _plain_str(_expand_auto(default)),
                "label": label,
                "required": bool(v.get("required", True)),
                "help": help_text,
                "secret": bool(v.get("secret", False) or default == "__RANDOM__"),
            }
    for name in found:
        # Server-injected placeholders are not user input; surfacing them would
        # render an empty required field the user cannot meaningfully fill.
        if name in AUTO_VARS:
            continue
        by_name.setdefault(
            name, {"name": name, "default": "", "label": name, "required": True}
        )
    meta["vars"] = list(by_name.values())
    if not meta.get("desc"):
        for line in body.splitlines():
            if line.startswith("#"):
                meta["desc"] = line.lstrip("# ").strip()
                break
        meta.setdefault("desc", f"Compose template {path.name}")
    meta["images"] = re.findall(r"image:\s*(\S+)", body)
    meta["category"] = _guess_category(path.stem, meta)
    meta["tags"] = _plain_str_list(meta.get("tags"))
    meta["ports"] = _plain_ports(meta.get("ports"))
    meta.setdefault("featured", False)
    meta.setdefault("notes", "")
    meta["url_template"] = _plain_str(meta.get("url_template"))
    meta["name"] = _plain_str(
        meta.get("name"), path.stem.replace("-", " ").title()
    ) or path.stem.replace("-", " ").title()
    meta["desc"] = _plain_str(meta.get("desc"))
    meta["notes"] = _plain_str(meta.get("notes"))
    # Fixed first-run login the upstream image ships when it cannot be preset
    # through env vars (e.g. "admin / admin123").  Shown prominently on the
    # install success panel with a change-it-now reminder.
    meta["first_run_credentials"] = _plain_str(meta.get("first_run_credentials")).strip()
    return meta, body



_list_cache: dict = {"t": 0.0, "sig": "", "items": None}
_LIST_TTL = 20.0
#: Guards the dict, and nothing else.  Separate from the refresh lock below so
#: that an install finishing mid-parse can drop the listing immediately instead
#: of queueing behind the parse it is invalidating.
_list_lock = threading.Lock()
#: Held across the parse, so concurrent callers that miss a cold cache wait for
#: one answer instead of each parsing all fifty templates.  Measured on this
#: tree: one build is 45ms, and six readers arriving together took 303ms and
#: did the work six times over.  The store page and the dashboard both land here.
_list_refresh_lock = threading.Lock()
#: Bumped by `invalidate_listing`.  The signature already catches a template
#: file or an install directory changing, but not a build that started before
#: the change and finishes after it -- that one carries the *old* signature and
#: would restore it along with the payload, making the stale listing look
#: current for another TTL.
_list_generation = 0


def _sig_int(value) -> int:
    """A stat number the signature f-string can render, or 0.

    ``int(...)`` with a try only guards *conversions*: a leftover FUSE/SMB
    ``st_size`` that is already a >4300-digit int passed through untouched,
    and CPython's int->str digit limit then ValueError'd the ``f"{...}"``
    below — outside the ``except OSError`` — 500ing GET /api/catalog and
    /api/catalog/templates before a single template was parsed.  ``float()``
    rejects anything beyond float range, the same junk test
    files_svc._finite_int and logs_svc._stat_size apply to their stat
    numbers.
    """
    try:
        value = int(value)
        float(value)
    except (TypeError, ValueError, OverflowError, OSError):
        return 0
    return value


def _templates_sig() -> str:
    """Cheap change detector for template dir + remote overrides + install dirs."""
    if not _is_dir(TEMPLATES):
        return "empty"
    parts = []
    try:
        for p in sorted(TEMPLATES.iterdir()):
            if p.suffix in (".yml", ".yaml"):
                st = p.stat()
                parts.append(f"{p.name}:{_sig_int(st.st_mtime)}:{_sig_int(st.st_size)}")
    except OSError:
        return "err"
    # Remote overrides change the merged listing without touching templates/,
    # so they must be part of the signature or a sync would not show up for
    # up to _LIST_TTL seconds.
    try:
        for p in catalog_remote.remote_template_files():
            st = p.stat()
            parts.append(f"r:{p.name}:{_sig_int(st.st_mtime)}:{_sig_int(st.st_size)}")
    except OSError:
        pass
    # installed flags change when ~/Services/<id>/docker-compose.yml appears
    try:
        for p in SERVICES_ROOT.iterdir():
            if _exists(p / "docker-compose.yml"):
                parts.append(f"i:{p.name}")
    except OSError:
        pass
    return "|".join(parts)


def _cache_store(now: float, sig: str, items: list, generation: int) -> list:
    """Cache *items* and hand the caller its own copy.

    ``catalog_overview()`` appends to ``notes`` on the entries it returns.  When
    the cache handed out its own objects that append landed on the cached dict
    and grew by one sentence per request, so the store page showed the same
    advisory repeated dozens of times.  Every exit from this function returns a
    deep copy: callers may mutate freely, the cache stays pristine.

    An install or uninstall that landed since *generation* was read means this
    listing describes the state before it, so it is handed back but not stored.
    """
    with _list_lock:
        if generation == _list_generation:
            _list_cache.update(t=now, sig=sig, items=items)
    return copy.deepcopy(items)


def invalidate_listing() -> None:
    """Drop the template listing after an install, uninstall or remote sync.

    Public, and the only supported way to do it.  Four call sites used to
    assign ``_list_cache["t"] = 0`` directly and one of them reached in from
    ``catalog_remote`` -- so renaming this cache would have turned invalidation
    into a silent no-op and left an uninstalled app showing as installed.  It
    also gives the generation counter one place to be bumped.
    """
    global _list_generation
    with _list_lock:
        _list_generation += 1
        _list_cache.update(t=0.0, items=None)


def _fresh_listing(now: float, sig: str):
    """The cached listing when it is still current, else None."""
    with _list_lock:
        if (
            _list_cache["items"] is not None
            and _list_cache["sig"] == sig
            and now - _list_cache["t"] < _LIST_TTL
        ):
            return copy.deepcopy(_list_cache["items"])
    return None


def list_templates(force: bool = False) -> list:
    import time as _time

    if not force:
        hit = _fresh_listing(_time.time(), _templates_sig())
        if hit is not None:
            return hit

    with _list_refresh_lock:
        # Re-read under the lock: the caller that held it has just published,
        # and re-parsing would defeat the point of having waited.  The
        # signature is re-taken with it, so the build records the state it
        # actually observed rather than one from before the wait.  `force`
        # keeps meaning "parse now" exactly as it did before the lock existed.
        now = _time.time()
        sig = _templates_sig()
        if not force:
            hit = _fresh_listing(now, sig)
            if hit is not None:
                return hit
        return _build_listing(now, sig)


def _build_listing(now: float, sig: str) -> list:
    with _list_lock:
        generation = _list_generation
    items = []
    if not _is_dir(TEMPLATES):
        return _cache_store(now, sig, items, generation)
    try:
        discovered = set(TEMPLATES.glob("*.yml")) | set(TEMPLATES.glob("*.yaml"))
    except OSError:
        discovered = set()
    builtin_ids = {p.stem for p in discovered}
    # Remote overrides shadow the built-in template with the same id; the
    # built-in file stays on disk untouched so "restore built-in" is a delete.
    by_id: dict[str, Path] = {p.stem: p for p in sorted(discovered)}
    try:
        remote_files = catalog_remote.remote_template_files()
    except OSError:
        remote_files = []
    for p in remote_files:
        by_id[p.stem] = p
    remote_versions = catalog_remote.remote_versions()
    remote_warnings = catalog_remote.remote_warnings()
    files = [by_id[k] for k in sorted(by_id)]
    for p in files:
        try:
            # glob-then-read raced: a vanished override used to 500 the store.
            meta, _ = _parse_template(p)
        except OSError:
            continue
        tid = meta.get("id") or p.stem
        if isinstance(tid, int) and not isinstance(tid, bool):
            # A numeric YAML id (`id: 8080`) must behave like its quoted twin:
            # coerce via a str() probe, not the strict isinstance gate that
            # silently renamed the entry to the filename.  Over-cap ints
            # (hex/octal YAML dodges the digit cap at parse time) make str()
            # the digit-cap ValueError — those keep the stem fallback.
            try:
                tid = str(tid)
            except ValueError:
                tid = p.stem
        if not isinstance(tid, str) or not tid or "\x00" in tid:
            tid = p.stem
        meta["id"] = tid
        is_remote = p.parent != TEMPLATES
        dest = None
        installed = False
        try:
            dest = SERVICES_ROOT / tid
            installed = _exists(dest / "docker-compose.yml")
        except (TypeError, ValueError, OSError):
            try:
                dest = SERVICES_ROOT / p.stem
            except (TypeError, ValueError, OSError):
                dest = None
            installed = False
        # UI defaults: show empty for __RANDOM__ so install mints once
        vars_out = []
        values_for_url: dict[str, str] = {}
        for v in meta.get("vars") or []:
            vv = dict(v)
            if vv.get("default") == "__RANDOM__":
                vv["default"] = ""
                vv["placeholder"] = "auto"
                vv["secret"] = True
            name = _plain_str(vv.get("name"))
            default = _plain_str(vv.get("default"))
            vv["name"] = name
            vv["default"] = default
            vv["label"] = _plain_str(vv.get("label")) or name
            vv["help"] = _plain_str(vv.get("help"))
            if vv.get("placeholder") is not None:
                vv["placeholder"] = _plain_str(vv.get("placeholder"))
            if not name:
                continue
            vars_out.append(vv)
            if default not in ("", "__RANDOM__"):
                values_for_url[name] = default
        # Resolve open URL for store / installed cards (frontend uses url_hint)
        url_hint = ""
        if meta.get("url_template"):
            try:
                url_hint = _suggest_url(meta, values_for_url) or ""
            except Exception:
                url_hint = ""
        if not url_hint and meta.get("ports"):
            # first numeric web-ish port as fallback
            hip = host_ip()
            for port_spec in meta.get("ports") or []:
                ps = str(port_spec).split("/")[0]
                if ps.isdigit() and ps not in ("1883", "5432", "6379", "3306", "5672", "5900", "9100", "22000"):
                    url_hint = f"http://{hip}:{ps}"
                    break
        path_out = None
        if dest is not None:
            # Through _plain_str: a leftover front-matter id carrying a lone
            # surrogate (or a Services tree named with surrogateescape bytes)
            # kept the raw str here while every other field was cleaned, and
            # Starlette's UTF-8 encode then 500'd GET /api/catalog and
            # /api/catalog/templates.
            path_out = _plain_str(str(dest)) if _exists(dest) else None
            path_out = path_out or None
        items.append({
            "id": _plain_str(tid, p.stem) or _plain_str(p.stem),
            "name": _plain_str(meta.get("name"), tid) or tid,
            "file": _plain_str(p.name),
            "desc": _plain_str(meta.get("desc")),
            "images": meta.get("images") or [],
            "vars": vars_out,
            "category": _plain_str(meta.get("category"), "other") or "other",
            "tags": meta.get("tags") or [],
            "ports": meta.get("ports") or [],
            "featured": bool(meta.get("featured")),
            "notes": _plain_str(meta.get("notes")),
            "first_run_credentials": _plain_str(meta.get("first_run_credentials")),
            "url_template": _plain_str(meta.get("url_template")),
            "url_hint": _plain_str(url_hint),
            "installed": installed,
            "path": path_out,
            "kind": "docker",
            "prefer_native": False,
            "source": "remote" if is_remote else "builtin",
            "remote_version": remote_versions.get(p.stem, "") if is_remote else "",
            "builtin_available": (p.stem in builtin_ids) if is_remote else True,
            # Elevated-access compose directives found at sync time; the
            # install dialog lists them in red for remote templates.
            "compose_warnings": remote_warnings.get(p.stem, []) if is_remote else [],
        })
    items.sort(key=lambda x: (0 if x.get("featured") else 1, str(x.get("name") or "")))
    return _cache_store(now, sig, items, generation)


def catalog_overview() -> dict:
    # Two independent halves of the store: the Docker templates, and the native
    # catalog's brew/launchd probes.  Neither reads the other -- the cross-reference
    # below works on both finished lists -- but the templates ran first, and they
    # resolve the host address on the way, so the brew listings queued behind a route
    # lookup and an `ipconfig`.
    #
    # Both halves reach `host_ip()`, which is single-flight: the second arrival waits
    # for the first rather than paying for its own two spawns.
    def docker_templates() -> list:
        try:
            return list_templates()
        except Exception:
            return []

    def native_apps() -> list:
        try:
            from hub import native_catalog
            # Always re-check brew/bin for store badges (install just finished)
            return native_catalog.list_native_apps(force=True)
        except Exception:
            return []

    docker, native = fan_out(
        lambda collect: collect(), [docker_templates, native_apps], max_workers=2
    )
    docker = [d for d in docker if _isinst(d, dict)]
    # Laundered through _jsonable: the native listing is another module's
    # payload and it is merged into this response verbatim.  A dict-subclass
    # row whose ``.get`` bombs (or a value ``__bool__``/``__eq__``/``__str__``
    # bomb reached by the installed filter and the sort key below), a
    # >4300-digit int, raw bytes, or a lone-surrogate name all used to 500
    # GET /api/catalog — either right here or later in Starlette's encoder.
    # _isinst, not a bare isinstance: the row filter runs *before* _jsonable
    # can launder anything, so a leftover row whose ``__class__`` is a raising
    # property detonated this gate itself (the jobs/auth rule) — one poisoned
    # row 500'd the whole store overview instead of costing only itself.
    native = [
        row for row in (_jsonable(a) for a in native if _isinst(a, dict))
        if _isinst(row, dict)
    ]
    # Prefer native: if Cloudflared brew is installed, steer away from Docker twin
    native_ids_installed = {
        a["id"] for a in native if a.get("installed") and isinstance(a.get("id"), str)
    }
    for d in docker:
        if d.get("id") == "cloudflared" and "native-cloudflared" in native_ids_installed:
            existing = d.get("notes")
            existing = existing if isinstance(existing, str) else str(existing or "")
            d["notes"] = (
                existing
                + (" · " if existing else "")
                + "The native cloudflared CLI is already installed on this machine, "
                "so the Docker version is usually unnecessary; use it only when you "
                "have a Zero Trust token and want it containerized."
            ).strip(" ·")
    # Prefer native: sort native featured first, then docker
    templates = native + docker
    templates.sort(
        key=lambda x: (
            0 if x.get("kind") == "native" else 1,
            0 if x.get("featured") else 1,
            str(x.get("name") or ""),
        )
    )
    by_cat: dict[str, int] = {}
    for t in templates:
        # A list leftover in category/kind used to raise on `by_cat[c]`
        # and 500 the store after the row filter already accepted the dict.
        c = t.get("category")
        c = c if isinstance(c, str) and c else "other"
        by_cat[c] = by_cat.get(c, 0) + 1
        k = t.get("kind")
        k = k if isinstance(k, str) and k else "docker"
        by_cat[k] = by_cat.get(k, 0) + 1
    return {
        "templates": templates,
        "categories": CATEGORIES,
        "counts": by_cat,
        "total": len(templates),
        "native_count": len(native),
        "docker_count": len(docker),
        "installed": sum(1 for t in templates if t.get("installed")),
        "hint": "Native first (brew / system) · Docker as a complement",
    }


def render_template(body: str, values: dict[str, str]) -> str:
    def repl(m):
        key = m.group(1)
        if key not in values:
            raise api_error("catalog.missing_var", name=key)
        value = str(values[key])
        # Templates place variables as bare YAML scalars (e.g. `- FOO={{FOO}}`).
        # A value carrying a newline plus matching indentation would close its
        # scalar and inject sibling compose keys (privileged: true, extra
        # volumes, devices...) into the rendered docker-compose.yml.  No install
        # variable — password, path, port, username — legitimately contains a
        # line break, so refusing them closes the escape without constraining
        # any real value.  ``!!python`` is the same class on one line: the
        # newline guard does not see it, and a FullLoader consumer of the
        # rendered compose would execute it.
        if "\n" in value or "\r" in value or "!!python" in value.lower():
            raise api_error("catalog.bad_var_value", name=key)
        return value

    return VAR_RE.sub(repl, body)


class _StacksUnchanged(Exception):
    """Raised inside a mutate() body to abort without rewriting the file."""


def _register_stack(template_id: str, name: str, dest_dir: Path) -> None:
    """Append to services.yaml stacks if missing.

    Through config.mutate, not save_full(deepcopy(cfg())): the snapshot form
    read the mtime-cached config outside the write lock and wrote the whole
    file back from it, so a concurrent install (two app-store tabs) or a
    settings save landing in between was silently overwritten — the exact
    lost-update save_full's own docstring warns about.
    """
    try:
        from hub.config import mutate

        def apply(data: dict) -> None:
            stacks = data.get("stacks")
            if not isinstance(stacks, list):
                stacks = []
                data["stacks"] = stacks
            for s in stacks:
                if isinstance(s, dict) and (
                    s.get("id") == template_id or s.get("path") == str(dest_dir)
                ):
                    raise _StacksUnchanged
            stacks.append({
                "id": template_id,
                "name": name,
                "path": str(dest_dir),
                "compose_file": "docker-compose.yml",
            })

        mutate(apply)
    except Exception:
        pass


def _suggest_url(meta: dict, values: dict) -> str | None:
    tpl = meta.get("url_template")
    if not isinstance(tpl, str) or not tpl:
        return None
    host = _plain_str(values.get("HOST_IP")).strip() or host_ip()
    port = _plain_str(values.get("HOST_PORT") or values.get("WEB_PORT"))
    out = tpl.replace("{{HOST_IP}}", host).replace("{{HOST_PORT}}", port)
    out = out.replace("{{WEB_PORT}}", _plain_str(values.get("WEB_PORT") or port))
    for k, v in values.items():
        # leftover RecursionError on ``str(var)`` used to 500 POST install.
        out = out.replace("{{" + _plain_str(k) + "}}", _plain_str(v))
    cleaned = _plain_str(out)
    return cleaned or None


#: host side of a compose "ports:" entry, e.g. "8080:80", "127.0.0.1:8080:80",
#: "8080:80/udp".  Group 1 is the host port.
_PORT_MAP_RE = re.compile(
    r"^\s*-?\s*[\"']?(?:\[?[0-9a-fA-F:.]+\]?:)??(\d{1,5}):\d{1,5}(?:/\w+)?[\"']?\s*$"
)


def _host_ports(body: str) -> list[int]:
    """Host ports bound by a rendered compose body, in order of appearance."""
    out: list[int] = []
    in_ports = False
    ports_indent = 0
    for raw in body.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        if re.match(r"^ports:\s*(\[.*\])?\s*$", stripped):
            in_ports = True
            ports_indent = indent
            # inline flow form: ports: ["8080:80", "443:443"]
            inline = stripped[len("ports:"):].strip()
            if inline.startswith("["):
                for chunk in inline.strip("[]").split(","):
                    m = _PORT_MAP_RE.match(chunk.strip())
                    if m:
                        out.append(int(m.group(1)))
                in_ports = False
            continue
        if in_ports:
            # a new key at or above the "ports:" indent ends the block
            if not stripped.startswith("-") and indent <= ports_indent:
                in_ports = False
            else:
                m = _PORT_MAP_RE.match(stripped)
                if m:
                    out.append(int(m.group(1)))
                continue
    # de-dup while keeping order (tcp+udp pairs bind the same host port once)
    seen: set[int] = set()
    return [p for p in out if not (p in seen or seen.add(p))]


def _port_is_bound(port: int) -> bool:
    """True only when the port is genuinely occupied on this host.

    Deliberately narrow: we bind without SO_REUSEADDR (with it, a listening
    socket on 127.0.0.1 can still be re-bound and would look free) and count
    *only* EADDRINUSE.  Privileged ports such as 53/80/443 raise EACCES for our
    unprivileged process even when free — Docker binds those as root, so
    treating EACCES as "busy" would wrongly block AdGuard Home and
    Nginx Proxy Manager on every install.
    """
    for family, addr in ((socket.AF_INET, ("0.0.0.0", port)),
                         (socket.AF_INET, ("127.0.0.1", port))):
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
        except OSError:
            continue
        try:
            s.bind(addr)
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                return True
        except Exception:
            pass
        finally:
            s.close()
    return False


def _ports_claimed_by_stacks(exclude_id: str = "") -> dict[int, str]:
    """Host ports already claimed by installed stacks -> owning stack id."""
    claimed: dict[int, str] = {}
    try:
        entries = sorted(SERVICES_ROOT.iterdir())
    except OSError:
        return claimed
    for d in entries:
        if not _is_dir(d) or d.name == exclude_id:
            continue
        compose = d / "docker-compose.yml"
        if not _exists(compose):
            continue
        try:
            text = read_text_capped(compose, _COMPOSE_SCAN_CAP, errors="replace")
        except OSError:
            continue
        for p in _host_ports(text):
            claimed.setdefault(p, d.name)
    return claimed


def _check_ports_free(rendered: str, template_id: str) -> None:
    """Fail fast before writing anything if a requested host port is taken."""
    wanted = _host_ports(rendered)
    if not wanted:
        return
    claimed = _ports_claimed_by_stacks(exclude_id=template_id)
    for port in wanted:
        owner = claimed.get(port)
        if owner:
            raise api_error("catalog.port_claimed", port=port, stack=owner)
        if _port_is_bound(port):
            raise api_error("catalog.port_in_use", port=port)


#: A template variable is treated as a host port when its name says so.  Every
#: shipped template spells these `HOST_PORT`, `WEB_PORT`, `MQTT_PORT`, `ADMIN_PORT`
#: and so on, and each one appears in the compose file as `"{{VAR}}:<container>"`.
def _is_port_var(name: str) -> bool:
    return "PORT" in str(name or "").upper()


def _port_taken(port: int, claimed: dict[int, str]) -> bool:
    return port in claimed or _port_is_bound(port)


def _next_free_port(preferred: int, claimed: dict[int, str], reserved: set[int]) -> int:
    """First free host port at or after *preferred*.

    Why this exists: every shipped template hardcodes a conventional default
    (AdGuard 3000, Uptime Kuma 3001, Postgres 5432, Redis 6379 …) and a busy host
    already uses many of them.  Refusing the install was technically correct and
    practically useless -- a third of the catalogue was uninstallable here purely
    because the suggested port was occupied, with no way forward from the UI.
    Every one of those ports is variable-driven, so moving it is safe.

    *reserved* holds ports already handed out earlier in this same install, so a
    template asking for three ports cannot be given the same one twice.
    """
    start = preferred if 1 <= preferred <= 65535 else 8000
    for candidate in range(start, 65536):
        if candidate in reserved or _port_taken(candidate, claimed):
            continue
        return candidate
    raise api_error("catalog.no_free_port", port=start)


#: Ports where the number *is* the protocol contract, so moving one produces a
#: service that starts, looks healthy and is unreachable: a DNS server on 54 or an
#: HTTPS endpoint on 4443 answers nobody that was not told to look there.  Only
#: ports above the IANA system range are relocated automatically; a conflict below
#: it is still refused so the operator resolves it deliberately.
_PROTOCOL_PORT_CEILING = 1024


def _may_relocate(port: int) -> bool:
    return port > _PROTOCOL_PORT_CEILING


class _InstallFailed(Exception):
    """`docker compose up` failed — triggers rollback of everything we made."""


def _rollback_install(
    template_id: str, dest_dir: Path, created_dir: bool
) -> str:
    """Undo a failed install so the next attempt is not blocked by 409.

    Always unregisters the stack.  Only removes ``dest_dir`` when *this*
    install created it: a pre-existing directory may hold user data (volumes,
    databases) and must never be deleted on our behalf.
    """
    notes: list[str] = []
    try:
        _unregister_stack(template_id, dest_dir)
    except Exception as e:  # never let cleanup mask the original failure
        notes.append(
            "stack registration left behind: " + (_plain_str(e) or "error")
        )
    if created_dir:
        try:
            shutil.rmtree(dest_dir)
        except OSError as e:
            notes.append(
                f"could not remove {dest_dir}: " + (_plain_str(e) or "error")
            )
    else:
        notes.append(
            f"kept pre-existing {dest_dir} (may contain your data); "
            "remove it yourself if you want a clean retry"
        )
    return "; ".join(notes)


def template_file(template_id: str) -> Path | None:
    """The file backing *template_id*: remote override first, then built-in."""
    if not cli_args.is_safe_positional(template_id):
        return None
    remote = catalog_remote.remote_template_path(template_id)
    if remote is not None:
        return remote
    for suffix in (".yml", ".yaml"):
        p = TEMPLATES / f"{template_id}{suffix}"
        if _exists(p):
            return p
    return None


def install_template(template_id: str, variables: dict | None = None) -> dict:
    # Native apps (brew / system / script)
    if str(template_id).startswith("native-"):
        from hub import native_catalog
        return native_catalog.install_native(template_id, variables)

    template_id = cli_args.require_positional(template_id, label="template id")

    src = template_file(template_id)
    if src is None:
        raise api_error("catalog.unknown_template", id=str(template_id))
    try:
        meta, body = _parse_template(src)
    except OSError:
        raise api_error("catalog.unknown_template", id=str(template_id))
    values: dict[str, str] = {}
    # Ports the operator typed themselves are honoured exactly; ports that came
    # from a template default (or that we had to invent) may be moved when taken.
    port_claims = _ports_claimed_by_stacks(exclude_id=template_id)
    handed_out: set[int] = set()
    remapped: list[str] = []

    def resolve_port(name: str, preferred: str | int, explicit: bool) -> str:
        try:
            wanted = int(str(preferred).strip())
        except (TypeError, ValueError, OverflowError):
            wanted = 0
        if explicit:
            # An explicit choice is a requirement, not a hint: silently moving it
            # would leave the operator with an app on a port they did not pick.
            if wanted and _port_taken(wanted, port_claims):
                owner = port_claims.get(wanted)
                if owner:
                    raise api_error("catalog.port_claimed", port=wanted, stack=owner)
                raise api_error("catalog.port_in_use", port=wanted)
            handed_out.add(wanted)
            return str(wanted)
        if wanted and _port_taken(wanted, port_claims) and not _may_relocate(wanted):
            # A system port is part of the protocol, not a preference.
            owner = port_claims.get(wanted)
            if owner:
                raise api_error("catalog.port_claimed", port=wanted, stack=owner)
            raise api_error("catalog.port_in_use", port=wanted)
        chosen = _next_free_port(wanted or 8000, port_claims, handed_out)
        handed_out.add(chosen)
        if wanted and chosen != wanted:
            remapped.append(f"{name} {wanted} -> {chosen}")
        return str(chosen)

    for v in meta.get("vars") or []:
        name = v["name"]
        raw_default = v.get("default")
        supplied = bool(variables and name in variables and variables[name] not in (None, ""))
        if supplied and _is_port_var(name):
            values[name] = resolve_port(name, variables[name], explicit=True)
        elif supplied:
            # A user may legitimately paste "{{SERVICES}}/foo" from the prefilled
            # default, so expand their input too rather than writing it literally.
            values[name] = _expand_auto(str(variables[name]))
        elif _is_port_var(name) and (raw_default not in (None, "") or v.get("required", True)):
            # Covers both "default is taken" and "template declares no default at
            # all", which previously failed as a missing required variable even
            # though the panel is perfectly able to pick a port.
            values[name] = resolve_port(name, raw_default or 0, explicit=False)
        elif raw_default == "__RANDOM__":
            values[name] = _rand_password(16)
        elif raw_default not in (None, ""):
            # _parse_template already expanded declared defaults; expand again so
            # this stays correct if a caller passes an unparsed meta dict.
            values[name] = _expand_auto(str(raw_default))
        elif v.get("required", True):
            # secret random fields: auto-fill when user left blank
            # Never auto-mint tunnel/API tokens — user must paste real ones
            if name.upper() in ("TUNNEL_TOKEN", "CF_API_TOKEN", "API_TOKEN"):
                raise api_error("catalog.missing_token", name=name)
            if v.get("secret") or name.upper() in (
                "PASSWORD", "ADMIN_TOKEN", "VNC_PASSWORD", "POSTGRES_PASSWORD",
                "MYSQL_ROOT_PASSWORD", "MYSQL_PASSWORD", "MINIO_ROOT_PASSWORD",
                "DB_PASSWORD", "PAPERLESS_ADMIN_PASSWORD",
            ):
                values[name] = _rand_password(16)
            else:
                raise api_error("catalog.missing_var", name=name)
        else:
            values[name] = ""
    # invalidate list cache after install so installed flag refreshes
    invalidate_listing()
    # Auto-injected placeholders so shipped templates never need to hardcode a
    # developer-specific absolute paths that would make templates non-portable.
    if "HOST_IP" not in values:
        values["HOST_IP"] = host_ip()
    home = user_home()
    values.setdefault("HOME", str(home) if home is not None else "")
    values.setdefault("SERVICES", str(SERVICES_ROOT))
    values.setdefault("TZ", host_timezone())
    values.setdefault("OCR_LANG", host_ocr_languages())
    values.setdefault("UI_LANGS", host_ui_languages())
    # Leftover ``\ud800`` in a pasted var used to UnicodeEncodeError compose
    # writes, ``.serverhub-vars.json``, the README, and the install JSON body.
    values = {_plain_str(k): _plain_str(v) for k, v in values.items()}

    rendered = render_template(body, values) if VAR_RE.search(body) else body

    dest_dir = SERVICES_ROOT / template_id
    dest = dest_dir / "docker-compose.yml"
    if _exists(dest):
        raise api_error("catalog.already_installed", path=str(dest))

    # Refuse before touching the filesystem when a host port is unavailable,
    # otherwise "up" fails and the user is left with a dead app.
    _check_ports_free(rendered, template_id)

    # Only a directory *we* created may be removed during rollback: the user may
    # have pre-seeded ~/Services/<id>/ with data before installing.
    created_dir = not _exists(dest_dir)
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        # Compose commonly contains generated database/admin secrets.
        # write_text()+chmod() leaves a umask window; O_EXCL so a lost
        # exists() race cannot O_TRUNC an operator-edited compose.
        if not secure_io.create_secret_text(dest, rendered):
            raise api_error("catalog.already_installed", path=str(dest))
        (dest_dir / "data").mkdir(exist_ok=True)
        # extra dirs often used
        for d in ("config", "media", "downloads", "uploads", "library", "pgdata", "model-cache"):
            if f"./{d}" in rendered or f"/{d}" in rendered:
                (dest_dir / d).mkdir(exist_ok=True)
        # optional bootstrap files from frontmatter
        for bf in meta.get("bootstrap_files") if isinstance(meta.get("bootstrap_files"), list) else []:
            if not isinstance(bf, dict) or not bf.get("path"):
                continue
            # _plain_str, not bare str(): bootstrap_files is the one block of
            # front matter _parse_template leaves raw.  A leftover hex-huge
            # YAML int in ``path`` (or ``content``) is a >4300-digit int whose
            # ``str()`` is the digit-cap ValueError, and a lone ``"\ud800"``
            # UnicodeEncodeError'd the write — either escaped this loop's
            # OSError guard and failed the *whole* install through the broad
            # rollback, discarding the operator's filled-in variables and
            # minted passwords over one junk entry.  Unrenderable entries are
            # dropped; the rest of the install proceeds.
            rel = _plain_str(bf["path"]).lstrip("/")
            if not rel or ".." in rel:
                continue
            fp = dest_dir / rel
            try:
                fp.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                # A leftover file occupying the parent path blocks this one
                # bootstrap file, not the install.
                continue
            content = _plain_str(bf.get("content") or "")
            for k, v in values.items():
                content = content.replace("{{" + k + "}}", str(v))
            # "x" so an existing file is never rewritten: these are deployment
            # files the operator may have edited by hand, and a check-then-write
            # trusts exists() with no way back if it answers wrongly.
            try:
                dest_root = dest_dir.resolve()
                resolved = fp.resolve()
                resolved.relative_to(dest_root)
            except (OSError, ValueError, RuntimeError):
                continue
            try:
                secure_io.create_secret_text(resolved, content)
            except OSError:
                pass
        vars_file = dest_dir / ".serverhub-vars.json"
        # Leftover HOST_IP inf / TZ dates / ``\\ud800`` used to TypeError
        # json.dumps or leak Infinity into the install JSON body.
        values = {
            _plain_str(k): _plain_str(v) for k, v in values.items()
        }
        try:
            vars_json = json.dumps(
                values, ensure_ascii=False, indent=2, allow_nan=False,
            )
        except (TypeError, ValueError, OverflowError, RecursionError):
            vars_json = "{}"
        secure_io.replace_secret_text(vars_file, vars_json)
        # README with notes
        notes = _plain_str(meta.get("notes"))
        url = _suggest_url(meta, values)
        desc = _plain_str(meta.get("desc"))
        readme = [
            f"# {_plain_str(meta.get('name') or template_id)}",
            "",
            desc,
            "",
        ]
        if url:
            readme += [f"URL: {url}", ""]
        if notes:
            readme += ["## Notes", notes, ""]
        secret_names = {
            _plain_str(v.get("name"))
            for v in (meta.get("vars") or [])
            if isinstance(v, dict) and v.get("secret")
        }
        redacted = {
            _plain_str(k): (
                "***"
                if k in secret_names or any(
                    x in _plain_str(k).upper() for x in ("PASSWORD", "TOKEN", "SECRET")
                )
                else _plain_str(v)
            )
            for k, v in values.items()
        }
        try:
            redacted_json = json.dumps(
                redacted, ensure_ascii=False, indent=2, allow_nan=False,
            )
        except (TypeError, ValueError, OverflowError, RecursionError):
            redacted_json = "{}"
        readme += ["## Variables (secrets redacted)", "```json", redacted_json, "```"]
        try:
            # replace_bytes, not a bare write_text(): install never removes a
            # pre-existing ~/Services/<id>/ (it may hold user data), so a
            # leftover FIFO occupying README.serverhub.md in a pre-seeded
            # directory reached the plain open — which parks until a reader
            # appears — hanging POST /api/catalog/{id}/install forever after
            # the compose file and stack registration had already landed.
            # The tmp+os.replace write never opens the squatting node and
            # atomically swaps the FIFO out.  A leftover non-empty
            # *directory* by that name still refuses os.replace as OSError:
            # the README is advisory documentation, so it costs only itself
            # (the bootstrap_files convention above), never the install the
            # operator's variables and minted passwords are riding on.
            secure_io.replace_bytes(
                dest_dir / "README.serverhub.md",
                "\n".join(readme).encode("utf-8", "replace"),
            )
        except OSError:
            pass

        _register_stack(template_id, meta.get("name") or template_id, dest_dir)

        docker_bin = DOCKER if DOCKER and _exists(Path(DOCKER)) else (shutil.which("docker") or "")
        if not docker_bin:
            # Not a failed install: the stack is registered and startable later
            # from "Apps -> Managed", so keep the files instead of rolling back.
            return {
                "ok": False,
                "path": str(dest_dir),
                "message": (
                    f"Wrote {dest}, but the docker CLI was not found (is OrbStack running?).\n"
                    f"Run manually: docker compose -f {dest} up -d"
                ),
                "variables": values,
                "url": url,
                "notes": notes,
                "first_run_credentials": _plain_str(meta.get("first_run_credentials")),
                "stack_id": template_id,
            }
        env = dict(os.environ)
        rc, msg = run_capped(
            [docker_bin, "compose", "-f", str(dest), "up", "-d"],
            cwd=str(dest_dir),
            timeout=600,
            env=env,
            cap=4000,
        )
        msg = (_plain_str(msg) or f"exit {rc}").strip()
        if rc != 0:
            # A docker CLI that vanished between the _exists() gate above and
            # this spawn leaves run_capped's exact ``(-1, "not found")``
            # sentinel — the same docker-unreachable state as a stopped
            # engine, and it used to fall through to _InstallFailed: a full
            # rollback (discarding the operator's filled-in variables and
            # generated passwords) reported as an uncoded two-word
            # ``message: "not found"`` the SPA cannot translate.
            unreachable = looks_engine_down(msg) or (
                # The sentinel is any FileNotFoundError spawn — a dest_dir
                # (the compose cwd) that vanished between mkdir and the
                # spawn raises identically — so the binary must be confirmed
                # gone from disk before the sentinel reads as a vanished CLI
                # (the compose_svc / actions convention): with the CLI still
                # present and the engine merely off, the keep-the-stack 503
                # pointed the operator at the wrong remedy.
                rc == -1 and looks_cli_vanished(msg) and not cli_on_disk()
            )
            if unreachable and not engine_up(force=True):
                # Same shape as the missing-CLI branch just above: the compose
                # file and registration are good, only the engine is off, so
                # rolling everything back (and discarding the operator's
                # filled-in variables and generated passwords) points away
                # from the real remedy.  Keep the stack startable from
                # "Apps -> Managed" and answer with the code the SPA can
                # translate.  The probe is forced -- the memoised answer has a
                # 5s TTL, and an engine that just stopped is exactly when a
                # stale "up" would misclassify this as a failed install.
                fail = soft_fail("container.engine_down")
                return {
                    "ok": False,
                    "code": fail["code"],
                    "path": str(dest_dir),
                    "message": (
                        f"{fail['message']}.\n"
                        f"Wrote {dest}; the stack is registered and can be started "
                        f"from Apps once the engine is running.\n"
                        f"Run manually: docker compose -f {dest} up -d"
                    ),
                    "variables": values,
                    "url": url,
                    "notes": notes,
                    "first_run_credentials": _plain_str(meta.get("first_run_credentials")),
                    "stack_id": template_id,
                }
            raise _InstallFailed(msg)
        if remapped:
            # The app is not on the port the template advertises, so say so here
            # rather than letting the operator hunt for it.
            msg = f"{msg}\nports moved (default in use): {', '.join(remapped)}".strip()
        if url:
            msg = f"{msg}\n→ {url}".strip()
        return {
            "ok": True,
            "path": str(dest_dir),
            "message": msg,
            "variables": values,
            "url": url,
            "notes": notes,
            "first_run_credentials": _plain_str(meta.get("first_run_credentials")),
            "stack_id": template_id,
            "remapped_ports": remapped,
        }
    except HTTPException:
        # api_error() raised inside the try block: nothing started, still roll back.
        _rollback_install(template_id, dest_dir, created_dir)
        raise
    except _InstallFailed as e:
        detail = _rollback_install(template_id, dest_dir, created_dir)
        msg = _plain_str(e) or "install failed"
        return {
            "ok": False,
            "path": None,
            "message": msg + ("\n\n" + detail if detail else ""),
            "variables": values,
            "url": None,
            "notes": _plain_str(meta.get("notes")),
            "stack_id": None,
        }
    except Exception as e:
        detail = _rollback_install(template_id, dest_dir, created_dir)
        msg = _plain_str(e) or "install failed"
        return {
            "ok": False,
            "path": None,
            "message": msg + ("\n\n" + detail if detail else ""),
            "variables": values,
            "url": None,
            "notes": _plain_str(meta.get("notes")),
            "stack_id": None,
        }


def _unregister_stack(template_id: str, dest_dir: Path | None = None) -> None:
    """Drop the stack row, read-modify-write under the config write lock.

    Same lost-update shape as :func:`_register_stack` before the fix: an
    uninstall racing another install or a settings save wrote a stale
    snapshot of the whole file back and took the concurrent change with it.
    """
    try:
        from hub.config import mutate

        dest_s = str(dest_dir) if dest_dir else None

        def apply(data: dict) -> None:
            stacks = data.get("stacks")
            rows = stacks if isinstance(stacks, list) else []
            kept = [
                s for s in rows
                if not isinstance(s, dict)
                or (s.get("id") != template_id
                    and (not dest_s or s.get("path") != dest_s))
            ]
            if len(kept) == len(rows):
                raise _StacksUnchanged
            data["stacks"] = kept

        mutate(apply)
    except Exception:
        pass


def uninstall_template(
    template_id: str,
    *,
    remove_data: bool = True,
    confirm: bool = False,
) -> dict:
    """Uninstall docker stack or native app from the store."""
    if not confirm:
        raise api_error("catalog.confirm_required")

    if str(template_id).startswith("native-"):
        from hub import native_catalog
        return native_catalog.uninstall_native(template_id, remove_data=remove_data)

    template_id = cli_args.require_positional(template_id, label="template id")

    dest_dir = SERVICES_ROOT / template_id
    compose = dest_dir / "docker-compose.yml"
    if not _exists(compose):
        # still try unregister
        _unregister_stack(template_id, dest_dir)
        invalidate_listing()
        raise api_error("catalog.not_installed", id=str(template_id))

    logs: list[str] = []
    env = dict(os.environ)
    try:
        # down + remove containers/networks; -v only if remove_data
        args = [DOCKER, "compose", "-f", str(compose), "down", "--remove-orphans"]
        if remove_data:
            args.append("-v")
        rc, text = run_capped(
            args, cwd=str(dest_dir), timeout=300, env=env, cap=4000,
        )
        logs.append((_plain_str(text) or f"down exit {rc}").strip())
        down_ok = rc == 0
    except Exception as e:
        logs.append(_plain_str(e) or "error")
        down_ok = False

    joined = "\n".join(logs)
    if (
        not down_ok
        # The vanished-CLI sentinel only classifies once the binary is
        # confirmed gone from disk (the compose_svc / actions convention):
        # any FileNotFoundError spawn collapses into the same "not found",
        # so a dest_dir that vanished mid-request with the CLI still on
        # disk keeps the ordinary uninstall path instead of the 503.
        and (
            looks_engine_down(joined)
            or (looks_cli_vanished(joined) and not cli_on_disk())
        )
        and not engine_up(force=True)
    ):
        # ``down`` did nothing: the containers, networks and volumes this
        # uninstall promises to remove still exist inside the stopped engine.
        # Proceeding used to rmtree the compose directory anyway and then --
        # because ``ok`` falls back to "the compose file is gone" -- report a
        # *successful* uninstall that had removed only the files, leaving
        # orphaned containers to restart against a deleted tree when the
        # engine came back.  Refuse with the coded 503 instead; the operator
        # retries once the engine is running.  A docker CLI that vanished
        # before the spawn (run_capped's exact ``"not found"`` sentinel) is
        # the same did-nothing state and used to take the destructive path
        # too, reporting the fake success.  Probe forced, failure path only,
        # same convention as the rest of this sweep.
        raise api_error("container.engine_down")

    removed_path = False
    if remove_data:
        import shutil as _shutil
        try:
            _shutil.rmtree(dest_dir)
            removed_path = True
            logs.append(f"Removed directory {dest_dir}")
        except Exception as e:
            logs.append(f"Failed to remove directory: {_plain_str(e) or 'error'}")
    else:
        # keep files; user can re-up later
        logs.append(f"Kept directory {dest_dir} (remove data was not selected)")

    _unregister_stack(template_id, dest_dir)
    invalidate_listing()

    ok = down_ok or not _exists(compose)
    return {
        "ok": ok,
        "message": "\n".join(logs)[-2000:],
        "path": str(dest_dir) if _exists(dest_dir) else None,
        "removed_data": removed_path,
        "kind": "docker",
        "stack_id": template_id,
    }
