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
import subprocess
from pathlib import Path
from typing import Any

import yaml
from fastapi import HTTPException

from hub import catalog_remote
from hub.errors import CODES, api_error
from hub.host_address import host_ip
from hub.paths import BASE, DOCKER
from hub.util import fan_out

TEMPLATES = BASE / "templates"
SERVICES_ROOT = Path.home() / "Services"

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


def _guess_category(tid: str, meta: dict) -> str:
    if meta.get("category"):
        return str(meta["category"])
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
_GLOBAL_PREFS = Path.home() / "Library/Preferences/.GlobalPreferences.plist"

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
        prefs = plistlib.loads(_GLOBAL_PREFS.read_bytes())
        raw = prefs.get("AppleLanguages") or []
    except Exception:
        raw = []
    seen: list[str] = []
    for tag in raw:
        key = _normalise_lang(str(tag))
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
    return {
        "HOST_IP": host_ip(),
        "HOME": str(Path.home()),
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
    text = path.read_text(errors="replace")
    meta: dict[str, Any] = {
        "id": path.stem,
        "name": path.stem.replace("-", " ").title(),
        "vars": [],
    }
    body = text
    m = FM_RE.match(text)
    if m:
        try:
            meta.update(yaml.safe_load(m.group(1)) or {})
        except Exception:
            pass
        body = m.group(2)
    found = sorted(set(VAR_RE.findall(body)))
    declared = meta.get("vars") or []
    by_name: dict[str, dict] = {}
    for v in declared:
        if isinstance(v, str):
            by_name[v] = {"name": v, "default": "", "label": v, "required": True}
        elif isinstance(v, dict) and v.get("name"):
            # Keep __RANDOM__ literal until install time (never mint secrets on list)
            default = v.get("default", "")
            by_name[v["name"]] = {
                "name": v["name"],
                "default": _expand_auto(str(default if default is not None else "")),
                "label": v.get("label") or v["name"],
                "required": bool(v.get("required", True)),
                "help": v.get("help", ""),
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
    meta.setdefault("tags", [])
    meta.setdefault("ports", [])
    meta.setdefault("featured", False)
    meta.setdefault("notes", "")
    meta.setdefault("url_template", "")
    return meta, body


_list_cache: dict = {"t": 0.0, "sig": "", "items": None}
_LIST_TTL = 20.0


def _templates_sig() -> str:
    """Cheap change detector for template dir + remote overrides + install dirs."""
    if not TEMPLATES.is_dir():
        return "empty"
    parts = []
    try:
        for p in sorted(TEMPLATES.iterdir()):
            if p.suffix in (".yml", ".yaml"):
                st = p.stat()
                parts.append(f"{p.name}:{int(st.st_mtime)}:{st.st_size}")
    except OSError:
        return "err"
    # Remote overrides change the merged listing without touching templates/,
    # so they must be part of the signature or a sync would not show up for
    # up to _LIST_TTL seconds.
    try:
        for p in catalog_remote.remote_template_files():
            st = p.stat()
            parts.append(f"r:{p.name}:{int(st.st_mtime)}:{st.st_size}")
    except OSError:
        pass
    # installed flags change when ~/Services/<id>/docker-compose.yml appears
    try:
        for p in SERVICES_ROOT.iterdir():
            if (p / "docker-compose.yml").exists():
                parts.append(f"i:{p.name}")
    except OSError:
        pass
    return "|".join(parts)


def _cache_store(now: float, sig: str, items: list) -> list:
    """Cache *items* and hand the caller its own copy.

    ``catalog_overview()`` appends to ``notes`` on the entries it returns.  When
    the cache handed out its own objects that append landed on the cached dict
    and grew by one sentence per request, so the store page showed the same
    advisory repeated dozens of times.  Every exit from this function returns a
    deep copy: callers may mutate freely, the cache stays pristine.
    """
    _list_cache.update(t=now, sig=sig, items=items)
    return copy.deepcopy(items)


def list_templates(force: bool = False) -> list:
    import time as _time

    now = _time.time()
    sig = _templates_sig()
    if (
        not force
        and _list_cache["items"] is not None
        and _list_cache["sig"] == sig
        and now - _list_cache["t"] < _LIST_TTL
    ):
        return copy.deepcopy(_list_cache["items"])

    items = []
    if not TEMPLATES.is_dir():
        return _cache_store(now, sig, items)
    builtin_ids = {
        p.stem
        for p in set(TEMPLATES.glob("*.yml")) | set(TEMPLATES.glob("*.yaml"))
    }
    # Remote overrides shadow the built-in template with the same id; the
    # built-in file stays on disk untouched so "restore built-in" is a delete.
    by_id: dict[str, Path] = {}
    for p in sorted(set(TEMPLATES.glob("*.yml")) | set(TEMPLATES.glob("*.yaml"))):
        by_id[p.stem] = p
    for p in catalog_remote.remote_template_files():
        by_id[p.stem] = p
    remote_versions = catalog_remote.remote_versions()
    files = [by_id[k] for k in sorted(by_id)]
    for p in files:
        meta, _ = _parse_template(p)
        tid = meta.get("id") or p.stem
        is_remote = p.parent != TEMPLATES
        dest = SERVICES_ROOT / tid
        installed = (dest / "docker-compose.yml").exists()
        # UI defaults: show empty for __RANDOM__ so install mints once
        vars_out = []
        values_for_url: dict[str, str] = {}
        for v in meta.get("vars") or []:
            vv = dict(v)
            if vv.get("default") == "__RANDOM__":
                vv["default"] = ""
                vv["placeholder"] = "auto"
                vv["secret"] = True
            vars_out.append(vv)
            if v.get("name") and v.get("default") not in (None, "__RANDOM__"):
                values_for_url[str(v["name"])] = str(v.get("default") or "")
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
        items.append({
            "id": tid,
            "name": meta.get("name") or tid,
            "file": p.name,
            "desc": meta.get("desc", ""),
            "images": meta.get("images") or [],
            "vars": vars_out,
            "category": meta.get("category") or "other",
            "tags": meta.get("tags") or [],
            "ports": meta.get("ports") or [],
            "featured": bool(meta.get("featured")),
            "notes": meta.get("notes") or "",
            "url_template": meta.get("url_template") or "",
            "url_hint": url_hint,
            "installed": installed,
            "path": str(dest) if dest.exists() else None,
            "kind": "docker",
            "prefer_native": False,
            "source": "remote" if is_remote else "builtin",
            "remote_version": remote_versions.get(p.stem, "") if is_remote else "",
            "builtin_available": (p.stem in builtin_ids) if is_remote else True,
        })
    items.sort(key=lambda x: (0 if x.get("featured") else 1, x.get("name") or ""))
    return _cache_store(now, sig, items)


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
        return list_templates()

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
    # Prefer native: if Cloudflared brew is installed, steer away from Docker twin
    native_ids_installed = {a["id"] for a in native if a.get("installed")}
    for d in docker:
        if d.get("id") == "cloudflared" and "native-cloudflared" in native_ids_installed:
            d["notes"] = (
                (d.get("notes") or "")
                + (" · " if d.get("notes") else "")
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
            x.get("name") or "",
        )
    )
    by_cat: dict[str, int] = {}
    for t in templates:
        c = t.get("category") or "other"
        by_cat[c] = by_cat.get(c, 0) + 1
        k = t.get("kind") or "docker"
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
        # any real value.
        if "\n" in value or "\r" in value:
            raise api_error("catalog.bad_var_value", name=key)
        return value

    return VAR_RE.sub(repl, body)


def _register_stack(template_id: str, name: str, dest_dir: Path) -> None:
    """Append to services.yaml stacks if missing."""
    try:
        from hub.config import cfg, save_full

        data = copy.deepcopy(cfg())
        stacks = data.setdefault("stacks", [])
        for s in stacks:
            if s.get("id") == template_id or s.get("path") == str(dest_dir):
                return
        stacks.append({
            "id": template_id,
            "name": name,
            "path": str(dest_dir),
            "compose_file": "docker-compose.yml",
        })
        save_full(data)
    except Exception:
        pass


def _suggest_url(meta: dict, values: dict) -> str | None:
    tpl = meta.get("url_template") or ""
    if not tpl:
        return None
    host = (values.get("HOST_IP") or "").strip()
    if not host:
        host = host_ip()
    port = values.get("HOST_PORT") or values.get("WEB_PORT") or ""
    out = tpl.replace("{{HOST_IP}}", host).replace("{{HOST_PORT}}", str(port))
    out = out.replace("{{WEB_PORT}}", str(values.get("WEB_PORT") or port))
    for k, v in values.items():
        out = out.replace("{{" + k + "}}", str(v))
    return out


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
        if not d.is_dir() or d.name == exclude_id:
            continue
        compose = d / "docker-compose.yml"
        if not compose.exists():
            continue
        try:
            text = compose.read_text(errors="replace")
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
        notes.append(f"stack registration left behind: {e}")
    if created_dir:
        try:
            shutil.rmtree(dest_dir)
        except OSError as e:
            notes.append(f"could not remove {dest_dir}: {e}")
    else:
        notes.append(
            f"kept pre-existing {dest_dir} (may contain your data); "
            "remove it yourself if you want a clean retry"
        )
    return "; ".join(notes)


def template_file(template_id: str) -> Path | None:
    """The file backing *template_id*: remote override first, then built-in."""
    remote = catalog_remote.remote_template_path(template_id)
    if remote is not None:
        return remote
    for suffix in (".yml", ".yaml"):
        p = TEMPLATES / f"{template_id}{suffix}"
        if p.exists():
            return p
    return None


def install_template(template_id: str, variables: dict | None = None) -> dict:
    # Native apps (brew / system / script)
    if str(template_id).startswith("native-"):
        from hub import native_catalog
        return native_catalog.install_native(template_id, variables)

    src = template_file(template_id)
    if src is None:
        raise api_error("catalog.unknown_template", id=str(template_id))
    meta, body = _parse_template(src)
    values: dict[str, str] = {}
    # Ports the operator typed themselves are honoured exactly; ports that came
    # from a template default (or that we had to invent) may be moved when taken.
    port_claims = _ports_claimed_by_stacks(exclude_id=template_id)
    handed_out: set[int] = set()
    remapped: list[str] = []

    def resolve_port(name: str, preferred: str | int, explicit: bool) -> str:
        try:
            wanted = int(str(preferred).strip())
        except (TypeError, ValueError):
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
    _list_cache["t"] = 0
    _list_cache["items"] = None
    # Auto-injected placeholders so shipped templates never need to hardcode a
    # developer-specific absolute paths that would make templates non-portable.
    if "HOST_IP" not in values:
        values["HOST_IP"] = host_ip()
    values.setdefault("HOME", str(Path.home()))
    values.setdefault("SERVICES", str(SERVICES_ROOT))
    values.setdefault("TZ", host_timezone())
    values.setdefault("OCR_LANG", host_ocr_languages())
    values.setdefault("UI_LANGS", host_ui_languages())

    rendered = render_template(body, values) if VAR_RE.search(body) else body

    dest_dir = SERVICES_ROOT / template_id
    dest = dest_dir / "docker-compose.yml"
    if dest.exists():
        raise api_error("catalog.already_installed", path=str(dest))

    # Refuse before touching the filesystem when a host port is unavailable,
    # otherwise "up" fails and the user is left with a dead app.
    _check_ports_free(rendered, template_id)

    # Only a directory *we* created may be removed during rollback: the user may
    # have pre-seeded ~/Services/<id>/ with data before installing.
    created_dir = not dest_dir.exists()
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest.write_text(rendered)
        # Compose commonly contains generated database/admin secrets.
        dest.chmod(0o600)
        (dest_dir / "data").mkdir(exist_ok=True)
        # extra dirs often used
        for d in ("config", "media", "downloads", "uploads", "library", "pgdata", "model-cache"):
            if f"./{d}" in rendered or f"/{d}" in rendered:
                (dest_dir / d).mkdir(exist_ok=True)
        # optional bootstrap files from frontmatter
        for bf in meta.get("bootstrap_files") or []:
            if not isinstance(bf, dict) or not bf.get("path"):
                continue
            rel = str(bf["path"]).lstrip("/")
            if ".." in rel:
                continue
            fp = dest_dir / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            content = str(bf.get("content") or "")
            for k, v in values.items():
                content = content.replace("{{" + k + "}}", str(v))
            # "x" so an existing file is never rewritten: these are deployment
            # files the operator may have edited by hand, and a check-then-write
            # trusts exists() with no way back if it answers wrongly.
            try:
                with fp.open("x", encoding="utf-8") as fh:
                    fh.write(content)
            except FileExistsError:
                pass
        vars_file = dest_dir / ".serverhub-vars.json"
        vars_file.write_text(json.dumps(values, ensure_ascii=False, indent=2))
        vars_file.chmod(0o600)
        # README with notes
        notes = meta.get("notes") or ""
        url = _suggest_url(meta, values)
        readme = [
            f"# {meta.get('name') or template_id}",
            "",
            meta.get("desc") or "",
            "",
        ]
        if url:
            readme += [f"URL: {url}", ""]
        if notes:
            readme += ["## Notes", notes, ""]
        secret_names = {
            str(v.get("name"))
            for v in (meta.get("vars") or [])
            if isinstance(v, dict) and v.get("secret")
        }
        redacted = {
            k: ("***" if k in secret_names or any(x in k.upper() for x in ("PASSWORD", "TOKEN", "SECRET")) else v)
            for k, v in values.items()
        }
        readme += ["## Variables (secrets redacted)", "```json", json.dumps(redacted, ensure_ascii=False, indent=2), "```"]
        (dest_dir / "README.serverhub.md").write_text("\n".join(readme))

        _register_stack(template_id, meta.get("name") or template_id, dest_dir)

        docker_bin = DOCKER if DOCKER and Path(DOCKER).exists() else (shutil.which("docker") or "")
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
                "stack_id": template_id,
            }
        env = dict(os.environ)
        p = subprocess.run(
            [docker_bin, "compose", "-f", str(dest), "up", "-d"],
            cwd=str(dest_dir),
            capture_output=True,
            text=True,
            timeout=600,
            env=env,
        )
        msg = ((p.stdout or "") + (p.stderr or "")).strip() or f"exit {p.returncode}"
        if p.returncode != 0:
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
            "stack_id": template_id,
            "remapped_ports": remapped,
        }
    except HTTPException:
        # api_error() raised inside the try block: nothing started, still roll back.
        _rollback_install(template_id, dest_dir, created_dir)
        raise
    except _InstallFailed as e:
        detail = _rollback_install(template_id, dest_dir, created_dir)
        return {
            "ok": False,
            "path": None,
            "message": f"{e}\n\n{detail}",
            "variables": values,
            "url": None,
            "notes": meta.get("notes") or "",
            "stack_id": None,
        }
    except Exception as e:
        detail = _rollback_install(template_id, dest_dir, created_dir)
        return {
            "ok": False,
            "path": None,
            "message": f"{e}\n\n{detail}",
            "variables": values,
            "url": None,
            "notes": meta.get("notes") or "",
            "stack_id": None,
        }


def _unregister_stack(template_id: str, dest_dir: Path | None = None) -> None:
    try:
        from hub.config import cfg, save_full

        data = copy.deepcopy(cfg())
        stacks = data.get("stacks") or []
        dest_s = str(dest_dir) if dest_dir else None
        new_stacks = [
            s for s in stacks
            if s.get("id") != template_id and (not dest_s or s.get("path") != dest_s)
        ]
        if len(new_stacks) != len(stacks):
            data["stacks"] = new_stacks
            save_full(data)
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

    dest_dir = SERVICES_ROOT / template_id
    compose = dest_dir / "docker-compose.yml"
    if not compose.exists():
        # still try unregister
        _unregister_stack(template_id, dest_dir)
        _list_cache["t"] = 0
        _list_cache["items"] = None
        raise api_error("catalog.not_installed", id=str(template_id))

    logs: list[str] = []
    env = dict(os.environ)
    try:
        # down + remove containers/networks; -v only if remove_data
        args = [DOCKER, "compose", "-f", str(compose), "down", "--remove-orphans"]
        if remove_data:
            args.append("-v")
        p = subprocess.run(
            args,
            cwd=str(dest_dir),
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
        logs.append(((p.stdout or "") + (p.stderr or "")).strip() or f"down exit {p.returncode}")
        down_ok = p.returncode == 0
    except Exception as e:
        logs.append(str(e))
        down_ok = False

    removed_path = False
    if remove_data:
        import shutil as _shutil
        try:
            _shutil.rmtree(dest_dir)
            removed_path = True
            logs.append(f"Removed directory {dest_dir}")
        except Exception as e:
            logs.append(f"Failed to remove directory: {e}")
    else:
        # keep files; user can re-up later
        logs.append(f"Kept directory {dest_dir} (remove data was not selected)")

    _unregister_stack(template_id, dest_dir)
    _list_cache["t"] = 0
    _list_cache["items"] = None

    ok = down_ok or not compose.exists()
    return {
        "ok": ok,
        "message": "\n".join(logs)[-2000:],
        "path": str(dest_dir) if dest_dir.exists() else None,
        "removed_data": removed_path,
        "kind": "docker",
        "stack_id": template_id,
    }
