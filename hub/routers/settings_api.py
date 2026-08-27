from __future__ import annotations

import time
from typing import Any, Optional

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from hub import __version__, alerts, audit, backups, metrics, metrics_rollup, ollama_svc
from hub.auth import auth_enabled, request_client_id, request_username
from hub.config import _YAML_CAP, cfg, settings_section, update_settings
from hub.errors import api_error
from hub.host_address import configured_host, host_ip
from hub.paths import DOCKER, ORB

router = APIRouter(tags=["settings"])


class AuthPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: Optional[bool] = None
    allow_localhost: Optional[bool] = None


class NotifyPatch(BaseModel):
    enabled: Optional[bool] = None
    include_warn: Optional[bool] = None
    notify_resolve: Optional[bool] = None
    ha_url: Optional[str] = None
    ha_token: Optional[str] = None
    ha_service: Optional[str] = None
    ha_webhook_url: Optional[str] = None
    webhook_url: Optional[str] = None


class UiPatch(BaseModel):
    locale: Optional[str] = None  # zh-CN | en | ja
    theme: Optional[str] = None  # system | unraid | unraid-dark | omv | docker | macos | macos-dark | nord | glass | mono
    density: Optional[str] = None  # compact | comfortable | cozy


class ThresholdsPatch(BaseModel):
    """Resource alert thresholds (OMV / TrueNAS style)."""
    enabled: Optional[bool] = None
    cpu_pct: Optional[int] = Field(None, ge=50, le=100)
    mem_pct: Optional[int] = Field(None, ge=50, le=100)
    disk_pct: Optional[int] = Field(None, ge=50, le=100)
    cooldown_sec: Optional[int] = Field(None, ge=60, le=86400)
    # SMART disk health.  These must be declared even though the merge below is
    # generic: it goes through `model_dump()`, which only ever yields declared
    # fields, so an undeclared threshold is accepted by the request and then
    # dropped on the way to services.yaml -- the user changes the value, gets a
    # 200, and the setting never moves.
    smart_enabled: Optional[bool] = None
    smart_temp_c: Optional[int] = Field(None, ge=30, le=95)
    smart_wear_pct: Optional[int] = Field(None, ge=50, le=100)
    #: Available Spare counts down, so this is a floor rather than a ceiling.
    smart_spare_pct: Optional[int] = Field(None, ge=1, le=50)


class IpAliasesPatch(BaseModel):
    auto_bind: Optional[bool] = None
    prefer_wired: Optional[bool] = None
    interval: Optional[int] = Field(None, ge=30, le=600)
    ips: Optional[list[str]] = None
    netmask: Optional[str] = None


class TerminalPatch(BaseModel):
    """Host-shell gate.

    ``host_enabled`` is remote code execution on the whole machine, so it has no
    default-on path anywhere: it must be switched on here, deliberately, by an
    already-authenticated administrator.
    """
    host_enabled: Optional[bool] = None
    shell: Optional[str] = None
    cwd: Optional[str] = None


class OllamaPatch(BaseModel):
    """Local LLM daemon the panel is allowed to talk to.

    ``url`` is fetched by the panel process, so it must be a loopback or
    private HTTP origin — the same gate ``hub.ollama_svc.base_url`` uses.
    ``label`` overrides LaunchAgent discovery; empty keeps auto-detect.
    """
    model_config = ConfigDict(extra="forbid")

    url: Optional[str] = Field(None, max_length=256)
    label: Optional[str] = Field(None, max_length=128)


class SettingsPatch(BaseModel):
    host_ip: Optional[str] = None
    auth: Optional[AuthPatch] = None
    notify: Optional[NotifyPatch] = None
    ui: Optional[UiPatch] = None
    metrics_interval: Optional[int] = Field(None, ge=15, le=600)
    alert_interval: Optional[int] = Field(None, ge=15, le=600)
    resource_mode: Optional[str] = Field(None, max_length=8)
    adaptive: Optional[bool] = None
    thresholds: Optional[ThresholdsPatch] = None
    ip_aliases: Optional[IpAliasesPatch] = None
    terminal: Optional[TerminalPatch] = None
    ollama: Optional[OllamaPatch] = None


_ALLOWED_LOCALES = {"zh-CN", "en", "ja"}
_ALLOWED_THEMES = {
    "system", "unraid", "unraid-dark", "omv", "docker", "macos", "macos-dark",
    "nord", "glass", "mono",
}
_ALLOWED_DENSITY = {"compact", "comfortable", "cozy"}


def _isa(value, kinds) -> bool:
    """``isinstance`` that a leftover ``__class__``-property bomb cannot 500.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the bare rank gates themselves — planted as the config root,
    the ``settings`` / ``settings.ollama`` block, or any scalar these
    helpers coerce, it 500'd GET /api/settings raw one line ahead of the
    laundering built to absorb junk shapes (the system/status rule).  A real
    subclass still matches through the C-level type check.
    """
    try:
        return isinstance(value, kinds)
    except Exception:
        return False


def _decode_bytes(value) -> str:
    """Unbound base decode: a bytes-subclass ``__bytes__``/``.decode`` bomb
    cannot 500.  ``bytes(value)`` dispatches into an overridden ``__bytes__``
    (and ``.decode`` into an overridden decode); the unbound base call reads
    the real buffer underneath either override."""
    base = bytes if _isa(value, bytes) else bytearray
    return base.decode(value, "utf-8", "replace")


def _as_map(v):
    """A plain-dict view of *v*, or ``{}``.

    ``dict(v)``, not ``v`` itself: a leftover ``cfg()`` section that is a dict
    *subclass* whose ``.get`` / ``.items`` / ``__bool__`` raises passes the
    ``isinstance(v, dict)`` gate and then 500'd every ``auth.get(...)`` /
    ``notify.get(...)`` read below (the bomb class usage5/metrics5/bookmarks5
    sealed elsewhere).  ``dict(subclass)`` copies through CPython's C-level
    storage, bypassing the overridden methods, so the returned map answers
    ``.get`` normally.  Nested *values* that are themselves bombs are handled
    by :func:`_jsonable`.
    """
    # _isa: a block whose ``__class__`` is a raising property used to
    # detonate the bare gate itself — the same GET /api/settings 500 this
    # launderer exists to prevent, one line earlier.
    if not _isa(v, dict):
        return {}
    try:
        return dict(v)
    except Exception:
        return {}


def _mapping_get(mapping, key, default=None):
    """Field read that a hostile mapping *key* cannot 500.

    ``_as_map``'s laundering ``dict(...)`` copy keeps hostile *keys*, and
    even a plain-dict ``.get`` probe still runs the stored keys' own
    ``__eq__`` on a hash collision — a leftover str-subclass key whose hash
    shadows ``host_enabled`` and whose ``__eq__`` raises used to detonate
    the terminal render and 500 GET /api/settings (the
    vm_console/storage_svc rule).  Only the shadowed field degrades to its
    default.
    """
    try:
        return dict.get(mapping, key, default)
    except Exception:
        return default


def _merged_section(name: str, patch: dict) -> dict:
    """Stored *name* section with *patch* laid over it, bomb-key safe.

    PUT /api/settings' terminal branch merges the stored section back into
    the write (``dict(settings_section(...))`` + ``cur.update(patch)``), and
    the update's insert probe runs hostile stored keys' own ``__eq__`` — a
    leftover str-subclass key whose hash shadows ``host_enabled`` and whose
    ``__eq__`` raises 500'd the save one line ahead of the dump-side
    laundering.  Keys ride through the same launder ``config._renderable_tree``
    would apply on the dump anyway (unbound base str copy); a stored key the
    merge still cannot probe drops with its value, siblings and the patch
    survive.
    """
    out: dict = {}
    try:
        items = list(dict.items(dict(settings_section(name))))
    except Exception:
        items = []
    for k, v in items:
        if _isa(k, str) and type(k) is not str:
            try:
                k = str.__str__(k)
            except Exception:
                continue
        try:
            out[k] = v
        except Exception:
            continue
    try:
        out.update(patch)
    except Exception:
        # A non-str hostile key whose hash shadows a patched field: the
        # patch wins; keep every stored sibling that can still be probed.
        merged = dict(patch)
        for k, v in dict.items(out):
            try:
                merged.setdefault(k, v)
            except Exception:
                continue
        out = merged
    return out


def _cfg_map():
    """Laundered top-level config snapshot for the settings render.

    ``cfg()`` normally returns a plain dict, but a leftover whose top level is
    a dict subclass with a bombing ``.get`` used to 500 the very first
    ``cfg().get("settings")``; launder it once here so every access below is
    on a plain dict.
    """
    try:
        data = cfg()
    except Exception:
        return {}
    return _as_map(data)


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    # _isa on the bytes gate, try on the decode: a ``__class__``-property
    # bomb detonated the bare isinstance; the old ``bytes(value)`` copy
    # dispatched into a bytes-subclass ``__bytes__`` bomb (the unbound base
    # decode reads the buffer underneath both overrides); a lying
    # ``__class__`` (claims bytes, is not) TypeErrors the unbound decode
    # and answers "" like any unreadable leftover.
    if _isa(value, (bytes, bytearray)):
        try:
            return _decode_bytes(value)
        except Exception:
            return ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    # Unbound str.encode, not text.encode: ``str(x)`` of a str *subclass*
    # whose ``__str__`` returns itself keeps the subclass, so the bound
    # ``.encode`` dispatched into a leftover override — a bomb there raised
    # out of the sanitizer and 500'd GET /api/settings (a stack name /
    # thresholds key was enough; the jobs6 class, sealed elsewhere).
    return str.encode(text, "utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    YAML ``metrics_interval: .inf``, ``username: 2026-08-19``, ``!!binary``
    theme, and a ``!!set`` groups_order each used to 500 GET /api/settings.
    A leftover ``\\ud800`` username or stack name still 500'd the same
    encoder (``ensure_ascii=False`` then UTF-8).
    A >4300-digit stack port / groups entry still passed through untouched:
    CPython's int->str digit limit then ValueError'd ``json.dumps`` itself.
    """
    if depth > 32:
        return None
    # _isa on every rank gate: a leftover whose ``__class__`` is a raising
    # property used to detonate the *first* bare isinstance below and 500
    # GET /api/settings raw, wherever it rode in the config tree.
    if value is None or _isa(value, bool):
        return value
    if _isa(value, int):
        try:
            # Base coercion to an exact int: an int *subclass* whose
            # ``__index__``/``__str__`` bombs (the modules5 class) used to
            # raise past the ValueError-only digit-cap catch and 500
            # GET /api/settings when it rode a stack port / groups entry.
            value = int.__index__(value)
            str(value)
        except Exception:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if _isa(value, float):
        try:
            # Base coercion to an exact float: a subclass ``__eq__``/``__ne__``
            # bomb used to blow the NaN/inf probes below.
            value = float.__float__(value)
        except Exception:
            return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isa(value, str):
        return _utf8_text(value)
    if _isa(value, (bytes, bytearray)):
        try:
            # Unbound base decode: the old ``bytes(value)`` copy dispatched
            # into a bytes-subclass ``__bytes__`` bomb and 500'd the render.
            # The try is for a lying ``__class__`` (claims bytes, is not),
            # which TypeErrors the unbound call and drops the impostor.
            return _decode_bytes(value)
        except Exception:
            return None
    if _isa(value, dict):
        out = {}
        try:
            items = list(value.items())
        except Exception:
            # A dict *subclass* whose items() raises (or a Mapping bomb) must
            # not 500 Starlette's encoder — drop the whole node like an
            # unrenderable scalar; healthy siblings around it are untouched.
            return None
        for k, v in items:
            # _isa on the key gates too: a ``__class__``-property bomb
            # riding a mapping *key* used to detonate the bare isinstance.
            if _isa(k, (bytes, bytearray)):
                try:
                    k = _decode_bytes(k)
                except Exception:
                    continue
            elif not _isa(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if _isa(value, (list, tuple, set, frozenset)):
        try:
            seq = list(value)
        except Exception:
            # A list/set subclass whose __iter__ raises drops to null rather
            # than 500ing the encode; the surrounding structure survives.
            return None
        return [_jsonable(v, depth + 1) for v in seq]
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # getattr's default only swallows AttributeError; a leftover whose
        # ``isoformat`` is a raising property (or a ``__getattr__`` bomb)
        # used to raise out of the probe itself and 500 GET /api/settings
        # raw (the hub.ollama_svc._jsonable rule).
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/settings.
            return _jsonable(iso(), depth + 1)
        except Exception:
            pass
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _text(value, default: str = "") -> str:
    cleaned = _jsonable(value)
    return cleaned if isinstance(cleaned, str) and cleaned else default


def _finite(value, default):
    # _isa on every gate: a ``__class__``-property bomb interval used to
    # detonate the bare isinstance itself instead of answering *default*.
    if _isa(value, bool) or value is None:
        return default
    if _isa(value, int):
        try:
            # Base coercion to an exact int first: an int *subclass* whose
            # ``__index__``/``__str__`` bombs used to raise past the
            # ValueError-only catch and 500 GET /api/settings.
            value = int.__index__(value)
            str(value)
        except Exception:
            # A >4300-digit leftover interval is unrenderable by json.dumps
            # (CPython's int->str digit cap) — fall back like inf.
            return default
        return value
    if _isa(value, float):
        try:
            # Base coercion to an exact float: a subclass ``__eq__``/``__ne__``
            # bomb used to blow the NaN/inf probes below.
            value = float.__float__(value)
        except Exception:
            return default
        if value != value or value in (float("inf"), float("-inf")):
            return default
        return value
    return default


def _epoch(value, default: int = 0) -> int:
    """Finite unix timestamp. Leftover inf ``time.time()`` OverflowError'd
    ``int(inf)`` on GET /api/metrics?range=."""
    # _isa on every gate: the same ``__class__``-property bomb class as
    # _finite, one endpoint over (GET /api/metrics window math).
    if _isa(value, bool) or value is None:
        return default
    if _isa(value, int):
        try:
            # Base coercion first: a subclass ``__index__``/``__str__`` bomb
            # used to raise past the ValueError-only digit-cap catch.
            value = int.__index__(value)
            str(value)
        except Exception:
            # A >4300-digit epoch cannot be JSON-encoded (int->str digit cap).
            return default
        return value
    if _isa(value, float):
        try:
            value = float.__float__(value)
        except Exception:
            return default
        if value != value or value in (float("inf"), float("-inf")):
            return default
        try:
            return int(value)
        except (OverflowError, ValueError):
            return default
    try:
        return int(value)
    except Exception:
        # ``int()`` of an arbitrary leftover dispatches into its own
        # ``__int__``/``__index__``, whose bomb is not one of the three
        # usual conversion errors.
        return default


def _flag(value, default: bool = True) -> bool:
    # _isa: a ``__class__``-property bomb flag used to detonate the bare
    # gate itself instead of answering *default*.
    return value if _isa(value, bool) else default


def _truthy(value) -> bool:
    """Guarded ``bool(...)`` for has_* / enabled flags.

    ``bool(notify.get("enabled"))`` reflects into the stored value's own
    ``__bool__``/``__len__``; a leftover bomb there (the modules5 class)
    used to 500 GET /api/settings where every healthy sibling around it
    rendered fine.
    """
    # _isa: a ``__class__``-property bomb used to detonate this bare gate
    # one line ahead of the guarded bool() below.
    if _isa(value, bool):
        return value
    try:
        return bool(value)
    except Exception:
        return False


def _json_list(value) -> list:
    # _isa: a ``__class__``-property bomb riding stacks / log_sources /
    # groups_order used to detonate the bare gate itself.
    cleaned = _jsonable(value if _isa(value, (list, tuple, set, frozenset)) else [])
    return cleaned if isinstance(cleaned, list) else []


def _public_settings() -> dict:
    data = _cfg_map()
    s = _as_map(data.get("settings"))
    auth = _as_map(s.get("auth"))
    notify = _as_map(s.get("notify"))
    ui = _as_map(s.get("ui"))
    thresholds = _as_map(s.get("thresholds"))
    locale = _text(ui.get("locale"), "zh-CN")
    if locale not in _ALLOWED_LOCALES:
        locale = "zh-CN"
    theme = _text(ui.get("theme"), "system")
    if theme not in _ALLOWED_THEMES:
        theme = "system"
    density = _text(ui.get("density"), "compact")
    if density not in _ALLOWED_DENSITY:
        density = "compact"
    ollama = _as_map(s.get("ollama"))
    aliases = _jsonable(_as_map(s.get("ip_aliases")))
    if not isinstance(aliases, dict):
        aliases = {}
    # ``password and password != "change-me"`` reflects into the leftover's
    # own ``__bool__`` / ``__ne__``; a subclass bomb there used to 500 the
    # whole render.  The probe is best-effort: an unanswerable leftover
    # reads as "no password set", never as a raw 500.
    password = auth.get("password")
    try:
        password_set = bool(password) and password != "change-me"
    except Exception:
        password_set = False
    # _text first, then membership: ``s.get("resource_mode") in ("low",
    # "high")`` gives a str-*subclass* ``__eq__`` bomb reflected priority,
    # and a float/int bomb the same — each used to 500 GET /api/settings.
    # _text answers an exact str, so the tuple compare cannot dispatch into
    # a leftover override; non-str leftovers default to "low" as before.
    resource_mode = _text(s.get("resource_mode"))
    return {
        "host_ip": _text(host_ip()),
        "host_ip_config": _text(configured_host()),
        "auth": {
            "enabled": auth_enabled(),
            # Loopback transport is never identity. Native clients authenticate
            # with the dedicated mode-0600 token instead.
            "allow_localhost": False,
            "username": _text(auth.get("username"), "admin"),
            "has_password": _truthy(auth.get("password_hash")) or password_set,
        },
        "notify": {
            "enabled": _truthy(notify.get("enabled")),
            "include_warn": _truthy(notify.get("include_warn")),
            "notify_resolve": _flag(notify.get("notify_resolve", True), True),
            "ha_url": _text(notify.get("ha_url"), "http://localhost:8123"),
            "ha_service": _text(notify.get("ha_service"), "notify.notify"),
            "has_token": _truthy(notify.get("ha_token")),
            "has_webhook": _truthy(notify.get("ha_webhook_url"))
            or _truthy(notify.get("webhook_url")),
        },
        "ui": {
            "locale": locale,
            "theme": theme,
            "density": density,
        },
        "metrics_interval": _finite(s.get("metrics_interval", 90), 90),
        "alert_interval": _finite(s.get("alert_interval", 90), 90),
        "resource_mode": resource_mode if resource_mode in ("low", "high") else "low",
        "adaptive": _flag(s.get("adaptive", True), True),
        "thresholds": {
            "enabled": _flag(thresholds.get("enabled", True), True),
            "cpu_pct": _finite(thresholds.get("cpu_pct", 90), 90),
            "mem_pct": _finite(thresholds.get("mem_pct", 90), 90),
            "disk_pct": _finite(thresholds.get("disk_pct", 90), 90),
            "cooldown_sec": _finite(thresholds.get("cooldown_sec", 1800), 1800),
            # Enumerated, not spread, so the read side has to be extended with the
            # write side: without these four the settings page can PUT a SMART
            # threshold but never reads back what it saved.
            "smart_enabled": _flag(thresholds.get("smart_enabled", True), True),
            "smart_temp_c": _finite(thresholds.get("smart_temp_c", 60), 60),
            "smart_wear_pct": _finite(thresholds.get("smart_wear_pct", 90), 90),
            "smart_spare_pct": _finite(thresholds.get("smart_spare_pct", 10), 10),
        },
        "ip_aliases": aliases,
        # Host terminal is RCE on this machine, so it ships off and the UI needs
        # to know the current state to render the gate honestly.
        "terminal": {
            # _mapping_get: a leftover str-subclass key shadowing
            # ``host_enabled`` with a bombing ``__eq__`` used to detonate
            # the plain ``.get`` probe here — a 500 on GET /api/settings.
            "host_enabled": _truthy(
                _mapping_get(_as_map(s.get("terminal")), "host_enabled", False)
            ),
        },
        "ollama": {
            # settings_text, not _text: a hand-edited numeric YAML value
            # (``label: 2023``) used to read back as int, fail the isinstance
            # gate, and render as "" — so the settings form showed an empty
            # label over a configured one and Save then wiped it.  The str()
            # probe inside is guarded: a YAML hex/octal over-cap integer
            # (exempt from the digit cap at parse time) answers "" instead of
            # ValueError'ing this whole endpoint.
            "url": (ollama_svc.settings_text(ollama.get("url")).strip().rstrip("/")
                    or ollama_svc.DEFAULT_URL),
            "label": ollama_svc.settings_text(ollama.get("label")).strip(),
        },
        "paths": {"docker": _text(DOCKER), "orb": _text(ORB)},
        # No ``or []``: the truthiness probe reflects into the stored value's
        # own ``__bool__``/``__len__``, so a leftover bomb riding ``stacks`` /
        # ``log_sources`` / ``groups_order`` (a non-list ``__bool__`` bomb, a
        # list *subclass* whose ``__len__`` raises, a dict-subclass
        # ``__bool__`` bomb) used to 500 GET /api/settings before _json_list
        # ever saw it.  _json_list already answers ``[]`` for None and every
        # non-list leftover, and degrades an unanswerable list subclass to
        # ``[]`` through _jsonable's guarded ``list(...)``.
        "stacks": _json_list(data.get("stacks")),
        "log_sources": _json_list(data.get("log_sources")),
        "groups_order": _json_list(data.get("groups_order")),
        "version": __version__,
    }


@router.get("/api/settings")
def get_settings():
    return _public_settings()


@router.put("/api/settings")
def put_settings(body: SettingsPatch, request: Request = None):
    patch: dict[str, Any] = {}
    if body.host_ip is not None:
        patch["host_ip"] = body.host_ip.strip()
    if body.metrics_interval is not None:
        patch["metrics_interval"] = body.metrics_interval
    if body.alert_interval is not None:
        patch["alert_interval"] = body.alert_interval
    if body.resource_mode is not None:
        if body.resource_mode not in ("low", "high"):
            raise api_error("settings.invalid_resource_mode", mode=body.resource_mode)
        patch["resource_mode"] = body.resource_mode
    if body.auth is not None:
        # ServerHub exposes host/container administration. Authentication is a
        # non-disableable safety boundary, and loopback callers use a dedicated
        # bearer token rather than network identity.
        if body.auth.enabled is False:
            raise api_error("auth.cannot_disable")
        if body.auth.allow_localhost is True:
            raise api_error("auth.local_token_required")
        patch["auth"] = {"enabled": True, "allow_localhost": False}
    if body.notify is not None:
        n = {k: v for k, v in body.notify.model_dump().items() if v is not None}
        if n.get("ha_token") == "":
            del n["ha_token"]
        if n.get("ha_webhook_url") == "":
            del n["ha_webhook_url"]
        patch["notify"] = n
    if body.ui is not None:
        ui_patch: dict[str, Any] = {}
        if body.ui.locale is not None:
            if body.ui.locale not in _ALLOWED_LOCALES:
                raise api_error("settings.invalid_locale", locale=body.ui.locale)
            ui_patch["locale"] = body.ui.locale
        if body.ui.theme is not None:
            if body.ui.theme not in _ALLOWED_THEMES:
                raise api_error("settings.invalid_theme", theme=body.ui.theme)
            ui_patch["theme"] = body.ui.theme
        if body.ui.density is not None:
            if body.ui.density not in _ALLOWED_DENSITY:
                raise api_error("settings.invalid_density", density=body.ui.density)
            ui_patch["density"] = body.ui.density
        if ui_patch:
            # merge with existing ui
            cur = dict(settings_section("ui"))
            cur.update(ui_patch)
            patch["ui"] = cur
    if body.adaptive is not None:
        patch["adaptive"] = bool(body.adaptive)
    if body.thresholds is not None:
        th = {k: v for k, v in body.thresholds.model_dump().items() if v is not None}
        if th:
            cur_th = dict(settings_section("thresholds"))
            cur_th.update(th)
            patch["thresholds"] = cur_th
    if body.ip_aliases is not None:
        al = {k: v for k, v in body.ip_aliases.model_dump().items() if v is not None}
        if al:
            cur_al = dict(settings_section("ip_aliases"))
            cur_al.update(al)
            patch["ip_aliases"] = cur_al
    if body.terminal is not None:
        tm = {k: v for k, v in body.terminal.model_dump().items() if v is not None}
        if tm:
            # _merged_section, not dict()+update: a hostile stored key used
            # to detonate the update's insert probe — a raw 500 on the save.
            patch["terminal"] = _merged_section("terminal", tm)
    if body.ollama is not None:
        o: dict[str, Any] = {}
        if body.ollama.url is not None:
            o["url"] = ollama_svc.validate_settings_url(body.ollama.url)
        if body.ollama.label is not None:
            o["label"] = ollama_svc.validate_settings_label(body.ollama.label)
        if o:
            cur_o = dict(settings_section("ollama"))
            cur_o.update(o)
            patch["ollama"] = cur_o
    if not patch:
        raise api_error("settings.empty_patch")
    update_settings(patch)
    if "notify" in patch:
        # The HA notify config carries a credential (ha_token); a swap through
        # this endpoint must leave the same trail a channel edit does.  Field
        # names only — record() redaction would drop the values anyway.
        audit.record(
            audit.NOTIFY_SETTINGS_CHANGED,
            # FastAPI always injects `request`; the None default only keeps
            # direct in-process calls (tests, tooling) working.
            username=request_username(request) if request is not None else "",
            client=request_client_id(request),
            fields=",".join(sorted(patch["notify"].keys())),
        )
    if "ollama" in patch:
        ollama_svc.status.invalidate()
    if "resource_mode" in patch:
        from hub import tools_svc
        from hub.status import invalidate_status
        # Sidebar/dashboard read the mode off /api/status; a warm snapshot
        # would keep the old poll cadence for the whole status TTL.
        invalidate_status()
        if patch["resource_mode"] == "high":
            tools_svc.start_updates_warmer()
        else:
            tools_svc.stop_updates_warmer()
    return {"ok": True, "settings": _public_settings()}


@router.get("/api/metrics")
def get_metrics(
    minutes: int = 60,
    range_: Optional[str] = Query(None, alias="range"),
    since: Optional[int] = None,
    until: Optional[int] = None,
    points: int = 1500,
):
    """Metrics history.

    Without ``range``/``since`` the legacy contract is untouched (same params,
    same response shape, raw points only) -- external pollers such as the
    menubar keep working.  With ``range`` (48h/30d/1y style) or an explicit
    ``since``[/``until``] epoch window, the tiered store picks the layer
    (raw 90s / 5m / 1h aggregates, see hub/metrics_rollup.py) and caps the
    response at ``points`` samples, decimating on the selected layer if
    needed.  Aggregated points keep the raw field names for the window
    average and add ``<field>_max`` peaks.
    """
    if range_ is None and since is None:
        minutes = max(5, min(minutes, 48 * 60))
        pts = metrics.history(minutes)
        return {"points": pts, "latest": pts[-1] if pts else None}
    now = _epoch(time.time())
    if since is not None:
        start = _epoch(since)
        end = now if until is None else _epoch(until, now)
        if end <= start:
            raise api_error("metrics.bad_window")
    else:
        try:
            span = metrics_rollup.parse_range(range_)
        except ValueError:
            raise api_error("metrics.bad_range")
        end = now
        start = end - span
    cap = max(50, min(points, metrics_rollup.MAX_QUERY_POINTS))
    result = metrics_rollup.query_range(start, end, max_points=cap)
    pts = result["points"]
    return {
        "points": pts,
        "latest": pts[-1] if pts else None,
        "tier": result["tier"],
        "since": start,
        "until": end,
    }


@router.get("/api/alerts")
def get_alerts(limit: int = 50):
    return {"alerts": alerts.list_alerts(limit)}


@router.post("/api/alerts/test")
def test_alert():
    return alerts.test_notify()


@router.post("/api/alerts/check")
def force_check():
    return {"emitted": alerts.check_once()}


#: Keys whose plaintext value is a live secret.  The settings API already hides
#: these behind has_* booleans; the raw export used to hand them out in full as a
#: cached-to-disk attachment.  Redacted on export so a backup file is not a
#: secret store — they must be re-entered after a restore.
_EXPORT_REDACT_KEYS = frozenset({
    "ha_token", "webhook_url", "ha_webhook_url", "password_hash", "psk", "private_key",
})


def _redact_export(node, depth: int = 0):
    # Depth-capped: leftover deeply-nested YAML used to RecursionError the
    # export after yaml.safe_load succeeded (RecursionError is not YAMLError).
    if depth > 64:
        return None
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if not isinstance(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            k = _utf8_text(k)
            if k in _EXPORT_REDACT_KEYS and v:
                out[k] = "***redacted***"
            else:
                out[k] = _redact_export(v, depth + 1)
        return out
    if isinstance(node, list):
        return [_redact_export(v, depth + 1) for v in node]
    if isinstance(node, str):
        return _utf8_text(node)
    return node


@router.get("/api/export/services-yaml")
def export_services_yaml():
    """Download current services.yaml for backup/edit, with secrets redacted."""
    import yaml
    from fastapi.responses import PlainTextResponse
    from hub.paths import CONFIG_FILE

    try:
        from hub.util import read_text_capped

        # load_yaml_int_capped, not yaml.safe_load: PyYAML raises bare
        # ValueError — not YAMLError — building a >4300-digit decimal int,
        # and the corrupt-config refusal below is a 500.  The hex/octal
        # spelling of the same leftover already exports fine (it parses
        # uncapped and _renderable_tree drops it below); the decimal
        # spelling used to block the whole backup download instead.
        from hub.config import _renderable_tree, load_yaml_int_capped

        data = load_yaml_int_capped(
            read_text_capped(CONFIG_FILE, _YAML_CAP, encoding="utf-8")
        ) or {}
        if not isinstance(data, dict):
            raise api_error("system_settings.export_failed")

        # An already-parsed over-cap int (YAML hex loads uncapped through
        # ``int(x, 16)``) fails only the re-dump, after parse and redaction
        # both succeeded.  Refusing the whole backup for one unrenderable
        # leftover bought nothing — drop that node like every read sanitizer
        # does and stream the rest.
        text = yaml.safe_dump(
            _renderable_tree(_redact_export(data)),
            allow_unicode=True, sort_keys=False,
        )
    except (
        OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError,
        TypeError, ValueError, AttributeError, KeyError,
    ):
        # Unparseable or torn config: better to refuse than to stream raw secrets.
        # RecursionError is leftover deeply nested YAML — not YAMLError.
        # TypeError/ValueError/AttributeError/KeyError: leftover ``!!timestamp .inf``,
        # ``2026-13-01``, a 5000-digit int, or ``!!bool 2`` are not YAMLError.
        raise api_error("system_settings.export_failed")
    return PlainTextResponse(
        text,
        media_type="text/yaml; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=services.yaml",
            "Cache-Control": "no-store",
        },
    )


#: Rows the backups page renders.  The list is capped because the page is a table
#: and a NAS accumulates a nightly dump indefinitely, but the total is reported
#: alongside it: truncating in silence is how an operator concludes that the
#: backups older than the cap were deleted.
BACKUP_ROWS = 40


@router.get("/api/backups")
def get_backups():
    found = backups.scan_backups()
    return {
        "backups": found[:BACKUP_ROWS],
        # backup_root_text, not str(): a BACKUP_ROOT under an undecodable
        # HOME carries lone surrogates, and the bare str() used to 500 the
        # whole page at Starlette's UTF-8 encode.
        "root": backups.backup_root_text(),
        "total": len(found),
        "postgres_targets": [
            {"id": t["id"], "db": t["db"], "port": t["port"]}
            for t in backups.pg_targets()
        ],
        "immich": backups.immich_backup_info(),
    }


def _audit_backup_run(kind: str, request: Request | None, result) -> None:
    # A backup reads every byte it protects and writes it somewhere else;
    # "who kicked off the postgres dump at 03:12" must be answerable.
    audit.record(
        audit.BACKUP_RUN,
        username=request_username(request) if request is not None else "",
        client=request_client_id(request),
        kind=kind,
        ok=bool(result.get("ok")) if isinstance(result, dict) else None,
    )


@router.post("/api/backups/postgres")
def do_pg_backup(request: Request = None):
    result = backups.backup_postgres()
    _audit_backup_run("postgres", request, result)
    return result


@router.post("/api/backups/immich")
def do_immich_backup(request: Request = None):
    result = backups.backup_immich()
    _audit_backup_run("immich", request, result)
    return result


@router.post("/api/backups/configs")
def do_cfg_backup(request: Request = None):
    result = backups.backup_configs()
    _audit_backup_run("configs", request, result)
    return result
