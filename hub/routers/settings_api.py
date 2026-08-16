from __future__ import annotations

import time
from typing import Any, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict, Field

from hub import __version__, alerts, backups, metrics, metrics_rollup, ollama_svc
from hub.auth import auth_enabled
from hub.config import cfg, update_settings
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
    theme: Optional[str] = None  # system | unraid | unraid-dark | omv | docker | nord | glass | mono
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
    "system", "unraid", "unraid-dark", "omv", "docker", "nord", "glass", "mono",
}
_ALLOWED_DENSITY = {"compact", "comfortable", "cozy"}


def _public_settings() -> dict:
    s = cfg().get("settings") or {}
    auth = s.get("auth") or {}
    notify = s.get("notify") or {}
    ui = s.get("ui") or {}
    return {
        "host_ip": host_ip(),
        "host_ip_config": configured_host(),
        "auth": {
            "enabled": auth_enabled(),
            # Loopback transport is never identity. Native clients authenticate
            # with the dedicated mode-0600 token instead.
            "allow_localhost": False,
            "username": auth.get("username") or "admin",
            "has_password": bool(auth.get("password_hash") or (auth.get("password") and auth.get("password") != "change-me")),
        },
        "notify": {
            "enabled": bool(notify.get("enabled")),
            "include_warn": bool(notify.get("include_warn")),
            "notify_resolve": notify.get("notify_resolve", True),
            "ha_url": notify.get("ha_url") or "http://localhost:8123",
            "ha_service": notify.get("ha_service") or "notify.notify",
            "has_token": bool(notify.get("ha_token")),
            "has_webhook": bool(
                notify.get("ha_webhook_url") or notify.get("webhook_url")
            ),
        },
        "ui": {
            "locale": ui.get("locale") or "zh-CN",
            "theme": ui.get("theme") or "system",
            "density": ui.get("density") or "compact",
        },
        "metrics_interval": s.get("metrics_interval", 90),
        "alert_interval": s.get("alert_interval", 90),
        "resource_mode": (
            s.get("resource_mode") if s.get("resource_mode") in ("low", "high") else "low"
        ),
        "adaptive": s.get("adaptive", True),
        "thresholds": {
            "enabled": (s.get("thresholds") or {}).get("enabled", True),
            "cpu_pct": (s.get("thresholds") or {}).get("cpu_pct", 90),
            "mem_pct": (s.get("thresholds") or {}).get("mem_pct", 90),
            "disk_pct": (s.get("thresholds") or {}).get("disk_pct", 90),
            "cooldown_sec": (s.get("thresholds") or {}).get("cooldown_sec", 1800),
            # Enumerated, not spread, so the read side has to be extended with the
            # write side: without these four the settings page can PUT a SMART
            # threshold but never reads back what it saved.
            "smart_enabled": (s.get("thresholds") or {}).get("smart_enabled", True),
            "smart_temp_c": (s.get("thresholds") or {}).get("smart_temp_c", 60),
            "smart_wear_pct": (s.get("thresholds") or {}).get("smart_wear_pct", 90),
            "smart_spare_pct": (s.get("thresholds") or {}).get("smart_spare_pct", 10),
        },
        "ip_aliases": s.get("ip_aliases") or {},
        # Host terminal is RCE on this machine, so it ships off and the UI needs
        # to know the current state to render the gate honestly.
        "terminal": {
            "host_enabled": bool((s.get("terminal") or {}).get("host_enabled", False)),
        },
        "ollama": {
            "url": str((s.get("ollama") or {}).get("url") or ollama_svc.DEFAULT_URL).rstrip("/"),
            "label": str((s.get("ollama") or {}).get("label") or ""),
        },
        "paths": {"docker": DOCKER, "orb": ORB},
        "stacks": cfg().get("stacks") or [],
        "log_sources": cfg().get("log_sources") or [],
        "groups_order": cfg().get("groups_order") or [],
        "version": __version__,
    }


@router.get("/api/settings")
def get_settings():
    return _public_settings()


@router.put("/api/settings")
def put_settings(body: SettingsPatch):
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
            cur = dict((cfg().get("settings") or {}).get("ui") or {})
            cur.update(ui_patch)
            patch["ui"] = cur
    if body.adaptive is not None:
        patch["adaptive"] = bool(body.adaptive)
    if body.thresholds is not None:
        th = {k: v for k, v in body.thresholds.model_dump().items() if v is not None}
        if th:
            cur_th = dict((cfg().get("settings") or {}).get("thresholds") or {})
            cur_th.update(th)
            patch["thresholds"] = cur_th
    if body.ip_aliases is not None:
        al = {k: v for k, v in body.ip_aliases.model_dump().items() if v is not None}
        if al:
            cur_al = dict((cfg().get("settings") or {}).get("ip_aliases") or {})
            cur_al.update(al)
            patch["ip_aliases"] = cur_al
    if body.terminal is not None:
        tm = {k: v for k, v in body.terminal.model_dump().items() if v is not None}
        if tm:
            cur_tm = dict((cfg().get("settings") or {}).get("terminal") or {})
            cur_tm.update(tm)
            patch["terminal"] = cur_tm
    if body.ollama is not None:
        o: dict[str, Any] = {}
        if body.ollama.url is not None:
            o["url"] = ollama_svc.validate_settings_url(body.ollama.url)
        if body.ollama.label is not None:
            o["label"] = ollama_svc.validate_settings_label(body.ollama.label)
        if o:
            cur_o = dict((cfg().get("settings") or {}).get("ollama") or {})
            cur_o.update(o)
            patch["ollama"] = cur_o
    if not patch:
        raise api_error("settings.empty_patch")
    update_settings(patch)
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
    now = int(time.time())
    if since is not None:
        start = int(since)
        end = int(until) if until is not None else now
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


def _redact_export(node):
    if isinstance(node, dict):
        return {
            k: ("***redacted***" if k in _EXPORT_REDACT_KEYS and v else _redact_export(v))
            for k, v in node.items()
        }
    if isinstance(node, list):
        return [_redact_export(v) for v in node]
    return node


@router.get("/api/export/services-yaml")
def export_services_yaml():
    """Download current services.yaml for backup/edit, with secrets redacted."""
    import yaml
    from fastapi.responses import PlainTextResponse
    from hub.paths import CONFIG_FILE

    try:
        data = yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8")) or {}
        text = yaml.safe_dump(_redact_export(data), allow_unicode=True, sort_keys=False)
    except yaml.YAMLError:
        # Unparseable config: better to refuse than to stream raw secrets.
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
        "root": str(backups.BACKUP_ROOT),
        "total": len(found),
        "postgres_targets": [
            {"id": t["id"], "db": t["db"], "port": t["port"]}
            for t in backups.pg_targets()
        ],
        "immich": backups.immich_backup_info(),
    }


@router.post("/api/backups/postgres")
def do_pg_backup():
    return backups.backup_postgres()


@router.post("/api/backups/immich")
def do_immich_backup():
    return backups.backup_immich()


@router.post("/api/backups/configs")
def do_cfg_backup():
    return backups.backup_configs()
