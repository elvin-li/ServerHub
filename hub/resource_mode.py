"""Panel resource profile: low (quiet idle) vs high (fresher UI)."""
from __future__ import annotations

from hub.config import cfg

ALLOWED = ("low", "high")
DEFAULT = "low"


def resource_mode() -> str:
    # ``settings: []`` / a scalar used to AttributeError ``.get`` and 500
    # GET /api/status on a cache hit (``_status_ttl`` → ``is_high``) plus
    # GET /api/system/sensors?light=1.  ``_as_config`` sanitizes disk reads;
    # this still has to tolerate a leftover in-memory mapping.
    try:
        settings = cfg().get("settings")
    except Exception:
        settings = {}
    if not isinstance(settings, dict):
        settings = {}
    v = settings.get("resource_mode") or DEFAULT
    return v if v in ALLOWED else DEFAULT


def is_high() -> bool:
    return resource_mode() == "high"
