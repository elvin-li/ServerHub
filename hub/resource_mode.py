"""Panel resource profile: low (quiet idle) vs high (fresher UI)."""
from __future__ import annotations

from hub.config import cfg

ALLOWED = ("low", "high")
DEFAULT = "low"


def resource_mode() -> str:
    v = (cfg().get("settings") or {}).get("resource_mode") or DEFAULT
    return v if v in ALLOWED else DEFAULT


def is_high() -> bool:
    return resource_mode() == "high"
