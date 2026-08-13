"""UPS / battery status and alert-policy endpoints."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from hub import ups_svc
from hub.errors import api_error

router = APIRouter(tags=["ups"])


class UpsSettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alerts_enabled: Optional[bool] = None
    #: Kept away from the extremes: 100 would alert on every discharge sample
    #: and 0 would never fire before macOS's own halt level does.
    low_battery_pct: Optional[int] = Field(None, ge=5, le=95)


@router.get("/api/ups")
def get_ups(force: bool = False):
    return ups_svc.ups_status(force=force)


@router.put("/api/ups/settings")
def put_ups_settings(body: UpsSettingsPatch):
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    if not patch:
        raise api_error("ups.empty_patch")
    ups_svc.save_ups_settings(patch)
    return {"ok": True, "ups": ups_svc.ups_status()}
