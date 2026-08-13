"""UPS / battery status, alert-policy and safe-shutdown endpoints."""
from __future__ import annotations

import re
from typing import List, Literal, Optional, Union

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from hub import audit, macos_admin, ups_policy, ups_svc
from hub.errors import api_error
from hub.routers.nas_common import (
    client_host,
    raise_for_admin_result,
    require_admin_browser,
)

router = APIRouter(tags=["ups"])

#: Stack / service ids that may enter the policy config.  They end up in a
#: state file and (via the stack catalog lookup) select a compose path, so
#: junk stays out at the API boundary.
_TARGET_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class UpsShutdownPatch(BaseModel):
    """settings.ups.shutdown — the soft-landing policy (hub/ups_policy.py).

    ``trigger_pct`` / ``trigger_remaining_min`` accept an explicit ``null``
    to switch that condition off, which is why provided-vs-absent is decided
    by ``model_dump(exclude_unset=True)`` rather than a None filter.
    """
    model_config = ConfigDict(extra="forbid")

    enabled: Optional[bool] = None
    trigger_pct: Optional[int] = Field(None, ge=5, le=95)
    trigger_remaining_min: Optional[int] = Field(None, ge=1, le=720)
    require_both: Optional[bool] = None
    stacks: Optional[Union[Literal["all"], List[str]]] = None
    stop_scripts: Optional[List[str]] = None


class UpsSettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alerts_enabled: Optional[bool] = None
    #: Kept away from the extremes: 100 would alert on every discharge sample
    #: and 0 would never fire before macOS's own halt level does.
    low_battery_pct: Optional[int] = Field(None, ge=5, le=95)
    shutdown: Optional[UpsShutdownPatch] = None


class UpsHaltPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: pmset semantics: -1 switches the level off; anything else is the
    #: battery percentage at which macOS itself performs an emergency halt.
    haltlevel: int


@router.get("/api/ups")
def get_ups(force: bool = False):
    return {**ups_svc.ups_status(force=force),
            "shutdown_state": ups_policy.public_state()}


def _checked_targets(ids: List[str]) -> List[str]:
    for sid in ids:
        if not _TARGET_ID_RE.match(sid or ""):
            raise api_error("ups.bad_stack_id", id=str(sid)[:80])
    return ids


@router.put("/api/ups/settings")
def put_ups_settings(body: UpsSettingsPatch, request: Request):
    patch = body.model_dump(exclude_unset=True)
    shutdown = patch.get("shutdown")
    if shutdown is not None:
        if isinstance(shutdown.get("stacks"), list):
            _checked_targets(shutdown["stacks"])
        if shutdown.get("stop_scripts") is not None:
            _checked_targets(shutdown["stop_scripts"])
        # Refuse the shape that silently never fires: enabled with both
        # trigger conditions off.  Judged on the *effective* result of the
        # merge, so switching the last condition off under an enabled policy
        # is caught the same way as enabling a condition-less one.
        effective = {**ups_svc.ups_settings()["shutdown"], **shutdown}
        if effective.get("enabled") and effective.get("trigger_pct") is None \
                and effective.get("trigger_remaining_min") is None:
            raise api_error("ups.policy_no_condition")
    if not patch:
        raise api_error("ups.empty_patch")
    saved = ups_svc.save_ups_settings(patch)
    if shutdown is not None:
        # The policy stops real workloads unattended, so a change to what it
        # may do names the operator (browser session; admin API keys record
        # an empty username, same as everywhere else).
        from hub import auth
        audit.record(audit.UPS_POLICY_CHANGED,
                     username=auth.request_username(request),
                     client=client_host(request),
                     shutdown=saved.get("shutdown"))
    return {"ok": True, "ups": {**ups_svc.ups_status(),
                                "shutdown_state": ups_policy.public_state()}}


@router.get("/api/ups/shutdown/plan")
def get_shutdown_plan():
    """Resolved action sequence + catalogs, for the settings form.

    Same payload as the drill, minus the audit record: this backs the form's
    stack/script pickers and re-renders on tab load, which should not spam
    the audit trail the way a deliberate button press legitimately does.
    """
    return ups_policy.drill()


@router.post("/api/ups/shutdown/drill")
def run_shutdown_drill(request: Request):
    """Simulate a power loss: report the exact sequence, execute nothing.

    Admin + browser-session gated like the other operational endpoints, and
    audited — a drill is an operator declaring "I checked what this box will
    do when the power dies", which is worth a line in the trail.
    """
    username = require_admin_browser(request)
    result = ups_policy.drill()
    audit.record(audit.UPS_POLICY_DRILL,
                 username=username,
                 client=client_host(request),
                 would_trigger_now=result.get("would_trigger_now"),
                 steps=[
                     {"kind": s.get("kind"), "id": s.get("id"), "running": s.get("running")}
                     for s in result.get("steps") or []
                 ])
    return result


@router.put("/api/ups/halt")
def put_halt_level(body: UpsHaltPatch, request: Request):
    """Write the macOS UPS emergency-halt level (``pmset -u haltlevel``).

    This is the OS's own last line of defense behind the panel's soft
    landing; writing it needs root, so the request rides the existing admin
    authorization flow (web-entered password → sudo -S, or a passwordless
    sudoers rule).  The panel itself never runs ``shutdown``.

    macOS ignores these thresholds on machines with an internal battery
    (laptops) — the UI says so rather than this endpoint refusing, because
    pmset accepts and stores the value regardless.
    """
    username = require_admin_browser(request)
    level = int(body.haltlevel)
    if level != -1 and not (5 <= level <= 95):
        raise api_error("ups.halt_bad_level")
    result = macos_admin.run_admin(
        ["/usr/bin/pmset", "-u", "haltlevel", str(level)], timeout=30,
    )
    raise_for_admin_result(result)
    audit.record(audit.UPS_HALT_CHANGED,
                 username=username, client=client_host(request), haltlevel=level)
    # Re-read so the response reflects what pmset now reports.  With no UPS
    # attached `pmset -g ups` prints nothing even after a successful write,
    # so the fresh snapshot — not a verify-else-fail — is the honest answer.
    return {"ok": True, "ups": {**ups_svc.ups_status(force=True),
                                "shutdown_state": ups_policy.public_state()}}
