from __future__ import annotations

from fastapi import APIRouter

from hub import shares_svc

router = APIRouter(tags=["shares"])


@router.get("/api/shares")
def shares():
    return shares_svc.shares_overview()
