"""Sites: every web site discovered on this host (read-only).

Mutations stay on the existing guarded routes: nginx test/reload is
POST /api/nginx/test and /api/nginx/reload (audited in modules_api).
"""
from __future__ import annotations

from fastapi import APIRouter

from hub import sites_svc

router = APIRouter(tags=["sites"])


@router.get("/api/sites")
def sites(force: bool = False):
    return sites_svc.list_sites(force=force)


@router.get("/api/sites/{site_id}/config")
def site_config(site_id: str):
    return sites_svc.site_config(site_id)
