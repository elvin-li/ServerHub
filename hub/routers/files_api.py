"""File manager APIs — lazy, no background worker."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, File, Form, Request, UploadFile
from pydantic import BaseModel

from hub import audit, auth, files_svc

router = APIRouter(tags=["files"])


def _audit_write(request: Request | None, action: str, **fields) -> None:
    """One line per file-manager write.  Deletes and renames are destructive
    and uploads plant arbitrary content; the listing/download reads are not
    recorded.  FastAPI always injects `request`; the None guard only keeps
    direct in-process calls (tests, tooling) working."""
    audit.record(
        audit.FILES_CHANGED,
        username=auth.request_username(request) if request is not None else "",
        client=auth.request_client_id(request),
        action=action,
        **fields,
    )


class PathBody(BaseModel):
    path: str
    root_id: Optional[str] = None


class MkdirBody(BaseModel):
    path: str
    name: str
    root_id: Optional[str] = None


class RenameBody(BaseModel):
    path: str
    new_name: str
    root_id: Optional[str] = None


class OndemandBody(BaseModel):
    enabled: bool = True


@router.get("/api/files")
def files_overview():
    return files_svc.overview()


@router.get("/api/files/list")
def files_list(path: Optional[str] = None, root_id: Optional[str] = None):
    return files_svc.list_dir(path=path, root_id=root_id)


@router.post("/api/files/mkdir")
def files_mkdir(body: MkdirBody, request: Request = None):
    result = files_svc.mkdir(body.path, body.name, root_id=body.root_id)
    _audit_write(request, "mkdir", path=body.path, name=body.name)
    return result


@router.post("/api/files/delete")
def files_delete(body: PathBody, request: Request = None):
    result = files_svc.delete_path(body.path, root_id=body.root_id)
    _audit_write(request, "delete", path=body.path)
    return result


@router.post("/api/files/rename")
def files_rename(body: RenameBody, request: Request = None):
    result = files_svc.rename_path(body.path, body.new_name, root_id=body.root_id)
    _audit_write(request, "rename", path=body.path, new_name=body.new_name)
    return result


@router.get("/api/files/download")
def files_download(path: str, root_id: Optional[str] = None):
    return files_svc.download(path, root_id=root_id)


@router.post("/api/files/upload")
async def files_upload(
    request: Request,
    path: str = Form(...),
    root_id: Optional[str] = Form(None),
    file: UploadFile = File(...),
):
    result = await files_svc.upload(path, file, root_id=root_id)
    _audit_write(request, "upload", path=path, name=file.filename or "")
    return result


@router.get("/api/files/filebrowser")
def fb_status():
    return files_svc.filebrowser_status()


@router.post("/api/files/filebrowser/ensure")
def fb_ensure(request: Request = None):
    result = files_svc.ensure_filebrowser()
    _audit_write(request, "filebrowser_start")
    return result


@router.post("/api/files/filebrowser/stop")
def fb_stop(request: Request = None):
    result = files_svc.stop_filebrowser()
    _audit_write(request, "filebrowser_stop")
    return result


@router.post("/api/files/filebrowser/ondemand")
def fb_ondemand(body: OndemandBody, request: Request = None):
    result = files_svc.set_filebrowser_ondemand(body.enabled)
    _audit_write(request, "filebrowser_ondemand", enabled=bool(body.enabled))
    return result
