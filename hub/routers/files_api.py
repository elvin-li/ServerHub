"""File manager APIs — lazy, no background worker."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, File, Form, UploadFile
from pydantic import BaseModel

from hub import files_svc

router = APIRouter(tags=["files"])


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
def files_mkdir(body: MkdirBody):
    return files_svc.mkdir(body.path, body.name, root_id=body.root_id)


@router.post("/api/files/delete")
def files_delete(body: PathBody):
    return files_svc.delete_path(body.path, root_id=body.root_id)


@router.post("/api/files/rename")
def files_rename(body: RenameBody):
    return files_svc.rename_path(body.path, body.new_name, root_id=body.root_id)


@router.get("/api/files/download")
def files_download(path: str, root_id: Optional[str] = None):
    return files_svc.download(path, root_id=root_id)


@router.post("/api/files/upload")
async def files_upload(
    path: str = Form(...),
    root_id: Optional[str] = Form(None),
    file: UploadFile = File(...),
):
    return await files_svc.upload(path, file, root_id=root_id)


@router.get("/api/files/filebrowser")
def fb_status():
    return files_svc.filebrowser_status()


@router.post("/api/files/filebrowser/ensure")
def fb_ensure():
    return files_svc.ensure_filebrowser()


@router.post("/api/files/filebrowser/stop")
def fb_stop():
    return files_svc.stop_filebrowser()


@router.post("/api/files/filebrowser/ondemand")
def fb_ondemand(body: OndemandBody):
    return files_svc.set_filebrowser_ondemand(body.enabled)
