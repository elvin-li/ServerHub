"""Dockge-inspired compose stack YAML read/write/validate."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from fastapi import HTTPException

from hub.containers_svc import _stack_paths
from hub.paths import DOCKER
from hub.status import invalidate_status as inv


def _find_stack(stack_id: str) -> dict:
    for s in _stack_paths():
        if s.get("id") == stack_id:
            return s
    raise HTTPException(404, f"unknown stack: {stack_id}")


def get_compose(stack_id: str) -> dict:
    s = _find_stack(stack_id)
    path = s.get("compose_path")
    if not path or not Path(path).is_file():
        raise HTTPException(400, "stack has no compose file")
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return {
        "id": s["id"],
        "name": s.get("name") or s["id"],
        "path": s.get("path"),
        "compose_path": path,
        "content": text,
        "size": len(text),
        "mtime": int(Path(path).stat().st_mtime),
    }


def save_compose(stack_id: str, content: str, validate: bool = True) -> dict:
    s = _find_stack(stack_id)
    path = s.get("compose_path")
    if not path:
        raise HTTPException(400, "stack has no compose file")
    if not content or not content.strip():
        raise HTTPException(400, "empty content")
    # basic safety: no path escape in content writing
    p = Path(path).resolve()
    services_root = (Path.home() / "Services").resolve()
    if services_root not in p.parents and p.parent != services_root:
        # allow only under ~/Services
        raise HTTPException(403, "compose path must be under ~/Services")
    if validate:
        v = validate_compose_text(content, cwd=str(p.parent))
        if not v.get("ok"):
            raise HTTPException(400, v.get("message") or "compose invalid")
    # backup
    bak = p.with_suffix(p.suffix + ".bak")
    if p.exists():
        bak.write_text(p.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        bak.chmod(0o600)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(p)
    inv()
    return {"ok": True, "path": str(p), "message": "已保存", "backup": str(bak)}


def validate_compose_text(content: str, cwd: str | None = None) -> dict:
    """docker compose config -q via temp file."""
    import tempfile
    work = cwd or str(Path.home() / "Services")
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yml", delete=False, dir=work, encoding="utf-8"
        ) as f:
            f.write(content)
            tmp = f.name
        try:
            p = subprocess.run(
                [DOCKER, "compose", "-f", tmp, "config", "-q"],
                cwd=work,
                capture_output=True,
                text=True,
                timeout=30,
                env={**os.environ, "PATH": "/opt/homebrew/bin:/usr/local/bin:" + os.environ.get("PATH", "")},
            )
            ok = p.returncode == 0
            return {
                "ok": ok,
                "message": (p.stderr or p.stdout or ("valid" if ok else "invalid")).strip()[:800],
            }
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    except Exception as e:
        return {"ok": False, "message": str(e)}


def validate_stack(stack_id: str) -> dict:
    data = get_compose(stack_id)
    return validate_compose_text(data["content"], cwd=data.get("path"))


def create_stack(stack_id: str, name: str | None, content: str) -> dict:
    """Create new stack under ~/Services/<id>/docker-compose.yml"""
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,40}$", stack_id):
        raise HTTPException(400, "stack id: alphanumeric/underscore/dash")
    root = Path.home() / "Services" / stack_id
    if root.exists() and (root / "docker-compose.yml").exists():
        raise HTTPException(409, f"already exists: {root}")
    v = validate_compose_text(content, cwd=str(Path.home() / "Services"))
    if not v.get("ok"):
        raise HTTPException(400, v.get("message") or "invalid compose")
    root.mkdir(parents=True, exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    compose = root / "docker-compose.yml"
    compose.write_text(content, encoding="utf-8")
    compose.chmod(0o600)
    # register in services.yaml stacks if not present
    from hub.config import cfg, save_full
    import copy
    data = copy.deepcopy(cfg())
    stacks = data.get("stacks") or []
    if not any(s.get("id") == stack_id for s in stacks):
        stacks.append({
            "id": stack_id,
            "name": name or stack_id,
            "path": str(root),
            "compose_file": "docker-compose.yml",
        })
        data["stacks"] = stacks
        save_full(data)
    inv()
    return {"ok": True, "path": str(compose), "id": stack_id}
