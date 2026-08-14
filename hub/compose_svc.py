"""Dockge-inspired compose stack YAML read/write/validate."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

from fastapi import HTTPException

from hub import secure_io
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
    # A compose file carries the generated database and admin passwords for the
    # stack, which is the payload secure_io was written for.  write_text() then
    # chmod() creates the file at the umask default -- 0644 here -- so both the
    # backup and the new content were world-readable for the length of the write.
    # replace_secret_text does the same temp-file-then-rename atomically, with the
    # restrictive mode applied from the first byte.
    bak = p.with_suffix(p.suffix + ".bak")
    if p.exists():
        secure_io.write_secret_text(
            bak, p.read_text(encoding="utf-8", errors="replace")
        )
    secure_io.replace_secret_text(p, content)
    inv()
    return {"ok": True, "path": str(p), "message": "已保存", "backup": str(bak)}


def validate_compose_text(content: str, cwd: str | None = None) -> dict:
    """docker compose config -q via a 0600 temp file."""
    work = cwd or str(Path.home() / "Services")
    tmp_path: Path | None = None
    fd = -1
    try:
        Path(work).mkdir(parents=True, exist_ok=True)
        # Compose text routinely embeds generated DB/admin passwords.  Write
        # through the mkstemp fd with an explicit 0600 mode so the bytes are
        # never world-readable in ~/Services, and never re-open the path
        # (which would race a symlink planted between create and write).
        fd, tmp_name = tempfile.mkstemp(suffix=".yml", prefix=".compose-validate-", dir=work)
        tmp_path = Path(tmp_name)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(content)
        p = subprocess.run(
            [DOCKER, "compose", "-f", str(tmp_path), "config", "-q"],
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
    except Exception as e:
        return {"ok": False, "message": str(e)}
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except OSError:
                pass


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
    # 0600 from creation: the content routinely contains generated credentials.
    secure_io.write_secret_text(compose, content)
    # Register in services.yaml stacks if not present, through config.mutate: it
    # re-reads inside the write lock, so this only ever *adds* the stack.  The old
    # save_full(deepcopy(cfg())) wrote a snapshot taken before the lock was held,
    # reverting whatever another process had committed since -- routine, not rare,
    # on a machine running the packaged app alongside a source checkout.
    from hub.config import mutate

    def apply(data: dict) -> None:
        stacks = data.setdefault("stacks", [])
        if any(entry.get("id") == stack_id for entry in stacks):
            return
        stacks.append({
            "id": stack_id,
            "name": name or stack_id,
            "path": str(root),
            "compose_file": "docker-compose.yml",
        })

    mutate(apply)
    inv()
    return {"ok": True, "path": str(compose), "id": stack_id}
