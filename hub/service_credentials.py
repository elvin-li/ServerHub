"""Service credential metadata + macOS Keychain storage.

Passwords never enter services.yaml or the metadata index.  The index only
contains usernames, URLs, notes, adapter state and timestamps; the secret is a
generic-password item in the current user's login Keychain.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import threading
import time
from pathlib import Path

from fastapi import HTTPException

from hub.paths import DATA_DIR
from hub.host_address import normalize_local_url
from hub import secure_io

INDEX_FILE = DATA_DIR / "service-credentials.json"
SECURITY = "/usr/bin/security"
HTPASSWD = "/usr/sbin/htpasswd"
TESLAMATE_ROOT = Path.home() / "Services" / "teslamate"
TESLAMATE_HTPASSWD = TESLAMATE_ROOT / ".htpasswd"
TESLAMATE_NGINX_SITE = Path.home() / "Services" / "nginx" / "conf.d" / "20-teslamate.conf"
_lock = threading.RLock()
_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9:_.@/+-]{0,159}$")
_HTTP_USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$")


def _valid_id(service_id: str) -> str:
    value = (service_id or "").strip()
    if not _ID_RE.fullmatch(value) or ".." in value:
        raise HTTPException(400, "非法服务 ID")
    return value


def _keychain_service(service_id: str) -> str:
    digest = hashlib.sha256(service_id.encode("utf-8")).hexdigest()[:24]
    return f"com.serverhub.credential.{digest}"


def _load() -> dict[str, dict]:
    try:
        raw = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _save(items: dict[str, dict]) -> None:
    # Atomic + 0600 from creation: the index holds account names paired with
    # keychain references, and the temp file previously spent the length of the
    # write at umask-derived 0644.
    secure_io.replace_secret_text(
        INDEX_FILE, json.dumps(items, ensure_ascii=False, indent=2) + "\n"
    )


def _security(
    args: list[str], *, timeout: int = 15, password_input: str | None = None
) -> tuple[int, str]:
    try:
        command = [SECURITY, *args]
        stdin = None
        if password_input is not None:
            # `security ... -w` reads from /dev/tty, not a pipe. Use its
            # interactive command channel with hex password data so the secret
            # stays out of both argv and plaintext command input.
            secure_args = [arg for arg in args if arg != "-w"]
            secure_args.extend(["-X", password_input.encode("utf-8").hex()])
            command = [SECURITY, "-i"]
            stdin = " ".join(shlex.quote(arg) for arg in secure_args) + "\n"
        result = subprocess.run(
            command,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, (result.stdout or result.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def _delete_keychain(service: str, username: str) -> None:
    if service and username:
        _security(["delete-generic-password", "-s", service, "-a", username])


def _keychain_has(service: str, username: str) -> bool:
    if not service or not username:
        return False
    rc, _ = _security(["find-generic-password", "-s", service, "-a", username])
    return rc == 0


def store(
    service_id: str,
    *,
    display_name: str,
    username: str,
    password: str,
    url: str = "",
    notes: str = "",
    adapter: str = "generic",
    applied: bool = False,
) -> dict:
    service_id = _valid_id(service_id)
    username = (username or "").strip()
    if not username:
        raise HTTPException(400, "用户名不能为空")
    if len(password or "") < 8:
        raise HTTPException(400, "服务密码至少需要 8 个字符")

    keychain_service = _keychain_service(service_id)
    with _lock:
        items = _load()
        old = items.get(service_id) or {}
        old_user = str(old.get("username") or "")
        rc, message = _security([
            "add-generic-password",
            "-U",
            "-s", keychain_service,
            "-a", username,
            "-l", f"ServerHub · {display_name or service_id}",
            # Keeping -w last makes `security` prompt on stdin instead of
            # exposing the password in the process argument list.
            "-w",
        ], password_input=password)
        if rc != 0:
            raise HTTPException(503, f"无法写入 macOS 钥匙串：{message[:160]}")
        item = {
            "service_id": service_id,
            "display_name": (display_name or service_id).strip()[:120],
            "username": username,
            "url": normalize_local_url(url)[:500],
            "notes": (notes or "").strip()[:1000],
            "adapter": adapter,
            "applied": bool(applied),
            "updated_at": int(time.time()),
        }
        items[service_id] = item
        try:
            _save(items)
        except OSError as exc:
            _delete_keychain(keychain_service, username)
            raise HTTPException(500, f"无法保存凭据索引：{exc}")
        if old_user and old_user != username:
            _delete_keychain(keychain_service, old_user)
        return public_item(item)


def get(service_id: str) -> dict:
    service_id = _valid_id(service_id)
    with _lock:
        item = _load().get(service_id)
    if not item:
        return {
            "service_id": service_id,
            "has_password": False,
            "username": "",
            "url": "",
            "notes": "",
            "adapter": adapter_for(service_id),
            "can_apply": adapter_for(service_id) != "generic",
        }
    result = public_item(item)
    result["has_password"] = _keychain_has(
        _keychain_service(service_id), str(item.get("username") or "")
    )
    return result


def public_item(item: dict) -> dict:
    service_id = str(item.get("service_id") or "")
    adapter = str(item.get("adapter") or adapter_for(service_id))
    return {
        "service_id": service_id,
        "display_name": item.get("display_name") or service_id,
        "username": item.get("username") or "",
        "url": item.get("url") or "",
        "notes": item.get("notes") or "",
        "adapter": adapter,
        "can_apply": adapter != "generic",
        "applied": bool(item.get("applied")),
        "has_password": True,
        "updated_at": item.get("updated_at"),
    }


def delete(service_id: str) -> dict:
    service_id = _valid_id(service_id)
    with _lock:
        items = _load()
        item = items.pop(service_id, None)
        if not item:
            return {"ok": True, "deleted": False}
        _delete_keychain(_keychain_service(service_id), str(item.get("username") or ""))
        _save(items)
    return {"ok": True, "deleted": True}


def adapter_for(service_id: str) -> str:
    value = (service_id or "").lower()
    if value in {
        "native:native-filebrowser", "native-filebrowser",
        "local.filebrowser", "filebrowser",
    }:
        return "filebrowser"
    if value in {"docker:teslamate", "teslamate"}:
        return "teslamate-basic-auth"
    return "generic"


def apply_filebrowser(username: str, password: str) -> dict:
    """Update File Browser through its official CLI, preserving run state."""
    from hub import files_svc
    from hub.util import sh

    # The username is a bare positional in a pflag CLI, so a value starting with
    # "-" is parsed as an option instead.  _HTTP_USER_RE (used on the teslamate
    # path below) requires a leading alphanumeric, which makes that
    # unrepresentable; it simply had not been applied here.
    username = (username or "").strip()
    if not _HTTP_USER_RE.fullmatch(username):
        raise HTTPException(400, "用户名只能包含字母、数字与 . _ @ + -，且需以字母或数字开头")
    if not files_svc.FB_BIN.exists() or not files_svc.FB_DB.exists():
        raise HTTPException(404, "未安装 File Browser 或数据库不存在")
    was_running = bool(files_svc.filebrowser_status().get("running"))
    if was_running:
        stopped = files_svc.stop_filebrowser()
        if stopped.get("running"):
            raise HTTPException(503, "无法暂停 File Browser，未修改密码")
    try:
        rc, out, err = sh([
            str(files_svc.FB_BIN),
            "users", "update", username,
            "--password", password,
            "-d", str(files_svc.FB_DB),
        ], timeout=30)
        if rc != 0:
            message = (err or out or "File Browser 拒绝修改密码").strip().replace(password, "***")
            raise HTTPException(400, message[:300])
        return {"ok": True, "message": "File Browser 登录密码已更新"}
    finally:
        if was_running:
            files_svc.ensure_filebrowser()


def apply_teslamate(username: str, password: str) -> dict:
    """Replace TeslaMate's Nginx Basic Auth user without exposing the secret."""
    if not _HTTP_USER_RE.fullmatch((username or "").strip()):
        raise HTTPException(400, "TeslaMate 用户名仅支持字母、数字及 . _ @ + -")
    if not TESLAMATE_NGINX_SITE.is_file():
        raise HTTPException(409, "TeslaMate 密码网关尚未安装")

    result = subprocess.run(
        # Nginx on macOS cannot validate Apache's $2y$ bcrypt records because
        # the platform crypt(3) lacks Blowfish; $apr1$ is supported natively.
        [HTPASSWD, "-ni", username],
        input=password + "\n",
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    entry = (result.stdout or "").strip()
    if result.returncode != 0 or not entry.startswith(username + ":"):
        message = (result.stderr or "无法生成 TeslaMate 密码摘要").strip()
        raise HTTPException(503, message[:200])

    with _lock:
        old = TESLAMATE_HTPASSWD.read_bytes() if TESLAMATE_HTPASSWD.exists() else None
        tmp = TESLAMATE_HTPASSWD.with_suffix(".tmp")
        try:
            TESLAMATE_HTPASSWD.parent.mkdir(parents=True, exist_ok=True)
            secure_io.write_secret_text(tmp, entry + "\n")
            os.replace(tmp, TESLAMATE_HTPASSWD)
            os.chmod(TESLAMATE_HTPASSWD, 0o600)

            from hub import nginx_svc
            reloaded = nginx_svc.reload_nginx()
            if not reloaded.get("ok"):
                raise RuntimeError(str(reloaded.get("message") or "Nginx 重载失败"))
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            if old is None:
                TESLAMATE_HTPASSWD.unlink(missing_ok=True)
            else:
                secure_io.write_secret_text(TESLAMATE_HTPASSWD, old.decode("utf-8", errors="replace"))
            raise HTTPException(503, f"TeslaMate 密码未生效，已回滚：{str(exc)[:180]}")

    return {"ok": True, "message": "TeslaMate 4000 端口访问密码已更新"}


def apply(service_id: str, username: str, password: str) -> dict:
    adapter = adapter_for(_valid_id(service_id))
    if adapter == "filebrowser":
        return apply_filebrowser(username, password)
    if adapter == "teslamate-basic-auth":
        return apply_teslamate(username, password)
    raise HTTPException(400, "该插件暂不支持自动改密，可仅保存凭据")
