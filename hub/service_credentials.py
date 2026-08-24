"""Service credential metadata + macOS Keychain storage.

Passwords never enter services.yaml or the metadata index.  The index only
contains usernames, URLs, notes, adapter state and timestamps; the secret is a
generic-password item in the current user's login Keychain.
"""
from __future__ import annotations

import errno
import hashlib
import json
import re
import shlex
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from hub.cli_args import as_argv
from hub.errors import api_error
from hub.paths import DATA_DIR, user_home
from hub.host_address import normalize_local_url
from hub import secure_io
from hub.util import read_bytes_capped, read_text_capped, safe_json_loads, utf8_env

INDEX_FILE = DATA_DIR / "service-credentials.json"
#: Leftover multi-MB service-credentials.json used to OOM GET /api/apps/credentials.
_INDEX_CAP = 256 * 1024
SECURITY = "/usr/bin/security"
HTPASSWD = "/usr/sbin/htpasswd"


def _home_dir() -> Path:
    """Best-effort HOME.  ``Path.home()`` leftover used to 500 import."""
    return user_home() or Path("/var/empty/serverhub-credentials")


_HOME = _home_dir()
TESLAMATE_ROOT = _HOME / "Services" / "teslamate"
TESLAMATE_HTPASSWD = TESLAMATE_ROOT / ".htpasswd"
TESLAMATE_NGINX_SITE = _HOME / "Services" / "nginx" / "conf.d" / "20-teslamate.conf"
_lock = threading.RLock()
_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9:_.@/+-]{0,159}$")
#: Per-stream cap for ``security`` / ``htpasswd``.  ``capture_output=True``
#: used to keep the whole pipe in RAM until exit.
_CRED_CAP = 4096
#: One ``user:hash`` line.  Leftover multi-MB ``.htpasswd`` used to OOM
#: PUT /api/apps/credentials for TeslaMate.
_HTPASSWD_CAP = 16 * 1024


def _stamp_now() -> int:
    """``int(time.time())`` OverflowError on leftover inf used to 500 PUT credentials."""
    try:
        n = int(time.time())
    except (TypeError, ValueError, OverflowError):
        return 0
    return n if n >= 0 else 0


def _as_text(val) -> str:
    """JSON-safe text. Leftover ``\\ud800`` used to 500 GET /api/apps/credentials."""
    if val is None:
        return ""
    if isinstance(val, (bytes, bytearray)):
        val = val.decode("utf-8", "replace")
    else:
        try:
            val = str(val)
        except RecursionError:
            try:
                return type(val).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    return val.encode("utf-8", "replace").decode("utf-8")


def _json_safe(value, depth: int = 0):
    """Drop leftover inf/bytes/dates/!!set so Starlette allow_nan=False cannot 500."""
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _as_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            try:
                key = _as_text(k)
            except Exception:
                continue
            if not key:
                continue
            out[key] = _json_safe(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/apps/credentials.
            return _json_safe(iso(), depth + 1)
        except Exception:
            pass
    try:
        return _as_text(value)
    except Exception:
        return None


def _run_with_input(command: list[str], stdin: str | None, *, timeout: int) -> tuple[int, str, str]:
    """Run *command* with optional stdin; stream stdout/stderr to temp files."""
    argv = as_argv(command)
    if argv is None:
        return -1, "", "invalid argv"
    try:
        payload = None if stdin is None else (
            stdin.encode("utf-8") if isinstance(stdin, str) else stdin
        )
    except UnicodeEncodeError as exc:
        return -1, "", _as_text(exc)[:200]
    try:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            result = subprocess.run(
                argv,
                input=payload,
                stdout=out,
                stderr=err,
                timeout=timeout,
                check=False,
                env=utf8_env(),
            )
            # Tests (and any stub) return a CompletedProcess with captured strings.
            if getattr(result, "stdout", None) is not None or getattr(result, "stderr", None) is not None:
                return result.returncode, _as_text(result.stdout), _as_text(result.stderr)
            def _head(fh) -> str:
                try:
                    fh.seek(0)
                    return fh.read(_CRED_CAP).decode("utf-8", "replace")
                except OSError:
                    return ""
            return result.returncode, _head(out), _head(err)
    except subprocess.TimeoutExpired as exc:
        return -1, "", _as_text(exc)[:200]
    except (OSError, ValueError, TypeError) as exc:
        return -1, "", _as_text(exc)[:200]


_HTTP_USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$")


def _valid_id(service_id: str) -> str:
    value = (service_id or "").strip()
    if not _ID_RE.fullmatch(value) or ".." in value:
        raise api_error("credentials.bad_service_id")
    return value


def _keychain_service(service_id: str) -> str:
    digest = hashlib.sha256(service_id.encode("utf-8")).hexdigest()[:24]
    return f"com.serverhub.credential.{digest}"


def _load() -> dict[str, dict]:
    try:
        raw = safe_json_loads(read_text_capped(INDEX_FILE, _INDEX_CAP, encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        # ValueError covers json.JSONDecodeError *and* UnicodeDecodeError
        # (torn write leaving non-UTF-8 bytes); RecursionError is a leftover
        # deeply nested store.  The credentials page reads this.
        return {}
    if not isinstance(raw, dict):
        return {}
    return {str(k): v for k, v in raw.items() if isinstance(v, dict)}


def _save(items: dict[str, dict]) -> None:
    # Atomic + 0600 from creation: the index holds account names paired with
    # keychain references, and the temp file previously spent the length of the
    # write at umask-derived 0644.
    cleaned = {}
    for key, value in items.items():
        row = _json_safe(value) if isinstance(value, dict) else None
        if isinstance(row, dict):
            cleaned[str(key)] = row
    secure_io.drop_leftover_nonfile(INDEX_FILE)
    try:
        secure_io.replace_secret_text(
            INDEX_FILE,
            json.dumps(cleaned, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        )
    except (OSError, TypeError, ValueError, OverflowError, RecursionError):
        # Leftover directory occupying service-credentials.json must not 500
        # PUT /api/apps/credentials. RecursionError: leftover nested index
        # after _json_safe is not OSError.
        pass


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
            try:
                secret_hex = password_input.encode("utf-8").hex()
            except UnicodeEncodeError as exc:
                return 1, _as_text(exc)
            secure_args.extend(["-X", secret_hex])
            command = [SECURITY, "-i"]
            stdin = " ".join(shlex.quote(arg) for arg in secure_args) + "\n"
        rc, out, err = _run_with_input(command, stdin, timeout=timeout)
        return rc, (out or err or "").strip()
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError) as exc:
        return 1, _as_text(exc)


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
        raise api_error("credentials.username_required")
    if len(password or "") < 8:
        raise api_error("credentials.password_too_short", min=8)

    keychain_service = _keychain_service(service_id)
    # file_lock as well as _lock: two panel processes sharing data/ both
    # edit this index, and a save from a stale snapshot used to erase the
    # other process's entry — or resurrect one a concurrent delete removed.
    with _lock, secure_io.file_lock(INDEX_FILE):
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
            raise api_error("credentials.keychain_write_failed", error=message[:160])
        item = {
            "service_id": service_id,
            "display_name": (display_name or service_id).strip()[:120],
            "username": username,
            "url": normalize_local_url(url)[:500],
            "notes": (notes or "").strip()[:1000],
            "adapter": adapter,
            "applied": bool(applied),
            "updated_at": _stamp_now(),
        }
        items[service_id] = item
        try:
            _save(items)
        except OSError as exc:
            _delete_keychain(keychain_service, username)
            # leftover ``str(exc)`` RecursionError used to 500 PUT /api/apps/credentials.
            raise api_error("credentials.index_save_failed", error=_as_text(exc))
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
    if not isinstance(item, dict):
        item = {}
    service_id = item.get("service_id")
    service_id = service_id if isinstance(service_id, str) else _as_text(service_id)
    adapter = item.get("adapter") or adapter_for(service_id)
    adapter = adapter if isinstance(adapter, str) else adapter_for(service_id)
    updated = item.get("updated_at")
    if isinstance(updated, bool):
        updated = None
    else:
        try:
            updated = int(updated) if updated is not None else None
        except (TypeError, ValueError, OverflowError):
            updated = None
    out = _json_safe({
        "service_id": service_id,
        "display_name": item.get("display_name") or service_id,
        "username": item.get("username") or "",
        "url": item.get("url") or "",
        "notes": item.get("notes") or "",
        "adapter": adapter,
        "can_apply": adapter != "generic",
        "applied": bool(item.get("applied")),
        "has_password": True,
        "updated_at": updated,
    })
    if not isinstance(out, dict):
        return {
            "service_id": service_id,
            "display_name": service_id,
            "username": "",
            "url": "",
            "notes": "",
            "adapter": adapter,
            "can_apply": adapter != "generic",
            "applied": False,
            "has_password": True,
            "updated_at": None,
        }
    for key, fallback in (
        ("service_id", service_id),
        ("display_name", service_id),
        ("username", ""),
        ("url", ""),
        ("notes", ""),
        ("adapter", adapter),
    ):
        if not isinstance(out.get(key), str):
            out[key] = fallback
    if not isinstance(out.get("updated_at"), int):
        out["updated_at"] = None
    out["can_apply"] = out.get("adapter") != "generic"
    out["applied"] = bool(out.get("applied"))
    out["has_password"] = True
    return out


def delete(service_id: str) -> dict:
    service_id = _valid_id(service_id)
    with _lock, secure_io.file_lock(INDEX_FILE):
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
        raise api_error("credentials.bad_username")
    try:
        have_bin = files_svc.FB_BIN.exists()
        have_db = files_svc.FB_DB.exists()
    except OSError:
        have_bin = have_db = False
    if not have_bin or not have_db:
        raise api_error("credentials.filebrowser_missing")
    was_running = bool(files_svc.filebrowser_status().get("running"))
    if was_running:
        stopped = files_svc.stop_filebrowser()
        if stopped.get("running"):
            raise api_error("credentials.filebrowser_stop_failed")
    try:
        # The password goes on argv, where `ps` exposes it to other local users
        # for the lifetime of the call.  That is a known residual, not an
        # oversight: FileBrowser's `users update` accepts the secret no other
        # way.  Verified against the shipped binary -- there is no stdin form,
        # and its subcommand flags are not bound to FB_* environment variables
        # (FB_LOCALE=fr leaves the locale untouched while --locale de applies,
        # so FB_PASSWORD would silently no-op and report success while leaving
        # the old password in place).  A silent failure to rotate a password is
        # strictly worse than a brief local disclosure on a single-user host,
        # so the flag stays until upstream offers stdin.
        rc, out, err = sh([
            str(files_svc.FB_BIN),
            "users", "update", username,
            "--password", password,
            "-d", str(files_svc.FB_DB),
        ], timeout=30)
        out, err = _as_text(out), _as_text(err)
        if rc != 0:
            message = (err or out or "").strip().replace(password, "***")
            raise api_error("credentials.filebrowser_update_failed", error=message[:300])
        return {"ok": True, "message": "File Browser login password updated"}
    finally:
        if was_running:
            files_svc.ensure_filebrowser()


def apply_teslamate(username: str, password: str) -> dict:
    """Replace TeslaMate's Nginx Basic Auth user without exposing the secret."""
    if not _HTTP_USER_RE.fullmatch((username or "").strip()):
        raise api_error("credentials.bad_username")
    try:
        have_site = TESLAMATE_NGINX_SITE.is_file()
    except OSError:
        have_site = False
    if not have_site:
        raise api_error("credentials.teslamate_gateway_missing")

    try:
        # Nginx on macOS cannot validate Apache's $2y$ bcrypt records because
        # the platform crypt(3) lacks Blowfish; $apr1$ is supported natively.
        rc, out, err = _run_with_input(
            [HTPASSWD, "-ni", username], password + "\n", timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise api_error("credentials.htpasswd_failed", error=_as_text(exc)[:200])
    entry = (out or "").strip()
    if rc != 0 or not entry.startswith(username + ":"):
        message = (err or "").strip()
        raise api_error("credentials.htpasswd_failed", error=message[:200])

    with _lock:
        old = None
        try:
            if TESLAMATE_HTPASSWD.exists():
                old = read_bytes_capped(TESLAMATE_HTPASSWD, _HTPASSWD_CAP)
        except OSError as exc:
            # EFBIG: leftover junk; replace it rather than OOM the request.
            if getattr(exc, "errno", None) != errno.EFBIG:
                raise api_error(
                    "credentials.teslamate_apply_failed", error=_as_text(exc)[:180]
                )
        try:
            # 0600 from the first byte: write_text+chmod left a umask window
            # on the hash file; write_bytes restore did the same.
            secure_io.replace_secret_text(TESLAMATE_HTPASSWD, entry + "\n")

            from hub import nginx_svc
            reloaded = nginx_svc.reload_nginx()
            if not reloaded.get("ok"):
                raise RuntimeError(_as_text(reloaded.get("message") or "Nginx reload failed"))
        except Exception as exc:
            if old is None:
                TESLAMATE_HTPASSWD.unlink(missing_ok=True)
            else:
                secure_io.replace_secret_text(
                    TESLAMATE_HTPASSWD, old.decode("utf-8", "replace")
                )
            raise api_error(
                "credentials.teslamate_apply_failed", error=_as_text(exc)[:180]
            )

    return {"ok": True, "message": "TeslaMate port 4000 access password updated"}


def apply(service_id: str, username: str, password: str) -> dict:
    adapter = adapter_for(_valid_id(service_id))
    if adapter == "filebrowser":
        return apply_filebrowser(username, password)
    if adapter == "teslamate-basic-auth":
        return apply_teslamate(username, password)
    raise api_error("credentials.adapter_unsupported")
