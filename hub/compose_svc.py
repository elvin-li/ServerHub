"""Dockge-inspired compose stack YAML read/write/validate."""
from __future__ import annotations

import errno
import os
import re
from pathlib import Path

import yaml

from hub import cli_args, secure_io
from hub.containers_svc import _stack_paths
from hub.docker_cli import engine_up, looks_engine_down
from hub.errors import api_error, exc_detail, soft_fail
from hub.paths import DOCKER, user_home
from hub.status import invalidate_status as inv
from hub.util import read_text_capped, run_capped

#: Leftover multi-MB junk occupying docker-compose.yml used to OOM GET /api/compose.
_COMPOSE_CAP = 1024 * 1024


def _utf8_text(value) -> str:
    """Drop leftover ``\\ud800`` so compose writes and Starlette cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        text = value.decode("utf-8", "replace")
    elif isinstance(value, str):
        text = value
    elif value is None:
        return ""
    else:
        try:
            text = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    try:
        return text.encode("utf-8", "replace").decode("utf-8")
    except Exception:
        return ""


def _find_stack(stack_id: str) -> dict:
    for s in _stack_paths():
        if s.get("id") == stack_id:
            return s
    raise api_error("compose.unknown_stack", stack=stack_id)


def get_compose(stack_id: str) -> dict:
    s = _find_stack(stack_id)
    path = s.get("compose_path")
    if not isinstance(path, str) or not path:
        raise api_error("container.no_compose_file")
    try:
        # is_file-then-read raced: a compose deleted between the check and
        # read_text raised FileNotFoundError and 500'd the Compose page.
        # Path() itself raises ValueError on NUL / TypeError on a list leftover,
        # which used to escape this handler.
        p = Path(path)
        text = read_text_capped(
            p, _COMPOSE_CAP, encoding="utf-8", errors="replace"
        )
        st = p.stat()
    except (OSError, ValueError, TypeError):
        raise api_error("container.no_compose_file")
    # FUSE ``st_mtime = inf`` OverflowError'd GET /api/compose/{id};
    # OverflowError is not ValueError, so it escaped the handler above.
    try:
        mtime = int(st.st_mtime)
    except (TypeError, ValueError, OverflowError):
        mtime = 0
    sid = _utf8_text(s.get("id")) if isinstance(s.get("id"), str) else ""
    if not sid:
        sid = "stack"
    name = _utf8_text(s.get("name")) if isinstance(s.get("name"), str) else ""
    if not name:
        name = sid
    stack_path = s.get("path")
    return {
        "id": sid,
        "name": name,
        "path": _utf8_text(stack_path) if isinstance(stack_path, str) else None,
        "compose_path": _utf8_text(path),
        "content": _utf8_text(text),
        "size": len(text),
        "mtime": mtime,
    }


def save_compose(stack_id: str, content: str, validate: bool = True) -> dict:
    s = _find_stack(stack_id)
    path = s.get("compose_path")
    if not isinstance(path, str) or not path:
        raise api_error("container.no_compose_file")
    if isinstance(content, (bytes, bytearray)):
        content = content.decode("utf-8", "replace")
    if not isinstance(content, str) or not content.strip():
        raise api_error("compose.empty_content")
    content = _utf8_text(content)
    # basic safety: no path escape in content writing
    home = user_home()
    if home is None:
        raise api_error("container.no_compose_file")
    try:
        p = Path(path).resolve()
        services_root = (home / "Services").resolve()
    except (OSError, ValueError, TypeError, RuntimeError):
        # Path.resolve() raises RuntimeError on a leftover symlink loop.
        raise api_error("container.no_compose_file")
    if services_root not in p.parents and p.parent != services_root:
        # allow only under ~/Services
        raise api_error("compose.path_forbidden")
    if validate:
        v = validate_compose_text(content, cwd=str(p.parent))
        if not v.get("ok"):
            _raise_validation_failure(v)
    # A compose file carries the generated database and admin passwords for the
    # stack, which is the payload secure_io was written for.  write_text() then
    # chmod() creates the file at the umask default -- 0644 here -- so both the
    # backup and the new content were world-readable for the length of the write.
    # replace_secret_text does the same temp-file-then-rename atomically, with the
    # restrictive mode applied from the first byte.
    bak = p.with_suffix(p.suffix + ".bak")
    try:
        # exists-then-read raced and FileNotFoundError 500'd the save.
        # A leftover directory at compose_path is IsADirectoryError (OSError).
        secure_io.replace_secret_text(
            bak,
            read_text_capped(p, _COMPOSE_CAP, encoding="utf-8", errors="replace"),
        )
    except FileNotFoundError:
        pass
    except OSError as exc:
        # Leftover multi-MB junk is not worth backing up; still save over it.
        if getattr(exc, "errno", None) != errno.EFBIG:
            raise api_error("container.no_compose_file")
    secure_io.replace_secret_text(p, content)
    inv()
    return {"ok": True, "path": str(p), "message": "Saved", "backup": str(bak)}


def _raise_validation_failure(v: dict):
    """Fail a compose save/create with the code the validation reported.

    An engine that is off is a dependency state (coded 503), not a defect in
    the operator's YAML (``compose.invalid``, 400).
    """
    if v.get("code") == "container.engine_down":
        raise api_error("container.engine_down")
    raise api_error("compose.invalid", detail=v.get("message") or "compose invalid")


def validate_compose_text(content: str, cwd: str | None = None) -> dict:
    """docker compose config -q via a 0600 temp file.

    NamedTemporaryFile in ~/Services was born at the umask (0644 here) and
    held the same generated passwords as the live compose until unlink.
    """
    if not isinstance(content, str) and not isinstance(content, (bytes, bytearray)):
        return {"ok": False, "message": "compose file must be a YAML mapping"}
    content = _utf8_text(content)
    if "!!python" in content.lower():
        return {"ok": False, "message": "python YAML tags are not allowed"}
    try:
        doc = yaml.safe_load(content)
    except (
        yaml.YAMLError, RecursionError, TypeError, ValueError, AttributeError, KeyError,
    ) as e:
        # RecursionError: leftover deeply-nested compose YAML is not YAMLError.
        # TypeError/ValueError/AttributeError/KeyError: leftover ``!!timestamp .inf``,
        # ``2026-13-01``, a 5000-digit int, or ``!!bool 2`` are not YAMLError.
        return {"ok": False, "message": exc_detail(e, 800)}
    if not isinstance(doc, dict):
        return {"ok": False, "message": "compose file must be a YAML mapping"}
    if isinstance(cwd, str) and cwd.strip():
        work = cwd
    else:
        home = user_home()
        if home is None:
            return {"ok": False, "message": "invalid working directory"}
        work = str(home / "Services")
    # NUL / control bytes never reach docker compose: Path() can store them
    # and unlink() then raises ValueError (not OSError) out of finally.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in work):
        return {"ok": False, "message": "invalid working directory"}
    try:
        tmp = Path(work) / f".compose-check.{os.getpid()}.yml"
    except (OSError, ValueError, TypeError):
        return {"ok": False, "message": "invalid working directory"}
    try:
        Path(work).mkdir(parents=True, exist_ok=True)
        # create, not write: write_secret_text O_TRUNCs a pre-created
        # guessable ".compose-check.<pid>.yml" and fills it with the
        # same generated passwords as the live compose.
        if not secure_io.create_secret_text(tmp, content):
            tmp.unlink(missing_ok=True)
            if not secure_io.create_secret_text(tmp, content):
                return {"ok": False, "message": "temp compose file exists"}
        rc, text = run_capped(
            [DOCKER, "compose", "-f", str(tmp), "config", "-q"],
            cwd=work,
            timeout=30,
            env={**os.environ, "PATH": "/opt/homebrew/bin:/usr/local/bin:" + os.environ.get("PATH", "")},
            cap=800,
        )
        # Leftover bytes used to land in the JSON body; a leftover int
        # AttributeError'd .strip and was only saved by the blanket except.
        if isinstance(text, (bytes, bytearray)):
            text = text.decode("utf-8", "replace")
        elif not isinstance(text, str):
            text = "" if text is None else str(text)
        ok = rc == 0
        if not ok and looks_engine_down(text) and not engine_up(force=True):
            # The compose file may be perfectly valid: the CLI could not reach
            # the daemon.  Reporting that as "compose file is invalid" (400 on
            # save/create) told the operator their YAML was broken and pointed
            # away from the real remedy (start the engine).  The probe is
            # forced -- same convention as containers_svc._raise_list_failure:
            # the memoised answer has a 5s TTL and the seconds right after the
            # engine stops are when a stale "up" would misclassify this.  The
            # message-pattern guard matters too: ``docker compose config`` is
            # mostly client-side, so a genuine YAML error with the engine
            # coincidentally off must keep reporting the YAML error.
            return soft_fail("container.engine_down")
        return {
            "ok": ok,
            "message": (text or ("valid" if ok else "invalid")).strip()[:800],
        }
    except Exception as e:
        return {"ok": False, "message": exc_detail(e, 800)}
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except (OSError, ValueError):
            pass


def validate_stack(stack_id: str) -> dict:
    data = get_compose(stack_id)
    return validate_compose_text(data["content"], cwd=data.get("path"))


def create_stack(stack_id: str, name: str | None, content: str) -> dict:
    """Create new stack under ~/Services/<id>/docker-compose.yml"""
    stack_id = cli_args.require_positional(stack_id, label="stack id", max_len=41)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,40}", stack_id):
        raise api_error("compose.bad_stack_id")
    if isinstance(content, (bytes, bytearray)):
        content = content.decode("utf-8", "replace")
    content = _utf8_text(content) if isinstance(content, str) else content
    home = user_home()
    if home is None:
        raise api_error("compose.invalid", detail="home directory is unavailable")
    root = home / "Services" / stack_id
    try:
        taken = root.exists() and (root / "docker-compose.yml").exists()
    except (OSError, ValueError):
        # Dying FUSE/SMB: exists() re-raises EIO/ESTALE.
        taken = False
    if taken:
        raise api_error("compose.exists", path=str(root))
    v = validate_compose_text(content, cwd=str(home / "Services"))
    if not v.get("ok"):
        _raise_validation_failure(v)
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        # A leftover file occupying ~/Services/<id> used to FileExistsError 500.
        raise api_error("compose.exists", path=str(root))
    try:
        (root / "data").mkdir(exist_ok=True)
    except OSError:
        pass
    compose = root / "docker-compose.yml"
    # 0600 from the first byte, O_EXCL so exists() losing a race cannot
    # truncate an operator-edited compose.
    try:
        created = secure_io.create_secret_text(compose, content)
    except OSError:
        raise api_error("compose.exists", path=str(root))
    if not created:
        raise api_error("compose.exists", path=str(root))
    # Register in services.yaml stacks if not present, through config.mutate: it
    # re-reads inside the write lock, so this only ever *adds* the stack.  The old
    # save_full(deepcopy(cfg())) wrote a snapshot taken before the lock was held,
    # reverting whatever another process had committed since -- routine, not rare,
    # on a machine running the packaged app alongside a source checkout.
    from hub.config import mutate

    def apply(data: dict) -> None:
        stacks = data.get("stacks")
        if not isinstance(stacks, list):
            stacks = []
            data["stacks"] = stacks
        if any(isinstance(entry, dict) and entry.get("id") == stack_id for entry in stacks):
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
