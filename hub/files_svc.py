"""On-demand file manager — no long-lived worker; only runs while handling requests.

Optional FileBrowser (port 8125) can be started/stopped for the full UI, but the
built-in browser works without it and uses no extra process memory when idle.
"""
from __future__ import annotations

import mimetypes
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

from fastapi import UploadFile
from fastapi.responses import FileResponse

from hub.config import cfg
from hub.errors import api_error
from hub.host_address import host_ip
from hub.paths import AGENTS_DIR, BASE, STATE_ROOT, UID
from hub.util import sh

HOME = Path.home()
SERVICES_ROOT = HOME / "Services"

# ─── Protected paths ──────────────────────────────────────────────────────────
# The default roots include ~/Services (which contains this install) and ~, so
# without an explicit deny-list the browser would hand out ServerHub's own
# session-signing key, its credential store and the admin password hash — and
# accept delete/rename on them.  Enforced in _resolve_safe() so a directly
# supplied path is refused too, not just filtered out of a listing.

#: Directory subtrees that are never browsable, downloadable or writable.
PROTECTED_DIRS: tuple[Path, ...] = (
    BASE,                       # immutable ServerHub runtime
    STATE_ROOT,                 # mutable config, tokens, audits, and metrics
    HOME / ".ssh",
    HOME / ".aws",
    HOME / ".gnupg",
    HOME / ".kube",
    HOME / "Library" / "Keychains",
    # A local private-integration directory may contain account credentials,
    # long-lived API tokens, session cookies, and browser profiles. File modes
    # are no defence here because the panel runs as the file owner.
    SERVICES_ROOT / "private_integration",
    # Backups are exactly as sensitive as what they copy, and PROTECTED_PREFIXES
    # already withholds "services.yaml*" — but configs_*.tgz contains that file
    # verbatim and matched none of the deny-list entries, so the file browser
    # would hand over the admin password hash and every token inside a tarball.
    # The deny-list protected the original and not the copy.  Database dumps live
    # here too.  0600/0700 is no defence: the panel runs as the owner.
    SERVICES_ROOT / "backups",
)

#: Basenames that are never exposed, wherever they appear.
PROTECTED_NAMES: frozenset[str] = frozenset({
    ".session-secret",
    "service-credentials.json",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
})

#: Filename prefixes that are never exposed (covers services.yaml.bak.<ts>
#: and private-integration credential/session artefacts copied elsewhere).
PROTECTED_PREFIXES: tuple[str, ...] = ("services.yaml", ".env", ".private_")


def _fold(value: str) -> str:
    """Case-fold a path string so the deny-list matches what the FS opens.

    macOS (APFS) is case-insensitive by default, so a deny-list that compares
    raw strings is trivially bypassed: `Services.YAML` does not equal
    `services.yaml`, and `.../ServerHub/...` is not `relative_to`
    `.../serverhub`, yet all of them open the very same bytes.  Confirmed on
    this host — requesting the install directory with a different capitalisation
    returned the session-signing key and the admin password hash.

    NOTE: os.path.normcase is *not* the primitive to use here.  It only folds
    case on Windows; on darwin it is the identity function (verified on this
    host), so it silently leaves the bypass wide open.  Fold explicitly.

    Folding unconditionally is the safe direction: on a case-sensitive volume
    it can only ever over-match (deny a name that differs just by case), never
    under-match.  A denied file is a visible annoyance; a leaked signing key is
    not.
    """
    return str(value).lower()


def is_protected(p: Path) -> bool:
    """True when *p* is inside a protected subtree or is a protected file."""
    folded = _fold(p)
    for d in PROTECTED_DIRS:
        try:
            resolved_dir = d.resolve()
        except OSError:
            continue
        folded_dir = _fold(resolved_dir)
        if folded == folded_dir:
            return True
        # Compare on the folded strings rather than Path.relative_to(): the
        # trailing separator keeps `/a/bcd` from matching the parent `/a/bc`.
        if folded.startswith(folded_dir.rstrip(os.sep) + os.sep):
            return True
    name = _fold(p.name)
    if name in {_fold(n) for n in PROTECTED_NAMES}:
        return True
    return any(name.startswith(_fold(pre)) for pre in PROTECTED_PREFIXES)


FB_LABEL = "local.filebrowser"
FB_PLIST = Path(AGENTS_DIR) / f"{FB_LABEL}.plist"
FB_BIN = SERVICES_ROOT / "filebrowser" / "filebrowser-bin"
FB_DB = SERVICES_ROOT / "filebrowser" / "filebrowser.db"
FB_PORT = 8125
FB_ROOT_DEFAULT = SERVICES_ROOT / "media"
# Not /tmp: that directory is world-writable and sticky, so any other local
# account could pre-create this name as a symlink and have ServerHub append the
# child's output into a file of the attacker's choosing, running as the panel
# user.  ~/Library/Logs is the macOS convention, is inside the 0700 home, and is
# already where the LaunchAgent variant of this service writes.
FB_LOG = HOME / "Library" / "Logs" / "filebrowser-hub.log"

# Session note: whether this hub session started FB (so stop can free memory)
_started_by_hub = False


def _settings() -> dict:
    return (cfg().get("settings") or {}).get("files") or {}


def default_roots() -> list[dict]:
    """Allowlisted roots. Configurable via settings.files.roots."""
    custom = _settings().get("roots")
    if custom:
        out = []
        for r in custom:
            if isinstance(r, str):
                p = Path(os.path.expanduser(r)).resolve()
                out.append({"id": p.name or "root", "name": p.name or str(p), "path": str(p)})
            elif isinstance(r, dict) and r.get("path"):
                p = Path(os.path.expanduser(r["path"])).resolve()
                out.append({
                    "id": r.get("id") or p.name or "root",
                    "name": r.get("name") or p.name or str(p),
                    "path": str(p),
                })
        return [x for x in out if Path(x["path"]).is_dir()]
    candidates = [
        {"id": "services", "name": "Services", "path": str(SERVICES_ROOT)},
        {"id": "media", "name": "Media", "path": str(SERVICES_ROOT / "media")},
        # NOTE: the whole home directory is deliberately NOT a default root — it
        # exposed ~/.ssh and every dotfile credential store.  Users who want it
        # can opt in explicitly via settings.files.roots.
        {"id": "downloads", "name": "Downloads", "path": str(HOME / "Downloads")},
        {"id": "documents", "name": "Documents", "path": str(HOME / "Documents")},
    ]
    out = []
    for c in candidates:
        p = Path(c["path"])
        if p.exists():
            out.append({**c, "path": str(p.resolve())})
    return out


def _resolve_safe(path: str | None, root_id: str | None = None) -> Path:
    """Resolve path, ensure it stays under an allowed root and is not protected."""
    roots = default_roots()
    if not roots:
        raise api_error("files.no_roots")

    root_path: Path | None = None
    if root_id:
        for r in roots:
            if r["id"] == root_id:
                root_path = Path(r["path"]).resolve()
                break
        if root_path is None:
            raise api_error("files.unknown_root", root_id=root_id)

    if not path or path in (".", "/"):
        if root_path:
            return root_path
        return Path(roots[0]["path"]).resolve()

    p = Path(os.path.expanduser(str(path))).resolve()

    # must be under some allowed root
    allowed = [Path(r["path"]).resolve() for r in roots]
    if root_path:
        allowed = [root_path]
    ok = False
    for a in allowed:
        try:
            p.relative_to(a)
            ok = True
            break
        except ValueError:
            continue
    if not ok:
        raise api_error("files.path_outside_root")
    # Protected paths are rejected here, at the single choke point every
    # list/download/upload/rename/delete call passes through, so supplying an
    # exact path cannot bypass the check the way listing filters can.
    if is_protected(p):
        raise api_error("files.path_protected")
    return p


def _resolve_leaf(path: str, root_id: str | None = None) -> Path:
    """Resolve for delete/rename: parent resolved, leaf name not followed.

    ``Path.resolve()`` follows the final symlink, so deleting
    ``~/Downloads/link → realfile`` would unlink ``realfile``.  Mutations keep
    the leaf as the operator named it; containment is checked on the parent,
    and both the link and its target (when present) are refused if protected.
    """
    raw = Path(os.path.expanduser(str(path)))
    if not raw.name or raw.name in (".", ".."):
        raise api_error("files.bad_name")
    parent = _resolve_safe(str(raw.parent), root_id)
    if not parent.is_dir():
        raise api_error("files.parent_not_a_dir")
    leaf = parent / raw.name
    if is_protected(leaf):
        raise api_error("files.path_protected")
    if leaf.exists() or leaf.is_symlink():
        try:
            target = leaf.resolve(strict=False)
        except OSError:
            target = None
        if target is not None and is_protected(target):
            raise api_error("files.path_protected")
    return leaf


def _entry(p: Path, root: Path) -> dict:
    try:
        st = p.lstat()
    except OSError as e:
        return {"name": p.name, "error": str(e)}
    is_link = p.is_symlink()
    is_dir = p.is_dir() and not is_link
    # follow only for size of regular files
    size = 0
    if p.is_file():
        try:
            size = st.st_size
        except OSError:
            size = 0
    try:
        rel = str(p.relative_to(root)) if p != root else ""
    except ValueError:
        rel = p.name
    mode = stat.filemode(st.st_mode)
    return {
        "name": p.name or str(p),
        "path": str(p),
        "rel": rel,
        "is_dir": bool(is_dir or (is_link and p.is_dir())),
        "is_file": p.is_file(),
        "is_link": is_link,
        "size": size,
        "mtime": int(st.st_mtime),
        "mode": mode,
        "ext": p.suffix.lower() if p.is_file() else "",
    }


def list_dir(path: str | None = None, root_id: str | None = None) -> dict:
    p = _resolve_safe(path, root_id)
    if not p.exists():
        raise api_error("files.not_found", path=str(p))
    if not p.is_dir():
        raise api_error("files.not_a_dir")

    # pick root for relative paths
    roots = default_roots()
    root = Path(roots[0]["path"]).resolve()
    if root_id:
        for r in roots:
            if r["id"] == root_id:
                root = Path(r["path"]).resolve()
                break
    else:
        for r in roots:
            rp = Path(r["path"]).resolve()
            try:
                p.relative_to(rp)
                root = rp
                root_id = r["id"]
                break
            except ValueError:
                continue

    items = []
    try:
        children = list(p.iterdir())
    except PermissionError:
        raise api_error("files.permission_denied", path=str(p))
    show_hidden = bool(_settings().get("show_hidden"))
    for c in children:
        if c.name.startswith(".") and not show_hidden:
            continue
        # Also omit protected entries so they do not show up as rows that
        # error on every click.  _resolve_safe() is the actual gate.
        if is_protected(c):
            continue
        items.append(_entry(c, root))
    items.sort(key=lambda x: (not x.get("is_dir"), (x.get("name") or "").lower()))

    # breadcrumb
    crumbs = []
    cur = p
    while True:
        try:
            cur.relative_to(root)
        except ValueError:
            break
        crumbs.append({"name": cur.name or root.name, "path": str(cur)})
        if cur == root:
            break
        cur = cur.parent
    crumbs.reverse()

    return {
        "path": str(p),
        "root_id": root_id,
        "root": str(root),
        "crumbs": crumbs,
        "items": items,
        "count": len(items),
    }


def _clean_component(value: str | None) -> str:
    """A single path component: no separators and no control characters.

    Stripping only ``/`` and ``\\`` left tabs, newlines and other control bytes
    in the name.  That is not just cosmetic: a directory created here can later
    be handed to ``POST /api/nfs/exports``, and exports(5) is whitespace
    delimited, so a name containing a tab split one validated path into several
    fields in the root-owned /etc/exports.  Names like this are never
    intentional, so refuse them at the point of creation too.
    """
    text = (value or "").strip().replace("/", "").replace("\\", "")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
        raise api_error("files.bad_name")
    return text


def mkdir(path: str, name: str, root_id: str | None = None) -> dict:
    parent = _resolve_safe(path, root_id)
    if not parent.is_dir():
        raise api_error("files.parent_not_a_dir")
    name = _clean_component(name)
    if not name or name in (".", ".."):
        raise api_error("files.bad_name")
    dest = (parent / name).resolve()
    _resolve_safe(str(dest), root_id)  # re-check under root
    if dest.exists():
        raise api_error("files.exists")
    dest.mkdir(parents=False)
    return {"ok": True, "path": str(dest)}


def delete_path(path: str, root_id: str | None = None) -> dict:
    p = _resolve_leaf(path, root_id)
    # never delete roots themselves
    for r in default_roots():
        if p.resolve() == Path(r["path"]).resolve():
            raise api_error("files.cannot_delete_root")
    if not p.exists() and not p.is_symlink():
        raise api_error("files.not_found")
    if p.is_symlink():
        p.unlink()
    elif p.is_dir():
        shutil.rmtree(p)
    else:
        p.unlink()
    return {"ok": True, "path": str(p)}


def rename_path(path: str, new_name: str, root_id: str | None = None) -> dict:
    p = _resolve_leaf(path, root_id)
    new_name = _clean_component(new_name)
    if not new_name or new_name in (".", ".."):
        raise api_error("files.bad_name")
    if not p.exists() and not p.is_symlink():
        raise api_error("files.not_found")
    dest = p.parent / new_name
    if dest.exists() or dest.is_symlink():
        raise api_error("files.dest_exists")
    # Dest must stay under the same root and must not land on a protected name.
    _resolve_safe(str(dest.parent), root_id)
    if is_protected(dest):
        raise api_error("files.path_protected")
    p.rename(dest)
    return {"ok": True, "path": str(dest), "from": str(p)}


def download(path: str, root_id: str | None = None) -> FileResponse:
    p = _resolve_safe(path, root_id)
    if not p.is_file():
        raise api_error("files.file_only")
    media = mimetypes.guess_type(str(p))[0] or "application/octet-stream"
    return FileResponse(str(p), filename=p.name, media_type=media)


async def upload(path: str, file: UploadFile, root_id: str | None = None) -> dict:
    parent = _resolve_safe(path, root_id)
    if not parent.is_dir():
        raise api_error("files.dest_not_a_dir")
    name = Path(file.filename or "upload.bin").name
    if not name or name in (".", ".."):
        raise api_error("files.bad_filename")
    dest = (parent / name).resolve()
    _resolve_safe(str(dest), root_id)
    # Refuse to clobber an existing file.  rename() already guards this way, and
    # the error code was defined for upload from the start but never raised, so an
    # upload silently overwrote whatever was there.  Combined with a deny-list
    # bypass that turns a read hole into arbitrary code execution: overwrite any
    # .py under the install dir and the next restart runs it.
    if dest.exists():
        raise api_error("files.upload_would_overwrite", name=name)
    # stream write
    max_mb = int(_settings().get("max_upload_mb") or 512)
    max_bytes = max_mb * 1024 * 1024
    written = 0
    try:
        with open(dest, "wb") as f:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    f.close()
                    try:
                        dest.unlink()
                    except OSError:
                        pass
                    raise api_error("files.upload_too_large", max_mb=max_mb)
                f.write(chunk)
    finally:
        await file.close()
    return {"ok": True, "path": str(dest), "size": written, "name": name}


# ─── Optional FileBrowser process (full UI) ───────────────────────────────────

def filebrowser_status() -> dict:
    running = False
    pid = None
    rc, out, _ = sh(["/bin/launchctl", "print", f"gui/{UID}/{FB_LABEL}"], timeout=5)
    if rc == 0 and "state = running" in (out or ""):
        running = True
        for line in (out or "").splitlines():
            if "pid =" in line:
                try:
                    pid = int(line.split("=")[-1].strip())
                except ValueError:
                    pass
    if not running:
        rc2, out2, _ = sh(["/bin/pgrep", "-f", "filebrowser-bin"], timeout=5)
        if rc2 == 0 and out2.strip():
            running = True
            try:
                pid = int(out2.splitlines()[0].strip())
            except ValueError:
                pass
    host = host_ip()
    return {
        "installed": FB_BIN.exists() or FB_PLIST.exists(),
        "running": running,
        "pid": pid,
        "port": FB_PORT,
        "url": f"http://{host}:{FB_PORT}",
        "plist": str(FB_PLIST) if FB_PLIST.exists() else None,
        "bin": str(FB_BIN) if FB_BIN.exists() else None,
        "root": str(FB_ROOT_DEFAULT),
        "started_by_hub": _started_by_hub,
        "keepalive": _plist_keepalive(),
    }


def _plist_keepalive() -> bool | None:
    if not FB_PLIST.exists():
        return None
    try:
        import plistlib
        with open(FB_PLIST, "rb") as f:
            pl = plistlib.load(f)
        return bool(pl.get("KeepAlive"))
    except Exception:
        return None


def ensure_filebrowser() -> dict:
    """Start FileBrowser only if needed (on-demand)."""
    global _started_by_hub
    st = filebrowser_status()
    if st["running"]:
        return {"ok": True, "message": "FileBrowser 已在运行", **st, "started": False}
    if not FB_BIN.exists() and not FB_PLIST.exists():
        raise api_error("files.fb_not_installed")

    dom = f"gui/{UID}"
    if FB_PLIST.exists():
        sh(["/bin/launchctl", "bootstrap", dom, str(FB_PLIST)], timeout=10)
        sh(["/bin/launchctl", "kickstart", "-k", f"{dom}/{FB_LABEL}"], timeout=10)
    elif FB_BIN.exists():
        # Direct start without KeepAlive. Pass an argv vector so spaces or shell
        # metacharacters in the user's home path can never change the command.
        FB_ROOT_DEFAULT.mkdir(parents=True, exist_ok=True)
        SERVICES_ROOT.joinpath("filebrowser").mkdir(parents=True, exist_ok=True)
        try:
            FB_LOG.parent.mkdir(parents=True, exist_ok=True)
            # O_NOFOLLOW refuses to follow a symlink planted at this exact path,
            # so a pre-existing link fails the start instead of redirecting the
            # child's stdout into whatever it points at.
            log_fd = os.open(
                FB_LOG,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(log_fd, "ab") as log:
                subprocess.Popen(
                    [
                        str(FB_BIN), "-d", str(FB_DB), "-r", str(FB_ROOT_DEFAULT),
                        "-a", "127.0.0.1", "-p", str(FB_PORT),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    close_fds=True,
                )
        except OSError:
            raise api_error("files.fb_start_failed")
    else:
        raise api_error("files.fb_start_failed")

    # wait up to ~3s for port
    for _ in range(15):
        time.sleep(0.2)
        st2 = filebrowser_status()
        if st2["running"]:
            _started_by_hub = True
            return {"ok": True, "message": "FileBrowser 已按需启动", **st2, "started": True}
    st3 = filebrowser_status()
    return {
        "ok": st3["running"],
        "message": "已发送启动命令" if st3["running"] else "启动超时，请检查日志",
        **st3,
        "started": st3["running"],
    }


def stop_filebrowser() -> dict:
    """Stop FileBrowser to free memory. Disables KeepAlive temporarily via bootout."""
    global _started_by_hub
    dom = f"gui/{UID}"
    if FB_PLIST.exists():
        sh(["/bin/launchctl", "bootout", f"{dom}/{FB_LABEL}"], timeout=10)
    # kill leftover
    sh(["/usr/bin/pkill", "-f", "filebrowser-bin"], timeout=5)
    _started_by_hub = False
    time.sleep(0.3)
    st = filebrowser_status()
    return {
        "ok": not st["running"],
        "message": "已停止 FileBrowser，内存已释放" if not st["running"] else "仍有进程在运行",
        **st,
    }


def set_filebrowser_ondemand(enabled: bool = True) -> dict:
    """Write LaunchAgent RunAtLoad/KeepAlive off for true on-demand (no boot RAM)."""
    if not FB_PLIST.exists():
        raise api_error("files.fb_no_plist")
    import plistlib
    with open(FB_PLIST, "rb") as f:
        pl = plistlib.load(f)
    if enabled:
        pl["RunAtLoad"] = False
        pl["KeepAlive"] = False
    else:
        pl["RunAtLoad"] = True
        pl["KeepAlive"] = True
    with open(FB_PLIST, "wb") as f:
        plistlib.dump(pl, f)
    # reload definition if loaded
    dom = f"gui/{UID}"
    sh(["/bin/launchctl", "bootout", f"{dom}/{FB_LABEL}"], timeout=8)
    if not enabled:
        # re-enable resident mode
        sh(["/bin/launchctl", "bootstrap", dom, str(FB_PLIST)], timeout=8)
        sh(["/bin/launchctl", "kickstart", f"{dom}/{FB_LABEL}"], timeout=8)
    return {
        "ok": True,
        "ondemand": enabled,
        "message": "已设为按需启动（开机不驻留）" if enabled else "已设为常驻（开机自启）",
        "plist": str(FB_PLIST),
    }


def overview() -> dict:
    return {
        "roots": default_roots(),
        "filebrowser": filebrowser_status(),
        "builtin": True,
        "hint": "内置文件管理仅在打开本页并请求时占用资源；完整 FileBrowser 可按需启停。",
    }
