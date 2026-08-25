"""System identification (Unraid Identification settings)."""
from __future__ import annotations

import platform
from pathlib import Path

from hub.config import cfg, update_settings
from hub.errors import api_error
from hub.host_address import configured_host, host_ip as effective_host_ip
from hub.util import LazyPool, sh, ttl_memo

_pool = LazyPool(7, "hub-identity")

#: The one binary :func:`set_identity` spawns.  Module-level so the
#: vanished-CLI probe re-checks the exact path the spawn used.
SCUTIL = "/usr/sbin/scutil"


def _scutil_missing(rc, err) -> bool:
    """Whether an ``sh()`` result means scutil itself is gone.

    ``sh`` reports a FileNotFoundError spawn as ``(-1, "", "not found")`` — a
    sentinel, never a real scutil exit.  The sentinel alone must not classify:
    rc -1 is also what a timeout or a signal-killed run reports, so the disk
    is re-probed *on this failure path only* (the vms ``_cli_missing`` /
    docker ``cli_on_disk`` rule — a successful spawn never pays the stat).
    Timeouts keep their own sentinel and are deliberately not classified;
    an authorization failure is a real scutil exit and never matches.
    """
    if rc != -1 or _as_text(err).strip() != "not found":
        return False
    try:
        return not Path(SCUTIL).is_file()
    except (OSError, ValueError):
        # An unreadable /usr/sbin must not upgrade the failure to a 503.
        return False


def shutdown_executor() -> None:
    _pool.shutdown()


def _as_text(value) -> str:
    """JSON-encodable scutil/sysctl field.  Leftover ``\\ud800`` used to 500 GET /api/identity."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif value is None:
        return ""
    else:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    return value.encode("utf-8", "replace").decode("utf-8")


def _encodable(text: str) -> bool:
    """False for a lone surrogate — no encoder (scutil argv, Bonjour, JSON)
    can carry it, so it is a bad name, not a spawn-time ValueError."""
    try:
        text.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


@ttl_memo(300.0)
def platform_string() -> str:
    """``platform.platform()``, which is not the string formatting it looks like.

    On macOS it shells out twice: ``uname -p``, and then ``file -b`` on the Python
    binary via ``platform.architecture()``. ``platform.uname()`` is cached inside the
    standard library but ``architecture()`` is not, and two callers reaching it
    concurrently on a cold interpreter each pay -- which is what one
    ``/api/diagnostics`` bundle did, since both this module and the bundle header want
    the string. Single-flight, so they share one answer.

    Process-static in practice: the OS version and the interpreter do not change under
    a running panel.
    """
    # Leftover ``\\ud800`` in ``uname`` used to 500 GET /api/diagnostics
    # (``_diag_host`` / Tools About) under Starlette's UTF-8 encoder.
    return _as_text(platform.platform())


def get_identity() -> dict:
    # Seven independent reads that used to run partly in series: five in a pool, and
    # then `platform.platform()` (two spawns) and the LAN address (two more) after it,
    # in the return dict itself -- four spawns of pure tail on a request the Settings
    # page makes on every open. Nothing here feeds anything else, so it is one wave.
    f_host = _pool.submit(sh, ["/bin/hostname"], timeout=3)
    f_comp = _pool.submit(sh, ["/usr/sbin/scutil", "--get", "ComputerName"], timeout=3)
    f_local = _pool.submit(sh, ["/usr/sbin/scutil", "--get", "LocalHostName"], timeout=3)
    f_model = _pool.submit(sh, ["/usr/sbin/sysctl", "-n", "hw.model"], timeout=3)
    f_tz = _pool.submit(time_zone)
    f_platform = _pool.submit(platform_string)
    f_ip = _pool.submit(effective_host_ip)

    def _result(fut, fallback):
        try:
            return fut.result()
        except Exception:
            return fallback

    # `.result()` re-raises; one scutil/sysctl miss must not 500 Settings.
    rc, hostname, _ = _result(f_host, (1, "", ""))
    rc2, comp, _ = _result(f_comp, (1, "", ""))
    rc3, local, _ = _result(f_local, (1, "", ""))
    rc4, model, _ = _result(f_model, (1, "", ""))
    tz = _result(f_tz, "") or ""
    platform_name = _result(f_platform, "") or ""
    host_ip = _result(f_ip, "") or ""
    raw = cfg().get("settings")
    s = raw if isinstance(raw, dict) else {}
    # Fallbacks (platform.node / machine, configured_host) used to skip
    # `_as_text`; leftover ``\ud800`` there 500'd GET /api/identity.
    return {
        "hostname": _as_text(hostname if rc == 0 else platform.node()),
        "computer_name": _as_text(comp) if rc2 == 0 else "",
        "local_hostname": _as_text(local) if rc3 == 0 else "",
        "model": _as_text(model if rc4 == 0 else platform.machine()),
        "platform": _as_text(platform_name),
        "arch": _as_text(platform.machine()),
        "host_ip": _as_text(host_ip),
        "host_ip_config": _as_text(configured_host()),
        "comment": _as_text(s.get("server_comment") or s.get("description") or ""),
        "timezone": _as_text(tz),
    }


@ttl_memo(60.0)
def time_zone() -> str:
    """The zone name behind /etc/localtime.

    Memoised because two of the sections in one ``/api/diagnostics`` bundle want it --
    ``get_datetime_info`` and ``get_identity`` -- and they run concurrently, so the
    read happened twice per request. The panel has no path that changes the timezone
    (the Settings page points the operator at System Settings for it), and the symlink
    does not move on its own, so a short TTL is enough and there is nothing to
    invalidate on.

    Single-flight matters here rather than incidentally: both callers sit inside the
    same fan-out, so without it they miss the cold cache together and each pays.

    The second probe is a fallback, not a second question: `ls -l` is tried first
    because it works when /etc/localtime is a regular file, and `readlink` covers the
    symlink case. Only one of them runs on a given host.
    """
    rc, out, _ = sh(["/bin/ls", "-l", "/etc/localtime"], timeout=3)
    text = _as_text(out)
    if rc == 0 and "zoneinfo/" in text:
        return text.split("zoneinfo/")[-1].strip()
    rc, out, _ = sh(["/usr/bin/readlink", "/etc/localtime"], timeout=3)
    text = _as_text(out)
    if "zoneinfo/" in text:
        return text.split("zoneinfo/")[-1].strip()
    return ""


def set_identity(computer_name: str | None = None, comment: str | None = None, host_ip: str | None = None) -> dict:
    """Update panel-stored identity; ComputerName needs user approval via scutil (may need admin)."""
    patch = {}
    msgs = []
    if comment is not None:
        # Scrubbed before it becomes YAML/JSON: a lone ``\ud800`` in the body
        # used to be persisted raw into services.yaml, where every consumer
        # had to re-scrub it forever (and the patch dict itself could never
        # be JSON-encoded again).
        patch["server_comment"] = _as_text(comment)
    if host_ip is not None:
        patch["host_ip"] = _as_text(host_ip).strip()
    if patch:
        update_settings(patch)
        msgs.append("Panel settings updated")
    if computer_name:
        name = str(computer_name).strip()
        if (
            not name
            or len(name) > 63
            or name.startswith("-")
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in name)
            or not _encodable(name)
        ):
            raise api_error("identity.bad_name")
        # Try without sudo first
        rc, out, err = sh([SCUTIL, "--set", "ComputerName", name], timeout=5)
        if rc != 0:
            if _scutil_missing(rc, err):
                # A vanished scutil used to answer ok:true with a message
                # blaming administrator privileges — the rename was silently
                # lost.  Coded so the panel can say what actually happened.
                raise api_error("identity.scutil_missing")
            # Leftover ``\ud800`` in scutil stderr used to 500 PUT /api/identity.
            msgs.append(
                "Setting ComputerName needs administrator privileges: "
                + _as_text(err or out)
            )
        else:
            msgs.append("ComputerName set")
            sh([SCUTIL, "--set", "LocalHostName", name.replace(" ", "-")[:63]], timeout=5)
    try:
        identity = get_identity()
    except Exception:
        identity = {}
    if not isinstance(identity, dict):
        identity = {}
    return {
        "ok": True,
        "message": _as_text("; ".join(msgs) or "No changes"),
        "identity": identity,
    }
