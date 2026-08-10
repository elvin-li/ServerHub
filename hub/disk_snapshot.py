"""Single source for the three disk reads that answer whole-machine questions.

``storage_svc``, ``disk_power_svc`` and ``disk_manage_svc`` each asked the same
three questions of the same host, and each shelled out for them:

    `df -P -k`                        the mount table      storage_svc, disk_power_svc
    `diskutil list -plist physical`   physical whole disks disk_power_svc, disk_manage_svc
    `diskutil info -plist /`          what `/` sits on     disk_power_svc, disk_manage_svc

plus `df -P /`, which is the mount table again filtered to one row -- and which
``disk_manage_svc`` ran once per node inside its listing walk.

``/api/storage`` fans all three modules out concurrently, so the duplication was
not sequential waste that a cache upstream would have absorbed; it was three
modules reaching the same cold read in the same millisecond.  Two of the
duplicates were also invisible to any measurement grouping spawns by argv, because
``storage_svc`` spelled the command ``df`` and ``disk_power_svc`` ``/bin/df``.

Same shape as :mod:`hub.brew_cache`, :mod:`hub.launchd_cache` and
:mod:`hub.proc_cache`: a short TTL, a single-flight refresh, and an explicit
invalidation that every path changing mount or presence state already reaches
through ``disk_power_svc.invalidate_power_disks()``.

The root-disk set deserves a note, because it is load-bearing for safety rather
than for latency: ``disk_power_svc`` refuses to sleep or eject a disk that carries
``/``, and it decides that from the union of three independent reads.  Only the two
that were duplicated are shared here.  The third -- scraping ``diskutil info /`` in
its text form -- stays where it is, because narrowing that union is how a panel ends
up offering to eject the boot disk.
"""
from __future__ import annotations

import plistlib
import re
import subprocess
from types import MappingProxyType
from typing import Any, Mapping

from hub.util import cached_snapshot, sh

#: Short, and for the usual reason: these are dependency reads whose consumers
#: already sit behind their own caches (the power-disk listing, the SMART snapshot).
#: The window that matters is one request's worth of overlapping readers.
_TTL = 5.0

#: A wedged diskutil -- typically an external HDD that has spun down -- used to pin
#: a whole listing at 12-15s per call.  Matches disk_power_svc._DISKUTIL_TIMEOUT.
_DISKUTIL_TIMEOUT = 5

_DISK_RE = re.compile(r"/dev/(disk\d+)")


@cached_snapshot(_TTL)
def df_lines() -> tuple[str, ...]:
    """`df -P -k` output lines including the header.

    A tuple so the cached table can be handed to concurrent callers without copying
    it per caller, and so none of them can mutate the shared copy.
    """
    rc, out, _ = sh(["/bin/df", "-P", "-k"], timeout=8)
    return tuple((out or "").splitlines()) if rc == 0 else ()


def root_devices() -> frozenset[str]:
    """Whole-disk ids carrying ``/``, read out of the shared mount table.

    This replaces a separate ``df -P /`` in two modules.  ``df -P /`` prints the
    filesystem holding ``/``; the full table contains that same row, so filtering it
    in memory asks nothing new of the host -- and ``disk_manage_svc`` was running
    that extra ``df`` once per node it examined.
    """
    found: set[str] = set()
    for line in df_lines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        if " ".join(parts[5:]) != "/":
            continue
        match = _DISK_RE.search(parts[0])
        if match:
            found.add(match.group(1))
    return frozenset(found)


@cached_snapshot(_TTL)
def physical_whole_disks() -> tuple[str, ...]:
    """Real physical whole disks, as opposed to synthesised APFS containers.

    Keeps the plaintext fallback: ``diskutil list -plist physical`` is the reliable
    form, but when it fails the text listing still names the disks, and returning
    nothing here means the storage page shows no disks at all.
    """
    try:
        p = subprocess.run(
            ["/usr/sbin/diskutil", "list", "-plist", "physical"],
            capture_output=True, timeout=_DISKUTIL_TIMEOUT,
        )
    except Exception:
        p = None
    if p is not None and p.returncode == 0 and p.stdout:
        try:
            parsed = plistlib.loads(p.stdout)
            return tuple(str(x) for x in (parsed.get("WholeDisks") or []))
        except Exception:
            pass
    rc, out, _ = sh(["/usr/sbin/diskutil", "list", "physical"], timeout=_DISKUTIL_TIMEOUT)
    if rc != 0:
        return ()
    ids: list[str] = []
    for match in re.finditer(r"/dev/(disk\d+)\s", out or ""):
        if match.group(1) not in ids:
            ids.append(match.group(1))
    return tuple(ids)


@cached_snapshot(_TTL)
def root_info() -> Mapping[str, Any]:
    """`diskutil info -plist /`, or an empty mapping.

    Read-only view: this is the shared copy, and one caller annotating it would
    become every later caller's answer.
    """
    try:
        p = subprocess.run(
            ["/usr/sbin/diskutil", "info", "-plist", "/"],
            capture_output=True, timeout=_DISKUTIL_TIMEOUT,
        )
        if p.returncode == 0 and p.stdout:
            parsed = plistlib.loads(p.stdout)
            if isinstance(parsed, dict):
                return MappingProxyType(parsed)
    except Exception:
        pass
    return MappingProxyType({})


def invalidate_disks() -> None:
    """Forget all three reads after something changed mount or presence state.

    Reached from ``disk_power_svc.invalidate_power_disks()`` and from
    ``disk_manage_svc.disk_action``, so a mount, unmount, eject or erase is visible
    to the next read rather than a TTL later.  Sleeping or ejecting a disk changes
    whether it is present at all, which is exactly the state these describe.
    """
    df_lines.invalidate()             # type: ignore[attr-defined]
    physical_whole_disks.invalidate()  # type: ignore[attr-defined]
    root_info.invalidate()            # type: ignore[attr-defined]
