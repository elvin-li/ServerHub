"""Disk / volume / SMART for macOS — capacity deduped by physical/container."""
from __future__ import annotations

import re
import shutil

from hub.disk_snapshot import df_lines
from hub.paths import SMARTCTL, user_home
from hub.util import LazyPool, fan_out, sh, ttl_memo

#: Outer composer only.  ``smart_devices`` fans out per disk on the shared
#: probe pool; putting that work on the same executor would serialize the
#: disks (or deadlock before the reentrancy guard).
_OVERVIEW_POOL = LazyPool(2, "storage-overview")


def shutdown_executor() -> None:
    _OVERVIEW_POOL.shutdown()

#: SMART is slow to read and slow to change: each disk costs a `diskutil info` plus a
#: `smartctl -a`, and wear and error counters move over weeks.
#:
#: Behind ``ttl_memo`` rather than a bare dict.  The dict this replaces checked its
#: timestamp and then computed outside any lock, so simultaneous cold readers -- the
#: storage page, the dashboard tile and the menu-bar client all want this -- each ran
#: the whole per-disk fan-out.  Measured with a counting fake: two readers spawned
#: four `smartctl` where two would do, four readers spawned eight.
_SMART_TTL = 600.0

# skip noisy synthetic mounts
SKIP_PREFIXES = (
    "/dev", "/System/Volumes/VM", "/System/Volumes/Preboot",
    "/System/Volumes/Update", "/System/Volumes/xarts",
    "/System/Volumes/iSCPreboot", "/System/Volumes/Hardware",
    "/private/var/vm",
)
SKIP_FS = {"devfs", "autofs", "map"}


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500."""
    base = bytes if isinstance(value, bytes) else bytearray
    return base.decode(value, "utf-8", "replace")


def _as_text(value) -> str:
    """JSON-safe text. Leftover ``\\ud800`` in a df mount / diskutil name
    used to 500 GET /api/storage under Starlette's UTF-8 encode.
    """
    if isinstance(value, (bytes, bytearray)):
        value = _decode_bytes(value)
    elif value is None:
        return ""
    elif isinstance(value, float):
        try:
            # Base coercion first (the modules5 rule): a float-subclass
            # ``__eq__`` bomb used to blow the NaN/inf probes below.
            value = float.__float__(value)
        except Exception:
            return ""
        if value != value or value in (float("inf"), float("-inf")):
            return ""
        value = str(value)
    elif isinstance(value, (list, tuple, dict, set, frozenset, bool)):
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
    # Unbound base encode: ``str()`` launders most subclasses, but one whose
    # ``__str__`` returns *self* keeps its type through the coercion above,
    # and its bound ``encode`` bomb used to raise out of here — nulling the
    # whole volume table on GET /api/storage?light for one bad field.
    return str.encode(value, "utf-8", "replace").decode("utf-8")


def _parent_disk_id(filesystem: str) -> str | None:
    """/dev/disk3s1s1 → disk3 ; OrbStack → None."""
    if not filesystem:
        return None
    m = re.search(r"(disk\d+)", filesystem)
    return m.group(1) if m else None


def list_volumes() -> list:
    items = []
    home = user_home()
    orbstack_home = str(home / "OrbStack") if home is not None else ""
    # The shared mount table (hub/disk_snapshot.py).  This module spelled the command
    # `df` and disk_power_svc spelled it `/bin/df`, so `/api/storage` read the table
    # twice and neither spawn looked like a duplicate of the other -- and the bare
    # spelling also depended on the panel's inherited PATH.
    #
    # The old call ignored its exit status and indexed straight into the output, so a
    # `df` timeout silently degraded this to "one volume, /" instead of reporting a
    # failure.  The shared read checks rc and does not cache a failed table.
    for line in df_lines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        fs, blocks, used, avail, pct = parts[0], parts[1], parts[2], parts[3], parts[4]
        fs, mount = _as_text(fs), _as_text(" ".join(parts[5:]))
        if any(mount == p or mount.startswith(p + "/") for p in SKIP_PREFIXES if p != "/"):
            if mount not in ("/", "/System/Volumes/Data"):
                if not mount.startswith("/Volumes/") and mount not in ("/", "/System/Volumes/Data") \
                        and "OrbStack" not in mount and not (
                            orbstack_home and mount.startswith(orbstack_home)
                        ):
                    if mount.startswith("/System/") or mount.startswith("/dev"):
                        continue
        if fs in SKIP_FS or mount.startswith("/dev"):
            continue
        if mount.startswith("/System/Volumes/") and mount not in ("/System/Volumes/Data",):
            continue
        try:
            total_kb = int(blocks)
            used_kb = int(used)
            avail_kb = int(avail)
        except (TypeError, ValueError, OverflowError):
            continue
        # Capacity can be "-" (or missing "%") on a 0-block mount.  The
        # percent parse used to divide first, so that row ZeroDivisionError'd
        # the whole volume table rather than skipping the unusable line.
        if total_kb <= 0:
            continue
        # A garbled 400-digit block count is a valid Python int, then
        # ``kb / 1024`` OverflowError'd the whole table.  ``inf%`` did the
        # same via ``int(float('inf'))``.
        try:
            total_gb = round(total_kb / 1024 / 1024, 1)
            used_gb = round(used_kb / 1024 / 1024, 1)
            avail_gb = round(avail_kb / 1024 / 1024, 1)
        except OverflowError:
            continue
        if any(
            v != v or v in (float("inf"), float("-inf"))
            for v in (total_gb, used_gb, avail_gb)
        ):
            continue
        try:
            if str(pct).endswith("%"):
                raw_pct = float(str(pct).rstrip("%"))
                if raw_pct != raw_pct or raw_pct in (float("inf"), float("-inf")):
                    pct_n = round(used_kb / total_kb * 100)
                else:
                    pct_n = int(raw_pct)
            else:
                pct_n = round(used_kb / total_kb * 100)
        except (TypeError, ValueError, OverflowError):
            continue
        if total_kb < 100 * 1024:  # < 100MB
            continue
        parent = _parent_disk_id(fs)
        items.append({
            "filesystem": fs,
            "device": fs,
            "disk_id": parent,  # whole-disk id when known
            "mount": mount,
            "total_gb": total_gb,
            "used_gb": used_gb,
            "avail_gb": avail_gb,
            "pct": pct_n,
            "kind": _classify(mount, fs),
        })
    mounts = {i["mount"] for i in items}
    if "/" not in mounts:
        # ``du.total == 0`` used to ZeroDivisionError the volume table the
        # same way it 500'd /api/health/checks before that path fail-closed.
        try:
            du = shutil.disk_usage("/")
        except OSError:
            du = None
        if du is not None and du.total:
            try:
                items.insert(0, {
                    "filesystem": "/",
                    "device": "/",
                    "disk_id": None,
                    "mount": "/",
                    "total_gb": round(du.total / 2**30, 1),
                    "used_gb": round(du.used / 2**30, 1),
                    "avail_gb": round(du.free / 2**30, 1),
                    "pct": round(du.used / du.total * 100),
                    "kind": "system",
                })
            except OverflowError:
                # A leftover 400-digit ``st_blocks`` OverflowError'd GET /api/storage
                # after the df path already skipped the same leftover.
                pass
    return items


def _classify(mount: str, fs: str) -> str:
    if mount == "/" or mount == "/System/Volumes/Data":
        return "system"
    if mount.startswith("/Volumes/"):
        return "external"
    if "OrbStack" in mount or mount.endswith("/OrbStack"):
        return "orbstack"
    if fs.startswith("OrbStack") or "orbstack" in fs.lower():
        return "orbstack"
    return "other"


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Leftover inf / ``\\ud800`` in a SMART attr or volume name still 500'd
    GET /api/storage after non-dict rows were skipped.
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int (the modules5 rule): a
                # subclass ``__str__`` bomb used to raise a non-ValueError
                # past the digit-cap probe below, out of the sequence
                # guard, and blank the whole volume table to ``null`` on
                # GET /api/storage.
                value = int.__index__(value)
            except Exception:
                return None
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if isinstance(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below the same way.
                value = float.__float__(value)
            except Exception:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _as_text(value)
    if isinstance(value, (bytes, bytearray)):
        # Unbound base decode: a leftover subclass ``.decode`` bomb used to
        # raise past the old bound call and null the containing table.
        return _decode_bytes(value)
    if isinstance(value, dict):
        # Unbound base view (the modules5 rule the shares6/nas sweeps
        # applied to every sibling ``_jsonable``): a dict subclass whose
        # ``items()`` raises used to collapse to None here; ``dict.items``
        # reads the real C-level storage, so the salvageable keys survive.
        out = {}
        for k, v in dict.items(value):
            if isinstance(k, (bytes, bytearray)):
                k = _decode_bytes(k)
            elif not isinstance(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_as_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        # Unbound base iteration (the ``dict.items`` rule at sequence rank):
        # a sequence subclass whose ``__iter__`` raises used to null the
        # whole field here, while the real elements sit readable in the
        # C-level storage.
        if isinstance(value, list):
            base = list
        elif isinstance(value, tuple):
            base = tuple
        elif isinstance(value, set):
            base = set
        else:
            base = frozenset
        try:
            items = list(base.__iter__(value))
        except Exception:
            return None
        try:
            return [_jsonable(v, depth + 1) for v in items]
        except Exception:
            # Residual raise out of the recursion: only this field drops,
            # never the volume table or the route.
            return None
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # A leftover whose ``isoformat`` is a raising property used to blow
        # this probe and null the containing table.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/storage.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _as_text(value)
    except Exception:
        return None


def _shared_pool(group: list) -> bool:
    """APFS (and similar) volumes on same container report the same total capacity."""
    if len(group) <= 1:
        return False
    totals = [_json_gb(v.get("total_gb")) for v in group if isinstance(v, dict)]
    if len(totals) <= 1:
        return False
    max_t = max(totals)
    if max_t <= 0:
        return False
    # all totals within 3% of the max → shared free space pool
    return all(abs(t - max_t) / max_t < 0.03 for t in totals)


def _json_gb(raw, ndigits: int = 1) -> float:
    """Finite GB/TB total. Two leftover ``1e308`` volumes summed to inf and
    500'd GET /api/storage under Starlette's ``allow_nan=False`` encoder.

    ``except Exception``, not the three usual conversion errors: an
    int-subclass ``__float__`` bomb rode a volume row's ``total_gb``
    through ``_volume_row``'s str() probe untouched, then raised here out
    of ``aggregate_capacity`` — a bare 500 on GET /api/storage?light.
    """
    if isinstance(raw, int) and not isinstance(raw, bool) and type(raw) is not int:
        try:
            # Base coercion first so the bombed subclass keeps its number.
            raw = int.__index__(raw)
        except Exception:
            return 0.0
    try:
        value = round(float(raw), ndigits)
    except Exception:
        return 0.0
    if value != value or value in (float("inf"), float("-inf")):
        return 0.0
    return value


def _json_int(raw, default: int = 0) -> int:
    if isinstance(raw, bool) or raw is None:
        return default
    if isinstance(raw, int) and type(raw) is not int:
        try:
            # Base coercion first so a bombed subclass keeps its number.
            raw = int.__index__(raw)
        except Exception:
            return default
    try:
        if isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
            return default
        # ``except Exception`` for the same reason as _json_gb: a subclass
        # ``__int__``/``__eq__`` bomb is not one of the three usual
        # conversion errors and used to raise out of the shaping loops.
        value = int(raw)
    except Exception:
        return default
    try:
        str(value)
    except ValueError:
        # A leftover already past CPython's int->str digit cap survives
        # ``int()`` unchanged and then ValueError'd ``json.dumps`` itself.
        return default
    return value


def _volume_row(raw) -> dict | None:
    """JSON-safe volume. Leftover incomplete dicts / inf / ``\\ud800`` used
    to KeyError or 500 GET /api/storage after non-dict rows were skipped.
    """
    if not isinstance(raw, dict):
        return None
    mount = _as_text(raw.get("mount"))
    if not mount:
        return None
    row = dict(raw)
    row["mount"] = mount
    row["kind"] = _as_text(row.get("kind")) or "other"
    disk_id = row.get("disk_id")
    if disk_id is None or isinstance(disk_id, bool):
        row["disk_id"] = None
    elif isinstance(disk_id, float) and (
        disk_id != disk_id or disk_id in (float("inf"), float("-inf"))
    ):
        row["disk_id"] = None
    else:
        # A numeric YAML/plist id that is already-int must coerce via the
        # str() probe in _as_text, not ride through an isinstance(str) gate:
        # volumes kept the raw int while aggregate_capacity stringified its
        # group key, so the shared-pool lookup (and the UI badge behind it)
        # silently missed.  A >4300-digit leftover int fails the probe and
        # drops to None like its inf float sibling.
        row["disk_id"] = _as_text(disk_id) or None
    for key in ("total_gb", "used_gb", "avail_gb"):
        val = row.get(key)
        if isinstance(val, bool) or val is None:
            row[key] = 0.0
        elif isinstance(val, int):
            if type(val) is not int:
                try:
                    # Base coercion (the modules5 rule): an int subclass
                    # wearing a ``__float__``/``__str__`` bomb used to ride
                    # through this fast path untouched and blow up later in
                    # aggregate_capacity / the encoder.
                    val = int.__index__(val)
                except Exception:
                    row[key] = 0.0
                    continue
                row[key] = val
            try:
                str(val)
            except ValueError:
                # A >4300-digit leftover int rode through the int fast path
                # and ValueError'd Starlette's encoder on GET /api/storage.
                row[key] = 0.0
        elif isinstance(val, float):
            if type(val) is not float:
                row[key] = _json_gb(val)
            elif val != val or val in (float("inf"), float("-inf")):
                row[key] = 0.0
        else:
            row[key] = _json_gb(val)
    row["pct"] = _json_int(row.get("pct"))
    for key in ("filesystem", "device"):
        if key in row:
            row[key] = _as_text(row.get(key))
    return row


def aggregate_capacity(vols: list, kinds: set | None = None) -> dict:
    """Sum capacity without double-counting shared APFS containers.

    Group by disk_id (physical/synthetic whole disk). Within a group:
    - shared pool (same total): count total once, used = max, free = max
    - independent partitions: sum totals/used/free
    """
    selected = [
        v for v in vols
        if isinstance(v, dict) and (kinds is None or v.get("kind") in kinds)
    ]
    groups: dict[str, list] = {}
    for v in selected:
        raw_id = v.get("disk_id")
        if isinstance(raw_id, bool) or raw_id is None:
            raw_id = None
        elif isinstance(raw_id, float) and (
            raw_id != raw_id or raw_id in (float("inf"), float("-inf"))
        ):
            raw_id = None
        else:
            raw_id = _as_text(raw_id) or None
        key = raw_id or (
            f"fs:{_as_text(v.get('filesystem'))}:{_as_text(v.get('mount'))}"
        )
        groups.setdefault(key, []).append(v)

    total = used = free = 0.0
    counted_mounts = []
    for key, group in groups.items():
        if _shared_pool(group):
            t = max(_json_gb(x.get("total_gb")) for x in group)
            u = max(_json_gb(x.get("used_gb")) for x in group)
            a = max(_json_gb(x.get("avail_gb")) for x in group)
            # prefer Data volume as representative for used (more accurate app data)
            data_vol = next(
                (x for x in group if x.get("mount") == "/System/Volumes/Data"), None
            )
            if data_vol:
                u = _json_gb(data_vol.get("used_gb"))
                a = _json_gb(data_vol.get("avail_gb"))
            total += t
            used += u
            free += a
            counted_mounts.append({
                "disk_id": key if not str(key).startswith("fs:") else group[0].get("disk_id"),
                "mode": "shared_pool",
                "mounts": [_as_text(x.get("mount")) for x in group],
                "total_gb": _json_gb(t),
                "used_gb": _json_gb(u),
                "avail_gb": _json_gb(a),
            })
        else:
            t = sum(_json_gb(x.get("total_gb")) for x in group)
            u = sum(_json_gb(x.get("used_gb")) for x in group)
            a = sum(_json_gb(x.get("avail_gb")) for x in group)
            total += t
            used += u
            free += a
            counted_mounts.append({
                "disk_id": key if not str(key).startswith("fs:") else group[0].get("disk_id"),
                "mode": "sum_partitions",
                "mounts": [_as_text(x.get("mount")) for x in group],
                "total_gb": _json_gb(t),
                "used_gb": _json_gb(u),
                "avail_gb": _json_gb(a),
            })
    return {
        "total_gb": _json_gb(total),
        "used_gb": _json_gb(used),
        "free_gb": _json_gb(free),
        "total_tb": _json_gb(total / 1024, 2),
        "used_tb": _json_gb(used / 1024, 2),
        "free_tb": _json_gb(free / 1024, 2),
        "groups": counted_mounts,
    }


#: smartctl prints a version line and a copyright line before anything else,
#: including before an error.  Those are the first thing a naive `serr or sout`
#: picks up, which is why an unreadable external disk used to explain itself to
#: the user as "smartctl 7.5 2025-04-30 ... Copyright (C) 2002-25 ...".
_SMARTCTL_BANNER = re.compile(r"^(smartctl \d|Copyright \(C\)|===)", re.IGNORECASE)


def _smartctl_failure(sout: str, serr: str) -> str:
    """The reason a SMART read failed, in terms that mean something to a reader.

    macOS gives userspace no SCSI/ATA passthrough for USB and Thunderbolt
    bridges, so an external enclosure answers "Operation not supported by
    device" no matter which `-d` transport is tried.  That is a property of the
    connection, not a symptom of a failing drive, and saying so avoids reading
    the Dashboard's "SMART unavailable" as a fault.
    """
    lines = [
        line.strip()
        for line in f"{serr}\n{sout}".splitlines()
        if line.strip() and not _SMARTCTL_BANNER.match(line.strip())
    ]
    detail = " ".join(lines)[:120]
    lowered = detail.lower()
    if "not supported by device" in lowered or "unsupported" in lowered:
        return "External USB/Thunderbolt drive: macOS offers no SMART passthrough, so it cannot be read (not a disk fault)"
    if any(x in lowered for x in ("permission", "operation not permitted", "access denied")):
        return "Reading SMART requires authorization: run deploy/install-sudoers.sh"
    return detail or "smartctl unavailable or needs sudo"


def _probe_disk(d: str) -> dict:
    """`diskutil info` + `smartctl -a` for one physical disk.

    Split out of smart_devices() so disks can be probed concurrently. The calls
    inside stay sequential: the sudo retry is conditional on the first smartctl
    result, and the parallelism that matters here is across disks, not within one.
    """
    dev = f"/dev/{d}"
    info = {
        "device": dev, "id": d, "name": d,
        "size": None, "size_bytes": None, "size_gb": None,
        "smart": None, "error": None,
    }
    try:
        return _probe_disk_uncached(dev, info)
    except Exception as exc:
        info["error"] = _as_text(exc)[:160]
        return info


def _probe_disk_uncached(dev: str, info: dict) -> dict:
    rc, iout, _ = sh(["/usr/sbin/diskutil", "info", dev], timeout=8)
    iout = _as_text(iout)
    if rc == 0:
        for line in iout.splitlines():
            if "Device / Media Name:" in line or "Media Name:" in line:
                info["name"] = _as_text(line.split(":", 1)[1].strip())
            elif "Disk Size:" in line:
                raw_size = line.split(":", 1)[1].strip()
                info["size"] = _as_text(raw_size.split("(")[0].strip())
                byte_match = re.search(r"\(([\d,]+)\s+Bytes\)", raw_size, re.IGNORECASE)
                if byte_match:
                    try:
                        size_bytes = int(byte_match.group(1).replace(",", ""))
                    except (TypeError, ValueError, OverflowError):
                        size_bytes = 0
                    info["size_bytes"] = size_bytes or None
                    try:
                        size_gb = round(size_bytes / 2**30, 1) if size_bytes else None
                    except OverflowError:
                        size_gb = None
                    if size_gb is not None and (
                        size_gb != size_gb or size_gb in (float("inf"), float("-inf"))
                    ):
                        size_gb = None
                    info["size_gb"] = size_gb
            elif "Solid State:" in line:
                info["ssd"] = "Yes" in line
            elif "Protocol:" in line:
                info["protocol"] = _as_text(line.split(":", 1)[1].strip())
    # Most macOS NVMe devices are readable as the login user.  Avoid a
    # failing sudo process on every disk; retry with passwordless sudo only
    # when the direct read clearly failed for permissions.
    rc, sout, serr = sh([SMARTCTL, "-a", dev], timeout=10)
    sout, serr = _as_text(sout), _as_text(serr)
    msg_lower = f"{sout}\n{serr}".lower()
    if rc not in (0, 4) and any(x in msg_lower for x in ("permission", "operation not permitted", "access denied")):
        rc, sout, serr = sh(["/usr/bin/sudo", "-n", SMARTCTL, "-a", dev], timeout=10)
    if rc in (0, 4) and sout:
        sm = {}
        attrs = []  # all raw SMART attributes for detail view
        in_smart_section = False
        in_ata_table = False
        nvme_attr_idx = 0
        for line in sout.splitlines():
            # --- summary fields (backward compat) ---
            if "Data Units Written" in line and "[" in line:
                sm["written"] = line.split("[")[1].rstrip("]")
            elif "Percentage Used" in line:
                sm["wear"] = line.split(":")[1].strip()
            elif "Wear_Leveling_Count" in line:
                parts = line.split()
                if len(parts) >= 10:
                    sm.setdefault("wear", f"{parts[9]}%")
            elif line.strip().startswith("Temperature:"):
                sm["temp"] = line.split(":")[1].strip()
            elif "Temperature_Celsius" in line:
                parts = line.split()
                if len(parts) >= 10:
                    sm.setdefault("temp", f"{parts[9]} Celsius")
            elif "Airflow_Temperature" in line:
                parts = line.split()
                if len(parts) >= 10:
                    sm.setdefault("temp", f"{parts[9]} Celsius")
            elif "Power On Hours" in line or "Power_On_Hours" in line:
                if ":" in line:
                    sm["power_on"] = line.split(":")[-1].strip()
                else:
                    parts = line.split()
                    if len(parts) >= 10:
                        sm["power_on"] = parts[9]
            elif "Serial Number:" in line:
                sm["serial"] = line.split(":")[1].strip()
            elif "Model Number:" in line or "Device Model:" in line:
                sm["model"] = line.split(":")[1].strip()
            elif "SMART overall-health" in line:
                sm["health"] = line.split(":")[-1].strip()
            elif line.strip().startswith("Critical Warning:"):
                raw = line.split(":", 1)[1].strip()
                sm["critical_warning"] = raw
            elif line.strip().startswith("Available Spare:"):
                sm["available_spare"] = line.split(":", 1)[1].strip()
            elif line.strip().startswith("Unsafe Shutdowns:"):
                sm["unsafe_shutdowns"] = line.split(":", 1)[1].strip()
            elif line.strip().startswith("Media and Data Integrity Errors:"):
                sm["media_errors"] = line.split(":", 1)[1].strip()
            elif "Reallocated_Sector_Ct" in line:
                sm["reallocated"] = line.split()[-1]
            elif "Current_Pending_Sector" in line:
                sm["pending"] = line.split()[-1]
            elif "Offline_Uncorrectable" in line:
                sm["uncorrectable"] = line.split()[-1]
            # --- collect ALL NVMe SMART key-value pairs ---
            if "SMART/Health Information" in line:
                in_smart_section = True
                in_ata_table = False
                continue
            if in_smart_section and not in_ata_table:
                stripped = line.strip()
                if (not stripped
                        or stripped.startswith("===")
                        or stripped.startswith("SMART")
                        or stripped.startswith("Read ")
                        or stripped.startswith("Error Information")):
                    in_smart_section = False
                elif ":" in stripped:
                    key, _, val = stripped.partition(":")
                    key = key.strip()
                    val = val.strip()
                    if key and val and key not in (
                        "SMART overall-health self-assessment test result",
                    ):
                        nvme_attr_idx += 1
                        attrs.append({
                            "id": nvme_attr_idx,
                            "name": key,
                            "value": val,
                        })
            # --- collect ALL ATA SMART attribute table rows ---
            if line.startswith("ID# ATTRIBUTE_NAME"):
                in_ata_table = True
                continue
            if in_ata_table:
                stripped = line.strip()
                if not stripped or stripped.startswith("SMART"):
                    in_ata_table = False
                    in_smart_section = False
                    continue
                parts = stripped.split()
                if len(parts) >= 10 and parts[0].isdigit():
                    try:
                        attr_id = int(parts[0])
                    except ValueError:
                        # ``isdigit()`` does not bound length: ``int()`` of a
                        # >4300-digit ID column is ValueError (CPython's
                        # str->int cap), which used to raise out of
                        # _probe_disk_uncached and degrade the whole disk to
                        # an error row on GET /api/storage.
                        continue
                    # If parts[8] is "-", raw is parts[9:]; else raw is parts[8:]
                    if parts[8] == "-":
                        raw_val = " ".join(parts[9:]) if len(parts) > 9 else "-"
                    else:
                        raw_val = " ".join(parts[8:])
                    attrs.append({
                        "id": attr_id,
                        "name": parts[1],
                        "value": parts[3],
                        "worst": parts[4],
                        "thresh": parts[5],
                        "type": parts[6],
                        "raw": raw_val,
                    })
        if "health" not in sm:
            critical = str(sm.get("critical_warning") or "0").lower()
            sm["health"] = "PASSED" if critical in ("0", "0x00") else "WARNING"
        if attrs:
            sm["attrs"] = attrs
        info["smart"] = sm
    else:
        info["error"] = _smartctl_failure(sout, serr)
    return info


@ttl_memo(_SMART_TTL)
def smart_devices() -> list:
    """Enumerate disks and pull SMART summary (cached 10 min).

    Each disk costs a `diskutil info` plus a `smartctl -a` (and sometimes a sudo
    retry), and smartctl on a spinning disk is not fast. Probing them one after
    another made a cold /api/storage scale linearly with disk count while the
    dashboard's storage tile and the whole Main Array page waited on it. The
    probes touch different devices and share no state, so they are independent;
    the only reason they were serial is that they were written as a for loop.

    Results are re-ordered to match `disk_ids` so the array table does not
    reshuffle its rows depending on which disk answered first.
    """
    rc, out, _ = sh(["/usr/sbin/diskutil", "list", "physical"], timeout=10)
    out = _as_text(out)
    disk_ids = []
    if rc == 0:
        for m in re.finditer(r"/dev/(disk\d+)\s", out):
            d = m.group(1)
            if d not in disk_ids:
                disk_ids.append(d)
    if not disk_ids:
        disk_ids = ["disk0"]

    # Bounded below the shared default: a Mac with many external disks should not
    # spawn one thread per device, and each probe is two subprocesses. 4 covers the
    # realistic case while keeping the worst-case subprocess count in check.
    #
    # `fan_out` supplies the single-item-inline and empty-list cases this hand-rolled
    # for itself, and narrows the pool to the item count.
    return fan_out(_probe_disk, disk_ids, max_workers=4)


def invalidate_smart() -> None:
    """Drop the SMART snapshot after an operation changed which disks are present.

    Nothing used to do this.  The TTL is ten minutes, so a disk ejected, mounted or
    erased kept its old SMART row -- or kept appearing at all -- for that long.
    """
    smart_devices.invalidate()


def storage_overview() -> dict:
    # `df` and the SMART probe read different things and neither feeds the other,
    # so overlap them: on a cold cache this takes the page from
    # "df, then every disk" to "df alongside every disk".
    f_vols = _OVERVIEW_POOL.submit(list_volumes)
    f_disks = _OVERVIEW_POOL.submit(smart_devices)
    # `.result()` re-raises; SMART must not blank the volume table.
    try:
        vols = f_vols.result()
    except Exception:
        vols = []
    if not isinstance(vols, list):
        vols = []
    try:
        disks = f_disks.result()
    except Exception:
        disks = []
    if not isinstance(disks, list):
        disks = []
    # Leftover non-dict rows TypeError'd ``v["kind"]``; leftover incomplete
    # dicts then KeyError'd ``total_gb`` / leaked inf / ``\\ud800`` into
    # Starlette's encoder on GET /api/storage.
    #
    # Per-row guard, the storage_pool_svc._candidates rule: a dict *subclass*
    # passes ``isinstance`` with a ``.get`` that raises, and one such row
    # used to raise out of _volume_row — a bare 500 on GET /api/storage?light
    # and the whole-page error wipe on the full route — while every healthy
    # sibling row was droppable collateral.  The hostile row drops alone.
    clean_vols = []
    for v in vols:
        try:
            row = _volume_row(v)
        except Exception:
            continue
        if row is not None:
            clean_vols.append(row)
    vols = clean_vols
    clean_disks = []
    for x in disks:
        try:
            d = _jsonable(x)
        except Exception:
            continue
        if isinstance(d, dict):
            clean_disks.append(d)
    disks = clean_disks
    system_vols = [v for v in vols if v.get("kind") == "system"]
    external_vols = [v for v in vols if v.get("kind") == "external"]
    other_vols = [
        v for v in vols
        if v.get("kind") not in ("system", "external")
    ]

    # Physical-ish capacity: system + external (exclude virtual OrbStack from array totals)
    cap_array = aggregate_capacity(vols, kinds={"system", "external"})
    cap_all = aggregate_capacity(vols, kinds=None)

    array_devices = []
    for v in system_vols + external_vols:
        array_devices.append({
            "role": "cache" if v.get("kind") == "system" else "data",
            "mount": v.get("mount"),
            "kind": v.get("kind"),
            "disk_id": v.get("disk_id"),
            "device": v.get("device") or v.get("filesystem"),
            "total_gb": _json_gb(v.get("total_gb")),
            "used_gb": _json_gb(v.get("used_gb")),
            "avail_gb": _json_gb(v.get("avail_gb")),
            "pct": _json_int(v.get("pct")),
            "filesystem": v.get("filesystem"),
            "shared_pool": False,  # filled below
        })

    # Mark shared-pool siblings so UI can show a hint
    groups = cap_array.get("groups") if isinstance(cap_array, dict) else None
    if not isinstance(groups, list):
        groups = []
    shared_keys = {
        g.get("disk_id") for g in groups
        if isinstance(g, dict) and g.get("mode") == "shared_pool" and g.get("disk_id")
    }
    for d in array_devices:
        if d.get("disk_id") in shared_keys:
            d["shared_pool"] = True

    return _jsonable({
        "volumes": vols,
        "disks": disks,
        "array": {
            "devices": array_devices,
            "system_count": len(system_vols),
            "data_count": len(external_vols),
            "other_count": len(other_vols),
            "disk_count": len(disks),
            "total_tb": cap_array["total_tb"],
            "used_tb": cap_array["used_tb"],
            "free_tb": cap_array["free_tb"],
            "total_gb": cap_array["total_gb"],
            "used_gb": cap_array["used_gb"],
            "free_gb": cap_array["free_gb"],
            "capacity_groups": cap_array["groups"],
            "status": "started",
        },
        "totals": {
            "volume_count": len(vols),
            "used_gb": cap_array["used_gb"],
            "total_gb": cap_array["total_gb"],
            "free_gb": cap_array["free_gb"],
            "all_including_virtual_gb": cap_all["total_gb"],
        },
    })
