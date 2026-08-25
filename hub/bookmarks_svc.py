"""Bookmark / quick_link health checks — green / gray / red.

health:
  ok      — reachable (green)
  stopped — the linked service/VM is deliberately stopped (gray)
  error   — expected online but the probe failed / unexpected exception (red)
"""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from hub.config import cfg
from hub.host_address import resolve_value
from hub.http_guard import _ip_from_host
from hub.errors import exc_detail
from hub.util import LazyPool, cached_snapshot, fan_out, strftime_now

_TTL = 120.0
_pool = LazyPool(2, "hub-bookmarks")


def shutdown_executor() -> None:
    _pool.shutdown()

#: A probe is an HTTP reachability check, nothing else.  urlopen also speaks
#: file:, ftp: and data:, and bookmark URLs are not all typed by the operator --
#: some are derived from container labels and VM metadata discovered at runtime --
#: so a "bookmark" could otherwise make the panel read a local file and report
#: its status back through the dashboard.
_ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Suffixes that mean "a host on my own network", where a self-signed
#: certificate is the norm rather than a sign of interception.
_PRIVATE_SUFFIXES = (".local", ".lan", ".internal", ".home", ".arpa")

#: Names that must never be probed. ``localhost`` is the panel itself;
#: ``metadata`` / ``metadata.google.internal`` are cloud IMDS aliases.
_BLOCKED_PROBE_NAMES = frozenset({
    "localhost",
    "metadata",
    "metadata.google.internal",
})


def _is_blocked_probe_host(host: str) -> bool:
    """Loopback, link-local (including 169.254.169.254), and IMDS names.

    Bookmark URLs come from quick_links and from discovered container/VM
    labels. Probing those would turn the dashboard into a LAN SSRF client
    against the panel, the metadata service, and other loopback listeners.
    """
    name = (host or "").strip().strip("[]").lower()
    if not name or name in _BLOCKED_PROBE_NAMES:
        return True
    # Same decimal / hex / IPv4-mapped parse as notify and Immich: ipaddress
    # rejects ``2852039166``, which is 169.254.169.254, and used to pass as
    # a single-label LAN name (TLS off, then a connect to IMDS).
    addr = _ip_from_host(name)
    if addr is None:
        return False
    return bool(
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
    )


def _is_private_host(host: str) -> bool:
    """Whether *host* is a LAN name we may probe with TLS verification off.

    RFC1918, ``.local`` / ``.lan`` / similar suffixes, and dotless short names
    are the Heimdall-style home-NAS case. Loopback, link-local, and unspecified
    addresses are not LAN for this purpose — they are blocked by
    :func:`_is_blocked_probe_host` before a socket is opened.

    Deliberately decided from the literal hostname and *not* from a DNS lookup.
    A resolver is not a trustworthy input for a security decision: split-horizon
    DNS, and fake-IP proxies such as Clash or Surge, map every public name into a
    private-looking range (198.18.0.0/15 in the case that surfaced this), which
    would have silently turned verification off for the entire internet.
    """
    name = (host or "").strip().strip("[]").lower()
    if not name or _is_blocked_probe_host(name):
        return False
    if name.endswith(_PRIVATE_SUFFIXES):
        return True
    addr = _ip_from_host(name)
    if addr is not None:
        return bool(addr.is_private)
    # Not a literal address.  A dotless short name is a LAN name in
    # practice ("nas", "pi"); anything with a dot is treated as a real
    # public DNS name and gets verified.  Integer/hex IPs are handled
    # above so ``134744072`` (8.8.8.8) is not a LAN name — but only up to
    # the 32-bit dword and CPython's 4300-digit int cap: a digit-only host
    # past either bound fell through ``_ip_from_host`` and read as a LAN
    # name, turning TLS verification off for it.  Same rule as
    # ``http_guard.local_http_origin``: a host with no letter is an
    # integer IP we failed to classify, not a LAN name, and a torn IPv6
    # leftover (``fe80:``) is not one either.
    return "." not in name and ":" not in name and any(c.isalpha() for c in name)


class _SchemeSafeRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse redirects that leave http/https.

    Without this, validating the bookmark URL up front is pointless: the remote
    server can answer 302 to a file: or ftp: location and urllib will follow it.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        if (parts.scheme or "").lower() not in _ALLOWED_SCHEMES:
            return None
        dest = parts.hostname or ""
        src = urllib.parse.urlsplit(getattr(req, "full_url", "") or "").hostname or ""
        # Loopback / link-local / IMDS are refused from every source, including
        # a LAN bookmark that 302s onto 169.254.169.254. A public bookmark that
        # 302s onto RFC1918 is still SSRF. LAN→LAN redirects stay allowed: that
        # is how a home NAS bookmark follows its own login bounce.
        if _is_blocked_probe_host(dest):
            return None
        if _is_private_host(dest) and not _is_private_host(src):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _probe_ms(t0: float) -> int:
    """Finite elapsed ms. Leftover ``time.time() = inf`` OverflowError'd GET /api/bookmarks."""
    try:
        ms = int((time.time() - t0) * 1000)
    except (TypeError, ValueError, OverflowError):
        return 0
    if ms != ms or ms in (float("inf"), float("-inf")):
        return 0
    return ms


def _probe(url: str, timeout: float = 3.0) -> dict:
    t0 = time.time()
    try:
        parts = urllib.parse.urlsplit(url)
        scheme = (parts.scheme or "").lower()
        if scheme not in _ALLOWED_SCHEMES:
            return {"ok": False, "status": None, "ms": 0,
                    "error": f"unsupported scheme: {scheme or 'none'}"}
        if _is_blocked_probe_host(parts.hostname or ""):
            return {"ok": False, "status": None, "ms": 0,
                    "error": "blocked host"}
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"User-Agent": "ServerHub-BookmarkProbe/1.0"},
        )
        handlers: list = [_SchemeSafeRedirects]
        if scheme == "https":
            if _is_private_host(parts.hostname or ""):
                # LAN service: a self-signed certificate is expected here, and
                # there is no meaningful interception risk inside the home network.
                ctx = ssl._create_unverified_context()
            else:
                # Public host: verify, so a network attacker cannot decide what
                # the dashboard reports about an internet-facing service.
                ctx = ssl.create_default_context()
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        # Empty ProxyHandler so HTTP(S)_PROXY cannot take this probe (and its
        # Host decision) to a resolver we did not check — the same hole notify
        # and the remote catalog already closed.
        handlers.append(urllib.request.ProxyHandler({}))
        # One opener so the scheme-safe redirect handler applies on every path.
        opener = urllib.request.build_opener(*handlers)
        with opener.open(req, timeout=timeout) as r:
            code = r.status
            r.read(256)
        ms = _probe_ms(t0)
        ok = 200 <= code < 400
        return {"ok": ok, "status": code, "ms": ms, "error": None}
    except urllib.error.HTTPError as e:
        ms = _probe_ms(t0)
        # 401/403 still means service is up
        ok = e.code in (401, 403)
        return {"ok": ok, "status": e.code, "ms": ms, "error": exc_detail(getattr(e, "reason", e), 120)}
    except Exception as e:
        ms = _probe_ms(t0)
        return {"ok": False, "status": None, "ms": ms, "error": exc_detail(e, 120)}


def _backend_index() -> dict:
    """Map id / name / url → backend runtime info for expected-state checks."""
    idx: dict[str, dict] = {}

    def put(key: str | None, info: dict):
        if not key:
            return
        idx[str(key)] = info
        # also strip common prefixes
        s = str(key)
        if s.startswith("orb:"):
            idx[s[4:]] = info

    # Three unrelated inventories -- UTM, OrbStack and the container engine -- and
    # none of them reads another's answer, yet this waited out their sum: measured at
    # six spawns in six waves, `utmctl list` then `orbctl list -f json` then
    # `orbctl list` then `docker ps -a`, one after another.
    #
    # Order is restored below rather than taken from completion, and that matters
    # here beyond cosmetics: `put()` lets a later entry overwrite an earlier one on
    # the same key, so which backend wins a name collision is decided by this
    # sequence.  `fan_out` returns results in submission order, so the winner is the
    # same one as when this ran top to bottom.
    #
    # Each collector absorbs its own failure, where a single try/except used to span
    # UTM and Orb together -- so an unavailable UTM also cost the Orb machines their
    # state, and every bookmark pointing at a stopped Orb machine got probed over the
    # network instead of being reported as stopped.
    def utm_vms() -> list:
        try:
            from hub import vms_svc
            return list(vms_svc.list_utm_vms() or [])
        except Exception:
            return []

    def orb_machines() -> list:
        try:
            from hub import vms_svc
            return list(vms_svc.list_orb_machines() or [])
        except Exception:
            return []

    def containers() -> list:
        try:
            from hub.discovery.containers import discover_containers
            items, _ = discover_containers()
            return list(items or [])
        except Exception:
            return []

    vm_rows, orb_rows, container_rows = fan_out(
        lambda collect: collect(), [utm_vms, orb_machines, containers], max_workers=3
    )

    try:
        for v in vm_rows + orb_rows:
            info = {
                "state": v.get("state") or "down",
                "status": v.get("status"),
                "kind": "vm",
                "backend": v.get("backend"),
                "name": v.get("name") or v.get("id"),
                "id": v.get("id"),
            }
            put(v.get("id"), info)
            put(v.get("uuid"), info)
            put(v.get("orb_name"), info)
            put(v.get("name"), info)
            if v.get("url"):
                put(f"url:{v['url'].rstrip('/')}", info)
    except Exception:
        pass

    try:
        for c in container_rows:
            info = {
                "state": c.get("state") or "down",
                "status": c.get("detail") or c.get("status"),
                "kind": "container",
                "name": c.get("name") or c.get("id"),
                "id": c.get("id"),
            }
            put(c.get("id"), info)
            put(c.get("name"), info)
            if c.get("url"):
                put(f"url:{c['url'].rstrip('/')}", info)
    except Exception:
        pass

    # overrides: map sid + url → best-effort (may fill gaps for launchd etc.)
    raw_ov = cfg().get("overrides")
    for sid, raw in (raw_ov.items() if isinstance(raw_ov, dict) else ()):
        try:
            ov = resolve_value(raw)
        except Exception:
            continue
        if not isinstance(ov, dict):
            continue
        if sid in idx:
            continue
        # only mark intentionally hidden/disabled as stopped if flag set
        if ov.get("expected") == "stopped" or ov.get("disabled") is True:
            info = {
                "state": "stopped",
                "status": "disabled",
                "kind": "override",
                "name": ov.get("name") or sid,
                "id": sid,
            }
            put(sid, info)
            if ov.get("url"):
                put(f"url:{str(ov['url']).rstrip('/')}", info)

    return idx


def _index_lookup(idx: dict, key) -> dict | None:
    """Look up a backend row. YAML leftovers like ``service: [nginx]`` are unhashable."""
    if not isinstance(idx, dict):
        return None
    if isinstance(key, bool) or not isinstance(key, (str, int)):
        return None
    s = key if isinstance(key, str) else str(key)
    if not s:
        return None
    row = idx.get(s)
    return row if isinstance(row, dict) else None


def _resolve_backend(link: dict, idx: dict) -> dict | None:
    """Find linked backend for a bookmark entry."""
    if not isinstance(link, dict):
        return None
    for key in (
        link.get("service"),
        link.get("id"),
        link.get("vm"),
        link.get("backend_id"),
    ):
        hit = _index_lookup(idx, key)
        if hit is not None:
            return hit
    url = str(link.get("url") or "").rstrip("/")
    if url:
        hit = _index_lookup(idx, f"url:{url}")
        if hit is not None:
            return hit
    # match override sid by identical url
    raw_ov = cfg().get("overrides")
    for sid, raw in (raw_ov.items() if isinstance(raw_ov, dict) else ()):
        try:
            ov = resolve_value(raw)
        except Exception:
            continue
        if not isinstance(ov, dict):
            continue
        ou = str(ov.get("url") or "").rstrip("/")
        if ou and ou == url:
            hit = _index_lookup(idx, sid)
            if hit is not None:
                return hit
    return None


def _compose_result(link: dict, probe: dict | None, backend: dict | None) -> dict:
    """Merge HTTP probe + backend expected-state into tri-state health."""
    if not isinstance(backend, dict):
        backend = None
    base = {
        "name": link.get("name"),
        "url": link.get("url"),
        "id": link.get("id") or link.get("service"),
        "service": link.get("service") or link.get("id"),
    }
    b_state = (backend or {}).get("state")
    # intentional stop / suspended (treat suspended as stopped-ish warn gray? user said 主动停止=灰)
    if b_state in ("stopped", "down") and (backend or {}).get("kind") == "vm":
        # VM: "stopped" = intentional; legacy "down" from old code treated as stopped for VMs
        # after our fix VMs use "stopped"; keep both
        if b_state == "stopped" or (backend or {}).get("status") in (
            "stopped", "stop", "exited", "created", "shutdown"
        ):
            return {
                **base,
                "ok": False,
                "health": "stopped",
                "status": None,
                "ms": None,
                "error": None,
                "reason": "backend_stopped",
                "backend": {
                    "id": backend.get("id"),
                    "name": backend.get("name"),
                    "kind": backend.get("kind"),
                    "state": backend.get("state"),
                    "status": backend.get("status"),
                },
            }
    if b_state == "stopped":
        return {
            **base,
            "ok": False,
            "health": "stopped",
            "status": None,
            "ms": None,
            "error": None,
            "reason": "backend_stopped",
            "backend": {
                "id": (backend or {}).get("id"),
                "name": (backend or {}).get("name"),
                "kind": (backend or {}).get("kind"),
                "state": b_state,
                "status": (backend or {}).get("status"),
            },
        }

    probe = probe or {"ok": False, "status": None, "ms": None, "error": "no probe"}
    if probe.get("ok"):
        health = "ok"
    else:
        # expected online (or unlinked) but unreachable → red
        health = "error"

    return {
        **base,
        "ok": health == "ok",
        "health": health,
        "status": probe.get("status"),
        "ms": probe.get("ms"),
        "error": probe.get("error"),
        "reason": None if health == "ok" else "probe_failed",
        "backend": (
            {
                "id": backend.get("id"),
                "name": backend.get("name"),
                "kind": backend.get("kind"),
                "state": backend.get("state"),
                "status": backend.get("status"),
            }
            if backend
            else None
        ),
    }


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    return text.encode("utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Unhashable YAML ``service: [nginx]`` was already isolated at lookup;
    ``name: 2026-08-19``, ``!!binary`` ids, ``id: .inf``, a ``!!set`` service,
    and leftover backend ``datetime`` / bytes / inf still leaked into
    GET /api/bookmarks. A leftover ``\\ud800`` in ``name`` still 500'd the
    same encoder (``ensure_ascii=False`` then UTF-8).
    """
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
        return _utf8_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, (str, bytes, bytearray)):
                try:
                    k = str(k)
                except Exception:
                    continue
            try:
                k = _utf8_text(k)
            except Exception:
                continue
            out[k] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            return _jsonable(iso(), depth + 1)
        except Exception:
            pass
    try:
        return _utf8_text(value)
    except Exception:
        return None


@cached_snapshot(_TTL)
def list_bookmarks() -> dict:
    """Bookmark health, cached for _TTL with one in-flight refresh.

    This cache had no lock at all before, which cost two things on a dashboard with
    more than one tab open: the probe sweep ran once per concurrent request instead
    of once -- up to eight HTTP probes each, the entire cost of this module -- and
    the two-key publish could be observed half-applied, so a reader saw the new
    timestamp beside the previous payload and served a stale answer as fresh for a
    whole TTL.
    """
    # The backend inventory does not read the link list, and resolving the links
    # reaches the host address -- a route lookup followed by an `ipconfig`, two
    # spawns deep -- so the two overlap instead of queueing.  Together with the
    # fan-out inside `_backend_index`, this took the endpoint from six spawns in six
    # waves to the same six in two.
    #
    # `_backend_index` is the one that can be slow (three CLIs), so it is submitted
    # first; the link resolution is then this thread's own work rather than a wait.
    f_idx = _pool.submit(_backend_index)

    raw_links = cfg().get("quick_links")
    try:
        links = resolve_value(list(raw_links) if isinstance(raw_links, list) else [])
    except Exception:
        links = list(raw_links) if isinstance(raw_links, list) else []
    if not isinstance(links, list):
        links = []
    raw_ov = cfg().get("overrides")
    overrides = raw_ov if isinstance(raw_ov, dict) else {}
    # also from overrides urls
    for sid, raw in overrides.items():
        try:
            ov = resolve_value(raw)
        except Exception:
            continue
        if not isinstance(ov, dict):
            continue
        if ov.get("url") and ov.get("hide") is not True:
            name = ov.get("name") or sid
            if not any(isinstance(l, dict) and l.get("url") == ov["url"] for l in links):
                links.append({
                    "name": name,
                    "url": ov["url"],
                    "id": sid,
                    "service": sid,
                })

    try:
        idx = f_idx.result()
    except Exception:
        # `_backend_index` already absorbs per-CLI failures; this is the
        # last net so a raise there still leaves the bookmark list.
        idx = {}
    if not isinstance(idx, dict):
        idx = {}

    # decide which need probe
    to_probe = []
    preassigned: dict[int, dict] = {}  # link index → result without probe
    for i, link in enumerate(links):
        if not isinstance(link, dict) or not link.get("url"):
            continue
        backend = _resolve_backend(link, idx)
        b_state = (backend or {}).get("state")
        if b_state == "stopped" or (
            backend
            and backend.get("kind") == "vm"
            and str(backend.get("status") or "").lower() in (
                "stopped", "stop", "exited", "created", "shutdown"
            )
        ):
            preassigned[i] = _compose_result(link, None, backend)
        else:
            to_probe.append((i, link, backend))

    def probe(url: str) -> dict:
        """Never raises: one unreachable bookmark must not drop the other rows."""
        try:
            return _probe(url)
        except Exception as e:  # noqa: BLE001 -- surfaced in the row
            return {"ok": False, "status": None, "ms": 0, "error": exc_detail(e, 120)}

    probes: dict[int, dict] = {
        i: _compose_result(link, result, backend)
        for (i, link, backend), result in zip(
            to_probe, fan_out(probe, [link["url"] for _, link, _ in to_probe])
        )
    }

    ordered = []
    seen = set()
    for i, link in enumerate(links):
        if not isinstance(link, dict):
            continue
        u = link.get("url")
        if not isinstance(u, str) or not u or u in seen:
            continue
        if i in preassigned:
            ordered.append(preassigned[i])
            seen.add(u)
        elif i in probes:
            ordered.append(probes[i])
            seen.add(u)

    up = sum(1 for r in ordered if r.get("health") == "ok")
    stopped = sum(1 for r in ordered if r.get("health") == "stopped")
    down = sum(1 for r in ordered if r.get("health") == "error")
    v = {
        "bookmarks": ordered,
        "up": up,
        "stopped": stopped,
        "down": down,
        "checked_at": strftime_now("%H:%M:%S"),
    }
    cleaned = _jsonable(v)
    return cleaned if isinstance(cleaned, dict) else v
