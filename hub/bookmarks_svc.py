"""Bookmark / quick_link health checks — green / gray / red.

health:
  ok      — reachable (green)
  stopped — the linked service/VM is deliberately stopped (gray)
  error   — expected online but the probe failed / unexpected exception (red)
"""
from __future__ import annotations

import re
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

#: Real control flow must keep propagating even through the bomb guards:
#: swallowing a Ctrl-C or an interpreter shutdown to save one bookmark row
#: would turn the sanitizer into a hang.  Everything else BaseException-shaped
#: that a leftover raises out of its own hooks is a bomb like any other —
#: every guard below used to stop at ``except Exception``, so a leftover
#: whose hooks raise a *BaseException* subclass (the jobs13/nas13/assistant13
#: watchdog/timeout shape) sailed past every net at once and 500'd
#: GET /api/bookmarks raw.
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

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
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # BaseException, not the (TypeError, ValueError, OverflowError) trio:
        # a leftover clock whose arithmetic hooks raise anything else — a
        # BaseException-subclass bomb included — escaped the narrower net,
        # and two of this helper's three call sites sit *inside* ``_probe``'s
        # own except handlers where nothing above caught it.
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
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        # BaseException, not Exception: a raw-kept str-subclass url whose
        # ``find`` / ``strip`` / ``__bool__`` hooks raise a BaseException
        # subclass detonated urlsplit / the host gates past the old net,
        # rode through the fan_out batch and 500'd the whole list route.
        # The host gates run before any socket opens, so a bomb still
        # fails closed — the row reads error, no probe happens.
        ms = _probe_ms(t0)
        return {"ok": False, "status": None, "ms": ms, "error": exc_detail(e, 120)}


def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so a value whose ``__class__`` is a raising
    property blew every unguarded gate here — the ``overrides`` /
    ``quick_links`` row plain-dict, the ``service:`` key scrub, the final
    ``_jsonable`` scrub and the merge-loop url compare — straight out of
    GET /api/bookmarks (the modules8 rule).  A lying ``__class__`` (answers
    ``int``) is *not* an error and still reports its claim here; the numeric
    arms' unbound base coercion then drops it, exactly as before.

    ``except BaseException``: the old guard stopped at ``Exception``, so a
    ``__class__`` property raising a *BaseException* subclass sailed past
    this catch — the gate every sanitizer arm in this module stands on —
    and out of GET /api/bookmarks raw.  Only genuine control flow keeps
    propagating.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _key_text(value) -> str | None:
    """Coerce a YAML/backend leftover into a scrubbed lookup key, or None.

    Two leftovers used to break the id → backend mapping here:

    * YAML hex/octal integers load uncapped (``int(x, 16)`` is exempt from
      CPython's 4300-digit conversion limit), so a leftover ``service:
      0xFF…`` arrived *already-int* and the bare ``str(key)`` raised the
      digit-cap ValueError — a 500 on GET /api/bookmarks from the lookup,
      and a silently-empty backend index from ``put``.  The probe is a
      str() attempt, not an ``isinstance(key, str)`` gate: a finite
      numeric id (``id: 8080``) must keep matching its backend row.
    * inventories publish names scrubbed (``vms_svc._as_text``) while YAML
      ``service: "cam\\ud800"`` stayed raw, so the two sides of the index
      keyed by different forms and a stopped VM's bookmark probed red
      instead of gray.  Keys are scrubbed on both put and lookup.
    """
    if _isinst(value, bool) or not _isinst(value, (str, int)):
        return None
    if _isinst(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int (the modules5 rule): an
                # int-subclass ``__str__`` bomb riding ``service:`` used
                # to raise past the ValueError-only catch below and 500
                # GET /api/bookmarks out of ``_resolve_backend``'s lookup.
                # BaseException, not Exception: an ``__index__`` bomb raising
                # a BaseException subclass sailed past the old net too.
                value = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        try:
            # ``except ValueError`` stays exactly this narrow (the pinned
            # union guard): *value* is an exact int here, so ``str()`` can
            # only raise the digit-cap ValueError — no hook of the leftover
            # runs on this line anymore.
            s = str(value)
        except ValueError:
            return None
    else:
        s = value
    return _utf8_text(s) or None


def _mapping_get(mapping, key, default=None):
    """Field read that a hostile mapping *key* cannot 500.

    The health11 rule on the bookmarks surface: even a plain-dict lookup
    still runs the *stored keys'* own ``__eq__`` during the hash probe.
    ``resolve_value`` launders row keys to exact strs, but its
    all-or-nothing fallback keeps the whole ``quick_links`` list raw when
    any sibling row bombs — and ``_plain_dict``'s C-level copy preserves a
    raw row's keys.  A leftover str-subclass key whose hash shadows
    ``url`` / ``name`` / ``service`` and whose ``__eq__`` raises then
    detonated every bound ``link.get(...)`` downstream — the url launder
    loop, the dedupe ``any()``, the probe-decision gate,
    ``_resolve_backend`` and ``_compose_result`` — a raw 500 on
    GET /api/bookmarks after every probe had already succeeded.  Only the
    shadowed field degrades to its default; the row's other fields and
    every sibling row survive.
    """
    if not _isinst(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # BaseException too: a stored shadow key whose ``__eq__`` raises a
        # BaseException subclass used to sail past the old net and out of
        # every bound field read this helper fronts.
        return default


def _plain_dict(value) -> dict | None:
    """*value* as a plain ``dict``, or None.

    A leftover dict-*subclass* (the usage5/metrics5 row-bomb class: passes
    the ``isinstance(x, dict)`` gate, then ``.get()`` / ``.items()`` /
    ``__bool__`` raises) used to 500 GET /api/bookmarks from four separate
    call sites — the overrides merge loop, ``_resolve_backend``'s override
    scan, the probe-decision loop, and the dedupe ``any()`` — and to wipe
    the whole backend index out of ``_backend_index``'s override loop.
    ``dict()`` copies through the C-level storage, so an overridden method
    cannot fire.
    """
    if not _isinst(value, dict):
        return None
    try:
        return dict(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _cmp_text(value) -> str:
    """*value* as an exact str for ``==`` / ``in`` decisions, else ``""``.

    State / status / kind compares used to run raw: a str-subclass
    ``__eq__`` bomb on a backend row's ``state`` 500'd the probe-decision
    loop (``b_state == "stopped"``) and ``_compose_result``'s tuple
    membership — the subclass side of ``==`` is asked first even when the
    bomb sits opposite an exact str.  A non-str bomb (``resolve_value``
    passes those through raw) blew the same compares from the reflected
    side.  Non-strs answer ``""``: they never matched a state literal
    before either, and ``""`` is not in any of the tuples compared here.
    """
    if not _isinst(value, str):
        return ""
    return _utf8_text(value)


def _cfg_get(key: str):
    """One config read, or None — a leftover config bomb cannot 500 through.

    ``cfg().get("quick_links")`` / ``…("overrides")`` used to run bare at
    four call sites, three of them on the request thread, so three whole
    families of leftover 500'd GET /api/bookmarks before a single link was
    even looked at:

    * a ``cfg`` that raises, or answers a non-mapping (None after a torn
      reload) — the ``.get`` AttributeError'd;
    * a dict-*subclass* config whose ``.get`` is a bomb (the usage5 row
      class riding the whole mapping instead of one row) — bypassed here
      by the unbound ``dict.get``, which reads the C-level storage;
    * a hash-shadowing key: a str-subclass key whose ``__hash__`` matches
      ``"quick_links"`` / ``"overrides"`` but whose ``__eq__`` raises.
      One subclass key degrades the whole dict to the generic lookup, so
      even the *exact-str probe key*'s ``.get`` asks the stored bomb's
      ``__eq__`` first and raised out of a plain ``dict``.

    The shadow case falls back to an item scan so one bomb key costs only
    itself: a shadowed ``overrides`` must not take ``quick_links`` with it.
    """
    try:
        m = cfg()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # BaseException too: a cfg() raising a BaseException-subclass bomb
        # (a leftover watchdog/timeout shape) used to sail past the old net
        # on the very first read of the request.
        return None
    if not _isinst(m, dict):
        return None
    try:
        return dict.get(m, key)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        pairs = list(dict.items(m))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    for pair in pairs:
        try:
            k, v = pair
            if type(k) is str and k == key:
                return v
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    return None


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb.

    Fails closed to False: a bomb url is not a probeable url and a bomb
    name is not a printable name — pre-fix, ``not link.get("url")`` and
    ``ov.get("url") and …`` raised straight out of GET /api/bookmarks.
    BaseException, not Exception: a ``__bool__`` bomb raising a
    BaseException subclass sailed past the old net the same way.
    """
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _backend_index() -> dict:
    """Map id / name / url → backend runtime info for expected-state checks."""
    idx: dict[str, dict] = {}

    def put(key, info: dict):
        s = _key_text(key)
        if not s:
            return
        idx[s] = info
        # also strip common prefixes
        if s.startswith("orb:"):
            idx[s[4:]] = info

    def put_url(url, info: dict):
        u = _key_text(url)
        if u:
            put("url:" + u.rstrip("/"), info)

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
    # BaseException, not Exception, in each collector: an inventory raising a
    # BaseException-subclass bomb used to sail past the old per-collector net,
    # ride the fan_out iteration into this builder's future, and re-raise at
    # ``f_idx.result()`` past *its* Exception-only net — a raw 500 on
    # GET /api/bookmarks from the pool thread.
    def utm_vms() -> list:
        try:
            from hub import vms_svc
            return list(vms_svc.list_utm_vms() or [])
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return []

    def orb_machines() -> list:
        try:
            from hub import vms_svc
            return list(vms_svc.list_orb_machines() or [])
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return []

    def containers() -> list:
        try:
            from hub.discovery.containers import discover_containers
            items, _ = discover_containers()
            return list(items or [])
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return []

    vm_rows, orb_rows, container_rows = fan_out(
        lambda collect: collect(), [utm_vms, orb_machines, containers], max_workers=3
    )

    # Per-row absorption, not one try spanning the loop: a single bomb row
    # (a dict-subclass ``.get`` bomb, or a ``__bool__`` bomb riding the
    # ``or "down"`` fallback) used to abort the whole loop and silently
    # wipe every sibling's entry — so all their stopped bookmarks probed
    # red instead of gray.  ``_plain_dict`` copies through C-level storage
    # first, so the row's own methods never run.
    for v in vm_rows + orb_rows:
        v = _plain_dict(v)
        if v is None:
            continue
        try:
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
            put_url(v.get("url"), info)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # BaseException too: a stored shadow key riding a copied row's
            # C-level storage used to blow this loop past the old net and
            # wipe every sibling's entry the same way as the Exception twin.
            continue

    for c in container_rows:
        c = _plain_dict(c)
        if c is None:
            continue
        try:
            info = {
                "state": c.get("state") or "down",
                "status": c.get("detail") or c.get("status"),
                "kind": "container",
                "name": c.get("name") or c.get("id"),
                "id": c.get("id"),
            }
            put(c.get("id"), info)
            put(c.get("name"), info)
            put_url(c.get("url"), info)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue

    # overrides: map sid + url → best-effort (may fill gaps for launchd etc.)
    # _plain_dict, not a bare isinstance: a dict-subclass overrides mapping
    # whose ``items()`` raised used to discard the entire index built above,
    # so every stopped VM's bookmark probed red instead of gray.  _cfg_get:
    # a raising / non-mapping / bomb-keyed config used to do the same.
    raw_ov = _plain_dict(_cfg_get("overrides")) or {}
    for sid, raw in raw_ov.items():
        try:
            # resolve_value stays deliberately raise-on-junk (the bookmarks5
            # pin): the walk itself is the junk detector.  Only the absorbing
            # net widens — a row whose hooks raise a BaseException subclass
            # out of the walk used to escape the old ``except Exception``.
            ov = resolve_value(raw)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        ov = _plain_dict(ov)
        if ov is None:
            continue
        key = _key_text(sid)
        if not key or key in idx:
            continue
        # only mark intentionally hidden/disabled as stopped if flag set.
        # _cmp_text: resolve_value launders str values but passes other
        # types through raw, so a non-str ``expected:`` __eq__ bomb used
        # to raise out of this compare and wipe the whole index built
        # above (absorbed at f_idx.result()) — every stopped VM's
        # bookmark probed red instead of gray.
        if _cmp_text(ov.get("expected")) == "stopped" or ov.get("disabled") is True:
            # _truthy: a __bool__-bomb name used to raise out of the ``or``
            # and cost the whole index the same way as the items() bomb.
            name = ov.get("name")
            info = {
                "state": "stopped",
                "status": "disabled",
                "kind": "override",
                "name": name if _truthy(name) else key,
                "id": key,
            }
            put(key, info)
            put_url(ov.get("url"), info)

    return idx


def _index_lookup(idx: dict, key) -> dict | None:
    """Look up a backend row. YAML leftovers like ``service: [nginx]`` are unhashable.

    The key goes through the same probe + scrub as the index side
    (:func:`_key_text`): a hex-YAML over-cap int used to ValueError the
    bare ``str(key)`` here — a 500 on GET /api/bookmarks.
    """
    if not _isinst(idx, dict):
        return None
    s = _key_text(key)
    if not s:
        return None
    row = idx.get(s)
    return row if _isinst(row, dict) else None


def _resolve_backend(link: dict, idx: dict) -> dict | None:
    """Find linked backend for a bookmark entry."""
    if not _isinst(link, dict):
        return None
    # _mapping_get throughout: a raw-kept row's hash-shadowing key (see
    # _mapping_get) used to detonate these bound reads per link.
    for key in (
        _mapping_get(link, "service"),
        _mapping_get(link, "id"),
        _mapping_get(link, "vm"),
        _mapping_get(link, "backend_id"),
    ):
        hit = _index_lookup(idx, key)
        if hit is not None:
            return hit
    url = (_key_text(_mapping_get(link, "url")) or "").rstrip("/")
    if url:
        hit = _index_lookup(idx, f"url:{url}")
        if hit is not None:
            return hit
    # match override sid by identical url.  _plain_dict: a dict-subclass
    # overrides mapping whose ``items()`` raised used to 500 the list route
    # out of this loop (unlike _backend_index, nothing absorbs a raise here).
    # _cfg_get, not a bare ``cfg().get``: a raising / non-mapping config, a
    # config-wide ``.get`` bomb subclass, and a hash-shadowing ``overrides``
    # key all raised here too — per link, on the request thread.
    raw_ov = _plain_dict(_cfg_get("overrides")) or {}
    for sid, raw in raw_ov.items():
        try:
            # raise-on-junk kept; the absorbing net widens (see _backend_index).
            # This copy runs per link on the request thread, where a
            # BaseException-shaped row bomb was a raw 500 past the old net.
            ov = resolve_value(raw)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        ov = _plain_dict(ov)
        if ov is None:
            continue
        ou = (_key_text(ov.get("url")) or "").rstrip("/")
        if ou and ou == url:
            hit = _index_lookup(idx, sid)
            if hit is not None:
                return hit
    return None


def _compose_result(link: dict, probe: dict | None, backend: dict | None) -> dict:
    """Merge HTTP probe + backend expected-state into tri-state health."""
    if not _isinst(backend, dict):
        backend = None
    # _truthy, not a bare ``or``: a __bool__-bomb id/service value used to
    # raise here and 500 the list route with every healthy sibling row.
    # _mapping_get: a raw-kept row's hash-shadowing key detonated the
    # bound reads the same way (see _mapping_get).
    lid = _mapping_get(link, "id")
    service = _mapping_get(link, "service")
    base = {
        "name": _mapping_get(link, "name"),
        "url": _mapping_get(link, "url"),
        "id": lid if _truthy(lid) else service,
        "service": service if _truthy(service) else lid,
    }
    # _cmp_text throughout: these compares used to run raw, so an __eq__
    # bomb riding a backend row's state / status / kind 500'd the list
    # route from here — the tuple membership asks the subclass first.
    b_state = _cmp_text((backend or {}).get("state"))
    # intentional stop / suspended (treat suspended as stopped-ish warn gray? user said 主动停止=灰)
    if b_state in ("stopped", "down") and _cmp_text((backend or {}).get("kind")) == "vm":
        # VM: "stopped" = intentional; legacy "down" from old code treated as stopped for VMs
        # after our fix VMs use "stopped"; keep both
        if b_state == "stopped" or _cmp_text((backend or {}).get("status")) in (
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


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500.

    The unbound base reads the operand's C-level buffer, so a *real* bytes /
    bytearray subclass whose ``.decode`` is a bomb decodes safely.  A *lying*
    ``__class__`` that answers ``bytes`` / ``bytearray`` without the matching
    storage is admitted by ``_isinst`` (that is not an error, the bookmarks8
    rule) but then has no buffer for the unbound base to read, so
    ``bytes.decode(value)`` raises ``TypeError`` — pre-fix that rode the
    ``_jsonable`` bytes branch out to a 500 on GET /api/bookmarks.  Fall back
    to ``""`` so the row still renders and its siblings survive.

    Both bases, real layout first-come (the jobs13/nas13/assistant13 rule):
    the old pick chose the base off the *claimed* ``__class__``, so a genuine
    ``bytearray`` whose ``__class__`` lied ``bytes`` was handed to
    ``bytes.decode``, refused by the descriptor, and its perfectly decodable
    content dropped to the empty cell even though the text was right there.
    Real str storage lying bytes recovers through ``_str_text`` the same way.
    A total liar (real type is none of the three) still drops to ``""``.
    BaseException, not Exception: a subclass ``decode`` never dispatches
    here, but a bomb hook reached mid-decode sailed past the old net.
    """
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    return _str_text(value) or ""


#: CPython's angle-repr shape (``<X object at 0x7f...>`` and the function /
#: bound-method variants) — a raw heap address, never bookmark data.
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _str_text(value) -> str | None:
    """Exact text of *really-str* storage, or ``None`` for an impostor.

    ``str.__str__`` is a descriptor bound to the real str layout: any real
    str (or subclass — even one riding a ``__str__`` / ``encode`` bomb)
    answers its character data without dispatching the override, while a
    *lying* ``__class__`` that only claims str rejects the operand.  The old
    dispatching ``str()`` rendered that impostor's ``repr`` — a raw memory
    address — into name / id / service cells of GET /api/bookmarks (the
    assistant12 rule).  The encode-replace pass scrubs lone surrogates the
    same way as before.
    """
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if _isinst(value, (bytes, bytearray)):
        return _decode_bytes(value)
    if _isinst(value, str):
        # Unbound base read, not the dispatching ``str()``: real str storage
        # keeps its text even when the subclass ``__str__`` raises, and a
        # lying ``__class__`` claiming str drops to "" instead of leaking
        # its ``repr`` (a heap address) into the response body.
        return _str_text(value) or ""
    # Only a type that renders *itself* may coerce.  This free-text arm ran
    # ``str()`` on any leftover shape, and for a type that never overrode
    # ``__str__`` / ``__repr__`` the answer is the default ``object.__repr__``
    # — ``<X object at 0x7f...>``, a raw heap address — which a junk link
    # name / id / service, an override sid riding into the merged row, and
    # a backend row's state / status / name / id / detail all carried
    # verbatim into the GET /api/bookmarks body.  A slot probe on the real
    # ``type(value)``, not an instance lookup: a ``__getattr__`` bomb
    # answers instance probes and a flickering ``__class__`` property
    # cannot swap the real type out.
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # BaseException, not Exception: a coercion ``__str__`` bomb raising
        # a BaseException subclass sailed past the old net and 500'd the
        # route from every rendered cell this arm fronts.
        return ""
    # Unbound base encode: ``str()`` of a subclass whose ``__str__`` answers
    # *self* skips CPython's exact-str copy, so a leftover bound ``encode``
    # bomb rode this line to a 500 — through ``_jsonable``'s str branch and
    # ``_key_text``'s lookup path alike.  ``str.encode`` reads the C-level
    # storage and always answers an exact str after the decode round-trip.
    text = str.encode(text, "utf-8", "replace").decode("utf-8")
    # Belt for what the slot probe cannot see: a function / bound-method
    # leftover (C-level ``__repr__`` override) and a value whose *rendering*
    # embeds a default repr (``{'x': <_Junk object at 0x...>}``) still
    # answered an address.  Only this coercion arm is scrubbed — real
    # str/bytes storage above is data and stays verbatim.
    return "" if _ADDR_REPR_RE.search(text) else text


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
    if value is None:
        return value
    if _isinst(value, bool):
        # ``bool`` is final — it cannot be subclassed — so an ``_isinst(...,
        # bool)`` True on a value whose real type is *not* ``bool`` is a lying
        # ``__class__`` impostor (bookmarks8), not a real bool.  Returned as-is
        # it leaked straight into Starlette's ``allow_nan=False`` encoder,
        # which cannot serialise the impostor and 500'd GET /api/bookmarks.
        # A real bool passes through; the impostor is dropped like a lying int.
        return value if type(value) is bool else None
    if _isinst(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int (modules5): a subclass
                # ``__str__`` bomb used to blow the digit-cap probe below
                # with a non-ValueError and 500 the route at encode time.
                # BaseException: an ``__index__`` bomb raising a
                # BaseException subclass sailed past the old net too.
                value = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        try:
            # ``except ValueError`` stays exactly this narrow (the pinned
            # union guard): *value* is an exact int here, so only the
            # digit-cap ValueError can fire.
            str(value)
        except ValueError:
            # YAML hex/octal leftovers dodge CPython's str->int digit cap,
            # so an over-cap link field arrived here already-int and
            # Starlette's own json.dumps raised the int->str digit-cap
            # ValueError — same drop as its inf float sibling.
            return None
        return value
    if _isinst(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isinst(value, str):
        return _utf8_text(value)
    if _isinst(value, (bytes, bytearray)):
        return _decode_bytes(value)
    if _isinst(value, dict):
        try:
            items = list(value.items())
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A mapping that refuses iteration (odd dict subclass riding a
            # link field): nothing to salvage from it, but its *siblings*
            # must survive — pre-fix this raised out of the final scrub and
            # 500'd GET /api/bookmarks (the ups_svc/nginx_svc rule) — and a
            # BaseException-shaped ``items`` bomb sailed past even that net.
            return None
        out = {}
        for pair in items:
            try:
                # Guarded unpack: an ``items()`` that answers non-pairs
                # (``[1, 2]``) used to TypeError here, outside the list()
                # try just above, and 500 the route at encode time.
                k, v = pair
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
            # No raw ``str(k)`` pre-coercion: a junk *key* (default
            # ``object.__repr__``) used to render its heap address as the
            # JSON key itself, one rank above the value scrub.  ``_utf8_text``
            # coerces the renderable kinds (int / float / tuple keys) the
            # same as before and drops the address shapes to "".
            was_text = _isinst(k, (str, bytes, bytearray))
            try:
                k = _utf8_text(k)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
            if not k and not was_text:
                # A key with no real text storage that coerced to nothing:
                # there is no name to file the value under — the pair drops
                # alone, siblings survive.  A real empty-str key stays.
                continue
            out[k] = _jsonable(v, depth + 1)
        return out
    if _isinst(value, (list, tuple, set, frozenset)):
        try:
            vals = list(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A sequence subclass whose __iter__ raises: same rule as the
            # dict branch — the bomb drops alone, siblings keep rendering.
            return None
        return [_jsonable(v, depth + 1) for v in vals]
    try:
        iso = getattr(value, "isoformat", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # getattr's default only swallows AttributeError; a leftover
        # ``__getattr__`` that raises anything else 500'd the final scrub —
        # and a BaseException-shaped one sailed past even the Exception net.
        iso = None
    if callable(iso):
        try:
            return _jsonable(iso(), depth + 1)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    try:
        return _utf8_text(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
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

    # _cfg_get: the very first read of the request.  A cfg() that raises,
    # answers None (torn reload), carries a subclass ``.get`` bomb, or holds
    # a hash-shadowing ``quick_links`` key used to 500 the route right here,
    # before a single link was looked at.
    raw_links = _cfg_get("quick_links")
    try:
        # Materialised once, on its own: a list-subclass ``__iter__`` bomb
        # used to raise out of ``list(raw_links)`` here and then raise a
        # second time out of the identical call in the except fallback — a
        # 500 from the exception handler itself.
        base_links = list(raw_links) if _isinst(raw_links, list) else []
    except _CONTROL_FLOW:
        raise
    except BaseException:
        base_links = []
    try:
        # raise-on-junk kept (the bookmarks5 pin): resolve_value's walk is
        # the junk detector and this absorb is its contract.  Only the net
        # widens — a row bombing the walk with a BaseException subclass
        # used to escape the old ``except Exception`` and 500 the route.
        links = resolve_value(list(base_links))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        links = base_links
    if not _isinst(links, list):
        links = []
    # Plain-dict every row up front: resolve_value launders well-behaved
    # rows into plain dicts, but its all-or-nothing fallback keeps the raw
    # list when any single row bombs, so a dict-subclass ``.get`` bomb used
    # to ride into every loop below and 500 the route.  Non-dict junk rows
    # were already skipped everywhere; dropping them here changes nothing.
    links = [row for row in (_plain_dict(l) for l in links) if row is not None]
    # Launder real-str urls up front: resolve_value normally answers exact
    # strs, but its all-or-nothing fallback keeps the whole list raw when a
    # sibling row bombs, so a raw-kept str-subclass ``__bool__`` /
    # ``__len__`` bomb url used to 500 the dedupe loop's bare ``not u`` and,
    # even short of that, to vanish its row at the ``_truthy`` probe gate —
    # though the underlying url text was fine.  The unbound ``str.encode``
    # reads the C-level storage, so only a value with *real* str storage is
    # rewritten; a lying ``__class__`` impostor raises here and keeps its
    # existing drop/error path.
    for row in links:
        # _mapping_get: a raw-kept row's hash-shadowing ``url`` key used to
        # detonate this bound read — the first seam of the request loop.
        u = _mapping_get(row, "url")
        if _isinst(u, str) and type(u) is not str:
            try:
                row["url"] = str.encode(u, "utf-8", "replace").decode("utf-8")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                pass
    # _plain_dict, not a bare isinstance: an overrides mapping whose
    # ``items()`` raised used to 500 the merge loop below.  _cfg_get for
    # the same three config-level bombs as the quick_links read above.
    overrides = _plain_dict(_cfg_get("overrides")) or {}
    # also from overrides urls
    for sid, raw in overrides.items():
        try:
            # raise-on-junk kept; only the absorbing net widens (see above).
            ov = resolve_value(raw)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        ov = _plain_dict(ov)
        if ov is None:
            continue
        # _truthy: a __bool__-bomb url or name value used to raise straight
        # out of this ``and`` / ``or`` and 500 the route.
        if _truthy(ov.get("url")) and ov.get("hide") is not True:
            name = ov.get("name")
            if not _truthy(name):
                name = sid
            # Laundered compare on *both* sides: the left is a link url
            # that survived resolve_value's all-or-nothing fallback, and a
            # str *subclass* ``__eq__`` bomb there is called first even on
            # the right (subclass reflected-first rule).  The right is the
            # override url — resolve_value launders strs, but passes other
            # types through raw, so a non-str ``url:`` __eq__ bomb used to
            # 500 this dedupe from the reflected side.  A non-str url can
            # never equal a str link url, so it skips the scan entirely.
            ov_url = ov["url"]
            ov_cmp = _utf8_text(ov_url) if _isinst(ov_url, str) else None
            # _mapping_get in the scan: a raw-kept link row's shadow ``url``
            # key used to detonate the bound read inside this any().
            if ov_cmp is None or not any(
                _isinst(l, dict)
                and _isinst(_mapping_get(l, "url"), str)
                and _utf8_text(_mapping_get(l, "url")) == ov_cmp
                for l in links
            ):
                links.append({
                    "name": name,
                    "url": ov["url"],
                    "id": sid,
                    "service": sid,
                })

    try:
        idx = f_idx.result()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # `_backend_index` already absorbs per-CLI failures; this is the
        # last net so a raise there still leaves the bookmark list.
        # BaseException, not Exception: ``Future.result()`` re-raises the
        # worker's exception verbatim, so a collector bombing the pool
        # thread with a BaseException subclass used to detonate *here*, on
        # the request thread, past the old net — a raw 500 after every
        # link had already been resolved.
        idx = {}
    if not _isinst(idx, dict):
        idx = {}

    # decide which need probe
    to_probe = []
    preassigned: dict[int, dict] = {}  # link index → result without probe
    for i, link in enumerate(links):
        # _truthy: a __bool__-bomb url value used to raise out of the bare
        # ``not link.get("url")`` and 500 the route.  _mapping_get: a
        # raw-kept row's hash-shadowing ``url`` key detonated the bound
        # read itself the same way (see _mapping_get).
        if not _isinst(link, dict) or not _truthy(_mapping_get(link, "url")):
            continue
        backend = _resolve_backend(link, idx)
        # _cmp_text on state / status / kind: a __bool__-bomb status used
        # to raise out of a bare ``str(… or "")`` here, and an __eq__-bomb
        # state / kind then 500'd the compares below the same way — at
        # decision time, after the index had already been built.
        b_state = _cmp_text((backend or {}).get("state"))
        vm_status = _cmp_text((backend or {}).get("status")).lower()
        if b_state == "stopped" or (
            backend
            and _cmp_text(backend.get("kind")) == "vm"
            and vm_status in (
                "stopped", "stop", "exited", "created", "shutdown"
            )
        ):
            preassigned[i] = _compose_result(link, None, backend)
        else:
            to_probe.append((i, link, backend))

    def probe(url: str) -> dict:
        """Never raises: one unreachable bookmark must not drop the other rows.

        BaseException, not Exception: fan_out's ``map`` re-raises on
        iteration, so one bomb url raising a BaseException subclass out of
        ``_probe``'s own seams used to cost the whole batch — a raw 500
        with every healthy sibling's probe already done.
        """
        try:
            return _probe(url)
        except _CONTROL_FLOW:
            raise
        except BaseException as e:  # noqa: BLE001 -- surfaced in the row
            return {"ok": False, "status": None, "ms": 0, "error": exc_detail(e, 120)}

    probes: dict[int, dict] = {
        i: _compose_result(link, result, backend)
        for (i, link, backend), result in zip(
            to_probe, fan_out(probe, [_mapping_get(link, "url") for _, link, _ in to_probe])
        )
    }

    ordered = []
    seen = set()
    for i, link in enumerate(links):
        if not _isinst(link, dict):
            continue
        # _mapping_get: same raw-kept shadow-``url`` class as the probe
        # decision loop — this dedupe runs after every probe succeeded.
        u = _mapping_get(link, "url")
        if not _isinst(u, str):
            continue
        # Exact-str copy *before any truthiness*: the old ``… or not u``
        # asked the raw value for ``bool()`` first, so a raw-kept str
        # subclass ``__bool__`` / ``__len__`` bomb (resolve_value's
        # all-or-nothing fallback keeps the whole list raw when a sibling
        # row bombs) and a lying ``__class__`` str impostor with a bomb
        # ``__bool__`` — admitted by ``_isinst``, never laundered because
        # it is not a real str — both 500'd the route from this dedupe,
        # after every probe had already succeeded.  ``_utf8_text`` answers
        # an exact str, so ``not u`` / ``u in seen`` / ``seen.add`` below
        # cannot ask the leftover anything.  The same copy already guarded
        # the hash side (a raw-kept ``__hash__`` bomb / ``__hash__ = None``
        # url used to 500 the membership check).
        u = _utf8_text(u)
        if not u or u in seen:
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
