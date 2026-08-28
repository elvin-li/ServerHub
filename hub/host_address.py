"""Central host-address discovery and configuration-template expansion."""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import threading
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from hub.util import sh, ttl_memo

#: Short: these are dependency reads, and every consumer already sits behind a
#: longer cache of its own.  Long enough to collapse the readers inside one
#: request, which is where every duplicate was measured.
_ROUTE_TTL = 5.0
_ADDRESS_TTL = 5.0

_AUTO_VALUES = {"", "auto", "automatic", "dhcp", "dynamic"}
#: Listen addresses are not an advertised LAN identity. If SERVERHUB_HOST is
#: 127.0.0.1 (the default bind) or 0.0.0.0, {host} templates still resolve
#: through route detection / settings.host_ip.
_BIND_ONLY_HOSTS = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1", "[::]", "[::1]"})
_VAR_RE = re.compile(r"\$?\{([A-Za-z][A-Za-z0-9_.-]{0,63})\}")
_cache_lock = threading.Lock()
#: Held across the detection itself, so concurrent callers that miss a cold cache
#: wait for one answer instead of each running the probes.  Separate from
#: `_cache_lock`, which is only ever held for the dict access: holding one lock for
#: both would block every cache *read* for the duration of a refresh.
_detect_refresh_lock = threading.Lock()
_detect_cache: dict[str, Any] = {"t": 0.0, "value": None}
_DETECT_TTL = 30.0
#: Bumped by `invalidate_routing`.  Because the refresh deliberately runs
#: outside `_cache_lock`, an invalidate can land in the middle of one -- and
#: every caller of `invalidate_routing` has just changed the very address being
#: detected.  Publishing the pre-change answer over it would report the address
#: the operator replaced for another thirty seconds.
_detect_generation = 0


def _isa(value, kinds) -> bool:
    """``isinstance`` that a leftover ``__class__``-property bomb cannot 500.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the gates themselves: planted in the LAN-detection cache it
    blew ``_as_text``'s bytes gate one step ahead of every scrub and 500'd
    ``host_ip()``'s one unguarded consumer, GET /api/system/host (the
    docker_cli / nas8 rule).  A real subclass still matches through the
    C-level type check; only a value that cannot answer what it is takes
    the non-matching branch.
    """
    try:
        return isinstance(value, kinds)
    except Exception:
        return False


def _mapping_get(mapping, key, default=None):
    """Field read that a hostile mapping *key* cannot 500.

    The health11 / dash11 rule, which this module's LAN-detection cache
    never got: even a plain-dict lookup still runs the *stored keys'* own
    ``__eq__`` during the hash probe, so a leftover str-subclass key whose
    hash shadows ``value`` and whose ``__eq__`` raises used to detonate the
    bare ``_detect_cache["value"]`` read in ``_cached_detection`` — a raw
    500 on ``host_ip()``'s one unguarded consumer, GET /api/system/host.
    Only the shadowed field degrades to its default; siblings survive.
    """
    if not _isa(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except Exception:
        return default


def _cache_publish(cache: dict, **fields) -> None:
    """Cache write that a hash-shadowing planted key cannot 500.

    ``dict.update`` with an exact-str keyword still runs the *stored*
    poison key's ``__eq__`` during the insert compare, so a shadow key
    planted over ``t`` used to raise at the very end of a successful
    detection — the ``_detect_cache.update`` in ``_detect_lan_ip_uncached``
    — and out of ``invalidate_routing`` (which ``network_svc._bust()``
    reaches on every address / DNS / order / alias change).  ``clear()``
    never compares keys, so evicting the poison and rewriting always lands.
    """
    try:
        cache.update(fields)
    except Exception:
        try:
            cache.clear()
            cache.update(fields)
        except Exception:
            pass


def _sh_run(cmd, timeout) -> tuple:
    """Spawn with the unpack inside the guard (the nginx `_sh_triple` rule).

    This module does not own ``sh`` (tests and tooling patch it), and a
    patched/odd one — raising outright, or answering a 2-tuple, a scalar,
    a tuple subclass whose ``__iter__`` raises, or a lying-``__class__``
    tuple impostor — used to detonate the bare ``rc, output, _ = sh(…)``
    unpacks in ``_default_route_fields`` / ``_interface_address``.  The
    raise rode ``detect_lan_ip`` out of ``host_ip()`` and 500'd its one
    unguarded consumer, GET /api/system/host (and GET /api/settings).
    Junk degrades to ``(-255, "", "")`` — nonzero, never a success rc, so
    the callers keep their empty-answer branch.
    """
    try:
        value = sh(cmd, timeout=timeout)
    except Exception:
        return (-255, "", "")
    if type(value) is tuple:
        items = value
    elif _isa(value, tuple):
        try:
            items = tuple(tuple.__iter__(value))
        except Exception:
            return (-255, "", "")
    elif _isa(value, list):
        try:
            items = tuple(list.__iter__(value))
        except Exception:
            return (-255, "", "")
    else:
        return (-255, "", "")
    if len(items) != 3:
        return (-255, "", "")
    return items


def _rc_int(rc) -> int:
    """Exact exit status for the ``==`` / ``!=`` probes; a bomb reads as failure.

    This module does not own ``sh`` (tests and tooling patch it), and an
    rc-*subclass* whose ``__eq__``/``__ne__`` raises used to detonate the
    bare ``rc != 0`` in ``_default_route_fields`` — straight out of
    ``host_ip()`` and 500ing GET /api/system/host (the health9 rule).
    ``-255`` is no honest exit status, so a bomb keeps the failure branch.
    """
    try:
        if isinstance(rc, bool):
            return int(rc)
        if isinstance(rc, int):
            return int.__index__(rc)
        return int(rc)
    except Exception:
        return -255


def _as_text(value) -> str:
    """Drop leftover ``\\ud800`` so host_ip JSON cannot UTF-8 500."""
    # _isa, not a bare isinstance: a ``__class__``-property bomb planted in
    # the detection cache used to detonate this gate itself.
    decoded = None
    if _isa(value, (bytes, bytearray)):
        try:
            # Unbound base decode: a bytes-subclass ``decode`` bomb planted
            # in the detection cache must not raise out of this scrub (the
            # modules5 convention its sibling sanitizers already use).  The
            # try is for a *lying* ``__class__`` (claims bytes, is not): the
            # unbound call TypeErrors and the impostor renders like any
            # other junk object below.
            base = bytes if isinstance(value, bytes) else bytearray
            decoded = base.decode(value, "utf-8", "replace")
        except Exception:
            decoded = None
    if decoded is not None:
        value = decoded
    elif value is None:
        return ""
    elif type(value) is not str:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    # Unbound ``str.encode``: a str-subclass whose ``__str__`` answers *self*
    # skips CPython's exact-str copy above and used to carry its bound
    # ``encode`` bomb into this scrub — a leftover planted in the LAN-address
    # detection cache then raised straight out of ``host_ip()`` and 500'd its
    # one unguarded consumer, GET /api/system/host (the status.py convention).
    try:
        return str.encode(value, "utf-8", "replace").decode("utf-8")
    except Exception:
        # Only a lying-``__class__`` str impostor lands here: junk.
        return ""


def configured_host() -> str:
    """Return the advertised host selector; auto means route discovery.

    ``SERVERHUB_HOST`` is also the bind address. Loopback and unspecified
    values there must not become ``{host}`` in bookmark / compose URLs.
    ``SERVERHUB_HOST_IP`` remains an explicit advertised-address override.
    """
    advertised = _as_text(os.environ.get("SERVERHUB_HOST_IP") or "").strip()
    if advertised and advertised not in _BIND_ONLY_HOSTS:
        return advertised
    bind_or_host = _as_text(os.environ.get("SERVERHUB_HOST") or "").strip()
    if bind_or_host and bind_or_host not in _BIND_ONLY_HOSTS:
        return bind_or_host
    try:
        from hub.config import cfg

        return _as_text((cfg().get("settings") or {}).get("host_ip") or "auto").strip()
    except Exception:
        return "auto"


def _usable_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(_as_text(value).strip())
    except (ValueError, TypeError):
        return False
    return not (address.is_loopback or address.is_unspecified or address.is_link_local)


@ttl_memo(_ROUTE_TTL)
def _default_route_fields() -> tuple[tuple[str, str], ...]:
    """One `route -n get default`, parsed into its ``key: value`` lines.

    Four modules asked the routing table this same question and each shelled out
    for it -- here, ``power_svc._default_iface``, ``wireguard_net_svc``'s WAN
    lookup and ``network_svc.default_route`` -- with three different timeouts and
    two different parses.  One ``/api/system/host`` read ran the command twice and
    ``/api/system/power`` did too, because the NIC branch and the host-address
    branch each started from scratch.

    Returned as an immutable tuple of pairs so the memo cannot be corrupted by a
    caller; :func:`default_route` builds a fresh dict from it per call.

    Memoised for :data:`_ROUTE_TTL`, which is far shorter than the 30s that
    :func:`detect_lan_ip` already caches the address *derived* from this -- so this
    adds no staleness that the module did not already accept.  ``network_svc._bust()``
    drops it alongside the interface and service-order caches, so a manual address
    change, a service reorder or an alias edit is reflected immediately.
    """
    # _sh_run: an sh answer-*shape* bomb (2-tuple, scalar, iter-bomb tuple
    # subclass, tuple liar) used to detonate this bare unpack itself and
    # 500 every host_ip() consumer, one seam ahead of the rc probe below.
    rc, output, _ = _sh_run(["/sbin/route", "-n", "get", "default"], timeout=5)
    # _rc_int: an rc-subclass ``__ne__`` bomb from a patched/odd ``sh`` used
    # to detonate this bare probe and 500 every host_ip() consumer.
    if _rc_int(rc) != 0:
        return ()
    fields: list[tuple[str, str]] = []
    # int / None / bytes payloads used to AttributeError on splitlines and
    # 500 every host_ip() consumer (status, bookmarks, compose URLs).
    for line in _as_text(output).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields.append((key.strip(), value.strip()))
    return tuple(fields)


def _route_fields(force: bool) -> dict[str, str]:
    """The memoised route fields, re-read from the host when *force*.

    ``force`` drops the memo and reads through it rather than passing a flag into
    the memoised function: an argument would become part of the cache key, so
    ``force=True`` would populate a *second* entry and leave the stale one to be
    served to everyone else.  That is the specific mistake this module is exempted
    for in tests/test_cache_single_flight.py, and re-introducing it broke
    ``detect_lan_ip(force=True)``.
    """
    if force:
        _default_route_fields.invalidate()
    return dict(_default_route_fields())


def default_route(*, force: bool = False) -> dict:
    """Gateway and interface of the default route, plus the raw field map.

    A fresh dict per call over an immutable memo: this is returned straight into an
    API payload, and handing out the cached object would let one caller's annotation
    become every later caller's answer.
    """
    raw = _route_fields(force)
    return {
        "gateway": raw.get("gateway"),
        "interface": raw.get("interface"),
        "raw": raw,
    }


def default_interface(*, force: bool = False) -> str:
    """The interface holding the default route, e.g. ``en0``, or ``""``."""
    return _route_fields(force).get("interface") or ""


@ttl_memo(_ADDRESS_TTL)
def _interface_address(interface: str) -> str:
    # _sh_run: same answer-shape bomb class as _default_route_fields.
    rc, output, _ = _sh_run(["/usr/sbin/ipconfig", "getifaddr", interface], timeout=3)
    # _rc_int: same rc-``__eq__`` bomb class as _default_route_fields.
    return _as_text(output).strip() if _rc_int(rc) == 0 else ""


def interface_address(interface: str, *, force: bool = False) -> str:
    """The IPv4 address of *interface*, or ``""``.

    Memoised per interface, so the two callers that both ask about the default one
    -- the host page's interface sweep and :func:`detect_lan_ip` -- share a spawn
    while a sweep over five interfaces still runs its five concurrently.  ``ttl_memo``
    locks per key, not globally, which is what keeps that fan-out a fan-out.
    """
    if not interface:
        return ""
    if force:
        _interface_address.invalidate()
    return _interface_address(interface)


def invalidate_routing() -> None:
    """Forget the routing table, the per-interface addresses and the LAN address.

    Called by ``network_svc._bust()``, which every path that changes an address, a
    DNS server, the service order or an alias already reaches.  Without it those
    handlers would re-read and report the configuration they replaced.
    """
    global _detect_generation
    _default_route_fields.invalidate()
    _interface_address.invalidate()
    with _cache_lock:
        _detect_generation += 1
        # _cache_publish, not a bare update: a hash-shadowing key planted
        # over ``value`` / ``t`` raises out of the C-level insert compare,
        # and network_svc._bust() reaches this on every address change.
        _cache_publish(_detect_cache, t=0.0, value=None)


def _cached_detection(now: float) -> str:
    with _cache_lock:
        # _mapping_get, not a bare subscript: a hash-shadowing key planted
        # over ``value`` (str subclass, same hash, raising ``__eq__``) ran
        # the stored bomb's compare inside the C-level probe — a raw 500 on
        # GET /api/system/host, one seam ahead of the ``t`` read already in
        # the try below.  A poisoned slot reads as None and re-detects.
        value = _mapping_get(_detect_cache, "value")
        try:
            age = now - float(_mapping_get(_detect_cache, "t", 0.0))
        except Exception:
            # Blanket, not the typed trio: a leftover planted in the ``t``
            # slot whose ``__float__`` raises RuntimeError (the same bomb
            # class its ``value`` sibling already absorbs below) used to
            # escape the numeric catch and 500 every host_ip() consumer.
            # Any unreadable stamp is a cache miss and re-detects.
            return ""
        # Guarded truthiness: the cache normally only ever holds the exact
        # str ``_detect_lan_ip_uncached`` writes, but a leftover whose
        # ``__bool__`` raises used to detonate this probe and 500 every
        # host_ip() consumer.  A bomb reads as a miss and re-detects.
        try:
            live = bool(value)
        except Exception:
            return ""
        if live and age < _DETECT_TTL:
            return _as_text(value)
    return ""


def detect_lan_ip(*, force: bool = False) -> str:
    """Detect the active LAN address without embedding a network-specific IP.

    Single-flight, not merely cached.  The TTL check used to release ``_cache_lock``
    before doing the work, which is correct only while callers arrive one at a time.
    ``host_ip()`` has 39 call sites and several of them now sit inside the same
    fan-out, so they reached a cold cache together, all missed, and each paid for
    the two subprocesses -- one ``/api/apps/managed`` read ran
    ``route -n get default`` and ``ipconfig getifaddr`` three times apiece for one
    answer.  The refresh lock makes the losers wait for the winner's result instead.
    """
    now = time.time()
    if not force:
        hit = _cached_detection(now)
        if hit:
            return hit

    with _detect_refresh_lock:
        # Re-check inside the lock: the winner filled the cache while the others
        # were queued behind it, and re-running the detection would defeat the
        # point of waiting.
        if not force:
            hit = _cached_detection(time.time())
            if hit:
                return hit

        return _detect_lan_ip_uncached(now, force=force)


def _detect_lan_ip_uncached(now: float, *, force: bool = False) -> str:
    with _cache_lock:
        began = _detect_generation
    candidates: list[str] = []
    # `force` has to reach the two host reads below, not just this function's own
    # cache.  Both are memoised now, so stopping at the outer cache would make
    # `detect_lan_ip(force=True)` return the address it was asked to re-detect.
    interface = default_interface(force=force)
    if interface:
        address = interface_address(interface, force=force)
        if address:
            candidates.append(address)
    try:
        candidates.extend(
            _as_text(item[4][0])
            for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        )
    except (OSError, UnicodeError, ValueError, TypeError):
        # Leftover ``\\ud800`` in the hostname is UnicodeError, not OSError;
        # GET /api/system/host and every host_ip() consumer used to 500.
        pass

    value = next((candidate for candidate in candidates if _usable_address(candidate)), "")
    if not value:
        try:
            local_name = _as_text(socket.gethostname()).strip()
        except (OSError, UnicodeError, ValueError, TypeError):
            local_name = ""
        value = local_name if local_name else "localhost"
    value = _as_text(value)
    with _cache_lock:
        if _detect_generation == began:
            # _cache_publish: a shadow key planted over ``t`` / ``value``
            # used to raise out of the insert compare at the very end of a
            # successful detection — a raw 500 on GET /api/system/host.
            _cache_publish(_detect_cache, t=now, value=value)
    return value


def host_ip() -> str:
    """Return the configured host or the currently detected LAN address."""
    value = configured_host()
    if value.lower() not in _AUTO_VALUES:
        return value
    return detect_lan_ip()


def template_variables(extra: dict[str, Any] | None = None) -> dict[str, str]:
    host = host_ip()
    values = {"host": host, "host_ip": host, "localhost": "localhost"}
    try:
        from hub.config import cfg

        address_book = (cfg().get("settings") or {}).get("address_book") or {}
        if not isinstance(address_book, dict):
            address_book = {}
        # _as_text absorbs a per-entry ``__class__``-property bomb now, so
        # one junk entry renders as junk text instead of raising into the
        # blanket except and silently dropping every sane sibling.
        values.update({
            _as_text(key): _as_text(value)
            for key, value in address_book.items()
            if value is not None
        })
    except Exception:
        pass
    if isinstance(extra, dict):
        values.update({
            _as_text(key): _as_text(value)
            for key, value in extra.items()
            if value is not None
        })
    return values


def resolve_template(value: str | None, extra: dict[str, Any] | None = None) -> str | None:
    """Expand host and named address-book variables."""
    if value is None or not isinstance(value, str):
        return value
    if "{" not in value:
        return _as_text(value)
    variables = template_variables(extra)
    return _as_text(_VAR_RE.sub(lambda match: variables.get(match.group(1), match.group(0)), value))


def resolve_value(value: Any, extra: dict[str, Any] | None = None, *, _depth: int = 0) -> Any:
    """Recursively expand address templates at API/use boundaries.

    Depth-capped: leftover deeply-nested YAML used to RecursionError
    compose/catalog/bookmark payloads that walk this walker.

    Deliberately raise-on-junk: every caller (containers overrides,
    bookmarks quick_links, ``_status_quick_links``) wraps this walk in a
    try and treats a raise as "the value is junk" — the bookmarks5 /
    docker9 pins depend on a subclass ``items()`` / ``__iter__`` /
    ``__class__`` bomb raising here rather than being laundered through.
    """
    if _depth > 16:
        if isinstance(value, (dict, list, tuple)):
            return None
        return resolve_template(value, extra) if isinstance(value, str) else value
    if isinstance(value, str):
        return resolve_template(value, extra)
    if isinstance(value, list):
        return [resolve_value(item, extra, _depth=_depth + 1) for item in value]
    if isinstance(value, tuple):
        return tuple(resolve_value(item, extra, _depth=_depth + 1) for item in value)
    if isinstance(value, dict):
        return {
            _as_text(key): resolve_value(item, extra, _depth=_depth + 1)
            for key, item in value.items()
        }
    return value


def normalize_local_url(value: str | None) -> str:
    """Store local URLs with {host} so DHCP/interface changes do not stale them."""
    if value is None:
        return ""
    # _isa + the scrub's strip: a ``__class__``-property bomb or a
    # str-subclass ``strip`` override must not raise out of a URL write.
    if type(value) is not str:
        raw = _as_text(value).strip()
    else:
        raw = value.strip()
    if not raw:
        return raw
    try:
        raw.encode("utf-8")
    except UnicodeEncodeError:
        # Leftover ``\\ud800`` used to UTF-8 500 bookmark / service URL writes.
        return _as_text(raw)
    if "{host}" in raw:
        return raw
    try:
        parsed = urlsplit(raw)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except (ValueError, UnicodeError):
        return raw
    if not parsed.scheme or not hostname or parsed.username or parsed.password:
        return raw
    local_names = {
        "localhost",
        "127.0.0.1",
        "::1",
        host_ip().lower(),
    }
    try:
        # Same leftover as detect_lan_ip: ``gethostname()`` OSError / a
        # lone surrogate used to 500 every caller that stores a local URL.
        local_names.add(_as_text(socket.gethostname()).lower())
    except (OSError, UnicodeError, ValueError, TypeError):
        pass
    if hostname not in local_names:
        return raw
    netloc = "{host}" + (f":{port}" if port else "")
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
