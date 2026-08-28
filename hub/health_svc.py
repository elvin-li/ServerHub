"""Fix Common Problems style health checks (Unraid plugin inspiration)."""
from __future__ import annotations

import os
import re
import shutil
import threading
import time

from hub.config import override
from hub.docker_cli import engine_up
from hub.launchd_cache import running_labels as launchd_running_labels
from hub.nginx_svc import overview as nginx_overview, test_config as nginx_test
from hub.paths import AGENTS_DIR, SMARTCTL, user_home
from hub.errors import exc_detail
from hub.util import fan_out, port_open, read_bytes_capped, sh, strftime_now
from hub.brew_cache import brew_services_list
from pathlib import Path

_cache = {"t": 0.0, "v": None}
_TTL = 45.0
#: Leftover multi-MB LaunchAgent plist used to OOM GET /api/health/checks.
_PLIST_CAP = 256 * 1024
#: One lock, not per-key: there is a single snapshot, so a reader arriving mid-collection
#: should wait for that result rather than starting a second seven-way fan-out.
_refresh_lock = threading.Lock()
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the gate itself: planted in the cache snapshot it 500'd
    ``_fresh_snapshot`` / ``_jsonable`` on every GET /api/health/checks,
    and returned as a check row from the Immich/Ollama probe modules it
    500'd ``_as_checks`` / ``_row_flags`` after every probe had already
    answered.  A real subclass still matches through the C-level type
    check; only a value that cannot answer what it is takes the
    non-matching branch (the smart_test_svc._isa rule).
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _mapping_get(mapping, key, default=None):
    """Field read that a hostile mapping *key* cannot 500.

    The ups_svc/vms_svc rule, which this module's bound ``.get`` probes and
    the module cache's bare ``_cache["v"]`` subscript never got: even a
    plain-dict lookup still runs the *stored keys'* own ``__eq__`` during
    the hash probe, so a leftover str-subclass key whose hash shadows the
    real key and whose ``__eq__`` raises used to detonate
    ``_fresh_snapshot`` / ``_collect_checks``'s cache write — a raw 500 on
    every GET /api/health/checks — and to collapse a *running* nginx into
    the combined not-installed error row inside ``_nginx_pair``.  Only the
    shadowed field degrades to its default; siblings keep their sane data.
    """
    if not _isa(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return default


def _truthy(value) -> bool:
    """``bool()`` that a leftover ``__bool__`` bomb cannot detonate.

    This module does not own the values it truth-tests: ``os.access`` /
    ``port_open`` / the nginx overview and config-test answers are all
    patched by tests and tooling, and a value whose ``__bool__`` raises
    used to ride those seams three different ways — a raw 500 out of the
    backup-dir ``if not ok`` (the one truth test left outside its try), a
    silent wipe of every port row through ``_safe``'s fallback, and the
    running-nginx collapse into the combined not-installed error row.  A
    value that cannot answer what it is reads as falsy, the same
    fail-closed direction every guard here already takes.
    """
    if type(value) is bool:
        return value
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _rc_int(rc) -> int:
    """Exact exit status for the ``==`` / ``in`` probes; a bomb reads as failure.

    This module does not own ``sh`` (tests and tooling patch it), and an
    rc-*subclass* whose ``__eq__`` raises used to detonate ``rc in (0, 4)``
    inside ``_smart_checks`` — ``_safe`` swallowed the raise and the SMART
    row silently vanished from GET /api/health/checks.  ``-255`` is no
    honest smartctl exit, so a bomb keeps the empty-row fallback.
    """
    try:
        if type(rc) is bool:
            return int(rc)
        if _isa(rc, int):
            return int.__index__(rc)
        return int(rc)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return -255


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500.

    Both bases, real layout first-come. A lying ``__class__`` that only
    claims bytes no longer wipes genuine str storage via ``str()``.
    """
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
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
        return ""
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _as_text(value) -> str:
    # _isa — same ``__class__``-property-bomb note as _utf8_text.
    if _isa(value, (bytes, bytearray)):
        value = _decode_bytes(value)
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
    # Unbound base encode — same subclass ``.encode`` bomb note as _utf8_text.
    return str.encode(value, "utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Drop leftover inf/bytes/``\\ud800`` so Starlette cannot 500 GET /api/health/checks.

    A >4300-digit int (a poisoned cache snapshot, a junk row from the Immich/
    Ollama check modules whose dicts bypass ``_check``) still passed through
    untouched: CPython's int->str digit limit then ValueError'd ``json.dumps``
    itself.
    """
    if depth > 32:
        return None
    # _isa at every rank (the smart_test_svc._jsonable rule): a
    # ``__class__``-property bomb nested in the cache snapshot or in a raw
    # Immich/Ollama check row used to detonate the first gate it failed and
    # 500 GET /api/health/checks; it now falls through to the final text
    # probe like any other leftover.
    if value is None or type(value) is bool:
        return value
    if _isa(value, bool):
        # ``type is bool`` above, not the old bare ``_isa`` return: bool
        # cannot be subclassed, so anything else that answers bool here is a
        # *lying*-``__class__`` impostor (the docker10/json9 shape) — and
        # returned raw it rode ``_serve_cached`` / the fresh collection into
        # Starlette's encoder and 500'd GET /api/health/checks on every TTL
        # hit.  Launder to the truth value it claims to be; a ``__bool__``
        # bomb drops like any other unreadable leftover.
        try:
            return bool(value)
        except Exception:
            return None
    if _isa(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int (the modules._jsonable rule):
                # a subclass ``__str__`` bomb planted in the cache snapshot
                # used to blow the digit-cap probe below and 500 GET
                # /api/health/checks on every TTL hit.
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
    if _isa(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except Exception:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isa(value, str):
        return _utf8_text(value)
    if _isa(value, (bytes, bytearray)):
        return _decode_bytes(value)
    if _isa(value, dict):
        try:
            # Unpacking inside the same try: a subclass ``items()`` that
            # *answers* but yields non-pairs used to raise out of the loop
            # header below — past the guard — and 500 GET /api/health/checks
            # exactly like the items bomb this try already absorbed.
            items = [(k, v) for k, v in value.items()]
        except Exception:
            # A mapping that refuses iteration (odd dict subclass planted in
            # the cache, or a raw Immich/Ollama check row that bypasses
            # ``_check``): nothing to salvage from it, but its *siblings*
            # must survive — pre-fix this raised out of ``_serve_cached`` and
            # out of the final collection pass and 500'd GET
            # /api/health/checks (the nginx_svc/smart_test_svc._jsonable rule).
            return None
        out = {}
        for k, v in items:
            try:
                # Per-pair guard (the smart_test_svc._jsonable rule): a
                # ``__class__``-bomb key used to detonate its own gate —
                # outside the old per-conversion trys — and 500 GET
                # /api/health/checks; the torn pair drops alone, its
                # sibling keys survive.
                if _isa(k, (bytes, bytearray)):
                    k = _decode_bytes(k)
                elif not _isa(k, str):
                    k = str(k)
                out[_utf8_text(k)] = _jsonable(v, depth + 1)
            except Exception:
                continue
        return out
    if _isa(value, (list, tuple, set, frozenset)):
        try:
            return [_jsonable(v, depth + 1) for v in value]
        except Exception:
            # Same class as the mapping above, at sequence rank: a list
            # subclass whose ``__iter__`` raises drops alone, never the
            # payload or the route.
            return None
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # getattr's default only swallows AttributeError; a property or
        # ``__getattr__`` bomb still raised out of the probe itself and
        # 500'd GET /api/health/checks.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/health/checks.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _check(id_: str, name: str, level: str, ok: bool, detail: str, fix: str = "") -> dict:
    try:
        ok_b = bool(ok)
    except Exception:
        ok_b = False
    return {
        "id": _as_text(id_),
        "name": _as_text(name),
        "level": _as_text(level if not ok_b else "ok") or "ok",
        "ok": ok_b,
        "detail": _as_text(detail),
        "fix": _as_text(fix),
    }


def _probe_port(port) -> bool:
    """Port reachability that never raises, for use inside the pool.

    ``_truthy``, not the raw answer: this module does not own ``port_open``
    (tests and tooling patch it), and a returned ``__bool__``-bomb rode
    this function's own try — the raise only fired later, inside
    ``_port_checks``'s ``if up`` comprehension, where ``_safe`` swallowed
    it and every port row silently vanished from GET /api/health/checks.
    """
    try:
        return _truthy(port_open(port))
    except Exception:
        return False


def _panel_port() -> int:
    try:
        n = int(os.environ.get("SERVERHUB_PORT", "8086"))
    except (TypeError, ValueError, OverflowError):
        return 8086
    return n if 1 <= n <= 65535 else 8086


def _key_ports() -> tuple:
    """Ports whose reachability is reported, in the order the page renders them."""
    port = _panel_port()
    return (
        (port, f"ServerHub panel :{port}", "launchctl kickstart local.serverhub.panel"),
        (8443, "ServerHub HTTPS :8443", "Check system Nginx / 35-serverhub.conf"),
        (8123, "Home Assistant :8123", "Check com.homeassistant.core"),
        (8281, "Nginx HTTPS :8281", "Check system Nginx / certificates"),
    )


def _label_set(labels) -> frozenset:
    """Exact-str running-labels set whose membership probes cannot detonate.

    The old ``frozenset(running_labels)`` copy kept the probe's *elements*
    as they were, and a set/frozenset membership check compares the lookup
    key against the **stored** elements — so a leftover hash-shadowing
    str-subclass element (same hash as ``homebrew.mxcl.postgresql@18`` or a
    KeepAlive label, raising ``__eq__``) rode the copy intact and detonated
    ``f"homebrew.mxcl.{n}" in running_labels`` / ``label in running_labels``
    inside their per-row trys: the postgres row this page exists to show and
    the agent's KeepAlive warning silently vanished from GET
    /api/health/checks.  ``_as_text`` launders every element to an exact
    str (honest labels are exact strs already, so they pass unchanged);
    the unbound base ``__iter__`` walks a subclass's real storage past an
    ``__iter__`` bomb, a lying-``__class__`` impostor falls through to the
    guarded pull, and a mid-walk raise keeps the elements already yielded
    (the worker_health._pull_guarded rule).
    """
    it = None
    for base in (set, frozenset, list, tuple):
        if _isa(labels, base):
            try:
                it = base.__iter__(labels)
            except Exception:
                it = None
            break
    else:
        return frozenset()
    if it is None:
        try:
            it = iter(labels)
        except Exception:
            return frozenset()
    out = []
    while True:
        try:
            item = next(it)
        except StopIteration:
            break
        except Exception:
            break
        out.append(_as_text(item))
    return frozenset(out)


def _engine_up() -> bool:
    try:
        return bool(engine_up())
    except Exception:
        return False


def _nginx_pair() -> list[dict]:
    """Both nginx checks -- or the single combined failure the page has always shown.

    One try/except spanning both calls is deliberate rather than sloppy: when nginx
    is not installed at all, `nginx_overview()` raises and the page shows one
    "System Nginx" error instead of that plus a second, redundant config-syntax
    failure. Returning the checks as a list preserves that all-or-one behaviour now
    that the pair runs inside a worker, where an escaping exception would cost the
    entire batch.
    """
    try:
        ngx = nginx_overview()
        # _mapping_get, not bound ``.get``: this function does not own the
        # overview dict, and a leftover hash-shadowing str-subclass key
        # (same hash as ``running``/``pid``/``site_count``, raising
        # ``__eq__``) detonated the plain-dict lookup inside the pair-wide
        # try — the same collapse as the over-cap ints below, one seam over.
        # _truthy, not bare ``bool()``: a ``__bool__``-bomb *value* under an
        # honest ``running`` key raised through the same pair-wide try — a
        # running nginx collapsed into the combined not-installed error row
        # and the config-syntax sibling vanished, the exact collapse the
        # shadow-key launder above already prevents one seam over.
        ok = _truthy(_mapping_get(ngx, "running"))
        # _as_text per field, not the bare f-string: this function does not
        # own the overview dict, and an already-int over-cap pid/site_count
        # leftover (YAML/plist hex loads uncapped) ValueError'd str() inside
        # the pair-wide try — a *running* nginx then collapsed into the
        # combined not-installed error row, the digit-cap exception text as
        # its detail, and the config-syntax sibling silently vanished.
        pair = [_check(
            "nginx", "System Nginx gateway",
            "error", ok,
            (
                f"running pid={_as_text(_mapping_get(ngx, 'pid')) or '?'}"
                f" · sites {_as_text(_mapping_get(ngx, 'site_count')) or '?'}"
            ) if ok else "not running",
            "launchctl kickstart -k gui/$(id -u)/local.system-nginx" if not ok else "",
        )]
        t = nginx_test()
        # _truthy: ``_check`` already guards its own ``bool(ok)``, but the
        # ``if not t_ok`` fix-string probe below ran the raw value's
        # ``__bool__`` inside the pair-wide try — a bomb under an honest
        # ``ok`` key collapsed both rows into the combined error row.
        t_ok = _truthy(_mapping_get(t, "ok"))
        pair.append(_check(
            "nginx_conf", "Nginx config syntax",
            "error", t_ok,
            # `(message or "")[:160]` TypeError'd a leftover int message into
            # the same pair-wide collapse.
            _as_text(_mapping_get(t, "message"))[:160],
            "Check ~/Services/nginx/conf.d/" if not t_ok else "",
        ))
        return pair
    except Exception as e:
        return [_check(
            "nginx", "System Nginx", "error", False, exc_detail(e, 160),
            "Check LaunchAgent local.system-nginx",
        )]


def _port_checks() -> list[dict]:
    """Reachability for every key port, probed together.

    Each connect waits out its full timeout when nothing is listening, so three
    dead ports charged the health page that wait three times in a row.
    """
    ports = _key_ports()
    return [
        _check(
            f"port_{port}", name,
            "warn", up,
            "port reachable" if up else "port not responding",
            fix if not up else "",
        )
        for (port, name, fix), up in zip(
            ports, fan_out(_probe_port, [port for port, _, _ in ports])
        )
    ]


def _skip_keepalive_watch(pl: dict, label: str) -> bool:
    """True when a KeepAlive plist is intentionally off, not unsupervised.

    `launchctl disable` does not write ``Disabled`` into the Homebrew plist, so
    panel ``hide`` is the other signal — otherwise a crash-loop we have already
    taken down keeps lighting Health as "KeepAlive not running".
    """
    if pl.get("Disabled"):
        return True
    try:
        return bool(override(label).get("hide"))
    except Exception:
        return False


def _stale_runtime_checks() -> list:
    """LaunchAgents whose interpreter was deleted under them.

    Side-effect free: the alerter kickstarts.  Must not raise — this runs
    inside the health fan-out, where one escaping exception drops the wave.
    """
    try:
        from hub import stale_runtime
        return stale_runtime.health_checks()
    except Exception as e:
        return [_check(
            "stale_runtime", "LaunchAgents on missing interpreter",
            "warn", False, exc_detail(e, 160),
            "Check LaunchAgents after a Homebrew Python upgrade",
        )]


def _running_labels() -> frozenset[str]:
    """Labels with a live PID, from one `launchctl list` for the whole function.

    This replaced per-service `launchctl` probes in the brew loop below: a label with
    a PID in column one is running, which is exactly what those probes asked.

    The listing now comes from :mod:`hub.launchd_cache`, shared with the Immich
    checks in the same fan-out and with nginx's own probe.  All three ran their own
    -- two of them spelled ``launchctl`` and one ``/bin/launchctl``, which is why
    grouping spawns by argv only ever showed one of the two duplicates -- so this
    endpoint read the same session listing three times.

    The local parse also had a bug worth recording: it accepted any first column
    that was not ``-`` or empty, and the header row's first column is ``PID``, so
    the literal string ``Label`` was reported as a running job.  Harmless only
    because nothing is called that.
    """
    return launchd_running_labels()


def _brew_snapshot() -> list:
    """brew service states, or an empty list.

    Failure is swallowed here rather than propagated because this now runs in a
    worker, where a raise would discard every other probe in the batch instead of
    just this one; the page then renders without the brew rows.
    """
    try:
        rows = brew_services_list() or []
    except Exception:
        return []
    # _isa: a ``__class__``-property-bomb listing detonated the bare gate.
    return rows if _isa(rows, list) else []


def _smart_checks() -> list[dict]:
    """System-disk SMART health, empty when smartctl is unavailable.

    SMARTCTL, not a literal /opt/homebrew path: the sudoers policy grants the
    root-owned copy under /usr/local/libexec/serverhub (Homebrew's prefix is
    writable by the panel's own account, so granting it would be passwordless
    root).  A hardcoded Homebrew path here matches no rule, so this probe would
    ask for a password nobody can type and the health card would go blank.
    """
    # Guarded unwrap of the whole ``sh`` answer, not just its slots (the
    # docker_cli.docker rule): this function does not own ``sh`` (tests and
    # tooling patch it), and a leftover riding the *shape* of the return —
    # a 2-tuple, a scalar, a tuple subclass whose ``__iter__`` raises, a
    # lying-``__class__`` tuple impostor — used to detonate the bare
    # ``rc, out, _ = …`` unpack itself; ``_safe`` swallowed the raise and
    # the SMART row silently vanished from GET /api/health/checks.  A junk
    # shape carries no exit status and no output: it reads as the same
    # ``-255`` failure ``_rc_int`` assigns junk rc values — never the
    # ``-1`` timeout / not-found sentinel, never success — and keeps the
    # empty-row fallback.
    try:
        rc, out, _err = sh(
            ["/usr/bin/sudo", "-n", SMARTCTL, "-H", "/dev/disk0"], timeout=10
        )
    except Exception:
        rc, out = -255, ""
    # The production sh always decodes (utf-8, replace), but this function
    # does not own the provider (nginx_svc guards the same class with
    # ``_sh_message``): bytes stdout from a patched/odd sh TypeError'd
    # ``"PASSED" in out.upper()`` and _safe swallowed the raise — the SMART
    # row silently vanished instead of rendering.  _rc_int: an rc-subclass
    # ``__eq__`` bomb detonated ``rc in (0, 4)`` into the same silent wipe.
    rc = _rc_int(rc)
    out = _as_text(out)
    if rc in (0, 4) and out:
        ok = "PASSED" in out.upper() or "OK" in out.upper()
        return [_check(
            "smart_disk0", "System disk SMART",
            "error", ok,
            out.strip().splitlines()[-1][:120] if out.strip() else "unknown",
            "Back up your data and check the disk" if not ok else "",
        )]
    return []


def _immich_checks() -> list[dict]:
    """Immich hybrid stack (containers + native worker + native ML + PG18).

    Kept in its own module because `docker ps` says nothing about the native
    halves: the worker and ML service run outside Docker, and a green
    immich_server tells you the web UI is up while thumbnails, transcode and
    face recognition are all silently dead.
    """
    try:
        from hub import immich_svc

        return list(immich_svc.run_checks().get("checks") or [])
    except Exception as e:
        return [_check(
            "immich", "Immich hybrid stack check", "warn", False,
            "check failed: " + exc_detail(e, 140),
            "See hub/immich_svc.py",
        )]


def _ollama_checks() -> list[dict]:
    """Local LLM daemon liveness + resident model count.

    hub/ollama_svc.py gates the row on this host actually running ollama (a
    binary on PATH or an ollama-referencing LaunchAgent plist) and probes with
    two short HTTP GETs — never a subprocess — so machines without ollama get
    no row at all and a sick daemon costs this fan-out at most the HTTP timeout.
    """
    try:
        from hub import ollama_svc

        return ollama_svc.health_checks()
    except Exception as e:
        return [_check(
            "ollama_api", "Ollama local LLM check", "warn", False,
            "check failed: " + exc_detail(e, 140), "See hub/ollama_svc.py",
        )]


def _time_machine_checks() -> list[dict]:
    """A Time Machine share is only a backup target while smbd is running.

    The share-point flag survives File Sharing being switched off, and client
    Macs then fail their backups silently — the panel row still looks
    configured.  Nothing is reported when no share carries the flag: this is a
    prerequisite check, not a feature advertisement.
    """
    try:
        from hub import shares_svc

        flagged = [
            name
            for name, info in shares_svc.time_machine_records().items()
            if info.get("time_machine")
        ]
        if not flagged:
            return []
        up = shares_svc.smb_service_running()
        return [_check(
            "tm_share_smb", "Time Machine share reachable",
            "warn", up,
            f"{len(flagged)} Time Machine share(s); SMB "
            + ("listening on :445" if up else "service not running"),
            "Turn on File Sharing in System Settings so client Macs can reach "
            "the backup share" if not up else "",
        )]
    except Exception as e:
        return [_check(
            "tm_share_smb", "Time Machine share check", "warn", False,
            "check failed: " + exc_detail(e, 140), "See hub/shares_svc.py",
        )]


def _wireguard_checks() -> list[dict]:
    """WireGuard tunnel liveness + boot daemon integrity.

    wg-quick is not a daemon: once it has configured the interface, nothing is
    left running, so a wireguard-go crash (or a reboot with a defective boot
    job) kills the tunnel silently.  That exact failure went unnoticed here for
    two days because no check watched it — remote clients just stopped
    connecting while every other light stayed green.

    Both probes are passwordless: `wg show` goes through the pinned sudoers
    rule, and daemon_state() only reads the plist and `launchctl print`.
    """
    try:
        from hub import wireguard_net_svc, wireguard_svc, wireguard_wstunnel

        if not wireguard_svc.installation().get("installed"):
            return []  # wireguard-tools absent — feature unused on this host
        cfg = wireguard_svc.settings()
        interface = cfg.get("interface") or "wg0"
        if not wireguard_svc.conf_path(interface).exists():
            return []  # no tunnel configured — nothing to watch
        checks = []

        device, _rows, error = wireguard_svc.live_interface(interface)
        up = bool(device) and not error
        checks.append(_check(
            "wg_tunnel", "WireGuard tunnel",
            "error", up,
            f"running on {device}" if up else (error or "not running"),
            "Start it from the WireGuard page — and fix the boot daemon below "
            "or it will die again" if not up else "",
        ))

        daemon = wireguard_net_svc.daemon_state()
        healthy = bool(daemon.get("healthy"))
        defects = ", ".join(daemon.get("defects") or [])
        checks.append(_check(
            "wg_daemon", "WireGuard boot daemon",
            "warn", healthy,
            "supervised (KeepAlive) and managed" if healthy
            else (f"defective: {defects}" if defects else "not installed"),
            "Use the fix action on the WireGuard page (admin password), or run "
            "deploy/repair-wireguard.sh" if not healthy else "",
        ))

        # Only when the operator asked for obfuscation.  A leftover root
        # wstunnel on this Mac must not turn Health red by itself.
        if cfg.get("wstunnel_enabled"):
            wst = wireguard_wstunnel.status(cfg)
            wst_up = bool(wst.get("running"))
            checks.append(_check(
                "wg_wstunnel", "WireGuard wstunnel",
                "warn", wst_up,
                wst.get("listen") if wst_up else "enabled but not running",
                "Apply the wstunnel daemon from the WireGuard page"
                if not wst_up else "",
            ))
            if wst_up and (not wst.get("stable_restrict") or wst.get("stale_restrict")):
                checks.append(_check(
                    "wg_wstunnel_restrict", "wstunnel restrict-to",
                    "warn", False,
                    wst.get("restrict_to") or "",
                    "Stabilize to 127.0.0.1 from the WireGuard page",
                ))
            elif wst_up and not wst.get("aligned"):
                checks.append(_check(
                    "wg_wstunnel_align", "wstunnel layout",
                    "warn", False,
                    f"{wst.get('listen')} != {wst.get('desired_listen')}",
                    "Apply the saved wstunnel settings from the WireGuard page",
                ))
        return checks
    except Exception as e:
        return [_check(
            "wg_check", "WireGuard check", "warn", False,
            "check failed: " + exc_detail(e, 140), "See hub/wireguard_net_svc.py",
        )]


def _worker_checks() -> list[dict]:
    """Liveness of the long-lived worker threads (hub/worker_health.py).

    A dead sampler/alerter/scheduler thread is otherwise invisible: the panel
    keeps serving requests while alerts stop firing and metrics stop
    recording, which is precisely the failure an operator opens this page to
    rule out.  Pure in-memory read — no subprocess, no lock held while slow —
    so it runs outside the fan-out and can never be the slow row.  No row is
    emitted before any worker has registered (unit-test apps built without
    the lifespan), so existing payload consumers see no change there.
    """
    try:
        from hub import worker_health

        registered = worker_health.snapshot()
        if not registered:
            return []
        dead = worker_health.problems(rows=registered)
        return [_check(
            "workers", "Panel background workers",
            "error", not dead,
            f"{len(registered)} worker threads ticking" if not dead
            else "; ".join(dead)[:160],
            "Restart the ServerHub panel LaunchAgent (launchctl kickstart)"
            if dead else "",
        )]
    except Exception:
        return []


def _serve_cached(hit: dict) -> dict:
    """JSON-safe snapshot, keeping the cached object when it is already clean.

    Leftover inf / ``\\ud800`` planted in the cache used to 500 GET
    ``/api/health/checks`` on a TTL hit (``_collect_checks`` sanitizes, the
    hit path used to return the live dict).  Mutate in place when dirty so
    single-flight waiters still share one snapshot object.
    """
    cleaned = _jsonable(hit)
    if not isinstance(cleaned, dict):
        return {
            "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
            "summary": {"ok": 0, "warn": 0, "error": 0, "total": 0},
            "checks": [],
            "healthy": False,
        }
    try:
        dirty = cleaned != hit
    except Exception:
        dirty = True
    if not dirty:
        return hit
    try:
        hit.clear()
        hit.update(cleaned)
    except Exception:
        # A dict subclass whose clear/update raises (a planted poisoned
        # snapshot): serve the cleaned copy rather than 500 the TTL hit.
        return cleaned
    return hit


def _fresh_snapshot() -> dict | None:
    # _mapping_get, not the bare ``_cache["v"]`` subscript: a leftover
    # hash-shadowing str-subclass key planted in the module cache (same
    # hash as ``v``, raising ``__eq__``) used to detonate the C-level
    # lookup itself and 500 every GET /api/health/checks — the one cache
    # poisoning ``_serve_cached`` could never reach.  An unreadable slot
    # reads as expired and re-collects like every other poisoning.
    hit = _mapping_get(_cache, "v")
    # _isa: a ``__class__``-property bomb planted as the whole cached
    # snapshot used to detonate this gate on every GET /api/health/checks —
    # a 500 where every other cache poisoning already re-collects.
    if not _isa(hit, dict):
        return None
    try:
        # A leftover over-cap int (or garbage) planted in _cache["t"] made
        # this subtraction OverflowError/TypeError and 500'd GET
        # /api/health/checks on every request; the sibling ``v`` poisonings
        # were already re-sanitized by _serve_cached.  Treat an unusable
        # timestamp as expired: _collect_checks rewrites both keys.
        # Exception, not the arithmetic trio: a numeric subclass whose
        # ``__rsub__``/``__le__`` raises RuntimeError still 500'd here.
        expired = time.time() - _cache["t"] >= _TTL
    except Exception:
        return None
    if expired:
        return None
    return _serve_cached(hit)


def run_checks(force: bool = False) -> dict:
    """Cached health snapshot, collected once however many readers ask at once.

    The TTL alone was not enough.  This check reads the cache, and the collection
    below is a seven-way fan-out that shells out to `sudo smartctl`, `launchctl`,
    brew and the Immich stack -- so every reader that arrived during a cold window
    ran the whole thing.  The health card, the dashboard and the diagnostics bundle
    all want this, and the panel and menu-bar client both poll: measured with four
    concurrent cold readers, four `launchctl list` and four `sudo -n smartctl` where
    one of each would have served all of them.

    Same double-checked shape as brew_cache and docker_cli, rather than `ttl_memo`,
    because `_cache` is inspected directly by tests that predate this.
    """
    if not force:
        hit = _fresh_snapshot()
        if hit is not None:
            return hit
    with _refresh_lock:
        # Re-check under the lock: another reader may have finished the same
        # collection while this one waited, which is what makes this single-flight.
        if not force:
            hit = _fresh_snapshot()
            if hit is not None:
                return hit
        return _collect_checks()


def _collect_checks() -> dict:
    checks = []

    # Disk space root.  ``du.total == 0`` used to ZeroDivisionError and 500
    # ``/api/health/checks``; treating it as 0% used would have shown a green
    # row, so fail closed instead.  Only OSError was caught, so a RuntimeError
    # from a broken mount still emptied the page.
    disk_row = None
    try:
        du = shutil.disk_usage("/")
        total = getattr(du, "total", 0) or 0
        used = getattr(du, "used", 0) or 0
        if total:
            pct = used / total * 100
            disk_row = _check(
                "disk_root", "System disk space",
                "error" if pct >= 95 else "warn",
                pct < 90,
                f"used {pct:.0f}% ({used//2**30}/{total//2**30} GB)",
                "Clean up large files / Docker images, or expand storage" if pct >= 90 else "",
            )
    except Exception:
        disk_row = None
    if disk_row is None:
        disk_row = _check(
            "disk_root", "System disk space",
            "warn", False,
            "unable to read system disk usage",
            "Check that / is mounted and readable",
        )
    checks.append(disk_row)

    # Every remaining probe in one wave.
    #
    # These ask unrelated questions of unrelated subsystems -- the container engine,
    # nginx, three TCP ports, launchd, brew, smartctl and the Immich stack -- and none
    # of them reads another's answer, yet the page used to wait out their sum. The
    # slow ones are also the ones most likely to be slow together on a sick host,
    # which is exactly when this page gets opened.
    #
    # Order is restored below, not taken from completion: `fan_out` returns results in
    # submission order, and each probe returns its checks already assembled, so the
    # rendered sequence is identical to when this ran top to bottom.
    def _safe(item):
        probe, fallback = item
        try:
            return probe()
        except Exception:
            return fallback

    # fan_out re-raises on iteration.  One probe that escapes would empty
    # /api/health/checks instead of dropping only its own rows.
    eng, nginx_checks, port_checks, running_labels, brew_states, smart, immich, wg, tm, ollama, stale_checks = fan_out(
        _safe,
        [
            (_engine_up, False),
            (_nginx_pair, []),
            (_port_checks, []),
            (_running_labels, frozenset()),
            (_brew_snapshot, []),
            (_smart_checks, []),
            (_immich_checks, []),
            (_wireguard_checks, []),
            (_time_machine_checks, []),
            (_ollama_checks, []),
            (_stale_runtime_checks, []),
        ],
        max_workers=11,
    )

    def _as_checks(rows):
        # _isa: a probe answering a ``__class__``-property bomb as its rows
        # object detonated this gate after the fan-out — a raw 500 where
        # every other junk answer already drops to no rows.
        if not _isa(rows, list):
            return []
        try:
            # Materialize: ``isinstance`` passes for a list *subclass*, and
            # one whose ``__iter__`` raises used to blow up ``checks.extend``
            # after the fan-out — ``_safe`` only covers the probe call, not a
            # lazily-raising return value — and 500 GET /api/health/checks
            # (the nginx_svc.overview rule).
            return list(rows)
        except Exception:
            return []

    # A plain frozenset of exact strs, not the object the probe answered: a
    # set/list subclass whose ``__iter__`` or ``__contains__`` raises — and,
    # post-health11, a hash-shadowing str-subclass *element* whose ``__eq__``
    # raises out of the membership compare — silently dropped brew launchd
    # re-checks and KeepAlive warnings through their per-row guards.
    running_labels = _label_set(running_labels)

    # OrbStack / docker
    checks.append(_check(
        "orbstack", "OrbStack / Docker engine",
        "error", eng,
        "engine running" if eng else "engine not running",
        "Start OrbStack from the Services page, or open -a OrbStack" if not eng else "",
    ))

    # nginx system
    checks.extend(_as_checks(nginx_checks))

    # key ports
    checks.extend(_as_checks(port_checks))

    # brew critical — through _as_checks: an iterbomb list subclass passed
    # the previous bare isinstance gate and raised out of the loop header
    # itself, 500ing GET /api/health/checks.
    #
    # Per-row guard, not one try spanning the loop: a single poisoned row
    # (an over-cap hex-YAML/JSON int in name or status, whose bare str()
    # is ValueError past CPython's digit cap) used to raise out of the
    # loop-wide try and silently drop every later brew check —
    # postgresql@18 included, the exact row this page exists to show
    # when Immich's database is down.  _as_text's guarded str() probe
    # coerces the renderable and absorbs the unrenderable to "".
    # _isa + _mapping_get per row (the _nginx_pair rule): a ``__class__``-
    # property-bomb row detonated the bare isinstance, and a hash-shadowing
    # junk key riding a row (same hash as ``name``/``status``, raising
    # ``__eq__``) detonated the bound ``.get`` — both inside the per-row
    # try, so the postgres/mosquitto/grafana row this page exists to show
    # silently vanished instead of rendering with the one field degraded.
    for s in _as_checks(brew_states):
        try:
            if not _isa(s, dict):
                continue
            n = _as_text(_mapping_get(s, "name"))
            # postgresql@18 is a *separate* cluster (:5433) holding the
            # Immich database; @17 (:5432) holds TeslaMate.  Checking only
            # @17 reports "database fine" while Immich's DB is down.
            if n not in ("postgresql@17", "postgresql@18", "mosquitto", "grafana"):
                continue
            st = _as_text(_mapping_get(s, "status")).lower()
            ok = st in ("started", "running")
            if not ok and st in ("none", ""):
                # brew reports "none" when a formula is running under a
                # LaunchAgent rather than `brew services`.  Re-check the
                # listing already taken above instead of spawning
                # launchctl per service.
                if f"homebrew.mxcl.{n}" in running_labels:
                    ok, st = True, "running (launchd)"
            checks.append(_check(
                f"brew_{n}", f"Homebrew {n}",
                "error" if n.startswith("postgres") else "warn",
                ok,
                st or "unknown",
                f"brew services start {n}" if not ok else "",
            ))
        except Exception:
            continue

    # Homebrew python upgrades delete Cellar paths while KeepAlive PIDs
    # keep listening; TCP still answers so the services table looks green.
    # Joins the same fan-out as `_running_labels` so both share one listing.
    checks.extend(_as_checks(stale_checks))

    # LaunchAgents with KeepAlive that are not running.
    # running_labels was built once at the top of this function.
    # One bad plist (array payload, .get on a list) used to raise here
    # after the fan-out and empty the whole /api/health/checks payload.
    import glob, plistlib
    try:
        # list() inside the same try: a patched glob answering a lazily
        # raising iterable would otherwise detonate the loop header below,
        # past this guard.
        agent_paths = list(glob.glob(str(Path(AGENTS_DIR) / "*.plist")))
    except Exception:
        # A None/NUL AGENTS_DIR used to TypeError after the fan-out and
        # empty GET /api/health/checks.  Exception, not the old
        # (OSError, TypeError, ValueError) trio: a leftover path-like
        # AGENTS_DIR whose ``__fspath__`` raises RuntimeError escaped the
        # narrow net out of ``Path(AGENTS_DIR)`` itself — a raw 500 on
        # every GET /api/health/checks (the _fresh_snapshot arithmetic-trio
        # rule, one seam over).  The KeepAlive rows drop; the page renders.
        agent_paths = []
    for path in agent_paths:
        try:
            pl = plistlib.loads(read_bytes_capped(path, _PLIST_CAP))
            if not isinstance(pl, dict):
                continue
            # str() probe via _as_text, with the plist filename as the
            # fallback (the stale_runtime.scan convention): plistlib parses
            # ``<integer>0x…</integer>`` through int(raw, 16), which CPython's
            # 4300-digit cap does not bound, so a bare str() over a poisoned
            # Label ValueError'd into this loop's except and silently dropped
            # the agent's KeepAlive warning from GET /api/health/checks.
            label = _as_text(pl.get("Label")) or _as_text(Path(path).stem)
            if not label:
                continue
            if _skip_keepalive_watch(pl, label):
                continue
            if not pl.get("KeepAlive"):
                continue
            if pl.get("StartInterval") or pl.get("StartCalendarInterval"):
                continue
            if label in running_labels:
                continue
            checks.append(_check(
                f"la_{label}", f"KeepAlive not running: {label}",
                "warn", False,
                "LaunchAgent has KeepAlive configured but is not running",
                f"launchctl kickstart -k gui/$(id -u)/{label}",
            ))
        except Exception:
            continue

    # SMART quick (cached style) — probed in the wave above.
    checks.extend(_as_checks(smart))

    # Backup dir writable — observe only; never create paths on the internal SSD.
    try:
        home = user_home()
        if home is None:
            raise RuntimeError("no home")
        bdir = home / "Services" / "backups"
        if not bdir.is_dir():
            ok = True
            backup_detail = f"{bdir} absent (not created by health check)"
        else:
            # _truthy: this function does not own ``os.access`` (tests and
            # tooling patch it), and a returned ``__bool__``-bomb escaped
            # this try raw — the ``if not ok`` fix-string probe on the
            # ``_check`` call below then raised out of ``_collect_checks``
            # itself, a raw 500 on GET /api/health/checks (the one truth
            # test on this page that sat outside every guard).
            ok = _truthy(os.access(bdir, os.W_OK))
            backup_detail = str(bdir)
    except Exception:
        # Path.home() raises RuntimeError when HOME cannot be resolved —
        # that used to sit outside this try and 500 /api/health/checks.
        ok = True
        backup_detail = "~/Services/backups absent (not created by health check)"
    checks.append(_check(
        "backup_dir", "Backup directory writable",
        "warn", ok,
        backup_detail,
        "Check ~/Services/backups permissions" if not ok else "",
    ))

    # Immich hybrid stack — probed in the wave above.
    checks.extend(_as_checks(immich))

    # WireGuard tunnel + boot daemon — probed in the wave above.
    checks.extend(_as_checks(wg))

    # Ollama local LLM daemon — probed in the wave above; empty on hosts
    # without ollama.
    checks.extend(_as_checks(ollama))

    # Time Machine share prerequisites — probed in the wave above.
    checks.extend(_as_checks(tm))

    # Worker-thread liveness — in-memory, deliberately outside the fan-out.
    checks.extend(_as_checks(_worker_checks()))

    def _row_flags(c):
        """``(ok, level)`` of a row this function does not own, or None.

        The raw Immich/Ollama rows bypass ``_check``, so a dict-subclass row
        whose ``.get`` (or its value's ``__bool__``) raises used to blow up
        these sums after every probe had already answered — the whole
        collection 500'd at summary time.  ``_as_text`` on level: an
        unrenderable over-cap int must compare as "", not raise.
        """
        # _isa: a ``__class__``-property-bomb check row detonated this gate
        # at summary time — a raw 500 after every probe had already answered.
        if not _isa(c, dict):
            return None
        try:
            # _mapping_get: the raw Immich/Ollama rows are plain dicts too,
            # and a hash-shadowing junk key (same hash as ``ok``/``level``,
            # raising ``__eq__``) used to knock the whole row out of the
            # summary through this try; the shadowed field now degrades
            # alone and the row still counts.
            return bool(_mapping_get(c, "ok")), _as_text(_mapping_get(c, "level"))
        except Exception:
            return None

    flags = [f for f in (_row_flags(c) for c in checks) if f is not None]
    errors = sum(1 for ok, level in flags if not ok and level == "error")
    warns = sum(1 for ok, level in flags if not ok and level == "warn")
    oks = sum(1 for ok, _level in flags if ok)
    v = _jsonable({
        "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
        "summary": {"ok": oks, "warn": warns, "error": errors, "total": len(checks)},
        "checks": checks,
        "healthy": errors == 0,
    })
    if not isinstance(v, dict):
        v = {
            "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
            "summary": {"ok": 0, "warn": 0, "error": 0, "total": 0},
            "checks": [],
            "healthy": False,
        }
    try:
        _cache.update(t=time.time(), v=v)
    except Exception:
        # A hash-shadowing junk key planted in the module cache raises out
        # of the C-level insert compare (never out of a plain ``t``/``v``
        # overwrite) — pre-fix that 500'd GET /api/health/checks at the
        # very end of a successful collection.  ``clear()`` never compares
        # keys, so evicting the poison and rewriting always lands.
        try:
            _cache.clear()
            _cache.update(t=time.time(), v=v)
        except Exception:
            pass
    return v
