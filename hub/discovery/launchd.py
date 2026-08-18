from __future__ import annotations

import glob
import plistlib
import socket
import ssl
from pathlib import Path

from hub.adaptive import (
    _classify_head,
    enrich_service,
    friendly_name,
    guess_group,
    ports_for_pid,
    ports_from_plist,
    url_from_plist,
)
from hub.config import override
from hub.host_address import resolve_template
from hub.launchd_cache import listing as launchd_listing
from hub.paths import AGENTS_DIR
from hub.service_signatures import configured_signatures, identify
from hub.stale_runtime import pid_exe_path
from hub.util import fan_out, port_open

#: Match adaptive._PROBE_TIMEOUT_S: a local UI answers in milliseconds, and
#: stacking a TLS handshake after a hang used to add a second full wait to
#: every /api/status poll (the ESPHome-on-deleted-python case).
_HTTP_TIMEOUT = 0.6
#: Handshake only.  350ms was enough on an idle loopback and too tight when
#: the host was at 100% CPU — Sunshine :47990 flapped to
#: "HTTP not answering" for one alert cycle (alerts.jsonl, 2026-08-18).
_TLS_TIMEOUT = 0.8
_TLS_CTX = ssl._create_unverified_context()
_HTTP_REQ = (
    "GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
    "User-Agent: ServerHub/status\r\nConnection: close\r\n\r\n"
)
#: One failed HTTP/TLS probe is not a verdict.  ESPHome on a deleted
#: interpreter fails every poll, so the third miss still surfaces within
#: two dashboard ticks.  Two timeouts under a multi-minute CPU spike
#: (alerts.jsonl, 2026-08-18 04:49, 96–100%) must not page the operator.
_HTTP_STRIKES = 3
_http_misses: dict[str, int] = {}


def _tls_alive(port) -> bool:
    """True when loopback:*port* completes a TLS handshake.

    Sunshine (and other TLS-only UIs) close a plaintext GET without a status
    line, so a header probe looks dead while ``https://127.0.0.1:*port*/``
    still answers 401.  A handshake is enough: this check is "the daemon is
    talking", not "the certificate is valid".
    """
    try:
        with socket.create_connection(
            ("127.0.0.1", int(port)), timeout=_TLS_TIMEOUT,
        ) as raw:
            raw.settimeout(_TLS_TIMEOUT)
            with _TLS_CTX.wrap_socket(raw, server_hostname="127.0.0.1"):
                return True
    except Exception:
        return False


def _http_alive(port) -> bool:
    """True when anything HTTP or TLS answers on loopback:*port*.

    401/403/421 count as alive: the status line is proof the daemon is
    talking.  A timeout on the plaintext probe is dead without a TLS retry —
    that is the ESPHome-on-deleted-python hang, and stacking a second wait
    would stall every status poll.  Bytes that are neither HTTP nor TLS
    (Redis ``-ERR``) are also dead without a handshake: adaptive already
    measured that cost on non-web ports.

    TLS-only daemons (Sunshine :47990) close plaintext immediately with no
    useful bytes; those fall through to a handshake.  Always ``127.0.0.1``,
    never the public HTTPS URL — this is "is the daemon talking", not "can
    the world reach it".
    """
    try:
        port_n = int(port)
    except (TypeError, ValueError):
        return False
    timed_out = False
    head = b""
    try:
        with socket.create_connection(
            ("127.0.0.1", port_n), timeout=_HTTP_TIMEOUT,
        ) as sock:
            sock.settimeout(_HTTP_TIMEOUT)
            sock.sendall(_HTTP_REQ.format(port=port_n).encode())
            try:
                head = sock.recv(256)
            except (TimeoutError, socket.timeout):
                timed_out = True
    except (TimeoutError, socket.timeout):
        return False
    except Exception:
        return _tls_alive(port_n)
    if timed_out:
        return False
    if _classify_head(head):
        return True
    if head:
        # Spoke something that is not HTTP or TLS.  Do not spend a handshake
        # timeout confirming it — Redis on a URL override would hang here.
        return False
    return _tls_alive(port_n)


def _http_answering(label: str, alive: bool) -> bool:
    """True when the row should still read as HTTP-alive.

    The first miss is held; a later success clears the counter.  Tests reset
    :data:`_http_misses` so the first-miss behaviour is explicit.
    """
    key = str(label or "")
    if not key:
        return bool(alive)
    if alive:
        _http_misses.pop(key, None)
        return True
    n = _http_misses.get(key, 0) + 1
    _http_misses[key] = n
    return n < _HTTP_STRIKES


def _wants_http_probe(ctx: dict) -> bool:
    if not ctx.get("port"):
        return False
    sig = ctx.get("sig")
    # Signature says this port is not a web UI (redis, postgres, mqtt, …)
    # even if the operator also stored a docs URL on the override.
    if sig and sig.get("http") is False:
        return False
    if ctx.get("url"):
        return True
    return bool(sig and sig.get("http") is True)


def launchctl_table():
    """label -> (pid, status), from the shared listing (hub/launchd_cache.py).

    This module's own `launchctl list` was a fourth copy of the same read, and the
    only one spelled without an absolute path -- so it depended on the panel's PATH,
    which a LaunchAgent does not necessarily set.
    """
    return launchd_listing().jobs


def _probe_port(port) -> bool | None:
    """Port reachability that never raises, for use inside the pool."""
    try:
        return port_open(port)
    except Exception:
        return False


def _enrich(entry):
    """``enrich_service`` for one item, absorbing its own failures.

    ``fan_out`` re-raises on iteration, so one service whose URL probe blew up
    would otherwise empty the whole service list rather than losing its own
    adaptive extras.
    """
    item, pl, pid = entry
    try:
        return enrich_service(item, pl=pl, pid=pid)
    except Exception:
        return item


def _annotate_ollama_agent(item: dict) -> None:
    """Tag LaunchAgents that actually start Ollama so the services table can find them.

    Cheap: a plist glob already cached by ``ollama_svc._candidate_labels``.  Does
    not probe :11434 — that belongs on the Ollama page, not on every status poll.
    """
    label = str(item.get("id") or "")
    if "ollama" not in label.lower():
        return
    try:
        from hub.ollama_svc import _candidate_labels

        if label not in _candidate_labels():
            return
    except Exception:
        return
    if not item.get("port"):
        item["port"] = 11434
    detail = item.get("detail") or ""
    if "Ollama" not in detail:
        item["detail"] = f"{detail} · Ollama" if detail else "Ollama"


def discover_launchd():
    table = launchctl_table()
    # Two network waits used to sit inside this loop, once per installed
    # LaunchAgent: the port reachability check (a connect that costs its whole
    # timeout when nothing is listening) and enrich_service, which probes a
    # detected port for an HTTP or HTTPS URL.  Fifteen agents therefore put
    # fifteen of each on /api/status, the endpoint the dashboard polls.
    #
    # So the work is staged instead: parse and resolve here, fan the connects out,
    # decide state from the answers, then fan the enrichment out.  Plist reads and
    # override lookups stay on this thread -- they are local and cheap, and
    # ports_for_pid already answers from a shared lsof snapshot.
    extras = configured_signatures()
    contexts = []
    seen_labels: set[str] = set()
    for path in sorted(glob.glob(f"{AGENTS_DIR}/*.plist")):
        try:
            with open(path, "rb") as f:
                pl = plistlib.load(f)
        except Exception:
            pl = {}
        if not isinstance(pl, dict):
            pl = {}
        stem = Path(path).stem
        # launchd registers the job under Label, which can differ from the
        # filename.  Using the stem made a renamed plist look "Not loaded"
        # and sent kickstart at the wrong id.
        label = str(pl.get("Label") or stem)
        if label in seen_labels:
            continue
        seen_labels.add(label)
        ov = override(label)
        if not ov and stem != label:
            ov = override(stem)
        if ov.get("hide"):
            continue
        interval = bool(pl.get("StartInterval") or pl.get("StartCalendarInterval"))
        arguments = pl.get("ProgramArguments") or []
        # Login helpers that delegate to LaunchServices are intentionally
        # one-shot: /usr/bin/open exits after handing the bundle to macOS. A
        # loaded job with exit code 0 is healthy even though it has no PID.
        launchservices_open = bool(
            pl.get("RunAtLoad")
            and arguments
            and arguments[0] == "/usr/bin/open"
        )
        pid, last = table.get(label, (None, None))
        loaded, running = pid is not None, pid not in (None, "-")

        # Adaptive port: override → plist args/env → live pid lsof
        port = ov.get("port")
        detected = ports_from_plist(pl)
        if port is None and detected:
            port = detected[0]
        if port is None and running and pid not in (None, "-"):
            live = ports_for_pid(pid)
            if live:
                port = live[0]
                detected = live

        url = resolve_template(ov.get("url") or url_from_plist(pl))
        name = ov.get("name") or friendly_name(label)
        group = ov.get("group") or guess_group(label, pl, interval)
        # Signature library: a recognised binary gets its real name, and a
        # generic "Native Services" group yields to the signature category.
        # Overrides and more specific groups (Gateway, Homebrew, …) win.
        prog = ""
        if pl.get("Program"):
            prog = Path(str(pl["Program"])).name
        elif arguments:
            prog = Path(str(arguments[0])).name
        sig = identify(prog, port, extras=extras)
        if not (sig and sig.get("confidence") == "high"):
            sig = None
        elif not ov.get("name"):
            name = sig["name"]
        if sig and not ov.get("group") and group == "Native Services":
            group = sig["category"]

        contexts.append({
            "label": label, "ov": ov, "pl": pl, "interval": interval,
            "launchservices_open": launchservices_open, "pid": pid, "last": last,
            "loaded": loaded, "running": running, "port": port,
            "detected": detected, "url": url, "name": name, "group": group,
            "sig": sig,
        })

    # None where no port was resolved, matching the previous conditional.
    reachability = fan_out(
        lambda port: _probe_port(port) if port else None,
        [ctx["port"] for ctx in contexts],
    )

    # TCP-open is not "the UI works": ESPHome kept accepting connects on a
    # deleted Homebrew Python while HTTP/WS died in connection_made.  Probe
    # loopback HTTP only for agents that look like web UIs, and only after
    # TCP already answered — postgres/mqtt stay on the port check.
    http_needed = []
    for i, (ctx, p) in enumerate(zip(contexts, reachability)):
        if (
            ctx["running"]
            and p
            and not ctx["interval"]
            and not ctx["launchservices_open"]
            and _wants_http_probe(ctx)
        ):
            http_needed.append((i, ctx["port"]))
    http_ok: dict[int, bool] = {}
    if http_needed:
        answers = fan_out(_http_alive, [port for _, port in http_needed])
        http_ok = {
            i: _http_answering(contexts[i]["label"], bool(ok))
            for (i, _), ok in zip(http_needed, answers)
        }

    items = []
    for idx, (ctx, p) in enumerate(zip(contexts, reachability)):
        label, ov, pl = ctx["label"], ctx["ov"], ctx["pl"]
        interval, launchservices_open = ctx["interval"], ctx["launchservices_open"]
        pid, last = ctx["pid"], ctx["last"]
        loaded, running = ctx["loaded"], ctx["running"]
        port, detected = ctx["port"], ctx["detected"]
        url, name, group = ctx["url"], ctx["name"], ctx["group"]

        plist_disabled = bool(pl.get("Disabled"))
        if not running and plist_disabled:
            # Operator-disabled jobs are stopped, not crashed.  Interval
            # PhotosHub agents ship with Disabled=true and are absent from
            # `launchctl list`; calling that "down" filled Needs Attention.
            state, detail, actions = "stopped", "Disabled", ["start", "logs"]
        elif interval:
            if not loaded:
                state, detail = "down", "Not loaded"
            elif last not in ("0", None):
                # Calendar/interval jobs keep the last exit code until the
                # next run.  A 3:30 timeout would otherwise sit in 需关注
                # all day; freshness_svc already watches the artifact.
                state = "ok"
                detail = f"Loaded · scheduled task · last exit code {last}"
            else:
                state, detail = "ok", "Loaded · scheduled task"
            actions = ["run", "logs"] + (["stop"] if loaded else ["start"])
        elif launchservices_open and loaded:
            if last in ("0", None):
                state = "ok"
                detail = "loaded · opens app at login"
            else:
                state = "warn"
                detail = f"loaded · app open failed · exit {last}"
            actions = ["run", "logs", "stop"]
        elif running and (p is None or p):
            exe = None
            if pid not in (None, "-"):
                try:
                    exe = pid_exe_path(pid)
                except Exception:
                    exe = None
            if exe and not Path(exe).exists():
                state = "warn"
                detail = f"Running on missing interpreter · pid {pid}"
                actions = ["restart", "stop", "logs"]
            elif http_ok.get(idx) is False:
                state = "warn"
                detail = f"Process alive but HTTP :{port} not answering"
                actions = ["restart", "stop", "logs"]
            else:
                state = "ok"
                detail = f"Running · pid {pid}" + (f" · :{port}" if port else "")
                actions = ["restart", "stop", "logs"]
        elif running:
            state, detail, actions = "warn", f"Process alive but port :{port} not responding", ["restart", "stop", "logs"]
        else:
            state, detail, actions = "down", ("Loaded but not running" if loaded else "Not loaded"), ["start", "logs"]
        if url and "open" not in actions:
            actions = list(actions) + ["open"]

        item = {
            "id": label,
            "kind": "launchd",
            "name": name,
            "state": state,
            "detail": detail,
            "url": url,
            "group": group,
            "actions": actions,
            "port": port,
        }
        if detected:
            item["meta"] = {"detected_ports": detected, "adaptive": not bool(ov.get("port"))}
            if not ov.get("port") or not ov.get("url") or not ov.get("name"):
                item["auto"] = True
        if ctx.get("sig"):
            item.setdefault("meta", {})["signature"] = ctx["sig"]
            item["signature"] = ctx["sig"]
        _annotate_ollama_agent(item)
        items.append((item, pl, pid if running else None))

    # keep enrich for any remaining gaps.  Independent per service, and it can
    # reach for a URL over the network, so it is the second thing worth
    # overlapping; fan_out preserves order, and this list is rendered.
    return fan_out(_enrich, items)
