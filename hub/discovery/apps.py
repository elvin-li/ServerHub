from __future__ import annotations

from hub import cli_args
from hub.config import cfg
from hub.host_address import resolve_value
from hub.util import fan_out, port_open, sh

# Both collectors here probe one configured entry at a time, and a single probe
# is a `pgrep` (up to 3s) plus a TCP connect (0.6s against a closed port).  In
# series that made the collectors scale with the number of configured entries, on
# the /api/status path the dashboard polls every few seconds -- ten apps with
# nothing listening cost tens of seconds before anything rendered.  The probes
# touch different processes and different ports and share no state, so they
# overlap safely.


def _probe_app(entry):
    """``(running, port_state)`` for one app.  Never raises.

    A probe that blows up must cost its own entry and nothing else: this runs
    behind /api/status, where a single exception used to take the whole response
    down rather than one row of it.
    """
    process, port = entry
    try:
        rc, _, _ = sh(["pgrep", "-x", process], timeout=3)
        return rc == 0, port_open(port)
    except Exception:
        return False, None


def collect_apps(engine_up):
    # Config resolution stays on this thread.  It is cheap, and keeping cfg()
    # out of the workers avoids putting avoidable traffic through the shared
    # config lock while the probes are in flight.
    plans: list[dict] = []
    for raw in cfg().get("apps") or []:
        a = resolve_value(raw)
        if a.get("container_engine") or a.get("docker_engine"):
            plans.append({"kind": "engine", "app": a})
            continue
        # `process` sits in a bare positional slot, so a value starting with "-"
        # would be read by pgrep as a flag rather than as a pattern.  A missing
        # key used to raise KeyError here and take the whole status response with
        # it, so an unnamed entry is now skipped instead.
        process = str(a.get("process") or "").strip()
        if not process or not cli_args.is_safe_positional(process):
            continue
        plans.append({"kind": "app", "app": a, "process": process})

    probed = [p for p in plans if p["kind"] == "app"]
    for plan, result in zip(
        probed,
        fan_out(_probe_app, [(p["process"], p["app"].get("port")) for p in probed]),
    ):
        plan["result"] = result

    items = []
    for plan in plans:
        a = plan["app"]
        if plan["kind"] == "engine":
            items.append({"id": a["id"], "kind": "app-engine", "name": a.get("name", "OrbStack"),
                          "state": "ok" if engine_up else "down",
                          "detail": "OrbStack engine running" if engine_up else "OrbStack engine not running",
                          "url": a.get("url"), "group": a.get("group", "Apps"),
                          "actions": ["stop"] if engine_up else ["start"]})
            continue
        running, p = plan["result"]
        state = "ok" if running and p in (None, True) else ("warn" if running else "down")
        detail = (f"Running · :{a['port']}" if p else "Running") if running else "Stopped"
        items.append({"id": a["id"], "kind": "app", "name": a.get("name", a["id"]),
                      "state": state, "detail": detail, "url": a.get("url"),
                      "group": a.get("group", "Apps"),
                      "actions": ["restart", "stop"] if running else ["start"]})
    return items


def _probe_port(port):
    """Port reachability that never raises, for use inside the pool."""
    try:
        return port_open(port)
    except Exception:
        return False


def collect_scripts():
    scripts = [resolve_value(raw) for raw in cfg().get("scripts") or []]
    # Flattened across scripts *and* their ports, so a machine with several
    # multi-port scripts overlaps every check rather than only the outer loop.
    # The (index, port) pairing is what lets the flat results be put back
    # together in configuration order.
    checks = [(i, port) for i, s in enumerate(scripts) for port in (s.get("ports") or [])]
    states = fan_out(_probe_port, [port for _, port in checks])

    reachable: dict[int, set] = {}
    for (index, port), ok in zip(checks, states):
        if ok:
            reachable.setdefault(index, set()).add(port)

    items = []
    for index, s in enumerate(scripts):
        ports = s.get("ports") or []
        live = reachable.get(index, set())
        up = [p for p in ports if p in live]
        if len(up) == len(ports) and ports:
            state, detail = "ok", "Running · " + " ".join(f":{p}" for p in ports)
        elif up:
            state = "warn"
            downp = [p for p in ports if p not in up]
            detail = f"Partially running · missing {' '.join(':'+str(p) for p in downp)}"
        else:
            state, detail = "down", "Stopped"
        items.append({"id": s["id"], "kind": "script", "name": s.get("name", s["id"]),
                      "state": state, "detail": detail, "url": s.get("url"),
                      "group": s.get("group", "Custom"), "links": s.get("links"),
                      "actions": ["restart", "stop"] if up else ["start"]})
    return items
