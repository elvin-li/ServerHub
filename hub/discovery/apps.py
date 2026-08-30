from __future__ import annotations

import re

from hub import cli_args
from hub.config import cfg
from hub.group_rules import configured_group_rules, resolve_yaml_entry_group
from hub.host_address import resolve_value
from hub.util import fan_out, port_open, sh

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    Fail-closed: a raising ``__class__`` property cannot 500 a JSON route.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False

_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

# Both collectors here probe one configured entry at a time, and a single probe
# is a `pgrep` (up to 3s) plus a TCP connect (0.6s against a closed port).  In
# series that made the collectors scale with the number of configured entries, on
# the /api/status path the dashboard polls every few seconds -- ten apps with
# nothing listening cost tens of seconds before anything rendered.  The probes
# touch different processes and different ports and share no state, so they
# overlap safely.


def _entry_id(raw) -> str:
    """Row id as text; ``""`` drops the entry (the jobs._task_id rule).

    YAML numeric ids (``id: 8080``) load as int; the rows here used to emit
    them raw while ``actions.registry()`` gated on ``_isinst(sid, str)``,
    so the dashboard rendered start/stop buttons on a target POST /api/action
    could never find.  A renderable int coerces through the ``str()`` probe;
    an over-cap hex leftover (``id: 0xfff…`` loads uncapped and its ``str()``
    raises the digit-cap ValueError ``json.dumps`` would) drops only its
    entry instead of rendering a ghost row whose id nulls out in JSON.  bool
    passes ``_isinst(int)`` and must not become ``"True"``.  The scrub
    matches ``actions._as_text`` so the id a row serves is byte-for-byte the
    registry key that can act on it.
    """
    if type(raw) is bool:
        return ""
    if raw is None:
        return ""
    for base in (bytes, bytearray):
        try:
            return base.decode(raw, "utf-8", "replace").strip()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    if type(raw) is int:
        try:
            text = str(raw)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
        return text
    if type(raw) is str:
        try:
            return str.encode(raw, "utf-8", "replace").decode("utf-8").strip()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    try:
        text = str(raw)
    except RecursionError:
        return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8").strip()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _probe_app(entry):
    """``(running, port_state)`` for one app.  Never raises.

    A probe that blows up must cost its own entry and nothing else: this runs
    behind /api/status, where a single exception used to take the whole response
    down rather than one row of it.
    """
    process, port = entry
    try:
        rc, _, _ = sh(["/usr/bin/pgrep", "-x", process], timeout=3)
        return rc == 0, port_open(port)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False, None


def collect_apps(engine_up):
    # Config resolution stays on this thread.  It is cheap, and keeping cfg()
    # out of the workers avoids putting avoidable traffic through the shared
    # config lock while the probes are in flight.
    plans: list[dict] = []
    for raw in cfg().get("apps") if _isinst(cfg().get("apps"), list) else []:
        a = resolve_value(raw)
        if not _isinst(a, dict):
            continue
        sid = _entry_id(a.get("id"))
        if not sid:
            continue
        if a.get("container_engine") or a.get("docker_engine"):
            plans.append({"kind": "engine", "app": a, "id": sid})
            continue
        # `process` sits in a bare positional slot, so a value starting with "-"
        # would be read by pgrep as a flag rather than as a pattern.  A missing
        # key used to raise KeyError here and take the whole status response with
        # it, so an unnamed entry is now skipped instead.
        try:
            process = str(a.get("process") or "").strip()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A hand-edited hex leftover (``process: 0xfff…`` loads uncapped
            # through YAML) raised the int->str digit-cap ValueError here and
            # killed the whole collector — every app row silently vanished
            # from /api/status.  Drop only the poisoned entry.
            continue
        if not process or not cli_args.is_safe_positional(process):
            continue
        plans.append({"kind": "app", "app": a, "id": sid, "process": process})

    probed = [p for p in plans if p["kind"] == "app"]
    for plan, result in zip(
        probed,
        fan_out(_probe_app, [(p["process"], p["app"].get("port")) for p in probed]),
    ):
        plan["result"] = result

    items = []
    rules = configured_group_rules()
    for plan in plans:
        a = plan["app"]
        sid = plan["id"]
        if plan["kind"] == "engine":
            items.append({"id": sid, "kind": "app-engine", "name": a.get("name", "OrbStack"),
                          "state": "ok" if engine_up else "down",
                          "detail": "OrbStack engine running" if engine_up else "OrbStack engine not running",
                          "url": a.get("url"),
                          "group": resolve_yaml_entry_group(a, fallback="Apps", rules=rules),
                          "actions": ["stop"] if engine_up else ["start"]})
            continue
        running, p = plan["result"]
        state = "ok" if running and p in (None, True) else ("warn" if running else "down")
        detail = (f"Running · :{a['port']}" if p else "Running") if running else "Stopped"
        items.append({"id": sid, "kind": "app", "name": a.get("name", sid),
                      "state": state, "detail": detail, "url": a.get("url"),
                      "group": resolve_yaml_entry_group(a, fallback="Apps", rules=rules),
                      "actions": ["restart", "stop"] if running else ["start"]})
    return items


def _probe_port(port):
    """Port reachability that never raises, for use inside the pool."""
    try:
        return port_open(port)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def collect_scripts():
    scripts = []
    for raw in cfg().get("scripts") if _isinst(cfg().get("scripts"), list) else []:
        s = resolve_value(raw)
        if _isinst(s, dict):
            scripts.append(s)
    # Flattened across scripts *and* their ports, so a machine with several
    # multi-port scripts overlaps every check rather than only the outer loop.
    # The (index, port) pairing is what lets the flat results be put back
    # together in configuration order.
    def _ports(s):
        raw = s.get("ports")
        if _isinst(raw, list):
            rows = raw
        elif type(raw) is int:
            rows = [raw]
        else:
            return []
        out = []
        for p in rows:
            if type(p) is int:
                try:
                    str(p)
                except ValueError:
                    # A hand-edited hex leftover (``ports: [0xfff…]`` parses
                    # uncapped) can never be listened on, and the
                    # partially-running detail's ``str(p)`` used to raise the
                    # int->str digit-cap ValueError and kill the whole
                    # collector — every script row vanished from /api/status.
                    continue
            out.append(p)
        return out

    checks = [(i, port) for i, s in enumerate(scripts) for port in _ports(s)]
    states = list(fan_out(_probe_port, [port for _, port in checks]))
    # Gravity's watchdogs bounce :3001/:3010/:8765 for a few seconds.  One
    # missed connect used to paint 需关注 until the next poll.  Retry only
    # the misses; a port that is actually down stays down.
    missing = [port for (_, port), ok in zip(checks, states) if not ok]
    if missing:
        recovered = dict(zip(missing, fan_out(_probe_port, missing)))
        states = [ok or recovered.get(port, False) for (_, port), ok in zip(checks, states)]

    reachable: dict[int, set] = {}
    for (index, port), ok in zip(checks, states):
        if ok:
            reachable.setdefault(index, set()).add(port)

    items = []
    rules = configured_group_rules()
    for index, s in enumerate(scripts):
        ports = _ports(s)
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
        # Only offer actions the registry can actually execute: a script's
        # start/stop run the commands from services.yaml, and an entry without
        # them (e.g. one adopted from adaptive discovery) would render buttons
        # that always fail.
        has_start, has_stop = bool(s.get("start")), bool(s.get("stop"))
        if up:
            acts = (["restart"] if has_start and has_stop else []) + (["stop"] if has_stop else [])
        else:
            acts = ["start"] if has_start else []
        sid = _entry_id(s.get("id"))
        if not sid:
            continue
        items.append({"id": sid, "kind": "script", "name": s.get("name", sid),
                      "state": state, "detail": detail, "url": s.get("url"),
                      "group": resolve_yaml_entry_group(s, fallback="Custom", rules=rules),
                      "links": s.get("links"),
                      "ports": list(ports),
                      "actions": acts,
                      "adopted": bool(s.get("adopted_from"))})
    return items
