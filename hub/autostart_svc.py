"""Boot / login autostart management for Docker, Homebrew services, LaunchAgents.

- Docker: HostConfig.RestartPolicy (unless-stopped / always / no / on-failure)
- Brew: brew services start/stop (loads/unloads LaunchAgent with RunAtLoad)
- LaunchAgents: RunAtLoad / KeepAlive / Disabled in plist + launchctl load/unload
"""
from __future__ import annotations

import os
import plistlib
import re
from pathlib import Path

from hub import cli_args
from hub.docker_cli import _jsonable, engine_up
from hub.errors import CODES, api_error
from hub.launchd_cache import invalidate_launchd, loaded_labels
from hub.util import cached_snapshot, fan_out, read_bytes_capped, run_capped, sh, strftime_now, utf8_env
from hub.brew_cache import brew_services_list, invalidate_brew_services

# Imported for the panel/launcher label spellings rather than restating them here:
# this module has to recognise the very jobs launcher_svc installs, and a second
# copy of those names would drift the moment either side gains a spelling. Safe at
# import time in this direction only -- launcher_svc reaches for hub.launchd_cache,
# hub.paths and hub.util, none of which import this module, so there is no cycle.
from hub import launcher_svc  # noqa: E402

from hub.paths import AGENTS_DIR, user_home  # noqa: E402
# Imported rather than redefined: hub.paths tries `which brew` before the two
# standard prefixes, so a Homebrew installed anywhere else is still found. The
# local copy this replaces only knew /opt/homebrew and /usr/local, which meant
# autostart quietly reported "brew missing" on a host where other pages using
# hub.paths.BREW worked fine.
from hub.paths import BREW  # noqa: E402

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

_TTL = 12.0
#: Leftover multi-MB LaunchAgent plist used to OOM GET /api/apps/autostart.
_PLIST_CAP = 256 * 1024

# Same code (and localized string) native_catalog registers for its own
# LaunchAgent writes; setdefault here too so raising it does not depend on
# import order — api_error() degrades unknown codes to HTTP 500.
CODES.setdefault(
    "catalog.plist_write_failed",
    (409, "could not write LaunchAgent {label}: {detail}"),
)


def _isinstance(value, types) -> bool:
    """isinstance that survives a leftover raising ``__class__`` property.

    When the type check fails, CPython's isinstance consults
    ``value.__class__`` — so a leftover object whose ``__class__`` is a
    raising property used to blow the snapshot gate / field probes in
    :func:`_brew_service_items` (wiping every Homebrew row into overview()'s
    _safe fallback) and the ``_plain_rc`` probes that run outside the toggle
    trys.  A real subclass never reaches the ``__class__`` lookup (the type
    check answers first) — the brew_svc/brew_cache ``_isinstance`` convention.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _as_text(value) -> str:
    """JSON-safe leftover. ``\\ud800`` in brew/Popen messages used to 500 autostart JSON.

    Unbound through the base types, like brew_svc._as_text: a leftover
    bytes-subclass whose bound ``.decode`` raises (or a str-subclass whose
    ``.encode`` does — including one minted by a self-``__str__``) used to
    raise out of the launchctl log tail below and 500 POST /api/apps/autostart.
    Guarded isinstance: a ``__class__`` property bomb used to blow the chain.
    """
    if value is None:
        return ""
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


def _plain_rc(value):
    """Exact-type launchctl/brew rc for the post-spawn tails below.

    The vanished-brew sentinel check in :func:`set_brew_autostart` and the
    ``ok`` render must run *outside* the spawn try (its broad except used to
    swallow the coded 503 raise), so a leftover numeric-subclass rc whose
    ``__eq__`` raises used to 500 POST /api/apps/autostart after the run had
    already finished — the exact class brew_svc.service_action sealed, left
    over in this sibling.  Unbound base-type calls dodge the override;
    anything non-numeric degrades to None.  Guarded isinstance: a leftover
    rc whose ``__class__`` property raises used to blow the first probe here.
    """
    if type(value) is bool:
        return int(value)
    if _isinstance(value, int) and type(value) is not bool:
        try:
            return int.__index__(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isinstance(value, float):
        try:
            return float.__float__(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    return None


def _rc_note(op: str, rc) -> str:
    """``{op} rc={rc}`` for the launchctl toggle message, whatever rc's shape.

    A leftover over-cap rc (hex-minted ints dodge CPython's str->int digit
    cap) used to ValueError the f-string and 500 POST /api/apps/autostart
    after launchctl had already run; subclass rc bombs degrade via _plain_rc.
    """
    rc = _plain_rc(rc)
    if rc is None:
        return f"{op} rc=unknown"
    try:
        return f"{op} rc={rc}"
    except (ValueError, TypeError, RecursionError, OverflowError):
        return f"{op} rc=unknown"


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _plist_label(pl: dict, fallback: str) -> str:
    raw = pl.get("Label") if isinstance(pl, dict) else None
    return raw if isinstance(raw, str) and raw else fallback

#: Labels this page must never switch *off*.  These are the panel itself and the
#: login launcher that starts it, and disabling either from here was a one-click,
#: hard-to-undo foot-gun: ``set_launchd_autostart(label, False)`` writes
#: ``RunAtLoad=False`` *and* runs ``launchctl disable gui/<uid>/<label>``, which is
#: recorded in launchd's per-user database and survives reboots -- after that even
#: restoring ``RunAtLoad=true`` in the plist will not load the job, so ServerHub
#: simply stops coming back at login and the operator has no button left to fix it
#: with.  ``PROTECTED_LABELS`` in hub/services_uninstall_svc.py only guards the
#: "uninstall service" path and never saw these calls.
#: The spellings come from hub.launcher_svc so the two modules cannot disagree
#: about what the panel is called; all three naming schemes (source, native app,
#: distribution) point at the same supervised job, so all of them are refused.
#: Compared lowercased, like the uninstall guard: LaunchAgents lives on a
#: case-insensitive volume by default, so ``Com.Elvin.Serverhub`` resolves to the
#: real panel plist and an exact match would let it through.
SELF_PROTECTED_LABELS = frozenset(
    label.lower()
    for label in (
        launcher_svc.PANEL_LABEL,
        *launcher_svc.PANEL_LABEL_ALTERNATES,
        launcher_svc.LAUNCHER_LABEL,
        *launcher_svc.LAUNCHER_LABEL_ALTERNATES,
    )
)

#: The login autostart agent has shipped under several labels: source installs use
#: the dotted ``local.serverhub.autostart``, distribution installs write
#: ``com.elvin.server-autostart``.  Only the first spelling was hard-coded below,
#: so on this host -- where the installed agent is ``com.elvin.server-autostart``,
#: loaded, RunAtLoad=true and demonstrably running at boot -- the "登录脚本" row
#: reported autostart=False/running=False with no actions, while
#: ``set_script_autostart()`` could only ever raise 404 "plist not found".
#: Order is priority: a source install keeps its dotted label even if a
#: distribution plist is also lying around.
SCRIPT_LABEL_CANDIDATES = (
    "local.serverhub.autostart",
    "com.elvin.server-autostart",
    "local.server-autostart",
    "com.elvin.serverhub.autostart",
)


def _brew_env() -> dict:
    env = dict(os.environ)
    path = env.get("PATH", "")
    for p in ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"):
        if p not in path:
            path = p + ":" + path
    env["PATH"] = path
    env.setdefault("HOMEBREW_NO_AUTO_UPDATE", "1")
    env.setdefault("HOMEBREW_NO_ANALYTICS", "1")
    return env


def _uid_domain() -> str:
    return f"gui/{os.getuid()}"


def _read_plist(path: Path) -> dict:
    try:
        pl = plistlib.loads(read_bytes_capped(path, _PLIST_CAP))
        return pl if isinstance(pl, dict) else {}
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return {}


def _write_plist(path: Path, data: dict) -> None:
    from hub import secure_io
    try:
        secure_io.replace_bytes(path, plistlib.dumps(data))
    except (OSError, OverflowError, ValueError, TypeError, RecursionError) as exc:
        # plistlib.loads reads any <integer> — the 0x… spelling parses uncapped
        # past CPython's digit limit — but the dumps writer refuses ints outside
        # the 64-bit window with OverflowError (the files_svc/ondemand class).
        # That, or an unwritable LaunchAgents dir (OSError from replace_bytes),
        # used to 500 POST /api/apps/autostart for a launchd/script toggle on a
        # plist that had already passed the bad_plist gate — homebrew.mxcl.*
        # agents included.  Same coded 409 as native_catalog's agent writes.
        label = data.get("Label") if isinstance(data.get("Label"), str) else path.stem
        raise api_error(
            "catalog.plist_write_failed", label=label, detail=_as_text(exc)
        )


def _loaded_labels() -> frozenset[str]:
    """Every loaded job in this session, from one `launchctl list`.

    This used to be called once *per label* from inside the plist loop, which is
    what made /api/apps/autostart cost 63 subprocesses on a 29-agent host:
    `launchctl list` already reports every job, so asking it again for each agent
    was N-1 invocations of one command answering one question.

    The listing itself now lives in :mod:`hub.launchd_cache`, shared with the health
    checks and the native catalog -- `/api/apps/managed` walks both this module and
    that one, and so ran two listings per page.

    A set of labels rather than the raw text it used to return, because the caller's
    test was ``label in text``: a substring match, which answers yes for
    ``local.foo`` when only ``local.foobar`` is loaded.  Exact matching can only
    move an answer from a wrong yes to the per-label probe below, which is the one
    that can actually tell.
    """
    return loaded_labels()


def _launchctl_loaded(label: str, loaded_snapshot: frozenset[str] | None = None) -> bool:
    """Whether *label* is loaded, cheapest signal first.

    Both probes mean the same thing and the answer is their OR, so the order is
    free to change: consult the shared `launchctl list` snapshot when the caller has
    one, and pay for a per-label `launchctl print` only when the snapshot does not
    already say yes. For a loaded agent that is zero extra subprocesses.
    """
    if loaded_snapshot is not None and label in loaded_snapshot:
        return True
    rc, out, _ = sh(["/bin/launchctl", "print", f"{_uid_domain()}/{label}"], timeout=5)
    if rc == 0 and out:
        return True
    if loaded_snapshot is not None:
        # Already checked above; re-running `list` would ask the same question twice.
        return False
    return label in loaded_labels()


# ─── Docker ──────────────────────────────────────────────────────────────────

def _docker_autostart_items() -> list[dict]:
    if not engine_up():
        return []
    from hub import containers_svc
    info = containers_svc.list_containers(with_stats=False)
    raw = info.get("containers") if isinstance(info, dict) else None
    items = []
    for c in raw if isinstance(raw, list) else []:
        if not isinstance(c, dict):
            continue
        ident = c.get("id") if c.get("id") is not None else c.get("name")
        # bool is an int; True must not become the container name "True".
        if isinstance(ident, bool) or ident is None or not isinstance(ident, (str, int)):
            continue
        name = str(ident)
        if not name:
            continue
        policy = c.get("restart_policy") or "no"
        auto = bool(c.get("autostart")) or policy in ("always", "unless-stopped", "on-failure")
        items.append({
            "id": f"docker-ctr:{name}",
            "kind": "docker",
            "name": c.get("name") or name,
            "label": name,
            "autostart": auto,
            "policy": policy,
            "running": c.get("raw_state") == "running" or c.get("state") == "ok",
            "state": c.get("state"),
            "detail": f"restart={policy}",
            "project": c.get("project"),
            "actions": ["enable", "disable", "set_policy"],
            "group": "Docker containers",
        })
    return items


def set_docker_autostart(name: str, enabled: bool, policy: str | None = None) -> dict:
    from hub import containers_svc
    if enabled:
        pol = policy if policy in ("always", "unless-stopped", "on-failure") else "unless-stopped"
    else:
        pol = "no"
    return containers_svc.set_restart_policy(name, pol)


# ─── Brew services ───────────────────────────────────────────────────────────

def _brew_service_items() -> list[dict]:
    if not _is_file(Path(BREW)):
        return []
    items = []
    # Shared TTL cache: this list was being fetched once per caller, and
    # `brew services list --json` costs ~1.3s each time.  Guarded probes:
    # a snapshot object — or one element — whose ``__class__`` property
    # raises used to blow the gates below (which run outside any try here)
    # into overview()'s _safe fallback and wipe every Homebrew row.
    try:
        data = brew_services_list()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []
    if not _isinstance(data, list):
        return []
    # Unbound base iteration into an exact list, the brew_cache._copy_items
    # convention: a leftover list-subclass ``__iter__`` bomb (or a
    # dict-subclass row whose ``get`` raises below) used to raise out of this
    # collector into overview()'s _safe fallback and wipe every Homebrew row
    # from GET /api/apps/autostart instead of costing only the poisoned value.
    try:
        rows = [s for s in list.__iter__(data) if _isinstance(s, dict)]
    except _CONTROL_FLOW:
        raise
    except BaseException:
        rows = []
    for s in rows:
        # _as_text yields an exact, surrogate-scrubbed str: a str-subclass
        # name/status whose ``__format__``/``.lower()`` raises used to bomb
        # the f-string / bound-lower below the same way.
        name = _as_text(dict.get(s, "name"))
        if not name or name == "nginx":  # managed separately via custom conf often
            # still show nginx but mark custom
            pass
        status = _as_text(dict.get(s, "status")).lower()
        raw_file = dict.get(s, "file")
        if _isinstance(raw_file, (str, bytes, bytearray)):
            # _as_text, not bound ``.decode``: a bytes-subclass decode bomb
            # used to raise here and cost the whole collector.
            file_path = _as_text(raw_file)
        else:
            file_path = ""
        pl = {}
        if file_path:
            try:
                fp = Path(file_path)
                if fp.exists():
                    pl = _read_plist(fp)
            except (OSError, ValueError, TypeError):
                pl = {}
        # brew services "started" means loaded; RunAtLoad typically true when managed by brew
        run_at = pl.get("RunAtLoad", True) if pl else (status in ("started", "running", "error"))
        # autostart ≈ will start at login: brew has registered the agent (file exists + RunAtLoad)
        auto = bool(file_path) and bool(run_at) and status != "none"
        # status none = not started as service; may still have plist from previous start
        if status == "none" and not file_path:
            auto = False
        items.append({
            "id": f"brew:{name}",
            "kind": "brew",
            "name": name,
            "label": _plist_label(pl, f"homebrew.mxcl.{name}"),
            "autostart": auto,
            "running": status in ("started", "running"),
            "status": status or "unknown",
            "plist": file_path or None,
            "run_at_load": bool(run_at) if pl else None,
            "keep_alive": bool(pl.get("KeepAlive")) if pl else None,
            "detail": f"brew services · {status or '—'}",
            "actions": ["enable", "disable"],
            "group": "Homebrew services",
        })
    return items


def set_brew_autostart(name: str, enabled: bool) -> dict:
    # Same hyphen-permissive class as brew_svc had: `{"id": "brew:--all"}`
    # reached `brew services stop --all`.
    name = cli_args.require_positional(name, label="brew service name")
    if not _is_file(Path(BREW)):
        raise api_error("brew.not_found")
    action = "start" if enabled else "stop"
    try:
        rc, msg = run_capped(
            [BREW, "services", action, name],
            timeout=120, env=_brew_env(), cap=2000,
        )
        msg = _as_text(msg).strip()
    except RecursionError:
        # leftover ``str(e)`` RecursionError is not OSError; PUT brew autostart used to 500.
        return {"ok": False, "message": "action failed"}
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        return {"ok": False, "message": _as_text(e) or "action failed"}
    # Exact-type rc before the comparisons below: they run outside the try
    # (deliberately, so the coded 503 raise cannot be swallowed), which meant
    # a leftover numeric-subclass rc whose ``__eq__`` raises 500'd the toggle
    # after brew had already run — the class service_action's tail sealed.
    rc = _plain_rc(rc)
    if rc == -1 and msg == "not found":
        # run_capped reports a FileNotFoundError spawn as (-1, "not found") —
        # a sentinel, never a real brew exit.  Homebrew vanished between the
        # _is_file(BREW) gate above and the spawn, so answer with the same
        # coded 503 that gate raises instead of the uncoded {ok: false,
        # message: "not found"} the SPA cannot translate (the exact leftover
        # brew_svc.brew_service_action already fixed; this sibling call kept
        # it).  Sits outside the try above so the broad except cannot swallow
        # the raise into that uncoded shape.  Confirmed against the
        # filesystem, mirroring the docker classifiers' forced engine probe:
        # a brew that is still present keeps its raw result.
        if not _is_file(Path(BREW)):
            raise api_error("brew.not_found")
    # `brew services start/stop` is exactly what the shared snapshot
    # reports on, so the cached copy is stale the moment this returns.
    invalidate_brew_services()
    # stop unloads agent → no login start; start loads with RunAtLoad
    return {
        "ok": rc == 0,
        "message": msg or f"brew services {action} {name}",
        "autostart": enabled if rc == 0 else None,
    }


# ─── LaunchAgents (user) ─────────────────────────────────────────────────────

def _launchd_items(loaded_snapshot: frozenset[str] | None = None) -> list[dict]:
    items = []
    if not _is_dir(AGENTS_DIR):
        return items

    # The login script agent gets its own "登录脚本" row from ``_script_status()``.
    # Listing it here as well put the same job on the page twice, and because the
    # two rows computed autostart differently they disagreed: the script row said
    # "未启用" (it was resolving a label that does not exist here) while this one
    # correctly said autostart=True.  Resolving once and skipping it keeps one row
    # per job whichever spelling is installed.  Cannot raise -- ``overview()`` calls
    # this through ``fan_out``.
    try:
        script_plist, script_label = _resolve_script_agent()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        script_plist, script_label = None, None

    # Parse and filter the plists first — pure filesystem work — so the subprocess
    # probes below are paid only for agents that survive the filter.
    parsed = []
    try:
        plist_paths = sorted(AGENTS_DIR.glob("*.plist"))
    except OSError:
        return items
    for path in plist_paths:
        pl = _read_plist(path)
        label = _plist_label(pl, path.stem)
        # skip brew-managed (shown under brew) to reduce dupes — still include non-mxcl
        if label.startswith("homebrew.mxcl."):
            continue  # covered by brew list
        # Compared by both label and path: the resolver may have matched on the
        # plist's internal Label, in which case the filename alone would not.
        if script_label is not None and (label == script_label or path == script_plist):
            continue  # owned by the login-script group above
        parsed.append((path, pl, label))
    if not parsed:
        return items

    if loaded_snapshot is None:
        loaded_snapshot = _loaded_labels()

    # Whatever the snapshot cannot answer needs its own `launchctl print`. Those are
    # independent of one another, so probe them together instead of walking the list.
    # `_launchctl_loaded` cannot raise, which is what fan_out requires.
    unknown = [label for _, _, label in parsed if label not in loaded_snapshot]
    probed = dict(zip(
        unknown,
        fan_out(lambda lb: _launchctl_loaded(lb, loaded_snapshot), unknown),
    ))

    for path, pl, label in parsed:
        run_at = bool(pl.get("RunAtLoad"))
        keep = pl.get("KeepAlive")
        disabled = bool(pl.get("Disabled"))
        loaded = True if label in loaded_snapshot else probed.get(label, False)
        auto = run_at and not disabled
        items.append({
            "id": f"launchd:{label}",
            "kind": "launchd",
            "name": label,
            "label": label,
            "autostart": auto,
            "running": loaded,
            "run_at_load": run_at,
            "keep_alive": bool(keep) if not isinstance(keep, dict) else True,
            "disabled": disabled,
            "plist": str(path),
            "detail": f"RunAtLoad={run_at} KeepAlive={bool(keep)} loaded={loaded}",
            "program": (
                " ".join(_as_text(a) for a in pl["ProgramArguments"])[:100]
                if isinstance(pl.get("ProgramArguments"), list) else ""
            ),
            # No "disable" for the panel and its login launcher: offering the button
            # invited a click that stops ServerHub from ever starting at login, and
            # the ``launchctl disable`` behind it outlives a reboot (see
            # SELF_PROTECTED_LABELS).  "enable" stays so this row can repair a host
            # that was disabled before the guard existed.  ``set_launchd_autostart``
            # refuses it too -- this only removes the temptation from the UI, the
            # rule itself lives at the sink where the API can also be called direct.
            "actions": (
                ["enable"]
                if label.lower() in SELF_PROTECTED_LABELS
                else ["enable", "disable"]
            ),
            "group": "LaunchAgents",
        })
    return items


def set_launchd_autostart(label: str, enabled: bool) -> dict:
    # The hyphen is inside the class with no anchor on the first character, so
    # "--foo" matches.  It is not exploitable at the sinks below, because the
    # label is always interpolated behind a "gui/<uid>/" prefix and so can never
    # be argv-initial -- but that is an accident of the current call sites, and a
    # launchd label does not start with a hyphen in the first place.
    # `^[\w.@+-]+$` matched `--all`.  The shared guard anchors the first character.
    label = cli_args.require_positional(label, label="launchd label")
    # Refused before anything is written or unloaded.  Only the off direction is
    # blocked: enabling has to stay reachable so a host that was already disabled --
    # by this endpoint before the guard existed, or by hand -- can be repaired from
    # the page instead of needing a shell.
    if not enabled and label.lower() in SELF_PROTECTED_LABELS:
        raise api_error("autostart.self_protected", label=label)
    path = AGENTS_DIR / f"{label}.plist"
    # find by Label field if filename differs
    if not _exists(path):
        try:
            found = list(AGENTS_DIR.glob("*.plist"))
        except OSError:
            found = []
        for p in found:
            pl = _read_plist(p)
            if pl.get("Label") == label:
                path = p
                break
    if not _exists(path):
        raise api_error("autostart.plist_missing", label=label)

    pl = _read_plist(path)
    # A torn/non-dict plist used to come back as {} and this wrote
    # {RunAtLoad, Disabled} over the live agent, wiping ProgramArguments.
    if not isinstance(pl.get("Label"), str) or not pl.get("Label"):
        raise api_error("autostart.bad_plist", label=label)
    pl["RunAtLoad"] = bool(enabled)
    if enabled:
        pl["Disabled"] = False
    else:
        # keep KeepAlive as-is but RunAtLoad false; unload if loaded
        pass
    _write_plist(path, pl)

    dom = _uid_domain()
    logs = []
    # ``_as_text(out) or _as_text(err)``, not ``_as_text(out or err)``: the
    # bare ``or`` asked the raw value for truth, so a leftover str-subclass
    # ``__bool__`` bomb from a hostile sh 500'd the toggle before the text
    # was ever laundered.  ``_rc_note`` renders the rc fallback: an over-cap
    # rc used to ValueError the bare f-string here too.
    if enabled:
        # bootout then bootstrap to pick up RunAtLoad
        sh(["/bin/launchctl", "bootout", f"{dom}/{label}"], timeout=8)
        rc, out, err = sh(["/bin/launchctl", "bootstrap", dom, str(path)], timeout=10)
        logs.append(_as_text(out) or _as_text(err) or _rc_note("bootstrap", rc))
        sh(["/bin/launchctl", "enable", f"{dom}/{label}"], timeout=5)
        sh(["/bin/launchctl", "kickstart", "-k", f"{dom}/{label}"], timeout=10)
    else:
        rc, out, err = sh(["/bin/launchctl", "bootout", f"{dom}/{label}"], timeout=10)
        logs.append(_as_text(out) or _as_text(err) or _rc_note("bootout", rc))
        # disable for session
        sh(["/bin/launchctl", "disable", f"{dom}/{label}"], timeout=5)

    # This label was just loaded or unloaded, and the overview the panel refetches
    # right after reads the shared listing.  Without dropping it, the toggle would
    # be answered from a listing taken before the change and read as a no-op.
    invalidate_launchd()
    overview.invalidate()
    return {
        "ok": True,
        "message": f"RunAtLoad={enabled} · " + " · ".join(logs)[:400],
        "autostart": enabled,
        "plist": str(path),
    }


# ─── Global login autostart script ───────────────────────────────────────────

def _resolve_script_agent() -> tuple[Path, str]:
    """Return the (plist, label) pair for the login script agent installed here.

    Same shape as ``launcher_svc._resolve()``: the highest-priority candidate whose
    plist exists wins, and with none installed the first candidate is still returned
    so the row has a stable label to display and a correct target to write.

    Matching also has to consider the plist's internal ``Label``, not just the
    filename -- ``set_launchd_autostart`` already falls back to that, and a hand-
    written agent whose file was renamed would otherwise resolve to nothing while
    launchd knows it perfectly well.  That scan is only paid when no filename
    matched, and it never raises: this runs inside ``fan_out`` via ``overview()``,
    where one exception costs the whole batch rather than one row.
    """
    default = (AGENTS_DIR / f"{SCRIPT_LABEL_CANDIDATES[0]}.plist", SCRIPT_LABEL_CANDIDATES[0])
    for label in SCRIPT_LABEL_CANDIDATES:
        candidate = AGENTS_DIR / f"{label}.plist"
        try:
            if candidate.is_file():
                return candidate, label
        except OSError:
            continue
    by_label: dict[str, Path] = {}
    try:
        for path in sorted(AGENTS_DIR.glob("*.plist")):
            declared = _read_plist(path).get("Label")
            # First file wins per label, so the answer does not depend on
            # directory order when two plists declare the same job.
            if isinstance(declared, str) and declared not in by_label:
                by_label[declared] = path
    except OSError:
        return default
    for label in SCRIPT_LABEL_CANDIDATES:
        hit = by_label.get(label)
        if hit is not None:
            return hit, label
    return default


def _script_status(loaded_snapshot: frozenset[str] | None = None) -> dict:
    # Resolved, never hard-coded: see SCRIPT_LABEL_CANDIDATES for what the fixed
    # ``local.serverhub.autostart`` spelling did to this row on a distribution
    # install.  The resolved label also feeds the skip in ``_launchd_items()``, so
    # the same agent stops being listed twice with contradictory states -- it used
    # to appear here as "未启用" and again under "LaunchAgents" as autostart=True.
    plist, label = _resolve_script_agent()
    home = user_home()
    script = (home / "Services" / "autostart.sh") if home is not None else None
    installed = _exists(plist)
    pl = _read_plist(plist) if installed else {}
    return {
        # Keeps the "script:" prefix: set_autostart() dispatches on kind:name and
        # this row has to keep landing in the `kind == "script"` branch.
        "id": f"script:{label}",
        "kind": "script",
        "name": "Login autostart script (autostart.sh)",
        "label": label,
        "autostart": bool(pl.get("RunAtLoad")) and installed,
        "running": _launchctl_loaded(label, loaded_snapshot) if installed else False,
        "plist": str(plist) if installed else None,
        "script": str(script) if script is not None and _exists(script) else None,
        "detail": "starts the configured local services after login",
        "actions": ["enable", "disable", "run_now"] if installed else [],
        "group": "Login script",
    }


def set_script_autostart(enabled: bool) -> dict:
    # Must target the same label the row reports.  Hard-coding the dotted spelling
    # meant the toggle read one job and wrote another: on any install that is not a
    # source install it raised 404 "plist not found" for a job that was right there.
    _, label = _resolve_script_agent()
    return set_launchd_autostart(label, enabled)


def run_autostart_now() -> dict:
    home = user_home()
    if home is None:
        raise api_error("autostart.script_missing")
    script = home / "Services" / "autostart.sh"
    if not _exists(script):
        raise api_error("autostart.script_missing")
    import subprocess
    try:
        p = subprocess.Popen(
            ["/bin/bash", str(script)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=utf8_env(_brew_env()),
        )
        return {"ok": True, "message": f"autostart.sh started in the background (pid {p.pid})"}
    except RecursionError:
        return {"ok": False, "message": "start failed"}
    except (OSError, ValueError, TypeError) as e:
        # Leftover ``\\ud800`` env UnicodeEncodeError is ValueError, not OSError.
        return {"ok": False, "message": _as_text(e) or "start failed"}
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        return {"ok": False, "message": _as_text(e) or "start failed"}


# ─── Overview ────────────────────────────────────────────────────────────────

@cached_snapshot(_TTL)
def overview(force: bool = False) -> dict:

    # Four independent inventories — docker inspect, the shared brew snapshot, the
    # LaunchAgents directory and the login script — plus one `launchctl list` that
    # the last two both read. Taking the snapshot first means it is fetched once
    # rather than once per collector, and the collectors then overlap.
    loaded_snapshot = _loaded_labels()

    def _safe(item):
        probe, fallback = item
        try:
            return probe()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return fallback

    # fan_out re-raises on iteration; a dead Docker socket must not
    # empty brew / LaunchAgent / login-script rows too.
    docker_items, brew_items, launchd_items, script = fan_out(
        _safe,
        [
            (_docker_autostart_items, []),
            (_brew_service_items, []),
            (lambda: _launchd_items(loaded_snapshot), []),
            (lambda: _script_status(loaded_snapshot), {
                "id": "script:",
                "kind": "script",
                "name": "Login autostart script (autostart.sh)",
                "label": "",
                "autostart": False,
                "running": False,
                "plist": None,
                "script": None,
                "detail": "status unavailable",
                "actions": [],
                "group": "Login script",
            }),
        ],
        max_workers=4,
    )

    items = [script] + brew_items + launchd_items + docker_items
    counts = {
        "total": len(items),
        "autostart_on": sum(1 for i in items if i.get("autostart")),
        "autostart_off": sum(1 for i in items if not i.get("autostart")),
        "docker": len(docker_items),
        "brew": len(brew_items),
        "launchd": len(launchd_items),
        "running": sum(1 for i in items if i.get("running")),
    }
    v = {
        "ts": strftime_now("%H:%M:%S"),
        "items": items,
        "counts": counts,
        "groups": ["Login script", "Homebrew services", "LaunchAgents", "Docker containers"],
        "hint": "Docker uses restart policies; brew/LaunchAgents load at login. Stopping a brew service also cancels its login autostart.",
    }
    cleaned = _jsonable(v)
    return cleaned if isinstance(cleaned, dict) else v


def set_autostart(item_id: str, enabled: bool, policy: str | None = None) -> dict:
    """Toggle autostart. id: docker-ctr:name | brew:name | launchd:label | script:..."""
    overview.invalidate()
    if ":" not in item_id:
        raise api_error("autostart.bad_id")
    kind, _, name = item_id.partition(":")
    if kind == "docker-ctr" or kind == "docker":
        # allow docker:name alias
        return set_docker_autostart(name, enabled, policy=policy)
    if kind == "brew":
        return set_brew_autostart(name, enabled)
    if kind == "launchd":
        return set_launchd_autostart(name, enabled)
    if kind == "script":
        return set_script_autostart(enabled)
    raise api_error("autostart.unknown_kind", kind=kind)


def set_docker_policy(name: str, policy: str) -> dict:
    overview.invalidate()
    from hub import containers_svc
    return containers_svc.set_restart_policy(name, policy)
