"""Append-only audit trail for security-relevant events.

``terminal_svc`` already audits command execution, but authentication itself was
invisible: a successful sign-in, a failed one, a logout, a first-run setup claim
and a password rotation all left no record at all.  With family accounts on the
way, "who did this and when" stops being answerable from memory, so those events
need a durable trail.

Two properties matter more than the schema:

* **Secrets never land in the log.**  The events recorded here are exactly the
  ones whose request bodies carry passwords and setup tokens, so redaction is
  not a nicety -- writing a plaintext password into a file that is later read
  back by an API endpoint would be worse than having no audit log.  Redaction is
  therefore applied by key name inside :func:`record`, not left to each caller
  to remember.

* **Logging never breaks the request.**  A full disk or an unwritable directory
  must not turn a valid sign-in into a 500.  Every failure path here is
  swallowed, matching ``terminal_svc._audit``.

This module deliberately does not decide *authorisation*.  It observes and
records; it never grants or refuses anything.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from hub import secure_io
from hub.paths import DATA_DIR
from hub.util import safe_json_loads, strftime_now, tail_file_lines

AUDIT_PATH = DATA_DIR / "auth-audit.jsonl"

#: Keep the trail bounded so it cannot fill the disk unattended.  Old lines are
#: dropped from the front, because the newest events are the ones being
#: investigated.
MAX_LINES = 5000
# Skip the full-file read while the log is still well under the cap.  A
# typical line is ~150 B; 192 B/line starts checking before a fat-line
# trail can run far past MAX_LINES.
_TRIM_SOFT_BYTES = MAX_LINES * 192

#: Serialises append + trim.  The O_APPEND write alone is atomic, but _trim is
#: a read-tail-then-replace: a record() on another request thread that lands
#: between the read and the rename is thrown away with the temp-file swap.
#: Sync handlers run on uvicorn's thread pool, so two operators (or one
#: operator plus the dashboard poll) hitting mutating routes concurrently is
#: the normal case, not a corner — and the loss would be a security event.
#:
#: This lock is per-interpreter only.  The deployment hub/config.py grew its
#: services.yaml flock for — a packaged ServerHub.app and the LaunchAgent
#: panel sharing one ``data/`` — writes this trail from two processes, so
#: record() additionally takes secure_io.file_lock (a kernel flock) around
#: the same window; without it a trim in one process discarded entries the
#: other had just appended to the pre-swap inode.
_WRITE_LOCK = threading.Lock()

#: Event names.  Kept as constants so a typo in a caller is an AttributeError
#: rather than a silently unqueryable log line.
LOGIN_OK = "auth.login.ok"
LOGIN_FAILED = "auth.login.failed"
LOGIN_RATE_LIMITED = "auth.login.rate_limited"
LOGOUT = "auth.logout"
SETUP_CLAIMED = "auth.setup.claimed"
SETUP_REJECTED = "auth.setup.rejected"
PASSWORD_CHANGED = "auth.password.changed"
PASSWORD_CHANGE_DENIED = "auth.password.change_denied"
#: Two-factor lifecycle.  Enabling, disabling and recovery-code churn change
#: what signing in takes, and a forced removal is an administrator acting on
#: someone else's credential — all of it leaves a trail.  The shared secret,
#: TOTP codes and recovery codes themselves are never passed to record().
TWOFA_ENABLED = "auth.2fa.enabled"
TWOFA_DISABLED = "auth.2fa.disabled"
TWOFA_FORCE_DISABLED = "auth.2fa.force_disabled"
TWOFA_RECOVERY_REGENERATED = "auth.2fa.recovery_regenerated"
TWOFA_RECOVERY_USED = "auth.2fa.recovery_used"
#: Panel accounts (multi-user).  Creating, re-scoping, resetting or deleting a
#: member account changes who can sign in and what they reach, so each names
#: both the administrator acting (``username``) and the account acted on
#: (``target``).  Passwords never reach record(); resource ids are public.
ACCOUNT_CREATED = "auth.account.created"
ACCOUNT_RESOURCES_CHANGED = "auth.account.resources_changed"
ACCOUNT_PASSWORD_RESET = "auth.account.password_reset"
ACCOUNT_DELETED = "auth.account.deleted"
#: API keys are standing credentials, so minting and revoking one names the
#: operator.  Records carry the key's id/name/role — never the key itself,
#: which exists in plaintext only inside the create response.
APIKEY_CREATED = "apikey.created"
APIKEY_REVOKED = "apikey.revoked"
SHARE_CHANGED = "shares.changed"
SYSTEM_SHARING_CHANGED = "shares.system.changed"
#: Storage and data-protection operations.  Every one of these either exposes
#: data to the network or destroys it, so each leaves a trail naming the operator.
NFS_CHANGED = "nfs.changed"
RAID_CHANGED = "raid.changed"
SNAPSHOT_CHANGED = "snapshots.changed"
SMART_TEST_STARTED = "smart.test.started"
SMART_TEST_ABORTED = "smart.test.aborted"
SMART_SCHEDULE_CHANGED = "smart.schedule.changed"
#: A backup run reads every byte of the data it protects and writes it
#: somewhere else, so a manual trigger names who asked for it.
BACKUP_RUN = "backup.run"
SPOTLIGHT_CHANGED = "spotlight.changed"
#: Shutdown / restart / sleep takes every service on the machine down at
#: once.  "Why did the server go dark at 02:14, and who told it to" is the
#: canonical audit-trail question, so the scheduled action and the operator
#: are recorded before the box goes away.  Wake-on-LAN decides whether the
#: machine can be brought back remotely, so flipping it is recorded too.
POWER_ACTION = "power.action"
POWER_WOL_CHANGED = "power.wol.changed"
#: Scheduled jobs run arbitrary shell commands and move data around, so every
#: definition change and manual trigger names the operator.  The command text
#: of a shell job is part of the record: "what exactly did the panel run at
#: 03:30" must be answerable from this trail alone.
SCHEDULE_JOB_CREATED = "scheduler.job.created"
SCHEDULE_JOB_UPDATED = "scheduler.job.updated"
SCHEDULE_JOB_DELETED = "scheduler.job.deleted"
SCHEDULE_JOB_RUN = "scheduler.job.run_now"
#: A notification channel is an outbound data path carrying alert content and
#: credentials, so its lifecycle names the operator.  Secret values never
#: enter these records (redaction drops token-shaped fields regardless).
NOTIFY_CHANNEL_CREATED = "notify.channel.created"
NOTIFY_CHANNEL_UPDATED = "notify.channel.updated"
NOTIFY_CHANNEL_DELETED = "notify.channel.deleted"
NOTIFY_CHANNEL_TESTED = "notify.channel.tested"
#: The legacy Home Assistant notify config (including its token) is edited
#: through PUT /api/settings rather than the channel CRUD, so without this
#: event a credential swap left no trace while the equivalent channel edit
#: did.  Only the changed field *names* are recorded, never values.
NOTIFY_SETTINGS_CHANGED = "notify.settings.changed"
#: A WireGuard peer is a credential granting network access, so issuing and
#: revoking one is recorded with the operator who did it.
WIREGUARD_PEER_ADDED = "wireguard.peer.added"
WIREGUARD_PEER_REMOVED = "wireguard.peer.removed"
WIREGUARD_PEER_CHANGED = "wireguard.peer.changed"
WIREGUARD_INTERFACE = "wireguard.interface"
#: Server-side tunnel settings (endpoint, subnet, DNS, wstunnel wrap) shape
#: what every issued credential can reach, so edits record the changed keys.
WIREGUARD_SETTINGS_CHANGED = "wireguard.settings.changed"
#: UPS safe-shutdown policy (hub/ups_policy.py).  The policy stops and starts
#: real workloads on its own, with nobody at the keyboard, so the trail must
#: answer "why is this stack down / who told it to do that" afterwards: every
#: trigger, every per-target stop/start result, the reset, each config change
#: and each drill leaves a record.  Trigger/step/reset events carry no
#: username — they are the machine acting on policy; the config/drill/halt
#: events name the operator.
UPS_POLICY_TRIGGERED = "ups.policy.triggered"
UPS_POLICY_STEP = "ups.policy.step"
UPS_POLICY_RESET = "ups.policy.reset"
UPS_POLICY_CHANGED = "ups.policy.changed"
UPS_POLICY_DRILL = "ups.policy.drill"
UPS_HALT_CHANGED = "ups.halt.changed"

#: Service lifecycle (hub/routers/api.py, hub/routers/services_api.py).
#: Starting, stopping or restarting a workload changes what is running on the
#: host, and unregistering a launch agent changes what starts at login — the
#: exact questions an operator asks after the fact ("who stopped Immich?").
#: These were the panel's most-used mutations and the only privileged ones
#: that left no record at all.  Maintenance tasks run arbitrary repo-defined
#: scripts, so a manual kick is recorded too.
SERVICE_ACTION = "service.action"
SERVICE_BULK_ACTION = "service.bulk_action"
SERVICE_UNINSTALLED = "service.uninstalled"
MAINTENANCE_RUN = "maintenance.run"

#: Container engine mutations (hub/routers/containers.py).  Creating a
#: container chooses its mounts and privilege level, exec runs an arbitrary
#: command inside one (the Terminal's equivalent has always recorded the
#: command; this trail is 0600 like that one), and removals/prunes destroy
#: data.  Lifecycle events share one name with a target field, mirroring
#: service.action.
CONTAINER_ACTION = "container.action"
CONTAINER_RUN = "container.run"
CONTAINER_EXEC = "container.exec"
CONTAINER_IMAGE_CHANGED = "container.image.changed"
CONTAINER_VOLUME_CHANGED = "container.volume.changed"
CONTAINER_NETWORK_CHANGED = "container.network.changed"
CONTAINER_PRUNED = "container.pruned"
CONTAINER_CONFIG_CHANGED = "container.config.changed"

#: App-store and managed-app mutations (hub/routers/catalog.py).  Installing
#: a template materialises a compose stack or brew formula on the host,
#: uninstalling can delete its data, the credential store writes to the
#: keychain (the password itself is never passed to record()), and the
#: autostart console changes what comes up at boot.
APP_INSTALLED = "app.installed"
APP_UNINSTALLED = "app.uninstalled"
APP_ACTION = "app.action"
APP_CREDENTIAL_SAVED = "app.credential.saved"
APP_CREDENTIAL_DELETED = "app.credential.deleted"
APP_AUTOSTART_CHANGED = "app.autostart.changed"

#: Cloudflare Tunnel lifecycle (hub/routers/cloudflared_api.py).  A tunnel
#: exposes this panel to the public internet, and route-dns points a public
#: hostname at it — exactly the changes to reconstruct after an exposure
#: question.  The connector token is never passed to record().
TUNNEL_CHANGED = "cloudflared.changed"

#: Compose editor, brew services and system nginx (hub/routers/modules_api.py).
#: A compose save is arbitrary container config awaiting the next stack run.
COMPOSE_CHANGED = "compose.changed"
NGINX_RELOADED = "nginx.reloaded"

#: File manager writes and the FileBrowser sidecar (hub/routers/files_api.py).
FILES_CHANGED = "files.changed"

#: Menu-bar launcher and panel self-management (hub/routers/launcher_api.py).
LAUNCHER_CHANGED = "launcher.changed"

#: Host-level mutations (hub/routers/system_extra.py, storage.py,
#: unraid_parity.py, services_api.py).  Network reconfiguration can cut the
#: panel off from the network it is administered over, a VM console ticket is
#: a raw framebuffer into a guest, eraseDisk is the most destructive action
#: in the panel, a saved service script is arbitrary code run by the next
#: start/stop, and a self-update replaces the panel's own code.
VM_CHANGED = "vm.changed"
VM_CONSOLE_OPENED = "vm.console.opened"
NETWORK_CHANGED = "network.changed"
UPDATES_APPLIED = "updates.applied"
DISK_CHANGED = "disk.changed"
POOL_CHANGED = "storage.pool.changed"
IDENTITY_CHANGED = "identity.changed"
SETTINGS_POWER_CHANGED = "settings.power.changed"
SERVICE_CONFIG_CHANGED = "service.config.changed"

#: Any field whose name contains one of these is replaced wholesale.  Substring
#: matching rather than exact names, so ``current_password``, ``new_password``
#: and ``setup_token`` are all covered without enumerating every variant a
#: future caller might invent.
_SECRET_HINTS = (
    "password",
    "token",
    "secret",
    "credential",
    "cookie",
    "session",
    "authorization",
    "passwd",
    "api_key",
    "apikey",
    # Key material.  The WireGuard events are the reason: a peer's private key
    # and preshared key are the credential itself, and the callers currently pass
    # only the public half by hand -- which is exactly the "left to each caller to
    # remember" arrangement this module's docstring says it exists to replace.  A
    # field named private_key, psk or preshared_key was not covered by any hint
    # above, so the safety net had a hole precisely where the most sensitive
    # values are.
    "key",
    "psk",
    "preshared",
    "passphrase",
    "private",
    "seed",
    "bearer",
)

#: Field names that contain a secret hint but are genuinely public.
#:
#: ``pubkey`` is a peer's identity -- it is what the operator matches a device by,
#: and dropping it would make the WireGuard trail unreadable.  This list is
#: deliberately tiny and explicit: the default for anything key-shaped is to
#: redact, and an addition here is a claim that the value is safe to write to
#: disk.
_PUBLIC_EXCEPTIONS = (
    "pubkey",
    "public_key",
    "publickey",
)

#: Longest string one field may contribute to a trail line.  Unbounded: a
#: caller auditing a whole payload (a 300 KB shell-job command was the found
#: case) wrote a line wider than any tail window.  _trim reads the last
#: ``MAX_LINES * 1024`` bytes and refuses to rewrite when that window holds
#: no complete line, so one runaway line past it turns the trail append-only
#: forever — unbounded disk growth on the one file that must stay bounded
#: unattended.  64 KB keeps the largest legitimate field (a pasted script,
#: a compose fragment) intact while keeping every line far inside the
#: windows both the trim and the reader use.
_STR_CAP = 64 * 1024

#: Real control flow must keep propagating through every bomb guard below:
#: swallowing a Ctrl-C or an interpreter shutdown to save one trail line
#: would turn the sanitizer into a hang.  Everything else BaseException-
#: shaped that a leftover raises out of its own hooks is a bomb like any
#: other — the modules12 rule, applied to the trail that must never break
#: the request it audits.
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)


def _isa(value, kinds) -> bool:
    """``isinstance`` that a leftover ``__class__``-property bomb cannot 500.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the bare type gates themselves: as the ``event`` argument it
    blew ``_utf8_text`` inside record()'s *fallback* entry — the one spot
    outside both nets — and raised into the request being audited; nested
    in a set/frozenset field or planted as a mapping key it blew
    ``_jsonable``'s rank gates and degraded the whole line to the minimal
    ts+event shape, wiping the who/where detail the trail exists for (the
    logs9 / vms_svc rule).  A real subclass still matches through the
    C-level type check; only a value that cannot answer what it is takes
    the non-matching branch.

    ``except BaseException``: the audit9 guard stopped at ``Exception``, so
    a leftover whose ``__class__`` property raises a *BaseException*
    subclass (a watchdog/timeout-style leftover) sailed past this catch —
    and past every sibling guard in this module — straight out of record()
    into the JSON request being audited, a raw 500 from the one module
    whose first guarantee is that logging never breaks the request.  Only
    genuine control flow keeps propagating.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500.

    Every read here goes through *unbound base-type* calls (``bytes.decode``,
    ``str.encode``), the same shape as ``tools_svc._as_text``: a subclass
    overriding ``decode``/``encode``/``__str__`` to raise used to blow this
    scrub from inside record()'s shaping — outside the (ValueError, TypeError,
    RecursionError) net — and 500 the request being audited.
    """
    if _isa(value, (bytes, bytearray)):
        # Both bases, real storage first-come — not the claimed class.  The
        # old arm picked the base off ``_isa(value, bytes)``, so a genuine
        # bytearray whose ``__class__`` lied ``bytes`` was handed to
        # ``bytes.decode``, rejected by the descriptor, and its perfectly
        # decodable content vanished to "" — the who/where detail this
        # line existed for, degraded at the wrong rank (the modules12
        # decode-fidelity rule).  Now the descriptor matching the real
        # layout wins; a total impostor still fails both and drops.
        for base in (bytes, bytearray):
            try:
                text = base.decode(value, "utf-8", "replace")
                break
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
        else:
            return ""
    else:
        if _isa(value, str):
            text = value
        else:
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
                # A ``__str__`` bomb raising a BaseException subclass used
                # to sail past the old ``except Exception`` here and raise
                # out of record()'s shaping — 500ing the audited request.
                return ""
        try:
            # str() may hand back a *subclass* instance (it only checks the
            # type, it does not copy), so the scrub itself must not trust
            # bound methods either.
            text = str.encode(text, "utf-8", "replace").decode("utf-8")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    if len(text) > _STR_CAP:
        # Same marker shape as util.py's log tailer.  Slicing is by code
        # point, so the scrubbed text cannot gain a torn surrogate here.
        text = text[:_STR_CAP] + " …[truncated]"
    return text


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Infinity in a leftover auth-audit.jsonl field was already dropped; a
    leftover ``\\ud800`` username or key still 500'd GET /api/audit/auth.
    """
    if depth > 32:
        return None
    # Exact type, not isinstance: bool cannot be subclassed, so the only
    # thing an isinstance gate admits that this one refuses is an impostor
    # whose lying ``__class__`` property answers ``bool``.  Passed through
    # raw, that impostor reached record()'s json.dumps (whose C encoder
    # checks the real type), fell to ``default=str``, and its ``__str__``
    # bomb then cost the *entire line* inside the disk net — a failed
    # sign-in left no trace at all.  Refused here, it falls through to the
    # int gate below, whose unbound ``int.__index__`` sheds it to None.
    if value is None or type(value) is bool:
        return value
    if _isa(value, int):
        try:
            # Shed a subclass first: an int subclass whose ``__str__`` raised
            # (anything, not just ValueError) used to escape this probe and
            # 500 the request record() was auditing.  ``int.__index__`` is the
            # unbound base slot, so an override cannot reach it.
            value = int.__index__(value)
            str(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Past CPython's int->str digit cap the encoder cannot render the
            # number at all — json.dumps raises the same ValueError.  YAML/plist
            # hex text loads uncapped (``int(x, 16)`` is a power-of-two base),
            # so an already-int leftover used to reach record()'s own dump and
            # cost the *entire* audit line to the logging-never-breaks try: a
            # poisoned failed sign-in left no trace at all.  Dropping just the
            # field keeps the event — the same probe as terminal_svc._jsonable
            # and hub.errors._jsonable_param.
            return None
        return value
    if _isa(value, float):
        try:
            # Base coercion before the finite probes: a float subclass whose
            # ``__ne__``/``__eq__`` raised used to blow ``value != value``.
            value = float.__float__(value)
            if value != value or value in (float("inf"), float("-inf")):
                return None
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
        return value
    if _isa(value, (str, bytes, bytearray)):
        return _utf8_text(value)
    if _isa(value, dict):
        out = {}
        try:
            # Unbound base read: a dict-subclass ``items()`` bomb must cost
            # this field, never the audit line (or the request behind it).
            items = list(dict.items(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return out
        for k, v in items:
            if not _isa(k, (str, bytes, bytearray)):
                try:
                    k = str(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    for base in (list, tuple, set, frozenset):
        if _isa(value, base):
            try:
                # Same shape as the dict read: subclass ``__iter__`` bombs
                # bypass the base slot, so the real elements still list.
                seq = list(base.__iter__(value))
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return []
            return [_jsonable(v, depth + 1) for v in seq]
    try:
        # getattr, guarded: a leftover object whose ``__getattr__`` (or an
        # ``isoformat`` property) raises non-AttributeError used to escape
        # the default and 500 out of record()'s shaping — including one
        # raising a BaseException subclass past the old ``except Exception``.
        iso = getattr(value, "isoformat", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/audit.
            return _jsonable(iso(), depth + 1)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    try:
        return _utf8_text(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _is_secret_key(key: str) -> bool:
    try:
        # Classify the text the *writer* will render, not what a bound
        # ``__str__`` volunteers.  The old probe was ``str(key)``: a str
        # subclass named ``password`` whose ``__str__`` raised made the
        # classifier answer "no name here" — while ``_jsonable`` rendered
        # that same key's real text through the unbound base encode
        # (``_utf8_text`` never calls ``str()`` on a str instance) and the
        # secret value landed on disk under its secret name.  The route's
        # read-side re-redact kept it off the wire, but the on-disk trail —
        # the copy an operator or an older build reads directly — carried
        # the plaintext, breaking this module's first guarantee.  Going
        # through ``_utf8_text`` keeps classifier and writer agreeing on
        # the key's name for every shape: a str subclass reads via the
        # unbound encode its bombs cannot reach, and a genuinely
        # unrenderable key (a >4300-digit YAML int, whose str() is the
        # digit-cap ValueError) still reads as "" — no name to match, and
        # _jsonable drops it before disk regardless, so "not secret" stays
        # the safe answer there.
        #
        # Unbound ``str.lower`` on the exact-str scrub result, as before:
        # the substring probes below must never run ``in`` against a
        # hostile bound ``lower()``/``__contains__``.
        lowered = str.lower(_utf8_text(key))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False
    if any(allowed in lowered for allowed in _PUBLIC_EXCEPTIONS):
        return False
    return any(hint in lowered for hint in _SECRET_HINTS)


def redact(value: Any, _depth: int = 0) -> Any:
    """Drop secret-looking fields anywhere in a nested structure.

    Recurses into dicts and lists so a password nested inside a body dump is
    caught too.  The *key* decides, not the value: guessing whether a string
    "looks like" a password is unreliable, whereas a field named ``password``
    is unambiguous.

    Secret keys are **removed**, not replaced with a placeholder.  Leaving
    ``{"token": "[redacted]"}`` behind still discloses that a token was part of
    the event, and a placeholder invites a later reader to treat the key as
    safe-by-construction and start logging a "shortened" or "hashed" variant of
    it.  An absent key cannot leak anything.

    Depth-capped like ``_jsonable``: this runs before record()'s swallow-all,
    so a leftover deeply-nested (or self-referential) detail dict used to
    RecursionError out of record() and 500 the request being audited.  The
    subtree past the cap is dropped, never passed through unredacted.
    """
    if _depth > 32:
        return None
    if _isa(value, dict):
        try:
            # Unbound base read, like _jsonable's: redact() runs before
            # record()'s swallow-all, so a dict-subclass ``items()`` bomb in
            # a nested detail used to raise out of the request being audited.
            items = list(dict.items(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
        out = {}
        for k, v in items:
            if _is_secret_key(k):
                continue
            try:
                out[k] = redact(v, _depth + 1)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                # A key whose ``__hash__`` re-raises on the rebuild costs
                # itself, never the sibling fields.
                continue
        return out
    for base in (list, tuple):
        if _isa(value, base):
            try:
                seq = list(base.__iter__(value))
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return []
            return [redact(v, _depth + 1) for v in seq]
    return value


def _trim(path: Path) -> None:
    """Drop the oldest lines once the log exceeds :data:`MAX_LINES`.

    A cheap size check avoids reading and rewriting the file on every
    sign-in while it is still far below the cap.  The keep-set is tailed
    rather than slurped so a trail that grew well past the cap cannot
    pin the login path.  Publish through ``replace_secret_text``: an
    in-place ``write_secret_text`` (O_TRUNC) emptied the history if the
    process died mid-rewrite.
    """
    try:
        if path.stat().st_size <= _TRIM_SOFT_BYTES:
            return
        lines = tail_file_lines(path, MAX_LINES, max_bytes=MAX_LINES * 1024)
    except OSError:
        return
    if not lines:
        return
    try:
        secure_io.replace_secret_text(path, "\n".join(lines) + "\n")
    except OSError:
        pass


def record(event: str, /, **fields: Any) -> dict:
    """Append one audit entry and return what was written.

    The returned dict is the redacted record, so a caller (or a test) can assert
    on exactly what reached disk rather than on what was passed in.
    """
    try:
        # Shape *before* the pop/merge below: redact() keeps the caller's
        # key objects, and ``**kwargs`` admits str-subclass keys, so a
        # hash-shadowing key whose ``__eq__`` raises used to detonate
        # ``extra.pop("ts", ...)`` (and the ``**extra`` merge) and degrade
        # the whole line to the minimal shape.  _jsonable rebuilds every
        # key as an exact str first, so the dict operations here only ever
        # touch plain keys.
        extra = _jsonable(redact(fields))
        if not isinstance(extra, dict):
            extra = {}
        # Callers pass **kwargs; a leftover ``ts=`` / ``event=`` must not
        # clobber the stamp or the event name the trail is queried by.
        extra.pop("ts", None)
        extra.pop("event", None)
        entry = {
            "ts": strftime_now("%Y-%m-%dT%H:%M:%S%z"),
            "event": _utf8_text(event),
            **extra,
        }
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Shaping runs before the swallow-all below, so a poisoned field
        # shape it cannot handle must degrade to a minimal line — losing the
        # detail is acceptable, raising into (or losing) the sign-in being
        # audited is not.  BaseException, not the audit9 ``Exception`` (nor
        # the older (ValueError, TypeError, RecursionError) shortlist): a
        # leftover subclass bomb raises whatever it likes — including a
        # watchdog/timeout-shaped BaseException subclass that sailed past
        # the Exception net straight into the JSON request being audited —
        # and this module's first guarantee is that logging never breaks
        # the request.  Genuine control flow re-raises above.
        entry = None
    if not isinstance(entry, dict):
        # This fallback runs *outside* both nets, so everything here must be
        # total.  _utf8_text used to open with a bare isinstance: an event
        # whose ``__class__`` property raised blew the shaping try above,
        # landed here, and blew _utf8_text *again* — this time straight into
        # the request being audited.  The _isa gates make _utf8_text
        # non-raising for any input.
        entry = {
            "ts": strftime_now("%Y-%m-%dT%H:%M:%S%z"),
            "event": _utf8_text(event),
        }
    try:
        # secure_io creates the file 0600 from the first byte.  A plain
        # open("a") would leave it 0644 under the default umask until a later
        # chmod, and this log names accounts and source addresses.
        #
        # Create-if-absent, not "check then write": the write_secret_text form
        # opens with O_TRUNC, so any false negative from exists() emptied the
        # entire audit trail before appending one line to it.  The same shape in
        # config._bootstrap() destroyed a populated services.yaml on every test
        # run, and here the loss would be the security history specifically.
        #
        # The locks cover append *and* trim: without them, an entry appended
        # by another thread — or another panel process sharing data/ —
        # between _trim's tail-read and its atomic rename is dropped with
        # the swap.
        with _WRITE_LOCK, secure_io.file_lock(AUDIT_PATH):
            secure_io.create_secret_text(AUDIT_PATH, "")
            # O_NOFOLLOW: open("a") would follow a replacement symlink onto
            # another file this process can write.
            secure_io.append_text(
                AUDIT_PATH,
                json.dumps(entry, ensure_ascii=False, allow_nan=False, default=str) + "\n",
                mode=0o600,
            )
            # chmod only when the mode drifted.  The create helper already
            # writes 0600; repeating chmod on every login is a metadata write
            # against an otherwise append-only file.
            if AUDIT_PATH.stat().st_mode & 0o777 != 0o600:
                os.chmod(AUDIT_PATH, 0o600)
            _trim(AUDIT_PATH)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # An unwritable or unencodable log must never turn a valid sign-in
        # into a 500.  BaseException (was Exception, before that OSError/
        # TypeError/ValueError/RecursionError): the write path crosses
        # locks, stat and chmod, and any surprise there belongs to the log,
        # not to the request.  Ctrl-C and interpreter shutdown still
        # propagate above.
        pass
    return entry


def _capped_json_int(text):
    """``json.loads`` parse_int hook: an over-cap digit run drops to None.

    ``int()`` of a >4300-digit number is the digit-cap *ValueError* (not
    JSONDecodeError) for the whole line, so one absurd number in a single
    row (a hand-edited ``attempts``, a restored backup) used to make
    :func:`recent` skip the entire row — silently hiding a sign-in or a
    privileged mutation from the one trail that exists to answer "who did
    this and when".  record() itself never writes such a number
    (``_jsonable`` drops it before disk), so any occurrence is a leftover
    from another writer; loading it as None keeps the rest of the row, the
    same drop terminal_svc.recent_audit applies to the command trail.
    """
    try:
        return int(text)
    except ValueError:
        return None


def recent(limit: int = 100) -> list[dict]:
    """Tail of the audit trail, newest last."""
    # _isa + except-Exception, the terminal_svc.recent_audit clamp verbatim:
    # the route validates its own ``limit``, but this reader does not own its
    # callers, and ``int()`` of a leftover runs the object's own ``__int__``/
    # ``__index__`` — a subclass bomb there raises RuntimeError, which the old
    # (TypeError, ValueError, OverflowError) shortlist let straight out of the
    # one reader whose job is answering "who did this" no matter what.  A
    # bool (or a bool-liar, which _isa fails closed on) reads as the default
    # rather than as 1-row/0-row nonsense.
    if _isa(limit, bool) or limit is None:
        n = 100
    else:
        try:
            n = int(limit)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # ``int()`` runs the object's own ``__int__``/``__index__``; the
            # audit11 clamp stopped at Exception, so a leftover whose slot
            # raised a BaseException subclass still blew out of the one
            # reader whose job is answering "who did this" no matter what.
            n = 100
    n = max(1, min(n, 1000))
    try:
        # Path.exists() re-raises EIO/ESTALE; that used to 500 GET /api/audit/auth.
        if not AUDIT_PATH.exists():
            return []
        # The byte window must match what _trim legitimately keeps
        # (MAX_LINES * 1024), not tail_file_lines' 256 KB default.  With the
        # smaller window, one leftover fat line at the tail put the seek
        # mid-line and the torn-row prefix-drop then discarded every complete
        # row in the window — GET /api/audit/auth answered an empty trail
        # while intact sign-in rows sat on disk right before the fat line.
        # The same undersizing quietly under-filled honest requests: 500 rows
        # of ~1 KB each need ~500 KB, so limit=500 returned ~250.
        lines = tail_file_lines(AUDIT_PATH, n, max_bytes=MAX_LINES * 1024)
    except OSError:
        return []
    out: list[dict] = []
    for raw in lines:
        try:
            parsed = safe_json_loads(raw, parse_int=_capped_json_int)
        except (ValueError, RecursionError):
            continue
        if isinstance(parsed, dict):
            out.append(_jsonable(parsed))
    return out
