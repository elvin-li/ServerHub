"""Multi-channel alert notifications, standard library only.

Six channel types (SMTP email, ntfy, Telegram, Discord, Slack, generic
webhook) plus Home Assistant, which used to be the panel's only outlet.
:func:`dispatch` is the single entry point the alert engine talks to via
``alerts.send_ha_notify``, so every alert call site keeps its historical
shape while gaining per-channel level routing.

Storage split follows the repo convention:

* non-secret channel parameters live in services.yaml under
  ``settings.notify.channels`` (via ``hub.config``);
* secret fields (SMTP passwords, bot tokens, webhook URLs that embed a
  token) live in ``data/notify-credentials.json``, written 0600-at-creation
  through ``hub.secure_io`` — never in services.yaml and never echoed back
  by the API.

The pre-existing ``settings.notify.{enabled, ha_*}`` Home Assistant config
is honoured as an implicit channel: nothing is rewritten on upgrade, the
legacy keys keep working, and the legacy ``include_warn``/``notify_resolve``
switches keep their old meaning for that one channel.

Failure containment: a channel that raises must never take the alert
thread or its sibling channels with it.  Every send is wrapped, failures
are logged and reported in the result dict, and dispatch itself never
raises.
"""
from __future__ import annotations

import errno
import json
import logging
import os
import re
import stat
import threading
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait as futures_wait

from hub import config, secure_io
from hub.errors import api_error, exc_detail, soft_fail
from hub.http_guard import (
    RedirectRefused,
    _ip_from_host,
    is_allowed_webhook_url,
    no_redirect_opener,
    notify_connect_peer,
    pinned_no_redirect_opener,
)
from hub.paths import DATA_DIR
from hub.util import read_text_capped, safe_json_loads

_OPENER = no_redirect_opener()

_log = logging.getLogger("serverhub.notify")

#: Where channel secrets live.  Module-level so tests can point it at a
#: scratch directory, same pattern as service_credentials.INDEX_FILE.
SECRETS_FILE = DATA_DIR / "notify-credentials.json"
#: Leftover multi-MB notify-credentials.json used to OOM GET /api/alerts/channels.
_SECRETS_CAP = 256 * 1024
#: Longest single secret value the API accepts.  Unbounded, one 300KB
#: "webhook URL" pushed the whole file past _SECRETS_CAP: every later read
#: answered {} (all channels lost their has_* flags and their sends), and the
#: next innocent write rewrote the file from that empty snapshot — wiping
#: every sibling channel's secrets.  4KB is far beyond any real token or URL.
_SECRET_VALUE_MAX = 4096
_secrets_lock = threading.Lock()

#: Network budget per channel.  A dead SMTP server or webhook endpoint must
#: not stall the single alert thread for long.  This is per socket operation
#: (SMTP alone does connect/starttls/login/send/quit), so a single dead
#: channel can still take several multiples of it — which is why dispatch()
#: additionally enforces DISPATCH_BUDGET below.
TIMEOUT = 10

#: Wall-clock ceiling for one dispatch() call across *all* channels.  The
#: caller is the single alert thread; before this existed, six channels on a
#: dead network stacked their per-socket-op timeouts serially and one sweep
#: could stall for minutes — delaying down/resolve, SMART and UPS alerts,
#: the last of which is a countdown scenario that cannot wait.  Channels
#: still in flight when the budget expires are reported as failed; their
#: worker threads finish (and are discarded) in the background.
DISPATCH_BUDGET = 15.0

#: Concurrent channel sends per dispatch.  Matches util.MAX_PROBE_WORKERS in
#: spirit: these threads only wait on sockets, so width is about not spawning
#: an unbounded pile, not about CPU.
_DISPATCH_WORKERS = 8

#: Severity order for min_level routing.  "ok" only appears on resolve
#: events, which are gated by notify_resolve instead.
LEVELS = {"info": 0, "ok": 0, "warn": 1, "down": 2}

#: id charset kept URL- and YAML-friendly; it also keys the secrets file.
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

#: Per-type schema: which keys are plain config (services.yaml), which are
#: secrets (credentials file), which must be present to send at all, and
#: which hold URLs that need the SSRF scheme check.
CHANNEL_TYPES: dict[str, dict] = {
    "email": {
        "fields": ("host", "port", "tls", "username", "from_addr", "to"),
        "secrets": ("password",),
        "required": ("host", "to"),
        "secret_required": (),
        "urls": (),
    },
    "ntfy": {
        "fields": ("server", "topic"),
        "secrets": ("token",),
        "required": ("topic",),
        "secret_required": (),
        "urls": ("server",),
    },
    "telegram": {
        "fields": ("chat_id",),
        "secrets": ("bot_token",),
        "required": ("chat_id",),
        "secret_required": ("bot_token",),
        "urls": (),
    },
    "discord": {
        "fields": (),
        "secrets": ("webhook_url",),
        "required": (),
        "secret_required": ("webhook_url",),
        "urls": ("webhook_url",),
    },
    "slack": {
        "fields": (),
        "secrets": ("webhook_url",),
        "required": (),
        "secret_required": ("webhook_url",),
        "urls": ("webhook_url",),
    },
    "webhook": {
        # The whole URL is treated as a secret: services like ntfy.sh topics
        # or bespoke endpoints routinely embed a token in the path.
        "fields": (),
        "secrets": ("url",),
        "required": (),
        "secret_required": ("url",),
        "urls": ("url",),
    },
    "home_assistant": {
        "fields": ("ha_url", "ha_service"),
        "secrets": ("ha_token", "ha_webhook_url"),
        "required": (),
        "secret_required": (),
        "urls": ("ha_url", "ha_webhook_url"),
    },
}

#: The implicit channel synthesised from the legacy settings.notify keys.
#: Not a valid explicit id (see _ID_RE), so it can never collide.
LEGACY_ID = "__legacy_home_assistant__"


def _http_url_ok(url: str) -> bool:
    """http(s) only, and never cloud metadata or link-local.

    Discord/Slack/ntfy are public, so this is not the local-origin guard.
    Scheme-only used to let ``http://169.254.169.254/`` through.

    ``urlsplit`` raises on a torn IPv6 paste (``http://[::1``); that used
    to 500 POST /api/alerts/channels instead of ``notify.bad_url``.
    """
    try:
        return is_allowed_webhook_url(url)
    except ValueError:
        return False


def valid_channel_id(cid) -> bool:
    return isinstance(cid, str) and bool(_ID_RE.fullmatch(cid))


def _id_text(raw) -> str:
    """A channel id coerced to its string form via the str() probe.

    services.yaml is hand-editable, so ``id: 123`` arrives as an *int*.  The
    strict ``isinstance(id, str)`` comparisons this replaces made such a row
    visible in GET /api/alerts/channels yet unreachable by PUT/DELETE/test
    (``123 == "123"`` is False), and save_channel appended a duplicate row
    instead of replacing it.  YAML hex/octal (``id: 0xFF…``) loads uncapped
    (``int(x, 16)`` is exempt from CPython's 4300-digit conversion limit), so
    a bare ``str()`` on it *is* the digit-cap ValueError — that used to 500
    GET /api/alerts/channels and raise out of dispatch() on the alert thread.
    Unrenderable ids coerce to "" and the callers drop the row.
    """
    if isinstance(raw, str):
        return raw
    if raw is None or isinstance(raw, bool):
        return ""
    try:
        return str(raw)
    except ValueError:
        # Past the int->str digit cap the id cannot be rendered, matched,
        # or used as a secrets key — treat the row as having no id at all.
        return ""
    except Exception:
        return ""


# ── configuration ─────────────────────────────────────────────────────────────

def _raw_notify_cfg() -> dict:
    return config.settings_section("notify")


def channels(raw: dict | None = None) -> list[dict]:
    """Explicit channels from services.yaml (legacy HA is not among them)."""
    if raw is None:
        raw = _raw_notify_cfg()
    out = []
    rows = raw.get("channels") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        rows = []
    for ch in rows:
        if not isinstance(ch, dict):
            continue
        # str() probe, not an isinstance gate: a numeric YAML ``id: 123``
        # must behave as "123" everywhere, and a hex over-cap id (whose str()
        # raises the digit-cap ValueError) must drop the row, not the route.
        cid = _id_text(ch.get("id"))
        if not cid:
            continue
        # Membership on a dict hashes the key.  A hand-edit like ``type: [ntfy]``
        # used to TypeError here and 500 GET /api/alerts/channels *and* the
        # alert thread (dispatch claims it never raises).
        ctype = ch.get("type")
        if isinstance(ctype, str) and ctype in CHANNEL_TYPES:
            if ch.get("id") != cid:
                # Copy: rows are the live cfg() cache, never mutated in place.
                ch = {**ch, "id": cid}
            out.append(ch)
    return out


def get_channel(cid: str) -> dict | None:
    for ch in channels():
        if ch.get("id") == cid:
            return ch
    return None


def save_channel(ch: dict) -> dict:
    """Upsert one channel into settings.notify.channels (cross-process safe)."""
    def apply(data: dict) -> None:
        settings = data.get("settings")
        if not isinstance(settings, dict):
            settings = {}
            data["settings"] = settings
        notify = settings.get("notify")
        if not isinstance(notify, dict):
            notify = {}
            settings["notify"] = notify
        chans = notify.get("channels")
        if not isinstance(chans, list):
            chans = []
            notify["channels"] = chans
        for i, existing in enumerate(chans):
            # _id_text, not ``==``: a numeric YAML ``id: 123`` used to miss
            # the str "123" here and the upsert appended a duplicate row.
            if isinstance(existing, dict) and _id_text(existing.get("id")) == ch["id"]:
                chans[i] = ch
                return
        chans.append(ch)

    config.mutate(apply)
    return ch


def delete_channel(cid: str) -> bool:
    removed = []

    def apply(data: dict) -> None:
        settings = data.get("settings")
        if not isinstance(settings, dict):
            return
        notify = settings.get("notify")
        if not isinstance(notify, dict):
            return
        chans = notify.get("channels")
        if not isinstance(chans, list):
            return
        # _id_text, not ``==``: a numeric YAML ``id: 123`` was listed but
        # could never be deleted (``123 == "123"`` is False → 404 forever).
        kept = [c for c in chans if not (isinstance(c, dict) and _id_text(c.get("id")) == cid)]
        if len(kept) != len(chans):
            removed.append(cid)
        notify["channels"] = kept

    config.mutate(apply)
    if removed:
        drop_channel_secrets(cid)
    return bool(removed)


def _min_rank(ch: dict) -> int:
    # _utf8_text, not bare str(): YAML hex/octal loads uncapped, so a
    # hand-edited ``min_level: 0xFF…`` arrives already-int and ``str()`` on it
    # is the digit-cap ValueError.  That raised out of _channel_wants inside
    # dispatch() — killing the alert thread's sweep despite the never-raises
    # contract — and out of effective_settings, whose caller fell back to the
    # raw legacy flags and silently stopped notifying for every explicit
    # channel.  An unrenderable level falls back to the "warn" default.
    return LEVELS.get(_utf8_text(ch.get("min_level") or "warn"), LEVELS["warn"])


def effective_settings(raw: dict) -> dict:
    """The view alerts.notify_settings() hands to the alert call sites.

    The call sites in hub/alerts.py gate on the *global* ``enabled`` /
    ``include_warn`` / ``notify_resolve`` flags before ever reaching
    dispatch().  With explicit channels those flags become "does any channel
    want this at all"; the per-channel filter inside dispatch() then does the
    precise routing.  With no enabled explicit channel the raw dict is
    returned untouched, so a pure-legacy install behaves exactly as before.
    """
    enabled = [c for c in channels(raw) if c.get("enabled", True)]
    if not enabled:
        return raw
    out = dict(raw)
    out["enabled"] = True
    if any(_min_rank(c) <= LEVELS["warn"] for c in enabled):
        out["include_warn"] = True
    if any(c.get("notify_resolve", True) for c in enabled):
        out["notify_resolve"] = True
    return out


def _legacy_target(raw: dict) -> tuple[dict, dict] | None:
    """The legacy HA settings as an implicit (channel, secrets) pair.

    Returns None when the legacy config has nothing to send to, so installs
    that never configured Home Assistant get no phantom channel.
    """
    if not (raw.get("ha_webhook_url") or raw.get("webhook_url") or raw.get("ha_token")):
        return None
    ch = {
        "id": LEGACY_ID,
        "type": "home_assistant",
        "name": "Home Assistant",
        "enabled": bool(raw.get("enabled")),
        # include_warn defaults to True here.  The stricter per-callsite
        # defaults (service warns need an explicit include_warn) are already
        # enforced by the gates in hub/alerts.py before dispatch() runs.
        "min_level": "warn" if raw.get("include_warn", True) else "down",
        "notify_resolve": raw.get("notify_resolve", True),
        "ha_url": raw.get("ha_url"),
        "ha_service": raw.get("ha_service"),
    }
    secrets = {
        "ha_token": raw.get("ha_token") or "",
        "ha_webhook_url": raw.get("ha_webhook_url") or raw.get("webhook_url") or "",
    }
    return ch, secrets


# ── secret storage ────────────────────────────────────────────────────────────

def _drop_leftover_nonfile(path) -> None:
    """Unlink a leftover directory/socket occupying notify-credentials.json."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError:
        return
    if stat.S_ISREG(st.st_mode):
        return
    try:
        if stat.S_ISDIR(st.st_mode):
            os.rmdir(path)
        else:
            os.unlink(path)
    except OSError:
        pass


def _capped_json_int(text):
    """``json.loads`` parse_int hook: an over-cap digit run drops to None.

    ``int()`` of a >4300-digit number is the digit-cap *ValueError* (not
    JSONDecodeError) for the whole document: one poisoned number used to make
    :func:`_load_secrets` return ``{}``, and the very next write — any channel
    edit, delete, or secret merge — rewrote notify-credentials.json from that
    empty snapshot, silently wiping every sibling channel's secrets.  Dropping
    just the number keeps the file, same as smart_test_svc's history hook.
    """
    try:
        return int(text)
    except ValueError:
        return None


def _load_secrets() -> dict[str, dict]:
    try:
        raw = safe_json_loads(
            read_text_capped(SECRETS_FILE, _SECRETS_CAP, encoding="utf-8"),
            parse_int=_capped_json_int,
        )
    except (OSError, ValueError, RecursionError):
        # ValueError covers json.JSONDecodeError *and* UnicodeDecodeError
        # (torn write leaving non-UTF-8 bytes); the alert sweep reads this.
        # RecursionError: a leftover deeply-nested document is not ValueError.
        return {}
    if not isinstance(raw, dict):
        return {}
    # Scrub keys (and values) *on load*, before they become lookup keys.
    # ``json.loads`` happily produces a lone-surrogate KEY from an escaped
    # ``"\\ud800…"`` in the file; _write_secrets scrubbed only at write time,
    # so the in-memory maps that set/drop/channel_secrets index — and hand to
    # the senders on the alert thread — still carried surrogates that no
    # UTF-8 encode downstream (urllib headers, SMTP login) can survive.
    cleaned = _json_safe(raw)
    return cleaned if isinstance(cleaned, dict) else {}


def _require_secrets_readable() -> None:
    """Refuse a secrets *write* while the stored file cannot be read back.

    ``set_channel_secrets`` merges onto whatever :func:`_load_secrets`
    returned.  When the file *exists* but is unreadable — grown past
    ``_SECRETS_CAP`` (OSError EFBIG), a dying mount (EIO), lost permissions
    (EACCES), a torn write leaving non-UTF-8 bytes, or corrupt JSON — that
    snapshot is ``{}``, and the merge used to rewrite the file from it:
    one innocent channel edit silently wiped every sibling channel's
    stored secrets.  The rows are still on disk and recoverable by hand,
    so the write is refused with a coded 503 instead.

    A *missing* file and a leftover non-regular node (FIFO / directory /
    socket, surfaced as OSError EINVAL by ``read_text_capped``) hold no
    sibling rows to preserve: those still start from ``{}``, and
    ``_write_secrets`` replaces the leftover node as before.  The read
    paths (``channel_secrets``, ``dispatch``) keep degrading to ``{}`` —
    they can never destroy anything.
    """
    try:
        text = read_text_capped(SECRETS_FILE, _SECRETS_CAP, encoding="utf-8")
    except FileNotFoundError:
        return
    except UnicodeDecodeError:
        raise api_error("notify.secrets_unreadable")
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.EINVAL:
            return
        raise api_error("notify.secrets_unreadable")
    try:
        safe_json_loads(text, parse_int=_capped_json_int)
    except (ValueError, RecursionError):
        raise api_error("notify.secrets_unreadable")


def _secret_map(data: dict, cid: str) -> dict:
    raw = data.get(cid)
    return dict(raw) if isinstance(raw, dict) else {}


def channel_secrets(cid: str) -> dict:
    with _secrets_lock:
        return _secret_map(_load_secrets(), cid)


def _has_control_chars(text: str) -> bool:
    # Same rule as rsync_svc._has_control_chars: C0 controls and DEL.
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in text)


def set_channel_secrets(cid: str, values: dict) -> None:
    """Merge secret values for one channel.  Empty string deletes a field.

    ``None`` means "leave unchanged", so the API can accept a partial edit
    without ever having seen (or re-sent) the current secret.

    Control characters are refused at this boundary rather than at send time:
    a telegram token pasted with a trailing ``\\n`` makes urllib raise with the
    full request URL — token included — in the exception text, which then
    lands verbatim in a 0644 error log.  No legitimate secret contains one.
    """
    # file_lock as well as _secrets_lock: the two panel processes sharing
    # data/ (packaged .app + LaunchAgent) both edit this file, and a write
    # from a stale snapshot used to erase the other process's change — or
    # resurrect credentials a concurrent delete had just removed.
    with _secrets_lock, secure_io.file_lock(SECRETS_FILE):
        _require_secrets_readable()
        data = _load_secrets()
        cur = _secret_map(data, cid)
        for key, value in (values or {}).items():
            if value is None:
                continue
            try:
                value = str(value)
            except RecursionError:
                raise api_error("notify.secret_control_chars", field="value")
            except Exception:
                continue
            if _has_control_chars(value):
                raise api_error("notify.secret_control_chars", field=str(key))
            if len(value) > _SECRET_VALUE_MAX:
                # An unbounded value used to push the whole file past the
                # read cap — see _SECRET_VALUE_MAX.  Refused before anything
                # lands on disk, so the siblings stay readable.
                raise api_error("notify.value_too_long",
                                field=str(key), max=_SECRET_VALUE_MAX)
            if value == "":
                cur.pop(key, None)
            else:
                cur[key] = value
        if cur:
            data[cid] = cur
        else:
            data.pop(cid, None)
        # Never persist a document the loader will refuse to read back:
        # a merged file past _SECRETS_CAP makes every later _load_secrets
        # answer {} — all channels lose their secrets in one write.  The
        # probe mirrors _write_secrets' exact dump (indent included);
        # read_text_capped compares characters, so len() is the right unit.
        try:
            payload = json.dumps(_json_safe(data), ensure_ascii=False,
                                 indent=2, allow_nan=False)
        except (TypeError, ValueError, RecursionError):
            payload = ""
        if len(payload) + 1 > _SECRETS_CAP:
            raise api_error("notify.secrets_too_large")
        _write_secrets(data)


def drop_channel_secrets(cid: str) -> None:
    with _secrets_lock, secure_io.file_lock(SECRETS_FILE):
        data = _load_secrets()
        if cid in data:
            del data[cid]
            _write_secrets(data)


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    try:
        text = str(value)
    except RecursionError:
        # Pathological leftover ``__str__`` used to 500 POST /api/alerts/test
        # via dispatch ``str(exc)`` after the sender was already wrapped.
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    return text.encode("utf-8", "replace").decode("utf-8")


def _json_safe(value, depth: int = 0):
    """JSON-encodable form of a leftover YAML/JSON channel field.

    Hand-edited ``port: .inf``, ``name: 2026-08-19`` (a YAML date), a
    ``!!set`` recipient list, or a ``!!binary`` topic each used to 500
    GET /api/alerts/channels under Starlette's allow_nan=False encoder.
    A leftover ``\\ud800`` in ``name`` / ``id`` / a nested key still 500'd
    the same route (and POST /api/alerts/test via dispatch results).
    """
    if depth > 32:
        return None
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            try:
                key = _utf8_text(k)
            except Exception:
                continue
            out[key] = _json_safe(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(v, depth + 1) for v in value]
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/alerts/channels.
            return _json_safe(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _write_secrets(data: dict) -> None:
    """Persist the credentials file without rewriting leftover Infinity.

    ``json.dumps`` without ``allow_nan=False`` used to copy ``1e400`` from a
    sibling channel back onto disk, and PUT /api/alerts/channels 500'd once
    the encoder refused NaN.
    """
    cleaned = _json_safe(data)
    if not isinstance(cleaned, dict):
        cleaned = {}
    _drop_leftover_nonfile(SECRETS_FILE)
    try:
        secure_io.replace_secret_text(
            SECRETS_FILE,
            json.dumps(cleaned, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        )
    except (OSError, TypeError, ValueError, RecursionError):
        # Leftover directory / EIO must not 500 PUT /api/alerts/channels.
        # RecursionError: leftover nested secrets after _json_safe is not OSError.
        pass


def public_channel(ch: dict) -> dict:
    """API-safe view: config fields verbatim, secrets as has_* booleans only."""
    spec = CHANNEL_TYPES.get(str(ch.get("type"))) or {"fields": (), "secrets": ()}
    # _id_text, not bare str(): a hex-YAML over-cap id made str() itself raise
    # the digit-cap ValueError and 500 GET /api/alerts/channels right here.
    raw_id = _id_text(ch.get("id"))
    stored = channel_secrets(raw_id)
    cid = _json_safe(raw_id if raw_id else ch.get("id"))
    name = _json_safe(ch.get("name"))
    if not (isinstance(name, str) and name.strip()):
        name = cid if isinstance(cid, str) and cid else cid
    out = {
        "id": cid,
        "type": _json_safe(ch.get("type")),
        "name": name,
        "enabled": bool(ch.get("enabled", True)),
        # _utf8_text directly, not around a bare str(): a hex-YAML over-cap
        # ``min_level`` made the inner str() raise the digit-cap ValueError
        # before _utf8_text ever ran, 500ing GET /api/alerts/channels.
        "min_level": _utf8_text(ch.get("min_level") or "warn") or "warn",
        "notify_resolve": bool(ch.get("notify_resolve", True)),
        "config": {},
        "has": {s: bool(stored.get(s)) for s in spec["secrets"]},
    }
    for field in spec["fields"]:
        value = _json_safe(ch.get(field))
        if value is not None:
            out["config"][field] = value
    return out


# ── senders ───────────────────────────────────────────────────────────────────

def _open_request(req, timeout, dest_ip=None):
    """Open *req*, pinning TCP to *dest_ip* when the send-path resolved one.

    Tests patch this instead of ``_OPENER.open`` so a hostname URL never
    triggers a second ``getaddrinfo`` inside urllib.
    """
    opener = pinned_no_redirect_opener(dest_ip) if dest_ip else _OPENER
    return opener.open(req, timeout=timeout)


def _smtp_tls_context():
    """Verify the SMTP peer.  stdlib starttls/SMTP_SSL default to CERT_NONE."""
    import ssl

    return ssl.create_default_context()


def _smtp_connect(host: str, port: int, timeout: float, *, use_ssl=False, dest_ip=None):
    """Build an SMTP client whose TCP peer is *dest_ip* when given.

    ``EHLO`` / STARTTLS / TLS SNI stay on *host*.  Constructing without a
    host first is what lets us swap ``_get_socket`` before the connect;
    callers that used ``SMTP(host, port)`` resolved twice.
    """
    import smtplib
    import socket

    ctor = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    ssl_ctx = _smtp_tls_context() if use_ssl else None
    if not dest_ip:
        if use_ssl:
            return ctor(host, port, timeout=timeout, context=ssl_ctx)
        return ctor(host, port, timeout=timeout)
    smtp = ctor(timeout=timeout, context=ssl_ctx) if use_ssl else ctor(timeout=timeout)
    smtp._host = host
    ctx = ssl_ctx or getattr(smtp, "context", None)

    def _get_socket(_sock_host, sock_port, sock_timeout):
        raw = socket.create_connection((dest_ip, sock_port), sock_timeout)
        if use_ssl and ctx is not None:
            return ctx.wrap_socket(raw, server_hostname=host)
        return raw

    smtp._get_socket = _get_socket
    smtp.connect(host, port)
    return smtp


def _post(url: str, payload: dict, headers: dict | None = None) -> dict:
    if not is_allowed_webhook_url(url, resolve=False):
        return soft_fail("notify.bad_url", field="url")
    try:
        host = (urlsplit(url).hostname or "").strip("[]")
    except ValueError:
        return soft_fail("notify.bad_url", field="url")
    try:
        # Leftover ``level: .inf`` / a YAML date in the payload used to raise
        # out of dumps (or send Infinity) before the socket was opened.
        # RecursionError: leftover deeply-nested title/body is not ValueError;
        # POST /api/alerts/test and the alert sweep used to 500.
        body = json.dumps(_json_safe(payload), default=str, allow_nan=False).encode()
    except (TypeError, ValueError, OverflowError, RecursionError) as e:
        return {"ok": False, "message": exc_detail(e)}
    # One DNS lookup.  Connecting via the hostname would resolve again
    # and could land on a metadata A record that was not in this answer.
    peer = notify_connect_peer(host) if host else None
    if not peer:
        return soft_fail("notify.bad_url", field="url")
    dest_ip = peer if _ip_from_host(peer) is not None else None
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with _open_request(req, TIMEOUT, dest_ip=dest_ip) as r:
            return {
                "ok": True,
                "status": r.status,
                "body": r.read(200).decode(errors="replace"),
            }
    except RedirectRefused as e:
        return {"ok": False, "message": exc_detail(e)}
    except urllib.error.HTTPError as e:
        try:
            detail = e.read(200).decode(errors="replace")
        finally:
            try:
                e.close()
            except Exception:
                pass
        return {"ok": False, "message": f"HTTP {e.code}: {detail}"}
    except Exception as e:
        return {"ok": False, "message": exc_detail(e)}


def _recipients(raw) -> list[str]:
    if isinstance(raw, str):
        return [a.strip() for a in re.split(r"[,;\s]+", raw) if a.strip()]
    if isinstance(raw, list):
        return [str(a).strip() for a in raw if str(a).strip()]
    return []


def _send_email(ch: dict, secrets: dict, title: str, message: str, **_) -> dict:
    import socket
    from email.message import EmailMessage

    host = str(ch.get("host") or "").strip()
    to = _recipients(ch.get("to"))
    if not host or not to:
        return soft_fail("notify.missing_field", field="host" if not host else "to")
    peer = notify_connect_peer(host)
    if not peer:
        return soft_fail("notify.bad_url", field="host")
    dest_ip = peer if _ip_from_host(peer) is not None and peer != host.lower().strip("[]") else None
    mode = str(ch.get("tls") or "starttls").lower()
    try:
        port = int(ch.get("port") or 0)
    except (TypeError, ValueError, OverflowError):
        port = 0
    username = str(ch.get("username") or "").strip()
    password = str(secrets.get("password") or "")
    sender = str(ch.get("from_addr") or "").strip() or username or f"serverhub@{socket.gethostname()}"

    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg.set_content(message)

    try:
        if mode == "ssl":
            smtp = _smtp_connect(host, port or 465, TIMEOUT, use_ssl=True, dest_ip=dest_ip)
        else:
            smtp = _smtp_connect(host, port or 587, TIMEOUT, use_ssl=False, dest_ip=dest_ip)
        try:
            if mode == "starttls":
                smtp.starttls(context=_smtp_tls_context())
            if username and password:
                smtp.login(username, password)
            smtp.send_message(msg)
        finally:
            try:
                smtp.quit()
            except Exception:
                pass
    except Exception as e:
        return {"ok": False, "message": exc_detail(e)}
    return {"ok": True, "message": f"sent to {len(to)} recipient(s)"}


#: alert level -> ntfy priority (1 min … 5 urgent).
_NTFY_PRIORITY = {"down": 5, "warn": 4}


def _send_ntfy(ch: dict, secrets: dict, title: str, message: str, *, level=None, **_) -> dict:
    server = str(ch.get("server") or "https://ntfy.sh").strip().rstrip("/")
    topic = str(ch.get("topic") or "").strip()
    if not topic:
        return soft_fail("notify.missing_field", field="topic")
    headers = {}
    token = str(secrets.get("token") or "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    # JSON publish to the server root: unlike per-topic PUTs with X-Title
    # headers, this keeps non-latin1 titles intact (urllib rejects them in
    # headers) and needs no escaping.
    return _post(server + "/", {
        "topic": topic,
        "title": title,
        "message": message,
        "priority": _NTFY_PRIORITY.get(str(level or ""), 3),
    }, headers)


def _send_telegram(ch: dict, secrets: dict, title: str, message: str, **_) -> dict:
    token = str(secrets.get("bot_token") or "").strip()
    chat_id = str(ch.get("chat_id") or "").strip()
    if not token or not chat_id:
        return soft_fail("notify.missing_field", field="bot_token" if not token else "chat_id")
    return _post(f"https://api.telegram.org/bot{token}/sendMessage", {
        "chat_id": chat_id,
        "text": f"{title}\n{message}"[:4000],
    })


def _send_discord(ch: dict, secrets: dict, title: str, message: str, **_) -> dict:
    url = str(secrets.get("webhook_url") or "").strip()
    if not url:
        return soft_fail("notify.missing_field", field="webhook_url")
    # Discord caps content at 2000 characters.
    return _post(url, {"content": f"**{title}**\n{message}"[:1900]})


def _send_slack(ch: dict, secrets: dict, title: str, message: str, **_) -> dict:
    url = str(secrets.get("webhook_url") or "").strip()
    if not url:
        return soft_fail("notify.missing_field", field="webhook_url")
    return _post(url, {"text": f"*{title}*\n{message}"})


def _send_webhook(ch: dict, secrets: dict, title: str, message: str, *, level=None, event=None, **_) -> dict:
    url = str(secrets.get("url") or "").strip()
    if not url:
        return soft_fail("notify.missing_field", field="url")
    # Superset of the historical HA-webhook payload, so anything that parsed
    # the old {title, message, text} keeps working when pointed at this type.
    return _post(url, {
        "title": title,
        "message": message,
        "text": f"{title}: {message}",
        "level": level,
        "event": event,
    })


def _send_home_assistant(ch: dict, secrets: dict, title: str, message: str, **_) -> dict:
    """The pre-channels send_ha_notify body, fed from channel config."""
    url = str(secrets.get("ha_webhook_url") or "").strip()
    if url:
        return _post(url, {
            "title": title,
            "message": message,
            "text": f"{title}: {message}",
        })
    token = str(secrets.get("ha_token") or "")
    if not token:
        return soft_fail("notify.missing_field", field="ha_webhook_url")
    base = str(ch.get("ha_url") or "http://localhost:8123").rstrip("/")
    if not _http_url_ok(base):
        return soft_fail("notify.bad_url", field="ha_url")
    service = str(ch.get("ha_service") or "notify.notify")
    parts = service.split(".", 1)
    domain = parts[0] if len(parts) == 2 else "notify"
    svc = parts[1] if len(parts) == 2 else parts[0]
    return _post(
        f"{base}/api/services/{domain}/{svc}",
        {"title": title, "message": message},
        {"Authorization": f"Bearer {token}"},
    )


_SENDERS = {
    "email": _send_email,
    "ntfy": _send_ntfy,
    "telegram": _send_telegram,
    "discord": _send_discord,
    "slack": _send_slack,
    "webhook": _send_webhook,
    "home_assistant": _send_home_assistant,
}


# ── dispatch ──────────────────────────────────────────────────────────────────

def _channel_wants(ch: dict, level, event) -> bool:
    if not ch.get("enabled", True):
        return False
    if event == "test":
        return True
    if event == "resolved":
        return bool(ch.get("notify_resolve", True))
    rank = LEVELS.get(str(level or "down"), LEVELS["down"])
    return rank >= _min_rank(ch)


def _send_via(sender, ch: dict, secrets: dict, title: str, message: str,
              *, level, event) -> dict:
    """One channel's send, shaped for a worker thread: never raises."""
    try:
        res = sender(ch, secrets, title, message, level=level, event=event)
    except Exception as e:  # a broken channel must not sink the others
        res = {"ok": False, "message": _utf8_text(e)}
    if not isinstance(res, dict):
        # A sender that returns None/list used to AttributeError *outside* the
        # try, so the "never raises" contract only covered exceptions, not types.
        res = {"ok": False, "message": "invalid sender response"}
    # Leftover YAML ``id: "\ud800"`` / a sender returning inf/bytes/a date
    # used to 500 POST /api/alerts/test under Starlette's UTF-8 encoder.
    return _json_safe({
        "id": _id_text(ch.get("id")),
        "type": ch.get("type"),
        "ok": bool(res.get("ok")),
        "message": res.get("message") or res.get("body") or "",
    })


def dispatch(title: str, message: str, *, level=None, event=None, channel_id: str | None = None) -> dict:
    """Send one notification through every channel that wants it.

    Never raises: this runs on the alert engine's single thread, and a dead
    alert thread is silent — the worst failure mode an alerting system has.
    A channel targeted explicitly by ``channel_id`` (the per-channel test
    button) bypasses the enabled/level filter; that is the point of testing.

    Channels send **concurrently**, and the whole call is bounded by
    :data:`DISPATCH_BUDGET`.  Serial sends multiplied every dead endpoint's
    socket timeouts into minutes of alert-thread stall; results keep the
    channel enumeration order regardless of completion order.
    """
    try:
        raw = _raw_notify_cfg()
    except Exception:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    targets: list[tuple[dict, dict]] = []
    legacy = _legacy_target(raw)
    if legacy:
        targets.append(legacy)
    for ch in channels(raw):
        # channels() already coerced ids via the str() probe; _id_text here
        # keeps the never-raises contract even for a caller that hands
        # dispatch a raw over-cap hex id (str() alone was the digit-cap
        # ValueError that killed the alert thread's sweep).
        targets.append((ch, channel_secrets(_id_text(ch.get("id")))))

    wanted: list[tuple] = []
    for ch, secrets in targets:
        cid = _id_text(ch.get("id"))
        if channel_id is not None:
            if cid != channel_id:
                continue
        elif not _channel_wants(ch, level, event):
            continue
        # Resolved here, on the caller's thread, so a test's patch of
        # _SENDERS cannot lapse before an abandoned worker looks it up.
        sender = _SENDERS.get(str(ch.get("type")))
        if sender is None:
            continue
        wanted.append((ch, secrets, sender))

    results = []
    if wanted:
        pool = ThreadPoolExecutor(
            max_workers=min(len(wanted), _DISPATCH_WORKERS),
            thread_name_prefix="notify-send",
        )
        futures = [
            pool.submit(_send_via, sender, ch, secrets, title, message,
                        level=level, event=event)
            for ch, secrets, sender in wanted
        ]
        futures_wait(futures, timeout=DISPATCH_BUDGET)
        # wait=False: a channel that outlived the budget keeps its thread
        # until its own socket timeouts fire, but nobody blocks on it.
        pool.shutdown(wait=False)
        for (ch, _secrets, _sender), fut in zip(wanted, futures):
            if fut.done():
                try:
                    results.append(fut.result())
                except Exception as e:
                    # Same leftover ``id: "\ud800"`` as _send_via: the
                    # timeout/exception path used to skip _json_safe and
                    # 500 POST /api/alerts/test under Starlette's UTF-8 encoder.
                    results.append(_json_safe({
                        "id": _id_text(ch.get("id")),
                        "type": ch.get("type"),
                        "ok": False,
                        "message": _utf8_text(e),
                    }))
            else:
                results.append(_json_safe({
                    "id": _id_text(ch.get("id")),
                    "type": ch.get("type"),
                    "ok": False,
                    "message": f"timed out ({DISPATCH_BUDGET:.0f}s dispatch budget exhausted)",
                }))
        for r in results:
            if isinstance(r, dict) and not r.get("ok"):
                _log.warning(
                    "notify channel %s (%s) failed: %s",
                    r.get("id"), r.get("type"), r.get("message"),
                )

    if not results:
        out = soft_fail("notify.no_match")
        out["results"] = []
        return out
    failed = [r for r in results if isinstance(r, dict) and not r.get("ok")]
    return _json_safe({
        "ok": not failed,
        "sent": len(results) - len(failed),
        "failed": len(failed),
        "message": "; ".join(f"{r.get('id') or r.get('type')}: {r.get('message')}" for r in failed)[:400]
        if failed else f"sent via {len(results)} channel(s)",
        "results": results,
    })
