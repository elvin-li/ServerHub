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

import json
import logging
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait as futures_wait

from hub import config, secure_io
from hub.errors import api_error, soft_fail
from hub.http_guard import RedirectRefused, no_redirect_opener
from hub.paths import DATA_DIR

_OPENER = no_redirect_opener()

_log = logging.getLogger("serverhub.notify")

#: Where channel secrets live.  Module-level so tests can point it at a
#: scratch directory, same pattern as service_credentials.INDEX_FILE.
SECRETS_FILE = DATA_DIR / "notify-credentials.json"
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
    """Same rule as alerts._http_url_ok: only http(s) may leave the box.

    Duplicated rather than imported so this module never has to import the
    (much heavier) alert engine.
    """
    try:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
    except ValueError:
        return False
    return scheme in ("http", "https")


def valid_channel_id(cid) -> bool:
    return isinstance(cid, str) and bool(_ID_RE.fullmatch(cid))


# ── configuration ─────────────────────────────────────────────────────────────

def _raw_notify_cfg() -> dict:
    return (config.cfg().get("settings") or {}).get("notify") or {}


def channels(raw: dict | None = None) -> list[dict]:
    """Explicit channels from services.yaml (legacy HA is not among them)."""
    if raw is None:
        raw = _raw_notify_cfg()
    out = []
    for ch in raw.get("channels") or []:
        if isinstance(ch, dict) and ch.get("id") and ch.get("type") in CHANNEL_TYPES:
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
        notify = data.setdefault("settings", {}).setdefault("notify", {})
        chans = notify.setdefault("channels", [])
        for i, existing in enumerate(chans):
            if isinstance(existing, dict) and existing.get("id") == ch["id"]:
                chans[i] = ch
                return
        chans.append(ch)

    config.mutate(apply)
    return ch


def delete_channel(cid: str) -> bool:
    removed = []

    def apply(data: dict) -> None:
        notify = data.setdefault("settings", {}).setdefault("notify", {})
        chans = notify.get("channels") or []
        kept = [c for c in chans if not (isinstance(c, dict) and c.get("id") == cid)]
        if len(kept) != len(chans):
            removed.append(cid)
        notify["channels"] = kept

    config.mutate(apply)
    if removed:
        drop_channel_secrets(cid)
    return bool(removed)


def _min_rank(ch: dict) -> int:
    return LEVELS.get(str(ch.get("min_level") or "warn"), LEVELS["warn"])


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

def _load_secrets() -> dict[str, dict]:
    try:
        raw = json.loads(SECRETS_FILE.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        # ValueError covers json.JSONDecodeError *and* UnicodeDecodeError
        # (torn write leaving non-UTF-8 bytes); the alert sweep reads this.
        return {}


def channel_secrets(cid: str) -> dict:
    with _secrets_lock:
        return dict(_load_secrets().get(cid) or {})


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
    with _secrets_lock:
        data = _load_secrets()
        cur = dict(data.get(cid) or {})
        for key, value in (values or {}).items():
            if value is None:
                continue
            value = str(value)
            if _has_control_chars(value):
                raise api_error("notify.secret_control_chars", field=str(key))
            if value == "":
                cur.pop(key, None)
            else:
                cur[key] = value
        if cur:
            data[cid] = cur
        else:
            data.pop(cid, None)
        secure_io.replace_secret_text(
            SECRETS_FILE, json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        )


def drop_channel_secrets(cid: str) -> None:
    with _secrets_lock:
        data = _load_secrets()
        if cid in data:
            del data[cid]
            secure_io.replace_secret_text(
                SECRETS_FILE, json.dumps(data, ensure_ascii=False, indent=2) + "\n"
            )


def public_channel(ch: dict) -> dict:
    """API-safe view: config fields verbatim, secrets as has_* booleans only."""
    spec = CHANNEL_TYPES.get(str(ch.get("type"))) or {"fields": (), "secrets": ()}
    stored = channel_secrets(str(ch.get("id") or ""))
    out = {
        "id": ch.get("id"),
        "type": ch.get("type"),
        "name": ch.get("name") or ch.get("id"),
        "enabled": bool(ch.get("enabled", True)),
        "min_level": str(ch.get("min_level") or "warn"),
        "notify_resolve": bool(ch.get("notify_resolve", True)),
        "config": {f: ch.get(f) for f in spec["fields"] if ch.get(f) is not None},
        "has": {s: bool(stored.get(s)) for s in spec["secrets"]},
    }
    return out


# ── senders ───────────────────────────────────────────────────────────────────

def _post(url: str, payload: dict, headers: dict | None = None) -> dict:
    if not _http_url_ok(url):
        return soft_fail("notify.bad_url", field="url")
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with _OPENER.open(req, timeout=TIMEOUT) as r:
            return {
                "ok": True,
                "status": r.status,
                "body": r.read()[:200].decode(errors="replace"),
            }
    except RedirectRefused as e:
        return {"ok": False, "message": str(e)}
    except urllib.error.HTTPError as e:
        detail = e.read()[:200].decode(errors="replace")
        return {"ok": False, "message": f"HTTP {e.code}: {detail}"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _recipients(raw) -> list[str]:
    if isinstance(raw, str):
        return [a.strip() for a in re.split(r"[,;\s]+", raw) if a.strip()]
    if isinstance(raw, list):
        return [str(a).strip() for a in raw if str(a).strip()]
    return []


def _send_email(ch: dict, secrets: dict, title: str, message: str, **_) -> dict:
    import smtplib
    import socket
    from email.message import EmailMessage

    host = str(ch.get("host") or "").strip()
    to = _recipients(ch.get("to"))
    if not host or not to:
        return soft_fail("notify.missing_field", field="host" if not host else "to")
    mode = str(ch.get("tls") or "starttls").lower()
    try:
        port = int(ch.get("port") or 0)
    except (TypeError, ValueError):
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
            smtp = smtplib.SMTP_SSL(host, port or 465, timeout=TIMEOUT)
        else:
            smtp = smtplib.SMTP(host, port or 587, timeout=TIMEOUT)
        try:
            if mode == "starttls":
                smtp.starttls()
            if username and password:
                smtp.login(username, password)
            smtp.send_message(msg)
        finally:
            try:
                smtp.quit()
            except Exception:
                pass
    except Exception as e:
        return {"ok": False, "message": str(e)}
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
        res = {"ok": False, "message": str(e)}
    return {
        "id": str(ch.get("id") or ""),
        "type": ch.get("type"),
        "ok": bool(res.get("ok")),
        "message": res.get("message") or res.get("body") or "",
    }


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
    targets: list[tuple[dict, dict]] = []
    legacy = _legacy_target(raw)
    if legacy:
        targets.append(legacy)
    for ch in channels(raw):
        targets.append((ch, channel_secrets(str(ch["id"]))))

    wanted: list[tuple] = []
    for ch, secrets in targets:
        cid = str(ch.get("id") or "")
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
                results.append(fut.result())
            else:
                results.append({
                    "id": str(ch.get("id") or ""),
                    "type": ch.get("type"),
                    "ok": False,
                    "message": f"timed out ({DISPATCH_BUDGET:.0f}s dispatch budget exhausted)",
                })
        for r in results:
            if not r["ok"]:
                _log.warning(
                    "notify channel %s (%s) failed: %s",
                    r["id"], r["type"], r["message"],
                )

    if not results:
        out = soft_fail("notify.no_match")
        out["results"] = []
        return out
    failed = [r for r in results if not r["ok"]]
    return {
        "ok": not failed,
        "sent": len(results) - len(failed),
        "failed": len(failed),
        "message": "; ".join(f"{r['id'] or r['type']}: {r['message']}" for r in failed)[:400]
        if failed else f"sent via {len(results)} channel(s)",
        "results": results,
    }
