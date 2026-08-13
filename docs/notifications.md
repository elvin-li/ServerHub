# Notifications

ServerHub's alert engine can deliver notifications through multiple channels
simultaneously: **SMTP email, ntfy, Telegram, Discord, Slack, a generic
webhook**, and **Home Assistant** (the panel's original outlet, kept for
compatibility). Channels are managed under **Settings → Notifications**, each
with its own severity filter and test button.

Everything is implemented on the Python standard library — configuring a
channel never installs a dependency.

## How alerts flow

A background alert thread sweeps the system every `alert_interval` seconds
(default 90). Each sweep checks:

| Check | Fires on | Level |
|---|---|---|
| Service state | a managed service transitions to `down` / `warn`; recovery emits a `resolved` event | `down` / `warn` |
| Resource thresholds | CPU / memory / disk % above `settings.thresholds` (re-announced at most once per `cooldown_sec`, default 1800) | `warn` |
| SMART health | disk health attribute trips (temperature, wear, spare capacity…), edge-triggered per disk serial | `warn` / `down` |
| UPS power | mains lost (always `down` — a NAS on battery is on a countdown), battery at/below the configured floor; power restored resolves | `down` |
| UPS shutdown policy | the soft-landing policy engages or completes (see [ups.md](ups.md)) | `down` / `warn` / `ok` |
| Scheduled jobs | a panel job fails **twice in a row** (single failures are considered routine) | `warn` |
| Artifact freshness | a daily job's output file is older than its cadence allows — catches launchd jobs that are *loaded but never firing*, which launchd itself reports as healthy | `down` |

Every alert is appended to `data/alerts.jsonl` (last 500 kept) and shown on
the **Alerts** page regardless of notification settings. Notification
delivery is a separate step: each alert is offered to every enabled channel,
and the channel's own filter decides whether it goes out.

## Per-channel routing

Each channel carries three routing fields:

- `min_level` — one of `info`, `warn`, `down`. The channel receives alerts at
  or above this severity. Default `warn`.
- `notify_resolve` — whether recovery (`resolved`) events are delivered.
  Default `true`.
- `enabled` — a disabled channel receives nothing except explicit tests.

The per-channel **test button** bypasses the filters on purpose — that is
what testing is for.

Delivery is concurrent across channels and bounded: each socket operation has
a 10 s timeout and one dispatch is capped at 15 s wall-clock in total, so a
dead SMTP server cannot stall the alert thread (and with it the UPS countdown
alerts) for minutes. A channel that fails only logs a warning; it can never
take the alert thread or its sibling channels down.

## Channel types

| Type | Non-secret config | Secrets | Notes |
|---|---|---|---|
| `email` | `host`, `port`, `tls`, `username`, `from_addr`, `to` | `password` | `tls` is `starttls` (default, port 587), `ssl` (port 465) or anything else for plain. `to` accepts a list or a comma/space-separated string. |
| `ntfy` | `server` (default `https://ntfy.sh`), `topic` | `token` (optional) | Alert level maps to ntfy priority: `down` → 5 (urgent), `warn` → 4, otherwise 3. Token is sent as a Bearer header. |
| `telegram` | `chat_id` | `bot_token` | Sent via `api.telegram.org/bot<token>/sendMessage`, message truncated at 4000 chars. |
| `discord` | — | `webhook_url` | Incoming webhook; content capped at Discord's limit. |
| `slack` | — | `webhook_url` | Incoming webhook. |
| `webhook` | — | `url` | POSTs JSON `{title, message, text, level, event}` — a superset of the historical Home Assistant webhook payload, so anything that parsed the old shape keeps working. The whole URL is treated as a secret because such URLs routinely embed tokens. |
| `home_assistant` | `ha_url`, `ha_service` | `ha_token`, `ha_webhook_url` | Same behaviour as the legacy integration: webhook if configured, otherwise the HA service call with a Bearer token. |

All URLs must be `http(s)` — the panel refuses to POST to `file://`,
`gopher://` etc. (SSRF guard). Secret values may not contain control
characters (a token pasted with a trailing newline would otherwise leak into
error logs via urllib's exception text).

## Where the configuration lives

The split follows the repository convention:

- **Non-secret channel parameters** live in `services.yaml` under
  `settings.notify.channels`.
- **Secrets** (SMTP passwords, bot tokens, webhook URLs) live in
  `data/notify-credentials.json`, created mode 0600. They are **never**
  written to `services.yaml` and never echoed back by the API — responses
  carry `has.<field>` booleans only. The redacted `services.yaml` export is
  therefore safe to share; secrets must be re-entered after a restore.

```yaml
settings:
  notify:
    channels:
      - id: ops-mail            # [a-z0-9][a-z0-9._-]{0,63}
        type: email             # immutable after creation
        name: Ops mailbox
        enabled: true
        min_level: warn         # info | warn | down
        notify_resolve: true
        host: smtp.example.com
        port: 587
        tls: starttls           # starttls | ssl | plain
        username: serverhub@example.com
        from_addr: serverhub@example.com
        to: [admin@example.com]
        # password lives in data/notify-credentials.json, set via the UI/API
      - id: phone
        type: ntfy
        enabled: true
        min_level: down
        topic: my-serverhub-topic
```

### Legacy Home Assistant settings

Installations configured before the notification center keep working without
any migration. The pre-existing keys —

```yaml
settings:
  notify:
    enabled: true
    ha_url: http://homeassistant.local:8123
    ha_service: notify.notify
    ha_token: '...'          # or ha_webhook_url
    include_warn: false      # legacy global filter
    notify_resolve: true
```

— are honoured as an *implicit* Home Assistant channel with
`min_level: warn`/`down` derived from `include_warn`. Nothing is rewritten on
upgrade, and the legacy Settings fields keep editing exactly these keys. Once
explicit channels exist, the per-channel filters take over routing.

## API

All endpoints are admin-only; every mutation is audited (channel id, type,
name — never secret values).

| Endpoint | Purpose |
|---|---|
| `GET /api/alerts/channels` | list channels (secrets as `has.*` booleans) + type schemas |
| `POST /api/alerts/channels` | create (`secrets` fields ride in on writes only) |
| `PUT /api/alerts/channels/{id}` | update; omitted/`null` secret = keep stored value, `""` = clear; the type is immutable |
| `DELETE /api/alerts/channels/{id}` | remove channel and its stored secrets |
| `POST /api/alerts/channels/{id}/test` | send a test through this one channel, bypassing filters |
| `POST /api/alerts/test` | broadcast a test through every configured channel |
| `GET /api/alerts` | recent alert history (the Alerts page) |
