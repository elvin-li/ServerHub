# UPS monitoring and safe shutdown

macOS recognises USB UPS units natively, and ServerHub builds on that:
plug a supported UPS into the Mac and the Dashboard grows a power tile,
power-loss and low-battery alerts flow through the
[notification center](notifications.md), and an optional **safe-shutdown
policy** gracefully stops your workloads before the battery runs out.

No NUT, no apcupsd — the data source is `pmset`, the same facility System
Settings uses. Readings are cached for 30 s and shared between the dashboard,
`GET /api/ups` and the alert sweep. A machine without a UPS simply reports
`present: false`.

## Status and alerts

`pmset -g batt` provides: power source (AC / UPS / battery), device name,
charge percentage, charging state and the estimated runtime (which pmset
withholds for a while after a power event — the panel shows "no estimate"
rather than guessing). `pmset -g ups` provides the system's own emergency
shutdown thresholds (`haltlevel` / `haltafter` / `haltremain`).

Two alerts, controlled by `settings.ups`:

- **Power lost** — the machine is running on battery. Always level `down`:
  a NAS on battery is on a countdown. Emitted once per outage
  (edge-triggered); *power restored* emits a resolve event.
- **UPS battery low** — charge at or below `low_battery_pct` (default 20)
  while on battery. Clears silently when power returns — the restored alert
  already tells that story.

A machine that *boots* on battery alerts immediately; a fresh alert-state
file is not a reason to stay silent about an outage in progress.

## Two-layer shutdown protection

The design separates a **soft landing** (the panel's job) from the **hard
cutoff** (the OS's job). They are deliberately different mechanisms:

### Layer 1 — panel soft landing (fires first)

`settings.ups.shutdown` configures when and what:

- **Trigger** — battery ≤ `trigger_pct` %, estimated runtime ≤
  `trigger_remaining_min` minutes, or both. Either condition may be `null`
  (off); with `require_both: true` both must hold. Only *readable* values
  count: the policy never fires on an unknown reading, so with
  `require_both` an unreadable runtime estimate blocks the trigger — the
  conservative reading of "both". The API refuses to save an enabled policy
  with no condition at all.
- **Actions** — stop Compose stacks in a configured order (`stacks: "all"`
  or an ordered list of stack ids; the list order is the stop order), then
  optionally stop `scripts:`/launchd services (`stop_scripts`).

Behavioural guarantees, all of which the *Simulate power loss* drill lets you
verify without touching anything:

- **Alert first, act second.** The `down` notification goes out before any
  stop is issued — early in an outage the network gear on the same UPS is
  still alive, so the message has its best chance of leaving the building.
- **Latched: one outage, one trigger.** The state machine
  (`idle → engaged → restoring → idle`, persisted in
  `data/ups-policy-state.json`) leaves `engaged` only when AC power is
  positively seen. A charge level flapping around the floor (49% ↔ 51%)
  cannot re-fire the sequence.
- **Crash-safe.** Each stack's `stop_issued` marker is persisted *before*
  its `compose stop` runs. If the panel dies mid-sequence, the next sweep —
  possibly in a fresh process — resumes the remaining stops while still on
  battery, or restores once AC is back.
- **Restores exactly what it stopped.** Only targets recorded as
  stopped-by-policy are started when power returns. A stack the operator had
  stopped by hand before the outage stays stopped. Failures to restart are
  reported by name in a `warn` alert.
- **No action on the unknown.** An unreadable pmset snapshot neither
  triggers nor resets the policy; the machine stays in its current phase
  until the sensor answers again.
- Every step is written to the audit trail (`ups.policy.*`), and slow work
  (compose stop/start) runs on a worker thread so the alert sweep is never
  blocked.

### Layer 2 — macOS halt thresholds (last resort)

`pmset -u haltlevel <pct>` is macOS's own emergency shutdown, executed by the
OS **whether or not the panel is alive**. The panel displays these thresholds
and can write `haltlevel` through the administrator authorization flow, but
it never runs `shutdown` itself.

Tune the two layers together: set the soft-landing trigger *above* the halt
level, so by the time macOS pulls the plug the machine has already quiesced —
databases flushed, containers exited cleanly.

Note: machines with an internal battery (laptops) ignore the pmset halt
thresholds; the UI says so. `haltlevel -1` switches the OS threshold off.

## Configuration reference

```yaml
settings:
  ups:
    alerts_enabled: true        # power-loss / low-battery alerts
    low_battery_pct: 20         # alert floor, 5–95
    shutdown:
      enabled: false
      trigger_pct: 25           # fire at ≤ this charge (5–95, or null = off)
      trigger_remaining_min: null  # fire at ≤ this est. runtime (1–720, or null)
      require_both: false       # true: both configured conditions must hold
      stacks: all               # "all", or ordered list: [db, immich, media]
      stop_scripts: []          # services.yaml scripts/launchd ids to stop too
```

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/ups` | live status + settings + shutdown-policy state |
| `PUT /api/ups/settings` | patch `settings.ups` (validates the no-condition shape; policy changes are audited with the operator's name) |
| `GET /api/ups/shutdown/plan` | the resolved stop sequence + stack/script catalogs (backs the settings form) |
| `POST /api/ups/shutdown/drill` | *simulate power loss*: reports whether the trigger would fire now and the exact ordered sequence; executes nothing. Admin browser session, audited |
| `PUT /api/ups/halt` | write the macOS `haltlevel` (−1 or 5–95) through the admin authorization flow. Admin browser session, audited |
