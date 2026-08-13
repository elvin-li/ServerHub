# Metrics history

The Dashboard charts CPU, load, memory pressure, root-volume usage and
network throughput over ranges from **1 hour to 1 year** (`1h · 6h · 24h ·
48h · 30d · 1y`). Long ranges are served by a tiered store that keeps roughly
a year of history in a few megabytes of JSONL — no database, SSD-friendly
write patterns throughout.

## The three tiers

| Tier | File | Resolution | Retention |
|---|---|---|---|
| raw | `data/metrics.jsonl` | one sample per `metrics_interval` (default 90 s) | ring buffer of 2880 points ≈ 48–72 h |
| 5-minute | `data/metrics-5m.jsonl` | 5-minute windows | ~30 days (~8 640 rows) |
| 1-hour | `data/metrics-1h.jsonl` | 1-hour windows | ~400 days (~9 600 rows) |

The sampler thread writes raw points in batches (a flush every ~4 samples or
5 minutes, full-file trims at most hourly) to keep SSD churn down. Rollups
ride the same thread: each tick costs an integer comparison unless a
wall-clock window boundary has been crossed, in which case the completed
windows are aggregated raw → 5m, and 5m → 1h.

Aggregate rows keep the raw field names for the **window average** and add a
`<field>_max` **peak** per numeric field. Peaks are the point: a 30-second
CPU spike would otherwise be averaged away in a 1-hour window, and the
Dashboard shades the avg–max band so spikes stay visible at year scale.
`t` is the window start (aligned to 5-minute / 1-hour boundaries, epoch/UTC),
`n` counts the raw samples behind the row.

## Semantics that are deliberate

- **Holes stay holes.** A Mac asleep, or a panel that was down, produces no
  samples — and no aggregate rows, and no interpolation. Decimation buckets
  by time, not by index, so gaps survive all the way to the chart instead of
  being bridged by their neighbours.
- **Restart-safe, crash-safe.** Per-tier watermarks are persisted
  (`data/metrics-rollup-state.json`) and recovery also consults the last row
  of each aggregate file, so a restart neither re-aggregates a window nor
  skips one, even if the crash landed between "append rows" and "save
  state".
- **Clock steps are contained.** An NTP correction backwards never moves a
  watermark back; raw rows stamped earlier than the watermark are ignored
  rather than double-counted.
- **Exact means.** The 1-hour tier aggregates 5-minute rows weighted by
  their sample counts, so an hour's average is the true mean of its raw
  samples, not an average of averages.

## Query API

`GET /api/metrics` serves both the legacy and the ranged contract:

- **Legacy** (no `range`/`since`): `?minutes=60` returns raw points,
  unchanged shape — external pollers (e.g. the menu-bar app) keep working.
- **Ranged**: `?range=48h` (`h`/`d`/`w`/`y` units, e.g. `30d`, `1y`), or an
  explicit `?since=<epoch>&until=<epoch>` window. Optional `points=` caps
  the response (50–1500, default 1500 — plenty for a chart, keeps a 1-year
  response around 300 KB instead of megabytes).

The tier is picked automatically — spans ≤ 48 h prefer the raw layer, up to
~30 days the 5-minute layer, beyond that the 1-hour layer — with one
refinement: if the preferred layer demonstrably does not reach back to
`since` and a coarser layer does, the coarser layer wins. The response
carries `tier` (`raw` / `5m` / `1h`) plus the resolved `since`/`until`, and
each point set may be decimated onto a coarser grid to honour `points`.

```json
{"points": [{"t": 1755000000, "n": 200, "cpu_used_pct": 12.3,
             "cpu_used_pct_max": 71.0, "...": "..."}],
  "latest": {"...": "..."}, "tier": "1h",
  "since": 1723464000, "until": 1755000000}
```

## Configuration

```yaml
settings:
  metrics_interval: 90   # raw sample cadence, seconds (15–600).
  alert_interval: 90     # alert sweep cadence, seconds (15–600).
```

A larger `metrics_interval` stretches the raw ring buffer further back in
time (2880 points at 90 s ≈ 3 days) at the cost of chart resolution; the
aggregate tiers are unaffected. History accumulates from the day the panel
is installed — a 1-year chart fills in as the panel lives that year.
