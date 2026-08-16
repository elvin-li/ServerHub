# Scheduler and backups

The **Tools → Scheduler** page manages recurring jobs the panel itself runs
(OMV-style "Scheduled Jobs"), alongside a read-only view of what macOS
(launchd) schedules. Backups — rsync sync jobs, Compose stack archives,
database/config archives — are the scheduler's most important consumers and
are covered here too.

## Panel jobs

A job is `{id, name, type, cron, enabled, timeout, params}`, stored in
`services.yaml` under `schedules:`. Four types exist:

| Type | What runs |
|---|---|
| `command` | a shell command via `/bin/bash -c` (max 4000 chars), with `settings.maintenance_env` merged into the environment |
| `rsync` | an rsync push/pull job (see below) |
| `stack_backup` | stop → archive → restart of one Compose stack (see below) |
| `snapshot` | a local APFS snapshot via `tmutil localsnapshot` (needs no elevation; snapshot *thinning/deletion* requires the admin sheet and is deliberately **not** schedulable) |

```yaml
schedules:
  - id: nightly-sync            # [A-Za-z0-9][A-Za-z0-9._-]{0,63}
    name: Nightly media sync
    type: rsync
    cron: '30 3 * * *'          # five fields, host local time
    enabled: true
    timeout: 7200               # seconds; default 3600, max 86400
    params:
      direction: push           # push | pull
      src: /Users/me/Services/media
      dest: /Volumes/Backup/media          # or user@host:path
      delete: false             # --delete is opt-in; sharpest edge rsync has
      compress: true            # only applied when the binary supports -z
      bwlimit_kbps: 20000       # only applied when supported
      exclude: ['.cache', '*.tmp']
  - id: appdata-weekly
    name: Weekly stack backup
    type: stack_backup
    cron: '0 4 * * 0'
    enabled: true
    params:
      stack_id: immich
      retain: 8                 # archives kept, 1–365; default 14
  - id: hourly-snapshot
    name: Hourly APFS snapshot
    type: snapshot
    cron: '0 * * * *'
    enabled: true
    params: {}
```

### Cron semantics

These match vixie cron and are relied on by the test suite — they are worth
knowing exactly:

- **Five fields** — `minute hour day-of-month month day-of-week`. Supported
  syntax: `*`, numbers, lists (`a,b`), ranges (`a-b`), steps (`*/n`, `a-b/n`,
  and vixie's `a/n` meaning "a through max, step n"). Day-of-week accepts
  both `0` and `7` as Sunday. When *both* day-of-month and day-of-week are
  restricted, a minute matching **either** fires (the vixie OR rule).
- **Host local time.** "03:30 nightly" stays 03:30 through DST changes.
- **Missed triggers are not back-filled.** The engine evaluates only the
  current minute. If the panel was down or the Mac slept through a match,
  that run is gone and the job fires at its next matching minute — the same
  contract as vixie cron. A `@daily` job on a machine that is off at that
  time simply does not run that day. This includes the boot minute: a restart
  inside a matching minute does not re-fire, so a quick panel restart cannot
  double-run a job.
- **Overlap is skipped, not queued.** If a job's previous run is still going
  at its next matching minute, the new trigger is journalled as `skipped` and
  dropped. Two concurrent runs of one backup are never right.

### Execution, history, failure alerts

Runs execute under a watchdog (process-group kill on timeout, bounded output
capture). Every run — scheduled, manual, or skipped — is journalled to
`data/schedule-runs.jsonl` (last 1000 kept) with status
`ok | failed | timeout | skipped`, exit code, duration and the last 2000
characters of output.

A job that fails **twice in a row** raises a `warn` alert through the
notification center ([notifications.md](notifications.md)); a success resets
the streak. Failure streaks are tracked in memory, so a panel restart starts
a clean slate rather than re-alerting on stale history.

### SMART self-tests

The SMART self-test schedule (Storage → SMART) appears on the Scheduler page
as a read-only "system" row. It deliberately keeps its own interval-based
engine instead of being converted to cron: that engine *catches up after
sleep* (a Mac that slept through the deadline still gets its weekly disk test
on wake), whereas the cron engine drops missed triggers. Converting it would
silently change disk-test cadence on sleep-prone machines.

### API

Admin-only (member sessions and member API keys cannot reach any
`/api/scheduler/jobs` path). Every mutation is audited; for `command` jobs
the audit record includes the command text itself.

| Endpoint | Purpose |
|---|---|
| `GET /api/scheduler/jobs` | jobs with next/last run state, plus the read-only system entries |
| `POST /api/scheduler/jobs` / `PUT /api/scheduler/jobs/{id}` / `DELETE …/{id}` | CRUD |
| `POST /api/scheduler/jobs/{id}/enable` | toggle |
| `POST /api/scheduler/jobs/{id}/run-now` | manual trigger, fire-and-forget (refused while already running) |
| `GET /api/scheduler/jobs/{id}/runs`, `GET /api/scheduler/runs` | run history |
| `GET /api/scheduler` | read-only launchd timer listing (the "System" tab) |

## rsync backups

macOS ships two very different rsyncs, and ServerHub adapts to whichever is
present, probing in order:

1. `/opt/homebrew/bin/rsync` (Homebrew rsync 3.x)
2. `/usr/local/bin/rsync`
3. `/usr/bin/rsync` — on recent macOS this is **openrsync**, which speaks the
   same protocol but supports only the classic flag set

Capabilities are probed, cached, and reported by
`GET /api/backups/rsync/binary`: `--itemize-changes`, `--info=progress2`,
`-z` (compression) and `--bwlimit` are used only on rsync 3.x. A job
configured with compression keeps running (without compression) if Homebrew's
rsync disappears — degraded, not broken.

Job parameters (validated, and stored exactly as validated):

- `direction` — `push` (this machine's data leaves) or `pull`. The local side
  must be an absolute local path; the far side may be a second local path
  (external disk, mounted SMB share) or `user@host:path` over SSH. SSH
  authentication uses the panel user's normal SSH setup (`~/.ssh`, agent);
  passwords are not supported and there is no per-job identity file setting.
- `delete` — maps to `--delete`, **opt-in**. As a safety measure a push run
  whose source directory does not exist is refused outright rather than
  passed to rsync, where `--delete` could translate "source vanished" into
  "empty the destination".
- `exclude` — list of patterns, each passed as a single `--exclude=PATTERN`
  token. Patterns starting with `-` are rejected, so no configured value can
  ever be parsed as an rsync option.
- `compress`, `bwlimit_kbps` — applied only when the binary supports them.

**Dry-run preview** (`POST /api/backups/rsync/preview`, the *Preview* button
on the Backups page) runs `rsync --dry-run` and reports counts of
creates/updates/deletes plus up to 200 sample paths — nothing is copied. The
preview streams rsync's output (bounded memory even over millions of files),
is limited to 120 s, and refuses a second concurrent preview of the same job.
On openrsync, which lacks `--itemize-changes`, creates and updates cannot be
distinguished and are counted together as updates.

Each real run's full output is kept in `data/backup-runs/<job>/<timestamp>.log`
(directory mode 0700, last 20 logs per job); the run journal keeps the tail.

## Compose stack backups (appdata)

A `stack_backup` job archives one Compose stack's data in the shape Unraid
users know from "CA Appdata Backup":

1. write a **crash-recovery marker** (`data/stack-backup-inflight-<stack>`),
2. `docker compose stop`,
3. archive: the compose file itself, every bind-mounted host directory/file,
   and every named volume (exported by a throwaway `alpine` container —
   named volumes live inside the Docker VM on macOS and have no host path to
   tar),
4. `docker compose start` — **always**, in a `finally:` a failed archive is
   an inconvenience; a stack left stopped overnight is an outage,
5. clear the marker, prune old archives.

If the panel process itself dies between stop and restart (kill, reboot,
watchdog kickstart — cases no `finally` can cover), the marker survives; on
the next panel startup a recovery scan finds it, issues `compose start`, and
raises a `warn` alert stating what happened. If even the in-process restart
fails, the job result is marked failed with an explicit *"STACK DID NOT
RESTART — start it manually"* message; the archive's success never masks it.

Archives land in `~/Services/backups/appdata/<stack>/<stack>_<stamp>.tgz`,
created owner-only (0600 file in a 0700 tree, `O_EXCL` so a name collision
can never truncate an existing archive) and pruned to `retain` copies
(default 14). Pruning runs only after a successful archive, so a failing job
cannot rotate away the last good copy.

Notes:

- Bind mounts nested inside another archived bind are skipped (tar would
  store them twice); sockets and device nodes are wiring, not data, and are
  skipped too.
- Mounts are resolved with `docker compose config`, so env interpolation,
  relative paths and project-prefixed volume names are handled by Compose
  itself.
- Stack backups run through the scheduler (create a job, optionally trigger
  it with *Run now*); the Docker engine must be up or the run fails cleanly
  without stopping anything.

## Database and config archives

The Backups page also offers one-click archives (also exposed as
`POST /api/backups/postgres`, `POST /api/backups/immich` and
`POST /api/backups/configs`):

- **PostgreSQL dump** — `pg_dump -F c` against each target listed under
  `backups.postgres` in services.yaml (`id`, `host`, `port`, `db`, `user`).
  The password is read from `data/backup-credentials.json`
  (`{"<id>": {"password": "..."}}`, mode 0600) or, with `password_env`, from
  that environment variable — never from services.yaml, which the export and
  the config archive both carry verbatim. With no targets configured the
  button reports "not configured" instead of dumping anything.
- **Immich dump** — the Immich cluster on this class of host is PostgreSQL 18
  on :5433. PATH `pg_dump` is 17.x and a version-mismatched dump is empty, so
  this job is separate from the generic postgres button. When
  `~/Services/immich/backup-db.sh` exists the panel runs that script; otherwise
  it uses Homebrew `postgresql@18`'s `pg_dump` and the password in
  `~/Services/immich/db.env` (never copied into services.yaml). Artefacts are
  `immich_*.sql.gz` (plain SQL, gzipped; restore with `gunzip | psql`).
  After the 2026-08-14 library redesign the Backups page also shows the other
  layers (Apple Photos originals, PhotosBridge index, generated media,
  PhotosHub external copy). A `stack_backup` of `immich_server` is the wrong
  tool: originals and PG18 are not inside that compose stack.
- **Config archive** — a tarball of `services.yaml` plus user-managed
  LaunchAgent plists matched by a keyword manifest: built-in keywords cover
  the panel's own agents and its integrations, and
  `backups.config_archive.agent_keywords` adds this install's own (config can
  widen the manifest, never narrow it). `extra_paths` archives additional
  files, such as compose files. A run that cannot include `services.yaml` is
  refused outright: a config archive without the config is a failure, not a
  partial success.

Both keep 14 copies with the same 0600/`O_EXCL` discipline, and each listed
artifact on the Backups page carries a **restore hint** — the exact command
that puts it back (`pg_restore` for custom-format dumps, not `psql`; tar
extraction notes for archives). Restoring is deliberately never a button:
it overwrites live data and stays an operator decision.

`GET /api/backups` lists all discovered artifacts with the total count, so a
capped table never reads as "older backups were deleted".

## Artifact freshness watchdog

launchd can keep a job *loaded* while its trigger is broken, and the service
sweep only alerts on "Not loaded" — so a scheduled job can silently stop
running. The freshness watchdog closes that hole by watching each job's
product instead of launchd's opinion of it: list jobs under a top-level
`freshness_targets:` in services.yaml (`id`, `label`, `pattern` — an
absolute glob for the artifact the job touches on every run — and
`max_age_hours`, the cadence plus slack for runtime). When the newest match
is older than the limit, an alert fires at level `down` (bypassing
`include_warn`, like a service-down alert) and resolves on recovery. There
are no built-in targets; an install that configures none simply skips the
check.
