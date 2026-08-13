# Upgrading ServerHub

ServerHub deploys from its own git checkout: the working tree is the
installation. Upgrading means moving that tree to a newer revision and
letting the pieces that cache anything (the virtualenv, the built web UI,
the LaunchAgents) catch up. `services.yaml`, `data/` and `~/Services/backups`
are gitignored state — no upgrade or rollback step below touches them.

## Which install do you have?

The panel has shipped under three launchd labels. Check which one is loaded:

```bash
DOMAIN="gui/$(id -u)"
for label in local.serverhub.panel local.serverhub com.elvin.serverhub; do
  launchctl print "$DOMAIN/$label" >/dev/null 2>&1 && echo "$label"
done
```

* `local.serverhub.panel` — installed by `install.sh`. Upgrade by re-running it.
* `com.elvin.serverhub` (early releases) or `local.serverhub` (native
  ServerHub.app) — `install.sh` does **not** manage these and will refuse to
  install a second panel beside them. Upgrade in place, below.

## Standard installs: re-run install.sh

```bash
cd ~/Services/serverhub    # wherever the checkout lives
git pull
./install.sh               # add --port/--no-menubar if you used them before
```

Re-running is the supported upgrade and is idempotent:

* the virtualenv is reused and `pip install -r requirements.txt` runs every
  time, so dependency changes are applied (note: packages a new revision no
  longer lists are not removed — after a large jump, `rm -rf .venv` first for
  a clean rebuild);
* the web UI is rebuilt only when `web/` sources are newer than `static/`,
  and the swap is transactional: the new bundle is validated in
  `static.next`, the previous one is kept in `static.prev`, and a failed
  install rolls the bundle back;
* `services.yaml` and `data/` are preserved (`services.yaml` is only created
  from the example when missing);
* the LaunchAgent plists are rewritten and the agents re-bootstrapped, so
  plist changes (port, environment, log paths) take effect;
* the script ends by waiting up to 30 s for `/api/health` and fails loudly
  if the panel did not come back.

## Legacy-label installs: upgrade in place

```bash
cd ~/Services/serverhub
git pull
.venv/bin/python -m pip install -r requirements.txt
# only if web/ changed and you build the UI from source:
npm --prefix web ci && npm --prefix web run build
launchctl kickstart -k "gui/$(id -u)/com.elvin.serverhub"   # or local.serverhub
```

Notes:

* the watchdog (`local.serverhub.watchdog`) needs nothing: it re-reads
  `deploy/panel-watchdog.sh` from the checkout on every 60 s tick;
* this path applies code changes but not plist changes. If a new revision
  changes what belongs in the panel's plist, edit
  `~/Library/LaunchAgents/<label>.plist` accordingly and reload that one
  label (`launchctl bootout gui/$UID/<label>` then `launchctl bootstrap
  gui/$UID <plist>`);
* to migrate a legacy install to the supported label instead, run
  `./uninstall.sh` (keeps `services.yaml` and `data/`) and then
  `./install.sh`.

## Rollback

Code rollback is git plus the same catch-up steps:

```bash
cd ~/Services/serverhub
git log --oneline -10                 # find the last good revision
git reset --hard <sha>                # static/ is committed, so the UI reverts too
.venv/bin/python -m pip install -r requirements.txt
launchctl kickstart -k "gui/$(id -u)/<your panel label>"
```

Configuration rollback is separate from code rollback:

* `data/services.yaml.bak.<epoch>` — the last 30 pre-images of
  `services.yaml`, written before every save;
* `~/Services/backups/configs_*.tgz` — the scheduled config archives
  (services.yaml, the `data/` credential/state files, selected LaunchAgent
  plists). Extract to a scratch directory and copy members back deliberately:
  `mkdir -p /tmp/restore && tar xzf <archive> -C /tmp/restore`.

After any upgrade or rollback, confirm the running version matches
`hub/__init__.py` (`__version__`) and tail the log if the panel misbehaves:
`tail -n 40 ~/Library/Logs/serverhub.err.log`.
