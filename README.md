# ServerHub v3.9.1

A home-server management panel for macOS — modelled on **Unraid**'s information architecture, with ideas borrowed from **Dockge / Portainer / Glances / Glance / Heimdall / CasaOS / Homebrew**.

**Panel:** binds `0.0.0.0:8086` by default, so it is reachable from any device on your local network — sign-in is mandatory once setup completes, so LAN clients get the login page rather than an open API. Set `SERVERHUB_HOST=127.0.0.1` to restrict it to loopback. Either way, do not expose port 8086 to the internet directly: put it behind a Cloudflare Tunnel or a reverse proxy that terminates TLS and enforces an identity policy.

## Screenshots

> The images below use entirely fictional demo data. They contain no real accounts, usernames, IP addresses, hostnames, tokens or service configuration.

### System overview

![ServerHub system overview (fictional demo data)](docs/screenshots/dashboard-demo.png)

### Apps and processes

![ServerHub apps and processes (fictional demo data)](docs/screenshots/apps-demo.png)

## Module map (`/modules`)

| Category | Modules | Inspiration |
|------|------|------|
| System | Dashboard, Services, **Brew**, Sensors | Unraid / Glances / Homebrew |
| Containers | Docker table, **Compose editor**, App catalog | dockerMan / **Dockge** / Portainer / CA |
| Storage | Storage array, Shares | Unraid Main / OMV |
| Network | Interfaces / Ports / Routes | Unraid Network |
| Apps | **Bookmark health probes** | **Heimdall / Homarr / Glance** |
| Operations | Logs, Alerts, Backups, Tools, Maintenance | Unraid Tools + Notifications |

## Highlights

### Compose (Dockge-style)
- Stack list with **in-browser YAML editing**
- **Validation** via `docker compose config`
- Automatic `.bak` on save
- New stacks are written to `~/Services/<id>/`
- Up / Down / update task logs

### Homebrew (macOS-specific)
- `brew services list --json`
- Start / stop / restart grafana, postgres, mosquitto and friends

### Bookmark probes (Homarr-style)
- HTTP probes against `quick_links` plus override URLs
- Latency in ms, 401/403 counted as online, self-signed HTTPS tolerated
- Dashboard tiles plus the `/bookmarks` page

### Sensors (Glances-style)
- CPU user/sys/idle, load, memory, root volume
- `/api/system/sensors`

### Module registry
- `/api/modules` makes every capability and its inspiration discoverable

## Stack

- FastAPI package `hub/` + Vue 3 (`web/` → `static/`)
- Container engine: **OrbStack**
- Menu bar: native `macos/ServerHubLauncher.swift`; `menubar.py` is the legacy implementation

## Quick start

Requires macOS 13+ and Python 3.10+. Rebuilding the frontend from source additionally needs Node.js 18, 20 or 22+ with npm.

```bash
git clone https://github.com/elvin-li/ServerHub.git
cd ServerHub
./install.sh
open http://localhost:8086
```

The install script creates a local virtual environment, preserves an existing `services.yaml`, and generates authentication tokens that stay on this machine and are gitignored. On first launch, use `data/.setup-token` to complete administrator setup. To uninstall, run `./uninstall.sh`; adding `--purge` also removes local configuration and runtime data.

## Native macOS menu bar

The native menu-bar app can be installed system-wide or into the current user's Applications directory. A per-user install does not need write access to `/Applications`:

```bash
mkdir -p "$HOME/Applications"
./macos/build_app.sh "$HOME/Applications/ServerHub.app"
open "$HOME/Applications/ServerHub.app"
```

The app follows the macOS preferred language: Chinese locales get a Simplified Chinese menu, everything else gets English. For development and snapshot testing you can override this explicitly with `SERVERHUB_LANGUAGE=zh-Hans` or `SERVERHUB_LANGUAGE=en`; an empty value falls back to the system language.

The panel's **Settings → Panel** page reports the state of the app, the menu-bar process, the background panel and login autostart, and can open the app, toggle login autostart, or restart and stop the panel. After stopping the panel, reopening `ServerHub.app` brings it back; if a status read fails, use the refresh button on the card to retry.

## Development

Run these from the repository root (`~/Services/serverhub`):

```bash
# Backend behaviour tests
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'

# Frontend tests, dead-code check and production build
npm --prefix web test
npm --prefix web run check:dead-code
npm --prefix web run build

# Python unused-code checks
.venv/bin/python -m pyflakes hub tests app.py menubar.py
.venv/bin/python -m vulture hub tests app.py menubar.py --min-confidence 100
```

Production builds are written to `static/`. The Vite build asserts that the first-paint entry JavaScript stays under 150 KiB and fails outright when it does not; that budget should only ever be lowered — if you need more room, split a route or a dependency out of the entry instead. Every page (including `/` and `/login`) is a lazily loaded chunk, and `main.js` prefetches the one matching the current URL in parallel at startup, so lazy loading does not add a serial round trip to first paint. The English dictionary is bundled as a synchronous fallback; Chinese and Japanese load asynchronously for the active language. When editing dictionaries, keep the keys and placeholders identical across all three languages — `npm --prefix web test` enforces that contract.

Once a build looks good, this snippet restarts whichever LaunchAgent label is actually installed. The panel task has used three names over time: `install.sh` writes `local.serverhub.panel`, the native ServerHub.app writes `local.serverhub`, and early releases installed `com.elvin.serverhub`. The loop probes each in turn and restarts the first one it finds:

```bash
DOMAIN="gui/$(id -u)"
for label in local.serverhub.panel local.serverhub com.elvin.serverhub; do
  if launchctl print "$DOMAIN/$label" >/dev/null 2>&1; then
    launchctl kickstart -k "$DOMAIN/$label"
    echo "restarted $label"
    break
  fi
done
```

## Panel watchdog

`install.sh` also loads `local.serverhub.watchdog`, a one-line probe that runs once a minute.

The panel's own LaunchAgent uses `KeepAlive`, which covers the ordinary failure: the process exits, launchd starts a replacement. It does not cover a hang. A replacement can wedge in `xpcproxy` — spinning on CPU, never exec'ing Python, never listening, and never exiting — and because it still holds the job's pid, launchd reports the job as running and `KeepAlive` never fires. That is the "panel never came back after a reboot" symptom.

The watchdog restarts the panel only after three consecutive unreachable probes (about three minutes), and only for a label that is currently loaded, so a deliberate `launchctl bootout` is left alone. Any HTTP status counts as healthy, including the 401 you get when signed out. It writes to `~/Library/Logs/serverhub-watchdog.log`, which stays quiet unless something actually happens.

```bash
# Watch it work
tail -f ~/Library/Logs/serverhub-watchdog.log

# Turn it off
launchctl bootout "gui/$(id -u)/local.serverhub.watchdog"
```

## Template catalog `templates/`

Templates must not hardcode anything specific to the machine they were authored on. The server fills these placeholders in automatically, so a template adapts to whoever installs it; they never appear as fields in the install form.

| Placeholder | Resolves to |
|------|------|
| `{{HOME}}` | the user's home directory |
| `{{SERVICES}}` | the services root, normally `~/Services` |
| `{{HOST_IP}}` | the detected LAN address |
| `{{TZ}}` | the host's IANA timezone, read from `/etc/localtime` (falls back to `UTC`) |
| `{{OCR_LANG}}` | Tesseract language list for the host's preferred languages, e.g. `eng+chi_sim` |
| `{{UI_LANGS}}` | Stirling PDF locale list, e.g. `en_GB,zh_CN` |

Both language lists come from the macOS preferred-language order and always keep English available. One caveat when writing templates: quote any default that starts with a placeholder — `default: "{{HOME}}/Music"`. Unquoted, YAML reads `{{` as a flow mapping, the front matter fails to parse, and the catalog silently discards the entire listing in favour of a generated placeholder card. `tests/test_template_metadata.py` fails the build if that happens.



uptime-kuma · portainer · navidrome · adguard-home · cloudflared · homarr · glance · dockge · filebrowser
