# App catalog

The **Apps** page installs curated self-hosted applications as Docker Compose
stacks with one click: pick a template, review the pre-filled variables,
install. Fifty templates ship built in — media (Jellyfin, Plex, Navidrome,
the *arr suite), photos (Immich), files and sync (Nextcloud, Syncthing,
FileBrowser), dashboards (Homarr, Glance, Homepage), networking (AdGuard
Home, Nginx Proxy Manager, wg-easy, cloudflared), databases (Postgres,
MariaDB, Redis), and operations tooling (Uptime Kuma, Dozzle, Watchtower,
Duplicati, ntfy, Vaultwarden, …).

Installed stacks land in `~/Services/<id>/` and are managed like any other
Compose stack (Compose page, stack backups, autostart policy). Uninstalling
can optionally remove data. Generated credentials are tracked per app and
shown on the app's detail card.

## Templates adapt to the machine

Templates never hardcode anything about the machine they were authored on.
The server fills these placeholders at install time; they never appear as
form fields:

| Placeholder | Resolves to |
|---|---|
| `{{HOME}}` | the user's home directory |
| `{{SERVICES}}` | the services root, normally `~/Services` |
| `{{HOST_IP}}` | the detected LAN address |
| `{{TZ}}` | the host's IANA timezone, read from `/etc/localtime` (falls back to `UTC`) |
| `{{OCR_LANG}}` | Tesseract language list for the host's preferred languages, e.g. `eng+chi_sim` |
| `{{UI_LANGS}}` | Stirling PDF locale list, e.g. `en_GB,zh_CN` |

Both language lists come from the macOS preferred-language order and always
keep English available.

Template authoring caveat: quote any front-matter default that starts with a
placeholder — `default: "{{HOME}}/Music"`. Unquoted, YAML reads `{{` as a
flow mapping, the front matter fails to parse, and the catalog silently
discards the listing in favour of a generated placeholder card.
`tests/test_template_metadata.py` fails the build if that happens.

## Remote catalog source

The built-in catalog always works offline. Optionally, an administrator can
point the panel at a **remote template source** (Apps → Catalog source) — a
static HTTPS file host serving a manifest plus one compose template per
entry:

```
index.json          the manifest
jellyfin.yml        one file per entry, path per manifest
```

```json
{
  "version": 1,
  "generated": "2026-08-01T00:00:00Z",
  "signature": "",
  "templates": [
    {"id": "jellyfin", "version": "1.2.0", "path": "jellyfin.yml",
     "sha256": "<hex sha256 of the file>", "size": 1234}
  ]
}
```

Behaviour:

- Syncing is an **explicit admin action** (*Check for updates*); there is no
  background poll. Every sync and source change is audited.
- Downloaded templates land in `data/catalog-remote/` (mode 0700) and
  **shadow** the built-in template with the same id. *Restore built-in*
  deletes the override and falls straight back to the shipped file — the
  panel keeps working with the catalog it was installed with even if the
  remote source disappears forever.
- Partial success is normal and reported: each rejected entry carries a
  machine-readable reason (`sha256_mismatch`, `too_large`, `parse_failed`,
  …) and never blocks its neighbours. Files are staged and moved into place
  atomically, so a crash mid-sync cannot leave a half-written template
  shadowing a working one.

### Trust model — read this before configuring a source

The integrity story is **sha256 pinning over verified HTTPS, not a
signature**. Concretely:

- the manifest URL must be plain `https://` (no embedded credentials);
  redirects that leave HTTPS are refused;
- template URLs must resolve to the **same origin** as the manifest — a
  manifest cannot point the panel at third-party hosts;
- every template file must hash to exactly the sha256 the manifest declares,
  so a CDN or mirror cannot substitute files without also controlling the
  manifest;
- blast-radius caps: 64 KB per template, 512 KB manifest, 500 entries; every
  template must parse (front matter + a non-empty `services:` mapping)
  before it is accepted.

What this does **not** give you: protection from whoever controls the
manifest URL itself. **The administrator's choice of source URL is the root
of trust** — a compromised source host can serve a malicious manifest with
matching hashes. The manifest format reserves a `signature` field so
public-key verification can be added without a format change (the project's
runtime deliberately carries no asymmetric-crypto dependency today), and the
API reports `signature_verified: false` honestly rather than implying
otherwise. Installing a template remains an explicit admin action either
way, and template rendering passes through the same injection guards as the
built-ins.

Only configure sources you would trust to run software on your machine —
because that is precisely what a catalog source is.

## Service recognition and adoption

Adaptive discovery (`settings.adaptive: true`) surfaces daemons that listen
on the host but are not in `services.yaml`. Two features make those rows
useful:

- **Recognition** — a curated signature library identifies common homelab
  daemons by process name (strong match) or default port (weak hint):
  PostgreSQL, MySQL/MariaDB, MongoDB, Redis, Mosquitto, nginx, Caddy, and
  friends. Recognised services get a proper display name and category, and
  services that are known to serve no web UI don't get a misleading link.
- **Adoption** — *Adopt* on an auto-discovered row promotes it into a
  managed `scripts:` entry in `services.yaml` (admin-only). The entry is
  health-checked by TCP port — exactly the evidence discovery has — and
  carries an `adopted_from` provenance marker so hand-written and adopted
  entries stay distinguishable later. Add `start`/`stop` commands to the
  entry to enable the action buttons.

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/catalog` | templates + categories (built-in overlaid with remote overrides) |
| `POST /api/catalog/{id}/install`, `POST /api/catalog/{id}/uninstall` | install / uninstall |
| `GET /api/catalog/remote` | source URL, last sync result, current overrides, `signature_verified` |
| `PUT /api/catalog/remote` | set or clear the source URL (admin browser session) |
| `POST /api/catalog/remote/check` | fetch + validate + apply the manifest (admin browser session) |
| `POST /api/catalog/remote/restore` | delete one override, restoring the built-in (admin browser session) |
| `POST /api/services/{id}/adopt` | adopt an auto-discovered service (admin) |
