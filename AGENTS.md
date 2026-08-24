# AGENTS.md

## Cursor Cloud specific instructions

ServerHub is a **macOS**-targeted home-server panel, but its FastAPI backend
(`hub/`, entry `app.py`) and Vue 3 frontend (`web/` → `static/`) run and test
fine on the Linux cloud VM. CI (`.github/workflows/ci.yml`) is the source of
truth for the supported toolchain (Python 3.12, Node 22).

### Services

Single web service: FastAPI + uvicorn, SPA served from the repo-root `static/`
directory. There is no database or external service to start.

### Non-obvious caveats

- **macOS-only Python deps must be excluded on Linux.** `requirements.txt`
  pins `rumps` and `pyobjc*` (the menu-bar app); they fail to install on Linux
  and are not needed by the panel or its tests. The update script and CI both
  install with `grep -vE '^(rumps|pyobjc)' requirements.txt`.
- **`command not found` WARNINGs during the backend tests are expected, not
  failures.** Most host features shell out to macOS-only tools (launchctl,
  diskutil, smartctl, brew, orb/OrbStack, utmctl, pmset, wg, pfctl). On Linux
  these are absent; the code tolerates it and tests stub/skip. Only the final
  `OK` / `FAILED` line matters.
- **Build the frontend before relying on the SPA.** `create_app()` serves the
  SPA only when `static/index.html` exists; otherwise it falls back to the
  legacy `index.html`. `static/` is committed, so a fresh checkout already has
  a usable SPA, but rerun `npm --prefix web run build` after editing `web/`.
- **First-paint JS budget.** `npm --prefix web run build` hard-fails if the
  entry chunk exceeds 150 KiB. Split a route/dependency rather than raising it.

### Run / test / build

Run these from the repo root. Standard commands are documented in `README.md`
(the "Development" section); the panel-run command below is the dev-server form.

- Run (dev): `.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8086 --reload`
  (binds loopback:8086). `SERVERHUB_HOST=0.0.0.0` opens it to the VM's network.
- Backend tests: `.venv/bin/python -m unittest discover -s tests -q`
- Frontend tests: `npm --prefix web test`
- Frontend build: `npm --prefix web run build`
- Dead-code check: `npm --prefix web run check:dead-code`
- Python unused-code checks (`pyflakes`/`vulture`) are dev-only and not in the
  update script; `.venv/bin/pip install pyflakes vulture` on demand.

### First-run auth

Sign-in is mandatory. On first launch the panel needs administrator setup. On a
loopback client the setup token is auto-supplied — `GET /api/auth/setup-token`
returns it and the setup form pre-fills it — so you can create the admin account
directly in the UI (or `POST /api/auth/setup` with a `password`). All auth state
lives under the gitignored `data/` directory; delete `data/.setup-token` and the
`data/services.yaml*` auth block to re-trigger first-run setup.
