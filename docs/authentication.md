# Authentication, accounts and API keys

ServerHub can execute host and container commands, so authentication is a
non-negotiable boundary: it is **mandatory after first-run setup and cannot
be disabled**, on the LAN or anywhere else. This page covers first-run setup,
the multi-user model, TOTP two-factor sign-in, API keys, and per-user share
access.

## First-run setup

`install.sh` writes a one-time random token to `data/.setup-token`
(mode 0600). Until an administrator credential exists, every privileged API
answers `setup_required` and the panel shows the setup form.

- Claiming from **another machine** requires the setup token — it is the only
  thing standing between an unclaimed panel and whoever reaches it first.
- Claiming from **this machine** (loopback) does not prompt for it by
  default: a local browser can fetch it from `GET /api/auth/setup-token`
  anyway, so demanding it there is friction without an excluded attacker.
  `settings.auth.setup_token_mode: auto | always | never` tunes this.
- The claim is atomic (two simultaneous setup requests cannot both become
  administrators) and consumes the token file.

Passwords are stored as scrypt hashes (n=2¹⁴, r=8, p=1) in `services.yaml`;
minimum length 10. Plaintext passwords never persist anywhere.

## Sessions

Browser sign-in issues an HMAC-signed cookie (`serverhub_session`, HttpOnly,
SameSite=Strict, `Secure` when the request arrived over TLS — including via a
reverse proxy's `X-Forwarded-Proto`). The signing secret lives in
`data/.session-secret` (0600). Sessions last 7 days and embed a per-account
version derived from the password hash plus a logout counter, so:

- rotating a password invalidates every outstanding session of that account
  (and only that account);
- **Sign out revokes server-side**: the account's logout counter is bumped,
  killing all of its outstanding cookies, not just the one in this browser.

Login failures are rate-limited per client address: 5 failures in 5 minutes
locks that client out until the window passes. Unknown usernames burn the
same scrypt evaluation as wrong passwords, so response timing does not
enumerate accounts. Sign-ins, failures, rate-limit hits, password changes and
logouts are all written to the audit trail (Tools → Audit).

## Multi-user: admin and member accounts

Two roles exist:

- **admin** — unrestricted. The administrator credential is created at setup
  and rotated through Settings (change-password requires the current
  password).
- **member** — the family role. Members sign in with their own username and
  password and see a reduced panel: Dashboard, their services, and a
  self-service **Account** page.

Members are managed on the **Users** page (admin browser session required):
create, delete, reset a forgotten password (no current password demanded —
that is the point; the reset kills the member's sessions), and grant
**resources** — the list of service ids the member may see and open.

Member authorization fails closed and is enforced server-side twice over:

- member requests pass a small **read-only whitelist** (`GET` only:
  `/api/health`, `/api/status`, `/api/services`, `/api/launcher`, and
  `/api/services/{id}/detail` for granted ids); everything else answers
  `admin_required`;
- service listings are additionally filtered to the account's `resources`
  list. An empty list means *no* services — never "all".

On their **Account** page members (and admins) manage their own password and
two-factor enrollment. A member can touch nobody's credential but their own.

```yaml
settings:
  auth:
    username: admin            # legacy admin pair, created by setup
    password_hash: scrypt$...
    accounts:                  # member accounts — manage via the Users page;
      - username: alice        #   password_hash is scrypt, not hand-editable
        password_hash: scrypt$...
        role: member
        resources: [jellyfin, immich]
```

## Two-factor sign-in (TOTP)

Any account can add TOTP two-factor authentication, self-service, from its
Account page (Settings → Security for the admin). Standard parameters —
SHA-1, 30-second step, 6 digits, ±1 step clock drift — so every authenticator
app pairs (Google Authenticator, 1Password, Aegis, …).

Enrollment is enforced only after it is proven: scan the QR (or type the
secret), then confirm with one valid code. Until that confirmation the
account keeps signing in with just the password, so a mistyped import cannot
lock anyone out. Confirmation returns **10 single-use recovery codes**
(format `XXXXX-XXXXX`) — shown exactly once; store them somewhere safe.

Sign-in with 2FA is a two-step exchange: the password check returns a signed,
short-lived (5 minute) *pending* token instead of a session; the code — TOTP
or a recovery code, one field accepts both — trades it for the real session.

Security properties worth knowing:

- **Replay is rejected.** The last accepted TOTP counter is persisted per
  account and a code only verifies when its counter is strictly greater —
  the same code cannot be spent twice even inside its 30-second window.
- **Code guessing burns the login budget.** TOTP attempts share the
  per-client rate limit with password attempts, and a correct password does
  *not* reset the counter — only a completed sign-in does.
- **Recovery codes** are stored as SHA-256 digests and deleted on use; each
  use is audited with the remaining count. Regenerating them (requires a
  valid code) replaces the whole set.
- **Enabling or disabling 2FA revokes the account's other sessions** — they
  were issued under different credential requirements. Disabling requires a
  currently valid code; a walked-away-from browser cannot strip an account
  down to password-only.
- **Locked out (lost phone)?** An administrator can strip 2FA off a member
  account (Users page / `POST /api/auth/totp/admin-disable`) — no code
  demanded, both sides named in the audit trail, target's sessions revoked.
  2FA state lives in `data/twofa.json` (0600), never in `services.yaml`.

## API keys

For scripts and monitoring, mint **bearer API keys** under Settings →
API keys (admin browser session required):

```
curl -H "Authorization: Bearer shk_..." http://<server>:8086/api/status
```

(The panel itself speaks plain HTTP on port 8086; put TLS in front of it —
Cloudflare Tunnel or a reverse proxy — before sending keys across anything
but the local network.)

- Keys are `shk_` + 43 chars of CSPRNG output, **shown exactly once** at
  creation. At rest only a SHA-256 digest is kept (`data/api-keys.json`,
  0600); verification compares in constant time against every stored key.
- Each key carries a **role** (`admin` or `member`) and reuses exactly the
  session role's authorization paths — keys have no permission model of
  their own. A member key behaves like a member account with an empty
  resource list: the read-only whitelist applies and every resource-gated
  route fails closed.
- Optional **expiry** (1–3650 days), enforced at verification. At most 50
  keys. `last_used` is tracked (persisted at most hourly, so a monitoring
  loop does not turn every request into a disk write).
- Creation and revocation are audited; the plaintext never touches the audit
  trail.

**The browser-session boundary — by design, a key is less than a session.**
API keys satisfy only the general API guard. Endpoints that demand a signed
*browser session* refuse any bearer token, whatever its role:

- interactive terminals and VM consoles (WebSocket),
- share and launcher mutations,
- API key management itself (a credential that could mint further
  credentials would make revocation meaningless),
- member account management,
- catalog remote-source management,
- the UPS shutdown drill and macOS halt-level writes.

So a leaked admin key cannot open a shell on the box, change what software
the panel offers to install, or create more keys. In audit records, admin-key
requests appear with an empty username (like HTTP basic auth); member-key
requests appear as `key:<name>`.

Two narrower tokens exist alongside and are unrelated to API keys: the
one-time setup token above, and `data/.local-client-token` — a loopback-only
token the native menu-bar app uses, scoped to a fixed handful of status/action
endpoints and nothing else.

## Per-user share access (filesystem ACLs)

SMB shares on macOS have no per-user allow-list in the share record itself —
`smbd` acts as the connected user, and what actually decides access is the
share **directory's** POSIX bits and NFSv4-style ACLs. The Shares page edits
exactly that (the macOS equivalent of OMV's "privileges"):

- pick a share, pick a macOS account (real accounts, uid ≥ 500), pick
  **none / read / read-write**;
- the panel replaces that user's ACL entries with a canonical grant
  (including inheritance flags, so files created later inside the share
  inherit the same access), running unprivileged when the panel user owns
  the directory and through the admin authorization flow otherwise;
- the result is **read back and verified** — the UI reports the state that
  is actually on disk. macOS normalises permission tokens on directories
  (`read` → `list` and so on), so verification classifies tokens
  semantically rather than comparing strings.

Note these are macOS system accounts (the ones that can authenticate to SMB),
not ServerHub panel accounts — a family member typically has one of each.
Inherited ACL entries (from a parent directory) are shown but never edited.

## Files and permissions summary

| File | Contains | Mode |
|---|---|---|
| `services.yaml` | accounts, roles, resources, password *hashes* | 0600 |
| `data/.session-secret` | session HMAC secret | 0600 |
| `data/.setup-token` | one-time setup token (deleted on claim) | 0600 |
| `data/.local-client-token` | loopback menu-bar token | 0600 |
| `data/twofa.json` | TOTP secrets, recovery-code digests, replay counters | 0600 |
| `data/api-keys.json` | API-key digests + metadata | 0600 |
| `data/auth-audit.jsonl` | authentication audit trail | — |

Keep `data/` out of world-readable backups; the panel's own config export
(`GET /api/export/services-yaml`) redacts secrets for exactly this reason.
