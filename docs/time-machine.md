# Time Machine backup destinations

Any SMB share managed on the **Storage → Shares** page can be offered as a
**Time Machine backup destination** for the other Macs in the house — the
same capability as System Settings → General → Sharing → File Sharing →
advanced options, controlled from the panel, with an optional per-share
size cap.

This uses macOS's native SMB server (`smbd`) end to end. No Samba, no
third-party daemon: Time Machine over SMB is a first-party macOS protocol
here, which is the platform advantage a Mac-based NAS has over Linux
alternatives that emulate it through Samba's `fruit` module.

## Enabling

Create or edit a share and switch on **Time Machine destination**; optionally
set a **quota in GB**. Both ride the same administrator authorization as the
share write itself (one approval for the whole sequence — the macOS admin
dialog, or the web-password fallback).

Under the hood the panel:

1. writes the share record with the `sharing` tool as usual;
2. sets the Time Machine attributes directly on the share-point directory
   record (`dscl` on `/Local/Default/SharePoints/<name>`):
   - `dsAttrTypeNative:timeMachineBackup = 1`
   - `dsAttrTypeNative:timeMachineBackupUUID` — minted **once** when first
     enabled and never rotated afterwards, because clients key their backup
     sets to this identity;
   - `dsAttrTypeNative:backupQuotaSize` — the quota in bytes (decimal GB ×
     10⁹, matching how macOS reports disk sizes); `0` means no cap;
3. **reads the attributes back and verifies them.** The write is only
   reported successful if a fresh read shows exactly the requested state. If
   a macOS release ever renames these attributes, enabling fails loudly with
   `verification_failed` instead of pretending the share is a backup target.
   (The attribute names follow the share-point records documented since
   OS X Server and the properties exposed by the current macOS Sharing
   settings pane; the read side additionally tolerates the alternate
   spellings seen on other macOS versions, so a share configured in System
   Settings is still recognized.)

Disabling the flag clears `timeMachineBackup` and the quota but deliberately
**keeps the UUID**: it names the existing backup sets, and keeping it lets a
re-enabled share adopt them again instead of starting the clients over.

## Prerequisites the panel checks for you

A flagged share is only *usable* when two things outside the share record are
true, and the Shares page reports both instead of assuming them:

- **File Sharing (smbd) must be running** — otherwise nothing is reachable.
- **Bonjour must be advertising `_adisk._tcp`** — that advertisement is what
  makes the share appear in clients' Time Machine destination pickers. The
  panel confirms it with a `dns-sd` browse (cached for a minute, and only
  performed while at least one Time Machine share exists).

If either is missing, the UI points at the fix (typically: enable File
Sharing in System Settings, which starts both `smbd` and the `sharingd`
advertisement).

## Connecting a client Mac

On the client:

- **System Settings → General → Time Machine → Add Backup Disk…** — the share
  appears under the server's name once `_adisk._tcp` is advertised; or
- explicitly: `sudo tmutil setdestination "smb://user@server/ShareName"`.

The connecting user must be able to authenticate to the share — see the
per-user access section in [authentication.md](authentication.md) for
granting individual macOS accounts read/write access to the share directory.

Practical notes:

- Put the share directory on the volume with the space to hold the backups;
  the share list shows each share's size and the quota next to it.
- The quota is enforced by Time Machine's server-side reporting; existing
  backups larger than a newly lowered quota are not deleted by the panel.
- Local Time Machine control of *this* machine (start/stop/enable backups of
  the server itself) is separate and lives on the Storage page
  (`/api/timemachine/action`).

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/shares` | share list; each row carries `time_machine`, `tm_quota_gb`, and the overview carries `time_machine: {share_count, smb_service_running, adisk_advertised}` |
| `POST /api/shares/smb` | create — body accepts `time_machine: bool`, `tm_quota_gb: int\|null` |
| `PUT /api/shares/smb/{record_name}` | update — same fields |

Setting `tm_quota_gb` requires `time_machine: true` (`shares.quota_requires_time_machine`);
the quota range is 1 GB – 1,000,000 GB. Share mutations require an
administrator **browser session** (API keys are deliberately not accepted for
share changes) and are audited.
