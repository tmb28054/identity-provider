# Backups and Restore

The identity provider keeps state that is **not** stored in git: the signing
key/certificate, users (with bcrypt password hashes and TOTP/MFA secrets), and
the service/claims configuration. This guide covers backing that state up to an
SMB share and restoring it.

## What gets backed up

A backup is a gzip tarball containing only the rebuild-critical files:

- `idp.key`, `idp.crt` — the signing key and certificate
- `users.json` — accounts, password hashes, MFA secrets
- `services.yaml`, `config.yaml` — routing and server configuration
- `claims.json`, `claim_roles.yaml`, `group_roles.yaml`, `adfs_config.yaml` — if present
- `recovery_tokens.json`, `backup_config.json`

The append-only access log (`audit.log`) and the backup bookkeeping files
(`backup_status.json`, `backup_archives.json`) are **not** included.

## How it works

- A root-owned systemd timer (`idp-backup.timer`) runs nightly at **02:30**
  (server time).
- The timer starts `idp-backup.service`, which mounts the configured SMB share,
  writes a timestamped archive `idp-YYYYMMDD-HHMMSS.tar.gz` into `daily/`, and on
  Sundays also into `weekly/`, then unmounts.
- Retention is pruned per run: **30** daily archives and **52** weekly archives
  are kept (configurable on the Backups page).
- The web app itself never mounts anything. It only writes configuration and
  triggers the root units through a narrow `sudo` rule.

> **Note on the signing key.** A backup archive contains `idp.key`, which is as
> sensitive as the live server. Restrict access to the SMB share accordingly —
> anyone who can read the archive can impersonate the IdP.

## Recovery objectives (RPO / RTO) and capacity

### Recovery Point Objective (RPO) ≈ 24 hours

The nightly timer runs once per day at **02:30** (server time, see *How it
works* above). The worst-case data loss is therefore **about one day** of
changes — accounts added, passwords or MFA re-enrolled, or service/claim config
edits — made between the last successful 02:30 archive and the incident.

Any config or user change made *after* a nightly run is at risk until the next
run. To shrink the RPO on demand, an operator can trigger **Run backup now** on
the Backups page immediately after a significant change; that produces a fresh
archive outside the nightly cadence.

### Recovery Time Objective (RTO) ≤ 15 minutes

RTO is the time to bring the service back from the most recent archive via the
documented *Restoring* procedure below:

1. Select the archive in the portal and provide a fresh MFA code (or captcha).
2. The root `idp-restore@` unit mounts the share, snapshots current data,
   verifies the SHA-256 digest and the Fernet authentication tag, and extracts
   the allow-listed files.
3. The `identity-provider` service restarts so the restored key and routes take
   effect.

A realistic target for an operator with portal access and the backup key present
is **≤ 15 minutes**. Meeting it depends on these prerequisites being in place
*before* an incident:

- the SMB share is reachable and the stored credentials still mount it;
- the backup key is available — `IDP_BACKUP_KEY` in the environment or
  `backup.key` on the host (restore fails closed without it);
- the restoring admin has MFA enrolled (or a captcha fallback) to authorise the
  high-impact restore.

### Capacity under stress

A single replica running a single worker is **intentional**, not an oversight.
The rate limiter, the MFA/captcha/WebAuthn nonce stores, the enrol-secret store,
and the audit chain cursor are all **per-process in-memory state**. Under a
demand spike or partial infrastructure loss the service degrades toward
*unavailable* rather than scaling out; recovery is a pod restart. Raising
capacity (more replicas or workers) is unsafe until that per-process state is
externalised to a shared backend first — doing so earlier would multiply the
failed-login budget and allow single-use nonces to be replayed once per process.

### Risk acceptance — single replica / single worker

The single-replica, single-worker topology is **accepted as a reasoned risk**,
consistent with the security-review response (see
`docs/security-review-20261006-response.md:190-215`, Finding 6, recorded there
as *accepted-with-a-plan*). The near-term control is documentation (these
objectives); the deferred architectural follow-up is to externalise the
per-process security state and audit cursor into a shared backend (e.g. Redis),
after which `replicas` / `--workers` can be raised and the
`PodDisruptionBudget` and `topologySpreadConstraints` templates in
`examples/kubernetes/` become effective. That change needs a product decision on
the shared-store dependency before implementation.

## Configuring backups

1. Sign in to the admin panel and open **Backups** (`/admin/backups`).
2. Under **SMB Destination**, enter:
   - **SMB server** — hostname or IP of the file server
   - **Share** — the share name
   - **Username** / **Password** — credentials with write access to the share
   - **Subpath** — directory within the share (default `idp-backup`)
   - **Daily / Weekly retention** — how many archives to keep
3. Click **Save settings**. The password is stored on the IdP host in
   `backup_config.json` with file mode `600` and is used only by the root backup
   job to mount the share.
4. Click **Test connection** to verify the share mounts and is writable. It
   reports how many daily archives are already present.

Leave the password field blank when saving to keep the previously stored
password.

## Running a backup manually

On the Backups page, click **Run backup now**. This starts the same root unit the
timer uses. Refresh the page after a moment to see the result in the **Status**
section. Success and failure are recorded in the access audit log
(`service=backup`).

## Restoring

Restore **overwrites all current IdP data** with the selected archive, then
restarts the service. It is a high-impact operation, so it is guarded:

1. On the Backups page, choose an archive from the **Restore** dropdown. The list
   is populated from the most recent successful backup run.
2. Enter your **MFA code** (or the captcha answer if you don't have MFA) to
   confirm your identity.
3. Click **Restore selected archive** and confirm the prompt.

What happens next:

- The current `data/` files are snapshotted to
  `data/pre-restore-snapshots/pre-restore-<timestamp>.tar.gz` first, so a bad
  restore can be rolled back.
- The selected archive is extracted into `data/` (all-or-nothing; archives are
  validated to reject absolute paths and directory traversal).
- The `identity-provider` service is restarted so the restored signing key and
  service routes take effect.
- The event is recorded in the access audit log (`service=restore`).

## Failure alerts

If the most recent backup failed, a red banner appears both on the main admin
panel and on the Backups page until a subsequent backup succeeds. The Status
section shows the last attempt, last success, and the failure detail.

## Deployment

`scripts/deploy.py` provisions everything on the server:

- Installs `cifs-utils` (for `mount.cifs`).
- Writes `idp-backup.service`, `idp-backup.timer`, and `idp-restore@.service` to
  `/etc/systemd/system/` and enables the timer.
- Installs a validated sudoers rule at `/etc/sudoers.d/idp-backup` that lets the
  unprivileged service user start **only** those units and run the connection
  test — nothing else.
