# Security Overview

This document records the security posture of the Identity Provider: what data it
holds, the threat model, and the operational controls expected around it. It
complements `docs/security-remediation-plan.md` (which tracks the pentest
findings and their fixes).

## Data inventory and classification

| Data | Location | Classification | Protection | Retention |
|------|----------|----------------|------------|-----------|
| SAML/JWT signing private key | `data/idp.key` | Secret (highest) | 0400, Secret volume, never logged; rotate if exposed | Life of the deployment; rotate on suspicion |
| User records (bcrypt hashes, TOTP secrets) | `data/users.json` | Secret | bcrypt at rest, Secret volume (not ConfigMap) | Until account removed |
| Recovery tokens | `data/recovery_tokens.json` | Secret | 384-bit random, single-use, 24 h expiry | Pruned on expiry/use |
| Backup SMB credentials | `data/backup_config.json` | Secret | 0600 on disk | Until reconfigured |
| Session / admin / step-up tokens | Cookies + hidden fields (transient) | Confidential | HMAC-signed, purpose-scoped, per-purpose key, short TTL | Seconds–hours |
| Access audit log | `data/audit.log` | Confidential (PII: usernames, IPs) | Append-only, hash-chained (keyed by `IDP_AUDIT_CHAIN_KEY`); centralise + rotate in prod | 12 months; most recent 3 months immediately queryable |
| Personal data (username, email) | `data/users.json` | Confidential (PII) | Same as user records | Until account removed |

Personal data handled: usernames, email addresses, source IPs, and AD group
memberships (ADFS mode). No payment or special-category data is processed.

## Threat model (summary)

Assets: the signing key (mints AWS federation credentials), the user database,
and the admin portal (can grant AWS entitlements).

Primary threats and controls:

- **Credential brute force / spraying** → per-IP and per-account rate limiting
  and lockout on every credential endpoint; single-use, time-bound captcha.
- **MFA/password bypass** → the TOTP step requires a signed, single-use ticket
  proving the password step passed; a TOTP code alone cannot authenticate.
- **Token confusion / privilege escalation** → session, admin, and step-up
  tokens are purpose-tagged and signed with per-purpose derived keys, so one
  cannot be replayed as another.
- **Stored/reflected XSS in the admin panel** → strict CSP (no inline script;
  nonce for the one required block), charset-validated identifiers, and no
  server data interpolated into JavaScript.
- **Path traversal via backup subpath** → subpath is charset-validated and
  containment-checked against the mount on both the writer and the root runner.
- **Privileged local compromise** → the web tier runs unprivileged; the root
  backup/restore bridge is reachable only through a narrow, pattern-constrained
  sudoers rule and a hardened systemd unit.
- **Credential theft in transit** → Secure/HttpOnly/SameSite cookies, HSTS, and
  a TLS-terminating proxy; the app binds to loopback behind it.
- **Destructive restore abuse** → restore requires a fresh TOTP code from the
  acting admin (the replayable captcha alternative was removed).

Assumptions / residual risk: a single upstream reverse proxy is trusted for the
client IP (ProxyFix `x_for=1`); in-memory rate-limit and nonce state is
per-process, so run a single worker or add a shared store when scaling out.

## Operational controls

### Time synchronization

Token expiry, TOTP verification, and audit ordering all depend on the local
clock. Run an NTP client (e.g. `systemd-timesyncd` or `chrony`) on the host and
alert on clock drift. In Kubernetes, rely on the node's time sync.

### Log protection and monitoring

`data/audit.log` is append-only JSON, with each record linked to the previous
one by a keyed hash chain (see "Audit-log integrity" below). In production:

- Ship it to a central, access-controlled log store (tamper-evidence).
- Rotate locally (e.g. `logrotate`) to bound disk use.
- Alert on: repeated `rate_limited` / `invalid_credentials`, any `mutation`
  event granting `idpadmin` (`grant_idpadmin`), `restore` events, and backup
  failures.

**Retention.** Retain audit records for **12 months**. Keep at least the most
recent **3 months immediately queryable** (hot); older records may be moved to
cheaper, slower storage so long as they remain retrievable within the retention
window. Local rotation and forwarding to an **external append-only (WORM)**
store are the **operator's responsibility** — the application only writes and
hash-chains the local file; it does not rotate, expire, or forward it.

### Audit-log integrity

Each record carries a keyed `entry_hash` over its own body plus the previous
record's hash, so any truncation or in-place rewrite is detectable by
re-walking the chain. The chain is keyed by a **dedicated** key, resolved
independently of the Flask `SECRET_KEY`:

- `IDP_AUDIT_CHAIN_KEY` if set, otherwise
- a stable per-deployment key stored 0600 at `data/audit_chain.key` (created on
  first start).

Keying the chain separately keeps the log verifiable across restarts and secret
rotation. The chain is verified at startup (a failure fires a `critical`
`audit_chain_invalid` notification) and on every admin audit-log render (a
failure shows an in-page integrity banner). If the key cannot be established the
app fails closed rather than auditing on an ephemeral key.

The in-memory sequence/last-hash cursor is **per-process**: a verifiable chain
assumes the documented **single-worker** topology. Running multiple workers over
one file would require externalising chain state and is out of scope.

### Signing-key and certificate rotation

The signing key (`idp.key`) is a long-lived secret. Establish a rotation
schedule, re-register IdP metadata with service providers after rotation, and
rotate immediately if the key may have been exposed (e.g. via a backup that
reached an untrusted destination).

### Supply chain

Install with pinned versions from `constraints.txt`
(`pip install -e . -c constraints.txt`), pin the container base image by digest,
and run `pip-audit` in CI. `docs/` and CI should treat a secret-scanning failure
as a blocking gate over the whole tree.

### Vulnerability management

Scanning is multi-layered and continuous (`.github/workflows/ci.yml`):

- **Python dependencies** — `pip-audit -c constraints.txt` on every push/PR,
  blocking.
- **Container / OS packages** — a Trivy image scan, blocking on fixable
  HIGH/CRITICAL findings, so base-image CVEs do not accumulate silently.
- **Static analysis** — `bandit` (medium+) and `ruff`, blocking.
- **Secrets** — `gitleaks`, blocking.
- **Schedule** — the full workflow also runs daily (cron), so an advisory
  published between commits is detected without waiting for the next push.

**Risk ranking.** A finding's severity is its CVSS base severity, escalated by
exploitability *in this workload*. A finding in a dependency that sits on the
signing or password path is treated as **Critical regardless of CVSS**, because
it can affect assertion/JWT integrity or credential handling directly. Those
dependencies are: `cryptography` (JWT signing), `lxml` / `signxml` (SAML
assertion signing), `bcrypt` (password hashing), and `pyotp` (TOTP).

**Remediation SLAs** (from detection):

| Severity | Deadline |
|----------|----------|
| Critical | 7 days (sooner if actively exploited) |
| High     | 30 days |
| Medium   | 90 days |
| Low      | next regular maintenance window |

**Triage.** A failed `pip-audit`/Trivy run is triaged by the project owner
(**Topaz Bott**): confirm applicability to this workload, assign a severity per
the ranking above, and either bump the pin in `constraints.txt` / the base-image
digest or record a time-boxed, justified acceptance in the changelog. Dependabot
PRs (`.github/dependabot.yml`) feed the same process weekly.
