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
| Access audit log | `data/audit.log` | Confidential (PII: usernames, IPs) | Append-only file; centralise + rotate in prod | Per retention policy |
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

`data/audit.log` is append-only JSON. In production:

- Ship it to a central, access-controlled log store (tamper-evidence).
- Rotate locally (e.g. `logrotate`) to bound disk use.
- Alert on: repeated `rate_limited` / `invalid_credentials`, any `mutation`
  event granting `idpadmin` (`grant_idpadmin`), `restore` events, and backup
  failures.

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
