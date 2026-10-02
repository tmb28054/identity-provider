# Incident Response & Communication Plan

This plan covers who to notify, how, and when if the identity provider is
compromised or its availability/integrity is affected. It complements
`docs/security-remediation-plan.md` (which covers technical remediation steps)
by defining the **communication** obligations the security review found missing.

The IdP processes PII (usernames, email addresses, source IPs, AD group
memberships — see `docs/security.md`) and federates access into third-party
relying parties by minting signed SAML assertions and OAuth JWTs. A compromise
of `data/idp.key` or `data/users.json` is therefore a breach affecting every
relying party and every data subject.

## Severity levels

| Level | Example | Target first-notification time |
|-------|---------|-------------------------------|
| Critical | Signing key (`idp.key`) or user DB (`users.json`) disclosure; unauthorized `idpadmin` grant | within 1 hour |
| High | Admin account takeover; backup destination repointed; repeated auth-bypass attempts | within 4 hours |
| Medium | Backup failures over multiple cycles; LDAP/AD outage affecting auth | within 1 business day |

## Stakeholders to notify

Fill in the concrete contacts for your deployment. These are the roles the
system's trust depends on:

| Role | Who | Channel | Notify when |
|------|-----|---------|-------------|
| IdP operator / owner | **Topaz Bott** | (email / phone) | all severities |
| Relying-party owners | per-SP `owner_contact` in `services.yaml` | email | key compromise, SP mis-registration |
| AD / directory owner | (fill in) | email | ADFS-mode auth incidents |
| SMB file-server operator | (fill in) | email | backup destination incidents |
| CDN / DNS operator | (fill in) | email | availability / routing incidents |
| Data-protection officer / regulator | (fill in) | per policy | personal-data breach (per applicable law) |

Per-relying-party contacts live in the SP registry: each `services.yaml`
entry supports an `owner_contact` field (see below), so the system records who
to tell for each relying party whose trust depends on `idp.key`.

```yaml
oauth:
  wiki:
    url: https://wiki.corp.com/auth/callback
    owner_contact: platform-team@corp.com
saml:
  aws:
    url: https://signin.aws.amazon.com/saml
    owner_contact: cloud-ops@corp.com
```

## Outbound notification channel

The workload can emit outbound notifications so recovery status does not depend
on an administrator opening the admin panel. Configure a webhook:

```bash
# Any HTTPS endpoint that accepts a JSON POST
export IDP_NOTIFY_WEBHOOK="https://hooks.example.com/services/XXXX"
```

Payload shape:

```json
{"event": "backup_failed", "severity": "critical", "message": "..."}
```

Events currently emitted:

- `backup_failed` (critical) — a nightly backup failed.
- `grant_idpadmin` (warning) — an account was granted the `idpadmin` claim.

When `IDP_NOTIFY_WEBHOOK` is unset, notifications are a no-op (the events are
still written to the audit log). Sends are best-effort and never block the
triggering operation.

## Message templates

**Incident (critical) — initial**

> Subject: [IdP INCIDENT] <summary>
> We are investigating a security incident affecting the identity provider at
> idp.botthouse.net detected at <time>. Potential impact: <scope>. Affected
> relying parties: <list>. We will send an update by <time>.

**Recovery — progress**

> Subject: [IdP INCIDENT] Update — <summary>
> Status: <contained / remediating / resolved>. Actions taken: <list>.
> Required of you: <e.g. re-register IdP metadata after key rotation>.
> Next update by <time>.

## Procedure

1. Detect & triage — determine severity from the table above.
2. Contain — follow `docs/security-remediation-plan.md` (rotate `idp.key`,
   disable affected accounts — which now revokes their sessions immediately via
   the session-epoch bump, review `data/audit.log`).
3. Notify — send the initial notification to the stakeholders for that severity
   within the target time, using the templates above.
4. Recover — restore from a verified (encrypted, digest-checked) backup if
   needed; re-register IdP metadata with relying parties if the signing key was
   rotated.
5. Communicate recovery — send progress/closure updates.
6. Post-incident — record a timeline and lessons learned.
