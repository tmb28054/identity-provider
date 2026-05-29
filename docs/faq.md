# FAQ

## Login and authentication

**Q: I get "Invalid credentials" but my username and password look correct.**

Check for trailing whitespace in `users.json`. Passwords are compared as exact strings (or verified against bcrypt hashes). Also confirm the file is valid JSON — the server hot-reloads it on each request, so syntax errors will prevent login.

---

**Q: I get "Too many attempts. Try again later."**

The server rate-limits login attempts to 5 per IP address per 60 seconds. Wait a minute and try again, or restart the server to clear the rate limiter state.

---

**Q: The login form submits but I land on an AWS error page saying "Your request included an invalid SAML response."**

The most common causes:

1. The SAML provider in IAM was registered with a different certificate than the one currently in `data/idp.crt`. Re-download `/metadata` and update the provider (see [Rotate the signing certificate](howto.md#rotate-the-signing-certificate)).
2. The role ARN in `users.json` doesn't match an actual IAM role. Verify the `account_id` and `role` values.
3. The IAM role's trust policy doesn't reference the correct SAML provider ARN or is missing the `sts:AssumeRoleWithSAML` action.
4. The `--provider-name` doesn't match the SAML provider name in AWS IAM (default: `local-idp`).

---

**Q: AWS shows a role-selection screen I didn't expect.**

The user has more than one entry in their `roles` array in `users.json`. AWS always shows the selector when more than one role is present in the assertion. Remove the roles the user shouldn't see.

---

**Q: The session expires after 1 hour. Can I extend it?**

Use the `--session-duration` flag to set a longer validity (up to 12 hours):

```bash
identity-provider-server --session-duration 8
```

AWS caps SAML-federated sessions at 12 hours regardless. The effective limit is also controlled by the IAM role's `MaxSessionDuration` setting:

```bash
aws iam update-role --role-name topaztestrole --max-session-duration 43200
```

---

**Q: How do I use bcrypt password hashes?**

1. Install the bcrypt dependency: `pip install -e ".[bcrypt]"`
2. Generate a hash: `idp-hash-password "mypassword"`
3. Put the hash (starting with `$2b$`) in the `password` field of `users.json`

Plaintext passwords still work for backward compatibility.

---

## AWS IAM setup

**Q: What exact trust policy does the IAM role need?**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<account_id>:saml-provider/local-idp"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
```

Replace `<account_id>` with your 12-digit AWS account ID. If you used a custom `--provider-name`, replace `local-idp` with that name.

---

**Q: I created the SAML provider but AWS says it doesn't exist.**

Confirm the provider name in IAM exactly matches the `--provider-name` value (default: `local-idp`). The ARN format is `arn:aws:iam::<account_id>:saml-provider/<provider-name>`. Check with:

```bash
aws iam list-saml-providers
```

---

**Q: Do I need to register the IdP separately in every AWS account?**

Yes. Each account needs its own SAML provider and its own IAM roles with trust policies. The same `idp.crt` / `idp.key` pair can be reused across accounts.

---

## Server and networking

**Q: The server starts but I can't reach it from another machine.**

By default the server binds to `127.0.0.1` (loopback only). To accept connections from other hosts:

```bash
identity-provider-server --host 0.0.0.0
```

Note: changing the host/port changes the IdP entity ID in the metadata. You'll need to re-register the metadata in AWS IAM.

---

**Q: Can I run this behind a reverse proxy (nginx, Caddy)?**

Yes. Point the proxy at `127.0.0.1:5000`. If you terminate TLS at the proxy, you should set `--host` and `--port` to match the public-facing URL so the metadata entity ID is correct, then re-register the metadata in AWS IAM.

---

**Q: Port 5000 is already in use.**

```bash
identity-provider-server --port 8080
```

On macOS, port 5000 is used by AirPlay Receiver. Disable it in **System Settings → General → AirDrop & Handoff**, or just use a different port.

---

**Q: How do I check if the server is healthy?**

Hit the health check endpoint:

```bash
curl http://localhost:5000/health
# {"status":"healthy"}
```

This is also used by Docker's `HEALTHCHECK` and load balancers.

---

## Data files

**Q: Can I store `users.json` outside the repo?**

Yes — that's what `--data-dir` is for:

```bash
identity-provider-server --data-dir ~/.secret/idp/
```

---

**Q: Is it safe to commit `data/` to git?**

No. `idp.key` is a private key and `users.json` contains passwords. Both are excluded via `.gitignore`. `idp.crt` is public and safe to commit if useful.

---

**Q: Can I hot-reload `users.json` without restarting?**

Yes — the server checks the file modification time on each request and reloads automatically if the file has changed.

---

## Multi-service-provider routing

**Q: How do I serve multiple applications from one IdP?**

Create a `data/services.yaml` file that maps paths to service providers:

```yaml
saml:
  aws: https://signin.aws.amazon.com/saml
  gitlab: https://gitlab.corp.com/users/auth/saml/callback

oauth:
  docs: https://docs.corp.com/
```

Each entry becomes a route on the server. See [Configuration — services.yaml](configuration.md#service-provider-routing-servicesyaml).

---

**Q: What happens if `services.yaml` doesn't exist?**

The server falls back to a single `/aws` route with the default AWS SAML configuration. This is fully backward compatible with v1.x behavior.

---

**Q: How does OAuth token delivery work?**

After successful authentication on an OAuth path, the server issues a signed JWT (RS256) and redirects the user to the SP URL with `?token=<jwt>`. The SP validates the token using the IdP's public certificate (`idp.crt`).

---

**Q: Can I mix SAML and OAuth service providers?**

Yes. Define SAML SPs under the `saml:` key and OAuth SPs under the `oauth:` key in `services.yaml`. Each gets its own route and protocol handling.

---

**Q: How do I validate the OAuth JWT in my application?**

The JWT is signed with RS256 using `idp.key`. Verify it with the public key from `idp.crt`. Key claims:
- `iss` — IdP entity ID
- `sub` — authenticated username
- `aud` — the `client_id` from services.yaml (defaults to the path name)
- `exp` — expiration timestamp
- `scope` — granted scopes
- `groups` — AD group memberships (ADFS mode only)

---

## ADFS / LDAP authentication

**Q: I get "Failed to bind to LDAP server" in the logs.**

Check that:
1. The `host` in your ADFS config is reachable from the server (try `telnet <host> 636` for LDAPS or port 389 for LDAP).
2. The service account `username` and `password` are correct.
3. If using `ldaps://`, the server's TLS certificate is trusted. Use `--skip-ldap-ssl-verify` for self-signed certs.

---

**Q: ADFS authentication works but I get "No AWS roles mapped to your groups."**

The user authenticated successfully against AD, but none of their group memberships matched entries in `group_roles.yaml`. Check:
1. The `group_roles.yaml` file exists in the data directory.
2. The group names in the file match the AD group CNs exactly (case-sensitive).
3. The user is actually a member of the expected groups in AD.

Use `-vv` to see which groups were returned for the user.

---

**Q: What is `--skip-ldap-ssl-verify` for?**

It disables TLS certificate verification on the LDAP connection. Use it when your AD server has a self-signed certificate or uses an internal CA that isn't in the system trust store:

```bash
identity-provider-server --adfs-config data/adfs_config.yaml --skip-ldap-ssl-verify
```

This only takes effect when the host uses `ldaps://`. Not recommended for production — install the CA certificate on the server instead.

---

**Q: Can I use ADFS mode with Kubernetes?**

Yes. Store the ADFS config in a Kubernetes Secret (it contains a password) and mount it into the pod. Add `--adfs-config /data/adfs_config.yaml` to the container command. Put `group_roles.yaml` in the ConfigMap alongside `config.yaml`.

---

**Q: The ADFS config file doesn't exist and the server exits immediately.**

When running non-interactively (e.g. in a container), the server can't prompt for input. Create the ADFS config file before starting the server. See `data/adfs_config.yaml.example` for the format.

---

## Docker

**Q: How do I run with Docker Compose?**

```bash
docker compose up
```

This builds the image, mounts `./data` as the data volume, and exposes port 5000. Set `SECRET_KEY` in your environment or a `.env` file for consistent CSRF tokens across restarts.

---

**Q: The Docker health check is failing.**

The health check hits `GET /health` inside the container. If it fails, the server likely isn't starting — check the container logs:

```bash
docker compose logs idp
```

Common causes: missing data files in the mounted volume, or permission issues on `idp.key`.
