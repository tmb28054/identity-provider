# How-to guides

## Add a new user

Edit `data/users.json` and append a new object to the array:

```json
[
  {
    "username": "topaztest",
    "password": "$2b$12$...",
    "roles": [
      { "account_id": "711387107691", "role": "topaztestrole" }
    ]
  },
  {
    "username": "newuser",
    "password": "$2b$12$...",
    "roles": [
      { "account_id": "711387107691", "role": "ReadOnlyRole" }
    ]
  }
]
```

Generate the password hash with:

```bash
idp-hash-password "somepassword"
```

The server hot-reloads `users.json` automatically — no restart needed.

---

## Hash passwords for users.json

The `idp-hash-password` CLI command generates bcrypt hashes:

```bash
# Interactive (prompts securely, no echo)
idp-hash-password

# Inline (useful for scripting)
idp-hash-password "mypassword"

# Custom cost factor (higher = slower but more secure)
idp-hash-password --rounds 14
```

Requires the bcrypt package (installed automatically with the server).

---

## Grant a user access to a role in a different account

Add an entry to the user's `roles` array with the target account ID and role name. The IAM role in that account must have a trust policy that references the SAML provider — see [Installation](installation.md#create-an-iam-role-for-saml-federation).

```json
"roles": [
  { "account_id": "111122223333", "role": "DevRole" },
  { "account_id": "444455556666", "role": "ReadOnlyRole" }
]
```

When the user logs in, AWS presents a role-selection screen.

---

## Use a custom SAML provider name

By default the server uses `local-idp` as the SAML provider name in role ARNs. To use a different name:

```bash
identity-provider-server --provider-name my-corp-idp
```

Make sure the SAML provider in AWS IAM is registered with the same name, and that IAM role trust policies reference `arn:aws:iam::<account>:saml-provider/my-corp-idp`.

---

## Extend session duration

The default SAML assertion validity is 1 hour. To extend it:

```bash
identity-provider-server --session-duration 8
```

Also update the IAM role's `MaxSessionDuration`:

```bash
aws iam update-role --role-name myrole --max-session-duration 28800
```

AWS caps SAML sessions at 12 hours maximum.

---

## Use a custom data directory

Keep credentials outside the repo:

```bash
identity-provider-server --data-dir /etc/idp/
```

The directory must contain `users.json`, `idp.crt`, and `idp.key`.

---

## Run on a non-default port or expose to the network

**Production (gunicorn):**

```bash
# Listen on port 8080 with 4 workers
gunicorn "identity_provider_server:create_app('data')" -b 0.0.0.0:8080 -w 4
```

**Development (Flask dev server):**

```bash
# Different port
identity-provider-server --port 8443

# Accessible from other machines
identity-provider-server --host 0.0.0.0 --port 5000
```

> When changing the host/port, the IdP entity ID in the metadata changes automatically. Re-register the metadata in AWS IAM after changing these values.

---

## Run with gunicorn (production)

The `identity-provider-server` CLI uses Flask's built-in development server which is not suitable for production. Use gunicorn instead:

```bash
# Basic — 2 workers, bind to all interfaces
gunicorn "identity_provider_server:create_app('data')" -b 0.0.0.0:5000 -w 2

# With access logging
gunicorn "identity_provider_server:create_app('data')" \
  -b 0.0.0.0:5000 -w 2 --access-logfile -

# Custom data directory
gunicorn "identity_provider_server:create_app('/etc/idp')" -b 0.0.0.0:5000

# With ADFS (pass config via environment or mount the file)
gunicorn "identity_provider_server:create_app('/data')" -b 0.0.0.0:5000
```

For ADFS mode with gunicorn, the app reads `services.yaml`, `config.yaml`, and all data files from the directory passed to `create_app()`. The `--adfs-config` CLI flag is only for the development server — in production, place `adfs_config.yaml` in the data directory and start with:

```bash
gunicorn "identity_provider_server:create_app('/data', adfs_config={'host': 'ldaps://dc.corp.com', ...})" \
  -b 0.0.0.0:5000
```

Or better, use the CLI wrapper for complex configurations:

```bash
identity-provider-server --data-dir /data --adfs-config /data/adfs_config.yaml &
```

### Gunicorn configuration file

For production deployments, create a `gunicorn.conf.py`:

```python
bind = "0.0.0.0:5000"
workers = 2
accesslog = "-"
errorlog = "-"
loglevel = "info"
```

Then run:

```bash
gunicorn "identity_provider_server:create_app('data')" -c gunicorn.conf.py
```

---

## Run with Docker Compose

```bash
# Start in foreground
docker compose up

# Start in background
docker compose up -d

# View logs
docker compose logs -f idp

# Stop
docker compose down
```

The `docker-compose.yml` mounts `./data` as the data volume and exposes port 5000. Set `SECRET_KEY` in a `.env` file for consistent CSRF tokens:

```bash
echo "SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" > .env
```

---

## Run as a systemd service (Linux)

Create `/etc/systemd/system/identity-provider.service`:

```ini
[Unit]
Description=Identity Provider Server
After=network.target

[Service]
ExecStart=/usr/local/bin/gunicorn "identity_provider_server:create_app('/etc/idp')" -b 0.0.0.0:5000 -w 2 --access-logfile -
Restart=on-failure
User=idp
Environment=SECRET_KEY=your-secret-key-here

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now identity-provider.service
```

---

## Run with a launchd plist (macOS)

Create `~/Library/LaunchAgents/com.local.idp.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.local.idp</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/identity-provider-server</string>
    <string>--data-dir</string>
    <string>/Users/yourname/.idp/</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/tmp/idp.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/idp.err</string>
</dict>
</plist>
```

```bash
launchctl load ~/Library/LaunchAgents/com.local.idp.plist
```

---

## Rotate the signing certificate

1. Generate a new certificate:

```bash
make cert
# or:
# openssl req -x509 -newkey rsa:2048 \
#   -keyout data/idp.key -out data/idp.crt \
#   -days 3650 -nodes -subj "/CN=local-idp"
```

2. Download fresh metadata:

```bash
# Start server with new cert first
identity-provider-server
curl http://localhost:5000/metadata -o metadata.xml
```

3. Update the SAML provider in each AWS account:

```bash
aws iam update-saml-provider \
  --saml-provider-arn arn:aws:iam::<account_id>:saml-provider/local-idp \
  --saml-metadata-document file://metadata.xml
```

---

## Use the server programmatically (embedding in another app)

`create_app` is a standard Flask application factory:

```python
from identity_provider_server import create_app

app = create_app(
    "/path/to/data/dir",
    host="0.0.0.0",
    port=8080,
    provider_name="my-idp",
    session_duration_hours=4,
)
app.run(port=8080)
```

---

## Set up multi-service-provider routing

Serve multiple applications from a single IdP instance using `services.yaml`:

**1. Create `data/services.yaml`:**

```bash
cp data/services.yaml.example data/services.yaml
```

**2. Define your service providers:**

```yaml
saml:
  aws: https://signin.aws.amazon.com/saml
  gitlab: https://gitlab.corp.com/users/auth/saml/callback

oauth:
  docs: https://docs.corp.com/
```

**3. Start the server:**

```bash
identity-provider-server
```

Users can now access:
- `http://localhost:5000/aws` — login for AWS Console (SAML)
- `http://localhost:5000/gitlab` — login for GitLab (SAML)
- `http://localhost:5000/docs` — login for internal docs (OAuth JWT)

The `/metadata` endpoint will list SSO locations for all SAML service providers.

---

## Add an OAuth service provider

OAuth SPs receive a signed JWT token via redirect after authentication:

**1. Add the SP to `data/services.yaml`:**

```yaml
oauth:
  docs:
    url: https://docs.corp.com/auth/callback
    client_id: docs-app
    scopes: ["openid", "profile", "email"]
    token_expiry_minutes: 120
```

**2. Configure your application** to validate the JWT:
- The token is signed with RS256 using the same `idp.key`
- Verify with the public key from `idp.crt`
- The `iss` claim is the IdP entity ID (`http://<host>:<port>/metadata`)
- The `sub` claim is the authenticated username
- The `aud` claim matches the `client_id`
- The `groups` claim contains AD group memberships (ADFS mode only)

---

## Enable and use passkeys (WebAuthn)

Passkeys add a phishing-resistant second factor (Touch ID, Windows Hello, or a
hardware security key) alongside TOTP. See
[Configuration › Passkey authentication](configuration.md#passkey-webauthn-authentication)
for the full option reference and the domain-binding caveat.

**1. Turn passkeys on** (config file or environment):

```yaml
webauthn:
  enabled: true
  rp_id: "idp.botthouse.net"
  rp_name: "Botthouse Identity Provider"
  expected_origin: "https://idp.botthouse.net"
```

`rp_id` and `expected_origin` must match the domain users actually visit.
Changing the domain later invalidates every enrolled passkey.

**2. Enroll a passkey** (each user, once):

- Sign in at `https://<host>/user` with username and password (complete TOTP if
  enabled).
- On the Account Settings page, under **Passkeys**, click **Register a passkey**
  and follow the browser prompt.
- Registered passkeys are listed with a **Remove** button.

**3. Sign in with a passkey:**

- On any service login page (e.g. `/aws`), enter your username.
- Click **Use a passkey** and complete the browser prompt.
- On success you are issued the SAML/OAuth credential and an SSO session, just
  like a password + TOTP login.

Passkeys require local-user mode; they are unavailable when the server runs in
ADFS mode.

**Admin sign-in:** the `/admin` page also offers **Use a passkey**. Enroll a
passkey (step 2) on an account that holds the `idpadmin` claim, then use it to
sign in to the admin panel — the `idpadmin` check and shared session are
identical to the password + MFA form.

**4. (Optional) Go password-less:**

On the Account Settings page, under **Password-less sign-in**, click **Enable
password-less sign-in**. Afterwards you can authenticate with a passkey alone
(no password). To avoid being locked out if a device is lost, the toggle is only
available once the account has a recovery path — **two passkeys**, or **one
passkey plus a password or TOTP**. The account-recovery link flow remains the
fallback if all passkeys are lost.

---

## Set up ADFS/LDAP authentication

Instead of managing users in `users.json`, authenticate against Active Directory:

**1. Install the ADFS dependency:**

```bash
pip install -e ".[adfs]"
```

**2. Create the ADFS config file** (or let the server prompt you):

```bash
cp data/adfs_config.yaml.example data/adfs_config.yaml
# Edit with your AD connection details
```

**3. Create the group-to-role mapping:**

```bash
cp data/group_roles.yaml.example data/group_roles.yaml
```

Edit `group_roles.yaml` to map your AD groups to AWS roles:

```yaml
AWS-Admins:
  - account_id: "123456789012"
    role: "AdminRole"

AWS-Developers:
  - account_id: "123456789012"
    role: "DeveloperRole"
```

**4. Run with ADFS mode:**

```bash
identity-provider-server --adfs-config data/adfs_config.yaml
```

If your AD server uses a self-signed certificate:

```bash
identity-provider-server --adfs-config data/adfs_config.yaml --skip-ldap-ssl-verify
```

---

## Enable verbose logging

Use `-v` for INFO level or `-vv` for DEBUG:

```bash
identity-provider-server -v     # login attempts, reloads
identity-provider-server -vv    # full debug output
```

Logs are JSON-formatted and written to stderr:

```json
{"time":"2025-04-19T10:30:00","level":"INFO","logger":"identity_provider_server.app","message":"Successful login: user=alice from ip=127.0.0.1"}
```

## Back up and restore the server

The signing key, users (with MFA secrets), and service configuration live in
`data/` and are not stored in git. Configure nightly SMB backups and perform
restores from the admin **Backups** page (`/admin/backups`).

See [backups.md](backups.md) for the full guide.
