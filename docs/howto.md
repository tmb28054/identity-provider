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

Requires the bcrypt extra: `pip install -e ".[bcrypt]"`

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

```bash
# Different port
identity-provider-server --port 8443

# Accessible from other machines (e.g. for team use)
identity-provider-server --host 0.0.0.0 --port 5000
```

> When changing the host/port, the IdP entity ID in the metadata changes automatically. Re-register the metadata in AWS IAM after changing these values.

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
ExecStart=/usr/local/bin/identity-provider-server --data-dir /etc/idp/ -v
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
