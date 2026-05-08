# Installation

## Requirements

- Python 3.10+
- OpenSSL (for certificate generation)

## Install the package

```bash
git clone <repo>
cd identity-provider-server
pip install -e .              # runtime dependencies only
pip install -e ".[dev]"       # also installs pytest, pytest-cov, ruff, mypy
pip install -e ".[bcrypt]"    # adds bcrypt password hashing support
pip install -e ".[all]"       # everything (dev + bcrypt)
```

Or use the Makefile:

```bash
make install    # runtime only
make dev        # all dependencies
```

## Run the tests

```bash
make test                                # all 58 tests
make test-unit                           # unit tests only (fast, no network)
make test-smoke                          # smoke tests only (starts a real server)

# With coverage
python3 -m pytest --cov=identity_provider_server --cov-report=term-missing
```

## Lint and format

```bash
make lint       # check for issues
make format     # auto-format code
```

## Generate a signing certificate

The IdP signs every SAML assertion with a private key. AWS verifies the signature using the public certificate registered in IAM. Generate a self-signed certificate once per deployment:

```bash
make cert
```

Or manually:

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout data/idp.key \
  -out data/idp.crt \
  -days 3650 -nodes \
  -subj "/CN=local-idp"
```

Keep `idp.key` private. `idp.crt` is public and will be uploaded to AWS.

> If you regenerate the certificate you must re-register the IdP in AWS IAM and update the trust policies on all associated roles.

## Register the IdP in AWS IAM

This is a one-time step per AWS account.

**1. Start the server**

```bash
identity-provider-server
```

**2. Download the metadata**

```bash
curl http://localhost:5000/metadata -o metadata.xml
```

**3. Create the SAML provider in IAM**

In the AWS console:

1. Go to **IAM → Identity providers → Add provider**
2. Select **SAML**
3. Provider name: `local-idp` (must match `--provider-name`, default is `local-idp`)
4. Upload `metadata.xml`
5. Click **Add provider**

Or with the AWS CLI:

```bash
aws iam create-saml-provider \
  --name local-idp \
  --saml-metadata-document file://metadata.xml
```

Note the returned ARN — you'll need it when creating roles.

## Create an IAM role for SAML federation

For each role a user should be able to assume:

**1. Create a trust policy file** (`trust.json`):

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

**2. Create the role**:

```bash
aws iam create-role \
  --role-name topaztestrole \
  --assume-role-policy-document file://trust.json
```

**3. Attach permissions** (example — read-only):

```bash
aws iam attach-role-policy \
  --role-name topaztestrole \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

**4. Add the user and role mapping to `data/users.json`** — see [Configuration](configuration.md).

## Docker installation

```bash
docker build -t identity-provider-server .
docker run -v /path/to/data:/data -p 5000:5000 identity-provider-server
```

Or with Docker Compose:

```bash
docker compose up
```

See [How-to: Run with Docker Compose](howto.md#run-with-docker-compose) for details.
