# Installation

## Requirements

- Python 3.10+
- OpenSSL (for certificate generation)

## Install the package

```bash
git clone <repo>
cd identity-provider-server
pip install -e .              # runtime dependencies (includes bcrypt)
pip install -e ".[dev]"       # also installs pytest, pytest-cov, ruff, mypy
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

---

## Kubernetes installation

This section walks through deploying the identity provider server on a Kubernetes cluster. Complete example manifests are in `examples/kubernetes/`.

### Prerequisites

- A Kubernetes cluster (1.24+)
- `kubectl` configured to talk to your cluster
- An ingress controller installed (e.g. nginx-ingress, Traefik, or AWS ALB)
- A container registry accessible from the cluster

### 1. Build and push the container image

```bash
docker build -t <your-registry>/identity-provider-server:latest .
docker push <your-registry>/identity-provider-server:latest
```

### 2. Generate the signing certificate

If you don't already have a certificate, generate one:

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout idp.key \
  -out idp.crt \
  -days 3650 -nodes \
  -subj "/CN=my-corp-idp"
```

### 3. Prepare your configuration

Copy the example manifests and customize them:

```bash
cp -r examples/kubernetes/ my-k8s-deployment/
cd my-k8s-deployment/
```

### 4. Create the Secret

Edit `secret.yaml` with your actual values:

- `SECRET_KEY` — generate with `python3 -c "import secrets; print(secrets.token_hex(32))"`
- `idp.crt` — paste the contents of your signing certificate
- `idp.key` — paste the contents of your private key

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: idp-secrets
  namespace: identity-provider
type: Opaque
stringData:
  SECRET_KEY: "your-generated-secret-key"
  idp.crt: |
    -----BEGIN CERTIFICATE-----
    ...your certificate...
    -----END CERTIFICATE-----
  idp.key: |
    -----BEGIN PRIVATE KEY-----
    ...your private key...
    -----END PRIVATE KEY-----
```

> For production, consider using an external secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault, or Sealed Secrets) instead of storing secrets directly in manifests.

### 5. Configure the ConfigMap

Edit `configmap.yaml` with your settings:

- Update `config.yaml` with your SAML provider name and desired settings
- Update `users.json` with your users and role mappings (use bcrypt hashes for passwords)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: idp-config
  namespace: identity-provider
data:
  config.yaml: |
    server:
      host: "0.0.0.0"
      port: 5000

    saml:
      provider_name: "my-corp-idp"
      session_duration_hours: 4

    logging:
      level: "INFO"

  users.json: |
    [
      {
        "username": "admin",
        "password": "$2b$12$...",
        "roles": [
          {
            "account_id": "123456789012",
            "role": "AdminRole"
          }
        ]
      }
    ]
```

Generate bcrypt password hashes with:

```bash
pip install bcrypt
python3 -c "import bcrypt; print(bcrypt.hashpw(b'your-password', bcrypt.gensalt()).decode())"
```

Or if the package is installed locally:

```bash
idp-hash-password "your-password"
```

### 6. Configure the Deployment

Edit `deployment.yaml`:

- Update the `image` field to point to your container registry
- Adjust `replicas` based on your availability needs
- Tune `resources` requests/limits for your workload

```yaml
containers:
  - name: idp
    image: <your-registry>/identity-provider-server:latest
    # ...
```

The deployment includes:

- **Gunicorn** — production WSGI server (2 workers by default)
- **Liveness probe** — restarts the pod if `/health` stops responding
- **Readiness probe** — removes the pod from service during startup
- **Security context** — runs as non-root with a read-only filesystem
- **Resource limits** — prevents runaway memory/CPU usage

### 7. Configure Ingress

Edit `ingress.yaml`:

- Set your hostname (e.g. `idp.example.com`)
- Configure TLS (strongly recommended — credentials are sent over this connection)
- Adjust annotations for your ingress controller

```yaml
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - idp.example.com
      secretName: idp-tls
  rules:
    - host: idp.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: identity-provider-server
                port:
                  number: 80
```

For TLS, you can use [cert-manager](https://cert-manager.io/) to automatically provision certificates:

```yaml
metadata:
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
```

### 8. Deploy

Apply everything with Kustomize:

```bash
kubectl apply -k my-k8s-deployment/
```

Or apply individual files:

```bash
kubectl apply -f namespace.yaml
kubectl apply -f secret.yaml
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml
```

### 9. Verify the deployment

```bash
# Check pods are running
kubectl -n identity-provider get pods

# Check the service
kubectl -n identity-provider get svc

# View logs
kubectl -n identity-provider logs -l app.kubernetes.io/name=identity-provider-server

# Test the health endpoint (port-forward for quick check)
kubectl -n identity-provider port-forward svc/identity-provider-server 5000:80
curl http://localhost:5000/health
```

### 10. Register the IdP in AWS IAM

Once the server is accessible, download the metadata and register it:

```bash
curl https://idp.example.com/metadata -o metadata.xml

aws iam create-saml-provider \
  --name my-corp-idp \
  --saml-metadata-document file://metadata.xml
```

Then create IAM roles with SAML trust policies as described in [Register the IdP in AWS IAM](#register-the-idp-in-aws-iam) above.

### Updating configuration

To update users or settings without redeploying:

```bash
# Edit the ConfigMap
kubectl -n identity-provider edit configmap idp-config

# Restart pods to pick up changes
kubectl -n identity-provider rollout restart deployment/identity-provider-server
```

> Note: `users.json` changes are hot-reloaded automatically if the file's modification time changes. However, ConfigMap volume mounts may take up to 60 seconds to propagate updates to pods. A rollout restart guarantees immediate pickup.

### Production considerations

| Concern | Recommendation |
|---------|----------------|
| TLS | Always terminate TLS at the ingress. Credentials are sent in plaintext HTTP between browser and server. |
| Secrets | Use Sealed Secrets, External Secrets Operator, or a vault integration instead of plain Kubernetes Secrets. |
| High availability | Run 2+ replicas. The server is stateless (rate limiting is per-pod, not shared). |
| Monitoring | Scrape the `/health` endpoint. Add Prometheus annotations if using a service monitor. |
| Network policy | Restrict ingress to the ingress controller only. Restrict egress to AWS endpoints. |
| Image tags | Use immutable tags (e.g. `v1.0.0`) instead of `latest` in production. |
| RBAC | The pods need no Kubernetes API access. Set `automountServiceAccountToken: false` if desired. |
| Scaling | The server is lightweight. A single pod handles hundreds of concurrent logins. Scale for availability, not throughput. |
