# Pin the base image to a specific patch release. For stronger supply-chain
# integrity, pin by digest instead, e.g.:
#   FROM python:3.13.7-slim@sha256:<digest>
# Resolve the digest with: docker buildx imagetools inspect python:3.13.7-slim
FROM python:3.13.7-slim

# Create an unprivileged user to run the service (never run as root).
RUN groupadd --system idp && useradd --system --gid idp --home /app idp

WORKDIR /app

COPY pyproject.toml CHANGELOG.md ./
COPY identity_provider_server/ identity_provider_server/

RUN pip install --no-cache-dir .

# /data holds secrets (signing key, user DB); owned by the service user.
RUN mkdir -p /data && chown -R idp:idp /data /app
VOLUME /data

EXPOSE 5000

USER idp

HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=5s \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')"

ENTRYPOINT ["gunicorn"]
# Single worker: in-memory rate-limit and single-use nonce state is per-process.
# Behind a TLS-terminating proxy, so ProxyFix + Secure cookies apply.
CMD ["--bind", "0.0.0.0:5000", "--workers", "1", "--access-logfile", "-", "identity_provider_server:create_app('/data')"]
