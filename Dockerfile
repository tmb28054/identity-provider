# Pin the base image by immutable digest, not just the mutable tag, so the
# build always resolves the exact image that was reviewed. The tag is kept in
# the comment for human readability.
# Re-pin after a deliberate base-image bump with:
#   docker buildx imagetools inspect python:3.13.7-slim
# tag: python:3.13.7-slim
FROM python:3.13.7-slim@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0

# Create an unprivileged user to run the service (never run as root).
RUN groupadd --system idp && useradd --system --gid idp --home /app idp

WORKDIR /app

COPY pyproject.toml CHANGELOG.md constraints.txt ./
COPY identity_provider_server/ identity_provider_server/

# Install against the pinned constraint set (the SBOM anchor) so the image
# resolves the same versions the CI test job verifies, rather than whatever
# PyPI serves at build time inside the open-ended ranges in pyproject.toml.
RUN pip install --no-cache-dir -c constraints.txt .

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
