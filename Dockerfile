# Pin the base image by immutable digest, not just the mutable tag, so the
# build always resolves the exact image that was reviewed. The tag is kept in
# the comment for human readability.
# Re-pin after a deliberate base-image bump with:
#   docker buildx imagetools inspect python:3.13.7-slim
# tag: python:3.13.7-slim
FROM python:3.14.7-slim@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d

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
# create_app('/data') is the single configuration entry point: it loads
# /data/config.yaml and all IDP_* environment variables itself, so settings
# such as IDP_TRUST_PROXY (ProxyFix) take effect on this gunicorn path.
CMD ["--bind", "0.0.0.0:5000", "--workers", "1", "--access-logfile", "-", "identity_provider_server:create_app('/data')"]
