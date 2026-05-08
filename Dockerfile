FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml CHANGELOG.md ./
COPY identity_provider_server/ identity_provider_server/

RUN pip install --no-cache-dir ".[bcrypt]"

VOLUME /data

EXPOSE 5000

HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=5s \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')"

ENTRYPOINT ["identity-provider-server"]
CMD ["--data-dir", "/data", "--host", "0.0.0.0"]
