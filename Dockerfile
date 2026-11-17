# syntax=docker/dockerfile:1
# DataCon Control Plane Image (REQ-05, REQ-10, TC-10)
# Base image pinned by the digest observed from the registry at build time:
#   docker pull python:3.12-slim-bookworm
#   docker inspect python:3.12-slim-bookworm --format '{{json .RepoDigests}}'
# tests/contract/test_release_workflow.py asserts both stages use this exact
# digest; PR CI builds the image so a stale or missing digest fails the build.
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS builder

# The builder venv lives at /app/.venv, exactly where the runtime stage copies
# it. uv writes absolute shebangs into console scripts, so building in /build
# and copying to /app produced an unrunnable `datacon` entry point.
WORKDIR /app

COPY requirements-ci.txt pyproject.toml uv.lock README.md ./
COPY src ./src

RUN python -m pip install --no-cache-dir --disable-pip-version-check \
        --require-hashes --only-binary :all: -r requirements-ci.txt \
    && uv sync --frozen --no-dev --no-editable \
    && uv build --wheel --out-dir /dist

FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATACON_RUN_ROOT=/var/lib/datacon/runs \
    DATACON_EVIDENCE_ROOT=/var/lib/datacon/evidence \
    DATACON_STAGING_ROOT=/var/lib/datacon/staging \
    DATACON_JOURNAL_SECRET_FILE=/etc/datacon/journal-secret

WORKDIR /app

# The authoritative worker needs the Docker CLI, git and clang at runtime. The
# packages are installed here rather than mounted so `docker run ... worker`
# fails with a clear message instead of a missing-binary traceback.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates clang docker.io git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/.venv /app/.venv
COPY migrations /app/migrations
COPY examples /app/examples
COPY src/datacon/data/seccomp/default.json /app/seccomp/default.json
COPY docker-entrypoint.sh /usr/local/bin/datacon-entrypoint
RUN chmod 0755 /usr/local/bin/datacon-entrypoint

ENV PATH="/app/.venv/bin:${PATH}"

RUN mkdir -p /var/lib/datacon/runs /var/lib/datacon/evidence /var/lib/datacon/staging /etc/datacon \
    && chown -R 65534:65534 /var/lib/datacon /etc/datacon /app

USER 65534:65534

ENTRYPOINT ["/usr/local/bin/datacon-entrypoint"]
CMD ["--help"]
