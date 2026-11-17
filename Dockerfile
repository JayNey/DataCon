# syntax=docker/dockerfile:1
# DataCon Control Plane Image (REQ-05, REQ-10, TC-10)
# Base image pinned by immutable sha256 digest (python:3.12-slim-bookworm).
FROM python:3.12-slim-bookworm@sha256:9c1d9a2232510a24b3388318075c352328562e635f275f44196c81401760b52f AS builder

WORKDIR /build

COPY requirements-ci.txt pyproject.toml uv.lock README.md ./
COPY src ./src

RUN python -m pip install --no-cache-dir --disable-pip-version-check \
        --require-hashes --only-binary :all: -r requirements-ci.txt \
    && uv sync --frozen --no-dev --no-editable \
    && uv build --wheel --out-dir /dist

FROM python:3.12-slim-bookworm@sha256:9c1d9a2232510a24b3388318075c352328562e635f275f44196c81401760b52f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATACON_RUN_ROOT=/var/lib/datacon/runs \
    DATACON_EVIDENCE_ROOT=/var/lib/datacon/evidence \
    DATACON_STAGING_ROOT=/var/lib/datacon/staging \
    DATACON_JOURNAL_SECRET_FILE=/etc/datacon/journal-secret

WORKDIR /app

COPY --from=builder /build/.venv /app/.venv
COPY migrations /app/migrations
COPY examples /app/examples
COPY src/datacon/data/seccomp/default.json /app/seccomp/default.json

ENV PATH="/app/.venv/bin:${PATH}"

RUN mkdir -p /var/lib/datacon/runs /var/lib/datacon/evidence /var/lib/datacon/staging /etc/datacon \
    && chown -R 65534:65534 /var/lib/datacon /etc/datacon /app

USER 65534:65534

ENTRYPOINT ["datacon"]
CMD ["--help"]
