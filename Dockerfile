# syntax=docker/dockerfile:1
# DataCon Control Plane Image (REQ-05, REQ-10, TC-10)
# Base image pinned by the multi-arch index digest observed from the registry at
# build time (2026-11-18, python 3.12.16-slim-trixie):
#   docker buildx imagetools inspect python:3.12-slim-trixie \
#       --format '{{json .Manifest.Digest}}'
# or, after a pull:
#   docker pull python:3.12-slim-trixie
#   docker inspect python:3.12-slim-trixie --format '{{json .RepoDigests}}'
# Both stages must use the same digest; tests/contract/test_release_workflow.py
# asserts it and PR CI builds the image so a stale or missing digest fails the
# build.
FROM python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS builder

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

FROM python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATACON_RUN_ROOT=/var/lib/datacon/runs \
    DATACON_EVIDENCE_ROOT=/var/lib/datacon/evidence \
    DATACON_STAGING_ROOT=/var/lib/datacon/staging \
    DATACON_JOURNAL_SECRET_FILE=/etc/datacon/journal-secret

WORKDIR /app

# The worker only drives the host daemon over the mounted Docker socket, so the
# runtime layer carries the Docker *client* only. Debian trixie splits it into
# `docker-cli`; `docker.io` would also drag in dockerd, containerd, runc and
# iptables, which are never started here and only enlarge the attack surface.
# `docker-cli` is only a Recommends of `docker.io`, hence the explicit install:
# without it `SandboxUnavailable("docker CLI is not executable")` breaks every
# worker. `clang` is deliberately absent as well: it is only invoked inside the
# pinned silkeh/clang sandbox container (src/datacon/tools/sandbox.py), never
# on the host side of this image, and it dragged in 71 linux-libc-dev findings.
# `git` stays: the worker clones operator-provided local bare repositories.
#
# `zlib1g` and `libzstd1` are requested explicitly because the pinned base
# digest predates their trixie-security updates (`zlib1g`
# 1:1.3.dfsg+really1.3.1-1+deb13u1 for CVE-2026-85091 / gz_vacate heap overflow,
# and `libzstd1` 1.5.7+dfsg-1+deb13u1 for CVE-2026-124851). Both are already
# installed, so this only upgrades them to the fixed copies from
# trixie-security instead of waiving either vulnerability.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates docker-cli git zlib1g libzstd1 \
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
