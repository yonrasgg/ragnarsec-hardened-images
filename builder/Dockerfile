ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-python-base:${BASE_TAG}

# OCI metadata (build-time args populated by CI; defaults for local builds)
ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec Hybrid Builder: Python 3 + Node.js LTS" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/builder" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# SECURITY: Upgrade system packages to patch CVEs, then install build tools + Node.js.
# Alpine ships Node.js LTS natively — no external repo (NodeSource) needed.
ARG UNDICI_VERSION=6.29.1
ARG UNDICI_SHA256=29c4b8e0b2d86cb8795571c1959012ce057a14ecfd34858335f47c31e770a04f
# hadolint ignore=DL3018
RUN apk upgrade --no-cache \
    && apk add --no-cache \
    nodejs \
    npm \
    build-base \
    git \
    curl \
    && npm install -g npm@latest \
    && curl -fsSLo /tmp/undici.tgz \
        "https://registry.npmjs.org/undici/-/undici-${UNDICI_VERSION}.tgz" \
    && printf '%s  %s\n' "${UNDICI_SHA256}" /tmp/undici.tgz > /tmp/undici.tgz.sha256 \
    && sha256sum -c /tmp/undici.tgz.sha256 \
    && rm -rf /usr/local/lib/node_modules/npm/node_modules/undici \
    && mkdir -p /usr/local/lib/node_modules/npm/node_modules/undici \
    && tar -xzf /tmp/undici.tgz -C /usr/local/lib/node_modules/npm/node_modules/undici --strip-components=1 \
    && rm -f /tmp/undici.tgz /tmp/undici.tgz.sha256 \
    && npm cache clean --force

# Smoke test: Verify versions
RUN python3 --version && \
    node --version && \
    npm --version

USER ragnarsec
WORKDIR /app
