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
# hadolint ignore=DL3018
RUN apk upgrade --no-cache \
    && apk add --no-cache \
    nodejs \
    npm \
    build-base \
    git \
    curl \
    && npm install -g npm@latest \
    && npm cache clean --force

# Smoke test: Verify versions
RUN python3 --version && \
    node --version && \
    npm --version

USER ragnarsec
WORKDIR /app
