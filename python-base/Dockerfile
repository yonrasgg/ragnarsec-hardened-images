ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI metadata (build-time args populated by CI; defaults for local builds)
ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec Python Base (Alpine 3.21 + Python 3)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/python-base" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# SECURITY: Upgrade system packages to patch CVEs, then install Python.
# hadolint ignore=DL3018
RUN apk upgrade --no-cache \
    && apk add --no-cache \
    python3 \
    py3-pip \
    && ln -sf /usr/bin/python3 /usr/bin/python

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/app/venv \
    PATH="/app/venv/bin:$PATH"

# Create virtual environment as ragnarsec user and upgrade core packages
USER ragnarsec
# hadolint ignore=DL3013
RUN python3 -m venv $VIRTUAL_ENV \
    && pip install --upgrade pip setuptools wheel

WORKDIR /app
CMD ["python3"]
