# syntax=docker/dockerfile:1

# Upstream: Nginx Proxy Manager (jc21/nginx-proxy-manager), MIT licensed.
# This wrapper (Dockerfile, docs, tests) is GPL-3.0 as declared below.
# A tag is not immutable: the digest below is the reviewed index for linux/arm64.
FROM docker.io/jc21/nginx-proxy-manager:2.16.0@sha256:4393e642e233e5efd5adeb7f10918d4aaea71c9ed875b94190273fc8e87f9594

ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="Hardened Nginx Proxy Manager wrapper" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/nginx-proxy-manager" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

# SECURITY: patch Debian packages inherited from the upstream layer.
# This trades build determinism for a smaller known-CVE surface; CI must re-scan
# and the resulting digest must be recorded before any consumer pins it.
# hadolint flags apt-get upgrade as DL3005 because it breaks reproducibility.
# The exception is deliberate: rebuilding by digest does not patch packages that
# the upstream layer already shipped, and this image exposes a network service.
# hadolint ignore=DL3005
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Upstream image runs nginx as root to bind 80/443 and drop privileges to www-data.
# Hardening is therefore applied at runtime by the consumer:
#   - no-new-privileges
#   - cap_drop of everything except NET_BIND_SERVICE/CHOWN/SETUID/SETGID
#   - no docker socket, no privileged mode
# Do not add USER here: it breaks the upstream entrypoint and privilege drop.

EXPOSE 80 81 443

# CMD inherited from upstream on purpose; the entrypoint + s6 supervision is part
# of the reviewed image interface.
