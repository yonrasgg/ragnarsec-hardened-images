ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-images" \
      org.opencontainers.image.description="RagnarSec Valkey (Hardened Alpine)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-images/tree/main/valkey" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# SECURITY: Upgrade system packages first
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache valkey && \
    mkdir -p /var/lib/valkey /etc/valkey && \
    chown -R ragnarsec:ragnarsec /var/lib/valkey /etc/valkey

USER ragnarsec
WORKDIR /var/lib/valkey

# Expose default Redis/Valkey port
EXPOSE 6379

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["valkey-server", "--protected-mode", "no"]
