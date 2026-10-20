ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-images" \
      org.opencontainers.image.description="RagnarSec Alertmanager (Hardened Alpine)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-images/tree/main/alertmanager" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# SECURITY: Upgrade system packages first
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache alertmanager && \
    mkdir -p /etc/alertmanager /var/lib/alertmanager && \
    chown -R ragnarsec:ragnarsec /etc/alertmanager /var/lib/alertmanager

USER ragnarsec
WORKDIR /var/lib/alertmanager

# Expose default port
EXPOSE 9093

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["alertmanager", "--config.file=/etc/alertmanager/alertmanager.yml", "--storage.path=/var/lib/alertmanager"]
