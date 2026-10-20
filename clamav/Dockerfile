ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec ClamAV (Antivirus)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/clamav" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# SECURITY: Upgrade system packages + Install ClamAV
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache \
    clamav \
    clamav-daemon \
    clamav-libunrar \
    curl \
    && mkdir -p /run/clamav /var/lib/clamav /var/log/clamav \
    && chown -R clamav:clamav /run/clamav /var/lib/clamav /var/log/clamav

# Initial DB update (optional, increases build time/size but ensures readiness)
# User running this might want Freshclam sidecar pattern instead.
# For now, let's just ensure directories exist.

# Configure ClamAV (basic hardening)
# Disable remote commands if not needed, use local socket.
RUN sed -i 's/^#LocalSocket /LocalSocket /' /etc/clamav/clamd.conf && \
    sed -i 's/^#Foreground yes/Foreground yes/' /etc/clamav/clamd.conf && \
    sed -i 's/^#Foreground yes/Foreground yes/' /etc/clamav/freshclam.conf

# HEALTHCHECK --interval=5m --timeout=3s \
#   CMD clamdscan --ping || exit 1

WORKDIR /var/lib/clamav
USER clamav

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["clamd"]
