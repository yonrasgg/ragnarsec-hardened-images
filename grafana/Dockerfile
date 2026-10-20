ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-images" \
      org.opencontainers.image.description="RagnarSec Grafana (Hardened Alpine)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-images/tree/main/grafana" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# SECURITY: Upgrade system packages first
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache grafana && \
    mkdir -p /var/lib/grafana /var/log/grafana /etc/grafana && \
    chown -R ragnarsec:ragnarsec /var/lib/grafana /var/log/grafana /etc/grafana

USER ragnarsec
WORKDIR /usr/share/grafana

# Expose default port
EXPOSE 3000

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["grafana", "server", \
     "--homepath=/usr/share/grafana", \
     "--config=/etc/grafana.ini", \
     "cfg:default.paths.data=/var/lib/grafana", \
     "cfg:default.paths.logs=/var/log/grafana"]
