ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec Prometheus (Hardened Alpine)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/prometheus" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# Refresh the security-sensitive packages inherited from the pinned Alpine base.
RUN apk add --no-cache \
        apk-tools=3.0.9-r0 \
        libapk=3.0.9-r0 \
        libcrypto3=3.5.9-r1 \
        libssl3=3.5.9-r1 \
        prometheus=3.5.3-r3 \
        zlib=1.4-r0 && \
    mkdir -p /etc/prometheus /var/lib/prometheus && \
    chown -R ragnarsec:ragnarsec /etc/prometheus /var/lib/prometheus

USER ragnarsec
WORKDIR /var/lib/prometheus

# Expose default port
EXPOSE 9090

# The base provides the tini entrypoint.
CMD ["prometheus", \
     "--config.file=/etc/prometheus/prometheus.yml", \
     "--storage.tsdb.path=/var/lib/prometheus", \
     "--web.console.libraries=/usr/share/prometheus/console_libraries", \
     "--web.console.templates=/usr/share/prometheus/consoles"]
