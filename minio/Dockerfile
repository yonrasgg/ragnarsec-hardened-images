ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec MinIO (Hardened Alpine)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/minio" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# SECURITY: Upgrade system packages first + Install Community Repo
# hadolint ignore=DL3018
RUN echo "https://dl-cdn.alpinelinux.org/alpine/v3.21/community" >> /etc/apk/repositories && \
    apk upgrade --no-cache && \
    apk add --no-cache minio && \
    mkdir -p /data /home/ragnarsec/.minio && \
    chown -R ragnarsec:ragnarsec /data /home/ragnarsec/.minio

USER ragnarsec
WORKDIR /data

# Expose ports: 9000 (API), 9001 (Console)
EXPOSE 9000 9001

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["minio", "server", "/data", "--console-address", ":9001"]
