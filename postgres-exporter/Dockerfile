# syntax=docker/dockerfile:1

ARG BASE_TAG=latest
FROM docker.io/prometheuscommunity/postgres-exporter:v0.21.1@sha256:3b8e05a84282cd1199ad2fb6c66f362738bf4c68c1547d8f4226a34a7dd6d8d7 AS upstream
FROM ghcr.io/yonrasgg/ragnarsec-base-min:${BASE_TAG}

# OCI metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec Postgres Exporter (shell-less runtime)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/postgres-exporter" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

COPY --from=upstream --chmod=0555 /bin/postgres_exporter /usr/bin/postgres_exporter
COPY --from=upstream /LICENSE /NOTICE /usr/share/licenses/postgres-exporter/

USER 1000:1000
WORKDIR /app

# Expose default port
EXPOSE 9187

CMD ["postgres_exporter"]
