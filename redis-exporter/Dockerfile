ARG BASE_TAG=latest

# Builder stage for downloading binary
FROM alpine:3.21 AS builder
ARG TARGETARCH
ARG REDIS_EXPORTER_VERSION=v1.67.0
WORKDIR /tmp
# hadolint ignore=DL3018
RUN apk add --no-cache curl \
    && case "${TARGETARCH}" in \
         ""|"amd64") arch="linux-amd64" ;; \
         "arm64") arch="linux-arm64" ;; \
         *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -LO "https://github.com/oliver006/redis_exporter/releases/download/${REDIS_EXPORTER_VERSION}/redis_exporter-${REDIS_EXPORTER_VERSION}.${arch}.tar.gz" \
    && tar -xvzf "redis_exporter-${REDIS_EXPORTER_VERSION}.${arch}.tar.gz" \
    && mv "redis_exporter-${REDIS_EXPORTER_VERSION}.${arch}/redis_exporter" /tmp/redis_exporter

# Final stage
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec Redis Exporter (Hardened Alpine)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/redis-exporter" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# SECURITY: Upgrade system packages first
RUN apk upgrade --no-cache

# Copy binary from builder
COPY --from=builder /tmp/redis_exporter /usr/local/bin/redis_exporter

USER ragnarsec
WORKDIR /app

# Expose default port
EXPOSE 9121

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["redis_exporter"]
