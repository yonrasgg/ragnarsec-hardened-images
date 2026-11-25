ARG BASE_TAG=latest

# Builder stage for downloading binary
FROM alpine:3.21 AS builder
ARG TARGETARCH
ARG REDIS_EXPORTER_VERSION=v1.99.0
WORKDIR /tmp
SHELL ["/bin/ash", "-o", "pipefail", "-c"]
# hadolint ignore=DL3018
RUN apk add --no-cache curl \
    && case "${TARGETARCH}" in \
         ""|"amd64") \
           arch="linux-amd64"; \
           sha256="93c7949cb06ea7075cb3b67a8c60937848063d0c9f2ab0521857e44720735ac7" ;; \
         "arm64") \
           arch="linux-arm64"; \
           sha256="3b6959d384781caa83e2d434d867d4b9251ae0bdccb13098aadb7b3ce26669fe" ;; \
         *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && asset="redis_exporter-${REDIS_EXPORTER_VERSION}.${arch}.tar.gz" \
    && binary="redis_exporter-${REDIS_EXPORTER_VERSION}.${arch}/redis_exporter" \
    && curl -fLsS -o "${asset}" "https://github.com/oliver006/redis_exporter/releases/download/${REDIS_EXPORTER_VERSION}/${asset}" \
    && printf '%s  %s\n' "${sha256}" "${asset}" | sha256sum -c - \
    && tar -xzf "${asset}" "${binary}" \
    && mv "${binary}" /tmp/redis_exporter

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

CMD ["redis_exporter"]
