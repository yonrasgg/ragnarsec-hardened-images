FROM alpine:3.21

# OCI metadata (build-time args populated by CI; defaults for local builds)
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec Base Image (Alpine 3.21)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/base" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

# SECURITY: Upgrade system packages to patch CVEs, then install essentials.
# hadolint ignore=DL3018
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates tzdata tini \
    && addgroup -g 1000 ragnarsec \
    && adduser -u 1000 -G ragnarsec -s /sbin/nologin -D -h /home/ragnarsec ragnarsec

USER ragnarsec
WORKDIR /app

ENTRYPOINT ["/sbin/tini", "--"]
