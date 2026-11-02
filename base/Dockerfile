FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=unknown
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec Base Image (Alpine 3.24.3)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/base" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

# Pinned packages; no apk upgrade. Patching means moving the Alpine digest and the
# pins together, then rebuilding and re-scanning.
# hadolint ignore=DL3018
RUN apk add --no-cache \
        ca-certificates=20261020-r0 \
        tzdata=2026e-r0 \
        tini=0.19.0-r3 \
    && addgroup -g 1000 ragnarsec \
    && adduser -u 1000 -G ragnarsec -s /sbin/nologin -D -h /home/ragnarsec ragnarsec

USER 1000:1000
WORKDIR /app
ENTRYPOINT ["/sbin/tini", "--"]
