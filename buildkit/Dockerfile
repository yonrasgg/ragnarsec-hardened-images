ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI Labels
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec BuildKit Daemon (Rootless)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# Install BuildKit and dependencies
# `uidmap` required for rootless execution
# `fuse-overlayfs` for rootless storage driver
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache \
        buildkit \
        runc \
        containerd \
        uidmap \
        fuse-overlayfs \
        iptables

# Prepare directory for buildkitd state
RUN mkdir -p /home/ragnarsec/.local/share/buildkit && \
    chown -R ragnarsec:ragnarsec /home/ragnarsec/.local

USER ragnarsec
WORKDIR /home/ragnarsec

# Default entrypoint for rootless buildkitd
# Note: Actual rootless execution might require `rootlesskit` wrapping depending on environment capabilities
CMD ["buildkitd", "--root", "/home/ragnarsec/.local/share/buildkit"]
