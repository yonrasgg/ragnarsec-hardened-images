# syntax=docker/dockerfile:1

# Upstream WGDashboard (GPL-3.0 upstream; wrapper GPL-3.0).
# Digest pinned; patching means moving to a new upstream digest and re-scanning.
FROM ghcr.io/wgdashboard/wgdashboard@sha256:8c5b550db4fda04eff06e96af801499be485c73e0912fcf0c1031babca0f7e7b

ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="Hardened WGDashboard wrapper (read-only deployment contract)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/wgdashboard" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

# policy: allow-root upstream entrypoint initializes its own configuration as root
# No apk upgrade here: this is an upstream Alpine image and the patch path is a new
# upstream digest. The consumer must mount /etc/wireguard read-only and must not
# grant NET_ADMIN; live handshake data is therefore out of scope by design.

EXPOSE 10086

# Entrypoint and command inherited from upstream on purpose: /entrypoint.sh is part
# of the reviewed image interface.
