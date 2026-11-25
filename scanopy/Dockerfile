# syntax=docker/dockerfile:1

# Scanopy hardened server candidate. The reviewed minimal Debian 13.8 rootfs is
# stored as an immutable, checksum-pinned data asset in this repository's GitHub
# release (not as a binary blob in git, which the publication boundary rejects).
# Extracted from candidate-image.tar SHA-256
# a2b23ebcbd2a4674a0a26869c473473533c5fa50c3c51f6bfe6811a372259c3d.
# Build-time egress uses only the already-allowlisted github.com /
# release-assets.githubusercontent.com hosts.
FROM alpine:3.22 AS rootfs

ADD --checksum=sha256:e30914e30ffa14f42224b3b94cee007859639d8fa4a2b2741ea9c7452cba4d13 \
    https://github.com/yonrasgg/ragnarsec-hardened-images/releases/download/scanopy-candidate-20261125/rootfs.tar.gz \
    /rootfs.tar.gz
RUN mkdir -p /rootfs && tar -xzf /rootfs.tar.gz -C /rootfs && rm /rootfs.tar.gz

FROM scratch

ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local

LABEL org.opencontainers.image.title="Scanopy" \
      org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="Hardened Scanopy network-discovery server candidate (non-root, shell-less)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER 1000:1000
WORKDIR /app
COPY --from=rootfs /rootfs/ /
ENTRYPOINT ["/usr/local/bin/server"]
