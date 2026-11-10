# syntax=docker/dockerfile:1

# Upstream Arcane (BSD-3-Clause upstream; wrapper GPL-3.0).
# Digest pinned to the reviewed multi-arch index; patching means moving to a new
# upstream digest and re-scanning. Upstream is a shell-less distroless runtime.
FROM ghcr.io/getarcaneapp/arcane:v2.17.3@sha256:2e0dc9f5ef03599181a49baf6470055d82e24d9cb15bbc62498ea642c0f882a7

ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="Hardened Arcane wrapper (Docker management UI, non-root runtime contract)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/arcane" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

# The wrapper pins a non-root runtime identity. Upstream starts as 0:0 and drops
# to PUID/PGID; this wrapper overrides that and runs as 1000:1000. The data
# volume must be owned by that identity. There is no shell or package manager,
# so patching means moving the pinned upstream digest and re-scanning.
USER 1000:1000

# The upstream compose contract uses this health command. Exec form is required
# because the runtime has no shell.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/app/arcane", "health", "--timeout", "2s"]

EXPOSE 3552

# Entrypoint and CMD are inherited from upstream on purpose: /app/arcane is part
# of the reviewed image interface.
