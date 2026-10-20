ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI Labels
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec BuildKit Daemon and Client (Rootless)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# Install runtime dependencies for rootless BuildKit.
# `shadow-uidmap` provides newuidmap/newgidmap; `rootlesskit` and
# `slirp4netns` provide the user-space network path used by rootless builds.
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache \
        ca-certificates \
        curl \
        fuse-overlayfs \
        git \
        iptables \
        rootlesskit \
        runc \
        shadow-uidmap \
        slirp4netns

# Install the upstream daemon and client from a pinned, checksummed release.
# Alpine's buildkit package only ships buildkitd, so the upstream release is used
# to keep both the daemon and the CLI available to consumers.
ARG TARGETARCH
ARG BUILDKIT_VERSION=0.34.0
ARG BUILDKIT_SHA256_AMD64=14813b1fb2a40082114e6d386c6fc5e7dd5298176ce7ee1a18bc33e73e109ac3
ARG BUILDKIT_SHA256_ARM64=0619ca3e3205a32ea2beb115e0242136e4a0716cc1917ba0ceaa4ef4d52382c9
RUN case "${TARGETARCH:-amd64}" in \
        "amd64") asset="buildkit-v${BUILDKIT_VERSION}.linux-amd64.tar.gz"; sha="${BUILDKIT_SHA256_AMD64}" ;; \
        "arm64") asset="buildkit-v${BUILDKIT_VERSION}.linux-arm64.tar.gz"; sha="${BUILDKIT_SHA256_ARM64}" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    curl -fsSLo /tmp/buildkit.tar.gz "https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/${asset}" && \
    printf '%s  %s\n' "${sha}" /tmp/buildkit.tar.gz > /tmp/buildkit.tar.gz.sha256 && \
    sha256sum -c /tmp/buildkit.tar.gz.sha256 && \
    tar -xzf /tmp/buildkit.tar.gz -C /usr/local bin/buildkitd bin/buildctl && \
    rm -f /tmp/buildkit.tar.gz /tmp/buildkit.tar.gz.sha256 && \
    buildkitd --version && \
    buildctl --version

# Prepare the subordinate ID ranges, state directory and rootless entrypoint.
COPY entrypoint.sh /usr/local/bin/buildkit-entrypoint.sh
RUN mkdir -p /home/ragnarsec/.local/share/buildkit && \
    printf 'ragnarsec:100000:65536\n' >> /etc/subuid && \
    printf 'ragnarsec:100000:65536\n' >> /etc/subgid && \
    chmod 0755 /usr/local/bin/buildkit-entrypoint.sh && \
    chown -R ragnarsec:ragnarsec /home/ragnarsec/.local

USER ragnarsec
WORKDIR /home/ragnarsec

# Start the daemon inside a RootlessKit user namespace.
CMD ["/usr/local/bin/buildkit-entrypoint.sh"]
