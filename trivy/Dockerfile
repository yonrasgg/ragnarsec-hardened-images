ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI Labels
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec Trivy Scanner" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# Alpine does not package a current Trivy release in the supported repositories.
# Install the upstream release and verify it against a pinned SHA256 digest.
ARG TARGETARCH
ARG TRIVY_VERSION=0.76.0
ARG TRIVY_SHA256_AMD64=e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7
ARG TRIVY_SHA256_ARM64=aab21e677a7b7071fc79f1711480840754c18a1b9d9cefa7ccd06af63a0e8f4c
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates curl && \
    case "${TARGETARCH:-amd64}" in \
        "amd64") asset="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; sha="${TRIVY_SHA256_AMD64}" ;; \
        "arm64") asset="trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz"; sha="${TRIVY_SHA256_ARM64}" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    curl -fsSLo /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${asset}" && \
    printf '%s  %s\n' "${sha}" /tmp/trivy.tar.gz > /tmp/trivy.tar.gz.sha256 && \
    sha256sum -c /tmp/trivy.tar.gz.sha256 && \
    tar -xzf /tmp/trivy.tar.gz -C /tmp trivy && \
    install -m 0755 /tmp/trivy /usr/bin/trivy && \
    rm -f /tmp/trivy /tmp/trivy.tar.gz /tmp/trivy.tar.gz.sha256 && \
    apk del curl && \
    trivy --version

# Create cache directory for non-root user
RUN mkdir -p /home/ragnarsec/.cache/trivy && \
    chown -R ragnarsec:ragnarsec /home/ragnarsec/.cache && \
    chmod 0755 /home/ragnarsec/.cache /home/ragnarsec/.cache/trivy

USER ragnarsec
WORKDIR /home/ragnarsec

ENTRYPOINT ["trivy"]
CMD ["--help"]
