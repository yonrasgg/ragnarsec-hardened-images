ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI Labels
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-images" \
      org.opencontainers.image.description="RagnarSec Trivy Scanner" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-images" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# Install Trivy from Alpine Community
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache \
        trivy \
        ca-certificates

# Create cache directory for non-root user
RUN mkdir -p /home/ragnarsec/.cache/trivy && \
    chown -R ragnarsec:ragnarsec /home/ragnarsec

USER ragnarsec
WORKDIR /home/ragnarsec

ENTRYPOINT ["trivy"]
CMD ["--help"]
