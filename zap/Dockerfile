ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI Labels
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec ZAP (OWASP Zed Attack Proxy)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# Install Java and Python deps
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache \
        bash \
        curl \
        git \
        libxml2-dev \
        libxslt-dev \
        openjdk17-jre-headless \
        py3-pip \
        python3

# ZAP publishes a Linux x86_64 archive only. Pin the release and verify its digest.
ARG TARGETARCH
ARG ZAP_VERSION=2.17.0
ARG ZAP_SHA256=efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a
RUN if [ "${TARGETARCH:-amd64}" != "amd64" ]; then \
        echo "ZAP ${ZAP_VERSION} is published for linux/amd64 only" >&2; \
        exit 1; \
    fi && \
    mkdir -p /zap && \
    curl -fsSLo /tmp/zap.tar.gz "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" && \
    printf '%s  %s\n' "${ZAP_SHA256}" /tmp/zap.tar.gz > /tmp/zap.tar.gz.sha256 && \
    sha256sum -c /tmp/zap.tar.gz.sha256 && \
    tar -xzf /tmp/zap.tar.gz -C /zap --strip-components=1 && \
    rm -f /tmp/zap.tar.gz /tmp/zap.tar.gz.sha256 && \
    chown -R ragnarsec:ragnarsec /zap

# Set up ZAP environment
ENV ZAP_PATH=/zap/zap.sh
ENV PATH=$PATH:/zap

USER ragnarsec
WORKDIR /zap

CMD ["zap.sh", "-daemon", "-host", "0.0.0.0", "-port", "8080", "-config", "api.disablekey=true"]
