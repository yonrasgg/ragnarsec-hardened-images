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
        openjdk17-jre-headless \
        python3 \
        py3-pip \
        git \
        curl \
        bash \
        libxml2-dev \
        libxslt-dev

# Install ZAP
ARG ZAP_VERSION=2.14.0
WORKDIR /zap
RUN curl -L "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" -o zap.tar.gz && \
    tar xzf zap.tar.gz --strip-components=1 && \
    rm zap.tar.gz && \
    chown -R ragnarsec:ragnarsec /zap

# Set up ZAP environment
ENV ZAP_PATH=/zap/zap.sh
ENV PATH=$PATH:/zap

USER ragnarsec
WORKDIR /zap

CMD ["zap.sh", "-daemon", "-host", "0.0.0.0", "-port", "8080", "-config", "api.disablekey=true"]
