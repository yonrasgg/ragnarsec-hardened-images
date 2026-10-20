ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-python-base:${BASE_TAG}

# OCI Labels
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-images" \
      org.opencontainers.image.description="RagnarSec IaC Tooling (Terraform, TFLint, Checkov, OPA)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-images" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# Install system dependencies & Terraform
# checkov needs python3-dev, build-base, libffi-dev for compilation
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache \
        terraform \
        git \
        curl \
        make \
        build-base \
        libffi-dev \
        openssl-dev \
        cargo \
        rust

# Install Python tools (Checkov) as ragnarsec user to keep venv ownership
USER ragnarsec
# hadolint ignore=DL3013
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir checkov

USER root
# Install Tools (TFLint, OPA, Conftest) with multi-arch support
ARG TARGETARCH
ARG TFLINT_VERSION=v0.50.3
ARG OPA_VERSION=v0.61.0
ARG CONFTEST_VERSION=0.49.0

RUN case "${TARGETARCH}" in \
        "amd64") ARCH="amd64"; OPA_ARCH="amd64"; CONFTEST_ARCH="x86_64" ;; \
        "arm64") ARCH="arm64"; OPA_ARCH="arm64"; CONFTEST_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}"; exit 1 ;; \
    esac && \
    # Install TFLint
    curl -L "https://github.com/terraform-linters/tflint/releases/download/${TFLINT_VERSION}/tflint_linux_${ARCH}.zip" -o tflint.zip && \
    unzip tflint.zip && \
    mv tflint /usr/local/bin/ && \
    rm tflint.zip && \
    # Install OPA
    curl -L -o /usr/local/bin/opa "https://openpolicyagent.org/downloads/${OPA_VERSION}/opa_linux_${OPA_ARCH}_static" && \
    chmod 755 /usr/local/bin/opa && \
    # Install Conftest
    curl -L "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_${CONFTEST_ARCH}.tar.gz" -o conftest.tar.gz && \
    tar xzf conftest.tar.gz conftest && \
    mv conftest /usr/local/bin/ && \
    rm conftest.tar.gz

# Cleanup build deps to reduce size
RUN apk del build-base libffi-dev openssl-dev cargo rust

USER ragnarsec
WORKDIR /app

CMD ["/bin/sh"]
