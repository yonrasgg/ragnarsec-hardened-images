ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-python-base:${BASE_TAG}

# OCI Labels
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec IaC Tooling (OpenTofu, TFLint, Checkov, OPA, Conftest)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# Install system dependencies. OpenTofu replaces the Terraform package that Alpine
# does not provide; a `terraform` compatibility symlink is installed below.
# checkov needs python3-dev, build-base, libffi-dev for compilation.
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache \
        build-base \
        cargo \
        curl \
        git \
        libffi-dev \
        make \
        openssl-dev \
        rust \
        unzip

# Install Python tools (Checkov) as ragnarsec user to keep venv ownership
USER ragnarsec
# hadolint ignore=DL3013
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir checkov

USER root
# Install OpenTofu and the remaining tools from pinned, checksummed releases.
ARG TARGETARCH
ARG TOFU_VERSION=1.13.1
ARG TOFU_SHA256_AMD64=378ada19d4bc70c43732004e8159be771b23b9a5afdf059e5f8a2b3fa2c70a69
ARG TOFU_SHA256_ARM64=9c1ef375aa1852db0b2888aa921b640c71f8140d4682aa4fec99378a64fa7dc3
ARG TFLINT_VERSION=0.50.3
ARG TFLINT_SHA256_AMD64=70d66470f161ed48e6da0c58dc61787eced1ebd02397618424b8a55ff67f465f
ARG TFLINT_SHA256_ARM64=46b04f8f793e5ff96b74948b993588e5f48476534b570216ad303951fa3ee1e3
ARG OPA_VERSION=0.61.0
ARG OPA_SHA256_AMD64=24a15b66a054b9e836a5dc1e07dff622999470eeb0c6e746340b4ccabde5663c
ARG OPA_SHA256_ARM64=172ca2925983cab76e8e80657e297a61be52ac24aaa9227c7fb0439435a7ae6d
ARG CONFTEST_VERSION=0.49.0
ARG CONFTEST_SHA256_AMD64=46fc01ae797c6b9a6fd85bebdabd0e395d77f074ed086b2ecbf019044ea04cca
ARG CONFTEST_SHA256_ARM64=85b1ca45e9be9400def594b7241987cabf968b56c896b881207ea85c875d7682

RUN case "${TARGETARCH:-amd64}" in \
        "amd64") \
            tofu_asset="tofu_${TOFU_VERSION}_linux_amd64.tar.gz"; tofu_sha="${TOFU_SHA256_AMD64}"; \
            tflint_asset="tflint_linux_amd64.zip"; tflint_sha="${TFLINT_SHA256_AMD64}"; \
            opa_asset="opa_linux_amd64_static"; opa_sha="${OPA_SHA256_AMD64}"; \
            conftest_asset="conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz"; conftest_sha="${CONFTEST_SHA256_AMD64}" ;; \
        "arm64") \
            tofu_asset="tofu_${TOFU_VERSION}_linux_arm64.tar.gz"; tofu_sha="${TOFU_SHA256_ARM64}"; \
            tflint_asset="tflint_linux_arm64.zip"; tflint_sha="${TFLINT_SHA256_ARM64}"; \
            opa_asset="opa_linux_arm64_static"; opa_sha="${OPA_SHA256_ARM64}"; \
            conftest_asset="conftest_${CONFTEST_VERSION}_Linux_arm64.tar.gz"; conftest_sha="${CONFTEST_SHA256_ARM64}" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    curl -fsSLo /tmp/tofu.tar.gz "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/${tofu_asset}" && \
    printf '%s  %s\n' "${tofu_sha}" /tmp/tofu.tar.gz > /tmp/tofu.tar.gz.sha256 && \
    sha256sum -c /tmp/tofu.tar.gz.sha256 && \
    tar -xzf /tmp/tofu.tar.gz -C /tmp tofu && \
    install -m 0755 /tmp/tofu /usr/local/bin/tofu && \
    ln -sf /usr/local/bin/tofu /usr/local/bin/terraform && \
    curl -fsSLo /tmp/tflint.zip "https://github.com/terraform-linters/tflint/releases/download/v${TFLINT_VERSION}/${tflint_asset}" && \
    printf '%s  %s\n' "${tflint_sha}" /tmp/tflint.zip > /tmp/tflint.zip.sha256 && \
    sha256sum -c /tmp/tflint.zip.sha256 && \
    unzip -q /tmp/tflint.zip -d /tmp/tflint && \
    install -m 0755 /tmp/tflint/tflint /usr/local/bin/tflint && \
    curl -fsSLo /tmp/opa "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/${opa_asset}" && \
    printf '%s  %s\n' "${opa_sha}" /tmp/opa > /tmp/opa.sha256 && \
    sha256sum -c /tmp/opa.sha256 && \
    install -m 0755 /tmp/opa /usr/local/bin/opa && \
    curl -fsSLo /tmp/conftest.tar.gz "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/${conftest_asset}" && \
    printf '%s  %s\n' "${conftest_sha}" /tmp/conftest.tar.gz > /tmp/conftest.tar.gz.sha256 && \
    sha256sum -c /tmp/conftest.tar.gz.sha256 && \
    tar -xzf /tmp/conftest.tar.gz -C /tmp conftest && \
    install -m 0755 /tmp/conftest /usr/local/bin/conftest && \
    rm -rf /tmp/tofu /tmp/tofu.tar.gz /tmp/tofu.tar.gz.sha256 /tmp/tflint /tmp/tflint.zip /tmp/tflint.zip.sha256 /tmp/opa /tmp/opa.sha256 /tmp/conftest /tmp/conftest.tar.gz /tmp/conftest.tar.gz.sha256

# Cleanup build deps to reduce size
RUN apk del build-base libffi-dev openssl-dev cargo rust

USER ragnarsec
WORKDIR /app

CMD ["/bin/sh"]
