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
ARG TOFU_VERSION=1.13.2
ARG TOFU_SHA256_AMD64=ac05d9952662c7db28dd57e93f0a68018837bfdf9342384ec0987977c16a9645
ARG TOFU_SHA256_ARM64=88e2d9e3f94f97b76ab2faf55ade87578f56aed19c5e45fa139d70e994366d1f
ARG TFLINT_VERSION=0.65.0
ARG TFLINT_SHA256_AMD64=d4c545ed2e29d6338604b586f34f544f380f70f243aa72f7b484713835eaec61
ARG TFLINT_SHA256_ARM64=843017c47a98be1de4d88fa038daa293770fe25cd01656c4f08b2e30d1d3b3a0
ARG OPA_VERSION=1.22.0
ARG OPA_SHA256_AMD64=791790254c598a942eb140959bcec9a47f844535a632fd01d11d870ba2a47047
ARG OPA_SHA256_ARM64=62f64100c5db155a7499c14668a5a453feb7d94221736e12c7d759c0f46fc585
ARG CONFTEST_VERSION=0.71.1
ARG CONFTEST_SHA256_AMD64=c3f6b2a753bd56e377a1e51a95ae3e057f926f2e9139f7d5b5dfbbaf810f7985
ARG CONFTEST_SHA256_ARM64=218c682e110ae7e826dc14a746a6f9b43eb782643dbe730b771fd305634e3f47

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
