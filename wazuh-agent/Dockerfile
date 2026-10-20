ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-images" \
      org.opencontainers.image.description="RagnarSec Wazuh Agent (FIM/HIDS)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-images/tree/main/wazuh-agent" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# SECURITY: Upgrade system packages + Install Wazuh dependencies
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache \
    curl \
    openssl \
    libstdc++ \
    bash \
    procps

# Install Wazuh Agent (example: fetch pre-built or source)
# For Alpine, often requires manual installation or copying from official image if license permits (GPLv2).
# Here we use a standard method: downloading the agent package if available, or just preparing the environment
# since actual installation might be complex in a single Dockerfile step without external assets.
# Alternatively, copying from official image is cleaner if compatible with Alpine version.

# Creating placeholder structure for now as full compilation is heavy.
# Practical approach: Use sidecar pattern with this base.

# Ensure directories exist
RUN mkdir -p /var/ossec/etc /var/ossec/logs /var/ossec/queue /var/ossec/var/run \
    && chown -R ragnarsec:ragnarsec /var/ossec

USER ragnarsec
WORKDIR /var/ossec

# Launch agent (requires configuration mounted at runtime)
# CMD ["/var/ossec/bin/wazuh-agentd"]
CMD ["echo", "Wazuh Agent Placeholder - Mount bins/config or use sidecar"]
