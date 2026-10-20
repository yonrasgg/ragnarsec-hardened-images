ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-nginx:${BASE_TAG}

# OCI metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-images" \
      org.opencontainers.image.description="RagnarSec WAF (ModSecurity + OWASP CRS)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-images/tree/main/waf" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# SECURITY: Upgrade system packages + Install WAF modules
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache \
    libmodsecurity \
    nginx-mod-http-modsecurity \
    git

# Install OWASP CRS
WORKDIR /etc/nginx/modsec
RUN git clone --depth 1 https://github.com/coreruleset/coreruleset.git crs && \
    mv crs/crs-setup.conf.example crs/crs-setup.conf && \
    mv crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf

# Clean up git to reduce size
RUN apk del git

# Copy custom WAF config if exists (or create default)
# We need to enable modsecurity in nginx.conf
# This usually requires modifying the base nginx config or adding an include.
# Since we are extending ragnarsec-nginx, we might need to overwrite or append.
# For now, let's assume the user will configure nginx to use it, or we provide a default waf.conf

WORKDIR /etc/nginx/modsec
USER ragnarsec
