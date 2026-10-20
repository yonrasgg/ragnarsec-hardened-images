ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI metadata (build-time args populated by CI; defaults for local builds)
ARG BUILD_DATE=unknown
ARG VCS_REF=local
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-images" \
      org.opencontainers.image.description="RagnarSec Nginx (Alpine 3.21)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-images/tree/main/nginx" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# SECURITY: Upgrade system packages to patch CVEs, then install nginx + openssl.
# hadolint ignore=DL3018
RUN apk upgrade --no-cache \
    && apk add --no-cache \
    nginx \
    openssl

# Configure Nginx
# Copy configuration files (overwrites default nginx.conf)
COPY conf /etc/nginx

# Ensure permissions for non-root user (ragnarsec)
# Create necessary directories and set ownership
RUN mkdir -p /var/log/nginx /var/lib/nginx /run/nginx /etc/nginx/tls /usr/share/nginx/html \
    && chown -R ragnarsec:ragnarsec /etc/nginx /var/log/nginx /var/lib/nginx /run/nginx /usr/share/nginx/html /etc/nginx/tls

USER ragnarsec

EXPOSE 8443
CMD ["nginx", "-g", "daemon off;"]
