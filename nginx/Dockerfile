ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI metadata (build-time args populated by CI; defaults for local builds)
ARG BUILD_DATE=unknown
ARG VCS_REF=local
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec Nginx runtime" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/nginx" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# Pin runtime additions to versions recorded in versions.json. Base updates are
# reviewed separately instead of upgrading the entire inherited filesystem.
RUN apk add --no-cache \
    nginx=1.30.6-r0 \
    openssl=3.5.9-r0 \
    pcre2=10.49-r0

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
