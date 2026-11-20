# syntax=docker/dockerfile:1

# Upstream: Nginx Proxy Manager (jc21/nginx-proxy-manager), MIT licensed.
# This wrapper (Dockerfile, docs, tests) is GPL-3.0 as declared below.
# A tag is not immutable: the digest below is the reviewed index for linux/arm64.
FROM docker.io/jc21/nginx-proxy-manager:2.16.0@sha256:4393e642e233e5efd5adeb7f10918d4aaea71c9ed875b94190273fc8e87f9594 AS sanitized

# SECURITY: patch Debian packages inherited from the upstream layer.
# This trades build determinism for a smaller known-CVE surface; CI must re-scan
# and the resulting digest must be recorded before any consumer pins it.
# hadolint flags apt-get upgrade as DL3005 because it breaks reproducibility.
# The exception is deliberate: rebuilding by digest does not patch packages that
# the upstream layer already shipped, and this image exposes a network service.
# hadolint ignore=DL3005
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/openresty /etc/nginx/pod

# Remove only the illustrative key value, preserving the API schema itself.
RUN node -e 'const fs=require("fs"); const p="/app/schema/paths/nginx/certificates/certID/upload/post.json"; const s=JSON.parse(fs.readFileSync(p,"utf8")); const v=s.responses["200"].content["application/json"].examples.default.value; if(typeof v.certificate_key!=="string") throw new Error("upstream schema changed"); v.certificate_key="REDACTED_PRIVATE_KEY_EXAMPLE"; fs.writeFileSync(p,JSON.stringify(s,null,2)+"\n");'

# Copy only the sanitized filesystem. Inheriting upstream layers would retain
# deleted test keys in the distributed image and in Trivy's secret scan.
FROM scratch
COPY --from=sanitized / /

ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="Hardened Nginx Proxy Manager wrapper" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/nginx-proxy-manager" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

# Upstream initializes as root. PUID/PGID default to 0, so nginx and the backend
# keep root privileges unless nonzero IDs are configured and validated.
# Non-root operation therefore requires explicit PUID/PGID and a runtime check of
# the effective uid; binding 80/443 still needs the root master or NET_BIND_SERVICE.
# Hardening is applied at runtime by the consumer:
#   - no-new-privileges
#   - cap_drop of everything except NET_BIND_SERVICE/CHOWN/SETUID/SETGID
#   - no docker socket, no privileged mode
# Do not add USER here: upstream initialization expects to start as root.

# Preserve the pinned upstream startup contract explicitly after flattening.
ENV PATH="/opt/certbot/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    OPENRESTY_VERSION=1.31.1.1 \
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SUPPRESS_NO_CONFIG_WARNING=1 \
    S6_BEHAVIOUR_IF_STAGE2_FAILS=1 \
    S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0 \
    S6_FIX_ATTRS_HIDDEN=1 \
    S6_KILL_FINISH_MAXTIME=10000 \
    S6_VERBOSITY=1 \
    NODE_ENV=production \
    NPM_BUILD_VERSION=2.16.0 \
    NPM_BUILD_COMMIT=a29eae9d \
    NPM_BUILD_DATE="2026-09-24 09:43:00 UTC" \
    NODE_OPTIONS=--openssl-legacy-provider
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
WORKDIR /app
VOLUME ["/data"]
EXPOSE 80 81 443
ENTRYPOINT ["/init"]
