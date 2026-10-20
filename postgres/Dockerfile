# syntax=docker/dockerfile:1

# Base image: Official Postgres 15 Alpine
FROM postgres:15-alpine

# OCI metadata (build-time args populated by CI; defaults for local builds)
ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local
ARG VERSION=dev

# NOTE: GPL-3.0 applies to this wrapper (Dockerfile, configs, scripts) only.
# PostgreSQL itself remains under the PostgreSQL License (permissive, similar to MIT/BSD).
LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-images" \
      org.opencontainers.image.description="Hardened Postgres 15 Wrapper" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-images/tree/main/postgres" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

# SECURITY: Explicitly upgrade Alpine packages to patch CVEs surfaced between official image releases.
# This trades build determinism for minimized attack surface.
RUN apk upgrade --no-cache \
    && rm -rf /var/cache/apk/*

# Copy custom configuration
# Postgres official image looks for config in /etc/postgresql/postgresql.conf if specified,
# or we can override the default location.
# The official image entrypoint allows placing config files.

COPY conf/postgresql.conf /etc/postgresql/postgresql.conf
COPY conf/pg_hba.conf /etc/postgresql/pg_hba.conf

# Ensure permissions (postgres user is uid 70 in alpine usually, or 999 in debian)
# Alpine postgres user is 'postgres'
RUN chown postgres:postgres /etc/postgresql/postgresql.conf /etc/postgresql/pg_hba.conf \
    # Remove gosu binary to eliminate Go vulnerabilities (CVE-2025-58183, CVE-2025-61729)
    # We don't use gosu in our entrypoint logic, so it's safe to remove to reduce attack surface.
    && rm -f /usr/local/bin/gosu

# Switch to postgres user to avoid entrypoint trying to use gosu (which we removed)
USER postgres

# Use the custom config file
CMD ["postgres", "-c", "config_file=/etc/postgresql/postgresql.conf", "-c", "hba_file=/etc/postgresql/pg_hba.conf"]
