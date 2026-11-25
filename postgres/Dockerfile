# syntax=docker/dockerfile:1

# Base image: Official Postgres 15 Alpine
FROM postgres:15-alpine@sha256:e18480a22d6e48f4d816a6696769b1ec09ac73a824c5649e49c7d8b684913f3d

# OCI metadata (build-time args populated by CI; defaults for local builds)
ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local
ARG VERSION=dev

# Pre-create a searchable directory before copying read-only config files.
RUN install -d -m 0555 /etc/postgresql

# NOTE: GPL-3.0 applies to this wrapper (Dockerfile, configs, scripts) only.
# PostgreSQL itself remains under the PostgreSQL License (permissive, similar to MIT/BSD).
LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="Hardened Postgres 15 Wrapper" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/postgres" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

# Keep configuration readable by the service without granting write access.
COPY --chmod=0444 conf/postgresql.conf conf/pg_hba.conf /etc/postgresql/

# The base index contains an older libxml2. Install the reviewed Alpine fix.
# The entrypoint already starts as postgres and does not need gosu.
RUN apk add --no-cache libxml2=2.13.9-r3 \
    && rm -f /usr/local/bin/gosu

USER postgres

# Use the custom config file
CMD ["postgres", "-c", "config_file=/etc/postgresql/postgresql.conf", "-c", "hba_file=/etc/postgresql/pg_hba.conf"]
