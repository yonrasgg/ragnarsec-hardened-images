# syntax=docker/dockerfile:1

# Minimal runtime floor: no shell, no package manager, no busybox.
# Consumers build their binaries in a separate stage and copy them here.

ARG ALPINE=alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
ARG CA_CERTIFICATES=20261020-r0
ARG TINI=0.19.0-r3

FROM ${ALPINE} AS build

ARG CA_CERTIFICATES
ARG TINI
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# hadolint ignore=DL3018
RUN apk add --no-cache \
        ca-certificates=${CA_CERTIFICATES} \
        tini=${TINI} \
    && addgroup -g 1000 ragnarsec \
    && adduser -u 1000 -G ragnarsec -s /sbin/nologin -D -h /home/ragnarsec ragnarsec

# Trivy needs Alpine release metadata and the APK installed database to scan
# the scratch runtime. Keep only records for packages whose files are copied
# below; the complete builder database would falsely report builder-only tools.
RUN mkdir -p /runtime-apk/lib/apk/db \
    && awk 'BEGIN { RS=""; ORS="\n\n"; keep=" musl tini ca-certificates-bundle alpine-baselayout-data alpine-release " } \
            { n=split($0, fields, "\n"); for (i=1; i<=n; i++) if (fields[i] ~ /^P:/) { \
                name=substr(fields[i], 3); if (index(keep, " " name " ")) print; break \
            } }' /lib/apk/db/installed > /runtime-apk/lib/apk/db/installed \
    && printf '%s\n' alpine-baselayout-data alpine-release ca-certificates-bundle musl tini > /tmp/expected-packages \
    && grep '^P:' /runtime-apk/lib/apk/db/installed | cut -c3- | sort > /tmp/runtime-packages \
    && cmp /tmp/expected-packages /tmp/runtime-packages

FROM scratch

ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG VCS_REF=local
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec minimal base (no shell)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/base-min" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

COPY --from=build /etc/ssl/certs /etc/ssl/certs
COPY --from=build /etc/passwd /etc/group /etc/
COPY --from=build /lib/ld-musl-*.so.1 /lib/
COPY --from=build /lib/libc.musl-*.so.1 /lib/
COPY --from=build /sbin/tini /sbin/tini
COPY --from=build /etc/alpine-release /etc/alpine-release
COPY --from=build /usr/lib/os-release /usr/lib/os-release
COPY --from=build /runtime-apk/lib/apk/db/installed /lib/apk/db/installed

USER 1000:1000
ENTRYPOINT ["/sbin/tini","--"]
