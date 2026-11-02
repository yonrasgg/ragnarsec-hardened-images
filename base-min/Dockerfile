# syntax=docker/dockerfile:1

# Minimal runtime floor: no shell, no package manager, no busybox.
# Consumers build their binaries in a separate stage and copy them here.

ARG ALPINE=alpine:3.21@sha256:ee16d92f96db08d9d2d07da48555a27f3a69d8f0759021dbc601195ed0d2b5bd
ARG CA_CERTIFICATES=20261020-r0
ARG TINI=0.19.0-r3

FROM ${ALPINE} AS build

ARG CA_CERTIFICATES
ARG TINI

# hadolint ignore=DL3018
RUN apk add --no-cache \
        ca-certificates=${CA_CERTIFICATES} \
        tini=${TINI} \
    && addgroup -g 1000 ragnarsec \
    && adduser -u 1000 -G ragnarsec -s /sbin/nologin -D -h /home/ragnarsec ragnarsec

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

USER 1000:1000
ENTRYPOINT ["/sbin/tini","--"]
