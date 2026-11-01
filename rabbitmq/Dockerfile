ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG}

# OCI metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/yonrasgg/ragnarsec-hardened-images" \
      org.opencontainers.image.description="RagnarSec RabbitMQ (Hardened Alpine)" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/yonrasgg/ragnarsec-hardened-images/tree/main/rabbitmq" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="RagnarSec"

USER root

# SECURITY: Upgrade system packages first + Install Community Repo
# hadolint ignore=DL3018
RUN echo "https://dl-cdn.alpinelinux.org/alpine/v3.21/community" >> /etc/apk/repositories && \
    apk upgrade --no-cache && \
    apk add --no-cache rabbitmq-server && \
    # Verify user existence (created by package)
    getent passwd rabbitmq >/dev/null || ( echo "rabbitmq user missing" && exit 1 ) && \
    mkdir -p /var/lib/rabbitmq /etc/rabbitmq /var/log/rabbitmq && \
    chown -R rabbitmq:rabbitmq /var/lib/rabbitmq /etc/rabbitmq /var/log/rabbitmq

USER rabbitmq
WORKDIR /var/lib/rabbitmq

# Environment variables for RabbitMQ
ENV RABBITMQ_DATA_DIR=/var/lib/rabbitmq \
    RABBITMQ_CONFIG_FILE=/etc/rabbitmq/rabbitmq \
    RABBITMQ_HOME=/usr/lib/rabbitmq

# Expose the AMQP port only. The management plugin is not enabled by default.
EXPOSE 5672

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["rabbitmq-server"]
