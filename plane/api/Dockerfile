# ragnarsec-plane-backend
# Django REST Framework API for Plane
ARG BASE_TAG=latest
# Use ragnarsec-python-base as the final runtime
FROM ghcr.io/yonrasgg/ragnarsec-python-base:${BASE_TAG} AS runtime

USER root

# Install system dependencies
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache \
        libpq \
        libxml2 \
        libxslt \
        mariadb-connector-c \
        xmlsec \
        ffmpeg \
        git \
        netcat-openbsd \
        gettext

# Clean build deps just in case
RUN apk add --no-cache --virtual .build-deps \
        postgresql-dev \
        libxml2-dev \
        libxslt-dev \
        mariadb-dev \
        gcc \
        g++ \
        musl-dev \
        libffi-dev \
        cargo

# Clone specific version of Plane (Frontend & Backend share same repo)
ARG PLANE_VERSION=v0.24.0
WORKDIR /tmp/plane-src
RUN git clone --depth 1 --branch ${PLANE_VERSION} https://github.com/makeplane/plane.git .

# Prepare backend directory
WORKDIR /app
RUN cp -r /tmp/plane-src/apiserver/* . && \
    cp -r /tmp/plane-src/requirements.txt . && \
    rm -rf /tmp/plane-src

# Install Python requirements
# hadolint ignore=DL3013
USER ragnarsec
ENV VIRTUAL_ENV=/app/venv
RUN . $VIRTUAL_ENV/bin/activate && \
    pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Post-install cleanup
USER root
RUN apk del .build-deps

USER ragnarsec

ENTRYPOINT ["/app/bin/docker-entrypoint.sh"]
CMD ["./bin/worker"]
