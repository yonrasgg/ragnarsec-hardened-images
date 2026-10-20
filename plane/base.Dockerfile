# ragnarsec-plane-base
# This is a meta-image used as a build context for Plane services.
# It clones the Plane repo and installs base deps.
ARG BASE_TAG=latest
FROM ghcr.io/yonrasgg/ragnarsec-builder:${BASE_TAG} AS builder

WORKDIR /app

# Plane Repo (Change tag as needed)
ARG PLANE_VERSION=v0.24.0
RUN git clone --depth 1 --branch ${PLANE_VERSION} https://github.com/makeplane/plane.git .

# Install pnpm
RUN npm install -g pnpm turbo

# Prune for specific service (defaults to web)
ONBUILD ARG SCOPE
ONBUILD RUN turbo prune --scope=${SCOPE} --docker
