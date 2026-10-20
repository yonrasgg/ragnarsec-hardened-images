# ragnarsec-plane-space
# Next.js Frontend for Plane (Public Pages)
ARG BASE_TAG=latest

# --- Builder Stage ---
FROM ghcr.io/yonrasgg/ragnarsec-builder:${BASE_TAG} AS builder

USER root
RUN npm install -g pnpm

# Clone specific version of Plane
ARG PLANE_VERSION=v0.24.0
WORKDIR /tmp/plane-src
RUN git clone --depth 1 --branch ${PLANE_VERSION} https://github.com/makeplane/plane.git .

# Install dependencies (monorepo root)
RUN pnpm install --frozen-lockfile

# Build space
WORKDIR /tmp/plane-src/space
# Plane space build
RUN pnpm build

# --- Runtime Stage ---
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG} AS runtime

USER root
# Install Node.js runtime
RUN apk upgrade --no-cache && \
    apk add --no-cache \
        nodejs \
        # Sharp/Image optimization deps
        vips \
        fftw \
        libc6-compat

WORKDIR /app

# Copy standalone build
# Next.js standalone output is usually in .next/standalone
COPY --from=builder /tmp/plane-src/space/.next/standalone ./
COPY --from=builder /tmp/plane-src/space/.next/static ./space/.next/static
COPY --from=builder /tmp/plane-src/space/public ./space/public

USER ragnarsec

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

CMD ["node", "space/server.js"]
