# ragnarsec-plane-web
# Next.js Frontend for Plane (App)
ARG BASE_TAG=latest

# --- Builder Stage ---
FROM ghcr.io/yonrasgg/ragnarsec-builder:${BASE_TAG} AS builder

USER root
# Install pnpm (Plane uses pnpm)
RUN npm install -g pnpm

# Clone specific version of Plane
ARG PLANE_VERSION=v0.24.0
WORKDIR /tmp/plane-src
RUN git clone --depth 1 --branch ${PLANE_VERSION} https://github.com/makeplane/plane.git .

# Setup web directory
WORKDIR /app/web
RUN cp -r /tmp/plane-src/web/* . && \
    cp /tmp/plane-src/pnpm-lock.yaml /app/ && \
    cp /tmp/plane-src/package.json /app/

# Install dependencies
# We need to install dependencies in root first for workspace?
# Plane is a monorepo. It likely uses pnpm workspaces.
# However, we only care about 'web'.
# Copying valid workspace config might be needed.
# For simplicity, let's try to install deps in the web folder if possible, 
# or copy the whole repo structure if workspaces are mandatory.

# Better approach for monorepo: Copy minimal files, install, then build.
# But since we cloned, we have everything.
WORKDIR /tmp/plane-src
RUN pnpm install --frozen-lockfile

# Build web
WORKDIR /tmp/plane-src/web
# Set Next.js standalone mode if not set in next.config.js?
# Plane usually sets it.
ENV NEXT_PUBLIC_API_BASE_URL=http://api:8000
ENV NEXT_PUBLIC_deploy_URL=http://localhost:3000
RUN pnpm build

# --- Runtime Stage ---
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG} AS runtime

USER root
# Install Node.js runtime (no npm/build tools needed usually, but next start might need them)
# standalone build needs node
RUN apk upgrade --no-cache && \
    apk add --no-cache \
        nodejs \
        # Some sharp/native deps might need these:
        vips-dev \
        fftw-dev \
        # libc6-compat for some binaries
        libc6-compat

WORKDIR /app

# Copy standalone build
# Next.js standalone output is usually in .next/standalone
COPY --from=builder /tmp/plane-src/web/.next/standalone ./
COPY --from=builder /tmp/plane-src/web/.next/static ./web/.next/static
COPY --from=builder /tmp/plane-src/web/public ./web/public

USER ragnarsec

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

CMD ["node", "web/server.js"]
