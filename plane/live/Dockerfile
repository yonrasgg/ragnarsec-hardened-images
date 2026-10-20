# ragnarsec-plane-live
# Node.js Realtime Service for Plane
ARG BASE_TAG=latest

# --- Builder Stage ---
FROM ghcr.io/yonrasgg/ragnarsec-builder:${BASE_TAG} AS builder

USER root
WORKDIR /build

# Clone specific version of Plane
ARG PLANE_VERSION=v0.24.0
RUN git clone --depth 1 --branch ${PLANE_VERSION} https://github.com/makeplane/plane.git .

# Install dependencies (monorepo root)
RUN npm install -g pnpm && \
    pnpm install --frozen-lockfile

# Build live service (if build step exists, usually tsc)
WORKDIR /build/live
RUN pnpm build

# --- Runtime Stage ---
FROM ghcr.io/yonrasgg/ragnarsec-base:${BASE_TAG} AS runtime

USER root
# Install Node.js runtime and npm for pnpm
RUN apk upgrade --no-cache && \
    apk add --no-cache \
        nodejs \
        npm \
        # Optional: native deps if needed
        libc6-compat

WORKDIR /app
COPY --from=builder /build/live/dist ./dist
COPY --from=builder /build/live/package.json ./
# Since this is not Next.js standalone, we need node_modules.
# However, pnpm monorepo structure makes this tricky.
# We might need to copy node_modules or reinstall prod deps.
# Let's try reinstalling prod deps in the separate folder.

# Reinstalling prod deps:
COPY --from=builder /build/pnpm-lock.yaml ./
RUN npm install -g pnpm && \
    pnpm install --prod --frozen-lockfile

USER ragnarsec
ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

CMD ["node", "dist/index.js"]
